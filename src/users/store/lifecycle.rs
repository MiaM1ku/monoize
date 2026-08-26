use super::helpers::*;
use crate::users::{
    RESERVED_INTERNAL_USER_PREFIX, UserStore,
};
use crate::transforms::{
    TransformRuleConfig,
    canonicalize_transform_rules,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::Utc;
use sea_orm::Value as SeaValue;
use sea_orm::ConnectionTrait;
use std::sync::Arc;

impl UserStore {
    pub fn api_key_batch_delete_max_ids() -> usize {
        api_key_batch_delete_max_ids()
    }

    pub fn is_reserved_internal_username(username: &str) -> bool {
        username
            .trim()
            .to_ascii_lowercase()
            .starts_with(RESERVED_INTERNAL_USER_PREFIX)
    }

    pub async fn new(
        db: crate::db::DbPool,
        log_broadcast: tokio::sync::broadcast::Sender<Vec<crate::users::InsertRequestLog>>,
    ) -> Result<Self, String> {
        Self::new_with_pending_request_logs(db, log_broadcast, Arc::new(dashmap::DashMap::new()))
            .await
    }

    pub async fn new_with_pending_request_logs(
        db: crate::db::DbPool,
        log_broadcast: tokio::sync::broadcast::Sender<Vec<crate::users::InsertRequestLog>>,
        pending_request_logs: Arc<dashmap::DashMap<String, crate::users::InsertRequestLog>>,
    ) -> Result<Self, String> {
        Self::new_with_pending_request_logs_and_spool_dir(
            db,
            log_broadcast,
            pending_request_logs,
            None,
        )
        .await
    }

    pub async fn new_with_pending_request_logs_and_spool_dir(
        db: crate::db::DbPool,
        log_broadcast: tokio::sync::broadcast::Sender<Vec<crate::users::InsertRequestLog>>,
        pending_request_logs: Arc<dashmap::DashMap<String, crate::users::InsertRequestLog>>,
        request_log_spool_dir: Option<std::path::PathBuf>,
    ) -> Result<Self, String> {
        Self::new_for_role(
            db,
            log_broadcast,
            pending_request_logs,
            request_log_spool_dir,
            false,
        )
        .await
    }

    /// `is_replica` skips the startup write passes (PRP11): transform-id canonicalization
    /// and expired-session deletion are primary responsibilities.
    pub async fn new_for_role(
        db: crate::db::DbPool,
        log_broadcast: tokio::sync::broadcast::Sender<Vec<crate::users::InsertRequestLog>>,
        pending_request_logs: Arc<dashmap::DashMap<String, crate::users::InsertRequestLog>>,
        request_log_spool_dir: Option<std::path::PathBuf>,
        is_replica: bool,
    ) -> Result<Self, String> {
        use std::time::Duration;
        let store = Self {
            db,
            last_used_batcher: crate::db_cache::LastUsedBatcher::new(),
            request_log_batcher: crate::db_cache::RequestLogBatcher::new_with_spool_dir(
                128,
                request_log_spool_dir,
                log_broadcast,
                pending_request_logs,
            ),
            api_key_cache: crate::db_cache::ApiKeyCache::new(Duration::from_secs(60)),
            balance_cache: crate::db_cache::BalanceCache::new(Duration::from_secs(30)),
            registration_lock: Arc::new(tokio::sync::Mutex::new(())),
            api_key_creation_lock: Arc::new(tokio::sync::Mutex::new(())),
            custom_transforms: crate::custom_transforms::CustomTransformSnapshotHandle::default(),
        };
        if !is_replica {
            store.migrate_transform_rule_ids().await?;
            store.cleanup_expired_sessions().await?;
        }
        Ok(store)
    }

    /// Attaches the shared enabled custom-transform snapshot (CJS-AKV-2).
    pub fn with_custom_transforms(
        mut self,
        handle: crate::custom_transforms::CustomTransformSnapshotHandle,
    ) -> Self {
        self.custom_transforms = handle;
        self
    }

    pub(crate) async fn migrate_transform_rule_ids(&self) -> Result<(), String> {
        const TRANSFORM_MIGRATION_MARKER: &str = "migration.api_key_transform_rule_ids.v2";
        const OBSOLETE_TRANSFORM_MIGRATION_MARKER: &str = "migration.api_key_transform_rule_ids.v1";
        const TRANSFORM_MIGRATION_CHUNK_SIZE: usize = 300;
        let marker = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT value FROM system_settings WHERE key = $1",
                vec![TRANSFORM_MIGRATION_MARKER.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        if marker
            .as_ref()
            .and_then(|row| row.try_get::<String>("", "value").ok())
            .as_deref()
            == Some("complete")
        {
            return Ok(());
        }
        let mut cursor: Option<String> = None;
        loop {
            let tx = self.db.begin_write().await.map_err(|e| e.to_string())?;
            let rows = match cursor.as_deref() {
                Some(cursor) => {
                    tx.query_all(self.db.stmt(
                        &format!(
                            "SELECT id, transforms FROM api_keys
                             WHERE id > $1 ORDER BY id LIMIT {TRANSFORM_MIGRATION_CHUNK_SIZE}"
                        ),
                        vec![cursor.into()],
                    ))
                    .await
                }
                None => {
                    tx.query_all(self.db.stmt(
                        &format!(
                            "SELECT id, transforms FROM api_keys
                             ORDER BY id LIMIT {TRANSFORM_MIGRATION_CHUNK_SIZE}"
                        ),
                        vec![],
                    ))
                    .await
                }
            }
            .map_err(|e| e.to_string())?;
            if rows.is_empty() {
                tx.commit().await.map_err(|e| e.to_string())?;
                break;
            }

            let mut updates = Vec::new();
            for row in rows {
                let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                cursor = Some(id.clone());
                let raw: String = row
                    .try_get("", "transforms")
                    .unwrap_or_else(|_| "[]".to_string());
                let Ok(mut transforms) = serde_json::from_str::<Vec<TransformRuleConfig>>(&raw)
                else {
                    tracing::warn!(api_key_id = %id, "skip invalid api key transforms during transform id migration");
                    continue;
                };
                if !canonicalize_transform_rules(&mut transforms) {
                    continue;
                }
                let encoded = serde_json::to_string(&transforms).map_err(|e| e.to_string())?;
                updates.push((id, encoded));
            }
            if !updates.is_empty() {
                let mut values: Vec<SeaValue> = Vec::with_capacity(updates.len() * 3);
                let mut cases = Vec::with_capacity(updates.len());
                let mut ids = Vec::with_capacity(updates.len());
                for (id, transforms) in &updates {
                    let id_index = values.len() + 1;
                    values.push(id.clone().into());
                    let transforms_index = values.len() + 1;
                    values.push(transforms.clone().into());
                    cases.push(format!("WHEN ${id_index} THEN ${transforms_index}"));
                }
                for (id, _) in &updates {
                    let id_index = values.len() + 1;
                    values.push(id.clone().into());
                    ids.push(format!("${id_index}"));
                }
                tx.execute(self.db.stmt(
                    &format!(
                        "UPDATE api_keys SET transforms = CASE id {} ELSE transforms END
                         WHERE id IN ({})",
                        cases.join(" "),
                        ids.join(", ")
                    ),
                    values,
                ))
                .await
                .map_err(|e| e.to_string())?;
            }
            tx.commit().await.map_err(|e| e.to_string())?;
            for (id, _) in updates {
                self.api_key_cache.invalidate_by_key_id(&id);
            }
        }
        let tx = self.db.begin_write().await.map_err(|e| e.to_string())?;
        tx.execute(self.db.stmt(
            "INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, $3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            vec![
                TRANSFORM_MIGRATION_MARKER.into(),
                "complete".into(),
                Utc::now().to_rfc3339().into(),
            ],
        ))
        .await
        .map_err(|e| e.to_string())?;
        tx.execute(self.db.stmt(
            "DELETE FROM system_settings WHERE key = $1",
            vec![OBSOLETE_TRANSFORM_MIGRATION_MARKER.into()],
        ))
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    pub fn spawn_background_tasks(&self) {
        self.spawn_background_tasks_for_role(false);
    }

    /// On a replica the DB flush loops, session cleanup, and log retention loops are
    /// replaced by the shipment pipeline (`primary-replica-deployment.spec.md` PRP12).
    pub fn spawn_background_tasks_for_role(&self, is_replica: bool) {
        if !is_replica {
            self.last_used_batcher
                .clone()
                .spawn_flush_task(self.db.clone(), std::time::Duration::from_secs(30));
            self.request_log_batcher
                .clone()
                .spawn_flush_task(self.db.clone(), std::time::Duration::from_secs(2));
        }
        self.api_key_cache
            .clone()
            .spawn_eviction_task(std::time::Duration::from_secs(30));
        self.balance_cache
            .clone()
            .spawn_eviction_task(std::time::Duration::from_secs(30));
        if is_replica {
            return;
        }
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(session_cleanup_interval()).await;
                if let Err(error) = store.cleanup_expired_sessions().await {
                    tracing::warn!(%error, "failed to cleanup expired sessions");
                }
            }
        });
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(
                    crate::users::request_logs::REQUEST_LOG_RETENTION_INTERVAL_SECS,
                ))
                .await;
                if let Err(e) = store.cleanup_expired_request_logs().await {
                    tracing::warn!("failed to cleanup expired request logs: {e}");
                }
            }
        });
        self.spawn_plan_grant_scheduler();
    }

    /// Replica shipment pipeline access (PRP12/M4).
    pub fn last_used_batcher_clone(&self) -> crate::db_cache::LastUsedBatcher {
        self.last_used_batcher.clone()
    }

    /// Replica shipment pipeline access (PRP12/M4).
    pub fn request_log_batcher_clone(&self) -> crate::db_cache::RequestLogBatcher {
        self.request_log_batcher.clone()
    }

    pub async fn flush_all_batchers(&self) {
        self.last_used_batcher.flush(&self.db).await;
        self.request_log_batcher.flush(&self.db).await;
    }

    pub fn hash_password(password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| e.to_string())?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Runs Argon2 outside the Tokio worker pool so request futures remain schedulable.
    pub async fn hash_password_async(password: &str) -> Result<String, String> {
        let password = password.to_string();
        tokio::task::spawn_blocking(move || Self::hash_password(&password))
            .await
            .map_err(|error| format!("password hashing task failed: {error}"))?
    }

    pub async fn verify_password_async(password: &str, hash: &str) -> Result<bool, String> {
        let password = password.to_string();
        let hash = hash.to_string();
        tokio::task::spawn_blocking(move || Self::verify_password(&password, &hash))
            .await
            .map_err(|error| format!("password verification task failed: {error}"))?
    }

    pub async fn user_count(&self) -> Result<i64, String> {
        let row = self.db.read()
            .query_one(self.db.stmt(
                "SELECT COUNT(*) as count FROM users WHERE substr(lower(username), 1, 9) != '_monoize_'",
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;
        let row = row.ok_or_else(|| "no count row".to_string())?;
        row.try_get::<i64>("", "count").map_err(|e| e.to_string())
    }

}
