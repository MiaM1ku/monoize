//! `MonoizeRoutingStore`: persistence and queries for providers and channels.

use crate::db::DbPool;
use crate::transforms::{TransformRuleConfig, canonicalize_transform_rules};
use crate::users::canonicalize_group_ids;
use chrono::Utc;
use sea_orm::{ConnectionTrait, Value as SeaValue};
use std::collections::{HashMap, HashSet};
use super::rows::*;
use super::*;

#[derive(Clone)]
pub struct MonoizeRoutingStore {
    db: DbPool,
}

pub(super) const TRANSFORM_MIGRATION_BATCH_SIZE: usize = 199;
pub(super) const TRANSFORM_MIGRATION_MARKER: &str = "migration.provider_transform_rule_ids.v2";
pub(super) const OBSOLETE_TRANSFORM_MIGRATION_MARKER: &str = "migration.provider_transform_rule_ids.v1";

impl MonoizeRoutingStore {
    pub async fn new(db: DbPool) -> Result<Self, String> {
        let store = Self { db };
        store.migrate_transform_rule_ids().await?;
        Ok(store)
    }

    /// Replica-side constructor per PRP11: skips canonicalization writes that the
    /// primary already performed on the shared database.
    pub async fn new_read_only(db: DbPool) -> Result<Self, String> {
        Ok(Self { db })
    }

    async fn migrate_transform_rule_ids(&self) -> Result<(), String> {
        let marker = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT value FROM system_settings WHERE key = $1",
                vec![TRANSFORM_MIGRATION_MARKER.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        let marker_value = marker
            .map(|row| {
                row.try_get::<String>("", "value")
                    .map_err(|e| e.to_string())
            })
            .transpose()?;
        if marker_value.as_deref() == Some("complete") {
            return Ok(());
        }

        let mut last_id: Option<String> = None;
        loop {
            let tx = self.db.begin_write().await.map_err(|e| e.to_string())?;
            let (sql, values) = match last_id.as_deref() {
                Some(last_id) => (
                    format!(
                        "SELECT id, transforms FROM monoize_providers
                         WHERE id > $1 ORDER BY id ASC LIMIT {TRANSFORM_MIGRATION_BATCH_SIZE}"
                    ),
                    vec![last_id.into()],
                ),
                None => (
                    format!(
                        "SELECT id, transforms FROM monoize_providers
                         ORDER BY id ASC LIMIT {TRANSFORM_MIGRATION_BATCH_SIZE}"
                    ),
                    vec![],
                ),
            };
            let rows = tx
                .query_all(self.db.stmt(&sql, values))
                .await
                .map_err(|e| e.to_string())?;
            if rows.is_empty() {
                tx.commit().await.map_err(|e| e.to_string())?;
                break;
            }
            let batch_len = rows.len();
            let next_last_id: String = rows
                .last()
                .expect("non-empty transform migration batch")
                .try_get("", "id")
                .map_err(|e| e.to_string())?;
            let mut updates = Vec::with_capacity(batch_len);
            for row in rows {
                let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                let raw: String = row.try_get("", "transforms").map_err(|e| e.to_string())?;
                let Ok(mut transforms) = serde_json::from_str::<Vec<TransformRuleConfig>>(&raw)
                else {
                    tracing::warn!(provider_id = %id, "skip invalid provider transforms during transform id migration");
                    continue;
                };
                if !canonicalize_transform_rules(&mut transforms) {
                    continue;
                }
                let encoded = serde_json::to_string(&transforms).map_err(|e| e.to_string())?;
                updates.push((id, encoded));
            }

            if !updates.is_empty() {
                let mut values: Vec<sea_orm::Value> = Vec::with_capacity(updates.len() * 2);
                let mut cases = Vec::with_capacity(updates.len());
                let mut ids = Vec::with_capacity(updates.len());
                for (id, transforms) in &updates {
                    let id_index = values.len() + 1;
                    values.push(id.clone().into());
                    ids.push(format!("${id_index}"));
                    let transforms_index = values.len() + 1;
                    values.push(transforms.clone().into());
                    cases.push(format!("WHEN ${id_index} THEN ${transforms_index}"));
                }
                tx.execute(self.db.stmt(
                    &format!(
                        "UPDATE monoize_providers
                         SET transforms = CASE id {} ELSE transforms END
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
            last_id = Some(next_last_id);
            if batch_len < TRANSFORM_MIGRATION_BATCH_SIZE {
                break;
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

    pub async fn provider_count(&self) -> Result<i64, String> {
        let row = self
            .db
            .read()
            .query_one(
                self.db
                    .stmt("SELECT COUNT(*) as cnt FROM monoize_providers", vec![]),
            )
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "count query returned no rows".to_string())?;
        row.try_get("", "cnt").map_err(|e| e.to_string())
    }

    async fn load_channels_bulk(
        &self,
        provider_id: Option<&str>,
    ) -> Result<HashMap<String, Vec<MonoizeChannel>>, String> {
        let provider_filter = if provider_id.is_some() {
            " WHERE provider_id = $1"
        } else {
            ""
        };
        let values = provider_id.map(|id| vec![id.into()]).unwrap_or_default();
        let channel_rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                &format!(
                    "SELECT id, provider_id, name, base_url, api_key, weight, enabled,
                            provider_type, passive_failure_count_threshold_override,
                            passive_cooldown_seconds_override, passive_window_seconds_override,
                            passive_rate_limit_cooldown_seconds_override,
                            active_probe_enabled_override, active_probe_interval_seconds_override,
                            active_probe_success_threshold_override, active_probe_model_override,
                            affinity_enabled_override, affinity_idle_ttl_seconds_override,
                            affinity_failback_mode_override, affinity_failback_delay_seconds_override,
                            proxy_url, extra_headers, session_affinity_auto, allow_missing_usage,
                            allow_unpriced_server_tools
                     FROM monoize_channels{provider_filter}
                     ORDER BY created_at ASC"
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;

        let (model_sql, model_values) = if let Some(provider_id) = provider_id {
            (
                "SELECT cm.channel_id, cm.model_name, cm.redirect, cm.multiplier
                 FROM monoize_channel_models cm
                 JOIN monoize_channels c ON c.id = cm.channel_id
                 WHERE c.provider_id = $1
                 ORDER BY cm.channel_id ASC, cm.model_name ASC",
                vec![provider_id.into()],
            )
        } else {
            (
                "SELECT channel_id, model_name, redirect, multiplier
                 FROM monoize_channel_models
                 ORDER BY channel_id ASC, model_name ASC",
                vec![],
            )
        };
        let model_rows = self
            .db
            .read()
            .query_all(self.db.stmt(model_sql, model_values))
            .await
            .map_err(|e| e.to_string())?;
        let mut models_by_channel: HashMap<String, HashMap<String, MonoizeModelEntry>> =
            HashMap::new();
        for row in model_rows {
            let channel_id: String = row.try_get("", "channel_id").map_err(|e| e.to_string())?;
            let model_name: String = row.try_get("", "model_name").map_err(|e| e.to_string())?;
            let multiplier = row
                .try_get::<String>("", "multiplier")
                .map_err(|e| e.to_string())?
                .parse()
                .map_err(|e: String| format!("channel {channel_id} invalid multiplier: {e}"))?;
            models_by_channel.entry(channel_id).or_default().insert(
                model_name,
                MonoizeModelEntry {
                    redirect: row.try_get("", "redirect").map_err(|e| e.to_string())?,
                    multiplier,
                },
            );
        }

        let mut channels_by_provider: HashMap<String, Vec<MonoizeChannel>> = HashMap::new();
        for row in channel_rows {
            let provider_id: String = row.try_get("", "provider_id").map_err(|e| e.to_string())?;
            let channel_id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
            channels_by_provider
                .entry(provider_id)
                .or_default()
                .push(decode_channel_row(
                    &row,
                    models_by_channel.remove(&channel_id).unwrap_or_default(),
                )?);
        }
        Ok(channels_by_provider)
    }

    pub async fn list_providers(&self) -> Result<Vec<MonoizeProvider>, String> {
        let rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                r#"SELECT id, name, max_retries, channel_max_retries,
                          channel_retry_interval_ms, circuit_breaker_enabled,
                          per_model_circuit_break, transforms, api_type_overrides,
                          active_probe_enabled_override, active_probe_interval_seconds_override,
                          active_probe_success_threshold_override, active_probe_model_override,
                          request_timeout_ms_override, extra_fields_whitelist,
                          strip_cross_protocol_nested_extra, group_ids,
                          enabled, priority, created_at, updated_at
                   FROM monoize_providers
                   ORDER BY priority ASC, created_at ASC"#,
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;

        let mut channels_by_provider = self.load_channels_bulk(None).await?;
        rows.iter()
            .map(|row| {
                let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                decode_provider_row(row, channels_by_provider.remove(&id).unwrap_or_default())
            })
            .collect()
    }

    pub async fn available_model_names(
        &self,
        candidates: &[String],
    ) -> Result<HashSet<String>, String> {
        if candidates.is_empty() {
            return Ok(HashSet::new());
        }
        let candidates = candidates
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut available = HashSet::new();
        const LOOKUP_CHUNK_SIZE: usize = 400;
        for chunk in candidates.chunks(LOOKUP_CHUNK_SIZE) {
            let placeholders = (0..chunk.len())
                .map(|index| format!("${}", index + 1))
                .collect::<Vec<_>>()
                .join(", ");
            let rows = self
                .db
                .read()
                .query_all(self.db.stmt(
                    &format!(
                        "SELECT DISTINCT cm.model_name
                         FROM monoize_channel_models cm
                         JOIN monoize_channels c ON c.id = cm.channel_id
                         JOIN monoize_providers p ON p.id = c.provider_id
                         WHERE p.enabled = 1
                           AND c.enabled = 1
                           AND c.weight > 0
                           AND cm.model_name IN ({placeholders})"
                    ),
                    chunk.iter().cloned().map(Into::into).collect(),
                ))
                .await
                .map_err(|e| e.to_string())?;
            for row in rows {
                available.insert(row.try_get("", "model_name").map_err(|e| e.to_string())?);
            }
        }
        Ok(available)
    }

    pub async fn list_available_model_names(&self) -> Result<Vec<String>, String> {
        let rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                "SELECT DISTINCT cm.model_name
                 FROM monoize_channel_models cm
                 JOIN monoize_channels c ON c.id = cm.channel_id
                 JOIN monoize_providers p ON p.id = c.provider_id
                 WHERE p.enabled = 1 AND c.enabled = 1 AND c.weight > 0
                 ORDER BY cm.model_name ASC",
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;
        rows.into_iter()
            .map(|row| row.try_get("", "model_name").map_err(|e| e.to_string()))
            .collect()
    }

    pub async fn list_providers_for_model(
        &self,
        model: &str,
    ) -> Result<Vec<MonoizeProvider>, String> {
        let provider_rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                r#"SELECT DISTINCT p.id, p.name, p.max_retries, p.channel_max_retries,
                          p.channel_retry_interval_ms, p.circuit_breaker_enabled,
                          p.per_model_circuit_break, p.transforms, p.api_type_overrides,
                          p.active_probe_enabled_override, p.active_probe_interval_seconds_override,
                          p.active_probe_success_threshold_override, p.active_probe_model_override,
                          p.request_timeout_ms_override, p.extra_fields_whitelist,
                          p.strip_cross_protocol_nested_extra, p.group_ids,
                          p.enabled, p.priority, p.created_at, p.updated_at
                   FROM monoize_providers p
                   JOIN monoize_channels c ON c.provider_id = p.id
                   JOIN monoize_channel_models cm ON cm.channel_id = c.id
                   WHERE cm.model_name = $1
                     AND p.enabled = 1
                     AND c.enabled = 1
                     AND c.weight > 0
                   ORDER BY p.priority ASC, p.created_at ASC"#,
                vec![model.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        if provider_rows.is_empty() {
            return Ok(Vec::new());
        }

        let channel_rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                r#"SELECT c.id, c.provider_id, c.name, c.base_url, c.api_key, c.weight, c.enabled,
                          c.provider_type, c.passive_failure_count_threshold_override,
                          c.passive_cooldown_seconds_override, c.passive_window_seconds_override,
                          c.passive_rate_limit_cooldown_seconds_override,
                          c.active_probe_enabled_override, c.active_probe_interval_seconds_override,
                          c.active_probe_success_threshold_override, c.active_probe_model_override,
                          c.affinity_enabled_override, c.affinity_idle_ttl_seconds_override,
                          c.affinity_failback_mode_override, c.affinity_failback_delay_seconds_override,
                          c.proxy_url,
                          c.extra_headers,
                          c.session_affinity_auto,
                          c.allow_missing_usage,
                          c.allow_unpriced_server_tools,
                          cm.redirect, cm.multiplier
                   FROM monoize_channels c
                   JOIN monoize_providers p ON p.id = c.provider_id
                   JOIN monoize_channel_models cm ON cm.channel_id = c.id
                   WHERE cm.model_name = $1
                     AND p.enabled = 1
                     AND c.enabled = 1
                     AND c.weight > 0
                   ORDER BY c.created_at ASC"#,
                vec![model.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        let mut channels_by_provider: HashMap<String, Vec<MonoizeChannel>> = HashMap::new();
        for row in channel_rows {
            let provider_id: String = row.try_get("", "provider_id").map_err(|e| e.to_string())?;
            channels_by_provider
                .entry(provider_id)
                .or_default()
                .push(decode_channel_model_row(&row, model)?);
        }
        provider_rows
            .iter()
            .map(|row| {
                let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                decode_provider_row(row, channels_by_provider.remove(&id).unwrap_or_default())
            })
            .collect()
    }

    pub async fn list_active_probe_candidates(&self) -> Result<Vec<MonoizeProvider>, String> {
        let provider_rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                r#"SELECT id, name, max_retries, channel_max_retries,
                          channel_retry_interval_ms, circuit_breaker_enabled,
                          per_model_circuit_break, transforms, api_type_overrides,
                          active_probe_enabled_override, active_probe_interval_seconds_override,
                          active_probe_success_threshold_override, active_probe_model_override,
                          request_timeout_ms_override, extra_fields_whitelist,
                          strip_cross_protocol_nested_extra, group_ids,
                          enabled, priority, created_at, updated_at
                   FROM monoize_providers
                   WHERE circuit_breaker_enabled = 1
                     AND enabled = 1
                     AND EXISTS (
                         SELECT 1
                         FROM monoize_channels c
                         WHERE c.provider_id = monoize_providers.id
                           AND c.enabled = 1
                           AND c.weight > 0
                     )
                   ORDER BY priority ASC, created_at ASC"#,
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;
        if provider_rows.is_empty() {
            return Ok(Vec::new());
        }
        let channel_model_rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                r#"SELECT c.id, c.provider_id, c.name, c.base_url, c.api_key, c.weight, c.enabled,
                          c.provider_type, c.passive_failure_count_threshold_override,
                          c.passive_cooldown_seconds_override, c.passive_window_seconds_override,
                          c.passive_rate_limit_cooldown_seconds_override,
                          c.active_probe_enabled_override, c.active_probe_interval_seconds_override,
                          c.active_probe_success_threshold_override, c.active_probe_model_override,
                          c.affinity_enabled_override, c.affinity_idle_ttl_seconds_override,
                          c.affinity_failback_mode_override, c.affinity_failback_delay_seconds_override,
                          c.proxy_url, c.extra_headers, c.session_affinity_auto,
                          c.allow_missing_usage,
                          c.allow_unpriced_server_tools,
                          cm.model_name, cm.redirect, cm.multiplier
                   FROM monoize_channels c
                   JOIN monoize_providers p ON p.id = c.provider_id
                   JOIN monoize_channel_models cm ON cm.channel_id = c.id
                   WHERE p.circuit_breaker_enabled = 1
                     AND p.enabled = 1
                     AND c.enabled = 1
                     AND c.weight > 0
                   ORDER BY c.created_at ASC, cm.model_name ASC"#,
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;

        let mut channels_by_provider: HashMap<String, Vec<MonoizeChannel>> = HashMap::new();
        let mut channel_positions: HashMap<(String, String), usize> = HashMap::new();
        for row in channel_model_rows {
            let provider_id: String = row.try_get("", "provider_id").map_err(|e| e.to_string())?;
            let channel_id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
            let model_name: String = row.try_get("", "model_name").map_err(|e| e.to_string())?;
            let channels = channels_by_provider.entry(provider_id.clone()).or_default();
            if let Some(index) = channel_positions.get(&(provider_id.clone(), channel_id.clone())) {
                let model_entry = decode_channel_model_row(&row, &model_name)?
                    .models
                    .remove(&model_name)
                    .expect("decoded channel model row must contain its model");
                channels[*index].models.insert(model_name, model_entry);
            } else {
                let index = channels.len();
                channels.push(decode_channel_model_row(&row, &model_name)?);
                channel_positions.insert((provider_id, channel_id), index);
            }
        }
        provider_rows
            .iter()
            .map(|row| {
                let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                decode_provider_row(row, channels_by_provider.remove(&id).unwrap_or_default())
            })
            .collect()
    }

    /// GR-I2/GR-C3 for the provider group set: canonicalize, replace an empty
    /// selection with the default group id, and require every id to reference
    /// an existing registry row.
    async fn resolve_provider_group_ids(
        &self,
        group_ids: &[String],
    ) -> Result<Vec<String>, String> {
        let group_ids = canonicalize_group_ids(group_ids);
        if group_ids.len() > 32 {
            return Err("at most 32 groups can be selected".to_string());
        }
        if group_ids.is_empty() {
            let row = self
                .db
                .read()
                .query_one(self.db.stmt(
                    "SELECT id FROM monoize_groups WHERE is_default = 1 LIMIT 1",
                    vec![],
                ))
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "default group row missing (GR-D2 violated)".to_string())?;
            let default_id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
            return Ok(vec![default_id]);
        }
        for id in &group_ids {
            let row = self
                .db
                .read()
                .query_one(self.db.stmt(
                    "SELECT 1 AS one FROM monoize_groups WHERE id = $1",
                    vec![id.clone().into()],
                ))
                .await
                .map_err(|e| e.to_string())?;
            if row.is_none() {
                return Err(format!("unknown group id: {id}"));
            }
        }
        Ok(group_ids)
    }

    pub async fn get_provider(&self, id: &str) -> Result<Option<MonoizeProvider>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                r#"SELECT id, name, max_retries, channel_max_retries,
                          channel_retry_interval_ms, circuit_breaker_enabled,
                          per_model_circuit_break, transforms, api_type_overrides,
                          active_probe_enabled_override, active_probe_interval_seconds_override,
                          active_probe_success_threshold_override, active_probe_model_override,
                          request_timeout_ms_override, extra_fields_whitelist,
                          strip_cross_protocol_nested_extra, group_ids,
                          enabled, priority, created_at, updated_at
                   FROM monoize_providers
                   WHERE id = $1"#,
                vec![id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        let Some(row) = row else {
            return Ok(None);
        };
        let mut channels_by_provider = self.load_channels_bulk(Some(id)).await?;
        Ok(Some(decode_provider_row(
            &row,
            channels_by_provider.remove(id).unwrap_or_default(),
        )?))
    }

    pub async fn create_provider(
        &self,
        input: CreateMonoizeProviderInput,
    ) -> Result<MonoizeProvider, String> {
        validate_provider_input(&input.name, &input.channels, &input.api_type_overrides)?;
        if let Some(v) = input.active_probe_interval_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "active_probe_interval_seconds_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(v) = input.active_probe_success_threshold_override {
            if !(1..=i32::MAX as u32).contains(&v) {
                return Err(
                    "active_probe_success_threshold_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(v) = input.request_timeout_ms_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "request_timeout_ms_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if input.channel_retry_interval_ms < 0 {
            return Err("channel_retry_interval_ms must be >= 0".to_string());
        }

        let id = generate_short_id();
        let now = Utc::now();
        // Resolve before begin_write: the registry lookup uses the read pool,
        // which on single-connection SQLite would deadlock behind our own
        // write transaction.
        let group_ids_json = serialize_provider_group_ids_json(
            &self.resolve_provider_group_ids(&input.group_ids).await?,
        )?;
        let txn = self.db.begin_write().await.map_err(|e| e.to_string())?;

        let priority = match input.priority {
            Some(v) => v,
            None => {
                if self.db.is_postgres() {
                    txn.execute_unprepared(
                        "LOCK TABLE monoize_providers IN SHARE ROW EXCLUSIVE MODE",
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                }
                let row = txn
                    .query_one(self.db.stmt(
                        "SELECT CAST(MAX(priority) AS BIGINT) AS max_p FROM monoize_providers",
                        vec![],
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                let max_priority = row
                    .map(|row| {
                        row.try_get::<Option<i64>>("", "max_p")
                            .map_err(|e| e.to_string())
                    })
                    .transpose()?
                    .flatten();
                let next_priority = max_priority
                    .unwrap_or(-1)
                    .checked_add(1)
                    .ok_or_else(|| "provider priority overflow".to_string())?;
                i32::try_from(next_priority)
                    .map_err(|_| "provider priority exceeds signed 32-bit range".to_string())?
            }
        };

        let mut transforms = input.transforms.clone();
        canonicalize_transform_rules(&mut transforms);
        let transforms_json = serde_json::to_string(&transforms).map_err(|e| e.to_string())?;
        let api_type_overrides_json =
            serde_json::to_string(&input.api_type_overrides).map_err(|e| e.to_string())?;
        let extra_fields_whitelist_json: Option<String> = input
            .extra_fields_whitelist
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string()));
        let strip_cross_proto = input.strip_cross_protocol_nested_extra;

        txn.execute(self.db.stmt(
                r#"INSERT INTO monoize_providers (
                        id, name, max_retries, channel_max_retries,
                        channel_retry_interval_ms, circuit_breaker_enabled,
                        per_model_circuit_break, transforms, api_type_overrides,
                        active_probe_enabled_override, active_probe_interval_seconds_override,
                        active_probe_success_threshold_override, active_probe_model_override,
                        request_timeout_ms_override, extra_fields_whitelist,
                        strip_cross_protocol_nested_extra, group_ids,
                        enabled, priority, created_at, updated_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)"#,
                vec![
                        id.clone().into(),
                        input.name.clone().into(),
                        SeaValue::Int(Some(input.max_retries)),
                        SeaValue::Int(Some(input.channel_max_retries)),
                        SeaValue::Int(Some(input.channel_retry_interval_ms)),
                        SeaValue::Int(Some(if input.circuit_breaker_enabled { 1 } else { 0 })),
                        SeaValue::Int(Some(if input.per_model_circuit_break { 1 } else { 0 })),
                        transforms_json.into(),
                        api_type_overrides_json.into(),
                        opt_bool_to_value(input.active_probe_enabled_override),
                        opt_u64_to_value(input.active_probe_interval_seconds_override),
                        opt_u64_to_value(
                            input
                                .active_probe_success_threshold_override
                                .map(|v| v as u64),
                        ),
                        input.active_probe_model_override.clone().into(),
                        opt_u64_to_value(input.request_timeout_ms_override),
                        extra_fields_whitelist_json.into(),
                        opt_bool_to_value(strip_cross_proto),
                        group_ids_json.into(),
                        SeaValue::Int(Some(if input.enabled { 1 } else { 0 })),
                        SeaValue::Int(Some(priority)),
                        now.to_rfc3339().into(),
                        now.to_rfc3339().into(),
                    ],
            ))
            .await
            .map_err(|e| e.to_string())?;

        self.replace_channels_on(&*txn, &id, &input.channels)
            .await?;
        txn.commit().await.map_err(|e| e.to_string())?;

        self.get_provider(&id)
            .await?
            .ok_or_else(|| "provider not found after create".to_string())
    }

    pub async fn update_provider(
        &self,
        id: &str,
        input: UpdateMonoizeProviderInput,
    ) -> Result<MonoizeProvider, String> {
        if let Some(channels) = &input.channels {
            validate_channels(channels, false)?;
        }
        if let Some(Some(v)) = input.active_probe_interval_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "active_probe_interval_seconds_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(Some(v)) = input.active_probe_success_threshold_override {
            if !(1..=i32::MAX as u32).contains(&v) {
                return Err(
                    "active_probe_success_threshold_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(Some(v)) = input.request_timeout_ms_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "request_timeout_ms_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if let Some(v) = input.channel_retry_interval_ms {
            if v < 0 {
                return Err("channel_retry_interval_ms must be >= 0".to_string());
            }
        }

        if let Some(api_type_overrides) = &input.api_type_overrides {
            validate_api_type_overrides(api_type_overrides)?;
        }

        let mut set_clauses = Vec::new();
        let mut values: Vec<SeaValue> = Vec::new();
        let mut push_value = |column: &str, value: SeaValue| {
            let index = values.len() + 1;
            set_clauses.push(format!("{column} = ${index}"));
            values.push(value);
        };
        if let Some(value) = &input.name {
            push_value("name", value.clone().into());
        }
        if let Some(value) = input.max_retries {
            push_value("max_retries", SeaValue::Int(Some(value)));
        }
        if let Some(value) = input.channel_max_retries {
            push_value("channel_max_retries", SeaValue::Int(Some(value)));
        }
        if let Some(value) = input.channel_retry_interval_ms {
            push_value("channel_retry_interval_ms", SeaValue::Int(Some(value)));
        }
        if let Some(value) = input.circuit_breaker_enabled {
            push_value(
                "circuit_breaker_enabled",
                SeaValue::Int(Some(if value { 1 } else { 0 })),
            );
        }
        if let Some(value) = input.per_model_circuit_break {
            push_value(
                "per_model_circuit_break",
                SeaValue::Int(Some(if value { 1 } else { 0 })),
            );
        }
        if let Some(mut transforms) = input.transforms.clone() {
            canonicalize_transform_rules(&mut transforms);
            push_value(
                "transforms",
                serde_json::to_string(&transforms)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
        }
        if let Some(value) = &input.api_type_overrides {
            push_value(
                "api_type_overrides",
                serde_json::to_string(value)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
        }
        if let Some(value) = input.active_probe_enabled_override {
            push_value("active_probe_enabled_override", opt_bool_to_value(value));
        }
        if let Some(value) = input.active_probe_interval_seconds_override {
            push_value(
                "active_probe_interval_seconds_override",
                opt_u64_to_value(value),
            );
        }
        if let Some(value) = input.active_probe_success_threshold_override {
            push_value(
                "active_probe_success_threshold_override",
                opt_u64_to_value(value.map(u64::from)),
            );
        }
        if let Some(value) = &input.active_probe_model_override {
            push_value("active_probe_model_override", value.clone().into());
        }
        if let Some(value) = input.request_timeout_ms_override {
            push_value("request_timeout_ms_override", opt_u64_to_value(value));
        }
        if let Some(value) = &input.extra_fields_whitelist {
            let encoded = value
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|e| e.to_string())?;
            push_value("extra_fields_whitelist", encoded.into());
        }
        if let Some(value) = input.strip_cross_protocol_nested_extra {
            push_value(
                "strip_cross_protocol_nested_extra",
                opt_bool_to_value(value),
            );
        }
        if let Some(value) = &input.group_ids {
            let resolved = self.resolve_provider_group_ids(value).await?;
            push_value(
                "group_ids",
                serialize_provider_group_ids_json(&resolved)?.into(),
            );
        }
        if let Some(value) = input.enabled {
            push_value("enabled", SeaValue::Int(Some(if value { 1 } else { 0 })));
        }
        if let Some(value) = input.priority {
            push_value("priority", SeaValue::Int(Some(value)));
        }
        push_value("updated_at", Utc::now().to_rfc3339().into());
        drop(push_value);

        let id_index = values.len() + 1;
        values.push(id.into());
        let txn = self.db.begin_write().await.map_err(|e| e.to_string())?;
        let result = txn
            .execute(self.db.stmt(
                &format!(
                    "UPDATE monoize_providers SET {} WHERE id = ${id_index}",
                    set_clauses.join(", ")
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        if result.rows_affected() == 0 {
            return Err("provider not found".to_string());
        }

        if let Some(channels) = &input.channels {
            self.replace_channels_on(&*txn, id, channels).await?;
        }

        txn.commit().await.map_err(|e| e.to_string())?;

        self.get_provider(id)
            .await?
            .ok_or_else(|| "provider not found after update".to_string())
    }

    pub async fn delete_provider(&self, id: &str) -> Result<(), String> {
        let result = self
            .db
            .write()
            .await
            .execute(self.db.stmt(
                "DELETE FROM monoize_providers WHERE id = $1",
                vec![id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if result.rows_affected() == 0 {
            return Err("provider not found".to_string());
        }

        Ok(())
    }

    pub async fn reorder_providers(&self, input: ReorderProvidersInput) -> Result<(), String> {
        if input.provider_ids.len() > provider_reorder_max_ids() {
            return Err(format!(
                "provider reorder accepts at most {} ids",
                provider_reorder_max_ids()
            ));
        }
        let mut uniq = HashSet::new();
        for id in &input.provider_ids {
            if !uniq.insert(id.clone()) {
                return Err("provider_ids contains duplicates".to_string());
            }
        }

        let txn = self.db.begin_write().await.map_err(|e| e.to_string())?;
        if self.db.is_postgres() {
            txn.execute_unprepared("LOCK TABLE monoize_providers IN SHARE ROW EXCLUSIVE MODE")
                .await
                .map_err(|e| e.to_string())?;
        }
        let rows = txn
            .query_all(
                self.db
                    .stmt("SELECT id FROM monoize_providers ORDER BY id", vec![]),
            )
            .await
            .map_err(|e| e.to_string())?;
        if rows.len() != input.provider_ids.len() {
            return Err("provider_ids must contain all providers exactly once".to_string());
        }

        let existing_ids: HashSet<String> = rows
            .into_iter()
            .map(|row| row.try_get("", "id").map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let input_ids: HashSet<String> = input.provider_ids.iter().cloned().collect();
        if existing_ids != input_ids {
            return Err("provider_ids must contain all providers exactly once".to_string());
        }
        if input.provider_ids.is_empty() {
            return txn.commit().await.map_err(|e| e.to_string());
        }

        let mut values = Vec::with_capacity(input.provider_ids.len() * 2 + 1);
        let mut cases = Vec::with_capacity(input.provider_ids.len());
        for (priority, id) in input.provider_ids.iter().enumerate() {
            let id_index = values.len() + 1;
            values.push(id.clone().into());
            let priority_index = values.len() + 1;
            values.push(SeaValue::Int(Some(priority as i32)));
            cases.push(format!("WHEN ${id_index} THEN ${priority_index}"));
        }
        let updated_at_index = values.len() + 1;
        values.push(Utc::now().to_rfc3339().into());
        txn.execute(self.db.stmt(
            &format!(
                "UPDATE monoize_providers
                 SET priority = CASE id {} END, updated_at = ${updated_at_index}",
                cases.join(" ")
            ),
            values,
        ))
        .await
        .map_err(|e| e.to_string())?;
        txn.commit().await.map_err(|e| e.to_string())
    }

    async fn replace_channels_on(
        &self,
        conn: &impl ConnectionTrait,
        provider_id: &str,
        channels: &[CreateMonoizeChannelInput],
    ) -> Result<(), String> {
        let existing_rows = conn
            .query_all(self.db.stmt(
                "SELECT id, api_key
                 FROM monoize_channels
                 WHERE provider_id = $1",
                vec![provider_id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        #[derive(Clone)]
        struct ExistingChannel {
            api_key: String,
        }
        let mut existing_channels: HashMap<String, ExistingChannel> = HashMap::new();
        for row in &existing_rows {
            let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
            existing_channels.insert(
                id,
                ExistingChannel {
                    api_key: row.try_get("", "api_key").map_err(|e| e.to_string())?,
                },
            );
        }

        conn.execute(self.db.stmt(
            "DELETE FROM monoize_channels WHERE provider_id = $1",
            vec![provider_id.into()],
        ))
        .await
        .map_err(|e| e.to_string())?;

        struct PreparedChannel<'a> {
            id: String,
            api_key: String,
            input: &'a CreateMonoizeChannelInput,
            models: HashMap<String, MonoizeModelEntry>,
        }

        let mut prepared = Vec::with_capacity(channels.len());
        for input in channels {
            let id = input
                .id
                .clone()
                .unwrap_or_else(|| format!("mono_ch_{}", uuid::Uuid::new_v4().simple()));

            let api_key = match input.api_key.as_deref() {
                Some(k) if !k.trim().is_empty() => k.to_string(),
                _ => existing_channels
                    .get(&id)
                    .map(|c| c.api_key.clone())
                    .ok_or_else(|| {
                        format!(
                            "channel api_key must not be empty for new channel '{}'",
                            input.name
                        )
                    })?,
            };
            prepared.push(PreparedChannel {
                id,
                api_key,
                input,
                models: canonicalize_models(&input.models),
            });
        }

        const CHANNEL_INSERT_CHUNK_SIZE: usize = 18;
        let now = Utc::now().to_rfc3339();
        for chunk in prepared.chunks(CHANNEL_INSERT_CHUNK_SIZE) {
            let mut values: Vec<SeaValue> = Vec::with_capacity(chunk.len() * 26);
            let mut rows = Vec::with_capacity(chunk.len());
            for channel in chunk {
                let start = values.len() + 1;
                let input = channel.input;
                values.extend([
                    channel.id.clone().into(),
                    provider_id.into(),
                    input.name.as_str().into(),
                    input.provider_type.as_str().into(),
                    input.base_url.as_str().into(),
                    channel.api_key.clone().into(),
                    SeaValue::Int(Some(input.weight)),
                    SeaValue::Int(Some(if input.enabled { 1 } else { 0 })),
                    opt_u64_to_value(
                        input
                            .passive_failure_count_threshold_override
                            .map(|value| value as u64),
                    ),
                    opt_u64_to_value(input.passive_cooldown_seconds_override),
                    opt_u64_to_value(input.passive_window_seconds_override),
                    opt_u64_to_value(input.passive_rate_limit_cooldown_seconds_override),
                    opt_bool_to_value(input.active_probe_enabled_override),
                    opt_u64_to_value(input.active_probe_interval_seconds_override),
                    opt_u64_to_value(
                        input
                            .active_probe_success_threshold_override
                            .map(|value| value as u64),
                    ),
                    input.active_probe_model_override.clone().into(),
                    opt_bool_to_value(input.affinity_enabled_override),
                    opt_u64_to_value(input.affinity_idle_ttl_seconds_override),
                    input
                        .affinity_failback_mode_override
                        .map(|mode| mode.as_str().to_string())
                        .into(),
                    opt_u64_to_value(input.affinity_failback_delay_seconds_override),
                    normalized_proxy_url(input.proxy_url.as_deref()).into(),
                    normalized_extra_headers_json(input.extra_headers.as_ref()).into(),
                    opt_bool_to_value(input.session_affinity_auto),
                    SeaValue::Int(Some(if input.allow_missing_usage { 1 } else { 0 })),
                    SeaValue::Int(Some(if input.allow_unpriced_server_tools {
                        1
                    } else {
                        0
                    })),
                    now.clone().into(),
                    now.clone().into(),
                ]);
                rows.push(format!(
                    "({})",
                    (start..start + 27)
                        .map(|index| format!("${index}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            conn.execute(self.db.stmt(
                &format!(
                    "INSERT INTO monoize_channels
                     (id, provider_id, name, provider_type, base_url, api_key, weight, enabled,
                      passive_failure_count_threshold_override, passive_cooldown_seconds_override,
                      passive_window_seconds_override, passive_rate_limit_cooldown_seconds_override,
                      active_probe_enabled_override, active_probe_interval_seconds_override,
                      active_probe_success_threshold_override, active_probe_model_override,
                      affinity_enabled_override, affinity_idle_ttl_seconds_override,
                      affinity_failback_mode_override, affinity_failback_delay_seconds_override,
                      proxy_url,
                      extra_headers,
                      session_affinity_auto,
                      allow_missing_usage,
                      allow_unpriced_server_tools,
                      created_at, updated_at)
                     VALUES {}",
                    rows.join(", ")
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        }

        let model_rows = prepared
            .iter()
            .flat_map(|channel| {
                channel
                    .models
                    .iter()
                    .map(|(model, entry)| (channel.id.clone(), model.clone(), entry.clone()))
            })
            .collect::<Vec<_>>();
        const MODEL_INSERT_CHUNK_SIZE: usize = 66;
        for chunk in model_rows.chunks(MODEL_INSERT_CHUNK_SIZE) {
            let mut values: Vec<SeaValue> = Vec::with_capacity(chunk.len() * 6);
            let mut rows = Vec::with_capacity(chunk.len());
            for (channel_id, model, entry) in chunk {
                let start = values.len() + 1;
                values.extend([
                    format!("mono_ch_model_{}", uuid::Uuid::new_v4().simple()).into(),
                    channel_id.clone().into(),
                    model.clone().into(),
                    entry.redirect.clone().into(),
                    entry.multiplier.to_string().into(),
                    now.clone().into(),
                ]);
                rows.push(format!(
                    "({})",
                    (start..start + 6)
                        .map(|index| format!("${index}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            conn.execute(self.db.stmt(
                &format!(
                    "INSERT INTO monoize_channel_models
                     (id, channel_id, model_name, redirect, multiplier, created_at)
                     VALUES {}",
                    rows.join(", ")
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
