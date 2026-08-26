//! User-account CRUD and atomic admin updates for `UserStore`.

use super::utils::parse_nano_usd;
use super::{
    AdminUpdateUserInput,
    RegisterUserError,
    User, UserRole, UserStore,
};
use chrono::{DateTime, Utc};
use sea_orm::Value as SeaValue;
use sea_orm::{ConnectionTrait, QueryResult, TransactionTrait};
use super::store::decode_required_bool;

impl UserStore {
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

    /// Create a user with the given group id, or the default group when `None`
    /// (`user-billing-and-model-metadata.spec.md` U3). A provided id must
    /// reference an existing registry row (GR-C3).
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
        group_id: Option<&str>,
    ) -> Result<User, String> {
        let id = uuid::Uuid::new_v4().to_string();
        let password_hash = Self::hash_password_async(password).await?;
        let now = Utc::now();
        let group_id = match group_id.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => {
                if self.get_group_by_id(value).await?.is_none() {
                    return Err(format!("unknown group id: {value}"));
                }
                value.to_string()
            }
            None => self.default_group_id().await?,
        };

        self.db.write().await
            .execute(self.db.stmt(
                r#"INSERT INTO users (id, username, password_hash, role, created_at, updated_at, enabled, balance_nano_usd, balance_unlimited, group_id)
                   VALUES ($1, $2, $3, $4, $5, $6, 1, '0', 0, $7)"#,
                vec![
                    id.clone().into(),
                    username.into(),
                    password_hash.clone().into(),
                    role.as_str().into(),
                    now.to_rfc3339().into(),
                    now.to_rfc3339().into(),
                    group_id.clone().into(),
                ],
            ))
            .await
            .map_err(|e| e.to_string())?;

        Ok(User {
            id,
            username: username.to_string(),
            password_hash,
            role,
            created_at: now,
            updated_at: now,
            last_login_at: None,
            enabled: true,
            balance_nano_usd: "0".to_string(),
            balance_unlimited: false,
            email: None,
            group_id,
            billing_plan_id: None,
            next_grant_at: None,
        })
    }

    pub async fn register_user_atomic(
        &self,
        username: &str,
        password: &str,
        registration_enabled: bool,
    ) -> Result<User, RegisterUserError> {
        let _registration_guard = self.registration_lock.lock().await;
        let user_count = self
            .user_count()
            .await
            .map_err(RegisterUserError::Storage)?;
        if user_count != 0 && !registration_enabled {
            return Err(RegisterUserError::RegistrationDisabled);
        }
        if self
            .get_user_by_username(username)
            .await
            .map_err(RegisterUserError::Storage)?
            .is_some()
        {
            return Err(RegisterUserError::UsernameExists);
        }
        let role = if user_count == 0 {
            UserRole::SuperAdmin
        } else {
            UserRole::User
        };
        self.create_user(username, password, role, None)
            .await
            .map_err(RegisterUserError::Storage)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, String> {
        let row = self.db.read()
            .query_one(self.db.stmt(
                "SELECT id, username, password_hash, role, created_at, updated_at, last_login_at, enabled, balance_nano_usd, balance_unlimited, email, group_id, billing_plan_id, next_grant_at FROM users WHERE id = $1",
                vec![id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row {
            Ok(Some(self.row_to_user(&row)?))
        } else {
            Ok(None)
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, String> {
        let row = self.db.read()
            .query_one(self.db.stmt(
                "SELECT id, username, password_hash, role, created_at, updated_at, last_login_at, enabled, balance_nano_usd, balance_unlimited, email, group_id, billing_plan_id, next_grant_at FROM users WHERE username = $1",
                vec![username.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row {
            Ok(Some(self.row_to_user(&row)?))
        } else {
            Ok(None)
        }
    }

    pub async fn list_users(&self) -> Result<Vec<User>, String> {
        let rows = self.db.read()
            .query_all(self.db.stmt(
                "SELECT id, username, password_hash, role, created_at, updated_at, last_login_at, enabled, balance_nano_usd, balance_unlimited, email, group_id, billing_plan_id, next_grant_at FROM users WHERE substr(lower(username), 1, 9) != '_monoize_' ORDER BY created_at DESC",
                vec![],
            ))
            .await
            .map_err(|e| e.to_string())?;

        rows.iter().map(|row| self.row_to_user(row)).collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_user(
        &self,
        id: &str,
        username: Option<&str>,
        password: Option<&str>,
        role: Option<UserRole>,
        enabled: Option<bool>,
        balance_nano_usd: Option<&str>,
        balance_unlimited: Option<bool>,
        email: Option<Option<&str>>,
        group_id: Option<&str>,
    ) -> Result<(), String> {
        let revokes_sessions = password.is_some() || role.is_some() || enabled == Some(false);
        let password_hash = match password {
            Some(password) => Some(Self::hash_password_async(password).await?),
            None => None,
        };
        let mut set_clauses = Vec::new();
        let mut values: Vec<SeaValue> = Vec::new();
        let mut idx = 1usize;

        if let Some(u) = username {
            set_clauses.push(format!("username = ${idx}"));
            values.push(u.into());
            idx += 1;
        }
        if let Some(password_hash) = password_hash {
            set_clauses.push(format!("password_hash = ${idx}"));
            values.push(password_hash.into());
            idx += 1;
        }
        if let Some(r) = role {
            set_clauses.push(format!("role = ${idx}"));
            values.push(r.as_str().into());
            idx += 1;
        }
        if let Some(e) = enabled {
            set_clauses.push(format!("enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if e { 1 } else { 0 })));
            idx += 1;
        }
        if let Some(balance) = balance_nano_usd {
            parse_nano_usd(balance)?;
            set_clauses.push(format!("balance_nano_usd = ${idx}"));
            values.push(balance.into());
            idx += 1;
        }
        if let Some(unlimited) = balance_unlimited {
            set_clauses.push(format!("balance_unlimited = ${idx}"));
            values.push(SeaValue::Int(Some(if unlimited { 1 } else { 0 })));
            idx += 1;
        }
        if let Some(email_opt) = email {
            match email_opt {
                Some(e) if !e.trim().is_empty() => {
                    set_clauses.push(format!("email = ${idx}"));
                    values.push(e.trim().into());
                    idx += 1;
                }
                _ => {
                    set_clauses.push("email = NULL".to_string());
                }
            }
        }
        if let Some(group_id) = group_id {
            if self.get_group_by_id(group_id).await?.is_none() {
                return Err(format!("unknown group id: {group_id}"));
            }
            set_clauses.push(format!("group_id = ${idx}"));
            values.push(group_id.into());
            idx += 1;
        }
        if set_clauses.is_empty() {
            return Ok(());
        }

        set_clauses.push(format!("updated_at = ${idx}"));
        values.push(Utc::now().to_rfc3339().into());
        idx += 1;

        values.push(id.into());

        let query = format!(
            "UPDATE users SET {} WHERE id = ${idx}",
            set_clauses.join(", ")
        );

        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;
        tx.execute(self.db.stmt(&query, values))
            .await
            .map_err(|e| e.to_string())?;

        if revokes_sessions {
            self.delete_user_sessions_tx(&tx, id).await?;
        }

        tx.commit().await.map_err(|e| e.to_string())?;

        if !set_clauses.is_empty() {
            self.api_key_cache.invalidate_by_user_id(id);
        }
        if balance_nano_usd.is_some() || balance_unlimited.is_some() {
            self.balance_cache.invalidate(id);
        }

        Ok(())
    }

    pub async fn admin_update_user_atomic(
        &self,
        id: &str,
        input: AdminUpdateUserInput,
        actor_user_id: &str,
    ) -> Result<(), String> {
        let AdminUpdateUserInput {
            username,
            password,
            role,
            enabled,
            balance_nano_usd,
            balance_unlimited,
            email,
            group_id,
            billing_plan_id,
        } = input;
        let has_balance_change = balance_nano_usd.is_some() || balance_unlimited.is_some();
        let has_plan_change = billing_plan_id.is_some();
        let revokes_sessions = password.is_some() || role.is_some() || enabled == Some(false);
        if username.is_none()
            && password.is_none()
            && role.is_none()
            && enabled.is_none()
            && !has_balance_change
            && email.is_none()
            && group_id.is_none()
            && billing_plan_id.is_none()
        {
            return Ok(());
        }

        let password_hash = match password.as_deref() {
            Some(password) => Some(Self::hash_password_async(password).await?),
            None => None,
        };
        let parsed_balance = balance_nano_usd
            .as_deref()
            .map(parse_nano_usd)
            .transpose()?;
        if let Some(group_id) = group_id.as_deref()
            && self.get_group_by_id(group_id).await?.is_none()
        {
            return Err(format!("unknown group id: {group_id}"));
        }

        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;
        let current = self
            .lock_user_balance_tx(&tx, id)
            .await
            .map_err(|error| error.message)?;
        let new_balance = parsed_balance.unwrap_or(current.balance);
        let new_unlimited = balance_unlimited.unwrap_or(current.unlimited);
        let user_enabled = enabled.unwrap_or(current.enabled);
        let now = Utc::now().to_rfc3339();
        let mut set_clauses = Vec::new();
        let mut values: Vec<SeaValue> = Vec::new();
        let mut idx = 1usize;
        let mut plan_grant: Option<(i128, String, String)> = None;

        if let Some(username) = username {
            set_clauses.push(format!("username = ${idx}"));
            values.push(username.into());
            idx += 1;
        }
        if let Some(password_hash) = password_hash {
            set_clauses.push(format!("password_hash = ${idx}"));
            values.push(password_hash.into());
            idx += 1;
        }
        if let Some(role) = role {
            set_clauses.push(format!("role = ${idx}"));
            values.push(role.as_str().into());
            idx += 1;
        }
        if let Some(enabled) = enabled {
            set_clauses.push(format!("enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if enabled { 1 } else { 0 })));
            idx += 1;
        }
        if parsed_balance.is_some() {
            set_clauses.push(format!("balance_nano_usd = ${idx}"));
            values.push(new_balance.to_string().into());
            idx += 1;
        }
        if balance_unlimited.is_some() {
            set_clauses.push(format!("balance_unlimited = ${idx}"));
            values.push(SeaValue::Int(Some(if new_unlimited { 1 } else { 0 })));
            idx += 1;
        }
        if let Some(email) = email {
            match email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                Some(email) => {
                    set_clauses.push(format!("email = ${idx}"));
                    values.push(email.into());
                    idx += 1;
                }
                None => set_clauses.push("email = NULL".to_string()),
            }
        }
        if let Some(group_id) = group_id {
            set_clauses.push(format!("group_id = ${idx}"));
            values.push(group_id.into());
            idx += 1;
        }
        if let Some(plan_assignment) = billing_plan_id {
            match plan_assignment {
                Some(plan_id) => {
                    // Lock the plan row so assignment cannot race delete (BP-D3)
                    // and the anchor matches a surviving plan (BP-S1/BP-S3).
                    let plan_lock_sql = if self.db.is_postgres() {
                        "SELECT schedule, grant_amount_nano_usd, name, enabled FROM billing_plans WHERE id = $1 FOR UPDATE"
                    } else {
                        "SELECT schedule, grant_amount_nano_usd, name, enabled FROM billing_plans WHERE id = $1"
                    };
                    let plan_row = tx
                        .query_one(self.db.stmt(plan_lock_sql, vec![plan_id.clone().into()]))
                        .await
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| "billing plan not found".to_string())?;
                    let schedule: String = plan_row
                        .try_get("", "schedule")
                        .map_err(|e| e.to_string())?;
                    let raw_amount: String = plan_row
                        .try_get("", "grant_amount_nano_usd")
                        .map_err(|e| e.to_string())?;
                    let grant_amount = parse_nano_usd(&raw_amount)?;
                    let plan_name: String =
                        plan_row.try_get("", "name").map_err(|e| e.to_string())?;
                    let plan_enabled = plan_row
                        .try_get::<i32>("", "enabled")
                        .map_err(|e| e.to_string())?
                        == 1;
                    let assignment_now = Utc::now();
                    let anchor = super::plans::next_grant_after(&schedule, assignment_now)?;
                    set_clauses.push(format!("billing_plan_id = ${idx}"));
                    values.push(plan_id.clone().into());
                    idx += 1;
                    set_clauses.push(format!("next_grant_at = ${idx}"));
                    values.push(anchor.to_rfc3339().into());
                    idx += 1;
                    if parsed_balance.is_none() && user_enabled && !new_unlimited && plan_enabled {
                        set_clauses.push(format!("balance_nano_usd = ${idx}"));
                        values.push(grant_amount.to_string().into());
                        idx += 1;
                        plan_grant = Some((grant_amount, plan_id, plan_name));
                    }
                }
                None => {
                    set_clauses.push("billing_plan_id = NULL".to_string());
                    set_clauses.push("next_grant_at = NULL".to_string());
                }
            }
        }
        set_clauses.push(format!("updated_at = ${idx}"));
        values.push(now.clone().into());
        idx += 1;
        values.push(id.into());
        tx.execute(self.db.stmt(
            &format!(
                "UPDATE users SET {} WHERE id = ${idx}",
                set_clauses.join(", ")
            ),
            values,
        ))
        .await
        .map_err(|e| e.to_string())?;

        if revokes_sessions {
            self.delete_user_sessions_tx(&tx, id).await?;
        }

        if has_balance_change {
            let delta = new_balance
                .checked_sub(current.balance)
                .ok_or_else(|| "balance delta overflow".to_string())?;
            self.insert_billing_ledger_tx(
                &tx,
                id,
                "admin_adjustment",
                delta,
                Some(new_balance),
                &serde_json::json!({
                    "actor_user_id": actor_user_id,
                    "before_balance_nano_usd": current.balance.to_string(),
                    "after_balance_nano_usd": new_balance.to_string(),
                    "before_balance_unlimited": current.unlimited,
                    "after_balance_unlimited": new_unlimited,
                }),
                &now,
            )
            .await
            .map_err(|error| error.message)?;
        }
        if let Some((grant_amount, plan_id, plan_name)) = plan_grant.as_ref() {
            let delta = grant_amount
                .checked_sub(current.balance)
                .ok_or_else(|| "balance overflow".to_string())?;
            self.insert_billing_ledger_tx(
                &tx,
                id,
                "plan_grant",
                delta,
                Some(*grant_amount),
                &serde_json::json!({
                    "plan_id": plan_id,
                    "plan_name": plan_name,
                    "before_balance_nano_usd": current.balance.to_string(),
                    "after_balance_nano_usd": grant_amount.to_string(),
                }),
                &now,
            )
            .await
            .map_err(|error| error.message)?;
        }

        tx.commit().await.map_err(|e| e.to_string())?;
        self.api_key_cache.invalidate_by_user_id(id);
        if has_balance_change || plan_grant.is_some() {
            self.balance_cache.invalidate(id);
        }
        if has_plan_change {
            // Cached auth results embed the plan's group restriction layer.
            self.api_key_cache.invalidate_by_user_id(id);
        }
        Ok(())
    }

    pub async fn delete_user(&self, id: &str) -> Result<(), String> {
        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;
        let user_lock_sql = if self.db.is_postgres() {
            "SELECT id FROM users WHERE id = $1 FOR UPDATE"
        } else {
            "SELECT id FROM users WHERE id = $1"
        };
        let user = tx
            .query_one(self.db.stmt(user_lock_sql, vec![id.into()]))
            .await
            .map_err(|e| e.to_string())?;
        if user.is_none() {
            return Err("user not found".to_string());
        }
        let result = tx
            .execute(
                self.db
                    .stmt("DELETE FROM users WHERE id = $1", vec![id.into()]),
            )
            .await
            .map_err(|e| e.to_string())?;
        if result.rows_affected() != 1 {
            return Err("user not found".to_string());
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        self.api_key_cache.invalidate_by_user_id(id);
        self.balance_cache.invalidate(id);
        Ok(())
    }

    pub async fn update_last_login(&self, id: &str) -> Result<(), String> {
        let now = Utc::now();
        self.db
            .write()
            .await
            .execute(self.db.stmt(
                "UPDATE users SET last_login_at = $1 WHERE id = $2",
                vec![now.to_rfc3339().into(), id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        self.api_key_cache.invalidate_by_user_id(id);
        Ok(())
    }

    pub(crate) fn row_to_user(&self, row: &QueryResult) -> Result<User, String> {
        let role_str: String = row.try_get("", "role").map_err(|e| e.to_string())?;
        let role = UserRole::from_str(&role_str).ok_or_else(|| "invalid role".to_string())?;

        let last_login_at: Option<String> = row
            .try_get("", "last_login_at")
            .map_err(|e| e.to_string())?;
        let last_login_at = last_login_at
            .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
            .transpose()
            .map_err(|e| e.to_string())?;
        let group_id: String = row
            .try_get("", "group_id")
            .map_err(|error| format!("invalid persisted users.group_id: {error}"))?;
        let billing_plan_id: Option<String> = row
            .try_get("", "billing_plan_id")
            .map_err(|e| e.to_string())?;
        let next_grant_at: Option<String> = row
            .try_get("", "next_grant_at")
            .map_err(|e| e.to_string())?;
        let next_grant_at = next_grant_at
            .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
            .transpose()
            .map_err(|e| e.to_string())?;
        if billing_plan_id.is_some() != next_grant_at.is_some() {
            return Err(
                "invalid persisted user: billing_plan_id and next_grant_at must be set together"
                    .to_string(),
            );
        }
        let balance_nano_usd: String = row
            .try_get("", "balance_nano_usd")
            .map_err(|e| e.to_string())?;
        parse_nano_usd(&balance_nano_usd)
            .map_err(|e| format!("invalid persisted user balance: {e}"))?;

        Ok(User {
            id: row.try_get("", "id").map_err(|e| e.to_string())?,
            username: row.try_get("", "username").map_err(|e| e.to_string())?,
            password_hash: row
                .try_get("", "password_hash")
                .map_err(|e| e.to_string())?,
            role,
            created_at: DateTime::parse_from_rfc3339(
                &row.try_get::<String>("", "created_at")
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(
                &row.try_get::<String>("", "updated_at")
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc),
            last_login_at,
            enabled: decode_required_bool(row, "enabled")?,
            balance_nano_usd,
            balance_unlimited: row
                .try_get::<i32>("", "balance_unlimited")
                .map_err(|e| e.to_string())?
                == 1,
            email: row
                .try_get::<Option<String>>("", "email")
                .map_err(|e| e.to_string())?,
            group_id,
            billing_plan_id,
            next_grant_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::DbPool;
    use crate::migration::Migrator;
    
    use crate::users::{
        AdminUpdateUserInput,
        RegisterUserError, UserRole, UserStore,
    };
    
    use sea_orm::ConnectionTrait;
    use sea_orm_migration::MigratorTrait;
    

    #[tokio::test]
    async fn update_last_login_invalidates_cached_user_for_api_keys() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("last-login-cache", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (_, token) = store
            .create_api_key(&user.id, "cached-key", None)
            .await
            .expect("key creates");

        let (_, cached_user, _) = store
            .validate_api_key(&token)
            .await
            .expect("initial validation succeeds")
            .expect("key is valid");
        assert!(cached_user.last_login_at.is_none());
        assert!(store.api_key_cache.get(&token).is_some());

        store
            .update_last_login(&user.id)
            .await
            .expect("last login updates");
        assert!(store.api_key_cache.get(&token).is_none());
        let (_, refreshed_user, _) = store
            .validate_api_key(&token)
            .await
            .expect("refreshed validation succeeds")
            .expect("key remains valid");
        assert!(refreshed_user.last_login_at.is_some());
    }

    #[tokio::test]
    async fn delete_user_uses_reverse_invalidation_without_returning_key_ids() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("delete-cache", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let mut tokens = Vec::new();
        for name in ["first", "second", "third"] {
            let (_, token) = store
                .create_api_key(&user.id, name, None)
                .await
                .expect("key creates");
            store
                .validate_api_key(&token)
                .await
                .expect("key validates")
                .expect("key exists");
            tokens.push(token);
        }
        store
            .get_user_balance(&user.id)
            .await
            .expect("balance reads")
            .expect("balance exists");
        assert!(
            tokens
                .iter()
                .all(|token| store.api_key_cache.get(token).is_some())
        );
        assert!(store.balance_cache.get(&user.id).is_some());

        store.delete_user(&user.id).await.expect("user deletes");

        assert!(
            tokens
                .iter()
                .all(|token| store.api_key_cache.get(token).is_none())
        );
        assert!(store.balance_cache.get(&user.id).is_none());
        assert!(store.get_user_by_id(&user.id).await.unwrap().is_none());
        assert!(store.delete_user(&user.id).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_registration_creates_exactly_one_first_super_admin() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for username in ["first-racer", "second-racer"] {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .register_user_atomic(username, "password123", false)
                    .await
            }));
        }

        let mut users = Vec::new();
        let mut disabled = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(user) => users.push(user),
                Err(RegisterUserError::RegistrationDisabled) => disabled += 1,
                Err(error) => panic!("unexpected registration result: {error:?}"),
            }
        }
        assert_eq!(users.len(), 1);
        assert_eq!(disabled, 1);
        assert_eq!(users[0].role, UserRole::SuperAdmin);
        assert_eq!(store.user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn admin_user_update_rolls_back_ordinary_fields_when_ledger_insert_fails() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("atomic-before", "password123", UserRole::User, None)
            .await
            .unwrap();
        let session = store.create_session(&user.id, 7).await.unwrap();
        db.write()
            .await
            .execute(db.stmt(
                "CREATE TRIGGER fail_admin_adjustment
                 BEFORE INSERT ON billing_ledger
                 WHEN NEW.kind = 'admin_adjustment'
                 BEGIN SELECT RAISE(FAIL, 'ledger blocked'); END",
                vec![],
            ))
            .await
            .unwrap();

        let result = store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    username: Some("atomic-after".to_string()),
                    password: Some("new-password123".to_string()),
                    balance_nano_usd: Some("50".to_string()),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await;
        assert!(result.is_err());

        let unchanged = store.get_user_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(unchanged.username, "atomic-before");
        assert_eq!(unchanged.balance_nano_usd, "0");
        assert!(
            UserStore::verify_password_async("password123", &unchanged.password_hash)
                .await
                .unwrap()
        );
        assert!(
            store
                .get_session_by_token(&session.token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn user_security_mutations_revoke_existing_sessions() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("session-revocation", "password123", UserRole::User, None)
            .await
            .unwrap();

        let password_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                Some("password456"),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&password_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let role_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                None,
                Some(UserRole::Admin),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&role_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let disabled_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                None,
                None,
                Some(false),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&disabled_session.token)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn atomic_admin_security_mutations_revoke_existing_sessions() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("admin-revocation", "password123", UserRole::User, None)
            .await
            .unwrap();

        let password_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    password: Some("password456".to_string()),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&password_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let role_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    role: Some(UserRole::Admin),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&role_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let disabled_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    enabled: Some(false),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&disabled_session.token)
                .await
                .unwrap()
                .is_none()
        );
    }
}
