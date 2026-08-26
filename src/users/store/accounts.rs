use super::helpers::*;
use crate::users::utils::parse_nano_usd;
use crate::users::{
    AdminUpdateUserInput,
    RegisterUserError, Session,
    User, UserRole, UserStore,
};
use chrono::{DateTime, Utc};
use sea_orm::Value as SeaValue;
use sea_orm::{ConnectionTrait, DatabaseTransaction, TransactionTrait};

impl UserStore {
    /// TM-GRP-3/TM-GRP-5 validation for an already canonicalized group-id list:
    /// bounded length, every id registered, and non-admin callers limited to
    /// `user_selectable` groups plus the owner's own current group.
    pub(crate) async fn validate_api_key_group_selection(
        &self,
        owner_group_id: &str,
        group_ids: &[String],
        is_admin: bool,
    ) -> Result<(), String> {
        if group_ids.len() > MAX_GROUP_IDS {
            return Err(format!("at most {MAX_GROUP_IDS} groups can be selected"));
        }
        for id in group_ids {
            let group = self
                .get_group_by_id(id)
                .await?
                .ok_or_else(|| format!("unknown group id: {id}"))?;
            if !is_admin && !group.user_selectable && id != owner_group_id {
                return Err(format!("group is not selectable: {}", group.name));
            }
        }
        Ok(())
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
                    let anchor = crate::users::plans::next_grant_after(&schedule, assignment_now)?;
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

    pub async fn create_session(
        &self,
        user_id: &str,
        session_ttl_days: i64,
    ) -> Result<Session, String> {
        let id = uuid::Uuid::new_v4().to_string();
        let token = format!(
            "urp_session_{}",
            uuid::Uuid::new_v4().to_string().replace("-", "")
        );
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(session_ttl_days);

        self.db
            .write()
            .await
            .execute(self.db.stmt(
                r#"INSERT INTO sessions (id, user_id, token, created_at, expires_at)
                   VALUES ($1, $2, $3, $4, $5)"#,
                vec![
                    id.clone().into(),
                    user_id.into(),
                    token.clone().into(),
                    now.to_rfc3339().into(),
                    expires_at.to_rfc3339().into(),
                ],
            ))
            .await
            .map_err(|e| e.to_string())?;

        Ok(Session {
            id,
            user_id: user_id.to_string(),
            token,
            created_at: now,
            expires_at,
        })
    }

    pub async fn change_password_and_rotate_session(
        &self,
        user_id: &str,
        expected_password_hash: &str,
        new_password: &str,
        session_ttl_days: i64,
    ) -> Result<Session, String> {
        let password_hash = Self::hash_password_async(new_password).await?;
        let now = Utc::now();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            token: format!(
                "urp_session_{}",
                uuid::Uuid::new_v4().to_string().replace('-', "")
            ),
            created_at: now,
            expires_at: now + chrono::Duration::days(session_ttl_days),
        };

        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;
        let lock_sql = if self.db.is_postgres() {
            "SELECT password_hash FROM users WHERE id = $1 FOR UPDATE"
        } else {
            "SELECT password_hash FROM users WHERE id = $1"
        };
        let row = tx
            .query_one(self.db.stmt(lock_sql, vec![user_id.into()]))
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "user not found".to_string())?;
        let current_password_hash: String = row
            .try_get("", "password_hash")
            .map_err(|e| e.to_string())?;
        if current_password_hash != expected_password_hash {
            return Err("password changed concurrently".to_string());
        }

        tx.execute(self.db.stmt(
            "UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
            vec![
                password_hash.into(),
                session.created_at.to_rfc3339().into(),
                user_id.into(),
            ],
        ))
        .await
        .map_err(|e| e.to_string())?;
        self.delete_user_sessions_tx(&tx, user_id).await?;
        tx.execute(self.db.stmt(
            r#"INSERT INTO sessions (id, user_id, token, created_at, expires_at)
               VALUES ($1, $2, $3, $4, $5)"#,
            vec![
                session.id.clone().into(),
                session.user_id.clone().into(),
                session.token.clone().into(),
                session.created_at.to_rfc3339().into(),
                session.expires_at.to_rfc3339().into(),
            ],
        ))
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;

        self.api_key_cache.invalidate_by_user_id(user_id);
        Ok(session)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
        let result = self
            .db
            .write()
            .await
            .execute(self.db.stmt(
                "DELETE FROM sessions WHERE expires_at <= $1",
                vec![Utc::now().to_rfc3339().into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        Ok(result.rows_affected())
    }

    pub async fn get_session_by_token(&self, token: &str) -> Result<Option<Session>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT id, user_id, token, created_at, expires_at FROM sessions WHERE token = $1",
                vec![token.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row {
            let expires_at: String = row.try_get("", "expires_at").map_err(|e| e.to_string())?;
            let expires_at = DateTime::parse_from_rfc3339(&expires_at)
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc);

            if expires_at < Utc::now() {
                self.delete_session(token).await?;
                return Ok(None);
            }

            Ok(Some(Session {
                id: row.try_get("", "id").map_err(|e| e.to_string())?,
                user_id: row.try_get("", "user_id").map_err(|e| e.to_string())?,
                token: row.try_get("", "token").map_err(|e| e.to_string())?,
                created_at: DateTime::parse_from_rfc3339(
                    &row.try_get::<String>("", "created_at")
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?
                .with_timezone(&Utc),
                expires_at,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), String> {
        self.db
            .write()
            .await
            .execute(
                self.db
                    .stmt("DELETE FROM sessions WHERE token = $1", vec![token.into()]),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub(super) async fn delete_user_sessions_tx(
        &self,
        tx: &DatabaseTransaction,
        user_id: &str,
    ) -> Result<(), String> {
        tx.execute(self.db.stmt(
            "DELETE FROM sessions WHERE user_id = $1",
            vec![user_id.into()],
        ))
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

}
