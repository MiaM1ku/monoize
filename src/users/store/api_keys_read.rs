use super::helpers::*;
use crate::users::utils::parse_nano_usd;
use crate::users::{
    ApiKey,
    User, UserRole, UserStore,
};
use chrono::{DateTime, Utc};
use sea_orm::Value as SeaValue;
use sea_orm::ConnectionTrait;

impl UserStore {
    pub async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, String> {
        let row = self.db.read()
            .query_one(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key, a.created_at, a.expires_at, a.last_used_at, a.enabled, a.sub_account_enabled, a.sub_account_balance_nano, a.model_limits_enabled, a.model_limits, a.ip_whitelist, a.use_user_group, a.group_ids, a.max_multiplier, a.transforms, a.model_redirects, a.reasoning_envelope_enabled, a.request_capture_enabled, a.request_capture_mode, a.request_capture_retention, u.role AS owner_role FROM api_keys a JOIN users u ON u.id = a.user_id WHERE a.key_prefix = $1",
                vec![prefix.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row {
            Ok(Some(self.row_to_api_key(&row).await?))
        } else {
            Ok(None)
        }
    }

    pub async fn get_api_key_by_key(&self, key: &str) -> Result<Option<ApiKey>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key, a.created_at, a.expires_at, a.last_used_at, a.enabled, a.sub_account_enabled, a.sub_account_balance_nano, a.model_limits_enabled, a.model_limits, a.ip_whitelist, a.use_user_group, a.group_ids, a.max_multiplier, a.transforms, a.model_redirects, a.reasoning_envelope_enabled, a.request_capture_enabled, a.request_capture_mode, a.request_capture_retention, u.role AS owner_role FROM api_keys a JOIN users u ON u.id = a.user_id WHERE a.key = $1",
                vec![key.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        match row {
            Some(row) => Ok(Some(self.row_to_api_key(&row).await?)),
            None => Ok(None),
        }
    }

    pub(super) async fn get_api_key_auth_candidate(
        &self,
        key: &str,
    ) -> Result<Option<(ApiKey, User, Option<Vec<String>>)>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key,
                        a.created_at, a.expires_at, a.last_used_at, a.enabled,
                        a.sub_account_enabled, a.sub_account_balance_nano,
                        a.model_limits_enabled, a.model_limits, a.ip_whitelist,
                        a.use_user_group, a.group_ids, a.max_multiplier, a.transforms,
                        a.model_redirects, a.reasoning_envelope_enabled,
                        a.request_capture_enabled, a.request_capture_mode,
                        a.request_capture_retention,
                        u.role AS owner_role,
                        u.id AS owner_id, u.username AS owner_username,
                        u.password_hash AS owner_password_hash,
                        u.created_at AS owner_created_at, u.updated_at AS owner_updated_at,
                        u.last_login_at AS owner_last_login_at, u.enabled AS owner_enabled,
                        u.balance_nano_usd AS owner_balance_nano_usd,
                        u.balance_unlimited AS owner_balance_unlimited,
                        u.email AS owner_email, u.group_id AS owner_group_id,
                        u.billing_plan_id AS owner_billing_plan_id,
                        u.next_grant_at AS owner_next_grant_at,
                        p.group_ids AS plan_group_ids
                  FROM api_keys a
                  JOIN users u ON u.id = a.user_id
                  LEFT JOIN billing_plans p ON p.id = u.billing_plan_id AND p.enabled = 1
                  WHERE a.key = $1
                  LIMIT 1",
                vec![key.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let api_key = self.row_to_api_key(&row).await?;
        let role_raw: String = row.try_get("", "owner_role").map_err(|e| e.to_string())?;
        let role = UserRole::from_str(&role_raw).ok_or_else(|| "invalid role".to_string())?;
        let parse_time = |column: &str| -> Result<DateTime<Utc>, String> {
            DateTime::parse_from_rfc3339(
                &row.try_get::<String>("", column)
                    .map_err(|e| e.to_string())?,
            )
            .map(|value| value.with_timezone(&Utc))
            .map_err(|e| e.to_string())
        };
        let last_login_at = row
            .try_get::<Option<String>>("", "owner_last_login_at")
            .map_err(|e| e.to_string())?
            .map(|value| DateTime::parse_from_rfc3339(&value).map(|v| v.with_timezone(&Utc)))
            .transpose()
            .map_err(|e| e.to_string())?;
        let balance_nano_usd: String = row
            .try_get("", "owner_balance_nano_usd")
            .map_err(|e| e.to_string())?;
        parse_nano_usd(&balance_nano_usd)
            .map_err(|e| format!("invalid persisted user balance: {e}"))?;
        let owner_enabled = decode_required_bool(&row, "owner_enabled")?;
        let owner_group_id: String = row
            .try_get("", "owner_group_id")
            .map_err(|error| format!("invalid persisted users.group_id: {error}"))?;
        let user = User {
            id: row.try_get("", "owner_id").map_err(|e| e.to_string())?,
            username: row
                .try_get("", "owner_username")
                .map_err(|e| e.to_string())?,
            password_hash: row
                .try_get("", "owner_password_hash")
                .map_err(|e| e.to_string())?,
            role,
            created_at: parse_time("owner_created_at")?,
            updated_at: parse_time("owner_updated_at")?,
            last_login_at,
            enabled: owner_enabled,
            balance_nano_usd,
            balance_unlimited: row
                .try_get::<i32>("", "owner_balance_unlimited")
                .map_err(|e| e.to_string())?
                == 1,
            email: row
                .try_get::<Option<String>>("", "owner_email")
                .map_err(|e| e.to_string())?,
            group_id: owner_group_id,
            billing_plan_id: row
                .try_get::<Option<String>>("", "owner_billing_plan_id")
                .map_err(|e| e.to_string())?,
            next_grant_at: row
                .try_get::<Option<String>>("", "owner_next_grant_at")
                .map_err(|e| e.to_string())?
                .map(|value| DateTime::parse_from_rfc3339(&value).map(|v| v.with_timezone(&Utc)))
                .transpose()
                .map_err(|e| e.to_string())?,
        };
        // A disabled or missing plan contributes no restriction (BP-R2).
        let plan_group_ids = row
            .try_get::<Option<String>>("", "plan_group_ids")
            .map_err(|e| e.to_string())?
            .map(|raw| parse_group_ids_json(Some(raw.as_str()), "billing_plans.group_ids"))
            .transpose()?;
        Ok(Some((api_key, user, plan_group_ids)))
    }

    pub async fn list_user_api_keys(&self, user_id: &str) -> Result<Vec<ApiKey>, String> {
        let rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key, a.created_at,
                        a.expires_at, a.last_used_at, a.enabled, a.sub_account_enabled,
                        a.sub_account_balance_nano, a.model_limits_enabled, a.model_limits,
                        a.ip_whitelist, a.use_user_group, a.group_ids, a.max_multiplier,
                        a.transforms, a.model_redirects, a.reasoning_envelope_enabled,
                        a.request_capture_enabled, a.request_capture_mode, a.request_capture_retention, u.role AS owner_role
                 FROM api_keys a JOIN users u ON u.id = a.user_id
                 WHERE a.user_id = $1 ORDER BY a.created_at DESC",
                vec![user_id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        let mut api_keys = Vec::with_capacity(rows.len());
        for row in &rows {
            api_keys.push(self.row_to_api_key(row).await?);
        }
        Ok(api_keys)
    }

    pub async fn count_user_api_keys(&self, user_id: &str) -> Result<i64, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT COUNT(*) AS cnt FROM api_keys WHERE user_id = $1",
                vec![user_id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "count query returned no row".to_string())?;
        row.try_get("", "cnt").map_err(|e| e.to_string())
    }

    pub async fn get_api_key_for_user(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<ApiKey>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key, a.created_at,
                        a.expires_at, a.last_used_at, a.enabled, a.sub_account_enabled,
                        a.sub_account_balance_nano, a.model_limits_enabled, a.model_limits,
                        a.ip_whitelist, a.use_user_group, a.group_ids, a.max_multiplier,
                        a.transforms, a.model_redirects, a.reasoning_envelope_enabled,
                        a.request_capture_enabled, a.request_capture_mode, a.request_capture_retention, u.role AS owner_role
                 FROM api_keys a JOIN users u ON u.id = a.user_id
                 WHERE a.id = $1 AND a.user_id = $2",
                vec![id.into(), user_id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        match row {
            Some(row) => Ok(Some(self.row_to_api_key(&row).await?)),
            None => Ok(None),
        }
    }

    pub async fn filter_user_api_key_ids(
        &self,
        user_id: &str,
        ids: &[String],
    ) -> Result<Vec<String>, String> {
        if ids.len() > api_key_batch_delete_max_ids() {
            return Err(format!(
                "batch delete accepts at most {} ids",
                api_key_batch_delete_max_ids()
            ));
        }
        let mut ids = ids.to_vec();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = (0..ids.len())
            .map(|index| format!("${}", index + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let mut values: Vec<SeaValue> = Vec::with_capacity(ids.len() + 1);
        values.push(user_id.into());
        values.extend(ids.iter().cloned().map(Into::into));
        let rows = self
            .db
            .read()
            .query_all(self.db.stmt(
                &format!(
                    "SELECT id FROM api_keys WHERE user_id = $1 AND id IN ({placeholders}) ORDER BY id"
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        rows.into_iter()
            .map(|row| row.try_get("", "id").map_err(|e| e.to_string()))
            .collect()
    }

    pub async fn update_api_key_last_used(&self, id: &str) -> Result<(), String> {
        let now = Utc::now();
        self.db
            .write()
            .await
            .execute(self.db.stmt(
                "UPDATE api_keys SET last_used_at = $1 WHERE id = $2",
                vec![now.to_rfc3339().into(), id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn validate_api_key(
        &self,
        key: &str,
    ) -> Result<Option<(ApiKey, User, Option<Vec<String>>)>, String> {
        if key.len() < 12 || key.len() > MAX_FORWARDING_API_KEY_BYTES {
            return Ok(None);
        }

        loop {
            if let Some((cached_key, cached_user, cached_plan_groups)) = self.api_key_cache.get(key)
            {
                let now = Utc::now();
                let not_expired = cached_key
                    .expires_at
                    .is_none_or(|expires_at| expires_at >= now);
                let is_valid = cached_key.enabled
                    && cached_user.enabled
                    && not_expired
                    && key == cached_key.key;
                if is_valid {
                    self.last_used_batcher.record(cached_key.id.clone(), now);
                    return Ok(Some((cached_key, cached_user, cached_plan_groups)));
                }

                self.api_key_cache.invalidate(key);
            }

            let generation = self.api_key_cache.current_generation();
            let (api_key, user, plan_allowed_groups) =
                match self.get_api_key_auth_candidate(key).await? {
                    Some(candidate) => candidate,
                    None => return Ok(None),
                };

            if !api_key.enabled {
                return Ok(None);
            }

            if let Some(expires_at) = api_key.expires_at
                && expires_at < Utc::now()
            {
                return Ok(None);
            }

            if key != api_key.key {
                return Ok(None);
            }

            if !user.enabled {
                return Ok(None);
            }

            if !self.api_key_cache.insert_if_current(
                key.to_string(),
                generation,
                api_key.clone(),
                user.clone(),
                plan_allowed_groups.clone(),
            ) {
                continue;
            }

            self.last_used_batcher
                .record(api_key.id.clone(), Utc::now());

            return Ok(Some((api_key, user, plan_allowed_groups)));
        }
    }

    /// Get API key by ID
    pub async fn get_api_key_by_id(&self, id: &str) -> Result<Option<ApiKey>, String> {
        let row = self.db.read()
            .query_one(self.db.stmt(
                "SELECT a.id, a.user_id, a.name, a.key_prefix, a.key, a.created_at, a.expires_at, a.last_used_at, a.enabled, a.sub_account_enabled, a.sub_account_balance_nano, a.model_limits_enabled, a.model_limits, a.ip_whitelist, a.use_user_group, a.group_ids, a.max_multiplier, a.transforms, a.model_redirects, a.reasoning_envelope_enabled, a.request_capture_enabled, a.request_capture_mode, a.request_capture_retention, u.role AS owner_role FROM api_keys a JOIN users u ON u.id = a.user_id WHERE a.id = $1",
                vec![id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row {
            Ok(Some(self.row_to_api_key(&row).await?))
        } else {
            Ok(None)
        }
    }

}
