use super::helpers::*;
use crate::users::utils::parse_nano_usd;
use crate::users::{
    ApiKey, ModelRedirectRule,
    User, UserRole, UserStore, compile_model_redirects,
};
use crate::transforms::TransformRuleConfig;
use chrono::{DateTime, Utc};
use sea_orm::QueryResult;

impl UserStore {
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

    pub(crate) async fn row_to_api_key(&self, row: &QueryResult) -> Result<ApiKey, String> {
        let expires_at: Option<String> =
            row.try_get("", "expires_at").map_err(|e| e.to_string())?;
        let expires_at = expires_at
            .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
            .transpose()
            .map_err(|e| e.to_string())?;

        let last_used_at: Option<String> =
            row.try_get("", "last_used_at").map_err(|e| e.to_string())?;
        let last_used_at = last_used_at
            .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
            .transpose()
            .map_err(|e| e.to_string())?;

        let sub_account_enabled = decode_required_bool(row, "sub_account_enabled")?;
        let sub_account_balance_nano: String = row
            .try_get("", "sub_account_balance_nano")
            .map_err(|e| e.to_string())?;
        parse_nano_usd(&sub_account_balance_nano)
            .map_err(|e| format!("invalid persisted sub-account balance: {e}"))?;
        let model_limits_enabled = decode_required_bool(row, "model_limits_enabled")?;

        let model_limits_str: String = row
            .try_get("", "model_limits")
            .map_err(|error| format!("invalid persisted model_limits: {error}"))?;
        let model_limits = parse_persisted_json_array(&model_limits_str, "model_limits")?;

        let ip_whitelist_str: String = row
            .try_get("", "ip_whitelist")
            .map_err(|error| format!("invalid persisted ip_whitelist: {error}"))?;
        let ip_whitelist: Vec<String> =
            parse_persisted_json_array(&ip_whitelist_str, "ip_whitelist")?;
        let ip_whitelist = canonicalize_ip_whitelist(&ip_whitelist)
            .map_err(|error| format!("invalid persisted ip_whitelist: {error}"))?;
        let use_user_group = decode_required_bool(row, "use_user_group")?;
        let group_ids_raw = row
            .try_get::<Option<String>>("", "group_ids")
            .map_err(|error| format!("invalid persisted api_keys.group_ids: {error}"))?;
        let group_ids = parse_group_ids_json(group_ids_raw.as_deref(), "api_keys.group_ids")?;

        let max_multiplier = row
            .try_get::<Option<String>>("", "max_multiplier")
            .map_err(|e| e.to_string())?
            .map(|value| value.parse())
            .transpose()
            .map_err(|e: String| format!("invalid persisted max_multiplier: {e}"))?;
        let transforms_str: String = row
            .try_get("", "transforms")
            .map_err(|error| format!("invalid persisted transforms: {error}"))?;
        let model_redirects_str: String = row
            .try_get("", "model_redirects")
            .map_err(|error| format!("invalid persisted model_redirects: {error}"))?;
        let user_id: String = row.try_get("", "user_id").map_err(|e| e.to_string())?;
        let owner_role = row
            .try_get::<String>("", "owner_role")
            .map_err(|error| format!("invalid persisted owner_role: {error}"))?;
        let is_admin = UserRole::from_str(&owner_role)
            .ok_or_else(|| format!("invalid persisted owner_role: {owner_role:?}"))?
            .can_manage_system();
        let transforms = parse_persisted_json_array(&transforms_str, "transforms")?;
        let transforms: Vec<TransformRuleConfig> =
            sanitize_api_key_transforms(transforms, is_admin, &self.custom_transforms.get());
        let model_redirects: Vec<ModelRedirectRule> =
            parse_persisted_json_array(&model_redirects_str, "model_redirects")?;
        let compiled_model_redirects = compile_model_redirects(&model_redirects)
            .map_err(|error| format!("invalid persisted model_redirects: {error}"))?;
        let reasoning_envelope_enabled = decode_required_bool(row, "reasoning_envelope_enabled")?;
        let request_capture_mode = decode_request_capture_mode(row)?;
        let request_capture_retention = decode_request_capture_retention(row)?;

        Ok(ApiKey {
            id: row.try_get("", "id").map_err(|e| e.to_string())?,
            user_id,
            name: row.try_get("", "name").map_err(|e| e.to_string())?,
            key_prefix: row.try_get("", "key_prefix").map_err(|e| e.to_string())?,
            key: row.try_get("", "key").map_err(|e| e.to_string())?,
            created_at: DateTime::parse_from_rfc3339(
                &row.try_get::<String>("", "created_at")
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc),
            expires_at,
            last_used_at,
            enabled: decode_required_bool(row, "enabled")?,
            sub_account_enabled,
            sub_account_balance_nano,
            model_limits_enabled,
            model_limits,
            ip_whitelist,
            use_user_group,
            group_ids,
            max_multiplier,
            transforms,
            model_redirects,
            compiled_model_redirects,
            reasoning_envelope_enabled,
            request_capture_mode,
            request_capture_retention,
        })
    }

}
