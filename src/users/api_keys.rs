//! API-key lifecycle for `UserStore`: creation, lookup, authentication-candidate
//! resolution, updates, and transactional deletion with sub-account settlement.

use super::utils::parse_nano_usd;
use super::{
    ApiKey, CreateApiKeyInput,
    CreateApiKeyWithLimitError, ModelRedirectRule, RequestCaptureMode, RequestCaptureRetention, UpdateApiKeyInput,
    User, UserRole, UserStore, canonicalize_group_ids, compile_model_redirects,
    validate_model_redirects,
};
use crate::transforms::{
    TransformRuleConfig, canonical_transform_id, canonicalize_transform_rule,
    canonicalize_transform_rules,
};
use chrono::{DateTime, Utc};
use sea_orm::Value as SeaValue;
use sea_orm::{ConnectionTrait, QueryResult, TransactionTrait};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::OnceLock;
use super::balance::{LockedApiKeyBalance, LockedUserBalance};
use super::store::{MAX_GROUP_IDS, decode_required_bool, parse_group_ids_json, serialize_group_ids_json};

const MAX_FORWARDING_API_KEY_BYTES: usize = 512;
const DEFAULT_API_KEY_BATCH_DELETE_MAX_IDS: usize = 400;

fn parse_api_key_batch_delete_limit(raw: Option<&str>) -> usize {
    crate::env_limits::parse_positive(raw, DEFAULT_API_KEY_BATCH_DELETE_MAX_IDS)
        .min(DEFAULT_API_KEY_BATCH_DELETE_MAX_IDS)
}

fn api_key_batch_delete_max_ids() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_api_key_batch_delete_limit(
            std::env::var("MONOIZE_API_KEY_BATCH_DELETE_MAX_IDS")
                .ok()
                .as_deref(),
        )
    })
}

fn canonicalize_ip_whitelist(entries: &[String]) -> Result<Vec<String>, String> {
    let mut canonical = BTreeSet::new();
    for entry in entries {
        let value = entry.trim();
        if value.is_empty() {
            return Err("ip_whitelist entries must not be empty".to_string());
        }
        let normalized = if let Ok(ip) = value.parse::<IpAddr>() {
            ip.to_string()
        } else if let Ok(network) = value.parse::<ipnet::IpNet>() {
            network.to_string()
        } else {
            return Err(format!("invalid ip_whitelist entry: {value}"));
        };
        canonical.insert(normalized);
    }
    Ok(canonical.into_iter().collect())
}

const ALLOWED_API_KEY_REQUEST_TRANSFORMS: &[&str] = &[
    "prompt_inject_system",
    "role_system_to_developer",
    "role_merge_consecutive",
    "prompt_append_empty_user",
    "image_compress_input",
    "image_enable_openai_generation_tool",
    "prompt_strip_anthropic_billing_header",
    "cache_anthropic_system",
    "cache_anthropic_tool_use",
    "cache_openai_tool_use",
    "cache_user_id",
    "cache_openai_prompt",
];

const ALLOWED_API_KEY_RESPONSE_TRANSFORMS: &[&str] = &[
    "reasoning_strip_output",
    "reasoning_strip_encrypted",
    "reasoning_to_think_xml",
    "reasoning_from_think_xml",
    "stream_split_sse_frames",
    "reasoning_content_to_summary",
    "reasoning_inject_content_field",
    "reasoning_summary_to_raw_cot",
    "image_markdown_to_output",
    "image_output_to_markdown",
    "image_compress_output",
];

pub(crate) fn is_allowed_api_key_transform(
    rule: &TransformRuleConfig,
    custom: &crate::custom_transforms::CustomTransformSnapshot,
) -> bool {
    let transform = canonical_transform_id(rule.transform.as_str());
    // CJS-AKV-2: a `js:` rule is allowed only when it resolves in the enabled
    // snapshot to a user-visible transform whose scopes include api_key and
    // whose declared phases include the rule phase.
    if transform.starts_with(crate::transforms::CUSTOM_TRANSFORM_ID_PREFIX) {
        return custom.get(transform).is_some_and(|entry| {
            entry.visibility == crate::custom_transforms::CustomTransformVisibility::User
                && entry
                    .scopes
                    .contains(&crate::transforms::TransformScope::ApiKey)
                && entry.phases.contains(&rule.phase)
        });
    }
    match rule.phase {
        crate::transforms::Phase::Request => {
            ALLOWED_API_KEY_REQUEST_TRANSFORMS.contains(&transform)
        }
        crate::transforms::Phase::Response => {
            ALLOWED_API_KEY_RESPONSE_TRANSFORMS.contains(&transform)
        }
    }
}

pub(crate) fn sanitize_api_key_transforms(
    transforms: Vec<TransformRuleConfig>,
    is_admin: bool,
    custom: &crate::custom_transforms::CustomTransformSnapshot,
) -> Vec<TransformRuleConfig> {
    let transforms: Vec<TransformRuleConfig> = transforms
        .into_iter()
        .map(|mut rule| {
            canonicalize_transform_rule(&mut rule);
            rule
        })
        .collect();
    if is_admin {
        return transforms;
    }
    transforms
        .into_iter()
        .filter(|rule| is_allowed_api_key_transform(rule, custom))
        .collect()
}

pub(crate) fn validate_api_key_transforms(
    transforms: &[TransformRuleConfig],
    is_admin: bool,
    custom: &crate::custom_transforms::CustomTransformSnapshot,
) -> Result<(), String> {
    if is_admin {
        return Ok(());
    }
    for rule in transforms {
        let mut canonical_rule = rule.clone();
        canonicalize_transform_rule(&mut canonical_rule);
        if !is_allowed_api_key_transform(&canonical_rule, custom) {
            return Err(format!(
                "transform '{}' is not allowed for API keys",
                rule.transform
            ));
        }
    }
    Ok(())
}

fn parse_persisted_json_array<T>(raw: &str, column: &str) -> Result<Vec<T>, String>
where
    T: DeserializeOwned,
{
    serde_json::from_str(raw).map_err(|error| format!("invalid persisted {column}: {error}"))
}

fn decode_request_capture_mode(row: &QueryResult) -> Result<RequestCaptureMode, String> {
    let raw = row
        .try_get::<Option<String>>("", "request_capture_mode")
        .map_err(|error| format!("invalid persisted request_capture_mode: {error}"))?;
    match raw.as_deref().map(str::trim) {
        None => Ok(RequestCaptureMode::Off),
        Some("off") => Ok(RequestCaptureMode::Off),
        Some("capture-all") => Ok(RequestCaptureMode::CaptureAll),
        Some("capture-only-abnormal") => Ok(RequestCaptureMode::CaptureOnlyAbnormal),
        Some(value) => Err(format!(
            "invalid persisted request_capture_mode: unsupported value {value:?}"
        )),
    }
}

/// TM-STORAGE-7: strict retention decode; absent/null reads as the `24h`
/// default (RCD-C5b), any other value fails the read.
fn decode_request_capture_retention(row: &QueryResult) -> Result<RequestCaptureRetention, String> {
    let raw = row
        .try_get::<Option<String>>("", "request_capture_retention")
        .map_err(|error| format!("invalid persisted request_capture_retention: {error}"))?;
    match raw.as_deref().map(str::trim) {
        None => Ok(RequestCaptureRetention::OneDay),
        Some("5m") => Ok(RequestCaptureRetention::FiveMinutes),
        Some("1h") => Ok(RequestCaptureRetention::OneHour),
        Some("24h") => Ok(RequestCaptureRetention::OneDay),
        Some("7d") => Ok(RequestCaptureRetention::SevenDays),
        Some(value) => Err(format!(
            "invalid persisted request_capture_retention: unsupported value {value:?}"
        )),
    }
}

impl UserStore {
    pub fn api_key_batch_delete_max_ids() -> usize {
        api_key_batch_delete_max_ids()
    }

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

    pub async fn create_api_key(
        &self,
        user_id: &str,
        name: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(ApiKey, String), String> {
        self.create_api_key_extended(
            user_id,
            CreateApiKeyInput {
                name: name.to_string(),
                expires_in_days: expires_at.map(|e| (e - Utc::now()).num_days()),
                sub_account_enabled: false,
                sub_account_balance_nano_usd: None,
                model_limits_enabled: false,
                model_limits: Vec::new(),
                ip_whitelist: Vec::new(),
                use_user_group: true,
                group_ids: Vec::new(),
                max_multiplier: None,
                transforms: Vec::new(),
                model_redirects: Vec::new(),
                reasoning_envelope_enabled: true,
                request_capture_mode: RequestCaptureMode::Off,
                request_capture_retention: RequestCaptureRetention::default(),
            },
            false,
        )
        .await
    }

    pub async fn create_api_key_extended(
        &self,
        user_id: &str,
        mut input: CreateApiKeyInput,
        is_admin: bool,
    ) -> Result<(ApiKey, String), String> {
        canonicalize_transform_rules(&mut input.transforms);
        validate_api_key_transforms(&input.transforms, is_admin, &self.custom_transforms.get())?;
        let compiled_model_redirects = compile_model_redirects(&input.model_redirects)?;
        input.ip_whitelist = canonicalize_ip_whitelist(&input.ip_whitelist)?;
        if input.sub_account_balance_nano_usd.is_some() && !is_admin {
            return Err("only admins may set an initial sub-account balance".to_string());
        }
        let initial_sub_account_balance = match input.sub_account_balance_nano_usd.as_deref() {
            Some(raw) => {
                let parsed = parse_nano_usd(raw)?;
                if raw != parsed.to_string() || parsed < 0 {
                    return Err(
                        "initial sub-account balance must be a canonical non-negative integer"
                            .to_string(),
                    );
                }
                parsed
            }
            None => 0,
        };
        if initial_sub_account_balance != 0 && !input.sub_account_enabled {
            return Err(
                "a non-zero sub-account balance requires sub-account billing to be enabled"
                    .to_string(),
            );
        }
        let owner_group_id = self
            .get_user_by_id(user_id)
            .await?
            .map(|user| user.group_id)
            .unwrap_or_default();
        // TM-GRP-4: an inheriting key stores no explicit selection.
        let group_ids = if input.use_user_group {
            Vec::new()
        } else {
            let group_ids = canonicalize_group_ids(&input.group_ids);
            if group_ids.is_empty() {
                return Err(
                    "group_ids must be non-empty when use_user_group is disabled".to_string(),
                );
            }
            self.validate_api_key_group_selection(&owner_group_id, &group_ids, is_admin)
                .await?;
            group_ids
        };
        let id = uuid::Uuid::new_v4().to_string();
        let key = format!("sk-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        let key_prefix = key[..12].to_string();
        let now = Utc::now();
        let expires_at = input
            .expires_in_days
            .map(|days| now + chrono::Duration::days(days));

        let model_limits_json =
            serde_json::to_string(&input.model_limits).map_err(|e| e.to_string())?;
        let ip_whitelist_json =
            serde_json::to_string(&input.ip_whitelist).map_err(|e| e.to_string())?;
        let group_ids_json = serialize_group_ids_json(&group_ids)?;
        let model_redirects_json =
            serde_json::to_string(&input.model_redirects).map_err(|e| e.to_string())?;

        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;
        self.lock_user_balance_tx(&tx, user_id)
            .await
            .map_err(|e| e.message)?;
        tx.execute(self.db.stmt(
                r#"INSERT INTO api_keys (id, user_id, name, key_prefix, key, created_at, expires_at, enabled, sub_account_enabled, sub_account_balance_nano, model_limits_enabled, model_limits, ip_whitelist, use_user_group, group_ids, max_multiplier, transforms, model_redirects, reasoning_envelope_enabled, request_capture_enabled, request_capture_mode, request_capture_retention)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)"#,
                vec![
                    id.clone().into(),
                    user_id.into(),
                    input.name.clone().into(),
                    key_prefix.clone().into(),
                    key.clone().into(),
                    now.to_rfc3339().into(),
                    expires_at.map(|e| e.to_rfc3339()).into(),
                    SeaValue::Int(Some(if input.sub_account_enabled { 1 } else { 0 })),
                    initial_sub_account_balance.to_string().into(),
                    SeaValue::Int(Some(if input.model_limits_enabled { 1 } else { 0 })),
                    model_limits_json.into(),
                    ip_whitelist_json.into(),
                    SeaValue::Int(Some(if input.use_user_group { 1 } else { 0 })),
                    group_ids_json.into(),
                    input.max_multiplier.map(|v| v.to_string()).into(),
                    serde_json::to_string(&input.transforms).map_err(|e| e.to_string())?.into(),
                    model_redirects_json.into(),
                    SeaValue::Int(Some(if input.reasoning_envelope_enabled { 1 } else { 0 })),
                    SeaValue::Int(Some(if input.request_capture_mode.should_start_capture() {
                        1
                    } else {
                        0
                    })),
                    input.request_capture_mode.as_str().into(),
                    input.request_capture_retention.as_str().into(),
                ],
            ))
            .await
            .map_err(|e| e.to_string())?;
        if initial_sub_account_balance != 0 {
            self.insert_billing_ledger_tx(
                &tx,
                user_id,
                "admin_sub_account_adjustment",
                initial_sub_account_balance,
                Some(initial_sub_account_balance),
                &serde_json::json!({ "api_key_id": id, "initial": true }),
                &now.to_rfc3339(),
            )
            .await
            .map_err(|e| e.message)?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;

        let api_key = ApiKey {
            id,
            user_id: user_id.to_string(),
            name: input.name,
            key_prefix,
            key: key.clone(),
            created_at: now,
            expires_at,
            last_used_at: None,
            enabled: true,
            sub_account_enabled: input.sub_account_enabled,
            sub_account_balance_nano: initial_sub_account_balance.to_string(),
            model_limits_enabled: input.model_limits_enabled,
            model_limits: input.model_limits,
            ip_whitelist: input.ip_whitelist,
            use_user_group: input.use_user_group,
            group_ids,
            max_multiplier: input.max_multiplier,
            transforms: input.transforms,
            model_redirects: input.model_redirects,
            compiled_model_redirects,
            reasoning_envelope_enabled: input.reasoning_envelope_enabled,
            request_capture_mode: input.request_capture_mode,
            request_capture_retention: input.request_capture_retention,
        };

        Ok((api_key, key))
    }

    pub async fn create_api_key_extended_with_limit(
        &self,
        user_id: &str,
        input: CreateApiKeyInput,
        is_admin: bool,
        max_per_user: i64,
    ) -> Result<(ApiKey, String), CreateApiKeyWithLimitError> {
        if max_per_user <= 0 {
            return Err(CreateApiKeyWithLimitError::InvalidRequest(
                "api_key_max_per_user must be positive".to_string(),
            ));
        }
        let _creation_guard = self.api_key_creation_lock.lock().await;
        let count = self
            .count_user_api_keys(user_id)
            .await
            .map_err(CreateApiKeyWithLimitError::InvalidRequest)?;
        if count >= max_per_user {
            return Err(CreateApiKeyWithLimitError::LimitReached {
                limit: max_per_user,
            });
        }
        self.create_api_key_extended(user_id, input, is_admin)
            .await
            .map_err(CreateApiKeyWithLimitError::InvalidRequest)
    }

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

    async fn get_api_key_auth_candidate(
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

    async fn delete_api_keys_transactional(&self, ids: &[String]) -> Result<usize, String> {
        if ids.len() > api_key_batch_delete_max_ids() {
            return Err(format!(
                "batch delete accepts at most {} ids",
                api_key_batch_delete_max_ids()
            ));
        }
        if ids.is_empty() {
            return Ok(0);
        }

        let mut key_ids = ids.to_vec();
        key_ids.sort();
        key_ids.dedup();

        let write = self.db.write().await;
        let tx = write.begin().await.map_err(|e| e.to_string())?;

        let placeholders = (0..key_ids.len())
            .map(|index| format!("${}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let key_values = key_ids.iter().cloned().map(Into::into).collect::<Vec<_>>();
        let owner_rows = tx
            .query_all(self.db.stmt(
                &format!(
                    "SELECT id, user_id FROM api_keys WHERE id IN ({placeholders}) ORDER BY user_id, id"
                ),
                key_values.clone(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        let mut expected_owners: BTreeMap<String, String> = BTreeMap::new();
        for row in owner_rows {
            expected_owners.insert(
                row.try_get("", "id").map_err(|e| e.to_string())?,
                row.try_get("", "user_id").map_err(|e| e.to_string())?,
            );
        }

        let user_ids: Vec<String> = expected_owners
            .values()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut user_balances = BTreeMap::new();
        if !user_ids.is_empty() {
            let user_placeholders = (0..user_ids.len())
                .map(|index| format!("${}", index + 1))
                .collect::<Vec<_>>()
                .join(", ");
            let user_lock_suffix = if self.db.is_postgres() {
                " FOR UPDATE"
            } else {
                ""
            };
            let user_rows = tx
                .query_all(self.db.stmt(
                    &format!(
                        "SELECT id, balance_nano_usd, balance_unlimited, enabled
                         FROM users WHERE id IN ({user_placeholders})
                         ORDER BY id{user_lock_suffix}"
                    ),
                    user_ids.iter().cloned().map(Into::into).collect(),
                ))
                .await
                .map_err(|e| e.to_string())?;
            for row in user_rows {
                let user_id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
                let raw: String = row
                    .try_get("", "balance_nano_usd")
                    .map_err(|e| e.to_string())?;
                let balance = parse_nano_usd(&raw)
                    .map_err(|e| format!("invalid persisted user balance: {e}"))?;
                let unlimited = row
                    .try_get::<i32>("", "balance_unlimited")
                    .map_err(|e| e.to_string())?
                    == 1;
                let enabled = row
                    .try_get::<i32>("", "enabled")
                    .map_err(|e| e.to_string())?
                    == 1;
                user_balances.insert(
                    user_id,
                    LockedUserBalance {
                        balance,
                        unlimited,
                        enabled,
                    },
                );
            }
            if user_balances.len() != user_ids.len() {
                return Err("api key owner was not found".to_string());
            }
        }

        let lock_suffix = if self.db.is_postgres() {
            " FOR UPDATE"
        } else {
            ""
        };
        let locked_rows = tx
            .query_all(self.db.stmt(
                &format!(
                    "SELECT id, user_id, sub_account_enabled, sub_account_balance_nano
                     FROM api_keys WHERE id IN ({placeholders})
                     ORDER BY user_id, id{lock_suffix}"
                ),
                key_values.clone(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        let mut locked_keys = Vec::with_capacity(locked_rows.len());
        for row in locked_rows {
            let key_id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
            let user_id: String = row.try_get("", "user_id").map_err(|e| e.to_string())?;
            if expected_owners.get(&key_id) != Some(&user_id) {
                continue;
            }
            let raw_balance: String = row
                .try_get("", "sub_account_balance_nano")
                .map_err(|e| e.to_string())?;
            let balance = parse_nano_usd(&raw_balance)
                .map_err(|e| format!("invalid persisted sub-account balance: {e}"))?;
            locked_keys.push((
                key_id,
                LockedApiKeyBalance {
                    user_id,
                    balance,
                    sub_account_enabled: row
                        .try_get::<i32>("", "sub_account_enabled")
                        .map_err(|e| e.to_string())?
                        == 1,
                },
            ));
        }

        let now = Utc::now().to_rfc3339();
        let deleted_key_ids = locked_keys
            .iter()
            .map(|(key_id, _)| key_id.clone())
            .collect::<Vec<_>>();
        let mut affected_user_ids = BTreeSet::new();
        let mut user_updates = BTreeMap::new();
        let mut settlement_rows = Vec::new();
        for (key_id, key) in &locked_keys {
            if key.balance != 0 {
                let user = user_balances
                    .get_mut(&key.user_id)
                    .ok_or_else(|| "locked user balance missing".to_string())?;
                let balance_after = if user.unlimited {
                    None
                } else {
                    let next = user
                        .balance
                        .checked_add(key.balance)
                        .ok_or_else(|| "sub-account delete settlement overflow".to_string())?;
                    user.balance = next;
                    user_updates.insert(key.user_id.clone(), next);
                    Some(next)
                };
                settlement_rows.push((
                    uuid::Uuid::new_v4().to_string(),
                    key.user_id.clone(),
                    key.balance,
                    balance_after,
                    serde_json::json!({ "api_key_id": key_id }).to_string(),
                ));
                affected_user_ids.insert(key.user_id.clone());
            }
        }

        const USER_UPDATE_CHUNK_SIZE: usize = 199;
        let user_updates = user_updates.into_iter().collect::<Vec<_>>();
        for chunk in user_updates.chunks(USER_UPDATE_CHUNK_SIZE) {
            let mut values = Vec::with_capacity(chunk.len() * 2 + 1);
            let mut cases = Vec::with_capacity(chunk.len());
            let mut ids = Vec::with_capacity(chunk.len());
            for (user_id, balance) in chunk {
                let id_index = values.len() + 1;
                values.push(user_id.clone().into());
                ids.push(format!("${id_index}"));
                let balance_index = values.len() + 1;
                values.push(balance.to_string().into());
                cases.push(format!("WHEN ${id_index} THEN ${balance_index}"));
            }
            let updated_at_index = values.len() + 1;
            values.push(now.clone().into());
            tx.execute(self.db.stmt(
                &format!(
                    "UPDATE users
                     SET balance_nano_usd = CASE id {} ELSE balance_nano_usd END,
                         updated_at = ${updated_at_index}
                     WHERE id IN ({})",
                    cases.join(" "),
                    ids.join(", ")
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        }

        const LEDGER_INSERT_CHUNK_SIZE: usize = 57;
        for chunk in settlement_rows.chunks(LEDGER_INSERT_CHUNK_SIZE) {
            let mut values = Vec::with_capacity(chunk.len() * 7);
            let mut rows = Vec::with_capacity(chunk.len());
            for (id, user_id, delta, balance_after, meta_json) in chunk {
                let start = values.len() + 1;
                values.push(id.clone().into());
                values.push(user_id.clone().into());
                values.push("sub_account_delete_settlement".into());
                values.push(delta.to_string().into());
                values.push(balance_after.map(|value| value.to_string()).into());
                values.push(meta_json.clone().into());
                values.push(now.clone().into());
                rows.push(format!(
                    "(${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    start,
                    start + 1,
                    start + 2,
                    start + 3,
                    start + 4,
                    start + 5,
                    start + 6
                ));
            }
            tx.execute(self.db.stmt(
                &format!(
                    "INSERT INTO billing_ledger
                     (id, user_id, kind, delta_nano_usd, balance_after_nano_usd, meta_json, created_at)
                     VALUES {}",
                    rows.join(", ")
                ),
                values,
            ))
            .await
            .map_err(|e| e.to_string())?;
        }
        if !deleted_key_ids.is_empty() {
            let delete_placeholders = (0..deleted_key_ids.len())
                .map(|index| format!("${}", index + 1))
                .collect::<Vec<_>>()
                .join(", ");
            tx.execute(self.db.stmt(
                &format!("DELETE FROM api_keys WHERE id IN ({delete_placeholders})"),
                deleted_key_ids.iter().cloned().map(Into::into).collect(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        }

        tx.commit().await.map_err(|e| e.to_string())?;
        self.api_key_cache.invalidate_by_key_ids(&key_ids);
        for user_id in affected_user_ids {
            self.balance_cache.invalidate(&user_id);
        }
        Ok(deleted_key_ids.len())
    }

    pub async fn delete_api_key(&self, id: &str) -> Result<(), String> {
        self.delete_api_keys_transactional(&[id.to_string()])
            .await?;
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

    /// Update an existing API key with new fields
    pub async fn update_api_key(
        &self,
        key_id: &str,
        input: UpdateApiKeyInput,
        is_admin: bool,
    ) -> Result<ApiKey, String> {
        if let Some(expires_at) = input.expires_at.as_deref() {
            DateTime::parse_from_rfc3339(expires_at)
                .map_err(|_| "expires_at must be a valid RFC3339 timestamp".to_string())?;
        }
        if let Some(transforms) = &input.transforms {
            validate_api_key_transforms(transforms, is_admin, &self.custom_transforms.get())?;
        }
        if let Some(model_redirects) = &input.model_redirects {
            validate_model_redirects(model_redirects)?;
        }
        let canonical_ip_whitelist = input
            .ip_whitelist
            .as_ref()
            .map(|entries| canonicalize_ip_whitelist(entries))
            .transpose()?;
        if input.sub_account_balance_nano_usd.is_some() && !is_admin {
            return Err("only admins may set a sub-account balance".to_string());
        }
        if input.sub_account_enabled == Some(false) && input.sub_account_balance_nano_usd.is_some()
        {
            return Err(
                "sub-account balance cannot be supplied while disabling sub-account billing"
                    .to_string(),
            );
        }
        let requested_sub_account_balance = input
            .sub_account_balance_nano_usd
            .as_deref()
            .map(parse_nano_usd)
            .transpose()?;
        let existing_key = self
            .get_api_key_by_id(key_id)
            .await?
            .ok_or_else(|| "API key not found".to_string())?;
        let resulting_sub_account_enabled = input
            .sub_account_enabled
            .unwrap_or(existing_key.sub_account_enabled);
        if requested_sub_account_balance.is_some_and(|balance| balance != 0)
            && !resulting_sub_account_enabled
        {
            return Err(
                "a non-zero sub-account balance requires sub-account billing to be enabled"
                    .to_string(),
            );
        }
        let disabling_sub_account = input.sub_account_enabled == Some(false);
        let group_fields_changed = input.use_user_group.is_some() || input.group_ids.is_some();
        let effective_use_user_group = input
            .use_user_group
            .unwrap_or(existing_key.use_user_group);
        // TM-GRP-4: an inheriting key stores []; an explicit key needs >= 1 group.
        let effective_group_ids = if effective_use_user_group {
            Vec::new()
        } else {
            let group_ids = input
                .group_ids
                .as_deref()
                .map(canonicalize_group_ids)
                .unwrap_or_else(|| existing_key.group_ids.clone());
            if group_fields_changed && group_ids.is_empty() {
                return Err(
                    "group_ids must be non-empty when use_user_group is disabled".to_string(),
                );
            }
            group_ids
        };
        let mut set_clauses = Vec::new();
        let mut values: Vec<SeaValue> = Vec::new();
        let mut idx = 1usize;

        if let Some(name) = &input.name {
            set_clauses.push(format!("name = ${idx}"));
            values.push(name.clone().into());
            idx += 1;
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push(format!("enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if enabled { 1 } else { 0 })));
            idx += 1;
        }
        if let Some(sub_account_enabled) = input.sub_account_enabled {
            set_clauses.push(format!("sub_account_enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if sub_account_enabled { 1 } else { 0 })));
            idx += 1;
        }
        if let Some(sub_account_balance) = requested_sub_account_balance {
            set_clauses.push(format!("sub_account_balance_nano = ${idx}"));
            values.push(sub_account_balance.to_string().into());
            idx += 1;
        }
        if let Some(model_limits_enabled) = input.model_limits_enabled {
            set_clauses.push(format!("model_limits_enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if model_limits_enabled {
                1
            } else {
                0
            })));
            idx += 1;
        }
        if let Some(model_limits) = &input.model_limits {
            set_clauses.push(format!("model_limits = ${idx}"));
            values.push(
                serde_json::to_string(model_limits)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
            idx += 1;
        }
        if let Some(ip_whitelist) = &canonical_ip_whitelist {
            set_clauses.push(format!("ip_whitelist = ${idx}"));
            values.push(
                serde_json::to_string(ip_whitelist)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
            idx += 1;
        }
        if group_fields_changed {
            set_clauses.push(format!("use_user_group = ${idx}"));
            values.push(SeaValue::Int(Some(if effective_use_user_group {
                1
            } else {
                0
            })));
            idx += 1;
            set_clauses.push(format!("group_ids = ${idx}"));
            values.push(serialize_group_ids_json(&effective_group_ids)?.into());
            idx += 1;
        }
        if let Some(max_multiplier) = input.max_multiplier {
            set_clauses.push(format!("max_multiplier = ${idx}"));
            values.push(max_multiplier.to_string().into());
            idx += 1;
        }
        if let Some(transforms) = &input.transforms {
            let mut transforms = transforms.clone();
            canonicalize_transform_rules(&mut transforms);
            set_clauses.push(format!("transforms = ${idx}"));
            values.push(
                serde_json::to_string(&transforms)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
            idx += 1;
        }
        if let Some(model_redirects) = &input.model_redirects {
            set_clauses.push(format!("model_redirects = ${idx}"));
            values.push(
                serde_json::to_string(model_redirects)
                    .map_err(|e| e.to_string())?
                    .into(),
            );
            idx += 1;
        }
        if let Some(reasoning_envelope_enabled) = input.reasoning_envelope_enabled {
            set_clauses.push(format!("reasoning_envelope_enabled = ${idx}"));
            values.push(SeaValue::Int(Some(if reasoning_envelope_enabled {
                1
            } else {
                0
            })));
            idx += 1;
        }
        if let Some(request_capture_mode) = input.request_capture_mode {
            set_clauses.push(format!("request_capture_enabled = ${idx}"));
            values.push(SeaValue::Int(Some(
                if request_capture_mode.should_start_capture() {
                    1
                } else {
                    0
                },
            )));
            idx += 1;
            set_clauses.push(format!("request_capture_mode = ${idx}"));
            values.push(request_capture_mode.as_str().into());
            idx += 1;
        }
        if let Some(request_capture_retention) = input.request_capture_retention {
            set_clauses.push(format!("request_capture_retention = ${idx}"));
            values.push(request_capture_retention.as_str().into());
            idx += 1;
        }
        if let Some(expires_at) = &input.expires_at {
            set_clauses.push(format!("expires_at = ${idx}"));
            values.push(expires_at.clone().into());
            idx += 1;
        }

        if set_clauses.is_empty() {
            return Ok(existing_key);
        }

        if group_fields_changed && !effective_use_user_group {
            let owner_group_id = self
                .get_user_by_id(&existing_key.user_id)
                .await?
                .map(|user| user.group_id)
                .unwrap_or_default();
            self.validate_api_key_group_selection(&owner_group_id, &effective_group_ids, is_admin)
                .await?;
        }

        values.push(key_id.into());

        let query = format!(
            "UPDATE api_keys SET {} WHERE id = ${idx}",
            set_clauses.join(", ")
        );

        if disabling_sub_account || requested_sub_account_balance.is_some() {
            let write = self.db.write().await;
            let tx = write.begin().await.map_err(|e| e.to_string())?;
            let user = self
                .lock_user_balance_tx(&tx, &existing_key.user_id)
                .await
                .map_err(|e| e.message)?;
            let key = self
                .lock_api_key_balance_tx(&tx, key_id, &existing_key.user_id)
                .await
                .map_err(|e| e.message)?;

            if disabling_sub_account && (key.sub_account_enabled || key.balance != 0) {
                let balance_after = if user.unlimited {
                    None
                } else {
                    let next = user
                        .balance
                        .checked_add(key.balance)
                        .ok_or_else(|| "sub-account disable settlement overflow".to_string())?;
                    tx.execute(self.db.stmt(
                        "UPDATE users SET balance_nano_usd = $1, updated_at = $2 WHERE id = $3",
                        vec![
                            next.to_string().into(),
                            Utc::now().to_rfc3339().into(),
                            existing_key.user_id.clone().into(),
                        ],
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                    Some(next)
                };

                tx.execute(self.db.stmt(
                    "UPDATE api_keys SET sub_account_balance_nano = '0' WHERE id = $1",
                    vec![key_id.into()],
                ))
                .await
                .map_err(|e| e.to_string())?;

                if key.balance != 0 {
                    let now = Utc::now().to_rfc3339();
                    let kind = if key.balance > 0 {
                        "sub_account_refund"
                    } else {
                        "sub_account_debt_transfer"
                    };
                    self.insert_billing_ledger_tx(
                        &tx,
                        &existing_key.user_id,
                        kind,
                        key.balance,
                        balance_after,
                        &serde_json::json!({ "api_key_id": key_id }),
                        &now,
                    )
                    .await
                    .map_err(|e| e.message)?;
                }
            } else if let Some(new_balance) = requested_sub_account_balance {
                let now = Utc::now().to_rfc3339();
                if new_balance < key.balance {
                    let refund = key
                        .balance
                        .checked_sub(new_balance)
                        .ok_or_else(|| "sub-account refund overflow".to_string())?;
                    let balance_after = if user.unlimited {
                        None
                    } else {
                        let next = user
                            .balance
                            .checked_add(refund)
                            .ok_or_else(|| "sub-account refund overflow".to_string())?;
                        tx.execute(self.db.stmt(
                            "UPDATE users SET balance_nano_usd = $1, updated_at = $2 WHERE id = $3",
                            vec![
                                next.to_string().into(),
                                now.clone().into(),
                                existing_key.user_id.clone().into(),
                            ],
                        ))
                        .await
                        .map_err(|e| e.to_string())?;
                        Some(next)
                    };
                    self.insert_billing_ledger_tx(
                        &tx,
                        &existing_key.user_id,
                        "sub_account_refund",
                        refund,
                        balance_after,
                        &serde_json::json!({
                            "api_key_id": key_id,
                            "balance_before_nano_usd": key.balance.to_string(),
                            "balance_after_nano_usd": new_balance.to_string(),
                        }),
                        &now,
                    )
                    .await
                    .map_err(|e| e.message)?;
                } else if new_balance > key.balance {
                    let increase = new_balance
                        .checked_sub(key.balance)
                        .ok_or_else(|| "sub-account adjustment overflow".to_string())?;
                    self.insert_billing_ledger_tx(
                        &tx,
                        &existing_key.user_id,
                        "admin_sub_account_adjustment",
                        increase,
                        Some(new_balance),
                        &serde_json::json!({
                            "api_key_id": key_id,
                            "balance_before_nano_usd": key.balance.to_string(),
                            "balance_after_nano_usd": new_balance.to_string(),
                        }),
                        &now,
                    )
                    .await
                    .map_err(|e| e.message)?;
                }
            }

            tx.execute(self.db.stmt(&query, values))
                .await
                .map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            if disabling_sub_account
                || requested_sub_account_balance.is_some_and(|balance| balance < key.balance)
            {
                self.balance_cache.invalidate(&existing_key.user_id);
            }
        } else {
            self.db
                .write()
                .await
                .execute(self.db.stmt(&query, values))
                .await
                .map_err(|e| e.to_string())?;
        }

        self.api_key_cache.invalidate_by_key_id(key_id);

        self.get_api_key_by_id(key_id)
            .await?
            .ok_or_else(|| "API key not found after update".to_string())
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

    /// Batch delete API keys
    pub async fn batch_delete_api_keys(&self, ids: &[String]) -> Result<usize, String> {
        self.delete_api_keys_transactional(ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_ip_whitelist, parse_api_key_batch_delete_limit, sanitize_api_key_transforms, validate_api_key_transforms};
    use crate::db::DbPool;
    use crate::migration::Migrator;
    use crate::transforms::{Phase, TransformRuleConfig};
    use crate::users::{
        CreateApiKeyInput, CreateApiKeyWithLimitError, CreateGroupInput, RequestCaptureMode, RequestCaptureRetention, UserRole, UserStore,
    };
    
    use sea_orm::{ConnectionTrait, Value as SeaValue};
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;

    #[test]
    fn api_key_batch_limit_parser_rejects_non_positive_values() {
        assert_eq!(parse_api_key_batch_delete_limit(Some("399")), 399);
        assert_eq!(parse_api_key_batch_delete_limit(Some("0")), 400);
        assert_eq!(parse_api_key_batch_delete_limit(Some("-1")), 400);
        assert_eq!(parse_api_key_batch_delete_limit(Some("invalid")), 400);
        assert_eq!(parse_api_key_batch_delete_limit(Some("401")), 400);
    }

    #[tokio::test]
    async fn persisted_auth_policy_corruption_returns_error_without_caching() {
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
            .create_user("corrupt-policy", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (api_key, token) = store
            .create_api_key(&user.id, "corrupt-policy-key", None)
            .await
            .expect("key creates");

        let api_key_cases: Vec<(&str, SeaValue, SeaValue)> = vec![
            (
                "model_limits",
                SeaValue::Int(Some(7)),
                "[]".to_string().into(),
            ),
            (
                "ip_whitelist",
                r#"["not-an-ip"]"#.to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "group_ids",
                "{".to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "transforms",
                "{".to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "model_redirects",
                r#"[{"pattern":"(","replace":"target"}]"#.to_string().into(),
                "[]".to_string().into(),
            ),
            ("enabled", SeaValue::Int(Some(2)), SeaValue::Int(Some(1))),
            (
                "sub_account_enabled",
                "not-an-integer".to_string().into(),
                SeaValue::Int(Some(0)),
            ),
            (
                "model_limits_enabled",
                SeaValue::Int(Some(2)),
                SeaValue::Int(Some(0)),
            ),
            (
                "reasoning_envelope_enabled",
                SeaValue::Int(Some(2)),
                SeaValue::Int(Some(1)),
            ),
            (
                "request_capture_mode",
                "unsupported".to_string().into(),
                "off".to_string().into(),
            ),
            (
                "request_capture_retention",
                "3 days".to_string().into(),
                "24h".to_string().into(),
            ),
        ];

        for (column, invalid, valid) in api_key_cases {
            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE api_keys SET {column} = $1 WHERE id = $2"),
                    vec![invalid, api_key.id.clone().into()],
                ))
                .await
                .expect("corrupt API-key policy column");

            let error = store
                .validate_api_key(&token)
                .await
                .expect_err("corrupt API-key policy must fail validation");
            assert!(error.contains(column), "{column}: {error}");
            assert!(store.api_key_cache.get(&token).is_none());

            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE api_keys SET {column} = $1 WHERE id = $2"),
                    vec![valid, api_key.id.clone().into()],
                ))
                .await
                .expect("restore API-key policy column");
        }

        // users.group_id needs no corruption case here: it is NOT NULL at the
        // schema level and any stored text decodes as an opaque id.
        for (column, invalid, valid) in [(
            "enabled",
            SeaValue::Int(Some(2)),
            SeaValue::Int(Some(1)),
        )] {
            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE users SET {column} = $1 WHERE id = $2"),
                    vec![invalid, user.id.clone().into()],
                ))
                .await
                .expect("corrupt user policy column");

            let error = store
                .validate_api_key(&token)
                .await
                .expect_err("corrupt user policy must fail validation");
            assert!(error.contains(column), "{column}: {error}");
            assert!(store.api_key_cache.get(&token).is_none());

            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE users SET {column} = $1 WHERE id = $2"),
                    vec![valid, user.id.clone().into()],
                ))
                .await
                .expect("restore user policy column");
        }

        let last_used_at = db
            .read()
            .query_one(db.stmt(
                "SELECT last_used_at FROM api_keys WHERE id = $1",
                vec![api_key.id.into()],
            ))
            .await
            .expect("last-used query")
            .expect("key row exists")
            .try_get::<Option<String>>("", "last_used_at")
            .expect("last-used decodes");
        assert!(last_used_at.is_none());

        store
            .validate_api_key(&token)
            .await
            .expect("restored policy validates")
            .expect("restored key authenticates");
        assert!(store.api_key_cache.get(&token).is_some());
    }

    fn limited_api_key_input(name: String) -> CreateApiKeyInput {
        CreateApiKeyInput {
            name,
            expires_in_days: None,
            sub_account_enabled: false,
            sub_account_balance_nano_usd: None,
            model_limits_enabled: false,
            model_limits: Vec::new(),
            ip_whitelist: Vec::new(),
            use_user_group: true,
            group_ids: Vec::new(),
            max_multiplier: None,
            transforms: Vec::new(),
            model_redirects: Vec::new(),
            reasoning_envelope_enabled: true,
            request_capture_mode: RequestCaptureMode::Off,
            request_capture_retention: RequestCaptureRetention::default(),
        }
    }

    #[tokio::test]
    async fn concurrent_api_key_creation_never_exceeds_user_limit() {
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
            .create_user("key-limit-user", "password123", UserRole::User, None)
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(6));
        let mut tasks = Vec::new();
        for index in 0..6 {
            let store = store.clone();
            let barrier = barrier.clone();
            let user_id = user.id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .create_api_key_extended_with_limit(
                        &user_id,
                        limited_api_key_input(format!("key-{index}")),
                        false,
                        2,
                    )
                    .await
            }));
        }

        let mut created = 0;
        let mut rejected = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => created += 1,
                Err(CreateApiKeyWithLimitError::LimitReached { limit: 2 }) => rejected += 1,
                Err(error) => panic!("unexpected key creation result: {error:?}"),
            }
        }
        assert_eq!(created, 2);
        assert_eq!(rejected, 4);
        assert_eq!(store.count_user_api_keys(&user.id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn batch_delete_settles_multiple_keys_for_one_user() {
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
            .create_user("batch-settlement", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (first, _) = store
            .create_api_key(&user.id, "first", None)
            .await
            .expect("first key creates");
        let (second, _) = store
            .create_api_key(&user.id, "second", None)
            .await
            .expect("second key creates");
        db.write()
            .await
            .execute(db.stmt(
                "UPDATE users SET balance_nano_usd = '100' WHERE id = $1",
                vec![user.id.clone().into()],
            ))
            .await
            .expect("user balance seeds");
        for (id, balance) in [(&first.id, "5"), (&second.id, "7")] {
            db.write()
                .await
                .execute(db.stmt(
                    "UPDATE api_keys
                     SET sub_account_enabled = 1, sub_account_balance_nano = $1
                     WHERE id = $2",
                    vec![balance.into(), id.as_str().into()],
                ))
                .await
                .expect("key balance seeds");
        }

        assert_eq!(
            store
                .batch_delete_api_keys(&[second.id.clone(), first.id.clone()])
                .await
                .expect("batch deletes"),
            2
        );
        let user_row = db
            .read()
            .query_one(db.stmt(
                "SELECT balance_nano_usd FROM users WHERE id = $1",
                vec![user.id.clone().into()],
            ))
            .await
            .expect("user query")
            .expect("user remains");
        assert_eq!(
            user_row
                .try_get::<String>("", "balance_nano_usd")
                .expect("balance decodes"),
            "112"
        );
        let ledger_rows = db
            .read()
            .query_all(db.stmt(
                "SELECT delta_nano_usd FROM billing_ledger
                 WHERE user_id = $1 AND kind = 'sub_account_delete_settlement'",
                vec![user.id.into()],
            ))
            .await
            .expect("ledger query");
        let mut deltas = ledger_rows
            .into_iter()
            .map(|row| {
                row.try_get::<String>("", "delta_nano_usd")
                    .expect("delta decodes")
            })
            .collect::<Vec<_>>();
        deltas.sort();
        assert_eq!(deltas, vec!["5".to_string(), "7".to_string()]);
    }

    #[test]
    fn ip_whitelist_accepts_and_canonicalizes_addresses_and_networks() {
        let values = canonicalize_ip_whitelist(&[
            " 2001:0db8::1 ".to_string(),
            "192.0.2.7".to_string(),
            "192.0.2.0/24".to_string(),
            "192.0.2.7".to_string(),
        ])
        .expect("valid whitelist");
        assert_eq!(
            values,
            vec![
                "192.0.2.0/24".to_string(),
                "192.0.2.7".to_string(),
                "2001:db8::1".to_string(),
            ]
        );
        assert!(canonicalize_ip_whitelist(&["not-an-ip".to_string()]).is_err());
    }

    #[test]
    fn sanitize_api_key_transforms_drops_disallowed_rules() {
        let transforms = vec![TransformRuleConfig {
            transform: "field_set".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.4-fast".to_string()]),
            phase: Phase::Request,
            config: json!({
                "path": "service_tier",
                "value": "priority"
            }),
        }];

        let sanitized = sanitize_api_key_transforms(transforms, false, &Default::default());
        assert!(sanitized.is_empty());
    }

    #[test]
    fn validate_api_key_transforms_allows_image_compression() {
        let transforms = vec![TransformRuleConfig {
            transform: "image_compress_input".to_string(),
            enabled: true,
            models: None,
            phase: Phase::Request,
            config: json!({
                "max_edge_px": 1024,
                "jpeg_quality": 80,
                "skip_if_smaller": true
            }),
        }];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    #[test]
    fn validate_api_key_transforms_allows_openai_tool_cache_breakpoints() {
        let transforms = vec![TransformRuleConfig {
            transform: "cache_openai_tool_use".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.6*".to_string()]),
            phase: Phase::Request,
            config: json!({}),
        }];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    #[test]
    fn sanitize_api_key_transforms_canonicalizes_allowed_aliases() {
        let transforms = vec![TransformRuleConfig {
            transform: "remove_anthropic_billing_header".to_string(),
            enabled: true,
            models: None,
            phase: Phase::Request,
            config: json!({}),
        }];

        let sanitized = sanitize_api_key_transforms(transforms, false, &Default::default());

        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, "prompt_strip_anthropic_billing_header");
    }

    #[test]
    fn validate_api_key_transforms_allows_new_response_transforms() {
        let transforms = vec![
            TransformRuleConfig {
                transform: "reasoning_content_to_summary".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_strip_encrypted".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_markdown_to_output".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_inject_content_field".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_summary_to_raw_cot".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_output_to_markdown".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_compress_output".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({
                    "max_edge_px": 1024,
                    "jpeg_quality": 80,
                    "skip_if_smaller": true
                }),
            },
        ];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    /// CJS-AKV-2/CJS-AKV-3: `js:` rules pass for non-admins exactly when the
    /// enabled snapshot entry is user-visible, api_key-scoped, and declares
    /// the rule phase.
    #[test]
    fn api_key_transforms_gate_custom_js_rules_by_snapshot() {
        use crate::custom_transforms::{
            CustomTransformEntry, CustomTransformSnapshot, CustomTransformVisibility,
        };
        use crate::transforms::TransformScope;
        use std::sync::Arc;

        let entry = |id: &str,
                     visibility: CustomTransformVisibility,
                     scopes: Vec<TransformScope>,
                     phases: Vec<Phase>| {
            (
                id.to_string(),
                Arc::new(CustomTransformEntry {
                    id: id.to_string(),
                    name: "n".to_string(),
                    description: "d".to_string(),
                    author: "a".to_string(),
                    source: "function transform(ctx) {}".to_string(),
                    visibility,
                    phases,
                    scopes,
                    config_schema: None,
                }),
            )
        };
        let snapshot = CustomTransformSnapshot::from_entries(
            [
                entry(
                    "js:allowed",
                    CustomTransformVisibility::User,
                    vec![TransformScope::ApiKey],
                    vec![Phase::Request],
                ),
                entry(
                    "js:admin-only",
                    CustomTransformVisibility::Admin,
                    vec![TransformScope::ApiKey],
                    vec![Phase::Request],
                ),
                entry(
                    "js:wrong-scope",
                    CustomTransformVisibility::User,
                    vec![TransformScope::Provider],
                    vec![Phase::Request],
                ),
            ]
            .into_iter()
            .collect(),
        );
        let rule = |id: &str, phase: Phase| TransformRuleConfig {
            transform: id.to_string(),
            enabled: true,
            models: None,
            phase,
            config: json!({}),
        };

        assert!(
            validate_api_key_transforms(&[rule("js:allowed", Phase::Request)], false, &snapshot)
                .is_ok()
        );
        for (id, phase) in [
            ("js:admin-only", Phase::Request),
            ("js:wrong-scope", Phase::Request),
            ("js:allowed", Phase::Response),
            ("js:missing", Phase::Request),
        ] {
            assert!(
                validate_api_key_transforms(&[rule(id, phase)], false, &snapshot).is_err(),
                "rule {id} in phase {phase:?} must be rejected"
            );
        }
        // Admin bypass keeps every rule.
        assert!(
            validate_api_key_transforms(
                &[rule("js:admin-only", Phase::Request)],
                true,
                &snapshot
            )
            .is_ok()
        );

        let sanitized = sanitize_api_key_transforms(
            vec![
                rule("js:allowed", Phase::Request),
                rule("js:admin-only", Phase::Request),
            ],
            false,
            &snapshot,
        );
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, "js:allowed");
    }

    #[test]
    fn sanitize_api_key_transforms_preserves_disallowed_rules_for_admin() {
        let transforms = vec![TransformRuleConfig {
            transform: "field_set".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.4-fast".to_string()]),
            phase: Phase::Request,
            config: json!({
                "path": "service_tier",
                "value": "priority"
            }),
        }];

        let sanitized = sanitize_api_key_transforms(transforms.clone(), true, &Default::default());
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, transforms[0].transform);
        assert_eq!(sanitized[0].enabled, transforms[0].enabled);
        assert_eq!(sanitized[0].models, transforms[0].models);
        assert_eq!(sanitized[0].phase as u8, transforms[0].phase as u8);
        assert_eq!(sanitized[0].config, transforms[0].config);
    }

    #[tokio::test]
    async fn api_key_group_selection_rejects_unknown_and_non_selectable_groups() {
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
        let default_id = store.default_group_id().await.expect("default exists");

        let hidden = store
            .create_group(CreateGroupInput {
                name: "hidden".to_string(),
                description: String::new(),
                user_selectable: false,
                sort_order: 5,
            })
            .await
            .expect("hidden group created");
        let open = store
            .create_group(CreateGroupInput {
                name: "open".to_string(),
                description: String::new(),
                user_selectable: true,
                sort_order: 6,
            })
            .await
            .expect("open group created");

        // Admin may select any registered group.
        store
            .validate_api_key_group_selection(&default_id, &[hidden.id.clone()], true)
            .await
            .expect("admin selects non-selectable group");
        // Non-admin may select user_selectable groups and their own group.
        store
            .validate_api_key_group_selection(&default_id, &[open.id.clone()], false)
            .await
            .expect("non-admin selects user_selectable group");
        store
            .validate_api_key_group_selection(&hidden.id, &[hidden.id.clone()], false)
            .await
            .expect("non-admin keeps own group");
        // Non-admin may not select other non-selectable groups.
        let err = store
            .validate_api_key_group_selection(&default_id, &[hidden.id.clone()], false)
            .await
            .expect_err("non-selectable group rejected");
        assert!(err.contains("not selectable"));
        // Unknown ids are always rejected.
        let err = store
            .validate_api_key_group_selection(&default_id, &["missing".to_string()], false)
            .await
            .expect_err("unknown group rejected");
        assert!(err.contains("unknown group id"));
    }
}
