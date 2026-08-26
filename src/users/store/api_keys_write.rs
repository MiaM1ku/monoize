use super::helpers::*;
use crate::users::utils::parse_nano_usd;
use crate::users::{
    ApiKey, CreateApiKeyInput,
    CreateApiKeyWithLimitError, RequestCaptureMode, RequestCaptureRetention, UpdateApiKeyInput, UserStore, canonicalize_group_ids, compile_model_redirects,
    validate_model_redirects,
};
use crate::transforms::canonicalize_transform_rules;
use chrono::{DateTime, Utc};
use sea_orm::Value as SeaValue;
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::collections::{BTreeMap, BTreeSet};

impl UserStore {
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

    pub(super) async fn delete_api_keys_transactional(&self, ids: &[String]) -> Result<usize, String> {
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

    /// Batch delete API keys
    pub async fn batch_delete_api_keys(&self, ids: &[String]) -> Result<usize, String> {
        self.delete_api_keys_transactional(ids).await
    }

}
