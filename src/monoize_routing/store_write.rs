use crate::transforms::canonicalize_transform_rules;
use chrono::Utc;
use sea_orm::{ConnectionTrait, Value as SeaValue};
use std::collections::{HashMap, HashSet};


use super::types::*;
use super::health::*;
use super::decode::*;
use super::MonoizeRoutingStore;
use super::validate::{canonicalize_models, validate_channels, validate_provider_input, validate_api_type_overrides};

impl MonoizeRoutingStore {
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

    pub(super) async fn replace_channels_on(
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
