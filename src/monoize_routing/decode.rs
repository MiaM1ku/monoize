use crate::transforms::{TransformRuleConfig, canonicalize_transform_rules};
use crate::users::canonicalize_group_ids;
use chrono::{DateTime, Utc};
use sea_orm::{QueryResult, Value as SeaValue};
use std::collections::{BTreeMap, HashMap, HashSet};


use super::types::*;

pub(crate) fn decode_provider_group_ids_json(
    provider_id: &str,
    raw: Option<String>,
) -> Result<Vec<String>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let group_ids = serde_json::from_str::<Vec<String>>(&raw)
        .map_err(|error| format!("provider {provider_id} invalid group_ids JSON: {error}"))?;
    Ok(canonicalize_group_ids(&group_ids))
}

pub(crate) fn serialize_provider_group_ids_json(group_ids: &[String]) -> Result<String, String> {
    serde_json::to_string(&canonicalize_group_ids(group_ids)).map_err(|e| e.to_string())
}

pub(crate) fn decode_database_bool(
    entity: &str,
    entity_id: &str,
    field: &str,
    value: i32,
) -> Result<bool, String> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(format!(
            "{entity} {entity_id} invalid {field} boolean: expected 0 or 1, got {value}"
        )),
    }
}

pub(crate) fn generate_short_id() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let bytes = uuid::Uuid::new_v4().into_bytes();
    (0..8)
        .map(|i| CHARSET[bytes[i] as usize % CHARSET.len()] as char)
        .collect()
}

/// CP-INV-14: trim and treat empty as NULL (follow-global).
pub(crate) fn normalized_proxy_url(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// CP-INV-15: reserved header names that must not be overridden by Channel extras.
pub(crate) const EXTRA_HEADERS_RESERVED: &[&str] = &[
    "authorization",
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "expect",
    "te",
    "trailer",
];

pub(crate) const EXTRA_HEADERS_MAX_ENTRIES: usize = 16;
pub(crate) const EXTRA_HEADERS_MAX_KEY_LEN: usize = 128;
pub(crate) const EXTRA_HEADERS_MAX_VALUE_LEN: usize = 4096;

pub(crate) fn validate_channel_extra_headers(
    channel_name: &str,
    headers: &BTreeMap<String, String>,
) -> Result<(), String> {
    if headers.len() > EXTRA_HEADERS_MAX_ENTRIES {
        return Err(format!(
            "channel '{channel_name}' extra_headers must contain at most {EXTRA_HEADERS_MAX_ENTRIES} entries"
        ));
    }
    let mut seen_lower: HashSet<String> = HashSet::new();
    for (key, value) in headers {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "channel '{channel_name}' extra_headers key must not be empty"
            ));
        }
        if trimmed.len() > EXTRA_HEADERS_MAX_KEY_LEN {
            return Err(format!(
                "channel '{channel_name}' extra_headers key exceeds {EXTRA_HEADERS_MAX_KEY_LEN} characters"
            ));
        }
        let valid_token = trimmed.bytes().all(|byte| {
            matches!(byte,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                | b'^' | b'_' | b'`' | b'|' | b'~'
                | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
        });
        if !valid_token {
            return Err(format!(
                "channel '{channel_name}' extra_headers key '{trimmed}' contains invalid characters"
            ));
        }
        let lower = trimmed.to_ascii_lowercase();
        // Case-insensitive duplicate keys would make the effective value ambiguous.
        if !seen_lower.insert(lower.clone()) {
            return Err(format!(
                "channel '{channel_name}' extra_headers contains duplicate key '{trimmed}'"
            ));
        }
        if EXTRA_HEADERS_RESERVED.contains(&lower.as_str()) {
            return Err(format!(
                "channel '{channel_name}' extra_headers key '{trimmed}' is reserved and must not be set"
            ));
        }
        if value.len() > EXTRA_HEADERS_MAX_VALUE_LEN {
            return Err(format!(
                "channel '{channel_name}' extra_headers value for '{trimmed}' exceeds {EXTRA_HEADERS_MAX_VALUE_LEN} characters"
            ));
        }
        if value.contains('\r') || value.contains('\n') {
            return Err(format!(
                "channel '{channel_name}' extra_headers value for '{trimmed}' must not contain CR or LF"
            ));
        }
    }
    Ok(())
}

/// CP-INV-15a: trim keys, drop nothing else, canonical JSON with sorted keys;
/// an empty map persists as NULL.
pub(crate) fn normalized_extra_headers_json(raw: Option<&BTreeMap<String, String>>) -> Option<String> {
    let headers = raw?;
    let mut trimmed: BTreeMap<&str, &String> = BTreeMap::new();
    for (key, value) in headers {
        trimmed.insert(key.trim(), value);
    }
    if trimmed.is_empty() {
        return None;
    }
    serde_json::to_string(&trimmed).ok()
}

pub(crate) fn decode_extra_headers(raw: Option<String>) -> Result<Option<BTreeMap<String, String>>, String> {
    let Some(text) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("invalid stored extra_headers JSON: {e}"))
}

pub(crate) fn decode_channel_model_row(row: &QueryResult, model: &str) -> Result<MonoizeChannel, String> {
    let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
    let multiplier = row
        .try_get::<String>("", "multiplier")
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e: String| format!("channel {id} invalid multiplier: {e}"))?;
    let models = HashMap::from([(
        model.to_string(),
        MonoizeModelEntry {
            redirect: row.try_get("", "redirect").map_err(|e| e.to_string())?,
            multiplier,
        },
    )]);
    decode_channel_row(row, models)
}

pub(crate) fn decode_channel_row(
    row: &QueryResult,
    models: HashMap<String, MonoizeModelEntry>,
) -> Result<MonoizeChannel, String> {
    let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
    let provider_type_raw: String = row
        .try_get("", "provider_type")
        .map_err(|e| format!("channel {id} missing provider_type: {e}"))?;
    let provider_type = MonoizeProviderType::from_str(&provider_type_raw)
        .ok_or_else(|| format!("channel {id} invalid provider type: {provider_type_raw}"))?;
    Ok(MonoizeChannel {
        id: id.clone(),
        name: row.try_get("", "name").map_err(|e| e.to_string())?,
        provider_type,
        base_url: row.try_get("", "base_url").map_err(|e| e.to_string())?,
        api_key: row.try_get("", "api_key").map_err(|e| e.to_string())?,
        weight: row.try_get("", "weight").map_err(|e| e.to_string())?,
        enabled: decode_database_bool(
            "channel",
            &id,
            "enabled",
            row.try_get::<i32>("", "enabled")
                .map_err(|e| e.to_string())?,
        )?,
        passive_failure_count_threshold_override: row
            .try_get::<Option<i32>>("", "passive_failure_count_threshold_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u32(
                    &id,
                    "passive_failure_count_threshold_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        passive_cooldown_seconds_override: row
            .try_get::<Option<i32>>("", "passive_cooldown_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(&id, "passive_cooldown_seconds_override", i64::from(value))
            })
            .transpose()?,
        passive_window_seconds_override: row
            .try_get::<Option<i32>>("", "passive_window_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(&id, "passive_window_seconds_override", i64::from(value))
            })
            .transpose()?,
        passive_rate_limit_cooldown_seconds_override: row
            .try_get::<Option<i32>>("", "passive_rate_limit_cooldown_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(
                    &id,
                    "passive_rate_limit_cooldown_seconds_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        models,
        active_probe_enabled_override: row
            .try_get::<Option<i32>>("", "active_probe_enabled_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_database_bool("channel", &id, "active_probe_enabled_override", value)
            })
            .transpose()?,
        active_probe_interval_seconds_override: row
            .try_get::<Option<i32>>("", "active_probe_interval_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(
                    &id,
                    "active_probe_interval_seconds_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        active_probe_success_threshold_override: row
            .try_get::<Option<i32>>("", "active_probe_success_threshold_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u32(
                    &id,
                    "active_probe_success_threshold_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        active_probe_model_override: row
            .try_get("", "active_probe_model_override")
            .map_err(|e| e.to_string())?,
        affinity_enabled_override: row
            .try_get::<Option<i32>>("", "affinity_enabled_override")
            .map_err(|e| e.to_string())?
            .map(|value| decode_database_bool("channel", &id, "affinity_enabled_override", value))
            .transpose()?,
        affinity_idle_ttl_seconds_override: row
            .try_get::<Option<i32>>("", "affinity_idle_ttl_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(&id, "affinity_idle_ttl_seconds_override", i64::from(value))
            })
            .transpose()?,
        affinity_failback_mode_override: row
            .try_get::<Option<String>>("", "affinity_failback_mode_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                AffinityFailbackMode::from_str(&value).ok_or_else(|| {
                    format!("channel {id} invalid affinity_failback_mode_override: {value}")
                })
            })
            .transpose()?,
        affinity_failback_delay_seconds_override: row
            .try_get::<Option<i32>>("", "affinity_failback_delay_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_nonnegative_u64(
                    &id,
                    "affinity_failback_delay_seconds_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        proxy_url: row
            .try_get::<Option<String>>("", "proxy_url")
            .map_err(|e| e.to_string())?
            .filter(|value| !value.trim().is_empty()),
        extra_headers: decode_extra_headers(
            row.try_get::<Option<String>>("", "extra_headers")
                .map_err(|e| e.to_string())?,
        )?,
        session_affinity_auto: row
            .try_get::<Option<i32>>("", "session_affinity_auto")
            .map_err(|e| e.to_string())?
            .map(|value| decode_database_bool("channel", &id, "session_affinity_auto", value))
            .transpose()?,
        allow_missing_usage: decode_database_bool(
            "channel",
            &id,
            "allow_missing_usage",
            row.try_get::<i32>("", "allow_missing_usage")
                .map_err(|e| e.to_string())?,
        )?,
        allow_unpriced_server_tools: decode_database_bool(
            "channel",
            &id,
            "allow_unpriced_server_tools",
            row.try_get::<i32>("", "allow_unpriced_server_tools")
                .map_err(|e| e.to_string())?,
        )?,
        _healthy: None,
        _last_success_at: None,
        _health_status: None,
        _unhealthy_models: None,
        _probing_models: None,
        _cooldown_until: None,
    })
}

pub(crate) fn decode_provider_row(
    row: &QueryResult,
    channels: Vec<MonoizeChannel>,
) -> Result<MonoizeProvider, String> {
    let id: String = row.try_get("", "id").map_err(|e| e.to_string())?;
    let mut transforms: Vec<TransformRuleConfig> = serde_json::from_str(
        &row.try_get::<String>("", "transforms")
            .map_err(|e| format!("provider {id} missing transforms column: {e}"))?,
    )
    .map_err(|e| format!("provider {id} invalid transforms JSON: {e}"))?;
    canonicalize_transform_rules(&mut transforms);
    let api_type_overrides: Vec<ApiTypeOverride> = serde_json::from_str(
        &row.try_get::<String>("", "api_type_overrides")
            .map_err(|e| format!("provider {id} missing api_type_overrides column: {e}"))?,
    )
    .map_err(|e| format!("provider {id} invalid api_type_overrides JSON: {e}"))?;
    let created_at = DateTime::parse_from_rfc3339(
        &row.try_get::<String>("", "created_at")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("provider {id} invalid created_at RFC3339: {e}"))?
    .with_timezone(&Utc);
    let updated_at = DateTime::parse_from_rfc3339(
        &row.try_get::<String>("", "updated_at")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("provider {id} invalid updated_at RFC3339: {e}"))?
    .with_timezone(&Utc);
    Ok(MonoizeProvider {
        id: id.clone(),
        name: row.try_get("", "name").map_err(|e| e.to_string())?,
        channels,
        max_retries: row.try_get("", "max_retries").map_err(|e| e.to_string())?,
        channel_max_retries: row
            .try_get("", "channel_max_retries")
            .map_err(|e| e.to_string())?,
        channel_retry_interval_ms: row
            .try_get("", "channel_retry_interval_ms")
            .map_err(|e| e.to_string())?,
        circuit_breaker_enabled: decode_database_bool(
            "provider",
            &id,
            "circuit_breaker_enabled",
            row.try_get::<i32>("", "circuit_breaker_enabled")
                .map_err(|e| e.to_string())?,
        )?,
        per_model_circuit_break: decode_database_bool(
            "provider",
            &id,
            "per_model_circuit_break",
            row.try_get::<i32>("", "per_model_circuit_break")
                .map_err(|e| e.to_string())?,
        )?,
        transforms,
        api_type_overrides,
        active_probe_enabled_override: row
            .try_get::<Option<i32>>("", "active_probe_enabled_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_database_bool("provider", &id, "active_probe_enabled_override", value)
            })
            .transpose()?,
        active_probe_interval_seconds_override: row
            .try_get::<Option<i32>>("", "active_probe_interval_seconds_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u64(
                    &id,
                    "active_probe_interval_seconds_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        active_probe_success_threshold_override: row
            .try_get::<Option<i32>>("", "active_probe_success_threshold_override")
            .map_err(|e| e.to_string())?
            .map(|value| {
                decode_positive_u32(
                    &id,
                    "active_probe_success_threshold_override",
                    i64::from(value),
                )
            })
            .transpose()?,
        active_probe_model_override: row
            .try_get("", "active_probe_model_override")
            .map_err(|e| e.to_string())?,
        request_timeout_ms_override: row
            .try_get::<Option<i32>>("", "request_timeout_ms_override")
            .map_err(|e| e.to_string())?
            .map(|value| decode_positive_u64(&id, "request_timeout_ms_override", i64::from(value)))
            .transpose()?,
        extra_fields_whitelist: row
            .try_get::<Option<String>>("", "extra_fields_whitelist")
            .map_err(|e| format!("provider {id} invalid extra_fields_whitelist column: {e}"))?
            .map(|raw| {
                serde_json::from_str::<Vec<String>>(&raw)
                    .map_err(|e| format!("provider {id} invalid extra_fields_whitelist JSON: {e}"))
            })
            .transpose()?,
        strip_cross_protocol_nested_extra: row
            .try_get::<Option<i32>>("", "strip_cross_protocol_nested_extra")
            .map_err(|e| {
                format!("provider {id} invalid strip_cross_protocol_nested_extra column: {e}")
            })?
            .map(|value| {
                decode_database_bool("provider", &id, "strip_cross_protocol_nested_extra", value)
            })
            .transpose()?,
        group_ids: decode_provider_group_ids_json(
            &id,
            row.try_get::<Option<String>>("", "group_ids")
                .map_err(|e| format!("provider {id} invalid group_ids column: {e}"))?,
        )?,
        enabled: decode_database_bool(
            "provider",
            &id,
            "enabled",
            row.try_get::<i32>("", "enabled")
                .map_err(|e| e.to_string())?,
        )?,
        priority: row.try_get("", "priority").map_err(|e| e.to_string())?,
        created_at,
        updated_at,
    })
}


pub(crate) fn opt_bool_to_value(v: Option<bool>) -> SeaValue {
    match v {
        Some(b) => SeaValue::Int(Some(if b { 1 } else { 0 })),
        None => SeaValue::Int(None),
    }
}

pub(crate) fn opt_u64_to_value(v: Option<u64>) -> SeaValue {
    match v {
        Some(n) => SeaValue::Int(Some(n as i32)),
        None => SeaValue::Int(None),
    }
}

pub(crate) fn decode_positive_u32(provider_id: &str, field: &str, value: i64) -> Result<u32, String> {
    u32::try_from(value)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or_else(|| format!("provider {provider_id} invalid {field}: must be >= 1"))
}

pub(crate) fn decode_positive_u64(provider_id: &str, field: &str, value: i64) -> Result<u64, String> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or_else(|| format!("provider {provider_id} invalid {field}: must be >= 1"))
}

pub(crate) fn decode_nonnegative_u64(provider_id: &str, field: &str, value: i64) -> Result<u64, String> {
    u64::try_from(value)
        .map_err(|_| format!("provider {provider_id} invalid {field}: must be >= 0"))
}

