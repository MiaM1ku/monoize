use std::collections::{HashMap, HashSet};


use super::types::*;
use super::decode::validate_channel_extra_headers;

pub(super) fn canonicalize_models(
    models: &HashMap<String, MonoizeModelEntry>,
) -> HashMap<String, MonoizeModelEntry> {
    let mut out = HashMap::new();
    for (model, entry) in models {
        let model = model.trim();
        if model.is_empty() {
            continue;
        }
        out.insert(
            model.to_string(),
            MonoizeModelEntry {
                redirect: entry
                    .redirect
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                multiplier: entry.multiplier,
            },
        );
    }
    out
}

pub(super) fn validate_models(models: &HashMap<String, MonoizeModelEntry>) -> Result<(), String> {
    for model in models.keys() {
        if model.trim().is_empty() {
            return Err("model key must not be empty".to_string());
        }
    }
    Ok(())
}

pub(super) fn validate_channels(
    channels: &[CreateMonoizeChannelInput],
    require_api_key: bool,
) -> Result<(), String> {
    if channels.is_empty() {
        return Err("channels must not be empty".to_string());
    }
    if !channels.iter().any(|channel| !channel.models.is_empty()) {
        return Err("at least one channel must define a model".to_string());
    }
    let mut ids = HashSet::new();
    for c in channels {
        if c.name.trim().is_empty() {
            return Err("channel name must not be empty".to_string());
        }
        if c.base_url.trim().is_empty() {
            return Err("channel base_url must not be empty".to_string());
        }
        if require_api_key {
            let key = c.api_key.as_deref().unwrap_or("");
            if key.trim().is_empty() {
                return Err("channel api_key must not be empty".to_string());
            }
        }
        if c.weight < 0 {
            return Err("channel weight must be >= 0".to_string());
        }
        if let Some(headers) = &c.extra_headers {
            validate_channel_extra_headers(&c.name, headers)?;
        }
        if let Some(v) = c.passive_failure_count_threshold_override {
            if !(1..=i32::MAX as u32).contains(&v) {
                return Err(
                    "channel passive_failure_count_threshold_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if let Some(v) = c.passive_cooldown_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "channel passive_cooldown_seconds_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(v) = c.passive_window_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "channel passive_window_seconds_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(v) = c.passive_rate_limit_cooldown_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "channel passive_rate_limit_cooldown_seconds_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if let Some(v) = c.active_probe_interval_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "channel active_probe_interval_seconds_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if let Some(v) = c.active_probe_success_threshold_override {
            if !(1..=i32::MAX as u32).contains(&v) {
                return Err(
                    "channel active_probe_success_threshold_override must be between 1 and 2147483647".to_string(),
                );
            }
        }
        if let Some(v) = c.affinity_idle_ttl_seconds_override {
            if !(1..=i32::MAX as u64).contains(&v) {
                return Err(
                    "channel affinity_idle_ttl_seconds_override must be between 1 and 2147483647"
                        .to_string(),
                );
            }
        }
        if let Some(v) = c.affinity_failback_delay_seconds_override {
            if v > i32::MAX as u64 {
                return Err(
                    "channel affinity_failback_delay_seconds_override must be between 0 and 2147483647"
                        .to_string(),
                );
            }
        }
        validate_models(&c.models)?;
        let mut model_seen = HashSet::new();
        for model in c.models.keys() {
            let model = model.trim();
            if model.is_empty() {
                return Err("channel model keys must not be empty".to_string());
            }
            if !model_seen.insert(model.to_string()) {
                return Err(format!(
                    "channel '{}' has duplicate model '{}'",
                    c.name, model
                ));
            }
        }
        if let Some(id) = &c.id {
            if !ids.insert(id.clone()) {
                return Err("duplicate channel id".to_string());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_provider_input(
    name: &str,
    channels: &[CreateMonoizeChannelInput],
    api_type_overrides: &[ApiTypeOverride],
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("provider name must not be empty".to_string());
    }
    validate_channels(channels, true)?;
    validate_api_type_overrides(api_type_overrides)?;
    Ok(())
}

pub(super) fn validate_api_type_overrides(overrides: &[ApiTypeOverride]) -> Result<(), String> {
    for (idx, entry) in overrides.iter().enumerate() {
        if entry.pattern.trim().is_empty() {
            return Err(format!(
                "api_type_overrides[{idx}].pattern must not be empty"
            ));
        }
    }
    Ok(())
}

