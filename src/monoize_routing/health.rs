use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use std::time::Duration;


use super::types::*;

pub const DEFAULT_CHANNEL_AFFINITY_MAX_ENTRIES: usize = 4096;
pub const DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS: u64 = 60;
pub const DEFAULT_CHANNEL_HEALTH_MAX_ENTRIES: usize = 10_000;
pub const DEFAULT_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES: usize = 1024;
pub const DEFAULT_PROVIDER_REORDER_MAX_IDS: usize = 199;
pub(crate) const TRANSFORM_MIGRATION_BATCH_SIZE: usize = 199;
pub(crate) const TRANSFORM_MIGRATION_MARKER: &str = "migration.provider_transform_rule_ids.v2";
pub(crate) const OBSOLETE_TRANSFORM_MIGRATION_MARKER: &str = "migration.provider_transform_rule_ids.v1";

pub(crate) fn parse_positive_entry_limit(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub(crate) fn parse_provider_reorder_limit(raw: Option<&str>) -> usize {
    parse_positive_entry_limit(raw, DEFAULT_PROVIDER_REORDER_MAX_IDS)
        .min(DEFAULT_PROVIDER_REORDER_MAX_IDS)
}

pub(crate) fn provider_reorder_max_ids() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_provider_reorder_limit(
            std::env::var("MONOIZE_PROVIDER_REORDER_MAX_IDS")
                .ok()
                .as_deref(),
        )
    })
}

pub fn channel_affinity_max_entries() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_positive_entry_limit(
            std::env::var("MONOIZE_CHANNEL_AFFINITY_MAX_ENTRIES")
                .ok()
                .as_deref(),
            DEFAULT_CHANNEL_AFFINITY_MAX_ENTRIES,
        )
    })
}

pub fn channel_affinity_cleanup_interval() -> Duration {
    static INTERVAL: OnceLock<Duration> = OnceLock::new();
    *INTERVAL.get_or_init(|| {
        parse_channel_affinity_cleanup_interval(
            std::env::var("MONOIZE_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS")
                .ok()
                .as_deref(),
        )
    })
}

pub(crate) fn parse_channel_affinity_cleanup_interval(raw: Option<&str>) -> Duration {
    let seconds = raw
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS);
    Duration::from_secs(seconds)
}

pub fn cleanup_channel_affinity(
    cache: &mut HashMap<String, ChannelAffinityBinding>,
    now_ts: i64,
) -> usize {
    let previous_len = cache.len();
    cache.retain(|_, binding| now_ts < binding.expires_at);
    previous_len - cache.len()
}

pub fn channel_health_max_entries() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_positive_entry_limit(
            std::env::var("MONOIZE_CHANNEL_HEALTH_MAX_ENTRIES")
                .ok()
                .as_deref(),
            DEFAULT_CHANNEL_HEALTH_MAX_ENTRIES,
        )
    })
}

pub fn channel_passive_failure_sample_max_entries() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_positive_entry_limit(
            std::env::var("MONOIZE_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES")
                .ok()
                .as_deref(),
            DEFAULT_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES,
        )
    })
}

pub fn effective_passive_failure_threshold(resolved_threshold: u32) -> usize {
    effective_passive_failure_threshold_with_limit(
        resolved_threshold,
        channel_passive_failure_sample_max_entries(),
    )
}

pub(crate) fn effective_passive_failure_threshold_with_limit(resolved_threshold: u32, limit: usize) -> usize {
    (resolved_threshold.max(1) as usize).min(limit.max(1))
}

pub fn prepare_channel_health_insert(
    health: &mut HashMap<String, ChannelHealthState>,
    key: &str,
) -> bool {
    prepare_channel_health_insert_with_limit(health, key, channel_health_max_entries())
}

pub(crate) fn prepare_channel_health_insert_with_limit(
    health: &mut HashMap<String, ChannelHealthState>,
    key: &str,
    limit: usize,
) -> bool {
    health.contains_key(key) || health.len() < limit
}

pub fn missing_channel_health_is_saturated(
    health: &HashMap<String, ChannelHealthState>,
    key: &str,
) -> bool {
    missing_channel_health_is_saturated_with_limit(health, key, channel_health_max_entries())
}

pub(crate) fn missing_channel_health_is_saturated_with_limit(
    health: &HashMap<String, ChannelHealthState>,
    key: &str,
    limit: usize,
) -> bool {
    !health.contains_key(key) && health.len() >= limit
}

impl ChannelHealthState {
    pub fn new() -> Self {
        Self {
            healthy: true,
            last_success_at: None,
            cooldown_until: None,
            probe_success_count: 0,
            last_probe_at: None,
            passive_failure_timestamps: VecDeque::new(),
        }
    }

    pub fn status(&self, now_ts: i64) -> &'static str {
        if self.healthy {
            return "healthy";
        }
        if let Some(until) = self.cooldown_until {
            if now_ts < until {
                return "unhealthy";
            }
        }
        "probing"
    }
}

