//! Provider/Channel routing domain: entity types, runtime configuration,
//! channel health and affinity bookkeeping, and process-wide routing limits.
//!
//! Persistence lives in `store`, row/input codecs in `rows`, and channel
//! probing in `probe`.

use crate::exact_decimal::Multiplier;
use crate::settings::{
    PricingProfilePattern, default_pricing_profile_model_patterns, default_reasoning_suffix_map,
};
use crate::transforms::TransformRuleConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::OnceLock;
use std::time::Duration;

mod probe;
mod rows;
mod store;
#[cfg(test)]
mod tests;

pub use probe::{
    ChannelProbeOutcome, format_probe_http_error, probe_channel_completion,
    probe_channel_list_models,
};
pub use store::MonoizeRoutingStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonoizeProviderType {
    Responses,
    ChatCompletion,
    Messages,
    Gemini,
    OpenaiImage,
    Replicate,
}

impl MonoizeProviderType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "responses" => Some(Self::Responses),
            "chat_completion" => Some(Self::ChatCompletion),
            "messages" => Some(Self::Messages),
            "gemini" => Some(Self::Gemini),
            "openai_image" => Some(Self::OpenaiImage),
            "replicate" => Some(Self::Replicate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Responses => "responses",
            Self::ChatCompletion => "chat_completion",
            Self::Messages => "messages",
            Self::Gemini => "gemini",
            Self::OpenaiImage => "openai_image",
            Self::Replicate => "replicate",
        }
    }

    pub fn to_config_type(&self) -> crate::config::ProviderType {
        match self {
            Self::Responses => crate::config::ProviderType::Responses,
            Self::ChatCompletion => crate::config::ProviderType::ChatCompletion,
            Self::Messages => crate::config::ProviderType::Messages,
            Self::Gemini => crate::config::ProviderType::Gemini,
            Self::OpenaiImage => crate::config::ProviderType::OpenaiImage,
            Self::Replicate => crate::config::ProviderType::Replicate,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffinityFailbackMode {
    #[default]
    Sticky,
    PreferHigherPriority,
}

impl AffinityFailbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sticky => "sticky",
            Self::PreferHigherPriority => "prefer_higher_priority",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "sticky" => Some(Self::Sticky),
            "prefer_higher_priority" => Some(Self::PreferHigherPriority),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTypeOverride {
    pub pattern: String,
    pub api_type: MonoizeProviderType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonoizeModelEntry {
    pub redirect: Option<String>,
    pub multiplier: Multiplier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonoizeChannel {
    pub id: String,
    pub name: String,
    pub provider_type: MonoizeProviderType,
    pub base_url: String,
    #[serde(skip_serializing)]
    pub api_key: String,
    #[serde(default = "default_channel_weight")]
    pub weight: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub allow_missing_usage: bool,
    #[serde(default)]
    pub allow_unpriced_server_tools: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_failure_count_threshold_override: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_cooldown_seconds_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_window_seconds_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_rate_limit_cooldown_seconds_override: Option<u64>,
    #[serde(default)]
    pub models: HashMap<String, MonoizeModelEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_probe_enabled_override: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_probe_interval_seconds_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_probe_success_threshold_override: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_probe_model_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity_enabled_override: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity_idle_ttl_seconds_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity_failback_mode_override: Option<AffinityFailbackMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity_failback_delay_seconds_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// CP-INV-15: static headers injected into every upstream request for this Channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_headers: Option<BTreeMap<String, String>>,
    /// CM-AFF-0: explicit override for URL-based automatic session affinity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_affinity_auto: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _last_success_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _health_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _unhealthy_models: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _probing_models: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _cooldown_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonoizeProvider {
    pub id: String,
    pub name: String,
    pub channels: Vec<MonoizeChannel>,
    pub max_retries: i32,
    pub channel_max_retries: i32,
    pub channel_retry_interval_ms: i32,
    pub circuit_breaker_enabled: bool,
    pub per_model_circuit_break: bool,
    #[serde(default)]
    pub transforms: Vec<TransformRuleConfig>,
    #[serde(default)]
    pub api_type_overrides: Vec<ApiTypeOverride>,
    pub active_probe_enabled_override: Option<bool>,
    pub active_probe_interval_seconds_override: Option<u64>,
    pub active_probe_success_threshold_override: Option<u32>,
    pub active_probe_model_override: Option<String>,
    pub request_timeout_ms_override: Option<u64>,
    #[serde(default)]
    pub extra_fields_whitelist: Option<Vec<String>>,
    #[serde(default)]
    pub strip_cross_protocol_nested_extra: Option<bool>,
    #[serde(default)]
    pub group_ids: Vec<String>,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMonoizeChannelInput {
    pub id: Option<String>,
    pub name: String,
    pub provider_type: MonoizeProviderType,
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_channel_weight")]
    pub weight: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub allow_missing_usage: bool,
    #[serde(default)]
    pub allow_unpriced_server_tools: bool,
    #[serde(default)]
    pub passive_failure_count_threshold_override: Option<u32>,
    #[serde(default)]
    pub passive_cooldown_seconds_override: Option<u64>,
    #[serde(default)]
    pub passive_window_seconds_override: Option<u64>,
    #[serde(default)]
    pub passive_rate_limit_cooldown_seconds_override: Option<u64>,
    #[serde(default)]
    pub models: HashMap<String, MonoizeModelEntry>,
    pub active_probe_enabled_override: Option<bool>,
    pub active_probe_interval_seconds_override: Option<u64>,
    pub active_probe_success_threshold_override: Option<u32>,
    pub active_probe_model_override: Option<String>,
    #[serde(default)]
    pub affinity_enabled_override: Option<bool>,
    #[serde(default)]
    pub affinity_idle_ttl_seconds_override: Option<u64>,
    #[serde(default)]
    pub affinity_failback_mode_override: Option<AffinityFailbackMode>,
    #[serde(default)]
    pub affinity_failback_delay_seconds_override: Option<u64>,
    /// CP-INV-14: None/empty = follow-global; Some(url) = custom http(s) egress proxy.
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// CP-INV-15: static upstream headers; None/empty map = none.
    #[serde(default)]
    pub extra_headers: Option<BTreeMap<String, String>>,
    /// CM-AFF-2: enable derived per-request session affinity.
    #[serde(default)]
    pub session_affinity_auto: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMonoizeProviderInput {
    pub name: String,
    pub channels: Vec<CreateMonoizeChannelInput>,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
    #[serde(default)]
    pub channel_max_retries: i32,
    #[serde(default)]
    pub channel_retry_interval_ms: i32,
    #[serde(default = "default_enabled")]
    pub circuit_breaker_enabled: bool,
    #[serde(default)]
    pub per_model_circuit_break: bool,
    #[serde(default)]
    pub transforms: Vec<TransformRuleConfig>,
    pub active_probe_enabled_override: Option<bool>,
    #[serde(default)]
    pub api_type_overrides: Vec<ApiTypeOverride>,
    pub active_probe_interval_seconds_override: Option<u64>,
    pub active_probe_success_threshold_override: Option<u32>,
    pub active_probe_model_override: Option<String>,
    pub request_timeout_ms_override: Option<u64>,
    #[serde(default)]
    pub extra_fields_whitelist: Option<Vec<String>>,
    #[serde(default)]
    pub strip_cross_protocol_nested_extra: Option<bool>,
    #[serde(default)]
    pub group_ids: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMonoizeProviderInput {
    pub name: Option<String>,
    pub channels: Option<Vec<CreateMonoizeChannelInput>>,
    pub max_retries: Option<i32>,
    pub channel_max_retries: Option<i32>,
    pub channel_retry_interval_ms: Option<i32>,
    pub circuit_breaker_enabled: Option<bool>,
    pub per_model_circuit_break: Option<bool>,
    pub transforms: Option<Vec<TransformRuleConfig>>,
    pub active_probe_enabled_override: Option<Option<bool>>,
    pub api_type_overrides: Option<Vec<ApiTypeOverride>>,
    pub active_probe_interval_seconds_override: Option<Option<u64>>,
    pub active_probe_success_threshold_override: Option<Option<u32>>,
    pub active_probe_model_override: Option<Option<String>>,
    pub request_timeout_ms_override: Option<Option<u64>>,
    pub extra_fields_whitelist: Option<Option<Vec<String>>>,
    pub strip_cross_protocol_nested_extra: Option<Option<bool>>,
    pub group_ids: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReorderProvidersInput {
    pub provider_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonoizeRuntimeConfig {
    pub request_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub enable_estimated_billing: bool,
    pub passive_failure_count_threshold: u32,
    pub passive_cooldown_seconds: u64,
    pub passive_window_seconds: u64,
    pub passive_rate_limit_cooldown_seconds: u64,
    pub active_enabled: bool,
    pub active_interval_seconds: u64,
    pub active_success_threshold: u32,
    pub active_method: String,
    pub active_probe_model: Option<String>,
    pub global_transforms: Vec<TransformRuleConfig>,
    pub global_model_redirects: Vec<crate::users::ModelRedirectRule>,
    #[serde(skip)]
    pub(crate) compiled_global_model_redirects: Vec<crate::users::CompiledModelRedirectRule>,
    pub reasoning_suffix_map: HashMap<String, String>,
    pub codex_model_ids: Vec<String>,
    pub pricing_profile_model_patterns: Vec<PricingProfilePattern>,
    pub extra_fields_whitelist: HashMap<String, Vec<String>>,
    pub strip_cross_protocol_nested_extra: bool,
    pub request_capture_enabled: bool,
    pub request_capture_max_total_bytes: u64,
    pub mask_sensitive_info: bool,
    pub affinity_enabled: bool,
    pub affinity_idle_ttl_seconds: u64,
    pub affinity_failback_mode: AffinityFailbackMode,
    pub affinity_failback_delay_seconds: u64,
}

impl Default for MonoizeRuntimeConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 30_000,
            stream_idle_timeout_ms: 120_000,
            enable_estimated_billing: true,
            passive_failure_count_threshold: 3,
            passive_cooldown_seconds: 60,
            passive_window_seconds: 30,
            passive_rate_limit_cooldown_seconds: 15,
            active_enabled: true,
            active_interval_seconds: 30,
            active_success_threshold: 1,
            active_method: "completion".to_string(),
            active_probe_model: None,
            global_transforms: Vec::new(),
            global_model_redirects: Vec::new(),
            compiled_global_model_redirects: Vec::new(),
            reasoning_suffix_map: default_reasoning_suffix_map(),
            codex_model_ids: Vec::new(),
            pricing_profile_model_patterns: default_pricing_profile_model_patterns(),
            extra_fields_whitelist: HashMap::new(),
            strip_cross_protocol_nested_extra: true,
            request_capture_enabled: false,
            request_capture_max_total_bytes:
                crate::settings::DEFAULT_REQUEST_CAPTURE_MAX_TOTAL_BYTES,
            mask_sensitive_info: true,
            affinity_enabled: true,
            affinity_idle_ttl_seconds: 30 * 60,
            affinity_failback_mode: AffinityFailbackMode::Sticky,
            affinity_failback_delay_seconds: 5 * 60,
        }
    }
}

impl MonoizeRuntimeConfig {
    pub fn set_global_model_redirects(
        &mut self,
        rules: Vec<crate::users::ModelRedirectRule>,
    ) -> Result<(), String> {
        let compiled = crate::users::compile_model_redirects(&rules)?;
        self.global_model_redirects = rules;
        self.compiled_global_model_redirects = compiled;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChannelHealthState {
    pub healthy: bool,
    pub last_success_at: Option<i64>,
    pub cooldown_until: Option<i64>,
    pub probe_success_count: u32,
    pub last_probe_at: Option<i64>,
    pub passive_failure_timestamps: VecDeque<i64>,
}

#[derive(Debug, Clone)]
pub struct ChannelAffinityBinding {
    pub provider_id: String,
    pub channel_id: String,
    pub bound_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
}

pub const DEFAULT_CHANNEL_AFFINITY_MAX_ENTRIES: usize = 4096;
pub const DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS: u64 = 60;
pub const DEFAULT_CHANNEL_HEALTH_MAX_ENTRIES: usize = 10_000;
pub const DEFAULT_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES: usize = 1024;
pub const DEFAULT_PROVIDER_REORDER_MAX_IDS: usize = 199;

fn parse_provider_reorder_limit(raw: Option<&str>) -> usize {
    crate::env_limits::parse_positive(raw, DEFAULT_PROVIDER_REORDER_MAX_IDS)
        .min(DEFAULT_PROVIDER_REORDER_MAX_IDS)
}

fn provider_reorder_max_ids() -> usize {
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
        crate::env_limits::positive(
            "MONOIZE_CHANNEL_AFFINITY_MAX_ENTRIES",
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

fn parse_channel_affinity_cleanup_interval(raw: Option<&str>) -> Duration {
    Duration::from_secs(crate::env_limits::parse_positive(
        raw,
        DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS,
    ))
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
        crate::env_limits::positive(
            "MONOIZE_CHANNEL_HEALTH_MAX_ENTRIES",
            DEFAULT_CHANNEL_HEALTH_MAX_ENTRIES,
        )
    })
}

pub fn channel_passive_failure_sample_max_entries() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        crate::env_limits::positive(
            "MONOIZE_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES",
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

fn effective_passive_failure_threshold_with_limit(resolved_threshold: u32, limit: usize) -> usize {
    (resolved_threshold.max(1) as usize).min(limit.max(1))
}

pub fn prepare_channel_health_insert(
    health: &mut HashMap<String, ChannelHealthState>,
    key: &str,
) -> bool {
    prepare_channel_health_insert_with_limit(health, key, channel_health_max_entries())
}

fn prepare_channel_health_insert_with_limit(
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

fn missing_channel_health_is_saturated_with_limit(
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

fn default_enabled() -> bool {
    true
}

fn default_max_retries() -> i32 {
    -1
}

fn default_channel_weight() -> i32 {
    1
}

pub fn resolve_effective_api_type(
    overrides: &[ApiTypeOverride],
    default_type: MonoizeProviderType,
    model: &str,
) -> MonoizeProviderType {
    for entry in overrides {
        if crate::glob::case_sensitive_glob_match(&entry.pattern, model) {
            return entry.api_type;
        }
    }
    default_type
}
