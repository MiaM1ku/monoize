//! Provider/channel routing store, health, and probe helpers.

mod types;
mod health;
mod decode;
mod store_read;
mod store_write;
mod validate;
mod probe;

#[cfg(test)]
mod tests;

pub use types::{
    AffinityFailbackMode, ApiTypeOverride, ChannelAffinityBinding, ChannelHealthState,
    CreateMonoizeChannelInput, CreateMonoizeProviderInput, MonoizeChannel, MonoizeModelEntry,
    MonoizeProvider, MonoizeProviderType, MonoizeRuntimeConfig, ReorderProvidersInput,
    UpdateMonoizeProviderInput,
};
pub use health::{
    DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS, DEFAULT_CHANNEL_AFFINITY_MAX_ENTRIES,
    DEFAULT_CHANNEL_HEALTH_MAX_ENTRIES, DEFAULT_CHANNEL_PASSIVE_FAILURE_SAMPLE_MAX_ENTRIES,
    DEFAULT_PROVIDER_REORDER_MAX_IDS, channel_affinity_cleanup_interval, channel_affinity_max_entries,
    channel_health_max_entries, channel_passive_failure_sample_max_entries, cleanup_channel_affinity,
    effective_passive_failure_threshold, missing_channel_health_is_saturated,
    prepare_channel_health_insert,
};
pub use store_read::MonoizeRoutingStore;
pub use probe::{
    ChannelProbeOutcome, format_probe_http_error, probe_channel_completion, probe_channel_list_models,
    resolve_effective_api_type,
};
