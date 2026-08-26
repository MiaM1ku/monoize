//! Hot-path DB write batching and auth/balance caches.

mod env;
mod last_used;
mod spool_io;
mod request_log;
mod api_key_cache;
mod balance_cache;
mod index_util;

#[cfg(test)]
mod tests;

pub use last_used::LastUsedBatcher;
pub(crate) use last_used::last_used_bulk_update;
pub use request_log::{RequestLogAdmissionError, RequestLogReservation, SpoolRequestLog};
pub(crate) use request_log::{
    MeteringSink, REQUEST_LOG_INSERT_CHUNK_ENTRIES,
    request_log_insert_chunk,
};
pub use request_log::RequestLogBatcher;
pub use api_key_cache::ApiKeyCache;
pub use balance_cache::BalanceCache;
