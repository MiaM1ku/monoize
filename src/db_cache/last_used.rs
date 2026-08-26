use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::db::DbPool;


use super::env::positive_env_usize;

// ---------------------------------------------------------------------------
// LastUsedBatcher: buffers api_key last_used timestamps, flushes periodically
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LastUsedBatcher {
    buffer: Arc<DashMap<String, DateTime<Utc>>>,
    capacity: usize,
    record_lock: Arc<std::sync::Mutex<()>>,
    flush_chunk_entries: usize,
}

impl Default for LastUsedBatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl LastUsedBatcher {
    pub fn new() -> Self {
        Self::with_capacity(positive_env_usize(
            "MONOIZE_LAST_USED_BUFFER_ENTRIES",
            10_000,
        ))
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(
            capacity,
            positive_env_usize("MONOIZE_LAST_USED_FLUSH_CHUNK_ENTRIES", 256),
        )
    }

    pub fn with_limits(capacity: usize, flush_chunk_entries: usize) -> Self {
        Self {
            buffer: Arc::new(DashMap::new()),
            capacity: capacity.max(1),
            record_lock: Arc::new(std::sync::Mutex::new(())),
            flush_chunk_entries: flush_chunk_entries.clamp(1, 400),
        }
    }

    pub fn record(&self, api_key_id: String, now: DateTime<Utc>) {
        let _guard = self
            .record_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(mut existing) = self.buffer.get_mut(&api_key_id) {
            if now > *existing {
                *existing = now;
            }
            return;
        }
        if self.buffer.len() >= self.capacity {
            tracing::warn!(
                capacity = self.capacity,
                "last_used buffer is full; omitting new key metadata"
            );
            return;
        }
        self.buffer.insert(api_key_id, now);
    }

    /// Drain all buffered entries and flush them to DB in a single write lock acquisition.
    pub async fn flush(&self, db: &DbPool) {
        let entries: Vec<(String, DateTime<Utc>)> = {
            let mut drained = Vec::new();
            self.buffer.retain(|k, v| {
                drained.push((k.clone(), *v));
                false
            });
            drained
        };
        if entries.is_empty() {
            return;
        }
        let write = db.write().await;
        use sea_orm::ConnectionTrait;
        let mut failed = Vec::new();
        for chunk in entries.chunks(self.flush_chunk_entries) {
            let (sql, values) = last_used_bulk_update(chunk);
            if let Err(error) = write.execute(db.stmt(&sql, values)).await {
                tracing::warn!(
                    entries = chunk.len(),
                    "last_used_batcher bulk flush error: {error}"
                );
                failed.extend_from_slice(chunk);
            }
        }
        drop(write);
        for (id, timestamp) in failed {
            self.record_retry(id, timestamp);
        }
    }

    /// Spawn background task that flushes every `interval`.
    pub fn spawn_flush_task(self, db: DbPool, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                self.flush(&db).await;
            }
        })
    }

    /// Replica shipment path (PRP12): atomically drain all buffered entries without
    /// touching the database. Callers re-insert via `record_retry` on delivery failure.
    pub fn drain(&self) -> Vec<(String, DateTime<Utc>)> {
        self.drain_limit(usize::MAX)
    }

    pub fn drain_limit(&self, max: usize) -> Vec<(String, DateTime<Utc>)> {
        let mut drained = Vec::new();
        if max == 0 {
            return drained;
        }
        self.buffer.retain(|k, v| {
            if drained.len() >= max {
                return true;
            }
            drained.push((k.clone(), *v));
            false
        });
        drained
    }

    pub(crate) fn record_retry(&self, api_key_id: String, timestamp: DateTime<Utc>) {
        let _guard = self
            .record_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(mut existing) = self.buffer.get_mut(&api_key_id) {
            if timestamp > *existing {
                *existing = timestamp;
            }
            return;
        }
        if self.buffer.len() >= self.capacity
            && let Some(eviction_key) = self.buffer.iter().next().map(|entry| entry.key().clone())
        {
            self.buffer.remove(&eviction_key);
            tracing::warn!(
                api_key_id = %eviction_key,
                "last_used buffer evicted metadata to retain a failed write for retry"
            );
        }
        self.buffer.insert(api_key_id, timestamp);
    }
}

pub(crate) fn last_used_bulk_update(
    entries: &[(String, DateTime<Utc>)],
) -> (String, Vec<sea_orm::Value>) {
    let mut sql = String::from("UPDATE api_keys SET last_used_at = CASE");
    let mut values = Vec::with_capacity(entries.len().saturating_mul(2));
    let mut id_placeholders = Vec::with_capacity(entries.len());
    for (index, (id, timestamp)) in entries.iter().enumerate() {
        let id_param = index.saturating_mul(2).saturating_add(1);
        let timestamp_param = id_param.saturating_add(1);
        sql.push_str(&format!(" WHEN id = ${id_param} THEN ${timestamp_param}"));
        id_placeholders.push(format!("${id_param}"));
        values.push(id.clone().into());
        values.push(timestamp.to_rfc3339().into());
    }
    sql.push_str(" ELSE last_used_at END WHERE id IN (");
    sql.push_str(&id_placeholders.join(", "));
    sql.push(')');
    (sql, values)
}

