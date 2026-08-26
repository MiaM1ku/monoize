use dashmap::DashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use crate::users::UserBalance;


use super::env::positive_env_usize;

// ---------------------------------------------------------------------------
// BalanceCache: caches user balance lookups, invalidated on charge/adjust
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(super) struct CachedBalanceEntry {
    balance: UserBalance,
    cached_at: Instant,
    generation: u64,
}

/// Caches `get_user_balance` results keyed by user_id.
/// Entries expire after `ttl`. Balance mutations must call `invalidate`.
#[derive(Debug, Clone)]
pub struct BalanceCache {
    cache: Arc<DashMap<String, CachedBalanceEntry>>,
    generation: Arc<AtomicU64>,
    ttl: Duration,
    capacity: usize,
    mutation_lock: Arc<std::sync::Mutex<()>>,
}

impl BalanceCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(
            ttl,
            positive_env_usize("MONOIZE_BALANCE_CACHE_CAPACITY", 10_000),
        )
    }

    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            ttl,
            capacity: capacity.max(1),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
        }
    }

    pub fn get(&self, user_id: &str) -> Option<UserBalance> {
        let entry = self.cache.get(user_id)?;
        if entry.cached_at.elapsed() > self.ttl {
            drop(entry);
            let _guard = self
                .mutation_lock
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            self.cache
                .remove_if(user_id, |_, v| v.cached_at.elapsed() > self.ttl);
            return None;
        }
        Some(entry.balance.clone())
    }

    pub(crate) fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn insert_if_current(
        &self,
        user_id: String,
        generation: u64,
        balance: UserBalance,
    ) -> bool {
        if self.current_generation() != generation {
            return false;
        }
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if self.current_generation() != generation {
            return false;
        }
        if !self.cache.contains_key(&user_id) && self.cache.len() >= self.capacity {
            let eviction_key = { self.cache.iter().next().map(|entry| entry.key().clone()) };
            if let Some(eviction_key) = eviction_key {
                self.cache.remove(&eviction_key);
            }
        }
        let cache_key = user_id.clone();
        self.cache.insert(
            user_id,
            CachedBalanceEntry {
                balance,
                cached_at: Instant::now(),
                generation,
            },
        );
        if self.current_generation() == generation {
            return true;
        }
        self.cache
            .remove_if(&cache_key, |_, entry| entry.generation == generation);
        false
    }

    pub fn invalidate(&self, user_id: &str) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.cache.remove(user_id);
    }

    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.cache.clear();
    }

    pub fn spawn_eviction_task(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let _guard = self
                    .mutation_lock
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                let ttl = self.ttl;
                self.cache.retain(|_, v| v.cached_at.elapsed() <= ttl);
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.cache.len()
    }
}

