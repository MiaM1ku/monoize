use super::index_util::remove_index_member;
use dashmap::DashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};



use super::env::positive_env_usize;

// ---------------------------------------------------------------------------
// ApiKeyCache: caches validated API key lookups, invalidated on mutation
// ---------------------------------------------------------------------------

use crate::users::{ApiKey, User};

#[derive(Clone)]
pub(super) struct CachedApiKeyEntry {
    api_key: ApiKey,
    user: User,
    plan_group_ids: Option<Vec<String>>,
    cached_at: Instant,
    generation: u64,
}

/// Caches successful `validate_api_key` results keyed by the complete API key.
/// Entries expire after `ttl`. Mutations to api_keys table must call `invalidate_*`.
#[derive(Debug, Clone)]
pub struct ApiKeyCache {
    cache: Arc<DashMap<String, CachedApiKeyEntry>>,
    key_id_index: Arc<DashMap<String, std::collections::HashSet<String>>>,
    user_id_index: Arc<DashMap<String, std::collections::HashSet<String>>>,
    generation: Arc<AtomicU64>,
    ttl: Duration,
    capacity: usize,
    mutation_lock: Arc<std::sync::Mutex<()>>,
}

impl std::fmt::Debug for CachedApiKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedApiKeyEntry")
            .field("api_key_id", &self.api_key.id)
            .field("user_id", &self.user.id)
            .finish()
    }
}

impl ApiKeyCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(
            ttl,
            positive_env_usize("MONOIZE_API_KEY_CACHE_CAPACITY", 10_000),
        )
    }

    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            key_id_index: Arc::new(DashMap::new()),
            user_id_index: Arc::new(DashMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            ttl,
            capacity: capacity.max(1),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
        }
    }

    pub fn get(&self, key: &str) -> Option<(ApiKey, User, Option<Vec<String>>)> {
        let entry = self.cache.get(key)?;
        if entry.cached_at.elapsed() > self.ttl {
            drop(entry);
            let _guard = self
                .mutation_lock
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if self
                .cache
                .get(key)
                .is_some_and(|entry| entry.cached_at.elapsed() > self.ttl)
            {
                self.remove_key_locked(key);
            }
            return None;
        }
        Some((
            entry.api_key.clone(),
            entry.user.clone(),
            entry.plan_group_ids.clone(),
        ))
    }

    pub(crate) fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn insert_if_current(
        &self,
        key: String,
        generation: u64,
        api_key: ApiKey,
        user: User,
        plan_group_ids: Option<Vec<String>>,
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
        if !self.cache.contains_key(&key) && self.cache.len() >= self.capacity {
            let eviction_key = { self.cache.iter().next().map(|entry| entry.key().clone()) };
            if let Some(eviction_key) = eviction_key {
                self.remove_key_locked(&eviction_key);
            }
        }
        if self.cache.contains_key(&key) {
            self.remove_key_locked(&key);
        }
        let cache_key = key.clone();
        let api_key_id = api_key.id.clone();
        let user_id = api_key.user_id.clone();
        self.cache.insert(
            key,
            CachedApiKeyEntry {
                api_key,
                user,
                plan_group_ids,
                cached_at: Instant::now(),
                generation,
            },
        );
        self.key_id_index
            .entry(api_key_id)
            .or_default()
            .insert(cache_key.clone());
        self.user_id_index
            .entry(user_id)
            .or_default()
            .insert(cache_key.clone());
        if self.current_generation() == generation {
            return true;
        }
        if self
            .cache
            .get(&cache_key)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.remove_key_locked(&cache_key);
        }
        false
    }

    fn begin_invalidation(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    pub fn invalidate_by_key_id(&self, key_id: &str) {
        self.begin_invalidation();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let keys = self
            .key_id_index
            .remove(key_id)
            .map(|(_, keys)| keys)
            .unwrap_or_default();
        for key in keys {
            self.remove_key_locked(&key);
        }
    }

    /// Invalidate all keys belonging to a user.
    pub fn invalidate_by_user_id(&self, user_id: &str) {
        self.begin_invalidation();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let keys = self
            .user_id_index
            .remove(user_id)
            .map(|(_, keys)| keys)
            .unwrap_or_default();
        for key in keys {
            self.remove_key_locked(&key);
        }
    }

    /// Invalidate entries matching any of the given key IDs.
    pub fn invalidate_by_key_ids(&self, key_ids: &[String]) {
        self.begin_invalidation();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        for key_id in key_ids {
            let keys = self
                .key_id_index
                .remove(key_id)
                .map(|(_, keys)| keys)
                .unwrap_or_default();
            for key in keys {
                self.remove_key_locked(&key);
            }
        }
    }

    pub fn invalidate(&self, key: &str) {
        self.begin_invalidation();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.remove_key_locked(key);
    }

    /// Remove all entries.
    pub fn invalidate_all(&self) {
        self.begin_invalidation();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.cache.clear();
        self.key_id_index.clear();
        self.user_id_index.clear();
    }

    pub fn spawn_eviction_task(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let expired = self
                    .cache
                    .iter()
                    .filter(|entry| entry.cached_at.elapsed() > self.ttl)
                    .map(|entry| entry.key().clone())
                    .collect::<Vec<_>>();
                let _guard = self
                    .mutation_lock
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                for key in expired {
                    if self
                        .cache
                        .get(&key)
                        .is_some_and(|entry| entry.cached_at.elapsed() > self.ttl)
                    {
                        self.remove_key_locked(&key);
                    }
                }
            }
        })
    }

    fn remove_key_locked(&self, key: &str) {
        let Some((_, entry)) = self.cache.remove(key) else {
            return;
        };
        remove_index_member(&self.key_id_index, &entry.api_key.id, key);
        remove_index_member(&self.user_id_index, &entry.api_key.user_id, key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.cache.len()
    }
}

