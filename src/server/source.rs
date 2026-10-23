//! The per-source concurrency cap (decision D-025).
//!
//! Keyed by `PrefixKey` with the standard library's keyed hasher (SipHash with a
//! per-process random key), so an attacker cannot choose addresses that
//! collide. Sharded to keep accept threads and workers off one lock; every map
//! is sized at build for the global cap, so it never grows (no allocation after
//! build) and it can never fill: each live entry belongs to an open connection.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Mutex, PoisonError};

use crate::addr::PrefixKey;

const SHARDS: usize = 16;

pub(crate) struct SourceTable {
    shards: Vec<Mutex<HashMap<PrefixKey, u32, RandomState>>>,
    hasher: RandomState,
    cap: u32,
}

impl SourceTable {
    pub(crate) fn new(max_connections: u32, cap_per_source: u32) -> SourceTable {
        let per_shard = (max_connections as usize).div_ceil(SHARDS).max(4) * 2;
        let hasher = RandomState::new();
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(HashMap::with_capacity_and_hasher(per_shard, hasher.clone())))
            .collect();
        SourceTable {
            shards,
            hasher,
            cap: cap_per_source,
        }
    }

    fn shard(&self, key: &PrefixKey) -> &Mutex<HashMap<PrefixKey, u32, RandomState>> {
        let h = self.hasher.hash_one(key);
        &self.shards[(h as usize) % SHARDS]
    }

    /// Counts one more connection from `key`; `false` when the source is at its cap.
    pub(crate) fn acquire(&self, key: PrefixKey) -> bool {
        let mut map = self
            .shard(&key)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = map.entry(key).or_insert(0);
        if *count >= self.cap {
            if *count == 0 {
                map.remove(&key);
            }
            return false;
        }
        *count += 1;
        true
    }

    /// One connection from `key` closed.
    pub(crate) fn release(&self, key: PrefixKey) {
        let mut map = self
            .shard(&key)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = map.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&key);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{PrefixKey, PrefixPolicy};

    fn key(s: &str) -> PrefixKey {
        PrefixKey::of(s.parse().unwrap(), PrefixPolicy::DEFAULT)
    }

    #[test]
    fn test_source_cap_enforced_and_released() {
        let t = SourceTable::new(100, 2);
        assert!(t.acquire(key("10.0.0.1")));
        assert!(t.acquire(key("10.0.0.1")));
        assert!(!t.acquire(key("10.0.0.1")));
        assert!(t.acquire(key("10.0.0.2")));
        t.release(key("10.0.0.1"));
        assert!(t.acquire(key("10.0.0.1")));
        t.release(key("10.0.0.1"));
        t.release(key("10.0.0.1"));
        t.release(key("10.0.0.2"));
        assert_eq!(t.live(), 0);
    }

    #[test]
    fn test_source_ipv6_grouped_by_64() {
        let t = SourceTable::new(100, 1);
        assert!(t.acquire(key("2001:db8::1")));
        assert!(!t.acquire(key("2001:db8::2")));
    }

    #[test]
    fn test_source_release_unknown_is_noop() {
        let t = SourceTable::new(10, 1);
        t.release(key("1.1.1.1"));
        assert_eq!(t.live(), 0);
    }
}
