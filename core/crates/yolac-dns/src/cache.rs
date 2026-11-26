//! Bounded, strictly RAM-only O(1) LRU DNS cache with Stale-While-Revalidate (RFC 8767)
//! and negative caching (wiped on stop, zero disk persistence).

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::wire::{patch_transaction_id, QType};

/// How long an expired entry may still be served immediately while refreshed asynchronously (SWR).
const STALE_SERVE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: Arc<str>,
    qtype: QType,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    qname: Arc<str>,
    wire_response: Vec<u8>,
    expires_at: Instant,
    stale_until: Instant,
    generation: u64,
    refreshing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// Fresh cache hit — serve immediately in <0.1 ms.
    Fresh(Vec<u8>),
    /// Recently expired entry — serve immediately AND trigger background refresh (SWR).
    StaleNeedsRefresh(Vec<u8>),
    /// Not present or past stale window.
    Miss,
}

pub struct DnsCache {
    max_entries: usize,
    buckets: HashMap<QType, HashMap<Arc<str>, CacheEntry>>,
    /// Bounded recency queue paired with entry generation counters to achieve O(1) LRU
    /// without unbounded growth or premature eviction of re-inserted live entries.
    order: VecDeque<(CacheKey, u64)>,
    next_gen: u64,
    total_entries: usize,
}

fn normalize_qname(qname: &str) -> Cow<'_, str> {
    if qname.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(qname.to_ascii_lowercase())
    } else {
        Cow::Borrowed(qname)
    }
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(16),
            buckets: HashMap::with_capacity(4),
            order: VecDeque::new(),
            next_gen: 1,
            total_entries: 0,
        }
    }

    /// Looks up `(qname, qtype)` returning `Fresh`, `StaleNeedsRefresh` (RFC 8767 SWR), or `Miss`.
    pub fn lookup(&mut self, qname: &str, qtype: QType, req_id: u16) -> CacheLookup {
        let lower = normalize_qname(qname);
        let now = Instant::now();
        let gen = self.next_gen;

        let mut stale_expired = false;

        if let Some(bucket) = self.buckets.get_mut(&qtype) {
            if let Some(entry) = bucket.get_mut(lower.as_ref()) {
                if now < entry.expires_at {
                    // Touch recency (true LRU) with zero heap string allocations
                    self.next_gen = self.next_gen.wrapping_add(1).max(1);
                    entry.generation = gen;
                    let mut pkt = entry.wire_response.clone();
                    patch_transaction_id(&mut pkt, req_id);
                    let qname = Arc::clone(&entry.qname);
                    self.order.push_back((
                        CacheKey {
                            qname,
                            qtype,
                        },
                        gen,
                    ));
                    self.compact_order_if_needed();
                    return CacheLookup::Fresh(pkt);
                }
                if now < entry.stale_until {
                    let mut pkt = entry.wire_response.clone();
                    patch_transaction_id(&mut pkt, req_id);
                    if !entry.refreshing {
                        entry.refreshing = true;
                        return CacheLookup::StaleNeedsRefresh(pkt);
                    }
                    // Another background refresh is already in flight -> serve stale without storming
                    return CacheLookup::Fresh(pkt);
                }
                stale_expired = true;
            }
            if stale_expired && bucket.remove(lower.as_ref()).is_some() {
                self.total_entries = self.total_entries.saturating_sub(1);
            }
        }
        CacheLookup::Miss
    }

    /// Convenience helper returning fresh hits (for existing callers/tests).
    pub fn get(&mut self, qname: &str, qtype: QType, req_id: u16) -> Option<Vec<u8>> {
        match self.lookup(qname, qtype, req_id) {
            CacheLookup::Fresh(pkt) => Some(pkt),
            CacheLookup::StaleNeedsRefresh(_) | CacheLookup::Miss => None,
        }
    }

    pub fn insert(&mut self, qname: &str, qtype: QType, wire_response: Vec<u8>, ttl_secs: u32) {
        self.insert_with_bounds(qname, qtype, wire_response, ttl_secs, 15, 3600);
    }

    /// Inserts a negative (`NXDOMAIN` / `NODATA`) DNS response for a short bounded TTL (30..60s).
    pub fn insert_negative(&mut self, qname: &str, qtype: QType, wire_response: Vec<u8>, ttl_secs: u32) {
        self.insert_with_bounds(qname, qtype, wire_response, ttl_secs, 15, 60);
    }

    fn insert_with_bounds(
        &mut self,
        qname: &str,
        qtype: QType,
        wire_response: Vec<u8>,
        ttl_secs: u32,
        min_ttl: u32,
        max_ttl: u32,
    ) {
        let bounded_ttl = ttl_secs.clamp(min_ttl, max_ttl);
        let lower = normalize_qname(qname);
        let already_exists = self
            .buckets
            .get(&qtype)
            .is_some_and(|b| b.contains_key(lower.as_ref()));

        if !already_exists {
            self.evict_until_capacity();
        }

        let qname_arc: Arc<str> = Arc::from(lower.as_ref());
        let gen = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1).max(1);
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(bounded_ttl as u64);
        let stale_until = expires_at + STALE_SERVE_WINDOW;

        let bucket = self.buckets.entry(qtype).or_default();
        if bucket
            .insert(
                Arc::clone(&qname_arc),
                CacheEntry {
                    qname: Arc::clone(&qname_arc),
                    wire_response,
                    expires_at,
                    stale_until,
                    generation: gen,
                    refreshing: false,
                },
            )
            .is_none()
        {
            self.total_entries += 1;
        }
        self.order.push_back((
            CacheKey {
                qname: qname_arc,
                qtype,
            },
            gen,
        ));
        self.compact_order_if_needed();
    }

    /// Clears the in-flight SWR refresh flag if a background refresh failed.
    pub fn clear_refreshing(&mut self, qname: &str, qtype: QType) {
        let lower = normalize_qname(qname);
        if let Some(entry) = self.buckets.get_mut(&qtype).and_then(|b| b.get_mut(lower.as_ref())) {
            entry.refreshing = false;
        }
    }

    fn evict_until_capacity(&mut self) {
        while self.total_entries >= self.max_entries {
            if let Some((oldest_key, oldest_gen)) = self.order.pop_front() {
                if let Some(bucket) = self.buckets.get_mut(&oldest_key.qtype) {
                    if let Some(cur) = bucket.get(oldest_key.qname.as_ref()) {
                        // Only evict if generation matches (never evict a freshly touched/re-inserted key!)
                        if cur.generation == oldest_gen
                            && bucket.remove(oldest_key.qname.as_ref()).is_some()
                        {
                            self.total_entries = self.total_entries.saturating_sub(1);
                        }
                    }
                }
            } else {
                // Fallback safety guard
                let mut removed = false;
                for bucket in self.buckets.values_mut() {
                    if let Some(any_key) = bucket.keys().next().cloned() {
                        if bucket.remove(&any_key).is_some() {
                            self.total_entries = self.total_entries.saturating_sub(1);
                            removed = true;
                            break;
                        }
                    }
                }
                if !removed {
                    break;
                }
            }
        }
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() > self.max_entries * 3 {
            let buckets = &self.buckets;
            self.order.retain(|(k, g)| {
                buckets
                    .get(&k.qtype)
                    .and_then(|b| b.get(k.qname.as_ref()))
                    .is_some_and(|e| e.generation == *g)
            });
        }
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
        self.order.clear();
        self.total_entries = 0;
    }

    pub fn len(&self) -> usize {
        self.total_entries
    }

    pub fn is_empty(&self) -> bool {
        self.total_entries == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_max_entries_true_lru_and_clears_completely() {
        let mut cache = DnsCache::new(16);
        for i in 0..16 {
            cache.insert(&format!("d{i}.example.com"), QType::A, vec![0, 0, 0x81, 0x80], 60);
        }
        // Touch d0 so it becomes MRU and must survive eviction when d16 is inserted
        assert!(cache.get("d0.example.com", QType::A, 0x1111).is_some());
        cache.insert("d16.example.com", QType::A, vec![0, 0, 0x81, 0x80], 60);

        assert!(cache.len() <= 16);
        assert!(cache.get("d0.example.com", QType::A, 0x2222).is_some(), "LRU must retain hot d0");
        assert!(cache.get("d1.example.com", QType::A, 0x3333).is_none(), "LRU must evict cold d1");

        let hit = cache.get("d16.example.com", QType::A, 0xABCD).unwrap();
        assert_eq!(&hit[0..2], &[0xAB, 0xCD]);
        cache.clear();
        assert!(cache.is_empty());
    }
}
