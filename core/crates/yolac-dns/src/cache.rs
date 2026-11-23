//! Bounded, strictly RAM-only LRU DNS cache (wiped on stop, zero disk persistence).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::wire::{patch_transaction_id, QType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: QType,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    wire_response: Vec<u8>,
    expires_at: Instant,
}

pub struct DnsCache {
    max_entries: usize,
    map: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<CacheKey>,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(16),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn get(&mut self, qname: &str, qtype: QType, req_id: u16) -> Option<Vec<u8>> {
        let key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype,
        };
        let now = Instant::now();
        if let Some(entry) = self.map.get(&key) {
            if now < entry.expires_at {
                let mut pkt = entry.wire_response.clone();
                patch_transaction_id(&mut pkt, req_id);
                return Some(pkt);
            }
        }
        self.map.remove(&key);
        None
    }

    pub fn insert(&mut self, qname: &str, qtype: QType, wire_response: Vec<u8>, ttl_secs: u32) {
        let bounded_ttl = ttl_secs.clamp(10, 3600);
        let key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype,
        };

        if !self.map.contains_key(&key) {
            while self.map.len() >= self.max_entries {
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(key.clone());
        }

        self.map.insert(
            key,
            CacheEntry {
                wire_response,
                expires_at: Instant::now() + Duration::from_secs(bounded_ttl as u64),
            },
        );
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_max_entries_and_clears_completely() {
        let mut cache = DnsCache::new(16);
        for i in 0..24 {
            cache.insert(&format!("d{i}.example.com"), QType::A, vec![0, 0, 0x81, 0x80], 60);
        }
        assert!(cache.len() <= 16);
        let hit = cache.get("d23.example.com", QType::A, 0xABCD).unwrap();
        assert_eq!(&hit[0..2], &[0xAB, 0xCD]);
        cache.clear();
        assert!(cache.is_empty());
    }
}
