#![forbid(unsafe_code)]
//! YOLAÇ Local Ad, Tracker & Malware Blocklist Engine.
//!
//! Stores normalized domains in reversed-label order inside a single contiguous
//! byte arena (`Vec<u8>`) indexed by `u32` offsets (`Vec<u32>`).
//! Lookup requires zero heap allocations and matches exact domains and subdomains.

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCategory {
    Ads,
    Trackers,
    Malware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMatch {
    pub category: BlockCategory,
}

#[derive(Debug, Clone)]
struct EntryMeta {
    offset: u32,
    len: u16,
    category: BlockCategory,
}

/// Contiguous-arena domain blocklist with O(labels * log N) zero-allocation lookup.
#[derive(Debug, Clone)]
pub struct Blocklist {
    arena: Vec<u8>,
    entries: Vec<EntryMeta>,
    allowlist: HashSet<String>,
}

const DEFAULT_RAW_LIST: &str = include_str!("../data/default_blocklist.txt");

impl Blocklist {
    /// Loads the embedded open-source curated baseline blocklist.
    pub fn embedded_default() -> Self {
        Self::from_rules_str(DEFAULT_RAW_LIST)
    }

    /// Creates an empty blocklist.
    pub fn empty() -> Self {
        Self {
            arena: Vec::new(),
            entries: Vec::new(),
            allowlist: HashSet::new(),
        }
    }

    /// Parses rules in `[category] domain` or `domain` / `0.0.0.0 domain` hosts format.
    pub fn from_rules_str(text: &str) -> Self {
        let mut items: Vec<(String, BlockCategory)> = Vec::new();

        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let first = match parts.next() {
                Some(p) => p,
                None => continue,
            };

            let (cat, domain) = match first {
                "ads" => (BlockCategory::Ads, parts.next()),
                "trackers" => (BlockCategory::Trackers, parts.next()),
                "malware" => (BlockCategory::Malware, parts.next()),
                "0.0.0.0" | "127.0.0.1" | "::" => (BlockCategory::Ads, parts.next()),
                _ => (BlockCategory::Ads, Some(first)),
            };

            if let Some(dom) = domain {
                if let Some(rev) = reverse_domain_to_string(dom) {
                    items.push((rev, cat));
                }
            }
        }

        items.sort_by(|a, b| a.0.cmp(&b.0));
        items.dedup_by(|a, b| a.0 == b.0);

        let total_bytes: usize = items.iter().map(|(s, _)| s.len()).sum();
        let mut arena = Vec::with_capacity(total_bytes);
        let mut entries = Vec::with_capacity(items.len());

        for (rev, category) in items {
            if rev.len() > u16::MAX as usize {
                continue;
            }
            let offset = arena.len() as u32;
            let len = rev.len() as u16;
            arena.extend_from_slice(rev.as_bytes());
            entries.push(EntryMeta {
                offset,
                len,
                category,
            });
        }

        Self {
            arena,
            entries,
            allowlist: HashSet::new(),
        }
    }

    /// Adds a local allowlist domain exception (normalized lowercase).
    pub fn add_allowlist(&mut self, domain: &str) {
        let normalized = normalize_domain(domain);
        if !normalized.is_empty() {
            self.allowlist.insert(normalized);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Approximate heap memory consumed by the compiled arena + index in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.arena.capacity() + self.entries.capacity() * std::mem::size_of::<EntryMeta>()
    }

    /// Zero-allocation domain check. Matches exact domain or any parent domain rule.
    pub fn check(&self, domain: &str) -> Option<BlockMatch> {
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > 253 {
            return None;
        }

        // Check allowlist (rarely populated; small stack lowercase check)
        if !self.allowlist.is_empty() && self.allowlist.contains(&trimmed.to_ascii_lowercase()) {
            return None;
        }

        let mut stack_buf = [0u8; 256];
        let rev_len = write_reversed_lowercase(trimmed, &mut stack_buf)?;
        let rev = &stack_buf[..rev_len];

        // Test every label prefix of the reversed domain:
        // For "sub.ads.example.com" -> rev is "com.example.ads.sub"
        // Prefixes tested: "com", "com.example", "com.example.ads", "com.example.ads.sub"
        for (idx, &b) in rev.iter().enumerate() {
            if b == b'.' {
                if let Some(m) = self.lookup_exact_reversed(&rev[..idx]) {
                    return Some(m);
                }
            }
        }
        self.lookup_exact_reversed(rev)
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        self.check(domain).is_some()
    }

    fn entry_bytes(&self, meta: &EntryMeta) -> &[u8] {
        let start = meta.offset as usize;
        let end = start + meta.len as usize;
        &self.arena[start..end]
    }

    fn lookup_exact_reversed(&self, rev_target: &[u8]) -> Option<BlockMatch> {
        let idx = self
            .entries
            .binary_search_by(|meta| self.entry_bytes(meta).cmp(rev_target))
            .ok()?;
        Some(BlockMatch {
            category: self.entries[idx].category,
        })
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn write_reversed_lowercase(domain: &str, out: &mut [u8; 256]) -> Option<usize> {
    let bytes = domain.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        return None;
    }
    let mut write_pos = 0usize;
    let mut end = bytes.len();

    while end > 0 {
        let start = bytes[..end]
            .iter()
            .rposition(|&b| b == b'.')
            .map(|p| p + 1)
            .unwrap_or(0);
        let label = &bytes[start..end];
        if label.is_empty() {
            return None;
        }
        if write_pos > 0 {
            out[write_pos] = b'.';
            write_pos += 1;
        }
        for &b in label {
            out[write_pos] = b.to_ascii_lowercase();
            write_pos += 1;
        }
        end = start.saturating_sub(1);
    }

    Some(write_pos)
}

fn reverse_domain_to_string(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_end_matches('.');
    let mut buf = [0u8; 256];
    let len = write_reversed_lowercase(trimmed, &mut buf)?;
    std::str::from_utf8(&buf[..len]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_and_subdomains_only() {
        let list = Blocklist::from_rules_str(
            "ads doubleclick.net\ntrackers analytics.example.com\nmalware bad.site",
        );

        assert!(list.is_blocked("doubleclick.net"));
        assert!(list.is_blocked("ad.doubleclick.net"));
        assert!(list.is_blocked("A.B.DOUBLECLICK.NET."));
        assert!(!list.is_blocked("notdoubleclick.net"));
        assert!(!list.is_blocked("example.com"));
        assert!(list.is_blocked("sub.analytics.example.com"));
        assert_eq!(
            list.check("bad.site"),
            Some(BlockMatch {
                category: BlockCategory::Malware
            })
        );
    }

    #[test]
    fn embedded_blocklist_loads_under_budget() {
        let bl = Blocklist::embedded_default();
        assert!(bl.len() >= 150);
        // Strictly within iOS NetworkExtension memory budget (< 400 KB arena+index)
        assert!(
            bl.memory_bytes() < 400 * 1024,
            "Blocklist memory {} exceeded 400 KB budget",
            bl.memory_bytes()
        );
        assert!(bl.is_blocked("stats.g.doubleclick.net"));

        // Zero-false-positive protection guard on essential services
        for safe_domain in [
            "wikipedia.org",
            "tr.wikipedia.org",
            "eff.org",
            "github.com",
            "api.github.com",
            "turkiye.gov.tr",
            "whatsapp.com",
            "telegram.org",
            "signal.org",
            "google.com",
            "youtube.com",
            "cloudflare.com",
            "yandex.ru",
            "t.co",
        ] {
            assert!(
                !bl.is_blocked(safe_domain),
                "False positive on essential domain: {safe_domain}"
            );
        }
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut bl = Blocklist::from_rules_str("ads doubleclick.net");
        assert!(bl.is_blocked("doubleclick.net"));
        bl.add_allowlist("doubleclick.net");
        assert!(!bl.is_blocked("doubleclick.net"));
    }
}
