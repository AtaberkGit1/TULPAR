#![forbid(unsafe_code)]
//! TULPAR Local Ad, Tracker & Malware Blocklist Engine.
//!
//! Stores normalized domains in reversed-label order inside a single contiguous
//! byte arena (`Vec<u8>`) indexed by `u32` offsets (`Vec<u32>`).
//! Lookup requires zero heap allocations and matches exact domains and subdomains.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCategory {
    Ads,
    Trackers,
    Malware,
}

impl BlockCategory {
    fn priority(self) -> u8 {
        match self {
            Self::Malware => 0,
            Self::Trackers => 1,
            Self::Ads => 2,
        }
    }
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

/// Contiguous-arena domain blocklist with O(labels * log N) zero-allocation lookup
/// and runtime custom user allowlist / blocklist overlays.
#[derive(Debug, Clone)]
pub struct Blocklist {
    arena: Vec<u8>,
    entries: Vec<EntryMeta>,
    /// Sorted reversed-lowercase allowlist supporting exact + subdomain exemptions with zero heap allocs.
    allowlist_rev: Vec<String>,
    /// Optional user-defined blocked domains (exact + subdomain match).
    custom_block_rev: Vec<String>,
    has_single_label_rule: bool,
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
            allowlist_rev: Vec::new(),
            custom_block_rev: Vec::new(),
            has_single_label_rule: false,
        }
    }

    /// Parses rules in `[category] domain` or `domain` / `0.0.0.0 domain` hosts format.
    /// Rejects IP literals/localhost, prioritizes Malware > Trackers > Ads, and prunes redundant subdomains.
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
                "0.0.0.0" | "127.0.0.1" | "::" | "::1" => (BlockCategory::Ads, parts.next()),
                _ => (BlockCategory::Ads, Some(first)),
            };

            if let Some(dom) = domain {
                if !is_valid_blockable_domain(dom) {
                    continue;
                }
                if let Some(rev) = reverse_domain_to_string(dom) {
                    items.push((rev, cat));
                }
            }
        }

        // Sort by reversed domain, then category priority (Malware < Trackers < Ads) so highest priority wins dedup
        items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.priority().cmp(&b.1.priority())));
        items.dedup_by(|a, b| a.0 == b.0);

        // Prune redundant subdomains whose parent is already listed with equal or higher priority
        let mut pruned: Vec<(String, BlockCategory)> = Vec::with_capacity(items.len());
        for (rev, cat) in items {
            let is_redundant = pruned.last().is_some_and(|(prev_rev, prev_cat)| {
                rev.len() > prev_rev.len()
                    && rev.starts_with(prev_rev.as_str())
                    && rev.as_bytes()[prev_rev.len()] == b'.'
                    && prev_cat.priority() <= cat.priority()
            });
            if !is_redundant {
                pruned.push((rev, cat));
            }
        }

        let total_bytes: usize = pruned.iter().map(|(s, _)| s.len()).sum();
        let mut arena = Vec::with_capacity(total_bytes);
        let mut entries = Vec::with_capacity(pruned.len());
        let mut has_single_label_rule = false;

        for (rev, category) in pruned {
            if rev.len() > u16::MAX as usize {
                continue;
            }
            let Ok(offset) = u32::try_from(arena.len()) else {
                break;
            };
            if !rev.contains('.') {
                has_single_label_rule = true;
            }
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
            allowlist_rev: Vec::new(),
            custom_block_rev: Vec::new(),
            has_single_label_rule,
        }
    }

    /// Adds a local allowlist domain exception (matches exact domain and all its subdomains).
    pub fn add_allowlist(&mut self, domain: &str) {
        if let Some(rev) = reverse_domain_to_string(domain) {
            if let Err(pos) = self.allowlist_rev.binary_search(&rev) {
                self.allowlist_rev.insert(pos, rev);
            }
        }
    }

    /// Adds a local user-blocked domain (matches exact domain and all its subdomains).
    pub fn add_custom_block(&mut self, domain: &str) {
        if !is_valid_blockable_domain(domain) {
            return;
        }
        if let Some(rev) = reverse_domain_to_string(domain) {
            if let Err(pos) = self.custom_block_rev.binary_search(&rev) {
                self.custom_block_rev.insert(pos, rev);
            }
        }
    }

    /// Clones the compiled embedded arena with fresh user-defined allowlist & custom blocklist rules.
    pub fn with_user_rules(&self, custom_allow: &[String], custom_block: &[String]) -> Self {
        let mut out = self.clone();
        out.allowlist_rev.clear();
        out.custom_block_rev.clear();
        for d in custom_allow {
            out.add_allowlist(d);
        }
        for d in custom_block {
            out.add_custom_block(d);
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.custom_block_rev.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.custom_block_rev.is_empty()
    }

    /// Approximate heap memory consumed by the compiled arena + index in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.arena.capacity() + self.entries.capacity() * std::mem::size_of::<EntryMeta>()
    }

    /// Zero-allocation domain check. Matches exact domain or any parent domain rule.
    pub fn check(&self, domain: &str) -> Option<BlockMatch> {
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > 253 || trimmed.starts_with('.') {
            return None;
        }

        let mut stack_buf = [0u8; 256];
        let rev_len = write_reversed_lowercase(trimmed, &mut stack_buf)?;
        let rev = &stack_buf[..rev_len];

        // 1. Zero-allocation allowlist check (exact + any parent allowlist rule)
        if !self.allowlist_rev.is_empty() && match_reversed_sorted(&self.allowlist_rev, rev) {
            return None;
        }

        // 2. Check custom user-blocked domains before compiled embedded arena
        if !self.custom_block_rev.is_empty() && match_reversed_sorted(&self.custom_block_rev, rev) {
            return Some(BlockMatch {
                category: BlockCategory::Ads,
            });
        }

        // 3. Test label prefixes of the reversed domain:
        //    Skip bare 1-label TLD ("com", "net", "tr") unless a single-label rule exists -> 33-50% faster!
        let mut dot_count = 0usize;
        for (idx, &b) in rev.iter().enumerate() {
            if b == b'.' {
                dot_count += 1;
                if dot_count == 1 && !self.has_single_label_rule {
                    continue;
                }
                if let Some(m) = self.lookup_exact_reversed(&rev[..idx]) {
                    return Some(m);
                }
            }
        }
        if dot_count == 0 && !self.has_single_label_rule {
            return None;
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

fn match_reversed_sorted(sorted_rev: &[String], rev: &[u8]) -> bool {
    let exact = |target: &[u8]| {
        sorted_rev
            .binary_search_by(|entry| entry.as_bytes().cmp(target))
            .is_ok()
    };
    for (idx, &b) in rev.iter().enumerate() {
        if b == b'.' && exact(&rev[..idx]) {
            return true;
        }
    }
    exact(rev)
}

fn is_valid_blockable_domain(raw: &str) -> bool {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.starts_with('.') {
        return false;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    !(matches!(
        lower.as_str(),
        "localhost" | "localhost.localdomain" | "local" | "broadcasthost"
    ) || lower.starts_with("ip6-"))
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
        assert!(bl.is_blocked("sub.doubleclick.net"));
        bl.add_allowlist("doubleclick.net");
        assert!(!bl.is_blocked("doubleclick.net"));
        assert!(!bl.is_blocked("sub.doubleclick.net"));
    }

    #[test]
    fn custom_block_and_allow_overlays_compose_cleanly() {
        let base = Blocklist::from_rules_str("ads ads.example.com");
        let overlaid = base.with_user_rules(
            &["ads.example.com".to_string(), "allowed-sub.custom.net".to_string()],
            &["custom.net".to_string(), "telemetry.corp-tracker.org".to_string()],
        );
        // Allowlist overrides both embedded and custom blocklist entries
        assert!(!overlaid.is_blocked("ads.example.com"));
        assert!(!overlaid.is_blocked("allowed-sub.custom.net"));
        // Custom block catches exact and subdomains
        assert!(overlaid.is_blocked("custom.net"));
        assert!(overlaid.is_blocked("metrics.custom.net"));
        assert!(overlaid.is_blocked("telemetry.corp-tracker.org"));
    }
}
