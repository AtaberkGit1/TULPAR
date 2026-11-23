//! Automatic SYN-ACK hop-distance estimation and per-destination TTL calibration.
//!
//! Privacy invariant: destination IPs are stored exclusively as ephemeral per-session
//! salted 64-bit hashes in RAM — never plaintext IP addresses, and zeroed on `clear()`.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::tcp::FakePacketMode;

/// Estimates the network hop distance from an observed inbound IPv4 TTL or IPv6 Hop Limit
/// using standard OS initial TTL defaults (64 for Linux/macOS/iOS/Android, 128 for Windows,
/// 255 for network gear/Solaris).
pub fn estimate_hop_count(observed_ttl: u8) -> u8 {
    if observed_ttl == 0 {
        return 0;
    }
    let initial: u8 = if observed_ttl <= 64 {
        64
    } else if observed_ttl <= 128 {
        128
    } else {
        255
    };
    initial.saturating_sub(observed_ttl)
}

/// Recommends the safest fake-packet evasion mode for a destination whose `SYN-ACK`
/// arrived with `observed_ttl`:
/// - When hop distance is `>= 3`, computes a mid-path TTL (`LowTtl`) so the decoy reaches
///   ISP middleboxes but expires before reaching the destination server.
/// - When hop distance is `<= 2` (local/CDN edge very close to client), automatically falls
///   back to `BadChecksum` so the decoy can never corrupt the server's TCP stream.
pub fn recommend_fake_mode(observed_ttl: u8) -> FakePacketMode {
    let hops = estimate_hop_count(observed_ttl);
    if hops <= 2 {
        return FakePacketMode::BadChecksum;
    }
    let max_safe = hops.saturating_sub(1).max(2);
    let calibrated = (hops / 2).clamp(2, max_safe);
    FakePacketMode::LowTtl(calibrated)
}

/// Ephemeral RAM-only hop calibrator keyed by per-instance randomly-seeded 64-bit hashes.
pub struct TtlCalibrator {
    hash_builder: RandomState,
    max_entries: usize,
    observed_ttls: Mutex<HashMap<u64, u8>>,
}

impl TtlCalibrator {
    pub fn new(max_entries: usize) -> Self {
        Self {
            hash_builder: RandomState::new(),
            max_entries: max_entries.max(64),
            observed_ttls: Mutex::new(HashMap::new()),
        }
    }

    fn hash_ip(&self, ip: IpAddr) -> u64 {
        self.hash_builder.hash_one(ip)
    }

    /// Records the IPv4 TTL / IPv6 Hop Limit observed on an inbound TCP `SYN-ACK` from `peer_ip`.
    pub fn observe_syn_ack(&self, peer_ip: IpAddr, observed_ttl: u8) {
        if observed_ttl == 0 {
            return;
        }
        let key = self.hash_ip(peer_ip);
        if let Ok(mut guard) = self.observed_ttls.lock() {
            if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                if let Some(&evict_key) = guard.keys().next() {
                    guard.remove(&evict_key);
                }
            }
            guard.insert(key, observed_ttl);
        }
    }

    /// Returns the estimated hop distance if a `SYN-ACK` was previously observed for `peer_ip`.
    pub fn estimated_hops(&self, peer_ip: IpAddr) -> Option<u8> {
        let key = self.hash_ip(peer_ip);
        let guard = self.observed_ttls.lock().ok()?;
        guard.get(&key).map(|&ttl| estimate_hop_count(ttl))
    }

    /// Returns a dynamically calibrated `FakePacketMode` for `peer_ip`, or `LowTtl(fallback_ttl)`
    /// if no `SYN-ACK` has been observed yet.
    pub fn recommended_fake_mode(&self, peer_ip: IpAddr, fallback_ttl: u8) -> FakePacketMode {
        let key = self.hash_ip(peer_ip);
        if let Ok(guard) = self.observed_ttls.lock() {
            if let Some(&ttl) = guard.get(&key) {
                return recommend_fake_mode(ttl);
            }
        }
        FakePacketMode::LowTtl(fallback_ttl.max(1))
    }

    pub fn len(&self) -> usize {
        self.observed_ttls.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Wipes all ephemeral hop observations from RAM.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.observed_ttls.lock() {
            guard.clear();
        }
    }
}

impl Default for TtlCalibrator {
    fn default() -> Self {
        Self::new(512)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn estimates_hops_for_standard_initial_ttls() {
        // Linux/BSD initial 64 -> 54 means 10 hops
        assert_eq!(estimate_hop_count(54), 10);
        // Windows initial 128 -> 116 means 12 hops
        assert_eq!(estimate_hop_count(116), 12);
        // Router/Solaris initial 255 -> 247 means 8 hops
        assert_eq!(estimate_hop_count(247), 8);
        // Zero/edge guard
        assert_eq!(estimate_hop_count(0), 0);
        assert_eq!(estimate_hop_count(64), 0);
    }

    #[test]
    fn recommends_calibrated_ttl_and_falls_back_to_bad_checksum_when_close() {
        // 10 hops away -> fake TTL 5 (reaches ISP middlebox, expires well before server)
        assert_eq!(recommend_fake_mode(54), FakePacketMode::LowTtl(5));
        // 4 hops away -> fake TTL 2
        assert_eq!(recommend_fake_mode(60), FakePacketMode::LowTtl(2));
        // 1 or 2 hops away -> BadChecksum instead of risking LowTtl hitting server
        assert_eq!(recommend_fake_mode(63), FakePacketMode::BadChecksum);
        assert_eq!(recommend_fake_mode(62), FakePacketMode::BadChecksum);
    }

    #[test]
    fn calibrator_tracks_peers_respects_bounds_and_clears() {
        let cal = TtlCalibrator::new(64);
        let peer_v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let peer_v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 1));

        // Before observation -> fallback TTL
        assert_eq!(cal.recommended_fake_mode(peer_v4, 3), FakePacketMode::LowTtl(3));

        cal.observe_syn_ack(peer_v4, 52); // 12 hops -> LowTtl(6)
        cal.observe_syn_ack(peer_v6, 63); // 1 hop -> BadChecksum

        assert_eq!(cal.estimated_hops(peer_v4), Some(12));
        assert_eq!(cal.recommended_fake_mode(peer_v4, 3), FakePacketMode::LowTtl(6));
        assert_eq!(cal.recommended_fake_mode(peer_v6, 3), FakePacketMode::BadChecksum);
        assert_eq!(cal.len(), 2);

        // Capacity bound check
        for i in 0..200u32 {
            cal.observe_syn_ack(IpAddr::V4(Ipv4Addr::from(0x0A00_0001 + i)), 56);
        }
        assert!(cal.len() <= 64);

        cal.clear();
        assert!(cal.is_empty());
        assert_eq!(cal.estimated_hops(peer_v4), None);
    }
}
