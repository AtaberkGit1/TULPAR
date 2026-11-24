//! Adaptive DPI strategy selector & throttling/RST detector.
//!
//! Privacy invariant: destination keys are stored exclusively as salted ephemeral
//! 64-bit SipHash digests in RAM — never plaintext domains or IP addresses.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use yolac_dpi::{DpiStrategy, PlatformCapabilities, QuicPolicy};
use yolac_net::{FlowOutcome, StrategyAdvisor};

const ENTRY_TTL: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Clone, Copy)]
struct DestinationState {
    strategy: DpiStrategy,
    consecutive_failures: u8,
    last_updated: Instant,
}

pub struct AdaptiveController {
    capabilities: PlatformCapabilities,
    initial_strategy: DpiStrategy,
    default_quic_blocked: bool,
    hash_builder: Mutex<RandomState>,
    max_entries: usize,
    /// Protected by std::sync::Mutex (critical sections are tiny O(1) map lookups).
    table: Mutex<HashMap<u64, DestinationState>>,
    quic_throttled: AtomicBool,
}

impl AdaptiveController {
    pub fn new(
        capabilities: PlatformCapabilities,
        initial_strategy: DpiStrategy,
        max_entries: usize,
    ) -> Self {
        Self::with_quic_policy(
            capabilities,
            initial_strategy,
            max_entries,
            QuicPolicy::BlockFallbackToTcp,
        )
    }

    pub fn with_quic_policy(
        capabilities: PlatformCapabilities,
        initial_strategy: DpiStrategy,
        max_entries: usize,
        quic_policy: QuicPolicy,
    ) -> Self {
        let effective_initial = if capabilities.supports(initial_strategy) {
            initial_strategy
        } else if capabilities.supports_raw_packets {
            DpiStrategy::RawDisorder
        } else {
            DpiStrategy::TlsMultiRecordAndTcpSplit
        };
        let default_quic_blocked = quic_policy == QuicPolicy::BlockFallbackToTcp;
        Self {
            capabilities,
            initial_strategy: effective_initial,
            default_quic_blocked,
            hash_builder: Mutex::new(RandomState::new()),
            max_entries: max_entries.max(64),
            table: Mutex::new(HashMap::new()),
            quic_throttled: AtomicBool::new(default_quic_blocked),
        }
    }

    fn hash_target(&self, dst: SocketAddr, sni: Option<&str>) -> u64 {
        let mut h = self
            .hash_builder
            .lock()
            .map(|b| b.build_hasher())
            .unwrap_or_else(|_| RandomState::new().build_hasher());
        if let Some(raw) = sni {
            let trimmed = raw.trim().trim_end_matches('.');
            if !trimmed.is_empty() {
                h.write_u8(0x01); // domain separation: SNI key
                for &b in trimmed.as_bytes() {
                    h.write_u8(b.to_ascii_lowercase());
                }
                dst.port().hash(&mut h);
                return h.finish();
            }
        }
        h.write_u8(0x02); // domain separation: IP key
        dst.ip().hash(&mut h);
        dst.port().hash(&mut h);
        h.finish()
    }

    pub fn report_quic_throttled(&self) {
        self.quic_throttled.store(true, Ordering::Relaxed);
    }

    pub fn recommended_quic_policy(&self) -> QuicPolicy {
        if self.quic_throttled.load(Ordering::Relaxed) {
            QuicPolicy::BlockFallbackToTcp
        } else {
            QuicPolicy::Allow
        }
    }

    pub fn escalated_entries_count(&self) -> usize {
        self.table.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Resets ephemeral strategy state and restores default QUIC policy on Wi-Fi <-> Cellular transitions.
    pub fn on_network_change(&self) {
        self.clear();
        self.quic_throttled
            .store(self.default_quic_blocked, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.table.lock() {
            guard.clear();
        }
        if let Ok(mut hb) = self.hash_builder.lock() {
            *hb = RandomState::new();
        }
    }
}

impl StrategyAdvisor for AdaptiveController {
    fn select_strategy(&self, dst: SocketAddr, sni: Option<&str>) -> DpiStrategy {
        self.select_strategy_with_default(dst, sni, self.initial_strategy)
    }

    fn select_strategy_with_default(
        &self,
        dst: SocketAddr,
        sni: Option<&str>,
        default_if_unseen: DpiStrategy,
    ) -> DpiStrategy {
        let key = self.hash_target(dst, sni);
        if let Ok(mut guard) = self.table.lock() {
            if let Some(entry) = guard.get(&key).copied() {
                if entry.last_updated.elapsed() < ENTRY_TTL {
                    return entry.strategy;
                }
                guard.remove(&key);
            }
        }
        default_if_unseen
    }

    fn report_outcome(
        &self,
        dst: SocketAddr,
        sni: Option<&str>,
        used: DpiStrategy,
        outcome: FlowOutcome,
    ) {
        let key = self.hash_target(dst, sni);
        let Ok(mut guard) = self.table.lock() else {
            return;
        };
        let now = Instant::now();

        match outcome {
            FlowOutcome::Success => {
                if let Some(entry) = guard.get_mut(&key) {
                    // Only reset failures if this matches the currently active strategy
                    // (do NOT let a slower in-flight socket overwrite a newer escalated strategy!)
                    if entry.strategy == used {
                        entry.consecutive_failures = 0;
                        entry.last_updated = now;
                    }
                }
            }
            FlowOutcome::ResetOrEofDuringHandshake
            | FlowOutcome::HandshakeTimeout
            | FlowOutcome::ThrottledSlowHandshake => {
                if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                    guard.retain(|_, v| now.duration_since(v.last_updated) < ENTRY_TTL);
                    if guard.len() >= self.max_entries {
                        if let Some(oldest_key) = guard
                            .iter()
                            .min_by_key(|(_, v)| v.last_updated)
                            .map(|(&k, _)| k)
                        {
                            guard.remove(&oldest_key);
                        }
                    }
                }
                let entry = guard.entry(key).or_insert(DestinationState {
                    strategy: used,
                    consecutive_failures: 0,
                    last_updated: now,
                });
                // Guard against concurrent escalation storms: only escalate if the failing flow
                // actually used the CURRENT strategy stored for this destination!
                if entry.strategy != used {
                    return;
                }
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                entry.last_updated = now;
                if let Some(next) = self.capabilities.escalate(entry.strategy) {
                    entry.strategy = next;
                    entry.consecutive_failures = 0;
                } else if entry.strategy == DpiStrategy::TcpOobAndTlsSplit
                    && entry.consecutive_failures >= 3
                {
                    // Avoid locking forever on MSG_OOB if a strict L7 proxy rejects OOB bytes
                    entry.strategy = DpiStrategy::TlsMultiRecordAndTcpSplit;
                    entry.consecutive_failures = 0;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn escalates_strategy_on_dpi_rst_and_clears_on_network_change() {
        let ctrl = AdaptiveController::new(
            PlatformCapabilities::MOBILE_SANDBOX,
            DpiStrategy::Passthrough,
            128,
        );
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        assert_eq!(ctrl.select_strategy(dst, Some("blocked.test")), DpiStrategy::Passthrough);

        ctrl.report_outcome(
            dst,
            Some("blocked.test"),
            DpiStrategy::Passthrough,
            FlowOutcome::ResetOrEofDuringHandshake,
        );
        assert_eq!(
            ctrl.select_strategy(dst, Some("blocked.test")),
            DpiStrategy::TlsRecordSplit
        );

        // Concurrent stale Passthrough failure must NOT double-escalate past TlsRecordSplit!
        ctrl.report_outcome(
            dst,
            Some("blocked.test"),
            DpiStrategy::Passthrough,
            FlowOutcome::ResetOrEofDuringHandshake,
        );
        assert_eq!(
            ctrl.select_strategy(dst, Some("blocked.test")),
            DpiStrategy::TlsRecordSplit
        );

        ctrl.report_outcome(
            dst,
            Some("blocked.test"),
            DpiStrategy::TlsRecordSplit,
            FlowOutcome::ResetOrEofDuringHandshake,
        );
        assert_eq!(
            ctrl.select_strategy(dst, Some("blocked.test")),
            DpiStrategy::TcpSniSplit
        );

        ctrl.on_network_change();
        assert_eq!(ctrl.select_strategy(dst, Some("blocked.test")), DpiStrategy::Passthrough);
    }
}
