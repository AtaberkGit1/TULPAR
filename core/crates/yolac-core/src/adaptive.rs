//! Adaptive DPI strategy selector & throttling/RST detector.
//!
//! Privacy invariant: destination keys are stored exclusively as salted ephemeral
//! 64-bit hashes in RAM — never plaintext domains or IP addresses.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use yolac_dpi::{DpiStrategy, PlatformCapabilities, QuicPolicy};
use yolac_net::{FlowOutcome, StrategyAdvisor};

#[derive(Debug, Clone, Copy)]
struct DestinationState {
    strategy: DpiStrategy,
    consecutive_failures: u8,
}

pub struct AdaptiveController {
    capabilities: PlatformCapabilities,
    initial_strategy: DpiStrategy,
    salt: u64,
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
        Self::with_quic_policy(capabilities, initial_strategy, max_entries, QuicPolicy::BlockFallbackToTcp)
    }

    pub fn with_quic_policy(
        capabilities: PlatformCapabilities,
        initial_strategy: DpiStrategy,
        max_entries: usize,
        quic_policy: QuicPolicy,
    ) -> Self {
        let effective_initial = if capabilities.supports(initial_strategy) {
            initial_strategy
        } else {
            DpiStrategy::TlsMultiRecordAndTcpSplit
        };
        Self {
            capabilities,
            initial_strategy: effective_initial,
            salt: rand::random(),
            max_entries: max_entries.max(64),
            table: Mutex::new(HashMap::new()),
            quic_throttled: AtomicBool::new(quic_policy == QuicPolicy::BlockFallbackToTcp),
        }
    }

    fn hash_target(&self, dst: SocketAddr, sni: Option<&str>) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.salt.hash(&mut h);
        if let Some(name) = sni {
            name.to_ascii_lowercase().hash(&mut h);
        } else {
            dst.ip().hash(&mut h);
        }
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

    /// Resets ephemeral strategy state on Wi-Fi <-> Cellular transitions.
    pub fn on_network_change(&self) {
        self.clear();
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.table.lock() {
            guard.clear();
        }
    }
}

impl StrategyAdvisor for AdaptiveController {
    fn select_strategy(&self, dst: SocketAddr, sni: Option<&str>) -> DpiStrategy {
        let key = self.hash_target(dst, sni);
        if let Ok(guard) = self.table.lock() {
            if let Some(entry) = guard.get(&key) {
                return entry.strategy;
            }
        }
        self.initial_strategy
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

        match outcome {
            FlowOutcome::Success => {
                if let Some(entry) = guard.get_mut(&key) {
                    entry.consecutive_failures = 0;
                    entry.strategy = used;
                }
            }
            FlowOutcome::ResetOrEofDuringHandshake
            | FlowOutcome::HandshakeTimeout
            | FlowOutcome::ThrottledSlowHandshake => {
                if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                    // Evict an arbitrary bounded subset to prevent unbounded growth
                    if let Some(&evict_key) = guard.keys().next() {
                        guard.remove(&evict_key);
                    }
                }
                let entry = guard.entry(key).or_insert(DestinationState {
                    strategy: used,
                    consecutive_failures: 0,
                });
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if let Some(next) = self.capabilities.escalate(entry.strategy) {
                    entry.strategy = next;
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
