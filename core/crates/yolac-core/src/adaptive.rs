//! Adaptive DPI strategy selector & throttling/RST detector.
//!
//! Privacy invariant: destination keys are stored exclusively as salted ephemeral
//! 64-bit SipHash digests in RAM — never plaintext domains or IP addresses.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tulpar_forge::{
    DecoySpec, DecoyTtlMode, ForgePlatformCaps, ForgeRuntime, ForgeStatusSnapshot, MatchProtocol,
    QuicMode, RawActionSpec, SocketActionSpec, VerifyReport,
};
use yolac_dpi::{
    build_benign_fake_client_hello, build_benign_fake_http_request, build_ipv4_tcp_packet,
    build_ipv6_tcp_packet, build_turkey_desync_packets, evade_http_request, parse_ip_packet,
    parse_tcp, DesyncPacket, DpiStrategy, FakePacketMode, HttpEvasionOptions, IpProtocol,
    PlatformCapabilities, QuicPolicy, TtlCalibrator,
};
use yolac_net::{FlowOutcome, StrategyAdvisor};

fn to_forge_caps(caps: PlatformCapabilities) -> ForgePlatformCaps {
    ForgePlatformCaps {
        supports_raw_packets: caps.supports_raw_packets,
        supports_ttl_fake: caps.supports_ttl_fake,
        supports_bad_checksum: caps.supports_bad_checksum,
    }
}

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
    forge: Arc<ForgeRuntime>,
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
            forge: Arc::new(ForgeRuntime::new(to_forge_caps(capabilities))),
        }
    }

    pub fn forge(&self) -> &Arc<ForgeRuntime> {
        &self.forge
    }

    pub fn load_forge_package_bytes(&self, bytes: &[u8]) -> Result<VerifyReport, String> {
        self.forge.load_package_bytes(bytes)
    }

    pub fn load_forge_package_file(&self, path: &Path) -> Result<VerifyReport, String> {
        self.forge.load_package_file(path)
    }

    pub fn unload_forge_package(&self) {
        self.forge.unload();
    }

    pub fn forge_status(&self) -> ForgeStatusSnapshot {
        self.forge.snapshot()
    }

    pub fn select_raw_forge_plan(
        &self,
        proto: MatchProtocol,
        dst_port: u16,
        sni: Option<&str>,
        payload_len: usize,
        is_sensitive: bool,
        retry_count: u8,
    ) -> Option<RawActionSpec> {
        self.forge
            .select_raw_rule(proto, dst_port, sni, payload_len, is_sensitive, retry_count)
    }

    pub fn effective_quic_policy(&self, dst_port: u16) -> QuicPolicy {
        if let Some(qm) = self.forge.select_quic_mode(dst_port) {
            return match qm {
                QuicMode::Allow => QuicPolicy::Allow,
                QuicMode::BlockFallbackTcp => QuicPolicy::BlockFallbackToTcp,
                QuicMode::DesyncTtl(_) => self.recommended_quic_policy(),
            };
        }
        self.recommended_quic_policy()
    }

    pub fn effective_udp_desync(&self, proto: MatchProtocol, dst_port: u16) -> Option<(u8, bool)> {
        self.forge.select_udp_desync(proto, dst_port)
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

    fn forge_socket_plan(
        &self,
        dst: SocketAddr,
        sni: Option<&str>,
        proto: MatchProtocol,
        payload_len: usize,
        retry_count: u8,
    ) -> Option<SocketActionSpec> {
        let is_sensitive = sni
            .map(yolac_dpi::is_sensitive_unblocked_domain)
            .unwrap_or(false);
        self.forge
            .select_socket_rule(proto, dst.port(), sni, payload_len, is_sensitive, retry_count)
    }

    fn report_forge_outcome(&self, dst: SocketAddr, sni: Option<&str>, success: bool) {
        self.forge.report_flow_outcome(dst, sni, success);
    }
}

/// Shared capability-verified raw L3/L4 packet executor for TULPAR Forge (`Windows WinDivert`,
/// `Linux NFQUEUE+Raw`, and `tulpar-forge-lab` L3 simulator) with zero logic duplication.
pub fn execute_raw_forge_tcp(
    raw_packet: &[u8],
    sni_mid: usize,
    host_mid: Option<usize>,
    is_http: bool,
    plan: &RawActionSpec,
    calibrator: &TtlCalibrator,
    dst_ip: IpAddr,
) -> Option<Vec<DesyncPacket>> {
    if plan.passthrough {
        return None;
    }
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    if tcp.payload.len() < 2 {
        return None;
    }

    let source_pkt = if is_http && (plan.http_host_case || plan.http_split_host) {
        if let Some(evaded) = evade_http_request(
            tcp.payload,
            HttpEvasionOptions {
                mix_host_case: plan.http_host_case,
                ..HttpEvasionOptions::default()
            },
        ) {
            if evaded.len() == tcp.payload.len() {
                let tcp_opts = if tcp.header_len > 20 {
                    &ip.payload[20..tcp.header_len]
                } else {
                    &[]
                };
                match (ip.src_ip, ip.dst_ip) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4_tcp_packet(
                        s,
                        d,
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.seq,
                        tcp.ack,
                        tcp.flags,
                        tcp.window,
                        ip.ttl,
                        ip.ip_id.max(1),
                        tcp_opts,
                        &evaded,
                    ),
                    (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6_tcp_packet(
                        s,
                        d,
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.seq,
                        tcp.ack,
                        tcp.flags,
                        tcp.window,
                        ip.ttl,
                        tcp_opts,
                        &evaded,
                    ),
                    _ => raw_packet.to_vec(),
                }
            } else {
                raw_packet.to_vec()
            }
        } else {
            raw_packet.to_vec()
        }
    } else {
        raw_packet.to_vec()
    };

    let payload_len = tcp.payload.len();
    let mut cuts: Vec<usize> = plan
        .tcp_splits
        .iter()
        .filter_map(|c| c.resolve(payload_len, Some(sni_mid), host_mid, None))
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    if cuts.is_empty() && (plan.disorder || !plan.decoys.is_empty()) {
        cuts.push(host_mid.unwrap_or(sni_mid).clamp(1, payload_len - 1));
    }

    let safe_hops_ttl = calibrator
        .estimated_hops(dst_ip)
        .map(|h| (h / 2).clamp(2, 5))
        .unwrap_or(3);
    let fakes: Vec<FakePacketMode> = plan
        .decoys
        .iter()
        .map(|d| match d {
            DecoySpec::BadChecksum => FakePacketMode::BadChecksum,
            DecoySpec::WrongSeq => FakePacketMode::WrongSeq,
            DecoySpec::BadChecksumWrongSeq => FakePacketMode::BadChecksumWrongSeq,
            DecoySpec::LowTtl(DecoyTtlMode::AutoCalibrated) => {
                calibrator.recommended_fake_mode(dst_ip, 3)
            }
            DecoySpec::LowTtl(DecoyTtlMode::Fixed(t)) => FakePacketMode::LowTtl(*t),
            DecoySpec::LowTtlWrongSeq(DecoyTtlMode::AutoCalibrated) => {
                FakePacketMode::LowTtlWrongSeq(safe_hops_ttl)
            }
            DecoySpec::LowTtlWrongSeq(DecoyTtlMode::Fixed(t)) => FakePacketMode::LowTtlWrongSeq(*t),
        })
        .collect();

    let decoy_payload = if is_http {
        build_benign_fake_http_request(&plan.decoy_sni)
    } else {
        build_benign_fake_client_hello(&plan.decoy_sni)
    };

    if cuts.is_empty() {
        return Some(vec![DesyncPacket {
            bytes: source_pkt,
            preserve_bad_tcp_checksum: false,
        }]);
    }

    build_turkey_desync_packets(&source_pkt, &cuts, &fakes, &decoy_payload, plan.disorder)
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
