//! Linux DPI & Anti-Throttling Packet Processing Engine.
//!
//! Shares core Turkey-ISP DPI & UDP desync logic with Windows:
//! - Valid benign `www.iana.org` Fake ClientHello (`LowTtlWrongSeq` + `BadChecksum`) + reverse multi-split
//! - Anti-throttling protection for WhatsApp CDN/media, Instagram, YouTube, X, Discord & Telegram
//! - Real-time `FlowTracker` detecting passive optical DPI forged `TCP RST` & BTK `HTTP 302`,
//!   plus active DPI `RST` and silent-blackhole retransmissions to auto-escalate Stage 1 -> 2 -> 3
//! - Default QUIC UDP/443 blocking + Discord Voice / WhatsApp STUN / Roblox RakNet UDP desync

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tulpar_forge::MatchProtocol;
use yolac_core::{execute_raw_forge_tcp, AdaptiveController, ErrorCode};
use yolac_dns::DnsEngine;
use yolac_dpi::{
    build_benign_fake_client_hello, build_benign_fake_http_request,
    build_disorder_and_fake_packets, build_ipv4_tcp_packet, build_ipv6_tcp_packet,
    build_quic_desync_decoys, build_reassembled_desync_packets, build_turkey_desync_packets,
    build_udp_desync_decoys, clamp_syn_mss, detect_quic_initial, detect_udp_desync_target,
    evade_http_request, inspect_client_hello_needs_reassembly, is_forged_dpi_http_redirect,
    is_forged_passive_dpi_rst, is_sensitive_unblocked_domain, parse_client_hello,
    parse_client_hello_prefix, parse_http_host, parse_ip_packet, parse_tcp, parse_udp,
    plan_tcp_splits, segment_tcp_packet, DpiStrategy, FakePacketMode, HttpEvasionOptions,
    IpProtocol, ParsedIpPacket, ParsedTcp, QuicPolicy, TtlCalibrator,
};
use yolac_net::{is_local_lan_ip, FlowOutcome, StrategyAdvisor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedPacket {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketVerdict {
    Accept,
    Drop,
    /// Drop the original packet in NFQUEUE and inject decoys + real segments via `IPPROTO_RAW`.
    ReplaceWithInjected(Vec<InjectedPacket>),
    /// Inject UDP desync decoys first, then accept the original packet unmodified in NFQUEUE.
    InjectDecoysThenAccept(Vec<InjectedPacket>),
}

#[derive(Debug, Clone)]
struct PendingFlow {
    dst: SocketAddr,
    sni: Option<String>,
    strategy: DpiStrategy,
    used_forge: bool,
    retransmit_count: u8,
    ch_seq: u32,
    ch_seq_end: u32,
    sent_at: Instant,
}

#[derive(Debug, Clone)]
pub enum PqAdvance {
    Waiting,
    Ready {
        template_pkt: Vec<u8>,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct PqStreamBuf {
    start_seq: u32,
    next_seq: u32,
    expected_len: usize,
    template_pkt: Vec<u8>,
    payload: Vec<u8>,
    started: Instant,
}

pub struct FlowTracker {
    hash_builder: RandomState,
    max_entries: usize,
    syn_ack_ttls: Mutex<HashMap<u64, u8>>,
    pending: Mutex<HashMap<u64, PendingFlow>>,
    udp_desynced: Mutex<HashMap<u64, Instant>>,
    pq_streams: Mutex<HashMap<u64, PqStreamBuf>>,
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl FlowTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            hash_builder: RandomState::new(),
            max_entries: max_entries.max(128),
            syn_ack_ttls: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            udp_desynced: Mutex::new(HashMap::new()),
            pq_streams: Mutex::new(HashMap::new()),
        }
    }

    pub fn begin_pq_stream(
        &self,
        local_port: u16,
        dst: SocketAddr,
        seq: u32,
        expected_len: usize,
        template_pkt: &[u8],
        first_payload: &[u8],
    ) -> bool {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let Ok(mut guard) = self.pq_streams.lock() else {
            return false;
        };
        if let Some(prev) = guard.get(&key) {
            if prev.start_seq == seq {
                guard.remove(&key);
                return false;
            }
        }
        guard.retain(|_, v| v.started.elapsed() < Duration::from_millis(120));
        if guard.len() >= 64 {
            if let Some(&evict) = guard.keys().next() {
                guard.remove(&evict);
            }
        }
        guard.insert(
            key,
            PqStreamBuf {
                start_seq: seq,
                next_seq: seq.wrapping_add(first_payload.len() as u32),
                expected_len: expected_len.min(16_389),
                template_pkt: template_pkt.to_vec(),
                payload: first_payload.to_vec(),
                started: Instant::now(),
            },
        );
        true
    }

    pub fn advance_pq_stream(
        &self,
        local_port: u16,
        dst: SocketAddr,
        seq: u32,
        seg: &[u8],
    ) -> Option<PqAdvance> {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let mut guard = self.pq_streams.lock().ok()?;
        let entry = guard.get_mut(&key)?;
        if entry.started.elapsed() > Duration::from_millis(150) || seq != entry.next_seq {
            guard.remove(&key);
            return None;
        }
        let room = entry.expected_len.saturating_sub(entry.payload.len());
        let take = if room > 0 { seg.len().min(room) } else { seg.len() };
        entry.payload.extend_from_slice(&seg[..take]);
        entry.next_seq = entry.next_seq.wrapping_add(seg.len() as u32);
        if entry.payload.len() >= entry.expected_len {
            let finished = guard.remove(&key)?;
            Some(PqAdvance::Ready {
                template_pkt: finished.template_pkt,
                payload: finished.payload,
            })
        } else {
            Some(PqAdvance::Waiting)
        }
    }

    fn flow_key(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> u64 {
        self.hash_builder.hash_one((local_port, remote_ip, remote_port))
    }

    pub fn should_desync_udp_flow(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> bool {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let Ok(mut guard) = self.udp_desynced.lock() else {
            return false;
        };
        let now = Instant::now();
        if let Some(&prev) = guard.get(&key) {
            if now.duration_since(prev) < Duration::from_secs(30) {
                return false;
            }
        }
        if guard.len() >= self.max_entries {
            guard.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(30));
            if guard.len() >= self.max_entries {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
        }
        guard.insert(key, now);
        true
    }

    pub fn observe_syn_ack(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16, ttl: u8) {
        if ttl == 0 {
            return;
        }
        let key = self.flow_key(local_port, remote_ip, remote_port);
        if let Ok(mut guard) = self.syn_ack_ttls.lock() {
            if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
            guard.insert(key, ttl);
        }
    }

    pub fn syn_ack_ttl(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Option<u8> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        self.syn_ack_ttls.lock().ok()?.get(&key).copied()
    }

    pub fn has_pending_flow(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> bool {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        self.pending
            .lock()
            .ok()
            .and_then(|g| g.get(&key).map(|e| e.sent_at.elapsed() < Duration::from_secs(8)))
            .unwrap_or(false)
    }

    pub fn record_client_hello(
        &self,
        local_port: u16,
        dst: SocketAddr,
        sni: Option<String>,
        seq_span: (u32, usize),
        strategy: DpiStrategy,
        used_forge: bool,
    ) -> Option<(DpiStrategy, bool, u8)> {
        let (seq, total_ch_len) = seq_span;
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let mut guard = self.pending.lock().ok()?;

        if let Some(prev) = guard.get_mut(&key) {
            if prev.ch_seq == seq && prev.sent_at.elapsed() >= Duration::from_millis(40) {
                let failed_strategy = prev.strategy;
                let prev_forge = prev.used_forge;
                prev.strategy = strategy;
                prev.used_forge = used_forge;
                prev.sent_at = Instant::now();
                prev.retransmit_count = prev.retransmit_count.saturating_add(1);
                return Some((failed_strategy, prev_forge, prev.retransmit_count));
            }
        }

        if guard.len() >= self.max_entries && !guard.contains_key(&key) {
            let now = Instant::now();
            guard.retain(|_, v| now.duration_since(v.sent_at) < Duration::from_secs(15));
            if guard.len() >= self.max_entries {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
        }

        guard.insert(
            key,
            PendingFlow {
                dst,
                sni,
                strategy,
                used_forge,
                retransmit_count: 0,
                ch_seq: seq,
                ch_seq_end: seq.wrapping_add(total_ch_len as u32),
                sent_at: Instant::now(),
            },
        );
        None
    }

    pub fn update_pending_strategy(
        &self,
        local_port: u16,
        dst: SocketAddr,
        strategy: DpiStrategy,
        used_forge: bool,
    ) {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        if let Ok(mut guard) = self.pending.lock() {
            if let Some(prev) = guard.get_mut(&key) {
                prev.strategy = strategy;
                prev.used_forge = used_forge;
            }
        }
    }

    pub fn check_outbound_progress(
        &self,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        seq: u32,
    ) -> Option<(SocketAddr, Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let mut guard = self.pending.lock().ok()?;
        let entry = guard.get(&key)?;
        let advanced = seq.wrapping_sub(entry.ch_seq_end) < 0x8000_0000;
        if advanced {
            let removed = guard.remove(&key)?;
            return Some((removed.dst, removed.sni, removed.strategy, removed.used_forge));
        }
        if entry.sent_at.elapsed() >= Duration::from_secs(12) {
            guard.remove(&key);
        }
        None
    }

    pub fn confirm_server_hello(
        &self,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Option<(SocketAddr, Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let mut guard = self.pending.lock().ok()?;
        let entry = guard.remove(&key)?;
        Some((entry.dst, entry.sni, entry.strategy, entry.used_forge))
    }

    pub fn take_pending_failure(
        &self,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Option<(SocketAddr, Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let mut guard = self.pending.lock().ok()?;
        let entry = guard.get(&key)?;
        if entry.sent_at.elapsed() > Duration::from_secs(8) {
            guard.remove(&key);
            return None;
        }
        let info = (
            entry.dst,
            entry.sni.clone(),
            entry.strategy,
            entry.used_forge,
        );
        guard.remove(&key);
        Some(info)
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.syn_ack_ttls.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pending.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.udp_desynced.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pq_streams.lock() {
            g.clear();
        }
    }
}

fn rebuild_tcp_payload_packet(
    ip: &ParsedIpPacket<'_>,
    tcp: &ParsedTcp<'_>,
    new_payload: &[u8],
) -> Option<Vec<u8>> {
    let tcp_opts = if tcp.header_len > 20 {
        &ip.payload[20..tcp.header_len]
    } else {
        &[]
    };
    match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Some(build_ipv4_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            tcp.seq,
            tcp.ack,
            tcp.flags,
            tcp.window,
            ip.ttl,
            1,
            tcp_opts,
            new_payload,
        )),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_ipv6_tcp_packet(
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
            new_payload,
        )),
        _ => None,
    }
}

pub fn process_packet(
    raw_packet: &[u8],
    is_outbound: bool,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    flows: &FlowTracker,
) -> PacketVerdict {
    let Some(ip) = parse_ip_packet(raw_packet) else {
        return PacketVerdict::Accept;
    };
    if is_local_lan_ip(ip.src_ip) && is_local_lan_ip(ip.dst_ip) {
        return PacketVerdict::Accept;
    }

    if !is_outbound {
        if ip.protocol != IpProtocol::Tcp {
            return PacketVerdict::Accept;
        }
        let Some(tcp) = parse_tcp(ip.payload) else {
            return PacketVerdict::Accept;
        };

        if tcp.src_port == 443 || tcp.src_port == 80 {
            if (tcp.flags & ParsedTcp::SYN) != 0 && (tcp.flags & ParsedTcp::ACK) != 0 {
                calibrator.observe_syn_ack(ip.src_ip, ip.ttl);
                flows.observe_syn_ack(tcp.dst_port, ip.src_ip, tcp.src_port, ip.ttl);
                return PacketVerdict::Accept;
            }

            let pending_ttl = flows.syn_ack_ttl(tcp.dst_port, ip.src_ip, tcp.src_port);
            if flows.has_pending_flow(tcp.dst_port, ip.src_ip, tcp.src_port)
                && is_forged_passive_dpi_rst(raw_packet, pending_ttl)
            {
                return PacketVerdict::Drop;
            }

            if tcp.src_port == 80
                && !tcp.payload.is_empty()
                && is_forged_dpi_http_redirect(raw_packet)
            {
                return PacketVerdict::Drop;
            }

            if tcp.src_port == 443
                && tcp.payload.len() >= 6
                && tcp.payload[0] == 0x16
                && tcp.payload[1] == 0x03
                && tcp.payload[5] == 0x02
            {
                if let Some((dst, sni, strat, used_forge)) =
                    flows.confirm_server_hello(tcp.dst_port, ip.src_ip, tcp.src_port)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), true);
                    } else {
                        adaptive.report_outcome(dst, sni.as_deref(), strat, FlowOutcome::Success);
                    }
                }
                return PacketVerdict::Accept;
            }

            if (tcp.flags & (ParsedTcp::RST | ParsedTcp::FIN)) != 0 {
                if let Some((dst, sni, failed_strat, used_forge)) =
                    flows.take_pending_failure(tcp.dst_port, ip.src_ip, tcp.src_port)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), false);
                    } else {
                        adaptive.report_outcome(
                            dst,
                            sni.as_deref(),
                            failed_strat,
                            FlowOutcome::ResetOrEofDuringHandshake,
                        );
                    }
                }
            }
        }
        return PacketVerdict::Accept;
    }

    match ip.protocol {
        IpProtocol::Udp => {
            let Some(udp) = parse_udp(ip.payload) else {
                return PacketVerdict::Accept;
            };
            if udp.dst_port == 443 {
                let policy = adaptive.effective_quic_policy(udp.dst_port);
                if policy == QuicPolicy::BlockFallbackToTcp && detect_quic_initial(udp.payload).is_some() {
                    return PacketVerdict::Drop;
                }
                if policy == QuicPolicy::DesyncFragment && detect_quic_initial(udp.payload).is_some() {
                    let fake_ttl = calibrator
                        .estimated_hops(ip.dst_ip)
                        .map(|h| (h / 2).clamp(2, 5))
                        .unwrap_or(3);
                    if let Some(decoys) = build_quic_desync_decoys(raw_packet, fake_ttl) {
                        let injected = decoys
                            .into_iter()
                            .map(|d| InjectedPacket { bytes: d.bytes })
                            .collect();
                        return PacketVerdict::InjectDecoysThenAccept(injected);
                    }
                }
            }
            if !is_local_lan_ip(ip.dst_ip)
                && flows.should_desync_udp_flow(udp.src_port, ip.dst_ip, udp.dst_port)
            {
                if let Some(kind) = detect_udp_desync_target(udp.payload, udp.dst_port) {
                    let match_proto = match kind {
                        yolac_dpi::UdpDesyncKind::RobloxRakNet => MatchProtocol::UdpRakNet,
                        _ => MatchProtocol::UdpStun,
                    };
                    let fake_ttl = if let Some((t, _)) =
                        adaptive.effective_udp_desync(match_proto, udp.dst_port)
                    {
                        t
                    } else {
                        match calibrator.recommended_fake_mode(ip.dst_ip, 3) {
                            FakePacketMode::LowTtl(t) | FakePacketMode::LowTtlWrongSeq(t) => t,
                            _ => 3,
                        }
                    };
                    if let Some(decoys) = build_udp_desync_decoys(raw_packet, fake_ttl) {
                        let injected = decoys
                            .into_iter()
                            .map(|d| InjectedPacket { bytes: d.bytes })
                            .collect();
                        return PacketVerdict::InjectDecoysThenAccept(injected);
                    }
                }
            }
            PacketVerdict::Accept
        }
        IpProtocol::Tcp => {
            let Some(tcp) = parse_tcp(ip.payload) else {
                return PacketVerdict::Accept;
            };

            if dns.is_active_upstream_ip(ip.dst_ip) {
                return PacketVerdict::Accept;
            }
            if tcp.dst_port == 53 || tcp.dst_port == 853 {
                if is_local_lan_ip(ip.dst_ip) {
                    return PacketVerdict::Accept;
                }
                return PacketVerdict::Drop;
            }

            let dst = SocketAddr::new(ip.dst_ip, tcp.dst_port);

            if tcp.is_syn_only()
                && (tcp.dst_port == 443 || tcp.dst_port == 80)
                && !is_local_lan_ip(ip.dst_ip)
            {
                let mss_clamp = adaptive
                    .select_raw_forge_plan(MatchProtocol::Tls, tcp.dst_port, None, 0, false, 0)
                    .and_then(|p| p.syn_mss_clamp)
                    .or_else(|| {
                        (adaptive.select_strategy(dst, None) == DpiStrategy::TurkeyDesyncAggressive)
                            .then_some(536)
                    });
                if let Some(mss) = mss_clamp {
                    if let Some(clamped) = clamp_syn_mss(raw_packet, mss) {
                        return PacketVerdict::ReplaceWithInjected(vec![InjectedPacket {
                            bytes: clamped,
                        }]);
                    }
                }
            }

            if tcp.payload.is_empty()
                || (tcp.flags & ParsedTcp::RST) != 0
                || (tcp.flags & ParsedTcp::SYN) != 0
            {
                return PacketVerdict::Accept;
            }

            if tcp.dst_port != 443 && tcp.dst_port != 80 {
                return PacketVerdict::Accept;
            }

            if tcp.dst_port == 443 {
                if let Some(pq_res) = flows.advance_pq_stream(
                    tcp.src_port,
                    dst,
                    tcp.seq,
                    tcp.payload,
                ) {
                    match pq_res {
                        PqAdvance::Waiting => return PacketVerdict::Drop,
                        PqAdvance::Ready {
                            template_pkt,
                            payload: full_payload,
                        } => {
                            if let (Some(tip), Some(ch)) = (
                                parse_ip_packet(&template_pkt),
                                parse_client_hello(&full_payload),
                            ) {
                                if let Some(ttcp) = parse_tcp(tip.payload) {
                                    return desync_linux_tls_hello(
                                        &template_pkt,
                                        tip.dst_ip,
                                        ttcp.src_port,
                                        dst,
                                        ttcp.seq,
                                        &full_payload,
                                        ch,
                                        adaptive,
                                        calibrator,
                                        flows,
                                        true,
                                    );
                                }
                            }
                            return PacketVerdict::Accept;
                        }
                    }
                }

                if let Some(expected_len) = inspect_client_hello_needs_reassembly(tcp.payload) {
                    let missing_sni = parse_client_hello_prefix(tcp.payload)
                        .map(|c| c.sni.is_none())
                        .unwrap_or(true);
                    if missing_sni
                        && flows.begin_pq_stream(
                            tcp.src_port,
                            dst,
                            tcp.seq,
                            expected_len,
                            raw_packet,
                            tcp.payload,
                        )
                    {
                        return PacketVerdict::Drop;
                    }
                }

                if let Some(ch) = parse_client_hello_prefix(tcp.payload) {
                    return desync_linux_tls_hello(
                        raw_packet,
                        ip.dst_ip,
                        tcp.src_port,
                        dst,
                        tcp.seq,
                        tcp.payload,
                        ch,
                        adaptive,
                        calibrator,
                        flows,
                        false,
                    );
                }

                if let Some((dst, sni, strat, used_forge)) =
                    flows.check_outbound_progress(tcp.src_port, ip.dst_ip, tcp.dst_port, tcp.seq)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), true);
                    } else {
                        adaptive.report_outcome(dst, sni.as_deref(), strat, FlowOutcome::Success);
                    }
                }
                return PacketVerdict::Accept;
            }

            if tcp.dst_port == 80 {
                if let Some(http_info) = parse_http_host(tcp.payload) {
                    let is_sensitive = is_sensitive_unblocked_domain(&http_info.host);
                    let host_mid = http_info.host_range.0
                        + (http_info.host_range.1 - http_info.host_range.0) / 2;
                    if let Some(fplan) = adaptive.select_raw_forge_plan(
                        MatchProtocol::Http,
                        tcp.dst_port,
                        Some(&http_info.host),
                        tcp.payload.len(),
                        is_sensitive,
                        0,
                    ) {
                        if fplan.passthrough {
                            return PacketVerdict::Accept;
                        }
                        if let Some(desync) = execute_raw_forge_tcp(
                            raw_packet,
                            host_mid,
                            Some(host_mid),
                            true,
                            &fplan,
                            calibrator,
                            ip.dst_ip,
                        ) {
                            if desync.len() > 1 {
                                return PacketVerdict::ReplaceWithInjected(
                                    desync
                                        .into_iter()
                                        .map(|d| InjectedPacket { bytes: d.bytes })
                                        .collect(),
                                );
                            }
                        }
                        return PacketVerdict::Accept;
                    }
                    let source_pkt = if let Some(evaded) =
                        evade_http_request(tcp.payload, HttpEvasionOptions::default())
                    {
                        if evaded.len() == tcp.payload.len() {
                            rebuild_tcp_payload_packet(&ip, &tcp, &evaded)
                                .unwrap_or_else(|| raw_packet.to_vec())
                        } else {
                            raw_packet.to_vec()
                        }
                    } else {
                        raw_packet.to_vec()
                    };
                    let split_mid = plan_tcp_splits(tcp.payload)
                        .map(|s| s.split_at)
                        .unwrap_or(2);
                    let fake_http = build_benign_fake_http_request("www.iana.org");
                    let fakes = [
                        FakePacketMode::LowTtlWrongSeq(3),
                        FakePacketMode::BadChecksumWrongSeq,
                    ];
                    if let Some(desync) =
                        build_turkey_desync_packets(&source_pkt, &[2, split_mid], &fakes, &fake_http, true)
                    {
                        if desync.len() > 1 {
                            return PacketVerdict::ReplaceWithInjected(
                                desync
                                    .into_iter()
                                    .map(|d| InjectedPacket { bytes: d.bytes })
                                    .collect(),
                            );
                        }
                    }
                }
            }

            PacketVerdict::Accept
        }
        _ => PacketVerdict::Accept,
    }
}

#[allow(clippy::too_many_arguments)]
fn desync_linux_tls_hello(
    base_pkt: &[u8],
    dst_ip: IpAddr,
    tcp_src_port: u16,
    dst: SocketAddr,
    tcp_seq: u32,
    ch_payload: &[u8],
    ch: yolac_dpi::ClientHelloInfo,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    flows: &FlowTracker,
    is_reassembled: bool,
) -> PacketVerdict {
    let sni_opt = ch.sni.as_deref();
    let is_sensitive = sni_opt.map(is_sensitive_unblocked_domain).unwrap_or(false);
    let mut forge_plan = adaptive.select_raw_forge_plan(
        MatchProtocol::Tls,
        dst.port(),
        sni_opt,
        ch_payload.len(),
        is_sensitive,
        0,
    );
    let mut strategy = if is_sensitive {
        adaptive.select_strategy_with_default(dst, sni_opt, DpiStrategy::Passthrough)
    } else {
        adaptive.select_strategy(dst, sni_opt)
    };

    if let Some((failed_strat, prev_forge, retry_n)) = flows.record_client_hello(
        tcp_src_port,
        dst,
        ch.sni.clone(),
        (tcp_seq, ch.record_total_len.max(ch_payload.len())),
        strategy,
        forge_plan.is_some(),
    ) {
        if prev_forge {
            adaptive.report_forge_outcome(dst, sni_opt, false);
            forge_plan = adaptive.select_raw_forge_plan(
                MatchProtocol::Tls,
                dst.port(),
                sni_opt,
                ch_payload.len(),
                is_sensitive,
                retry_n,
            );
        } else {
            adaptive.report_outcome(dst, sni_opt, failed_strat, FlowOutcome::HandshakeTimeout);
            strategy = adaptive.select_strategy(dst, sni_opt);
        }
        flows.update_pending_strategy(tcp_src_port, dst, strategy, forge_plan.is_some());
    }

    let sni_mid = if let Some((s, e)) = ch.sni_range {
        (s + (e.saturating_sub(s)) / 2).clamp(1, ch_payload.len().saturating_sub(1).max(1))
    } else {
        (ch_payload.len() / 2).max(2)
    };
    let decoy = build_benign_fake_client_hello("www.iana.org");

    let build_segments = |split_points: &[usize],
                          fakes: &[FakePacketMode],
                          reverse: bool|
     -> Option<Vec<yolac_dpi::DesyncPacket>> {
        if is_reassembled {
            build_reassembled_desync_packets(
                base_pkt,
                ch_payload,
                split_points,
                fakes,
                &decoy,
                reverse,
                1380,
            )
        } else {
            build_turkey_desync_packets(base_pkt, split_points, fakes, &decoy, reverse)
        }
    };

    if let Some(ref fplan) = forge_plan {
        if fplan.passthrough {
            return if is_reassembled {
                build_segments(&[ch_payload.len().min(1380)], &[], false)
                    .map(|b| PacketVerdict::ReplaceWithInjected(b.into_iter().map(|d| InjectedPacket { bytes: d.bytes }).collect()))
                    .unwrap_or(PacketVerdict::Accept)
            } else {
                PacketVerdict::Accept
            };
        }
        let built_opt = if is_reassembled {
            build_segments(&[2, sni_mid], &[FakePacketMode::BadChecksum], true)
        } else {
            execute_raw_forge_tcp(base_pkt, sni_mid, None, false, fplan, calibrator, dst_ip)
        };
        if let Some(built) = built_opt {
            if built.len() > 1 {
                return PacketVerdict::ReplaceWithInjected(
                    built.into_iter().map(|d| InjectedPacket { bytes: d.bytes }).collect(),
                );
            }
        }
        return PacketVerdict::Accept;
    }

    if strategy == DpiStrategy::Passthrough {
        return if is_reassembled {
            build_segments(&[ch_payload.len().min(1380)], &[], false)
                .map(|b| PacketVerdict::ReplaceWithInjected(b.into_iter().map(|d| InjectedPacket { bytes: d.bytes }).collect()))
                .unwrap_or(PacketVerdict::Accept)
        } else {
            PacketVerdict::Accept
        };
    }

    let built_opt = match strategy {
        DpiStrategy::TurkeyDesyncAuto => {
            let safe_ttl = calibrator
                .estimated_hops(dst_ip)
                .map(|h| (h / 2).clamp(2, 5))
                .unwrap_or(3);
            let fakes = [
                FakePacketMode::BadChecksum,
                FakePacketMode::LowTtlWrongSeq(safe_ttl),
                FakePacketMode::BadChecksumWrongSeq,
            ];
            build_segments(&[2, sni_mid], &fakes, true)
        }
        DpiStrategy::TurkeyDesyncSuperonline => {
            let fakes = [
                FakePacketMode::LowTtlWrongSeq(2),
                FakePacketMode::LowTtlWrongSeq(5),
                FakePacketMode::BadChecksum,
                FakePacketMode::BadChecksumWrongSeq,
                FakePacketMode::BadTcpTimestamp,
            ];
            build_segments(&[1, sni_mid], &fakes, true)
        }
        DpiStrategy::TurkeyDesyncAggressive => {
            let cal_mode = calibrator.recommended_fake_mode(dst_ip, 3);
            let fakes = [
                cal_mode,
                FakePacketMode::LowTtlWrongSeq(6),
                FakePacketMode::BadChecksum,
                FakePacketMode::BadChecksumWrongSeq,
                FakePacketMode::BadTcpTimestamp,
            ];
            build_segments(&[1, 2, sni_mid], &fakes, true)
        }
        DpiStrategy::TlsRecordSplit
        | DpiStrategy::TcpSniSplit
        | DpiStrategy::TlsAndTcpSplit
        | DpiStrategy::TlsMultiRecordAndTcpSplit
        | DpiStrategy::TcpOobAndTlsSplit
        | DpiStrategy::TlsSmallChunks => {
            if is_reassembled {
                build_segments(&[sni_mid], &[], false)
            } else if let Some((p1, p2)) = segment_tcp_packet(base_pkt, sni_mid) {
                return PacketVerdict::ReplaceWithInjected(vec![
                    InjectedPacket { bytes: p1 },
                    InjectedPacket { bytes: p2 },
                ]);
            } else {
                None
            }
        }
        DpiStrategy::RawDisorder => {
            if is_reassembled {
                build_segments(&[sni_mid], &[], true)
            } else if let Some(plan) = build_disorder_and_fake_packets(base_pkt, sni_mid, None) {
                return PacketVerdict::ReplaceWithInjected(
                    plan.packets.into_iter().map(|bytes| InjectedPacket { bytes }).collect(),
                );
            } else {
                None
            }
        }
        DpiStrategy::RawFakeTtl { ttl } => {
            let mode = calibrator.recommended_fake_mode(dst_ip, ttl);
            build_segments(&[sni_mid], &[mode], true)
        }
        DpiStrategy::RawBadChecksum => {
            build_segments(&[sni_mid], &[FakePacketMode::BadChecksum], true)
        }
        DpiStrategy::Passthrough => None,
    };

    if let Some(built) = built_opt {
        if built.len() > 1 {
            return PacketVerdict::ReplaceWithInjected(
                built.into_iter().map(|d| InjectedPacket { bytes: d.bytes }).collect(),
            );
        }
    }
    PacketVerdict::Accept
}

pub fn run_nfqueue_loop(
    queue_num: u16,
    dns: Arc<DnsEngine>,
    adaptive: Arc<AdaptiveController>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), (ErrorCode, String)> {
    use crate::nfqueue::{NfqSocket, NF_ACCEPT, NF_DROP, NF_INET_LOCAL_OUT};
    use crate::raw_inject::RawPacketInjector;
    use std::sync::atomic::Ordering;

    let nfq = NfqSocket::open(queue_num)
        .map_err(|e| (ErrorCode::PermissionDenied, format!("NFQUEUE ({queue_num}) açılamadı: {e}")))?;
    nfq.set_recv_timeout_ms(300);

    let raw = RawPacketInjector::open()
        .map_err(|e| (ErrorCode::PermissionDenied, format!("Ham paket soketi açılamadı: {e}")))?;

    let calibrator = TtlCalibrator::default();
    let flows = FlowTracker::default();
    let mut buf = vec![0u8; 128 * 1024];

    while !stop_flag.load(Ordering::Relaxed) {
        let pkts = match nfq.recv_packets(&mut buf) {
            Ok(p) => p,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR | libc::ENOBUFS)
                ) =>
            {
                continue;
            }
            Err(e) => {
                return Err((ErrorCode::InternalError, format!("NFQUEUE okuma hatası: {e}")));
            }
        };

        for pkt in pkts {
            let is_outbound = pkt.hook == NF_INET_LOCAL_OUT;
            match process_packet(
                &pkt.payload,
                is_outbound,
                &dns,
                &adaptive,
                &calibrator,
                &flows,
            ) {
                PacketVerdict::Accept => {
                    let _ = nfq.send_verdict(pkt.packet_id, NF_ACCEPT);
                }
                PacketVerdict::Drop => {
                    let _ = nfq.send_verdict(pkt.packet_id, NF_DROP);
                }
                PacketVerdict::ReplaceWithInjected(pkts_out) => {
                    let mut all_ok = true;
                    for seg in &pkts_out {
                        if raw.inject(&seg.bytes).is_err() {
                            all_ok = false;
                            break;
                        }
                    }
                    let _ = nfq.send_verdict(pkt.packet_id, if all_ok { NF_DROP } else { NF_ACCEPT });
                }
                PacketVerdict::InjectDecoysThenAccept(decoys) => {
                    for d in &decoys {
                        let _ = raw.inject(&d.bytes);
                    }
                    let _ = nfq.send_verdict(pkt.packet_id, NF_ACCEPT);
                }
            }
        }
    }

    flows.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use yolac_blocklist::Blocklist;
    use yolac_dns::{default_public_upstreams, DnsConfig};
    use yolac_dpi::{build_ipv4_udp_packet, PlatformCapabilities};

    fn test_engines(initial: DpiStrategy) -> (Arc<DnsEngine>, Arc<AdaptiveController>) {
        let dns = Arc::new(DnsEngine::new(
            DnsConfig {
                upstreams: default_public_upstreams(),
                ..DnsConfig::default()
            },
            Arc::new(Blocklist::embedded_default()),
            None,
        ));
        let adaptive = Arc::new(AdaptiveController::with_quic_policy(
            PlatformCapabilities::LINUX_NFQUEUE,
            initial,
            128,
            QuicPolicy::BlockFallbackToTcp,
        ));
        (dns, adaptive)
    }

    fn sample_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        let sni_b = sni.as_bytes();
        let list_len = 1 + 2 + sni_b.len();
        let sni_ext_len = 2 + list_len;
        let exts_len = 4 + sni_ext_len;
        body.extend_from_slice(&(exts_len as u16).to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        body.extend_from_slice(&(list_len as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(sni_b.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_b);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        rec.push(0x01);
        rec.push(0x00);
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn linux_engine_defeats_tls_throttling_and_protects_edevlet() {
        let (dns, adaptive) = test_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();

        for domain in ["mmg.whatsapp.net", "discord.com", "rr1---sn-x.googlevideo.com"] {
            let ch = sample_tls_client_hello(domain);
            let pkt = build_ipv4_tcp_packet(
                Ipv4Addr::new(192, 168, 1, 20),
                Ipv4Addr::new(162, 159, 130, 234),
                50100,
                443,
                1000,
                2000,
                ParsedTcp::ACK | ParsedTcp::PSH,
                65535,
                64,
                1,
                &[],
                &ch,
            );
            match process_packet(&pkt, true, &dns, &adaptive, &calibrator, &flows) {
                PacketVerdict::ReplaceWithInjected(segs) => assert_eq!(segs.len(), 6),
                other => panic!("Expected ReplaceWithInjected for {domain}, got {other:?}"),
            }
        }

        let gov_ch = sample_tls_client_hello("www.turkiye.gov.tr");
        let gov_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(212, 174, 15, 20),
            50101,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            2,
            &[],
            &gov_ch,
        );
        assert_eq!(
            process_packet(&gov_pkt, true, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Accept
        );
    }

    #[test]
    fn linux_engine_drops_quic_btk302_forged_rst_and_emits_udp_decoys() {
        let (dns, adaptive) = test_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();

        let mut quic = vec![0xC3u8; 1200];
        quic[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        let quic_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(142, 250, 187, 174),
            51000,
            443,
            64,
            &quic,
        );
        assert_eq!(
            process_packet(&quic_pkt, true, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Drop
        );

        let btk = b"HTTP/1.1 302 Found\r\nLocation: http://195.175.254.2/bilgi\r\n\r\n";
        let btk_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(192, 168, 1, 20),
            80,
            51001,
            100,
            200,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            54,
            0,
            &[],
            btk,
        );
        assert_eq!(
            process_packet(&btk_pkt, false, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Drop
        );

        let mut stun = vec![0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let stun_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(66, 22, 240, 10),
            52000,
            50005,
            64,
            &stun,
        );
        match process_packet(&stun_pkt, true, &dns, &adaptive, &calibrator, &flows) {
            PacketVerdict::InjectDecoysThenAccept(d) => assert_eq!(d.len(), 2),
            other => panic!("Expected InjectDecoysThenAccept, got {other:?}"),
        }
    }

    #[test]
    fn linux_engine_executes_forge_package_without_recompiling() {
        let (dns, adaptive) = test_engines(DpiStrategy::Passthrough);
        let pkg = include_bytes!("../../../forge/examples/turkey_balanced.tulpar");
        adaptive.load_forge_package_bytes(pkg).expect("valid .tulpar loads on Linux");

        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();
        let ch = sample_tls_client_hello("blocked.linux-forge.test");
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(93, 184, 216, 34),
            53000,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &ch,
        );
        match process_packet(&pkt, true, &dns, &adaptive, &calibrator, &flows) {
            PacketVerdict::ReplaceWithInjected(pkts) => {
                assert!(pkts.len() >= 4, "Forge turkey-balanced decoys+splits must emit >=4 packets");
            }
            other => panic!("Expected Forge ReplaceWithInjected verdict, got {other:?}"),
        }
    }

    #[test]
    fn reassembles_pq_client_hello_and_handles_quic_desync_and_port_853() {
        let (dns, adaptive) = test_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();

        let sni = "pq.youtube.com";
        let sni_bytes = sni.as_bytes();
        let ks_len = 1380usize;
        let name_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + name_entry_len;
        let exts_len = 4 + ks_len + 4 + sni_ext_len;
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x44u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts_len as u16).to_be_bytes());
        body.extend_from_slice(&0x0033u16.to_be_bytes());
        body.extend_from_slice(&(ks_len as u16).to_be_bytes());
        body.extend_from_slice(&vec![0x66u8; ks_len]);
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);
        let hs_len = body.len();
        let mut full_ch = vec![0x16, 0x03, 0x01];
        full_ch.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        full_ch.push(0x01);
        full_ch.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        full_ch.extend_from_slice(&body);

        let split = 1400usize;
        let seg1 = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(142, 250, 187, 174),
            54100,
            443,
            20_000,
            1_000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &full_ch[..split],
        );
        let seg2 = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(142, 250, 187, 174),
            54100,
            443,
            20_000 + split as u32,
            1_000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            2,
            &[],
            &full_ch[split..],
        );
        assert_eq!(
            process_packet(&seg1, true, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Drop
        );
        match process_packet(&seg2, true, &dns, &adaptive, &calibrator, &flows) {
            PacketVerdict::ReplaceWithInjected(pkts) => {
                assert!(pkts.len() >= 5);
                for p in &pkts {
                    assert!(p.bytes.len() <= 1460);
                }
            }
            other => panic!("Expected ReplaceWithInjected for PQ Seg 2, got {other:?}"),
        }

        // QuicPolicy::DesyncFragment injects QUIC decoys before accepting real UDP/443
        adaptive.set_quic_policy(QuicPolicy::DesyncFragment);
        let mut quic = vec![0xC3u8; 1200];
        quic[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        let quic_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(142, 250, 187, 174),
            54101,
            443,
            64,
            &quic,
        );
        match process_packet(&quic_pkt, true, &dns, &adaptive, &calibrator, &flows) {
            PacketVerdict::InjectDecoysThenAccept(d) => assert_eq!(d.len(), 2),
            other => panic!("Expected InjectDecoysThenAccept, got {other:?}"),
        }

        // Rogue 853 dropped while active bootstrap DoH/DoT IP (1.1.1.1) passes
        let dot_rogue = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(198, 51, 100, 53),
            54102,
            853,
            1,
            1,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            &[],
        );
        assert_eq!(
            process_packet(&dot_rogue, true, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Drop
        );
        let dot_bootstrap = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(1, 1, 1, 1),
            54103,
            853,
            1,
            1,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            &[],
        );
        assert_eq!(
            process_packet(&dot_bootstrap, true, &dns, &adaptive, &calibrator, &flows),
            PacketVerdict::Accept
        );
    }
}
