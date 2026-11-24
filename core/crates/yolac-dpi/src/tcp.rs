//! TCP payload segmentation, out-of-order (disorder), and fake-packet construction.

use std::net::IpAddr;

use crate::fake_hello::build_benign_fake_client_hello;
use crate::http::parse_http_host;
use crate::packet::{
    build_ipv4_tcp_packet, build_ipv6_tcp_packet, parse_ip_packet, parse_tcp, IpProtocol, ParsedTcp,
};
use crate::tls::parse_client_hello_prefix;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSplitPlan {
    /// Split index inside the application payload (0 < split_at < payload_len).
    pub split_at: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePacketMode {
    /// Fake packet with low IP TTL/HopLimit so middlebox sees it, server never receives it.
    LowTtl(u8),
    /// Fake packet with intentionally corrupted TCP checksum so server kernel discards it.
    BadChecksum,
    /// Fake packet with shifted TCP SEQ (-10000) and ACK (-66000) (`--wrong-seq`).
    WrongSeq,
    /// Combines Low-TTL with `--wrong-seq` so both home NAT and real servers safely reject it while DPI desyncs.
    LowTtlWrongSeq(u8),
    /// Combines intentionally corrupted TCP checksum with `--wrong-seq`.
    BadChecksumWrongSeq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesyncPacket {
    pub bytes: Vec<u8>,
    /// True when TCP checksum is intentionally corrupted and OS NIC offload must NOT repair it.
    pub preserve_bad_tcp_checksum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacketPlan {
    /// Ordered sequence of raw L3 packets to inject onto the wire.
    pub packets: Vec<Vec<u8>>,
}

/// Computes an optimal TCP payload split point inside the SNI (TLS) or Host header (HTTP).
pub fn plan_tcp_splits(payload: &[u8]) -> Option<TcpSplitPlan> {
    if payload.len() < 4 {
        return None;
    }

    if let Some(ch) = parse_client_hello_prefix(payload) {
        if let Some((start, end)) = ch.sni_range {
            let mid = start + (end.saturating_sub(start)) / 2;
            let split_at = mid.clamp(1, payload.len() - 1);
            return Some(TcpSplitPlan { split_at });
        }
        return Some(TcpSplitPlan {
            split_at: (payload.len() / 2).clamp(1, payload.len() - 1),
        });
    }

    if let Some(http) = parse_http_host(payload) {
        let mid = http.host_range.0 + (http.host_range.1 - http.host_range.0) / 2;
        return Some(TcpSplitPlan {
            split_at: mid.clamp(1, payload.len() - 1),
        });
    }

    None
}

/// Segments a raw IPv4/IPv6 TCP packet into two valid L3 packets at `split_at` in the TCP payload.
pub fn segment_tcp_packet(raw_packet: &[u8], split_at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    if tcp.payload.len() < 2 || split_at == 0 || split_at >= tcp.payload.len() {
        return None;
    }

    let tcp_options = if tcp.header_len > 20 {
        &ip.payload[20..tcp.header_len]
    } else {
        &[]
    };

    let part1 = &tcp.payload[..split_at];
    let part2 = &tcp.payload[split_at..];

    // Clear PSH/FIN on first segment if needed, keep ACK; preserve original flags on last segment
    let flags1 = tcp.flags & !(ParsedTcp::FIN);
    let flags2 = tcp.flags;
    let seq1 = tcp.seq;
    let seq2 = tcp.seq.wrapping_add(split_at as u32);

    let (pkt1, pkt2) = match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            build_ipv4_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq1,
                tcp.ack,
                flags1,
                tcp.window,
                ip.ttl,
                1,
                tcp_options,
                part1,
            ),
            build_ipv4_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq2,
                tcp.ack,
                flags2,
                tcp.window,
                ip.ttl,
                2,
                tcp_options,
                part2,
            ),
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            build_ipv6_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq1,
                tcp.ack,
                flags1,
                tcp.window,
                ip.ttl,
                tcp_options,
                part1,
            ),
            build_ipv6_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq2,
                tcp.ack,
                flags2,
                tcp.window,
                ip.ttl,
                tcp_options,
                part2,
            ),
        ),
        _ => return None,
    };

    Some((pkt1, pkt2))
}

/// Segments a raw IPv4/IPv6 TCP packet into multiple valid L3 packets at sorted `split_points`.
pub fn segment_tcp_packet_multi(raw_packet: &[u8], split_points: &[usize]) -> Option<Vec<Vec<u8>>> {
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    if tcp.payload.len() < 2 {
        return None;
    }

    let mut cuts: Vec<usize> = split_points
        .iter()
        .copied()
        .filter(|&p| p > 0 && p < tcp.payload.len())
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    if cuts.is_empty() {
        return None;
    }

    let tcp_options = if tcp.header_len > 20 {
        &ip.payload[20..tcp.header_len]
    } else {
        &[]
    };

    let mut boundaries = Vec::with_capacity(cuts.len() + 2);
    boundaries.push(0usize);
    boundaries.extend_from_slice(&cuts);
    boundaries.push(tcp.payload.len());

    let seg_count = boundaries.len() - 1;
    let mut out = Vec::with_capacity(seg_count);

    for i in 0..seg_count {
        let start = boundaries[i];
        let end = boundaries[i + 1];
        let part = &tcp.payload[start..end];
        let is_last = i + 1 == seg_count;
        let flags = if is_last {
            tcp.flags
        } else {
            tcp.flags & !ParsedTcp::FIN
        };
        let seq = tcp.seq.wrapping_add(start as u32);
        let ip_id = 10u16.wrapping_add(i as u16);

        let pkt = match (ip.src_ip, ip.dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq,
                tcp.ack,
                flags,
                tcp.window,
                ip.ttl,
                ip_id,
                tcp_options,
                part,
            ),
            (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6_tcp_packet(
                s,
                d,
                tcp.src_port,
                tcp.dst_port,
                seq,
                tcp.ack,
                flags,
                tcp.window,
                ip.ttl,
                tcp_options,
                part,
            ),
            _ => return None,
        };
        out.push(pkt);
    }

    Some(out)
}

fn build_single_fake_packet(
    ip: &crate::packet::ParsedIpPacket<'_>,
    tcp: &ParsedTcp<'_>,
    mode: FakePacketMode,
    decoy_payload: &[u8],
    ip_id: u16,
) -> Option<DesyncPacket> {
    let ttl = match mode {
        FakePacketMode::LowTtl(t) | FakePacketMode::LowTtlWrongSeq(t) => t.max(1),
        FakePacketMode::BadChecksum | FakePacketMode::WrongSeq | FakePacketMode::BadChecksumWrongSeq => {
            ip.ttl
        }
    };
    let (seq, ack) = match mode {
        FakePacketMode::WrongSeq
        | FakePacketMode::LowTtlWrongSeq(_)
        | FakePacketMode::BadChecksumWrongSeq => (
            tcp.seq.wrapping_sub(10_000),
            tcp.ack.wrapping_sub(66_000),
        ),
        FakePacketMode::LowTtl(_) | FakePacketMode::BadChecksum => (tcp.seq, tcp.ack),
    };

    let mut fake_pkt = match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            seq,
            ack,
            tcp.flags,
            tcp.window,
            ttl,
            ip_id,
            &[],
            decoy_payload,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            seq,
            ack,
            tcp.flags,
            tcp.window,
            ttl,
            &[],
            decoy_payload,
        ),
        _ => return None,
    };

    let bad_csum = matches!(
        mode,
        FakePacketMode::BadChecksum | FakePacketMode::BadChecksumWrongSeq
    );
    if bad_csum {
        let l4_off = if ip.version == 4 { 20 } else { 40 };
        fake_pkt[l4_off + 16] ^= 0xFF;
        fake_pkt[l4_off + 17] ^= 0x5A;
    }

    Some(DesyncPacket {
        bytes: fake_pkt,
        preserve_bad_tcp_checksum: bad_csum,
    })
}

/// Builds a full Turkey-ISP-grade DPI desynchronization burst:
/// 1. One or more valid benign fake decoy packets (`LowTtl`, `WrongSeq`, `BadChecksum`)
/// 2. Multi-point segmented real payload sent in reverse/disorder order (`seg[1..]`, then `seg[0]`)
///    so stateful DPI fails to match SNI/Host while the destination server reassembles identically.
pub fn build_turkey_desync_packets(
    raw_packet: &[u8],
    split_points: &[usize],
    fake_modes: &[FakePacketMode],
    fake_payload: &[u8],
    reverse_first_segment: bool,
) -> Option<Vec<DesyncPacket>> {
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    let mut segs = segment_tcp_packet_multi(raw_packet, split_points)?;

    let mut out = Vec::with_capacity(fake_modes.len() + segs.len());
    for (idx, &mode) in fake_modes.iter().enumerate() {
        if let Some(fake) = build_single_fake_packet(
            &ip,
            &tcp,
            mode,
            fake_payload,
            90u16.wrapping_add(idx as u16),
        ) {
            out.push(fake);
        }
    }

    if reverse_first_segment && segs.len() >= 2 {
        // Transmit tail segments BEFORE the 1-2 byte leading segment (`--reverse-frag` / disorder)
        let first = segs.remove(0);
        for seg in segs {
            out.push(DesyncPacket {
                bytes: seg,
                preserve_bad_tcp_checksum: false,
            });
        }
        out.push(DesyncPacket {
            bytes: first,
            preserve_bad_tcp_checksum: false,
        });
    } else {
        for seg in segs {
            out.push(DesyncPacket {
                bytes: seg,
                preserve_bad_tcp_checksum: false,
            });
        }
    }

    Some(out)
}

/// Detects forged inbound `TCP RST` packets injected by passive optical-splitter DPI boxes
/// (e.g. Türk Telekom / Vodafone Procera / Sandvine):
/// - IPv4 `IP.ID == 0x0000` or `0x0001` (classic passive DPI generator fingerprint)
/// - OR inbound TTL differs by `>= 3` hops from the real server's observed `SYN-ACK` TTL.
pub fn is_forged_passive_dpi_rst(raw_packet: &[u8], expected_syn_ack_ttl: Option<u8>) -> bool {
    let Some(ip) = parse_ip_packet(raw_packet) else {
        return false;
    };
    if ip.protocol != IpProtocol::Tcp {
        return false;
    }
    let Some(tcp) = parse_tcp(ip.payload) else {
        return false;
    };
    if (tcp.flags & ParsedTcp::RST) == 0 {
        return false;
    }

    if ip.version == 4 && raw_packet.len() >= 6 {
        let ip_id = u16::from_be_bytes([raw_packet[4], raw_packet[5]]);
        if ip_id == 0 || ip_id == 1 {
            return true;
        }
    }

    if let Some(syn_ttl) = expected_syn_ack_ttl {
        if syn_ttl > 0 && ip.ttl > 0 && syn_ttl.abs_diff(ip.ttl) >= 3 {
            return true;
        }
    }

    false
}

/// Detects forged inbound plaintext HTTP 302/307 ISP censorship redirect responses (e.g. BTK block page).
pub fn is_forged_dpi_http_redirect(raw_packet: &[u8]) -> bool {
    let Some(ip) = parse_ip_packet(raw_packet) else {
        return false;
    };
    if ip.protocol != IpProtocol::Tcp {
        return false;
    }
    let Some(tcp) = parse_tcp(ip.payload) else {
        return false;
    };
    if tcp.payload.len() < 16 || !tcp.payload.starts_with(b"HTTP/1.") {
        return false;
    }
    let text = String::from_utf8_lossy(tcp.payload).to_ascii_lowercase();
    let is_redirect = text.starts_with("http/1.1 302")
        || text.starts_with("http/1.0 302")
        || text.starts_with("http/1.1 307");
    if !is_redirect {
        return false;
    }
    text.contains("195.175.254.2")
        || text.contains("btk.gov.tr")
        || text.contains("tib.gov.tr")
        || text.contains("turktelekom")
        || text.contains("superonline")
        || text.contains("vodafone")
        || text.contains("engelliweb")
}

/// Builds an out-of-order (disorder) + optional fake packet transmission plan for raw packet engines (Windows).
pub fn build_disorder_and_fake_packets(
    raw_packet: &[u8],
    split_at: usize,
    fake: Option<FakePacketMode>,
) -> Option<RawPacketPlan> {
    let fake_slice: Vec<FakePacketMode> = fake.into_iter().collect();
    let decoy = build_benign_fake_client_hello("www.iana.org");
    let desync = build_turkey_desync_packets(raw_packet, &[split_at], &fake_slice, &decoy, true)?;
    Some(RawPacketPlan {
        packets: desync.into_iter().map(|d| d.bytes).collect(),
    })
}

/// Clamps the TCP Maximum Segment Size (MSS, option kind 2) inside an outbound TCP `SYN`
/// packet to at most `max_mss` (floor 256) and recomputes valid IPv4/TCP RFC 1071 checksums.
///
/// Smaller MSS during the TLS handshake encourages the server to send smaller response
/// segments, disrupting DPI devices that inspect or inject against ServerHello / certificates.
/// Returns `None` if the packet is not a `SYN` or already has `MSS <= max_mss`.
pub fn clamp_syn_mss(raw_packet: &[u8], max_mss: u16) -> Option<Vec<u8>> {
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    if !tcp.is_syn_only() || tcp.header_len <= 20 {
        return None;
    }

    let safe_mss = max_mss.max(256);
    let mut opts = ip.payload[20..tcp.header_len].to_vec();
    let mut pos = 0usize;
    let mut modified = false;

    while pos < opts.len() {
        let kind = opts[pos];
        if kind == 0 {
            break; // End of Option List
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        if pos + 1 >= opts.len() {
            break;
        }
        let len = opts[pos + 1] as usize;
        if len < 2 || pos + len > opts.len() {
            break;
        }
        if kind == 2 && len == 4 {
            let cur_mss = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]);
            if cur_mss > safe_mss {
                let bytes = safe_mss.to_be_bytes();
                opts[pos + 2] = bytes[0];
                opts[pos + 3] = bytes[1];
                modified = true;
            }
            break;
        }
        pos += len;
    }

    if !modified {
        return None;
    }

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
            &opts,
            tcp.payload,
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
            &opts,
            tcp.payload,
        )),
        _ => None,
    }
}

/// Clamps the advertised TCP receive window on a handshake packet to at most `max_window`,
/// recomputing valid RFC 1071 checksums. Returns `None` if already `<= max_window`.
pub fn clamp_tcp_window(raw_packet: &[u8], max_window: u16) -> Option<Vec<u8>> {
    let ip = parse_ip_packet(raw_packet)?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = parse_tcp(ip.payload)?;
    let safe_win = max_window.max(1);
    if tcp.window <= safe_win {
        return None;
    }

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
            safe_win,
            ip.ttl,
            1,
            tcp_opts,
            tcp.payload,
        )),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_ipv6_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            tcp.seq,
            tcp.ack,
            tcp.flags,
            safe_win,
            ip.ttl,
            tcp_opts,
            tcp.payload,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ipv4_header_checksum, tcp_checksum_ipv4};
    use crate::tls::tests::build_sample_client_hello;
    use std::net::Ipv4Addr;

    #[test]
    fn segments_raw_ipv4_tcp_packet_with_valid_checksums() {
        let ch = build_sample_client_hello("censored.example.net");
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let raw = build_ipv4_tcp_packet(
            src,
            dst,
            51234,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            10,
            &[],
            &ch,
        );

        let split = plan_tcp_splits(&ch).unwrap();
        let (p1, p2) = segment_tcp_packet(&raw, split.split_at).unwrap();

        let ip1 = parse_ip_packet(&p1).unwrap();
        let ip2 = parse_ip_packet(&p2).unwrap();
        let tcp1 = parse_tcp(ip1.payload).unwrap();
        let tcp2 = parse_tcp(ip2.payload).unwrap();

        assert_eq!(tcp1.seq, 1000);
        assert_eq!(tcp2.seq, 1000 + split.split_at as u32);
        assert_eq!(tcp1.payload.len() + tcp2.payload.len(), ch.len());
        assert_eq!([tcp1.payload, tcp2.payload].concat(), ch);

        assert_eq!(ipv4_header_checksum(&p1[0..20]), u16::from_be_bytes([p1[10], p1[11]]));
        assert_eq!(tcp_checksum_ipv4(src, dst, ip1.payload), u16::from_be_bytes([ip1.payload[16], ip1.payload[17]]));
        assert_eq!(tcp_checksum_ipv4(src, dst, ip2.payload), u16::from_be_bytes([ip2.payload[16], ip2.payload[17]]));
    }

    #[test]
    fn disorder_and_fake_packet_plan() {
        let ch = build_sample_client_hello("censored.example.net");
        let raw = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            51234,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            10,
            &[],
            &ch,
        );
        let split = plan_tcp_splits(&ch).unwrap();
        let plan = build_disorder_and_fake_packets(&raw, split.split_at, Some(FakePacketMode::LowTtl(3))).unwrap();
        assert_eq!(plan.packets.len(), 3);
        let fake_ip = parse_ip_packet(&plan.packets[0]).unwrap();
        assert_eq!(fake_ip.ttl, 3);
        let first_sent = parse_tcp(parse_ip_packet(&plan.packets[1]).unwrap().payload).unwrap();
        let second_sent = parse_tcp(parse_ip_packet(&plan.packets[2]).unwrap().payload).unwrap();
        assert!(first_sent.seq > second_sent.seq);
    }

    #[test]
    fn clamps_syn_mss_and_tcp_window_with_valid_checksums() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        // TCP options: NOP (1), MSS 1460 (2, 4, 0x05, 0xB4), NOP, NOP, End (0) -> 8 bytes aligned
        let opts = [1u8, 2, 4, 0x05, 0xB4, 1, 1, 0];
        let syn = build_ipv4_tcp_packet(
            src,
            dst,
            51235,
            443,
            500,
            0,
            ParsedTcp::SYN,
            64240,
            64,
            7,
            &opts,
            &[],
        );

        let clamped_syn = clamp_syn_mss(&syn, 536).expect("MSS should be clamped");
        let ip = parse_ip_packet(&clamped_syn).unwrap();
        let tcp = parse_tcp(ip.payload).unwrap();
        assert_eq!(ipv4_header_checksum(&clamped_syn[0..20]), u16::from_be_bytes([clamped_syn[10], clamped_syn[11]]));
        assert_eq!(tcp_checksum_ipv4(src, dst, ip.payload), u16::from_be_bytes([ip.payload[16], ip.payload[17]]));
        assert_eq!(u16::from_be_bytes([ip.payload[20 + 3], ip.payload[20 + 4]]), 536);
        assert_eq!(tcp.window, 64240);

        // Already <= 536 -> returns None (no redundant rebuild)
        assert!(clamp_syn_mss(&clamped_syn, 536).is_none());

        // Window clamping test
        let win_clamped = clamp_tcp_window(&clamped_syn, 40).expect("window should be clamped");
        let wip = parse_ip_packet(&win_clamped).unwrap();
        let wtcp = parse_tcp(wip.payload).unwrap();
        assert_eq!(wtcp.window, 40);
        assert_eq!(tcp_checksum_ipv4(src, dst, wip.payload), u16::from_be_bytes([wip.payload[16], wip.payload[17]]));
    }
}
