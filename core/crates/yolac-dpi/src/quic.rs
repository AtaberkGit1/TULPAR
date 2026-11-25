//! QUIC Initial packet detection, fallback policy, and raw UDP-443 DPI desync.

use std::net::IpAddr;

use crate::packet::{
    build_ipv4_udp_packet, build_ipv6_udp_packet, parse_ip_packet, parse_udp, IpProtocol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPolicy {
    /// Forward QUIC UDP/443 packets normally.
    Allow,
    /// Block QUIC Initial packets so browsers fall back to DPI-protected TCP/TLS via Happy Eyeballs.
    BlockFallbackToTcp,
    /// Raw engines only: emit low-TTL + bad-checksum benign QUIC Initial decoys to bypass QUIC SNI DPI
    /// without dropping HTTP/3 traffic (automatically degrades to `BlockFallbackToTcp` when raw unavailable).
    DesyncFragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInitialInfo {
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicDesyncPacket {
    pub bytes: Vec<u8>,
    pub preserve_bad_udp_checksum: bool,
}

/// Detects RFC 9000 / RFC 9369 QUIC Initial Long Header packets over UDP.
pub fn detect_quic_initial(udp_payload: &[u8]) -> Option<QuicInitialInfo> {
    // QUIC Initial packets must be >= 1200 bytes (RFC 9000 Section 14.1) or at least Long Header (5+ bytes).
    if udp_payload.len() < 7 {
        return None;
    }
    let first = udp_payload[0];
    // Long header bit (0x80) and Fixed bit (0x40)
    if (first & 0xC0) != 0xC0 {
        return None;
    }
    let version = u32::from_be_bytes([udp_payload[1], udp_payload[2], udp_payload[3], udp_payload[4]]);
    // QUIC v1 (0x00000001) & Meta/Instagram mvfst drafts (0xfaceb00x) -> type 0 = Initial
    // QUIC v2 (0x6b3343cf) -> type 1 = Initial
    let pkt_type = (first >> 4) & 0x03;
    let is_initial = match version {
        0x0000_0001 => pkt_type == 0,
        0x6b33_43cf => pkt_type == 1,
        v if (v & 0xFFFF_FF00) == 0xface_b000 => pkt_type == 0,
        _ => false,
    };
    if is_initial {
        Some(QuicInitialInfo { version })
    } else {
        None
    }
}

/// Builds a 2-packet QUIC Initial desynchronization decoy burst (`LowTtl` + `BadUdpChecksum`)
/// formatted as a benign RFC 9000 QUIC v1 Initial carrying an inert `www.iana.org` label.
pub fn build_quic_desync_decoys(raw_udp_packet: &[u8], fake_ttl: u8) -> Option<Vec<QuicDesyncPacket>> {
    let ip = parse_ip_packet(raw_udp_packet)?;
    if ip.protocol != IpProtocol::Udp {
        return None;
    }
    let udp = parse_udp(ip.payload)?;
    detect_quic_initial(udp.payload)?;

    // Build a syntactically plausible RFC 9000 1200-byte QUIC v1 Initial decoy
    let mut decoy = vec![0x00u8; 1200];
    decoy[0] = 0xC3; // Long header + fixed + Initial + 4-byte Packet Number
    decoy[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
    decoy[5] = 8; // DCID len
    decoy[6..14].copy_from_slice(&[0x54, 0x55, 0x4C, 0x50, 0x41, 0x52, 0x01, 0x02]);
    decoy[14] = 0; // SCID len
    decoy[15] = 0; // Token len = 0
    decoy[16] = 0x44; // 2-byte varint payload length (~1180)
    decoy[17] = 0x9C;
    // Minimal benign SNI bytes inside encrypted payload area so naive middlebox entropy/parser engages
    decoy[32..44].copy_from_slice(b"www.iana.org");

    let max_ttl = ip.ttl.saturating_sub(1).max(1);
    let safe_ttl = fake_ttl.clamp(2, 6).min(max_ttl);

    let (low_ttl_pkt, mut bad_csum_pkt) = match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            build_ipv4_udp_packet(s, d, udp.src_port, udp.dst_port, safe_ttl, &decoy),
            build_ipv4_udp_packet(s, d, udp.src_port, udp.dst_port, ip.ttl, &decoy),
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            build_ipv6_udp_packet(s, d, udp.src_port, udp.dst_port, safe_ttl, &decoy),
            build_ipv6_udp_packet(s, d, udp.src_port, udp.dst_port, ip.ttl, &decoy),
        ),
        _ => return None,
    };

    let l4_off = if ip.version == 4 { 20 } else { 40 };
    bad_csum_pkt[l4_off + 6] ^= 0xFF;
    bad_csum_pkt[l4_off + 7] ^= 0x5A;
    if bad_csum_pkt[l4_off + 6] == 0 && bad_csum_pkt[l4_off + 7] == 0 {
        bad_csum_pkt[l4_off + 6] = 0xDE;
        bad_csum_pkt[l4_off + 7] = 0xAD;
    }

    Some(vec![
        QuicDesyncPacket {
            bytes: low_ttl_pkt,
            preserve_bad_udp_checksum: false,
        },
        QuicDesyncPacket {
            bytes: bad_csum_pkt,
            preserve_bad_udp_checksum: true,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn detects_quic_v1_and_v2_initial() {
        let mut v1 = vec![0u8; 1200];
        v1[0] = 0xC3; // Long header + fixed + type 0
        v1[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        assert_eq!(detect_quic_initial(&v1), Some(QuicInitialInfo { version: 1 }));

        let mut v2 = vec![0u8; 1200];
        v2[0] = 0xD3; // Long header + fixed + type 1
        v2[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert_eq!(detect_quic_initial(&v2), Some(QuicInitialInfo { version: 0x6b33_43cf }));

        assert!(detect_quic_initial(b"\x40\x00\x00\x00\x01\x00\x00").is_none());
    }

    #[test]
    fn builds_quic_initial_desync_decoys_with_low_ttl_and_bad_checksum() {
        let mut q = vec![0u8; 1200];
        q[0] = 0xC3;
        q[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        let raw = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(172, 217, 16, 14),
            55123,
            443,
            64,
            &q,
        );
        let decoys = build_quic_desync_decoys(&raw, 4).expect("should build QUIC decoys");
        assert_eq!(decoys.len(), 2);
        let ip0 = parse_ip_packet(&decoys[0].bytes).unwrap();
        assert_eq!(ip0.ttl, 4);
        assert!(!decoys[0].preserve_bad_udp_checksum);
        let ip1 = parse_ip_packet(&decoys[1].bytes).unwrap();
        assert_eq!(ip1.ttl, 64);
        assert!(decoys[1].preserve_bad_udp_checksum);
    }
}
