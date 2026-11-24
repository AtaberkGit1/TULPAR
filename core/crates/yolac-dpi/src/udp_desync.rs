//! UDP desynchronization helpers (Discord Voice STUN/IP-Discovery & Roblox RakNet)
//! and sensitive unblocked service protection (WhatsApp, Turkish e-Devlet, Banking).

use std::net::IpAddr;

use crate::packet::{
    build_ipv4_udp_packet, build_ipv6_udp_packet, parse_ip_packet, parse_udp, IpProtocol,
};

/// RakNet offline connection magic bytes (16 bytes) used by Roblox game client (`OpenConnectionRequest1`).
const RAKNET_OFFLINE_MAGIC: [u8; 16] = [
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
];

/// RFC 5389 STUN Magic Cookie (`0x2112A442`) used by Discord Voice / WebRTC ICE/STUN.
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDesyncKind {
    /// Discord Voice IP Discovery (74-byte UDP packet on ephemeral voice ports).
    DiscordVoiceDiscovery,
    /// RFC 5389 STUN Binding Request (Discord Voice / WebRTC RTC setup).
    StunBinding,
    /// Roblox game client RakNet `OpenConnectionRequest1` handshake (`UDP 49152..=65535`).
    RobloxRakNet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDesyncPacket {
    pub bytes: Vec<u8>,
    /// True when UDP checksum is intentionally corrupted so NIC offload must NOT repair it.
    pub preserve_bad_udp_checksum: bool,
}

/// Identifies initial handshake packets of UDP protocols frequently disrupted by Turkish ISP DPI
/// (Discord Voice STUN/IP-Discovery and Roblox RakNet game-server handshakes).
/// Returns `None` for normal steady-state media/game packets so zero per-packet overhead is added.
pub fn detect_udp_desync_target(udp_payload: &[u8], dst_port: u16) -> Option<UdpDesyncKind> {
    if dst_port < 1024 || udp_payload.len() < 16 {
        return None;
    }

    // 1. Discord Voice IP Discovery: 74 bytes starting with type=0x0001, length=0x0046 (70)
    if dst_port >= 49152
        && udp_payload.len() == 74
        && udp_payload[0..4] == [0x00, 0x01, 0x00, 0x46]
    {
        return Some(UdpDesyncKind::DiscordVoiceDiscovery);
    }

    // 2. RFC 5389 STUN Binding Request (type 0x0001, first two bits 00, magic cookie at bytes 4..8)
    if udp_payload.len() >= 20
        && (udp_payload[0] & 0xC0) == 0
        && udp_payload[0] == 0x00
        && udp_payload[1] == 0x01
        && udp_payload[4..8] == STUN_MAGIC_COOKIE
    {
        return Some(UdpDesyncKind::StunBinding);
    }

    // 3. Roblox RakNet OpenConnectionRequest1 (ID 0x05 + 16-byte RakNet offline magic on UDP 49152..=65535)
    if dst_port >= 49152
        && udp_payload.len() >= 17
        && udp_payload[0] == 0x05
        && udp_payload[1..17] == RAKNET_OFFLINE_MAGIC
    {
        return Some(UdpDesyncKind::RobloxRakNet);
    }

    None
}

/// Builds 2 lightweight Zapret-style UDP desync decoys for raw packet engines (Windows WinDivert):
/// 1. `LowTtl(fake_ttl)` decoy with valid UDP checksum (passes home NAT, expires before destination server)
/// 2. `BadUdpChecksum` decoy with normal TTL (reaches deep ISP DPI, dropped by server kernel/NIC)
pub fn build_udp_desync_decoys(raw_udp_packet: &[u8], fake_ttl: u8) -> Option<Vec<UdpDesyncPacket>> {
    let ip = parse_ip_packet(raw_udp_packet)?;
    if ip.protocol != IpProtocol::Udp {
        return None;
    }
    let udp = parse_udp(ip.payload)?;
    let decoy_payload = [0u8; 32];
    let safe_ttl = fake_ttl.clamp(2, 5);

    let (low_ttl_pkt, mut bad_csum_pkt) = match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            build_ipv4_udp_packet(s, d, udp.src_port, udp.dst_port, safe_ttl, &decoy_payload),
            build_ipv4_udp_packet(s, d, udp.src_port, udp.dst_port, ip.ttl, &decoy_payload),
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            build_ipv6_udp_packet(s, d, udp.src_port, udp.dst_port, safe_ttl, &decoy_payload),
            build_ipv6_udp_packet(s, d, udp.src_port, udp.dst_port, ip.ttl, &decoy_payload),
        ),
        _ => return None,
    };

    // Corrupt UDP checksum (bytes +6..+8 inside UDP header)
    let l4_off = if ip.version == 4 { 20 } else { 40 };
    bad_csum_pkt[l4_off + 6] ^= 0xFF;
    bad_csum_pkt[l4_off + 7] ^= 0x5A;
    // Ensure corrupted checksum is non-zero (in IPv4, 0x0000 means "no checksum" and would NOT be dropped!)
    if bad_csum_pkt[l4_off + 6] == 0 && bad_csum_pkt[l4_off + 7] == 0 {
        bad_csum_pkt[l4_off + 6] = 0xDE;
        bad_csum_pkt[l4_off + 7] = 0xAD;
    }

    Some(vec![
        UdpDesyncPacket {
            bytes: low_ttl_pkt,
            preserve_bad_udp_checksum: false,
        },
        UdpDesyncPacket {
            bytes: bad_csum_pkt,
            preserve_bad_udp_checksum: true,
        },
    ])
}

/// Sensitive, non-censored essential services (WhatsApp, Turkish e-Devlet, universities, banks)
/// whose strict L4 load balancers / WAFs can reject unnecessary out-of-order TLS splits.
/// These start in clean Passthrough and ONLY escalate to DPI desync if an ISP actually blocks them!
const SENSITIVE_UNBLOCKED_SUFFIXES: &[&str] = &[
    "whatsapp.com",
    "whatsapp.net",
    "gov.tr",
    "edu.tr",
    "bel.tr",
    "pol.tr",
    "tsk.tr",
    "garantibbva.com.tr",
    "isbank.com.tr",
    "yapikredi.com.tr",
    "akbank.com",
    "ziraatbank.com.tr",
    "vakifbank.com.tr",
    "halkbank.com.tr",
    "qnb.com.tr",
    "qnbfinansbank.com",
    "denizbank.com",
    "enpara.com",
    "papara.com",
    "ing.com.tr",
    "teb.com.tr",
    "kuveytturk.com.tr",
];

/// Returns `true` if `sni` belongs to a critical unblocked service that should try clean
/// Passthrough first (falling back to full DPI desync automatically if ever reset/blocked).
pub fn is_sensitive_unblocked_domain(sni: &str) -> bool {
    let norm = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    SENSITIVE_UNBLOCKED_SUFFIXES.iter().any(|&suffix| {
        norm == suffix
            || (norm.len() > suffix.len()
                && norm.ends_with(suffix)
                && norm.as_bytes()[norm.len() - suffix.len() - 1] == b'.')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn detects_discord_voice_stun_and_roblox_raknet_without_false_positives() {
        // Discord IP Discovery (74 bytes)
        let mut discord = vec![0u8; 74];
        discord[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x46]);
        assert_eq!(
            detect_udp_desync_target(&discord, 50005),
            Some(UdpDesyncKind::DiscordVoiceDiscovery)
        );

        // STUN Binding Request
        let mut stun = vec![0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert_eq!(
            detect_udp_desync_target(&stun, 50010),
            Some(UdpDesyncKind::StunBinding)
        );

        // Roblox RakNet OpenConnectionRequest1
        let mut raknet = vec![0u8; 64];
        raknet[0] = 0x05;
        raknet[1..17].copy_from_slice(&RAKNET_OFFLINE_MAGIC);
        assert_eq!(
            detect_udp_desync_target(&raknet, 53120),
            Some(UdpDesyncKind::RobloxRakNet)
        );

        // Normal UDP payload -> ignored
        assert_eq!(detect_udp_desync_target(b"ordinary_game_tick_data_1234", 53120), None);
    }

    #[test]
    fn builds_valid_low_ttl_and_non_zero_bad_checksum_udp_decoys() {
        let mut raknet = vec![0u8; 64];
        raknet[0] = 0x05;
        raknet[1..17].copy_from_slice(&RAKNET_OFFLINE_MAGIC);
        let raw = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(128, 116, 114, 3),
            54000,
            53120,
            64,
            &raknet,
        );
        let decoys = build_udp_desync_decoys(&raw, 3).expect("should emit 2 decoys");
        assert_eq!(decoys.len(), 2);
        assert!(!decoys[0].preserve_bad_udp_checksum);
        assert_eq!(parse_ip_packet(&decoys[0].bytes).unwrap().ttl, 3);
        assert!(decoys[1].preserve_bad_udp_checksum);
        let bad_csum = u16::from_be_bytes([decoys[1].bytes[26], decoys[1].bytes[27]]);
        assert_ne!(bad_csum, 0, "Bad IPv4 UDP checksum must be non-zero so server drops it");
    }

    #[test]
    fn recognizes_whatsapp_edevlet_and_banks_without_matching_censored_sites() {
        assert!(is_sensitive_unblocked_domain("web.whatsapp.com"));
        assert!(is_sensitive_unblocked_domain("g.whatsapp.net"));
        assert!(is_sensitive_unblocked_domain("www.turkiye.gov.tr"));
        assert!(is_sensitive_unblocked_domain("sube.garantibbva.com.tr"));
        assert!(!is_sensitive_unblocked_domain("www.roblox.com"));
        assert!(!is_sensitive_unblocked_domain("www.pornhub.com"));
        assert!(!is_sensitive_unblocked_domain("discord.com"));
        assert!(!is_sensitive_unblocked_domain("evilwhatsapp.com"));
    }
}
