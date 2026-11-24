//! QUIC Initial packet detection & fallback policy.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPolicy {
    /// Forward QUIC UDP/443 packets normally.
    Allow,
    /// Block QUIC Initial packets so browsers fall back to DPI-protected TCP/TLS via Happy Eyeballs.
    BlockFallbackToTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInitialInfo {
    pub version: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
