//! DPI evasion strategies and OS platform capability modeling.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DpiStrategy {
    /// Zero-overhead passthrough (used when destination is unaffected).
    Passthrough,
    /// Fragment TLS ClientHello into multiple TLS records inside the SNI field.
    TlsRecordSplit,
    /// Split the first TCP write right inside SNI / HTTP Host using TCP_NODELAY.
    TcpSniSplit,
    /// Combine TLS Record Fragmentation + TCP Segmentation (default mobile & safe desktop strategy).
    TlsAndTcpSplit,
    /// Raw packet engine only: send segment 2 before segment 1 (out-of-order).
    RawDisorder,
    /// Raw packet engine only: inject decoy ClientHello with low TTL + out-of-order segments.
    RawFakeTtl { ttl: u8 },
    /// Raw packet engine only: inject decoy ClientHello with corrupted TCP checksum + disorder.
    RawBadChecksum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub supports_raw_packets: bool,
    pub supports_ttl_fake: bool,
    pub supports_bad_checksum: bool,
}

impl PlatformCapabilities {
    /// Android `VpnService` / iOS `NEPacketTunnelProvider` (standard userspace sockets).
    pub const MOBILE_SANDBOX: Self = Self {
        supports_raw_packets: false,
        supports_ttl_fake: false,
        supports_bad_checksum: false,
    };

    /// Windows `WinDivert` kernel filter driver (full L3/L4 raw packet injection).
    pub const WINDOWS_WINDIVERT: Self = Self {
        supports_raw_packets: true,
        supports_ttl_fake: true,
        supports_bad_checksum: true,
    };

    pub fn supports(&self, strategy: DpiStrategy) -> bool {
        match strategy {
            DpiStrategy::Passthrough
            | DpiStrategy::TlsRecordSplit
            | DpiStrategy::TcpSniSplit
            | DpiStrategy::TlsAndTcpSplit => true,
            DpiStrategy::RawDisorder => self.supports_raw_packets,
            DpiStrategy::RawFakeTtl { .. } => self.supports_raw_packets && self.supports_ttl_fake,
            DpiStrategy::RawBadChecksum => self.supports_raw_packets && self.supports_bad_checksum,
        }
    }

    /// Returns the next stronger strategy supported by this platform, if any.
    pub fn escalate(&self, current: DpiStrategy) -> Option<DpiStrategy> {
        let ladder: &[DpiStrategy] = if self.supports_raw_packets {
            &[
                DpiStrategy::Passthrough,
                DpiStrategy::TlsRecordSplit,
                DpiStrategy::TlsAndTcpSplit,
                DpiStrategy::RawDisorder,
                DpiStrategy::RawFakeTtl { ttl: 3 },
                DpiStrategy::RawBadChecksum,
            ]
        } else {
            &[
                DpiStrategy::Passthrough,
                DpiStrategy::TlsRecordSplit,
                DpiStrategy::TcpSniSplit,
                DpiStrategy::TlsAndTcpSplit,
            ]
        };

        let pos = ladder.iter().position(|&s| s == current)?;
        ladder.get(pos + 1).copied().filter(|s| self.supports(*s))
    }
}
