//! DPI evasion strategies and OS platform capability modeling.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DpiStrategy {
    /// Zero-overhead passthrough (used when destination is unaffected).
    Passthrough,
    /// Fragment TLS ClientHello into multiple TLS records inside the SNI field.
    TlsRecordSplit,
    /// Split the first TCP write right inside SNI / HTTP Host using TCP_NODELAY.
    TcpSniSplit,
    /// Combine TLS Record Fragmentation + TCP Segmentation.
    TlsAndTcpSplit,
    /// Unrooted mobile/desktop ByeDPI-Turkey Stage 1 (`-r1+s -s1`): 3-record TLS split (offset 2 + SNI mid) + paced TCP writes.
    TlsMultiRecordAndTcpSplit,
    /// Unrooted mobile/desktop ByeDPI-Turkey Stage 2 (`-o1 -r1+s`): POSIX TCP Out-of-Band (`MSG_OOB`) byte + TLS SNI split.
    TcpOobAndTlsSplit,
    /// Unrooted mobile/desktop Stage 3: Multi-chunk small 32-byte TLS records sent over separate TCP segments.
    TlsSmallChunks,
    /// Raw packet engine only: send segment 2 before segment 1 (out-of-order).
    RawDisorder,
    /// Raw packet engine only: inject decoy ClientHello with low TTL + out-of-order segments.
    RawFakeTtl { ttl: u8 },
    /// Raw packet engine only: inject decoy ClientHello with corrupted TCP checksum + disorder.
    RawBadChecksum,
    /// Windows WinDivert Turkey Stage 1 (GoodbyeDPI-Turkey `-5` + `--wrong-seq` + `--wrong-chksum` + `-e 2` reverse-frag):
    /// Valid benign fake ClientHello (Auto-TTL+WrongSeq AND BadChecksum+WrongSeq) + 3-segment disordered offset-2/SNI split.
    TurkeyDesyncAuto,
    /// Windows WinDivert Turkey Stage 2 (Vodafone / Superonline strict DPI escalation):
    /// Triple decoy (`LowTtl(2)+WrongSeq`, `LowTtl(5)+WrongSeq`, `BadChecksum+WrongSeq`) + 1-byte reverse-frag 3-segment split.
    TurkeyDesyncSuperonline,
    /// Windows WinDivert Turkey Stage 3 (Ultra-strict DPI fallback):
    /// `LowTtl(6)+WrongSeq` + `BadChecksum+WrongSeq` + 4-piece disordered tiny split (`[1..2]`, `[2..sni_mid]`, `[sni_mid..]`, `[0..1]`).
    TurkeyDesyncAggressive,
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

    /// Linux `NFQUEUE` + `IPPROTO_RAW` packet engine (full L3/L4 raw packet injection).
    pub const LINUX_NFQUEUE: Self = Self::WINDOWS_WINDIVERT;

    pub fn supports(&self, strategy: DpiStrategy) -> bool {
        match strategy {
            DpiStrategy::Passthrough
            | DpiStrategy::TlsRecordSplit
            | DpiStrategy::TcpSniSplit
            | DpiStrategy::TlsAndTcpSplit
            | DpiStrategy::TlsMultiRecordAndTcpSplit
            | DpiStrategy::TcpOobAndTlsSplit
            | DpiStrategy::TlsSmallChunks => true,
            DpiStrategy::RawDisorder => self.supports_raw_packets,
            DpiStrategy::RawFakeTtl { .. } => self.supports_raw_packets && self.supports_ttl_fake,
            DpiStrategy::RawBadChecksum => self.supports_raw_packets && self.supports_bad_checksum,
            DpiStrategy::TurkeyDesyncAuto
            | DpiStrategy::TurkeyDesyncSuperonline
            | DpiStrategy::TurkeyDesyncAggressive => {
                self.supports_raw_packets && self.supports_ttl_fake && self.supports_bad_checksum
            }
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
                DpiStrategy::TurkeyDesyncAuto,
                DpiStrategy::TurkeyDesyncSuperonline,
                DpiStrategy::TurkeyDesyncAggressive,
            ]
        } else {
            &[
                DpiStrategy::Passthrough,
                DpiStrategy::TlsRecordSplit,
                DpiStrategy::TcpSniSplit,
                DpiStrategy::TlsAndTcpSplit,
                DpiStrategy::TlsMultiRecordAndTcpSplit,
                DpiStrategy::TlsSmallChunks,
                DpiStrategy::TcpOobAndTlsSplit,
            ]
        };

        let normalized = match (self.supports_raw_packets, current) {
            (true, DpiStrategy::RawFakeTtl { .. }) => DpiStrategy::RawFakeTtl { ttl: 3 },
            (
                true,
                DpiStrategy::TcpSniSplit
                | DpiStrategy::TlsMultiRecordAndTcpSplit
                | DpiStrategy::TlsSmallChunks
                | DpiStrategy::TcpOobAndTlsSplit,
            ) => DpiStrategy::TlsAndTcpSplit,
            (
                false,
                DpiStrategy::RawDisorder
                | DpiStrategy::RawFakeTtl { .. }
                | DpiStrategy::RawBadChecksum
                | DpiStrategy::TurkeyDesyncAuto
                | DpiStrategy::TurkeyDesyncSuperonline
                | DpiStrategy::TurkeyDesyncAggressive,
            ) => DpiStrategy::TlsMultiRecordAndTcpSplit,
            _ => current,
        };

        let pos = ladder.iter().position(|&s| s == normalized)?;
        ladder[pos + 1..]
            .iter()
            .copied()
            .find(|&s| self.supports(s))
    }
}
