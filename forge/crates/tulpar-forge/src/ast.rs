//! Typed, non-Turing-complete AST and capability model for TULPAR Strategy Language (TSL v1).

/// Strict safety & resource bounds enforced during parsing, decoding, and static verification.
pub const MAX_PACKAGE_BYTES: usize = 128 * 1024;
pub const MAX_RULES: usize = 32;
pub const MAX_PORTS_PER_RULE: usize = 16;
pub const MAX_SNI_SUFFIXES_PER_RULE: usize = 32;
pub const MAX_SPLIT_CUTS: usize = 6;
pub const MAX_DECOYS_PER_RULE: usize = 4;
pub const MAX_FIXED_OFFSET: u16 = 512;
pub const MAX_DECOY_TTL: u8 = 8;
pub const MIN_SAFE_SYN_MSS: u16 = 536;
pub const MAX_SYN_MSS: u16 = 1460;
pub const MAX_UDP_DESYNC_TTL: u8 = 8;
pub const MAX_ROLLBACK_CONSECUTIVE: u8 = 16;

/// Allowed inert RFC 2606 / RFC 6761 / IANA decoy SNI/Host domains.
/// Prevents any malicious strategy package from weaponizing decoys against third-party victims.
pub const ALLOWED_BENIGN_DECOY_HOSTS: &[&str] = &[
    "www.iana.org",
    "iana.org",
    "example.com",
    "www.example.com",
    "example.org",
    "www.example.org",
    "example.net",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgePlatformCaps {
    pub supports_raw_packets: bool,
    pub supports_ttl_fake: bool,
    pub supports_bad_checksum: bool,
}

impl ForgePlatformCaps {
    pub const WINDOWS: Self = Self {
        supports_raw_packets: true,
        supports_ttl_fake: true,
        supports_bad_checksum: true,
    };

    pub const LINUX: Self = Self::WINDOWS;

    pub const ANDROID: Self = Self {
        supports_raw_packets: false,
        supports_ttl_fake: false,
        supports_bad_checksum: false,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MatchProtocol {
    Tls = 1,
    Http = 2,
    Quic = 3,
    UdpStun = 4,
    UdpRakNet = 5,
    Any = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RawFallbackPolicy {
    /// Rejects execution on socket-only platforms (e.g. Android) if a rule requires raw L3/L4 packets.
    Strict = 0,
    /// Automatically degrades raw-only actions to verified socket actions on Android.
    AutoDegrade = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackPolicy {
    /// Auto-disable package after N consecutive handshake failures across flows (1..=16).
    pub max_consecutive_failures: u8,
    /// Minimum observed flow outcomes before percentage threshold applies (3..=64).
    pub min_samples: u16,
    /// Auto-disable if failure percentage meets/exceeds this threshold (20..=90).
    pub max_failure_pct: u8,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 4,
            min_samples: 6,
            max_failure_pct: 65,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SplitCutSpec {
    FixedOffset(u16),
    SniMid,
    HostMid,
    FirstRecordEnd,
}

impl SplitCutSpec {
    pub fn resolve(
        self,
        payload_len: usize,
        sni_mid: Option<usize>,
        host_mid: Option<usize>,
        first_record_end: Option<usize>,
    ) -> Option<usize> {
        if payload_len < 2 {
            return None;
        }
        let max_cut = payload_len - 1;
        let raw = match self {
            Self::FixedOffset(off) => off as usize,
            Self::SniMid => sni_mid.unwrap_or(payload_len / 2),
            Self::HostMid => host_mid.unwrap_or(payload_len / 2),
            Self::FirstRecordEnd => first_record_end.unwrap_or_else(|| (payload_len / 2).max(2)),
        };
        Some(raw.clamp(1, max_cut))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecoyTtlMode {
    /// Dynamically calibrated via SYN-ACK hop estimator (bounded 2..=6).
    AutoCalibrated,
    /// Explicit static TTL (bounded 1..=8 by Verifier).
    Fixed(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecoySpec {
    BadChecksum,
    WrongSeq,
    BadChecksumWrongSeq,
    LowTtl(DecoyTtlMode),
    LowTtlWrongSeq(DecoyTtlMode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsRecordMode {
    None,
    SniMid,
    OffsetAndSniMid(u16),
    SmallChunks(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicMode {
    Allow,
    BlockFallbackTcp,
    DesyncTtl(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawActionSpec {
    pub passthrough: bool,
    pub tcp_splits: Vec<SplitCutSpec>,
    pub disorder: bool,
    pub decoy_sni: String,
    pub decoys: Vec<DecoySpec>,
    pub http_split_host: bool,
    pub http_host_case: bool,
    pub syn_mss_clamp: Option<u16>,
    pub drop_forged_passive_rst: bool,
    pub drop_forged_http_redirect: bool,
}

impl Default for RawActionSpec {
    fn default() -> Self {
        Self {
            passthrough: false,
            tcp_splits: Vec::new(),
            disorder: false,
            decoy_sni: "www.iana.org".to_string(),
            decoys: Vec::new(),
            http_split_host: true,
            http_host_case: false,
            syn_mss_clamp: None,
            drop_forged_passive_rst: true,
            drop_forged_http_redirect: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketActionSpec {
    pub passthrough: bool,
    pub tls_record: Option<TlsRecordMode>,
    pub tcp_splits: Vec<SplitCutSpec>,
    pub paced_flush: bool,
    pub tcp_oob: bool,
    pub http_split_host: bool,
    pub http_host_case: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSpec {
    pub protocols: Vec<MatchProtocol>,
    pub ports: Vec<u16>,
    pub sni_suffixes: Vec<String>,
    pub min_payload: u16,
    /// When true, sensitive unblocked domains (banking, e-Devlet, WhatsApp) default to passthrough unless retried.
    pub exclude_sensitive: bool,
}

impl Default for MatchSpec {
    fn default() -> Self {
        Self {
            protocols: vec![MatchProtocol::Tls],
            ports: Vec::new(),
            sni_suffixes: Vec::new(),
            min_payload: 0,
            exclude_sensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyRule {
    pub name: String,
    pub priority: u16,
    /// Minimum handshake retry attempt required to activate (`0` = first attempt, `1` = retry #1, ...).
    pub when_on_retry: u8,
    pub matcher: MatchSpec,
    pub raw_actions: Option<RawActionSpec>,
    pub socket_actions: Option<SocketActionSpec>,
    pub quic_mode: Option<QuicMode>,
    pub udp_desync_ttl: Option<u8>,
    pub udp_bad_checksum_decoy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LabExpectations {
    pub expect_pass: Vec<String>,
    pub expect_honest_unbypassable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategySpec {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub min_core_version: String,
    pub fallback_policy: RawFallbackPolicy,
    pub rollback: RollbackPolicy,
    pub rules: Vec<StrategyRule>,
    pub lab_assert: LabExpectations,
}
