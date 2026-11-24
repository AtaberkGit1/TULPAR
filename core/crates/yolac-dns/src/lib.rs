#![forbid(unsafe_code)]
//! YOLAÇ Encrypted DNS & Leak-Prevention Engine.
//!
//! Features:
//! - Cycle-safe RFC 1035 DNS wire parser & blocked-response synthesizer
//! - Local ad/tracker/malware blocking + CNAME uncloaking
//! - DNS poisoning & bogon/loopback hijacking detection
//! - Encrypted DoH (RFC 8484) & DoT (RFC 7858) upstreams via hardcoded bootstrap IPs
//! - Optional DPI evasion on upstream DoH/DoT TLS handshakes
//! - Strictly RAM-only bounded LRU cache (zero disk logging, wiped on clear)

pub mod cache;
pub mod poison;
pub(crate) mod pool;
pub mod resolver;
pub mod upstream;
pub mod wire;

pub use cache::{CacheLookup, DnsCache};
pub use poison::{detect_poisoning, detect_poisoning_tls, PoisonReason};
pub use resolver::{DnsConfig, DnsEngine, DnsOutcome, DnsStatsSnapshot, UpstreamBenchmark};
pub use upstream::{default_public_upstreams, UpstreamConfig, UpstreamProtocol};
pub use wire::{
    build_blocked_response, build_empty_noerror_response, parse_dns_query, parse_dns_response,
    DnsQuery, DnsRecordData, DnsResponse, QType,
};
