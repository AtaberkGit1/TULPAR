#![forbid(unsafe_code)]
//! YOLAÇ DPI Inspection & Circumvention Engine
//!
//! Pure, zero-panic parsers and payload/packet circumvention transforms for:
//! - IPv4 / IPv6 + TCP / UDP packet inspection and RFC 1071 checksum calculation
//! - TLS 1.2 / 1.3 ClientHello SNI extraction & TLS Record Fragmentation
//! - TCP SNI segmentation, out-of-order (disorder), TTL-limited & bad-checksum fake packets
//! - Plaintext HTTP Host splitting and header evasion
//! - QUIC Initial packet detection & TCP fallback policy
//! - Adaptive strategy selection constrained by platform capabilities

pub mod http;
pub mod packet;
pub mod quic;
pub mod strategy;
pub mod tcp;
pub mod tls;
pub mod ttl;

pub use http::{evade_http_request, parse_http_host, HttpEvasionOptions, HttpHostInfo};
pub use packet::{
    build_ipv4_tcp_packet, build_ipv4_udp_packet, build_ipv6_tcp_packet, build_ipv6_udp_packet,
    ipv4_header_checksum, parse_ip_packet, parse_tcp, parse_udp, tcp_checksum_ipv4,
    tcp_checksum_ipv6, udp_checksum_ipv4, udp_checksum_ipv6, IpProtocol, ParsedIpPacket,
    ParsedTcp, ParsedUdp,
};
pub use quic::{detect_quic_initial, QuicInitialInfo, QuicPolicy};
pub use strategy::{DpiStrategy, PlatformCapabilities};
pub use tcp::{
    build_disorder_and_fake_packets, clamp_syn_mss, clamp_tcp_window, plan_tcp_splits,
    segment_tcp_packet, FakePacketMode, RawPacketPlan, TcpSplitPlan,
};
pub use tls::{
    fragment_tls_client_hello, parse_client_hello, ClientHelloInfo, SplitStrategy,
};
pub use ttl::{estimate_hop_count, recommend_fake_mode, TtlCalibrator};
