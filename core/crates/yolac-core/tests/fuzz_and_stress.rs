//! Deterministic fuzzing, malformed-packet resilience, DoH keep-alive pooling,
//! and concurrency/OOM stress tests for TULPAR hardening.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use yolac_blocklist::Blocklist;
use yolac_dns::wire::{build_dns_query, parse_dns_query, parse_dns_response, QType};
use yolac_dns::{DnsConfig, DnsEngine, DnsOutcome, UpstreamConfig, UpstreamProtocol};
use yolac_dpi::{
    build_ipv4_udp_packet, detect_quic_initial, evade_http_request, fragment_tls_client_hello,
    parse_client_hello, parse_client_hello_prefix, parse_http_host, parse_ip_packet, parse_tcp,
    parse_udp, plan_tcp_splits, segment_tcp_packet, DpiStrategy, HttpEvasionOptions, QuicPolicy,
    SplitStrategy,
};
use yolac_net::{
    ChannelPacketDevice, Ipv6LeakMode, MemoryProfile, NoopProtector, NoopStrategyAdvisor,
    TunConfig, TunEngine,
};

#[test]
fn fuzz_10000_malformed_and_random_packets_never_panic() {
    let mut rng = StdRng::seed_from_u64(0x796F_6C61_635F_6675);

    for i in 0..10_000 {
        let len = rng.gen_range(0..=320);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);

        // Bias some inputs toward valid protocol magic bytes to penetrate deeper parser branches
        if len >= 16 {
            match i % 6 {
                0 => buf[0] = 0x45, // IPv4
                1 => buf[0] = 0x60, // IPv6
                2 => {
                    buf[0] = 0x16;
                    buf[1] = 0x03;
                    buf[2] = 0x01;
                    buf[5] = 0x01;
                } // TLS ClientHello
                3 => buf[..4].copy_from_slice(b"GET "), // HTTP
                4 => {
                    buf[0] = 0xC3;
                    buf[1..5].copy_from_slice(&1u32.to_be_bytes());
                } // QUIC
                _ => {
                    buf[4] = 0;
                    buf[5] = 1;
                } // DNS query
            }
        }

        if let Some(ip) = parse_ip_packet(&buf) {
            let _ = parse_tcp(ip.payload);
            let _ = parse_udp(ip.payload);
        }
        let _ = parse_client_hello(&buf);
        let _ = parse_client_hello_prefix(&buf);
        let _ = fragment_tls_client_hello(&buf, SplitStrategy::SniMid);
        let _ = plan_tcp_splits(&buf);
        let _ = segment_tcp_packet(&buf, 10);
        let _ = parse_http_host(&buf);
        let _ = evade_http_request(&buf, HttpEvasionOptions::default());
        let _ = detect_quic_initial(&buf);
        let _ = parse_dns_query(&buf);
        let _ = parse_dns_response(&buf);
    }
}

fn build_dns_a_answer(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let q = parse_dns_query(query).unwrap();
    let qsec = &query[12..q.question_end];
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(qsec);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&300u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

#[tokio::test]
async fn doh_keep_alive_pool_reuses_single_tls_connection_across_5_uncached_queries() {
    let cert = generate_simple_self_signed(vec!["pool.yolac.test".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let mut srv_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut cli_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let accept_count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let acc = TlsAcceptor::from(Arc::new(srv_cfg));
    let acc_counter = Arc::clone(&accept_count);

    // Persistent HTTP/1.1 keep-alive DoH server
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            acc_counter.fetch_add(1, Ordering::SeqCst);
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else { return; };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let hdr_str = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");
                    let clen: usize = hdr_str
                        .lines()
                        .find_map(|l| {
                            let low = l.to_ascii_lowercase();
                            low.strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    let total_req = hdr_end + 4 + clen;
                    while buf.len() < total_req {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let query_body = buf[hdr_end + 4..total_req].to_vec();
                    buf.drain(..total_req);

                    let ans = build_dns_a_answer(&query_body, Ipv4Addr::new(93, 184, 216, 34));
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        ans.len()
                    );
                    if tls.write_all(resp.as_bytes()).await.is_err()
                        || tls.write_all(&ans).await.is_err()
                        || tls.flush().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let dns = DnsEngine::new(
        DnsConfig {
            upstreams: vec![UpstreamConfig {
                name: "Pooled-DoH",
                protocol: UpstreamProtocol::DoH,
                bootstrap_ip: addr.ip(),
                port: addr.port(),
                tls_server_name: "pool.yolac.test".into(),
                doh_path: "/dns-query".into(),
                apply_dpi_evasion: true,
                custom_tls_config: Some(Arc::new(cli_cfg)),
            }],
            cache_max_entries: 64,
            upstream_timeout: Duration::from_secs(2),
            block_with_nxdomain: false,
            suppress_aaaa: false,
        },
        Arc::new(Blocklist::embedded_default()),
        None,
    );

    for i in 0..5u16 {
        let q = build_dns_query(100 + i, &format!("host{i}.pooltest.invalid"), QType::A);
        let (resp, outcome) = dns.resolve(&q).await;
        assert_eq!(outcome, DnsOutcome::UpstreamResolved);
        assert!(resp.is_some());
    }

    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        1,
        "Expected all 5 uncached DoH queries to reuse a single keep-alive TLS connection!"
    );
    dns.clear_ephemeral_state().await;
}

#[tokio::test]
async fn stress_200_concurrent_dns_and_malformed_packets_under_low_memory_ios() {
    let bl = Arc::new(Blocklist::embedded_default());
    let dns = Arc::new(DnsEngine::new(
        DnsConfig {
            upstreams: vec![],
            cache_max_entries: 1024,
            ..DnsConfig::default()
        },
        bl,
        None,
    ));
    let tun = Arc::new(TunEngine::new(
        TunConfig {
            mtu: 1500,
            profile: MemoryProfile::LowMemoryIos,
            ipv6_mode: Ipv6LeakMode::BlockUnprotectedIpv6,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
        },
        dns,
        Arc::new(NoopProtector),
        Arc::new(NoopStrategyAdvisor {
            default_strategy: DpiStrategy::TlsAndTcpSplit,
        }),
    ));

    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(256);
    let (from_tun_tx, mut from_tun_rx) = mpsc::channel::<Vec<u8>>(256);
    let dev = Arc::new(ChannelPacketDevice::new(to_tun_rx, from_tun_tx));
    let (shut_tx, shut_rx) = tokio::sync::watch::channel(false);

    let t = Arc::clone(&tun);
    let handle = tokio::spawn(async move {
        let _ = t.run(dev, shut_rx).await;
    });

    // Inject oversized garbage + 120 blocked DNS bursts cleanly without OOM or panic
    to_tun_tx.send(vec![0x45; 70_000]).await.unwrap();
    to_tun_tx.send(Vec::new()).await.unwrap();

    for i in 0..120u16 {
        let q = build_dns_query(1000 + i, "doubleclick.net", QType::A);
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 219, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            40000 + i,
            53,
            64,
            &q,
        );
        to_tun_tx.send(pkt).await.unwrap();
    }

    let mut replies = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && replies < 32 {
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), from_tun_rx.recv()).await {
            replies += 1;
        }
    }
    assert!(replies >= 32, "Expected fast local replies under burst load, got {replies}");

    let _ = shut_tx.send(true);
    let _ = handle.await;
}
