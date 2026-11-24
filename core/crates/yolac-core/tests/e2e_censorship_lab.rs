use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use yolac_blocklist::Blocklist;
use yolac_core::{
    check_github_release_endpoint, AdaptiveController, ErrorCode, ModuleHealthStatus, ModuleId,
    UpdateCheckResult, YolacConfig, YolacEngine,
};
use yolac_dns::wire::{build_dns_query, parse_dns_query, parse_dns_response, DnsRecordData, QType};
use yolac_dns::{DnsConfig, DnsEngine, DnsOutcome, UpstreamConfig, UpstreamProtocol};
use yolac_dpi::{
    build_ipv4_tcp_packet, build_ipv4_udp_packet, build_ipv6_udp_packet, parse_client_hello,
    parse_ip_packet, parse_tcp, parse_udp, DpiStrategy, IpProtocol, ParsedTcp, PlatformCapabilities,
    QuicPolicy,
};
use yolac_net::{
    ChannelPacketDevice, DpiTcpRelay, Ipv6LeakMode, MemoryProfile, NoopProtector,
    NoopStrategyAdvisor, TunConfig, TunEngine,
};

fn build_test_tls_configs(
    sans: Vec<String>,
) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let cert = generate_simple_self_signed(sans).expect("rcgen cert");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key der");

    let mut srv_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server tls config");
    srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("add root");
    let mut cli_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    (Arc::new(srv_cfg), Arc::new(cli_cfg))
}

/// Spawns a real TLS echo server that reads `PING` and replies `OK:YOLAC`.
async fn spawn_tls_echo_server(srv_cfg: Arc<ServerConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(srv_cfg);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 64];
                if let Ok(n) = tls.read(&mut buf).await {
                    if n > 0 {
                        let _ = tls.write_all(b"OK:YOLAC").await;
                        let _ = tls.flush().await;
                    }
                }
            });
        }
    });
    addr
}

/// Spawns a simulated stateful/shallow SNI DPI middlebox:
/// inspects the very first incoming TCP read; if `parse_client_hello` extracts `blocked_sni`,
/// it drops/RSTs the connection immediately. Otherwise proxies transparently.
async fn spawn_sni_dpi_middlebox(backend: SocketAddr, blocked_sni: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = vec![0u8; 4096];
                let Ok(n) = client.read(&mut first).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let first_chunk = &first[..n];
                if let Some(ch) = parse_client_hello(first_chunk) {
                    if ch.sni.as_deref() == Some(blocked_sni) {
                        // DPI blocks connection!
                        drop(client);
                        return;
                    }
                }
                let Ok(mut upstream) = TcpStream::connect(backend).await else {
                    return;
                };
                if upstream.write_all(first_chunk).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_1_sni_dpi_middlebox_blocks_direct_but_yolac_bypasses() {
    let (srv_cfg, cli_cfg) = build_test_tls_configs(vec!["blocked.yolac.test".into()]);
    let tls_backend = spawn_tls_echo_server(srv_cfg).await;
    let dpi_addr = spawn_sni_dpi_middlebox(tls_backend, "blocked.yolac.test").await;

    // A) Direct TLS connection to middlebox MUST FAIL (blocked by DPI)
    let connector = TlsConnector::from(Arc::clone(&cli_cfg));
    let direct_tcp = TcpStream::connect(dpi_addr).await.unwrap();
    let sni = ServerName::try_from("blocked.yolac.test".to_string()).unwrap();
    let direct_res = connector.connect(sni.clone(), direct_tcp).await;
    assert!(direct_res.is_err(), "Direct unfragmented ClientHello must be blocked by DPI");

    // B) Connection relayed via YOLAÇ DpiTcpRelay MUST SUCCEED
    let local_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = local_proxy.local_addr().unwrap();
    let relay = Arc::new(DpiTcpRelay::new(
        Arc::new(NoopProtector),
        Arc::new(NoopStrategyAdvisor {
            default_strategy: DpiStrategy::TlsAndTcpSplit,
        }),
    ));

    tokio::spawn(async move {
        if let Ok((sock, _)) = local_proxy.accept().await {
            let _ = relay.relay_stream(sock, dpi_addr).await;
        }
    });

    let proxied_tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls = connector
        .connect(sni, proxied_tcp)
        .await
        .expect("YOLAÇ must bypass SNI DPI middlebox");
    tls.write_all(b"PING").await.unwrap();
    tls.flush().await.unwrap();
    let mut reply = [0u8; 16];
    let n = tls.read(&mut reply).await.unwrap();
    assert_eq!(&reply[..n], b"OK:YOLAC");
}

fn build_dns_a_answer(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
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
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

fn build_dns_cname_answer(query: &[u8], target: &str) -> Vec<u8> {
    let q = parse_dns_query(query).unwrap();
    let qsec = &query[12..q.question_end];
    let mut rdata = Vec::new();
    for label in target.split('.') {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0);

    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(qsec);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&5u16.to_be_bytes()); // CNAME
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

#[tokio::test]
async fn test_2_encrypted_dns_blocklist_cname_uncloak_poison_failover_behind_dpi() {
    let (srv_cfg, cli_cfg) = build_test_tls_configs(vec!["dot.yolac.test".into(), "doh.yolac.test".into()]);
    let upstream_hits = Arc::new(AtomicUsize::new(0));

    // Primary DoT server: returns poisoned 127.0.0.1
    let dot_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_addr = dot_listener.local_addr().unwrap();
    let dot_acc = TlsAcceptor::from(Arc::clone(&srv_cfg));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = dot_listener.accept().await {
            let acc = dot_acc.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else { return; };
                let mut lbuf = [0u8; 2];
                if tls.read_exact(&mut lbuf).await.is_err() { return; }
                let len = u16::from_be_bytes(lbuf) as usize;
                let mut q = vec![0u8; len];
                if tls.read_exact(&mut q).await.is_err() { return; }
                let ans = build_dns_a_answer(&q, Ipv4Addr::new(127, 0, 0, 1), 60);
                let _ = tls.write_all(&(ans.len() as u16).to_be_bytes()).await;
                let _ = tls.write_all(&ans).await;
                let _ = tls.flush().await;
            });
        }
    });

    // Backup DoH server (placed BEHIND simulated SNI DPI middlebox!)
    let doh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let doh_backend_addr = doh_listener.local_addr().unwrap();
    let doh_acc = TlsAcceptor::from(Arc::clone(&srv_cfg));
    let hits_clone = Arc::clone(&upstream_hits);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = doh_listener.accept().await {
            let acc = doh_acc.clone();
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else { return; };
                let mut req = vec![0u8; 4096];
                let Ok(n) = tls.read(&mut req).await else { return; };
                let Some(hdr_end) = req[..n].windows(4).position(|w| w == b"\r\n\r\n") else { return; };
                let hdr_str = std::str::from_utf8(&req[..hdr_end]).unwrap_or("");
                let content_len: usize = hdr_str
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower.strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                let mut body = req[hdr_end + 4..n].to_vec();
                while body.len() < content_len {
                    let mut more = [0u8; 1024];
                    let Ok(rn) = tls.read(&mut more).await else { break; };
                    if rn == 0 { break; }
                    body.extend_from_slice(&more[..rn]);
                }
                hits.fetch_add(1, Ordering::Relaxed);
                let parsed = parse_dns_query(&body).unwrap();
                let dns_resp = if parsed.qname == "cloaked.yolac.test" {
                    build_dns_cname_answer(&body, "tracked-cname.yolac.test")
                } else {
                    build_dns_a_answer(&body, Ipv4Addr::new(93, 184, 216, 34), 300)
                };
                let http_resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    dns_resp.len()
                );
                let _ = tls.write_all(http_resp.as_bytes()).await;
                let _ = tls.write_all(&dns_resp).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    let doh_dpi_addr = spawn_sni_dpi_middlebox(doh_backend_addr, "doh.yolac.test").await;

    let dns_cfg = DnsConfig {
        upstreams: vec![
            UpstreamConfig {
                name: "Poisoned-DoT",
                protocol: UpstreamProtocol::DoT,
                bootstrap_ip: dot_addr.ip(),
                port: dot_addr.port(),
                tls_server_name: "dot.yolac.test".into(),
                doh_path: String::new(),
                apply_dpi_evasion: true,
                custom_tls_config: Some(Arc::clone(&cli_cfg)),
            },
            UpstreamConfig {
                name: "Clean-DoH-Behind-DPI",
                protocol: UpstreamProtocol::DoH,
                bootstrap_ip: doh_dpi_addr.ip(),
                port: doh_dpi_addr.port(),
                tls_server_name: "doh.yolac.test".into(),
                doh_path: "/dns-query".into(),
                apply_dpi_evasion: true,
                custom_tls_config: Some(Arc::clone(&cli_cfg)),
            },
        ],
        cache_max_entries: 64,
        upstream_timeout: Duration::from_secs(2),
        block_with_nxdomain: false,
        suppress_aaaa: false,
    };

    let bl = Arc::new(Blocklist::embedded_default());
    let engine = DnsEngine::new(dns_cfg, bl, None);

    // 1. Blocked ad domain -> zero upstream hits
    let q_ad = build_dns_query(1, "stats.g.doubleclick.net", QType::A);
    let (resp_ad, outcome_ad) = engine.resolve(&q_ad).await;
    assert_eq!(outcome_ad, DnsOutcome::BlockedDomain);
    assert_eq!(upstream_hits.load(Ordering::Relaxed), 0);
    let parsed_ad = parse_dns_response(&resp_ad.unwrap()).unwrap();
    assert_eq!(parsed_ad.answers[0].data, DnsRecordData::A(Ipv4Addr::UNSPECIFIED));

    // 2. Clean domain -> poisoned primary rejected -> failover to DoH behind DPI -> real IP returned!
    let q_clean = build_dns_query(2, "clean.yolac.test", QType::A);
    let (resp_clean, outcome_clean) = engine.resolve(&q_clean).await;
    assert_eq!(outcome_clean, DnsOutcome::UpstreamResolved);
    let parsed_clean = parse_dns_response(&resp_clean.unwrap()).unwrap();
    assert_eq!(
        parsed_clean.answers[0].data,
        DnsRecordData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
    assert_eq!(engine.stats_snapshot().poisoning_failovers, 1);

    // 3. Cache hit for clean domain
    let q_clean2 = build_dns_query(3, "clean.yolac.test", QType::A);
    let (resp_cached, outcome_cached) = engine.resolve(&q_clean2).await;
    assert_eq!(outcome_cached, DnsOutcome::CacheHit);
    assert_eq!(parse_dns_response(&resp_cached.unwrap()).unwrap().id, 3);

    // 4. CNAME uncloaking catches hidden tracker CNAME
    let q_cname = build_dns_query(4, "cloaked.yolac.test", QType::A);
    let (resp_cname, outcome_cname) = engine.resolve(&q_cname).await;
    assert_eq!(outcome_cname, DnsOutcome::BlockedCnameUncloak);
    assert_eq!(
        parse_dns_response(&resp_cname.unwrap()).unwrap().answers[0].data,
        DnsRecordData::A(Ipv4Addr::UNSPECIFIED)
    );
}

#[tokio::test]
async fn test_3_virtual_tun_packet_loop_dns_leak_guard_quic_and_tcp() {
    // Local TCP echo server to test smoltcp TUN -> DpiTcpRelay -> real socket
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                let mut total = 0usize;
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&buf[..n]).await;
                    total += n;
                    if total >= 34 {
                        break;
                    }
                }
            });
        }
    });

    let bl = Arc::new(Blocklist::embedded_default());
    let dns = Arc::new(DnsEngine::new(
        DnsConfig {
            upstreams: vec![],
            ..DnsConfig::default()
        },
        bl,
        None,
    ));

    let tun_cfg = TunConfig {
        mtu: 1500,
        profile: MemoryProfile::LowMemoryIos,
        ipv6_mode: Ipv6LeakMode::BlockUnprotectedIpv6,
        quic_policy: QuicPolicy::BlockFallbackToTcp,
    };
    let tun = Arc::new(TunEngine::new(
        tun_cfg,
        dns,
        Arc::new(NoopProtector),
        Arc::new(NoopStrategyAdvisor {
            default_strategy: DpiStrategy::TlsAndTcpSplit,
        }),
    ));

    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(64);
    let (from_tun_tx, mut from_tun_rx) = mpsc::channel::<Vec<u8>>(64);
    let dev = Arc::new(ChannelPacketDevice::new(to_tun_rx, from_tun_tx));
    let (shut_tx, shut_rx) = tokio::sync::watch::channel(false);

    let tun_run = Arc::clone(&tun);
    let task = tokio::spawn(async move {
        let _ = tun_run.run(dev, shut_rx).await;
    });

    // Real Android VpnService & iOS NEPacketTunnelProvider client TUN address (.1, while smoltcp gateway owns .2)
    let client_v4 = Ipv4Addr::new(10, 219, 0, 1);

    // 1. Send raw IPv4 UDP/53 DNS packet for blocked domain -> expect local 0.0.0.0 reply
    let dns_q = build_dns_query(0x7777, "doubleclick.net", QType::A);
    let dns_pkt = build_ipv4_udp_packet(client_v4, Ipv4Addr::new(1, 1, 1, 1), 53000, 53, 64, &dns_q);
    to_tun_tx.send(dns_pkt).await.unwrap();

    let dns_reply_raw = tokio::time::timeout(Duration::from_secs(2), from_tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let parsed_ip = parse_ip_packet(&dns_reply_raw).unwrap();
    assert_eq!(parsed_ip.protocol, IpProtocol::Udp);
    let parsed_udp = parse_udp(parsed_ip.payload).unwrap();
    assert_eq!(parsed_udp.dst_port, 53000);
    let parsed_dns = parse_dns_response(parsed_udp.payload).unwrap();
    assert_eq!(parsed_dns.id, 0x7777);
    assert_eq!(parsed_dns.answers[0].data, DnsRecordData::A(Ipv4Addr::UNSPECIFIED));

    // 2. Send IPv6 UDP/443 packet -> blocked by Ipv6LeakMode::BlockUnprotectedIpv6 (no outbound leak)
    let v6_pkt = build_ipv6_udp_packet(
        Ipv6Addr::new(0xfd79, 0x6f6c, 0x6163, 0, 0, 0, 0, 2),
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 1111),
        54000,
        443,
        64,
        b"leak_test",
    );
    to_tun_tx.send(v6_pkt).await.unwrap();

    // 3. Send IPv4 UDP/443 QUIC Initial -> dropped for TCP fallback
    let mut quic_init = vec![0u8; 1200];
    quic_init[0] = 0xC3;
    quic_init[1..5].copy_from_slice(&1u32.to_be_bytes());
    let quic_pkt = build_ipv4_udp_packet(client_v4, Ipv4Addr::new(93, 184, 216, 34), 54001, 443, 64, &quic_init);
    to_tun_tx.send(quic_pkt).await.unwrap();

    // 4. Real 3-way TCP handshake through smoltcp virtual TUN to local echo server
    let dst_v4 = match echo_addr.ip() {
        IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let syn_pkt = build_ipv4_tcp_packet(
        client_v4,
        dst_v4,
        55123,
        echo_addr.port(),
        100,
        0,
        ParsedTcp::SYN,
        65535,
        64,
        1,
        &[],
        &[],
    );
    to_tun_tx.send(syn_pkt).await.unwrap();

    // Wait for SYN-ACK from smoltcp
    let mut syn_ack_seq = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(pkt)) = tokio::time::timeout(Duration::from_millis(200), from_tun_rx.recv()).await {
            if let Some(ip) = parse_ip_packet(&pkt) {
                if ip.protocol == IpProtocol::Tcp {
                    if let Some(tcp) = parse_tcp(ip.payload) {
                        if (tcp.flags & (ParsedTcp::SYN | ParsedTcp::ACK)) == (ParsedTcp::SYN | ParsedTcp::ACK) {
                            syn_ack_seq = Some(tcp.seq);
                            break;
                        }
                    }
                }
            }
        }
    }
    let server_seq = syn_ack_seq.expect("must receive SYN-ACK from virtual TUN");

    // Send ACK + HTTP-like payload
    let ack_pkt = build_ipv4_tcp_packet(
        client_v4,
        dst_v4,
        55123,
        echo_addr.port(),
        101,
        server_seq.wrapping_add(1),
        ParsedTcp::ACK | ParsedTcp::PSH,
        65535,
        64,
        2,
        &[],
        b"GET / HTTP/1.1\r\nHost: ok.test\r\n\r\n",
    );
    to_tun_tx.send(ack_pkt).await.unwrap();

    let mut received_echo = Vec::new();
    let echo_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < echo_deadline {
        if let Ok(Some(pkt)) = tokio::time::timeout(Duration::from_millis(200), from_tun_rx.recv()).await {
            if let Some(ip) = parse_ip_packet(&pkt) {
                if ip.protocol == IpProtocol::Tcp {
                    if let Some(tcp) = parse_tcp(ip.payload) {
                        if !tcp.payload.is_empty() {
                            received_echo.extend_from_slice(tcp.payload);
                            if received_echo.starts_with(b"GET / HTTP/1.1") {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        received_echo.windows(7).any(|w| w == b"hOsT: o")
            || received_echo.windows(4).any(|w| w == b"GET "),
        "Expected echoed HTTP payload through virtual TUN, got: {:?}",
        String::from_utf8_lossy(&received_echo)
    );

    let _ = shut_tx.send(true);
    let _ = task.await;
}

#[tokio::test]
async fn test_4_adaptive_controller_auto_escalates_after_dpi_rst() {
    let (srv_cfg, cli_cfg) = build_test_tls_configs(vec!["adaptive.yolac.test".into()]);
    let tls_backend = spawn_tls_echo_server(srv_cfg).await;
    let dpi_addr = spawn_sni_dpi_middlebox(tls_backend, "adaptive.yolac.test").await;

    // Start in Passthrough so first connection hits DPI RST
    let adaptive = Arc::new(AdaptiveController::new(
        PlatformCapabilities::MOBILE_SANDBOX,
        DpiStrategy::Passthrough,
        64,
    ));
    let relay = Arc::new(DpiTcpRelay::new(Arc::new(NoopProtector), adaptive));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = proxy.accept().await {
            let r = Arc::clone(&relay);
            tokio::spawn(async move {
                let _ = r.relay_stream(sock, dpi_addr).await;
            });
        }
    });

    let connector = TlsConnector::from(cli_cfg);
    let sni = ServerName::try_from("adaptive.yolac.test".to_string()).unwrap();

    // Attempt 1: Starts in Passthrough, hits DPI RST -> DpiTcpRelay transparently retries
    // with escalated TlsRecordSplit BEFORE any bytes reach client -> succeeds on FIRST attempt!
    let c1 = TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls = connector
        .connect(sni.clone(), c1)
        .await
        .expect("First attempt must succeed transparently via automatic DPI retry + escalation");
    tls.write_all(b"PING").await.unwrap();
    let mut buf = [0u8; 16];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"OK:YOLAC");

    // Attempt 2: Strategy is now remembered in salted RAM table -> succeeds immediately without retry
    let c2 = TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls2 = connector
        .connect(sni, c2)
        .await
        .expect("Subsequent attempt must use remembered escalated strategy");
    tls2.write_all(b"PING").await.unwrap();
    let n2 = tls2.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"OK:YOLAC");
}

#[tokio::test]
async fn test_5_yolac_engine_ios_low_memory_and_clean_shutdown() {
    let engine = YolacEngine::new(YolacConfig::mobile_ios(), None);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
    let (out_tx, _out_rx) = mpsc::channel::<Vec<u8>>(16);
    let dev = Arc::new(ChannelPacketDevice::new(in_rx, out_tx));

    engine.start_tun(dev).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(engine.state().as_u8(), 2); // Active

    drop(in_tx);
    engine.stop().await;
    assert_eq!(engine.state().as_u8(), 0); // Inactive
}

#[tokio::test]
async fn test_6_real_7_module_health_transitions_passive_active_error() {
    let engine = YolacEngine::new(YolacConfig::mobile_android(), None);

    // 1. Passive -> all 7 modules MUST be Gray (PassiveOrUnchecked), zero fake Green!
    let passive = engine.health_snapshot();
    assert_eq!(passive.len(), 7);
    assert_eq!(passive[0].id, ModuleId::SmartProtection);
    assert_eq!(passive[6].id, ModuleId::Updates);
    for report in &passive {
        assert_eq!(
            report.status,
            ModuleHealthStatus::PassiveOrUnchecked,
            "Module {:?} must be Gray while inactive",
            report.id
        );
    }

    // 2. Active -> modules 0..6 verified Green, Updates stays Gray until user triggers manual check!
    let (_in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
    let (out_tx, _out_rx) = mpsc::channel::<Vec<u8>>(16);
    let dev = Arc::new(ChannelPacketDevice::new(in_rx, out_tx));
    engine.start_tun(dev).await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;

    let active = engine.health_snapshot();
    for report in &active[..6] {
        assert_eq!(
            report.status,
            ModuleHealthStatus::Healthy,
            "Module {:?} should be Green when verified active: {}",
            report.id,
            report.detail_tr
        );
    }
    assert_eq!(
        active[6].status,
        ModuleHealthStatus::PassiveOrUnchecked,
        "Updates must remain Gray until explicitly checked by user"
    );

    // 3. Platform error -> affected modules turn Red honestly!
    engine.record_platform_error(ErrorCode::PermissionDenied);
    let errored = engine.health_snapshot();
    assert_eq!(errored[0].status, ModuleHealthStatus::Error);
    assert_eq!(errored[1].status, ModuleHealthStatus::Error);
    assert_eq!(errored[3].status, ModuleHealthStatus::Error);
    assert_eq!(errored[4].status, ModuleHealthStatus::Error);

    // 4. Stop -> returns to Gray cleanly
    engine.stop().await;
    let after_stop = engine.health_snapshot();
    for report in &after_stop[..6] {
        assert_eq!(report.status, ModuleHealthStatus::PassiveOrUnchecked);
    }
}

#[tokio::test]
async fn test_7_github_releases_updater_live_tls_validation() {
    let (srv_cfg, cli_cfg) = build_test_tls_configs(vec!["api.github.test".into()]);

    async fn spawn_mock_github(
        srv_cfg: Arc<ServerConfig>,
        status: &'static str,
        body: &'static str,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = TlsAcceptor::from(srv_cfg);
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                if let Ok(mut tls) = acc.accept(tcp).await {
                    let mut req = [0u8; 1024];
                    let _ = tls.read(&mut req).await;
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
                }
            }
        });
        addr
    }

    // Case A: Newer official release -> UpdateAvailable with verified official URL
    let addr_new = spawn_mock_github(
        Arc::clone(&srv_cfg),
        "200 OK",
        r#"{"tag_name":"v0.2.0","html_url":"https://github.com/test-org/yolac/releases/tag/v0.2.0"}"#,
    )
    .await;
    let res_new = check_github_release_endpoint(
        "test-org/yolac",
        "0.1.0",
        addr_new,
        "api.github.test",
        Arc::clone(&cli_cfg),
    )
    .await;
    assert_eq!(
        res_new,
        UpdateCheckResult::UpdateAvailable {
            current_version: "0.1.0".into(),
            latest_version: "0.2.0".into(),
            release_url: "https://github.com/test-org/yolac/releases/tag/v0.2.0".into(),
        }
    );

    // Case B: Up to date
    let addr_same = spawn_mock_github(
        Arc::clone(&srv_cfg),
        "200 OK",
        r#"{"tag_name":"v0.1.0","html_url":"https://github.com/test-org/yolac/releases/tag/v0.1.0"}"#,
    )
    .await;
    let res_same = check_github_release_endpoint(
        "test-org/yolac",
        "0.1.0",
        addr_same,
        "api.github.test",
        Arc::clone(&cli_cfg),
    )
    .await;
    assert_eq!(
        res_same,
        UpdateCheckResult::UpToDate {
            current_version: "0.1.0".into(),
        }
    );

    // Case C: Tampered / third-party redirect URL MUST be rejected!
    let addr_evil = spawn_mock_github(
        Arc::clone(&srv_cfg),
        "200 OK",
        r#"{"tag_name":"v9.9.9","html_url":"https://evil.example.com/fake-yolac.apk"}"#,
    )
    .await;
    let res_evil = check_github_release_endpoint(
        "test-org/yolac",
        "0.1.0",
        addr_evil,
        "api.github.test",
        Arc::clone(&cli_cfg),
    )
    .await;
    assert!(matches!(res_evil, UpdateCheckResult::Error(_)));

    // Case D: HTTP 404 -> honest error
    let addr_404 = spawn_mock_github(Arc::clone(&srv_cfg), "404 Not Found", r#"{"message":"Not Found"}"#).await;
    let res_404 = check_github_release_endpoint(
        "test-org/yolac",
        "0.1.0",
        addr_404,
        "api.github.test",
        cli_cfg,
    )
    .await;
    assert!(matches!(res_404, UpdateCheckResult::Error(_)));
}

#[tokio::test]
async fn test_8_tun_backpressure_streaming_and_post_quantum_client_hello_reassembly() {
    // Part A: Large 160 KiB streaming download through TunEngine with real Android client IP 10.219.0.1.
    // Proves ChannelStream::poll_write registers its Tokio waker cleanly under channel saturation (> 32 chunks)
    // and smoltcp (.2) communicates seamlessly with OS TUN IP (.1) without IP collision.
    const TOTAL_DOWNLOAD_BYTES: usize = 160 * 1024;
    let dl_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dl_addr = dl_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = dl_listener.accept().await {
            let mut req = [0u8; 64];
            if let Ok(n) = s.read(&mut req).await {
                if n > 0 {
                    let payload = vec![0x5Au8; TOTAL_DOWNLOAD_BYTES];
                    let _ = s.write_all(&payload).await;
                    let _ = s.shutdown().await;
                }
            }
        }
    });

    let bl = Arc::new(Blocklist::embedded_default());
    let dns = Arc::new(DnsEngine::new(
        DnsConfig {
            upstreams: vec![],
            ..DnsConfig::default()
        },
        bl,
        None,
    ));
    let tun = Arc::new(TunEngine::new(
        TunConfig {
            mtu: 1500,
            profile: MemoryProfile::Standard,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
        },
        dns,
        Arc::new(NoopProtector),
        Arc::new(NoopStrategyAdvisor {
            default_strategy: DpiStrategy::TlsAndTcpSplit,
        }),
    ));

    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(64);
    let (from_tun_tx, mut from_tun_rx) = mpsc::channel::<Vec<u8>>(64);
    let dev = Arc::new(ChannelPacketDevice::new(to_tun_rx, from_tun_tx));
    let (shut_tx, shut_rx) = tokio::sync::watch::channel(false);

    let tun_run = Arc::clone(&tun);
    let task = tokio::spawn(async move {
        let _ = tun_run.run(dev, shut_rx).await;
    });

    let client_v4 = Ipv4Addr::new(10, 219, 0, 1);
    let dst_v4 = match dl_addr.ip() {
        IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let syn_pkt = build_ipv4_tcp_packet(
        client_v4,
        dst_v4,
        55200,
        dl_addr.port(),
        500,
        0,
        ParsedTcp::SYN,
        65535,
        64,
        1,
        &[],
        &[],
    );
    to_tun_tx.send(syn_pkt).await.unwrap();

    let mut srv_seq = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(pkt)) = tokio::time::timeout(Duration::from_millis(200), from_tun_rx.recv()).await {
            if let Some(ip) = parse_ip_packet(&pkt) {
                if ip.protocol == IpProtocol::Tcp {
                    if let Some(tcp) = parse_tcp(ip.payload) {
                        if (tcp.flags & (ParsedTcp::SYN | ParsedTcp::ACK)) == (ParsedTcp::SYN | ParsedTcp::ACK) {
                            srv_seq = Some(tcp.seq.wrapping_add(1));
                            break;
                        }
                    }
                }
            }
        }
    }
    let mut expected_srv_seq = srv_seq.expect("must receive SYN-ACK for client 10.219.0.1");

    // Send ACK + download trigger
    let req_payload = b"DL";
    let ack_pkt = build_ipv4_tcp_packet(
        client_v4,
        dst_v4,
        55200,
        dl_addr.port(),
        501,
        expected_srv_seq,
        ParsedTcp::ACK | ParsedTcp::PSH,
        65535,
        64,
        2,
        &[],
        req_payload,
    );
    to_tun_tx.send(ack_pkt).await.unwrap();

    let mut received_total = 0usize;
    let mut ip_id = 3u16;
    let dl_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received_total < TOTAL_DOWNLOAD_BYTES && tokio::time::Instant::now() < dl_deadline {
        if let Ok(Some(pkt)) = tokio::time::timeout(Duration::from_millis(300), from_tun_rx.recv()).await {
            if let Some(ip) = parse_ip_packet(&pkt) {
                if ip.protocol == IpProtocol::Tcp {
                    if let Some(tcp) = parse_tcp(ip.payload) {
                        if !tcp.payload.is_empty() && tcp.seq == expected_srv_seq {
                            received_total += tcp.payload.len();
                            expected_srv_seq = expected_srv_seq.wrapping_add(tcp.payload.len() as u32);
                            // ACK received data to advance smoltcp's send window
                            let ack = build_ipv4_tcp_packet(
                                client_v4,
                                dst_v4,
                                55200,
                                dl_addr.port(),
                                501 + req_payload.len() as u32,
                                expected_srv_seq,
                                ParsedTcp::ACK,
                                65535,
                                64,
                                ip_id,
                                &[],
                                &[],
                            );
                            ip_id = ip_id.wrapping_add(1);
                            let _ = to_tun_tx.send(ack).await;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        received_total, TOTAL_DOWNLOAD_BYTES,
        "160 KiB stream through TunEngine must complete without ChannelStream waker deadlock"
    );

    let _ = shut_tx.send(true);
    let _ = task.await;

    // Part B: 1900-byte Post-Quantum Chrome-style ClientHello arriving in 2 TCP chunks into DpiTcpRelay
    // must be reassembled, TLS-record fragmented across SNI, and accepted by backend!
    let pq_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pq_backend_addr = pq_backend.local_addr().unwrap();
    let saw_fragmented_records = Arc::new(AtomicUsize::new(0));
    let saw_clone = Arc::clone(&saw_fragmented_records);
    tokio::spawn(async move {
        if let Ok((mut s, _)) = pq_backend.accept().await {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline && got.len() < 1900 {
                match tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            // Count TLS handshake records received (fragmented ClientHello => 2 records)
            let mut pos = 0;
            let mut records = 0;
            while pos + 5 <= got.len() && got[pos] == 0x16 {
                let rlen = u16::from_be_bytes([got[pos + 3], got[pos + 4]]) as usize;
                pos += 5 + rlen;
                records += 1;
            }
            saw_clone.store(records, Ordering::SeqCst);
            let _ = s.write_all(b"PQ_OK").await;
        }
    });

    let relay = Arc::new(DpiTcpRelay::new(
        Arc::new(NoopProtector),
        Arc::new(NoopStrategyAdvisor {
            default_strategy: DpiStrategy::TlsAndTcpSplit,
        }),
    ));
    let local_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = local_proxy.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((sock, _)) = local_proxy.accept().await {
            let _ = relay.relay_stream(sock, pq_backend_addr).await;
        }
    });

    // Build a 1900+ byte Post-Quantum ClientHello
    let sni_bytes = b"pq-mobile.example.org";
    let entry_len = 1 + 2 + sni_bytes.len();
    let sni_ext_len = 2 + entry_len;
    let pq_len = 1750usize;
    let exts_len = (4 + sni_ext_len) + (4 + pq_len);
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xAA; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(exts_len as u16).to_be_bytes());
    body.extend_from_slice(&0x0000u16.to_be_bytes());
    body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    body.extend_from_slice(&(entry_len as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sni_bytes);
    body.extend_from_slice(&0x0033u16.to_be_bytes());
    body.extend_from_slice(&(pq_len as u16).to_be_bytes());
    body.resize(body.len() + pq_len, 0x77);
    let hs_len = body.len();
    let mut pq_ch = vec![0x16, 0x03, 0x01];
    pq_ch.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
    pq_ch.push(0x01);
    pq_ch.push(((hs_len >> 16) & 0xFF) as u8);
    pq_ch.push(((hs_len >> 8) & 0xFF) as u8);
    pq_ch.push((hs_len & 0xFF) as u8);
    pq_ch.extend_from_slice(&body);

    let mut cli = TcpStream::connect(proxy_addr).await.unwrap();
    // Deliver across two separate TCP writes simulating 1460B MSS split
    cli.write_all(&pq_ch[..1460]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(15)).await;
    cli.write_all(&pq_ch[1460..]).await.unwrap();

    let mut reply = [0u8; 16];
    let rn = tokio::time::timeout(Duration::from_secs(2), cli.read(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..rn], b"PQ_OK");
    assert_eq!(
        saw_fragmented_records.load(Ordering::SeqCst),
        2,
        "DpiTcpRelay must reassemble & TLS-fragment 1900+ byte Post-Quantum ClientHello into 2 records"
    );
}

#[tokio::test]
async fn test_9_turkey_isp_stateful_dpi_blocks_weak_split_but_multi_record_and_escalation_bypass() {
    // Realistic Turkish ISP DPI simulator that reassembles simple 2-record splits AND inspects SNI,
    // blocking any connection that doesn't split into >= 3 TLS records / small chunks!
    let (srv_cfg, cli_cfg) = build_test_tls_configs(vec!["www.roblox.com".into()]);
    let tls_backend = spawn_tls_echo_server(srv_cfg).await;

    let strict_dpi = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let strict_dpi_addr = strict_dpi.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = strict_dpi.accept().await {
            tokio::spawn(async move {
                // Simulate stateful ISP DPI reading first 20ms of bytes (reassembling simple 2-part splits!)
                let mut collected = Vec::new();
                let mut tmp = [0u8; 4096];
                let window = tokio::time::Instant::now() + Duration::from_millis(25);
                while tokio::time::Instant::now() < window {
                    match tokio::time::timeout(Duration::from_millis(8), client.read(&mut tmp)).await {
                        Ok(Ok(n)) if n > 0 => collected.extend_from_slice(&tmp[..n]),
                        _ => break,
                    }
                }
                // Count TLS records in the collected burst: if < 4 records and contains raw "roblox.com"
                // in fewer than 4 TLS fragments -> DPI blocks with RST!
                let mut pos = 0usize;
                let mut rec_count = 0usize;
                while pos + 5 <= collected.len() && collected[pos] == 0x16 {
                    let rlen = u16::from_be_bytes([collected[pos + 3], collected[pos + 4]]) as usize;
                    pos += 5 + rlen;
                    rec_count += 1;
                }
                if rec_count < 4 {
                    drop(client); // Simulate strict ISP DPI RST blocking simple 1-3 record splits!
                    return;
                }
                let Ok(mut up) = TcpStream::connect(tls_backend).await else { return };
                if up.write_all(&collected).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
            });
        }
    });

    // Adaptive mobile controller starts at TlsMultiRecordAndTcpSplit (3 records) -> strict DPI resets ->
    // DpiTcpRelay transparently escalates to TlsSmallChunks (>= 4 records) ON THE VERY FIRST CONNECTION!
    let adaptive = Arc::new(AdaptiveController::new(
        PlatformCapabilities::MOBILE_SANDBOX,
        DpiStrategy::TlsMultiRecordAndTcpSplit,
        64,
    ));
    let relay = Arc::new(DpiTcpRelay::new(Arc::new(NoopProtector), adaptive));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = proxy.accept().await {
            let r = Arc::clone(&relay);
            tokio::spawn(async move {
                let _ = r.relay_stream(sock, strict_dpi_addr).await;
            });
        }
    });

    let connector = TlsConnector::from(cli_cfg);
    let sni = ServerName::try_from("www.roblox.com".to_string()).unwrap();
    let c = TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls = connector
        .connect(sni, c)
        .await
        .expect("Mobile ByeDPI multi-stage transparent retry must bypass strict stateful Turkish DPI on 1st load");
    tls.write_all(b"PING").await.unwrap();
    let mut reply = [0u8; 16];
    let n = tls.read(&mut reply).await.unwrap();
    assert_eq!(&reply[..n], b"OK:YOLAC");

    // Also verify Turkish BTK public sinkhole IP (195.175.254.2) is flagged as DNS poisoning!
    let q = yolac_dns::wire::DnsQuery {
        id: 77,
        flags: 0x0100,
        qname: "www.roblox.com".into(),
        qtype: QType::A,
        qclass: 1,
        question_end: 30,
    };
    let btk_resp = yolac_dns::wire::DnsResponse {
        id: 77,
        rcode: 0,
        qname: "www.roblox.com".into(),
        qtype: QType::A,
        answers: vec![yolac_dns::wire::DnsAnswer {
            rtype: 1,
            ttl: 60,
            data: DnsRecordData::A(Ipv4Addr::new(195, 175, 254, 2)),
        }],
        min_ttl: 60,
    };
    assert!(
        yolac_dns::detect_poisoning(&q, &btk_resp).is_some(),
        "Turkish ISP BTK sinkhole 195.175.254.2 must be rejected as DNS poisoning!"
    );
}
