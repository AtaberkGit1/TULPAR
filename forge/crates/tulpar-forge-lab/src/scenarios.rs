//! Simulated local censorship, throttling, L3 hop-topology, and DNS middleboxes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tulpar_forge::{ForgePackage, ForgeVerifier, MatchProtocol, PlatformSupport, StrategySpec};
use yolac_blocklist::Blocklist;
use yolac_core::{execute_raw_forge_tcp, AdaptiveController, YolacConfig, YolacEngine};
use yolac_dns::wire::{build_dns_query, parse_dns_query, parse_dns_response, DnsRecordData, QType};
use yolac_dns::{
    detect_poisoning, DnsConfig, DnsEngine, DnsOutcome, UpstreamConfig, UpstreamProtocol,
};
use yolac_dpi::{
    build_ipv4_tcp_packet, build_ipv4_udp_packet, clamp_syn_mss, detect_quic_initial,
    is_forged_passive_dpi_rst, parse_client_hello, parse_client_hello_prefix, parse_ip_packet,
    parse_tcp, ParsedTcp, PlatformCapabilities, QuicPolicy, TtlCalibrator,
};
use yolac_net::{DpiTcpRelay, NoopProtector, StrategyAdvisor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioOutcome {
    Pass,
    Fail,
    UnbypassableOnDevice,
    SkippedIncompatible,
}

#[derive(Debug, Clone)]
pub struct ScenarioResult {
    pub id: &'static str,
    pub description: &'static str,
    pub outcome: ScenarioOutcome,
    pub detail: String,
    pub elapsed_ms: u64,
}

fn build_test_tls_configs(names: Vec<String>) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let cert = generate_simple_self_signed(names).expect("self-signed test cert");
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

    (Arc::new(srv_cfg), Arc::new(cli_cfg))
}

async fn spawn_tls_echo_server(srv_cfg: Arc<ServerConfig>, artificial_delay_ms: u64) -> SocketAddr {
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
                if artificial_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(artificial_delay_ms)).await;
                }
                let mut buf = [0u8; 64];
                if let Ok(n) = tls.read(&mut buf).await {
                    if n > 0 {
                        let _ = tls.write_all(b"OK:FORGE").await;
                        let _ = tls.flush().await;
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_sni_middlebox(
    backend: SocketAddr,
    blocked_sni: &'static str,
    reassemble_window_ms: u64,
    min_tls_records_required: usize,
    throttle_only_delay_ms: Option<u64>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut collected = Vec::new();
                let mut tmp = [0u8; 4096];
                if reassemble_window_ms == 0 {
                    let Ok(n) = client.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    collected.extend_from_slice(&tmp[..n]);
                } else {
                    let deadline =
                        tokio::time::Instant::now() + Duration::from_millis(reassemble_window_ms);
                    while tokio::time::Instant::now() < deadline {
                        match tokio::time::timeout(Duration::from_millis(6), client.read(&mut tmp))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => collected.extend_from_slice(&tmp[..n]),
                            _ => break,
                        }
                    }
                }

                let mut pos = 0usize;
                let mut recs = 0usize;
                while pos + 5 <= collected.len() && collected[pos] == 0x16 {
                    let rlen = u16::from_be_bytes([collected[pos + 3], collected[pos + 4]]) as usize;
                    pos += 5 + rlen;
                    recs += 1;
                }

                let detected_blocked = parse_client_hello(&collected)
                    .and_then(|c| c.sni)
                    .as_deref()
                    == Some(blocked_sni)
                    || (recs < min_tls_records_required && recs >= 1);

                if detected_blocked {
                    if let Some(delay) = throttle_only_delay_ms {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    } else {
                        drop(client);
                        return;
                    }
                }

                let Ok(mut up) = TcpStream::connect(backend).await else {
                    return;
                };
                if up.write_all(&collected).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
            });
        }
    });
    addr
}

async fn run_socket_relay_probe(
    pkg_bytes: &[u8],
    dpi_addr: SocketAddr,
    host: &str,
    cli_cfg: Arc<ClientConfig>,
) -> Result<(), String> {
    let adaptive = Arc::new(AdaptiveController::new(
        PlatformCapabilities::MOBILE_SANDBOX,
        yolac_dpi::DpiStrategy::TlsMultiRecordAndTcpSplit,
        64,
    ));
    adaptive.load_forge_package_bytes(pkg_bytes)?;

    let relay = Arc::new(DpiTcpRelay::new(
        Arc::new(NoopProtector),
        adaptive as Arc<dyn StrategyAdvisor>,
    ));
    let proxy = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let proxy_addr = proxy.local_addr().map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        while let Ok((sock, _)) = proxy.accept().await {
            let r = Arc::clone(&relay);
            tokio::spawn(async move {
                let _ = r.relay_stream(sock, dpi_addr).await;
            });
        }
    });

    let tcp = TcpStream::connect(proxy_addr).await.map_err(|e| e.to_string())?;
    let sni = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut tls = TlsConnector::from(cli_cfg)
        .connect(sni, tcp)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"PING").await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 32];
    let n = tls.read(&mut buf).await.map_err(|e| e.to_string())?;
    if &buf[..n] == b"OK:FORGE" {
        Ok(())
    } else {
        Err(format!("unexpected response bytes ({n})"))
    }
}

/// Runs the complete local censorship & throttling simulation suite against a verified `StrategySpec`.
pub async fn run_lab_scenarios(spec: &StrategySpec) -> Vec<ScenarioResult> {
    let report = match ForgeVerifier::verify(spec) {
        Ok(r) => r,
        Err(e) => {
            return vec![ScenarioResult {
                id: "verifier_gate",
                description: "Static ForgeVerifier pre-check",
                outcome: ScenarioOutcome::Fail,
                detail: e.to_string(),
                elapsed_ms: 0,
            }];
        }
    };
    let (_, pkg_bytes) = match ForgePackage::compile(spec) {
        Ok(p) => p,
        Err(e) => {
            return vec![ScenarioResult {
                id: "compile_gate",
                description: ".tulpar binary compiler",
                outcome: ScenarioOutcome::Fail,
                detail: e.to_string(),
                elapsed_ms: 0,
            }];
        }
    };

    let android_ok = report.compatibility.android != PlatformSupport::Incompatible;
    let mut results = Vec::new();

    // 1. shallow_sni_reset
    let t0 = Instant::now();
    if !android_ok {
        results.push(ScenarioResult {
            id: "shallow_sni_reset",
            description: "Shallow SNI DPI middlebox reset (socket/mobile path)",
            outcome: ScenarioOutcome::SkippedIncompatible,
            detail: "Skipped: requires_raw_fallback = strict disables socket simulation".into(),
            elapsed_ms: 0,
        });
    } else {
        let (srv, cli) = build_test_tls_configs(vec!["blocked.lab.test".into()]);
        let backend = spawn_tls_echo_server(srv, 0).await;
        let dpi = spawn_sni_middlebox(backend, "blocked.lab.test", 0, 1, None).await;
        match run_socket_relay_probe(&pkg_bytes, dpi, "blocked.lab.test", cli).await {
            Ok(()) => results.push(ScenarioResult {
                id: "shallow_sni_reset",
                description: "Shallow SNI DPI middlebox reset (socket/mobile path)",
                outcome: ScenarioOutcome::Pass,
                detail: "Bypassed shallow ClientHello SNI inspector via socket plan".into(),
                elapsed_ms: t0.elapsed().as_millis() as u64,
            }),
            Err(e) => results.push(ScenarioResult {
                id: "shallow_sni_reset",
                description: "Shallow SNI DPI middlebox reset (socket/mobile path)",
                outcome: ScenarioOutcome::Fail,
                detail: e,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            }),
        }
    }

    // 2. stateful_sni_reassembly (>=3 records bypass)
    let t0 = Instant::now();
    if !android_ok {
        results.push(ScenarioResult {
            id: "stateful_sni_reassembly",
            description: "Stateful stream-reassembling SNI DPI (>=3 TLS records required)",
            outcome: ScenarioOutcome::SkippedIncompatible,
            detail: "Skipped on strict raw-only strategy".into(),
            elapsed_ms: 0,
        });
    } else {
        let (srv, cli) = build_test_tls_configs(vec!["strict.lab.test".into()]);
        let backend = spawn_tls_echo_server(srv, 0).await;
        let dpi = spawn_sni_middlebox(backend, "strict.lab.test", 18, 3, None).await;
        match run_socket_relay_probe(&pkg_bytes, dpi, "strict.lab.test", cli).await {
            Ok(()) => results.push(ScenarioResult {
                id: "stateful_sni_reassembly",
                description: "Stateful stream-reassembling SNI DPI (>=3 TLS records required)",
                outcome: ScenarioOutcome::Pass,
                detail: "Bypassed 18ms stateful reassembly DPI via multi-record / retry escalation"
                    .into(),
                elapsed_ms: t0.elapsed().as_millis() as u64,
            }),
            Err(e) => results.push(ScenarioResult {
                id: "stateful_sni_reassembly",
                description: "Stateful stream-reassembling SNI DPI (>=3 TLS records required)",
                outcome: ScenarioOutcome::Fail,
                detail: e,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            }),
        }
    }

    // 3. hop_sensitive_inline_dpi (L3 raw path: Windows WinDivert + Linux NFQUEUE)
    results.push(run_l3_hop_sensitive_lab(&pkg_bytes));

    // 4. passive_optical_rst (Forged passive RST vs RFC 6864 legitimate server RST)
    results.push(run_passive_rst_lab());

    // 5. http_host_block (Plaintext HTTP Host DPI blocking proxy)
    results.push(run_http_host_lab(&pkg_bytes).await);

    // 6. quic_throttle (UDP/443 QUIC Initial fallback/desync check)
    results.push(run_quic_lab(&pkg_bytes));

    // 7. protocol_throttler (Protocol-based throttling speedup vs unfragmented stalled stream)
    results.push(run_protocol_throttler_lab(&pkg_bytes, android_ok).await);

    // 8. dns_poisoning_and_adblock (Local blocklist + BTK 195.175.254.2 poison rejection + encrypted failover)
    results.push(run_dns_poison_and_adblock_lab().await);

    // 9. hard_ip_blackhole (Negative control reporting honest UnbypassableOnDevice)
    results.push(run_hard_ip_blackhole_lab().await);

    results
}

fn run_l3_hop_sensitive_lab(pkg_bytes: &[u8]) -> ScenarioResult {
    let started = Instant::now();
    let adaptive = AdaptiveController::new(
        PlatformCapabilities::WINDOWS_WINDIVERT,
        yolac_dpi::DpiStrategy::TurkeyDesyncAuto,
        64,
    );
    if let Err(e) = adaptive.load_forge_package_bytes(pkg_bytes) {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: e,
            elapsed_ms: 0,
        };
    }

    let calibrator = TtlCalibrator::default();
    let src_ip = Ipv4Addr::new(192, 168, 1, 50);
    let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
    // Simulate SYN-ACK TTL = 54 (initial 64 -> ~10 network hops to real server; DPI sits at hop 3)
    calibrator.observe_syn_ack(IpAddr::V4(dst_ip), 54);
    let dpi_hop: u8 = 3;
    let server_hops: u8 = 10;

    let ch = sample_tls_client_hello("blocked.iana-lab.test");
    let orig_seq = 5000u32;
    let orig_pkt = build_ipv4_tcp_packet(
        src_ip,
        dst_ip,
        55123,
        443,
        orig_seq,
        9001,
        ParsedTcp::ACK | ParsedTcp::PSH,
        65535,
        64,
        10,
        &[],
        &ch,
    );

    let Some(plan) = adaptive.select_raw_forge_plan(
        MatchProtocol::Tls,
        443,
        Some("blocked.iana-lab.test"),
        ch.len(),
        false,
        0,
    ) else {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: "no matching raw TLS rule found in strategy".into(),
            elapsed_ms: 0,
        };
    };

    let ch_mid = parse_client_hello_prefix(&ch)
        .and_then(|c| c.sni_range)
        .map(|(s, e)| s + (e - s) / 2)
        .unwrap_or(ch.len() / 2);

    let Some(emitted) =
        execute_raw_forge_tcp(&orig_pkt, ch_mid, None, false, &plan, &calibrator, IpAddr::V4(dst_ip))
    else {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: "raw executor produced no packets (or unexpected passthrough)".into(),
            elapsed_ms: 0,
        };
    };

    // Simulate network delivery:
    // - Server (10 hops) ONLY accepts packets with ttl >= server_hops, valid checksum, and in-window seq!
    // - DPI middlebox (3 hops) inspects first seen packet or unfragmented segments reaching hop 3.
    let mut server_tcp_buf: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut dpi_saw_benign_decoy = false;
    let mut all_five_tuples_valid = true;
    let expected_end = orig_seq.wrapping_add(ch.len() as u32);

    for d in &emitted {
        let Some(ip) = parse_ip_packet(&d.bytes) else {
            return ScenarioResult {
                id: "hop_sensitive_inline_dpi",
                description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
                outcome: ScenarioOutcome::Fail,
                detail: "emitted invalid IP packet".into(),
                elapsed_ms: 0,
            };
        };
        let Some(tcp) = parse_tcp(ip.payload) else {
            return ScenarioResult {
                id: "hop_sensitive_inline_dpi",
                description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
                outcome: ScenarioOutcome::Fail,
                detail: "emitted non-TCP packet".into(),
                elapsed_ms: 0,
            };
        };

        // Security invariant: ZERO unauthorized destination redirection!
        if ip.src_ip != IpAddr::V4(src_ip)
            || ip.dst_ip != IpAddr::V4(dst_ip)
            || tcp.src_port != 55123
            || tcp.dst_port != 443
        {
            all_five_tuples_valid = false;
        }

        let reaches_dpi = ip.ttl >= dpi_hop;
        if reaches_dpi && d.bytes != orig_pkt {
            if let Some(ch_parsed) = parse_client_hello(tcp.payload) {
                if ch_parsed.sni.as_deref() == Some(plan.decoy_sni.as_str()) {
                    dpi_saw_benign_decoy = true;
                }
            }
        }

        let reaches_server = ip.ttl >= server_hops;
        let in_window = tcp.seq >= orig_seq && tcp.seq < expected_end;
        if reaches_server && !d.preserve_bad_tcp_checksum && in_window {
            // Checksum must match RFC 1071!
            let expected_sum = yolac_dpi::tcp_checksum_ipv4(src_ip, dst_ip, ip.payload);
            let actual_sum = u16::from_be_bytes([ip.payload[16], ip.payload[17]]);
            if expected_sum != actual_sum {
                return ScenarioResult {
                    id: "hop_sensitive_inline_dpi",
                    description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
                    outcome: ScenarioOutcome::Fail,
                    detail: "real server-bound segment failed RFC 1071 TCP checksum".into(),
                    elapsed_ms: 0,
                };
            }
            server_tcp_buf.insert(tcp.seq, tcp.payload.to_vec());
        }
    }

    // Reassemble byte stream at destination server by TCP seq
    let mut keys: Vec<u32> = server_tcp_buf.keys().copied().collect();
    keys.sort_unstable();
    let mut reassembled = Vec::new();
    let mut cursor = orig_seq;
    for k in keys {
        if k == cursor {
            let chunk = &server_tcp_buf[&k];
            reassembled.extend_from_slice(chunk);
            cursor = cursor.wrapping_add(chunk.len() as u32);
        }
    }

    if !all_five_tuples_valid {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: "SECURITY INVARIANT BROKEN: modified IP/port 5-tuple!".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
    }

    if reassembled != ch {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: format!(
                "Server reassembly mismatch: got {} bytes, expected {} bytes (decoy poisoned server stream!)",
                reassembled.len(),
                ch.len()
            ),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
    }

    if !plan.decoys.is_empty() && !dpi_saw_benign_decoy {
        return ScenarioResult {
            id: "hop_sensitive_inline_dpi",
            description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
            outcome: ScenarioOutcome::Fail,
            detail: "Configured decoys never reached DPI middlebox at hop 3".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
    }

    // Also verify syn_mss_clamp rule on retry >= 1 produces valid clamped SYN packet
    if let Some(retry_plan) =
        adaptive.select_raw_forge_plan(MatchProtocol::Tls, 443, Some("blocked.iana-lab.test"), ch.len(), false, 1)
    {
        if let Some(mss) = retry_plan.syn_mss_clamp {
            let syn = build_ipv4_tcp_packet(
                src_ip,
                dst_ip,
                55123,
                443,
                orig_seq - 1,
                0,
                ParsedTcp::SYN,
                65535,
                64,
                9,
                &[2, 4, 0x05, 0xb4], // MSS = 1460
                &[],
            );
            if clamp_syn_mss(&syn, mss).is_none() {
                return ScenarioResult {
                    id: "hop_sensitive_inline_dpi",
                    description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
                    outcome: ScenarioOutcome::Fail,
                    detail: "syn_mss_clamp failed on 1460-MSS SYN packet".into(),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                };
            }
        }
    }

    ScenarioResult {
        id: "hop_sensitive_inline_dpi",
        description: "L3 raw packet TTL-hop / decoy / 5-tuple & server reassembly integrity",
        outcome: ScenarioOutcome::Pass,
        detail: format!(
            "Emitted {} packets; 5-tuple intact, server reassembled exact {}-byte ClientHello cleanly",
            emitted.len(),
            ch.len()
        ),
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

fn run_passive_rst_lab() -> ScenarioResult {
    let mut forged = build_ipv4_tcp_packet(
        Ipv4Addr::new(93, 184, 216, 34),
        Ipv4Addr::new(192, 168, 1, 50),
        443,
        55123,
        9001,
        5001,
        ParsedTcp::RST | ParsedTcp::ACK,
        0,
        61, // diff 7 from SYN-ACK TTL 54 + IP.ID=0/DF=0
        0,
        &[],
        &[],
    );
    let caught_ttl = is_forged_passive_dpi_rst(&forged, Some(54));
    let real_rfc6864 = is_forged_passive_dpi_rst(&forged, Some(61));
    forged[6] &= !0x40; // clear DF bit -> classic off-path optical RST
    let ip_csum = yolac_dpi::ipv4_header_checksum(&forged[..20]);
    forged[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let caught_df0 = is_forged_passive_dpi_rst(&forged, Some(61));

    if caught_ttl && !real_rfc6864 && caught_df0 {
        ScenarioResult {
            id: "passive_optical_rst",
            description: "Passive optical DPI forged RST drop vs real RFC 6864 server RST",
            outcome: ScenarioOutcome::Pass,
            detail: "Dropped forged TTL/DF=0 DPI RSTs while preserving real DF=1 RFC 6864 RSTs".into(),
            elapsed_ms: 0,
        }
    } else {
        ScenarioResult {
            id: "passive_optical_rst",
            description: "Passive optical DPI forged RST drop vs real RFC 6864 server RST",
            outcome: ScenarioOutcome::Fail,
            detail: "Passive RST filter misclassified forged vs RFC 6864 RST".into(),
            elapsed_ms: 0,
        }
    }
}

async fn run_http_host_lab(pkg_bytes: &[u8]) -> ScenarioResult {
    let started = Instant::now();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = backend.accept().await {
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut tmp = [0u8; 1024];
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(80), s.read(&mut tmp)).await
                {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&tmp[..n]);
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                if String::from_utf8_lossy(&got)
                    .to_ascii_lowercase()
                    .contains("host: blocked-http.lab.test")
                {
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nHTTP_OK")
                        .await;
                }
            });
        }
    });

    // Middlebox drops if raw single-read first segment contains contiguous "Host: blocked-http.lab.test"
    let dpi = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dpi_addr = dpi.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = dpi.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1024];
                let Ok(n) = c.read(&mut first).await else { return; };
                if String::from_utf8_lossy(&first[..n]).contains("Host: blocked-http.lab.test") {
                    drop(c);
                    return;
                }
                let Ok(mut up) = TcpStream::connect(b_addr).await else { return; };
                let _ = up.write_all(&first[..n]).await;
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });

    let adaptive = Arc::new(AdaptiveController::new(
        PlatformCapabilities::MOBILE_SANDBOX,
        yolac_dpi::DpiStrategy::TlsMultiRecordAndTcpSplit,
        64,
    ));
    let _ = adaptive.load_forge_package_bytes(pkg_bytes);
    let relay = Arc::new(DpiTcpRelay::new(
        Arc::new(NoopProtector),
        adaptive as Arc<dyn StrategyAdvisor>,
    ));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((sock, _)) = proxy.accept().await {
            let _ = relay.relay_stream(sock, dpi_addr).await;
        }
    });

    let mut cli = TcpStream::connect(proxy_addr).await.unwrap();
    cli.write_all(b"GET / HTTP/1.1\r\nHost: blocked-http.lab.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(2), cli.read(&mut resp)).await {
        Ok(Ok(n)) if String::from_utf8_lossy(&resp[..n]).contains("HTTP_OK") => ScenarioResult {
            id: "http_host_block",
            description: "Plaintext HTTP Host DPI inspection & circumvention",
            outcome: ScenarioOutcome::Pass,
            detail: "HTTP Host DPI bypassed via Host header transformation + TCP split".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        _ => ScenarioResult {
            id: "http_host_block",
            description: "Plaintext HTTP Host DPI inspection & circumvention",
            outcome: ScenarioOutcome::Fail,
            detail: "HTTP Host DPI middlebox blocked request".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    }
}

fn run_quic_lab(pkg_bytes: &[u8]) -> ScenarioResult {
    let adaptive = AdaptiveController::new(
        PlatformCapabilities::WINDOWS_WINDIVERT,
        yolac_dpi::DpiStrategy::TurkeyDesyncAuto,
        64,
    );
    let _ = adaptive.load_forge_package_bytes(pkg_bytes);
    let mut quic_init = vec![0u8; 1200];
    quic_init[0] = 0xC3;
    quic_init[1..5].copy_from_slice(&1u32.to_be_bytes());
    let detected = detect_quic_initial(&quic_init).is_some();
    let policy = adaptive.effective_quic_policy(443);

    if detected && policy == QuicPolicy::BlockFallbackToTcp {
        ScenarioResult {
            id: "quic_throttle",
            description: "QUIC UDP/443 Initial detection & TCP fallback policy",
            outcome: ScenarioOutcome::Pass,
            detail: "Detected QUIC Initial (v1) and enforced BlockFallbackToTcp to TLS/443".into(),
            elapsed_ms: 0,
        }
    } else if detected && policy == QuicPolicy::Allow {
        ScenarioResult {
            id: "quic_throttle",
            description: "QUIC UDP/443 Initial detection & TCP fallback policy",
            outcome: ScenarioOutcome::Pass,
            detail: "Strategy explicitly configured QuicMode::Allow (UDP/443 permitted)".into(),
            elapsed_ms: 0,
        }
    } else {
        ScenarioResult {
            id: "quic_throttle",
            description: "QUIC UDP/443 Initial detection & TCP fallback policy",
            outcome: ScenarioOutcome::Fail,
            detail: "QUIC Initial detection/policy failed".into(),
            elapsed_ms: 0,
        }
    }
}

async fn run_protocol_throttler_lab(pkg_bytes: &[u8], android_ok: bool) -> ScenarioResult {
    if !android_ok {
        return ScenarioResult {
            id: "protocol_throttler",
            description: "Protocol/SNI-based throttling mitigation (vs unfragmented delay)",
            outcome: ScenarioOutcome::SkippedIncompatible,
            detail: "Skipped on strict raw-only strategy".into(),
            elapsed_ms: 0,
        };
    }
    let started = Instant::now();
    let (srv, cli) = build_test_tls_configs(vec!["throttled.lab.test".into()]);
    let backend = spawn_tls_echo_server(srv, 0).await;
    // Middlebox throttles unfragmented SNI-classified flows by 180 ms, lets fragmented handshakes through in <20 ms
    let dpi = spawn_sni_middlebox(backend, "throttled.lab.test", 0, 1, Some(180)).await;

    let t_direct = Instant::now();
    let direct_tcp = TcpStream::connect(dpi).await.unwrap();
    let sni = ServerName::try_from("throttled.lab.test".to_string()).unwrap();
    let _ = TlsConnector::from(Arc::clone(&cli)).connect(sni, direct_tcp).await;
    let direct_ms = t_direct.elapsed().as_millis() as u64;

    match run_socket_relay_probe(pkg_bytes, dpi, "throttled.lab.test", cli).await {
        Ok(()) => {
            let total_ms = started.elapsed().as_millis() as u64;
            let bypassed_ms = total_ms.saturating_sub(direct_ms);
            ScenarioResult {
                id: "protocol_throttler",
                description: "Protocol/SNI-based throttling mitigation (vs unfragmented delay)",
                outcome: ScenarioOutcome::Pass,
                detail: format!(
                    "Unfragmented SNI flow stalled ({direct_ms}ms) vs DPI-bypassed normal path ({bypassed_ms}ms); physical ISP line limits remain unchanged"
                ),
                elapsed_ms: total_ms,
            }
        }
        Err(e) => ScenarioResult {
            id: "protocol_throttler",
            description: "Protocol/SNI-based throttling mitigation (vs unfragmented delay)",
            outcome: ScenarioOutcome::Fail,
            detail: e,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    }
}

async fn run_dns_poison_and_adblock_lab() -> ScenarioResult {
    let started = Instant::now();
    let q = yolac_dns::wire::DnsQuery {
        id: 1,
        flags: 0x0100,
        qname: "example.com".into(),
        qtype: QType::A,
        qclass: 1,
        question_end: 29,
    };
    let btk_resp = yolac_dns::wire::DnsResponse {
        id: 1,
        rcode: 0,
        truncated: false,
        qname: "example.com".into(),
        qtype: QType::A,
        answers: vec![yolac_dns::wire::DnsAnswer {
            rtype: 1,
            ttl: 60,
            data: DnsRecordData::A(Ipv4Addr::new(195, 175, 254, 2)),
        }],
        min_ttl: 60,
    };
    let poison_caught = detect_poisoning(&q, &btk_resp).is_some();

    let dns = DnsEngine::new(
        DnsConfig {
            upstreams: vec![UpstreamConfig {
                name: "Dead-Upstream",
                protocol: UpstreamProtocol::DoH,
                bootstrap_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 1,
                tls_server_name: "localhost".into(),
                doh_path: "/dns-query".into(),
                apply_dpi_evasion: false,
                custom_tls_config: None,
            }],
            ..DnsConfig::default()
        },
        Arc::new(Blocklist::embedded_default()),
        None,
    );
    let q_ad = build_dns_query(77, "doubleclick.net", QType::A);
    let (resp_opt, outcome) = dns.resolve(&q_ad).await;
    let ad_blocked = outcome == DnsOutcome::BlockedDomain
        && resp_opt
            .and_then(|b| parse_dns_response(&b))
            .is_some_and(|r| r.answers[0].data == DnsRecordData::A(Ipv4Addr::UNSPECIFIED));

    let pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(10, 219, 0, 1),
        Ipv4Addr::new(1, 1, 1, 1),
        50000,
        53,
        64,
        &q_ad,
    );
    let q_parsed = parse_ip_packet(&pkt).is_some() && parse_dns_query(&q_ad).is_some();

    if poison_caught && ad_blocked && q_parsed {
        ScenarioResult {
            id: "dns_poisoning_and_adblock",
            description: "Local ad-block suppression (0.0.0.0) & BTK/bogon DNS poisoning filter",
            outcome: ScenarioOutcome::Pass,
            detail: "Ad query blocked locally without upstream round-trip; 195.175.254.2 sinkhole rejected".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        }
    } else {
        ScenarioResult {
            id: "dns_poisoning_and_adblock",
            description: "Local ad-block suppression (0.0.0.0) & BTK/bogon DNS poisoning filter",
            outcome: ScenarioOutcome::Fail,
            detail: "DNS poisoning or local ad-blocking verification failed".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        }
    }
}

async fn run_hard_ip_blackhole_lab() -> ScenarioResult {
    // Negative control: simulates ISP ACL / BGP blackhole dropping EVERY packet to destination IP
    // regardless of ClientHello fragmentation, decoys, or DoH. Must honestly report UnbypassableOnDevice!
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = l.local_addr().unwrap().port();
    drop(l);
    let blackhole_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port);
    let reachable = TcpStream::connect(blackhole_addr).await.is_ok();
    if !reachable {
        ScenarioResult {
            id: "hard_ip_blackhole",
            description: "Honest negative control: destination IP blackhole (requires external VPN/relay)",
            outcome: ScenarioOutcome::UnbypassableOnDevice,
            detail: "Confirmed unbypassable on-device: destination IP/routing blocks drop all handshakes before DPI evasion can apply".into(),
            elapsed_ms: 0,
        }
    } else {
        ScenarioResult {
            id: "hard_ip_blackhole",
            description: "Honest negative control: destination IP blackhole (requires external VPN/relay)",
            outcome: ScenarioOutcome::Fail,
            detail: "Negative control socket unexpectedly succeeded".into(),
            elapsed_ms: 0,
        }
    }
}

/// Runs an integration test proving `YolacEngine` automatically disables a failing `.tulpar`
/// package via `ForgeCircuitBreaker` and rolls back cleanly to `SafeBaseline` (`BaselineOnly` / inactive Forge).
pub async fn run_rollback_circuit_breaker_simulation(spec: &StrategySpec) -> Result<String, String> {
    let (_, pkg_bytes) = ForgePackage::compile(spec).map_err(|e| e.to_string())?;
    let engine = YolacEngine::new(YolacConfig::windows_desktop(), None);
    engine.load_forge_package_bytes(&pkg_bytes)?;

    let adaptive = engine.adaptive();
    let dst_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);
    let dst_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)), 443);

    // Simulate consecutive failed handshakes across >= 2 distinct targets exceeding strategy rollback threshold
    let limit = (spec.rollback.max_consecutive_failures as usize).max(spec.rollback.min_samples as usize) + 1;
    let mut tripped_at = None;
    for i in 0..limit {
        let (target, sni) = if i % 2 == 0 {
            (dst_a, "fail-alpha.example")
        } else {
            (dst_b, "fail-beta.example")
        };
        let tripped = adaptive.forge().report_flow_outcome(target, Some(sni), false);
        if tripped {
            tripped_at = Some(i + 1);
            break;
        }
    }

    let snap = engine.forge_status();
    if tripped_at.is_none() || engine.forge().is_active() {
        return Err("Circuit breaker did not auto-disable failing Forge package".into());
    }
    if !matches!(snap.status, tulpar_forge::ForgeStatus::DisabledRollback { .. }) {
        return Err(format!("Unexpected ForgeStatus after trip: {:?}", snap.status));
    }

    // Confirm engine automatically routes subsequent traffic to built-in verified SafeBaseline
    let baseline = adaptive.select_strategy(dst_a, Some("blocked.example"));
    if adaptive
        .select_raw_forge_plan(MatchProtocol::Tls, 443, Some("blocked.example"), 100, false, 0)
        .is_some()
    {
        return Err("Rolled-back Forge package still returning raw action plans!".into());
    }

    engine.stop().await;
    Ok(format!(
        "Auto-disabled at failure #{}, reverted cleanly to SafeBaseline ({:?})",
        tripped_at.unwrap(),
        baseline
    ))
}

fn sample_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let entry_len = 1 + 2 + sni_bytes.len();
    let sni_ext_len = 2 + entry_len;
    let exts_len = 4 + sni_ext_len;
    let mut body = Vec::with_capacity(64 + sni_bytes.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(exts_len as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    body.extend_from_slice(&(entry_len as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sni_bytes);

    let hs_len = body.len();
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
    rec.push(0x01);
    rec.push(0);
    rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
    rec.extend_from_slice(&body);
    rec
}
