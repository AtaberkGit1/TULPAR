//! Zero-telemetry on-device domain censorship doctor: diagnoses DNS resolution (DoH/DoT + ECH),
//! local blocklist state, direct TLS handshake vs DPI RST/timeout, and TLS/TCP split bypass on any domain.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use yolac_blocklist::Blocklist;
use yolac_dns::{build_dns_query, parse_dns_response, DnsEngine, DnsOutcome, DnsRecordData, QType};
use yolac_dpi::{fragment_tls_client_hello, SplitStrategy};
use yolac_net::{connect_protected_tcp, SocketProtector};

use crate::updater::escape_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainVerdict {
    BlockedLocally,
    DnsFailed,
    CleanReachable,
    BypassedWithDpiEvasion,
    DirectAndSocketSplitFailed,
    HardIpBlackholeOrUnreachable,
}

impl DomainVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockedLocally => "blocked_locally",
            Self::DnsFailed => "dns_failed",
            Self::CleanReachable => "clean_reachable",
            Self::BypassedWithDpiEvasion => "bypassed_with_dpi_evasion",
            Self::DirectAndSocketSplitFailed => "direct_and_split_failed",
            Self::HardIpBlackholeOrUnreachable => "hard_ip_or_unreachable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainDiagnosticReport {
    pub domain: String,
    pub verdict: DomainVerdict,
    pub dns_ok: bool,
    pub resolved_ip: Option<String>,
    pub has_ech: bool,
    pub dns_rtt_ms: Option<u64>,
    pub direct_tls_ok: bool,
    pub evasion_tls_ok: bool,
    pub summary_tr: String,
}

impl DomainDiagnosticReport {
    pub fn to_json(&self) -> String {
        let ip = self.resolved_ip.as_deref().unwrap_or("");
        let rtt = self
            .dns_rtt_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"domain\":\"{}\",\"verdict\":\"{}\",\"dns_ok\":{},\"resolved_ip\":\"{}\",\"has_ech\":{},\"dns_rtt_ms\":{},\"direct_tls_ok\":{},\"evasion_tls_ok\":{},\"summary\":\"{}\"}}",
            escape_json(&self.domain),
            self.verdict.as_str(),
            self.dns_ok,
            escape_json(ip),
            self.has_ech,
            rtt,
            self.direct_tls_ok,
            self.evasion_tls_ok,
            escape_json(&self.summary_tr),
        )
    }
}

fn build_probe_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let name_entry_len = 1 + 2 + sni_bytes.len();
    let sni_ext_data_len = 2 + name_entry_len;
    // Standard TLS 1.3 + 1.2 extensions so strict endpoints (Cloudflare/Google/Discord) answer with ServerHello:
    // supported_groups (0x000a: x25519, secp256r1)
    let sg_ext_data = [0x00u8, 0x04, 0x00, 0x1D, 0x00, 0x17];
    // signature_algorithms (0x000d: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp384r1_sha384)
    let sa_ext_data = [0x00u8, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03];
    // supported_versions (0x002b: TLS 1.3, TLS 1.2)
    let sv_ext_data = [0x04u8, 0x03, 0x04, 0x03, 0x03];
    // key_share (0x0033): X25519 valid RFC 7748 basepoint (u = 9)
    let mut ks_ext_data = vec![0x00u8, 0x24, 0x00, 0x1D, 0x00, 0x20, 0x09];
    ks_ext_data.extend_from_slice(&[0u8; 31]);

    let extensions_len = (4 + sni_ext_data_len)
        + (4 + sg_ext_data.len())
        + (4 + sa_ext_data.len())
        + (4 + sv_ext_data.len())
        + (4 + ks_ext_data.len());

    let mut body = Vec::with_capacity(180 + sni_bytes.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x54u8; 32]);
    body.push(0x00);
    // Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, ECDHE_RSA_AES_128_GCM, ECDHE_ECDSA_AES_128_GCM
    body.extend_from_slice(&[0x00, 0x08, 0x13, 0x01, 0x13, 0x02, 0xC0, 0x2F, 0xC0, 0x2B]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&0x0000u16.to_be_bytes());
    body.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sni_bytes);
    body.extend_from_slice(&0x000au16.to_be_bytes());
    body.extend_from_slice(&(sg_ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&sg_ext_data);
    body.extend_from_slice(&0x000du16.to_be_bytes());
    body.extend_from_slice(&(sa_ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&sa_ext_data);
    body.extend_from_slice(&0x002bu16.to_be_bytes());
    body.extend_from_slice(&(sv_ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&sv_ext_data);
    body.extend_from_slice(&0x0033u16.to_be_bytes());
    body.extend_from_slice(&(ks_ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ks_ext_data);

    let hs_len = body.len();
    let mut rec = Vec::with_capacity(9 + hs_len);
    rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
    rec.push(0x01);
    rec.push(((hs_len >> 16) & 0xFF) as u8);
    rec.push(((hs_len >> 8) & 0xFF) as u8);
    rec.push((hs_len & 0xFF) as u8);
    rec.extend_from_slice(&body);
    rec
}

fn looks_like_server_hello(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x02
}

async fn probe_tls_endpoint(
    addr: SocketAddr,
    ch: &[u8],
    split: bool,
    protector: &dyn SocketProtector,
) -> Result<bool, std::io::Error> {
    let mut stream = timeout(Duration::from_millis(2200), connect_protected_tcp(addr, protector))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP bağlantı zaman aşımı"))??;
    let _ = stream.set_nodelay(true);

    if split {
        if let Some(frag) = fragment_tls_client_hello(ch, SplitStrategy::OffsetAndSniMid(2)) {
            let mut pos = 0usize;
            while pos < frag.len() {
                let rec_len = if pos + 5 <= frag.len() {
                    (5 + u16::from_be_bytes([frag[pos + 3], frag[pos + 4]]) as usize)
                        .min(frag.len() - pos)
                } else {
                    frag.len() - pos
                };
                stream.write_all(&frag[pos..pos + rec_len]).await?;
                stream.flush().await?;
                pos += rec_len;
                if pos < frag.len() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        } else {
            stream.write_all(ch).await?;
            stream.flush().await?;
        }
    } else {
        stream.write_all(ch).await?;
        stream.flush().await?;
    }

    let mut reply = [0u8; 64];
    match timeout(Duration::from_millis(2200), stream.read(&mut reply)).await {
        Ok(Ok(n)) if n >= 6 && looks_like_server_hello(&reply[..n]) => Ok(true),
        Ok(Ok(_)) => Ok(false),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

pub async fn diagnose_domain_against_addr(
    domain: &str,
    addr: SocketAddr,
    dns_rtt_ms: Option<u64>,
    has_ech: bool,
    protector: &dyn SocketProtector,
) -> DomainDiagnosticReport {
    let ch = build_probe_client_hello(domain);
    match probe_tls_endpoint(addr, &ch, false, protector).await {
        Ok(true) => DomainDiagnosticReport {
            domain: domain.to_string(),
            verdict: DomainVerdict::CleanReachable,
            dns_ok: true,
            resolved_ip: Some(addr.ip().to_string()),
            has_ech,
            dns_rtt_ms,
            direct_tls_ok: true,
            evasion_tls_ok: true,
            summary_tr: format!(
                "{domain} ({}): Doğrudan TLS erişimi açık{}{}",
                addr.ip(),
                dns_rtt_ms.map(|m| format!(" · DNS {m} ms")).unwrap_or_default(),
                if has_ech { " · ECH destekli" } else { "" },
            ),
        },
        Ok(false) => {
            let evasion_ok = probe_tls_endpoint(addr, &ch, true, protector)
                .await
                .unwrap_or(false);
            if evasion_ok {
                DomainDiagnosticReport {
                    domain: domain.to_string(),
                    verdict: DomainVerdict::BypassedWithDpiEvasion,
                    dns_ok: true,
                    resolved_ip: Some(addr.ip().to_string()),
                    has_ech,
                    dns_rtt_ms,
                    direct_tls_ok: false,
                    evasion_tls_ok: true,
                    summary_tr: format!(
                        "{domain} ({}): Doğrudan TLS DPI tarafından kesildi — TULPAR TLS/TCP bölme başarıyla aştı.",
                        addr.ip()
                    ),
                }
            } else {
                DomainDiagnosticReport {
                    domain: domain.to_string(),
                    verdict: DomainVerdict::DirectAndSocketSplitFailed,
                    dns_ok: true,
                    resolved_ip: Some(addr.ip().to_string()),
                    has_ech,
                    dns_rtt_ms,
                    direct_tls_ok: false,
                    evasion_tls_ok: false,
                    summary_tr: format!(
                        "{domain} ({}): Doğrudan TLS ve basit soket bölme yanıt vermedi (Windows/Linux ham L3 sahte paket gereksinimi veya IP engeli olabilir).",
                        addr.ip()
                    ),
                }
            }
        }
        Err(_) => DomainDiagnosticReport {
            domain: domain.to_string(),
            verdict: DomainVerdict::HardIpBlackholeOrUnreachable,
            dns_ok: true,
            resolved_ip: Some(addr.ip().to_string()),
            has_ech,
            dns_rtt_ms,
            direct_tls_ok: false,
            evasion_tls_ok: false,
            summary_tr: format!(
                "{domain} ({}): TCP bağlantısı kurulamadı (zaman aşımı/ret). Sabit IP veya yönlendirme engeli cihaz üstü DPI bölme ile aşılamaz.",
                addr.ip()
            ),
        },
    }
}

pub async fn diagnose_domain_live(
    raw_domain: &str,
    blocklist: &Blocklist,
    dns: &DnsEngine,
    protector: &dyn SocketProtector,
) -> DomainDiagnosticReport {
    let domain = raw_domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return DomainDiagnosticReport {
            domain: raw_domain.trim().to_string(),
            verdict: DomainVerdict::DnsFailed,
            dns_ok: false,
            resolved_ip: None,
            has_ech: false,
            dns_rtt_ms: None,
            direct_tls_ok: false,
            evasion_tls_ok: false,
            summary_tr: "Geçerli bir alan adı girin (ör. example.org).".into(),
        };
    }

    if let Some(m) = blocklist.check(&domain) {
        return DomainDiagnosticReport {
            domain: domain.clone(),
            verdict: DomainVerdict::BlockedLocally,
            dns_ok: false,
            resolved_ip: None,
            has_ech: false,
            dns_rtt_ms: None,
            direct_tls_ok: false,
            evasion_tls_ok: false,
            summary_tr: format!(
                "{domain}: TULPAR yerel engelleme listesinde engelli ({:?}). Erişim için izin listesine ekleyin.",
                m.category
            ),
        };
    }

    let q_a = build_dns_query(0x444F, &domain, QType::A);
    let q_https = build_dns_query(0x4450, &domain, QType::HTTPS);
    let dns_started = Instant::now();
    let ((a_wire_opt, a_outcome), (https_wire_opt, _)) =
        tokio::join!(dns.resolve(&q_a), dns.resolve(&q_https));
    let dns_rtt_ms = dns_started.elapsed().as_millis().max(1) as u64;

    let has_ech = https_wire_opt
        .as_deref()
        .and_then(parse_dns_response)
        .is_some_and(|r| {
            r.answers
                .iter()
                .any(|a| matches!(a.data, DnsRecordData::Https { has_ech: true, .. }))
        });

    let target_ip = a_wire_opt
        .as_deref()
        .and_then(parse_dns_response)
        .and_then(|r| {
            r.answers.into_iter().find_map(|ans| match ans.data {
                DnsRecordData::A(v4) => Some(std::net::IpAddr::V4(v4)),
                DnsRecordData::AAAA(v6) => Some(std::net::IpAddr::V6(v6)),
                _ => None,
            })
        });

    let Some(ip) = target_ip else {
        let reason = if matches!(a_outcome, DnsOutcome::BlockedCnameUncloak | DnsOutcome::BlockedDomain) {
            format!("{domain}: Şifreli DNS CNAME/alan adı yerel engelleme listesine takıldı.")
        } else {
            format!("{domain}: Şifreli DNS üzerinden IP çözümlenemedi.")
        };
        return DomainDiagnosticReport {
            domain,
            verdict: if matches!(a_outcome, DnsOutcome::BlockedCnameUncloak | DnsOutcome::BlockedDomain) {
                DomainVerdict::BlockedLocally
            } else {
                DomainVerdict::DnsFailed
            },
            dns_ok: false,
            resolved_ip: None,
            has_ech,
            dns_rtt_ms: Some(dns_rtt_ms),
            direct_tls_ok: false,
            evasion_tls_ok: false,
            summary_tr: reason,
        };
    };

    diagnose_domain_against_addr(&domain, SocketAddr::new(ip, 443), Some(dns_rtt_ms), has_ech, protector).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use yolac_net::NoopProtector;

    #[tokio::test]
    async fn doctor_distinguishes_dpi_bypass_and_hard_ip_blackhole() {
        // 1. Mock DPI middlebox: sends RST if whole ClientHello arrives intact, replies ServerHello when split!
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dpi_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        // Unsplit single ClientHello starts with complete single TLS record containing full SNI
                        if n > 30 && buf[0] == 0x16 {
                            let rec_len = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                            if n >= rec_len {
                                // Simulated DPI drops/closes unsplit handshake
                                drop(sock);
                                return;
                            }
                        }
                        // Split multi-record ClientHello: drain tail & return ServerHello prefix
                        let _ = timeout(Duration::from_millis(50), sock.read(&mut buf)).await;
                        let _ = sock.write_all(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0]).await;
                    });
                }
            }
        });

        let prot = NoopProtector;
        let rep = diagnose_domain_against_addr("censored.example.org", dpi_addr, Some(12), true, &prot).await;
        assert_eq!(rep.verdict, DomainVerdict::BypassedWithDpiEvasion);
        assert!(!rep.direct_tls_ok);
        assert!(rep.evasion_tls_ok);
        assert!(rep.has_ech);

        // 2. Closed/blackholed port -> HardIpBlackholeOrUnreachable
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let dead_rep = diagnose_domain_against_addr("blackhole.example.org", dead_addr, Some(8), false, &prot).await;
        assert_eq!(dead_rep.verdict, DomainVerdict::HardIpBlackholeOrUnreachable);
    }
}
