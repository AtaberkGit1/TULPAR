//! Manual, user-initiated GitHub Releases update checker (zero background checks, zero invented URLs).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use yolac_net::{connect_protected_tcp, SocketProtector};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SECURITY_WARNING_TR: &str = "GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.";

/// Returns the verified official GitHub `owner/repo` slug detected at build time from
/// `YOLAC_GITHUB_REPO` or `git remote origin`. Returns `None` if unconfigured (never fabricates a URL).
pub fn official_github_repo() -> Option<&'static str> {
    option_env!("YOLAC_DETECTED_GITHUB_REPO")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn parse(raw: &str) -> Option<Self> {
        let cleaned = raw
            .trim()
            .trim_start_matches('v')
            .trim_start_matches('V')
            .split(['-', '+'])
            .next()?;
        let mut parts = cleaned.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckResult {
    UpToDate {
        current_version: String,
    },
    UpdateAvailable {
        current_version: String,
        latest_version: String,
        release_url: String,
    },
    Error(String),
}

impl UpdateCheckResult {
    pub fn to_json(&self) -> String {
        match self {
            Self::UpToDate { current_version } => format!(
                "{{\"status\":\"up_to_date\",\"message\":\"{}\",\"release_url\":\"\"}}",
                escape_json(&format!("Uygulama güncel (v{current_version})."))
            ),
            Self::UpdateAvailable {
                current_version,
                latest_version,
                release_url,
            } => format!(
                "{{\"status\":\"update_available\",\"message\":\"{}\",\"release_url\":\"{}\"}}",
                escape_json(&format!(
                    "Yeni sürüm bulundu: v{latest_version} (mevcut: v{current_version}). Resmî GitHub Releases sayfasına yönlendiriliyor."
                )),
                escape_json(release_url)
            ),
            Self::Error(msg) => format!(
                "{{\"status\":\"error\",\"message\":\"{}\",\"release_url\":\"\"}}",
                escape_json(msg)
            ),
        }
    }
}

/// Checks ONLY the official GitHub repository's published latest release when explicitly requested by the user.
pub async fn check_github_release(repo_override: Option<&str>) -> UpdateCheckResult {
    check_github_release_with_protector(repo_override, None).await
}

/// Checks GitHub Releases using an optional `SocketProtector` (prevents Android VPN routing loops)
/// and tries all resolved IP addresses (preferring IPv4 first) inside a single bounded timeout.
pub async fn check_github_release_with_protector(
    repo_override: Option<&str>,
    protector: Option<&dyn SocketProtector>,
) -> UpdateCheckResult {
    let repo_owned: String = match repo_override
        .map(str::to_string)
        .or_else(|| official_github_repo().map(str::to_string))
    {
        Some(r) => r,
        None => {
            return UpdateCheckResult::Error(
                "Resmî GitHub depo adresi yapılandırılmadı (YOLAC_GITHUB_REPO veya git remote origin tanımlı değil)."
                    .into(),
            );
        }
    };
    let repo = repo_owned.as_str();

    let resolved = match tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::lookup_host("api.github.com:443"),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let mut list: Vec<SocketAddr> = addrs.collect();
            // Prefer IPv4 endpoints first to avoid broken IPv6 blackholes on IPv4-only networks
            list.sort_by_key(|a| a.is_ipv6());
            list
        }
        _ => {
            return UpdateCheckResult::Error(
                "api.github.com adresine ulaşılamadı (ağ bağlantısı yok).".into(),
            );
        }
    };
    if resolved.is_empty() {
        return UpdateCheckResult::Error("api.github.com çözümlenemedi.".into());
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let mut last_err = UpdateCheckResult::Error("api.github.com bağlantısı kurulamadı.".into());
    for addr in resolved.into_iter().take(4) {
        let res = check_github_release_endpoint_inner(
            repo,
            APP_VERSION,
            addr,
            "api.github.com",
            Arc::clone(&tls_cfg),
            protector,
        )
        .await;
        if !matches!(res, UpdateCheckResult::Error(_)) {
            return res;
        }
        last_err = res;
    }
    last_err
}

/// Core HTTPS GitHub Releases checker (also used directly in live local-TLS automated tests).
pub async fn check_github_release_endpoint(
    repo_slug: &str,
    current_version: &str,
    endpoint_addr: SocketAddr,
    tls_host: &str,
    tls_config: Arc<ClientConfig>,
) -> UpdateCheckResult {
    check_github_release_endpoint_inner(
        repo_slug,
        current_version,
        endpoint_addr,
        tls_host,
        tls_config,
        None,
    )
    .await
}

async fn check_github_release_endpoint_inner(
    repo_slug: &str,
    current_version: &str,
    endpoint_addr: SocketAddr,
    tls_host: &str,
    tls_config: Arc<ClientConfig>,
    protector: Option<&dyn SocketProtector>,
) -> UpdateCheckResult {
    if !is_valid_repo_slug(repo_slug) {
        return UpdateCheckResult::Error("Geçersiz resmî GitHub depo formatı.".into());
    }
    let Some(current_sv) = SemVer::parse(current_version) else {
        return UpdateCheckResult::Error("Mevcut uygulama sürümü okunamadı.".into());
    };

    let fetch = tokio::time::timeout(Duration::from_secs(6), async {
        let tcp = match protector {
            Some(p) => connect_protected_tcp(endpoint_addr, p).await?,
            None => TcpStream::connect(endpoint_addr).await?,
        };
        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(tls_host.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS host"))?;
        let mut tls = connector.connect(server_name, tcp).await?;

        let req = format!(
            "GET /repos/{repo_slug}/releases/latest HTTP/1.1\r\nHost: {tls_host}\r\nUser-Agent: TULPAR/{current_version}\r\nAccept: application/vnd.github+json\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;

        let mut raw = Vec::with_capacity(4096);
        let mut buf = [0u8; 2048];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if raw.len() > 256 * 1024 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
                Err(e) => return Err(e),
            }
        }
        Ok::<Vec<u8>, io::Error>(raw)
    })
    .await;

    let raw = match fetch {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return UpdateCheckResult::Error(format!(
                "GitHub bağlantı hatası: {e}"
            ));
        }
        Err(_) => {
            return UpdateCheckResult::Error(
                "Güncelleme kontrolü zaman aşımına uğradı.".into(),
            );
        }
    };

    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return UpdateCheckResult::Error("GitHub sunucusundan geçersiz yanıt alındı.".into());
    };
    let header_str = String::from_utf8_lossy(&raw[..hdr_end]);
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code = status_line.split_whitespace().nth(1).unwrap_or("");
    if status_code == "404" {
        return UpdateCheckResult::Error(
            "Resmî depoda herkese açık yayınlanmış bir sürüm bulunamadı (depo gizli olabilir).".into(),
        );
    }
    if status_code != "200" {
        return UpdateCheckResult::Error(format!(
            "GitHub API hatası: {status_line}"
        ));
    }

    let body_raw = &raw[hdr_end + 4..];
    let body_bytes = if header_str
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"))
    {
        decode_chunked(body_raw).unwrap_or_else(|| body_raw.to_vec())
    } else {
        body_raw.to_vec()
    };
    let body = String::from_utf8_lossy(&body_bytes);

    let Some(tag_name) = extract_json_string(&body, "tag_name") else {
        return UpdateCheckResult::Error("Yayınlanan sürüm etiketi (tag_name) okunamadı.".into());
    };
    let Some(latest_sv) = SemVer::parse(&tag_name) else {
        return UpdateCheckResult::Error(format!("Geçersiz sürüm biçimi: {tag_name}"));
    };

    let fallback_url = format!("https://github.com/{repo_slug}/releases/latest");
    let candidate_url = extract_json_string(&body, "html_url").unwrap_or_else(|| fallback_url.clone());

    // Strict case-insensitive official GitHub origin validation: refuse any third-party redirect!
    let expected_prefix = format!("https://github.com/{}/releases", repo_slug.to_ascii_lowercase());
    if !candidate_url.to_ascii_lowercase().starts_with(&expected_prefix) {
        return UpdateCheckResult::Error(
            "Güvenlik ihlali: Yanıt resmî GitHub Releases adresine işaret etmiyor.".into(),
        );
    }

    if latest_sv > current_sv {
        UpdateCheckResult::UpdateAvailable {
            current_version: current_version.to_string(),
            latest_version: format!("{}.{}.{}", latest_sv.major, latest_sv.minor, latest_sv.patch),
            release_url: candidate_url,
        }
    } else {
        UpdateCheckResult::UpToDate {
            current_version: current_version.to_string(),
        }
    }
}

fn is_valid_repo_slug(slug: &str) -> bool {
    let mut parts = slug.split('/');
    let Some(owner) = parts.next() else { return false };
    let Some(repo) = parts.next() else { return false };
    if parts.next().is_some() || owner.is_empty() || repo.is_empty() {
        return false;
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    owner.chars().all(ok) && repo.chars().all(ok)
}

fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let pos = data.windows(2).position(|w| w == b"\r\n")?;
        let hex = std::str::from_utf8(&data[..pos]).ok()?.split(';').next()?.trim();
        let len = usize::from_str_radix(hex, 16).ok()?;
        data = &data[pos + 2..];
        if len == 0 {
            break;
        }
        let end_with_crlf = len.checked_add(2)?;
        if data.len() < end_with_crlf {
            return None;
        }
        out.extend_from_slice(&data[..len]);
        data = &data[end_with_crlf..];
    }
    Some(out)
}

/// Lightweight top-level JSON string-field extractor (tracks brace depth & string escapes so
/// nested `"author": {"html_url": ...}` or markdown release notes never shadow top-level keys!).
fn extract_json_string(json: &str, target_key: &str) -> Option<String> {
    let bytes = json.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                let (s, next_i) = parse_json_str(json, i)?;
                i = next_i;
                if depth == 1 && s == target_key {
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == b':' {
                        i += 1;
                        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                            i += 1;
                        }
                        if i < bytes.len() && bytes[i] == b'"' {
                            let (val, _) = parse_json_str(json, i)?;
                            return Some(val);
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn parse_json_str(json: &str, start_quote: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut chars = json[start_quote + 1..].char_indices();
    while let Some((rel, c)) = chars.next() {
        if c == '\\' {
            let (_, esc) = chars.next()?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            }
        } else if c == '"' {
            return Some((out, start_quote + 1 + rel + 1));
        } else {
            out.push(c);
        }
    }
    None
}

pub(crate) fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_compares_semver() {
        assert!(SemVer::parse("v0.2.0").unwrap() > SemVer::parse("0.1.0").unwrap());
        assert_eq!(SemVer::parse("v1.2.3-rc1"), SemVer::parse("1.2.3"));
        assert!(SemVer::parse("not-a-version").is_none());
    }

    #[test]
    fn extracts_json_fields_cleanly() {
        let sample = r#"{"tag_name": "v0.3.1", "html_url": "https:\/\/github.com\/org\/yolac\/releases\/tag\/v0.3.1"}"#;
        assert_eq!(extract_json_string(sample, "tag_name").as_deref(), Some("v0.3.1"));
        assert_eq!(
            extract_json_string(sample, "html_url").as_deref(),
            Some("https://github.com/org/yolac/releases/tag/v0.3.1")
        );
    }

    #[tokio::test]
    async fn unconfigured_repo_returns_honest_error_without_inventing_url() {
        if official_github_repo().is_none() {
            let res = check_github_release(None).await;
            assert!(matches!(res, UpdateCheckResult::Error(_)));
        }
    }
}
