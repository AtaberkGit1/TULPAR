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
    let repo_owned: String = match repo_override.map(str::to_string).or_else(|| official_github_repo().map(str::to_string)) {
        Some(r) => r,
        None => {
            return UpdateCheckResult::Error(
                "Resmî GitHub depo adresi yapılandırılmadı (YOLAC_GITHUB_REPO veya git remote origin tanımlı değil)."
                    .into(),
            );
        }
    };
    let repo = repo_owned.as_str();

    let Ok(mut addrs) = tokio::net::lookup_host("api.github.com:443").await else {
        return UpdateCheckResult::Error(
            "api.github.com adresine ulaşılamadı (ağ bağlantısı yok).".into(),
        );
    };
    let Some(addr) = addrs.next() else {
        return UpdateCheckResult::Error("api.github.com çözümlenemedi.".into());
    };

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    check_github_release_endpoint(repo, APP_VERSION, addr, "api.github.com", tls_cfg).await
}

/// Core HTTPS GitHub Releases checker (also used directly in live local-TLS automated tests).
pub async fn check_github_release_endpoint(
    repo_slug: &str,
    current_version: &str,
    endpoint_addr: SocketAddr,
    tls_host: &str,
    tls_config: Arc<ClientConfig>,
) -> UpdateCheckResult {
    if !is_valid_repo_slug(repo_slug) {
        return UpdateCheckResult::Error("Geçersiz resmî GitHub depo formatı.".into());
    }
    let Some(current_sv) = SemVer::parse(current_version) else {
        return UpdateCheckResult::Error("Mevcut uygulama sürümü okunamadı.".into());
    };

    let fetch = tokio::time::timeout(Duration::from_secs(6), async {
        let tcp = TcpStream::connect(endpoint_addr).await?;
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
    if status_line.contains(" 404") {
        return UpdateCheckResult::Error(
            "Resmî depoda herkese açık yayınlanmış bir sürüm bulunamadı (depo gizli olabilir).".into(),
        );
    }
    if !status_line.contains(" 200") {
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

    // Strict official GitHub origin validation: refuse any redirect outside the official repo!
    let expected_prefix = format!("https://github.com/{repo_slug}/releases");
    if !candidate_url.starts_with(&expected_prefix) {
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
        if data.len() < len + 2 {
            return None;
        }
        out.extend_from_slice(&data[..len]);
        data = &data[len + 2..];
    }
    Some(out)
}

/// Lightweight JSON string-field extractor (avoids pulling heavy JSON crate into mobile binaries).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let mut search_from = 0usize;
    while let Some(rel) = json[search_from..].find(&pattern) {
        let after_key = search_from + rel + pattern.len();
        let rest = json[after_key..].trim_start();
        if let Some(after_colon) = rest.strip_prefix(':') {
            let val_rest = after_colon.trim_start();
            if let Some(quoted) = val_rest.strip_prefix('"') {
                let mut out = String::new();
                let mut chars = quoted.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        match chars.next()? {
                            '"' => out.push('"'),
                            '\\' => out.push('\\'),
                            '/' => out.push('/'),
                            'n' => out.push('\n'),
                            'r' => out.push('\r'),
                            't' => out.push('\t'),
                            other => out.push(other),
                        }
                    } else if c == '"' {
                        return Some(out);
                    } else {
                        out.push(c);
                    }
                }
            }
        }
        search_from = after_key;
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
