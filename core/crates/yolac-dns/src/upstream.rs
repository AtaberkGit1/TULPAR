//! Encrypted DNS (DoH RFC 8484 & DoT RFC 7858) upstreams with bootstrap IPs & DPI evasion.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use yolac_dpi::{fragment_tls_client_hello, SplitStrategy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    DoH,
    DoT,
}

#[derive(Clone)]
pub struct UpstreamConfig {
    pub name: &'static str,
    pub protocol: UpstreamProtocol,
    pub bootstrap_ip: IpAddr,
    pub port: u16,
    pub tls_server_name: String,
    pub doh_path: String,
    /// Apply TLS record fragmentation to the DoH/DoT ClientHello itself in case SNI DPI blocks encrypted DNS.
    pub apply_dpi_evasion: bool,
    /// Optional custom TLS config (used for local test servers with ephemeral certs).
    pub custom_tls_config: Option<Arc<ClientConfig>>,
}

impl std::fmt::Debug for UpstreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamConfig")
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("bootstrap_ip", &self.bootstrap_ip)
            .field("port", &self.port)
            .field("tls_server_name", &self.tls_server_name)
            .finish()
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction for opening outbound TCP sockets (allows Android `VpnService.protect()` injection).
pub trait UpstreamDialer: Send + Sync {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

pub struct DefaultUpstreamDialer;

impl UpstreamDialer for DefaultUpstreamDialer {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            Ok(stream)
        })
    }
}

/// Public, independent, no-log encrypted DNS upstreams using hardcoded bootstrap IPs.
/// Zero reliance on ISP DNS to resolve DNS endpoints; mixes port-443 DoH (firewall-friendly)
/// and port-853 DoT across independent providers (Cloudflare, Quad9, Mullvad, Google).
pub fn default_public_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig {
            name: "Cloudflare-DoH",
            protocol: UpstreamProtocol::DoH,
            bootstrap_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 443,
            tls_server_name: "cloudflare-dns.com".into(),
            doh_path: "/dns-query".into(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
        UpstreamConfig {
            name: "Quad9-DoT",
            protocol: UpstreamProtocol::DoT,
            bootstrap_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 853,
            tls_server_name: "dns.quad9.net".into(),
            doh_path: String::new(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
        UpstreamConfig {
            name: "Mullvad-DoT",
            protocol: UpstreamProtocol::DoT,
            bootstrap_ip: IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2)),
            port: 853,
            tls_server_name: "dns.mullvad.net".into(),
            doh_path: String::new(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
        UpstreamConfig {
            name: "Cloudflare-DoT",
            protocol: UpstreamProtocol::DoT,
            bootstrap_ip: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            port: 853,
            tls_server_name: "1dot1dot1dot1.cloudflare-dns.com".into(),
            doh_path: String::new(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
        UpstreamConfig {
            name: "Google-DoH",
            protocol: UpstreamProtocol::DoH,
            bootstrap_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 443,
            tls_server_name: "dns.google".into(),
            doh_path: "/dns-query".into(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
        UpstreamConfig {
            name: "Cloudflare-DoH-v6",
            protocol: UpstreamProtocol::DoH,
            bootstrap_ip: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            port: 443,
            tls_server_name: "cloudflare-dns.com".into(),
            doh_path: "/dns-query".into(),
            apply_dpi_evasion: true,
            custom_tls_config: None,
        },
    ]
}

pub fn default_rustls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// RFC 7858 / RFC 7301 ALPN-compliant TLS config for DNS-over-TLS (port 853, ALPN = "dot").
pub fn default_dot_rustls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"dot".to_vec()];
    Arc::new(cfg)
}

/// Wraps a `TcpStream` to fragment the very first TLS ClientHello write across TLS records
/// so DoH/DoT connections also evade SNI-based DPI middleboxes.
pub(crate) struct DpiEvasiveTlsStream {
    inner: TcpStream,
    evade_first_write: bool,
    pending_tail: Vec<u8>,
    tail_pos: usize,
    reported_first_len: usize,
}

pub(crate) type EncryptedTlsStream = tokio_rustls::client::TlsStream<DpiEvasiveTlsStream>;

impl DpiEvasiveTlsStream {
    fn new(inner: TcpStream, evade_first_write: bool) -> Self {
        Self {
            inner,
            evade_first_write,
            pending_tail: Vec::new(),
            tail_pos: 0,
            reported_first_len: 0,
        }
    }
}

impl AsyncRead for DpiEvasiveTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DpiEvasiveTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.tail_pos < self.pending_tail.len() {
            let this = &mut *self;
            let remaining = &this.pending_tail[this.tail_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to flush fragmented TLS ClientHello",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.tail_pos += n;
                    if this.tail_pos >= this.pending_tail.len() {
                        this.pending_tail.clear();
                        this.tail_pos = 0;
                        let ret = this.reported_first_len;
                        this.reported_first_len = 0;
                        return Poll::Ready(Ok(ret));
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.evade_first_write {
            self.evade_first_write = false;
            if let Some(frag) = fragment_tls_client_hello(buf, SplitStrategy::SniMid) {
                // Split TCP write right at the boundary between fragmented TLS record 1 and record 2
                let first_rec_len = 5 + u16::from_be_bytes([frag[3], frag[4]]) as usize;
                let (head, tail) = frag.split_at(first_rec_len.min(frag.len()));
                match Pin::new(&mut self.inner).poll_write(cx, head) {
                    Poll::Ready(Ok(n)) => {
                        if n < head.len() || !tail.is_empty() {
                            self.pending_tail.extend_from_slice(&head[n..]);
                            self.pending_tail.extend_from_slice(tail);
                            self.tail_pos = 0;
                            self.reported_first_len = buf.len();
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        return Poll::Ready(Ok(buf.len()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        self.evade_first_write = true;
                        return Poll::Pending;
                    }
                }
            }
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.tail_pos < self.pending_tail.len() {
            let this = &mut *self;
            let remaining = &this.pending_tail[this.tail_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero during TLS flush",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.tail_pos += n;
                    if this.tail_pos < this.pending_tail.len() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    this.pending_tail.clear();
                    this.tail_pos = 0;
                    this.reported_first_len = 0;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn connect_upstream_tls(
    upstream: &UpstreamConfig,
    dialer: &dyn UpstreamDialer,
    default_tls: &Arc<ClientConfig>,
) -> io::Result<EncryptedTlsStream> {
    let addr = SocketAddr::new(upstream.bootstrap_ip, upstream.port);
    let tcp = dialer.connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let wrapped = DpiEvasiveTlsStream::new(tcp, upstream.apply_dpi_evasion);

    let tls_cfg = upstream
        .custom_tls_config
        .clone()
        .unwrap_or_else(|| Arc::clone(default_tls));
    let connector = TlsConnector::from(tls_cfg);
    let server_name = ServerName::try_from(upstream.tls_server_name.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS SNI"))?;
    connector.connect(server_name, wrapped).await
}

/// Exchanges one DNS query/response over an established TLS stream, returning `(dns_wire, reusable)`.
pub(crate) async fn exchange_on_tls_stream(
    upstream: &UpstreamConfig,
    tls: &mut EncryptedTlsStream,
    query_wire: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    match upstream.protocol {
        UpstreamProtocol::DoT => {
            let len = u16::try_from(query_wire.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"))?;
            tls.write_all(&len.to_be_bytes()).await?;
            tls.write_all(query_wire).await?;
            tls.flush().await?;

            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if resp_len < 12 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short DoT reply"));
            }
            let mut resp = vec![0u8; resp_len];
            tls.read_exact(&mut resp).await?;
            Ok((resp, true))
        }
        UpstreamProtocol::DoH => {
            let req = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                upstream.doh_path,
                upstream.tls_server_name,
                query_wire.len()
            );
            tls.write_all(req.as_bytes()).await?;
            tls.write_all(query_wire).await?;
            tls.flush().await?;

            let mut raw = Vec::with_capacity(2048);
            let mut tmp = [0u8; 2048];
            let hdr_end = loop {
                match tls.read(&mut tmp).await {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "DoH EOF before HTTP headers",
                        ));
                    }
                    Ok(n) => {
                        raw.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos;
                        }
                        if raw.len() > 16384 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "DoH headers too large",
                            ));
                        }
                    }
                    Err(e) => return Err(e),
                }
            };

            let header_str = std::str::from_utf8(&raw[..hdr_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 DoH headers"))?
                .to_string();
            let status_line = header_str.lines().next().unwrap_or("");
            if status_line.split_whitespace().nth(1) != Some("200") {
                return Err(io::Error::other(format!(
                    "DoH upstream returned HTTP status: {status_line}"
                )));
            }

            let server_wants_close = header_str.lines().any(|l| {
                let lower = l.to_ascii_lowercase();
                lower.starts_with("connection:") && lower.contains("close")
            });
            let is_chunked = header_str.lines().any(|l| {
                let lower = l.to_ascii_lowercase();
                lower.starts_with("transfer-encoding:") && lower.contains("chunked")
            });
            let content_len = header_str.lines().find_map(|l| {
                let lower = l.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            });

            const MAX_DNS_BODY: usize = 65_535;
            let body_start = hdr_end + 4;
            if let Some(clen) = content_len {
                if clen > MAX_DNS_BODY {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DoH Content-Length exceeds 65535 bytes",
                    ));
                }
                let exact_end = body_start
                    .checked_add(clen)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DoH length overflow"))?;
                while raw.len() < exact_end {
                    let n = tls.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated DoH body",
                        ));
                    }
                    raw.extend_from_slice(&tmp[..n]);
                }
                let reusable = !server_wants_close && raw.len() == exact_end;
                return Ok((raw[body_start..exact_end].to_vec(), reusable));
            }

            if is_chunked {
                // Incremental chunked decoding: terminates immediately on `0\r\n\r\n` instead of
                // blocking 2.5s waiting for keep-alive TCP EOF!
                loop {
                    if let Some((decoded, consumed)) = try_decode_chunked_complete(&raw[body_start..])? {
                        let reusable = !server_wants_close && body_start + consumed == raw.len();
                        return Ok((decoded, reusable));
                    }
                    if raw.len().saturating_sub(body_start) > MAX_DNS_BODY + 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunked DoH body too large",
                        ));
                    }
                    let n = tls.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated chunked DoH body",
                        ));
                    }
                    raw.extend_from_slice(&tmp[..n]);
                }
            }

            loop {
                if raw.len().saturating_sub(body_start) > MAX_DNS_BODY {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DoH body exceeds 65535 bytes",
                    ));
                }
                match tls.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => raw.extend_from_slice(&tmp[..n]),
                    Err(e)
                        if e.kind() == io::ErrorKind::UnexpectedEof && raw.len() > body_start =>
                    {
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            let body = parse_http_dns_body(&header_str, &raw[body_start..])?;
            Ok((body, false))
        }
    }
}

/// Sends a single DNS wire query to an encrypted upstream (DoH or DoT) with timeout.
pub async fn query_upstream(
    upstream: &UpstreamConfig,
    query_wire: &[u8],
    dialer: &dyn UpstreamDialer,
    default_tls: &Arc<ClientConfig>,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        let mut tls = connect_upstream_tls(upstream, dialer, default_tls).await?;
        let (resp, _) = exchange_on_tls_stream(upstream, &mut tls, query_wire).await?;
        Ok(resp)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "encrypted DNS upstream timeout"))?
}

fn parse_http_dns_body(header_str: &str, body: &[u8]) -> io::Result<Vec<u8>> {
    let is_chunked = header_str
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));

    if is_chunked {
        decode_chunked_body(body)
    } else {
        Ok(body.to_vec())
    }
}

/// Incrementally decodes an HTTP/1.1 chunked body.
/// Returns `Ok(Some((decoded, bytes_consumed)))` as soon as the final `0\r\n...\r\n` terminator arrives,
/// `Ok(None)` if more bytes need to be read from the TLS stream, or `Err` on malformed/oversized framing.
fn try_decode_chunked_complete(body: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    const MAX_DECODED: usize = 65_535;
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_end) = body[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_str = std::str::from_utf8(&body[pos..pos + rel_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk hex"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        pos += rel_end + 2;
        if size == 0 {
            // Expect terminating `\r\n` (or optional trailers followed by `\r\n\r\n`)
            if body.len() >= pos + 2 && &body[pos..pos + 2] == b"\r\n" {
                return Ok(Some((out, pos + 2)));
            }
            if let Some(tr_end) = body[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(Some((out, pos + tr_end + 4)));
            }
            return Ok(None);
        }
        if out.len().saturating_add(size) > MAX_DECODED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked DoH payload exceeds 65535 bytes",
            ));
        }
        let end_with_crlf = pos
            .checked_add(size)
            .and_then(|v| v.checked_add(2))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        if body.len() < end_with_crlf {
            return Ok(None);
        }
        if &body[pos + size..end_with_crlf] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after chunk",
            ));
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos = end_with_crlf;
    }
}

fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    match try_decode_chunked_complete(body)? {
        Some((decoded, _)) => Ok(decoded),
        None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated chunk")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{build_dns_query, parse_dns_response, QType};

    #[tokio::test]
    #[ignore = "requires live internet access to public DoH/DoT resolvers"]
    async fn live_probe_all_default_public_upstreams_with_dpi_fragmentation() {
        let tls = default_rustls_config();
        let dialer = DefaultUpstreamDialer;
        let query = build_dns_query(0x4242, "example.com", QType::A);
        let mut successes = 0usize;
        for up in default_public_upstreams() {
            let res = query_upstream(&up, &query, &dialer, &tls, Duration::from_secs(4)).await;
            match res {
                Ok(resp) => {
                    let parsed = parse_dns_response(&resp).expect("valid DNS wire reply");
                    assert_eq!(parsed.id, 0x4242);
                    assert!(!parsed.answers.is_empty(), "{} returned 0 answers", up.name);
                    println!("[LIVE OK] {} ({}:{}) -> {} answers", up.name, up.bootstrap_ip, up.port, parsed.answers.len());
                    successes += 1;
                }
                Err(e) => {
                    println!("[LIVE WARN] {} ({}:{}) -> {}", up.name, up.bootstrap_ip, up.port, e);
                }
            }
        }
        assert!(successes >= 3, "At least 3 IPv4 public encrypted DNS upstreams must succeed live, got {successes}");
    }
}
