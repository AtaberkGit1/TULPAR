//! DPI-evasive outbound TCP relay with speculative parallel connect, adaptive failure/RST feedback,
//! 64 KB high-throughput steady-state copy, and zero-overhead non-web / LAN passthrough.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use yolac_dpi::{
    evade_http_request, fragment_tls_client_hello, is_sensitive_unblocked_domain,
    parse_client_hello, parse_client_hello_prefix, parse_http_host, plan_tcp_splits, DpiStrategy,
    HttpEvasionOptions, SplitStrategy,
};

use crate::captive_portal::is_local_lan_ip;
use crate::protect::{connect_protected_tcp, SocketProtector};

/// Bounded TCP connect timeout prevents 60-127s hangs on blackholed IPs.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 64 KB steady-state copy buffer (8x larger than Tokio's default 8 KB -> cuts syscalls & allocs 8x).
const RELAY_COPY_BUF: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOutcome {
    Success,
    ResetOrEofDuringHandshake,
    HandshakeTimeout,
    ThrottledSlowHandshake,
}

/// Callback interface allowing `yolac-core::AdaptiveController` to choose & adapt DPI strategies.
pub trait StrategyAdvisor: Send + Sync {
    fn select_strategy(&self, dst: SocketAddr, sni: Option<&str>) -> DpiStrategy;
    /// Selects the learned strategy for `(dst, sni)` if one exists, otherwise returns `default_if_unseen`.
    fn select_strategy_with_default(
        &self,
        dst: SocketAddr,
        sni: Option<&str>,
        default_if_unseen: DpiStrategy,
    ) -> DpiStrategy {
        let _ = default_if_unseen;
        self.select_strategy(dst, sni)
    }
    fn report_outcome(&self, dst: SocketAddr, sni: Option<&str>, used: DpiStrategy, outcome: FlowOutcome);
}

pub struct NoopStrategyAdvisor {
    pub default_strategy: DpiStrategy,
}

impl StrategyAdvisor for NoopStrategyAdvisor {
    fn select_strategy(&self, _dst: SocketAddr, _sni: Option<&str>) -> DpiStrategy {
        self.default_strategy
    }

    fn report_outcome(
        &self,
        _dst: SocketAddr,
        _sni: Option<&str>,
        _used: DpiStrategy,
        _outcome: FlowOutcome,
    ) {
    }
}

pub struct DpiTcpRelay {
    protector: Arc<dyn SocketProtector>,
    advisor: Arc<dyn StrategyAdvisor>,
    handshake_timeout: Duration,
}

impl DpiTcpRelay {
    pub fn new(protector: Arc<dyn SocketProtector>, advisor: Arc<dyn StrategyAdvisor>) -> Self {
        Self {
            protector,
            advisor,
            handshake_timeout: Duration::from_millis(2500),
        }
    }

    async fn connect_upstream(&self, dst: SocketAddr) -> io::Result<TcpStream> {
        timeout(CONNECT_TIMEOUT, connect_protected_tcp(dst, self.protector.as_ref()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream TCP connect timeout"))?
    }

    /// Relays a client stream to `dst`, applying DPI circumvention on TLS ClientHello / HTTP requests,
    /// while passing LAN traffic, non-web/server-speaks-first protocols (WhatsApp 5222 / Noise `WA\x06`,
    /// Telegram MTProto, SSH, IMAP, databases, games), and pre-warmed sockets straight through!
    pub async fn relay_stream<S>(&self, mut client: S, dst: SocketAddr) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Local LAN / router portals / NAS / printers: never split or mangle HTTP/TLS!
        if is_local_lan_ip(dst.ip()) {
            let mut upstream = self.connect_upstream(dst).await?;
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                RELAY_COPY_BUF,
                RELAY_COPY_BUF,
            )
            .await?;
            return Ok(());
        }

        // Tier 1: Known non-web / messaging / DB / game / server-speaks-first ports:
        // connect upstream immediately and relay bidirectionally with zero artificial wait.
        let is_direct_non_web_port = matches!(
            dst.port(),
            21 | 22
                | 25
                | 110
                | 143
                | 465
                | 554
                | 587
                | 993
                | 995
                | 1883
                | 3306
                | 3389
                | 5060
                | 5222
                | 5223
                | 5228
                | 5242
                | 5432
                | 5900
                | 6379
                | 6667
                | 6697
                | 8883
                | 25565
                | 27017
        );
        if is_direct_non_web_port {
            let mut upstream = self.connect_upstream(dst).await?;
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                RELAY_COPY_BUF,
                RELAY_COPY_BUF,
            )
            .await?;
            return Ok(());
        }

        // Tier 2: Standard web/TLS ports wait up to 30s so pre-warmed idle mobile sockets
        // (Chrome, WhatsApp/Telegram push) are never dropped prematurely.
        // Tier 3: Custom/other ports peek briefly (150ms) so custom HTTPS ports still get DPI
        // protection while arbitrary server-speaks-first protocols connect right away.
        let is_standard_web_port =
            matches!(dst.port(), 443 | 80 | 8443 | 8080 | 2053 | 2083 | 2087 | 2096);
        let initial_peek_timeout = if is_standard_web_port {
            Duration::from_secs(30)
        } else {
            Duration::from_millis(150)
        };

        // Speculative parallel TCP connect on standard web ports: hides 1 full remote TCP SYN/SYN-ACK RTT
        // behind the local ClientHello write AND delivers instant Happy Eyeballs RST on unreachable IPs!
        let mut speculative_upstream: Option<TcpStream> = None;
        let mut initial = Vec::with_capacity(2048);
        let mut chunk = [0u8; 4096];

        if is_standard_web_port {
            let connect_fut = self.connect_upstream(dst);
            let read_fut = timeout(initial_peek_timeout, client.read(&mut chunk));
            tokio::pin!(connect_fut);
            tokio::pin!(read_fut);

            let mut conn_done = false;
            let n = loop {
                tokio::select! {
                    c_res = &mut connect_fut, if !conn_done => {
                        conn_done = true;
                        match c_res {
                            Ok(s) => speculative_upstream = Some(s),
                            Err(e) => return Err(e), // Instant RST propagation to Happy Eyeballs!
                        }
                    }
                    r_res = &mut read_fut => {
                        match r_res {
                            Ok(Ok(0)) => return Ok(()),
                            Ok(Ok(n)) => break n,
                            Ok(Err(e)) => return Err(e),
                            Err(_) => {
                                let mut upstream = match speculative_upstream.take() {
                                    Some(s) => s,
                                    None => connect_fut.await?,
                                };
                                let _ = tokio::io::copy_bidirectional_with_sizes(
                                    &mut client, &mut upstream, RELAY_COPY_BUF, RELAY_COPY_BUF,
                                ).await?;
                                return Ok(());
                            }
                        }
                    }
                }
            };
            initial.extend_from_slice(&chunk[..n]);
            if !conn_done {
                speculative_upstream = Some(connect_fut.await?);
            }
        } else {
            let n = match timeout(initial_peek_timeout, client.read(&mut chunk)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let mut upstream = self.connect_upstream(dst).await?;
                    let _ = tokio::io::copy_bidirectional_with_sizes(
                        &mut client,
                        &mut upstream,
                        RELAY_COPY_BUF,
                        RELAY_COPY_BUF,
                    )
                    .await?;
                    return Ok(());
                }
            };
            initial.extend_from_slice(&chunk[..n]);
        }

        // Reassemble multi-segment Post-Quantum TLS ClientHello (RFC 8446 max record = 16389 bytes)
        let mut tls_reassembly_incomplete = false;
        if initial.len() >= 5 && initial[0] == 0x16 && initial[1] == 0x03 && initial[2] <= 0x04 {
            let expected_len = 5 + u16::from_be_bytes([initial[3], initial[4]]) as usize;
            if expected_len <= 16_389 && initial.len() < expected_len {
                let deadline = Instant::now() + Duration::from_millis(500);
                while initial.len() < expected_len {
                    let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    match timeout(rem, client.read(&mut chunk)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(more)) => initial.extend_from_slice(&chunk[..more]),
                    }
                }
                if initial.len() < expected_len {
                    tls_reassembly_incomplete = true;
                }
            }
        }
        let initial = initial.as_slice();

        let tls_info = parse_client_hello(initial).or_else(|| parse_client_hello_prefix(initial));
        let http_info = if tls_info.is_none() {
            parse_http_host(initial)
        } else {
            None
        };

        // Non-TLS / Non-HTTP binary protocols on port 443 (WhatsApp Noise `WA\x06\x03`, Telegram MTProto)
        // OR truncated ClientHello that couldn't finish reassembly -> direct copy with ZERO retry hang!
        if (tls_info.is_none() && http_info.is_none()) || tls_reassembly_incomplete {
            let mut upstream = match speculative_upstream.take() {
                Some(s) => s,
                None => self.connect_upstream(dst).await?,
            };
            upstream.write_all(initial).await?;
            upstream.flush().await?;
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                RELAY_COPY_BUF,
                RELAY_COPY_BUF,
            )
            .await?;
            return Ok(());
        }

        let sni = tls_info
            .as_ref()
            .and_then(|c| c.sni.clone())
            .or_else(|| http_info.as_ref().map(|h| h.host.clone()));

        // Sensitive unblocked services (WhatsApp, e-Devlet, Turkish banks) default to clean Passthrough
        // ONLY when AdaptiveController has no prior learned escalation for that domain!
        let sensitive_passthrough = sni
            .as_deref()
            .map(is_sensitive_unblocked_domain)
            .unwrap_or(false);
        let mut strategy = if sensitive_passthrough {
            self.advisor
                .select_strategy_with_default(dst, sni.as_deref(), DpiStrategy::Passthrough)
        } else {
            self.advisor.select_strategy(dst, sni.as_deref())
        };

        // Non-idempotent HTTP (POST/PUT/PATCH/DELETE) or partial HTTP headers (>4KB body):
        // apply HTTP evasion on the first write and immediately enter bidirectional copy so we NEVER
        // deadlock waiting for a response before forwarding the rest of the body or duplicate POSTs!
        if let Some(_http) = &http_info {
            let is_complete_idempotent_http = (initial.starts_with(b"GET ") || initial.starts_with(b"HEAD "))
                && initial.windows(4).any(|w| w == b"\r\n\r\n");
            if !is_complete_idempotent_http {
                let mut upstream = match speculative_upstream.take() {
                    Some(s) => s,
                    None => self.connect_upstream(dst).await?,
                };
                send_with_strategy_tcp(&mut upstream, initial, strategy).await?;
                let _ = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut upstream,
                    RELAY_COPY_BUF,
                    RELAY_COPY_BUF,
                )
                .await?;
                return Ok(());
            }
        }

        // Attempt 1 (using speculative warm TCP stream when available) + transparent multi-stage retry
        let mut attempt = 0u8;
        const MAX_RETRIES: u8 = 3;
        let (mut upstream, first_resp) = loop {
            let from_speculative = speculative_upstream.is_some();
            let mut candidate = match speculative_upstream.take() {
                Some(s) => s,
                None => self.connect_upstream(dst).await?,
            };
            let sent_at = Instant::now();
            if let Err(e) = send_with_strategy_tcp(&mut candidate, initial, strategy).await {
                if from_speculative && attempt < MAX_RETRIES {
                    attempt += 1;
                    continue;
                }
                return Err(e);
            }

            let mut resp_buf = [0u8; 4096];
            match timeout(self.handshake_timeout, candidate.read(&mut resp_buf)).await {
                Ok(Ok(rn)) if rn > 0 => {
                    let outcome = if strategy == DpiStrategy::Passthrough
                        && sent_at.elapsed() > Duration::from_millis(1500)
                    {
                        FlowOutcome::ThrottledSlowHandshake
                    } else {
                        FlowOutcome::Success
                    };
                    self.advisor
                        .report_outcome(dst, sni.as_deref(), strategy, outcome);
                    break (candidate, resp_buf[..rn].to_vec());
                }
                Ok(Ok(_)) => {
                    // An idle pre-warmed speculative socket closed before TLS exchange must NOT
                    // falsely escalate domain DPI strategy; retry immediately on a fresh socket!
                    if from_speculative && attempt < MAX_RETRIES {
                        attempt += 1;
                        continue;
                    }
                    self.advisor.report_outcome(
                        dst,
                        sni.as_deref(),
                        strategy,
                        FlowOutcome::ResetOrEofDuringHandshake,
                    );
                    if attempt < MAX_RETRIES {
                        let next = self.advisor.select_strategy(dst, sni.as_deref());
                        if next != strategy {
                            strategy = next;
                            attempt += 1;
                            continue;
                        }
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "upstream closed during handshake (possible DPI RST)",
                    ));
                }
                Ok(Err(e)) => {
                    if from_speculative && attempt < MAX_RETRIES {
                        attempt += 1;
                        continue;
                    }
                    self.advisor.report_outcome(
                        dst,
                        sni.as_deref(),
                        strategy,
                        FlowOutcome::ResetOrEofDuringHandshake,
                    );
                    if attempt < MAX_RETRIES {
                        let next = self.advisor.select_strategy(dst, sni.as_deref());
                        if next != strategy {
                            strategy = next;
                            attempt += 1;
                            continue;
                        }
                    }
                    return Err(e);
                }
                Err(_) => {
                    self.advisor.report_outcome(
                        dst,
                        sni.as_deref(),
                        strategy,
                        FlowOutcome::HandshakeTimeout,
                    );
                    if attempt < MAX_RETRIES {
                        let next = self.advisor.select_strategy(dst, sni.as_deref());
                        if next != strategy {
                            strategy = next;
                            attempt += 1;
                            continue;
                        }
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream handshake timeout",
                    ));
                }
            }
        };

        client.write_all(&first_resp).await?;
        client.flush().await?;

        // Steady state: high-throughput 64 KB zero-inspection bidirectional copy
        let _ = tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut upstream,
            RELAY_COPY_BUF,
            RELAY_COPY_BUF,
        )
        .await?;
        Ok(())
    }
}

/// Sends an initial TLS ClientHello or HTTP request over a real `TcpStream` using the selected
/// `DpiStrategy`, supporting POSIX `MSG_OOB` (ByeDPI `-o1`) on Linux/Android when escalated.
async fn send_with_strategy_tcp(
    stream: &mut TcpStream,
    payload: &[u8],
    strategy: DpiStrategy,
) -> io::Result<()> {
    if (strategy == DpiStrategy::TcpOobAndTlsSplit
        && parse_client_hello(payload).is_some())
        || (strategy == DpiStrategy::TcpOobAndTlsSplit
            && parse_client_hello_prefix(payload).is_some())
    {
        if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::OffsetAndSniMid(2)) {
            let first_rec_len = (5 + u16::from_be_bytes([frag[3], frag[4]]) as usize).min(frag.len());
            stream.write_all(&frag[..1]).await?;
            stream.flush().await?;
            tokio::task::yield_now().await;
            if first_rec_len > 1 {
                stream.write_all(&frag[1..first_rec_len]).await?;
                stream.flush().await?;
            }
            // Inject 1 urgent TCP OOB byte (`MSG_OOB`, ByeDPI `-o1`) on Linux/Android sockets
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                use std::os::unix::io::AsRawFd;
                let fd = stream.as_raw_fd();
                let oob: u8 = b'a';
                let _ = unsafe {
                    libc::send(
                        fd,
                        (&oob as *const u8).cast(),
                        1,
                        libc::MSG_OOB | libc::MSG_NOSIGNAL,
                    )
                };
            }
            tokio::task::yield_now().await;
            if first_rec_len < frag.len() {
                return write_tls_records_paced(stream, &frag[first_rec_len..], false).await;
            }
            return Ok(());
        }
    }
    send_with_strategy(stream, payload, strategy).await
}

/// Sends an initial TLS ClientHello or HTTP request using the selected `DpiStrategy`.
pub async fn send_with_strategy<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    strategy: DpiStrategy,
) -> io::Result<()> {
    if parse_client_hello(payload).is_some() || parse_client_hello_prefix(payload).is_some() {
        match strategy {
            DpiStrategy::Passthrough => {
                writer.write_all(payload).await?;
                writer.flush().await?;
                return Ok(());
            }
            DpiStrategy::TlsRecordSplit => {
                if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::SniMid) {
                    writer.write_all(&frag).await?;
                    writer.flush().await?;
                    return Ok(());
                }
                return write_tcp_split(writer, payload, 2.min(payload.len().saturating_sub(1))).await;
            }
            DpiStrategy::TcpSniSplit => {
                if let Some(plan) = plan_tcp_splits(payload) {
                    return write_tcp_split(writer, payload, plan.split_at).await;
                }
                return write_tcp_split(writer, payload, 2.min(payload.len().saturating_sub(1))).await;
            }
            DpiStrategy::TlsMultiRecordAndTcpSplit => {
                // ByeDPI-Turkey `-r1+s -s1` equivalent: 3 valid TLS records (offset 2 + mid-SNI)
                // under TCP_NODELAY with zero artificial timer-coalescing sleeps!
                if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::OffsetAndSniMid(2)) {
                    writer.write_all(&frag[..1]).await?;
                    writer.flush().await?;
                    tokio::task::yield_now().await;
                    let first_rec_len = (5 + u16::from_be_bytes([frag[3], frag[4]]) as usize).min(frag.len());
                    if first_rec_len > 1 {
                        writer.write_all(&frag[1..first_rec_len]).await?;
                        writer.flush().await?;
                        tokio::task::yield_now().await;
                    }
                    if first_rec_len < frag.len() {
                        return write_tls_records_paced(writer, &frag[first_rec_len..], false).await;
                    }
                    return Ok(());
                }
            }
            DpiStrategy::TlsSmallChunks => {
                // Escalated mobile stage: 24-byte TLS records guaranteed to split inside SNI
                if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::MultiChunk(24)) {
                    return write_tls_records_paced(writer, &frag, false).await;
                }
            }
            DpiStrategy::TlsAndTcpSplit
            | DpiStrategy::TcpOobAndTlsSplit
            | DpiStrategy::RawDisorder
            | DpiStrategy::RawFakeTtl { .. }
            | DpiStrategy::RawBadChecksum
            | DpiStrategy::TurkeyDesyncAuto
            | DpiStrategy::TurkeyDesyncSuperonline
            | DpiStrategy::TurkeyDesyncAggressive => {
                if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::SniMid) {
                    let first_rec_len = 5 + u16::from_be_bytes([frag[3], frag[4]]) as usize;
                    let split_at = first_rec_len.clamp(1, frag.len().saturating_sub(1));
                    return write_tcp_split(writer, &frag, split_at).await;
                }
                if let Some(plan) = plan_tcp_splits(payload) {
                    return write_tcp_split(writer, payload, plan.split_at).await;
                }
                return write_tcp_split(writer, payload, 2.min(payload.len().saturating_sub(1))).await;
            }
        }
    } else if parse_http_host(payload).is_some() && strategy != DpiStrategy::Passthrough {
        let evaded = evade_http_request(payload, HttpEvasionOptions::default())
            .unwrap_or_else(|| payload.to_vec());
        if let Some(plan) = plan_tcp_splits(&evaded) {
            return write_tcp_split(writer, &evaded, plan.split_at).await;
        }
        writer.write_all(&evaded).await?;
        writer.flush().await?;
        return Ok(());
    }

    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Writes concatenated TLS records one record per TCP segment under TCP_NODELAY.
async fn write_tls_records_paced<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    use_sleep: bool,
) -> io::Result<()> {
    let mut pos = 0usize;
    while pos + 5 <= data.len() && data[pos] == 0x16 {
        let rlen = 5 + u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let end = (pos + rlen).min(data.len());
        writer.write_all(&data[pos..end]).await?;
        writer.flush().await?;
        pos = end;
        if pos < data.len() {
            if use_sleep {
                tokio::time::sleep(Duration::from_millis(1)).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
    }
    if pos < data.len() {
        writer.write_all(&data[pos..]).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn write_tcp_split<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    split_at: usize,
) -> io::Result<()> {
    if data.len() < 2 {
        writer.write_all(data).await?;
        writer.flush().await?;
        return Ok(());
    }
    let idx = split_at.clamp(1, data.len() - 1);
    writer.write_all(&data[..idx]).await?;
    writer.flush().await?;
    tokio::task::yield_now().await;
    writer.write_all(&data[idx..]).await?;
    writer.flush().await?;
    Ok(())
}
