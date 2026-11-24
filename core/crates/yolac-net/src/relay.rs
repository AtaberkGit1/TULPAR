//! DPI-evasive outbound TCP relay with adaptive failure/RST feedback and zero-overhead steady-state copy.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use yolac_dpi::{
    evade_http_request, fragment_tls_client_hello, parse_client_hello, parse_http_host,
    plan_tcp_splits, DpiStrategy, HttpEvasionOptions, SplitStrategy,
};

use crate::protect::{connect_protected_tcp, SocketProtector};

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
            handshake_timeout: Duration::from_secs(4),
        }
    }

    /// Relays a client stream to `dst`, applying DPI circumvention on the initial ClientHello / HTTP request,
    /// then entering zero-overhead `copy_bidirectional` for steady-state traffic.
    pub async fn relay_stream<S>(&self, mut client: S, dst: SocketAddr) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read initial client payload (e.g., TLS ClientHello or HTTP request).
        // Modern browsers (Chrome 131+ X25519MLKEM768 post-quantum TLS 1.3) send ClientHellos
        // larger than a single 1460-byte TCP MSS segment; reassemble the complete first TLS
        // record (bounded at 8 KiB / 400ms) so TLS record fragmentation always succeeds.
        let mut initial = Vec::with_capacity(2048);
        let mut chunk = [0u8; 4096];
        let n = match timeout(Duration::from_secs(5), client.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "client initial read timeout")),
        };
        initial.extend_from_slice(&chunk[..n]);

        if initial.len() >= 5 && initial[0] == 0x16 && initial[1] == 0x03 && initial[2] <= 0x04 {
            let expected_len = 5 + u16::from_be_bytes([initial[3], initial[4]]) as usize;
            if expected_len <= 8192 && initial.len() < expected_len {
                let deadline = Instant::now() + Duration::from_millis(400);
                while initial.len() < expected_len {
                    let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    match timeout(rem, client.read(&mut chunk)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(more)) => initial.extend_from_slice(&chunk[..more]),
                    }
                }
            }
        }
        let initial = initial.as_slice();

        let sni = parse_client_hello(initial)
            .and_then(|c| c.sni)
            .or_else(|| parse_http_host(initial).map(|h| h.host));

        // Attempt 1 + optional transparent single retry on DPI RST / early EOF before any bytes reach client
        let mut strategy = self.advisor.select_strategy(dst, sni.as_deref());
        let mut attempt = 0u8;
        let (mut upstream, first_resp) = loop {
            let mut candidate = connect_protected_tcp(dst, self.protector.as_ref()).await?;
            let sent_at = Instant::now();
            send_with_strategy(&mut candidate, initial, strategy).await?;

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
                    self.advisor.report_outcome(
                        dst,
                        sni.as_deref(),
                        strategy,
                        FlowOutcome::ResetOrEofDuringHandshake,
                    );
                    if attempt == 0 {
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
                    self.advisor.report_outcome(
                        dst,
                        sni.as_deref(),
                        strategy,
                        FlowOutcome::ResetOrEofDuringHandshake,
                    );
                    if attempt == 0 {
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
                    if attempt == 0 {
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

        // Steady state: zero-inspection bidirectional copy (no throughput penalty)
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }
}

/// Sends an initial TLS ClientHello or HTTP request using the selected `DpiStrategy`.
pub async fn send_with_strategy<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    strategy: DpiStrategy,
) -> io::Result<()> {
    if parse_client_hello(payload).is_some() {
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
            }
            DpiStrategy::TcpSniSplit => {
                if let Some(plan) = plan_tcp_splits(payload) {
                    return write_tcp_split(writer, payload, plan.split_at).await;
                }
            }
            DpiStrategy::TlsAndTcpSplit
            | DpiStrategy::RawDisorder
            | DpiStrategy::RawFakeTtl { .. }
            | DpiStrategy::RawBadChecksum => {
                if let Some(frag) = fragment_tls_client_hello(payload, SplitStrategy::SniMid) {
                    // Split TCP segments right on the TLS record boundary inside SNI
                    let first_rec_len = 5 + u16::from_be_bytes([frag[3], frag[4]]) as usize;
                    if first_rec_len < frag.len() {
                        return write_tcp_split(writer, &frag, first_rec_len).await;
                    }
                    writer.write_all(&frag).await?;
                    writer.flush().await?;
                    return Ok(());
                }
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
    writer.flush().await
}

async fn write_tcp_split<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    split_at: usize,
) -> io::Result<()> {
    let idx = split_at.clamp(1, data.len().saturating_sub(1));
    writer.write_all(&data[..idx]).await?;
    writer.flush().await?;
    // Brief yield ensures separate TCP segments are pushed to kernel/middlebox even under Nagle/coalescing
    tokio::time::sleep(Duration::from_millis(1)).await;
    writer.write_all(&data[idx..]).await?;
    writer.flush().await
}
