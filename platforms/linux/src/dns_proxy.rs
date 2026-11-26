//! Local encrypted DNS + Ad/Tracker-Blocker UDP & TCP proxy (`127.0.0.1:5354`, optional `[::1]:5354`).
//! Binds listeners synchronously BEFORE firewall NAT rules are installed so DNS can never blackhole.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use yolac_dns::wire::{build_blocked_response, is_local_lan_hostname};
use yolac_dns::{parse_dns_query, DnsEngine};

pub const DNS_PROXY_PORT: u16 = 5354;

pub struct BoundDnsListeners {
    udp_v4: UdpSocket,
    udp_v6: Option<UdpSocket>,
    tcp_v4: TcpListener,
    tcp_v6: Option<TcpListener>,
}

/// Binds UDP/TCP local DNS sockets synchronously before `apply_firewall_rules()` runs.
pub async fn bind_dns_listeners() -> std::io::Result<BoundDnsListeners> {
    let udp_v4 = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], DNS_PROXY_PORT))).await?;
    let tcp_v4 = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], DNS_PROXY_PORT))).await?;
    let udp_v6 = UdpSocket::bind("[::1]:5354").await.ok();
    let tcp_v6 = TcpListener::bind("[::1]:5354").await.ok();
    Ok(BoundDnsListeners {
        udp_v4,
        udp_v6,
        tcp_v4,
        tcp_v6,
    })
}

async fn resolve_dns_wire(dns: &Arc<DnsEngine>, query_pkt: &[u8]) -> Option<Vec<u8>> {
    if let Some(q) = parse_dns_query(query_pkt) {
        if is_local_lan_hostname(&q.qname) {
            return build_blocked_response(query_pkt, true);
        }
    }
    if let Some((resp_opt, _)) = dns.try_resolve_local(query_pkt) {
        return resp_opt;
    }
    dns.resolve_with_swr(query_pkt).await.0
}

fn maybe_truncate_udp_dns(query_pkt: &[u8], mut reply: Vec<u8>) -> Vec<u8> {
    // RFC 1035 / EDNS0 safe truncation for oversized UDP responses -> client retries over TCP!
    if reply.len() > 1232 && reply.len() >= 12 {
        if let Some(q) = parse_dns_query(query_pkt) {
            let mut trunc = Vec::with_capacity(q.question_end);
            trunc.extend_from_slice(&reply[..12]);
            trunc[2] |= 0x02; // TC=1
            trunc[6..12].fill(0);
            trunc.extend_from_slice(&query_pkt[12..q.question_end]);
            reply = trunc;
        }
    }
    reply
}

async fn serve_udp(sock: Arc<UdpSocket>, dns: Arc<DnsEngine>, mut shutdown: watch::Receiver<bool>) {
    let mut buf = [0u8; 4096];
    let dns_sem = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            recv = sock.recv_from(&mut buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(q) = parse_dns_query(&buf[..n]) {
                    if is_local_lan_hostname(&q.qname) {
                        if let Some(reply) = build_blocked_response(&buf[..n], true) {
                            let _ = sock.send_to(&reply, peer).await;
                        }
                        continue;
                    }
                }
                // Fast-path synchronous RAM cache / ad-block / AAAA suppression without spawning a task
                if let Some((resp_opt, _)) = dns.try_resolve_local(&buf[..n]) {
                    if let Some(reply) = resp_opt {
                        let wire = maybe_truncate_udp_dns(&buf[..n], reply);
                        let _ = sock.send_to(&wire, peer).await;
                    }
                    continue;
                }
                let Ok(permit) = Arc::clone(&dns_sem).try_acquire_owned() else {
                    continue;
                };
                let query_pkt = buf[..n].to_vec();
                let dns_ref = Arc::clone(&dns);
                let sock_ref = Arc::clone(&sock);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(reply) = resolve_dns_wire(&dns_ref, &query_pkt).await {
                        let wire = maybe_truncate_udp_dns(&query_pkt, reply);
                        let _ = sock_ref.send_to(&wire, peer).await;
                    }
                });
            }
        }
    }
}

async fn handle_tcp_dns_conn(mut stream: TcpStream, dns: Arc<DnsEngine>) {
    const TCP_DNS_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    let mut len_buf = [0u8; 2];
    while matches!(
        tokio::time::timeout(TCP_DNS_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await,
        Ok(Ok(_))
    ) {
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 4096 {
            break;
        }
        let mut query = vec![0u8; msg_len];
        if !matches!(
            tokio::time::timeout(TCP_DNS_IDLE_TIMEOUT, stream.read_exact(&mut query)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let Some(reply) = resolve_dns_wire(&dns, &query).await else {
            break;
        };
        if reply.len() > u16::MAX as usize {
            break;
        }
        let rlen = (reply.len() as u16).to_be_bytes();
        if stream.write_all(&rlen).await.is_err() || stream.write_all(&reply).await.is_err() {
            break;
        }
    }
}

async fn serve_tcp(listener: TcpListener, dns: Arc<DnsEngine>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let dns_ref = Arc::clone(&dns);
                tokio::spawn(handle_tcp_dns_conn(stream, dns_ref));
            }
        }
    }
}

pub async fn run_dns_proxy(
    listeners: BoundDnsListeners,
    dns: Arc<DnsEngine>,
    block_ipv6: bool,
    shutdown: watch::Receiver<bool>,
) {
    dns.set_suppress_aaaa(block_ipv6);
    let mut handles = Vec::new();
    handles.push(tokio::spawn(serve_udp(
        Arc::new(listeners.udp_v4),
        Arc::clone(&dns),
        shutdown.clone(),
    )));
    handles.push(tokio::spawn(serve_tcp(
        listeners.tcp_v4,
        Arc::clone(&dns),
        shutdown.clone(),
    )));
    if let Some(u6) = listeners.udp_v6 {
        handles.push(tokio::spawn(serve_udp(
            Arc::new(u6),
            Arc::clone(&dns),
            shutdown.clone(),
        )));
    }
    if let Some(t6) = listeners.tcp_v6 {
        handles.push(tokio::spawn(serve_tcp(
            t6,
            Arc::clone(&dns),
            shutdown,
        )));
    }
    for h in handles {
        let _ = h.await;
    }
}
