//! Userspace L3 TUN packet router using `smoltcp` (for Android VpnService & iOS NEPacketTunnelProvider).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer as SmolTcpSocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use yolac_dns::{parse_dns_query, DnsEngine, DnsOutcome};
use yolac_dpi::{
    build_ipv4_udp_packet, build_ipv6_udp_packet, detect_quic_initial, parse_ip_packet, parse_tcp,
    parse_udp, IpProtocol, QuicPolicy,
};

use crate::captive_portal::CaptivePortalMonitor;
use crate::leak_guard::{Ipv6LeakMode, LeakDecision, LeakGuard};
use crate::protect::{bind_protected_udp, SocketProtector};
use crate::relay::{DpiTcpRelay, StrategyAdvisor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProfile {
    Standard,
    /// Constrained memory budget for iOS NEPacketTunnelProvider (~15-50 MB ceiling).
    LowMemoryIos,
}

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub mtu: usize,
    pub profile: MemoryProfile,
    pub ipv6_mode: Ipv6LeakMode,
    pub quic_policy: QuicPolicy,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            profile: MemoryProfile::Standard,
            ipv6_mode: Ipv6LeakMode::DualStackProtected,
            quic_policy: QuicPolicy::BlockFallbackToTcp,
        }
    }
}

impl TunConfig {
    pub fn max_tcp_flows(&self) -> usize {
        match self.profile {
            MemoryProfile::Standard => 1024,
            MemoryProfile::LowMemoryIos => 256,
        }
    }

    pub fn max_udp_sessions(&self) -> usize {
        match self.profile {
            MemoryProfile::Standard => 512,
            MemoryProfile::LowMemoryIos => 128,
        }
    }

    pub fn tcp_buf_size(&self) -> usize {
        match self.profile {
            MemoryProfile::Standard => 32 * 1024,
            MemoryProfile::LowMemoryIos => 16 * 1024,
        }
    }

    pub fn max_concurrent_dns_tasks(&self) -> usize {
        match self.profile {
            MemoryProfile::Standard => 64,
            MemoryProfile::LowMemoryIos => 32,
        }
    }
}

/// Abstract L3 packet interface (backed by OS TUN fd or Swift `NEPacketTunnelFlow` channels or test pipes).
pub trait PacketDevice: Send + Sync {
    fn recv_packet(&self) -> impl std::future::Future<Output = io::Result<Vec<u8>>> + Send;
    fn send_packet(&self, pkt: Vec<u8>) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

/// In-memory or FFI-bridged `PacketDevice` using bounded Tokio MPSC channels.
pub struct ChannelPacketDevice {
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl ChannelPacketDevice {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            rx: Mutex::new(rx),
            tx,
        }
    }
}

impl PacketDevice for ChannelPacketDevice {
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "TUN packet channel closed"))
    }

    async fn send_packet(&self, pkt: Vec<u8>) -> io::Result<()> {
        self.tx
            .send(pkt)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN tx channel closed"))
    }
}

/// smoltcp virtual IP-medium device backed by in-memory packet queues.
struct VirtualIpDevice {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualIpDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::with_capacity(64),
            tx_queue: VecDeque::with_capacity(64),
        }
    }
}

struct VecRxToken(Vec<u8>);
impl RxToken for VecRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct VecTxToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for VecTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = VecRxToken where Self: 'a;
    type TxToken<'a> = VecTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((VecRxToken(pkt), VecTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VecTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

struct ActiveTcpFlow {
    handle: SocketHandle,
    to_relay: mpsc::Sender<Vec<u8>>,
    from_relay: mpsc::Receiver<Vec<u8>>,
    relay_closed: bool,
    pending_write: Vec<u8>,
}

struct UdpSession {
    tx: mpsc::Sender<Vec<u8>>,
    last_active: Instant,
}

pub struct TunEngine {
    config: TunConfig,
    dns: Arc<DnsEngine>,
    protector: Arc<dyn SocketProtector>,
    advisor: Arc<dyn StrategyAdvisor>,
    leak_guard: LeakGuard,
    captive_portal: Arc<CaptivePortalMonitor>,
    dns_semaphore: Arc<Semaphore>,
}

impl TunEngine {
    pub fn new(
        config: TunConfig,
        dns: Arc<DnsEngine>,
        protector: Arc<dyn SocketProtector>,
        advisor: Arc<dyn StrategyAdvisor>,
    ) -> Self {
        Self::with_captive_portal(
            config,
            dns,
            protector,
            advisor,
            Arc::new(CaptivePortalMonitor::new()),
        )
    }

    pub fn with_captive_portal(
        config: TunConfig,
        dns: Arc<DnsEngine>,
        protector: Arc<dyn SocketProtector>,
        advisor: Arc<dyn StrategyAdvisor>,
        captive_portal: Arc<CaptivePortalMonitor>,
    ) -> Self {
        let leak_guard = LeakGuard {
            ipv6_mode: config.ipv6_mode,
            block_plaintext_dns_tcp_bypass: true,
        };
        let dns_semaphore = Arc::new(Semaphore::new(config.max_concurrent_dns_tasks()));
        Self {
            config,
            dns,
            protector,
            advisor,
            leak_guard,
            captive_portal,
            dns_semaphore,
        }
    }

    /// Runs the L3 packet loop until `shutdown_rx` receives `true` or `device` closes.
    pub async fn run<D: PacketDevice + 'static>(
        &self,
        device: Arc<D>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let mut vdev = VirtualIpDevice::new(self.config.mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = 0x796F_6C61_6300_0001;
        let mut iface = Interface::new(iface_cfg, &mut vdev, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 219, 0, 1)), 30));
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::new(0xfd79, 0x6f6c, 0x6163, 0, 0, 0, 0, 1)),
                126,
            ));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 219, 0, 1));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfd79, 0x6f6c, 0x6163, 0, 0, 0, 0, 1));

        let mut sockets = SocketSet::new(Vec::new());
        let mut tcp_flows: HashMap<FlowKey, ActiveTcpFlow> = HashMap::new();
        let mut udp_sessions: HashMap<FlowKey, UdpSession> = HashMap::new();

        let (wake_tx, mut wake_rx) = mpsc::channel::<()>(64);
        let mut cleanup_tick = tokio::time::interval(Duration::from_secs(10));

        loop {
            let poll_delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_millis(d.total_millis().max(1)))
                .unwrap_or(Duration::from_millis(50));

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                pkt_res = device.recv_packet() => {
                    match pkt_res {
                        Ok(pkt) => {
                            self.handle_inbound_tun_packet(
                                pkt,
                                &device,
                                &mut vdev,
                                &mut iface,
                                &mut sockets,
                                &mut tcp_flows,
                                &mut udp_sessions,
                                &wake_tx,
                            ).await;
                        }
                        Err(_) => break,
                    }
                }
                _ = wake_rx.recv() => {}
                _ = tokio::time::sleep(poll_delay) => {}
                _ = cleanup_tick.tick() => {
                    let now = Instant::now();
                    udp_sessions.retain(|_, s| now.duration_since(s.last_active) < Duration::from_secs(45));
                }
            }

            // Pump smoltcp interface and relay channels
            iface.poll(SmolInstant::now(), &mut vdev, &mut sockets);
            self.pump_tcp_flows(&mut sockets, &mut tcp_flows);
            iface.poll(SmolInstant::now(), &mut vdev, &mut sockets);

            while let Some(out_pkt) = vdev.tx_queue.pop_front() {
                let _ = device.send_packet(out_pkt).await;
            }
        }

        // Wipe active sessions cleanly
        tcp_flows.clear();
        udp_sessions.clear();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_inbound_tun_packet<D: PacketDevice + 'static>(
        &self,
        pkt: Vec<u8>,
        device: &Arc<D>,
        vdev: &mut VirtualIpDevice,
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        tcp_flows: &mut HashMap<FlowKey, ActiveTcpFlow>,
        udp_sessions: &mut HashMap<FlowKey, UdpSession>,
        wake_tx: &mpsc::Sender<()>,
    ) {
        // DoS / OOM guard: drop empty or oversized packets before parsing
        if pkt.is_empty() || pkt.len() > 65535 {
            return;
        }
        let Some(ip) = parse_ip_packet(&pkt) else {
            return;
        };

        let portal_active = self.captive_portal.is_bypass_active();
        match self.leak_guard.inspect_outbound_with_portal(&ip, portal_active) {
            LeakDecision::BlockIpv6Leak | LeakDecision::BlockDnsBypassTcp => return,
            LeakDecision::InterceptDnsUdp => {
                if let Some(udp) = parse_udp(ip.payload) {
                    let Ok(permit) = Arc::clone(&self.dns_semaphore).try_acquire_owned() else {
                        return; // Backpressure under DNS flood
                    };
                    let dns = Arc::clone(&self.dns);
                    let portal = Arc::clone(&self.captive_portal);
                    let dev = Arc::clone(device);
                    let query_bytes = udp.payload.to_vec();
                    let src_ip = ip.src_ip;
                    let dst_ip = ip.dst_ip;
                    let src_port = udp.src_port;
                    let dst_port = udp.dst_port;
                    tokio::spawn(async move {
                        let _permit = permit;
                        let qname = parse_dns_query(&query_bytes).map(|q| q.qname);
                        let (resp_opt, outcome) = dns.resolve(&query_bytes).await;
                        match outcome {
                            DnsOutcome::UpstreamResolved => {
                                portal.on_dns_upstream_success();
                            }
                            DnsOutcome::Failed => {
                                if let Some(name) = qname.as_deref() {
                                    portal.on_dns_query_and_failure_state(
                                        name,
                                        dns.consecutive_failures(),
                                    );
                                }
                            }
                            _ => {}
                        }
                        if let Some(resp) = resp_opt {
                            let reply_pkt = match (dst_ip, src_ip) {
                                (IpAddr::V4(s), IpAddr::V4(d)) => {
                                    build_ipv4_udp_packet(s, d, dst_port, src_port, 64, &resp)
                                }
                                (IpAddr::V6(s), IpAddr::V6(d)) => {
                                    build_ipv6_udp_packet(s, d, dst_port, src_port, 64, &resp)
                                }
                                _ => return,
                            };
                            let _ = dev.send_packet(reply_pkt).await;
                        }
                    });
                }
                return;
            }
            LeakDecision::Allow => {}
        }

        match ip.protocol {
            IpProtocol::Udp => {
                let Some(udp) = parse_udp(ip.payload) else {
                    return;
                };
                if udp.dst_port == 443
                    && self.config.quic_policy == QuicPolicy::BlockFallbackToTcp
                    && detect_quic_initial(udp.payload).is_some()
                {
                    // Drop QUIC Initial cleanly to trigger Happy Eyeballs fallback to DPI-protected TCP/TLS
                    return;
                }

                let key = FlowKey {
                    src_ip: ip.src_ip,
                    src_port: udp.src_port,
                    dst_ip: ip.dst_ip,
                    dst_port: udp.dst_port,
                };

                if let Some(sess) = udp_sessions.get_mut(&key) {
                    sess.last_active = Instant::now();
                    let _ = sess.tx.try_send(udp.payload.to_vec());
                    return;
                }

                if udp_sessions.len() >= self.config.max_udp_sessions() {
                    // LRU eviction of oldest idle UDP NAT session so flood packets cannot starve real traffic
                    if let Some(oldest_key) = udp_sessions
                        .iter()
                        .min_by_key(|(_, s)| s.last_active)
                        .map(|(k, _)| *k)
                    {
                        udp_sessions.remove(&oldest_key);
                    } else {
                        return;
                    }
                }

                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
                let _ = tx.try_send(udp.payload.to_vec());
                udp_sessions.insert(
                    key,
                    UdpSession {
                        tx,
                        last_active: Instant::now(),
                    },
                );

                let protector = Arc::clone(&self.protector);
                let dev = Arc::clone(device);
                tokio::spawn(async move {
                    let is_v6 = key.dst_ip.is_ipv6();
                    let Ok(sock) = bind_protected_udp(is_v6, protector.as_ref()).await else {
                        return;
                    };
                    let remote = SocketAddr::new(key.dst_ip, key.dst_port);
                    if sock.connect(remote).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; 2048];
                    loop {
                        tokio::select! {
                            msg = rx.recv() => {
                                match msg {
                                    Some(payload) => { let _ = sock.send(&payload).await; }
                                    None => break,
                                }
                            }
                            res = tokio::time::timeout(Duration::from_secs(30), sock.recv(&mut buf)) => {
                                match res {
                                    Ok(Ok(n)) if n > 0 => {
                                        let pkt = match (key.dst_ip, key.src_ip) {
                                            (IpAddr::V4(s), IpAddr::V4(d)) => {
                                                build_ipv4_udp_packet(s, d, key.dst_port, key.src_port, 64, &buf[..n])
                                            }
                                            (IpAddr::V6(s), IpAddr::V6(d)) => {
                                                build_ipv6_udp_packet(s, d, key.dst_port, key.src_port, 64, &buf[..n])
                                            }
                                            _ => continue,
                                        };
                                        let _ = dev.send_packet(pkt).await;
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                });
            }
            IpProtocol::Tcp => {
                let Some(tcp) = parse_tcp(ip.payload) else {
                    return;
                };
                let key = FlowKey {
                    src_ip: ip.src_ip,
                    src_port: tcp.src_port,
                    dst_ip: ip.dst_ip,
                    dst_port: tcp.dst_port,
                };

                if tcp.is_syn_only() && !tcp_flows.contains_key(&key) {
                    if tcp_flows.len() >= self.config.max_tcp_flows() {
                        return;
                    }

                    let buf_size = self.config.tcp_buf_size();
                    let mut sock = SmolTcpSocket::new(
                        SmolTcpSocketBuffer::new(vec![0; buf_size]),
                        SmolTcpSocketBuffer::new(vec![0; buf_size]),
                    );
                    let listen_ip = match key.dst_ip {
                        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())),
                        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
                    };
                    if sock.listen((listen_ip, key.dst_port)).is_err() {
                        return;
                    }
                    let handle = sockets.add(sock);

                    let (to_relay_tx, to_relay_rx) = mpsc::channel::<Vec<u8>>(32);
                    let (from_relay_tx, from_relay_rx) = mpsc::channel::<Vec<u8>>(32);

                    tcp_flows.insert(
                        key,
                        ActiveTcpFlow {
                            handle,
                            to_relay: to_relay_tx,
                            from_relay: from_relay_rx,
                            relay_closed: false,
                            pending_write: Vec::new(),
                        },
                    );

                    let relay = DpiTcpRelay::new(
                        Arc::clone(&self.protector),
                        Arc::clone(&self.advisor),
                    );
                    let wake = wake_tx.clone();
                    tokio::spawn(async move {
                        let stream = ChannelStream::new(to_relay_rx, from_relay_tx, wake);
                        let _ = relay
                            .relay_stream(stream, SocketAddr::new(key.dst_ip, key.dst_port))
                            .await;
                    });
                }

                vdev.rx_queue.push_back(pkt);
                // Immediately poll so a new Listen socket transitions to SynReceived for this exact SYN
                iface.poll(SmolInstant::now(), vdev, sockets);
            }
            _ => {}
        }
    }

    fn pump_tcp_flows(
        &self,
        sockets: &mut SocketSet<'_>,
        tcp_flows: &mut HashMap<FlowKey, ActiveTcpFlow>,
    ) {
        let mut to_remove = Vec::new();

        for (key, flow) in tcp_flows.iter_mut() {
            let sock = sockets.get_mut::<SmolTcpSocket>(flow.handle);

            // 1. Read from local app (smoltcp rx buffer) -> send to DpiTcpRelay
            if sock.can_recv() {
                let mut chunk = Vec::new();
                let _ = sock.recv(|data| {
                    chunk.extend_from_slice(data);
                    (data.len(), ())
                });
                if !chunk.is_empty() && flow.to_relay.try_send(chunk).is_err() {
                    flow.relay_closed = true;
                }
            }

            // 2. Drain outbound bytes from DpiTcpRelay -> write into smoltcp tx buffer
            while !flow.relay_closed && flow.pending_write.is_empty() {
                match flow.from_relay.try_recv() {
                    Ok(data) => flow.pending_write = data,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        flow.relay_closed = true;
                        break;
                    }
                }
            }

            if !flow.pending_write.is_empty() && sock.can_send() {
                if let Ok(sent) = sock.send_slice(&flow.pending_write) {
                    if sent > 0 {
                        flow.pending_write.drain(..sent);
                    }
                }
            }

            if flow.relay_closed && flow.pending_write.is_empty() {
                sock.close();
            }

            if sock.state() == SmolTcpState::Closed
                || (!sock.is_active() && flow.relay_closed)
            {
                to_remove.push(*key);
            }
        }

        for key in to_remove {
            if let Some(flow) = tcp_flows.remove(&key) {
                sockets.remove(flow.handle);
            }
        }
    }
}

/// Bridges an `mpsc` packet/byte stream pair into a Tokio `AsyncRead + AsyncWrite` stream for `DpiTcpRelay`.
struct ChannelStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    wake: mpsc::Sender<()>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ChannelStream {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        wake: mpsc::Sender<()>,
    ) -> Self {
        Self {
            rx,
            tx,
            wake,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl tokio::io::AsyncRead for ChannelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let avail = &self.read_buf[self.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.read_buf = chunk;
                    self.read_pos = n;
                }
                let _ = self.wake.try_send(());
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for ChannelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.tx.try_send(buf.to_vec()) {
            Ok(()) => {
                let _ = self.wake.try_send(());
                std::task::Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let _ = self.wake.try_send(());
                std::task::Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN closed")))
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let _ = self.wake.try_send(());
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
