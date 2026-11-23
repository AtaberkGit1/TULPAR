#![allow(dead_code)]
//! Real WinDivert 2.2 dynamic FFI packet interception & DPI circumvention engine.

#[cfg(windows)]
use std::ffi::{c_char, c_void, CString};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::runtime::Runtime;
use yolac_core::{AdaptiveController, EngineState, ErrorCode};
use yolac_dns::{parse_dns_query, DnsEngine, DnsOutcome};
use yolac_dpi::{
    build_disorder_and_fake_packets, build_ipv4_tcp_packet, build_ipv6_tcp_packet, clamp_syn_mss,
    detect_quic_initial, evade_http_request, parse_client_hello, parse_http_host, parse_ip_packet,
    parse_tcp, parse_udp, plan_tcp_splits, segment_tcp_packet, DpiStrategy, FakePacketMode,
    HttpEvasionOptions, IpProtocol, QuicPolicy, TtlCalibrator,
};
use yolac_net::{is_local_lan_ip, CaptivePortalMonitor, FlowOutcome, StrategyAdvisor};

use crate::dns_guard::{build_dns_reply_l3, flush_windows_dns_cache};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub layer_flags: u32,
    pub reserved2: u32,
    pub union_data: [u8; 64],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            layer_flags: 0,
            reserved2: 0,
            union_data: [0u8; 64],
        }
    }
}

impl WinDivertAddress {
    /// Marks packet direction as Inbound (bit 17 in WinDivert 2.2 `WINDIVERT_ADDRESS` flags).
    pub fn set_inbound(&mut self) {
        // Outbound bit is bit 17 (`0x0002_0000` in little-endian bitfield: Layer(8), Event(8), Sniffed(1), Outbound(1))
        self.layer_flags &= !(1 << 17);
    }

    pub fn set_outbound(&mut self) {
        self.layer_flags |= 1 << 17;
    }

    pub fn is_outbound(&self) -> bool {
        (self.layer_flags & (1 << 17)) != 0
    }
}

#[cfg(windows)]
mod loader {
    use super::*;
    use crate::integrity::verify_windivert_next_to_exe;
    use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    };

    pub type WinDivertOpenFn = unsafe extern "C" fn(
        filter: *const c_char,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> *mut c_void;
    pub type WinDivertRecvFn = unsafe extern "C" fn(
        handle: *mut c_void,
        p_packet: *mut c_void,
        packet_len: u32,
        p_recv_len: *mut u32,
        p_addr: *mut WinDivertAddress,
    ) -> i32;
    pub type WinDivertSendFn = unsafe extern "C" fn(
        handle: *mut c_void,
        p_packet: *const c_void,
        packet_len: u32,
        p_send_len: *mut u32,
        p_addr: *const WinDivertAddress,
    ) -> i32;
    pub type WinDivertHelperCalcChecksumsFn = unsafe extern "C" fn(
        p_packet: *mut c_void,
        packet_len: u32,
        p_addr: *mut WinDivertAddress,
        flags: u64,
    ) -> i32;
    pub type WinDivertShutdownFn = unsafe extern "C" fn(handle: *mut c_void, how: u32) -> i32;
    pub type WinDivertCloseFn = unsafe extern "C" fn(handle: *mut c_void) -> i32;

    pub struct WinDivertApi {
        module: HMODULE,
        pub open: WinDivertOpenFn,
        pub recv: WinDivertRecvFn,
        pub send: WinDivertSendFn,
        pub calc_checksums: WinDivertHelperCalcChecksumsFn,
        pub shutdown: WinDivertShutdownFn,
        pub close: WinDivertCloseFn,
    }

    unsafe impl Send for WinDivertApi {}
    unsafe impl Sync for WinDivertApi {}

    impl WinDivertApi {
        pub fn load() -> Result<Self, ErrorCode> {
            let verified_dll_path = verify_windivert_next_to_exe()?;
            unsafe {
                let mut dll: Vec<u16> = verified_dll_path
                    .to_string_lossy()
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                // Load strictly from the application directory (prevents Windows DLL hijacking)
                let module = LoadLibraryExW(
                    dll.as_mut_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
                );
                if module.is_null() {
                    return Err(ErrorCode::DriverMissing);
                }

                macro_rules! sym {
                    ($name:literal, $ty:ty) => {
                        match GetProcAddress(module, $name.as_ptr()) {
                            Some(p) => std::mem::transmute::<_, $ty>(p),
                            None => {
                                FreeLibrary(module);
                                return Err(ErrorCode::DriverMissing);
                            }
                        }
                    };
                }

                Ok(Self {
                    module,
                    open: sym!(b"WinDivertOpen\0", WinDivertOpenFn),
                    recv: sym!(b"WinDivertRecv\0", WinDivertRecvFn),
                    send: sym!(b"WinDivertSend\0", WinDivertSendFn),
                    calc_checksums: sym!(b"WinDivertHelperCalcChecksums\0", WinDivertHelperCalcChecksumsFn),
                    shutdown: sym!(b"WinDivertShutdown\0", WinDivertShutdownFn),
                    close: sym!(b"WinDivertClose\0", WinDivertCloseFn),
                })
            }
        }

        pub fn is_invalid_handle(h: *mut c_void) -> bool {
            h.is_null() || h == INVALID_HANDLE_VALUE
        }
    }

    impl Drop for WinDivertApi {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

pub struct WindowsPacketEngine {
    stop_flag: Arc<AtomicBool>,
    handle_ptr: Arc<std::sync::Mutex<usize>>,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    calibrator: Arc<TtlCalibrator>,
}

impl WindowsPacketEngine {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            handle_ptr: Arc::new(std::sync::Mutex::new(0)),
            worker: std::sync::Mutex::new(None),
            calibrator: Arc::new(TtlCalibrator::default()),
        }
    }

    #[cfg(windows)]
    pub fn start<F>(
        &self,
        dns: Arc<DnsEngine>,
        adaptive: Arc<AdaptiveController>,
        portal: Arc<CaptivePortalMonitor>,
        on_state: F,
    ) -> Result<(), ErrorCode>
    where
        F: Fn(EngineState) + Send + Sync + 'static,
    {
        let api = Arc::new(loader::WinDivertApi::load()?);
        let filter = CString::new(
            "(outbound and ((tcp.DstPort == 443 or tcp.DstPort == 80) or udp.DstPort == 53 or tcp.DstPort == 53 or udp.DstPort == 443)) or (inbound and tcp.Syn and tcp.Ack and (tcp.SrcPort == 443 or tcp.SrcPort == 80))",
        )
        .map_err(|_| ErrorCode::InternalError)?;

        // WINDIVERT_LAYER_NETWORK = 0, priority = 0, flags = 0
        let raw_handle = unsafe { (api.open)(filter.as_ptr(), 0, 0, 0) };
        if loader::WinDivertApi::is_invalid_handle(raw_handle) {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(5) => ErrorCode::PermissionDenied, // ERROR_ACCESS_DENIED
                Some(2) | Some(577) => ErrorCode::DriverMissing,
                _ => ErrorCode::TunSetupFailed,
            });
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.handle_ptr.lock() {
            *g = raw_handle as usize;
        }
        flush_windows_dns_cache();
        on_state(EngineState::Active);

        let stop_flag = Arc::clone(&self.stop_flag);
        let handle_ptr = Arc::clone(&self.handle_ptr);
        let thread_api = Arc::clone(&api);
        let calibrator = Arc::clone(&self.calibrator);
        let raw_handle_addr = raw_handle as usize;

        let jh = std::thread::spawn(move || {
            let raw_handle = raw_handle_addr as *mut c_void;
            let rt = Runtime::new().expect("tokio runtime");
            let mut buf = vec![0u8; 65536];
            let mut addr = WinDivertAddress::default();
            let mut recv_len = 0u32;

            while !stop_flag.load(Ordering::Relaxed) {
                let ok = unsafe {
                    (thread_api.recv)(
                        raw_handle,
                        buf.as_mut_ptr().cast(),
                        buf.len() as u32,
                        &mut recv_len,
                        &mut addr,
                    )
                };
                if ok == 0 {
                    break;
                }
                let pkt = &buf[..recv_len as usize];
                let processed = process_packet(
                    pkt,
                    addr,
                    &rt,
                    &dns,
                    &adaptive,
                    &calibrator,
                    &portal,
                );

                for (out_pkt, mut out_addr) in processed {
                    let mut send_len = 0u32;
                    let mut mutable = out_pkt;
                    unsafe {
                        let _ = (thread_api.send)(
                            raw_handle,
                            mutable.as_mut_ptr().cast(),
                            mutable.len() as u32,
                            &mut send_len,
                            &mut out_addr,
                        );
                    }
                }
            }

            if let Ok(mut g) = handle_ptr.lock() {
                *g = 0;
            }
            unsafe {
                let _ = (thread_api.close)(raw_handle);
            }
            calibrator.clear();
            flush_windows_dns_cache();
            on_state(EngineState::Inactive);
        });

        if let Ok(mut w) = self.worker.lock() {
            *w = Some(jh);
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn start<F>(
        &self,
        _dns: Arc<DnsEngine>,
        _adaptive: Arc<AdaptiveController>,
        _portal: Arc<CaptivePortalMonitor>,
        _on_state: F,
    ) -> Result<(), ErrorCode>
    where
        F: Fn(EngineState) + Send + Sync + 'static,
    {
        Err(ErrorCode::DriverMissing)
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            if let Ok(g) = self.handle_ptr.lock() {
                let h = *g as *mut c_void;
                if !h.is_null() {
                    if let Ok(api) = loader::WinDivertApi::load() {
                        // WINDIVERT_SHUTDOWN_BOTH = 3
                        unsafe {
                            let _ = (api.shutdown)(h, 3);
                        }
                    }
                }
            }
        }
        if let Ok(mut w) = self.worker.lock() {
            if let Some(jh) = w.take() {
                let _ = jh.join();
            }
        }
        self.calibrator.clear();
        flush_windows_dns_cache();
    }
}

impl Drop for WindowsPacketEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Pure, cross-platform testable WinDivert packet processor supporting inbound SYN-ACK
/// hop calibration, smart SYN MSS clamping, Captive Portal local-LAN allowance, and DPI transforms.
pub fn process_packet(
    pkt: &[u8],
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    portal: &CaptivePortalMonitor,
) -> Vec<(Vec<u8>, WinDivertAddress)> {
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![(pkt.to_vec(), addr)];
    };

    // Observe inbound SYN-ACK TTL/HopLimit to dynamically calibrate per-destination fake TTL
    if !addr.is_outbound() {
        if ip.protocol == IpProtocol::Tcp {
            if let Some(tcp) = parse_tcp(ip.payload) {
                if (tcp.flags & (yolac_dpi::ParsedTcp::SYN | yolac_dpi::ParsedTcp::ACK))
                    == (yolac_dpi::ParsedTcp::SYN | yolac_dpi::ParsedTcp::ACK)
                {
                    calibrator.observe_syn_ack(ip.src_ip, ip.ttl);
                }
            }
        }
        return vec![(pkt.to_vec(), addr)];
    }

    process_outbound_inner(pkt, &ip, addr, rt, dns, adaptive, calibrator, portal)
}

/// Convenience wrapper for outbound-only tests and callers.
pub fn process_outbound_packet(
    pkt: &[u8],
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
) -> Vec<(Vec<u8>, WinDivertAddress)> {
    let calibrator = TtlCalibrator::default();
    let portal = CaptivePortalMonitor::new();
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![(pkt.to_vec(), addr)];
    };
    process_outbound_inner(pkt, &ip, addr, rt, dns, adaptive, &calibrator, &portal)
}

#[allow(clippy::too_many_arguments)]
fn process_outbound_inner(
    pkt: &[u8],
    ip: &yolac_dpi::ParsedIpPacket<'_>,
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    portal: &CaptivePortalMonitor,
) -> Vec<(Vec<u8>, WinDivertAddress)> {
    match ip.protocol {
        IpProtocol::Udp => {
            let Some(udp) = parse_udp(ip.payload) else {
                return vec![(pkt.to_vec(), addr)];
            };

            // 1. Intercept ALL UDP/53 DNS queries locally via DoH/DoT + blocklist -> zero ISP DNS leak
            //    (except direct local LAN gateway DNS during a bounded Captive Portal login window)
            if udp.dst_port == 53 {
                if portal.is_bypass_active() && is_local_lan_ip(ip.dst_ip) {
                    return vec![(pkt.to_vec(), addr)];
                }
                let qname = parse_dns_query(udp.payload).map(|q| q.qname);
                let (resp_opt, outcome) = rt.block_on(dns.resolve(udp.payload));
                match outcome {
                    DnsOutcome::UpstreamResolved => portal.on_dns_upstream_success(),
                    DnsOutcome::Failed => {
                        if let Some(name) = qname.as_deref() {
                            portal.on_dns_query_and_failure_state(name, dns.consecutive_failures());
                        }
                    }
                    _ => {}
                }
                if let Some(resp_wire) = resp_opt {
                    if let Some(reply_pkt) = build_dns_reply_l3(
                        ip.src_ip,
                        ip.dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        &resp_wire,
                    ) {
                        let mut inbound_addr = addr;
                        inbound_addr.set_inbound();
                        return vec![(reply_pkt, inbound_addr)];
                    }
                }
                return vec![];
            }

            // 2. QUIC UDP/443 fallback policy when QUIC throttling is active
            if udp.dst_port == 443
                && adaptive.recommended_quic_policy() == QuicPolicy::BlockFallbackToTcp
                && detect_quic_initial(udp.payload).is_some()
            {
                return vec![];
            }
        }
        IpProtocol::Tcp => {
            let Some(tcp) = parse_tcp(ip.payload) else {
                return vec![(pkt.to_vec(), addr)];
            };

            // Prevent plaintext TCP/53 DNS bypass
            if tcp.dst_port == 53 {
                return vec![];
            }

            // Smart SYN MSS clamping on outbound 443/80 handshakes (disrupts server-response DPI)
            if tcp.is_syn_only() && (tcp.dst_port == 443 || tcp.dst_port == 80) && !is_local_lan_ip(ip.dst_ip) {
                if let Some(clamped) = clamp_syn_mss(pkt, 536) {
                    return vec![(clamped, addr)];
                }
            }

            if !tcp.payload.is_empty() {
                let dst = SocketAddr::new(ip.dst_ip, tcp.dst_port);
                if let Some(ch) = parse_client_hello(tcp.payload) {
                    let strategy = adaptive.select_strategy(dst, ch.sni.as_deref());
                    adaptive.report_outcome(dst, ch.sni.as_deref(), strategy, FlowOutcome::Success);

                    match strategy {
                        DpiStrategy::Passthrough => {}
                        // Raw L3 WinDivert preserves exact TCP sequence length via TCP SNI segmentation,
                        // Disorder, auto-calibrated Low-TTL fake, and Bad-Checksum fake packets.
                        DpiStrategy::TlsRecordSplit | DpiStrategy::TcpSniSplit | DpiStrategy::TlsAndTcpSplit => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                if let Some((p1, p2)) = segment_tcp_packet(pkt, split.split_at) {
                                    return vec![(p1, addr), (p2, addr)];
                                }
                            }
                        }
                        DpiStrategy::RawDisorder => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                if let Some(plan) = build_disorder_and_fake_packets(pkt, split.split_at, None) {
                                    return plan.packets.into_iter().map(|p| (p, addr)).collect();
                                }
                            }
                        }
                        DpiStrategy::RawFakeTtl { ttl } => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                let mode = calibrator.recommended_fake_mode(ip.dst_ip, ttl);
                                if let Some(plan) = build_disorder_and_fake_packets(
                                    pkt,
                                    split.split_at,
                                    Some(mode),
                                ) {
                                    return plan.packets.into_iter().map(|p| (p, addr)).collect();
                                }
                            }
                        }
                        DpiStrategy::RawBadChecksum => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                if let Some(plan) = build_disorder_and_fake_packets(
                                    pkt,
                                    split.split_at,
                                    Some(FakePacketMode::BadChecksum),
                                ) {
                                    return plan.packets.into_iter().map(|p| (p, addr)).collect();
                                }
                            }
                        }
                    }
                } else if parse_http_host(tcp.payload).is_some() {
                    if let Some(evaded) = evade_http_request(tcp.payload, HttpEvasionOptions::default()) {
                        let source_pkt = if evaded.len() == tcp.payload.len() {
                            rebuild_tcp_payload_packet(ip, &tcp, &evaded).unwrap_or_else(|| pkt.to_vec())
                        } else {
                            pkt.to_vec()
                        };
                        if let Some(split) = plan_tcp_splits(&evaded) {
                            if let Some((p1, p2)) = segment_tcp_packet(&source_pkt, split.split_at) {
                                return vec![(p1, addr), (p2, addr)];
                            }
                        }
                        return vec![(source_pkt, addr)];
                    }
                }
            }
        }
        _ => {}
    }

    vec![(pkt.to_vec(), addr)]
}

fn rebuild_tcp_payload_packet(
    ip: &yolac_dpi::ParsedIpPacket<'_>,
    tcp: &yolac_dpi::ParsedTcp<'_>,
    new_payload: &[u8],
) -> Option<Vec<u8>> {
    let tcp_opts = if tcp.header_len > 20 {
        &ip.payload[20..tcp.header_len]
    } else {
        &[]
    };
    match (ip.src_ip, ip.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Some(build_ipv4_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            tcp.seq,
            tcp.ack,
            tcp.flags,
            tcp.window,
            ip.ttl,
            1,
            tcp_opts,
            new_payload,
        )),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_ipv6_tcp_packet(
            s,
            d,
            tcp.src_port,
            tcp.dst_port,
            tcp.seq,
            tcp.ack,
            tcp.flags,
            tcp.window,
            ip.ttl,
            tcp_opts,
            new_payload,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use yolac_blocklist::Blocklist;
    use yolac_dns::wire::{build_dns_query, parse_dns_response, DnsRecordData, QType};
    use yolac_dns::DnsConfig;
    use yolac_dpi::{build_ipv4_udp_packet, ipv4_header_checksum, tcp_checksum_ipv4, ParsedTcp, PlatformCapabilities};

    fn sample_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + entry_len;
        let exts_len = 4 + sni_ext_len;
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBB; 32]);
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

        let hs_len = body.len();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        rec.push(0x01);
        rec.push(0);
        rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    fn test_runtime_and_engines(
        initial_strategy: DpiStrategy,
    ) -> (Runtime, Arc<DnsEngine>, Arc<AdaptiveController>) {
        let rt = Runtime::new().unwrap();
        let bl = Arc::new(Blocklist::embedded_default());
        let dns = Arc::new(DnsEngine::new(
            DnsConfig {
                upstreams: vec![],
                ..DnsConfig::default()
            },
            bl,
            None,
        ));
        let adaptive = Arc::new(AdaptiveController::new(
            PlatformCapabilities::WINDOWS_WINDIVERT,
            initial_strategy,
            128,
        ));
        (rt, dns, adaptive)
    }

    #[test]
    fn intercepts_blocked_dns_locally_with_inbound_reply() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TlsAndTcpSplit);
        let q = build_dns_query(0x9001, "doubleclick.net", QType::A);
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(8, 8, 8, 8),
            55000,
            53,
            64,
            &q,
        );
        let mut addr = WinDivertAddress::default();
        addr.set_outbound();

        let out = process_outbound_packet(&pkt, addr, &rt, &dns, &adaptive);
        assert_eq!(out.len(), 1);
        let (reply_raw, reply_addr) = &out[0];
        assert_eq!(reply_addr.layer_flags & (1 << 17), 0); // Inbound
        let ip = parse_ip_packet(reply_raw).unwrap();
        let udp = parse_udp(ip.payload).unwrap();
        let resp = parse_dns_response(udp.payload).unwrap();
        assert_eq!(resp.id, 0x9001);
        assert_eq!(resp.answers[0].data, DnsRecordData::A(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn drops_tcp_port_53_dns_bypass() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TlsAndTcpSplit);
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(8, 8, 8, 8),
            55001,
            53,
            1,
            0,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            b"dns",
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert!(out.is_empty());
    }

    #[test]
    fn splits_tls_client_hello_with_valid_checksums() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TlsAndTcpSplit);
        let ch = sample_tls_client_hello("blocked.example.com");
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_ipv4_tcp_packet(
            src,
            dst,
            55002,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &ch,
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert_eq!(out.len(), 2);
        for (seg, _) in &out {
            let ip = parse_ip_packet(seg).unwrap();
            assert_eq!(ipv4_header_checksum(&seg[0..20]), u16::from_be_bytes([seg[10], seg[11]]));
            assert_eq!(
                tcp_checksum_ipv4(src, dst, ip.payload),
                u16::from_be_bytes([ip.payload[16], ip.payload[17]])
            );
        }
    }

    #[test]
    fn raw_fake_ttl_emits_decoy_and_disordered_segments() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::RawFakeTtl { ttl: 3 });
        let ch = sample_tls_client_hello("blocked.example.com");
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            55003,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &ch,
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert_eq!(out.len(), 3);
        assert_eq!(parse_ip_packet(&out[0].0).unwrap().ttl, 3);
        let seq1 = parse_tcp(parse_ip_packet(&out[1].0).unwrap().payload).unwrap().seq;
        let seq2 = parse_tcp(parse_ip_packet(&out[2].0).unwrap().payload).unwrap().seq;
        assert!(seq1 > seq2);
    }

    #[test]
    fn drops_quic_initial_when_throttled_for_tcp_fallback() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TlsAndTcpSplit);
        adaptive.report_quic_throttled();
        let mut quic = vec![0u8; 1200];
        quic[0] = 0xC3;
        quic[1..5].copy_from_slice(&1u32.to_be_bytes());
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            55004,
            443,
            64,
            &quic,
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert!(out.is_empty());
    }

    #[test]
    fn calibrates_fake_ttl_dynamically_from_inbound_syn_ack() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::RawFakeTtl { ttl: 3 });
        let calibrator = TtlCalibrator::default();
        let portal = CaptivePortalMonitor::new();

        let client_ip = Ipv4Addr::new(192, 168, 1, 10);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);

        // Inbound SYN-ACK with TTL=52 (12 hops from Linux initial 64 -> calibrated fake TTL = 6)
        let syn_ack = build_ipv4_tcp_packet(
            server_ip,
            client_ip,
            443,
            55100,
            9000,
            1000,
            ParsedTcp::SYN | ParsedTcp::ACK,
            65535,
            52,
            1,
            &[],
            &[],
        );
        let mut in_addr = WinDivertAddress::default();
        in_addr.set_inbound();
        let in_out = process_packet(&syn_ack, in_addr, &rt, &dns, &adaptive, &calibrator, &portal);
        assert_eq!(in_out.len(), 1);
        assert_eq!(calibrator.estimated_hops(IpAddr::V4(server_ip)), Some(12));

        // Outbound ClientHello -> decoy packet MUST use calibrated TTL=6 instead of static 3
        let ch = sample_tls_client_hello("blocked.example.com");
        let ch_pkt = build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            55100,
            443,
            1000,
            9001,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            2,
            &[],
            &ch,
        );
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();
        let out = process_packet(&ch_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &portal);
        assert_eq!(out.len(), 3);
        assert_eq!(parse_ip_packet(&out[0].0).unwrap().ttl, 6);
    }
}
