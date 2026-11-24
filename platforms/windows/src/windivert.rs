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
    detect_quic_initial, evade_http_request, parse_client_hello_prefix, parse_http_host,
    parse_ip_packet, parse_tcp, parse_udp, plan_tcp_splits, segment_tcp_packet, DpiStrategy,
    FakePacketMode, HttpEvasionOptions, IpProtocol, QuicPolicy, TtlCalibrator,
};
use yolac_net::{is_local_lan_ip, CaptivePortalMonitor, FlowOutcome, StrategyAdvisor};

use crate::dns_guard::{build_dns_reply_l3, flush_windows_dns_cache};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

    /// Marks IP/TCP/UDP checksums as already computed so Windows NIC checksum offload
    /// preserves our software-calculated (or intentionally corrupted BadChecksum decoy) values.
    /// WinDivert 2.2 bit layout: IPv6=bit 20, IPChecksum=bit 21, TCPChecksum=bit 22, UDPChecksum=bit 23.
    pub fn mark_checksums_valid(&mut self, is_v6: bool, is_tcp: bool) {
        if is_v6 {
            self.layer_flags |= 1 << 20;
        } else {
            self.layer_flags &= !(1 << 20);
            self.layer_flags |= 1 << 21; // IPChecksum valid
        }
        if is_tcp {
            self.layer_flags |= 1 << 22; // TCPChecksum valid
        } else {
            self.layer_flags |= 1 << 23; // UDPChecksum valid
        }
    }
}

/// Controls how `WinDivertHelperCalcChecksums` / `WINDIVERT_ADDRESS` offload flags are applied before `WinDivertSend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAction {
    /// Original untouched packet: keep original Windows NIC offload flags as received.
    Passthrough,
    /// Modified or newly synthesized packet: recalculate checksums & set valid checksum flags via WinDivert.
    Recalculate,
    /// Intentionally corrupted TCP checksum fake packet: do NOT recalculate TCP checksum,
    /// and mark IPChecksum + TCPChecksum valid so NIC hardware offload does not repair our decoy!
    PreserveBadTcpChecksum,
}

#[derive(Debug, Clone)]
pub struct OutgoingPacket {
    pub bytes: Vec<u8>,
    pub addr: WinDivertAddress,
    pub checksum: ChecksumAction,
}

#[cfg(windows)]
mod loader {
    use super::*;
    use crate::integrity::ensure_verified_windivert;
    use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        LOAD_LIBRARY_SEARCH_SYSTEM32,
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
            let verified_dll_path = ensure_verified_windivert()?;
            unsafe {
                let mut dll: Vec<u16> = verified_dll_path
                    .to_string_lossy()
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                // Load strictly from the verified directory + System32 (prevents Windows DLL hijacking)
                let module = LoadLibraryExW(
                    dll.as_mut_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
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
    #[cfg(windows)]
    active_api: std::sync::Mutex<Option<Arc<loader::WinDivertApi>>>,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    calibrator: Arc<TtlCalibrator>,
}

impl WindowsPacketEngine {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            handle_ptr: Arc::new(std::sync::Mutex::new(0)),
            #[cfg(windows)]
            active_api: std::sync::Mutex::new(None),
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
    ) -> Result<(), (ErrorCode, String)>
    where
        F: Fn(EngineState) + Send + Sync + 'static,
    {
        let api = Arc::new(loader::WinDivertApi::load().map_err(|code| {
            let os_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let detail = match code {
                ErrorCode::DriverIntegrityFailed => {
                    "WinDivert sürücüsü (WinDivert.dll / WinDivert64.sys) SHA-256 bütünlük doğrulamasından geçemedi.".to_string()
                }
                ErrorCode::DriverMissing if os_err != 0 => {
                    format!("WinDivert.dll yüklenemedi (Windows hata kodu: {os_err}). Antivirüs engeli veya eksik dosya olabilir.")
                }
                _ => "WinDivert sürücüsü (WinDivert.dll / WinDivert64.sys) bulunamadı.".to_string(),
            };
            (code, detail)
        })?);
        let full_filter = CString::new(
            "not loopback and ((outbound and ((tcp.DstPort == 443 or tcp.DstPort == 80) or udp.DstPort == 53 or tcp.DstPort == 53 or udp.DstPort == 443)) or (inbound and tcp.Syn and tcp.Ack and (tcp.SrcPort == 443 or tcp.SrcPort == 80)))",
        )
        .map_err(|_| (ErrorCode::InternalError, "WinDivert filtre derleme hatası.".into()))?;
        let fallback_filter = CString::new(
            "not loopback and outbound and (tcp.DstPort == 443 or tcp.DstPort == 80 or udp.DstPort == 53 or tcp.DstPort == 53 or udp.DstPort == 443)",
        )
        .map_err(|_| (ErrorCode::InternalError, "WinDivert yedek filtre derleme hatası.".into()))?;

        // WINDIVERT_LAYER_NETWORK = 0, priority = 0, flags = 0
        let mut raw_handle = unsafe { (api.open)(full_filter.as_ptr(), 0, 0, 0) };
        if loader::WinDivertApi::is_invalid_handle(raw_handle) {
            raw_handle = unsafe { (api.open)(fallback_filter.as_ptr(), 0, 0, 0) };
        }
        if loader::WinDivertApi::is_invalid_handle(raw_handle) {
            let os_code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(match os_code {
                5 => (
                    ErrorCode::PermissionDenied,
                    "Yönetici izni veya güvenlik yazılımı WinDivert erişimini engelledi (Windows kod: 5).".into(),
                ),
                2 | 3 => (
                    ErrorCode::DriverMissing,
                    format!("WinDivert64.sys sürücüsü başlatılamadı (Windows kod: {os_code}). Daha önce farklı klasörden çalıştırılan eski bir WinDivert hizmeti varsa bilgisayarı yeniden başlatın."),
                ),
                577 | 1275 => (
                    ErrorCode::DriverIntegrityFailed,
                    format!("Windows sürücü imza / Bellek Bütünlüğü (HVCI) veya antivirüs WinDivert64.sys yüklemesini engelledi (Windows kod: {os_code})."),
                ),
                _ => (
                    ErrorCode::InternalError,
                    format!("WinDivert çekirdek sürücüsü açılamadı (Windows hata kodu: {os_code})."),
                ),
            });
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.handle_ptr.lock() {
            *g = raw_handle as usize;
        }
        if let Ok(mut g) = self.active_api.lock() {
            *g = Some(Arc::clone(&api));
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
            let send_handle = Arc::new(std::sync::Mutex::new(raw_handle_addr));
            let dns_sem = Arc::new(tokio::sync::Semaphore::new(64));
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

                // CRITICAL: Handle outbound UDP/53 DNS asynchronously so the WinDivertRecv thread
                // NEVER deadlocks waiting for its own DoH/DoT TCP/443 upstream handshake!
                if addr.is_outbound() {
                    if let Some(ip) = parse_ip_packet(pkt) {
                        if ip.protocol == IpProtocol::Udp {
                            if let Some(udp) = parse_udp(ip.payload) {
                                if udp.dst_port == 53
                                    && !(portal.is_bypass_active() && is_local_lan_ip(ip.dst_ip))
                                {
                                    if let Ok(permit) = Arc::clone(&dns_sem).try_acquire_owned() {
                                        let dns_c = Arc::clone(&dns);
                                        let portal_c = Arc::clone(&portal);
                                        let api_c = Arc::clone(&thread_api);
                                        let sh_c = Arc::clone(&send_handle);
                                        let query_bytes = udp.payload.to_vec();
                                        let src_ip = ip.src_ip;
                                        let dst_ip = ip.dst_ip;
                                        let src_port = udp.src_port;
                                        let dst_port = udp.dst_port;
                                        let mut reply_addr = addr;
                                        reply_addr.set_inbound();

                                        rt.spawn(async move {
                                            let _permit = permit;
                                            let qname = parse_dns_query(&query_bytes).map(|q| q.qname);
                                            let (resp_opt, outcome) = dns_c.resolve(&query_bytes).await;
                                            match outcome {
                                                DnsOutcome::UpstreamResolved => {
                                                    portal_c.on_dns_upstream_success()
                                                }
                                                DnsOutcome::Failed => {
                                                    if let Some(name) = qname.as_deref() {
                                                        portal_c.on_dns_query_and_failure_state(
                                                            name,
                                                            dns_c.consecutive_failures(),
                                                        );
                                                    }
                                                }
                                                _ => {}
                                            }
                                            if let Some(resp_wire) = resp_opt {
                                                if let Some(mut reply_pkt) = build_dns_reply_l3(
                                                    src_ip, dst_ip, src_port, dst_port, &resp_wire,
                                                ) {
                                                    // CRITICAL: Recalculate & mark IP/UDP checksum flags valid on
                                                    // synthesized inbound DNS replies so Windows NIC checksum offload
                                                    // never drops the reply!
                                                    reply_addr.mark_checksums_valid(dst_ip.is_ipv6(), false);
                                                    unsafe {
                                                        let _ = (api_c.calc_checksums)(
                                                            reply_pkt.as_mut_ptr().cast(),
                                                            reply_pkt.len() as u32,
                                                            &mut reply_addr,
                                                            0,
                                                        );
                                                    }
                                                    if let Ok(guard) = sh_c.lock() {
                                                        if *guard != 0 {
                                                            let h = *guard as *mut c_void;
                                                            let mut send_len = 0u32;
                                                            unsafe {
                                                                let _ = (api_c.send)(
                                                                    h,
                                                                    reply_pkt.as_mut_ptr().cast(),
                                                                    reply_pkt.len() as u32,
                                                                    &mut send_len,
                                                                    &mut reply_addr,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }

                let processed = process_packet(
                    pkt,
                    addr,
                    &rt,
                    &dns,
                    &adaptive,
                    &calibrator,
                    &portal,
                );

                for mut out in processed {
                    match out.checksum {
                        ChecksumAction::Passthrough => {}
                        ChecksumAction::Recalculate => {
                            unsafe {
                                let _ = (thread_api.calc_checksums)(
                                    out.bytes.as_mut_ptr().cast(),
                                    out.bytes.len() as u32,
                                    &mut out.addr,
                                    0,
                                );
                            }
                        }
                        ChecksumAction::PreserveBadTcpChecksum => {
                            let is_v6 = out.bytes.first().map(|b| (b >> 4) == 6).unwrap_or(false);
                            out.addr.mark_checksums_valid(is_v6, true);
                        }
                    }
                    let mut send_len = 0u32;
                    if let Ok(guard) = send_handle.lock() {
                        if *guard != 0 {
                            let h = *guard as *mut c_void;
                            unsafe {
                                let _ = (thread_api.send)(
                                    h,
                                    out.bytes.as_mut_ptr().cast(),
                                    out.bytes.len() as u32,
                                    &mut send_len,
                                    &mut out.addr,
                                );
                            }
                        }
                    }
                }
            }

            if let Ok(mut g) = send_handle.lock() {
                *g = 0;
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
    ) -> Result<(), (ErrorCode, String)>
    where
        F: Fn(EngineState) + Send + Sync + 'static,
    {
        Err((
            ErrorCode::DriverMissing,
            "WinDivert sürücüsü yalnızca Windows üzerinde çalışır.".into(),
        ))
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            let api_opt = self.active_api.lock().ok().and_then(|mut g| g.take());
            if let Ok(g) = self.handle_ptr.lock() {
                let h = *g as *mut c_void;
                if !h.is_null() {
                    if let Some(api) = api_opt {
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
) -> Vec<OutgoingPacket> {
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![OutgoingPacket {
            bytes: pkt.to_vec(),
            addr,
            checksum: ChecksumAction::Passthrough,
        }];
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
        return vec![OutgoingPacket {
            bytes: pkt.to_vec(),
            addr,
            checksum: ChecksumAction::Passthrough,
        }];
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
) -> Vec<OutgoingPacket> {
    let calibrator = TtlCalibrator::default();
    let portal = CaptivePortalMonitor::new();
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![OutgoingPacket {
            bytes: pkt.to_vec(),
            addr,
            checksum: ChecksumAction::Passthrough,
        }];
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
) -> Vec<OutgoingPacket> {
    let passthrough = |bytes: Vec<u8>, a: WinDivertAddress| OutgoingPacket {
        bytes,
        addr: a,
        checksum: ChecksumAction::Passthrough,
    };
    let recalc = |bytes: Vec<u8>, a: WinDivertAddress| OutgoingPacket {
        bytes,
        addr: a,
        checksum: ChecksumAction::Recalculate,
    };

    match ip.protocol {
        IpProtocol::Udp => {
            let Some(udp) = parse_udp(ip.payload) else {
                return vec![passthrough(pkt.to_vec(), addr)];
            };

            // 1. Intercept ALL UDP/53 DNS queries locally via DoH/DoT + blocklist -> zero ISP DNS leak
            //    (except direct local LAN gateway DNS during a bounded Captive Portal login window)
            if udp.dst_port == 53 {
                if portal.is_bypass_active() && is_local_lan_ip(ip.dst_ip) {
                    return vec![passthrough(pkt.to_vec(), addr)];
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
                        inbound_addr.mark_checksums_valid(ip.dst_ip.is_ipv6(), false);
                        return vec![recalc(reply_pkt, inbound_addr)];
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
                return vec![passthrough(pkt.to_vec(), addr)];
            };

            // Prevent plaintext TCP/53 DNS bypass
            if tcp.dst_port == 53 {
                return vec![];
            }

            // Let encrypted DoH/DoT bootstrap upstreams pass straight through without double-fragmentation
            if is_bootstrap_dns_ip(ip.dst_ip) {
                return vec![passthrough(pkt.to_vec(), addr)];
            }

            // Smart SYN MSS clamping on outbound 443/80 handshakes (disrupts server-response DPI)
            if tcp.is_syn_only() && (tcp.dst_port == 443 || tcp.dst_port == 80) && !is_local_lan_ip(ip.dst_ip) {
                if let Some(clamped) = clamp_syn_mss(pkt, 536) {
                    return vec![recalc(clamped, addr)];
                }
            }

            if !tcp.payload.is_empty() {
                let dst = SocketAddr::new(ip.dst_ip, tcp.dst_port);
                if let Some(ch) = parse_client_hello_prefix(tcp.payload) {
                    let strategy = adaptive.select_strategy(dst, ch.sni.as_deref());
                    adaptive.report_outcome(dst, ch.sni.as_deref(), strategy, FlowOutcome::Success);

                    match strategy {
                        DpiStrategy::Passthrough => {}
                        // Raw L3 WinDivert preserves exact TCP sequence length via TCP SNI segmentation,
                        // Disorder, auto-calibrated Low-TTL fake, and Bad-Checksum fake packets.
                        DpiStrategy::TlsRecordSplit | DpiStrategy::TcpSniSplit | DpiStrategy::TlsAndTcpSplit => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                if let Some((p1, p2)) = segment_tcp_packet(pkt, split.split_at) {
                                    return vec![recalc(p1, addr), recalc(p2, addr)];
                                }
                            }
                        }
                        DpiStrategy::RawDisorder => {
                            if let Some(split) = plan_tcp_splits(tcp.payload) {
                                if let Some(plan) = build_disorder_and_fake_packets(pkt, split.split_at, None) {
                                    return plan.packets.into_iter().map(|p| recalc(p, addr)).collect();
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
                                    let is_bad_csum = matches!(mode, FakePacketMode::BadChecksum);
                                    return plan
                                        .packets
                                        .into_iter()
                                        .enumerate()
                                        .map(|(idx, p)| {
                                            if idx == 0 && is_bad_csum {
                                                let mut bad_addr = addr;
                                                bad_addr.mark_checksums_valid(ip.version == 6, true);
                                                OutgoingPacket {
                                                    bytes: p,
                                                    addr: bad_addr,
                                                    checksum: ChecksumAction::PreserveBadTcpChecksum,
                                                }
                                            } else {
                                                recalc(p, addr)
                                            }
                                        })
                                        .collect();
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
                                    return plan
                                        .packets
                                        .into_iter()
                                        .enumerate()
                                        .map(|(idx, p)| {
                                            if idx == 0 {
                                                let mut bad_addr = addr;
                                                bad_addr.mark_checksums_valid(ip.version == 6, true);
                                                OutgoingPacket {
                                                    bytes: p,
                                                    addr: bad_addr,
                                                    checksum: ChecksumAction::PreserveBadTcpChecksum,
                                                }
                                            } else {
                                                recalc(p, addr)
                                            }
                                        })
                                        .collect();
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
                                return vec![recalc(p1, addr), recalc(p2, addr)];
                            }
                        }
                        return vec![recalc(source_pkt, addr)];
                    }
                }
            }
        }
        _ => {}
    }

    vec![passthrough(pkt.to_vec(), addr)]
}

fn is_bootstrap_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            [1, 1, 1, 1]
                | [1, 0, 0, 1]
                | [9, 9, 9, 9]
                | [149, 112, 112, 112]
                | [194, 242, 2, 2]
                | [8, 8, 8, 8]
                | [8, 8, 4, 4]
        ),
        IpAddr::V6(v6) => matches!(
            v6.segments(),
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]
                | [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001]
                | [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe]
                | [0x2a07, 0xe340, 0, 0, 0, 0, 0, 2]
                | [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]
        ),
    }
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
        let reply = &out[0];
        assert_eq!(reply.addr.layer_flags & (1 << 17), 0); // Inbound
        assert_ne!(reply.addr.layer_flags & (1 << 21), 0); // IPChecksum valid
        assert_ne!(reply.addr.layer_flags & (1 << 23), 0); // UDPChecksum valid
        assert_eq!(reply.checksum, ChecksumAction::Recalculate);
        let ip = parse_ip_packet(&reply.bytes).unwrap();
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
        for seg in &out {
            assert_eq!(seg.checksum, ChecksumAction::Recalculate);
            let ip = parse_ip_packet(&seg.bytes).unwrap();
            assert_eq!(
                ipv4_header_checksum(&seg.bytes[0..20]),
                u16::from_be_bytes([seg.bytes[10], seg.bytes[11]])
            );
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
        assert_eq!(parse_ip_packet(&out[0].bytes).unwrap().ttl, 3);
        let seq1 = parse_tcp(parse_ip_packet(&out[1].bytes).unwrap().payload).unwrap().seq;
        let seq2 = parse_tcp(parse_ip_packet(&out[2].bytes).unwrap().payload).unwrap().seq;
        assert!(seq1 > seq2);
    }

    #[test]
    fn bad_checksum_fake_packet_preserves_bad_checksum_flag_and_mullvad_dns_passes_through() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::RawBadChecksum);
        let ch = sample_tls_client_hello("blocked.example.com");
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            55009,
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
        assert_eq!(out[0].checksum, ChecksumAction::PreserveBadTcpChecksum);
        assert_ne!(out[0].addr.layer_flags & (1 << 21), 0); // IPChecksum valid
        assert_ne!(out[0].addr.layer_flags & (1 << 22), 0); // TCPChecksum valid (prevent NIC overwrite!)
        assert_eq!(out[1].checksum, ChecksumAction::Recalculate);
        assert_eq!(out[2].checksum, ChecksumAction::Recalculate);

        // Mullvad DoH bootstrap IP 194.242.2.2 passes through without double-fragmentation
        let mullvad_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(194, 242, 2, 2),
            55010,
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
        let m_out = process_outbound_packet(&mullvad_pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert_eq!(m_out.len(), 1);
        assert_eq!(m_out[0].checksum, ChecksumAction::Passthrough);
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
        assert_eq!(parse_ip_packet(&out[0].bytes).unwrap().ttl, 6);
    }
}
