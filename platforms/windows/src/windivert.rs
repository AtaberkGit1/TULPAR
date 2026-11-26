#![allow(dead_code)]
//! Real WinDivert 2.2 dynamic FFI packet interception & Turkey-ISP-grade DPI circumvention engine.
//!
//! Features:
//! - Valid benign decoy ClientHello (`www.iana.org`) with calibrated Auto-TTL + `--wrong-seq` + `--wrong-chksum`
//! - Multi-point reverse-order (disorder) TCP segmentation (`-e 2` / `-e 1` + mid-SNI)
//! - Passive optical-splitter DPI forged `TCP RST` & BTK `HTTP 302` redirect dropping
//! - Real `FlowTracker` (salted 64-bit hash, zero plaintext IP logging) detecting active DPI RSTs &
//!   silent-blackhole TCP retransmissions to auto-escalate Stage 1 -> Stage 2 -> Stage 3 in real time
//! - Default QUIC UDP/443 blocking (`-q`) forcing browsers immediately onto DPI-protected TCP/443
//! - Asynchronous encrypted DoH/DoT UDP/53 interception with `WinDivertHelperCalcChecksums`

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
#[cfg(windows)]
use std::ffi::{c_char, c_void, CString};
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tulpar_forge::MatchProtocol;
use yolac_core::{execute_raw_forge_tcp, AdaptiveController, EngineState, ErrorCode};
use yolac_dns::wire::is_local_lan_hostname;
use yolac_dns::{parse_dns_query, DnsEngine, DnsOutcome};
use yolac_dpi::{
    build_benign_fake_client_hello, build_benign_fake_http_request,
    build_disorder_and_fake_packets, build_ipv4_tcp_packet, build_ipv6_tcp_packet,
    build_quic_desync_decoys, build_reassembled_desync_packets, build_turkey_desync_packets,
    build_udp_desync_decoys, clamp_syn_mss, detect_quic_initial, detect_udp_desync_target,
    evade_http_request, inspect_client_hello_needs_reassembly, is_forged_dpi_http_redirect,
    is_forged_passive_dpi_rst, is_sensitive_unblocked_domain, parse_client_hello,
    parse_client_hello_prefix, parse_http_host, parse_ip_packet, parse_tcp, parse_udp,
    plan_tcp_splits, segment_tcp_packet, DpiStrategy, FakePacketMode, HttpEvasionOptions,
    IpProtocol, QuicPolicy, TtlCalibrator,
};
use yolac_net::{is_local_lan_ip, CaptivePortalMonitor, FlowOutcome, StrategyAdvisor};
#[cfg(windows)]
use yolac_net::{probe_ipv6_leak_mode, Ipv6LeakMode, NoopProtector};

use crate::dns_guard::{build_dns_reply_l3, flush_windows_dns_cache};
#[cfg(windows)]
use crate::net_optimizer::cleanup_stale_windivert_service;

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
        self.layer_flags &= !(1 << 17);
    }

    pub fn set_outbound(&mut self) {
        self.layer_flags |= 1 << 17;
    }

    pub fn is_outbound(&self) -> bool {
        (self.layer_flags & (1 << 17)) != 0
    }

    /// Marks IP/TCP/UDP checksums as already computed so Windows NIC checksum offload
    /// preserves software-calculated (or intentionally corrupted BadChecksum decoy) values.
    /// WinDivert 2.2 bit layout: IPv6=bit 20, IPChecksum=bit 21, TCPChecksum=bit 22, UDPChecksum=bit 23.
    pub fn mark_checksums_valid(&mut self, is_v6: bool, is_tcp: bool) {
        if is_v6 {
            self.layer_flags |= 1 << 20;
        } else {
            self.layer_flags &= !(1 << 20);
            self.layer_flags |= 1 << 21;
        }
        if is_tcp {
            self.layer_flags |= 1 << 22;
        } else {
            self.layer_flags |= 1 << 23;
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
    /// Intentionally corrupted UDP checksum fake packet (Discord Voice / Roblox RakNet UDP desync):
    /// mark IPChecksum + UDPChecksum valid so NIC hardware offload does not repair our UDP decoy!
    PreserveBadUdpChecksum,
}

#[derive(Debug, Clone)]
pub struct OutgoingPacket {
    pub bytes: Vec<u8>,
    pub addr: WinDivertAddress,
    pub checksum: ChecksumAction,
}

/// Ephemeral RAM-only TCP handshake tracker keyed by per-session salted 64-bit hashes.
/// Never stores plaintext IP addresses or domain names. Detects:
/// 1. Real `SYN-ACK` TTL per flow (for passive DPI forged `RST` detection & hop calibration)
/// 2. Silent-blackhole DPI drops via outbound `ClientHello` TCP retransmissions (same `seq`)
/// 3. Active DPI `RST`/`FIN` during handshake before `ServerHello`
/// 4. Genuine `FlowOutcome::Success` when the client advances past `ClientHello` (`seq >= ch_seq_end`)
#[derive(Debug, Clone)]
struct PendingFlow {
    dst: SocketAddr,
    sni: Option<String>,
    strategy: DpiStrategy,
    used_forge: bool,
    ch_seq: u32,
    ch_seq_end: u32,
    syn_ack_ttl: Option<u8>,
    sent_at: Instant,
    retransmit_count: u8,
}

#[derive(Debug, Clone)]
pub enum PqAdvance {
    Waiting,
    Ready {
        template_pkt: Vec<u8>,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct PqStreamBuf {
    start_seq: u32,
    next_seq: u32,
    expected_len: usize,
    template_pkt: Vec<u8>,
    payload: Vec<u8>,
    started: Instant,
}

pub struct FlowTracker {
    hash_builder: RandomState,
    max_entries: usize,
    syn_ack_ttls: Mutex<HashMap<u64, u8>>,
    pending: Mutex<HashMap<u64, PendingFlow>>,
    udp_desynced: Mutex<HashMap<u64, Instant>>,
    pq_streams: Mutex<HashMap<u64, PqStreamBuf>>,
    pq_bypass: Mutex<HashMap<u64, Instant>>,
}

impl FlowTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            hash_builder: RandomState::new(),
            max_entries: max_entries.max(128),
            syn_ack_ttls: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            udp_desynced: Mutex::new(HashMap::new()),
            pq_streams: Mutex::new(HashMap::new()),
            pq_bypass: Mutex::new(HashMap::new()),
        }
    }

    fn mark_pq_bypass(&self, key: u64) {
        if let Ok(mut bp) = self.pq_bypass.lock() {
            let now = Instant::now();
            if bp.len() >= 128 && !bp.contains_key(&key) {
                bp.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(30));
                if bp.len() >= 128 {
                    if let Some(&evict) = bp.keys().next() {
                        bp.remove(&evict);
                    }
                }
            }
            bp.insert(key, now);
        }
    }

    pub fn begin_pq_stream(
        &self,
        local_port: u16,
        dst: SocketAddr,
        seq: u32,
        expected_len: usize,
        template_pkt: &[u8],
        first_payload: &[u8],
    ) -> bool {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        if let Ok(mut bp) = self.pq_bypass.lock() {
            if let Some(&ts) = bp.get(&key) {
                if ts.elapsed() < Duration::from_secs(30) {
                    return false;
                }
                bp.remove(&key);
            }
        }
        let Ok(mut guard) = self.pq_streams.lock() else {
            return false;
        };
        if let Some(prev) = guard.get(&key) {
            if prev.start_seq == seq {
                // Retransmission of initial PQ segment: stop delaying and let normal path send immediately.
                guard.remove(&key);
                drop(guard);
                self.mark_pq_bypass(key);
                return false;
            }
        }
        guard.retain(|_, v| v.started.elapsed() < Duration::from_millis(450));
        if guard.len() >= 64 {
            if let Some(&evict) = guard.keys().next() {
                guard.remove(&evict);
            }
        }
        guard.insert(
            key,
            PqStreamBuf {
                start_seq: seq,
                next_seq: seq.wrapping_add(first_payload.len() as u32),
                expected_len: expected_len.min(16_389),
                template_pkt: template_pkt.to_vec(),
                payload: first_payload.to_vec(),
                started: Instant::now(),
            },
        );
        true
    }

    pub fn advance_pq_stream(
        &self,
        local_port: u16,
        dst: SocketAddr,
        seq: u32,
        seg: &[u8],
    ) -> Option<PqAdvance> {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let mut guard = self.pq_streams.lock().ok()?;
        let entry = guard.get_mut(&key)?;
        if entry.started.elapsed() > Duration::from_millis(450) {
            guard.remove(&key);
            drop(guard);
            self.mark_pq_bypass(key);
            return None;
        }
        if seq != entry.next_seq {
            guard.remove(&key);
            drop(guard);
            self.mark_pq_bypass(key);
            return None;
        }
        let room = entry.expected_len.saturating_sub(entry.payload.len());
        if room > 0 {
            let take = seg.len().min(room);
            entry.payload.extend_from_slice(&seg[..take]);
        } else {
            entry.payload.extend_from_slice(seg);
        }
        entry.next_seq = entry.next_seq.wrapping_add(seg.len() as u32);
        if entry.payload.len() >= entry.expected_len {
            let finished = guard.remove(&key)?;
            Some(PqAdvance::Ready {
                template_pkt: finished.template_pkt,
                payload: finished.payload,
            })
        } else {
            Some(PqAdvance::Waiting)
        }
    }

    /// Returns `true` ONLY on the first handshake packet of a UDP flow (cooldown 30s),
    /// ensuring Discord Voice / Roblox RakNet UDP desync adds zero steady-state game latency!
    pub fn should_desync_udp_flow(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> bool {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let Ok(mut guard) = self.udp_desynced.lock() else {
            return false;
        };
        let now = Instant::now();
        if let Some(&prev) = guard.get(&key) {
            if now.duration_since(prev) < Duration::from_secs(30) {
                return false;
            }
        }
        if guard.len() >= self.max_entries {
            guard.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(30));
            if guard.len() >= self.max_entries {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
        }
        guard.insert(key, now);
        true
    }

    fn flow_key(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> u64 {
        self.hash_builder.hash_one((local_port, remote_ip, remote_port))
    }

    pub fn observe_syn_ack(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16, ttl: u8) {
        if ttl == 0 {
            return;
        }
        let key = self.flow_key(local_port, remote_ip, remote_port);
        if let Ok(mut guard) = self.syn_ack_ttls.lock() {
            if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
            guard.insert(key, ttl);
        }
    }

    pub fn syn_ack_ttl(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Option<u8> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        self.syn_ack_ttls.lock().ok()?.get(&key).copied()
    }

    pub fn has_pending_flow(&self, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> bool {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        self.pending
            .lock()
            .ok()
            .and_then(|g| g.get(&key).map(|e| e.sent_at.elapsed() < Duration::from_secs(8)))
            .unwrap_or(false)
    }

    /// Registers an outbound `ClientHello` (using full `record_total_len` so 2-segment Chrome 131+
    /// PQ ClientHellos are NEVER prematurely marked `Success` on segment #2!).
    /// Returns `Some(previous_strategy)` if this exact TCP sequence is a retransmission.
    pub fn record_client_hello(
        &self,
        local_port: u16,
        dst: SocketAddr,
        sni: Option<String>,
        seq_span: (u32, usize),
        strategy: DpiStrategy,
        used_forge: bool,
    ) -> Option<(DpiStrategy, bool, u8)> {
        let (seq, total_ch_len) = seq_span;
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let syn_ttl = self.syn_ack_ttl(local_port, dst.ip(), dst.port());
        let mut guard = self.pending.lock().ok()?;

        // Check if this is a TCP retransmission of a blackholed ClientHello
        if let Some(prev) = guard.get_mut(&key) {
            if prev.ch_seq == seq && prev.sent_at.elapsed() >= Duration::from_millis(40) {
                let failed_strategy = prev.strategy;
                let prev_forge = prev.used_forge;
                prev.strategy = strategy;
                prev.used_forge = used_forge;
                prev.sent_at = Instant::now();
                prev.retransmit_count = prev.retransmit_count.saturating_add(1);
                return Some((failed_strategy, prev_forge, prev.retransmit_count));
            }
        }

        if guard.len() >= self.max_entries && !guard.contains_key(&key) {
            let now = Instant::now();
            guard.retain(|_, v| now.duration_since(v.sent_at) < Duration::from_secs(15));
            if guard.len() >= self.max_entries {
                if let Some(&evict) = guard.keys().next() {
                    guard.remove(&evict);
                }
            }
        }

        guard.insert(
            key,
            PendingFlow {
                dst,
                sni,
                strategy,
                used_forge,
                ch_seq: seq,
                ch_seq_end: seq.wrapping_add(total_ch_len as u32),
                syn_ack_ttl: syn_ttl,
                sent_at: Instant::now(),
                retransmit_count: 0,
            },
        );
        None
    }

    /// Updates pending flow strategy after an immediate retransmission escalation.
    pub fn update_pending_strategy(
        &self,
        local_port: u16,
        dst: SocketAddr,
        new_strategy: DpiStrategy,
        used_forge: bool,
    ) {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        if let Ok(mut guard) = self.pending.lock() {
            if let Some(entry) = guard.get_mut(&key) {
                entry.strategy = new_strategy;
                entry.used_forge = used_forge;
                entry.sent_at = Instant::now();
            }
        }
    }

    /// Confirms handshake success when an inbound TLS `ServerHello` arrives from the destination server.
    pub fn on_inbound_server_hello(
        &self,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Option<(SocketAddr, Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let mut guard = self.pending.lock().ok()?;
        let entry = guard.remove(&key)?;
        Some((entry.dst, entry.sni, entry.strategy, entry.used_forge))
    }

    /// Checks whether a follow-up outbound TLS payload (`seq >= ch_seq_end`) proves that the
    /// server's `ServerHello` arrived and the handshake succeeded!
    pub fn on_outbound_followup(
        &self,
        local_port: u16,
        dst: SocketAddr,
        seq: u32,
    ) -> Option<(Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, dst.ip(), dst.port());
        let mut guard = self.pending.lock().ok()?;
        let entry = guard.get(&key)?;
        let advanced = seq.wrapping_sub(entry.ch_seq_end) < 0x8000_0000;
        if advanced {
            let entry = guard.remove(&key)?;
            return Some((entry.sni, entry.strategy, entry.used_forge));
        }
        None
    }

    /// Handles an inbound `RST` or premature `FIN` on a tracked flow.
    pub fn on_inbound_reset_or_fin(
        &self,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        is_forged_rst: bool,
    ) -> Option<(SocketAddr, Option<String>, DpiStrategy, bool)> {
        let key = self.flow_key(local_port, remote_ip, remote_port);
        let mut guard = self.pending.lock().ok()?;
        if is_forged_rst {
            return None;
        }
        if let Some(entry) = guard.remove(&key) {
            if entry.sent_at.elapsed() < Duration::from_secs(6) {
                return Some((entry.dst, entry.sni, entry.strategy, entry.used_forge));
            }
        }
        None
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.syn_ack_ttls.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pending.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.udp_desynced.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pq_streams.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pq_bypass.lock() {
            g.clear();
        }
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(windows)]
mod loader {
    use super::*;
    use crate::integrity::{ensure_verified_windivert_locked, VerifiedWinDivertLock};
    use std::os::windows::ffi::OsStrExt;
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
    pub type WinDivertRecvExFn = unsafe extern "C" fn(
        handle: *mut c_void,
        p_packet: *mut c_void,
        packet_len: u32,
        p_recv_len: *mut u32,
        flags: u64,
        p_addr: *mut WinDivertAddress,
        p_addr_len: *mut u32,
        lp_overlapped: *mut c_void,
    ) -> i32;
    pub type WinDivertSendExFn = unsafe extern "C" fn(
        handle: *mut c_void,
        p_packet: *const c_void,
        packet_len: u32,
        p_send_len: *mut u32,
        flags: u64,
        p_addr: *const WinDivertAddress,
        addr_len: u32,
        lp_overlapped: *mut c_void,
    ) -> i32;
    pub type WinDivertHelperCalcChecksumsFn = unsafe extern "C" fn(
        p_packet: *mut c_void,
        packet_len: u32,
        p_addr: *mut WinDivertAddress,
        flags: u64,
    ) -> i32;
    pub type WinDivertSetParamFn =
        unsafe extern "C" fn(handle: *mut c_void, param: u32, value: u64) -> i32;
    pub type WinDivertShutdownFn = unsafe extern "C" fn(handle: *mut c_void, how: u32) -> i32;
    pub type WinDivertCloseFn = unsafe extern "C" fn(handle: *mut c_void) -> i32;

    pub const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 0;
    pub const WINDIVERT_PARAM_QUEUE_TIME: u32 = 1;
    pub const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 2;

    pub struct WinDivertApi {
        module: HMODULE,
        _integrity_lock: VerifiedWinDivertLock,
        pub open: WinDivertOpenFn,
        pub recv: WinDivertRecvFn,
        pub recv_ex: Option<WinDivertRecvExFn>,
        pub send: WinDivertSendFn,
        pub send_ex: Option<WinDivertSendExFn>,
        pub calc_checksums: WinDivertHelperCalcChecksumsFn,
        pub set_param: Option<WinDivertSetParamFn>,
        pub shutdown: WinDivertShutdownFn,
        pub close: WinDivertCloseFn,
    }

    unsafe impl Send for WinDivertApi {}
    unsafe impl Sync for WinDivertApi {}

    impl WinDivertApi {
        pub fn load() -> Result<Self, (ErrorCode, i32)> {
            let lock = ensure_verified_windivert_locked().map_err(|c| (c, 0))?;
            unsafe {
                let mut dll: Vec<u16> = lock
                    .dll_path
                    .as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let module = LoadLibraryExW(
                    dll.as_mut_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                );
                if module.is_null() {
                    let os_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    return Err((ErrorCode::DriverMissing, os_err));
                }

                macro_rules! sym {
                    ($name:expr, $ty:ty) => {
                        match GetProcAddress(module, $name.as_ptr().cast()) {
                            Some(p) => {
                                std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(p)
                            }
                            None => {
                                let os_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                FreeLibrary(module);
                                return Err((ErrorCode::DriverMissing, os_err));
                            }
                        }
                    };
                }

                let set_param = GetProcAddress(module, c"WinDivertSetParam".as_ptr().cast()).map(
                    |p| std::mem::transmute::<unsafe extern "system" fn() -> isize, WinDivertSetParamFn>(p),
                );
                let recv_ex = GetProcAddress(module, c"WinDivertRecvEx".as_ptr().cast()).map(|p| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, WinDivertRecvExFn>(p)
                });
                let send_ex = GetProcAddress(module, c"WinDivertSendEx".as_ptr().cast()).map(|p| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, WinDivertSendExFn>(p)
                });

                Ok(Self {
                    module,
                    _integrity_lock: lock,
                    open: sym!(c"WinDivertOpen", WinDivertOpenFn),
                    recv: sym!(c"WinDivertRecv", WinDivertRecvFn),
                    recv_ex,
                    send: sym!(c"WinDivertSend", WinDivertSendFn),
                    send_ex,
                    calc_checksums: sym!(
                        c"WinDivertHelperCalcChecksums",
                        WinDivertHelperCalcChecksumsFn
                    ),
                    set_param,
                    shutdown: sym!(c"WinDivertShutdown", WinDivertShutdownFn),
                    close: sym!(c"WinDivertClose", WinDivertCloseFn),
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
    handle_ptr: Arc<Mutex<usize>>,
    #[cfg(windows)]
    active_api: Mutex<Option<Arc<loader::WinDivertApi>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    calibrator: Arc<TtlCalibrator>,
    flows: Arc<FlowTracker>,
}

impl WindowsPacketEngine {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            handle_ptr: Arc::new(Mutex::new(0)),
            #[cfg(windows)]
            active_api: Mutex::new(None),
            worker: Mutex::new(None),
            calibrator: Arc::new(TtlCalibrator::default()),
            flows: Arc::new(FlowTracker::default()),
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
        // Guard against accidental double-start overwriting a live worker, while cleaning up dead threads
        if let Ok(mut w) = self.worker.lock() {
            if let Some(ref jh) = *w {
                if !jh.is_finished() {
                    return Err((
                        ErrorCode::AlreadyRunning,
                        "TULPAR paket motoru zaten çalışıyor.".into(),
                    ));
                }
            }
            if let Some(dead) = w.take() {
                let _ = dead.join();
            }
        }
        if let Ok(mut g) = self.active_api.lock() {
            *g = None;
        }

        let api = Arc::new(loader::WinDivertApi::load().map_err(|(code, os_err)| {
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

        // v0.5.0 ZERO-JITTER KERNEL BYTECODE FILTER:
        // Captures TLS SYN + ClientHello (including multi-segment Post-Quantum X25519MLKEM768),
        // HTTP verbs/3xx redirects, DNS (53), rogue DoT (853), QUIC (443), Discord IP Discovery (74B),
        // STUN Binding (0x2112A442), and Roblox RakNet while keeping download ACKs in kernel!
        let kernel_fast_filter = CString::new(
            "not loopback and ((outbound and ((tcp.DstPort == 443 and ((tcp.Syn and not tcp.Ack) or (tcp.PayloadLength > 0 and not (tcp.PayloadLength >= 5 and tcp.Payload[0] == 0x17 and tcp.Payload[1] == 0x03 and tcp.Payload[2] >= 0x01 and tcp.Payload[2] <= 0x04)))) or (tcp.DstPort == 80 and ((tcp.Syn and not tcp.Ack) or (tcp.PayloadLength >= 16 and (tcp.Payload[0] == 0x47 or tcp.Payload[0] == 0x50 or tcp.Payload[0] == 0x48 or tcp.Payload[0] == 0x44 or tcp.Payload[0] == 0x4F)))) or udp.DstPort == 53 or tcp.DstPort == 53 or tcp.DstPort == 853 or udp.DstPort == 443 or (udp.DstPort >= 10000 and udp.PayloadLength == 74 and udp.Payload[0] == 0x00 and udp.Payload[1] == 0x01 and udp.Payload[2] == 0x00 and udp.Payload[3] == 0x46) or ((udp.DstPort >= 10000 or udp.DstPort == 3478 or udp.DstPort == 5349 or udp.DstPort == 1400 or (udp.DstPort >= 596 and udp.DstPort <= 599)) and udp.PayloadLength >= 20 and udp.Payload[0] == 0x00 and udp.Payload[1] == 0x01 and udp.Payload[4] == 0x21 and udp.Payload[5] == 0x12 and udp.Payload[6] == 0xA4 and udp.Payload[7] == 0x42) or (udp.DstPort >= 49152 and udp.PayloadLength >= 17 and udp.Payload[0] == 0x05 and udp.Payload[1] == 0x00 and udp.Payload[2] == 0xFF and udp.Payload[3] == 0xFF and udp.Payload[4] == 0x00 and udp.Payload[5] == 0xFE))) or (inbound and ((tcp.SrcPort == 443 and (tcp.Syn or tcp.Rst or tcp.Fin or (tcp.PayloadLength >= 6 and tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[5] == 0x02))) or (tcp.SrcPort == 80 and (tcp.Syn or tcp.Rst or tcp.Fin or (tcp.PayloadLength >= 16 and tcp.Payload[0] == 0x48 and tcp.Payload[1] == 0x54 and tcp.Payload[2] == 0x54 and tcp.Payload[3] == 0x50 and tcp.Payload[9] == 0x33))))))",
        )
        .map_err(|_| (ErrorCode::InternalError, "WinDivert filtre derleme hatası.".into()))?;
        let fallback_filter = CString::new(
            "not loopback and ((outbound and (tcp.DstPort == 443 or tcp.DstPort == 80 or udp.DstPort == 53 or tcp.DstPort == 53 or tcp.DstPort == 853 or udp.DstPort == 443 or udp.DstPort == 3478 or udp.DstPort == 5349 or udp.DstPort == 1400 or (udp.DstPort >= 596 and udp.DstPort <= 599))) or (inbound and (tcp.SrcPort == 443 or tcp.SrcPort == 80) and (tcp.Syn or tcp.Rst or tcp.Fin)))",
        )
        .map_err(|_| (ErrorCode::InternalError, "WinDivert yedek filtre derleme hatası.".into()))?;

        let open_with_fallback = |api_ref: &loader::WinDivertApi| -> *mut c_void {
            let mut h = unsafe { (api_ref.open)(kernel_fast_filter.as_ptr(), 0, 0, 0) };
            if loader::WinDivertApi::is_invalid_handle(h) {
                h = unsafe { (api_ref.open)(fallback_filter.as_ptr(), 0, 0, 0) };
            }
            h
        };

        let mut raw_handle = open_with_fallback(&api);
        if loader::WinDivertApi::is_invalid_handle(raw_handle) {
            let os_code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // Auto-heal stale stopped WinDivert SCM service from old GoodbyeDPI/Zapret/moved folder!
            if matches!(os_code, 2 | 3) && cleanup_stale_windivert_service() {
                raw_handle = open_with_fallback(&api);
            }
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
                    format!("WinDivert64.sys sürücüsü başlatılamadı (Windows kod: {os_code}). Ayarlar'dan 'Windows Ağ ve TCP Onarımı' çalıştırın veya bilgisayarı yeniden başlatın."),
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

        // Raise WinDivert kernel packet queue ceilings to eliminate drops under bursty Gigabit traffic
        if let Some(set_param) = api.set_param {
            unsafe {
                let _ = set_param(raw_handle, loader::WINDIVERT_PARAM_QUEUE_LENGTH, 16_384);
                let _ = set_param(raw_handle, loader::WINDIVERT_PARAM_QUEUE_SIZE, 33_554_432);
                let _ = set_param(raw_handle, loader::WINDIVERT_PARAM_QUEUE_TIME, 4_000);
            }
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
        let flows = Arc::clone(&self.flows);
        let raw_handle_addr = raw_handle as usize;

        let jh = std::thread::spawn(move || {
            let raw_handle = raw_handle_addr as *mut c_void;
            let rt = Runtime::new().expect("tokio runtime");

            // Startup probe: race all encrypted DNS upstreams & check live IPv6 reachability
            {
                let dns_init = Arc::clone(&dns);
                rt.spawn(async move {
                    let (_, v6_mode) = tokio::join!(
                        dns_init.probe_fastest_upstream(),
                        probe_ipv6_leak_mode(&NoopProtector, None, Duration::from_millis(1200))
                    );
                    dns_init.set_suppress_aaaa(v6_mode == Ipv6LeakMode::BlockUnprotectedIpv6);
                });
            }

            let send_handle = Arc::new(RwLock::new(raw_handle_addr));
            let dns_sem = Arc::new(tokio::sync::Semaphore::new(64));
            let mut batch_buf = vec![0u8; 65_536 * 8];
            let mut batch_addrs = vec![WinDivertAddress::default(); 16];
            let mut batch_tx: Vec<OutgoingPacket> = Vec::with_capacity(32);
            let mut tx_bytes_buf: Vec<u8> = Vec::with_capacity(65_536);
            let mut tx_addrs_buf: Vec<WinDivertAddress> = Vec::with_capacity(16);
            let mut recv_len = 0u32;
            let mut unexpected_exit = false;

            while !stop_flag.load(Ordering::Relaxed) {
                batch_tx.clear();
                let mut rx_pairs: Vec<(&[u8], WinDivertAddress)> = Vec::new();
                if let Some(recv_ex) = thread_api.recv_ex {
                    let mut addr_len_bytes =
                        (batch_addrs.len() * std::mem::size_of::<WinDivertAddress>()) as u32;
                    let ok = unsafe {
                        recv_ex(
                            raw_handle,
                            batch_buf.as_mut_ptr().cast(),
                            batch_buf.len() as u32,
                            &mut recv_len,
                            0,
                            batch_addrs.as_mut_ptr(),
                            &mut addr_len_bytes,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 {
                        if !stop_flag.load(Ordering::SeqCst) {
                            unexpected_exit = true;
                        }
                        break;
                    }
                    let count = (addr_len_bytes as usize)
                        / std::mem::size_of::<WinDivertAddress>();
                    rx_pairs = unpack_windivert_batch(
                        &batch_buf[..recv_len as usize],
                        &batch_addrs[..count.min(batch_addrs.len())],
                    );
                    if rx_pairs.is_empty() && recv_len > 0 {
                        rx_pairs.push((&batch_buf[..recv_len as usize], batch_addrs[0]));
                    }
                } else {
                    let ok = unsafe {
                        (thread_api.recv)(
                            raw_handle,
                            batch_buf.as_mut_ptr().cast(),
                            65_536,
                            &mut recv_len,
                            &mut batch_addrs[0],
                        )
                    };
                    if ok == 0 {
                        if !stop_flag.load(Ordering::SeqCst) {
                            unexpected_exit = true;
                        }
                        break;
                    }
                    rx_pairs.push((&batch_buf[..recv_len as usize], batch_addrs[0]));
                }

                for (pkt, addr) in rx_pairs {
                    // Handle outbound UDP/53 DNS asynchronously with <50us local fast-path
                    let mut handled_dns = false;
                    if addr.is_outbound() {
                        if let Some(ip) = parse_ip_packet(pkt) {
                            if ip.protocol == IpProtocol::Udp {
                                if let Some(udp) = parse_udp(ip.payload) {
                                    if udp.dst_port == 53 {
                                        let is_local_lan = is_local_lan_ip(ip.dst_ip);
                                        let is_local_name = is_local_lan
                                            && parse_dns_query(udp.payload)
                                                .map(|q| is_local_lan_hostname(&q.qname))
                                                .unwrap_or(false);
                                        if !(portal.is_bypass_active() && is_local_lan) && !is_local_name {
                                            handled_dns = true;
                                            if let Some((resp_opt, _)) = dns.try_resolve_local(udp.payload) {
                                                if let Some(resp_wire) = resp_opt {
                                                    if let Some(reply_pkt) = build_dns_reply_l3(
                                                        ip.src_ip,
                                                        ip.dst_ip,
                                                        udp.src_port,
                                                        udp.dst_port,
                                                        &resp_wire,
                                                    ) {
                                                        let mut reply_addr = addr;
                                                        reply_addr.set_inbound();
                                                        batch_tx.push(OutgoingPacket {
                                                            bytes: reply_pkt,
                                                            addr: reply_addr,
                                                            checksum: ChecksumAction::Recalculate,
                                                        });
                                                    }
                                                }
                                            } else if let Ok(permit) = Arc::clone(&dns_sem).try_acquire_owned() {
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
                                                    let (resp_opt, outcome) =
                                                        dns_c.resolve_with_swr(&query_bytes).await;
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
                                                            reply_addr.mark_checksums_valid(
                                                                dst_ip.is_ipv6(),
                                                                false,
                                                            );
                                                            unsafe {
                                                                let _ = (api_c.calc_checksums)(
                                                                    reply_pkt.as_mut_ptr().cast(),
                                                                    reply_pkt.len() as u32,
                                                                    &mut reply_addr,
                                                                    0,
                                                                );
                                                            }
                                                            if let Ok(guard) = sh_c.read() {
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
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !handled_dns {
                        let processed = process_packet_with_tracker(
                            pkt,
                            addr,
                            &rt,
                            &dns,
                            &adaptive,
                            &calibrator,
                            &flows,
                            &portal,
                        );
                        batch_tx.extend(processed);
                    }
                }

                if batch_tx.is_empty() {
                    continue;
                }

                for out in &mut batch_tx {
                    match out.checksum {
                        ChecksumAction::Passthrough => {}
                        ChecksumAction::Recalculate => unsafe {
                            let _ = (thread_api.calc_checksums)(
                                out.bytes.as_mut_ptr().cast(),
                                out.bytes.len() as u32,
                                &mut out.addr,
                                0,
                            );
                        },
                        ChecksumAction::PreserveBadTcpChecksum => {
                            let is_v6 = out.bytes.first().map(|b| (b >> 4) == 6).unwrap_or(false);
                            out.addr.mark_checksums_valid(is_v6, true);
                        }
                        ChecksumAction::PreserveBadUdpChecksum => {
                            let is_v6 = out.bytes.first().map(|b| (b >> 4) == 6).unwrap_or(false);
                            out.addr.mark_checksums_valid(is_v6, false);
                        }
                    }
                }

                if let Ok(guard) = send_handle.read() {
                    if *guard != 0 {
                        let h = *guard as *mut c_void;
                        if let (Some(send_ex), true) = (thread_api.send_ex, batch_tx.len() > 1) {
                            tx_bytes_buf.clear();
                            tx_addrs_buf.clear();
                            for out in &batch_tx {
                                tx_bytes_buf.extend_from_slice(&out.bytes);
                                tx_addrs_buf.push(out.addr);
                            }
                            let mut send_len = 0u32;
                            let ok = unsafe {
                                send_ex(
                                    h,
                                    tx_bytes_buf.as_ptr().cast(),
                                    tx_bytes_buf.len() as u32,
                                    &mut send_len,
                                    0,
                                    tx_addrs_buf.as_ptr(),
                                    (tx_addrs_buf.len() * std::mem::size_of::<WinDivertAddress>())
                                        as u32,
                                    std::ptr::null_mut(),
                                )
                            };
                            if ok != 0 {
                                continue;
                            }
                        }
                        for out in &mut batch_tx {
                            let mut send_len = 0u32;
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

            if let Ok(mut g) = send_handle.write() {
                *g = 0;
            }
            if let Ok(mut g) = handle_ptr.lock() {
                *g = 0;
            }
            unsafe {
                let _ = (thread_api.close)(raw_handle);
            }
            // Privacy invariant: wipe RAM DNS cache & keep-alive TLS pool cleanly on stop/exit!
            rt.block_on(dns.clear_ephemeral_state());
            calibrator.clear();
            flows.clear();
            flush_windows_dns_cache();
            if unexpected_exit {
                on_state(EngineState::Error(ErrorCode::InternalError));
            } else {
                on_state(EngineState::Inactive);
            }
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
        self.flows.clear();
        flush_windows_dns_cache();
    }
}

impl Drop for WindowsPacketEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Unpacks concatenated L3 IPv4/IPv6 packets returned by `WinDivertRecvEx` along with their
/// parallel `WINDIVERT_ADDRESS` slice, cleanly stopping on malformed lengths.
pub fn unpack_windivert_batch<'a>(
    buf: &'a [u8],
    addrs: &[WinDivertAddress],
) -> Vec<(&'a [u8], WinDivertAddress)> {
    let mut out = Vec::with_capacity(addrs.len());
    let mut off = 0usize;
    for &addr in addrs {
        if off >= buf.len() {
            break;
        }
        let rem = &buf[off..];
        let pkt_len = match rem[0] >> 4 {
            4 if rem.len() >= 20 => u16::from_be_bytes([rem[2], rem[3]]) as usize,
            6 if rem.len() >= 40 => 40 + u16::from_be_bytes([rem[4], rem[5]]) as usize,
            _ => break,
        };
        if pkt_len == 0 || off + pkt_len > buf.len() {
            break;
        }
        out.push((&buf[off..off + pkt_len], addr));
        off += pkt_len;
    }
    out
}

/// Pure, cross-platform testable WinDivert packet processor with full FlowTracker feedback,
/// passive DPI RST dropping, BTK HTTP 302 redirect dropping, and real Turkey DPI escalation.
#[allow(clippy::too_many_arguments)]
pub fn process_packet_with_tracker(
    pkt: &[u8],
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    flows: &FlowTracker,
    portal: &CaptivePortalMonitor,
) -> Vec<OutgoingPacket> {
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![OutgoingPacket {
            bytes: pkt.to_vec(),
            addr,
            checksum: ChecksumAction::Passthrough,
        }];
    };

    if !addr.is_outbound() {
        return process_inbound_inner(pkt, &ip, addr, adaptive, calibrator, flows);
    }

    process_outbound_inner(pkt, &ip, addr, rt, dns, adaptive, calibrator, flows, portal)
}

/// Convenience wrapper for callers without an external FlowTracker.
pub fn process_packet(
    pkt: &[u8],
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    portal: &CaptivePortalMonitor,
) -> Vec<OutgoingPacket> {
    let flows = FlowTracker::default();
    process_packet_with_tracker(pkt, addr, rt, dns, adaptive, calibrator, &flows, portal)
}

/// Convenience wrapper for outbound-only tests.
pub fn process_outbound_packet(
    pkt: &[u8],
    addr: WinDivertAddress,
    rt: &Runtime,
    dns: &Arc<DnsEngine>,
    adaptive: &Arc<AdaptiveController>,
) -> Vec<OutgoingPacket> {
    let calibrator = TtlCalibrator::default();
    let flows = FlowTracker::default();
    let portal = CaptivePortalMonitor::new();
    let Some(ip) = parse_ip_packet(pkt) else {
        return vec![OutgoingPacket {
            bytes: pkt.to_vec(),
            addr,
            checksum: ChecksumAction::Passthrough,
        }];
    };
    process_outbound_inner(pkt, &ip, addr, rt, dns, adaptive, &calibrator, &flows, &portal)
}

fn process_inbound_inner(
    pkt: &[u8],
    ip: &yolac_dpi::ParsedIpPacket<'_>,
    addr: WinDivertAddress,
    adaptive: &Arc<AdaptiveController>,
    calibrator: &TtlCalibrator,
    flows: &FlowTracker,
) -> Vec<OutgoingPacket> {
    if ip.protocol == IpProtocol::Tcp {
        if let Some(tcp) = parse_tcp(ip.payload) {
            let local_port = tcp.dst_port;
            let remote_port = tcp.src_port;

            // 1. Observe inbound SYN-ACK TTL/HopLimit for dynamic hop calibration & forged-RST baseline
            if (tcp.flags & (yolac_dpi::ParsedTcp::SYN | yolac_dpi::ParsedTcp::ACK))
                == (yolac_dpi::ParsedTcp::SYN | yolac_dpi::ParsedTcp::ACK)
            {
                calibrator.observe_syn_ack(ip.src_ip, ip.ttl);
                flows.observe_syn_ack(local_port, ip.src_ip, remote_port, ip.ttl);
            }

            // 2. Inspect inbound TCP RST: ONLY drop forged passive-DPI RSTs for flows actively
            //    in handshake (`has_pending_flow`) so legitimate server resets on idle/closed sockets
            //    never stall Windows clients!
            if (tcp.flags & yolac_dpi::ParsedTcp::RST) != 0 {
                let in_handshake = flows.has_pending_flow(local_port, ip.src_ip, remote_port);
                let expected_ttl = flows.syn_ack_ttl(local_port, ip.src_ip, remote_port);
                let forged = in_handshake && is_forged_passive_dpi_rst(pkt, expected_ttl);
                if forged {
                    return vec![];
                }
                if let Some((dst, sni, failed_strategy, used_forge)) =
                    flows.on_inbound_reset_or_fin(local_port, ip.src_ip, remote_port, false)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), false);
                    } else {
                        adaptive.report_outcome(
                            dst,
                            sni.as_deref(),
                            failed_strategy,
                            FlowOutcome::ResetOrEofDuringHandshake,
                        );
                    }
                }
            } else if (tcp.flags & yolac_dpi::ParsedTcp::FIN) != 0 {
                if let Some((dst, sni, failed_strategy, used_forge)) =
                    flows.on_inbound_reset_or_fin(local_port, ip.src_ip, remote_port, false)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), false);
                    } else {
                        adaptive.report_outcome(
                            dst,
                            sni.as_deref(),
                            failed_strategy,
                            FlowOutcome::ResetOrEofDuringHandshake,
                        );
                    }
                }
            } else if remote_port == 443
                && tcp.payload.len() >= 6
                && tcp.payload[0] == 0x16
                && tcp.payload[1] == 0x03
                && tcp.payload[5] == 0x02
            {
                // 3. Inbound TLS ServerHello -> confirms genuine handshake success (zero outbound data capture!)
                if let Some((dst, sni, verified_strategy, used_forge)) =
                    flows.on_inbound_server_hello(local_port, ip.src_ip, remote_port)
                {
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), true);
                    } else {
                        adaptive.report_outcome(
                            dst,
                            sni.as_deref(),
                            verified_strategy,
                            FlowOutcome::Success,
                        );
                    }
                }
            } else if remote_port == 80 && !tcp.payload.is_empty() && is_forged_dpi_http_redirect(pkt) {
                // 4. Drop forged plaintext BTK / ISP HTTP redirect!
                return vec![];
            }
        }
    }

    vec![OutgoingPacket {
        bytes: pkt.to_vec(),
        addr,
        checksum: ChecksumAction::Passthrough,
    }]
}

#[inline]
fn passthrough_pkt(bytes: Vec<u8>, addr: WinDivertAddress) -> OutgoingPacket {
    OutgoingPacket {
        bytes,
        addr,
        checksum: ChecksumAction::Passthrough,
    }
}

#[inline]
fn recalc_pkt(bytes: Vec<u8>, addr: WinDivertAddress) -> OutgoingPacket {
    OutgoingPacket {
        bytes,
        addr,
        checksum: ChecksumAction::Recalculate,
    }
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
    flows: &FlowTracker,
    portal: &CaptivePortalMonitor,
) -> Vec<OutgoingPacket> {
    let passthrough = passthrough_pkt;
    let recalc = recalc_pkt;

    match ip.protocol {
        IpProtocol::Udp => {
            let Some(udp) = parse_udp(ip.payload) else {
                return vec![passthrough(pkt.to_vec(), addr)];
            };

            // 1. Intercept ALL UDP/53 DNS queries locally via DoH/DoT + blocklist -> zero ISP DNS leak
            //    (except direct local LAN hostnames like .local/.lan/single-label or active Captive Portal)
            if udp.dst_port == 53 {
                let qname = parse_dns_query(udp.payload).map(|q| q.qname);
                if is_local_lan_ip(ip.dst_ip)
                    && (portal.is_bypass_active()
                        || qname.as_deref().map(is_local_lan_hostname).unwrap_or(false))
                {
                    return vec![passthrough(pkt.to_vec(), addr)];
                }
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

            // 2. QUIC UDP/443 policy (BlockFallbackToTcp OR selective QuicPolicy::DesyncFragment)
            if udp.dst_port == 443 && !is_local_lan_ip(ip.dst_ip) {
                let policy = adaptive.effective_quic_policy(udp.dst_port);
                if policy == QuicPolicy::BlockFallbackToTcp
                    && detect_quic_initial(udp.payload).is_some()
                {
                    return vec![];
                }
                if policy == QuicPolicy::DesyncFragment
                    && detect_quic_initial(udp.payload).is_some()
                {
                    let fake_ttl = calibrator
                        .estimated_hops(ip.dst_ip)
                        .map(|h| (h / 2).clamp(2, 5))
                        .unwrap_or(3);
                    if let Some(decoys) = build_quic_desync_decoys(pkt, fake_ttl) {
                        let mut burst = Vec::with_capacity(decoys.len() + 1);
                        for d in decoys {
                            if d.preserve_bad_udp_checksum {
                                let mut bad_addr = addr;
                                bad_addr.mark_checksums_valid(ip.version == 6, false);
                                burst.push(OutgoingPacket {
                                    bytes: d.bytes,
                                    addr: bad_addr,
                                    checksum: ChecksumAction::PreserveBadUdpChecksum,
                                });
                            } else {
                                burst.push(recalc(d.bytes, addr));
                            }
                        }
                        burst.push(passthrough(pkt.to_vec(), addr));
                        return burst;
                    }
                }
            }

            // 3. Single-shot UDP desync for Discord Voice STUN/IP-Discovery, WhatsApp/Telegram STUN & Roblox RakNet
            if !is_local_lan_ip(ip.dst_ip)
                && flows.should_desync_udp_flow(udp.src_port, ip.dst_ip, udp.dst_port)
            {
                if let Some(kind) = detect_udp_desync_target(udp.payload, udp.dst_port) {
                    let match_proto = match kind {
                        yolac_dpi::UdpDesyncKind::RobloxRakNet => MatchProtocol::UdpRakNet,
                        _ => MatchProtocol::UdpStun,
                    };
                    let fake_ttl = adaptive
                        .effective_udp_desync(match_proto, udp.dst_port)
                        .map(|(t, _)| t)
                        .unwrap_or(3);
                    if let Some(decoys) = build_udp_desync_decoys(pkt, fake_ttl) {
                        let mut burst = Vec::with_capacity(decoys.len() + 1);
                        for d in decoys {
                            if d.preserve_bad_udp_checksum {
                                let mut bad_addr = addr;
                                bad_addr.mark_checksums_valid(ip.version == 6, false);
                                burst.push(OutgoingPacket {
                                    bytes: d.bytes,
                                    addr: bad_addr,
                                    checksum: ChecksumAction::PreserveBadUdpChecksum,
                                });
                            } else {
                                burst.push(recalc(d.bytes, addr));
                            }
                        }
                        burst.push(passthrough(pkt.to_vec(), addr));
                        return burst;
                    }
                }
            }
        }
        IpProtocol::Tcp => {
            let Some(tcp) = parse_tcp(ip.payload) else {
                return vec![passthrough(pkt.to_vec(), addr)];
            };

            // Prevent plaintext TCP/53 DNS bypass (allow local LAN during active Captive Portal)
            if tcp.dst_port == 53 {
                if portal.is_bypass_active() && is_local_lan_ip(ip.dst_ip) {
                    return vec![passthrough(pkt.to_vec(), addr)];
                }
                return vec![];
            }

            // Let active/bootstrap DoH/DoT upstreams pass straight through without double-fragmentation,
            // and block rogue unauthorized DoT (port 853) leaks to third-party IPs.
            if dns.is_active_upstream_ip(ip.dst_ip) || is_bootstrap_dns_ip(ip.dst_ip) {
                return vec![passthrough(pkt.to_vec(), addr)];
            }
            if tcp.dst_port == 853 {
                if portal.is_bypass_active() && is_local_lan_ip(ip.dst_ip) {
                    return vec![passthrough(pkt.to_vec(), addr)];
                }
                return vec![];
            }

            let dst = SocketAddr::new(ip.dst_ip, tcp.dst_port);

            // Apply aggressive SYN MSS clamp when escalated OR requested by active Forge rule
            if tcp.is_syn_only()
                && (tcp.dst_port == 443 || tcp.dst_port == 80)
                && !is_local_lan_ip(ip.dst_ip)
            {
                let mss_clamp = adaptive
                    .select_raw_forge_plan(MatchProtocol::Tls, tcp.dst_port, None, 0, false, 0)
                    .and_then(|p| p.syn_mss_clamp)
                    .or_else(|| {
                        (adaptive.select_strategy(dst, None) == DpiStrategy::TurkeyDesyncAggressive)
                            .then_some(536)
                    });
                if let Some(mss) = mss_clamp {
                    if let Some(clamped) = clamp_syn_mss(pkt, mss) {
                        return vec![recalc(clamped, addr)];
                    }
                }
            }

            if !tcp.payload.is_empty() {
                if tcp.dst_port == 443 {
                    if let Some(pq_res) = flows.advance_pq_stream(
                        tcp.src_port,
                        dst,
                        tcp.seq,
                        tcp.payload,
                    ) {
                        match pq_res {
                            PqAdvance::Waiting => return vec![],
                            PqAdvance::Ready {
                                template_pkt,
                                payload: full_payload,
                            } => {
                                if let (Some(tip), Some(ch)) = (
                                    parse_ip_packet(&template_pkt),
                                    parse_client_hello(&full_payload),
                                ) {
                                    if let Some(ttcp) = parse_tcp(tip.payload) {
                                        if let Some(out) = desync_tls_hello(
                                            &template_pkt,
                                            tip.version == 6,
                                            tip.dst_ip,
                                            ttcp.src_port,
                                            dst,
                                            ttcp.seq,
                                            addr,
                                            &full_payload,
                                            ch,
                                            adaptive,
                                            calibrator,
                                            flows,
                                            true,
                                        ) {
                                            return out;
                                        }
                                    }
                                }
                                return vec![passthrough(pkt.to_vec(), addr)];
                            }
                        }
                    }

                    if let Some(expected_len) = inspect_client_hello_needs_reassembly(tcp.payload) {
                        let missing_sni = parse_client_hello_prefix(tcp.payload)
                            .map(|c| c.sni.is_none())
                            .unwrap_or(true);
                        if missing_sni
                            && flows.begin_pq_stream(
                                tcp.src_port,
                                dst,
                                tcp.seq,
                                expected_len,
                                pkt,
                                tcp.payload,
                            )
                        {
                            return vec![];
                        }
                    }
                }

                if let Some(ch) = parse_client_hello_prefix(tcp.payload) {
                    if let Some(out) = desync_tls_hello(
                        pkt,
                        ip.version == 6,
                        ip.dst_ip,
                        tcp.src_port,
                        dst,
                        tcp.seq,
                        addr,
                        tcp.payload,
                        ch,
                        adaptive,
                        calibrator,
                        flows,
                        false,
                    ) {
                        return out;
                    }
                } else if let Some(http_info) = parse_http_host(tcp.payload) {
                    let is_sensitive = is_sensitive_unblocked_domain(&http_info.host)
                        || yolac_net::is_captive_portal_probe_domain(&http_info.host);
                    let host_mid = http_info.host_range.0
                        + (http_info.host_range.1 - http_info.host_range.0) / 2;
                    if let Some(fplan) = adaptive.select_raw_forge_plan(
                        MatchProtocol::Http,
                        tcp.dst_port,
                        Some(&http_info.host),
                        tcp.payload.len(),
                        is_sensitive,
                        0,
                    ) {
                        if !fplan.passthrough {
                            if let Some(desync) = execute_raw_forge_tcp(
                                pkt,
                                host_mid,
                                Some(host_mid),
                                true,
                                &fplan,
                                calibrator,
                                ip.dst_ip,
                            ) {
                                return desync
                                    .into_iter()
                                    .map(|d| {
                                        if d.preserve_bad_tcp_checksum {
                                            let mut bad_addr = addr;
                                            bad_addr.mark_checksums_valid(ip.version == 6, true);
                                            OutgoingPacket {
                                                bytes: d.bytes,
                                                addr: bad_addr,
                                                checksum: ChecksumAction::PreserveBadTcpChecksum,
                                            }
                                        } else {
                                            recalc(d.bytes, addr)
                                        }
                                    })
                                    .collect();
                            }
                        }
                        return vec![passthrough(pkt.to_vec(), addr)];
                    }
                    let http_strategy = if is_sensitive {
                        adaptive.select_strategy_with_default(
                            dst,
                            Some(&http_info.host),
                            DpiStrategy::Passthrough,
                        )
                    } else {
                        adaptive.select_strategy(dst, Some(&http_info.host))
                    };
                    if http_strategy == DpiStrategy::Passthrough {
                        return vec![passthrough(pkt.to_vec(), addr)];
                    }
                    // Plaintext HTTP port 80: mix Host case + benign fake HTTP decoy + reverse-frag `-f 2` split
                    let source_pkt = if let Some(evaded) =
                        evade_http_request(tcp.payload, HttpEvasionOptions::default())
                    {
                        if evaded.len() == tcp.payload.len() {
                            rebuild_tcp_payload_packet(ip, &tcp, &evaded)
                                .unwrap_or_else(|| pkt.to_vec())
                        } else {
                            pkt.to_vec()
                        }
                    } else {
                        pkt.to_vec()
                    };
                    let split_mid = plan_tcp_splits(tcp.payload)
                        .map(|s| s.split_at)
                        .unwrap_or(2);
                    let fake_http = build_benign_fake_http_request("www.iana.org");
                    let fakes = [
                        FakePacketMode::LowTtlWrongSeq(3),
                        FakePacketMode::BadChecksumWrongSeq,
                    ];
                    if let Some(desync) = build_turkey_desync_packets(
                        &source_pkt,
                        &[2, split_mid],
                        &fakes,
                        &fake_http,
                        true,
                    ) {
                        return desync
                            .into_iter()
                            .map(|d| {
                                if d.preserve_bad_tcp_checksum {
                                    let mut bad_addr = addr;
                                    bad_addr.mark_checksums_valid(ip.version == 6, true);
                                    OutgoingPacket {
                                        bytes: d.bytes,
                                        addr: bad_addr,
                                        checksum: ChecksumAction::PreserveBadTcpChecksum,
                                    }
                                } else {
                                    recalc(d.bytes, addr)
                                }
                            })
                            .collect();
                    }
                    return vec![recalc(source_pkt, addr)];
                } else if let Some((sni, verified_strategy, used_forge)) =
                    flows.on_outbound_followup(tcp.src_port, dst, tcp.seq)
                {
                    // Client moved past full ClientHello (`seq >= ch_seq_end`) -> GENUINE handshake success!
                    if used_forge {
                        adaptive.report_forge_outcome(dst, sni.as_deref(), true);
                    } else {
                        adaptive.report_outcome(dst, sni.as_deref(), verified_strategy, FlowOutcome::Success);
                    }
                }
            }
        }
        _ => {}
    }

    vec![passthrough(pkt.to_vec(), addr)]
}

#[allow(clippy::too_many_arguments)]
fn desync_tls_hello(
    base_pkt: &[u8],
    is_v6: bool,
    dst_ip: IpAddr,
    tcp_src_port: u16,
    dst: SocketAddr,
    tcp_seq: u32,
    addr: WinDivertAddress,
    ch_payload: &[u8],
    ch: yolac_dpi::ClientHelloInfo,
    adaptive: &AdaptiveController,
    calibrator: &TtlCalibrator,
    flows: &FlowTracker,
    is_reassembled: bool,
) -> Option<Vec<OutgoingPacket>> {
    let sni_opt = ch.sni.as_deref();
    let is_sensitive = sni_opt.map(is_sensitive_unblocked_domain).unwrap_or(false);
    let mut forge_plan = adaptive.select_raw_forge_plan(
        MatchProtocol::Tls,
        dst.port(),
        sni_opt,
        ch_payload.len(),
        is_sensitive,
        0,
    );
    let mut strategy = if is_sensitive {
        adaptive.select_strategy_with_default(dst, sni_opt, DpiStrategy::Passthrough)
    } else {
        adaptive.select_strategy(dst, sni_opt)
    };

    if let Some((failed_strategy, prev_forge, retry_n)) = flows.record_client_hello(
        tcp_src_port,
        dst,
        ch.sni.clone(),
        (tcp_seq, ch.record_total_len.max(ch_payload.len())),
        strategy,
        forge_plan.is_some(),
    ) {
        if prev_forge {
            adaptive.report_forge_outcome(dst, sni_opt, false);
            forge_plan = adaptive.select_raw_forge_plan(
                MatchProtocol::Tls,
                dst.port(),
                sni_opt,
                ch_payload.len(),
                is_sensitive,
                retry_n,
            );
        } else {
            adaptive.report_outcome(dst, sni_opt, failed_strategy, FlowOutcome::HandshakeTimeout);
            strategy = adaptive.select_strategy(dst, sni_opt);
        }
        flows.update_pending_strategy(tcp_src_port, dst, strategy, forge_plan.is_some());
    }

    let sni_mid = if let Some((s, e)) = ch.sni_range {
        (s + (e.saturating_sub(s)) / 2).clamp(1, ch_payload.len().saturating_sub(1).max(1))
    } else {
        (ch_payload.len() / 2).max(2)
    };

    let emit_desync = |desync: Vec<yolac_dpi::DesyncPacket>| -> Vec<OutgoingPacket> {
        desync
            .into_iter()
            .map(|d| {
                if d.preserve_bad_tcp_checksum {
                    let mut bad_addr = addr;
                    bad_addr.mark_checksums_valid(is_v6, true);
                    OutgoingPacket {
                        bytes: d.bytes,
                        addr: bad_addr,
                        checksum: ChecksumAction::PreserveBadTcpChecksum,
                    }
                } else {
                    recalc_pkt(d.bytes, addr)
                }
            })
            .collect()
    };

    let build_segments = |split_points: &[usize],
                          fakes: &[FakePacketMode],
                          reverse: bool|
     -> Option<Vec<yolac_dpi::DesyncPacket>> {
        let decoy_buf;
        let decoy: &[u8] = if fakes.is_empty() {
            &[]
        } else {
            decoy_buf = build_benign_fake_client_hello("www.iana.org");
            &decoy_buf
        };
        if is_reassembled {
            build_reassembled_desync_packets(
                base_pkt,
                ch_payload,
                split_points,
                fakes,
                decoy,
                reverse,
                1380,
            )
        } else {
            build_turkey_desync_packets(base_pkt, split_points, fakes, decoy, reverse)
        }
    };

    if let Some(ref fplan) = forge_plan {
        if !fplan.passthrough {
            if !is_reassembled {
                if let Some(desync) = execute_raw_forge_tcp(
                    base_pkt,
                    sni_mid,
                    None,
                    false,
                    fplan,
                    calibrator,
                    dst_ip,
                ) {
                    return Some(emit_desync(desync));
                }
            } else if let Some(desync) = build_segments(&[2, sni_mid], &[FakePacketMode::BadChecksum], true) {
                return Some(emit_desync(desync));
            }
        }
        return (!is_reassembled).then(|| vec![passthrough_pkt(base_pkt.to_vec(), addr)]);
    }

    match strategy {
        DpiStrategy::Passthrough => {
            if is_reassembled {
                return build_segments(&[ch_payload.len().min(1380)], &[], false).map(emit_desync);
            }
            None
        }
        DpiStrategy::TurkeyDesyncAuto => {
            let safe_ttl = calibrator
                .estimated_hops(dst_ip)
                .map(|h| (h / 2).clamp(2, 5))
                .unwrap_or(3);
            let fakes = [
                FakePacketMode::BadChecksum,
                FakePacketMode::LowTtlWrongSeq(safe_ttl),
                FakePacketMode::BadChecksumWrongSeq,
            ];
            build_segments(&[2, sni_mid], &fakes, true).map(emit_desync)
        }
        DpiStrategy::TurkeyDesyncSuperonline => {
            let fakes = [
                FakePacketMode::LowTtlWrongSeq(2),
                FakePacketMode::LowTtlWrongSeq(5),
                FakePacketMode::BadChecksum,
                FakePacketMode::BadChecksumWrongSeq,
                FakePacketMode::BadTcpTimestamp,
            ];
            build_segments(&[1, sni_mid], &fakes, true).map(emit_desync)
        }
        DpiStrategy::TurkeyDesyncAggressive => {
            let cal_mode = calibrator.recommended_fake_mode(dst_ip, 3);
            let fakes = [
                cal_mode,
                FakePacketMode::LowTtlWrongSeq(6),
                FakePacketMode::BadChecksum,
                FakePacketMode::BadChecksumWrongSeq,
                FakePacketMode::BadTcpTimestamp,
            ];
            build_segments(&[1, 2, sni_mid], &fakes, true).map(emit_desync)
        }
        DpiStrategy::TlsRecordSplit
        | DpiStrategy::TcpSniSplit
        | DpiStrategy::TlsAndTcpSplit
        | DpiStrategy::TlsMultiRecordAndTcpSplit
        | DpiStrategy::TcpOobAndTlsSplit
        | DpiStrategy::TlsSmallChunks => {
            if is_reassembled {
                build_segments(&[sni_mid], &[], false).map(emit_desync)
            } else {
                segment_tcp_packet(base_pkt, sni_mid)
                    .map(|(p1, p2)| vec![recalc_pkt(p1, addr), recalc_pkt(p2, addr)])
            }
        }
        DpiStrategy::RawDisorder => {
            if is_reassembled {
                build_segments(&[sni_mid], &[], true).map(emit_desync)
            } else {
                build_disorder_and_fake_packets(base_pkt, sni_mid, None)
                    .map(|plan| plan.packets.into_iter().map(|p| recalc_pkt(p, addr)).collect())
            }
        }
        DpiStrategy::RawFakeTtl { ttl } => {
            let mode = calibrator.recommended_fake_mode(dst_ip, ttl);
            build_segments(&[sni_mid], &[mode], true).map(emit_desync)
        }
        DpiStrategy::RawBadChecksum => {
            build_segments(&[sni_mid], &[FakePacketMode::BadChecksum], true).map(emit_desync)
        }
    }
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
    use yolac_dpi::{
        build_ipv4_udp_packet, ipv4_header_checksum, parse_client_hello, tcp_checksum_ipv4,
        ParsedTcp, PlatformCapabilities,
    };

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
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
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
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
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
    fn default_windows_config_blocks_quic_udp_443_without_manual_trigger() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let mut quic = vec![0u8; 1200];
        quic[0] = 0xC3;
        quic[1..5].copy_from_slice(&1u32.to_be_bytes());
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(128, 116, 114, 3), // roblox edge IP
            55004,
            443,
            64,
            &quic,
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        assert!(out.is_empty(), "Windows default must block QUIC UDP/443 for TCP fallback");
    }

    #[test]
    fn turkey_desync_auto_emits_valid_benign_fakes_and_reassembles_identically_at_server() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let ch = sample_tls_client_hello("www.roblox.com");
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(128, 116, 114, 3);
        let orig_seq = 50_000u32;
        let orig_ack = 90_000u32;
        let pkt = build_ipv4_tcp_packet(
            src,
            dst,
            55002,
            443,
            orig_seq,
            orig_ack,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &ch,
        );
        let out = process_outbound_packet(&pkt, WinDivertAddress::default(), &rt, &dns, &adaptive);
        // 3 valid benign decoys (BadChecksum, LowTtlWrongSeq(3), BadChecksumWrongSeq) + 3 disordered real segments = 6 packets
        assert_eq!(out.len(), 6);

        // Decoy 0: exact-seq BadChecksum with PreserveBadTcpChecksum flag + valid benign www.iana.org TLS ClientHello!
        assert_eq!(out[0].checksum, ChecksumAction::PreserveBadTcpChecksum);
        assert_ne!(out[0].addr.layer_flags & (1 << 22), 0); // TCPChecksum valid bit stops NIC overwrite
        let d0_ip = parse_ip_packet(&out[0].bytes).unwrap();
        let d0_tcp = parse_tcp(d0_ip.payload).unwrap();
        assert_eq!(d0_tcp.seq, orig_seq);
        assert_eq!(
            parse_client_hello(d0_tcp.payload).and_then(|c| c.sni).as_deref(),
            Some("www.iana.org")
        );

        // Decoy 1: LowTtl(3) + WrongSeq with valid checksum (passes home NAT routers!)
        let d1_ip = parse_ip_packet(&out[1].bytes).unwrap();
        let d1_tcp = parse_tcp(d1_ip.payload).unwrap();
        assert_eq!(d1_ip.ttl, 3);
        assert_eq!(d1_tcp.seq, orig_seq.wrapping_sub(10_000));

        // Decoy 2: BadChecksum + WrongSeq
        assert_eq!(out[2].checksum, ChecksumAction::PreserveBadTcpChecksum);

        // Real segments (indices 3, 4, 5): sent out-of-order (seg[1], seg[2], seg[0]=2 bytes!)
        // Simulate real server TCP reassembly by sorting real valid-checksum packets by seq:
        let mut real_segs: Vec<(u32, Vec<u8>)> = Vec::new();
        for seg in &out[3..] {
            assert_eq!(seg.checksum, ChecksumAction::Recalculate);
            let ip = parse_ip_packet(&seg.bytes).unwrap();
            let tcp = parse_tcp(ip.payload).unwrap();
            assert_eq!(ipv4_header_checksum(&seg.bytes[0..20]), u16::from_be_bytes([seg.bytes[10], seg.bytes[11]]));
            assert_eq!(tcp_checksum_ipv4(src, dst, ip.payload), u16::from_be_bytes([ip.payload[16], ip.payload[17]]));
            real_segs.push((tcp.seq, tcp.payload.to_vec()));
        }
        // First transmitted real segment starts at orig_seq + 2 (reverse-frag!), last is orig_seq (2 bytes!)
        assert_eq!(real_segs[0].0, orig_seq + 2);
        assert_eq!(real_segs[2].0, orig_seq);
        assert_eq!(real_segs[2].1.len(), 2);

        real_segs.sort_by_key(|(seq, _)| *seq);
        let reassembled: Vec<u8> = real_segs.into_iter().flat_map(|(_, p)| p).collect();
        assert_eq!(reassembled, ch, "Destination server must reassemble exact byte-identical ClientHello");
    }

    #[test]
    fn drops_passive_dpi_forged_rst_and_escalates_on_active_dpi_rst_and_retransmit() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();
        let portal = CaptivePortalMonitor::new();

        let client_ip = Ipv4Addr::new(192, 168, 1, 10);
        let server_ip = Ipv4Addr::new(66, 254, 114, 41);
        let dst = SocketAddr::new(IpAddr::V4(server_ip), 443);

        // 1. Real server SYN-ACK arrives with TTL=54
        let syn_ack = build_ipv4_tcp_packet(
            server_ip,
            client_ip,
            443,
            56000,
            9000,
            1000,
            ParsedTcp::SYN | ParsedTcp::ACK,
            65535,
            54,
            42,
            &[],
            &[],
        );
        let mut in_addr = WinDivertAddress::default();
        in_addr.set_inbound();
        let r_syn = process_packet_with_tracker(&syn_ack, in_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(r_syn.len(), 1);

        // 2. Client sends ClientHello under Stage 1 (TurkeyDesyncAuto)
        let ch = sample_tls_client_hello("www.pornhub.com");
        let ch_pkt = build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            56000,
            443,
            1000,
            9001,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            10,
            &[],
            &ch,
        );
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();
        let out1 = process_packet_with_tracker(&ch_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(out1.len(), 6); // Stage 1: 3 server-safe decoys (BadChecksum, LowTtlWrongSeq(5), BadChecksumWrongSeq) + 3 real segments
        assert_eq!(out1[0].checksum, ChecksumAction::PreserveBadTcpChecksum);
        assert_eq!(parse_ip_packet(&out1[1].bytes).unwrap().ttl, 5); // Calibrated from SYN-ACK TTL=54 (10 hops -> 5)
        assert_eq!(adaptive.select_strategy(dst, Some("www.pornhub.com")), DpiStrategy::TurkeyDesyncAuto);

        // 3. Passive DPI injects forged RST with IP.ID=0 and TTL=60 (diff 6 from SYN-ACK TTL 54) -> MUST BE DROPPED!
        let forged_rst = build_ipv4_tcp_packet(
            server_ip,
            client_ip,
            443,
            56000,
            9001,
            1000,
            ParsedTcp::RST | ParsedTcp::ACK,
            0,
            60,
            0,
            &[],
            &[],
        );
        let r_forged = process_packet_with_tracker(&forged_rst, in_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert!(r_forged.is_empty(), "Forged passive DPI RST must be dropped!");

        // 4. Active inline DPI sends matching-TTL RST -> triggers immediate SNI-scoped escalation to Stage 2
        //    WITHOUT contaminating unrelated sites hosted on the exact same CDN IP!
        let active_rst = build_ipv4_tcp_packet(
            server_ip,
            client_ip,
            443,
            56000,
            9001,
            1000,
            ParsedTcp::RST,
            0,
            54,
            555,
            &[],
            &[],
        );
        let _ = process_packet_with_tracker(&active_rst, in_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(
            adaptive.select_strategy(dst, Some("www.pornhub.com")),
            DpiStrategy::TurkeyDesyncSuperonline,
            "Active DPI RST must immediately escalate to TurkeyDesyncSuperonline!"
        );
        assert_eq!(
            adaptive.select_strategy(dst, Some("unrelated-cdn-site.org")),
            DpiStrategy::TurkeyDesyncAuto,
            "SNI-scoped escalation must NEVER pollute unrelated sites sharing the same CDN IP!"
        );

        // 5. Silent blackhole retransmission on a new flow escalates Stage 2 -> Stage 3 automatically!
        let ch_pkt2 = build_ipv4_tcp_packet(
            client_ip,
            server_ip,
            56001,
            443,
            2000,
            8001,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            11,
            &[],
            &ch,
        );
        let out_s2 = process_packet_with_tracker(&ch_pkt2, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(out_s2.len(), 7); // Stage 2: 4 decoys + 3 real segments
        std::thread::sleep(Duration::from_millis(50));
        let out_retrans = process_packet_with_tracker(&ch_pkt2, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(adaptive.select_strategy(dst, Some("www.pornhub.com")), DpiStrategy::TurkeyDesyncAggressive);
        assert_eq!(out_retrans.len(), 8); // Stage 3: 4 decoys + 4 real segments
    }

    #[test]
    fn drops_forged_btk_http_302_redirect_and_passes_mullvad_bootstrap() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();
        let portal = CaptivePortalMonitor::new();

        let btk_resp = b"HTTP/1.1 302 Found\r\nLocation: http://195.175.254.2/engelli\r\nConnection: close\r\n\r\n";
        let redirect_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(192, 168, 1, 10),
            80,
            56050,
            9001,
            1001,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            55,
            0,
            &[],
            btk_resp,
        );
        let mut in_addr = WinDivertAddress::default();
        in_addr.set_inbound();
        let res = process_packet_with_tracker(&redirect_pkt, in_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert!(res.is_empty(), "Forged BTK HTTP 302 redirect must be dropped!");

        // Mullvad DoH/DoT bootstrap IP passes through unmodified
        let ch = sample_tls_client_hello("dns.mullvad.net");
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
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();
        let m_out = process_outbound_packet(&mullvad_pkt, out_addr, &rt, &dns, &adaptive);
        assert_eq!(m_out.len(), 1);
        assert_eq!(m_out[0].checksum, ChecksumAction::Passthrough);
    }

    #[test]
    fn protects_whatsapp_edevlet_local_dns_and_desyncs_discord_roblox_udp() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();
        let portal = CaptivePortalMonitor::new();
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();

        // 1. WhatsApp TLS media/CDN gets anti-throttling DPI desync (while non-TLS WA\x06 messaging
        //    stays untouched), whereas Turkish e-Devlet/banks start in clean Passthrough!
        let edevlet_ch = sample_tls_client_hello("www.turkiye.gov.tr");
        let edevlet_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(212, 174, 15, 20),
            56100,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &edevlet_ch,
        );
        let edevlet_out = process_packet_with_tracker(&edevlet_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(edevlet_out.len(), 1);
        assert_eq!(edevlet_out[0].checksum, ChecksumAction::Passthrough);

        let wa_media_ch = sample_tls_client_hello("mmg.whatsapp.net");
        let wa_media_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(157, 240, 22, 60),
            56105,
            443,
            1000,
            2000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            2,
            &[],
            &wa_media_ch,
        );
        let wa_out = process_packet_with_tracker(&wa_media_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert!(wa_out.len() > 1, "WhatsApp CDN TLS must get anti-throttling DPI desync");

        // 2. Local LAN .local DNS query to home router passes through directly to local router
        let local_q = build_dns_query(0x4444, "printer.local", QType::A);
        let local_dns_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 1),
            56101,
            53,
            64,
            &local_q,
        );
        let dns_out = process_packet_with_tracker(&local_dns_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(dns_out.len(), 1);
        assert_eq!(dns_out[0].checksum, ChecksumAction::Passthrough);
        assert!(dns_out[0].addr.is_outbound());

        // 3. Roblox RakNet UDP handshake emits 2 decoys (LowTtl + PreserveBadUdpChecksum) + real packet ONCE per flow!
        let mut raknet = vec![0u8; 64];
        raknet[0] = 0x05;
        raknet[1..17].copy_from_slice(&[
            0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
        ]);
        let udp_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(128, 116, 114, 3),
            56102,
            53120,
            64,
            &raknet,
        );
        let first_udp = process_packet_with_tracker(&udp_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(first_udp.len(), 3);
        assert_eq!(parse_ip_packet(&first_udp[0].bytes).unwrap().ttl, 3);
        assert_eq!(first_udp[1].checksum, ChecksumAction::PreserveBadUdpChecksum);
        assert_eq!(first_udp[2].checksum, ChecksumAction::Passthrough);

        // Second packet on same UDP flow passes straight through with ZERO overhead!
        let second_udp = process_packet_with_tracker(&udp_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(second_udp.len(), 1);
        assert_eq!(second_udp[0].checksum, ChecksumAction::Passthrough);
    }

    #[test]
    fn windows_engine_executes_forge_package_without_recompiling() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::Passthrough);
        let pkg = include_bytes!("../../../forge/examples/turkey_balanced.tulpar");
        adaptive
            .load_forge_package_bytes(pkg)
            .expect("valid .tulpar loads on Windows");

        let ch = sample_tls_client_hello("blocked.win-forge.test");
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            56200,
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
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();
        let out = process_outbound_packet(&pkt, out_addr, &rt, &dns, &adaptive);
        assert!(out.len() >= 4, "Forge turkey-balanced must emit decoys+segments on Windows");
    }

    #[test]
    fn unpacks_windivert_batch_packets_cleanly() {
        let p1 = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(1, 1, 1, 1),
            55001,
            443,
            64,
            b"abc",
        );
        let p2 = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(9, 9, 9, 9),
            55002,
            443,
            64,
            b"hello!",
        );
        let mut concat = Vec::new();
        concat.extend_from_slice(&p1);
        concat.extend_from_slice(&p2);
        let mut a1 = WinDivertAddress::default();
        a1.set_outbound();
        let a2 = WinDivertAddress::default();
        let unpacked = unpack_windivert_batch(&concat, &[a1, a2]);
        assert_eq!(unpacked.len(), 2);
        assert_eq!(unpacked[0].0, p1.as_slice());
        assert!(unpacked[0].1.is_outbound());
        assert_eq!(unpacked[1].0, p2.as_slice());
        assert!(!unpacked[1].1.is_outbound());
    }

    #[test]
    fn reassembles_pq_two_segment_client_hello_and_supports_quic_desync_and_853_guard() {
        let (rt, dns, adaptive) = test_runtime_and_engines(DpiStrategy::TurkeyDesyncAuto);
        let calibrator = TtlCalibrator::default();
        let flows = FlowTracker::default();
        let portal = CaptivePortalMonitor::default();
        let mut out_addr = WinDivertAddress::default();
        out_addr.set_outbound();

        // Build ~1700-byte Post-Quantum ClientHello with X25519MLKEM768 dummy key_share BEFORE SNI
        let sni = "pq.discord.com";
        let sni_bytes = sni.as_bytes();
        let ks_len = 1380usize;
        let name_entry_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + name_entry_len;
        let exts_len = 4 + ks_len + 4 + sni_ext_len;
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x33u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts_len as u16).to_be_bytes());
        body.extend_from_slice(&0x0033u16.to_be_bytes());
        body.extend_from_slice(&(ks_len as u16).to_be_bytes());
        body.extend_from_slice(&vec![0x77u8; ks_len]);
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        body.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);
        let hs_len = body.len();
        let mut full_ch = vec![0x16, 0x03, 0x01];
        full_ch.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        full_ch.push(0x01);
        full_ch.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        full_ch.extend_from_slice(&body);

        let split = 1400usize;
        let seg1_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(162, 159, 130, 234),
            56301,
            443,
            10_000,
            5_000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            &full_ch[..split],
        );
        let seg2_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(162, 159, 130, 234),
            56301,
            443,
            10_000 + split as u32,
            5_000,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            2,
            &[],
            &full_ch[split..],
        );

        let r1 = process_packet_with_tracker(&seg1_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert!(r1.is_empty(), "PQ Seg 1 without SNI must be held briefly for Seg 2");

        let r2 = process_packet_with_tracker(&seg2_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert!(r2.len() >= 5, "PQ Seg 2 completion must emit decoys + MTU-safe SNI-split burst");
        for out in &r2 {
            assert!(out.bytes.len() <= 1460, "Reassembled segments must respect MTU ceiling");
        }

        // Verify unauthorized port 853 DoT is dropped while active upstream IP passes
        let dot_rogue = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(198, 51, 100, 53),
            56302,
            853,
            1,
            1,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            &[],
        );
        assert!(process_packet_with_tracker(&dot_rogue, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal).is_empty());

        let dot_trusted = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(1, 1, 1, 1),
            56303,
            853,
            1,
            1,
            ParsedTcp::SYN,
            65535,
            64,
            1,
            &[],
            &[],
        );
        assert_eq!(process_packet_with_tracker(&dot_trusted, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal).len(), 1);

        // Verify QuicPolicy::DesyncFragment emits QUIC decoy burst + passthrough
        adaptive.set_quic_policy(QuicPolicy::DesyncFragment);
        let mut quic_init = vec![0u8; 1200];
        quic_init[0] = 0xC3;
        quic_init[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        let quic_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(162, 159, 130, 234),
            56304,
            443,
            64,
            &quic_init,
        );
        let q_out = process_packet_with_tracker(&quic_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(q_out.len(), 3, "DesyncFragment must emit LowTtl + BadCsum QUIC decoys + real packet");
        assert_eq!(q_out[1].checksum, ChecksumAction::PreserveBadUdpChecksum);

        // Non-QUIC UDP/443 (e.g. WireGuard / TURN / WebRTC) must pass even under BlockFallbackToTcp
        adaptive.set_quic_policy(QuicPolicy::BlockFallbackToTcp);
        let non_quic_udp443 = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(198, 51, 100, 44),
            56305,
            443,
            64,
            &[0x01, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44],
        );
        let nq_out = process_packet_with_tracker(&non_quic_udp443, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(nq_out.len(), 1, "Non-QUIC UDP/443 must never be blackholed");
        assert_eq!(nq_out[0].checksum, ChecksumAction::Passthrough);

        // Captive portal & sensitive HTTP/80 domains must pass unmodified
        let captive_http = b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n";
        let captive_pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(142, 250, 187, 174),
            56306,
            80,
            100,
            200,
            ParsedTcp::ACK | ParsedTcp::PSH,
            65535,
            64,
            1,
            &[],
            captive_http,
        );
        let cap_out = process_packet_with_tracker(&captive_pkt, out_addr, &rt, &dns, &adaptive, &calibrator, &flows, &portal);
        assert_eq!(cap_out.len(), 1);
        assert_eq!(cap_out[0].checksum, ChecksumAction::Passthrough);
    }
}
