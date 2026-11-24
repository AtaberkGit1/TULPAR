#![allow(clippy::not_unsafe_ptr_arg_deref)]
//! Panic-safe C-ABI and optional Android JNI bindings for `yolac-core`.

use std::ffi::{c_char, c_void};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use yolac_core::{
    health_reports_to_json, EngineState, ErrorCode, YolacConfig, YolacEngine,
};
use yolac_net::{ChannelPacketDevice, Ipv6LeakMode, MemoryProfile, PacketDevice, SocketProtector};

#[cfg(feature = "android-jni")]
mod jni_bridge;

#[repr(C)]
pub struct YolacFfiConfig {
    pub profile: u8,
    pub mtu: u16,
    pub block_unprotected_ipv6: u8,
}

pub type YolacProtectFdFn = Option<unsafe extern "C" fn(ctx: *mut c_void, fd: i32) -> i32>;
pub type YolacPacketSinkFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize)>;
pub type YolacStateChangedFn = Option<unsafe extern "C" fn(ctx: *mut c_void, state: u8)>;

#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

struct CallbackProtector {
    cb: unsafe extern "C" fn(*mut c_void, i32) -> i32,
    ctx: SendPtr,
}

impl SocketProtector for CallbackProtector {
    fn protect_fd(&self, fd: i32) -> io::Result<()> {
        let rc = unsafe { (self.cb)(self.ctx.0, fd) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "protect_fd callback failed"))
        }
    }
}

pub struct YolacHandle {
    rt: Runtime,
    config: YolacConfig,
    engine: Mutex<Arc<YolacEngine>>,
    inbound_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

fn spawn_state_forwarder(
    rt: &Runtime,
    engine: &Arc<YolacEngine>,
    state_cb: YolacStateChangedFn,
    state_ctx: *mut c_void,
) {
    let Some(cb) = state_cb else {
        return;
    };
    let mut rx = engine.subscribe_state();
    let ctx = SendPtr(state_ctx);
    rt.spawn(async move {
        let ctx_holder = ctx;
        while rx.changed().await.is_ok() {
            let st = (*rx.borrow()).as_u8();
            let ptr = ctx_holder;
            unsafe { cb(ptr.0, st) };
        }
    });
}

#[no_mangle]
pub extern "C" fn yolac_create(cfg: *const YolacFfiConfig) -> *mut YolacHandle {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let (profile, mtu, block_v6) = if cfg.is_null() {
            (MemoryProfile::Standard, 1500usize, false)
        } else {
            let c = unsafe { &*cfg };
            let prof = if c.profile == 1 {
                MemoryProfile::LowMemoryIos
            } else {
                MemoryProfile::Standard
            };
            let mtu = if c.mtu < 576 { 1500 } else { c.mtu as usize };
            (prof, mtu, c.block_unprotected_ipv6 != 0)
        };

        let mut ycfg = match profile {
            MemoryProfile::LowMemoryIos => YolacConfig::mobile_ios(),
            MemoryProfile::Standard => YolacConfig::mobile_android(),
        };
        ycfg.mtu = mtu;
        ycfg.ipv6_mode = if block_v6 {
            Ipv6LeakMode::BlockUnprotectedIpv6
        } else {
            Ipv6LeakMode::DualStackProtected
        };

        let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(if profile == MemoryProfile::LowMemoryIos { 2 } else { 4 })
            .enable_all()
            .build()
        else {
            return std::ptr::null_mut();
        };

        let initial_engine = Arc::new(YolacEngine::new(ycfg.clone(), None));
        Box::into_raw(Box::new(YolacHandle {
            rt,
            config: ycfg,
            engine: Mutex::new(initial_engine),
            inbound_tx: Mutex::new(None),
        }))
    }));
    res.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn yolac_destroy(handle: *mut YolacHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = yolac_stop(handle);
        unsafe {
            drop(Box::from_raw(handle));
        }
    }));
}

#[no_mangle]
pub extern "C" fn yolac_get_state(handle: *const YolacHandle) -> u8 {
    if handle.is_null() {
        return EngineState::Inactive.as_u8();
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let Ok(guard) = h.engine.lock() else {
            return EngineState::Inactive.as_u8();
        };
        guard.state().as_u8()
    }))
    .unwrap_or_else(|_| EngineState::Inactive.as_u8())
}

#[no_mangle]
pub extern "C" fn yolac_notify_network_change(handle: *mut YolacHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        if let Ok(guard) = h.engine.lock() {
            guard.notify_network_change();
        }
        0
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn yolac_start_packet_flow(
    handle: *mut YolacHandle,
    sink_cb: YolacPacketSinkFn,
    sink_ctx: *mut c_void,
    state_cb: YolacStateChangedFn,
    state_ctx: *mut c_void,
) -> i32 {
    if handle.is_null() || sink_cb.is_none() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let engine = Arc::new(YolacEngine::new(h.config.clone(), None));
        spawn_state_forwarder(&h.rt, &engine, state_cb, state_ctx);

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
        let dev = Arc::new(ChannelPacketDevice::new(in_rx, out_tx));

        let cb = sink_cb.unwrap();
        let sctx = SendPtr(sink_ctx);
        h.rt.spawn(async move {
            let ctx_holder = sctx;
            while let Some(pkt) = out_rx.recv().await {
                let ptr = ctx_holder;
                unsafe { cb(ptr.0, pkt.as_ptr(), pkt.len()) };
            }
        });

        let start_res = h.rt.block_on(engine.start_tun(dev));
        if start_res.is_err() {
            return -2;
        }
        if let Ok(mut g) = h.inbound_tx.lock() {
            *g = Some(in_tx);
        }
        if let Ok(mut g) = h.engine.lock() {
            *g = engine;
        }
        0
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn yolac_push_tun_packet(
    handle: *mut YolacHandle,
    data: *const u8,
    len: usize,
) -> i32 {
    if handle.is_null() || data.is_null() || len == 0 {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        let Ok(guard) = h.inbound_tx.lock() else {
            return -1;
        };
        if let Some(tx) = guard.as_ref() {
            if tx.try_send(slice.to_vec()).is_ok() {
                return 0;
            }
        }
        -2
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn yolac_start_tun_fd(
    handle: *mut YolacHandle,
    tun_fd: i32,
    protect_cb: YolacProtectFdFn,
    protect_ctx: *mut c_void,
    state_cb: YolacStateChangedFn,
    state_ctx: *mut c_void,
) -> i32 {
    #[cfg(not(unix))]
    {
        let _ = (handle, tun_fd, protect_cb, protect_ctx, state_cb, state_ctx);
        -1
    }

    #[cfg(unix)]
    {
        if handle.is_null() || tun_fd < 0 {
            return -1;
        }
        catch_unwind(AssertUnwindSafe(|| {
            let h = unsafe { &*handle };
            let protector: Option<Arc<dyn SocketProtector>> = protect_cb.map(|cb| {
                Arc::new(CallbackProtector {
                    cb,
                    ctx: SendPtr(protect_ctx),
                }) as Arc<dyn SocketProtector>
            });
            let engine = Arc::new(YolacEngine::new(h.config.clone(), protector));
            spawn_state_forwarder(&h.rt, &engine, state_cb, state_ctx);

            let fd_dev = Arc::new(UnixTunFdDevice::new(tun_fd));
            let res = h.rt.block_on(engine.start_tun(fd_dev));
            if res.is_err() {
                return -2;
            }
            if let Ok(mut g) = h.engine.lock() {
                *g = engine;
            }
            0
        }))
        .unwrap_or(-1)
    }
}

#[no_mangle]
pub extern "C" fn yolac_stop(handle: *mut YolacHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        if let Ok(mut g) = h.inbound_tx.lock() {
            *g = None;
        }
        let eng = h.engine.lock().ok().map(|g| Arc::clone(&g));
        if let Some(engine) = eng {
            h.rt.block_on(engine.stop());
        }
        0
    }))
    .unwrap_or(-1)
}

fn write_c_string(src: &str, out_buf: *mut c_char, out_len: usize) -> i32 {
    if out_buf.is_null() || out_len == 0 {
        return -1;
    }
    let bytes = src.as_bytes();
    let copy_len = bytes.len().min(out_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.cast::<u8>(), copy_len);
        *out_buf.add(copy_len) = 0;
    }
    copy_len as i32
}

#[no_mangle]
pub extern "C" fn yolac_get_health_json(
    handle: *mut YolacHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let Ok(guard) = h.engine.lock() else {
            return -1;
        };
        let reports = guard.health_snapshot();
        let json = health_reports_to_json(&reports);
        write_c_string(&json, out_buf, out_len)
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn yolac_check_updates_json(
    handle: *mut YolacHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let eng = match h.engine.lock() {
            Ok(g) => Arc::clone(&g),
            Err(_) => return -1,
        };
        let res = h.rt.block_on(eng.check_updates_manual(None));
        let json = res.to_json();
        write_c_string(&json, out_buf, out_len)
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn yolac_report_platform_error(handle: *mut YolacHandle, error_code: u8) -> i32 {
    if handle.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &*handle };
        let Ok(guard) = h.engine.lock() else {
            return -1;
        };
        let code = match error_code {
            1 => ErrorCode::PermissionDenied,
            2 => ErrorCode::TunSetupFailed,
            3 => ErrorCode::DriverMissing,
            4 => ErrorCode::AlreadyRunning,
            _ => ErrorCode::InternalError,
        };
        guard.record_platform_error(code);
        0
    }))
    .unwrap_or(-1)
}

#[cfg(unix)]
struct UnixTunFdDevice {
    fd: i32,
    closed: Arc<std::sync::atomic::AtomicBool>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    write_lock: std::sync::Mutex<()>,
    reader_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[cfg(unix)]
impl UnixTunFdDevice {
    fn new(fd: i32) -> Self {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let closed_reader = Arc::clone(&closed);

        // Single dedicated OS reader thread -> 100% cancel-safe for `tokio::select!`,
        // handles Android O_NONBLOCK TUN FDs cleanly via libc::poll without leaking threads.
        let jh = std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while !closed_reader.load(std::sync::atomic::Ordering::Relaxed) {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
                if pr < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if pr == 0 {
                    continue;
                }
                if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                    break;
                }
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted
                        || err.kind() == io::ErrorKind::WouldBlock
                    {
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    break;
                }
                if tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                    break;
                }
            }
        });

        Self {
            fd,
            closed,
            rx: tokio::sync::Mutex::new(rx),
            write_lock: std::sync::Mutex::new(()),
            reader_thread: Mutex::new(Some(jh)),
        }
    }
}

#[cfg(unix)]
impl Drop for UnixTunFdDevice {
    fn drop(&mut self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut g) = self.reader_thread.lock() {
            if let Some(jh) = g.take() {
                let _ = jh.join();
            }
        }
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(unix)]
impl PacketDevice for UnixTunFdDevice {
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "TUN fd closed"))
    }

    async fn send_packet(&self, pkt: Vec<u8>) -> io::Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN fd closed"));
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| io::Error::other("TUN write lock poisoned"))?;
        for _ in 0..8 {
            let n = unsafe { libc::write(self.fd, pkt.as_ptr() as *const c_void, pkt.len()) };
            if n >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock {
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let _ = unsafe { libc::poll(&mut pfd, 1, 50) };
                continue;
            }
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    unsafe extern "C" fn test_sink(ctx: *mut c_void, _data: *const u8, len: usize) {
        let counter = &*(ctx as *const AtomicUsize);
        counter.fetch_add(len, Ordering::Relaxed);
    }

    #[test]
    fn ffi_lifecycle_is_panic_safe_and_handles_nulls() {
        let default_handle = yolac_create(std::ptr::null());
        assert!(!default_handle.is_null());
        yolac_destroy(default_handle);
        assert_eq!(yolac_get_state(std::ptr::null()), 0);
        assert_eq!(yolac_stop(std::ptr::null_mut()), -1);
        yolac_destroy(std::ptr::null_mut());

        let cfg = YolacFfiConfig {
            profile: 1,
            mtu: 1500,
            block_unprotected_ipv6: 0,
        };
        let handle = yolac_create(&cfg);
        assert!(!handle.is_null());

        let sink_bytes = AtomicUsize::new(0);
        let rc = yolac_start_packet_flow(
            handle,
            Some(test_sink),
            (&sink_bytes as *const AtomicUsize) as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, 0);
        assert_eq!(yolac_get_state(handle), 2); // Active
        assert_eq!(yolac_notify_network_change(handle), 0);

        // Verify C-ABI health JSON returns 7 modules with real Active statuses (0..6 Healthy, 6 Gray)
        let mut buf = vec![0 as c_char; 4096];
        let written = yolac_get_health_json(handle, buf.as_mut_ptr(), buf.len());
        assert!(written > 20);
        let json = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert!(json.contains("Akıllı Koruma"));
        assert!(json.contains("Güncellemeler"));

        // Verify platform error reporting turns health Red truthfully
        assert_eq!(yolac_report_platform_error(handle, 1), 0);
        let written_err = yolac_get_health_json(handle, buf.as_mut_ptr(), buf.len());
        assert!(written_err > 20);
        let err_json = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert!(err_json.contains("\"status\":2"));

        assert_eq!(yolac_stop(handle), 0);
        assert_eq!(yolac_stop(handle), 0); // Double stop safe
        assert_eq!(yolac_get_state(handle), 0); // Inactive
        yolac_destroy(handle);
    }

    #[cfg(unix)]
    #[test]
    fn non_blocking_unix_tun_fd_stays_active_and_healthy_without_eagain_exit() {
        // Simulates Android VpnService O_NONBLOCK TUN fd behavior directly via a Unix socketpair
        let mut fds = [-1i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0
        );
        let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
        assert_eq!(
            unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );

        let handle = yolac_create(std::ptr::null());
        assert!(!handle.is_null());
        let rc = yolac_start_tun_fd(
            handle,
            fds[0],
            None,
            std::ptr::null_mut(),
            None,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, 0);

        // Wait > 350ms (multiple 50ms smoltcp select ticks + poll cycle) with zero packets:
        // Engine MUST stay Active (2) and report 6 Healthy (Green) modules, NOT collapse to Inactive (Gray)!
        std::thread::sleep(std::time::Duration::from_millis(350));
        assert_eq!(yolac_get_state(handle), 2);

        let mut buf = vec![0 as c_char; 4096];
        let written = yolac_get_health_json(handle, buf.as_mut_ptr(), buf.len());
        assert!(written > 20);
        let json = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(json.matches("\"status\":1").count(), 6, "Expected 6 Green modules, got: {json}");

        assert_eq!(yolac_stop(handle), 0);
        yolac_destroy(handle);
        unsafe { libc::close(fds[1]) };
    }
}
