#![allow(dead_code)]
//! Pure #000000 minimalist Win32 UI (PerMonitorV2 HiDPI, Double-Buffered Paint, Single-Instance,
//! Main Screen + Top-Right Settings Icon + 7-Module Health Row + Swiss Army Knife Tools:
//! Live DNS/IPv6 Speed Diagnostic, 1-Click Network/TCP Optimizer, UAC-Free Autostart Toggle,
//! Manual GitHub Releases Updater + Security Warning).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(any(windows, test))]
use yolac_core::ModuleHealthStatus;
#[cfg(windows)]
use yolac_core::SECURITY_WARNING_TR;
use yolac_core::{
    EngineState, ErrorCode, ModuleHealthReport, UpdateCheckResult, YolacConfig, YolacEngine,
};

use crate::net_optimizer::{
    inspect_and_repair_windows_network, is_windows_autostart_enabled, toggle_windows_autostart,
};
use crate::permissions::{is_elevated, request_uac_elevation};
use crate::windivert::WindowsPacketEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    FirstLaunchWarning,
    Main,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    /// Protection is active/starting: hide window to Windows System Tray without interrupting protection.
    MinimizeToTray,
    /// Protection is off or errored: clean shutdown and exit.
    ExitApp,
}

pub struct AppController {
    engine: Arc<YolacEngine>,
    pkt_engine: Arc<WindowsPacketEngine>,
    screen: Mutex<Screen>,
    selected_module: Mutex<Option<usize>>,
    update_message: Mutex<Option<(bool, String)>>,
    checking_updates: Mutex<bool>,
    diag_message: Mutex<Option<(bool, String)>>,
    running_diag: Mutex<bool>,
    optimizer_message: Mutex<Option<String>>,
    running_optimizer: Mutex<bool>,
    autostart_enabled: AtomicBool,
    settings_scroll_y: AtomicI32,
}

impl AppController {
    pub fn new() -> Self {
        let engine = Arc::new(YolacEngine::new(YolacConfig::windows_desktop(), None));
        let initial_screen = if is_security_warning_acked() {
            Screen::Main
        } else {
            Screen::FirstLaunchWarning
        };
        let autostart_init = is_windows_autostart_enabled();
        Self {
            engine,
            pkt_engine: Arc::new(WindowsPacketEngine::new()),
            screen: Mutex::new(initial_screen),
            selected_module: Mutex::new(None),
            update_message: Mutex::new(None),
            checking_updates: Mutex::new(false),
            diag_message: Mutex::new(None),
            running_diag: Mutex::new(false),
            optimizer_message: Mutex::new(None),
            running_optimizer: Mutex::new(false),
            autostart_enabled: AtomicBool::new(autostart_init),
            settings_scroll_y: AtomicI32::new(0),
        }
    }

    pub fn current_state(&self) -> EngineState {
        self.engine.state()
    }

    pub fn current_screen(&self) -> Screen {
        *self.screen.lock().unwrap()
    }

    pub fn set_screen(&self, s: Screen) {
        if let Ok(mut g) = self.screen.lock() {
            *g = s;
        }
        if s != Screen::Settings {
            self.settings_scroll_y.store(0, Ordering::Relaxed);
        }
    }

    pub fn scroll_settings(&self, delta: i32, max_scroll: i32) {
        let cur = self.settings_scroll_y.load(Ordering::Relaxed);
        let next = (cur + delta).clamp(0, max_scroll.max(0));
        self.settings_scroll_y.store(next, Ordering::Relaxed);
    }

    pub fn settings_scroll_y(&self) -> i32 {
        self.settings_scroll_y.load(Ordering::Relaxed)
    }

    pub fn clamp_settings_scroll(&self, max_scroll: i32) -> i32 {
        let cur = self.settings_scroll_y.load(Ordering::Relaxed);
        let clamped = cur.clamp(0, max_scroll.max(0));
        if clamped != cur {
            self.settings_scroll_y.store(clamped, Ordering::Relaxed);
        }
        clamped
    }

    pub fn acknowledge_first_launch_warning(&self) {
        mark_security_warning_acked();
        self.set_screen(Screen::Main);
    }

    pub fn selected_module(&self) -> Option<usize> {
        *self.selected_module.lock().unwrap()
    }

    pub fn set_selected_module(&self, idx: Option<usize>) {
        if let Ok(mut g) = self.selected_module.lock() {
            *g = idx;
        }
    }

    pub fn health_snapshot(&self) -> [ModuleHealthReport; 7] {
        self.engine.health_snapshot()
    }

    pub fn update_status_text(&self) -> Option<(bool, String)> {
        self.update_message.lock().ok().and_then(|g| g.clone())
    }

    pub fn is_checking_updates(&self) -> bool {
        *self.checking_updates.lock().unwrap()
    }

    pub fn diag_status_text(&self) -> Option<(bool, String)> {
        self.diag_message.lock().ok().and_then(|g| g.clone())
    }

    pub fn is_running_diag(&self) -> bool {
        *self.running_diag.lock().unwrap()
    }

    pub fn optimizer_status_text(&self) -> Option<String> {
        self.optimizer_message.lock().ok().and_then(|g| g.clone())
    }

    pub fn is_running_optimizer(&self) -> bool {
        *self.running_optimizer.lock().unwrap()
    }

    pub fn is_autostart_enabled(&self) -> bool {
        self.autostart_enabled.load(Ordering::Relaxed)
    }

    pub fn notify_network_resume(&self) {
        if self.current_state() == EngineState::Active {
            self.engine.adaptive().on_network_change();
            self.engine.captive_portal().reset();
            let dns = Arc::clone(self.engine.dns_engine());
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        dns.on_network_change().await;
                        let _ = dns.probe_fastest_upstream().await;
                    });
                }
            });
        }
    }

    /// Runs live encrypted DNS latency benchmark + IPv6 reachability diagnostic in background.
    pub fn run_diagnostics_async(
        self: &Arc<Self>,
        on_done: impl Fn() + Send + Sync + 'static,
    ) {
        {
            let mut flag = self.running_diag.lock().unwrap();
            if *flag {
                return;
            }
            *flag = true;
        }
        if let Ok(mut msg) = self.diag_message.lock() {
            *msg = Some((
                false,
                "Şifreli DNS sunucuları ve IPv6 erişimi ölçülüyor...".into(),
            ));
        }

        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let res = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()
                .map(|rt| rt.block_on(this.engine.run_live_diagnostics()));
            let (is_err, text) = match res {
                Some(rep) => (rep.fastest_dns_rtt_ms.is_none(), rep.summary_tr),
                None => (true, "Tanılama çalışma zamanı başlatılamadı.".into()),
            };
            if let Ok(mut msg) = this.diag_message.lock() {
                *msg = Some((is_err, text));
            }
            if let Ok(mut flag) = this.running_diag.lock() {
                *flag = false;
            }
            on_done();
        });
    }

    /// Safely repairs Windows TCP Auto-Tuning/RSS, inspects MTU, cleans stale WinDivert SCM
    /// service, and flushes Windows DNS cache on a background thread.
    pub fn run_network_optimizer_async(
        self: &Arc<Self>,
        on_done: impl Fn() + Send + Sync + 'static,
    ) {
        {
            let mut flag = self.running_optimizer.lock().unwrap();
            if *flag {
                return;
            }
            *flag = true;
        }
        if let Ok(mut msg) = self.optimizer_message.lock() {
            *msg = Some("Windows TCP/IP, MTU ve DNS önbelleği denetleniyor...".into());
        }

        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let report = inspect_and_repair_windows_network();
            if let Ok(mut msg) = this.optimizer_message.lock() {
                *msg = Some(report);
            }
            if let Ok(mut flag) = this.running_optimizer.lock() {
                *flag = false;
            }
            on_done();
        });
    }

    /// Toggles opt-in UAC-free Windows logon autostart (Task Scheduler `RunLevel=Highest`).
    pub fn toggle_autostart_async(
        self: &Arc<Self>,
        on_done: impl Fn() + Send + Sync + 'static,
    ) {
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let (enabled, note) = toggle_windows_autostart();
            this.autostart_enabled.store(enabled, Ordering::Relaxed);
            if let Ok(mut msg) = this.optimizer_message.lock() {
                *msg = Some(note);
            }
            on_done();
        });
    }

    /// User-triggered manual GitHub Releases update check (never runs in background automatically).
    pub fn check_updates_manual_async(
        self: &Arc<Self>,
        on_done: impl Fn(Option<String>) + Send + Sync + 'static,
    ) {
        {
            let mut flag = self.checking_updates.lock().unwrap();
            if *flag {
                return;
            }
            *flag = true;
        }
        if let Ok(mut msg) = self.update_message.lock() {
            *msg = Some((false, "Resmî GitHub sürümleri kontrol ediliyor...".into()));
        }

        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let res = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()
                .map(|rt| rt.block_on(this.engine.check_updates_manual(None)))
                .unwrap_or_else(|| {
                    UpdateCheckResult::Error("Güncelleme çalışma zamanı başlatılamadı.".into())
                });
            let (is_err, text, url_to_open) = match res {
                UpdateCheckResult::UpToDate { current_version } => (
                    false,
                    format!("Uygulama güncel (v{current_version})."),
                    None,
                ),
                UpdateCheckResult::UpdateAvailable {
                    current_version,
                    latest_version,
                    release_url,
                } => (
                    false,
                    format!(
                        "Yeni sürüm bulundu: v{latest_version} (mevcut: v{current_version}). GitHub Releases açılıyor."
                    ),
                    Some(release_url),
                ),
                UpdateCheckResult::Error(err) => (true, err, None),
            };
            if let Ok(mut msg) = this.update_message.lock() {
                *msg = Some((is_err, text));
            }
            if let Ok(mut flag) = this.checking_updates.lock() {
                *flag = false;
            }
            on_done(url_to_open);
        });
    }

    /// Synchronous toggle helper (also exercised by cross-platform unit tests).
    pub fn toggle(&self, redraw: impl Fn(EngineState) + Send + Sync + 'static) {
        let cur = self.current_state();
        match cur {
            EngineState::Activating | EngineState::Deactivating => {}
            EngineState::Active => {
                self.engine.set_state(EngineState::Deactivating);
                redraw(EngineState::Deactivating);
                self.pkt_engine.stop();
                self.engine.adaptive().clear();
                self.engine.clear_platform_error();
                self.engine.set_state(EngineState::Inactive);
                redraw(EngineState::Inactive);
            }
            EngineState::Inactive | EngineState::Error(_) => {
                if !is_elevated() {
                    if request_uac_elevation() {
                        std::process::exit(0);
                    } else {
                        self.engine
                            .record_platform_error(ErrorCode::PermissionDenied);
                        redraw(EngineState::Error(ErrorCode::PermissionDenied));
                        return;
                    }
                }
                self.engine.set_state(EngineState::Activating);
                redraw(EngineState::Activating);
                let dns = Arc::clone(self.engine.dns_engine());
                let adaptive = Arc::clone(self.engine.adaptive());
                let portal = Arc::clone(self.engine.captive_portal());
                let eng_ref = Arc::clone(&self.engine);
                let ctrl_ref = Arc::new(redraw);
                let cb_ref = Arc::clone(&ctrl_ref);
                match self.pkt_engine.start(dns, adaptive, portal, move |st| {
                    eng_ref.set_state(st);
                    cb_ref(st);
                }) {
                    Ok(()) => {
                        self.engine.set_state(EngineState::Active);
                        ctrl_ref(EngineState::Active);
                    }
                    Err((code, detail)) => {
                        self.engine.record_platform_error_with_detail(code, detail);
                        ctrl_ref(EngineState::Error(code));
                    }
                }
            }
        }
    }

    /// Non-blocking Win32 UI toggle: runs WinDivert start/stop off the UI message pump thread so
    /// the window stays 100% responsive and cleans up the System Tray icon before UAC relaunch!
    pub fn toggle_async(
        self: &Arc<Self>,
        before_uac_exit: impl FnOnce() + Send + 'static,
        redraw: impl Fn(EngineState) + Send + Sync + 'static,
    ) {
        let cur = self.current_state();
        match cur {
            EngineState::Activating | EngineState::Deactivating => {}
            EngineState::Active => {
                self.engine.set_state(EngineState::Deactivating);
                redraw(EngineState::Deactivating);
                let this = Arc::clone(self);
                std::thread::spawn(move || {
                    this.pkt_engine.stop();
                    this.engine.adaptive().clear();
                    this.engine.clear_platform_error();
                    this.engine.set_state(EngineState::Inactive);
                    redraw(EngineState::Inactive);
                });
            }
            EngineState::Inactive | EngineState::Error(_) => {
                if !is_elevated() {
                    if request_uac_elevation() {
                        before_uac_exit();
                        std::process::exit(0);
                    } else {
                        self.engine
                            .record_platform_error(ErrorCode::PermissionDenied);
                        redraw(EngineState::Error(ErrorCode::PermissionDenied));
                        return;
                    }
                }
                self.engine.set_state(EngineState::Activating);
                redraw(EngineState::Activating);
                let this = Arc::clone(self);
                std::thread::spawn(move || {
                    let dns = Arc::clone(this.engine.dns_engine());
                    let adaptive = Arc::clone(this.engine.adaptive());
                    let portal = Arc::clone(this.engine.captive_portal());
                    let eng_ref = Arc::clone(&this.engine);
                    let ctrl_ref = Arc::new(redraw);
                    let cb_ref = Arc::clone(&ctrl_ref);
                    match this.pkt_engine.start(dns, adaptive, portal, move |st| {
                        eng_ref.set_state(st);
                        cb_ref(st);
                    }) {
                        Ok(()) => {
                            this.engine.set_state(EngineState::Active);
                            ctrl_ref(EngineState::Active);
                        }
                        Err((code, detail)) => {
                            this.engine.record_platform_error_with_detail(code, detail);
                            ctrl_ref(EngineState::Error(code));
                        }
                    }
                });
            }
        }
    }

    /// Decides window close (`X`) behavior: minimize to System Tray while protection is active,
    /// otherwise exit cleanly.
    pub fn on_window_close_requested(&self) -> CloseAction {
        match self.current_state() {
            EngineState::Active | EngineState::Activating => CloseAction::MinimizeToTray,
            EngineState::Inactive | EngineState::Deactivating | EngineState::Error(_) => {
                CloseAction::ExitApp
            }
        }
    }

    pub fn shutdown(&self) {
        self.pkt_engine.stop();
        self.engine.adaptive().clear();
        self.engine.captive_portal().reset();
        self.engine.set_state(EngineState::Inactive);
    }
}

/// Validates that a URL points strictly to the official TULPAR GitHub Releases page.
pub fn is_trusted_official_release_url(url: &str) -> bool {
    url.to_ascii_lowercase()
        .starts_with("https://github.com/ataberkgit1/tulpar/releases")
}

fn ack_flag_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))?;
    Some(base.join("Tulpar").join("security_ack"))
}

fn is_security_warning_acked() -> bool {
    ack_flag_path().map(|p| p.exists()).unwrap_or(false)
}

fn mark_security_warning_acked() {
    if let Some(p) = ack_flag_path() {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, b"1");
    }
}

#[cfg(windows)]
pub fn run_win32_ui(autostart: bool) {
    use std::sync::atomic::AtomicU32;
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, COLORREF, ERROR_ALREADY_EXISTS, HANDLE, HWND, LPARAM, LRESULT,
        RECT, WPARAM,
    };
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_CAPTION_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
    };
    use windows_sys::Win32::Graphics::Gdi::{
        Arc as GdiArc, BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW,
        CreatePen, CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW, Ellipse, EndPaint,
        FillRect, GetStockObject, InvalidateRect, LineTo, MoveToEx, Rectangle, RoundRect,
        SelectObject, SetBkMode, SetTextColor, BLACK_BRUSH, DT_CENTER, DT_LEFT, DT_SINGLELINE,
        DT_VCENTER, DT_WORDBREAK, HDC, NULL_BRUSH, PAINTSTRUCT, PS_SOLID, SRCCOPY, TRANSPARENT,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::HiDpi::{
        GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
        GetClientRect, GetMessageW, LoadCursorW, LoadIconW, PostMessageW, PostQuitMessage,
        RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetWindowPos, ShowWindow,
        TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, IDC_ARROW, IDI_APPLICATION,
        MINMAXINFO, MSG, SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, WM_APP,
        WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_DPICHANGED, WM_ERASEBKGND, WM_GETMINMAXINFO,
        WM_KEYDOWN, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEWHEEL, WM_PAINT,
        WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    use crate::tray::{
        add_icon, remove_icon, show_context_menu, update_icon, IDM_TRAY_EXIT, IDM_TRAY_SHOW,
        IDM_TRAY_TOGGLE, WM_TRAY_ICON,
    };

    const WM_YOLAC_STATE: u32 = WM_APP + 1;
    const WM_POWERBROADCAST_MSG: u32 = 0x0218;
    const PBT_APMRESUMESUSPEND_CODE: usize = 0x0007;
    const PBT_APMRESUMEAUTOMATIC_CODE: usize = 0x0012;
    const VK_RETURN_U: usize = 0x0D;
    const VK_SPACE_U: usize = 0x20;
    const VK_ESCAPE_U: usize = 0x1B;
    const VK_UP_U: usize = 0x26;
    const VK_DOWN_U: usize = 0x28;

    static CTRL: OnceLock<Arc<AppController>> = OnceLock::new();
    static TASKBAR_CREATED_MSG: AtomicU32 = AtomicU32::new(0);
    static SINGLE_INSTANCE_MUTEX: Mutex<usize> = Mutex::new(0);

    let controller = CTRL.get_or_init(|| Arc::new(AppController::new())).clone();

    fn release_single_instance_mutex() {
        if let Ok(mut g) = SINGLE_INSTANCE_MUTEX.lock() {
            let raw = *g;
            *g = 0;
            if raw != 0 {
                unsafe {
                    let _ = CloseHandle(raw as HANDLE);
                }
            }
        }
    }

    fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
        (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
    }

    fn status_rgb(status: ModuleHealthStatus) -> COLORREF {
        match status {
            ModuleHealthStatus::Healthy => rgb(0x2E, 0xCC, 0x71),
            ModuleHealthStatus::Error => rgb(0xE7, 0x4C, 0x3C),
            ModuleHealthStatus::PassiveOrUnchecked => rgb(0x6E, 0x6E, 0x6E),
        }
    }

    fn dpi_for(hwnd: HWND) -> i32 {
        let d = unsafe { GetDpiForWindow(hwnd) } as i32;
        if d >= 72 {
            d
        } else {
            96
        }
    }

    #[inline]
    fn sc(logical_px: i32, dpi: i32) -> i32 {
        (logical_px * dpi + 48) / 96
    }

    /// Opens the official TULPAR GitHub Releases URL de-elevated via `explorer.exe`
    /// so an Administrator `tulpar.exe` never launches an elevated browser!
    fn open_official_url(url: &str) {
        if !is_trusted_official_release_url(url) {
            return;
        }
        let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
    }

    unsafe fn draw_utf8(
        hdc: HDC,
        text: &str,
        rect: &mut RECT,
        color: COLORREF,
        flags: u32,
        font_height_px: i32,
    ) {
        let mut face: Vec<u16> = "Segoe UI\0".encode_utf16().collect();
        let font = CreateFontW(
            -font_height_px,
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            0,
            0,
            0,
            5,
            0,
            face.as_mut_ptr(),
        );
        let old = SelectObject(hdc, font.cast());
        SetBkMode(hdc, TRANSPARENT as i32);
        SetTextColor(hdc, color);
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        DrawTextW(hdc, wide.as_mut_ptr(), wide.len() as i32, rect, flags);
        SelectObject(hdc, old);
        DeleteObject(font.cast());
    }

    struct SettingsLayout {
        back_rc: RECT,
        icons: [RECT; 7],
        error_rc: Option<RECT>,
        selected_rc: Option<RECT>,
        diag_btn: RECT,
        diag_text_rc: Option<RECT>,
        opt_btn: RECT,
        autostart_btn: RECT,
        opt_text_rc: Option<RECT>,
        update_btn: RECT,
        update_text_rc: Option<RECT>,
        warn_box: RECT,
        content_height: i32,
    }

    fn compute_settings_layout(
        w: i32,
        dpi: i32,
        scroll_y: i32,
        has_errors: bool,
        has_selected: bool,
        has_diag: bool,
        has_opt_msg: bool,
        has_update_msg: bool,
    ) -> SettingsLayout {
        let pad = sc(24, dpi);
        let right = (w - pad).max(pad + sc(180, dpi));
        let back_rc = RECT {
            left: sc(16, dpi),
            top: sc(12, dpi),
            right: sc(160, dpi),
            bottom: sc(52, dpi),
        };

        let icon_size = sc(44, dpi);
        let icon_gap = sc(10, dpi);
        let total_icons = 7 * icon_size + 6 * icon_gap;
        let start_x = ((w - total_icons) / 2).max(sc(10, dpi));
        let icon_y = sc(68, dpi) - scroll_y;
        let mut icons = [RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        }; 7];
        for (i, r) in icons.iter_mut().enumerate() {
            let x = start_x + (i as i32) * (icon_size + icon_gap);
            *r = RECT {
                left: x,
                top: icon_y,
                right: x + icon_size,
                bottom: icon_y + icon_size,
            };
        }

        let mut y = icon_y + icon_size + sc(14, dpi);
        let error_rc = if has_errors {
            let h = sc(78, dpi);
            let r = RECT {
                left: pad,
                top: y,
                right,
                bottom: y + h,
            };
            y += h + sc(8, dpi);
            Some(r)
        } else {
            None
        };

        let selected_rc = if has_selected {
            let h = sc(46, dpi);
            let r = RECT {
                left: pad,
                top: y,
                right,
                bottom: y + h,
            };
            y += h + sc(8, dpi);
            Some(r)
        } else {
            None
        };

        let btn_h = sc(40, dpi);
        let btn_gap = sc(10, dpi);

        // 1. Live DNS & IPv6 speed diagnostic button
        let diag_btn = RECT {
            left: pad,
            top: y,
            right,
            bottom: y + btn_h,
        };
        y += btn_h + sc(6, dpi);

        let diag_text_rc = if has_diag {
            let h = sc(68, dpi);
            let r = RECT {
                left: pad,
                top: y,
                right,
                bottom: y + h,
            };
            y += h + sc(8, dpi);
            Some(r)
        } else {
            y += sc(4, dpi);
            None
        };

        // 2. 1-click Windows TCP/IP & DNS Network Optimizer/Repair
        let opt_btn = RECT {
            left: pad,
            top: y,
            right,
            bottom: y + btn_h,
        };
        y += btn_h + btn_gap;

        // 3. Opt-in UAC-free Windows logon autostart toggle
        let autostart_btn = RECT {
            left: pad,
            top: y,
            right,
            bottom: y + btn_h,
        };
        y += btn_h + sc(6, dpi);

        let opt_text_rc = if has_opt_msg {
            let h = sc(44, dpi);
            let r = RECT {
                left: pad,
                top: y,
                right,
                bottom: y + h,
            };
            y += h + sc(8, dpi);
            Some(r)
        } else {
            y += sc(4, dpi);
            None
        };

        // 4. Manual GitHub Releases update check button
        let update_btn = RECT {
            left: pad,
            top: y,
            right,
            bottom: y + btn_h,
        };
        y += btn_h + sc(6, dpi);

        let update_text_rc = if has_update_msg {
            let h = sc(38, dpi);
            let r = RECT {
                left: pad,
                top: y,
                right,
                bottom: y + h,
            };
            y += h + sc(8, dpi);
            Some(r)
        } else {
            y += sc(4, dpi);
            None
        };

        // 5. Security Warning Box
        let warn_h = sc(88, dpi);
        let warn_box = RECT {
            left: pad,
            top: y,
            right,
            bottom: y + warn_h,
        };
        y += warn_h + sc(22, dpi);

        SettingsLayout {
            back_rc,
            icons,
            error_rc,
            selected_rc,
            diag_btn,
            diag_text_rc,
            opt_btn,
            autostart_btn,
            opt_text_rc,
            update_btn,
            update_text_rc,
            warn_box,
            content_height: y + scroll_y,
        }
    }

    fn pt_in_rect(x: i32, y: i32, r: RECT) -> bool {
        x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
    }

    unsafe fn draw_outline_button(
        hdc: HDC,
        rc: RECT,
        label: &str,
        border_color: COLORREF,
        text_color: COLORREF,
        dpi: i32,
    ) {
        let pen = CreatePen(PS_SOLID as i32, 1, border_color);
        let op = SelectObject(hdc, pen.cast());
        let ob = SelectObject(hdc, GetStockObject(BLACK_BRUSH as i32));
        let rad = sc(8, dpi);
        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
        SelectObject(hdc, op);
        SelectObject(hdc, ob);
        DeleteObject(pen.cast());
        let mut trc = rc;
        draw_utf8(
            hdc,
            label,
            &mut trc,
            text_color,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            sc(13, dpi),
        );
    }

    unsafe fn draw_module_glyph(
        hdc: HDC,
        idx: usize,
        rc: RECT,
        color: COLORREF,
        selected: bool,
        dpi: i32,
    ) {
        let cx = (rc.left + rc.right) / 2;
        let cy = (rc.top + rc.bottom) / 2;
        let ring_color = if selected {
            rgb(255, 255, 255)
        } else {
            rgb(0x28, 0x28, 0x28)
        };
        let ring_pen = CreatePen(PS_SOLID as i32, sc(1, dpi).max(1), ring_color);
        let old_p = SelectObject(hdc, ring_pen.cast());
        let old_b = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
        Ellipse(hdc, rc.left, rc.top, rc.right, rc.bottom);
        SelectObject(hdc, old_p);
        DeleteObject(ring_pen.cast());

        let pen = CreatePen(PS_SOLID as i32, sc(2, dpi).max(1), color);
        let old_p2 = SelectObject(hdc, pen.cast());
        let r = sc(9, dpi);
        match idx {
            0 => {
                MoveToEx(hdc, cx, cy - r, std::ptr::null_mut());
                LineTo(hdc, cx + r - sc(1, dpi), cy - sc(4, dpi));
                LineTo(hdc, cx + r - sc(3, dpi), cy + sc(4, dpi));
                LineTo(hdc, cx, cy + r);
                LineTo(hdc, cx - r + sc(3, dpi), cy + sc(4, dpi));
                LineTo(hdc, cx - r + sc(1, dpi), cy - sc(4, dpi));
                LineTo(hdc, cx, cy - r);
            }
            1 => {
                Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                MoveToEx(hdc, cx - r, cy, std::ptr::null_mut());
                LineTo(hdc, cx + r, cy);
                Ellipse(hdc, cx - sc(4, dpi), cy - r, cx + sc(4, dpi), cy + r);
            }
            2 => {
                Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                let d = sc(6, dpi);
                MoveToEx(hdc, cx - d, cy - d, std::ptr::null_mut());
                LineTo(hdc, cx + d, cy + d);
            }
            3 => {
                MoveToEx(hdc, cx - r, cy, std::ptr::null_mut());
                LineTo(hdc, cx - sc(1, dpi), cy);
                LineTo(hdc, cx + r - sc(1, dpi), cy - sc(6, dpi));
                MoveToEx(hdc, cx - sc(1, dpi), cy, std::ptr::null_mut());
                LineTo(hdc, cx + r - sc(1, dpi), cy + sc(6, dpi));
            }
            4 => {
                Rectangle(
                    hdc,
                    cx - sc(7, dpi),
                    cy - sc(1, dpi),
                    cx + sc(7, dpi),
                    cy + sc(8, dpi),
                );
                GdiArc(
                    hdc,
                    cx - sc(5, dpi),
                    cy - sc(8, dpi),
                    cx + sc(5, dpi),
                    cy + sc(2, dpi),
                    cx + sc(5, dpi),
                    cy - sc(3, dpi),
                    cx - sc(5, dpi),
                    cy - sc(3, dpi),
                );
            }
            5 => {
                MoveToEx(hdc, cx + sc(2, dpi), cy - r, std::ptr::null_mut());
                LineTo(hdc, cx - sc(5, dpi), cy + sc(1, dpi));
                LineTo(hdc, cx + sc(1, dpi), cy + sc(1, dpi));
                LineTo(hdc, cx - sc(2, dpi), cy + r);
                LineTo(hdc, cx + sc(5, dpi), cy - sc(1, dpi));
                LineTo(hdc, cx - sc(1, dpi), cy - sc(1, dpi));
                LineTo(hdc, cx + sc(2, dpi), cy - r);
            }
            _ => {
                let rr = sc(8, dpi);
                GdiArc(
                    hdc,
                    cx - rr,
                    cy - rr,
                    cx + rr,
                    cy + rr,
                    cx + sc(6, dpi),
                    cy - sc(5, dpi),
                    cx + sc(7, dpi),
                    cy + sc(3, dpi),
                );
                MoveToEx(hdc, cx + sc(6, dpi), cy - sc(5, dpi), std::ptr::null_mut());
                LineTo(hdc, cx + sc(2, dpi), cy - sc(5, dpi));
                MoveToEx(hdc, cx + sc(6, dpi), cy - sc(5, dpi), std::ptr::null_mut());
                LineTo(hdc, cx + sc(6, dpi), cy - sc(1, dpi));
            }
        }
        SelectObject(hdc, old_p2);
        SelectObject(hdc, old_b);
        DeleteObject(pen.cast());
    }

    unsafe fn trigger_toggle(ctrl: &Arc<AppController>, hwnd: HWND) {
        let hwnd_val = hwnd as usize;
        ctrl.toggle_async(
            move || {
                remove_icon(hwnd_val as HWND);
                release_single_instance_mutex();
            },
            move |_| {
                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
            },
        );
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let Some(ctrl) = CTRL.get() else {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        };

        let tb_msg = TASKBAR_CREATED_MSG.load(Ordering::Relaxed);
        if tb_msg != 0 && msg == tb_msg {
            add_icon(hwnd, ctrl.current_state());
            return 0;
        }

        match msg {
            WM_ERASEBKGND => 1,
            WM_GETMINMAXINFO => {
                let dpi = dpi_for(hwnd);
                let info = lparam as *mut MINMAXINFO;
                if !info.is_null() {
                    (*info).ptMinTrackSize.x = sc(400, dpi);
                    (*info).ptMinTrackSize.y = sc(480, dpi);
                }
                0
            }
            WM_DPICHANGED => {
                let suggested = lparam as *const RECT;
                if !suggested.is_null() {
                    let r = *suggested;
                    let _ = SetWindowPos(
                        hwnd,
                        std::ptr::null_mut(),
                        r.left,
                        r.top,
                        r.right - r.left,
                        r.bottom - r.top,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
                InvalidateRect(hwnd, std::ptr::null(), 0);
                0
            }
            WM_POWERBROADCAST_MSG => {
                if wparam == PBT_APMRESUMEAUTOMATIC_CODE || wparam == PBT_APMRESUMESUSPEND_CODE {
                    ctrl.notify_network_resume();
                }
                1
            }
            WM_MOUSEWHEEL => {
                if ctrl.current_screen() == Screen::Settings {
                    let wheel_delta = ((wparam >> 16) & 0xFFFF) as i16 as i32;
                    let dpi = dpi_for(hwnd);
                    let mut rc: RECT = std::mem::zeroed();
                    GetClientRect(hwnd, &mut rc);
                    let w = (rc.right - rc.left).max(1);
                    let h = (rc.bottom - rc.top).max(1);
                    let reports = ctrl.health_snapshot();
                    let has_errors = reports.iter().any(|r| r.status == ModuleHealthStatus::Error);
                    let layout = compute_settings_layout(
                        w,
                        dpi,
                        ctrl.settings_scroll_y(),
                        has_errors,
                        ctrl.selected_module().is_some(),
                        ctrl.diag_status_text().is_some(),
                        ctrl.optimizer_status_text().is_some(),
                        ctrl.update_status_text().is_some(),
                    );
                    let max_scroll = (layout.content_height - h).max(0);
                    let step = sc(36, dpi);
                    ctrl.scroll_settings(if wheel_delta > 0 { -step } else { step }, max_scroll);
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                }
                0
            }
            WM_PAINT => {
                let mut ps: PAINTSTRUCT = std::mem::zeroed();
                let screen_hdc = BeginPaint(hwnd, &mut ps);
                let mut rc: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rc);
                let w = (rc.right - rc.left).max(1);
                let h = (rc.bottom - rc.top).max(1);
                let dpi = dpi_for(hwnd);

                // Double-buffered offscreen DC eliminates flicker on resize/scroll/state changes
                let mem_dc = CreateCompatibleDC(screen_hdc);
                let mem_bmp = CreateCompatibleBitmap(screen_hdc, w, h);
                let old_bmp = SelectObject(mem_dc, mem_bmp.cast());
                let hdc = if !mem_dc.is_null() && !mem_bmp.is_null() {
                    mem_dc
                } else {
                    screen_hdc
                };

                FillRect(hdc, &rc, GetStockObject(BLACK_BRUSH as i32).cast());

                match ctrl.current_screen() {
                    Screen::FirstLaunchWarning => {
                        let pad = sc(28, dpi);
                        let box_rc = RECT {
                            left: pad,
                            top: (h / 2) - sc(110, dpi),
                            right: w - pad,
                            bottom: (h / 2) + sc(26, dpi),
                        };
                        let bg = CreateSolidBrush(rgb(0x11, 0x07, 0x07));
                        let pen = CreatePen(PS_SOLID as i32, 1, rgb(0x8A, 0x2E, 0x2E));
                        let ob = SelectObject(hdc, bg.cast());
                        let op = SelectObject(hdc, pen.cast());
                        let rad = sc(10, dpi);
                        RoundRect(
                            hdc,
                            box_rc.left,
                            box_rc.top,
                            box_rc.right,
                            box_rc.bottom,
                            rad,
                            rad,
                        );
                        SelectObject(hdc, ob);
                        SelectObject(hdc, op);
                        DeleteObject(bg.cast());
                        DeleteObject(pen.cast());

                        let mut txt_rc = RECT {
                            left: box_rc.left + sc(14, dpi),
                            top: box_rc.top + sc(14, dpi),
                            right: box_rc.right - sc(14, dpi),
                            bottom: box_rc.bottom - sc(14, dpi),
                        };
                        draw_utf8(
                            hdc,
                            SECURITY_WARNING_TR,
                            &mut txt_rc,
                            rgb(255, 255, 255),
                            DT_LEFT | DT_WORDBREAK,
                            sc(14, dpi),
                        );

                        let mut ok_rc = RECT {
                            left: pad,
                            top: box_rc.bottom + sc(18, dpi),
                            right: w - pad,
                            bottom: box_rc.bottom + sc(64, dpi),
                        };
                        let wbrush = CreateSolidBrush(rgb(255, 255, 255));
                        let ob2 = SelectObject(hdc, wbrush.cast());
                        RoundRect(
                            hdc,
                            ok_rc.left,
                            ok_rc.top,
                            ok_rc.right,
                            ok_rc.bottom,
                            sc(8, dpi),
                            sc(8, dpi),
                        );
                        SelectObject(hdc, ob2);
                        DeleteObject(wbrush.cast());
                        draw_utf8(
                            hdc,
                            "Anladım",
                            &mut ok_rc,
                            rgb(0, 0, 0),
                            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                            sc(15, dpi),
                        );
                    }
                    Screen::Main => {
                        // Top-right small minimalist gear icon
                        let gx = w - sc(34, dpi);
                        let gy = sc(30, dpi);
                        let gpen = CreatePen(PS_SOLID as i32, sc(2, dpi).max(1), rgb(0x7A, 0x7A, 0x7A));
                        let ogp = SelectObject(hdc, gpen.cast());
                        let onb = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
                        let r_in = sc(4, dpi);
                        let r_out = sc(9, dpi);
                        Ellipse(hdc, gx - r_in, gy - r_in, gx + r_in, gy + r_in);
                        Ellipse(hdc, gx - r_out, gy - r_out, gx + r_out, gy + r_out);
                        SelectObject(hdc, onb);
                        SelectObject(hdc, ogp);
                        DeleteObject(gpen.cast());

                        // Center single toggle button
                        let cx = w / 2;
                        let cy = h / 2;
                        let diam = (((w.min(h) as f32) * 0.42)
                            .clamp(sc(160, dpi) as f32, sc(220, dpi) as f32))
                            as i32;
                        let r = diam / 2;

                        let st = ctrl.current_state();
                        let (fill_rgb, stroke_rgb, glyph_rgb) = match st {
                            EngineState::Inactive => {
                                (rgb(0, 0, 0), rgb(0x44, 0x44, 0x44), rgb(0x7A, 0x7A, 0x7A))
                            }
                            EngineState::Activating | EngineState::Deactivating => {
                                (rgb(0, 0, 0), rgb(0x99, 0x99, 0x99), rgb(0xCC, 0xCC, 0xCC))
                            }
                            EngineState::Active => {
                                (rgb(255, 255, 255), rgb(255, 255, 255), rgb(0, 0, 0))
                            }
                            EngineState::Error(_) => {
                                (rgb(0, 0, 0), rgb(0xC9, 0x3B, 0x3B), rgb(0xC9, 0x3B, 0x3B))
                            }
                        };

                        let brush = CreateSolidBrush(fill_rgb);
                        let pen = CreatePen(PS_SOLID as i32, sc(2, dpi).max(1), stroke_rgb);
                        let old_brush = SelectObject(hdc, brush.cast());
                        let old_pen = SelectObject(hdc, pen.cast());
                        Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                        SelectObject(hdc, old_brush);
                        SelectObject(hdc, old_pen);
                        DeleteObject(brush.cast());
                        DeleteObject(pen.cast());

                        let gr = (r as f32 * 0.28) as i32;
                        let gpen2 = CreatePen(PS_SOLID as i32, sc(3, dpi).max(2), glyph_rgb);
                        let old_gpen = SelectObject(hdc, gpen2.cast());
                        let old_nb = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
                        let start_x = cx + (gr as f32 * 0.57) as i32;
                        let start_y = cy - (gr as f32 * 0.82) as i32;
                        let end_x = cx - (gr as f32 * 0.57) as i32;
                        let end_y = cy - (gr as f32 * 0.82) as i32;
                        GdiArc(
                            hdc,
                            cx - gr,
                            cy - gr,
                            cx + gr,
                            cy + gr,
                            end_x,
                            end_y,
                            start_x,
                            start_y,
                        );
                        MoveToEx(hdc, cx, cy - (gr as f32 * 1.15) as i32, std::ptr::null_mut());
                        LineTo(hdc, cx, cy - (gr as f32 * 0.15) as i32);
                        SelectObject(hdc, old_nb);
                        SelectObject(hdc, old_gpen);
                        DeleteObject(gpen2.cast());
                    }
                    Screen::Settings => {
                        let reports = ctrl.health_snapshot();
                        let mut seen_details: Vec<String> = Vec::new();
                        let mut errors: Vec<String> = Vec::new();
                        for r in reports
                            .iter()
                            .filter(|r| r.status == ModuleHealthStatus::Error)
                        {
                            if !seen_details.contains(&r.detail_tr) {
                                seen_details.push(r.detail_tr.clone());
                                errors.push(format!("{}: {}", r.id.display_name_tr(), r.detail_tr));
                            }
                        }
                        let has_errors = !errors.is_empty();
                        let sel = ctrl.selected_module();
                        let diag_msg = ctrl.diag_status_text();
                        let opt_msg = ctrl.optimizer_status_text();
                        let upd_msg = ctrl.update_status_text();

                        let probe_layout = compute_settings_layout(
                            w,
                            dpi,
                            0,
                            has_errors,
                            sel.is_some(),
                            diag_msg.is_some(),
                            opt_msg.is_some(),
                            upd_msg.is_some(),
                        );
                        let scroll_y = ctrl.clamp_settings_scroll((probe_layout.content_height - h).max(0));
                        let layout = compute_settings_layout(
                            w,
                            dpi,
                            scroll_y,
                            has_errors,
                            sel.is_some(),
                            diag_msg.is_some(),
                            opt_msg.is_some(),
                            upd_msg.is_some(),
                        );

                        // Scrollable content drawn first, then fixed header bar drawn cleanly over top
                        for (i, rep) in reports.iter().enumerate() {
                            draw_module_glyph(
                                hdc,
                                i,
                                layout.icons[i],
                                status_rgb(rep.status),
                                sel == Some(i),
                                dpi,
                            );
                        }

                        if let Some(mut err_rc) = layout.error_rc {
                            let err_joined = errors.join("\n");
                            draw_utf8(
                                hdc,
                                &err_joined,
                                &mut err_rc,
                                rgb(0xE7, 0x4C, 0x3C),
                                DT_LEFT | DT_WORDBREAK,
                                sc(12, dpi),
                            );
                        }

                        if let (Some(sidx), Some(mut sel_rc)) = (sel, layout.selected_rc) {
                            let rep = &reports[sidx];
                            let st_label = match rep.status {
                                ModuleHealthStatus::Healthy => "Aktif",
                                ModuleHealthStatus::Error => "Hata",
                                ModuleHealthStatus::PassiveOrUnchecked => "Pasif / Kontrol edilmedi",
                            };
                            let text = format!(
                                "{} ({}): {}",
                                rep.id.display_name_tr(),
                                st_label,
                                rep.detail_tr
                            );
                            draw_utf8(
                                hdc,
                                &text,
                                &mut sel_rc,
                                status_rgb(rep.status),
                                DT_LEFT | DT_WORDBREAK,
                                sc(12, dpi),
                            );
                        }

                        // 1. Live DNS & IPv6 speed diagnostic button
                        let diag_label = if ctrl.is_running_diag() {
                            "Ağ ve DNS Hızı Ölçülüyor..."
                        } else {
                            "Ağ ve Hız Testi (DNS / IPv6)"
                        };
                        draw_outline_button(
                            hdc,
                            layout.diag_btn,
                            diag_label,
                            rgb(0x4A, 0x7A, 0x5A),
                            rgb(255, 255, 255),
                            dpi,
                        );
                        if let (Some((is_err, msg)), Some(mut drc)) = (diag_msg, layout.diag_text_rc) {
                            let col = if is_err {
                                rgb(0xE7, 0x4C, 0x3C)
                            } else {
                                rgb(0x2E, 0xCC, 0x71)
                            };
                            draw_utf8(hdc, &msg, &mut drc, col, DT_LEFT | DT_WORDBREAK, sc(12, dpi));
                        }

                        // 2. 1-Click Network & TCP Optimizer/Repair button
                        let opt_label = if ctrl.is_running_optimizer() {
                            "TCP/IP & DNS Onarılıyor..."
                        } else {
                            "Ağ ve TCP Hızlandır / Onar"
                        };
                        draw_outline_button(
                            hdc,
                            layout.opt_btn,
                            opt_label,
                            rgb(0x55, 0x55, 0x55),
                            rgb(255, 255, 255),
                            dpi,
                        );

                        // 3. Opt-in UAC-free autostart toggle button
                        let auto_label = if ctrl.is_autostart_enabled() {
                            "Windows Açılışında Başlat: AÇIK"
                        } else {
                            "Windows Açılışında Başlat: KAPALI"
                        };
                        let auto_border = if ctrl.is_autostart_enabled() {
                            rgb(0x2E, 0xCC, 0x71)
                        } else {
                            rgb(0x55, 0x55, 0x55)
                        };
                        draw_outline_button(
                            hdc,
                            layout.autostart_btn,
                            auto_label,
                            auto_border,
                            rgb(255, 255, 255),
                            dpi,
                        );

                        if let (Some(msg), Some(mut orc)) = (opt_msg, layout.opt_text_rc) {
                            draw_utf8(
                                hdc,
                                &msg,
                                &mut orc,
                                rgb(0xBD, 0xBD, 0xBD),
                                DT_LEFT | DT_WORDBREAK,
                                sc(12, dpi),
                            );
                        }

                        // 4. Manual GitHub Releases update button
                        let upd_label = if ctrl.is_checking_updates() {
                            "Kontrol ediliyor..."
                        } else {
                            "Güncellemeleri Kontrol Et"
                        };
                        draw_outline_button(
                            hdc,
                            layout.update_btn,
                            upd_label,
                            rgb(0x55, 0x55, 0x55),
                            rgb(255, 255, 255),
                            dpi,
                        );
                        if let (Some((is_err, msg)), Some(mut urc)) = (upd_msg, layout.update_text_rc) {
                            let col = if is_err {
                                rgb(0xE7, 0x4C, 0x3C)
                            } else {
                                rgb(0x2E, 0xCC, 0x71)
                            };
                            draw_utf8(hdc, &msg, &mut urc, col, DT_LEFT | DT_WORDBREAK, sc(12, dpi));
                        }

                        // 5. Security Warning Box
                        let warn_box = layout.warn_box;
                        let wbg = CreateSolidBrush(rgb(0x11, 0x07, 0x07));
                        let wpen = CreatePen(PS_SOLID as i32, 1, rgb(0x7A, 0x2B, 0x2B));
                        let owb = SelectObject(hdc, wbg.cast());
                        let owp = SelectObject(hdc, wpen.cast());
                        RoundRect(
                            hdc,
                            warn_box.left,
                            warn_box.top,
                            warn_box.right,
                            warn_box.bottom,
                            sc(8, dpi),
                            sc(8, dpi),
                        );
                        SelectObject(hdc, owb);
                        SelectObject(hdc, owp);
                        DeleteObject(wbg.cast());
                        DeleteObject(wpen.cast());

                        let mut wtxt = RECT {
                            left: warn_box.left + sc(12, dpi),
                            top: warn_box.top + sc(10, dpi),
                            right: warn_box.right - sc(12, dpi),
                            bottom: warn_box.bottom - sc(10, dpi),
                        };
                        draw_utf8(
                            hdc,
                            SECURITY_WARNING_TR,
                            &mut wtxt,
                            rgb(0xE6, 0xB0, 0xAA),
                            DT_LEFT | DT_WORDBREAK,
                            sc(12, dpi),
                        );

                        // Sticky top header bar over scrolled content
                        let hdr_bg = RECT {
                            left: 0,
                            top: 0,
                            right: w,
                            bottom: sc(56, dpi),
                        };
                        FillRect(hdc, &hdr_bg, GetStockObject(BLACK_BRUSH as i32).cast());
                        let mut hdr = RECT {
                            left: sc(24, dpi),
                            top: sc(16, dpi),
                            right: w - sc(24, dpi),
                            bottom: sc(48, dpi),
                        };
                        draw_utf8(
                            hdc,
                            "←  Ayarlar",
                            &mut hdr,
                            rgb(255, 255, 255),
                            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
                            sc(17, dpi),
                        );
                    }
                }

                if hdc == mem_dc {
                    let _ = BitBlt(screen_hdc, 0, 0, w, h, mem_dc, 0, 0, SRCCOPY);
                }
                if !old_bmp.is_null() && !mem_dc.is_null() {
                    SelectObject(mem_dc, old_bmp);
                }
                if !mem_bmp.is_null() {
                    DeleteObject(mem_bmp.cast());
                }
                if !mem_dc.is_null() {
                    DeleteDC(mem_dc);
                }
                EndPaint(hwnd, &ps);
                0
            }
            WM_LBUTTONDOWN => {
                let x = (lparam & 0xFFFF) as i16 as i32;
                let y = ((lparam >> 16) & 0xFFFF) as i16 as i32;
                let mut rc: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rc);
                let w = rc.right - rc.left;
                let h = rc.bottom - rc.top;
                let dpi = dpi_for(hwnd);

                match ctrl.current_screen() {
                    Screen::FirstLaunchWarning => {
                        let pad = sc(28, dpi);
                        let ok_rc = RECT {
                            left: pad,
                            top: (h / 2) + sc(44, dpi),
                            right: w - pad,
                            bottom: (h / 2) + sc(90, dpi),
                        };
                        if pt_in_rect(x, y, ok_rc) {
                            ctrl.acknowledge_first_launch_warning();
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                        }
                    }
                    Screen::Main => {
                        let gear_rc = RECT {
                            left: w - sc(56, dpi),
                            top: sc(8, dpi),
                            right: w - sc(10, dpi),
                            bottom: sc(54, dpi),
                        };
                        if pt_in_rect(x, y, gear_rc) {
                            ctrl.set_screen(Screen::Settings);
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }
                        let cx = w / 2;
                        let cy = h / 2;
                        let diam = (((w.min(h) as f32) * 0.42)
                            .clamp(sc(160, dpi) as f32, sc(220, dpi) as f32))
                            as i32;
                        let r = diam / 2;
                        let dx = (x - cx) as i64;
                        let dy = (y - cy) as i64;
                        if dx * dx + dy * dy <= (r as i64) * (r as i64) {
                            trigger_toggle(ctrl, hwnd);
                        }
                    }
                    Screen::Settings => {
                        let reports = ctrl.health_snapshot();
                        let has_errors = reports
                            .iter()
                            .any(|r| r.status == ModuleHealthStatus::Error);
                        let layout = compute_settings_layout(
                            w,
                            dpi,
                            ctrl.settings_scroll_y(),
                            has_errors,
                            ctrl.selected_module().is_some(),
                            ctrl.diag_status_text().is_some(),
                            ctrl.optimizer_status_text().is_some(),
                            ctrl.update_status_text().is_some(),
                        );

                        if pt_in_rect(x, y, layout.back_rc) {
                            ctrl.set_screen(Screen::Main);
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        // Ignore clicks hidden under the sticky header bar
                        if y < sc(56, dpi) {
                            return 0;
                        }

                        for (i, r) in layout.icons.iter().enumerate() {
                            if pt_in_rect(x, y, *r) {
                                ctrl.set_selected_module(Some(i));
                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                return 0;
                            }
                        }

                        let hwnd_val = hwnd as usize;
                        if pt_in_rect(x, y, layout.diag_btn) {
                            ctrl.run_diagnostics_async(move || {
                                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                            });
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        if pt_in_rect(x, y, layout.opt_btn) {
                            ctrl.run_network_optimizer_async(move || {
                                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                            });
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        if pt_in_rect(x, y, layout.autostart_btn) {
                            ctrl.toggle_autostart_async(move || {
                                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                            });
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        if pt_in_rect(x, y, layout.update_btn) {
                            ctrl.check_updates_manual_async(move |url_opt| {
                                if let Some(url) = url_opt {
                                    open_official_url(&url);
                                }
                                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                            });
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                        }
                    }
                }
                0
            }
            WM_KEYDOWN => {
                match ctrl.current_screen() {
                    Screen::FirstLaunchWarning
                        if wparam == VK_RETURN_U || wparam == VK_SPACE_U =>
                    {
                        ctrl.acknowledge_first_launch_warning();
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                    Screen::Settings if wparam == VK_ESCAPE_U => {
                        ctrl.set_screen(Screen::Main);
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                    Screen::Settings if wparam == VK_UP_U || wparam == VK_DOWN_U => {
                        let dpi = dpi_for(hwnd);
                        let step = sc(40, dpi);
                        ctrl.scroll_settings(if wparam == VK_UP_U { -step } else { step }, sc(400, dpi));
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                    Screen::Main if wparam == VK_SPACE_U || wparam == VK_RETURN_U => {
                        trigger_toggle(ctrl, hwnd);
                    }
                    _ => {}
                }
                0
            }
            WM_YOLAC_STATE => {
                update_icon(hwnd, ctrl.current_state());
                InvalidateRect(hwnd, std::ptr::null(), 0);
                0
            }
            WM_TRAY_ICON => {
                let evt = (lparam as u32) & 0xFFFF;
                if evt == WM_LBUTTONUP || evt == WM_LBUTTONDBLCLK {
                    ShowWindow(hwnd, SW_SHOW);
                    ShowWindow(hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(hwnd);
                } else if evt == WM_RBUTTONUP {
                    show_context_menu(hwnd, ctrl.current_state());
                }
                0
            }
            WM_COMMAND => {
                let cmd = wparam & 0xFFFF;
                if cmd == IDM_TRAY_SHOW {
                    ShowWindow(hwnd, SW_SHOW);
                    ShowWindow(hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(hwnd);
                } else if cmd == IDM_TRAY_TOGGLE {
                    trigger_toggle(ctrl, hwnd);
                } else if cmd == IDM_TRAY_EXIT {
                    remove_icon(hwnd);
                    ctrl.shutdown();
                    let _ = DestroyWindow(hwnd);
                }
                0
            }
            WM_CLOSE => match ctrl.on_window_close_requested() {
                CloseAction::MinimizeToTray => {
                    ShowWindow(hwnd, SW_HIDE);
                    0
                }
                CloseAction::ExitApp => {
                    remove_icon(hwnd);
                    ctrl.shutdown();
                    DefWindowProcW(hwnd, msg, wparam, lparam)
                }
            },
            WM_DESTROY => {
                remove_icon(hwnd);
                ctrl.shutdown();
                release_single_instance_mutex();
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    unsafe {
        // Enable crisp Per-Monitor V2 HiDPI rendering before creating any HWND
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        let class_name: Vec<u16> = "TulparMainWindow\0".encode_utf16().collect();
        let mutex_name: Vec<u16> = "Local\\TULPAR_SingleInstance_v1\0".encode_utf16().collect();

        // Single-instance mutex (allows brief handoff delay during UAC `--elevated-start` relaunch)
        let mut acquired = false;
        let attempts = if autostart { 12 } else { 1 };
        for _ in 0..attempts {
            let h = CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr());
            if !h.is_null() {
                if GetLastError() == ERROR_ALREADY_EXISTS {
                    let _ = CloseHandle(h);
                    if attempts > 1 {
                        std::thread::sleep(std::time::Duration::from_millis(120));
                        continue;
                    }
                    let existing = FindWindowW(class_name.as_ptr(), std::ptr::null());
                    if !existing.is_null() {
                        ShowWindow(existing, SW_SHOW);
                        ShowWindow(existing, SW_RESTORE);
                        let _ = SetForegroundWindow(existing);
                    }
                    return;
                }
                if let Ok(mut g) = SINGLE_INSTANCE_MUTEX.lock() {
                    *g = h as usize;
                }
                acquired = true;
                break;
            }
        }
        if !acquired && !autostart {
            return;
        }

        let tb_name: Vec<u16> = "TaskbarCreated\0".encode_utf16().collect();
        TASKBAR_CREATED_MSG.store(RegisterWindowMessageW(tb_name.as_ptr()), Ordering::Relaxed);

        let hinst = GetModuleHandleW(std::ptr::null());
        let title: Vec<u16> = "TULPAR\0".encode_utf16().collect();

        let app_icon = {
            let embedded = LoadIconW(hinst, 1usize as *const u16);
            if !embedded.is_null() {
                embedded
            } else {
                LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
            }
        };

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: app_icon,
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: GetStockObject(BLACK_BRUSH as i32).cast(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            480,
            620,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            release_single_instance_mutex();
            return;
        }

        // Scale initial window size to monitor DPI cleanly
        let init_dpi = dpi_for(hwnd);
        if init_dpi != 96 {
            let _ = SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                0,
                0,
                sc(480, init_dpi),
                sc(620, init_dpi),
                SWP_NOZORDER | SWP_NOACTIVATE | 0x0002, // SWP_NOMOVE
            );
        }

        let dark: i32 = 1;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            (&dark as *const i32).cast(),
            std::mem::size_of::<i32>() as u32,
        );
        let black_caption: u32 = 0x0000_0000;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR as u32,
            (&black_caption as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        );

        ShowWindow(hwnd, SW_SHOW);
        add_icon(hwnd, controller.current_state());

        if autostart && is_elevated() {
            controller.acknowledge_first_launch_warning();
            trigger_toggle(&controller, hwnd);
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        release_single_instance_mutex();
    }
}

#[cfg(not(windows))]
pub fn run_win32_ui(_autostart: bool) {
    let _ctrl = AppController::new();
    eprintln!("TULPAR Windows GUI requires Windows Win32 APIs.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use yolac_core::{official_github_repo, SECURITY_WARNING_TR};

    #[test]
    fn windows_controller_reports_honest_passive_and_error_health() {
        let ctrl = AppController::new();
        let snap = ctrl.health_snapshot();
        assert_eq!(snap.len(), 7);
        assert!(snap
            .iter()
            .all(|r| r.status == ModuleHealthStatus::PassiveOrUnchecked));

        // Attempting toggle on non-elevated/non-Windows host must NOT fake Green; reports PermissionDenied (Red)
        ctrl.toggle(|_| {});
        let after = ctrl.health_snapshot();
        assert_eq!(after[0].status, ModuleHealthStatus::Error);
        assert_eq!(after[3].status, ModuleHealthStatus::Error);
        assert_eq!(after[6].status, ModuleHealthStatus::PassiveOrUnchecked);
    }

    #[test]
    fn windows_settings_screen_selection_and_official_repo_checks() {
        let ctrl = AppController::new();
        ctrl.set_screen(Screen::Settings);
        assert_eq!(ctrl.current_screen(), Screen::Settings);

        for idx in 0..7 {
            ctrl.set_selected_module(Some(idx));
            assert_eq!(ctrl.selected_module(), Some(idx));
        }

        ctrl.scroll_settings(80, 200);
        assert_eq!(ctrl.settings_scroll_y(), 80);
        ctrl.set_screen(Screen::Main);
        assert_eq!(ctrl.settings_scroll_y(), 0);

        assert!(SECURITY_WARNING_TR
            .contains("TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin"));
        if let Some(repo) = official_github_repo() {
            assert!(repo == "AtaberkGit1/TULPAR" || repo == "AtaberkGit1/YOLAC");
        }
        assert!(is_trusted_official_release_url(
            "https://github.com/AtaberkGit1/TULPAR/releases/tag/v0.4.0"
        ));
        assert!(!is_trusted_official_release_url(
            "https://github.com/evil-attacker/TULPAR/releases/tag/v9.9.9"
        ));
    }

    #[test]
    fn window_close_minimizes_to_tray_only_while_active() {
        let ctrl = AppController::new();
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::ExitApp);

        ctrl.engine.set_state(EngineState::Active);
        assert_eq!(
            ctrl.on_window_close_requested(),
            CloseAction::MinimizeToTray
        );

        ctrl.engine.set_state(EngineState::Activating);
        assert_eq!(
            ctrl.on_window_close_requested(),
            CloseAction::MinimizeToTray
        );

        ctrl.engine.set_state(EngineState::Inactive);
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::ExitApp);
    }
}
