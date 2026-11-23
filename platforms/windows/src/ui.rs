#![allow(dead_code)]
//! Pure #000000 minimalist Win32 UI (Main Screen + Top-Right Settings Icon + 7-Module Health Row
//! + Manual GitHub Releases Updater + First-Launch & Settings Security Warning + Footer).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use yolac_core::{DEVELOPER_CREDIT_TR, SECURITY_WARNING_TR};
use yolac_core::{
    EngineState, ErrorCode, ModuleHealthReport, ModuleHealthStatus, UpdateCheckResult,
    YolacConfig, YolacEngine,
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
}

impl AppController {
    pub fn new() -> Self {
        let engine = Arc::new(YolacEngine::new(YolacConfig::windows_desktop(), None));
        let initial_screen = if is_security_warning_acked() {
            Screen::Main
        } else {
            Screen::FirstLaunchWarning
        };
        Self {
            engine,
            pkt_engine: Arc::new(WindowsPacketEngine::new()),
            screen: Mutex::new(initial_screen),
            selected_module: Mutex::new(None),
            update_message: Mutex::new(None),
            checking_updates: Mutex::new(false),
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
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let res = rt.block_on(this.engine.check_updates_manual(None));
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
                        self.engine.record_platform_error(ErrorCode::PermissionDenied);
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
                    Err(code) => {
                        self.engine.record_platform_error(code);
                        ctrl_ref(EngineState::Error(code));
                    }
                }
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
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_CAPTION_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
    };
    use windows_sys::Win32::Graphics::Gdi::{
        Arc as GdiArc, BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject,
        DrawTextW, Ellipse, EndPaint, FillRect, GetStockObject, InvalidateRect, LineTo, MoveToEx,
        Rectangle, RoundRect, SelectObject, SetBkMode, SetTextColor, BLACK_BRUSH, DT_CENTER,
        DT_LEFT, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, NULL_BRUSH, PAINTSTRUCT, PS_SOLID,
        TRANSPARENT,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, LoadCursorW, PostMessageW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
        IDC_ARROW, IDC_HAND, MSG, SW_HIDE, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL, WM_APP, WM_CLOSE,
        WM_COMMAND, WM_DESTROY, WM_KEYDOWN, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP,
        WM_PAINT, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    use crate::tray::{
        add_icon, remove_icon, show_context_menu, update_icon, IDM_TRAY_EXIT, IDM_TRAY_SHOW,
        IDM_TRAY_TOGGLE, WM_TRAY_ICON,
    };

    const WM_YOLAC_STATE: u32 = WM_APP + 1;
    const VK_RETURN_U: usize = 0x0D;
    const VK_SPACE_U: usize = 0x20;
    const VK_ESCAPE_U: usize = 0x1B;

    static CTRL: OnceLock<Arc<AppController>> = OnceLock::new();
    let controller = CTRL.get_or_init(|| Arc::new(AppController::new())).clone();

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

    fn open_official_url(url: &str) {
        if !url.starts_with("https://github.com/") {
            return;
        }
        let mut verb: Vec<u16> = "open\0".encode_utf16().collect();
        let mut target: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_mut_ptr(),
                target.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }

    unsafe fn draw_utf8(
        hdc: windows_sys::Win32::Graphics::Gdi::HDC,
        text: &str,
        rect: &mut RECT,
        color: COLORREF,
        flags: u32,
        font_height: i32,
    ) {
        let mut face: Vec<u16> = "Segoe UI\0".encode_utf16().collect();
        let font = CreateFontW(
            -font_height,
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

    fn icon_row_rects(w: i32) -> [RECT; 7] {
        let size = 44;
        let gap = 10;
        let total = 7 * size + 6 * gap;
        let start_x = ((w - total) / 2).max(12);
        let y = 78;
        let mut rects = [RECT { left: 0, top: 0, right: 0, bottom: 0 }; 7];
        for (i, r) in rects.iter_mut().enumerate() {
            let x = start_x + (i as i32) * (size + gap);
            *r = RECT {
                left: x,
                top: y,
                right: x + size,
                bottom: y + size,
            };
        }
        rects
    }

    fn update_btn_rect(w: i32, has_errors: bool, has_selected: bool) -> RECT {
        let mut y = 148;
        if has_errors {
            y += 74;
        }
        if has_selected {
            y += 38;
        }
        RECT {
            left: 28,
            top: y,
            right: (w - 28).max(200),
            bottom: y + 44,
        }
    }

    fn pt_in_rect(x: i32, y: i32, r: RECT) -> bool {
        x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
    }

    unsafe fn draw_module_glyph(
        hdc: windows_sys::Win32::Graphics::Gdi::HDC,
        idx: usize,
        rc: RECT,
        color: COLORREF,
        selected: bool,
    ) {
        let cx = (rc.left + rc.right) / 2;
        let cy = (rc.top + rc.bottom) / 2;
        let ring_color = if selected { rgb(255, 255, 255) } else { rgb(0x28, 0x28, 0x28) };
        let ring_pen = CreatePen(PS_SOLID as i32, 1, ring_color);
        let old_p = SelectObject(hdc, ring_pen.cast());
        let old_b = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
        Ellipse(hdc, rc.left, rc.top, rc.right, rc.bottom);
        SelectObject(hdc, old_p);
        DeleteObject(ring_pen.cast());

        let pen = CreatePen(PS_SOLID as i32, 2, color);
        let old_p2 = SelectObject(hdc, pen.cast());
        let r = 9;
        match idx {
            0 => {
                // Akıllı Koruma: shield
                MoveToEx(hdc, cx, cy - r, std::ptr::null_mut());
                LineTo(hdc, cx + r - 1, cy - 4);
                LineTo(hdc, cx + r - 3, cy + 4);
                LineTo(hdc, cx, cy + r);
                LineTo(hdc, cx - r + 3, cy + 4);
                LineTo(hdc, cx - r + 1, cy - 4);
                LineTo(hdc, cx, cy - r);
            }
            1 => {
                // DNS Koruması: globe
                Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                MoveToEx(hdc, cx - r, cy, std::ptr::null_mut());
                LineTo(hdc, cx + r, cy);
                Ellipse(hdc, cx - 4, cy - r, cx + 4, cy + r);
            }
            2 => {
                // Reklam ve Takip Engelleme: slash circle
                Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                MoveToEx(hdc, cx - 6, cy - 6, std::ptr::null_mut());
                LineTo(hdc, cx + 6, cy + 6);
            }
            3 => {
                // Gelişmiş Sansür Aşma: split path
                MoveToEx(hdc, cx - r, cy, std::ptr::null_mut());
                LineTo(hdc, cx - 1, cy);
                LineTo(hdc, cx + r - 1, cy - 6);
                MoveToEx(hdc, cx - 1, cy, std::ptr::null_mut());
                LineTo(hdc, cx + r - 1, cy + 6);
            }
            4 => {
                // Bağlantı Güvenliği: padlock
                Rectangle(hdc, cx - 7, cy - 1, cx + 7, cy + 8);
                GdiArc(hdc, cx - 5, cy - 8, cx + 5, cy + 2, cx + 5, cy - 3, cx - 5, cy - 3);
            }
            5 => {
                // Performans: bolt
                MoveToEx(hdc, cx + 2, cy - r, std::ptr::null_mut());
                LineTo(hdc, cx - 5, cy + 1);
                LineTo(hdc, cx + 1, cy + 1);
                LineTo(hdc, cx - 2, cy + r);
                LineTo(hdc, cx + 5, cy - 1);
                LineTo(hdc, cx - 1, cy - 1);
                LineTo(hdc, cx + 2, cy - r);
            }
            _ => {
                // Güncellemeler: refresh arc
                GdiArc(hdc, cx - 8, cy - 8, cx + 8, cy + 8, cx + 6, cy - 5, cx + 7, cy + 3);
                MoveToEx(hdc, cx + 6, cy - 5, std::ptr::null_mut());
                LineTo(hdc, cx + 2, cy - 5);
                MoveToEx(hdc, cx + 6, cy - 5, std::ptr::null_mut());
                LineTo(hdc, cx + 6, cy - 1);
            }
        }
        SelectObject(hdc, old_p2);
        SelectObject(hdc, old_b);
        DeleteObject(pen.cast());
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

        match msg {
            WM_PAINT => {
                let mut ps: PAINTSTRUCT = std::mem::zeroed();
                let hdc = BeginPaint(hwnd, &mut ps);
                let mut rc: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rc);
                let w = (rc.right - rc.left).max(1);
                let h = (rc.bottom - rc.top).max(1);

                FillRect(hdc, &rc, GetStockObject(BLACK_BRUSH as i32).cast());

                match ctrl.current_screen() {
                    Screen::FirstLaunchWarning => {
                        let box_rc = RECT {
                            left: 28,
                            top: (h / 2) - 110,
                            right: w - 28,
                            bottom: (h / 2) + 20,
                        };
                        let bg = CreateSolidBrush(rgb(0x11, 0x07, 0x07));
                        let pen = CreatePen(PS_SOLID as i32, 1, rgb(0x8A, 0x2E, 0x2E));
                        let ob = SelectObject(hdc, bg.cast());
                        let op = SelectObject(hdc, pen.cast());
                        RoundRect(hdc, box_rc.left, box_rc.top, box_rc.right, box_rc.bottom, 10, 10);
                        SelectObject(hdc, ob);
                        SelectObject(hdc, op);
                        DeleteObject(bg.cast());
                        DeleteObject(pen.cast());

                        let mut txt_rc = RECT {
                            left: box_rc.left + 14,
                            top: box_rc.top + 14,
                            right: box_rc.right - 14,
                            bottom: box_rc.bottom - 14,
                        };
                        draw_utf8(hdc, SECURITY_WARNING_TR, &mut txt_rc, rgb(255, 255, 255), DT_LEFT | DT_WORDBREAK, 15);

                        let mut ok_rc = RECT {
                            left: 28,
                            top: box_rc.bottom + 18,
                            right: w - 28,
                            bottom: box_rc.bottom + 64,
                        };
                        let wbrush = CreateSolidBrush(rgb(255, 255, 255));
                        let ob2 = SelectObject(hdc, wbrush.cast());
                        RoundRect(hdc, ok_rc.left, ok_rc.top, ok_rc.right, ok_rc.bottom, 8, 8);
                        SelectObject(hdc, ob2);
                        DeleteObject(wbrush.cast());
                        draw_utf8(hdc, "Anladım", &mut ok_rc, rgb(0, 0, 0), DT_CENTER | DT_VCENTER | DT_SINGLELINE, 15);
                    }
                    Screen::Main => {
                        // Top-right small minimalist gear icon
                        let gx = w - 34;
                        let gy = 30;
                        let gpen = CreatePen(PS_SOLID as i32, 2, rgb(0x7A, 0x7A, 0x7A));
                        let ogp = SelectObject(hdc, gpen.cast());
                        let onb = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
                        Ellipse(hdc, gx - 4, gy - 4, gx + 4, gy + 4);
                        Ellipse(hdc, gx - 9, gy - 9, gx + 9, gy + 9);
                        SelectObject(hdc, onb);
                        SelectObject(hdc, ogp);
                        DeleteObject(gpen.cast());

                        // Center single toggle button
                        let cx = w / 2;
                        let cy = h / 2;
                        let diam = (((w.min(h) as f32) * 0.42).clamp(160.0, 220.0)) as i32;
                        let r = diam / 2;

                        let st = ctrl.current_state();
                        let (fill_rgb, stroke_rgb, glyph_rgb) = match st {
                            EngineState::Inactive => (rgb(0, 0, 0), rgb(0x44, 0x44, 0x44), rgb(0x7A, 0x7A, 0x7A)),
                            EngineState::Activating | EngineState::Deactivating => {
                                (rgb(0, 0, 0), rgb(0x99, 0x99, 0x99), rgb(0xCC, 0xCC, 0xCC))
                            }
                            EngineState::Active => (rgb(255, 255, 255), rgb(255, 255, 255), rgb(0, 0, 0)),
                            EngineState::Error(_) => (rgb(0, 0, 0), rgb(0xC9, 0x3B, 0x3B), rgb(0xC9, 0x3B, 0x3B)),
                        };

                        let brush = CreateSolidBrush(fill_rgb);
                        let pen = CreatePen(PS_SOLID as i32, 2, stroke_rgb);
                        let old_brush = SelectObject(hdc, brush.cast());
                        let old_pen = SelectObject(hdc, pen.cast());
                        Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
                        SelectObject(hdc, old_brush);
                        SelectObject(hdc, old_pen);
                        DeleteObject(brush.cast());
                        DeleteObject(pen.cast());

                        let gr = (r as f32 * 0.28) as i32;
                        let gpen2 = CreatePen(PS_SOLID as i32, 3, glyph_rgb);
                        let old_gpen = SelectObject(hdc, gpen2.cast());
                        let old_nb = SelectObject(hdc, GetStockObject(NULL_BRUSH as i32));
                        let start_x = cx + (gr as f32 * 0.57) as i32;
                        let start_y = cy - (gr as f32 * 0.82) as i32;
                        let end_x = cx - (gr as f32 * 0.57) as i32;
                        let end_y = cy - (gr as f32 * 0.82) as i32;
                        GdiArc(hdc, cx - gr, cy - gr, cx + gr, cy + gr, end_x, end_y, start_x, start_y);
                        MoveToEx(hdc, cx, cy - (gr as f32 * 1.15) as i32, std::ptr::null_mut());
                        LineTo(hdc, cx, cy - (gr as f32 * 0.15) as i32);
                        SelectObject(hdc, old_nb);
                        SelectObject(hdc, old_gpen);
                        DeleteObject(gpen2.cast());
                    }
                    Screen::Settings => {
                        let mut hdr = RECT { left: 24, top: 20, right: w - 24, bottom: 52 };
                        draw_utf8(hdc, "←  Ayarlar", &mut hdr, rgb(255, 255, 255), DT_LEFT | DT_VCENTER | DT_SINGLELINE, 18);

                        let reports = ctrl.health_snapshot();
                        let rects = icon_row_rects(w);
                        let sel = ctrl.selected_module();
                        for (i, rep) in reports.iter().enumerate() {
                            draw_module_glyph(hdc, i, rects[i], status_rgb(rep.status), sel == Some(i));
                        }

                        let errors: Vec<String> = reports
                            .iter()
                            .filter(|r| r.status == ModuleHealthStatus::Error)
                            .map(|r| format!("{}: {}", r.id.display_name_tr(), r.detail_tr))
                            .collect();
                        let has_errors = !errors.is_empty();
                        let mut cursor_y = 136;

                        if has_errors {
                            let err_joined = errors.join("\n");
                            let mut err_rc = RECT { left: 28, top: cursor_y, right: w - 28, bottom: cursor_y + 72 };
                            draw_utf8(hdc, &err_joined, &mut err_rc, rgb(0xE7, 0x4C, 0x3C), DT_LEFT | DT_WORDBREAK, 13);
                            cursor_y += 74;
                        }

                        if let Some(sidx) = sel {
                            let rep = &reports[sidx];
                            let st_label = match rep.status {
                                ModuleHealthStatus::Healthy => "Aktif",
                                ModuleHealthStatus::Error => "Hata",
                                ModuleHealthStatus::PassiveOrUnchecked => "Pasif / Kontrol edilmedi",
                            };
                            let text = format!("{} ({}): {}", rep.id.display_name_tr(), st_label, rep.detail_tr);
                            let mut sel_rc = RECT { left: 28, top: cursor_y, right: w - 28, bottom: cursor_y + 38 };
                            draw_utf8(hdc, &text, &mut sel_rc, status_rgb(rep.status), DT_LEFT | DT_WORDBREAK, 13);
                        }

                        // Manual update button
                        let mut ubtn = update_btn_rect(w, has_errors, sel.is_some());
                        let upen = CreatePen(PS_SOLID as i32, 1, rgb(0x55, 0x55, 0x55));
                        let oup = SelectObject(hdc, upen.cast());
                        let oub = SelectObject(hdc, GetStockObject(BLACK_BRUSH as i32));
                        RoundRect(hdc, ubtn.left, ubtn.top, ubtn.right, ubtn.bottom, 8, 8);
                        SelectObject(hdc, oup);
                        SelectObject(hdc, oub);
                        DeleteObject(upen.cast());
                        let btn_label = if ctrl.is_checking_updates() {
                            "Kontrol ediliyor..."
                        } else {
                            "Güncellemeleri Kontrol Et"
                        };
                        draw_utf8(hdc, btn_label, &mut ubtn, rgb(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE, 14);

                        let mut after_btn_y = ubtn.bottom + 10;
                        if let Some((is_err, msg)) = ctrl.update_status_text() {
                            let mut urc = RECT { left: 28, top: after_btn_y, right: w - 28, bottom: after_btn_y + 36 };
                            let col = if is_err { rgb(0xE7, 0x4C, 0x3C) } else { rgb(0x2E, 0xCC, 0x71) };
                            draw_utf8(hdc, &msg, &mut urc, col, DT_LEFT | DT_WORDBREAK, 13);
                            after_btn_y += 40;
                        }

                        // Security warning box directly below update button
                        let warn_box = RECT {
                            left: 28,
                            top: after_btn_y + 6,
                            right: w - 28,
                            bottom: (after_btn_y + 92).min(h - 44),
                        };
                        let wbg = CreateSolidBrush(rgb(0x11, 0x07, 0x07));
                        let wpen = CreatePen(PS_SOLID as i32, 1, rgb(0x7A, 0x2B, 0x2B));
                        let owb = SelectObject(hdc, wbg.cast());
                        let owp = SelectObject(hdc, wpen.cast());
                        RoundRect(hdc, warn_box.left, warn_box.top, warn_box.right, warn_box.bottom, 8, 8);
                        SelectObject(hdc, owb);
                        SelectObject(hdc, owp);
                        DeleteObject(wbg.cast());
                        DeleteObject(wpen.cast());

                        let mut wtxt = RECT {
                            left: warn_box.left + 12,
                            top: warn_box.top + 10,
                            right: warn_box.right - 12,
                            bottom: warn_box.bottom - 10,
                        };
                        draw_utf8(hdc, SECURITY_WARNING_TR, &mut wtxt, rgb(0xE6, 0xB0, 0xAA), DT_LEFT | DT_WORDBREAK, 13);

                        // Footer credit
                        let mut footer_rc = RECT { left: 20, top: h - 34, right: w - 20, bottom: h - 10 };
                        draw_utf8(hdc, DEVELOPER_CREDIT_TR, &mut footer_rc, rgb(0x6E, 0x6E, 0x6E), DT_CENTER | DT_VCENTER | DT_SINGLELINE, 12);
                    }
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

                match ctrl.current_screen() {
                    Screen::FirstLaunchWarning => {
                        let ok_rc = RECT {
                            left: 28,
                            top: (h / 2) + 38,
                            right: w - 28,
                            bottom: (h / 2) + 84,
                        };
                        if pt_in_rect(x, y, ok_rc) {
                            ctrl.acknowledge_first_launch_warning();
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                        }
                    }
                    Screen::Main => {
                        let gear_rc = RECT { left: w - 56, top: 8, right: w - 10, bottom: 54 };
                        if pt_in_rect(x, y, gear_rc) {
                            ctrl.set_screen(Screen::Settings);
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }
                        let cx = w / 2;
                        let cy = h / 2;
                        let diam = (((w.min(h) as f32) * 0.42).clamp(160.0, 220.0)) as i32;
                        let r = diam / 2;
                        let dx = x - cx;
                        let dy = y - cy;
                        if dx * dx + dy * dy <= r * r {
                            let hwnd_val = hwnd as usize;
                            ctrl.toggle(move |_| {
                                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                            });
                        }
                    }
                    Screen::Settings => {
                        let back_rc = RECT { left: 16, top: 14, right: 150, bottom: 56 };
                        if pt_in_rect(x, y, back_rc) {
                            ctrl.set_screen(Screen::Main);
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        let rects = icon_row_rects(w);
                        for (i, r) in rects.iter().enumerate() {
                            if pt_in_rect(x, y, *r) {
                                ctrl.set_selected_module(Some(i));
                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                return 0;
                            }
                        }

                        let reports = ctrl.health_snapshot();
                        let has_errors = reports.iter().any(|r| r.status == ModuleHealthStatus::Error);
                        let ubtn = update_btn_rect(w, has_errors, ctrl.selected_module().is_some());
                        if pt_in_rect(x, y, ubtn) {
                            let hwnd_val = hwnd as usize;
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
                    Screen::FirstLaunchWarning if wparam == VK_RETURN_U || wparam == VK_SPACE_U => {
                        ctrl.acknowledge_first_launch_warning();
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                    Screen::Settings if wparam == VK_ESCAPE_U => {
                        ctrl.set_screen(Screen::Main);
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                    Screen::Main if wparam == VK_SPACE_U || wparam == VK_RETURN_U => {
                        let hwnd_val = hwnd as usize;
                        ctrl.toggle(move |_| {
                            let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                        });
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
                    let hwnd_val = hwnd as usize;
                    ctrl.toggle(move |_| {
                        let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
                    });
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
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class_name: Vec<u16> = "TulparMainWindow\0".encode_utf16().collect();
        let title: Vec<u16> = "TULPAR\0".encode_utf16().collect();

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_HAND.max(IDC_ARROW)),
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
            460,
            580,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return;
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

        if autostart {
            controller.acknowledge_first_launch_warning();
            let hwnd_val = hwnd as usize;
            controller.toggle(move |_| {
                let _ = PostMessageW(hwnd_val as HWND, WM_YOLAC_STATE, 0, 0);
            });
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
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
    use yolac_core::{official_github_repo, DEVELOPER_CREDIT_TR, SECURITY_WARNING_TR};

    #[test]
    fn windows_controller_reports_honest_passive_and_error_health() {
        let ctrl = AppController::new();
        let snap = ctrl.health_snapshot();
        assert_eq!(snap.len(), 7);
        assert!(snap.iter().all(|r| r.status == ModuleHealthStatus::PassiveOrUnchecked));

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

        assert!(SECURITY_WARNING_TR.contains("TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin"));
        assert_eq!(DEVELOPER_CREDIT_TR, "Ataberk Yıldız tarafından geliştirildi.");
        if let Some(repo) = official_github_repo() {
            assert!(repo == "AtaberkGit1/TULPAR" || repo == "AtaberkGit1/YOLAC");
        }
    }

    #[test]
    fn window_close_minimizes_to_tray_only_while_active() {
        let ctrl = AppController::new();
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::ExitApp);

        ctrl.engine.set_state(EngineState::Active);
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::MinimizeToTray);

        ctrl.engine.set_state(EngineState::Activating);
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::MinimizeToTray);

        ctrl.engine.set_state(EngineState::Inactive);
        assert_eq!(ctrl.on_window_close_requested(), CloseAction::ExitApp);
    }
}
