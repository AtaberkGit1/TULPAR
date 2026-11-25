#![allow(dead_code)]
//! Native Win32 System Tray integration (Shell_NotifyIconW + Turkish popup context menu).
//! Zero external crate dependencies.

use yolac_core::EngineState;

pub const WM_TRAY_ICON: u32 = 0x8000 + 2; // WM_APP + 2
pub const IDM_TRAY_SHOW: usize = 1001;
pub const IDM_TRAY_TOGGLE: usize = 1002;
pub const IDM_TRAY_EXIT: usize = 1003;

/// Returns the Turkish tooltip text shown when hovering the Windows System Tray icon.
pub fn tooltip_for_state(state: EngineState) -> &'static str {
    match state {
        EngineState::Active => "TULPAR — Koruma Aktif",
        EngineState::Activating => "TULPAR — Başlatılıyor...",
        EngineState::Deactivating => "TULPAR — Kapatılıyor...",
        EngineState::Error(_) => "TULPAR — Hata",
        EngineState::Inactive => "TULPAR — Koruma Kapalı",
    }
}

/// Returns the Turkish label for the toggle menu item in the system tray popup menu.
pub fn toggle_menu_label(state: EngineState) -> &'static str {
    match state {
        EngineState::Active | EngineState::Activating => "Korumayı Kapat",
        EngineState::Inactive | EngineState::Deactivating | EngineState::Error(_) => "Korumayı Aç",
    }
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use windows_sys::Win32::Foundation::{HWND, POINT};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, LoadIconW, PostMessageW,
        SetForegroundWindow, TrackPopupMenu, IDI_APPLICATION, MF_SEPARATOR, MF_STRING,
        TPM_BOTTOMALIGN, TPM_LEFTALIGN, WM_NULL,
    };

    const TRAY_ICON_ID: u32 = 1;

    fn write_tip(buf: &mut [u16; 128], text: &str) {
        buf.fill(0);
        for (slot, unit) in buf.iter_mut().take(127).zip(text.encode_utf16()) {
            *slot = unit;
        }
    }

    unsafe fn load_app_icon() -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
        let hinst = GetModuleHandleW(std::ptr::null());
        let embedded = LoadIconW(hinst, std::ptr::without_provenance::<u16>(1));
        if !embedded.is_null() {
            embedded
        } else {
            LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
        }
    }

    unsafe fn make_nid(hwnd: HWND, state: EngineState) -> NOTIFYICONDATAW {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY_ICON;
        nid.hIcon = load_app_icon();
        write_tip(&mut nid.szTip, tooltip_for_state(state));
        nid
    }

    pub unsafe fn add_icon(hwnd: HWND, state: EngineState) {
        let nid = make_nid(hwnd, state);
        let _ = Shell_NotifyIconW(NIM_ADD, &nid);
    }

    pub unsafe fn update_icon(hwnd: HWND, state: EngineState) {
        let nid = make_nid(hwnd, state);
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    pub unsafe fn remove_icon(hwnd: HWND) {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    }

    pub unsafe fn show_context_menu(hwnd: HWND, state: EngineState) {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let show_w: Vec<u16> = "TULPAR'ı Göster\0".encode_utf16().collect();
        let toggle_w: Vec<u16> = format!("{}\0", toggle_menu_label(state))
            .encode_utf16()
            .collect();
        let exit_w: Vec<u16> = "Çıkış\0".encode_utf16().collect();

        AppendMenuW(menu, MF_STRING, IDM_TRAY_SHOW, show_w.as_ptr());
        AppendMenuW(menu, MF_STRING, IDM_TRAY_TOGGLE, toggle_w.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, exit_w.as_ptr());

        let mut pt = POINT { x: 0, y: 0 };
        let _ = GetCursorPos(&mut pt);
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(
            menu,
            TPM_LEFTALIGN | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        // Win32 KB135788: post WM_NULL so clicking outside dismisses cleanly on next right-click
        let _ = PostMessageW(hwnd, WM_NULL, 0, 0);
        let _ = DestroyMenu(menu);
    }
}

#[cfg(windows)]
pub use win_impl::{add_icon, remove_icon, show_context_menu, update_icon};

#[cfg(test)]
mod tests {
    use super::*;
    use yolac_core::ErrorCode;

    #[test]
    fn produces_turkish_tulpar_tray_tooltips_and_labels() {
        assert_eq!(tooltip_for_state(EngineState::Active), "TULPAR — Koruma Aktif");
        assert_eq!(tooltip_for_state(EngineState::Inactive), "TULPAR — Koruma Kapalı");
        assert_eq!(
            tooltip_for_state(EngineState::Error(ErrorCode::PermissionDenied)),
            "TULPAR — Hata"
        );
        assert_eq!(toggle_menu_label(EngineState::Active), "Korumayı Kapat");
        assert_eq!(toggle_menu_label(EngineState::Inactive), "Korumayı Aç");
    }
}
