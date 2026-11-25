#![allow(dead_code)]
//! Windows "Swiss Army Knife" safe, reversible network speed optimizer, stale WinDivert SCM
//! cleaner, PPPoE Path-MTU inspector, and opt-in UAC-free Task Scheduler autostart manager.

use crate::dns_guard::flush_windows_dns_cache;

#[cfg(windows)]
fn run_hidden_cmd(program: &str, args: &[&str]) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.stderr.is_empty() {
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Some(text)
}

/// Cleans up a stopped stale `WinDivert` kernel service entry in Windows SCM (common when a user
/// previously ran GoodbyeDPI/Zapret or moved an older `tulpar.exe` folder, which otherwise fails
/// `WinDivertOpen` with Error 2/3 and demands a reboot!). Returns `true` if a stale service was cleaned.
#[cfg(windows)]
pub fn cleanup_stale_windivert_service() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOPPED,
    };
    const DELETE_ACCESS: u32 = 0x0001_0000;

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let mut cleaned = false;
        for svc_name in ["WinDivert\0", "WinDivert14\0"] {
            let wide: Vec<u16> = svc_name.encode_utf16().collect();
            let svc = OpenServiceW(scm, wide.as_ptr(), SERVICE_QUERY_STATUS | DELETE_ACCESS);
            if !svc.is_null() {
                let mut status: SERVICE_STATUS = std::mem::zeroed();
                if QueryServiceStatus(svc, &mut status) != 0
                    && status.dwCurrentState == SERVICE_STOPPED
                    && DeleteService(svc) != 0
                {
                    cleaned = true;
                }
                CloseServiceHandle(svc);
            }
        }
        CloseServiceHandle(scm);
        cleaned
    }
}

#[cfg(not(windows))]
pub fn cleanup_stale_windivert_service() -> bool {
    false
}

/// Inspects and safely repairs broken Windows TCP/IP speed bottlenecks:
/// - Restores Windows TCP Receive Window Auto-Tuning to `normal` if disabled/restricted
///   (disabled auto-tuning caps 100-1000 Mbps fiber connections down to ~20-40 Mbps!)
/// - Ensures Receive-Side Scaling (RSS) is enabled on multi-core CPUs
/// - Flushes Windows DNS resolver cache & cleans any stopped stale WinDivert SCM service
/// - Reports active interface MTU (useful for Turkish PPPoE VDSL/Fiber 1492/1480 checks)
pub fn inspect_and_repair_windows_network() -> String {
    flush_windows_dns_cache();
    let scm_cleaned = cleanup_stale_windivert_service();

    #[cfg(windows)]
    {
        let mut notes: Vec<String> = Vec::new();
        let before = run_hidden_cmd("netsh", &["interface", "tcp", "show", "global"]).unwrap_or_default();

        // Line-by-line check supporting both English and Turkish Windows locales
        let find_line_val = |keys: &[&str]| -> Option<String> {
            before.lines().find_map(|line| {
                let low = line.to_ascii_lowercase();
                if keys.iter().any(|k| low.contains(k)) {
                    Some(low)
                } else {
                    None
                }
            })
        };

        let autotune_line = find_line_val(&["auto-tuning level", "autotuninglevel", "otomatik ayarlama"]);
        let autotuning_crippled = autotune_line.as_deref().is_some_and(|l| {
            l.contains("disabled")
                || l.contains("restricted")
                || l.contains("devre")
                || l.contains("kısıt")
                || l.contains("kisit")
        });
        if autotuning_crippled {
            let _ = run_hidden_cmd("netsh", &["int", "tcp", "set", "global", "autotuninglevel=normal"]);
            notes.push("TCP Auto-Tuning onarıldı (normal)".into());
        } else {
            notes.push("TCP Auto-Tuning: normal".into());
        }

        let rss_line = find_line_val(&["receive-side scaling", "ölçekleme", "olcekleme"]);
        let rss_disabled = rss_line
            .as_deref()
            .is_some_and(|l| l.contains("disabled") || l.contains("devre"));
        if rss_disabled {
            let _ = run_hidden_cmd("netsh", &["int", "tcp", "set", "global", "rss=enabled"]);
            notes.push("RSS etkinleştirildi".into());
        } else {
            notes.push("RSS: aktif".into());
        }

        // Report active primary MTU
        if let Some(subif) = run_hidden_cmd("netsh", &["interface", "ipv4", "show", "subinterfaces"]) {
            if let Some(mtu_val) = subif
                .lines()
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|tok| tok.parse::<u32>().ok())
                .find(|&m| (576..=1500).contains(&m))
            {
                notes.push(format!("MTU: {mtu_val}"));
            }
        }

        if scm_cleaned {
            notes.push("Eski WinDivert servisi temizlendi".into());
        }
        notes.push("Windows DNS önbelleği sıfırlandı".into());
        notes.join(" · ")
    }

    #[cfg(not(windows))]
    {
        let _ = scm_cleaned;
        "Windows ağ onarımı yalnızca Windows üzerinde çalışır.".into()
    }
}

/// Checks whether the opt-in UAC-free logon autostart task (`TULPAR_AutoStart`) is registered.
pub fn is_windows_autostart_enabled() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("schtasks")
            .args(["/Query", "/TN", "TULPAR_AutoStart"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Toggles opt-in UAC-free Windows logon autostart via Task Scheduler (`RunLevel = Highest`).
pub fn toggle_windows_autostart() -> (bool, String) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        if is_windows_autostart_enabled() {
            let ok = Command::new("schtasks")
                .args(["/Delete", "/TN", "TULPAR_AutoStart", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                (false, "Açılışta otomatik başlatma kapatıldı.".into())
            } else {
                (true, "Otomatik başlatma kaldırılamadı (Yönetici izni gerekir).".into())
            }
        } else {
            let Ok(exe) = std::env::current_exe() else {
                return (false, "Uygulama yolu okunamadı.".into());
            };
            let tr = format!("\"{}\" --elevated-start", exe.display());
            let ok = Command::new("schtasks")
                .args([
                    "/Create",
                    "/TN",
                    "TULPAR_AutoStart",
                    "/TR",
                    &tr,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "HIGHEST",
                    "/F",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                (true, "Windows açılışında UAC sormadan otomatik başlatma açıldı.".into())
            } else {
                (false, "Otomatik başlatma eklenemedi (Yönetici olarak çalıştırın).".into())
            }
        }
    }
    #[cfg(not(windows))]
    {
        (false, "Yalnızca Windows üzerinde desteklenir.".into())
    }
}
