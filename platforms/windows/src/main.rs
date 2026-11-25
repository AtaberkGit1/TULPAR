#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod dns_guard;
mod integrity;
mod net_optimizer;
mod permissions;
mod tray;
mod ui;
mod windivert;

use std::path::PathBuf;

fn parse_flag_value(args: &[String], idx: &mut usize, name: &str) -> Option<String> {
    if args[*idx] == name {
        if let Some(val) = args.get(*idx + 1) {
            *idx += 2;
            return Some(val.clone());
        }
    } else if let Some(prefix) = args[*idx].strip_prefix(&format!("{name}=")) {
        *idx += 1;
        return Some(prefix.to_string());
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let elevated_start = args.iter().any(|a| a == "--elevated-start" || a == "--autostart");
    let mut strategy_path: Option<PathBuf> = None;
    let mut dns_spec: Option<String> = None;
    let mut quic_mode: Option<String> = None;
    let mut diagnose_domain: Option<String> = None;
    let mut i = 1usize;
    while i < args.len() {
        if let Some(v) = parse_flag_value(&args, &mut i, "--strategy") {
            strategy_path = Some(PathBuf::from(v));
            continue;
        }
        if let Some(v) = parse_flag_value(&args, &mut i, "--dns") {
            dns_spec = Some(v);
            continue;
        }
        if let Some(v) = parse_flag_value(&args, &mut i, "--quic") {
            quic_mode = Some(v);
            continue;
        }
        if let Some(v) = parse_flag_value(&args, &mut i, "--diagnose")
            .or_else(|| parse_flag_value(&args, &mut i, "--doctor"))
        {
            diagnose_domain = Some(v);
            continue;
        }
        i += 1;
    }

    if let Some(domain) = diagnose_domain {
        #[cfg(windows)]
        unsafe {
            let _ = windows_sys::Win32::System::Console::AttachConsole(u32::MAX);
        }
        ui::run_cli_domain_doctor(&domain, dns_spec.as_deref(), quic_mode.as_deref());
        return;
    }

    ui::run_win32_ui(ui::LaunchOptions {
        elevated_start,
        strategy_path,
        dns_spec,
        quic_mode,
    });
}
