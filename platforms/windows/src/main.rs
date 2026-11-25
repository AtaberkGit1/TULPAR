#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod dns_guard;
mod integrity;
mod net_optimizer;
mod permissions;
mod tray;
mod ui;
mod windivert;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let elevated_start = args.iter().any(|a| a == "--elevated-start" || a == "--autostart");
    let mut strategy_path: Option<PathBuf> = None;
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--strategy" {
            if let Some(p) = args.get(i + 1) {
                strategy_path = Some(PathBuf::from(p));
                i += 2;
                continue;
            }
        } else if let Some(p) = args[i].strip_prefix("--strategy=") {
            strategy_path = Some(PathBuf::from(p));
        }
        i += 1;
    }
    ui::run_win32_ui(elevated_start, strategy_path);
}
