#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod dns_guard;
mod integrity;
mod net_optimizer;
mod permissions;
mod tray;
mod ui;
mod windivert;

fn main() {
    let elevated_start = std::env::args().any(|a| a == "--elevated-start" || a == "--autostart");
    ui::run_win32_ui(elevated_start);
}
