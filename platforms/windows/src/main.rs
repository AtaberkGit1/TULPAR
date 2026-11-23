#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod dns_guard;
mod integrity;
mod permissions;
mod tray;
mod ui;
mod windivert;

fn main() {
    let autostart = std::env::args().any(|a| a == "--autostart");
    ui::run_win32_ui(autostart);
}
