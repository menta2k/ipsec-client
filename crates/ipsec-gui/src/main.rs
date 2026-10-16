//! `ipsec-gui`: the unprivileged, cross-platform window + tray for the IPsec
//! client. It only talks to `ipsec-service` over IPC (Constitution II).
//!
//! `--tray` starts hidden in the tray (for autostart).

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod conn;
mod tray;
mod views;

use eframe::egui;

fn main() -> eframe::Result {
    let start_hidden = std::env::args().any(|a| a == "--tray");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("IPsec Client")
            .with_inner_size([640.0, 520.0])
            .with_min_inner_size([480.0, 380.0]),
        ..Default::default()
    };
    eframe::run_native(
        "IPsec Client",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, start_hidden)))),
    )
}
