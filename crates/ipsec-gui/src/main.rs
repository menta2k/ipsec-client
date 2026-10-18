//! `ipsec-gui`: the unprivileged, cross-platform window + tray for the IPsec
//! client. It only talks to `ipsec-service` over IPC (Constitution II).
//!
//! `--tray` starts hidden in the tray (for autostart).

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod conn;
mod icon;
mod icon_export;
#[cfg(windows)]
mod pipe_owner;
mod tray;
mod views;

use eframe::egui;

/// Linux (002 research R9): winit cannot hide a window on Wayland, which the
/// close-to-tray behaviour relies on. When XWayland is available (`DISPLAY`
/// set), drop `WAYLAND_DISPLAY` so winit uses X11. Without XWayland the app
/// stays on Wayland and behaves as if there were no tray.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn should_drop_wayland(display: bool, wayland: bool) -> bool {
    display && wayland
}

fn main() -> eframe::Result {
    #[cfg(target_os = "linux")]
    if should_drop_wayland(
        std::env::var_os("DISPLAY").is_some(),
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
    ) {
        // Sound: first thing in main, before any thread exists.
        std::env::remove_var("WAYLAND_DISPLAY");
    }
    // Verify who serves the service pipe before sending it anything.
    #[cfg(windows)]
    ipc_proto::client::set_pipe_owner_probe(pipe_owner::owner_sid);
    // Packaging helper (not for users): write the PNG icon theme and exit.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--write-icons") {
        let Some(dir) = args.get(i + 1) else {
            eprintln!("usage: ipsec-gui --write-icons <dir>");
            std::process::exit(2);
        };
        match icon_export::write_icons(std::path::Path::new(dir)) {
            Ok(files) => {
                for f in files {
                    println!("{}", f.display());
                }
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    let start_hidden = args.iter().any(|a| a == "--tray");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("IPsec Client")
            .with_inner_size([640.0, 520.0])
            .with_min_inner_size([480.0, 380.0])
            .with_icon(egui::IconData {
                rgba: icon::render(64, icon::APP),
                width: 64,
                height: 64,
            }),
        // macOS (004 T048): a menu-bar app, with no Dock icon even when run
        // outside the app bundle.
        #[cfg(target_os = "macos")]
        event_loop_builder: Some(Box::new(|b| {
            use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
            b.with_activation_policy(ActivationPolicy::Accessory);
        })),
        ..Default::default()
    };
    eframe::run_native(
        "IPsec Client",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, start_hidden)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_is_dropped_only_when_xwayland_is_available() {
        assert!(
            should_drop_wayland(true, true),
            "Wayland session with XWayland"
        );
        assert!(!should_drop_wayland(false, true), "pure Wayland: keep it");
        assert!(
            !should_drop_wayland(true, false),
            "plain X11: nothing to do"
        );
        assert!(!should_drop_wayland(false, false));
    }
}
