//! System tray icon and menu (FR-033, FR-034).
//!
//! Icons are drawn in code (a coloured disc per state), so no image assets or
//! decoders are needed. Menu clicks are forwarded through a channel plus a
//! wake-up so they are handled even while the window is hidden.
//!
//! Windows/macOS: the tray is created on the main (event-loop) thread.
//! Linux: tray-icon needs a GTK main loop, so a dedicated thread owns it and
//! receives updates over a channel.

use crate::conn::Wake;
use ipc_proto::{ConnectionState, ProfileView};
use std::sync::mpsc::{channel, Receiver, Sender};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub const ID_DISCONNECT: &str = "disconnect";
pub const ID_OPEN: &str = "open";
pub const ID_QUIT: &str = "quit";
pub const CONNECT_PREFIX: &str = "connect:";

/// What a menu click asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrayAction {
    Connect(String),
    Disconnect,
    Open,
    Quit,
}

fn parse(id: &str) -> Option<TrayAction> {
    match id {
        ID_DISCONNECT => Some(TrayAction::Disconnect),
        ID_OPEN => Some(TrayAction::Open),
        ID_QUIT => Some(TrayAction::Quit),
        s => s
            .strip_prefix(CONNECT_PREFIX)
            .map(|p| TrayAction::Connect(p.to_string())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Look {
    Off,
    Busy,
    On,
    Error,
}

fn look(state: &ConnectionState) -> Look {
    match state {
        ConnectionState::Disconnected => Look::Off,
        ConnectionState::Connecting { .. }
        | ConnectionState::Authenticating { .. }
        | ConnectionState::Disconnecting => Look::Busy,
        ConnectionState::Connected { .. } => Look::On,
        ConnectionState::Error { .. } => Look::Error,
    }
}

/// A 32x32 RGBA disc with a light rim; a padlock-like dark core when on.
fn draw_icon(l: Look) -> Icon {
    const N: u32 = 32;
    let (r, g, b) = match l {
        Look::Off => (0x8a, 0x8f, 0x98),
        Look::Busy => (0xe8, 0xa3, 0x17),
        Look::On => (0x2e, 0xa0, 0x43),
        Look::Error => (0xd6, 0x3a, 0x3a),
    };
    let mut px = Vec::with_capacity((N * N * 4) as usize);
    let c = (N as f32 - 1.0) / 2.0;
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let (pr, pg, pb, a) = if d > 15.5 {
                (0, 0, 0, 0)
            } else if d > 13.5 {
                (0xff, 0xff, 0xff, 0xe0)
            } else if l == Look::On && d < 5.0 {
                (0xff, 0xff, 0xff, 0xff)
            } else {
                (r, g, b, 0xff)
            };
            px.extend_from_slice(&[pr, pg, pb, a]);
        }
    }
    Icon::from_rgba(px, N, N).expect("valid icon")
}

fn tooltip(state: &ConnectionState) -> String {
    match state {
        ConnectionState::Error { message, .. } => format!("IPsec Client — Error: {message}"),
        s => format!("IPsec Client — {}", s.label()),
    }
}

fn build_menu(state: &ConnectionState, profiles: &[ProfileView]) -> Menu {
    let menu = Menu::new();
    let active = state.is_active();
    let connect = Submenu::new("Connect", !active && !profiles.is_empty());
    for p in profiles {
        let _ = connect.append(&MenuItem::with_id(
            format!("{CONNECT_PREFIX}{}", p.id),
            &p.name,
            true,
            None,
        ));
    }
    let _ = menu.append_items(&[
        &connect,
        &MenuItem::with_id(ID_DISCONNECT, "Disconnect", active, None),
        &PredefinedMenuItem::separator(),
        &MenuItem::with_id(ID_OPEN, "Open window", true, None),
        &MenuItem::with_id(ID_QUIT, "Quit", true, None),
    ]);
    menu
}

struct TrayCore {
    icon: TrayIcon,
    look: Option<Look>,
}

impl TrayCore {
    fn new(state: &ConnectionState, profiles: &[ProfileView]) -> Result<Self, String> {
        let l = look(state);
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(build_menu(state, profiles)))
            .with_icon(draw_icon(l))
            .with_tooltip(tooltip(state))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(TrayCore {
            icon,
            look: Some(l),
        })
    }

    fn update(&mut self, state: &ConnectionState, profiles: &[ProfileView]) {
        let l = look(state);
        if self.look != Some(l) {
            let _ = self.icon.set_icon(Some(draw_icon(l)));
            self.look = Some(l);
        }
        let _ = self.icon.set_tooltip(Some(tooltip(state)));
        self.icon
            .set_menu(Some(Box::new(build_menu(state, profiles))));
    }
}

/// Handle to the tray, whichever thread owns it.
pub struct Tray {
    #[cfg(not(target_os = "linux"))]
    core: TrayCore,
    #[cfg(target_os = "linux")]
    updates: Sender<(ConnectionState, Vec<ProfileView>)>,
    pub actions: Receiver<TrayAction>,
}

impl Tray {
    /// Create the tray. Must be called on the main thread on Windows/macOS.
    pub fn create(wake: Wake) -> Result<Tray, String> {
        let (tx, actions) = channel();
        install_menu_handler(tx, wake);
        #[cfg(not(target_os = "linux"))]
        {
            let core = TrayCore::new(&ConnectionState::Disconnected, &[])?;
            Ok(Tray { core, actions })
        }
        #[cfg(target_os = "linux")]
        {
            let (updates, rx) = channel::<(ConnectionState, Vec<ProfileView>)>();
            let (ready_tx, ready_rx) = channel();
            std::thread::Builder::new()
                .name("tray-gtk".into())
                .spawn(move || linux_tray_thread(rx, ready_tx))
                .map_err(|e| e.to_string())?;
            ready_rx
                .recv()
                .map_err(|_| "tray thread died".to_string())??;
            Ok(Tray { updates, actions })
        }
    }

    pub fn update(&mut self, state: &ConnectionState, profiles: &[ProfileView]) {
        #[cfg(not(target_os = "linux"))]
        self.core.update(state, profiles);
        #[cfg(target_os = "linux")]
        let _ = self.updates.send((state.clone(), profiles.to_vec()));
    }
}

fn install_menu_handler(tx: Sender<TrayAction>, wake: Wake) {
    let tx = std::sync::Mutex::new(tx);
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        if let Some(a) = parse(e.id().as_ref()) {
            let _ = tx.lock().unwrap().send(a);
            wake();
        }
    }));
}

#[cfg(target_os = "linux")]
fn linux_tray_thread(
    rx: Receiver<(ConnectionState, Vec<ProfileView>)>,
    ready: Sender<Result<(), String>>,
) {
    if let Err(e) = gtk::init() {
        let _ = ready.send(Err(format!("GTK init failed: {e}")));
        return;
    }
    let mut core = match TrayCore::new(&ConnectionState::Disconnected, &[]) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    loop {
        while gtk::events_pending() {
            gtk::main_iteration();
        }
        loop {
            match rx.try_recv() {
                Ok((s, p)) => core.update(&s, &p),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_ids_parse() {
        assert_eq!(
            parse("connect:abc"),
            Some(TrayAction::Connect("abc".into()))
        );
        assert_eq!(parse(ID_DISCONNECT), Some(TrayAction::Disconnect));
        assert_eq!(parse(ID_QUIT), Some(TrayAction::Quit));
        assert_eq!(parse("nope"), None);
    }

    #[test]
    fn looks_follow_state() {
        assert_eq!(look(&ConnectionState::Disconnected), Look::Off);
        assert_eq!(
            look(&ConnectionState::Connected {
                profile_id: "x".into()
            }),
            Look::On
        );
        assert_eq!(
            look(&ConnectionState::Authenticating {
                profile_id: "x".into()
            }),
            Look::Busy
        );
    }
}
