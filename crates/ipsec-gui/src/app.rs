//! The GUI application: state, message handling, tray integration and the
//! window shell (tabs, banners, password prompt). Views live in `views/`.

use crate::conn::{Backend, Tag, UiMsg, Wake};
use crate::tray::{Tray, TrayAction};
use crate::views::profiles::Editor;
use eframe::egui;
use ipc_proto::*;
use std::collections::VecDeque;
use std::sync::Arc;

const MAX_LOG_LINES: usize = 2000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Status,
    Profiles,
    Log,
}

pub enum ServiceLink {
    Unknown,
    Online,
    Offline(String),
    Incompatible(String),
    /// Running, but this user may not control it (002 FR-017).
    Unauthorized,
}

/// Banner for a user without access. It must not read like an outage.
pub const UNAUTHORIZED_TEXT: &str = if cfg!(target_os = "linux") {
    "You are not allowed to control the VPN. Ask an administrator to add you to the \
     'ipsec-client' group, then log in again."
} else {
    "You are not allowed to control the VPN on this computer. Ask an administrator for access."
};

/// Pending password prompt for an EAP profile without a saved password.
pub struct PasswordPrompt {
    pub profile_id: String,
    pub profile_name: String,
    pub password: SecretString,
    pub save: bool,
}

pub struct App {
    pub backend: Backend,
    pub link: ServiceLink,
    pub state: ConnectionState,
    pub session: Option<SessionInfo>,
    pub profiles: Vec<ProfileView>,
    pub logs: VecDeque<LogLine>,
    pub tab: Tab,
    pub editor: Option<Editor>,
    pub prompt: Option<PasswordPrompt>,
    /// Transient feedback (e.g. a failed request).
    pub notice: Option<String>,
    pub selected_profile: Option<String>,
    pub log_level: usize,
    tray: Option<Tray>,
    quitting: bool,
    /// State before the latest transition (for notifications).
    was_connected: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, start_hidden: bool) -> App {
        let ctx = cc.egui_ctx.clone();
        let wake: Wake = Arc::new(move || ctx.request_repaint());
        let tray = match Tray::create(wake.clone()) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("warning: system tray unavailable ({e}); the window stays available and closing it minimizes");
                None
            }
        };
        if start_hidden && tray.is_some() {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        App {
            backend: Backend::start(wake),
            link: ServiceLink::Unknown,
            state: ConnectionState::Disconnected,
            session: None,
            profiles: Vec::new(),
            logs: VecDeque::new(),
            tab: Tab::Status,
            editor: None,
            prompt: None,
            notice: None,
            selected_profile: None,
            log_level: 2,
            tray,
            quitting: false,
            was_connected: false,
        }
    }

    pub fn profile_name(&self, id: &str) -> String {
        self.profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    /// Start connecting, prompting for a password when needed (FR-032).
    pub fn request_connect(&mut self, id: &str) {
        let Some(p) = self.profiles.iter().find(|p| p.id == id) else {
            return;
        };
        if p.auth == AuthMode::Eap && !p.has_password {
            self.prompt = Some(PasswordPrompt {
                profile_id: p.id.clone(),
                profile_name: p.name.clone(),
                password: SecretString::default(),
                save: false,
            });
            return;
        }
        self.backend.send(
            Tag::Connect,
            Request::Connect {
                id: id.to_string(),
                password: None,
                save_password: false,
            },
        );
    }

    pub fn request_disconnect(&mut self) {
        self.backend.send(Tag::Disconnect, Request::Disconnect);
    }

    fn refresh_tray(&mut self) {
        if let Some(t) = &mut self.tray {
            t.update(&self.state, &self.profiles);
        }
    }

    fn on_state(&mut self, s: ConnectionState) {
        let name = |id: &str| self.profile_name(id);
        match &s {
            ConnectionState::Connected { profile_id } => {
                let ip = self
                    .session
                    .as_ref()
                    .and_then(|x| x.assigned_ip.clone())
                    .unwrap_or_default();
                notify("VPN connected", &format!("{} — {}", name(profile_id), ip));
                self.was_connected = true;
            }
            ConnectionState::Error { message, .. } => {
                let title = if self.was_connected {
                    "VPN connection lost"
                } else {
                    "VPN connection failed"
                };
                notify(title, message);
                self.was_connected = false;
            }
            ConnectionState::Disconnected => self.was_connected = false,
            _ => {}
        }
        if !s.is_active() {
            self.session = None;
        }
        self.state = s;
        self.refresh_tray();
    }

    fn handle(&mut self, msg: UiMsg) {
        match msg {
            UiMsg::Online(snap) => {
                self.link = ServiceLink::Online;
                self.session = snap.session;
                self.was_connected = matches!(snap.state, ConnectionState::Connected { .. });
                self.state = snap.state;
                self.logs = snap.recent_logs.into();
                self.backend.send(Tag::Profiles, Request::ListProfiles);
                self.refresh_tray();
            }
            UiMsg::Offline(m) => {
                self.link = ServiceLink::Offline(m);
                self.state = ConnectionState::Disconnected;
                self.session = None;
                self.refresh_tray();
            }
            UiMsg::Unauthorized => {
                // No profile, status or log data for users without access.
                self.link = ServiceLink::Unauthorized;
                self.state = ConnectionState::Disconnected;
                self.session = None;
                self.profiles.clear();
                self.logs.clear();
                self.refresh_tray();
            }
            UiMsg::Incompatible(m) => self.link = ServiceLink::Incompatible(m),
            UiMsg::Event(Event::State { state }) => self.on_state(state),
            UiMsg::Event(Event::Session { session }) => self.session = Some(session),
            UiMsg::Event(Event::Log { line }) => {
                self.logs.push_back(line);
                while self.logs.len() > MAX_LOG_LINES {
                    self.logs.pop_front();
                }
            }
            UiMsg::Event(Event::ProfilesChanged) => {
                self.backend.send(Tag::Profiles, Request::ListProfiles)
            }
            UiMsg::Reply(tag, result) => self.on_reply(tag, result),
        }
    }

    fn on_reply(&mut self, tag: Tag, result: Result<Response, String>) {
        match (tag, result) {
            (Tag::Profiles, Ok(Response::Profiles { profiles })) => {
                self.profiles = profiles;
                self.refresh_tray();
            }
            (Tag::SaveProfile, Ok(Response::Profile { profile })) => {
                self.selected_profile = Some(profile.id.clone());
                self.editor = None;
                self.notice = Some(format!("Saved profile \"{}\"", profile.name));
            }
            (Tag::SaveProfile, Err(e)) => {
                if let Some(ed) = &mut self.editor {
                    ed.error = Some(e);
                }
            }
            (Tag::DeleteProfile, Ok(_)) => {
                self.selected_profile = None;
                self.editor = None;
            }
            (_, Err(e)) => self.notice = Some(e),
            _ => {}
        }
    }

    fn on_tray(&mut self, ctx: &egui::Context, a: TrayAction) {
        match a {
            TrayAction::Connect(id) => {
                self.request_connect(&id);
                if self.prompt.is_some() {
                    show_window(ctx);
                }
            }
            TrayAction::Disconnect => self.request_disconnect(),
            TrayAction::Open => show_window(ctx),
            TrayAction::Quit => {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn banner(&self, ui: &mut egui::Ui) {
        let (text, color) = match &self.link {
            ServiceLink::Online => return,
            ServiceLink::Unknown => ("Connecting to the VPN service…".to_string(), egui::Color32::GRAY),
            ServiceLink::Offline(m) => (
                format!(
                    "Service not running. Ask an administrator to run `ipsec-service install`. ({m}) Retrying automatically…"
                ),
                egui::Color32::from_rgb(0xd6, 0x3a, 0x3a),
            ),
            ServiceLink::Incompatible(m) => (format!("Client and service versions are incompatible: {m}"), egui::Color32::from_rgb(0xd6, 0x3a, 0x3a)),
            ServiceLink::Unauthorized => (UNAUTHORIZED_TEXT.to_string(), egui::Color32::from_rgb(0xe8, 0xa3, 0x17)),
        };
        egui::Frame::new()
            .fill(color.gamma_multiply(0.15))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.colored_label(color, text);
            });
    }

    fn password_dialog(&mut self, ctx: &egui::Context) {
        let Some(p) = &mut self.prompt else { return };
        let mut submit = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::unique("password-prompt")).show(ctx, |ui| {
            ui.set_width(320.0);
            ui.heading(format!("Connect to {}", p.profile_name));
            ui.add_space(6.0);
            ui.label("Password");
            let mut pw = p.password.expose().to_string();
            let r = ui.add(
                egui::TextEdit::singleline(&mut pw)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            p.password = SecretString::new(pw);
            r.request_focus();
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            ui.checkbox(&mut p.save, "Save password (encrypted by the service)");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!p.password.is_empty(), egui::Button::new("Connect"))
                    .clicked()
                {
                    submit = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if submit && !p.password.is_empty() {
            let p = self.prompt.take().expect("prompt");
            self.backend.send(
                Tag::Connect,
                Request::Connect {
                    id: p.profile_id,
                    password: Some(p.password),
                    save_password: p.save,
                },
            );
        } else if cancel {
            self.prompt = None;
        }
    }
}

fn show_window(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}

/// Desktop notification, off the UI thread.
#[cfg(not(target_os = "macos"))]
fn notify(summary: &str, body: &str) {
    let (s, b) = (summary.to_string(), body.to_string());
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .appname("IPsec Client")
            .summary(&s)
            .body(&b)
            .show();
    });
}

/// macOS: native notifications arrive with 004 T049.
#[cfg(target_os = "macos")]
fn notify(_summary: &str, _body: &str) {}

/// What closing the window does (002 FR-022).
#[derive(Debug, PartialEq, Eq)]
pub enum CloseAction {
    /// Keep running in the tray.
    HideToTray,
    /// No tray to come back from: minimize instead of vanishing.
    Minimize,
    Exit,
}

pub fn close_action(has_tray: bool, quitting: bool) -> CloseAction {
    match (quitting, has_tray) {
        (true, _) => CloseAction::Exit,
        (false, true) => CloseAction::HideToTray,
        (false, false) => CloseAction::Minimize,
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(m) = self.backend.rx.try_recv() {
            self.handle(m);
        }
        let actions: Vec<TrayAction> = self
            .tray
            .as_ref()
            .map(|t| t.actions.try_iter().collect())
            .unwrap_or_default();
        for a in actions {
            self.on_tray(ctx, a);
        }
        // Closing hides to the tray; without a tray it minimizes (the window
        // is the only way back). "Quit" really exits.
        if ctx.input(|i| i.viewport().close_requested()) {
            match close_action(self.tray.is_some(), self.quitting) {
                CloseAction::HideToTray => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
                CloseAction::Minimize => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
                CloseAction::Exit => {}
            }
        }
        // Tick the connected-duration display.
        if matches!(self.state, ConnectionState::Connected { .. }) {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("tabs").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Profiles, "Profiles");
                ui.selectable_value(&mut self.tab, Tab::Log, "Log");
                // Without a tray, closing only minimizes; this is the way out.
                if self.tray.is_none() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Quit").clicked() {
                            self.quitting = true;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                }
            });
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            self.banner(ui);
            if let Some(n) = self.notice.clone() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(n).italics());
                    if ui.small_button("✕").clicked() {
                        self.notice = None;
                    }
                });
            }
            match self.tab {
                Tab::Status => self.status_view(ui),
                Tab::Profiles => self.profiles_view(ui),
                Tab::Log => self.log_view(ui),
            }
        });
        self.password_dialog(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_the_window_depends_on_the_tray() {
        assert_eq!(close_action(true, false), CloseAction::HideToTray);
        assert_eq!(close_action(false, false), CloseAction::Minimize);
        // An explicit Quit always exits.
        assert_eq!(close_action(true, true), CloseAction::Exit);
        assert_eq!(close_action(false, true), CloseAction::Exit);
    }
}
