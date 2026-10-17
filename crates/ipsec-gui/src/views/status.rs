//! Status view (FR-036): state, session details, counters, connect controls.

use super::{human_bytes, human_duration};
use crate::app::{App, ServiceLink};
use eframe::egui::{self, Color32, RichText};
use ipc_proto::ConnectionState;
use std::time::{SystemTime, UNIX_EPOCH};

fn state_color(s: &ConnectionState) -> Color32 {
    match s {
        ConnectionState::Connected { .. } => Color32::from_rgb(0x2e, 0xa0, 0x43),
        ConnectionState::Error { .. } => Color32::from_rgb(0xd6, 0x3a, 0x3a),
        ConnectionState::Disconnected => Color32::GRAY,
        _ => Color32::from_rgb(0xe8, 0xa3, 0x17),
    }
}

impl App {
    pub fn status_view(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        let state = self.state.clone();
        let label = match &state {
            ConnectionState::Connecting { attempt, .. } if *attempt > 1 => {
                format!("Connecting (attempt {attempt})")
            }
            s => s.label().to_string(),
        };
        ui.label(
            RichText::new(label)
                .size(26.0)
                .strong()
                .color(state_color(&state)),
        );
        if let ConnectionState::Error { message, .. } = &state {
            ui.label(RichText::new(message).color(state_color(&state)));
        }
        ui.add_space(10.0);

        let online = matches!(self.link, ServiceLink::Online);
        ui.horizontal(|ui| {
            if state.is_active() {
                let can = !matches!(state, ConnectionState::Disconnecting);
                if ui
                    .add_enabled(online && can, egui::Button::new("Disconnect"))
                    .clicked()
                {
                    self.request_disconnect();
                }
            } else {
                if self
                    .selected_profile
                    .as_ref()
                    .is_none_or(|id| !self.profiles.iter().any(|p| &p.id == id))
                {
                    self.selected_profile = self.profiles.first().map(|p| p.id.clone());
                }
                let current = self
                    .selected_profile
                    .as_deref()
                    .map(|id| self.profile_name(id))
                    .unwrap_or_else(|| "(no profiles)".into());
                egui::ComboBox::from_id_salt("status-profile")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for p in &self.profiles {
                            ui.selectable_value(
                                &mut self.selected_profile,
                                Some(p.id.clone()),
                                &p.name,
                            );
                        }
                    });
                let id = self.selected_profile.clone();
                if ui
                    .add_enabled(online && id.is_some(), egui::Button::new("Connect"))
                    .clicked()
                {
                    if let Some(id) = id {
                        self.request_connect(&id);
                    }
                }
            }
        });
        if self.profiles.is_empty() && online {
            ui.label("No profiles yet — create one on the Profiles tab.");
        }
        ui.add_space(12.0);

        let Some(s) = self.session.clone() else {
            return;
        };
        egui::Grid::new("session")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .striped(true)
            .show(ui, |ui| {
                let row = |ui: &mut egui::Ui, k: &str, v: String| {
                    ui.label(RichText::new(k).strong());
                    ui.label(v);
                    ui.end_row();
                };
                row(ui, "Profile", s.profile_name.clone());
                row(
                    ui,
                    "Gateway",
                    format!(
                        "{}{}",
                        s.gateway,
                        if s.nat_detected { "  (NAT-T)" } else { "" }
                    ),
                );
                row(
                    ui,
                    "Assigned IP",
                    s.assigned_ip.clone().unwrap_or_else(|| "—".into()),
                );
                row(
                    ui,
                    "DNS",
                    if s.dns.is_empty() {
                        "—".into()
                    } else {
                        s.dns.join(", ")
                    },
                );
                row(ui, "Routes", s.remote_ts.join(", "));
                if let Some(since) = s.connected_since_unix {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(since);
                    row(
                        ui,
                        "Connected for",
                        human_duration(now.saturating_sub(since)),
                    );
                }
                row(
                    ui,
                    "Received",
                    format!(
                        "{}  ({} packets)",
                        human_bytes(s.stats.bytes_in),
                        s.stats.packets_in
                    ),
                );
                row(
                    ui,
                    "Sent",
                    format!(
                        "{}  ({} packets)",
                        human_bytes(s.stats.bytes_out),
                        s.stats.packets_out
                    ),
                );
                if s.stats.dropped_in + s.stats.dropped_out > 0 {
                    row(
                        ui,
                        "Dropped",
                        format!("{} in / {} out", s.stats.dropped_in, s.stats.dropped_out),
                    );
                }
                if s.stats.filtered_out > 0 {
                    row(
                        ui,
                        "Not tunneled",
                        format!("{} (IPv6, multicast, broadcast)", s.stats.filtered_out),
                    );
                }
                row(ui, "IKE", s.ike_suite.clone());
                row(ui, "ESP", s.esp_suite.clone());
            });
    }
}
