//! Profiles view (FR-029..FR-032): list + editor. Secrets are write-only:
//! a stored secret shows as "•••• (saved)" and can be replaced or cleared,
//! never revealed.

use crate::app::App;
use crate::conn::Tag;
use eframe::egui::{self, RichText};
use ipc_proto::*;

/// Edit state for one stored secret.
#[derive(Default)]
pub struct SecretField {
    pub saved: bool,
    pub replacing: bool,
    pub cleared: bool,
    pub value: SecretString,
}

impl SecretField {
    fn new(saved: bool) -> Self {
        SecretField {
            saved,
            ..Default::default()
        }
    }

    fn update(&self) -> SecretUpdate {
        if self.cleared && !self.replacing {
            SecretUpdate::Clear
        } else if (self.replacing || !self.saved) && !self.value.is_empty() {
            SecretUpdate::Set(self.value.clone())
        } else {
            SecretUpdate::Keep
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, id: &str) {
        if self.saved && !self.replacing && !self.cleared {
            ui.horizontal(|ui| {
                ui.label("•••• (saved)");
                if ui.small_button("Replace").clicked() {
                    self.replacing = true;
                }
                if ui.small_button("Clear").clicked() {
                    self.cleared = true;
                }
            });
        } else {
            ui.horizontal(|ui| {
                let mut v = self.value.expose().to_string();
                ui.add(
                    egui::TextEdit::singleline(&mut v)
                        .password(true)
                        .id_salt(id)
                        .desired_width(220.0),
                );
                self.value = SecretString::new(v);
                if self.saved && ui.small_button("Keep saved").clicked() {
                    *self = SecretField::new(true);
                }
            });
            if self.cleared && !self.replacing {
                ui.label(RichText::new("will be removed on save").italics());
            }
        }
    }
}

pub struct Editor {
    /// `None` when creating a new profile.
    pub id: Option<String>,
    pub edit: ProfileEdit,
    pub psk: SecretField,
    pub password: SecretField,
    pub error: Option<String>,
    /// Offered at the Windows sign-in screen (003); shown, never edited here.
    pub sign_in: bool,
}

/// Text of a profile in the list: sign-in profiles are marked (003 FR-018).
pub fn list_label(p: &ProfileView) -> String {
    if p.sign_in {
        format!("{}  (sign-in)", p.name)
    } else {
        p.name.clone()
    }
}

/// Read-only note in the editor for sign-in profiles.
pub const SIGN_IN_NOTE: &str = "Available at sign-in (set by an administrator)";
pub const SIGN_IN_HINT: &str =
    "Administrators change this with `ipsec-service plc enable|disable <name>`.";

impl Editor {
    pub fn new_profile() -> Self {
        Editor {
            id: None,
            edit: ProfileEdit::default(),
            psk: SecretField::new(false),
            password: SecretField::new(false),
            error: None,
            sign_in: false,
        }
    }

    pub fn for_profile(v: &ProfileView) -> Self {
        Editor {
            id: Some(v.id.clone()),
            edit: ProfileEdit::from_view(v),
            psk: SecretField::new(v.has_psk),
            password: SecretField::new(v.has_password),
            error: None,
            sign_in: v.sign_in,
        }
    }

    /// Quick client-side checks; the service validates authoritatively.
    fn local_error(&self) -> Option<String> {
        if self.edit.name.trim().is_empty() {
            return Some("Name is required".into());
        }
        if self.edit.gateway.trim().is_empty() {
            return Some("Gateway is required".into());
        }
        if self.edit.local_id.trim().is_empty() {
            return Some("Local identity is required".into());
        }
        if self.edit.auth == AuthMode::Eap && self.edit.username.trim().is_empty() {
            return Some("Username is required for EAP".into());
        }
        None
    }
}

impl App {
    pub fn profiles_view(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("profile-list")
            .resizable(true)
            .default_size(180.0)
            .show(ui, |ui| {
                ui.add_space(6.0);
                if ui.button("➕ New profile").clicked() {
                    self.editor = Some(Editor::new_profile());
                }
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for p in self.profiles.clone() {
                        let selected = self.editor.as_ref().and_then(|e| e.id.as_deref())
                            == Some(p.id.as_str());
                        if ui.selectable_label(selected, list_label(&p)).clicked() {
                            self.editor = Some(Editor::for_profile(&p));
                        }
                    }
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            let in_use = |id: &Option<String>| -> bool {
                match (&self.state, id) {
                    (ConnectionState::Connecting { profile_id, .. }, Some(id))
                    | (ConnectionState::Authenticating { profile_id }, Some(id))
                    | (ConnectionState::Connected { profile_id }, Some(id)) => profile_id == id,
                    _ => false,
                }
            };
            let Some(ed) = &mut self.editor else {
                ui.label("Select a profile, or create a new one.");
                return;
            };
            let busy = in_use(&ed.id);
            ui.heading(if ed.id.is_some() {
                "Edit profile"
            } else {
                "New profile"
            });
            ui.add_space(6.0);
            egui::Grid::new("editor")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut ed.edit.name);
                    ui.end_row();

                    ui.label("Gateway");
                    ui.text_edit_singleline(&mut ed.edit.gateway);
                    ui.end_row();

                    ui.label("Port");
                    ui.add(egui::DragValue::new(&mut ed.edit.port).range(1..=65535));
                    ui.end_row();

                    ui.label("Local identity");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut ed.edit.local_id);
                        egui::ComboBox::from_id_salt("idtype")
                            .selected_text(match ed.edit.id_type {
                                IdType::Fqdn => "FQDN",
                                IdType::Email => "Email",
                                IdType::Ipv4 => "IPv4",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut ed.edit.id_type, IdType::Fqdn, "FQDN");
                                ui.selectable_value(&mut ed.edit.id_type, IdType::Email, "Email");
                                ui.selectable_value(&mut ed.edit.id_type, IdType::Ipv4, "IPv4");
                            });
                    });
                    ui.end_row();

                    ui.label("DH group");
                    egui::ComboBox::from_id_salt("dh")
                        .selected_text(match ed.edit.dh_group {
                            DhGroupSel::Modp2048 => "MODP-2048 (group 14)",
                            DhGroupSel::Modp1536 => "MODP-1536 (group 5)",
                            DhGroupSel::X25519 => "Curve25519 (group 31)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut ed.edit.dh_group,
                                DhGroupSel::Modp2048,
                                "MODP-2048 (group 14)",
                            );
                            ui.selectable_value(
                                &mut ed.edit.dh_group,
                                DhGroupSel::Modp1536,
                                "MODP-1536 (group 5)",
                            );
                            ui.selectable_value(
                                &mut ed.edit.dh_group,
                                DhGroupSel::X25519,
                                "Curve25519 (group 31)",
                            );
                        });
                    ui.end_row();

                    ui.label("Authentication");
                    ui.horizontal(|ui| {
                        ui.radio_value(
                            &mut ed.edit.auth,
                            AuthMode::Eap,
                            "Username + password (EAP)",
                        );
                        ui.radio_value(&mut ed.edit.auth, AuthMode::Psk, "Pre-shared key only");
                    });
                    ui.end_row();

                    ui.label("Pre-shared key");
                    ed.psk.ui(ui, "psk");
                    ui.end_row();

                    if ed.edit.auth == AuthMode::Eap {
                        ui.label("Username");
                        ui.text_edit_singleline(&mut ed.edit.username);
                        ui.end_row();

                        ui.label("Saved password");
                        ed.password.ui(ui, "password");
                        ui.end_row();

                        ui.label("");
                        ui.checkbox(
                            &mut ed.edit.auto_reconnect,
                            "Reconnect automatically when the connection drops",
                        );
                        ui.end_row();
                    } else {
                        ui.label("");
                        ui.checkbox(
                            &mut ed.edit.auto_reconnect,
                            "Reconnect automatically when the connection drops",
                        );
                        ui.end_row();
                    }
                });

            if ed.sign_in {
                ui.add_space(4.0);
                ui.label(RichText::new(SIGN_IN_NOTE).weak())
                    .on_hover_text(SIGN_IN_HINT);
            }
            if let Some(e) = &ed.error {
                ui.colored_label(egui::Color32::from_rgb(0xd6, 0x3a, 0x3a), e);
            }
            ui.add_space(8.0);
            let mut save = false;
            let mut delete = false;
            let mut duplicate = false;
            let mut close = false;
            ui.horizontal(|ui| {
                save = ui.button("Save").clicked();
                if ed.id.is_some() {
                    duplicate = ui.button("Duplicate").clicked();
                    delete = ui
                        .add_enabled(!busy, egui::Button::new("Delete"))
                        .on_disabled_hover_text("Disconnect before deleting the profile in use")
                        .clicked();
                }
                close = ui.button("Close").clicked();
            });

            if save {
                if let Some(err) = ed.local_error() {
                    ed.error = Some(err);
                } else {
                    let mut edit = ed.edit.clone();
                    edit.psk = ed.psk.update();
                    edit.password = if edit.auth == AuthMode::Eap {
                        ed.password.update()
                    } else {
                        SecretUpdate::Clear
                    };
                    let req = match &ed.id {
                        Some(id) => Request::UpdateProfile {
                            id: id.clone(),
                            profile: edit,
                        },
                        None => Request::CreateProfile { profile: edit },
                    };
                    self.backend.send(Tag::SaveProfile, req);
                }
            } else if duplicate {
                let mut copy = Editor::new_profile();
                copy.edit = ed.edit.clone();
                copy.edit.name = format!("{} (copy)", ed.edit.name);
                copy.error =
                    Some("Secrets are not copied; enter the pre-shared key for the copy.".into());
                self.editor = Some(copy);
            } else if delete {
                if let Some(id) = ed.id.clone() {
                    self.backend
                        .send(Tag::DeleteProfile, Request::DeleteProfile { id });
                }
            } else if close {
                self.editor = None;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_profiles_are_marked_and_kept_read_only() {
        let mut v = ProfileView {
            name: "Office".into(),
            ..Default::default()
        };
        assert_eq!(list_label(&v), "Office");
        assert!(!Editor::for_profile(&v).sign_in);
        v.sign_in = true;
        assert_eq!(list_label(&v), "Office  (sign-in)");
        let ed = Editor::for_profile(&v);
        assert!(ed.sign_in);
        // The edit sent on save has no way to carry the flag.
        let wire = serde_json::to_string(&ed.edit).unwrap();
        assert!(!wire.contains("sign_in"), "{wire}");
    }
}
