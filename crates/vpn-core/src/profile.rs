//! Connection profiles: persisted form, validation (data-model.md) and the
//! secret-free IPC view.

use ipc_proto::{AuthMode, DhGroupSel, IdType, ProfileEdit, ProfileView, SignInProfile};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// A profile as persisted by the service. Secrets are protector-encrypted,
/// hex-encoded blobs and never leave the service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub port: u16,
    pub local_id: String,
    pub id_type: IdType,
    pub dh_group: DhGroupSel,
    pub auth: AuthMode,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub auto_reconnect: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_blob: Option<String>,
    /// Offered at the Windows sign-in screen (003). Changed only through
    /// administrator requests, never by a normal edit.
    #[serde(default)]
    pub sign_in: bool,
}

impl Profile {
    pub fn view(&self) -> ProfileView {
        ProfileView {
            id: self.id.clone(),
            name: self.name.clone(),
            gateway: self.gateway.clone(),
            port: self.port,
            local_id: self.local_id.clone(),
            id_type: self.id_type,
            dh_group: self.dh_group,
            auth: self.auth,
            username: self.username.clone(),
            auto_reconnect: self.auto_reconnect,
            has_psk: self.psk_blob.is_some(),
            has_password: self.password_blob.is_some(),
            sign_in: self.sign_in,
        }
    }

    /// The minimal view the sign-in screen gets (003).
    pub fn sign_in_view(&self) -> SignInProfile {
        SignInProfile {
            id: self.id.clone(),
            name: self.name.clone(),
            auth: self.auth,
            username: self.username.clone(),
        }
    }

    /// True if every secret needed to connect without prompting is stored.
    pub fn has_all_secrets(&self) -> bool {
        self.psk_blob.is_some() && (self.auth == AuthMode::Psk || self.password_blob.is_some())
    }

    /// Copy the non-secret fields of an edit (already normalized/validated).
    pub fn apply_fields(&mut self, e: &ProfileEdit) {
        self.name = e.name.trim().to_string();
        self.gateway = e.gateway.trim().to_string();
        self.port = e.port;
        self.local_id = e.local_id.trim().to_string();
        self.id_type = e.id_type;
        self.dh_group = e.dh_group;
        self.auth = e.auth;
        self.username = if e.auth == AuthMode::Eap {
            e.username.trim().to_string()
        } else {
            String::new()
        };
        self.auto_reconnect = e.auto_reconnect;
    }
}

/// A field-level validation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

fn err(field: &'static str, message: &str) -> FieldError {
    FieldError {
        field,
        message: message.to_string(),
    }
}

/// Validate an edit (uniqueness of the name is checked by the store).
///
/// Rules (data-model.md):
/// * "name 1–64 chars, unique case-insensitive"
/// * "gateway DNS name or IPv4, 1–253 chars, no whitespace"
/// * "port 1–65535 default 500"
/// * "local_id 1–255; ipv4 must parse when id_type=ipv4"
/// * "username required 1–256 when auth=eap"
pub fn validate(e: &ProfileEdit) -> Result<(), FieldError> {
    let name = e.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(err("name", "must be 1–64 characters"));
    }
    let gw = e.gateway.trim();
    if gw.is_empty() || gw.len() > 253 {
        return Err(err("gateway", "must be 1–253 characters"));
    }
    if gw.chars().any(char::is_whitespace) {
        return Err(err("gateway", "must not contain whitespace"));
    }
    let looks_numeric = gw.chars().all(|c| c.is_ascii_digit() || c == '.');
    if looks_numeric {
        if gw.parse::<Ipv4Addr>().is_err() {
            return Err(err("gateway", "is not a valid IPv4 address"));
        }
    } else if !gw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || gw.starts_with('.')
        || gw.starts_with('-')
        || gw.contains("..")
    {
        return Err(err("gateway", "must be a DNS name or IPv4 address"));
    }
    if e.port == 0 {
        return Err(err("port", "must be 1–65535"));
    }
    let lid = e.local_id.trim();
    if lid.is_empty() || lid.len() > 255 {
        return Err(err("local_id", "must be 1–255 characters"));
    }
    if e.id_type == IdType::Ipv4 && lid.parse::<Ipv4Addr>().is_err() {
        return Err(err(
            "local_id",
            "must be an IPv4 address when the identity type is IPv4",
        ));
    }
    if e.auth == AuthMode::Eap {
        let u = e.username.trim();
        if u.is_empty() || u.chars().count() > 256 {
            return Err(err("username", "is required (1–256 characters) for EAP"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_edit() -> ProfileEdit {
        ProfileEdit {
            name: "Office".into(),
            gateway: "vpn.example.com".into(),
            local_id: "laptop".into(),
            username: "alice".into(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_valid() {
        assert_eq!(validate(&ok_edit()), Ok(()));
        let mut e = ok_edit();
        e.gateway = "203.0.113.7".into();
        assert_eq!(validate(&e), Ok(()));
    }

    #[test]
    fn rejects_bad_fields() {
        type Mutate = Box<dyn Fn(&mut ProfileEdit)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("name", Box::new(|e| e.name = "  ".into())),
            ("name", Box::new(|e| e.name = "x".repeat(65))),
            ("gateway", Box::new(|e| e.gateway = String::new())),
            (
                "gateway",
                Box::new(|e| e.gateway = "vpn example.com".into()),
            ),
            ("gateway", Box::new(|e| e.gateway = "300.1.1.1".into())),
            ("gateway", Box::new(|e| e.gateway = "a".repeat(254))),
            ("port", Box::new(|e| e.port = 0)),
            ("local_id", Box::new(|e| e.local_id = String::new())),
            (
                "local_id",
                Box::new(|e| {
                    e.id_type = IdType::Ipv4;
                    e.local_id = "not-an-ip".into();
                }),
            ),
            ("username", Box::new(|e| e.username = String::new())),
        ];
        for (field, mutate) in cases {
            let mut e = ok_edit();
            mutate(&mut e);
            assert_eq!(validate(&e).unwrap_err().field, field);
        }
    }

    #[test]
    fn psk_mode_needs_no_username() {
        let mut e = ok_edit();
        e.auth = AuthMode::Psk;
        e.username = String::new();
        assert_eq!(validate(&e), Ok(()));
    }
}
