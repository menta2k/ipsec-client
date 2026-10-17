//! Wire messages of the GUI <-> service protocol (contracts/ipc-protocol.md).
//!
//! Invariant: nothing the service sends ever carries a PSK, password or key.
//! [`ProfileView`] therefore has only `has_psk` / `has_password` flags, and the
//! only secret-bearing types ([`SecretString`]) appear in client->service
//! requests.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// Protocol version; both sides refuse to talk on a mismatch.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum number of log lines a client may request.
pub const MAX_LOG_LINES: u32 = 2000;

/// A secret string travelling GUI -> service. Zeroized on drop; `Debug` never
/// prints the content.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString(Zeroizing::new(s.into()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

/// Top-level frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Frame {
    Hello {
        protocol_version: u32,
        client: String,
    },
    HelloOk {
        protocol_version: u32,
        service: String,
    },
    Error {
        code: HandshakeError,
        message: String,
    },
    Request {
        body: Request,
    },
    Response {
        body: Response,
    },
    Event {
        body: Event,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeError {
    VersionMismatch,
    ProtocolError,
}

/// Client -> service requests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    GetStatus,
    ListProfiles,
    CreateProfile {
        profile: ProfileEdit,
    },
    UpdateProfile {
        id: String,
        profile: ProfileEdit,
    },
    DeleteProfile {
        id: String,
    },
    Connect {
        id: String,
        #[serde(default)]
        password: Option<SecretString>,
        #[serde(default)]
        save_password: bool,
    },
    Disconnect,
    GetLogs {
        max: u32,
    },
    Subscribe,
    // --- Pre-Login Connect (003 contracts/ipc-additions.md); additive. ---
    /// Profiles an administrator made available at the sign-in screen.
    ListSignInProfiles,
    /// Connect from the sign-in screen: the profile must be available at
    /// sign-in, a saved password is never used, and nothing is saved.
    ConnectAtSignIn {
        id: String,
        #[serde(default)]
        password: Option<SecretString>,
    },
    /// Administrator only.
    SetSignIn {
        id: String,
        enabled: bool,
    },
    GetPolicy,
    /// Administrator only.
    SetPolicy {
        policy: Policy,
    },
    /// Administrator only: create or update (by name) for unattended
    /// deployment.
    ImportProfile {
        profile: ProfileEdit,
        #[serde(default)]
        sign_in: bool,
    },
}

/// Service -> client responses (exactly one per request).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Response {
    Ok,
    Status {
        state: ConnectionState,
        session: Option<SessionInfo>,
    },
    Profiles {
        profiles: Vec<ProfileView>,
    },
    Profile {
        profile: ProfileView,
    },
    Logs {
        lines: Vec<LogLine>,
    },
    Subscribed {
        state: ConnectionState,
        session: Option<SessionInfo>,
        recent_logs: Vec<LogLine>,
    },
    Failed {
        code: RequestError,
        message: String,
    },
    SignInProfiles {
        profiles: Vec<SignInProfile>,
    },
    Policy {
        policy: Policy,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestError {
    NotFound,
    Invalid,
    AlreadyConnected,
    NotConnected,
    MissingSecret,
    NameTaken,
    Internal,
    /// The request needs an elevated administrator (003).
    AdminRequired,
    /// The profile is not available at the sign-in screen (003).
    NotAvailableAtSignIn,
}

/// Service -> subscribed client events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    State { state: ConnectionState },
    Session { session: SessionInfo },
    Log { line: LogLine },
    ProfilesChanged,
}

/// Connection state machine (data-model.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum ConnectionState {
    Disconnected,
    Connecting { profile_id: String, attempt: u32 },
    Authenticating { profile_id: String },
    Connected { profile_id: String },
    Disconnecting,
    Error { code: ErrorCode, message: String },
}

impl ConnectionState {
    /// True while a tunnel exists or is being set up/torn down.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ConnectionState::Connecting { .. }
                | ConnectionState::Authenticating { .. }
                | ConnectionState::Connected { .. }
                | ConnectionState::Disconnecting
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting { .. } => "Connecting",
            ConnectionState::Authenticating { .. } => "Authenticating",
            ConnectionState::Connected { .. } => "Connected",
            ConnectionState::Disconnecting => "Disconnecting",
            ConnectionState::Error { .. } => "Error",
        }
    }
}

/// Machine-readable failure reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    GatewayUnreachable,
    NoProposalChosen,
    InvalidKe,
    CookieRequired,
    GatewayAuthFailed,
    UserAuthFailed,
    TsUnacceptable,
    NoAddressAssigned,
    UnsupportedCipher,
    GatewayLost,
    DeletedByGateway,
    TunError,
    NetConfigError,
    ProfileInvalid,
    MissingSecret,
    Internal,
}

/// Live session details (never contains key material).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub profile_id: String,
    pub profile_name: String,
    pub gateway: String,
    pub nat_detected: bool,
    pub assigned_ip: Option<String>,
    pub dns: Vec<String>,
    pub ike_suite: String,
    pub esp_suite: String,
    pub remote_ts: Vec<String>,
    pub connected_since_unix: Option<u64>,
    pub stats: Stats,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    /// Packets lost to errors: failed decryption/replay check, or a failed send.
    pub dropped_in: u64,
    pub dropped_out: u64,
    /// Outbound packets deliberately not tunneled (IPv6, multicast, broadcast).
    /// Defaulted so peers that predate the field still interoperate.
    #[serde(default)]
    pub filtered_out: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdType {
    #[default]
    Fqdn,
    Email,
    Ipv4,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DhGroupSel {
    #[default]
    Modp2048,
    Modp1536,
    X25519,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Psk,
    #[default]
    Eap,
}

/// A profile as the GUI sees it: no secrets, only "is set" flags.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub port: u16,
    pub local_id: String,
    pub id_type: IdType,
    pub dh_group: DhGroupSel,
    pub auth: AuthMode,
    pub username: String,
    pub auto_reconnect: bool,
    pub has_psk: bool,
    pub has_password: bool,
    /// Offered at the Windows sign-in screen (003); set by administrators only.
    #[serde(default)]
    pub sign_in: bool,
}

/// All the sign-in screen learns about a profile (003 data-model.md): no
/// gateway, and deliberately no hint whether secrets are saved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInProfile {
    pub id: String,
    pub name: String,
    pub auth: AuthMode,
    pub username: String,
}

/// Machine-wide Pre-Login Connect policy (003).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Keep the tunnel when the user signs out of Windows (default: disconnect).
    #[serde(default)]
    pub keep_tunnel_on_signout: bool,
}

/// How to change a stored secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "value")]
pub enum SecretUpdate {
    #[default]
    Keep,
    Clear,
    Set(SecretString),
}

/// Create/update payload for a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileEdit {
    pub name: String,
    pub gateway: String,
    pub port: u16,
    pub local_id: String,
    pub id_type: IdType,
    pub dh_group: DhGroupSel,
    pub auth: AuthMode,
    pub username: String,
    pub auto_reconnect: bool,
    pub psk: SecretUpdate,
    pub password: SecretUpdate,
}

impl Default for ProfileEdit {
    fn default() -> Self {
        ProfileEdit {
            name: String::new(),
            gateway: String::new(),
            port: 500,
            local_id: String::new(),
            id_type: IdType::Fqdn,
            dh_group: DhGroupSel::Modp2048,
            auth: AuthMode::Eap,
            username: String::new(),
            auto_reconnect: false,
            psk: SecretUpdate::Keep,
            password: SecretUpdate::Keep,
        }
    }
}

impl ProfileEdit {
    /// An edit pre-filled from an existing profile, keeping its secrets.
    pub fn from_view(v: &ProfileView) -> Self {
        ProfileEdit {
            name: v.name.clone(),
            gateway: v.gateway.clone(),
            port: v.port,
            local_id: v.local_id.clone(),
            id_type: v.id_type,
            dh_group: v.dh_group,
            auth: v.auth,
            username: v.username.clone(),
            auto_reconnect: v.auto_reconnect,
            psk: SecretUpdate::Keep,
            password: SecretUpdate::Keep,
        }
    }
}

/// One redacted service log line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub ts_unix_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_without_filtered_out_still_parse() {
        let s: Stats = serde_json::from_str(
            r#"{"bytes_in":1,"bytes_out":2,"packets_in":3,"packets_out":4,"dropped_in":5,"dropped_out":6}"#,
        )
        .unwrap();
        assert_eq!((s.dropped_out, s.filtered_out), (6, 0));
    }

    #[test]
    fn sign_in_requests_and_responses_round_trip() {
        let frames = [
            Frame::Request {
                body: Request::ListSignInProfiles,
            },
            Frame::Request {
                body: Request::ConnectAtSignIn {
                    id: "a".into(),
                    password: Some(SecretString::new("pw")),
                },
            },
            Frame::Request {
                body: Request::ConnectAtSignIn {
                    id: "a".into(),
                    password: None,
                },
            },
            Frame::Request {
                body: Request::SetSignIn {
                    id: "a".into(),
                    enabled: true,
                },
            },
            Frame::Request {
                body: Request::GetPolicy,
            },
            Frame::Request {
                body: Request::SetPolicy {
                    policy: Policy {
                        keep_tunnel_on_signout: true,
                    },
                },
            },
            Frame::Request {
                body: Request::ImportProfile {
                    profile: ProfileEdit {
                        name: "Office".into(),
                        ..Default::default()
                    },
                    sign_in: true,
                },
            },
            Frame::Response {
                body: Response::SignInProfiles {
                    profiles: vec![SignInProfile {
                        id: "a".into(),
                        name: "Office".into(),
                        auth: AuthMode::Eap,
                        username: "alice".into(),
                    }],
                },
            },
            Frame::Response {
                body: Response::Policy {
                    policy: Policy::default(),
                },
            },
            Frame::Response {
                body: Response::Failed {
                    code: RequestError::AdminRequired,
                    message: "x".into(),
                },
            },
            Frame::Response {
                body: Response::Failed {
                    code: RequestError::NotAvailableAtSignIn,
                    message: "x".into(),
                },
            },
        ];
        for f in &frames {
            rt(f);
        }
    }

    #[test]
    fn sign_in_profile_exposes_only_name_auth_and_username() {
        let v = serde_json::to_value(SignInProfile {
            id: "i".into(),
            name: "n".into(),
            auth: AuthMode::Psk,
            username: "u".into(),
        })
        .unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["auth", "id", "name", "username"]);
    }

    #[test]
    fn profile_view_from_001_parses_with_sign_in_false() {
        let mut v = serde_json::to_value(ProfileView::default()).unwrap();
        v.as_object_mut().unwrap().remove("sign_in");
        let back: ProfileView = serde_json::from_value(v).unwrap();
        assert!(!back.sign_in);
    }

    #[test]
    fn policy_defaults_to_disconnect_on_signout() {
        assert!(!Policy::default().keep_tunnel_on_signout);
        let p: Policy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, Policy::default());
    }

    fn rt(f: &Frame) {
        let s = serde_json::to_string(f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert_eq!(&back, f, "{s}");
    }

    #[test]
    fn hello_wire_shape_matches_contract() {
        let f = Frame::Hello {
            protocol_version: 1,
            client: "ipsec-gui 0.1.0".into(),
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"Hello","protocol_version":1,"client":"ipsec-gui 0.1.0"}"#
        );
    }

    #[test]
    fn request_wire_shape_matches_contract() {
        let f = Frame::Request {
            body: Request::GetStatus,
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"Request","body":{"op":"GetStatus"}}"#
        );
    }

    #[test]
    fn all_frames_roundtrip() {
        let edit = ProfileEdit {
            name: "Office".into(),
            gateway: "vpn.example.com".into(),
            psk: SecretUpdate::Set(SecretString::new("psk")),
            password: SecretUpdate::Clear,
            ..Default::default()
        };
        let session = SessionInfo {
            profile_id: "p1".into(),
            assigned_ip: Some("10.0.0.2".into()),
            dns: vec!["10.0.0.1".into()],
            stats: Stats {
                bytes_in: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let line = LogLine {
            ts_unix_ms: 1,
            level: "INFO".into(),
            target: "t".into(),
            message: "m".into(),
        };
        let frames = vec![
            Frame::HelloOk {
                protocol_version: 1,
                service: "s".into(),
            },
            Frame::Error {
                code: HandshakeError::VersionMismatch,
                message: "x".into(),
            },
            Frame::Request {
                body: Request::CreateProfile {
                    profile: edit.clone(),
                },
            },
            Frame::Request {
                body: Request::UpdateProfile {
                    id: "a".into(),
                    profile: edit,
                },
            },
            Frame::Request {
                body: Request::DeleteProfile { id: "a".into() },
            },
            Frame::Request {
                body: Request::Connect {
                    id: "a".into(),
                    password: Some(SecretString::new("pw")),
                    save_password: true,
                },
            },
            Frame::Request {
                body: Request::Disconnect,
            },
            Frame::Request {
                body: Request::GetLogs { max: 10 },
            },
            Frame::Request {
                body: Request::Subscribe,
            },
            Frame::Response { body: Response::Ok },
            Frame::Response {
                body: Response::Status {
                    state: ConnectionState::Connecting {
                        profile_id: "a".into(),
                        attempt: 1,
                    },
                    session: Some(session.clone()),
                },
            },
            Frame::Response {
                body: Response::Profiles {
                    profiles: vec![ProfileView::default()],
                },
            },
            Frame::Response {
                body: Response::Logs {
                    lines: vec![line.clone()],
                },
            },
            Frame::Response {
                body: Response::Subscribed {
                    state: ConnectionState::Error {
                        code: ErrorCode::GatewayLost,
                        message: "lost".into(),
                    },
                    session: None,
                    recent_logs: vec![line.clone()],
                },
            },
            Frame::Response {
                body: Response::Failed {
                    code: RequestError::AlreadyConnected,
                    message: "x".into(),
                },
            },
            Frame::Event {
                body: Event::State {
                    state: ConnectionState::Disconnecting,
                },
            },
            Frame::Event {
                body: Event::Session { session },
            },
            Frame::Event {
                body: Event::Log { line },
            },
            Frame::Event {
                body: Event::ProfilesChanged,
            },
        ];
        for f in &frames {
            rt(f);
        }
    }

    #[test]
    fn profile_view_has_no_secret_fields() {
        let v = serde_json::to_value(ProfileView::default()).unwrap();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        for k in &keys {
            assert!(
                !k.contains("blob") && k != "psk" && k != "password",
                "secret field {k}"
            );
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretString::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        let r = Request::Connect {
            id: "x".into(),
            password: Some(s),
            save_password: false,
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    #[test]
    fn unknown_op_is_an_error_not_a_panic() {
        assert!(
            serde_json::from_str::<Frame>(r#"{"type":"Request","body":{"op":"Nope"}}"#).is_err()
        );
        assert!(serde_json::from_str::<Frame>("{garbage").is_err());
    }
}
