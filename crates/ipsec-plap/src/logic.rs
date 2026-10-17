//! Sign-in screen model (003 data-model.md): profiles, fields, and the
//! connect / cancel / disconnect state machine. Pure Rust, no Windows types:
//! the COM layer only adapts LogonUI's callbacks to the functions here.

#![forbid(unsafe_code)]

use ipc_proto::{AuthMode, ConnectionState, RequestError, SecretString, SignInProfile};
use std::time::Duration;
use zeroize::Zeroizing;

/// Why a call to the service did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The service is not running (no endpoint).
    Unavailable,
    /// The service did not answer in time.
    Timeout,
    /// The service does not understand the sign-in requests (older version).
    OutOfDate,
    /// The service refused the request.
    Failed { code: RequestError, message: String },
}

/// The service, as the sign-in screen needs it. Every call is time-limited
/// by the implementation (`ipc.rs`).
pub trait ServiceApi: Send + Sync {
    fn status(&self) -> Result<ConnectionState, ApiError>;
    fn list(&self) -> Result<Vec<SignInProfile>, ApiError>;
    fn connect(&self, id: &str, password: Option<SecretString>) -> Result<(), ApiError>;
    fn disconnect(&self) -> Result<(), ApiError>;
    /// Start receiving state changes (subscribe before connecting so none is
    /// missed).
    fn events(&self) -> Result<Box<dyn StateEvents>, ApiError>;
}

/// A stream of connection-state changes.
pub trait StateEvents: Send {
    /// The next state, or `None` if none arrived within `wait`.
    fn next(&mut self, wait: Duration) -> Result<Option<ConnectionState>, ApiError>;
}

/// Where the sign-in screen is (003 data-model.md, "Sign-in screen model").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Loading,
    /// Nothing to offer: service down/out of date, or no sign-in profiles.
    Message(String),
    Ready,
    Connecting,
    /// A tunnel is up (started here or still active from earlier).
    Connected {
        id: String,
    },
    /// The last attempt failed; the user may try again.
    Failed(String),
}

/// Result of [`SignInModel::run_connect`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Connected,
    Cancelled,
    Failed(String),
}

/// One "Network sign-in" tile per profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tile {
    pub id: String,
    pub title: String,
    pub username: String,
    pub needs_password: bool,
}

pub const MSG_NOT_RUNNING: &str = "VPN service is not running";
pub const MSG_NOT_RESPONDING: &str = "VPN service is not responding";
pub const MSG_OUT_OF_DATE: &str = "VPN service is out of date";
pub const MSG_NO_PROFILES: &str = "No VPN connections are available at sign-in";

/// User-facing text for a service problem; refusals carry the service's own
/// message, which is the one the app shows too.
pub fn message(e: &ApiError) -> String {
    match e {
        ApiError::Unavailable => MSG_NOT_RUNNING.into(),
        ApiError::Timeout => MSG_NOT_RESPONDING.into(),
        ApiError::OutOfDate => MSG_OUT_OF_DATE.into(),
        ApiError::Failed { message, .. } => message.clone(),
    }
}

pub struct SignInModel {
    phase: Phase,
    tiles: Vec<Tile>,
    selected: usize,
    /// What the user typed; cleared as soon as it has been handed over.
    password: Zeroizing<String>,
}

impl Default for SignInModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SignInModel {
    pub fn new() -> Self {
        SignInModel {
            phase: Phase::Loading,
            tiles: Vec::new(),
            selected: 0,
            password: Zeroizing::new(String::new()),
        }
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn tiles(&self) -> &[Tile] {
        &self.tiles
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn select(&mut self, index: usize) {
        if index < self.tiles.len() && index != self.selected {
            self.selected = index;
            self.clear_password();
        }
    }

    pub fn set_password(&mut self, text: &str) {
        self.clear_password();
        self.password.push_str(text);
    }

    pub fn password_is_empty(&self) -> bool {
        self.password.is_empty()
    }

    fn clear_password(&mut self) {
        // Zeroizing wipes the old buffer when replaced.
        self.password = Zeroizing::new(String::new());
    }

    /// Label of the submit button.
    pub fn action_label(&self) -> &'static str {
        match self.phase {
            Phase::Connected { .. } => "Disconnect",
            _ => "Connect",
        }
    }

    /// Text for the status line under the tile.
    pub fn status_text(&self) -> String {
        match &self.phase {
            Phase::Loading => "Loading…".into(),
            Phase::Message(m) | Phase::Failed(m) => m.clone(),
            Phase::Ready => String::new(),
            Phase::Connecting => "Connecting…".into(),
            Phase::Connected { .. } => "Connected".into(),
        }
    }

    /// Ask the service what to show. Runs off LogonUI's UI thread.
    pub fn load(&mut self, api: &dyn ServiceApi) {
        self.tiles.clear();
        self.selected = 0;
        self.clear_password();
        let state = match api.status() {
            Ok(s) => s,
            Err(e) => return self.phase = Phase::Message(message(&e)),
        };
        let profiles = match api.list() {
            Ok(p) => p,
            Err(e) => return self.phase = Phase::Message(message(&e)),
        };
        self.tiles = profiles
            .into_iter()
            .map(|p| Tile {
                needs_password: p.auth == AuthMode::Eap,
                id: p.id,
                title: p.name,
                username: p.username,
            })
            .collect();
        self.phase = if state.is_active() {
            let id = match state {
                ConnectionState::Connecting { profile_id, .. }
                | ConnectionState::Authenticating { profile_id }
                | ConnectionState::Connected { profile_id } => profile_id,
                _ => String::new(),
            };
            Phase::Connected { id }
        } else if self.tiles.is_empty() {
            Phase::Message(MSG_NO_PROFILES.into())
        } else {
            Phase::Ready
        };
    }

    fn fail(&mut self, msg: impl Into<String>) -> Outcome {
        let msg = msg.into();
        self.phase = Phase::Failed(msg.clone());
        Outcome::Failed(msg)
    }

    /// The body of `IConnectableCredentialProviderCredential::Connect`:
    /// connect the selected tile, report progress through `status`, poll
    /// `keep_going` (LogonUI's cancel) every `tick`, and give up after
    /// `limit` (FR-008).
    pub fn run_connect(
        &mut self,
        api: &dyn ServiceApi,
        keep_going: &mut dyn FnMut() -> bool,
        status: &mut dyn FnMut(&str),
        limit: Duration,
        tick: Duration,
    ) -> Outcome {
        let Some(tile) = self.tiles.get(self.selected).cloned() else {
            return self.fail("No connection selected");
        };
        let password = if tile.needs_password {
            if self.password.is_empty() {
                return self.fail("Enter the password");
            }
            Some(SecretString::new(self.password.as_str()))
        } else {
            None
        };
        self.clear_password();

        // Subscribe first so no state change is missed.
        let mut events = match api.events() {
            Ok(e) => e,
            Err(e) => return self.fail(message(&e)),
        };
        if let Err(e) = api.connect(&tile.id, password) {
            return self.fail(message(&e));
        }
        self.phase = Phase::Connecting;
        let mut last = String::new();
        let mut say = |text: &str, last: &mut String| {
            if text != last {
                status(text);
                *last = text.to_string();
            }
        };
        say("Connecting…", &mut last);

        let start = std::time::Instant::now();
        let mut started = false;
        loop {
            if !keep_going() {
                let _ = api.disconnect();
                self.phase = Phase::Ready;
                return Outcome::Cancelled;
            }
            if start.elapsed() >= limit {
                let _ = api.disconnect();
                return self.fail("The connection timed out");
            }
            match events.next(tick) {
                Ok(None) => {}
                Ok(Some(state)) => match state {
                    ConnectionState::Connecting { .. } => {
                        started = true;
                        say("Connecting…", &mut last);
                    }
                    ConnectionState::Authenticating { .. } => {
                        started = true;
                        say("Authenticating…", &mut last);
                    }
                    ConnectionState::Connected { profile_id } => {
                        say("Connected", &mut last);
                        self.phase = Phase::Connected { id: profile_id };
                        return Outcome::Connected;
                    }
                    ConnectionState::Error { message, .. } => return self.fail(message),
                    // The first state seen may still be the old one.
                    ConnectionState::Disconnected if started => {
                        return self.fail("The connection was closed")
                    }
                    ConnectionState::Disconnected | ConnectionState::Disconnecting => {}
                },
                Err(e) => {
                    let _ = api.disconnect();
                    return self.fail(message(&e));
                }
            }
        }
    }

    /// Disconnect from the sign-in screen (also LogonUI's `Disconnect`).
    pub fn disconnect(&mut self, api: &dyn ServiceApi) {
        self.phase = match api.disconnect() {
            Ok(())
            | Err(ApiError::Failed {
                code: RequestError::NotConnected,
                ..
            }) => {
                if self.tiles.is_empty() {
                    Phase::Message(MSG_NO_PROFILES.into())
                } else {
                    Phase::Ready
                }
            }
            Err(e) => Phase::Failed(message(&e)),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn profile(id: &str, auth: AuthMode) -> SignInProfile {
        SignInProfile {
            id: id.into(),
            name: format!("Profile {id}"),
            auth,
            username: if auth == AuthMode::Eap {
                "alice".into()
            } else {
                String::new()
            },
        }
    }

    #[derive(Default)]
    struct Fake {
        status: Mutex<Option<Result<ConnectionState, ApiError>>>,
        list: Mutex<Option<Result<Vec<SignInProfile>, ApiError>>>,
        connect_result: Mutex<Option<ApiError>>,
        /// States delivered after connect, one per `next` call (None = tick).
        script: Mutex<VecDeque<Option<ConnectionState>>>,
        calls: Mutex<Vec<String>>,
    }

    impl Fake {
        fn with(list: Vec<SignInProfile>) -> Arc<Fake> {
            let f = Fake::default();
            *f.status.lock().unwrap() = Some(Ok(ConnectionState::Disconnected));
            *f.list.lock().unwrap() = Some(Ok(list));
            Arc::new(f)
        }
        fn script(&self, states: Vec<Option<ConnectionState>>) {
            *self.script.lock().unwrap() = states.into();
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    struct FakeEvents(Arc<Fake>);

    impl StateEvents for FakeEvents {
        fn next(&mut self, _wait: Duration) -> Result<Option<ConnectionState>, ApiError> {
            Ok(self.0.script.lock().unwrap().pop_front().flatten())
        }
    }

    impl ServiceApi for Arc<Fake> {
        fn status(&self) -> Result<ConnectionState, ApiError> {
            self.status.lock().unwrap().clone().unwrap()
        }
        fn list(&self) -> Result<Vec<SignInProfile>, ApiError> {
            self.list.lock().unwrap().clone().unwrap()
        }
        fn connect(&self, id: &str, password: Option<SecretString>) -> Result<(), ApiError> {
            self.calls.lock().unwrap().push(format!(
                "connect {id} {}",
                password.as_ref().map(|p| p.expose()).unwrap_or("-")
            ));
            match self.connect_result.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn disconnect(&self) -> Result<(), ApiError> {
            self.calls.lock().unwrap().push("disconnect".into());
            Ok(())
        }
        fn events(&self) -> Result<Box<dyn StateEvents>, ApiError> {
            Ok(Box::new(FakeEvents(self.clone())))
        }
    }

    fn connecting() -> Option<ConnectionState> {
        Some(ConnectionState::Connecting {
            profile_id: "a".into(),
            attempt: 1,
        })
    }
    fn authenticating() -> Option<ConnectionState> {
        Some(ConnectionState::Authenticating {
            profile_id: "a".into(),
        })
    }
    fn connected() -> Option<ConnectionState> {
        Some(ConnectionState::Connected {
            profile_id: "a".into(),
        })
    }

    /// Run a connect with recorded status lines; `cancel_after` polls.
    fn run(
        m: &mut SignInModel,
        api: &Arc<Fake>,
        cancel_after: Option<usize>,
    ) -> (Outcome, Vec<String>) {
        let mut statuses = Vec::new();
        let mut polls = 0usize;
        let outcome = m.run_connect(
            api,
            &mut || {
                polls += 1;
                cancel_after.is_none_or(|n| polls <= n)
            },
            &mut |s: &str| statuses.push(s.to_string()),
            Duration::from_secs(15),
            Duration::from_millis(1),
        );
        (outcome, statuses)
    }

    #[test]
    fn loads_profiles_and_offers_one_tile_each() {
        let api = Fake::with(vec![
            profile("a", AuthMode::Eap),
            profile("b", AuthMode::Psk),
        ]);
        let mut m = SignInModel::new();
        assert_eq!(m.phase(), &Phase::Loading);
        m.load(&api);
        assert_eq!(m.phase(), &Phase::Ready);
        assert_eq!(m.tiles().len(), 2);
        assert_eq!(m.tiles()[0].title, "Profile a");
        assert_eq!(m.tiles()[0].username, "alice");
        assert!(m.tiles()[0].needs_password);
        assert!(!m.tiles()[1].needs_password);
    }

    #[test]
    fn service_problems_become_messages() {
        for (err, expect) in [
            (ApiError::Unavailable, "VPN service is not running"),
            (ApiError::Timeout, "VPN service is not responding"),
            (ApiError::OutOfDate, "VPN service is out of date"),
        ] {
            let api = Fake::with(vec![]);
            *api.list.lock().unwrap() = Some(Err(err));
            let mut m = SignInModel::new();
            m.load(&api);
            assert_eq!(m.phase(), &Phase::Message(expect.into()));
            assert!(m.tiles().is_empty());
        }
    }

    #[test]
    fn no_profiles_explains_itself() {
        let api = Fake::with(vec![]);
        let mut m = SignInModel::new();
        m.load(&api);
        assert_eq!(
            m.phase(),
            &Phase::Message("No VPN connections are available at sign-in".into())
        );
    }

    #[test]
    fn an_active_tunnel_shows_as_connected_with_disconnect() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        *api.status.lock().unwrap() = connected().map(Ok);
        let mut m = SignInModel::new();
        m.load(&api);
        assert_eq!(m.phase(), &Phase::Connected { id: "a".into() });
        assert_eq!(m.action_label(), "Disconnect");
        m.disconnect(&api);
        assert_eq!(api.calls(), ["disconnect"]);
        assert_eq!(m.phase(), &Phase::Ready);
        assert_eq!(m.action_label(), "Connect");
    }

    #[test]
    fn eap_needs_a_typed_password_before_any_request() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        let mut m = SignInModel::new();
        m.load(&api);
        let (outcome, _) = run(&mut m, &api, None);
        assert_eq!(outcome, Outcome::Failed("Enter the password".into()));
        assert!(api.calls().is_empty());
    }

    #[test]
    fn eap_connect_walks_the_states_and_clears_the_password() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        api.script(vec![connecting(), None, authenticating(), connected()]);
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("s3cret");
        let (outcome, statuses) = run(&mut m, &api, None);
        assert_eq!(outcome, Outcome::Connected);
        assert_eq!(api.calls(), ["connect a s3cret"]);
        assert_eq!(statuses, ["Connecting…", "Authenticating…", "Connected"]);
        assert_eq!(m.phase(), &Phase::Connected { id: "a".into() });
        assert!(
            m.password_is_empty(),
            "typed secret must be cleared after use"
        );
    }

    #[test]
    fn psk_connects_without_a_password() {
        let api = Fake::with(vec![profile("b", AuthMode::Psk)]);
        api.script(vec![connected()]);
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("ignored");
        let (outcome, _) = run(&mut m, &api, None);
        assert_eq!(outcome, Outcome::Connected);
        assert_eq!(api.calls(), ["connect b -"]);
    }

    #[test]
    fn errors_use_the_service_messages() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        api.script(vec![
            connecting(),
            Some(ConnectionState::Error {
                code: ipc_proto::ErrorCode::UserAuthFailed,
                message: "Authentication failed: wrong username or password".into(),
            }),
        ]);
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("wrong");
        let (outcome, _) = run(&mut m, &api, None);
        let msg = "Authentication failed: wrong username or password".to_string();
        assert_eq!(outcome, Outcome::Failed(msg.clone()));
        assert_eq!(m.phase(), &Phase::Failed(msg));
        assert!(m.password_is_empty());
        // The user can try again.
        assert_eq!(m.action_label(), "Connect");
    }

    #[test]
    fn rejected_requests_use_their_message() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        *api.connect_result.lock().unwrap() = Some(ApiError::Failed {
            code: RequestError::NotAvailableAtSignIn,
            message: "This connection is not available at sign-in".into(),
        });
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("pw");
        let (outcome, _) = run(&mut m, &api, None);
        assert_eq!(
            outcome,
            Outcome::Failed("This connection is not available at sign-in".into())
        );
    }

    #[test]
    fn cancel_disconnects_and_returns_to_ready() {
        let api = Fake::with(vec![profile("a", AuthMode::Eap)]);
        api.script(vec![connecting(), None, None, None, None]);
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("pw");
        let (outcome, _) = run(&mut m, &api, Some(2));
        assert_eq!(outcome, Outcome::Cancelled);
        assert_eq!(api.calls(), ["connect a pw", "disconnect"]);
        assert_eq!(m.phase(), &Phase::Ready);
    }

    #[test]
    fn connect_is_bounded_in_time() {
        let api = Fake::with(vec![profile("b", AuthMode::Psk)]);
        api.script(vec![connecting()]); // then silence
        let mut m = SignInModel::new();
        m.load(&api);
        let mut statuses = Vec::new();
        let outcome = m.run_connect(
            &api,
            &mut || true,
            &mut |s: &str| statuses.push(s.to_string()),
            Duration::from_millis(30),
            Duration::from_millis(1),
        );
        assert_eq!(outcome, Outcome::Failed("The connection timed out".into()));
        assert_eq!(api.calls().last().unwrap(), "disconnect");
    }

    #[test]
    fn an_unexpected_disconnect_during_connect_is_a_failure() {
        let api = Fake::with(vec![profile("b", AuthMode::Psk)]);
        api.script(vec![connecting(), Some(ConnectionState::Disconnected)]);
        let mut m = SignInModel::new();
        m.load(&api);
        let (outcome, _) = run(&mut m, &api, None);
        assert_eq!(outcome, Outcome::Failed("The connection was closed".into()));
    }

    #[test]
    fn selecting_another_tile_clears_the_password() {
        let api = Fake::with(vec![
            profile("a", AuthMode::Eap),
            profile("c", AuthMode::Eap),
        ]);
        let mut m = SignInModel::new();
        m.load(&api);
        m.set_password("pw");
        m.select(1);
        assert!(m.password_is_empty());
        assert_eq!(m.selected(), 1);
        m.select(9); // out of range: ignored
        assert_eq!(m.selected(), 1);
    }
}
