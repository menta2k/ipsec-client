//! Simulated engine for `ipsec-service run --mock` (research R12): walks the
//! real state machine with delays and fake data so the GUI can be developed
//! and demonstrated on any OS without privileges or a gateway.
//!
//! Demo hooks: a password of `fail` produces an authentication error, and a
//! gateway named `unreachable.invalid` produces a timeout.

use crate::server::Engine;
use ipc_proto::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;
use vpn_core::{EventBus, ProfileStore, RejectError};

pub struct SimulatedEngine {
    store: Arc<ProfileStore>,
    bus: EventBus,
    state: Arc<Mutex<ConnectionState>>,
    session: Arc<Mutex<Option<SessionInfo>>>,
    cancel: Arc<AtomicBool>,
}

impl SimulatedEngine {
    pub fn new(store: Arc<ProfileStore>, bus: EventBus) -> Arc<Self> {
        Arc::new(SimulatedEngine {
            store,
            bus,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            session: Arc::new(Mutex::new(None)),
            cancel: Arc::new(AtomicBool::new(false)),
        })
    }
}

fn set(state: &Mutex<ConnectionState>, bus: &EventBus, s: ConnectionState) {
    *state.lock().unwrap() = s.clone();
    info!(target: "simulate", state = s.label(), "state changed");
    bus.publish(Event::State { state: s });
}

/// Sleep in small steps; false if cancelled.
fn wait(cancel: &AtomicBool, d: Duration) -> bool {
    let steps = (d.as_millis() / 50).max(1);
    for _ in 0..steps {
        if cancel.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

impl Engine for SimulatedEngine {
    fn state(&self) -> ConnectionState {
        self.state.lock().unwrap().clone()
    }
    fn session(&self) -> Option<SessionInfo> {
        self.session.lock().unwrap().clone()
    }
    fn active_profile(&self) -> Option<String> {
        match self.state() {
            ConnectionState::Connecting { profile_id, .. }
            | ConnectionState::Authenticating { profile_id }
            | ConnectionState::Connected { profile_id } => Some(profile_id),
            _ => None,
        }
    }

    fn on_signout(&self, policy: Policy) -> bool {
        if !self.state().is_active() || policy.keep_tunnel_on_signout {
            return false;
        }
        info!(target: "simulate", reason = "signout", "user signed out; disconnecting");
        if self.disconnect().is_err() {
            return false;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.state().is_active() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    fn connect_at_sign_in(
        &self,
        id: &str,
        password: Option<SecretString>,
    ) -> Result<(), RejectError> {
        // Same rules as the real engine (003 research R6), then the usual
        // simulated walk with only the typed password.
        let p = self.store.get(id).ok_or(RejectError {
            code: RequestError::NotFound,
            message: "Profile not found".into(),
        })?;
        if !p.sign_in {
            return Err(RejectError {
                code: RequestError::NotAvailableAtSignIn,
                message: "This connection is not available at sign-in".into(),
            });
        }
        let typed = password.filter(|p| !p.is_empty());
        match (p.auth, &typed) {
            (AuthMode::Eap, None) => Err(RejectError {
                code: RequestError::MissingSecret,
                message: "Enter the password for this connection".into(),
            }),
            (AuthMode::Psk, Some(_)) => Err(RejectError {
                code: RequestError::Invalid,
                message: "This connection does not use a password".into(),
            }),
            _ => {
                info!(target: "simulate", origin = "sign_in_screen", "connect at sign-in");
                self.connect(id, typed, false)
            }
        }
    }

    fn connect(
        &self,
        id: &str,
        password: Option<SecretString>,
        save_password: bool,
    ) -> Result<(), RejectError> {
        if self.state().is_active() {
            return Err(RejectError {
                code: RequestError::AlreadyConnected,
                message: "Already connected".into(),
            });
        }
        let p = self.store.get(id).ok_or(RejectError {
            code: RequestError::NotFound,
            message: "Profile not found".into(),
        })?;
        if p.psk_blob.is_none() {
            return Err(RejectError {
                code: RequestError::MissingSecret,
                message: "The profile has no saved pre-shared key".into(),
            });
        }
        let pw = password.filter(|p| !p.is_empty());
        if p.auth == AuthMode::Eap && pw.is_none() && p.password_blob.is_none() {
            return Err(RejectError {
                code: RequestError::MissingSecret,
                message: "A password is required for this profile".into(),
            });
        }
        if save_password {
            if let Some(pw) = &pw {
                let _ = self.store.set_password(id, pw.expose());
            }
        }
        let fail_auth = pw.as_ref().map(|p| p.expose() == "fail").unwrap_or(false);
        self.cancel.store(false, Ordering::SeqCst);
        set(
            &self.state,
            &self.bus,
            ConnectionState::Connecting {
                profile_id: p.id.clone(),
                attempt: 1,
            },
        );

        let (state, session, bus, cancel) = (
            self.state.clone(),
            self.session.clone(),
            self.bus.clone(),
            self.cancel.clone(),
        );
        std::thread::spawn(move || {
            if p.gateway == "unreachable.invalid" {
                if wait(&cancel, Duration::from_secs(3)) {
                    set(
                        &state,
                        &bus,
                        ConnectionState::Error {
                            code: ErrorCode::GatewayUnreachable,
                            message: "Gateway did not respond".into(),
                        },
                    );
                } else {
                    set(&state, &bus, ConnectionState::Disconnected);
                }
                return;
            }
            if !wait(&cancel, Duration::from_millis(800)) {
                return set(&state, &bus, ConnectionState::Disconnected);
            }
            set(
                &state,
                &bus,
                ConnectionState::Authenticating {
                    profile_id: p.id.clone(),
                },
            );
            if !wait(&cancel, Duration::from_millis(900)) {
                return set(&state, &bus, ConnectionState::Disconnected);
            }
            if fail_auth {
                return set(
                    &state,
                    &bus,
                    ConnectionState::Error {
                        code: ErrorCode::UserAuthFailed,
                        message: "Authentication failed: wrong username or password".into(),
                    },
                );
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut info = SessionInfo {
                profile_id: p.id.clone(),
                profile_name: p.name.clone(),
                gateway: format!("{}:4500", p.gateway),
                nat_detected: true,
                assigned_ip: Some("10.212.134.7".into()),
                dns: vec!["10.212.0.1".into(), "10.212.0.2".into()],
                ike_suite: "AES-256-GCM-16 / PRF-HMAC-SHA2-384 / MODP-2048 (simulated)".into(),
                esp_suite: "AES-256-GCM-16 (simulated)".into(),
                remote_ts: vec!["10.0.0.0/8".into()],
                connected_since_unix: Some(now),
                stats: Stats::default(),
            };
            *session.lock().unwrap() = Some(info.clone());
            bus.publish(Event::Session {
                session: info.clone(),
            });
            set(
                &state,
                &bus,
                ConnectionState::Connected {
                    profile_id: p.id.clone(),
                },
            );
            let mut tick = 0u64;
            while wait(&cancel, Duration::from_secs(1)) {
                tick += 1;
                info.stats.packets_in += 40 + tick % 7;
                info.stats.packets_out += 35 + tick % 5;
                info.stats.bytes_in += 48_000 + (tick * 1371) % 9000;
                info.stats.bytes_out += 12_000 + (tick * 733) % 4000;
                *session.lock().unwrap() = Some(info.clone());
                bus.publish(Event::Session {
                    session: info.clone(),
                });
            }
            set(&state, &bus, ConnectionState::Disconnecting);
            std::thread::sleep(Duration::from_millis(300));
            *session.lock().unwrap() = None;
            set(&state, &bus, ConnectionState::Disconnected);
        });
        Ok(())
    }

    fn disconnect(&self) -> Result<(), RejectError> {
        if !self.state().is_active() {
            return Err(RejectError {
                code: RequestError::NotConnected,
                message: "Not connected".into(),
            });
        }
        self.cancel.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn shutdown(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(400));
    }
}
