//! Background connection to the service (FR-037, FR-039).
//!
//! * An event thread keeps an `EventStream` subscription alive, reconnecting
//!   with backoff whenever the service is missing or restarts.
//! * A command thread executes requests one at a time over a lazily
//!   (re)connected `CommandClient`.
//!
//! Results reach the UI through a channel; `wake` asks egui to repaint (which
//! also runs `App::logic` while the window is hidden in the tray).

use ipc_proto::{ClientError, CommandClient, Event, EventStream, Request, Response, Snapshot};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

const CLIENT_NAME: &str = concat!("ipsec-gui ", env!("CARGO_PKG_VERSION"));

pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// Identifies what a reply belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    Profiles,
    SaveProfile,
    DeleteProfile,
    Connect,
    Disconnect,
}

pub enum UiMsg {
    /// Subscription (re)established.
    Online(Snapshot),
    /// The service is not reachable.
    Offline(String),
    /// The service is running but this user may not control it (002 FR-017).
    Unauthorized,
    /// Client/service protocol versions differ.
    Incompatible(String),
    Event(Event),
    Reply(Tag, Result<Response, String>),
}

/// What the UI shows when the service cannot be used.
pub fn link_message(e: &ClientError) -> UiMsg {
    match e {
        ClientError::VersionMismatch { .. } => UiMsg::Incompatible(e.to_string()),
        ClientError::Unauthorized => UiMsg::Unauthorized,
        _ => UiMsg::Offline(e.to_string()),
    }
}

pub struct Backend {
    cmd_tx: Sender<(Tag, Request)>,
    pub rx: Receiver<UiMsg>,
}

impl Backend {
    pub fn start(wake: Wake) -> Backend {
        let (ui_tx, rx) = channel();
        let (cmd_tx, cmd_rx) = channel::<(Tag, Request)>();

        {
            let (tx, wake) = (ui_tx.clone(), wake.clone());
            std::thread::Builder::new()
                .name("ipc-events".into())
                .spawn(move || event_loop(tx, wake))
                .expect("spawn event thread");
        }
        std::thread::Builder::new()
            .name("ipc-commands".into())
            .spawn(move || command_loop(cmd_rx, ui_tx, wake))
            .expect("spawn command thread");
        Backend { cmd_tx, rx }
    }

    pub fn send(&self, tag: Tag, req: Request) {
        let _ = self.cmd_tx.send((tag, req));
    }
}

fn event_loop(tx: Sender<UiMsg>, wake: Wake) {
    let mut backoff = Duration::from_millis(500);
    loop {
        match EventStream::subscribe(CLIENT_NAME) {
            Ok((snap, mut stream)) => {
                backoff = Duration::from_millis(500);
                if tx.send(UiMsg::Online(snap)).is_err() {
                    return;
                }
                wake();
                loop {
                    match stream.next_event() {
                        Ok(ev) => {
                            if tx.send(UiMsg::Event(ev)).is_err() {
                                return;
                            }
                            wake();
                        }
                        Err(e) => {
                            let _ = tx.send(UiMsg::Offline(format!(
                                "connection to the service lost ({e})"
                            )));
                            wake();
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let msg = link_message(&e);
                let incompatible = matches!(msg, UiMsg::Incompatible(_));
                if tx.send(msg).is_err() {
                    return;
                }
                wake();
                if incompatible {
                    std::thread::sleep(Duration::from_secs(10));
                } else {
                    // Offline or not authorized: keep retrying (a group
                    // membership or a service start may fix it).
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    }
}

fn command_loop(rx: Receiver<(Tag, Request)>, tx: Sender<UiMsg>, wake: Wake) {
    let mut client: Option<CommandClient> = None;
    while let Ok((tag, req)) = rx.recv() {
        let mut result = run(&mut client, req.clone());
        // One retry on a stale connection (service restarted).
        if matches!(
            result,
            Err(ClientError::Io(_)) | Err(ClientError::Protocol(_))
        ) {
            client = None;
            result = run(&mut client, req);
        }
        let result = result.map_err(|e| {
            if !matches!(e, ClientError::Failed { .. }) {
                client = None;
            }
            e.to_string()
        });
        if tx.send(UiMsg::Reply(tag, result)).is_err() {
            return;
        }
        wake();
    }
}

fn run(client: &mut Option<CommandClient>, req: Request) -> Result<Response, ClientError> {
    if client.is_none() {
        *client = Some(CommandClient::connect(CLIENT_NAME)?);
    }
    client.as_mut().expect("client").request(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failures_map_to_the_right_banner() {
        assert!(matches!(
            link_message(&ClientError::Unauthorized),
            UiMsg::Unauthorized
        ));
        assert!(matches!(
            link_message(&ClientError::VersionMismatch {
                service: 2,
                client: 1
            }),
            UiMsg::Incompatible(_)
        ));
        assert!(matches!(
            link_message(&ClientError::Unavailable(std::io::Error::from(
                std::io::ErrorKind::NotFound
            ))),
            UiMsg::Offline(_)
        ));
    }

    #[test]
    fn unauthorized_text_says_how_access_is_granted() {
        let t = crate::app::UNAUTHORIZED_TEXT;
        assert!(t.contains("not allowed to control the VPN"), "{t}");
        if cfg!(target_os = "linux") {
            assert!(
                t.contains("'ipsec-client' group") && t.contains("log in again"),
                "{t}"
            );
        }
        if cfg!(target_os = "macos") {
            assert!(t.contains("ipsec-service access-group"), "{t}");
        }
        assert!(
            !t.contains("not running"),
            "must not look like an outage: {t}"
        );
    }
}
