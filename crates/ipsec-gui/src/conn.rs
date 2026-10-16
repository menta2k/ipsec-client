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
    /// Client/service protocol versions differ.
    Incompatible(String),
    Event(Event),
    Reply(Tag, Result<Response, String>),
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
            Err(e @ ClientError::VersionMismatch { .. }) => {
                if tx.send(UiMsg::Incompatible(e.to_string())).is_err() {
                    return;
                }
                wake();
                std::thread::sleep(Duration::from_secs(10));
            }
            Err(e) => {
                if tx.send(UiMsg::Offline(e.to_string())).is_err() {
                    return;
                }
                wake();
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
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
