//! Fan-out of [`ipc_proto::Event`]s to any number of subscribers.
//!
//! Must not log (the log layer publishes through this bus).

use ipc_proto::Event;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvError, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Most events a subscriber may have queued (published but not yet received).
///
/// A subscriber that falls a full queue behind is disconnected rather than
/// buffered without limit: the bus drops its sender, so once the subscriber
/// has drained what is already queued its `recv` fails and the IPC server
/// closes that event stream. The GUI then reconnects and takes a fresh
/// snapshot; a sign-in screen (PLAP) connect in progress would fail. Readers
/// that keep up never get near this. The queue only grows with the actual
/// backlog, so an idle subscriber costs no more than an empty channel.
pub const SUBSCRIBER_QUEUE_LIMIT: usize = 1024;

struct Sub {
    tx: Sender<Event>,
    /// Events sent to this subscriber that it has not received yet.
    pending: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
pub struct EventBus {
    subs: Arc<Mutex<Vec<Sub>>>,
}

/// The receiving end of [`EventBus::subscribe`].
pub struct Subscription {
    rx: Receiver<Event>,
    pending: Arc<AtomicUsize>,
}

impl Subscription {
    fn took(&self, ev: Event) -> Event {
        self.pending.fetch_sub(1, Ordering::Relaxed);
        ev
    }

    pub fn recv(&self) -> Result<Event, RecvError> {
        self.rx.recv().map(|ev| self.took(ev))
    }

    pub fn try_recv(&self) -> Result<Event, TryRecvError> {
        self.rx.try_recv().map(|ev| self.took(ev))
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.rx.recv_timeout(timeout).map(|ev| self.took(ev))
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&self) -> Subscription {
        let (tx, rx) = channel();
        let pending = Arc::new(AtomicUsize::new(0));
        self.subs.lock().unwrap().push(Sub {
            tx,
            pending: pending.clone(),
        });
        Subscription { rx, pending }
    }

    /// Deliver to every live subscriber, pruning closed ones and any that is
    /// [`SUBSCRIBER_QUEUE_LIMIT`] events behind.
    pub fn publish(&self, ev: Event) {
        let mut subs = self.subs.lock().unwrap();
        subs.retain(|s| {
            // Count before sending so the receiver never decrements first.
            if s.pending.fetch_add(1, Ordering::Relaxed) >= SUBSCRIBER_QUEUE_LIMIT {
                return false;
            }
            s.tx.send(ev.clone()).is_ok()
        });
    }

    pub fn subscriber_count(&self) -> usize {
        self.subs.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fan_out_and_prune() {
        let bus = EventBus::new();
        let a = bus.subscribe();
        let b = bus.subscribe();
        bus.publish(Event::ProfilesChanged);
        assert_eq!(a.recv().unwrap(), Event::ProfilesChanged);
        assert_eq!(b.recv().unwrap(), Event::ProfilesChanged);
        drop(b);
        bus.publish(Event::ProfilesChanged);
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn stalled_subscriber_is_bounded_and_dropped() {
        let bus = EventBus::new();
        let stalled = bus.subscribe();
        let prompt = bus.subscribe();
        for i in 0..3 * SUBSCRIBER_QUEUE_LIMIT {
            bus.publish(Event::ProfilesChanged);
            // A reader that keeps up receives every event, however many.
            let ev = match i % 3 {
                0 => prompt.recv().ok(),
                1 => prompt.try_recv().ok(),
                _ => prompt.recv_timeout(Duration::from_secs(1)).ok(),
            };
            assert_eq!(ev, Some(Event::ProfilesChanged));
            // The stalled one is kept up to a full queue, then disconnected.
            let live = if i < SUBSCRIBER_QUEUE_LIMIT { 2 } else { 1 };
            assert_eq!(bus.subscriber_count(), live, "after event {i}");
        }
        // It still gets exactly what was queued, then the end.
        for _ in 0..SUBSCRIBER_QUEUE_LIMIT {
            assert_eq!(stalled.try_recv().unwrap(), Event::ProfilesChanged);
        }
        assert_eq!(stalled.try_recv(), Err(TryRecvError::Disconnected));
    }
}
