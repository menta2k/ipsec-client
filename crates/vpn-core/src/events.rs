//! Fan-out of [`ipc_proto::Event`]s to any number of subscribers.
//!
//! Must not log (the log layer publishes through this bus).

use ipc_proto::Event;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct EventBus {
    subs: Arc<Mutex<Vec<Sender<Event>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subs.lock().unwrap().push(tx);
        rx
    }

    /// Deliver to every live subscriber, pruning closed ones.
    pub fn publish(&self, ev: Event) {
        let mut subs = self.subs.lock().unwrap();
        subs.retain(|s| s.send(ev.clone()).is_ok());
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
}
