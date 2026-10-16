//! In-memory ring of recent log lines (FR-040) and the `tracing` layer that
//! feeds it. Each new line is also published as an `Event::Log`.
//!
//! Redaction is by construction: secret types never implement `Display`/`Debug`
//! with their content, so nothing formatted here can contain them.

use crate::events::EventBus;
use ipc_proto::{Event, LogLine};
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::{Event as TEvent, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Default ring capacity.
pub const LOG_CAPACITY: usize = 2000;

#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<LogLine>>>,
    cap: usize,
    bus: Option<EventBus>,
}

impl LogBuffer {
    pub fn new(cap: usize, bus: Option<EventBus>) -> Self {
        LogBuffer {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(cap))),
            cap,
            bus,
        }
    }

    pub fn push(&self, line: LogLine) {
        {
            let mut q = self.inner.lock().unwrap();
            if q.len() == self.cap {
                q.pop_front();
            }
            q.push_back(line.clone());
        }
        if let Some(bus) = &self.bus {
            bus.publish(Event::Log { line });
        }
    }

    /// The newest `max` lines, oldest first.
    pub fn recent(&self, max: usize) -> Vec<LogLine> {
        let q = self.inner.lock().unwrap();
        let skip = q.len().saturating_sub(max);
        q.iter().skip(skip).cloned().collect()
    }

    /// A `tracing` layer writing into this buffer.
    pub fn layer(&self) -> LogBufferLayer {
        LogBufferLayer { buf: self.clone() }
    }
}

pub struct LogBufferLayer {
    buf: LogBuffer,
}

struct MsgVisitor {
    message: String,
    fields: String,
}

impl Visit for MsgVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &TEvent<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut v = MsgVisitor {
            message: String::new(),
            fields: String::new(),
        };
        event.record(&mut v);
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.buf.push(LogLine {
            ts_unix_ms,
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: format!("{}{}", v.message, v.fields),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn line(i: u64) -> LogLine {
        LogLine {
            ts_unix_ms: i,
            level: "INFO".into(),
            target: "t".into(),
            message: i.to_string(),
        }
    }

    #[test]
    fn ring_keeps_newest() {
        let b = LogBuffer::new(3, None);
        for i in 0..5 {
            b.push(line(i));
        }
        let r = b.recent(10);
        assert_eq!(
            r.iter().map(|l| l.ts_unix_ms).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        assert_eq!(b.recent(1)[0].ts_unix_ms, 4);
    }

    #[test]
    fn layer_captures_and_publishes() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        let b = LogBuffer::new(10, Some(bus));
        let sub = tracing_subscriber::registry().with(b.layer());
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(peer = "1.2.3.4", "hello {}", 42);
        });
        let r = b.recent(10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level, "WARN");
        assert!(r[0].message.contains("hello 42") && r[0].message.contains("peer=1.2.3.4"));
        assert!(matches!(rx.try_recv().unwrap(), Event::Log { .. }));
    }
}
