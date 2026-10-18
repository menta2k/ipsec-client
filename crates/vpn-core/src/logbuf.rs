//! In-memory ring of recent log lines (FR-040) and the `tracing` layer that
//! feeds it. Each new line is also published as an `Event::Log`.
//!
//! Redaction is by construction: secret types never implement `Display`/`Debug`
//! with their content, so nothing formatted here can contain them.
//!
//! Sizes are bounded because some logged values come from untrusted clients
//! (e.g. the self-reported `Hello` client name): a message or field value is
//! cut at [`MAX_FIELD_BYTES`] and a line at [`MAX_LINE_BYTES`], the ring holds
//! at most [`LOG_CAPACITY_BYTES`] besides its line count, and replies built
//! with [`LogBuffer::recent_within`] and [`LOG_REPLY_BYTES`] fit one frame.

use crate::events::EventBus;
use ipc_proto::framing::MAX_FRAME;
use ipc_proto::{Event, LogLine};
use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::{Event as TEvent, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Default ring capacity.
pub const LOG_CAPACITY: usize = 2000;

/// Most bytes the ring holds, counted as serialized lines; the oldest lines
/// are dropped first.
pub const LOG_CAPACITY_BYTES: usize = 512 * 1024;

/// Most serialized log bytes one reply (`GetLogs`, the `Subscribe` snapshot)
/// carries, leaving the rest of the frame for the reply around them.
pub const LOG_REPLY_BYTES: usize = 512 * 1024;

const _: () = assert!(LOG_REPLY_BYTES <= MAX_FRAME / 2);

/// Longest message or field value kept in a line.
pub const MAX_FIELD_BYTES: usize = 4096;

/// Longest line message kept.
pub const MAX_LINE_BYTES: usize = 8192;

/// Appended where a value or a line was cut.
pub const TRUNCATED: &str = "\u{2026}";

struct Ring {
    /// Each line with its serialized size.
    lines: VecDeque<(LogLine, usize)>,
    /// Sum of the sizes in `lines`.
    bytes: usize,
}

#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Mutex<Ring>>,
    cap: usize,
    bus: Option<EventBus>,
}

impl LogBuffer {
    /// A ring of at most `cap` lines and at most [`LOG_CAPACITY_BYTES`].
    pub fn new(cap: usize, bus: Option<EventBus>) -> Self {
        LogBuffer {
            inner: Arc::new(Mutex::new(Ring {
                lines: VecDeque::with_capacity(cap),
                bytes: 0,
            })),
            cap,
            bus,
        }
    }

    pub fn push(&self, line: LogLine) {
        let size = wire_len(&line);
        // A line larger than the whole ring is not kept (the layer never
        // produces one).
        if size <= LOG_CAPACITY_BYTES {
            let mut r = self.inner.lock().unwrap();
            while !r.lines.is_empty()
                && (r.lines.len() >= self.cap || r.bytes + size > LOG_CAPACITY_BYTES)
            {
                if let Some((_, old)) = r.lines.pop_front() {
                    r.bytes -= old;
                }
            }
            r.bytes += size;
            r.lines.push_back((line.clone(), size));
        }
        if let Some(bus) = &self.bus {
            bus.publish(Event::Log { line });
        }
    }

    /// The newest `max` lines, oldest first.
    pub fn recent(&self, max: usize) -> Vec<LogLine> {
        let r = self.inner.lock().unwrap();
        let skip = r.lines.len().saturating_sub(max);
        r.lines.iter().skip(skip).map(|(l, _)| l.clone()).collect()
    }

    /// The newest lines, at most `max` of them and at most `max_bytes` once
    /// serialized, oldest first.
    pub fn recent_within(&self, max: usize, max_bytes: usize) -> Vec<LogLine> {
        let r = self.inner.lock().unwrap();
        let mut used = 0usize;
        let mut lines: Vec<LogLine> = r
            .lines
            .iter()
            .rev()
            .take(max)
            .take_while(|(_, size)| {
                used += size;
                used <= max_bytes
            })
            .map(|(l, _)| l.clone())
            .collect();
        lines.reverse();
        lines
    }

    /// A `tracing` layer writing into this buffer.
    pub fn layer(&self) -> LogBufferLayer {
        LogBufferLayer { buf: self.clone() }
    }
}

/// Bytes `line` takes in a serialized reply, including a separating comma.
fn wire_len(line: &LogLine) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    let _ = serde_json::to_writer(&mut c, line);
    c.0 + 1
}

/// A sink keeping at most `room` bytes, cut on a character boundary; it fails
/// once full so the formatting of a huge value stops early.
struct Capped<'a> {
    out: &'a mut String,
    room: usize,
    cut: bool,
}

impl fmt::Write for Capped<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() <= self.room {
            self.out.push_str(s);
            self.room -= s.len();
            return Ok(());
        }
        let mut end = self.room;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.out.push_str(&s[..end]);
        self.room = 0;
        self.cut = true;
        Err(fmt::Error)
    }
}

/// Append at most `room` bytes of `value` to `out`, marking a cut.
fn push_capped(out: &mut String, room: usize, value: fmt::Arguments<'_>) {
    let mut w = Capped {
        out,
        room,
        cut: false,
    };
    let _ = w.write_fmt(value);
    if w.cut {
        w.out.push_str(TRUNCATED);
    }
}

pub struct LogBufferLayer {
    buf: LogBuffer,
}

struct MsgVisitor {
    message: String,
    fields: String,
}

impl MsgVisitor {
    fn record(&mut self, field: &Field, value: fmt::Arguments<'_>) {
        // A value gets its own cap, and no more than what is left of the line.
        let used = self.message.len() + self.fields.len();
        let room = MAX_FIELD_BYTES.min(MAX_LINE_BYTES.saturating_sub(used));
        if field.name() == "message" {
            push_capped(&mut self.message, room, value);
        } else {
            let _ = write!(self.fields, " {}=", field.name());
            push_capped(&mut self.fields, room, value);
        }
    }
}

impl Visit for MsgVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, format_args!("{value}"));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field, format_args!("{value:?}"));
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
        let mut message = v.message;
        let room = MAX_LINE_BYTES.saturating_sub(message.len());
        push_capped(&mut message, room, format_args!("{}", v.fields));
        self.buf.push(LogLine {
            ts_unix_ms,
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_proto::{Frame, Response, MAX_LOG_LINES};
    use std::net::Ipv4Addr;
    use tracing_subscriber::prelude::*;

    fn line(i: u64) -> LogLine {
        LogLine {
            ts_unix_ms: i,
            level: "INFO".into(),
            target: "t".into(),
            message: i.to_string(),
        }
    }

    /// Lines captured by a fresh ring while `f` runs.
    fn capture(cap: usize, f: impl FnOnce()) -> LogBuffer {
        let b = LogBuffer::new(cap, None);
        let sub = tracing_subscriber::registry().with(b.layer());
        tracing::subscriber::with_default(sub, f);
        b
    }

    fn frame_len(lines: Vec<LogLine>) -> usize {
        serde_json::to_vec(&Frame::Response {
            body: Response::Logs { lines },
        })
        .unwrap()
        .len()
    }

    /// Over 1 MiB of a character that takes six bytes once serialized, mixed
    /// with a multi-byte one so cuts must respect character boundaries.
    fn huge_value() -> String {
        "\u{1}\u{e9}".repeat(1 << 19)
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

    /// The session's "Child SA established" line (US5: negotiated traffic
    /// selectors) is kept whole even with many remote ranges.
    #[test]
    fn child_sa_line_with_many_selectors_is_unchanged() {
        let ip = Ipv4Addr::new(10, 8, 0, 2);
        let dns = vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 1, 53)];
        let remote_ts: Vec<(Ipv4Addr, Ipv4Addr)> = (0..64u8)
            .map(|i| (Ipv4Addr::new(10, i, 0, 0), Ipv4Addr::new(10, i, 255, 255)))
            .collect();
        let b = capture(10, || {
            tracing::info!(
                target: "vpn_core::session",
                ip = %ip,
                dns = ?dns,
                esp = "AES-GCM-256",
                remote_ts = ?remote_ts,
                "Child SA established"
            );
        });
        let want = format!(
            "Child SA established ip={ip} dns={dns:?} esp=AES-GCM-256 remote_ts={remote_ts:?}"
        );
        assert!(want.len() > 1500, "{}", want.len());
        assert_eq!(b.recent(1)[0].message, want);
    }

    /// A reconnect reason naming a maximum-length gateway host name is kept
    /// whole.
    #[test]
    fn long_resolver_reason_is_unchanged() {
        let label = "a".repeat(63);
        let host = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        assert_eq!(host.len(), 253);
        let reason = format!(
            "Could not resolve the gateway {host}: failed to lookup address information: \
             No such host is known. (os error 11001)"
        );
        let b = capture(10, || {
            tracing::warn!(reason = %reason, delay_s = 30u64, "reconnecting");
        });
        assert_eq!(
            b.recent(1)[0].message,
            format!("reconnecting reason={reason} delay_s=30")
        );
    }

    /// A huge untrusted value is cut, the fields after it survive, and the
    /// published line fits one frame.
    #[test]
    fn huge_values_are_cut_and_later_fields_kept() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        let b = LogBuffer::new(10, Some(bus));
        let huge = huge_value();
        let sub = tracing_subscriber::registry().with(b.layer());
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(
                client = huge.as_str(),
                peer = "pid=4242 user=TEST\\alice",
                "refused"
            );
            tracing::info!("{huge}");
        });
        let r = b.recent(10);
        let m = &r[0].message;
        assert!(m.starts_with("refused client=\u{1}\u{e9}"), "{}", m.len());
        assert!(m.ends_with(&format!("{TRUNCATED} peer=pid=4242 user=TEST\\alice")));
        assert!(m.len() <= MAX_LINE_BYTES + TRUNCATED.len());
        let client = &m["refused client=".len()..m.find(TRUNCATED).unwrap()];
        assert!(client.len() <= MAX_FIELD_BYTES && client.len() > MAX_FIELD_BYTES - 2);
        assert!(r[1].message.len() <= MAX_FIELD_BYTES + TRUNCATED.len());
        assert!(r[1].message.ends_with(TRUNCATED));
        for _ in 0..2 {
            let ev = Frame::Event {
                body: rx.try_recv().unwrap(),
            };
            assert!(serde_json::to_vec(&ev).unwrap().len() <= MAX_FRAME);
        }
    }

    /// Whatever the line sizes, the ring holds at most `LOG_CAPACITY_BYTES`
    /// and replies stay within their budget, newest lines kept.
    #[test]
    fn ring_and_replies_are_bounded_by_bytes() {
        let huge = huge_value();
        let b = capture(LOG_CAPACITY, || {
            for i in 0..LOG_CAPACITY {
                tracing::warn!(client = huge.as_str(), n = i, "refused");
            }
        });
        let all = b.recent(usize::MAX);
        let held: usize = all.iter().map(wire_len).sum();
        assert!(held <= LOG_CAPACITY_BYTES, "{held}");
        assert_eq!(held, b.inner.lock().unwrap().bytes);
        assert!(all.last().unwrap().message.ends_with(" n=1999"));

        let reply = b.recent_within(MAX_LOG_LINES as usize, LOG_REPLY_BYTES);
        assert!(!reply.is_empty());
        assert_eq!(reply.last(), all.last());
        assert!(frame_len(reply) <= MAX_FRAME);

        // A line larger than the whole ring is not kept and evicts nothing.
        b.push(LogLine {
            message: "x".repeat(LOG_CAPACITY_BYTES),
            ..line(0)
        });
        assert_eq!(b.recent(usize::MAX), all);
    }

    /// A full ring of ordinary lines is served whole.
    #[test]
    fn ordinary_lines_are_served_whole() {
        let b = capture(LOG_CAPACITY, || {
            for i in 0..LOG_CAPACITY {
                tracing::info!(
                    target: "ipc",
                    client = "ipsec-gui",
                    peer = "pid=4242 user=CONTOSO\\alice elevated=false",
                    origin = "app",
                    n = i,
                    "connect requested"
                );
            }
        });
        let reply = b.recent_within(MAX_LOG_LINES as usize, LOG_REPLY_BYTES);
        assert_eq!(reply.len(), LOG_CAPACITY);
        assert!(frame_len(reply) <= MAX_FRAME);
    }
}
