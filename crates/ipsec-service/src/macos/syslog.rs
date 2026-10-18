//! Lifecycle events, warnings and errors to the system log, which on macOS is
//! the unified log (004 research R8, FR-006). The selection and formatting
//! are portable and unit-tested; the macOS sink is `syslog(3)` in `sys`.

use std::fmt::{self, Write};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// `syslog(3)` priorities (`<syslog.h>`).
pub const LOG_ERR: i32 = 3;
pub const LOG_WARNING: i32 = 4;
pub const LOG_INFO: i32 = 6;

/// Longest message sent; the file log keeps the full line.
const MAX_MESSAGE: usize = 1024;

/// The priority an event is forwarded with, or `None` to keep it out of the
/// system log: every warning and error, and service lifecycle (`host`) events
/// at info level.
pub fn priority(target: &str, level: &Level) -> Option<i32> {
    match *level {
        Level::ERROR => Some(LOG_ERR),
        Level::WARN => Some(LOG_WARNING),
        Level::INFO if target == "host" => Some(LOG_INFO),
        _ => None,
    }
}

type Sink = Box<dyn Fn(i32, &str) + Send + Sync>;

pub struct SyslogLayer {
    sink: Sink,
}

impl SyslogLayer {
    pub fn new(sink: impl Fn(i32, &str) + Send + Sync + 'static) -> Self {
        SyslogLayer {
            sink: Box::new(sink),
        }
    }

    /// The real sink: `syslog(3)` as `ipsec-service`.
    #[cfg(target_os = "macos")]
    pub fn system() -> Self {
        super::sys::syslog_open();
        Self::new(super::sys::syslog_write)
    }
}

/// `message` first, then ` key=value` pairs. Every value is escaped (no
/// control characters reach the log) and the whole is capped.
#[derive(Default)]
struct Line {
    message: String,
    fields: String,
}

impl Line {
    fn push(&mut self, field: &Field, value: fmt::Arguments<'_>) {
        let escaped: String = value.to_string().escape_debug().collect();
        if field.name() == "message" {
            self.message.push_str(&escaped);
        } else {
            let _ = write!(self.fields, " {}={escaped}", field.name());
        }
    }

    fn finish(mut self, target: &str) -> String {
        let mut out = format!("[{target}] ");
        out.push_str(&self.message);
        out.push_str(&std::mem::take(&mut self.fields));
        if out.len() > MAX_MESSAGE {
            let mut cut = MAX_MESSAGE;
            while !out.is_char_boundary(cut) {
                cut -= 1;
            }
            out.truncate(cut);
            out.push('…');
        }
        out
    }
}

impl Visit for Line {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, format_args!("{value}"));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format_args!("{value:?}"));
    }
}

impl<S: Subscriber> Layer<S> for SyslogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let Some(prio) = priority(meta.target(), meta.level()) else {
            return;
        };
        let mut line = Line::default();
        event.record(&mut line);
        (self.sink)(prio, &line.finish(meta.target()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    #[test]
    fn selects_lifecycle_warnings_and_errors() {
        assert_eq!(priority("host", &Level::INFO), Some(LOG_INFO));
        assert_eq!(priority("session", &Level::INFO), None);
        assert_eq!(priority("host", &Level::DEBUG), None);
        assert_eq!(priority("session", &Level::WARN), Some(LOG_WARNING));
        assert_eq!(priority("ipc", &Level::ERROR), Some(LOG_ERR));
    }

    fn capture(f: impl FnOnce()) -> Vec<(i32, String)> {
        let got = Arc::new(Mutex::new(Vec::new()));
        let sink = got.clone();
        let sub = tracing_subscriber::registry().with(SyslogLayer::new(move |p, m| {
            sink.lock().unwrap().push((p, m.to_string()))
        }));
        tracing::subscriber::with_default(sub, f);
        let v = got.lock().unwrap().clone();
        v
    }

    #[test]
    fn formats_target_message_and_escaped_fields() {
        let got = capture(|| {
            tracing::info!(target: "host", version = "1.0", "starting");
            tracing::info!(target: "session", "not forwarded");
            tracing::warn!(target: "ipc", peer = "evil\nline", "bad frame");
        });
        assert_eq!(
            got,
            [
                (LOG_INFO, "[host] starting version=1.0".to_string()),
                (LOG_WARNING, "[ipc] bad frame peer=evil\\nline".to_string()),
            ]
        );
    }

    #[test]
    fn long_messages_are_capped() {
        let long = "é".repeat(2000);
        let got = capture(|| tracing::error!(target: "host", detail = %long, "boom"));
        let (_, msg) = &got[0];
        assert!(msg.len() <= MAX_MESSAGE + '…'.len_utf8());
        assert!(msg.starts_with("[host] boom detail="));
        assert!(msg.ends_with('…'));
    }
}
