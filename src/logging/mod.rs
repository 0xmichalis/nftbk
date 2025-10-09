use std::fmt;
use time::{macros::format_description, OffsetDateTime, UtcOffset};
use tracing::Level;
use tracing_subscriber::fmt::format::{FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

static TIME_FORMAT: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:2]Z");

pub fn init(log_level: LogLevel, enable_color: bool) {
    tracing_subscriber::fmt()
        .with_level(true)
        .with_ansi(enable_color)
        .with_max_level(Level::from(log_level))
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .event_format(CustomFormat)
        .init();
}

struct CustomFormat;

impl<S, N> FormatEvent<S, N> for CustomFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        // Print timestamp
        let now = OffsetDateTime::now_utc().to_offset(UtcOffset::UTC);
        if writer.has_ansi_escapes() {
            write!(
                writer,
                "\x1b[96m{}\x1b[0m ",
                now.format(TIME_FORMAT).unwrap_or("".into())
            )?;
        } else {
            write!(writer, "{} ", now.format(TIME_FORMAT).unwrap_or("".into()))?;
        }

        // Print log level
        let level = *event.metadata().level();
        if writer.has_ansi_escapes() {
            let color = match level {
                Level::ERROR => "\x1b[31m", // Red
                Level::WARN => "\x1b[33m",  // Yellow
                Level::INFO => "\x1b[32m",  // Green
                Level::DEBUG => "\x1b[36m", // Cyan
                _ => "\x1b[0m",             // Default
            };
            write!(writer, "{color}{level:>5}\x1b[0m ")?;
        } else {
            write!(writer, "{level:>5} ")?;
        }

        // Print the log message
        _ctx.format_fields(writer.by_ref(), event)?;

        // Print span fields at the end
        if let Some(scope) = _ctx.event_scope() {
            let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
            for span in scope.from_root() {
                let exts = span.extensions();
                let Some(fields) = exts.get::<FormattedFields<N>>() else {
                    continue;
                };
                let fields = fields.fields.as_str();
                if fields.is_empty() {
                    continue;
                }
                if !writer.has_ansi_escapes() {
                    write!(writer, " {fields}")?;
                } else {
                    let colored: String = fields
                        .split_whitespace()
                        .map(|pair| {
                            let mut parts = pair.splitn(2, '=');
                            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                                let clean_key = ansi_regex.replace_all(key, "");
                                let clean_value = ansi_regex.replace_all(value, "");
                                format!("\x1b[36m{clean_key}\x1b[0m=\x1b[93m{clean_value}\x1b[0m",)
                            } else {
                                pair.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    write!(writer, " {colored}")?;
                }
            }
        }
        writeln!(writer)
    }
}

#[cfg(test)]
mod from_loglevel_tests {
    #[test]
    fn maps_loglevel_to_tracing_level() {
        assert_eq!(
            tracing::Level::from(super::LogLevel::Debug),
            tracing::Level::DEBUG
        );
        assert_eq!(
            tracing::Level::from(super::LogLevel::Info),
            tracing::Level::INFO
        );
        assert_eq!(
            tracing::Level::from(super::LogLevel::Warn),
            tracing::Level::WARN
        );
        assert_eq!(
            tracing::Level::from(super::LogLevel::Error),
            tracing::Level::ERROR
        );
    }
}

#[cfg(test)]
mod custom_format_tests {
    use std::io::{Result as IoResult, Write};
    use std::sync::{Arc, Mutex};
    use tracing::{info, Level as TracingLevel};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedBufferWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for SharedBufferWriter {
        type Writer = BufferGuard;

        fn make_writer(&'a self) -> Self::Writer {
            BufferGuard(self.0.clone())
        }
    }

    struct BufferGuard(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferGuard {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            let mut guard = self.0.lock().unwrap();
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    fn with_subscriber<F: FnOnce()>(ansi: bool, buf: &SharedBufferWriter, f: F) {
        let subscriber = tracing_subscriber::fmt()
            .with_level(true)
            .with_ansi(ansi)
            .with_max_level(TracingLevel::DEBUG)
            .with_file(false)
            .with_line_number(false)
            .with_target(false)
            .event_format(super::CustomFormat)
            .with_writer(buf.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            f();
        });
    }

    #[test]
    fn formats_without_ansi() {
        let buffer = SharedBufferWriter(Arc::new(Mutex::new(Vec::new())));
        with_subscriber(false, &buffer, || {
            let span = tracing::info_span!("span_name", user_id = 42, kind = "test");
            let _entered = span.enter();
            info!("hello world");
        });
        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();

        // Expect timestamp (YYYY-MM-DDTHH:MM:SS), level, message, and span fields without color codes
        assert!(output.contains(" INFO "));
        assert!(output.contains("hello world"));
        assert!(output.contains("user_id=42"));
        assert!(output.contains("kind=\"test\""));
        // No ANSI escapes expected
        assert!(!output.contains("\x1b["));
    }

    #[test]
    fn formats_with_ansi() {
        let buffer = SharedBufferWriter(Arc::new(Mutex::new(Vec::new())));
        with_subscriber(true, &buffer, || {
            let span = tracing::info_span!("span_name", user_id = 7, label = "x");
            let _entered = span.enter();
            info!("colored message");
        });
        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();

        // Expect ANSI colored timestamp (cyan), level (green for INFO), and colored span fields
        assert!(output.contains("\x1b[96m")); // timestamp color
        assert!(output.contains("\x1b[32m")); // has level color
        assert!(output.contains(" INFO")); // right-justified level text has at least one leading space
        assert!(output.contains("\x1b[0m")); // reset code present
        assert!(output.contains("colored message"));
        assert!(output.contains("\x1b[36muser_id\x1b[0m=\x1b[93m7\x1b[0m"));
        assert!(output.contains("\x1b[36mlabel\x1b[0m=\x1b[93m\"x\"\x1b[0m"));
    }
}
