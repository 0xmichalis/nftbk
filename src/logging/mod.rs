use time::{macros::format_description, UtcOffset};
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::OffsetTime;

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

pub fn init(log_level: LogLevel) {
    static TIME_FORMAT: &[time::format_description::FormatItem<'_>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    let timer = OffsetTime::new(UtcOffset::UTC, TIME_FORMAT);
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(false)
        .with_span_events(FmtSpan::NONE)
        .with_level(true)
        .with_ansi(true)
        .with_max_level(Level::from(log_level))
        .init();
}
