use std::fmt;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::FormatTime;

struct NoTime;

impl FormatTime for NoTime {
    fn format_time(&self, _: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        Ok(())
    }
}

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
    tracing_subscriber::fmt()
        .with_timer(NoTime)
        .with_target(false)
        .with_span_events(FmtSpan::NONE)
        .with_level(true)
        .with_ansi(true)
        .with_max_level(Level::from(log_level))
        .init();
}
