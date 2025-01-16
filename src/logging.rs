use std::fmt;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::FormatTime;

struct NoTime;

impl FormatTime for NoTime {
    fn format_time(&self, _: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        Ok(())
    }
}
pub fn init() {
    tracing_subscriber::fmt()
        .with_timer(NoTime)
        .with_target(false)
        .with_span_events(FmtSpan::NONE)
        .with_level(true)
        .with_ansi(true)
        .init();
}
