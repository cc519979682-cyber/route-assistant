use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

pub fn init(data_dir: &Path) -> Option<WorkerGuard> {
    let appender = tracing_appender::rolling::never(data_dir, "route-assistant.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::new("route_assistant=info,warn");
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .with_writer(writer)
        .try_init()
        .ok()?;
    Some(guard)
}

pub fn safe_info(event: &str, detail: &str) {
    tracing::info!(event, detail = %crate::redact::redact(detail));
}
