//! Logging: `tracing` to standard error, optionally also to a file, as text or JSON.
//!
//! `RUST_LOG` takes precedence over the configured level. Under the Windows Service Control
//! Manager there is no console, so the service writes to a file only (the Event Log
//! arrives in Slice 3).

use std::{
    fs::{File, OpenOptions},
    io::IsTerminal as _,
    path::Path,
    sync::Arc,
};

use tracing_subscriber::{
    EnvFilter,
    fmt::{MakeWriter, writer::MakeWriterExt as _},
};

use crate::config::{LogFormat, LogSection};

/// Where log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// Standard error, and the file when one is configured.
    Console,
    /// The file only (a service without a console).
    FileOnly,
}

/// Installs the global subscriber for `tenko serve`.
///
/// # Errors
///
/// The log file cannot be opened, or a subscriber is already installed.
pub fn init_server(log: &LogSection, file: Option<&Path>, sink: Sink) -> anyhow::Result<()> {
    let filter = filter(&log.level);
    let file = file.map(open_append).transpose()?;
    match (sink, file) {
        (Sink::Console, None) => install(filter, log.format, std::io::stderr, terminal()),
        (Sink::Console, Some(file)) => {
            install(filter, log.format, std::io::stderr.and(file), false)
        }
        (Sink::FileOnly, Some(file)) => install(filter, log.format, file, false),
        (Sink::FileOnly, None) => anyhow::bail!("a file-only log needs a log file"),
    }
}

/// Installs the subscriber of the client commands: warnings and errors to standard error.
pub fn init_client() {
    let filter = filter("warn");
    // A second installation (tests that run commands in-process) is not an error.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(terminal())
        .try_init();
}

/// The filter: `RUST_LOG` when set, else `level`. openraft reports every election and
/// membership step at `info`; it logs at `warn` unless the directive names it.
fn filter(level: &str) -> EnvFilter {
    let directive = if level.contains("openraft") {
        level.to_owned()
    } else {
        format!("{level},openraft=warn")
    };
    EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&directive))
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

fn terminal() -> bool {
    std::io::stderr().is_terminal()
}

fn open_append(path: &Path) -> anyhow::Result<Arc<File>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("log directory {}: {error}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| anyhow::anyhow!("log file {}: {error}", path.display()))?;
    Ok(Arc::new(file))
}

fn install<W>(filter: EnvFilter, format: LogFormat, writer: W, ansi: bool) -> anyhow::Result<()>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer);
    let result = match format {
        LogFormat::Text => builder.with_ansi(ansi).try_init(),
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
    };
    result.map_err(|error| anyhow::anyhow!("logging: {error}"))
}
