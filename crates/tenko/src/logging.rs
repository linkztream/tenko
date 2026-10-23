//! Logging: `tracing` to standard error, optionally also to a file, as text or JSON; under
//! the Windows service also to the Application Event Log (OPS-10).
//!
//! `RUST_LOG` takes precedence over the configured level. The file is rotated by size
//! (`[log] max_file_mb`, `keep_files`): `tenko.log` becomes `tenko.log.1`, `tenko.log.1`
//! becomes `tenko.log.2` and so on, and the oldest one is removed. Under the Windows Service
//! Control Manager there is no console, so the service writes to the file and to the Event
//! Log ([`event_log`]).
//!
//! The subscriber is a registry with one layer per sink, each with its own filter, so that
//! one more layer (the OpenTelemetry traces of `crate::telemetry`) can be composed in
//! through [`Layers::extra`] without touching the others.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use tracing_subscriber::{
    EnvFilter, Layer as _, Registry,
    fmt::{MakeWriter, writer::MakeWriterExt as _},
    layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

use tenko_api::routes::system::diagnostics::LogTail;

use crate::config::{LogFormat, LogSection};

/// A layer of the server's subscriber.
pub type BoxedLayer = Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>;

/// Where log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// Standard error, and the file when one is configured.
    Console,
    /// The file only (a service without a console).
    FileOnly,
}

/// Layers composed beside the console and the file.
#[derive(Default)]
pub struct Layers {
    /// The Windows Event Log of the service ([`event_log::layer`]), with its own filter.
    pub event_log: Option<BoxedLayer>,
    /// One more layer, filtered by the configured level like the console and the file.
    pub extra: Option<BoxedLayer>,
}

impl std::fmt::Debug for Layers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layers")
            .field("event_log", &self.event_log.is_some())
            .field("extra", &self.extra.is_some())
            .finish()
    }
}

/// Installs the global subscriber for `tenko serve`.
///
/// # Errors
///
/// The log file cannot be opened, or a subscriber is already installed.
pub fn init_server(log: &LogSection, file: Option<&Path>, sink: Sink) -> anyhow::Result<()> {
    init_server_with(log, file, sink, Layers::default())
}

/// [`init_server`] with more layers.
///
/// # Errors
///
/// The log file cannot be opened, or a subscriber is already installed.
pub fn init_server_with(
    log: &LogSection,
    file: Option<&Path>,
    sink: Sink,
    layers: Layers,
) -> anyhow::Result<()> {
    let file = file
        .map(|path| RotatingFile::open(path, Rotation::of(log)))
        .transpose()?
        .map(Arc::new);
    let output = match (sink, file) {
        (Sink::Console, None) => output_layer(log.format, std::io::stderr, terminal()),
        (Sink::Console, Some(file)) => output_layer(log.format, std::io::stderr.and(file), false),
        (Sink::FileOnly, Some(file)) => output_layer(log.format, file, false),
        (Sink::FileOnly, None) => anyhow::bail!("a file-only log needs a log file"),
    };
    let mut all = vec![output.with_filter(filter(&log.level)).boxed()];
    if let Some(extra) = layers.extra {
        all.push(extra.with_filter(filter(&log.level)).boxed());
    }
    if let Some(event_log) = layers.event_log {
        all.push(event_log);
    }
    let tail = Arc::new(LogTail::new(
        tenko_api::routes::system::diagnostics::LOG_TAIL_CAPACITY,
    ));
    all.push(tail_layer(Arc::clone(&tail)));
    tracing_subscriber::registry()
        .with(all)
        .try_init()
        .map_err(|error| anyhow::anyhow!("logging: {error}"))?;
    let _ = LOG_TAIL.set(tail);
    Ok(())
}

/// The tail of the server's log that `GET /system/diagnostics` shows (bug reports): the
/// last lines at warn level or above, whatever the configured level says. Set by
/// [`init_server_with`] together with the subscriber; `None` before it ran (the client
/// commands, tests that install no server subscriber).
static LOG_TAIL: std::sync::OnceLock<Arc<LogTail>> = std::sync::OnceLock::new();

/// The log tail of this process, once the server subscriber is installed.
pub fn log_tail() -> Option<Arc<LogTail>> {
    LOG_TAIL.get().cloned()
}

/// The text layer that keeps the last warnings and errors in `tail`: the same text format
/// as the console, without colour, at warn level or above.
pub fn tail_layer(tail: Arc<LogTail>) -> BoxedLayer {
    tracing_subscriber::fmt::layer()
        .with_writer(tail)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::LevelFilter::WARN)
        .boxed()
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

/// The text or JSON layer that writes to `writer`.
fn output_layer<W>(format: LogFormat, writer: W, ansi: bool) -> BoxedLayer
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer().with_writer(writer);
    match format {
        LogFormat::Text => layer.with_ansi(ansi).boxed(),
        LogFormat::Json => layer.json().flatten_event(true).boxed(),
    }
}

/// When the log file is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// The size in bytes at which the file is rotated; 0: never.
    pub max_bytes: u64,
    /// Rotated files kept besides the active one.
    pub keep: u32,
}

impl Rotation {
    /// The rotation of `[log]`.
    pub fn of(log: &LogSection) -> Self {
        Self {
            max_bytes: log.max_file_mb.saturating_mul(1024 * 1024),
            keep: log.keep_files.max(1),
        }
    }
}

/// After a failed rotation (on Windows another process may hold a rotated file open without
/// sharing delete access), the next attempt waits until the file has grown by this much,
/// instead of renaming on every line.
const RETRY_AFTER_BYTES: u64 = 1024 * 1024;

/// A log file that is rotated by size. Every line is one `write` call of the formatting
/// layer, so a line is never split across two files.
#[derive(Debug)]
pub struct RotatingFile {
    state: Mutex<FileState>,
}

#[derive(Debug)]
struct FileState {
    path: PathBuf,
    rotation: Rotation,
    /// `None` only between closing the old file and opening the new one.
    file: Option<File>,
    size: u64,
    /// The size from which a rotation is tried again after a failed one.
    retry_at: u64,
}

impl RotatingFile {
    /// Opens `path` for appending, creating it and its directory.
    ///
    /// # Errors
    ///
    /// The directory or the file cannot be created or opened.
    pub fn open(path: &Path, rotation: Rotation) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| anyhow::anyhow!("log directory {}: {error}", parent.display()))?;
        }
        let file = open_append(path)
            .map_err(|error| anyhow::anyhow!("log file {}: {error}", path.display()))?;
        let size = file.metadata().map_or(0, |meta| meta.len());
        Ok(Self {
            state: Mutex::new(FileState {
                path: path.to_owned(),
                rotation,
                file: Some(file),
                size,
                retry_at: 0,
            }),
        })
    }

    /// The path of the `index`-th rotated file of `path` (`tenko.log.1`).
    pub fn rotated(path: &Path, index: u32) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl FileState {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let max = self.rotation.max_bytes;
        if max > 0
            && self.size > 0
            && self.size.saturating_add(len) > max
            && self.size >= self.retry_at
            && self.rotate().is_err()
        {
            self.retry_at = self.size.saturating_add(RETRY_AFTER_BYTES);
        }
        let file = match &mut self.file {
            Some(file) => file,
            None => self.file.insert(open_append(&self.path)?),
        };
        file.write_all(buf)?;
        self.size = self.size.saturating_add(len);
        Ok(buf.len())
    }

    /// Shifts `path.N-1` to `path.N` down to `path` to `path.1` and opens a new `path`. The
    /// file is closed before it is renamed, which Windows needs.
    fn rotate(&mut self) -> io::Result<()> {
        let keep = self.rotation.keep;
        if let Some(mut file) = self.file.take() {
            let _ = file.flush();
        }
        let shifted = (|| {
            let oldest = RotatingFile::rotated(&self.path, keep);
            match fs::remove_file(&oldest) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            for index in (1..keep).rev() {
                let from = RotatingFile::rotated(&self.path, index);
                if from.exists() {
                    fs::rename(&from, RotatingFile::rotated(&self.path, index + 1))?;
                }
            }
            fs::rename(&self.path, RotatingFile::rotated(&self.path, 1))
        })();
        // Whatever happened, the log goes on: into a new file, or the old one again.
        let file = open_append(&self.path)?;
        self.size = file.metadata().map_or(0, |meta| meta.len());
        self.file = Some(file);
        shifted
    }
}

impl io::Write for &RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .file
        {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// The Windows Application Event Log (OPS-10): the source is the service name, registered
/// by `tenko service install` and removed by `tenko service uninstall`. Levels map to the
/// event types: errors to Error, warnings to Warning, everything else to Information. The
/// lines of the target [`event_log::SERVICE_TARGET`] (the start and the stop of the
/// service) are written whatever `[log] event_log` says.
///
/// The Windows calls are made by the `tracing-layer-win-eventlog` crate, which keeps this
/// crate free of `unsafe` code. The message file is the one of the .NET Framework, which
/// renders every event id as its text (`%1`); see [`event_log::message_file`].
pub mod event_log {
    use std::path::PathBuf;

    use tracing_subscriber::filter::{LevelFilter, Targets};

    use crate::config::EventLogLevel;

    /// The target of the lines that always reach the Event Log.
    pub const SERVICE_TARGET: &str = "tenko::service";

    /// The registry key of an Application log source.
    pub fn source_key(source: &str) -> String {
        format!(r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}")
    }

    /// The message file of the .NET Framework under `system_root` (`%SystemRoot%`): it holds
    /// the text `%1` for every event id, so an event shows exactly the string it was
    /// written with. It ships with every supported Windows version.
    pub fn message_file(system_root: &std::path::Path) -> PathBuf {
        system_root
            .join("Microsoft.NET")
            .join("Framework64")
            .join("v4.0.30319")
            .join("EventLogMessages.dll")
    }

    /// The filter of the Event Log layer.
    pub fn targets(level: EventLogLevel) -> Targets {
        let level = match level {
            EventLogLevel::Off => LevelFilter::OFF,
            EventLogLevel::Error => LevelFilter::ERROR,
            EventLogLevel::Warn => LevelFilter::WARN,
            EventLogLevel::Info => LevelFilter::INFO,
            EventLogLevel::Debug => LevelFilter::DEBUG,
            EventLogLevel::Trace => LevelFilter::TRACE,
        };
        Targets::new()
            .with_default(level)
            .with_target(SERVICE_TARGET, LevelFilter::INFO.max(level))
    }

    /// The Event Log layer for `source`, filtered by `level`.
    ///
    /// # Errors
    ///
    /// The event source cannot be opened.
    #[cfg(windows)]
    pub fn layer(source: &str, level: EventLogLevel) -> anyhow::Result<super::BoxedLayer> {
        use tracing_subscriber::Layer as _;

        let layer = tracing_layer_win_eventlog::EventLogLayer::new(source)
            .map_err(|error| anyhow::anyhow!("event log source {source}: {error}"))?;
        Ok(layer.with_filter(targets(level)).boxed())
    }

    /// Writes one error to the Event Log of `source` without a global subscriber: for
    /// failures before the log is set up (a configuration that stopped being valid, a log
    /// directory that cannot be written).
    #[cfg(windows)]
    pub fn report_early(source: &str, message: &str) {
        use tracing_subscriber::layer::SubscriberExt as _;

        let Ok(layer) = tracing_layer_win_eventlog::EventLogLayer::new(source) else {
            return;
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: SERVICE_TARGET, "{message}");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EventLogLevel;

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(file: &RotatingFile, count: usize, width: usize) {
        for index in 0..count {
            let line = format!("{index:0width$}\n", width = width - 1);
            (&*file).write_all(line.as_bytes()).expect("write");
        }
    }

    #[test]
    fn a_file_below_the_limit_is_not_rotated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("logs").join("tenko.log");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 1_000,
                keep: 2,
            },
        )
        .expect("open");
        write_lines(&file, 10, 10);
        assert_eq!(lines(&path).len(), 10);
        assert!(!RotatingFile::rotated(&path, 1).exists());
    }

    #[test]
    fn a_full_file_moves_to_dot_one_and_lines_stay_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 100,
                keep: 3,
            },
        )
        .expect("open");
        // 25 lines of 10 bytes: 10 per file, the newest 5 in the active file.
        write_lines(&file, 25, 10);
        let active = lines(&path);
        let first = lines(&RotatingFile::rotated(&path, 1));
        let second = lines(&RotatingFile::rotated(&path, 2));
        assert_eq!(active.len(), 5);
        assert_eq!(first.len(), 10);
        assert_eq!(second.len(), 10);
        assert_eq!(second.first().map(String::as_str), Some("000000000"));
        assert_eq!(first.first().map(String::as_str), Some("000000010"));
        assert_eq!(active.first().map(String::as_str), Some("000000020"));
        assert!(
            [&active, &first, &second]
                .iter()
                .flat_map(|lines| lines.iter())
                .all(|line| line.len() == 9)
        );
    }

    #[test]
    fn only_keep_files_are_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 50,
                keep: 2,
            },
        )
        .expect("open");
        write_lines(&file, 40, 10);
        assert!(RotatingFile::rotated(&path, 1).exists());
        assert!(RotatingFile::rotated(&path, 2).exists());
        assert!(!RotatingFile::rotated(&path, 3).exists());
        // The newest lines survive.
        let active = lines(&path);
        assert_eq!(active.last().map(String::as_str), Some("000000039"));
    }

    #[test]
    fn rotation_zero_never_rotates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 0,
                keep: 1,
            },
        )
        .expect("open");
        write_lines(&file, 100, 10);
        assert_eq!(lines(&path).len(), 100);
        assert!(!RotatingFile::rotated(&path, 1).exists());
    }

    #[test]
    fn an_existing_file_counts_towards_the_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        fs::write(&path, "x".repeat(95) + "\n").expect("seed");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 100,
                keep: 1,
            },
        )
        .expect("open");
        write_lines(&file, 1, 10);
        assert_eq!(lines(&RotatingFile::rotated(&path, 1)).len(), 1);
        assert_eq!(lines(&path), vec!["000000000".to_owned()]);
    }

    #[test]
    fn a_line_longer_than_the_limit_is_written_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 10,
                keep: 1,
            },
        )
        .expect("open");
        (&file)
            .write_all(format!("{}\n", "y".repeat(40)).as_bytes())
            .expect("write");
        (&file).write_all(b"z\n").expect("write");
        assert_eq!(
            lines(&RotatingFile::rotated(&path, 1)),
            vec!["y".repeat(40)]
        );
        assert_eq!(lines(&path), vec!["z".to_owned()]);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_keeps_logging_and_waits_before_the_next_try() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tenko.log");
        // A directory where the oldest rotated file would go makes the removal fail.
        fs::create_dir_all(RotatingFile::rotated(&path, 1).join("busy")).expect("block");
        let file = RotatingFile::open(
            &path,
            Rotation {
                max_bytes: 20,
                keep: 1,
            },
        )
        .expect("open");
        write_lines(&file, 6, 10);
        assert_eq!(lines(&path).len(), 6);
        let state = file.state.lock().expect("lock");
        assert!(state.retry_at >= RETRY_AFTER_BYTES);
    }

    #[test]
    fn rotation_follows_the_configuration() {
        let log = LogSection {
            max_file_mb: 3,
            keep_files: 7,
            ..LogSection::default()
        };
        assert_eq!(
            Rotation::of(&log),
            Rotation {
                max_bytes: 3 * 1024 * 1024,
                keep: 7
            }
        );
    }

    /// Records the target and level of every event it sees.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(String, tracing::Level)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let meta = event.metadata();
            self.0
                .lock()
                .expect("lock")
                .push((meta.target().to_owned(), *meta.level()));
        }
    }

    fn seen_by(level: EventLogLevel) -> Vec<(String, tracing::Level)> {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry()
            .with(capture.clone().with_filter(event_log::targets(level)));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "tenko::serve", "e");
            tracing::warn!(target: "tenko::serve", "w");
            tracing::info!(target: "tenko::serve", "i");
            tracing::debug!(target: "tenko_store", "d");
            tracing::info!(target: event_log::SERVICE_TARGET, "starting");
            tracing::trace!(target: event_log::SERVICE_TARGET, "t");
        });
        capture.0.lock().expect("lock").clone()
    }

    #[test]
    fn event_log_levels_keep_the_service_lines() {
        use tracing::Level;
        let service = event_log::SERVICE_TARGET.to_owned();
        let serve = "tenko::serve".to_owned();
        assert_eq!(
            seen_by(EventLogLevel::Warn),
            vec![
                (serve.clone(), Level::ERROR),
                (serve.clone(), Level::WARN),
                (service.clone(), Level::INFO),
            ]
        );
        assert_eq!(
            seen_by(EventLogLevel::Off),
            vec![(service.clone(), Level::INFO)]
        );
        assert_eq!(seen_by(EventLogLevel::Debug).len(), 5);
        assert_eq!(seen_by(EventLogLevel::Trace).len(), 6);
        assert_eq!(seen_by(EventLogLevel::Error).len(), 2);
    }

    #[test]
    fn the_source_key_and_the_message_file() {
        assert_eq!(
            event_log::source_key("tenko"),
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\tenko"
        );
        let file = event_log::message_file(Path::new("C:/Windows"));
        assert!(file.ends_with("EventLogMessages.dll"));
        assert!(file.to_string_lossy().contains("v4.0.30319"));
    }
}
