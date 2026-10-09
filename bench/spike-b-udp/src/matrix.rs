//! Matrix runner: backend x mode x workers x clients.
//!
//! For every combination a fresh `serve` child process is started from this
//! very executable, the in-process load generator is run against it, the
//! server is killed and the result is appended to a JSONL file straight away,
//! so an interrupted matrix keeps everything measured so far.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};

use crate::backend::BackendKind;
use crate::load::{self, LoadArgs, group_thousands};
use crate::record::{LoadResult, RunRecord};
use crate::server::IoMode;

/// How long to wait for the `ready ` line of a freshly started server.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Rough per-run overhead (server start, process exit) used only for the time estimate.
const RUN_OVERHEAD: Duration = Duration::from_secs(2);

fn default_out() -> PathBuf {
    PathBuf::from(format!("results/raw/matrix-{}.jsonl", std::env::consts::OS))
}

#[derive(clap::Args, Debug, Clone)]
pub struct MatrixArgs {
    /// Backends to run (comma-separated).
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = BackendKind::all())]
    pub backends: Vec<BackendKind>,
    /// I/O modes to run (comma-separated).
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [IoMode::Tokio, IoMode::Threads])]
    pub modes: Vec<IoMode>,
    /// Server worker counts to run (comma-separated).
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 2, 4, 8, 16])]
    pub workers: Vec<usize>,
    /// Load-generator client counts to run (comma-separated).
    #[arg(long, value_delimiter = ',', default_values_t = [8usize])]
    pub clients: Vec<usize>,
    /// Outstanding queries per client.
    #[arg(long, default_value_t = 32)]
    pub inflight: usize,
    /// Length of the measurement window of each run.
    #[arg(long, default_value = "20s", value_parser = humantime::parse_duration)]
    pub duration: Duration,
    /// Warmup before the measurement window of each run.
    #[arg(long, default_value = "2s", value_parser = humantime::parse_duration)]
    pub warmup: Duration,
    /// Query timeout.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    pub timeout: Duration,
    /// Percentage of queries for non-existent names.
    #[arg(long, default_value_t = 5.0)]
    pub nx_percent: f64,
    /// Number of `host-{n}` names in the server's zone and in the queries.
    #[arg(long, default_value_t = crate::zone::DEFAULT_ZONE_SIZE)]
    pub zone_size: u32,
    /// Address the spawned servers listen on and the load is sent to.
    #[arg(long, default_value = "127.0.0.1:5353")]
    pub listen: std::net::SocketAddr,
    /// Pass `--reuseport` to every `serve`.
    #[arg(long)]
    pub reuseport: bool,
    /// Pause after each run, before the next server is started.
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    pub settle: Duration,
    /// JSONL file the results are appended to.
    #[arg(long, default_value_os_t = default_out())]
    pub out: PathBuf,
    /// Free-form label copied into every record.
    #[arg(long)]
    pub label: Option<String>,
    /// Print the planned runs and exit.
    #[arg(long)]
    pub dry_run: bool,
}

/// One cell of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Planned {
    backend: BackendKind,
    mode: IoMode,
    workers: usize,
    clients: usize,
}

impl Planned {
    /// `domain tokio w=4 c=8x32`
    fn describe(&self, inflight: usize) -> String {
        format!(
            "{} {} w={} c={}x{}",
            self.backend.as_str(),
            self.mode.as_str(),
            self.workers,
            self.clients,
            inflight
        )
    }
}

/// All runs in the order backend, mode, workers, clients (outermost first).
fn plan(args: &MatrixArgs) -> Vec<Planned> {
    let mut runs = Vec::new();
    for &backend in &args.backends {
        for &mode in &args.modes {
            for &workers in &args.workers {
                for &clients in &args.clients {
                    runs.push(Planned {
                        backend,
                        mode,
                        workers,
                        clients,
                    });
                }
            }
        }
    }
    runs
}

fn check_args(args: &MatrixArgs) -> anyhow::Result<()> {
    if args.backends.is_empty()
        || args.modes.is_empty()
        || args.workers.is_empty()
        || args.clients.is_empty()
    {
        bail!("--backends, --modes, --workers and --clients need at least one value each");
    }
    if args.workers.contains(&0) {
        bail!("--workers values must be at least 1");
    }
    if args.clients.contains(&0) {
        bail!("--clients values must be at least 1");
    }
    Ok(())
}

/// What the stdout reader thread of a server reports.
#[derive(Debug, PartialEq, Eq)]
enum ServerEvent {
    /// The `ready ...` line.
    Ready(String),
    /// stdout was closed (the server exited).
    Closed,
}

/// Reads the server's stdout line by line on a background thread: every line
/// is forwarded to stderr prefixed with `server: ` (which also keeps the pipe
/// from filling up), and the first line starting with `ready ` is reported.
fn pump_stdout<R: Read + Send + 'static>(stdout: R) -> Receiver<ServerEvent> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut ready_sent = false;
        for chunk in BufReader::new(stdout).split(b'\n') {
            let Ok(bytes) = chunk else { break };
            let line = String::from_utf8_lossy(&bytes);
            let line = line.trim_end_matches('\r');
            eprintln!("server: {line}");
            if !ready_sent && line.starts_with("ready ") {
                ready_sent = true;
                let _ = tx.send(ServerEvent::Ready(line.to_string()));
            }
        }
        let _ = tx.send(ServerEvent::Closed);
    });
    rx
}

/// A running `serve` child; killed and reaped when dropped.
struct ServerProc {
    child: Child,
}

impl ServerProc {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `serve` and waits until it reports `ready`.
fn start_server(args: &MatrixArgs, p: &Planned) -> anyhow::Result<ServerProc> {
    let exe = std::env::current_exe().context("cannot find the current executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("serve")
        .arg("--listen")
        .arg(args.listen.to_string())
        .arg("--backend")
        .arg(p.backend.as_str())
        .arg("--mode")
        .arg(p.mode.as_str())
        .arg("--workers")
        .arg(p.workers.to_string())
        .arg("--zone-size")
        .arg(args.zone_size.to_string());
    if args.reuseport {
        cmd.arg("--reuseport");
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("cannot start the server process")?;
    let stdout = child.stdout.take().expect("stdout was piped");
    // From here on the guard kills the child on every early return.
    let mut server = ServerProc { child };
    let events = pump_stdout(stdout);

    match events.recv_timeout(READY_TIMEOUT) {
        Ok(ServerEvent::Ready(_)) => Ok(server),
        Ok(ServerEvent::Closed) | Err(RecvTimeoutError::Disconnected) => {
            let status = server
                .child
                .wait()
                .map(|s| s.to_string())
                .unwrap_or_default();
            bail!("server exited before it was ready ({status})");
        }
        Err(RecvTimeoutError::Timeout) => {
            bail!("server not ready after {} s", READY_TIMEOUT.as_secs())
        }
    }
}

/// Starts a server, runs the load against it and stops the server again.
fn run_one(args: &MatrixArgs, p: &Planned) -> anyhow::Result<LoadResult> {
    let server = start_server(args, p)?;
    let load_args = LoadArgs {
        target: args.listen,
        clients: p.clients,
        inflight: args.inflight,
        duration: args.duration,
        warmup: args.warmup,
        timeout: args.timeout,
        nx_percent: args.nx_percent,
        zone_size: args.zone_size,
        no_edns: false,
        server_pid: Some(server.pid()),
        json: None,
        label: None,
        seed: 1,
    };
    let result = load::run_load(&load_args);
    // Kill and reap the server (also done by Drop) before reporting anything.
    drop(server);
    result
}

/// One progress line, e.g.
/// `[3/24] domain tokio w=4 c=8x32: 123,456 qps p50 41.0us p99 120.3us p99.9 300.1us srv-cpu 3.95 cores rss 21.3 MiB timeouts 0 errors 0`
fn progress_line(index: usize, total: usize, desc: &str, r: &LoadResult) -> String {
    let l = &r.latency_us;
    let server = match &r.server {
        Some(s) => format!(
            "srv-cpu {:.2} cores rss {:.1} MiB",
            s.cpu_cores, s.peak_rss_mib
        ),
        None => "srv-cpu n/a rss n/a".to_string(),
    };
    let mut line = format!(
        "[{index}/{total}] {desc}: {} qps p50 {:.1}us p99 {:.1}us p99.9 {:.1}us {server} timeouts {} errors {}",
        group_thousands(r.qps.round() as u64),
        l.p50,
        l.p99,
        l.p999,
        r.timeouts,
        r.errors
    );
    if r.unexpected > 0 {
        line.push_str(&format!(" unexpected {}", r.unexpected));
    }
    if r.send_errors > 0 {
        line.push_str(&format!(" send-errors {}", r.send_errors));
    }
    line
}

fn estimate(args: &MatrixArgs, runs: usize) -> Duration {
    (args.warmup + args.duration + args.settle + RUN_OVERHEAD) * runs as u32
}

pub fn run(args: &MatrixArgs) -> anyhow::Result<()> {
    check_args(args)?;
    let runs = plan(args);
    let total = runs.len();

    if args.dry_run {
        for (i, p) in runs.iter().enumerate() {
            println!("[{}/{}] {}", i + 1, total, p.describe(args.inflight));
        }
        println!(
            "{total} runs of {} warmup + {} measured, about {} in total, results to {}",
            humantime::format_duration(args.warmup),
            humantime::format_duration(args.duration),
            humantime::format_duration(Duration::from_secs(estimate(args, total).as_secs())),
            args.out.display()
        );
        return Ok(());
    }

    eprintln!(
        "matrix: {total} runs, about {}, results to {}",
        humantime::format_duration(Duration::from_secs(estimate(args, total).as_secs())),
        args.out.display()
    );
    let mut failed = 0usize;
    for (i, p) in runs.iter().enumerate() {
        let index = i + 1;
        let desc = p.describe(args.inflight);
        match run_one(args, p) {
            Ok(result) => {
                eprintln!("{}", progress_line(index, total, &desc, &result));
                let rec = RunRecord {
                    timestamp: load::now_rfc3339(),
                    os: std::env::consts::OS.to_string(),
                    label: args.label.clone(),
                    backend: Some(p.backend.as_str().to_string()),
                    mode: Some(p.mode.as_str().to_string()),
                    workers: Some(p.workers),
                    reuseport: Some(args.reuseport),
                    result,
                };
                load::append_record(&args.out, &rec)?;
            }
            Err(e) => {
                failed += 1;
                eprintln!("[{index}/{total}] {desc}: FAILED: {e:#}");
            }
        }
        thread::sleep(args.settle);
    }
    if failed > 0 {
        bail!("{failed} of {total} runs failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{LatencyUs, ServerStats};
    use clap::{CommandFactory, Parser};
    use std::io::Cursor;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: MatrixArgs,
    }

    fn parse(extra: &[&str]) -> MatrixArgs {
        let mut argv = vec!["x"];
        argv.extend_from_slice(extra);
        Wrapper::try_parse_from(argv).unwrap().args
    }

    #[test]
    fn cli_definition_and_defaults() {
        Wrapper::command().debug_assert();
        let a = parse(&[]);
        assert_eq!(a.backends, BackendKind::all());
        assert_eq!(a.modes, vec![IoMode::Tokio, IoMode::Threads]);
        assert_eq!(a.workers, vec![1, 2, 4, 8, 16]);
        assert_eq!(a.clients, vec![8]);
        assert_eq!(a.inflight, 32);
        assert_eq!(a.duration, Duration::from_secs(20));
        assert_eq!(a.warmup, Duration::from_secs(2));
        assert_eq!(a.timeout, Duration::from_secs(1));
        assert_eq!(a.settle, Duration::from_secs(1));
        assert_eq!(a.nx_percent, 5.0);
        assert_eq!(a.zone_size, 100_000);
        assert_eq!(a.listen.to_string(), "127.0.0.1:5353");
        assert!(!a.reuseport && !a.dry_run);
        assert_eq!(a.out, default_out());
        assert!(
            a.out
                .to_string_lossy()
                .ends_with(&format!("matrix-{}.jsonl", std::env::consts::OS))
        );
        assert!(a.label.is_none());
    }

    #[cfg(feature = "backend-domain")]
    #[test]
    fn cli_lists_are_comma_separated() {
        let a = parse(&[
            "--backends",
            "domain",
            "--modes",
            "threads,tokio",
            "--workers",
            "1,4",
            "--clients",
            "2,8",
            "--duration",
            "3s",
            "--warmup",
            "500ms",
            "--reuseport",
            "--dry-run",
        ]);
        assert_eq!(a.backends, vec![BackendKind::Domain]);
        assert_eq!(a.modes, vec![IoMode::Threads, IoMode::Tokio]);
        assert_eq!(a.workers, vec![1, 4]);
        assert_eq!(a.clients, vec![2, 8]);
        assert_eq!(a.duration, Duration::from_secs(3));
        assert_eq!(a.warmup, Duration::from_millis(500));
        assert!(a.reuseport && a.dry_run);
    }

    #[cfg(all(feature = "backend-domain", feature = "backend-hickory"))]
    #[test]
    fn plan_nests_backend_mode_workers_clients() {
        let a = parse(&[
            "--backends",
            "domain,hickory",
            "--modes",
            "tokio,threads",
            "--workers",
            "1,2",
            "--clients",
            "4,8",
        ]);
        let runs = plan(&a);
        assert_eq!(runs.len(), 16);
        let key = |p: &Planned| (p.backend.as_str(), p.mode.as_str(), p.workers, p.clients);
        assert_eq!(key(&runs[0]), ("domain", "tokio", 1, 4));
        assert_eq!(key(&runs[1]), ("domain", "tokio", 1, 8));
        assert_eq!(key(&runs[2]), ("domain", "tokio", 2, 4));
        assert_eq!(key(&runs[4]), ("domain", "threads", 1, 4));
        assert_eq!(key(&runs[8]), ("hickory", "tokio", 1, 4));
        assert_eq!(key(&runs[15]), ("hickory", "threads", 2, 8));
        assert_eq!(runs[0].describe(32), "domain tokio w=1 c=4x32");
    }

    #[test]
    fn rejects_zero_workers_or_clients() {
        assert!(check_args(&parse(&["--workers", "0"])).is_err());
        assert!(check_args(&parse(&["--clients", "0"])).is_err());
        assert!(check_args(&parse(&[])).is_ok());
    }

    #[test]
    fn progress_line_format() {
        let r = LoadResult {
            qps: 123_456.4,
            latency_us: LatencyUs {
                p50: 41.04,
                p99: 120.3,
                p999: 300.1,
                ..Default::default()
            },
            server: Some(ServerStats {
                cpu_cores: 3.951,
                peak_rss_mib: 21.34,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            progress_line(3, 24, "domain tokio w=4 c=8x32", &r),
            "[3/24] domain tokio w=4 c=8x32: 123,456 qps p50 41.0us p99 120.3us p99.9 300.1us \
             srv-cpu 3.95 cores rss 21.3 MiB timeouts 0 errors 0"
        );
        let r = LoadResult {
            unexpected: 2,
            send_errors: 1,
            ..r
        };
        assert!(progress_line(1, 1, "d", &r).ends_with("errors 0 unexpected 2 send-errors 1"));
    }

    #[test]
    fn pump_reports_the_ready_line_once_and_then_closed() {
        let rx = pump_stdout(Cursor::new(
            b"starting\r\nready pid=1 listen=127.0.0.1:5353 backend=domain mode=tokio workers=1\r\nready again\nbye".to_vec(),
        ));
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            first,
            ServerEvent::Ready(
                "ready pid=1 listen=127.0.0.1:5353 backend=domain mode=tokio workers=1".into()
            )
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            ServerEvent::Closed
        );
    }

    #[test]
    fn pump_without_ready_line_only_reports_closed() {
        let rx = pump_stdout(Cursor::new(b"not ready\nreadying\n".to_vec()));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            ServerEvent::Closed
        );
    }
}
