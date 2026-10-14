//! Paired runs: the same load against the responder with the metrics off and on, back to
//! back, alternating which goes first in each pair, so that slow drifts in machine load
//! hit both alike. Every run starts a fresh `serve` child from this executable, runs the
//! closed-loop load generator of Spike B in process, stops the child (by closing its
//! standard input) and appends one JSON line in the Spike B record format.

use std::{
    io::{BufRead as _, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail};
use spike_b_udp::{
    load::{self, LoadArgs},
    record::{LoadResult, RunRecord},
    zone::DEFAULT_ZONE_SIZE,
};

use crate::responder::Metrics;

/// How long to wait for the `ready` line of a fresh server.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Options of `pairs`.
#[derive(clap::Args, Debug, Clone)]
pub struct PairsArgs {
    /// Address of the responder (a loopback address; on Windows not 5353, which mDNS holds).
    #[arg(long, default_value = "127.0.0.1:5399")]
    pub listen: std::net::SocketAddr,
    /// Worker threads of the responder.
    #[arg(long, default_value_t = 4)]
    pub workers: usize,
    /// Client sockets of the load generator, one thread each.
    #[arg(long, default_value_t = 8)]
    pub clients: usize,
    /// Outstanding queries per client.
    #[arg(long, default_value_t = 32)]
    pub inflight: usize,
    /// Length of each measurement window.
    #[arg(long, default_value = "20s", value_parser = humantime::parse_duration)]
    pub duration: Duration,
    /// Load before each window, not counted.
    #[arg(long, default_value = "2s", value_parser = humantime::parse_duration)]
    pub warmup: Duration,
    /// Number of pairs.
    #[arg(long, default_value_t = 5)]
    pub pairs: usize,
    /// JSONL file the records are appended to.
    #[arg(long, default_value = "results/raw/m8.jsonl")]
    pub out: PathBuf,
    /// Prefix of the record labels.
    #[arg(long, default_value = "m8")]
    pub label: String,
}

/// Options of `report`.
#[derive(clap::Args, Debug, Clone)]
pub struct ReportArgs {
    /// JSONL files written by `pairs`.
    #[arg(long, required = true)]
    pub input: Vec<PathBuf>,
}

/// One run of a pair.
#[derive(Debug, Clone)]
pub struct Run {
    /// The set of pairs: the label without the pair and the metrics switch.
    pub set: String,
    /// The pair, from 1.
    pub pair: usize,
    /// Worker threads.
    pub workers: usize,
    /// Metrics on or off.
    pub metrics: Metrics,
    /// Responses per second.
    pub qps: f64,
    /// 99th percentile latency, microseconds.
    pub p99_us: f64,
    /// Timeouts and invalid responses.
    pub failures: u64,
}

/// Runs the pairs and prints the table.
///
/// # Errors
///
/// A server that does not start, or a failed load run.
pub fn run(args: &PairsArgs) -> anyhow::Result<()> {
    let mut runs = Vec::new();
    for pair in 1..=args.pairs {
        let order = if pair % 2 == 1 {
            [Metrics::Off, Metrics::On]
        } else {
            [Metrics::On, Metrics::Off]
        };
        for metrics in order {
            let result = run_one(args, metrics)?;
            let label = format!(
                "{}-w{}-pair-{pair}-metrics-{}",
                args.label,
                args.workers,
                metrics.as_str()
            );
            eprintln!(
                "{label}: {:.0} qps p50 {:.1} us p99 {:.1} us timeouts {} errors {}",
                result.qps,
                result.latency_us.p50,
                result.latency_us.p99,
                result.timeouts,
                result.errors
            );
            let record = RunRecord {
                timestamp: load::now_rfc3339(),
                os: std::env::consts::OS.to_owned(),
                label: Some(label),
                backend: Some("domain".to_owned()),
                mode: Some("threads".to_owned()),
                workers: Some(args.workers),
                reuseport: Some(false),
                result: result.clone(),
            };
            load::append_record(&args.out, &record)?;
            runs.push(Run {
                set: format!("{}-w{}", args.label, args.workers),
                pair,
                workers: args.workers,
                metrics,
                qps: result.qps,
                p99_us: result.latency_us.p99,
                failures: result.timeouts + result.errors,
            });
        }
    }
    print!("{}", table(&runs));
    Ok(())
}

/// Reads JSONL files written by `pairs` and prints the tables.
///
/// # Errors
///
/// A file that cannot be read or a line that is not a record.
pub fn report(args: &ReportArgs) -> anyhow::Result<()> {
    let mut runs = Vec::new();
    for path in &args.input {
        runs.extend(read_runs(path)?);
    }
    let mut sets: Vec<String> = Vec::new();
    for run in &runs {
        if !sets.contains(&run.set) {
            sets.push(run.set.clone());
        }
    }
    for set in &sets {
        let subset: Vec<Run> = runs.iter().filter(|run| run.set == *set).cloned().collect();
        println!("Set {set}\n");
        print!("{}", table(&subset));
        println!();
    }
    let mut workers: Vec<usize> = runs.iter().map(|run| run.workers).collect();
    workers.sort_unstable();
    workers.dedup();
    for count in workers {
        let (mut qps, mut p99) = (Vec::new(), Vec::new());
        for set in &sets {
            for (pair_qps, pair_p99) in changes(
                &runs
                    .iter()
                    .filter(|run| run.set == *set && run.workers == count)
                    .cloned()
                    .collect::<Vec<_>>(),
            ) {
                qps.push(pair_qps);
                p99.push(pair_p99);
            }
        }
        println!(
            "Workers {count}, all sets: {} pairs, median QPS change {:+.2} %, median p99 change {:+.1} %",
            qps.len(),
            median(&mut qps),
            median(&mut p99)
        );
    }
    Ok(())
}

/// The QPS and p99 changes (on against off, percent) of every complete pair of one set.
fn changes(runs: &[Run]) -> Vec<(f64, f64)> {
    let mut pairs: Vec<usize> = runs.iter().map(|run| run.pair).collect();
    pairs.sort_unstable();
    pairs.dedup();
    pairs
        .into_iter()
        .filter_map(|pair| {
            let find = |metrics| {
                runs.iter()
                    .find(|run| run.pair == pair && run.metrics == metrics)
            };
            let (off, on) = (find(Metrics::Off)?, find(Metrics::On)?);
            Some((percent(on.qps, off.qps), percent(on.p99_us, off.p99_us)))
        })
        .collect()
}

fn read_runs(path: &Path) -> anyhow::Result<Vec<Run>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut runs = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let record: RunRecord = serde_json::from_str(line).context("a run record")?;
        let Some(label) = record.label.as_deref() else {
            continue;
        };
        let Some((head, metrics)) = label.rsplit_once("-metrics-") else {
            continue;
        };
        let metrics = if metrics == "on" {
            Metrics::On
        } else {
            Metrics::Off
        };
        let pair = head
            .rsplit_once("-pair-")
            .and_then(|(_, pair)| pair.parse().ok())
            .unwrap_or_default();
        let set = head.rsplit_once("-pair-").map_or(head, |(set, _)| set);
        runs.push(Run {
            set: set.to_owned(),
            pair,
            workers: record.workers.unwrap_or_default(),
            metrics,
            qps: record.result.qps,
            p99_us: record.result.latency_us.p99,
            failures: record.result.timeouts + record.result.errors,
        });
    }
    Ok(runs)
}

/// The Markdown table of the pairs: QPS and p99 off and on, and the change.
pub fn table(runs: &[Run]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "| Pair | QPS off | QPS on | QPS change | p99 off (µs) | p99 on (µs) | p99 change |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|");
    let mut qps_changes = Vec::new();
    let mut p99_changes = Vec::new();
    let mut pairs: Vec<usize> = runs.iter().map(|run| run.pair).collect();
    pairs.sort_unstable();
    pairs.dedup();
    for pair in pairs {
        let find = |metrics| {
            runs.iter()
                .find(|run| run.pair == pair && run.metrics == metrics)
        };
        let (Some(off), Some(on)) = (find(Metrics::Off), find(Metrics::On)) else {
            continue;
        };
        let qps_change = percent(on.qps, off.qps);
        let p99_change = percent(on.p99_us, off.p99_us);
        qps_changes.push(qps_change);
        p99_changes.push(p99_change);
        let _ = writeln!(
            out,
            "| {pair} | {:.0} | {:.0} | {qps_change:+.2} % | {:.1} | {:.1} | {p99_change:+.1} % |",
            off.qps, on.qps, off.p99_us, on.p99_us
        );
    }
    let _ = writeln!(
        out,
        "| median | | | {:+.2} % | | | {:+.1} % |",
        median(&mut qps_changes),
        median(&mut p99_changes)
    );
    let failures: u64 = runs.iter().map(|run| run.failures).sum();
    let _ = writeln!(
        out,
        "\nTimeouts and invalid responses over all runs: {failures}"
    );
    out
}

/// `(value / base - 1) * 100`.
fn percent(value: f64, base: f64) -> f64 {
    if base == 0.0 {
        0.0
    } else {
        (value / base - 1.0) * 100.0
    }
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        values[middle]
    } else {
        f64::midpoint(values[middle - 1], values[middle])
    }
}

/// A running `serve` child; stopped and reaped when dropped.
struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        // Closing standard input stops the server; kill it if that did not happen.
        drop(self.child.stdin.take());
        for _ in 0..50 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum Event {
    Ready,
    Closed,
}

fn pump(stdout: impl Read + Send + 'static) -> Receiver<Event> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut ready = false;
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            eprintln!("server: {line}");
            if !ready && line.starts_with("ready ") {
                ready = true;
                let _ = tx.send(Event::Ready);
            }
        }
        let _ = tx.send(Event::Closed);
    });
    rx
}

fn start_server(args: &PairsArgs, metrics: Metrics) -> anyhow::Result<Server> {
    let exe = std::env::current_exe().context("the current executable")?;
    let mut child = Command::new(exe)
        .arg("serve")
        .arg("--listen")
        .arg(args.listen.to_string())
        .arg("--workers")
        .arg(args.workers.to_string())
        .arg("--metrics")
        .arg(metrics.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start the server")?;
    let stdout = child.stdout.take().context("stdout")?;
    let mut server = Server { child };
    match pump(stdout).recv_timeout(READY_TIMEOUT) {
        Ok(Event::Ready) => Ok(server),
        Ok(Event::Closed) | Err(RecvTimeoutError::Disconnected) => {
            let status = server
                .child
                .wait()
                .map(|status| status.to_string())
                .unwrap_or_default();
            bail!("the server exited before it was ready ({status})")
        }
        Err(RecvTimeoutError::Timeout) => bail!("the server was not ready in time"),
    }
}

fn run_one(args: &PairsArgs, metrics: Metrics) -> anyhow::Result<LoadResult> {
    let server = start_server(args, metrics)?;
    let load_args = LoadArgs {
        target: args.listen,
        clients: args.clients,
        inflight: args.inflight,
        duration: args.duration,
        warmup: args.warmup,
        timeout: Duration::from_secs(1),
        nx_percent: 5.0,
        zone_size: DEFAULT_ZONE_SIZE,
        no_edns: false,
        server_pid: Some(server.child.id()),
        json: None,
        label: None,
        seed: 1,
    };
    let result = load::run_load(&load_args);
    drop(server);
    result
}
