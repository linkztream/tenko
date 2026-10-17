//! Markdown report writer: turns JSONL result files into tables.
//!
//! Input is one [`RunRecord`] per line (written by `load --json`). A
//! configuration is (label, transport, EDNS, workers, metrics); of several runs
//! of one configuration the one with the highest QPS is shown, and every run
//! is listed at the end.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;

use anyhow::Context;

use crate::load::group_thousands;
use crate::record::RunRecord;

#[derive(clap::Args, Debug, Clone)]
pub struct ReportArgs {
    /// JSONL result files to read (one RunRecord per line).
    #[arg(long = "input", required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
    /// Write the Markdown here instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Reads the input files, renders the tables and writes them to `--out` or stdout.
pub fn run(args: &ReportArgs) -> anyhow::Result<()> {
    let records = load_records(&args.inputs)?;
    let markdown = render_markdown(&records);
    match &args.out {
        Some(path) => {
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            std::fs::write(path, markdown)
                .with_context(|| format!("writing {}", path.display()))?;
            tracing::info!(records = records.len(), out = %path.display(), "report written");
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(markdown.as_bytes())
                .context("writing report to stdout")?;
            stdout.flush().context("writing report to stdout")?;
        }
    }
    Ok(())
}

/// Reads all records from the given JSONL files, in file order and line order.
/// Blank lines are skipped; a malformed line is an error that names `file:line`.
pub fn load_records(paths: &[PathBuf]) -> anyhow::Result<Vec<RunRecord>> {
    let mut records = Vec::new();
    for path in paths {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_no = index + 1;
            let line =
                line.with_context(|| format!("{}:{line_no}: reading line", path.display()))?;
            // Tolerate a UTF-8 byte order mark at the start of a file.
            let line = line.trim_start_matches('\u{feff}').trim();
            if line.is_empty() {
                continue;
            }
            let record: RunRecord = serde_json::from_str(line)
                .with_context(|| format!("{}:{line_no}: invalid run record", path.display()))?;
            records.push(record);
        }
    }
    Ok(records)
}

/// One table per (label, transport, EDNS); the key orders the tables.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    label: String,
    transport: String,
    edns: bool,
}

/// Rows within a table: workers, then metrics off before on before unknown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey {
    workers: Option<usize>,
    metrics: Option<bool>,
}

type Groups<'a> = BTreeMap<GroupKey, BTreeMap<RowKey, &'a RunRecord>>;

/// Escapes a free-form value for a Markdown table cell.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn group_key(r: &RunRecord) -> GroupKey {
    GroupKey {
        label: cell(r.label.as_deref().unwrap_or("(no label)")),
        transport: if r.result.transport.is_empty() {
            "udp".to_string()
        } else {
            r.result.transport.clone()
        },
        edns: r.result.edns,
    }
}

/// The run with the highest QPS for each configuration.
fn best_runs(records: &[RunRecord]) -> Groups<'_> {
    let mut groups: Groups = BTreeMap::new();
    for r in records {
        let row = RowKey {
            workers: r.workers,
            metrics: r.metrics,
        };
        let slot = groups.entry(group_key(r)).or_default().entry(row);
        slot.and_modify(|best| {
            if r.result.qps > best.result.qps {
                *best = r;
            }
        })
        .or_insert(r);
    }
    groups
}

fn opt_workers(w: Option<usize>) -> String {
    w.map_or("-".to_string(), |w| w.to_string())
}

fn metrics_cell(m: Option<bool>) -> &'static str {
    match m {
        Some(true) => "on",
        Some(false) => "off",
        None => "-",
    }
}

/// Server CPU per received query in microseconds.
fn cpu_us_per_query(r: &RunRecord) -> Option<f64> {
    let s = r.result.server.as_ref()?;
    (r.result.received > 0).then(|| s.cpu_seconds * 1e6 / r.result.received as f64)
}

/// Received queries per second of server CPU: QPS per busy core.
fn qps_per_core(r: &RunRecord) -> Option<f64> {
    let s = r.result.server.as_ref()?;
    (s.cpu_seconds > 0.0).then(|| r.result.received as f64 / s.cpu_seconds)
}

fn fmt_opt(v: Option<f64>, decimals: usize) -> String {
    v.map_or("-".to_string(), |v| format!("{v:.decimals$}"))
}

fn qps_cell(q: f64) -> String {
    group_thousands(q.round() as u64)
}

fn mode_text(r: &RunRecord) -> String {
    match r.result.target_qps {
        Some(q) => format!("paced {}", qps_cell(q)),
        None => format!("{} x {}", r.result.clients, r.result.inflight),
    }
}

/// Renders the report as Markdown.
pub fn render_markdown(records: &[RunRecord]) -> String {
    let groups = best_runs(records);
    let mut out = String::new();
    for (key, rows) in &groups {
        write_group(&mut out, key, rows);
        out.push('\n');
    }
    write_metrics_cost(&mut out, &groups);
    write_all_runs(&mut out, records);
    out
}

fn write_group(out: &mut String, key: &GroupKey, rows: &BTreeMap<RowKey, &RunRecord>) {
    let _ = writeln!(
        out,
        "### {}, {}, EDNS {}\n",
        key.label,
        key.transport.to_uppercase(),
        if key.edns { "on" } else { "off" }
    );
    out.push_str(
        "| Workers | Metrics | Clients x in flight | QPS | p50 us | p99 us | p99.9 us | Server cores | QPS per server core | Server CPU us/query | Timeouts | Errors | Peak RSS MiB |\n",
    );
    out.push_str("| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for (row, r) in rows {
        let l = &r.result.latency_us;
        let s = r.result.server.as_ref();
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {} | {} | {} | {} | {} | {} |",
            opt_workers(row.workers),
            metrics_cell(row.metrics),
            mode_text(r),
            qps_cell(r.result.qps),
            l.p50,
            l.p99,
            l.p999,
            fmt_opt(s.map(|s| s.cpu_cores), 2),
            qps_per_core(r).map_or("-".to_string(), qps_cell),
            fmt_opt(cpu_us_per_query(r), 2),
            group_thousands(r.result.timeouts),
            group_thousands(r.result.errors),
            fmt_opt(s.map(|s| s.peak_rss_mib), 1),
        );
    }
}

/// The metrics cost (M22): where a configuration has a run with metrics off
/// and one with metrics on, compare them.
fn write_metrics_cost(out: &mut String, groups: &Groups<'_>) {
    let mut lines = String::new();
    for (key, rows) in groups {
        for (row, on) in rows.iter().filter(|(k, _)| k.metrics == Some(true)) {
            let off_key = RowKey {
                workers: row.workers,
                metrics: Some(false),
            };
            let Some(off) = rows.get(&off_key) else {
                continue;
            };
            if off.result.qps <= 0.0 {
                continue;
            }
            let _ = writeln!(
                lines,
                "| {} | {} | {} | {} | {} | {:+.1} % | {:.1} | {:.1} |",
                key.label,
                key.transport,
                opt_workers(row.workers),
                qps_cell(off.result.qps),
                qps_cell(on.result.qps),
                (on.result.qps / off.result.qps - 1.0) * 100.0,
                off.result.latency_us.p99,
                on.result.latency_us.p99,
            );
        }
    }
    if lines.is_empty() {
        return;
    }
    out.push_str("### Metrics cost (on against off)\n\n");
    out.push_str(
        "| Label | Transport | Workers | QPS off | QPS on | Change | p99 us off | p99 us on |\n",
    );
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&lines);
    out.push('\n');
}

fn write_all_runs(out: &mut String, records: &[RunRecord]) {
    out.push_str("### All runs\n\n");
    out.push_str("| Time (UTC) | OS | Label | Transport | Workers | Metrics | Load | QPS | p99 us | Timeouts | Errors |\n");
    out.push_str("| --- | --- | --- | --- | ---: | --- | --- | ---: | ---: | ---: | ---: |\n");
    for r in records {
        let key = group_key(r);
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1} | {} | {} |",
            cell(&r.timestamp),
            cell(&r.os),
            key.label,
            key.transport,
            opt_workers(r.workers),
            metrics_cell(r.metrics),
            mode_text(r),
            qps_cell(r.result.qps),
            r.result.latency_us.p99,
            group_thousands(r.result.timeouts),
            group_thousands(r.result.errors),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{LatencyUs, LoadResult, ServerStats};

    fn rec(label: &str, workers: usize, metrics: Option<bool>, qps: f64) -> RunRecord {
        RunRecord {
            timestamp: "2026-10-17T10:00:00Z".into(),
            os: "windows".into(),
            label: Some(label.into()),
            workers: Some(workers),
            metrics,
            result: LoadResult {
                transport: "udp".into(),
                clients: 8,
                inflight: 32,
                edns: true,
                measured_seconds: 10.0,
                received: (qps * 10.0) as u64,
                qps,
                latency_us: LatencyUs {
                    p50: 100.0,
                    p99: 400.0,
                    p999: 900.0,
                    ..Default::default()
                },
                server: Some(ServerStats {
                    pid: 1,
                    cpu_seconds: 10.0 * workers as f64,
                    cpu_cores: workers as f64,
                    peak_rss_mib: 50.0,
                    end_rss_mib: 40.0,
                }),
                ..Default::default()
            },
        }
    }

    #[test]
    fn best_run_per_configuration_wins() {
        let recs = vec![
            rec("srv", 1, None, 100_000.0),
            rec("srv", 1, None, 150_000.0),
            rec("srv", 4, None, 400_000.0),
        ];
        let md = render_markdown(&recs);
        assert!(md.contains("### srv, UDP, EDNS on"));
        assert!(md.contains("150,000"));
        // The slower run of the same configuration is only in the run list.
        let best = md.split("### All runs").next().unwrap();
        assert!(!best.contains("100,000 | 100.0"), "{md}");
        // 1 worker: 1.5 M queries in 10 core-seconds = 150,000 QPS per core.
        assert!(md.contains("| 1 | - | 8 x 32 | 150,000 |"), "{md}");
        assert!(md.contains("| 6.67 |"), "cpu per query: {md}");
    }

    #[test]
    fn metrics_cost_table_pairs_on_and_off() {
        let recs = vec![
            rec("srv", 2, Some(false), 200_000.0),
            rec("srv", 2, Some(true), 196_000.0),
            rec("srv", 4, Some(true), 300_000.0),
        ];
        let md = render_markdown(&recs);
        assert!(md.contains("### Metrics cost"), "{md}");
        assert!(
            md.contains("| srv | udp | 2 | 200,000 | 196,000 | -2.0 % |"),
            "{md}"
        );
        // Workers 4 has no run with metrics off: no row.
        let cost = md
            .split("### Metrics cost")
            .nth(1)
            .unwrap()
            .split("### All runs")
            .next()
            .unwrap();
        assert!(!cost.contains("| 4 |"), "{md}");
    }

    #[test]
    fn no_metrics_table_without_pairs_and_labels_are_escaped() {
        let md = render_markdown(&[rec("a|b", 1, None, 10.0)]);
        assert!(!md.contains("Metrics cost"));
        assert!(md.contains("a\\|b"));
    }

    #[test]
    fn jsonl_round_trip() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("report-{}.jsonl", std::process::id()));
        let line = serde_json::to_string(&rec("srv", 1, None, 5.0)).unwrap();
        std::fs::write(&path, format!("\u{feff}{line}\n\n{line}\n")).unwrap();
        let recs = load_records(std::slice::from_ref(&path)).unwrap();
        assert_eq!(recs.len(), 2);
        std::fs::write(&path, "{not json}\n").unwrap();
        let err = load_records(std::slice::from_ref(&path)).unwrap_err();
        assert!(format!("{err:#}").contains(":1:"), "{err:#}");
        let _ = std::fs::remove_file(&path);
    }
}
