//! Markdown report writer: turns JSONL result files into comparison tables.
//!
//! Input is one [`RunRecord`] per line (written by `load --json` and by
//! `matrix`). Output is three sections: the best run per configuration,
//! a worker-count scaling pivot and the list of all runs.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader, Write as _};

use anyhow::Context;

use crate::record::RunRecord;

#[derive(clap::Args, Debug, Clone)]
pub struct ReportArgs {
    /// JSONL result files to read (one RunRecord per line).
    #[arg(long = "input", required = true, num_args = 1..)]
    pub inputs: Vec<std::path::PathBuf>,
    /// Write the Markdown here instead of stdout.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
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
pub fn load_records(paths: &[std::path::PathBuf]) -> anyhow::Result<Vec<crate::record::RunRecord>> {
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

/// Renders the three report sections as Markdown.
pub fn render_markdown(records: &[RunRecord]) -> String {
    let best = best_runs(records);
    let mut out = String::new();
    write_best_section(&mut out, &best);
    out.push('\n');
    write_scaling_section(&mut out, &best);
    out.push('\n');
    write_all_runs_section(&mut out, records);
    out
}

/// Mode and socket sharing: one table per group in the "best run" section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    /// Orders the known modes (tokio, threads) before any other value.
    rank: u8,
    mode: String,
    reuseport: bool,
}

impl GroupKey {
    fn new(mode: &str, reuseport: bool) -> Self {
        let rank = match mode {
            "tokio" => 0,
            "threads" => 1,
            _ => 2,
        };
        Self {
            rank,
            mode: cell(mode),
            reuseport,
        }
    }

    fn caption(&self) -> String {
        let socket = if self.reuseport {
            "SO_REUSEPORT"
        } else {
            "shared socket"
        };
        format!("Mode: {} ({socket})", self.mode)
    }

    /// Short form used in pivot headers: `tokio` or `tokio+reuseport`.
    fn short(&self) -> String {
        if self.reuseport {
            format!("{}+reuseport", self.mode)
        } else {
            self.mode.clone()
        }
    }
}

/// A configuration: (backend, mode, reuseport, workers), ordered for display.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ConfigKey {
    group: GroupKey,
    workers: usize,
    backend: String,
}

/// The run with the highest QPS for each configuration. Records without
/// backend, mode or workers (standalone `load` runs) have no configuration.
fn best_runs(records: &[RunRecord]) -> BTreeMap<ConfigKey, &RunRecord> {
    let mut best: BTreeMap<ConfigKey, &RunRecord> = BTreeMap::new();
    for record in records {
        let (Some(backend), Some(mode), Some(workers)) =
            (&record.backend, &record.mode, record.workers)
        else {
            continue;
        };
        let key = ConfigKey {
            group: GroupKey::new(mode, record.reuseport.unwrap_or(false)),
            workers,
            backend: cell(backend),
        };
        match best.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(record);
            }
            Entry::Occupied(mut slot) => {
                if record.result.qps > slot.get().result.qps {
                    slot.insert(record);
                }
            }
        }
    }
    best
}

fn write_best_section(out: &mut String, best: &BTreeMap<ConfigKey, &RunRecord>) {
    out.push_str("### Best run per configuration\n\n");
    out.push_str(
        "Loopback measurements: client and server run on the same machine and share its CPUs.\n\n",
    );
    if best.is_empty() {
        out.push_str("_No runs with backend, mode and workers set._\n");
        return;
    }
    let headers = [
        "Workers",
        "Backend",
        "Clients x in-flight",
        "QPS",
        "p50 (µs)",
        "p99 (µs)",
        "p99.9 (µs)",
        "Server CPU (cores)",
        "QPS per server core",
        "Peak RSS (MiB)",
        "Timeouts",
        "Errors",
    ];
    let aligns = "rlrrrrrrrrrr";

    let mut groups: Vec<(&GroupKey, Vec<Vec<String>>)> = Vec::new();
    for (key, record) in best {
        if groups.last().is_none_or(|(group, _)| *group != &key.group) {
            groups.push((&key.group, Vec::new()));
        }
        let r = &record.result;
        let server = r.server.as_ref();
        let per_core = server
            .filter(|s| s.cpu_cores > 0.0)
            .map(|s| fmt_int(r.qps / s.cpu_cores));
        let row = vec![
            key.workers.to_string(),
            key.backend.clone(),
            format!("{} x {}", r.clients, r.inflight),
            fmt_int(r.qps),
            fmt_one_decimal(r.latency_us.p50),
            fmt_one_decimal(r.latency_us.p99),
            fmt_one_decimal(r.latency_us.p999),
            server.map_or_else(na, |s| fmt_two_decimals(s.cpu_cores)),
            per_core.unwrap_or_else(na),
            server.map_or_else(na, |s| fmt_one_decimal(s.peak_rss_mib)),
            r.timeouts.to_string(),
            r.errors.to_string(),
        ];
        if let Some((_, rows)) = groups.last_mut() {
            rows.push(row);
        }
    }
    for (index, (group, rows)) in groups.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let _ = write!(out, "**{}**\n\n", group.caption());
        write_table(out, &headers, aligns, rows);
    }
}

fn write_scaling_section(out: &mut String, best: &BTreeMap<ConfigKey, &RunRecord>) {
    out.push_str("### Throughput scaling (best QPS per configuration)\n\n");
    if best.is_empty() {
        out.push_str("_No runs with backend, mode and workers set._\n");
        return;
    }
    let workers: BTreeSet<usize> = best.keys().map(|k| k.workers).collect();
    let columns: BTreeSet<(&GroupKey, &str)> = best
        .keys()
        .map(|k| (&k.group, k.backend.as_str()))
        .collect();

    let mut headers: Vec<String> = vec!["Workers".to_owned()];
    headers.extend(
        columns
            .iter()
            .map(|(group, backend)| format!("{backend} / {}", group.short())),
    );
    let header_refs: Vec<&str> = headers.iter().map(String::as_str).collect();
    let aligns = "r".repeat(headers.len());

    let rows: Vec<Vec<String>> = workers
        .iter()
        .map(|&w| {
            let mut row = vec![w.to_string()];
            for (group, backend) in &columns {
                let key = ConfigKey {
                    group: (*group).clone(),
                    workers: w,
                    backend: (*backend).to_owned(),
                };
                row.push(best.get(&key).map_or_else(dash, |r| fmt_int(r.result.qps)));
            }
            row
        })
        .collect();
    write_table(out, &header_refs, &aligns, &rows);
}

fn write_all_runs_section(out: &mut String, records: &[RunRecord]) {
    out.push_str("### All runs\n\n");
    if records.is_empty() {
        out.push_str("_No runs._\n");
        return;
    }
    let headers = [
        "#",
        "Backend",
        "Mode",
        "Reuseport",
        "Workers",
        "Clients",
        "In-flight",
        "QPS",
        "p50 (µs)",
        "p99 (µs)",
        "p99.9 (µs)",
        "Server CPU (cores)",
        "Peak RSS (MiB)",
        "Timeouts",
        "Errors",
        "Unexpected",
        "Client CPU (cores)",
    ];
    let aligns = "rlllrrrrrrrrrrrrr";
    let rows: Vec<Vec<String>> = records
        .iter()
        .enumerate()
        .map(|(index, rec)| {
            let r = &rec.result;
            let server = r.server.as_ref();
            vec![
                (index + 1).to_string(),
                rec.backend.as_deref().map_or_else(dash, cell),
                rec.mode.as_deref().map_or_else(dash, cell),
                match rec.reuseport {
                    Some(true) => "yes".to_owned(),
                    Some(false) => "no".to_owned(),
                    None => dash(),
                },
                rec.workers.map_or_else(dash, |w| w.to_string()),
                r.clients.to_string(),
                r.inflight.to_string(),
                fmt_int(r.qps),
                fmt_one_decimal(r.latency_us.p50),
                fmt_one_decimal(r.latency_us.p99),
                fmt_one_decimal(r.latency_us.p999),
                server.map_or_else(na, |s| fmt_two_decimals(s.cpu_cores)),
                server.map_or_else(na, |s| fmt_one_decimal(s.peak_rss_mib)),
                r.timeouts.to_string(),
                r.errors.to_string(),
                r.unexpected.to_string(),
                r.client_cpu_cores.map_or_else(na, fmt_two_decimals),
            ]
        })
        .collect();
    write_table(out, &headers, aligns, &rows);
}

/// Writes a Markdown table. `aligns` has one `l` or `r` per column.
fn write_table(out: &mut String, headers: &[&str], aligns: &str, rows: &[Vec<String>]) {
    debug_assert_eq!(headers.len(), aligns.len());
    out.push('|');
    for header in headers {
        let _ = write!(out, " {header} |");
    }
    out.push_str("\n|");
    for align in aligns.chars() {
        out.push_str(if align == 'r' { " ---: |" } else { " --- |" });
    }
    out.push('\n');
    for row in rows {
        debug_assert_eq!(row.len(), headers.len());
        out.push('|');
        for value in row {
            let _ = write!(out, " {value} |");
        }
        out.push('\n');
    }
}

/// Keeps a free-text value from breaking the table layout.
fn cell(text: &str) -> String {
    text.replace(['|', '\n', '\r'], "/")
}

fn na() -> String {
    "n/a".to_owned()
}

fn dash() -> String {
    "-".to_owned()
}

/// Integer with thousands separators (`123,456`).
fn fmt_int(value: f64) -> String {
    if !value.is_finite() {
        return na();
    }
    let n = value.round() as i64;
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn fmt_one_decimal(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.1}")
    } else {
        na()
    }
}

fn fmt_two_decimals(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.2}")
    } else {
        na()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::record::{LatencyUs, LoadResult, ServerStats};

    /// One synthetic record. Configured runs get server stats of 2.00 cores.
    fn record(
        backend: Option<&str>,
        mode: Option<&str>,
        workers: Option<usize>,
        reuseport: Option<bool>,
        clients: usize,
        qps: f64,
    ) -> RunRecord {
        let server = backend.map(|_| ServerStats {
            pid: 4242,
            cpu_seconds: 40.0,
            cpu_cores: 2.0,
            peak_rss_mib: 31.24,
            end_rss_mib: 30.0,
        });
        RunRecord {
            timestamp: "2026-10-09T12:00:00Z".to_owned(),
            os: "windows".to_owned(),
            label: None,
            backend: backend.map(str::to_owned),
            mode: mode.map(str::to_owned),
            workers,
            reuseport,
            result: LoadResult {
                target: "127.0.0.1:5353".to_owned(),
                clients,
                inflight: 32,
                edns: true,
                measured_seconds: 20.0,
                qps,
                latency_us: LatencyUs {
                    p50: 120.0,
                    p99: 450.54,
                    p999: 1200.0,
                    ..Default::default()
                },
                server,
                client_cpu_cores: Some(3.5),
                ..Default::default()
            },
        }
    }

    fn sample() -> Vec<RunRecord> {
        vec![
            record(
                Some("domain"),
                Some("tokio"),
                Some(1),
                Some(false),
                8,
                100_000.0,
            ),
            record(
                Some("domain"),
                Some("tokio"),
                Some(1),
                Some(false),
                16,
                120_000.0,
            ),
            record(
                Some("hickory"),
                Some("tokio"),
                Some(1),
                Some(false),
                8,
                90_000.0,
            ),
            record(
                Some("domain"),
                Some("tokio"),
                Some(2),
                Some(true),
                8,
                180_000.0,
            ),
            record(
                Some("domain"),
                Some("threads"),
                Some(2),
                Some(false),
                8,
                150_000.0,
            ),
            record(None, None, None, None, 4, 777_777.0),
        ]
    }

    /// Text between `heading` and the next `### ` heading (or the end).
    fn section<'a>(markdown: &'a str, heading: &str) -> &'a str {
        let start = markdown
            .find(heading)
            .unwrap_or_else(|| panic!("missing heading {heading}"));
        let rest = &markdown[start + heading.len()..];
        &rest[..rest.find("\n### ").unwrap_or(rest.len())]
    }

    /// Table lines of a section split into trimmed cells (header and separator included).
    fn table_rows(text: &str) -> Vec<Vec<String>> {
        text.lines()
            .filter(|l| l.starts_with('|'))
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|c| c.trim().to_owned())
                    .collect()
            })
            .collect()
    }

    fn strings(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|s| (*s).to_owned()).collect()
    }

    const BEST: &str = "### Best run per configuration";
    const SCALING: &str = "### Throughput scaling (best QPS per configuration)";
    const ALL: &str = "### All runs";

    #[test]
    fn picks_the_highest_qps_run_per_configuration() {
        let markdown = render_markdown(&sample());
        let best = section(&markdown, BEST);
        let rows: Vec<_> = table_rows(best)
            .into_iter()
            .filter(|c| c[0] == "1" && c[1] == "domain")
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "one row for domain / tokio / 1 worker:\n{best}"
        );
        let row = &rows[0];
        assert_eq!(row[2], "16 x 32");
        assert_eq!(row[3], "120,000");
        assert_eq!(row[4], "120.0");
        assert_eq!(row[5], "450.5");
        assert_eq!(row[7], "2.00");
        assert_eq!(row[8], "60,000");
        assert_eq!(row[9], "31.2");
        assert!(
            !best.contains("100,000"),
            "the slower run must not appear:\n{best}"
        );
    }

    #[test]
    fn groups_follow_the_documented_order() {
        let markdown = render_markdown(&sample());
        let tokio_shared = markdown
            .find("**Mode: tokio (shared socket)**")
            .expect("tokio shared");
        let tokio_reuse = markdown
            .find("**Mode: tokio (SO_REUSEPORT)**")
            .expect("tokio reuseport");
        let threads_shared = markdown
            .find("**Mode: threads (shared socket)**")
            .expect("threads shared");
        assert!(tokio_shared < tokio_reuse && tokio_reuse < threads_shared);
        assert!(
            !markdown.contains("Mode: threads (SO_REUSEPORT)"),
            "absent groups are not printed"
        );
        assert!(section(&markdown, BEST).contains(
            "Loopback measurements: client and server run on the same machine and share its CPUs."
        ));
    }

    #[test]
    fn pivot_marks_missing_cells() {
        let markdown = render_markdown(&sample());
        let rows = table_rows(section(&markdown, SCALING));
        assert_eq!(
            rows[0],
            strings(&[
                "Workers",
                "domain / tokio",
                "hickory / tokio",
                "domain / tokio+reuseport",
                "domain / threads"
            ])
        );
        assert_eq!(rows[2], strings(&["1", "120,000", "90,000", "-", "-"]));
        assert_eq!(rows[3], strings(&["2", "-", "-", "180,000", "150,000"]));
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn standalone_record_only_in_all_runs() {
        let markdown = render_markdown(&sample());
        assert!(!section(&markdown, BEST).contains("777,777"));
        assert!(!section(&markdown, SCALING).contains("777,777"));
        let rows = table_rows(section(&markdown, ALL));
        // header + separator + one row per record, in input order
        assert_eq!(rows.len(), 2 + 6);
        let last = &rows[7];
        assert_eq!(last[0], "6");
        assert_eq!(last[1..5], strings(&["-", "-", "-", "-"]));
        assert_eq!(last[7], "777,777");
        assert_eq!(last[11], "n/a");
        assert_eq!(last[12], "n/a");
        assert_eq!(last[16], "3.50");
        assert_eq!(rows[2][0], "1");
        assert_eq!(rows[2][3], "no");
        assert_eq!(rows[5][3], "yes");
    }

    #[test]
    fn every_table_row_matches_its_header() {
        let markdown = render_markdown(&sample());
        let mut expected: Option<usize> = None;
        let mut tables = 0;
        for line in markdown.lines() {
            if line.starts_with('|') {
                let pipes = line.matches('|').count();
                match expected {
                    None => {
                        expected = Some(pipes);
                        tables += 1;
                    }
                    Some(n) => assert_eq!(
                        pipes, n,
                        "row has a different cell count than its header: {line}"
                    ),
                }
            } else {
                expected = None;
            }
        }
        // three mode groups + pivot + all runs
        assert_eq!(tables, 5);
    }

    #[test]
    fn empty_input_renders_headings_without_tables() {
        let markdown = render_markdown(&[]);
        assert!(markdown.contains(BEST) && markdown.contains(SCALING) && markdown.contains(ALL));
        assert!(!markdown.contains('|'));
    }

    #[test]
    fn thousands_separators() {
        assert_eq!(fmt_int(0.0), "0");
        assert_eq!(fmt_int(999.4), "999");
        assert_eq!(fmt_int(1_000.0), "1,000");
        assert_eq!(fmt_int(123_456.6), "123,457");
        assert_eq!(fmt_int(12_345_678.0), "12,345,678");
        assert_eq!(fmt_int(f64::NAN), "n/a");
    }

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "spike-b-report-{name}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn load_records_round_trip() {
        let records = sample();
        let mut text = String::new();
        for (i, rec) in records.iter().enumerate() {
            text.push_str(&serde_json::to_string(rec).expect("serialize"));
            text.push('\n');
            if i % 2 == 0 {
                text.push_str("\n   \n");
            }
        }
        let path = temp_path("roundtrip");
        std::fs::write(&path, text).expect("write temp file");
        let loaded = load_records(&[path.clone(), path.clone()]).expect("load");
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.len(), 2 * records.len());
        assert_eq!(loaded[1].result.clients, 16);
        assert_eq!(loaded[3].workers, Some(2));
        assert_eq!(loaded[3].reuseport, Some(true));
        assert!(loaded[5].backend.is_none());
        assert_eq!(loaded[5].result.qps, 777_777.0);
        assert_eq!(loaded[0].result.server.as_ref().map(|s| s.pid), Some(4242));
        assert_eq!(
            render_markdown(&loaded[..records.len()]),
            render_markdown(&records)
        );
    }

    #[test]
    fn malformed_line_names_file_and_line() {
        let good = serde_json::to_string(&sample()[0]).expect("serialize");
        let path = temp_path("malformed");
        std::fs::write(&path, format!("{good}\n{{\"timestamp\": \n")).expect("write temp file");
        let err = load_records(std::slice::from_ref(&path)).expect_err("must fail");
        std::fs::remove_file(&path).ok();
        let message = format!("{err:#}");
        assert!(
            message.contains(&format!("{}:2", path.display())),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn missing_input_file_is_an_error() {
        let path = temp_path("does-not-exist");
        assert!(load_records(&[path]).is_err());
    }
}
