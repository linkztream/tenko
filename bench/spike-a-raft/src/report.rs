//! Markdown rendering of the Spike A results.
//!
//! Every public function is pure string formatting over the structs in `crate::results`: the
//! values printed are exactly the values stored in those structs. Nothing is estimated or
//! filled in here; a missing optional measurement is rendered as "not measured" and a latency
//! summary without samples is rendered as "-".
//!
//! Output conventions: GitHub pipe tables, LF line endings, no trailing spaces, `|` inside cell
//! text escaped as `\|`, numeric columns right-aligned.

use std::fmt::Write as _;
use std::path::Path;

use crate::results::BulkLoadResult;
use crate::results::CatchUpResult;
use crate::results::ChangeFeedResult;
use crate::results::Criterion;
use crate::results::DepVersion;
use crate::results::LatencyRun;
use crate::results::LatencySummary;
use crate::results::MachineInfo;
use crate::results::NodeDiskUsage;
use crate::results::Results;
use crate::results::RunConfig;
use crate::results::SteadyStateResult;

/// Shown for a value that is a non-finite float or a ratio with a zero denominator.
const NOT_AVAILABLE: &str = "n/a";
/// Shown for an optional measurement that was not taken.
const NOT_MEASURED: &str = "not measured";
/// Shown for a cell that does not apply (for example write columns of a read-only run).
const DASH: &str = "-";
/// Body of a section whose input is empty.
const NOT_RUN: &str = "_Not run._\n";
/// Body of the disk usage sub-section when no run recorded per-node file sizes.
const DISK_NOT_MEASURED: &str = "_Not measured._\n";

// ---------------------------------------------------------------------------------------------
// Value formatting helpers
// ---------------------------------------------------------------------------------------------

/// Unsigned integer with comma thousands separators: `1234567` -> `1,234,567`.
fn fmt_count(n: u64) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Binary units above plain bytes.
const BYTE_UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/// Scales a byte count of at least 1 KiB into the largest unit that keeps the value below 1024,
/// with two decimals: `1536` -> `1.50 KiB`.
fn scale_bytes(bytes: f64) -> String {
    let mut value = bytes / 1024.0;
    let mut unit = 0;
    // 1023.995 is the smallest value that would print as "1024.00".
    while value >= 1023.995 && unit + 1 < BYTE_UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", BYTE_UNITS[unit])
}

/// Exact byte count in binary units: `512` -> `512 B`, `1536` -> `1.50 KiB`.
fn fmt_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    scale_bytes(bytes as f64)
}

/// Fractional byte count (an average): `63.4` -> `63.4 B`, larger values as in [`fmt_bytes`].
fn fmt_bytes_f64(bytes: f64) -> String {
    if !bytes.is_finite() || bytes < 0.0 {
        return NOT_AVAILABLE.to_string();
    }
    // 1023.95 is the smallest value that would print as "1024.0 B".
    if bytes < 1023.95 {
        return format!("{bytes:.1} B");
    }
    scale_bytes(bytes)
}

/// Three significant digits: `123.4` -> `123`, `12.34` -> `12.3`, `1.234` -> `1.23`.
fn sig3(value: f64) -> String {
    let decimals: usize = if value >= 99.95 {
        0
    } else if value >= 9.995 {
        1
    } else {
        2
    };
    format!("{value:.decimals$}")
}

/// Nanoseconds in the unit that reads best: `850 ns`, `12.3 us`, `1.23 ms`, `1.50 s`.
fn fmt_ns_f64(ns: f64) -> String {
    if !ns.is_finite() || ns < 0.0 {
        return NOT_AVAILABLE.to_string();
    }
    if ns < 999.5 {
        return format!("{ns:.0} ns");
    }
    let (unit, scale) = if ns < 999.5e3 {
        ("us", 1e3)
    } else if ns < 999.5e6 {
        ("ms", 1e6)
    } else {
        ("s", 1e9)
    };
    format!("{} {unit}", sig3(ns / scale))
}

fn fmt_ns(ns: u64) -> String {
    fmt_ns_f64(ns as f64)
}

/// Seconds with two decimals: `12.34 s`. A non-zero duration below 100 ms would keep only one
/// significant digit (or print as `0.00 s`), so those switch to the nanosecond scale (`42.1 ms`).
fn fmt_secs(secs: f64) -> String {
    if !secs.is_finite() {
        return NOT_AVAILABLE.to_string();
    }
    if secs > 0.0 && secs < 0.1 {
        return fmt_ns_f64(secs * 1e9);
    }
    format!("{secs:.2} s")
}

/// Achieved rate: `123,456/s` for large values, up to two decimals for small ones.
fn fmt_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return NOT_AVAILABLE.to_string();
    }
    if rate == 0.0 {
        return "0/s".to_string();
    }
    if rate >= 99.95 {
        format!("{}/s", fmt_count(rate.round() as u64))
    } else if rate >= 9.995 {
        format!("{rate:.1}/s")
    } else {
        format!("{rate:.2}/s")
    }
}

/// Configured integer rate: `1,000/s`.
fn fmt_rate_target(rate: u64) -> String {
    format!("{}/s", fmt_count(rate))
}

/// `numerator / denominator` with two decimals and an `x` suffix: `2.31x`.
fn fmt_ratio(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return NOT_AVAILABLE.to_string();
    }
    format!("{:.2}x", numerator as f64 / denominator as f64)
}

/// Free text for a cell: a blank value becomes a dash so the cell is never empty.
fn text(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        DASH.to_string()
    } else {
        value.to_string()
    }
}

/// Collapses line breaks so a value stays on one line.
fn one_line(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

// ---------------------------------------------------------------------------------------------
// Table builder
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Align {
    Left,
    Right,
}

use Align::Left;
use Align::Right;

/// Cell text as it appears in the table source: one line, `|` escaped.
fn escape_cell(value: &str) -> String {
    one_line(value).replace('|', "\\|")
}

fn push_row(out: &mut String, cells: &[String], columns: &[(&str, Align)], widths: &[usize]) {
    out.push('|');
    for (i, (_, align)) in columns.iter().enumerate() {
        let cell = cells.get(i).map_or("", String::as_str);
        let pad = widths[i].saturating_sub(cell.chars().count());
        out.push(' ');
        if *align == Right {
            out.extend(std::iter::repeat_n(' ', pad));
        }
        out.push_str(cell);
        if *align == Left {
            out.extend(std::iter::repeat_n(' ', pad));
        }
        out.push_str(" |");
    }
    out.push('\n');
}

/// Renders a pipe table. `columns` holds header text and alignment; every row is padded or cut
/// to the number of columns, so each line always has the header's cell count.
fn table(columns: &[(&str, Align)], rows: &[Vec<String>]) -> String {
    let header: Vec<String> = columns.iter().map(|(h, _)| escape_cell(h)).collect();
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            (0..columns.len())
                .map(|i| escape_cell(row.get(i).map_or("", String::as_str)))
                .collect()
        })
        .collect();

    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, (_, align))| {
            let min = if *align == Right { 4 } else { 3 };
            body.iter()
                .map(|row| row[i].chars().count())
                .fold(header[i].chars().count().max(min), usize::max)
        })
        .collect();

    let mut out = String::new();
    push_row(&mut out, &header, columns, &widths);
    out.push('|');
    for (i, (_, align)) in columns.iter().enumerate() {
        out.push(' ');
        match align {
            Left => out.extend(std::iter::repeat_n('-', widths[i])),
            Right => {
                out.extend(std::iter::repeat_n('-', widths[i] - 1));
                out.push(':');
            }
        }
        out.push_str(" |");
    }
    out.push('\n');
    for row in &body {
        push_row(&mut out, row, columns, &widths);
    }
    out
}

/// Two-column key/value table.
fn key_value_table(key_header: &str, rows: Vec<(&str, String)>) -> String {
    let rows: Vec<Vec<String>> = rows
        .into_iter()
        .map(|(key, value)| vec![key.to_string(), value])
        .collect();
    table(&[(key_header, Left), ("Value", Left)], &rows)
}

// ---------------------------------------------------------------------------------------------
// Public tables
// ---------------------------------------------------------------------------------------------

/// Markdown table: Machine (OS, CPU brand, logical CPUs, total RAM, rustc version).
pub fn machine_table(m: &MachineInfo) -> String {
    key_value_table(
        "Property",
        vec![
            ("OS", text(&m.os)),
            ("CPU", text(&m.cpu_brand)),
            ("Logical CPUs", fmt_count(m.logical_cpus as u64)),
            ("Total RAM", fmt_bytes(m.total_memory_bytes)),
            ("rustc", text(&m.rustc_version)),
        ],
    )
}

/// Markdown table: crate | version.
pub fn deps_table(deps: &[DepVersion]) -> String {
    let rows: Vec<Vec<String>> = deps
        .iter()
        .map(|d| vec![text(&d.name), text(&d.version)])
        .collect();
    table(&[("Crate", Left), ("Version", Left)], &rows)
}

/// Markdown table of RunConfig fields (setting | value).
pub fn config_table(c: &RunConfig) -> String {
    key_value_table(
        "Setting",
        vec![
            ("Replication mode", text(&c.mode)),
            ("Voters", fmt_count(u64::from(c.voters))),
            ("Batch records", fmt_count(c.batch_records)),
            ("PTR percent", format!("{}%", c.ptr_percent)),
            (
                "redb cache per database file",
                fmt_bytes(c.redb_cache_bytes),
            ),
            ("Raft log store", text(&c.log_store)),
            ("Log durability", text(&c.log_durability)),
            ("State machine durability", text(&c.sm_durability)),
            ("Max payload entries", fmt_count(c.max_payload_entries)),
            ("In-process network", text(&c.network)),
        ],
    )
}

/// Columns: Criterion | Threshold | Measured | Result, where Result is "**PASS**" or "**FAIL**".
pub fn criteria_table(c: &[Criterion]) -> String {
    let rows: Vec<Vec<String>> = c
        .iter()
        .map(|x| {
            vec![
                text(&x.name),
                text(&x.threshold),
                text(&x.measured),
                if x.pass { "**PASS**" } else { "**FAIL**" }.to_string(),
            ]
        })
        .collect();
    table(
        &[
            ("Criterion", Left),
            ("Threshold", Left),
            ("Measured", Left),
            ("Result", Left),
        ],
        &rows,
    )
}

/// One row per BulkLoadResult. Columns: Forward-zone records | Total RRsets | Voters | Raft entries |
/// Wall time | Records/s | RSS before | Peak RSS | RSS after | Avg entry (key+value) | Raw KV bytes |
/// Index entries (per node) | Index size est. (per node).
pub fn bulk_load_table(rows: &[BulkLoadResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|b| {
            vec![
                text(&b.disk),
                fmt_count(b.forward_zone_records),
                fmt_count(b.total_records),
                fmt_count(u64::from(b.voters)),
                fmt_count(b.raft_entries),
                fmt_secs(b.wall_secs),
                fmt_rate(b.records_per_sec),
                fmt_bytes(b.rss_before_bytes),
                fmt_bytes(b.peak_rss_bytes),
                fmt_bytes(b.rss_after_bytes),
                fmt_bytes_f64(b.avg_entry_bytes),
                fmt_bytes(b.raw_kv_bytes),
                fmt_count(b.index_entries),
                fmt_bytes(b.index_estimated_bytes),
                fmt_bytes(b.process_written_bytes),
                fmt_ratio(
                    b.process_written_bytes,
                    b.raw_kv_bytes.saturating_mul(u64::from(b.voters)),
                ),
            ]
        })
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Forward-zone records", Right),
            ("Total RRsets", Right),
            ("Voters", Right),
            ("Raft entries", Right),
            ("Wall time", Right),
            ("Records/s", Right),
            ("RSS before", Right),
            ("Peak RSS", Right),
            ("RSS after", Right),
            ("Avg entry (key+value)", Right),
            ("Raw KV bytes", Right),
            ("Index entries (per node)", Right),
            ("Index size est. (per node)", Right),
            ("Bytes written (process)", Right),
            ("Written / (raw KV x voters)", Right),
        ],
        &body,
    )
}

fn disk_row(run: &BulkLoadResult, node: &NodeDiskUsage) -> Vec<String> {
    let both = node.log_file_bytes.saturating_add(node.sm_file_bytes);
    vec![
        text(&run.disk),
        fmt_count(run.total_records),
        fmt_count(u64::from(run.voters)),
        node.node_id.to_string(),
        fmt_bytes(node.log_file_bytes),
        fmt_bytes(node.sm_file_bytes),
        fmt_bytes(both),
        fmt_ratio(node.sm_file_bytes, run.raw_kv_bytes),
        fmt_ratio(both, run.raw_kv_bytes),
        fmt_bytes(node.sm_stored_bytes),
        fmt_bytes(node.sm_fragmented_bytes),
    ]
}

/// One row per (run, node). Columns: Total RRsets | Voters | Node | log.redb | sm.redb | log+sm |
/// sm.redb / raw KV (ratio, 2 decimals, e.g. "2.31x") | (log+sm) / raw KV (ratio).
pub fn disk_table(rows: &[BulkLoadResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .flat_map(|run| run.per_node.iter().map(move |node| disk_row(run, node)))
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Total RRsets", Right),
            ("Voters", Right),
            ("Node", Right),
            ("log.redb", Right),
            ("sm.redb", Right),
            ("log+sm", Right),
            ("sm.redb / raw KV", Right),
            ("(log+sm) / raw KV", Right),
            ("sm.redb stored bytes (redb stats)", Right),
            ("sm.redb fragmented bytes (redb stats)", Right),
        ],
        &body,
    )
}

/// Columns: Total RRsets | Snapshot build | Snapshot size | Transfer (in-process) | Install |
/// of which index rebuild | Total catch-up | Size / 125 MB/s (1 Gbit/s) | Learner sm.redb | Peak RSS.
pub fn catch_up_table(rows: &[CatchUpResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|c| {
            vec![
                text(&c.disk),
                fmt_count(c.total_records),
                fmt_secs(c.snapshot_build_secs),
                fmt_bytes(c.snapshot_bytes),
                fmt_secs(c.snapshot_transfer_secs),
                fmt_secs(c.snapshot_install_secs),
                fmt_secs(c.index_rebuild_secs),
                fmt_secs(c.total_catch_up_secs),
                fmt_secs(c.theoretical_1gbit_secs),
                fmt_bytes(c.learner_sm_file_bytes),
                fmt_bytes(c.peak_rss_bytes),
            ]
        })
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Total RRsets", Right),
            ("Snapshot build", Right),
            ("Snapshot size", Right),
            ("Transfer (in-process)", Right),
            ("Install", Right),
            ("of which index rebuild", Right),
            ("Total catch-up", Right),
            ("Size / 125 MB/s (1 Gbit/s)", Right),
            ("Learner sm.redb", Right),
            ("Peak RSS", Right),
        ],
        &body,
    )
}

/// One latency percentile, or a dash when the summary holds no samples.
fn percentile(summary: &LatencySummary, pick: fn(&LatencySummary) -> u64) -> String {
    if summary.count == 0 {
        DASH.to_string()
    } else {
        fmt_ns(pick(summary))
    }
}

fn steady_row(
    disk: &str,
    total_records: u64,
    run: &LatencyRun,
    fallback_label: &str,
) -> Vec<String> {
    let label = if run.label.trim().is_empty() {
        fallback_label.to_string()
    } else {
        run.label.clone()
    };
    let lookups = &run.lookup_latency;

    // A run without a write target did no writes: every write column is a dash. With a write
    // target the rate and error columns always show the stored values; the latency columns
    // show a dash when there is no latency summary (or it holds no samples).
    let writes = run.write_target_rate > 0;
    let write_latency = run.write_latency.as_ref().filter(|w| writes && w.count > 0);
    let write_pct = |pick: fn(&LatencySummary) -> u64| {
        write_latency.map_or_else(|| DASH.to_string(), |w| percentile(w, pick))
    };
    let if_writes = |value: String| if writes { value } else { DASH.to_string() };

    vec![
        text(disk),
        fmt_count(total_records),
        label,
        fmt_secs(run.duration_secs),
        fmt_rate_target(run.lookup_target_rate),
        fmt_rate(run.lookup_achieved_rate),
        percentile(lookups, |l| l.p50_ns),
        percentile(lookups, |l| l.p90_ns),
        percentile(lookups, |l| l.p99_ns),
        percentile(lookups, |l| l.p999_ns),
        percentile(lookups, |l| l.max_ns),
        if_writes(fmt_rate_target(run.write_target_rate)),
        if_writes(fmt_rate(run.write_achieved_rate)),
        write_pct(|l| l.p50_ns),
        write_pct(|l| l.p99_ns),
        if_writes(fmt_count(run.write_errors)),
        run.other_cpu_busy
            .map_or_else(|| NOT_MEASURED.to_string(), |v| format!("{v:.1}")),
    ]
}

/// One row per bulk load that measured an offline compaction. Columns: Data disk |
/// Total RRsets | Node | sm.redb before | sm.redb after | Reduction | Compaction time.
pub fn compaction_table(rows: &[BulkLoadResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .filter_map(|b| b.compaction.as_ref().map(|c| (b, c)))
        .map(|(b, c)| {
            let saved = c.file_bytes_before.saturating_sub(c.file_bytes_after);
            vec![
                text(&b.disk),
                fmt_count(b.total_records),
                c.node_id.to_string(),
                fmt_bytes(c.file_bytes_before),
                fmt_bytes(c.file_bytes_after),
                fmt_bytes(saved),
                fmt_secs(c.compact_secs),
            ]
        })
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Total RRsets", Right),
            ("Node", Right),
            ("sm.redb before", Right),
            ("sm.redb after", Right),
            ("Reduction", Right),
            ("Compaction time", Right),
        ],
        &body,
    )
}

/// Two rows per SteadyStateResult (baseline, under_writes). Columns: Total RRsets | Run (label) |
/// Duration | Lookups target/s | Lookups achieved/s | p50 | p90 | p99 | p99.9 | max |
/// Writes target/s | Writes achieved/s | Write p50 | Write p99 | Write errors
/// (write columns show "-" when write_target_rate is 0 or write_latency is None).
///
/// A run with a write target but no write latency summary still shows its stored target,
/// achieved rate and error count, because those are measured values; only the two write
/// latency columns show "-".
pub fn steady_table(rows: &[SteadyStateResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .flat_map(|s| {
            [
                steady_row(&s.disk, s.total_records, &s.baseline, "baseline"),
                steady_row(&s.disk, s.total_records, &s.under_writes, "under writes"),
            ]
        })
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Total RRsets", Right),
            ("Run", Left),
            ("Duration", Right),
            ("Lookups target/s", Right),
            ("Lookups achieved/s", Right),
            ("p50", Right),
            ("p90", Right),
            ("p99", Right),
            ("p99.9", Right),
            ("max", Right),
            ("Writes target/s", Right),
            ("Writes achieved/s", Right),
            ("Write p50", Right),
            ("Write p99", Right),
            ("Write errors", Right),
            ("Other processes: busy logical CPUs", Right),
        ],
        &body,
    )
}

/// Columns: Changes requested | Approach | Journal: changes read | Journal: time | Journal: bytes |
/// Raft log: changes read | Raft log: time ("not measured" when None).
pub fn change_feed_table(rows: &[ChangeFeedResult]) -> String {
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|c| {
            vec![
                text(&c.disk),
                fmt_count(c.total_records),
                fmt_count(c.changes_requested),
                text(&c.approach),
                fmt_count(c.journal_changes_read),
                fmt_secs(c.journal_secs),
                fmt_bytes(c.journal_bytes),
                c.log_changes_read
                    .map_or_else(|| NOT_MEASURED.to_string(), fmt_count),
                c.log_secs
                    .map_or_else(|| NOT_MEASURED.to_string(), fmt_secs),
            ]
        })
        .collect();
    table(
        &[
            ("Data disk", Left),
            ("Total RRsets", Right),
            ("Changes requested", Right),
            ("Approach", Left),
            ("Journal: changes read", Right),
            ("Journal: time", Right),
            ("Journal: bytes", Right),
            ("Raft log: changes read", Right),
            ("Raft log: time", Right),
        ],
        &body,
    )
}

// ---------------------------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------------------------

/// Appends `\n<heading>\n\n<body>`; `body` already ends with a newline.
fn push_section(out: &mut String, heading: &str, body: &str) {
    out.push('\n');
    out.push_str(heading);
    out.push_str("\n\n");
    out.push_str(body);
}

/// The table, or the "not run" line when there is nothing to tabulate.
fn table_or_not_run(empty: bool, render: impl FnOnce() -> String) -> String {
    if empty { NOT_RUN.to_string() } else { render() }
}

/// One Markdown bullet per note; continuation lines are indented so they stay in the bullet.
fn push_note(out: &mut String, note: &str) {
    for (i, line) in note.trim().lines().enumerate() {
        let line = line.trim_end();
        match (i, line.is_empty()) {
            (0, _) => {
                out.push_str("- ");
                out.push_str(line);
            }
            (_, true) => {}
            (_, false) => {
                out.push_str("  ");
                out.push_str(line);
            }
        }
        out.push('\n');
    }
}

/// Full document:
/// # Spike A results: openraft + redb, {r.date} (Windows)
/// A prominent blockquote line stating the replication mode, plus one sentence on what produced
/// the numbers, then one section per measurement (criteria, machine, dependencies, cluster
/// configuration, bulk load with per-node disk usage, learner catch-up, steady-state lookup
/// latency under writes, change feed), then the notes. `extra` (methodology, observations,
/// recommendation) is inserted verbatim after a blank line right after the criteria summary.
/// Sections whose input vector is empty render a single line "_Not run._".
pub fn render_markdown(r: &Results, extra: Option<&str>) -> String {
    let mut out = String::new();

    let date = one_line(r.date.trim());
    let date = if date.is_empty() {
        "unknown date"
    } else {
        &date
    };
    let _ = writeln!(out, "# Spike A results: openraft + redb, {date} (Windows)");
    out.push('\n');

    let mode = one_line(r.config.mode.trim());
    if mode.is_empty() {
        out.push_str("> **Replication mode: not recorded**\n>\n");
        out.push_str("> The replication mode was not recorded for this run.\n");
    } else if mode == "openraft" {
        let _ = writeln!(out, "> **Replication mode: {mode}**\n>");
        out.push_str(
            "> All numbers were produced by a real openraft cluster (3 voters, or 1 voter for \
             the per-node RSS run, plus 1 learner for the catch-up test) running in one \
             process with an in-process channel network.\n",
        );
    } else {
        let _ = writeln!(out, "> **Replication mode: {mode}**\n>");
        out.push_str(
            "> All numbers were produced by the SIMULATED replication fallback, not by openraft.\n",
        );
    }

    push_section(
        &mut out,
        "## Summary: pass criteria",
        &table_or_not_run(r.criteria.is_empty(), || criteria_table(&r.criteria)),
    );
    // Free-form sections (methodology, observations, recommendation) follow the verdict.
    if let Some(extra) = extra {
        out.push('\n');
        out.push_str(extra);
    }
    push_section(&mut out, "## Machine", &machine_table(&r.machine));
    push_section(
        &mut out,
        "## Exact dependency versions",
        &table_or_not_run(r.deps.is_empty(), || deps_table(&r.deps)),
    );
    push_section(
        &mut out,
        "## Cluster configuration",
        &config_table(&r.config),
    );

    let mut bulk = table_or_not_run(r.bulk_loads.is_empty(), || bulk_load_table(&r.bulk_loads));
    if !r.bulk_loads.is_empty() {
        bulk.push_str("\n### Disk usage per node\n\n");
        if r.bulk_loads.iter().all(|b| b.per_node.is_empty()) {
            bulk.push_str(DISK_NOT_MEASURED);
        } else {
            bulk.push_str(&disk_table(&r.bulk_loads));
        }
        if r.bulk_loads.iter().any(|b| b.compaction.is_some()) {
            bulk.push_str(
                "
### Offline compaction of one follower sm.redb (after the run)

",
            );
            bulk.push_str(&compaction_table(&r.bulk_loads));
        }
    }
    push_section(&mut out, "## 1. Bulk load", &bulk);

    push_section(
        &mut out,
        "## 2. Learner catch-up (snapshot)",
        &table_or_not_run(r.catch_ups.is_empty(), || catch_up_table(&r.catch_ups)),
    );
    push_section(
        &mut out,
        "## 3. Lookup latency, steady state under writes",
        &table_or_not_run(r.steady.is_empty(), || steady_table(&r.steady)),
    );
    push_section(
        &mut out,
        "## 4. Change feed (IXFR delta enumeration)",
        &table_or_not_run(r.change_feed.is_empty(), || {
            change_feed_table(&r.change_feed)
        }),
    );

    let mut notes = String::new();
    for note in &r.notes {
        push_note(&mut notes, note);
    }
    if !notes.is_empty() {
        push_section(&mut out, "## Notes", &notes);
    }

    out
}

/// Creates parent directories and writes render_markdown(r, extra) to `path`.
pub fn write_markdown(path: &Path, r: &Results, extra: Option<&str>) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, render_markdown(r, extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- sample data -------------------------------------------------------------------------

    fn node(id: u64, log: u64, sm: u64) -> NodeDiskUsage {
        NodeDiskUsage {
            node_id: id,
            log_file_bytes: log,
            sm_file_bytes: sm,
            ..Default::default()
        }
    }

    fn bulk(forward: u64, total: u64, wall: f64, raw: u64) -> BulkLoadResult {
        BulkLoadResult {
            forward_zone_records: forward,
            total_records: total,
            voters: 3,
            batch_records: 1_000,
            raft_entries: total / 1_000,
            wall_secs: wall,
            records_per_sec: total as f64 / wall,
            peak_rss_bytes: 3_221_225_472,
            rss_after_bytes: 2_147_483_648,
            rss_before_bytes: 52_428_800,
            raw_kv_bytes: raw,
            avg_entry_bytes: 63.4,
            per_node: vec![
                node(1, raw * 2, raw * 231 / 100),
                node(2, raw * 2, raw * 232 / 100),
                node(3, raw * 2, raw * 233 / 100),
            ],
            index_entries: total,
            index_estimated_bytes: total * 150,
            ..Default::default()
        }
    }

    fn latency(scale: u64) -> LatencySummary {
        LatencySummary {
            count: 1_000_000,
            min_ns: 120 * scale,
            p50_ns: 850 * scale,
            p90_ns: 1_230 * scale,
            p99_ns: 12_300 * scale,
            p999_ns: 123_000 * scale,
            max_ns: 1_230_000 * scale,
            mean_ns: 900.0 * scale as f64,
        }
    }

    fn sample() -> Results {
        Results {
            date: "2026-10-09".to_string(),
            machine: MachineInfo {
                os: "Windows 11 Enterprise 10.0.26300".to_string(),
                cpu_brand: "Example CPU | 16-Core".to_string(),
                logical_cpus: 32,
                total_memory_bytes: 68_719_476_736,
                rustc_version: "rustc 1.99.0 (5f94df478 2026-08-27)".to_string(),
            },
            deps: vec![
                DepVersion {
                    name: "openraft".to_string(),
                    version: "0.9.25".to_string(),
                },
                DepVersion {
                    name: "redb".to_string(),
                    version: "4.3.0".to_string(),
                },
            ],
            config: RunConfig {
                mode: "openraft".to_string(),
                voters: 3,
                batch_records: 1_000,
                ptr_percent: 10,
                redb_cache_bytes: 1_073_741_824,
                log_store: "redb (log.redb per node)".to_string(),
                log_durability: "Immediate (fsync per append)".to_string(),
                sm_durability: "Immediate (fsync per apply batch)".to_string(),
                max_payload_entries: 300,
                network: "in-process channels".to_string(),
            },
            bulk_loads: vec![
                bulk(1_000_000, 1_100_000, 12.3456, 90_000_000),
                bulk(100_000, 110_000, 1.5, 9_000_000),
            ],
            catch_ups: vec![CatchUpResult {
                total_records: 1_100_000,
                snapshot_build_secs: 2.5,
                snapshot_bytes: 250_000_000,
                snapshot_transfer_secs: 0.004,
                snapshot_install_secs: 6.789,
                index_rebuild_secs: 3.21,
                total_catch_up_secs: 9.99,
                theoretical_1gbit_secs: 2.0,
                learner_sm_file_bytes: 300_000_000,
                peak_rss_bytes: 4_294_967_296,
                ..Default::default()
            }],
            steady: vec![SteadyStateResult {
                total_records: 1_100_000,
                baseline: LatencyRun {
                    label: "baseline".to_string(),
                    lookup_target_rate: 100_000,
                    lookup_achieved_rate: 99_876.4,
                    duration_secs: 30.0,
                    lookup_latency: latency(1),
                    write_target_rate: 0,
                    write_achieved_rate: 0.0,
                    write_latency: None,
                    write_errors: 0,
                    ..Default::default()
                },
                under_writes: LatencyRun {
                    label: "under_writes".to_string(),
                    lookup_target_rate: 100_000,
                    lookup_achieved_rate: 98_001.2,
                    duration_secs: 30.0,
                    lookup_latency: latency(2),
                    write_target_rate: 500,
                    write_achieved_rate: 497.5,
                    write_latency: Some(latency(1_000)),
                    write_errors: 3,
                    ..Default::default()
                },
                ..Default::default()
            }],
            change_feed: vec![ChangeFeedResult {
                changes_requested: 100_000,
                approach: "change-journal table in the state machine".to_string(),
                journal_changes_read: 100_000,
                journal_secs: 0.0421,
                journal_bytes: 6_400_000,
                log_changes_read: None,
                log_secs: None,
                ..Default::default()
            }],
            criteria: vec![
                Criterion {
                    name: "p99 lookup latency".to_string(),
                    threshold: "< 1 ms".to_string(),
                    measured: "12.3 us".to_string(),
                    pass: true,
                },
                Criterion {
                    name: "Snapshot catch-up".to_string(),
                    threshold: "< 5 s".to_string(),
                    measured: "9.99 s".to_string(),
                    pass: false,
                },
                Criterion {
                    name: "Peak RSS".to_string(),
                    threshold: "<= 4 GiB".to_string(),
                    measured: "3.00 GiB".to_string(),
                    pass: true,
                },
            ],
            notes: vec![
                "Single machine, loopback only.".to_string(),
                "Second note with a pipe | inside.".to_string(),
            ],
        }
    }

    // ----- table parsing helpers -----------------------------------------------------------------

    /// Splits a table line on unescaped pipes, trimming the cells.
    /// Data cells after the leading "Data disk" column, limited to `n` cells.
    fn data_cells(line: &str, n: usize) -> Vec<String> {
        cells(line)[1..1 + n].to_vec()
    }

    fn cells(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut prev_backslash = false;
        for ch in line.chars() {
            if ch == '|' && !prev_backslash {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(ch);
            }
            prev_backslash = ch == '\\';
        }
        out.push(cur);
        // Leading and trailing delimiters produce one empty fragment each.
        assert!(
            out.first().is_some_and(|c| c.trim().is_empty()),
            "line: {line}"
        );
        assert!(
            out.last().is_some_and(|c| c.trim().is_empty()),
            "line: {line}"
        );
        out.remove(0);
        out.pop();
        out.into_iter().map(|c| c.trim().to_string()).collect()
    }

    /// Groups the document's table lines into blocks of consecutive lines starting with `|`.
    fn table_blocks(doc: &str) -> Vec<Vec<&str>> {
        let mut blocks: Vec<Vec<&str>> = Vec::new();
        let mut in_table = false;
        for line in doc.lines() {
            if line.starts_with('|') {
                if !in_table {
                    blocks.push(Vec::new());
                    in_table = true;
                }
                blocks.last_mut().unwrap().push(line);
            } else {
                in_table = false;
            }
        }
        blocks
    }

    fn header_of(table: &str) -> Vec<String> {
        cells(table.lines().next().unwrap())
    }

    fn assert_well_formed(doc: &str) {
        assert!(doc.ends_with('\n'));
        assert!(!doc.contains('\r'), "CR found");
        for (n, line) in doc.lines().enumerate() {
            assert_eq!(line, line.trim_end(), "trailing space on line {}", n + 1);
        }
        for block in table_blocks(doc) {
            assert!(block.len() >= 2, "table without separator row: {block:?}");
            let width = cells(block[0]).len();
            for line in &block {
                assert_eq!(cells(line).len(), width, "cell count differs on: {line}");
            }
            for sep in cells(block[1]) {
                let core = sep.strip_prefix(':').unwrap_or(&sep);
                let core = core.strip_suffix(':').unwrap_or(core);
                assert!(
                    !core.is_empty() && core.chars().all(|c| c == '-'),
                    "bad separator cell {sep:?}"
                );
            }
        }
    }

    // ----- tests -----------------------------------------------------------------------------

    #[test]
    fn full_document_is_complete_and_well_formed() {
        let r = sample();
        let doc = render_markdown(&r, None);
        println!("{doc}");

        for heading in [
            "# Spike A results: openraft + redb, 2026-10-09 (Windows)",
            "## Summary: pass criteria",
            "## Machine",
            "## Exact dependency versions",
            "## Cluster configuration",
            "## 1. Bulk load",
            "### Disk usage per node",
            "## 2. Learner catch-up (snapshot)",
            "## 3. Lookup latency, steady state under writes",
            "## 4. Change feed (IXFR delta enumeration)",
            "## Notes",
        ] {
            assert!(
                doc.lines().any(|l| l == heading),
                "missing heading {heading:?}"
            );
        }
        assert!(doc.contains("**PASS**"));
        assert!(doc.contains("**FAIL**"));
        assert!(doc.contains("not measured"));
        assert!(doc.contains("> **Replication mode: openraft**"));
        assert!(doc.contains(
            "All numbers were produced by a real openraft cluster (3 voters, or 1 voter for \
             the per-node RSS run, plus 1 learner for the catch-up test) running in one \
             process with an in-process channel network."
        ));
        assert!(!doc.contains("SIMULATED"));
        assert!(doc.contains("- Single machine, loopback only."));
        assert!(doc.contains("- Second note with a pipe | inside."));
        assert!(!doc.contains("_Not run._"));

        assert_well_formed(&doc);
        // criteria, machine, deps, config, bulk, disk, catch-up, steady, change feed
        assert_eq!(table_blocks(&doc).len(), 9);
    }

    #[test]
    fn simulated_mode_is_stated() {
        let mut r = sample();
        r.config.mode = "simulated".to_string();
        let doc = render_markdown(&r, None);
        assert!(doc.contains("> **Replication mode: simulated**"));
        assert!(doc.contains(
            "> All numbers were produced by the SIMULATED replication fallback, not by openraft."
        ));
        assert!(!doc.contains("real openraft cluster"));
        assert_well_formed(&doc);
    }

    #[test]
    fn pipe_in_cell_text_is_escaped() {
        let r = sample();
        let machine = machine_table(&r.machine);
        let line = machine.lines().nth(3).unwrap();
        assert!(line.contains("Example CPU \\| 16-Core"));
        assert_eq!(cells(line).len(), 2);
        // Line breaks inside a value cannot split the row.
        let c = criteria_table(&[Criterion {
            name: "a\nb".to_string(),
            threshold: "x | y".to_string(),
            measured: String::new(),
            pass: true,
        }]);
        assert_eq!(c.lines().count(), 3);
        assert_eq!(
            cells(c.lines().nth(2).unwrap()),
            ["a b", "x \\| y", "-", "**PASS**"]
        );
    }

    #[test]
    fn exact_headers() {
        let r = sample();
        assert_eq!(
            header_of(&criteria_table(&r.criteria)),
            ["Criterion", "Threshold", "Measured", "Result"]
        );
        assert_eq!(header_of(&deps_table(&r.deps)), ["Crate", "Version"]);
        assert_eq!(header_of(&config_table(&r.config)), ["Setting", "Value"]);
        assert_eq!(header_of(&machine_table(&r.machine)), ["Property", "Value"]);
        assert_eq!(
            header_of(&bulk_load_table(&r.bulk_loads)),
            [
                "Data disk",
                "Forward-zone records",
                "Total RRsets",
                "Voters",
                "Raft entries",
                "Wall time",
                "Records/s",
                "RSS before",
                "Peak RSS",
                "RSS after",
                "Avg entry (key+value)",
                "Raw KV bytes",
                "Index entries (per node)",
                "Index size est. (per node)",
                "Bytes written (process)",
                "Written / (raw KV x voters)",
            ]
        );
        assert_eq!(
            header_of(&disk_table(&r.bulk_loads)),
            [
                "Data disk",
                "Total RRsets",
                "Voters",
                "Node",
                "log.redb",
                "sm.redb",
                "log+sm",
                "sm.redb / raw KV",
                "(log+sm) / raw KV",
                "sm.redb stored bytes (redb stats)",
                "sm.redb fragmented bytes (redb stats)",
            ]
        );
        assert_eq!(
            header_of(&catch_up_table(&r.catch_ups)),
            [
                "Data disk",
                "Total RRsets",
                "Snapshot build",
                "Snapshot size",
                "Transfer (in-process)",
                "Install",
                "of which index rebuild",
                "Total catch-up",
                "Size / 125 MB/s (1 Gbit/s)",
                "Learner sm.redb",
                "Peak RSS",
            ]
        );
        assert_eq!(
            header_of(&steady_table(&r.steady)),
            [
                "Data disk",
                "Total RRsets",
                "Run",
                "Duration",
                "Lookups target/s",
                "Lookups achieved/s",
                "p50",
                "p90",
                "p99",
                "p99.9",
                "max",
                "Writes target/s",
                "Writes achieved/s",
                "Write p50",
                "Write p99",
                "Write errors",
                "Other processes: busy logical CPUs",
            ]
        );
        assert_eq!(
            header_of(&change_feed_table(&r.change_feed)),
            [
                "Data disk",
                "Total RRsets",
                "Changes requested",
                "Approach",
                "Journal: changes read",
                "Journal: time",
                "Journal: bytes",
                "Raft log: changes read",
                "Raft log: time",
            ]
        );
    }

    #[test]
    fn row_values_are_rendered_from_the_structs() {
        let r = sample();

        let bulk = bulk_load_table(&r.bulk_loads);
        assert_eq!(bulk.lines().count(), 4);
        assert_eq!(
            data_cells(bulk.lines().nth(2).unwrap(), 13),
            [
                "1,000,000",
                "1,100,000",
                "3",
                "1,100",
                "12.35 s",
                "89,101/s",
                "50.00 MiB",
                "3.00 GiB",
                "2.00 GiB",
                "63.4 B",
                "85.83 MiB",
                "1,100,000",
                "157.36 MiB",
            ]
        );

        let disk = disk_table(&r.bulk_loads);
        // 2 runs x 3 nodes, plus header and separator.
        assert_eq!(disk.lines().count(), 8);
        assert_eq!(
            data_cells(disk.lines().nth(2).unwrap(), 8),
            [
                "1,100,000",
                "3",
                "1",
                "171.66 MiB",
                "198.27 MiB",
                "369.93 MiB",
                "2.31x",
                "4.31x",
            ]
        );

        let catch_up = catch_up_table(&r.catch_ups);
        assert_eq!(
            data_cells(catch_up.lines().nth(2).unwrap(), 10),
            [
                "1,100,000",
                "2.50 s",
                "238.42 MiB",
                "4.00 ms",
                "6.79 s",
                "3.21 s",
                "9.99 s",
                "2.00 s",
                "286.10 MiB",
                "4.00 GiB",
            ]
        );

        let steady = steady_table(&r.steady);
        assert_eq!(steady.lines().count(), 4);
        assert_eq!(
            data_cells(steady.lines().nth(2).unwrap(), 15),
            [
                "1,100,000",
                "baseline",
                "30.00 s",
                "100,000/s",
                "99,876/s",
                "850 ns",
                "1.23 us",
                "12.3 us",
                "123 us",
                "1.23 ms",
                "-",
                "-",
                "-",
                "-",
                "-",
            ]
        );
        assert_eq!(
            data_cells(steady.lines().nth(3).unwrap(), 15),
            [
                "1,100,000",
                "under_writes",
                "30.00 s",
                "100,000/s",
                "98,001/s",
                "1.70 us",
                "2.46 us",
                "24.6 us",
                "246 us",
                "2.46 ms",
                "500/s",
                "498/s",
                "850 us",
                "12.3 ms",
                "3",
            ]
        );

        let feed = change_feed_table(&r.change_feed);
        assert_eq!(
            data_cells(feed.lines().nth(2).unwrap(), 8),
            [
                "0",
                "100,000",
                "change-journal table in the state machine",
                "100,000",
                "42.1 ms",
                "6.10 MiB",
                "not measured",
                "not measured",
            ]
        );
    }

    #[test]
    fn change_feed_with_log_values_shows_them() {
        let mut r = sample();
        r.change_feed[0].log_changes_read = Some(99_999);
        r.change_feed[0].log_secs = Some(1.5);
        let feed = change_feed_table(&r.change_feed);
        let row = cells(feed.lines().nth(2).unwrap());
        assert_eq!(row[7], "99,999");
        assert_eq!(row[8], "1.50 s");
        assert!(!feed.contains("not measured"));
    }

    #[test]
    fn steady_write_columns_follow_target_and_latency() {
        let mut r = sample();
        // Write target set but no latency summary: rates and errors stay, latency columns dash.
        r.steady[0].under_writes.write_latency = None;
        let t = steady_table(&r.steady);
        let row = cells(t.lines().nth(3).unwrap());
        assert_eq!(&row[11..16], ["500/s", "498/s", "-", "-", "3"]);
        // A latency summary without samples never prints zeros.
        r.steady[0].under_writes.write_latency = Some(LatencySummary::default());
        let t = steady_table(&r.steady);
        let row = cells(t.lines().nth(3).unwrap());
        assert_eq!(&row[13..15], ["-", "-"]);
        // Empty labels fall back to the run kind.
        r.steady[0].baseline.label.clear();
        r.steady[0].under_writes.label.clear();
        let t = steady_table(&r.steady);
        assert_eq!(cells(t.lines().nth(2).unwrap())[2], "baseline");
        assert_eq!(cells(t.lines().nth(3).unwrap())[2], "under writes");
        assert_well_formed(&t);
    }

    #[test]
    fn tables_render_header_only_for_empty_input() {
        for t in [
            deps_table(&[]),
            criteria_table(&[]),
            bulk_load_table(&[]),
            disk_table(&[]),
            catch_up_table(&[]),
            steady_table(&[]),
            change_feed_table(&[]),
        ] {
            assert_eq!(t.lines().count(), 2);
            assert_well_formed(&t);
        }
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1536), "1.50 KiB");
        assert_eq!(fmt_bytes(1_048_575), "1.00 MiB");
        assert_eq!(fmt_bytes(1_319_413_954), "1.23 GiB");
        assert_eq!(fmt_bytes(u64::MAX), "16.00 EiB");
        assert_eq!(fmt_bytes_f64(63.4), "63.4 B");
        assert_eq!(fmt_bytes_f64(1023.99), "1.00 KiB");
        assert_eq!(fmt_bytes_f64(2048.0), "2.00 KiB");
        assert_eq!(fmt_bytes_f64(f64::NAN), "n/a");

        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(1_234_567), "1,234,567");
        assert_eq!(fmt_count(12_345_678), "12,345,678");
        assert_eq!(fmt_count(u64::MAX), "18,446,744,073,709,551,615");

        assert_eq!(fmt_ns(0), "0 ns");
        assert_eq!(fmt_ns(850), "850 ns");
        assert_eq!(fmt_ns(999), "999 ns");
        assert_eq!(fmt_ns(1_000), "1.00 us");
        assert_eq!(fmt_ns(12_300), "12.3 us");
        assert_eq!(fmt_ns(123_456), "123 us");
        assert_eq!(fmt_ns(999_499), "999 us");
        assert_eq!(fmt_ns(999_500), "1.00 ms");
        assert_eq!(fmt_ns(1_230_000), "1.23 ms");
        assert_eq!(fmt_ns(45_600_000), "45.6 ms");
        assert_eq!(fmt_ns(1_500_000_000), "1.50 s");
        assert_eq!(fmt_ns_f64(f64::INFINITY), "n/a");

        assert_eq!(fmt_secs(0.0), "0.00 s");
        assert_eq!(fmt_secs(12.3456), "12.35 s");
        assert_eq!(fmt_secs(1234.5), "1234.50 s");
        assert_eq!(fmt_secs(0.5), "0.50 s");
        assert_eq!(fmt_secs(0.004), "4.00 ms");
        assert_eq!(fmt_secs(0.0421), "42.1 ms");
        assert_eq!(fmt_secs(0.0999), "99.9 ms");
        assert_eq!(fmt_secs(0.1), "0.10 s");
        assert_eq!(fmt_secs(f64::NAN), "n/a");

        assert_eq!(fmt_rate(0.0), "0/s");
        assert_eq!(fmt_rate(123_456.4), "123,456/s");
        assert_eq!(fmt_rate(123_456.6), "123,457/s");
        assert_eq!(fmt_rate(99.96), "100/s");
        assert_eq!(fmt_rate(12.34), "12.3/s");
        assert_eq!(fmt_rate(0.5), "0.50/s");
        assert_eq!(fmt_rate(f64::NAN), "n/a");
        assert_eq!(fmt_rate_target(1_000_000), "1,000,000/s");

        assert_eq!(fmt_ratio(231, 100), "2.31x");
        assert_eq!(fmt_ratio(1, 3), "0.33x");
        assert_eq!(fmt_ratio(5, 0), "n/a");
    }

    #[test]
    fn empty_vectors_render_not_run() {
        let r = Results {
            date: "2026-10-09".to_string(),
            ..Results::default()
        };
        let doc = render_markdown(&r, None);
        println!("{doc}");
        assert_eq!(doc.matches("_Not run._").count(), 6);
        for heading in [
            "## Summary: pass criteria",
            "## Exact dependency versions",
            "## 1. Bulk load",
            "## 2. Learner catch-up (snapshot)",
            "## 3. Lookup latency, steady state under writes",
            "## 4. Change feed (IXFR delta enumeration)",
        ] {
            let at = doc
                .find(heading)
                .unwrap_or_else(|| panic!("missing {heading}"));
            let body = &doc[at + heading.len()..];
            assert!(
                body.starts_with("\n\n_Not run._\n"),
                "{heading}: {body:.40}"
            );
        }
        assert!(!doc.contains("### Disk usage per node"));
        assert!(!doc.contains("## Notes"));
        assert!(doc.contains("> **Replication mode: not recorded**"));
        assert_well_formed(&doc);
    }

    #[test]
    fn disk_section_without_per_node_data_says_not_measured() {
        let mut r = sample();
        for b in &mut r.bulk_loads {
            b.per_node.clear();
        }
        let doc = render_markdown(&r, None);
        assert!(doc.contains("### Disk usage per node\n\n_Not measured._\n"));
        assert_well_formed(&doc);
    }

    #[test]
    fn multi_line_notes_stay_inside_their_bullet() {
        let mut r = sample();
        r.notes = vec![
            "first line\nsecond line\n\nthird line  ".to_string(),
            "   ".to_string(),
        ];
        let doc = render_markdown(&r, None);
        assert!(doc.ends_with("## Notes\n\n- first line\n  second line\n\n  third line\n"));
        assert_well_formed(&doc);
    }

    #[test]
    fn extra_is_inserted_verbatim_after_the_summary() {
        let r = sample();
        let plain = render_markdown(&r, None);
        let extra = "## Appendix\n\nraw text | with pipe\n";
        let doc = render_markdown(&r, Some(extra));
        assert_eq!(doc.len(), plain.len() + extra.len() + 1);
        let at = doc.find(extra).expect("extra present");
        assert!(at > doc.find("## Summary: pass criteria").expect("summary"));
        assert!(at < doc.find("## Machine").expect("machine"));
    }

    #[test]
    fn write_markdown_creates_parent_directories() {
        let dir = std::env::temp_dir().join(format!("report-test-{}", std::process::id()));
        let path = dir.join("nested").join("deeper").join("out.md");
        let r = sample();
        write_markdown(&path, &r, Some("tail\n")).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, render_markdown(&r, Some("tail\n")));
        assert!(!std::fs::read(&path).unwrap().contains(&b'\r'));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sample_round_trips_through_json_then_renders_identically() {
        // Guards against the report depending on anything that is lost in the child-process
        // JSON protocol.
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        let back: Results = serde_json::from_str(&json).unwrap();
        assert_eq!(render_markdown(&r, None), render_markdown(&back, None));
    }
}
