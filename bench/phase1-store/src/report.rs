//! The results document: `results/2026-10-09-windows.md`, written from `results/raw/*.json`
//! and the hand-written observations in `results/notes/*.md`.

#![allow(
    clippy::too_many_lines,
    reason = "the document is assembled by one long function per measurement"
)]

use std::{fmt::Write as _, fs, path::Path};

use anyhow::{Context as _, Result};

use crate::{
    Ctx,
    common::{GIB, MIB, Machine, RunMeta, bytes_f64, count_f64},
    m1, m2, m5, m6, m10,
};

const DOCUMENT: &str = "2026-10-09-windows.md";

/// One row of the summary table.
struct Summary {
    measurement: String,
    threshold: String,
    measured: String,
    result: String,
}

fn verdict(pass: bool) -> String {
    if pass { "PASS" } else { "FAIL" }.to_owned()
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

fn ns(nanos: u64) -> String {
    let value = count_f64(nanos);
    if nanos < 1_000 {
        format!("{nanos} ns")
    } else if nanos < 1_000_000 {
        format!("{:.1} us", value / 1e3)
    } else if nanos < 1_000_000_000 {
        format!("{:.1} ms", value / 1e6)
    } else {
        format!("{:.2} s", value / 1e9)
    }
}

fn ns_f(nanos: f64) -> String {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "display"
    )]
    ns(nanos.max(0.0).round() as u64)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "display"
)]
fn per_second(count: u64, secs: f64) -> String {
    thousands((count_f64(count) / secs).max(0.0) as u64)
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes_f64(bytes) / bytes_f64(MIB))
}

fn gib(bytes: u64) -> String {
    format!("{:.2} GiB", bytes_f64(bytes) / bytes_f64(GIB))
}

fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (position, digit) in digits.chars().enumerate() {
        if position > 0 && (digits.len() - position).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "| {} |", headers.join(" | "));
    let _ = writeln!(
        out,
        "|{}|",
        headers.iter().map(|_| "---").collect::<Vec<_>>().join("|")
    );
    for row in rows {
        let _ = writeln!(out, "| {} |", row.join(" | "));
    }
    out
}

fn code_block(text: &str) -> String {
    format!("```text\n{}\n```\n", text.trim_end())
}

fn notes(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join("notes").join(format!("{name}.md")))
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
}

fn observations(dir: &Path, name: &str) -> String {
    let text = notes(dir, name);
    if text.is_empty() {
        String::new()
    } else {
        format!("\n### Observations\n\n{text}\n")
    }
}

// ---------------------------------------------------------------------------------------------
// M1
// ---------------------------------------------------------------------------------------------

fn m1_section(
    report: Option<&m1::Report>,
    dir: &Path,
    notes_name: &str,
    summary: &mut Vec<Summary>,
) -> String {
    let threshold = "No empty reads; lookup p99 during install below 2x the baseline p99";
    let mut out = String::from("## M1: index swap on snapshot install\n\n");
    let Some(report) = report else {
        out.push_str("Not run.\n");
        summary.push(Summary {
            measurement: "M1 index swap on snapshot install".to_owned(),
            threshold: threshold.to_owned(),
            measured: "not measured: not run".to_owned(),
            result: "-".to_owned(),
        });
        return out;
    };
    let config = &report.config;
    out.push_str(
        "**Method.** A leader (node 1) and a learner (node 2) run in one process over \
         `InProcessNetwork`, each with its own data directory. The learner holds a test \
         `DerivedIndex` modelled on Spike A's serving index: 64 shards of \
         `RwLock<HashMap<Bytes, Bytes>>` behind an `ArcSwap`; `apply` updates the live image in \
         place, `build` scans the table in pages of 20,000 rows into a new image, `install` \
         swaps it in. N records of 150 bytes (22-byte key, 128-byte value) are loaded into the \
         leader in batches of 10,000 records, the leader snapshots and purges its log, and the \
         learner catches up from that snapshot (its first install builds the index). The \
         learner is then cut off. Each round updates a random 10 percent of the records on the \
         leader, snapshots, and pushes the snapshot to the learner through \
         `RaftStore::receive_snapshot()` + `write_chunk` + `install(vote, meta)`. Four reader \
         threads look up random keys that exist throughout, at a fixed 50,000 lookups/s in \
         total (paced per millisecond, each lookup timed on its own with `Instant`), once \
         for a baseline window without an install and once from the first streamed byte until \
         the learner has applied the snapshot (the install window). A lookup that returns \
         nothing is an empty read; a lookup that returns the value of another record is a \
         mismatch. After the last round the learner is reconnected and must follow the leader \
         by log again.\n\n",
    );
    let _ = writeln!(
        out,
        "**Configuration.** {} rounds per size; {} reader threads; {} lookups/s in total; \
         baseline window {} s (after 1 s of warm-up); {} percent of the records updated per \
         round; batches of {} records; `sm_cache_bytes` {} MiB, `log_cache_bytes` {} MiB \
         (store defaults); durability: {}; snapshots: {}; index: {}.\n",
        config.rounds,
        config.readers,
        thousands(config.lookups_per_s),
        config.baseline_secs,
        config.update_percent,
        thousands(config.batch_records as u64),
        config.sm_cache_bytes / (1 << 20),
        config.log_cache_bytes / (1 << 20),
        config.durability,
        config.snapshot_policy,
        config.index,
    );
    let _ = writeln!(
        out,
        "Memory available at the start: {}.\n",
        gib(report.available_memory_bytes)
    );

    let mut results = Vec::new();
    for run in &report.runs {
        let _ = writeln!(out, "### {} records\n", thousands(run.records));
        out.push_str(&table(
            &["Step", "Value"],
            &[
                vec![
                    "Load into the leader".to_owned(),
                    format!(
                        "{:.1} s ({} records/s)",
                        run.load_secs,
                        per_second(run.records, run.load_secs)
                    ),
                ],
                vec![
                    "First snapshot".to_owned(),
                    format!(
                        "{} built in {:.2} s",
                        mib(run.initial_snapshot_bytes),
                        run.initial_snapshot_build_secs
                    ),
                ],
                vec![
                    "Learner catch-up by snapshot (add_learner until applied)".to_owned(),
                    format!("{:.1} s", run.catch_up_secs),
                ],
                vec![
                    "First install on the learner (including index build)".to_owned(),
                    format!(
                        "{:.2} s, of which index build {:.2} s",
                        run.catch_up_install_secs, run.catch_up_index_rebuild_secs
                    ),
                ],
                vec![
                    "Process RSS after catch-up (leader and learner)".to_owned(),
                    format!("{:.0} MiB", run.rss_after_catch_up_mib),
                ],
            ],
        ));
        out.push('\n');
        let rows: Vec<Vec<String>> = run
            .rounds
            .iter()
            .map(|r| {
                vec![
                    r.number.to_string(),
                    thousands(r.updated_records),
                    mib(r.snapshot_bytes),
                    thousands(r.baseline.lookups),
                    format!(
                        "{} / {} / {}",
                        ns(r.baseline.latency.p50_ns),
                        ns(r.baseline.latency.p99_ns),
                        ns(r.baseline.latency.max_ns)
                    ),
                    thousands(r.install.lookups),
                    format!(
                        "{} / {} / {}",
                        ns(r.install.latency.p50_ns),
                        ns(r.install.latency.p99_ns),
                        ns(r.install.latency.max_ns)
                    ),
                    format!("{:.2}x", r.p99_ratio),
                    (r.baseline.empty_reads + r.install.empty_reads).to_string(),
                    (r.baseline.mismatches + r.install.mismatches).to_string(),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "Round",
                "Updated",
                "Snapshot",
                "Baseline lookups",
                "Baseline p50 / p99 / max",
                "Install lookups",
                "Install p50 / p99 / max",
                "p99 ratio",
                "Empty reads",
                "Mismatches",
            ],
            &rows,
        ));
        out.push('\n');
        let rows: Vec<Vec<String>> = run
            .rounds
            .iter()
            .map(|r| {
                vec![
                    r.number.to_string(),
                    format!("{:.1} s", r.update_secs),
                    format!("{:.2} s", r.snapshot_build_secs),
                    format!("{:.2} s", r.transfer_secs),
                    format!("{:.2} s", r.install_call_secs),
                    format!("{:.2} s", r.window_secs),
                    format!("{:.2} s", r.learner_install_secs),
                    format!("{:.2} s", r.index_rebuild_secs),
                    if r.compact_secs > 0.0 {
                        format!("{:.2} s", r.compact_secs)
                    } else {
                        "-".to_owned()
                    },
                    format!(
                        "{:.0} -> {:.0} MiB",
                        r.rss_before_mib, r.rss_peak_install_mib
                    ),
                    r.installs_during_window.to_string(),
                    yes_no(r.updated_visible_after && r.index_revision_matches).to_owned(),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "Round",
                "10% update on leader",
                "Snapshot build",
                "Transfer",
                "install() call",
                "Install window",
                "Learner install (engine_stats)",
                "Index rebuild (engine_stats)",
                "Compaction of the new state file (engine_stats)",
                "RSS before -> peak",
                "Installs in window",
                "Index current after",
            ],
            &rows,
        ));
        let s = &run.summary;
        let _ = writeln!(
            out,
            "\nMedian of {} rounds: baseline p99 {}, install p99 {}, ratio {:.2}x (worst round \
             {:.2}x); worst install p99 {}, worst install max {}; median install window {:.1} \
             s, of which index rebuild {:.2} s. Empty reads {}, mismatches {}. After the \
             installs the learner followed the leader by log: {}. Result: **{}**.\n",
            run.rounds.len(),
            ns_f(s.median_baseline_p99_ns),
            ns_f(s.median_install_p99_ns),
            s.median_p99_ratio,
            s.worst_p99_ratio,
            ns(s.worst_install_p99_ns),
            ns(s.worst_install_max_ns),
            s.median_install_secs,
            s.median_index_rebuild_secs,
            s.empty_reads,
            s.mismatches,
            if run.replication_by_log_after_installs {
                "yes"
            } else {
                "no"
            },
            verdict(s.pass),
        );
        let lookups: u64 = run
            .rounds
            .iter()
            .map(|r| r.baseline.lookups + r.install.lookups)
            .sum();
        results.push(Summary {
            measurement: format!("M1 index swap, {} records", thousands(run.records)),
            threshold: threshold.to_owned(),
            measured: format!(
                "{} empty reads in {} lookups; p99 {} baseline vs {} during install ({:.2}x, \
                 median of {}; worst {:.2}x); install window {:.1} s",
                s.empty_reads,
                thousands(lookups),
                ns_f(s.median_baseline_p99_ns),
                ns_f(s.median_install_p99_ns),
                s.median_p99_ratio,
                run.rounds.len(),
                s.worst_p99_ratio,
                s.median_install_secs
            ),
            result: verdict(s.pass),
        });
    }
    for skipped in &report.skipped {
        let _ = writeln!(
            out,
            "### {} records\n\n{}\n",
            thousands(skipped.records),
            skipped.reason
        );
        results.push(Summary {
            measurement: format!("M1 index swap, {} records", thousands(skipped.records)),
            threshold: threshold.to_owned(),
            measured: format!("not measured: {}", skipped.reason),
            result: "-".to_owned(),
        });
    }
    summary.extend(results);
    out.push_str(&observations(dir, notes_name));
    out
}

// ---------------------------------------------------------------------------------------------
// M2
// ---------------------------------------------------------------------------------------------

fn m2_section(report: Option<&m2::Report>, dir: &Path, summary: &mut Vec<Summary>) -> String {
    let threshold = "No lost commit or partial batch; the audit chain verifies";
    let mut out = String::from("## M2: crash and restart\n\n");
    let Some(report) = report else {
        out.push_str("Not run.\n");
        summary.push(Summary {
            measurement: "M2 crash and restart".to_owned(),
            threshold: threshold.to_owned(),
            measured: "not measured: not run".to_owned(),
            result: "-".to_owned(),
        });
        return out;
    };
    out.push_str(
        "**Method.** The benchmark binary starts itself in a hidden child mode that opens a \
         store in a data directory and writes batches under `bulk` or `steady` load. Every batch \
         writes `m` rows, one manifest row that states `m`, bumps a counter and carries one \
         audit draft. After `propose` returns, the child appends the batch id, the revision and \
         `m` to `acks.log`. The parent kills the child at a random point with `Child::kill` \
         (`TerminateProcess`), reopens the store with `verify_full_audit_chain: true`, times \
         the open, verifies the invariants below over the whole store (not only the last run), \
         shuts the store down cleanly and starts the next child. Each sequence reuses one data \
         directory, so the store grows over its kills.\n\n",
    );
    out.push_str("Invariants checked after every restart:\n\n");
    for invariant in &report.config.invariants {
        let _ = writeln!(out, "- {invariant}");
    }
    let _ = writeln!(
        out,
        "\n**Configuration.** Bulk: {}. Steady: {}. Kills: {} Snapshot policy: {}. Journal \
         retention: {} change sets. Parent: {}. Deferred durability uses a 1 s checkpoint \
         interval.\n",
        report.config.bulk,
        report.config.steady,
        report.config.kill_window,
        report.config.snapshot_policy,
        thousands(report.config.journal_retention as u64),
        report.config.parent_open,
    );
    let rows: Vec<Vec<String>> = report
        .sequences
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                format!("{} ({} before ready)", s.kills, s.kills_before_ready),
                s.violations.to_string(),
                format!(
                    "{} / {} / {}",
                    ns(s.restart.p50_ns),
                    ns(s.restart.p99_ns),
                    ns(s.restart.max_ns)
                ),
                thousands(s.final_revision),
                thousands(s.acked_total),
                thousands(s.final_revision.saturating_sub(s.acked_total)),
                thousands(s.rows_total),
                thousands(s.audit_records),
                format!("{} of {}", s.restarts_with_purged_log, s.iterations.len()),
                format!("{:.0} s", s.elapsed_secs),
            ]
        })
        .collect();
    out.push_str(&table(
        &[
            "Sequence",
            "Kills",
            "Violations",
            "Restart p50 / p99 / max",
            "Final revision",
            "Acknowledged batches",
            "Committed but never acknowledged (revision minus acknowledged)",
            "Rows at the end",
            "Audit records at the end",
            "Restarts after a log purge",
            "Time",
        ],
        &rows,
    ));
    let _ = writeln!(
        out,
        "\nAll sequences: {} kills, {} violations. Restart p50 {} / p99 {} / max {} over the \
         kills of the four main sequences (a recovery sequence, if present, is in the table \
         only). Result: **{}**.\n",
        report.kills,
        report.violations,
        ns(report.restart_all.p50_ns),
        ns(report.restart_all.p99_ns),
        ns(report.restart_all.max_ns),
        verdict(report.pass),
    );
    out.push_str(
        "Restart time as each store grows (open time includes the full audit verification):\n\n",
    );
    let mut rows = Vec::new();
    for s in &report.sequences {
        let picks = [
            0,
            s.iterations.len() / 2,
            s.iterations.len().saturating_sub(1),
        ];
        let mut seen = Vec::new();
        for pick in picks {
            if seen.contains(&pick) {
                continue;
            }
            seen.push(pick);
            if let Some(it) = s.iterations.get(pick) {
                rows.push(vec![
                    s.name.clone(),
                    it.run.to_string(),
                    thousands(it.checked.revision),
                    thousands(it.checked.rows),
                    thousands(it.checked.audit_records),
                    thousands(it.checked.journal_len),
                    format!("{:.0} ms", it.open_ms),
                    format!("{:.0} ms", it.checked.verify_ms),
                ]);
            }
        }
    }
    out.push_str(&table(
        &[
            "Sequence",
            "Kill no.",
            "Revision",
            "Rows",
            "Audit records",
            "Journal change sets",
            "Open",
            "Verification",
        ],
        &rows,
    ));
    let samples: Vec<&String> = report
        .sequences
        .iter()
        .flat_map(|s| s.violation_samples.iter())
        .take(20)
        .collect();
    if !samples.is_empty() {
        out.push_str("\nViolations recorded (first 20):\n\n");
        for sample in samples {
            let _ = writeln!(out, "- {sample}");
        }
    }
    out.push_str(
        "\n**Not measured: the VM power cut.** A process kill cannot lose data that was already \
         handed to the operating system, so it does not exercise unsynced writes. The power cut \
         needs a virtual machine whose power can be cut and belongs to the Slice 3 run.\n",
    );
    out.push_str(&observations(dir, "m2"));

    let deferred: Vec<&m2::SequenceResult> = report
        .sequences
        .iter()
        .filter(|s| s.durability == "deferred" && !s.name.starts_with("recovery"))
        .collect();
    let recovery: Vec<&m2::SequenceResult> = report
        .sequences
        .iter()
        .filter(|s| s.name.starts_with("recovery"))
        .collect();
    let immediate: Vec<&m2::SequenceResult> = report
        .sequences
        .iter()
        .filter(|s| s.durability == "immediate")
        .collect();
    let describe = |list: &[&m2::SequenceResult]| {
        let kills: usize = list.iter().map(|s| s.kills).sum();
        let violations: usize = list.iter().map(|s| s.violations).sum();
        let acked: u64 = list.iter().map(|s| s.acked_total).sum();
        (kills, violations, acked, violations == 0 && kills > 0)
    };
    for (label, list) in [
        ("deferred durability", &deferred),
        ("immediate durability", &immediate),
        ("kills during recovery, deferred durability", &recovery),
    ] {
        if list.is_empty() {
            continue;
        }
        let (kills, violations, acked, pass) = describe(list);
        let restarts = list
            .iter()
            .map(|s| {
                format!(
                    "{} p50 {} / p99 {} / max {}",
                    s.mode_label(),
                    ns(s.restart.p50_ns),
                    ns(s.restart.p99_ns),
                    ns(s.restart.max_ns)
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        summary.push(Summary {
            measurement: format!("M2 crash and restart, {label}"),
            threshold: threshold.to_owned(),
            measured: format!(
                "{kills} kills ({}), {violations} violations over {} acknowledged batches; \
                 restart {}",
                list.iter()
                    .map(|s| format!("{} {}", s.kills, s.mode_label()))
                    .collect::<Vec<_>>()
                    .join(", "),
                thousands(acked),
                restarts,
            ),
            result: verdict(pass),
        });
    }
    summary.push(Summary {
        measurement: "M2 VM power cut".to_owned(),
        threshold: threshold.to_owned(),
        measured: "not measured: needs a VM power cut; belongs to the Slice 3 run".to_owned(),
        result: "-".to_owned(),
    });
    out
}

impl m2::SequenceResult {
    fn mode_label(&self) -> &'static str {
        match self.mode {
            m2::Mode::Bulk => "bulk",
            m2::Mode::Steady => "steady",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// M5
// ---------------------------------------------------------------------------------------------

fn m5_section(
    report: Option<&m5::Report>,
    sensitivity: &[m5::Report],
    dir: &Path,
    summary: &mut Vec<Summary>,
) -> String {
    let threshold = "At least 1,000 updates/s sustained, zero errors";
    let mut out = String::from("## M5: coalescer ceiling\n\n");
    let Some(report) = report else {
        out.push_str("Not run.\n");
        summary.push(Summary {
            measurement: "M5 coalescer ceiling".to_owned(),
            threshold: threshold.to_owned(),
            measured: "not measured: not run".to_owned(),
            result: "-".to_owned(),
        });
        return out;
    };
    let config = &report.config;
    out.push_str(
        "**Method.** A single-voter store is preloaded with 1,000,000 records. Open-loop writers \
         offer single-record updates at 1,000, 2,000 and 5,000 per second for 30 s each. A \
         dedicated thread issues, every millisecond, the number of proposals that are due, each \
         as its own task, so a late timer tick delays proposals but never lowers the offered \
         rate. An update is a `WriteBatch` with one `put` of a 128-byte value under a 22-byte \
         key (150 bytes) of a random existing record and one audit draft, as a DNS update would \
         be. Latency is measured from just before `propose` to its return and includes queueing \
         in the coalescer. Achieved updates/s counts proposals that returned before the end of \
         the 30 s window. After the open-loop windows, 256 writers each propose in a closed \
         loop for 20 s (the maximum). Entries, batches and log commits are `engine_stats()` \
         deltas over each window including the drain. The whole sequence runs once with \
         `SmDurability::Deferred` (the default) and once with `SmDurability::Immediate`. PASS \
         when the 1,000/s level is sustained (at least 99 percent of the offered rate returned \
         within the window) with zero errors.\n\n",
    );
    let _ = writeln!(
        out,
        "**Configuration.** Coalescer: at most {} batches and {} MiB per entry, {} entries in \
         flight; `sm_cache_bytes` {} MiB, `log_cache_bytes` {} MiB; snapshots: {}; deferred \
         checkpoint interval {} ms; update: {}.\n",
        thousands(config.coalescer_max_batches_per_entry as u64),
        config.coalescer_max_entry_bytes / (1 << 20),
        config.coalescer_max_inflight_entries,
        config.sm_cache_bytes / (1 << 20),
        config.log_cache_bytes / (1 << 20),
        config.snapshot_policy,
        config.checkpoint_ms(),
        config.update,
    );
    for run in &report.runs {
        let _ = writeln!(
            out,
            "### {} durability ({} records preloaded in {:.1} s)\n",
            run.durability,
            thousands(run.preload_records),
            run.preload_secs
        );
        let rows: Vec<Vec<String>> = run
            .levels
            .iter()
            .map(|l| {
                vec![
                    l.offered_per_s.map_or_else(
                        || format!("closed, {} writers", l.writers.unwrap_or(0)),
                        |rate| format!("open, {}/s", thousands(rate)),
                    ),
                    thousands(l.issued),
                    thousands(l.completed_in_window),
                    format!("{:.1}", l.achieved_per_s),
                    l.errors.to_string(),
                    ns(l.latency.p50_ns),
                    ns(l.latency.p99_ns),
                    ns(l.latency.p999_ns),
                    ns(l.latency.max_ns),
                    thousands(l.backlog_at_window_end),
                    format!("{:.1} s", l.drain_secs),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "Load",
                "Issued",
                "Returned within window",
                "Achieved /s",
                "Errors",
                "Latency p50",
                "p99",
                "p99.9",
                "max",
                "Outstanding at window end",
                "Drain",
            ],
            &rows,
        ));
        out.push('\n');
        let rows: Vec<Vec<String>> = run
            .levels
            .iter()
            .map(|l| {
                vec![
                    l.offered_per_s.map_or_else(
                        || format!("closed, {} writers", l.writers.unwrap_or(0)),
                        |rate| format!("open, {}/s", thousands(rate)),
                    ),
                    thousands(l.entries),
                    thousands(l.batches),
                    format!("{:.1}", l.batches_per_entry),
                    thousands(l.log_commits),
                    mib(l.log_appended_bytes),
                    l.checkpoints.to_string(),
                    l.snapshots_built.to_string(),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "Load",
                "Raft entries",
                "Batches",
                "Batches per entry",
                "Log commits (fsync)",
                "Log appended",
                "Checkpoints",
                "Snapshots built",
            ],
            &rows,
        ));
        let one_k = run.levels.iter().find(|l| l.offered_per_s == Some(1_000));
        let closed = run.levels.iter().find(|l| l.writers.is_some());
        let _ = writeln!(
            out,
            "\nSustained 1,000/s with zero errors: **{}**. Closed-loop maximum: {}.\n",
            verdict(run.pass),
            closed.map_or_else(
                || "not run".to_owned(),
                |l| format!(
                    "{:.0} updates/s with {} writers",
                    l.achieved_per_s,
                    l.writers.unwrap_or(0)
                )
            ),
        );
        if let (Some(one_k), Some(closed)) = (one_k, closed) {
            summary.push(Summary {
                measurement: format!("M5 coalescer ceiling, {} durability", run.durability),
                threshold: threshold.to_owned(),
                measured: format!(
                    "1,000/s offered: {:.0}/s achieved, {} errors, p50 {}, p99 {}, {:.1} \
                     batches per entry; closed loop ({} writers): {:.0}/s, p99 {}",
                    one_k.achieved_per_s,
                    one_k.errors,
                    ns(one_k.latency.p50_ns),
                    ns(one_k.latency.p99_ns),
                    one_k.batches_per_entry,
                    closed.writers.unwrap_or(0),
                    closed.achieved_per_s,
                    ns(closed.latency.p99_ns),
                ),
                result: verdict(run.pass),
            });
        }
    }
    out.push_str(&m5_sensitivity(report, sensitivity));
    out.push_str(&observations(dir, "m5"));
    out
}

// ---------------------------------------------------------------------------------------------
// M6
// ---------------------------------------------------------------------------------------------

fn m6_section(reports: &[&m6::Report], dir: &Path, summary: &mut Vec<Summary>) -> String {
    let threshold = "`sm.redb` below 2x raw after re-seed";
    let mut out = String::from("## M6: disk growth after re-seed\n\n");
    let Some(first) = reports.first() else {
        out.push_str("Not run.\n");
        summary.push(Summary {
            measurement: "M6 disk growth after re-seed".to_owned(),
            threshold: threshold.to_owned(),
            measured: "not measured: not run".to_owned(),
            result: "-".to_owned(),
        });
        return out;
    };
    let config = &first.config;
    let _ = writeln!(
        out,
        "**Method.** A leader is loaded with N records in batches of 10,000, then runs a \
         compressed week: seven rounds, each updating a random 10 percent of the records, \
         deleting 1 percent and inserting 1 percent new ones, in batches of 10,000 mutations. \
         After the load and after every round the sizes are recorded. Raw is defined two ways: \
         *all tables* is `status().data_bytes`, the live keys plus values of every table \
         including the journal, audit records, counters and idempotency records; *user table* \
         is the keys plus values of the data table itself, counted by a full scan. After the \
         last round the leader takes a final snapshot. A fresh learner is then added; the \
         leader's log has been purged past the start, so the learner catches up by snapshot \
         install, which writes `sm.redb` in key order in one transaction. The learner's \
         `sm.redb` is compared with raw. File sizes are the lengths of `sm.redb` and `log.redb` \
         and the total size of the `snapshots` directory while the stores run; sizes after a \
         clean shutdown, and redb's own accounting of the closed files (read with redb 4.3.0), \
         follow. The measurement ran {} times; each heading names the record count and the journal \
         retention. The runs with the default journal retention measure the store as built; the \
         runs with a retention of 20 change sets and the offline `compact()` tables measure the \
         two levers discussed under Observations, and their verdicts in the summary are marked \
         as non-default settings.\n",
        reports.len()
    );
    let _ = writeln!(
        out,
        "**Configuration.** {} rounds of {} percent updates, {} percent deletes, {} percent \
         inserts; batches of {} mutations; `sm_cache_bytes` {} MiB, `log_cache_bytes` {} MiB; \
         durability: {}; snapshots: {}.\n",
        config.rounds,
        config.update_percent,
        config.delete_percent,
        config.insert_percent,
        thousands(config.batch_records as u64),
        config.sm_cache_bytes / (1 << 20),
        config.log_cache_bytes / (1 << 20),
        config.durability,
        config.snapshot_policy,
    );
    for report in reports {
        out.push_str(&m6_block(report, threshold, summary));
    }
    out.push_str(&observations(dir, "m6"));
    out
}

fn m6_block(report: &m6::Report, threshold: &str, summary: &mut Vec<Summary>) -> String {
    let config = &report.config;
    let retention = thousands(config.journal_retention as u64);
    let retention_note = if config.journal_retention == m6::default_journal_retention() {
        format!("journal retention {retention} change sets (the default)")
    } else {
        format!("journal retention {retention} change sets")
    };
    let retention_note = if config.journal_max_bytes > 0 {
        format!(
            "{retention_note}, journal limit {}",
            mib(config.journal_max_bytes)
        )
    } else {
        retention_note
    };
    let leader_label = if report.leader_reseed.is_some() {
        "leader (after the week and an in-place re-seed)"
    } else {
        "leader (after the week)"
    };
    let mut out = format!(
        "### {} records, {retention_note}\n\n",
        thousands(config.records)
    );
    let mut rows: Vec<Vec<String>> = report
        .points
        .iter()
        .map(|p| {
            vec![
                p.label.clone(),
                thousands(p.live_records),
                mib(p.data_bytes),
                mib(p.user_bytes),
                mib(p.sizes.sm_redb),
                format!("{:.2}x", p.sm_over_data),
                format!("{:.2}x", p.sm_over_user),
                mib(p.sizes.log_redb),
                mib(p.sizes.snapshots),
                p.snapshots_built.to_string(),
                thousands(p.purged_index),
                thousands(p.entries_proposed),
            ]
        })
        .collect();
    let after = &report.reseed.point;
    rows.push(vec![
        format!("{} [node 2]", after.label),
        thousands(after.live_records),
        mib(after.data_bytes),
        mib(after.user_bytes),
        mib(after.sizes.sm_redb),
        format!("{:.2}x", after.sm_over_data),
        format!("{:.2}x", after.sm_over_user),
        mib(after.sizes.log_redb),
        mib(after.sizes.snapshots),
        after.snapshots_built.to_string(),
        thousands(after.purged_index),
        thousands(after.entries_proposed),
    ]);
    out.push_str(&table(
        &[
            "Point",
            "Live records",
            "Raw, all tables",
            "Raw, user table",
            "sm.redb",
            "sm.redb / all tables",
            "sm.redb / user table",
            "log.redb",
            "snapshots",
            "Snapshots built",
            "Log purged up to",
            "Entries proposed",
        ],
        &rows,
    ));
    let rest = &report.at_rest;
    let _ = writeln!(
        out,
        "\nRe-seed: the learner was seeded by snapshot install: {}{}; catch-up {:.1} s, install \
         {:.2} s; same revision as the leader: {}; same `data_bytes`: {}.\n",
        yes_no(report.reseed.installed_by_snapshot),
        if report.reseed.fallback_push_used {
            " (pushed explicitly through the snapshot receiver)"
        } else {
            " (by openraft, because the leader had purged its log)"
        },
        report.reseed.catch_up_secs,
        report.reseed.install_secs,
        yes_no(report.reseed.revisions_equal),
        yes_no(report.reseed.data_bytes_equal),
    );
    if let Some(r) = &report.leader_reseed {
        let _ = writeln!(
            out,
            "In-place re-seed of the leader after the week (`RaftStore::reseed_in_place`, \
             the single-node path): state file {} -> {} in {:.1} s, writes waiting meanwhile; \
             {:.2}x all tables, {:.2}x user table.\n",
            mib(r.bytes_before),
            mib(r.bytes_after),
            r.secs,
            r.over_data,
            r.over_user,
        );
    }
    out.push_str("After a clean shutdown of both nodes (files at rest):\n\n");
    out.push_str(&table(
        &[
            "Node",
            "sm.redb",
            "log.redb",
            "snapshots",
            "sm.redb / all tables",
            "sm.redb / user table",
        ],
        &[
            vec![
                leader_label.to_owned(),
                mib(rest.leader.sm_redb),
                mib(rest.leader.log_redb),
                mib(rest.leader.snapshots),
                format!("{:.2}x", rest.leader_sm_over_data),
                format!("{:.2}x", rest.leader_sm_over_user),
            ],
            vec![
                "learner (re-seeded)".to_owned(),
                mib(rest.learner.sm_redb),
                mib(rest.learner.log_redb),
                mib(rest.learner.snapshots),
                format!("{:.2}x", rest.learner_sm_over_data),
                format!("{:.2}x", rest.learner_sm_over_user),
            ],
        ],
    ));
    let stats: Vec<Vec<String>> = [
        (leader_label, &rest.leader_redb),
        ("learner (re-seeded)", &rest.learner_redb),
    ]
    .into_iter()
    .filter_map(|(name, stats)| {
        stats.as_ref().map(|s| {
            vec![
                name.to_owned(),
                mib(s.file_bytes),
                mib(s.allocated_bytes),
                mib(s.stored_bytes),
                mib(s.metadata_bytes),
                mib(s.fragmented_bytes),
                format!(
                    "{} / {}",
                    thousands(s.leaf_pages),
                    thousands(s.branch_pages)
                ),
                format!("{} KiB, height {}", s.page_size / 1024, s.tree_height),
            ]
        })
    })
    .collect();
    let per_table: Vec<Vec<String>> = [
        ("leader", &rest.leader_redb),
        ("learner", &rest.learner_redb),
    ]
    .into_iter()
    .filter_map(|(node, stats)| stats.as_ref().map(|s| (node, s)))
    .flat_map(|(node, s)| {
        s.tables.iter().map(move |t| {
            vec![
                node.to_owned(),
                format!("`{}`", t.name),
                thousands(t.rows),
                mib(t.stored_bytes),
                mib((t.leaf_pages + t.branch_pages) * s.page_size),
                format!(
                    "{} / {}",
                    thousands(t.leaf_pages),
                    thousands(t.branch_pages)
                ),
                mib(t.metadata_bytes),
                mib(t.fragmented_bytes),
            ]
        })
    })
    .collect();
    if !stats.is_empty() {
        out.push_str("\nredb's accounting of the closed `sm.redb` files:\n\n");
        out.push_str(&table(
            &[
                "Node",
                "File length",
                "Allocated pages x page size",
                "Stored key + value bytes",
                "Metadata bytes",
                "Fragmented (free pages + unused page space)",
                "Leaf / branch pages",
                "Page size, tree",
            ],
            &stats,
        ));
    }
    let compacted: Vec<Vec<String>> = [
        (leader_label, &rest.leader_compacted),
        ("learner (re-seeded)", &rest.learner_compacted),
    ]
    .into_iter()
    .filter_map(|(name, c)| {
        c.as_ref().map(|c| {
            vec![
                name.to_owned(),
                mib(c.file_bytes_before),
                mib(c.file_bytes_after),
                format!("{:.1} s", c.secs),
                format!("{:.2}x", c.over_data),
                format!("{:.2}x", c.over_user),
            ]
        })
    })
    .collect();
    if !per_table.is_empty() {
        out.push_str("\nThe same accounting per table (largest first):\n\n");
        out.push_str(&table(
            &[
                "Node",
                "Table",
                "Rows",
                "Stored key + value bytes",
                "Pages x page size",
                "Leaf / branch pages",
                "Metadata bytes",
                "Unused space in pages",
            ],
            &per_table,
        ));
    }
    if !compacted.is_empty() {
        out.push_str(if config.journal_max_bytes > 0 {
            "\nThe closed files after an offline `redb::Database::compact()` (run by the benchmark \
             after the measurement above; since WP1.1b the store compacts every fresh state \
             file itself):\n\n"
        } else {
            "\nThe closed files after an offline `redb::Database::compact()` (run by the benchmark \
             after the measurement above; not something the store did at the time):\n\n"
        });
        out.push_str(&table(
            &[
                "Node",
                "sm.redb before",
                "sm.redb after compact()",
                "Duration",
                "After / all tables",
                "After / user table",
            ],
            &compacted,
        ));
    }
    let _ = writeln!(
        out,
        "\n`sm.redb` over raw before the re-seed: {:.2}x (all tables), {:.2}x (user table). After \
         the re-seed: {:.2}x (all tables), {:.2}x (user table). Result: **{}** (PASS needs both \
         figures below 2x).\n",
        report.ratio_before_reseed_data,
        report.ratio_before_reseed_user,
        report.ratio_after_reseed_data,
        report.ratio_after_reseed_user,
        verdict(report.pass),
    );
    summary.push(Summary {
        measurement: format!(
            "M6 disk growth after re-seed ({} records, {} rounds, {})",
            thousands(config.records),
            config.rounds,
            retention_note
        ),
        threshold: threshold.to_owned(),
        measured: format!(
            "sm.redb / raw after re-seed {:.2}x (all tables), {:.2}x (user table) while \
             running, {:.2}x and {:.2}x at rest after a clean shutdown; before re-seed {:.2}x \
             and {:.2}x",
            report.ratio_after_reseed_data,
            report.ratio_after_reseed_user,
            report.at_rest.learner_sm_over_data,
            report.at_rest.learner_sm_over_user,
            report.ratio_before_reseed_data,
            report.ratio_before_reseed_user,
        ),
        result: if config.journal_retention == m6::default_journal_retention() {
            verdict(report.pass)
        } else {
            format!("{} (non-default setting)", verdict(report.pass))
        },
    });
    out
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

// ---------------------------------------------------------------------------------------------
// After WP1.1b
// ---------------------------------------------------------------------------------------------

/// Moves every Markdown heading one level down.
fn demote(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.starts_with('#') {
                format!("#{line}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn after_section(
    m1: Option<&m1::Report>,
    m6: &[&m6::Report],
    dir: &Path,
    summary: &mut Vec<Summary>,
) -> String {
    if m1.is_none() && m6.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "## After WP1.1b: fresh state file on install, byte-bounded journal\n\n\
         The sections above measure the store as first built. WP1.1b then changed two things \
         the M6 observations recommended, and the measurements below were repeated with the \
         changed store and its defaults: a snapshot install (and the new in-place re-seed, \
         `RaftStore::reseed_in_place`) writes the state into a fresh file, compacts it while it \
         is private and switches to it through the pointer file `sm.current`, instead of \
         rewriting the live `sm.redb`; and the journal is bounded by bytes (default 32 MiB) as \
         well as by its change-set count, with the limit carried in every Raft entry. The \
         method and configuration of each measurement are unchanged otherwise. The earlier \
         figures stay above for comparison.\n\n",
    );
    let start = summary.len();
    if !m6.is_empty() {
        out.push_str("### M6 after WP1.1b\n\n");
        let threshold = "`sm.redb` below 2x raw after re-seed";
        for report in m6 {
            out.push_str(&demote(&m6_block(report, threshold, summary)));
            out.push('\n');
        }
    }
    if let Some(m1) = m1 {
        out.push_str(&demote(&m1_section(Some(m1), dir, "m1-after", summary)));
        out.push('\n');
    }
    for row in &mut summary[start..] {
        row.measurement.push_str(" (after WP1.1b)");
    }
    out.push_str(&observations(dir, "after"));
    out
}

// ---------------------------------------------------------------------------------------------
// M10
// ---------------------------------------------------------------------------------------------

fn m10_section(
    report: Option<&m10::Report>,
    first: Option<&m10::Report>,
    dir: &Path,
    summary: &mut Vec<Summary>,
) -> String {
    let threshold = "Warns on SMR, silent on NVMe";
    let mut out = String::from("## M10: fsync probe\n\n");
    let Some(report) = report else {
        out.push_str("Not run.\n");
        summary.push(Summary {
            measurement: "M10 fsync probe".to_owned(),
            threshold: threshold.to_owned(),
            measured: "not measured: not run".to_owned(),
            result: "-".to_owned(),
        });
        return out;
    };
    let _ = writeln!(
        out,
        "**Method.** `tenko_store::raft::fsync::fsync_probe(dir, {})` ran {} times in a \
         temporary directory on each drive: one under the data root on `C:` and one created, \
         probed and removed on `D:` (the only write the benchmarks make on `D:`). The store's \
         own start-up entry point, `probe_and_report`, ran once per drive with {} commits under \
         a `tracing` subscriber that captured what it logged. The threshold is a p50 above {:.0} \
         ms (`FSYNC_WARN_P50`); `is_slow()` compares against it.\n",
        report.drives[0].runs.first().map_or(0, |r| r.samples),
        report.drives[0].runs.len(),
        report.startup_samples,
        report.threshold_p50_ms,
    );
    let mut sets = vec![("final run", report)];
    if let Some(first) = first {
        sets.insert(0, ("first run, earlier the same day", first));
    }
    for (label, set) in &sets {
        let _ = writeln!(out, "### Probe results ({label})\n");
        let mut rows = Vec::new();
        for drive in &set.drives {
            for (index, run) in drive.runs.iter().enumerate() {
                rows.push(vec![
                    drive.label.clone(),
                    (index + 1).to_string(),
                    format!("{:.2} ms", run.p50_ms),
                    format!("{:.2} ms", run.p99_ms),
                    format!("{:.2} ms", run.max_ms),
                    run.is_slow.to_string(),
                ]);
            }
        }
        out.push_str(&table(
            &["Drive", "Run", "p50", "p99", "max", "is_slow()"],
            &rows,
        ));
        out.push('\n');
        for drive in &set.drives {
            let _ = writeln!(
                out,
                "- Start-up probe on {} ({}): {}",
                drive.label,
                if drive.startup_warned {
                    "logged a warning"
                } else {
                    "no warning"
                },
                drive
                    .startup_log
                    .first()
                    .map_or("no log line", String::as_str),
            );
        }
        out.push('\n');
    }
    out.push_str("### Identifying the drives\n\n");
    out.push_str(
        "`Get-PhysicalDisk | Select DeviceId,FriendlyName,MediaType,BusType,Size` (the \
         requested command with `DeviceId` added so that a disk number can be matched):\n\n",
    );
    out.push_str(&code_block(&report.get_physical_disk));
    out.push_str("\n`Get-Partition | Select DriveLetter,DiskNumber`:\n\n");
    out.push_str(&code_block(&report.get_partition));
    out.push_str("\n`Get-Volume` (drive letters with a volume):\n\n");
    out.push_str(&code_block(&report.get_volume));
    let _ = writeln!(
        out,
        "\nSo `C:` is disk 1, the Samsung SSD 960 EVO 1TB (NVMe), and `D:` is disk 0, the \
         ST4000DM004-2CV104 (a 4 TB SATA hard disk; Spike A identified it as SMR).\n"
    );
    out.push_str(&observations(dir, "m10"));
    for drive in &report.drives {
        let worst = drive.runs.iter().map(|r| r.p50_ms).fold(0.0_f64, f64::max);
        let best = drive.runs.iter().map(|r| r.p50_ms).fold(f64::MAX, f64::min);
        let all_slow = drive.runs.iter().all(|r| r.is_slow);
        let any_slow = drive.runs.iter().any(|r| r.is_slow);
        let silent_needed = drive.label.starts_with("C:");
        let ok = if silent_needed {
            !any_slow && !drive.startup_warned
        } else {
            all_slow && drive.startup_warned
        };
        summary.push(Summary {
            measurement: format!("M10 fsync probe, {}", drive.label),
            threshold: threshold.to_owned(),
            measured: format!(
                "p50 {best:.2} to {worst:.2} ms over {} runs of {} commits (p99 up to {:.1} ms); \
                 is_slow {}; start-up probe {}",
                drive.runs.len(),
                drive.runs.first().map_or(0, |r| r.samples),
                drive.runs.iter().map(|r| r.p99_ms).fold(0.0_f64, f64::max),
                if all_slow {
                    "true in every run"
                } else if any_slow {
                    "true in some runs"
                } else {
                    "false in every run"
                },
                if drive.startup_warned {
                    "warned"
                } else {
                    "silent (info only)"
                },
            ),
            result: verdict(ok),
        });
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------------------------

struct RunRow {
    name: String,
    meta: RunMeta,
}

fn provenance(machine: Option<&Machine>, runs: &[RunRow], dir: &Path) -> String {
    let mut out = String::from("## How these numbers were produced\n\n");
    if let Some(machine) = machine {
        out.push_str(&table(
            &["Item", "Value"],
            &[
                vec!["CPU".to_owned(), format!("{}, {} logical CPUs", machine.cpu, machine.logical_cpus)],
                vec!["RAM".to_owned(), gib(machine.ram_bytes)],
                vec!["OS".to_owned(), format!("{} (build {})", machine.os, machine.kernel)],
                vec!["Toolchain".to_owned(), machine.rustc.clone()],
                vec![
                    "Crates".to_owned(),
                    "openraft 0.9.25, redb 4.3.0 (from `Cargo.lock`), the store at `crates/tenko-store` \
                     with features `raft` and `testing`"
                        .to_owned(),
                ],
                vec![
                    "Data drive".to_owned(),
                    "`C:`, Samsung SSD 960 EVO 1TB (NVMe); every data directory was created \
                     under `%TEMP%\\tenko-phase1-bench` on it and removed afterwards"
                        .to_owned(),
                ],
                vec![
                    "Repository drive".to_owned(),
                    "`D:`, Seagate ST4000DM004 (SATA hard disk); the only write there was the \
                     M10 probe in a temporary directory, removed afterwards"
                        .to_owned(),
                ],
            ],
        ));
        out.push('\n');
    }
    let rows: Vec<Vec<String>> = runs
        .iter()
        .map(|run| {
            let meta = &run.meta;
            vec![
                run.name.clone(),
                meta.started.clone(),
                format!("{:.0} s", meta.elapsed_secs),
                format!(
                    "{:.0} / {:.0}",
                    meta.cpu_machine_mean_pct, meta.cpu_machine_max_pct
                ),
                format!("{:.1}", meta.cpu_self_mean_pct),
                meta.data_root_free_bytes_before
                    .map_or_else(|| "-".to_owned(), gib),
            ]
        })
        .collect();
    let total_secs: f64 = runs.iter().map(|run| run.meta.elapsed_secs).sum();
    out.push_str(
        "**The machine was shared.** Other builds and tests ran on this workstation during \
         every measurement. The table shows the CPU use of the whole machine (mean / maximum \
         over one-second samples, percent of all logical CPUs) and of the benchmark process \
         alone, and the free space on `C:` (the drive was nearly full, which may slow an NVMe \
         drive's writes). Microsecond-level latencies and fsync-bound rates are therefore \
         noisy, and a rerun can differ.\n\n",
    );
    out.push_str(&table(
        &[
            "Measurement",
            "Started (UTC)",
            "Duration",
            "Machine CPU mean / max %",
            "Benchmark CPU mean %",
            "Free on C: before",
        ],
        &rows,
    ));
    let _ = writeln!(
        out,
        "\nTotal measured time: {:.1} minutes (the sum of the durations above; the runs were \
         sequential and one at a time).\n",
        total_secs / 60.0
    );
    out.push_str(
        "**Commands** (the benchmark is built with `cargo build --release`; run from \
         `bench/phase1-store`, with the data directories under `%TEMP%` on `C:`):\n\n",
    );
    out.push_str(&code_block(
        "export PATH=\"/c/Users/plm/.cargo/bin:$PATH\"; export CARGO_TARGET_DIR=F:/cargo-target-wp11-bench\n\
         cd /d/Development/DDI/bench/phase1-store\n\
         cargo build --release\n\
         phase1-store m10 && cp results/raw/m10.json results/raw/m10-first.json\n\
         phase1-store m1 --records 1000000,6000000\n\
         phase1-store m5\n\
         phase1-store m6\n\
         phase1-store m2\n\
         phase1-store m6 --records 1500000 --out-name m6-1500k\n\
         phase1-store m6 --journal-retention 20 --out-name m6-journal-20\n\
         phase1-store m6 --records 1500000 --journal-retention 20 --out-name m6-1500k-journal-20\n\
         phase1-store m5 --durability deferred --rates 1000 --closed-secs 0 --checkpoint-ms 250 --out-name m5-ckpt-250\n\
         phase1-store m5 --durability deferred --rates 1000 --closed-secs 0 --checkpoint-ms 10000 --out-name m5-ckpt-10000\n\
         phase1-store m2 --bulk-kills 0 --steady-kills 0 --immediate-bulk-kills 0 --immediate-steady-kills 0 --recovery-kills 40 --out-name m2-recovery\n\
         phase1-store m10\n\
         # After WP1.1b (fresh state file on install, byte-bounded journal):\n\
         phase1-store m6 --out-name m6-wp11b\n\
         phase1-store m6 --records 1500000 --out-name m6-1500k-wp11b\n\
         phase1-store m1 --records 1000000,6000000 --out-name m1-wp11b\n\
         phase1-store report",
    ));
    out.push_str(
        "\nThe defaults of each subcommand are the configuration shown in its section \
         (`phase1-store <subcommand> --help` lists them). Raw results are in \
         `results/raw/*.json`, console logs in `results/logs/`, and the hand-written \
         observations in `results/notes/`; `phase1-store report` writes this document from them.\n\n",
    );
    let extra = notes(dir, "provenance");
    if !extra.is_empty() {
        out.push_str(&extra);
        out.push('\n');
    }
    out
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let dir = ctx.out.dir.clone();
    let m1: Option<m1::Report> = ctx.out.read("m1")?;
    let mut runs: Vec<RunRow> = Vec::new();
    let mut m2: Option<m2::Report> = ctx.out.read("m2")?;
    let m2_recovery: Option<m2::Report> = ctx.out.read("m2-recovery")?;
    if let Some(recovery) = &m2_recovery {
        runs.push(RunRow {
            name: "M2 recovery sequence (40 kills)".to_owned(),
            meta: recovery.meta.clone(),
        });
    }
    if let (Some(main), Some(recovery)) = (m2.as_mut(), m2_recovery) {
        main.kills += recovery.kills;
        main.violations += recovery.violations;
        main.pass = main.pass && recovery.pass;
        main.sequences.extend(recovery.sequences);
    }
    let m5: Option<m5::Report> = ctx.out.read("m5")?;
    let mut m6_all: Vec<m6::Report> = Vec::new();
    for name in ["m6", "m6-1500k", "m6-journal-20", "m6-1500k-journal-20"] {
        if let Some(report) = ctx.out.read::<m6::Report>(name)? {
            m6_all.push(report);
        }
    }
    let mut m5_sensitivity_runs: Vec<m5::Report> = Vec::new();
    for name in ["m5-ckpt-250", "m5-ckpt-10000"] {
        if let Some(report) = ctx.out.read::<m5::Report>(name)? {
            m5_sensitivity_runs.push(report);
        }
    }
    let m1_after: Option<m1::Report> = ctx.out.read("m1-wp11b")?;
    let mut m6_after: Vec<m6::Report> = Vec::new();
    for name in ["m6-wp11b", "m6-1500k-wp11b"] {
        if let Some(report) = ctx.out.read::<m6::Report>(name)? {
            m6_after.push(report);
        }
    }
    let m10: Option<m10::Report> = ctx.out.read("m10")?;
    let m10_first: Option<m10::Report> = ctx.out.read("m10-first")?;

    let mut summary = Vec::new();
    let sections = [
        m1_section(m1.as_ref(), &dir, "m1", &mut summary),
        m2_section(m2.as_ref(), &dir, &mut summary),
        m5_section(m5.as_ref(), &m5_sensitivity_runs, &dir, &mut summary),
        m6_section(&m6_all.iter().collect::<Vec<_>>(), &dir, &mut summary),
        m10_section(m10.as_ref(), m10_first.as_ref(), &dir, &mut summary),
        after_section(
            m1_after.as_ref(),
            &m6_after.iter().collect::<Vec<_>>(),
            &dir,
            &mut summary,
        ),
    ];
    // The summary is ordered by measurement number.
    let order = |text: &str| -> u32 {
        text.trim_start_matches('M')
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(99)
    };
    summary.sort_by_key(|row| order(&row.measurement));

    let machine = m1
        .as_ref()
        .map(|r| r.machine.clone())
        .or_else(|| m5.as_ref().map(|r| r.machine.clone()))
        .or_else(|| m10.as_ref().map(|r| r.machine.clone()));
    let mut add = |name: &str, meta: Option<RunMeta>| {
        if let Some(meta) = meta {
            runs.push(RunRow {
                name: name.to_owned(),
                meta,
            });
        }
    };
    add("M10 (final run)", m10.as_ref().map(|r| r.meta.clone()));
    add(
        "M10 (first run)",
        m10_first.as_ref().map(|r| r.meta.clone()),
    );
    add(
        "M1 (1,000,000 and 6,000,000 records)",
        m1.as_ref().map(|r| r.meta.clone()),
    );
    add(
        "M5 (both durability modes)",
        m5.as_ref().map(|r| r.meta.clone()),
    );
    for report in &m6_all {
        let retention = if report.config.journal_retention == m6::default_journal_retention() {
            String::new()
        } else {
            format!(
                ", journal retention {}",
                thousands(report.config.journal_retention as u64)
            )
        };
        add(
            &format!(
                "M6 ({} records{retention})",
                thousands(report.config.records)
            ),
            Some(report.meta.clone()),
        );
    }
    for (index, name) in [
        "M5 checkpoint interval 250 ms",
        "M5 checkpoint interval 10,000 ms",
    ]
    .iter()
    .enumerate()
    {
        add(name, m5_sensitivity_runs.get(index).map(|r| r.meta.clone()));
    }
    add("M2 (100 + 20 kills)", m2.as_ref().map(|r| r.meta.clone()));
    add(
        "M1 after WP1.1b (1,000,000 and 6,000,000 records)",
        m1_after.as_ref().map(|r| r.meta.clone()),
    );
    for report in &m6_after {
        add(
            &format!(
                "M6 after WP1.1b ({} records)",
                thousands(report.config.records)
            ),
            Some(report.meta.clone()),
        );
    }
    runs.sort_by(|a, b| a.meta.started.cmp(&b.meta.started));

    let mut doc = String::new();
    doc.push_str("# Phase 1 store results: openraft + redb, 2026-10-09 (Windows)\n\n");
    doc.push_str(
        "Measurements M1, M2, M5, M6 and M10 of the Phase 1 plan (section 8) on the new Raft \
         store, `tenko_store::raft::RaftStore`: openraft 0.9.25 over redb 4.3.0, built from \
         `crates/tenko-store`. The benchmark is the standalone package `bench/phase1-store`. \
         Every number below comes from a run of that package on this workstation; anything that \
         was not measured says so and gives the reason.\n\n",
    );
    doc.push_str("## Summary\n\n");
    let rows: Vec<Vec<String>> = summary
        .iter()
        .map(|row| {
            vec![
                row.measurement.clone(),
                row.threshold.clone(),
                row.measured.clone(),
                format!("**{}**", row.result),
            ]
        })
        .collect();
    doc.push_str(&table(
        &["Measurement", "Threshold", "Measured", "Result"],
        &rows,
    ));
    doc.push('\n');
    let headline = notes(&dir, "summary");
    if !headline.is_empty() {
        doc.push_str(&headline);
        doc.push_str("\n\n");
    }
    for section in sections {
        doc.push_str(&section);
        doc.push('\n');
    }
    doc.push_str(&provenance(machine.as_ref(), &runs, &dir));
    let path = dir.join(DOCUMENT);
    fs::write(&path, doc).with_context(|| format!("write {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

/// The latency tail at 1,000 updates/s for several checkpoint intervals of deferred durability.
fn m5_sensitivity(main: &m5::Report, others: &[m5::Report]) -> String {
    let mut rows = Vec::new();
    let mut push = |report: &m5::Report, label: String| {
        for run in report.runs.iter().filter(|r| r.durability == "deferred") {
            if let Some(level) = run.levels.iter().find(|l| l.offered_per_s == Some(1_000)) {
                rows.push(vec![
                    label.clone(),
                    format!("{:.0}", level.achieved_per_s),
                    level.errors.to_string(),
                    ns(level.latency.p50_ns),
                    ns(level.latency.p99_ns),
                    ns(level.latency.p999_ns),
                    ns(level.latency.max_ns),
                    format!("{:.1}", level.batches_per_entry),
                    level.checkpoints.to_string(),
                    level.snapshots_built.to_string(),
                ]);
            }
        }
    };
    for report in others {
        push(report, format!("{} ms", report.config.checkpoint_ms()));
    }
    push(
        main,
        format!("{} ms (default)", main.config.checkpoint_ms()),
    );
    if others.is_empty() {
        return String::new();
    }
    rows.sort_by_key(|row| row[0].split(' ').next().and_then(|n| n.parse::<u64>().ok()));
    let mut out = String::from(
        "\n### Checkpoint interval and the latency tail (deferred durability, 1,000/s)\n\n\
         The same 30 s open-loop window at 1,000 updates/s, repeated with other checkpoint \
         intervals of deferred durability (each run on a fresh store with 1,000,000 records \
         preloaded). A checkpoint is an empty durable commit that makes the non-durable \
         applies since the last one durable.\n\n",
    );
    out.push_str(&table(
        &[
            "Checkpoint interval",
            "Achieved /s",
            "Errors",
            "p50",
            "p99",
            "p99.9",
            "max",
            "Batches per entry",
            "Checkpoints in window",
            "Snapshots built",
        ],
        &rows,
    ));
    out
}
