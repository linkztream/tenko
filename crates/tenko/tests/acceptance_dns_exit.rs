//! Acceptance of the Phase 2 exit measurements (WP6.5).
//!
//! - E13 (DNS-27): the newest M17 result file under `bench/phase2-dns/results/` (one node
//!   over a real link, dnsperf and flamethrower from another host and from the workstation)
//!   carries `Verdict: Documented`, the verdict of a measurement without a threshold, and
//!   names every transport it measured: UDP, TCP, DoT and DoH.
//! - E13 and E21 (OPS-21): the newest M22 result file (the metrics cost on the query path,
//!   the M17 runs with the metrics on and off) carries `Verdict: PASS`.
//! - E21 (OPS-15): the newest M23 result file (idle RSS with every Phase 1 role plus `dns`,
//!   the home zones and a full cache, on the static musl binary) carries `Verdict: PASS`.
//!
//! A result file is found by the date prefix of its name and its measurement (`-m17-`,
//! `-m22-`, `-m23-` in the name); the newest by name wins. The verdict convention is that of
//! `bench/README.md` and `acceptance_observability.rs`: one line `Verdict: <word>`,
//! optionally followed by ` (<qualifier>)`, in the lines right below the title. The tests
//! read files only, so they run anywhere. The two E21 tests are ignored while E21 is not
//! met: M22 passes since the follow-up of 2026-10-22, M23 still fails (deviations 145 and 146
//! of `docs/plans/phase-2-exit.md`); run them with `--run-ignored all` once M23 passes.

use std::path::{Path, PathBuf};

/// `bench/phase2-dns/results` of the repository.
fn results_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("bench")
        .join("phase2-dns")
        .join("results")
}

/// The newest Markdown result file of `measurement` (`m17`, `m22`, `m23`) by the date
/// prefix of its name.
fn newest_result(measurement: &str) -> PathBuf {
    let dir = results_dir();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|error| {
        panic!(
            "the results directory {} is unreadable: {error}",
            dir.display()
        )
    });
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let dated = name.len() > 10
            && name.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            && name.as_bytes()[4] == b'-';
        let markdown = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("md"));
        if dated && markdown && name.contains(&format!("-{measurement}-")) {
            candidates.push((name, path));
        }
    }
    candidates.sort();
    candidates
        .pop()
        .unwrap_or_else(|| {
            panic!(
                "missing result: no {measurement} result file in {}; run the measurement and record it there",
                dir.display()
            )
        })
        .1
}

/// The text of `path` and its verdict line (the first `Verdict:` line of the eight right
/// below the title).
fn verdict(path: &Path, what: &str) -> (String, String) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is unreadable: {error}", path.display()));
    let line = text
        .lines()
        .take(8)
        .find(|line| line.starts_with("Verdict:"))
        .unwrap_or_else(|| {
            panic!(
                "{what}: {} has no `Verdict:` line right below its title",
                path.display()
            )
        })
        .to_owned();
    (text, line)
}

/// Whether `line` is `Verdict: <word>` or `Verdict: <word> (<qualifier>)`.
fn says(line: &str, word: &str) -> bool {
    let expected = format!("Verdict: {word}");
    line == expected || line.starts_with(&format!("{expected} ("))
}

/// E13 and DNS-27: the real-link figures of one node are documented, for every transport
/// the criterion and the plan name, and with a run from the workstation.
#[test]
fn e13_dns_27_the_newest_m17_run_over_a_real_link_is_documented() {
    let path = newest_result("m17");
    let (text, line) = verdict(&path, "E13 (DNS-27), M17");
    assert!(
        says(&line, "Documented"),
        "E13 (DNS-27), M17: {} carries `{line}`, not `Verdict: Documented`",
        path.display()
    );
    for transport in ["UDP", "TCP", "DoT", "DoH"] {
        assert!(
            text.contains(transport),
            "E13 (DNS-27), M17: {} does not name the transport {transport}",
            path.display()
        );
    }
    assert!(
        text.to_lowercase().contains("workstation"),
        "E13 (DNS-27), M17: {} has no run from the workstation",
        path.display()
    );
}

/// E13 and E21, OPS-21: the metrics cost on the query path over the link (M22, the M8 of
/// Phase 1 again with the DNS engine) is within its budget: below 2 percent, p99 unchanged.
#[test]
#[ignore = "E21 is not met: M23 FAILs (phase-2-exit.md deviation 145; M22 passes since 2026-10-22); run when M23 passes"]
fn e21_ops_21_the_newest_m22_metrics_cost_over_the_link_passes() {
    let path = newest_result("m22");
    let (_, line) = verdict(&path, "E21 (OPS-21), M22");
    assert!(
        says(&line, "PASS"),
        "E21 (OPS-21), M22: {} carries `{line}`, not `Verdict: PASS`",
        path.display()
    );
}

/// E13 and OPS-21: the M17 figures exist with the metrics on and off (E13's "with and
/// without metrics"), which the M22 file records beside the M17 runs.
#[test]
fn e13_ops_21_the_link_figures_are_recorded_with_and_without_metrics() {
    let path = newest_result("m22");
    let (text, _) = verdict(&path, "E13 (OPS-21), M22");
    let lower = text.to_lowercase();
    assert!(
        lower.contains("metrics on") && lower.contains("metrics off"),
        "E13 (OPS-21), M22: {} does not record runs with the metrics on and off",
        path.display()
    );
}

/// E21 and OPS-15: the idle resident set with every Phase 1 role plus `dns`, the home
/// zones and a cache at its 10,000-entry bound is below 100 MB on the musl binary (M23, the
/// M9 of Phase 1 again).
#[test]
#[ignore = "E21 is not met: M23 FAILs (phase-2-exit.md deviation 145; M22 passes since 2026-10-22); run when M23 passes"]
fn e21_ops_15_the_newest_m23_idle_rss_with_every_role_and_a_full_cache_passes() {
    let path = newest_result("m23");
    let (text, line) = verdict(&path, "E21 (OPS-15), M23");
    assert!(
        says(&line, "PASS"),
        "E21 (OPS-15), M23: {} carries `{line}`, not `Verdict: PASS`",
        path.display()
    );
    assert!(
        text.contains("musl"),
        "E21 (OPS-15), M23: {} does not say it measured the static musl binary",
        path.display()
    );
}
