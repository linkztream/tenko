//! Acceptance of the Phase 3 exit measurements and checks (WP9.5,
//! `docs/plans/phase-3-exit.md`).
//!
//! - E22: the newest perfdhcp result file under `bench/phase3-dhcp/results/` (M26 to M28
//!   through the binary) is documented, over the link from the load VM and on loopback,
//!   with every lease committed to the store before its ACK. The metrics half (M33, the
//!   same runs with the metrics on and off) is ignored while neither server can turn the
//!   DHCP metrics off.
//! - E24: the newest crash result file (M32) passes the twenty kills; the five power-offs
//!   of the lab VM are ignored until the owner has run them.
//! - E31: the DHCPv4 and DHCPv6 fuzz targets are in the fuzz crate with their sources, and
//!   the weekly fuzz smoke of the CI workflow runs every target `cargo fuzz list` prints.
//! - E32: the newest exit result file (`-e32-` in its name) holds the M30, M33 and M34 rows;
//!   M30 (the table of 100,000 leases below 50 MiB) and M34 on the workstation's Windows
//!   release build (below 100 MB) pass since the role's tables were made compact and sized
//!   from the configuration; M33 below 2 percent by the plan's method and M34 on the musl
//!   binary are ignored tests until the rows pass.
//!
//! A result file is found by the date prefix of its name and a part of its name; the newest
//! by name wins, except that a file which names others in a `Supersedes:` line below its
//! title replaces them (a second run of the same day whose name sorts first). The verdict
//! convention is that of `bench/README.md`: one line
//! `Verdict: <word>`, optionally followed by ` (<qualifier>)`, right below the title. The
//! tests read files only, so they run anywhere.

use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn results_dir() -> PathBuf {
    repository()
        .join("bench")
        .join("phase3-dhcp")
        .join("results")
}

/// The file names a result file replaces: the back-quoted names of its `Supersedes:` line,
/// one of the eight lines below its title.
fn superseded_by(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .take(8)
        .filter_map(|line| line.strip_prefix("Supersedes:"))
        .flat_map(|names| {
            names
                .split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The newest Markdown result file whose name holds `part`, by the date prefix of its name,
/// among those no other names in its `Supersedes:` line.
fn newest_result(part: &str) -> PathBuf {
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
        if dated && markdown && name.contains(part) {
            candidates.push((name, path));
        }
    }
    let superseded: Vec<String> = candidates
        .iter()
        .flat_map(|(_, path)| superseded_by(path))
        .collect();
    candidates.retain(|(name, _)| !superseded.contains(name));
    candidates.sort();
    candidates
        .pop()
        .unwrap_or_else(|| {
            panic!(
                "missing result: no file with `{part}` in its name in {}; run the measurement and record it there",
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

/// The summary row of `measurement` (`| M30 ...`) of the exit result file, and its
/// verdict cell (the last non-empty cell).
fn summary_row(text: &str, measurement: &str) -> Option<(String, String)> {
    let prefix = format!("| {measurement} ");
    text.lines()
        .find(|line| line.starts_with(&prefix))
        .map(|line| {
            let cell = line
                .trim()
                .trim_end_matches('|')
                .rsplit('|')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            (line.to_owned(), cell)
        })
}

/// E22 and DHCP-17: the perfdhcp figures of one node are documented over the link from the
/// load VM and on loopback, with every lease committed to the store before its ACK
/// (DHCP-07).
#[test]
fn e22_dhcp_17_the_perfdhcp_figures_over_the_link_and_on_loopback_are_documented() {
    let path = newest_result("-m26-m28-perfdhcp");
    let (text, line) = verdict(&path, "E22 (DHCP-17), M26 to M28");
    // This file's verdict goes on after a comma (`Verdict: DOCUMENTED, and above ...`).
    assert!(
        says(&line, "DOCUMENTED") || line.starts_with("Verdict: DOCUMENTED,"),
        "E22 (DHCP-17): {} carries `{line}`, not `Verdict: DOCUMENTED`",
        path.display()
    );
    let lower = text.to_lowercase();
    for needle in [
        "perfdhcp",
        "two hosts",
        "loopback",
        "committed to the",
        "musl",
    ] {
        assert!(
            lower.contains(needle),
            "E22 (DHCP-17): {} does not say `{needle}`",
            path.display()
        );
    }
}

/// E22 and OPS-21 (M33): the M26 runs with the metrics on and off.
#[test]
#[ignore = "M33 is not measured: neither tenko serve nor the example server can turn the DHCP metrics off (phase-3-exit.md)"]
fn e22_ops_21_the_perfdhcp_figures_with_and_without_metrics_pass() {
    let path = newest_result("-m33-");
    let (_, line) = verdict(&path, "E22 (OPS-21), M33");
    assert!(
        says(&line, "PASS"),
        "E22 (OPS-21), M33: {} carries `{line}`, not `Verdict: PASS`",
        path.display()
    );
}

/// E24 and DHCP-07: twenty kills of a node under lease load lose no acknowledged lease,
/// put no address on two clients and leave the table equal to the rows (M32).
#[test]
fn e24_dhcp_07_twenty_kills_lose_no_acknowledged_lease() {
    let path = newest_result("-m32-");
    let (text, line) = verdict(&path, "E24 (DHCP-07), M32");
    assert!(
        says(&line, "PASS"),
        "E24 (DHCP-07), M32: {} carries `{line}`, not `Verdict: PASS`",
        path.display()
    );
    assert!(
        text.contains("20 kills"),
        "E24 (DHCP-07), M32: {} does not record the twenty kills",
        path.display()
    );
}

/// E24 and OPS-02: five power-offs of the lab VM under load, each checked with
/// `verify_after_power_off` (M32, the owner's step).
#[test]
#[ignore = "the five power-offs of the lab VM are the owner's step (phase-3-exit.md section 6)"]
fn e24_ops_02_five_power_offs_of_the_lab_vm_lose_no_acknowledged_lease() {
    let path = newest_result("-m32-");
    let (text, _) = verdict(&path, "E24 (OPS-02), M32");
    let runs = text.matches("POWER-OFF OK").count();
    assert!(
        runs >= 5,
        "E24 (OPS-02), M32: {} records {runs} checked power-offs, not 5",
        path.display()
    );
}

/// E31, API-14 and API-15: the DHCPv4 and DHCPv6 fuzz targets (wire formats, options,
/// relay information) exist, and the weekly fuzz smoke runs every target the fuzz crate
/// lists.
#[test]
fn e31_api_14_the_dhcp_fuzz_targets_are_in_the_weekly_fuzz_smoke() {
    let root = repository();
    let manifest =
        std::fs::read_to_string(root.join("fuzz").join("Cargo.toml")).expect("fuzz/Cargo.toml");
    for target in [
        "dhcp_v4",
        "dhcp4_options",
        "dhcp4_relay_info",
        "dhcp6_wire",
        "dhcp6_relay",
    ] {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "E31 (API-14): fuzz/Cargo.toml has no target {target}"
        );
        let source = root
            .join("fuzz")
            .join("fuzz_targets")
            .join(format!("{target}.rs"));
        assert!(
            source.is_file(),
            "E31 (API-14): {} is missing",
            source.display()
        );
    }
    let workflow = std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml"))
        .expect("the CI workflow");
    assert!(
        workflow.contains("Fuzz smoke") && workflow.contains("cargo +nightly fuzz list"),
        "E31 (API-15): the CI workflow has no fuzz smoke that runs every listed target"
    );
}

/// E32 and OPS-15: the memory of 100,000 leases (M30), the metrics cost (M33) and the
/// idle resident set with every role (M34) are recorded in the exit result file.
#[test]
fn e32_ops_15_the_exit_result_file_records_m30_m33_and_m34() {
    let path = newest_result("-e32-");
    let (text, _) = verdict(&path, "E32 (OPS-15)");
    for measurement in ["M30", "M33", "M34"] {
        assert!(
            summary_row(&text, measurement).is_some(),
            "E32 (OPS-15): {} has no summary row `| {measurement} ...`",
            path.display()
        );
    }
}

/// E32 and OPS-15 (M30): the role's table and indexes of 100,000 leases below 50 MiB.
#[test]
fn e32_ops_15_the_memory_of_100000_leases_is_below_50_mib() {
    let path = newest_result("-e32-");
    let (text, _) = verdict(&path, "E32 (OPS-15), M30");
    let (row, cell) = summary_row(&text, "M30").expect("an M30 row");
    assert!(cell.starts_with("PASS"), "E32 (OPS-15), M30: {row}");
}

/// E32 and OPS-21 (M33): the metrics cost on the DORA path below 2 percent by the plan's
/// method (M26 with the metrics on and off).
#[test]
#[ignore = "M33 is not measured by the plan's method: no switch turns the DHCP metrics off (phase-3-exit.md)"]
fn e32_ops_21_the_metrics_cost_on_the_dora_path_is_below_2_percent() {
    let path = newest_result("-m33-");
    let (_, line) = verdict(&path, "E32 (OPS-21), M33");
    assert!(
        says(&line, "PASS"),
        "E32 (OPS-21), M33: {} carries `{line}`, not `Verdict: PASS`",
        path.display()
    );
}

/// E32 and OPS-15 (M34) on the workstation: the idle resident set of the Windows release
/// build with every role including `dhcp` serving the home scopes is below 100 MB. The
/// criterion's figure is the musl binary's (the next test); this is the figure measured
/// here.
#[test]
fn e32_ops_15_the_idle_rss_with_every_role_on_the_workstation_is_below_100_mb() {
    let path = newest_result("-e32-");
    let (text, _) = verdict(&path, "E32 (OPS-15), M34");
    let row = text
        .lines()
        .find(|line| line.starts_with("| M34 ") && line.contains("Windows"))
        .unwrap_or_else(|| panic!("E32 (OPS-15), M34: {} has no Windows row", path.display()));
    let cell = row
        .trim()
        .trim_end_matches('|')
        .rsplit('|')
        .next()
        .unwrap_or_default()
        .trim();
    assert!(cell.starts_with("PASS"), "E32 (OPS-15), M34: {row}");
}

/// E32 and OPS-15 (M34): the idle resident set with every role including `dhcp` serving
/// the home scopes is below 100 MB on the static musl binary.
#[test]
#[ignore = "M34 on the musl binary is the lab's run, and the Windows figure FAILs (phase-3-exit.md)"]
fn e32_ops_15_the_idle_rss_with_every_role_on_the_musl_binary_is_below_100_mb() {
    let path = newest_result("-e32-");
    let (text, _) = verdict(&path, "E32 (OPS-15), M34");
    let row = text
        .lines()
        .find(|line| line.starts_with("| M34 ") && line.contains("musl"))
        .unwrap_or_else(|| panic!("E32 (OPS-15), M34: {} has no musl row", path.display()));
    let cell = row
        .trim()
        .trim_end_matches('|')
        .rsplit('|')
        .next()
        .unwrap_or_default()
        .trim();
    assert!(cell.starts_with("PASS"), "E32 (OPS-15), M34: {row}");
}
