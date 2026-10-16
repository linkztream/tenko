//! Acceptance of the observability requirements.
//!
//! - E12 (OPS-21): the newest M8 result file of Windows and of Linux under
//!   `bench/phase1-metrics/results/` carries `Verdict: PASS`.
//! - E11 (OPS-15): the newest M9 result file of Windows and of Linux under
//!   `bench/phase1-server/results/` carries `Verdict: PASS`.
//! - OPS-05: a real `tenko serve` answers `GET /api/v1/metrics` to a signed-in
//!   administrator in the `OpenMetrics` format, the text passes the strict checker of
//!   `tenko-core` (the one the product's own tests use), and the documented families of
//!   `docs/observability.md` are present.
//!
//! A result file is found by the date prefix of its name, its measurement (`m8` or `m9` in
//! the name) and its platform (the parenthesis at the end of its title line). The verdict
//! convention: one line `Verdict: PASS` or `Verdict: FAIL`, optionally followed by
//! ` (<qualifier>)`, in the lines right below the title (see `bench/README.md`).

mod serve_support;

use std::path::{Path, PathBuf};

use serve_support::{Node, api::Api, wait_for_setup_token};

/// The `bench/` directory of the repository.
fn bench_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("bench")
}

/// The newest result file of `measurement` (`m8`, `m9`) for `platform` under
/// `bench/<suite>/results/`, by the date prefix of the file name. A file belongs to a
/// platform when the parenthesis at the end of its title line names it.
fn newest_result(suite: &str, measurement: &str, platform: &str) -> PathBuf {
    let dir = bench_dir().join(suite).join("results");
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
        if !dated || !markdown || !name.contains(&format!("-{measurement}")) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is unreadable: {error}", path.display()));
        let title = text.lines().next().unwrap_or_default();
        let platforms = title.rsplit_once('(').map_or("", |(_, rest)| rest);
        if platforms.contains(platform) {
            candidates.push((name, path));
        }
    }
    candidates.sort();
    candidates
        .pop()
        .unwrap_or_else(|| {
            panic!(
                "missing result: no {measurement} result file for {platform} in {}; run the measurement and record it there",
                dir.display()
            )
        })
        .1
}

/// Asserts that the lines below the title of `path` carry `Verdict: PASS`.
fn assert_verdict_pass(path: &Path, what: &str) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is unreadable: {error}", path.display()));
    let verdict = text
        .lines()
        .take(8)
        .find(|line| line.starts_with("Verdict:"))
        .unwrap_or_else(|| {
            panic!(
                "{what}: {} has no `Verdict: PASS` or `Verdict: FAIL` line right below its title",
                path.display()
            )
        });
    let passes = verdict == "Verdict: PASS" || verdict.starts_with("Verdict: PASS (");
    assert!(
        passes,
        "{what}: {} carries `{verdict}`, not `Verdict: PASS`",
        path.display()
    );
}

/// E12 and OPS-21: the metrics cost of the newest M8 run is within the budget (below 2
/// percent throughput, p99 unchanged, no allocation on update) on Windows.
#[test]
fn e12_ops_21_the_newest_m8_run_on_windows_passes() {
    let path = newest_result("phase1-metrics", "m8", "Windows");
    assert_verdict_pass(&path, "E12 (OPS-21), M8 on Windows");
}

/// E12 and OPS-21: the same for the newest M8 run on Linux.
#[test]
fn e12_ops_21_the_newest_m8_run_on_linux_passes() {
    let path = newest_result("phase1-metrics", "m8", "Linux");
    assert_verdict_pass(&path, "E12 (OPS-21), M8 on Linux");
}

/// E11 and OPS-15: the idle resident set of the newest M9 run is below 100 MB on Windows.
#[test]
fn e11_ops_15_the_newest_m9_run_on_windows_passes() {
    let path = newest_result("phase1-server", "m9", "Windows");
    assert_verdict_pass(&path, "E11 (OPS-15), M9 on Windows");
}

/// E11 and OPS-15: the same for the newest M9 run on Linux.
#[test]
fn e11_ops_15_the_newest_m9_run_on_linux_passes() {
    let path = newest_result("phase1-server", "m9", "Linux");
    assert_verdict_pass(&path, "E11 (OPS-15), M9 on Linux");
}

/// The value of the first sample whose line starts with `prefix`.
fn sample<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next())
}

/// OPS-05: the metrics of a running controller are served in the `OpenMetrics` format to
/// a signed-in administrator, refused without credentials, parse strictly, and carry the
/// documented families.
#[test]
fn ops_05_the_metrics_endpoint_serves_parsable_openmetrics_with_the_documented_families() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    // Some traffic of a known route class, so the request families have samples.
    api.get("/prefixes").expect(200);

    assert_eq!(
        api.anonymous().get("/metrics").status,
        401,
        "a request for the metrics without credentials is refused"
    );
    let reply = api.get("/metrics");
    assert_eq!(reply.status, 200, "the metrics: {}", reply.text);
    let content_type = reply.header("content-type").unwrap_or_default();
    assert!(
        content_type.starts_with("application/openmetrics-text; version=1.0.0"),
        "the content type is the OpenMetrics one, got `{content_type}`"
    );
    let text = &reply.text;
    // The product's strict checker: TYPE and HELP placement, sample syntax, cumulative
    // ascending buckets ending in +Inf equal to _count, _sum, no duplicate sample, # EOF.
    if let Err(error) = tenko_core::metrics::check(text) {
        panic!("the metrics text does not parse: {error}\n{text}");
    }
    assert!(text.ends_with("# EOF\n"), "the text ends with # EOF");

    for (family, kind) in [
        ("tenko_build_info", "gauge"),
        ("tenko_uptime_seconds", "gauge"),
        ("tenko_http_requests", "counter"),
        ("tenko_http_request_duration_seconds", "histogram"),
        ("tenko_store_revision", "gauge"),
        ("tenko_audit_head", "gauge"),
        ("tenko_raft_role", "gauge"),
        ("tenko_sse_subscribers", "gauge"),
    ] {
        assert!(
            text.contains(&format!("# TYPE {family} {kind}\n")),
            "the documented family {family} ({kind}) is missing\n{text}"
        );
        assert!(
            text.contains(&format!("# HELP {family} ")),
            "the documented family {family} has no HELP line"
        );
    }
    assert_eq!(sample(text, "tenko_build_info"), Some("1"));
    // The request counter has seen the read of the prefixes, and the duration histogram
    // has an +Inf bucket, a sum and a count for the same class.
    let counted = text.lines().any(|line| {
        line.starts_with("tenko_http_requests_total{")
            && line.contains("method=\"GET\"")
            && line.contains("status=\"200\"")
    });
    assert!(
        counted,
        "no GET 200 sample in tenko_http_requests_total\n{text}"
    );
    for suffix in [
        "_bucket{class=\"prefixes\",le=\"+Inf\"}",
        "_sum{class=\"prefixes\"}",
        "_count{class=\"prefixes\"}",
    ] {
        let prefix = format!("tenko_http_request_duration_seconds{suffix}");
        assert!(
            sample(text, &prefix).is_some(),
            "no sample {prefix} for the prefixes class\n{text}"
        );
    }

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
}
