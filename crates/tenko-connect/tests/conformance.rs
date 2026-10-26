//! The conformance suite against the sample plugin: the well-behaved sample passes every
//! check, and each way of misbehaving fails exactly the checks that cover it.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use tenko_connect::{
    Secrets,
    conformance::{Outcome, Report, SuiteOptions, run},
    host::launch::LaunchSpec,
    sample,
};
use zeroize::Zeroizing;

fn spec(mode: &str, with_manifest: bool) -> LaunchSpec {
    LaunchSpec {
        expected: with_manifest.then(sample::manifest),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample")),
        args: vec![OsString::from("--mode"), OsString::from(mode)],
        cwd: None,
        env: Vec::new(),
    }
}

fn options() -> SuiteOptions {
    SuiteOptions {
        call_timeout: Duration::from_secs(5),
        ..SuiteOptions::default()
    }
}

fn outcome(report: &Report, id: &str) -> Outcome {
    report
        .check(id)
        .unwrap_or_else(|| panic!("no check {id} in {report}"))
        .outcome
}

fn failed(report: &Report) -> Vec<String> {
    report.failures().map(|check| check.id.clone()).collect()
}

#[tokio::test]
async fn the_sample_passes_every_check() {
    let mut secrets = Secrets::new();
    secrets.insert("api_key", Zeroizing::new(b"conformance-key".to_vec()));
    let options = SuiteOptions {
        settings: Some(serde_json::json!({ "hosts": 12, "page_size": 5 })),
        secrets,
        ..options()
    };
    let report = run(&spec("normal", true), &options).await;
    assert!(report.passed(), "{report}");
    let ids: Vec<&str> = report
        .checks
        .iter()
        .map(|check| check.id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "launch",
            "manifest",
            "ping",
            "token",
            "concurrency",
            "check",
            "capability.inventory",
            "undeclared",
            "malformed_request",
            "shutdown",
            "protocol_mismatch",
            "stdin_close",
        ]
    );
    let inventory = report.check("capability.inventory").expect("inventory");
    assert!(
        inventory.detail.contains("12 hosts in 3 page(s)"),
        "{report}"
    );
    assert_eq!(report.plugin.as_deref(), Some("sample"));
    let text = report.to_string();
    assert!(text.ends_with("conformance: every check passed"), "{text}");
}

#[tokio::test]
async fn an_executable_without_a_manifest_file_is_tested_on_its_handshake() {
    let report = run(&spec("normal", false), &options()).await;
    assert!(report.passed(), "{report}");
}

#[tokio::test]
async fn a_plugin_that_ignores_the_token_fails_the_token_check() {
    let report = run(&spec("ignore-token", true), &options()).await;
    assert_eq!(failed(&report), ["token"], "{report}");
}

#[tokio::test]
async fn a_plugin_that_ignores_its_input_closing_fails_stdin_close() {
    let report = run(&spec("ignore-stdin-close", true), &options()).await;
    assert_eq!(failed(&report), ["stdin_close"], "{report}");
}

#[tokio::test]
async fn hanging_calls_fail_on_their_timeout() {
    let options = SuiteOptions {
        call_timeout: Duration::from_millis(700),
        ..options()
    };
    let report = run(&spec("hang-calls", true), &options).await;
    assert_eq!(
        failed(&report),
        ["check", "capability.inventory"],
        "{report}"
    );
    let check = report.check("check").expect("check");
    assert!(check.detail.contains("timed out"), "{report}");
}

#[tokio::test]
async fn a_crash_during_a_call_fails_the_call_and_what_follows() {
    let report = run(&spec("crash-on-poll", true), &options()).await;
    assert_eq!(outcome(&report, "check"), Outcome::Pass, "{report}");
    assert_eq!(outcome(&report, "capability.inventory"), Outcome::Fail);
    assert_eq!(outcome(&report, "undeclared"), Outcome::Fail);
    assert_eq!(outcome(&report, "shutdown"), Outcome::Fail);
    // The later launches start a fresh process.
    assert_eq!(outcome(&report, "protocol_mismatch"), Outcome::Pass);
    assert_eq!(outcome(&report, "stdin_close"), Outcome::Pass);
}

#[tokio::test]
async fn malformed_inventory_values_fail_the_capability() {
    let report = run(&spec("malformed-hosts", true), &options()).await;
    assert_eq!(failed(&report), ["capability.inventory"], "{report}");
}

#[tokio::test]
async fn a_protocol_mismatch_stops_at_launch_with_a_clear_error() {
    let report = run(&spec("protocol-2", true), &options()).await;
    assert_eq!(failed(&report), ["launch"], "{report}");
    let launch = report.check("launch").expect("launch");
    assert!(
        launch.detail.contains("no common protocol version"),
        "{report}"
    );
    assert!(
        report
            .checks
            .iter()
            .skip(1)
            .all(|check| check.outcome == Outcome::Skip)
    );
}

#[tokio::test]
async fn a_hanging_handshake_fails_launch() {
    let options = SuiteOptions {
        handshake_timeout: Duration::from_millis(800),
        ..options()
    };
    let report = run(&spec("hang-handshake", true), &options).await;
    assert_eq!(failed(&report), ["launch"], "{report}");
}

#[tokio::test]
async fn a_manifest_that_differs_from_plugin_json_fails_launch() {
    let report = run(&spec("wrong-version", true), &options()).await;
    assert_eq!(failed(&report), ["launch"], "{report}");
    assert!(
        report
            .check("launch")
            .expect("launch")
            .detail
            .contains("9.9.9")
    );
}

fn switch_spec(nudge: bool) -> LaunchSpec {
    LaunchSpec {
        expected: Some(tenko_connect::sample_switch::manifest(nudge)),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample")),
        args: vec![
            OsString::from("--mode"),
            OsString::from(if nudge { "switch" } else { "switch-plain" }),
        ],
        cwd: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn a_switch_that_declares_the_bounce_and_the_kick_passes_their_checks() {
    let report = run(&switch_spec(true), &options()).await;
    assert!(report.passed(), "{report}");
    for id in ["capability.port_bounce", "capability.client_kick"] {
        assert_eq!(outcome(&report, id), Outcome::Pass, "{report}");
    }
    let bounce = report.check("capability.port_bounce").expect("bounce");
    // The suite plans a bounce of a switch the sample does not have: a coded answer.
    assert!(
        bounce.detail.contains("connect.not_found") || bounce.detail.contains("does not exist"),
        "{report}"
    );
}

#[tokio::test]
async fn a_switch_without_them_answers_unimplemented_for_both() {
    let report = run(&switch_spec(false), &options()).await;
    assert!(report.passed(), "{report}");
    assert!(report.check("capability.port_bounce").is_none());
    let undeclared = report.check("undeclared").expect("undeclared");
    assert!(
        undeclared.detail.contains("port_bounce, client_kick"),
        "{report}"
    );
}
