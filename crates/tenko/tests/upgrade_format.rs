//! The data-directory format against the real binary (OPS-23): a new store gets its marker,
//! `tenko upgrade check` reports with its exit codes, and a directory with a newer format
//! is refused by `tenko serve` (exit status 3) and by the check (exit status 11) without
//! being touched.

mod serve_support;

use std::path::Path;

use serve_support::{Node, run_tenko};

/// The format this binary writes, as `tenko upgrade format` prints it.
fn binary_format() -> u32 {
    let outcome = run_tenko(&["upgrade", "format"], &[]);
    outcome.assert_code(0);
    outcome.stdout.trim().parse().expect("a format number")
}

fn marker(data_dir: &Path) -> String {
    std::fs::read_to_string(data_dir.join("store").join("format")).expect("the format marker")
}

fn check(data_dir: &Path) -> serve_support::Outcome {
    run_tenko(
        &[
            "upgrade",
            "check",
            "--data-dir",
            data_dir.to_str().expect("UTF-8 path"),
            "--json",
        ],
        &[],
    )
}

#[test]
fn a_fresh_directory_needs_nothing() {
    let node = Node::new();
    let outcome = check(&node.data_dir());
    outcome.assert_code(0);
    let report = outcome.json();
    assert_eq!(report["verdict"], "fresh", "{}", outcome.diagnostics());
    assert_eq!(report["binary_format"], binary_format());
    assert!(
        !node.data_dir().join("store").exists(),
        "the check creates nothing"
    );
}

#[test]
fn a_new_store_has_the_marker_and_checks_clean() {
    let mut node = Node::new();
    let mut server = node.start();
    // While the server runs the store is open: the check refuses to copy it.
    let busy = check(&node.data_dir());
    busy.assert_code(1);
    assert_eq!(
        busy.json()["problem"]["code"],
        "upgrade.in_use",
        "{}",
        busy.diagnostics()
    );
    server.stop().assert_code(0);

    let format = binary_format();
    assert!(
        marker(&node.data_dir()).starts_with(&format!("tenko-data-format {format}\n")),
        "{}",
        marker(&node.data_dir())
    );
    let outcome = check(&node.data_dir());
    outcome.assert_code(0);
    let report = outcome.json();
    assert_eq!(report["verdict"], "current", "{}", outcome.diagnostics());
    assert_eq!(report["found_format"], format);
    assert!(
        !node.data_dir().join("upgrade-check").exists(),
        "the work copy is removed"
    );
    // The text report says the same.
    let text = run_tenko(
        &[
            "upgrade",
            "check",
            "--data-dir",
            node.data_dir().to_str().expect("UTF-8 path"),
        ],
        &[],
    );
    text.assert_code(0)
        .assert_stdout_contains("nothing to do (exit 0)");
}

#[test]
fn a_newer_format_is_refused_and_left_alone() {
    let mut node = Node::new();
    node.start().stop().assert_code(0);
    let newer = binary_format() + 7;
    let store = node.data_dir().join("store");
    std::fs::write(
        store.join("format"),
        format!("tenko-data-format {newer}\nwritten-by 99.0.0\n"),
    )
    .expect("a newer marker");
    let log_before = std::fs::read(store.join("log.redb")).expect("the log");

    let mut server = node.spawn();
    let outcome = server.finish(serve_support::STOP_TIMEOUT);
    outcome
        .assert_code(3)
        .assert_stderr_contains("upgrade.format_newer")
        .assert_stderr_contains(&format!(
            "format {newer}, newer than format {}",
            binary_format()
        ));

    let refused = check(&node.data_dir());
    refused.assert_code(11);
    let report = refused.json();
    assert_eq!(report["verdict"], "refused");
    assert_eq!(report["found_format"], newer);
    assert_eq!(report["problem"]["code"], "upgrade.format_newer");

    assert_eq!(
        std::fs::read(store.join("log.redb")).expect("the log"),
        log_before,
        "a refused directory is not touched"
    );
    assert!(marker(&node.data_dir()).starts_with(&format!("tenko-data-format {newer}\n")));
}
