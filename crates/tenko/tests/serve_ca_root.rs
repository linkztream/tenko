//! `GET /system/ca-root` and `tenko ca-root` against a real `tenko serve`: the root of the
//! internal CA is downloadable before the client trusts it, but only with the fingerprint
//! the server printed at start; in the other TLS modes there is no internal CA root.

mod serve_support;

use std::fs;

use serve_support::{Node, READY_TIMEOUT, Transport, run_tenko};

/// The fingerprint line the server prints on standard output in TLS mode a.
const FINGERPRINT_LINE: &str = "SHA-256 fingerprint: ";

#[test]
fn the_root_downloads_with_the_printed_fingerprint() {
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    let line = server
        .wait_stdout_line(READY_TIMEOUT, |line| line.contains(FINGERPRINT_LINE))
        .unwrap_or_else(|| panic!("no fingerprint line:\n{}", server.diagnostics()));
    let fingerprint = line
        .trim()
        .strip_prefix(FINGERPRINT_LINE)
        .expect("the line starts with the label")
        .to_owned();
    assert_eq!(fingerprint.len(), 64, "{fingerprint}");
    let on_disk = fs::read_to_string(node.data_dir().join("tls").join("ca-root.pem"))
        .expect("the server writes the root");
    let url = node.url();
    let credentials = node.root().join("none.json");
    let env = [(
        "TENKO_CREDENTIALS",
        credentials.to_str().expect("UTF-8 path"),
    )];

    // Not trusted yet and no fingerprint: refused, with a hint.
    run_tenko(&["ca-root", "--url", &url], &env)
        .assert_code(7)
        .assert_stderr_contains("--fingerprint");

    // A wrong fingerprint: refused as an integrity failure.
    let wrong = "00".repeat(32);
    run_tenko(&["ca-root", "--url", &url, "--fingerprint", &wrong], &env).assert_code(9);

    // The printed fingerprint: the root, identical to the file in the data directory.
    let outcome = run_tenko(
        &["ca-root", "--url", &url, "--fingerprint", &fingerprint],
        &env,
    );
    outcome.assert_code(0);
    assert_eq!(outcome.stdout, on_disk);

    // With the root trusted, the download verifies normally and writes a file.
    let ca_file = node.ca_file().expect("internal CA mode has a CA file");
    let target = node.root().join("downloaded.pem");
    run_tenko(
        &[
            "ca-root",
            "--url",
            &url,
            "--ca-file",
            ca_file.to_str().expect("UTF-8 path"),
            "-o",
            target.to_str().expect("UTF-8 path"),
        ],
        &env,
    )
    .assert_code(0)
    .assert_stderr_contains(&fingerprint);
    assert_eq!(fs::read_to_string(&target).expect("written"), on_disk);

    server.stop().assert_graceful_shutdown();
}

#[test]
fn other_tls_modes_have_no_internal_ca_root() {
    let mut node = Node::new();
    let mut server = node.start();
    let credentials = node.root().join("none.json");
    run_tenko(
        &["ca-root", "--url", &node.url()],
        &[(
            "TENKO_CREDENTIALS",
            credentials.to_str().expect("UTF-8 path"),
        )],
    )
    .assert_code(5)
    .assert_stderr_contains("error[tls.no_internal_ca]");
    server.stop().assert_graceful_shutdown();
}
