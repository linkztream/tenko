//! Black-box tests of the start and the stop of `tenko serve`: the start steps in
//! order, readiness, graceful shutdown by the end of standard input (and by `SIGTERM` on
//! Unix), and the refusals of a second server on the same data directory and of a port that
//! is already taken.

mod serve_support;

use std::net::TcpListener;

use serve_support::{
    Kek, Node, READY_PATH, STEP_COUNT, STEPS, STOP_TIMEOUT, Transport, VERSION, assert_in_order,
    lines_with, step_marker, step_millis,
};

/// The log lines that announce the steps `from..=to` (1-based), each with its number.
fn step_ready_lines(from: usize, to: usize) -> Vec<String> {
    (from..=to)
        .map(|number| step_marker(STEPS[number - 1], "ready in "))
        .collect()
}

#[test]
fn the_start_steps_run_in_order_and_the_api_becomes_ready() {
    let mut node = Node::new();
    let mut server = node.start();

    let (status, body) = node.get(READY_PATH).expect("the probe answers");
    assert_eq!(status, 200, "{body}");
    let probe: serde_json::Value = serde_json::from_str(&body).expect("the probe answers JSON");
    assert_eq!(probe["status"], "ready", "{body}");

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();

    let mut needles = step_ready_lines(1, STEP_COUNT);
    needles.push("started in ".to_owned());
    needles.push(format!("tenko {VERSION} ready"));
    assert_in_order(&outcome.stderr, &needles);
    let summary = lines_with(&outcome.stderr, "started in ");
    assert_eq!(summary.len(), 1, "{}", outcome.stderr);
    for name in STEPS {
        assert!(
            summary[0].contains(&format!("{name} {} ms", step_millis(&outcome.stderr, name))),
            "the summary lacks the timing of {name}: {}",
            summary[0]
        );
    }
    assert!(
        lines_with(&outcome.stderr, &format!("/{STEP_COUNT} "))
            .iter()
            .all(|line| !line.contains(" failed")),
        "{}",
        outcome.stderr
    );
    outcome.assert_stdout_contains(&format!("tenko {VERSION} ready at "));
}

#[test]
fn the_end_of_standard_input_stops_the_server_gracefully() {
    let mut node = Node::new();
    let mut server = node.start();
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    assert_in_order(
        &outcome.stderr,
        &[
            "standard input closed",
            "shutdown requested",
            "tenko stopped",
        ],
    );

    // The port is free again. Binding it proves that no listener is left; connecting would
    // not, because the network proxy of some WSL set-ups keeps accepting connections on a
    // port long after the process behind it has gone.
    TcpListener::bind(("127.0.0.1", node.port)).expect("the port is still taken after the exit");
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_server_gracefully() {
    let mut node = Node::new().without_stop_on_eof();
    let mut server = node.start();
    server.terminate();
    let outcome = server.finish(STOP_TIMEOUT);
    outcome.assert_graceful_shutdown();
    assert!(
        !outcome.stderr.contains("standard input closed"),
        "the signal, not the end of input, stopped the server\n{}",
        outcome.stderr
    );
}

#[test]
fn a_second_server_on_the_same_data_directory_is_refused() {
    let mut node = Node::new();
    let mut first = node.start();

    let mut second = node.spawn_second();
    let refused = second.finish(STOP_TIMEOUT);
    refused.assert_code(4);
    refused.assert_stderr_contains(&step_marker("store", "failed"));
    refused.assert_stderr_contains("tenko serve: start step `store` failed [sys.store.");
    assert!(
        refused.stdout.is_empty(),
        "a refused server prints nothing on stdout\n{}",
        refused.diagnostics()
    );

    // The refused start did not disturb the first server.
    let (status, body) = node
        .get(READY_PATH)
        .expect("the first server still answers");
    assert_eq!(status, 200, "{body}");
    first.stop().assert_graceful_shutdown();
}

#[test]
fn a_busy_port_fails_the_api_step_and_leaves_the_data_directory_usable() {
    let mut node = Node::new();
    let blocker = TcpListener::bind(("127.0.0.1", node.port)).expect("occupy the port");

    let mut refused = node.spawn();
    let outcome = refused.finish(STOP_TIMEOUT);
    outcome.assert_code(4);
    let api = STEPS
        .iter()
        .position(|step| *step == "api")
        .expect("the api step");
    let mut needles = step_ready_lines(1, api);
    needles.push(step_marker("api", "failed"));
    assert_in_order(&outcome.stderr, &needles);
    outcome.assert_stderr_contains("tenko serve: start step `api` failed [start.api.bind]");
    assert!(
        !outcome.stdout.contains(" ready at "),
        "a server that did not start must not announce itself\n{}",
        outcome.diagnostics()
    );

    // The failed start closed what it had opened: the same data directory starts normally.
    drop(blocker);
    let mut server = node.start();
    let stopped = server.stop();
    stopped.assert_graceful_shutdown();
    stopped.assert_stderr_contains("opened at revision");
}

#[test]
fn the_platform_default_kek_starts_the_server() {
    let mut node = Node::new().with_kek(Kek::Platform);
    let mut server = node.start();
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();

    let step = lines_with(&outcome.stderr, &step_marker("kek", "ready in "));
    assert_eq!(step.len(), 1, "{}", outcome.stderr);
    let weak = outcome.stderr.contains("THE KEY-ENCRYPTION KEY IS");
    assert_eq!(
        weak,
        step[0].contains("plain key file"),
        "the warning and the description of the key must agree\n{}",
        outcome.stderr
    );
    if cfg!(windows) {
        assert!(step[0].contains("DPAPI"), "{}", step[0]);
        assert!(
            !weak,
            "DPAPI is an operating-system protection\n{}",
            outcome.stderr
        );
    }
    let kek_files = std::fs::read_dir(node.kek_dir())
        .expect("the key directory exists")
        .count();
    assert!(kek_files > 0, "the key directory is empty");
}

#[test]
fn internal_ca_mode_serves_https_with_the_published_ca_root() {
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    let ca_file = node.ca_file().expect("an HTTPS node has a CA file");

    let pem = std::fs::read_to_string(&ca_file).expect("the CA root is published");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
    assert!(
        !pem.contains("PRIVATE KEY"),
        "the published root holds no private key"
    );

    let (status, _) = node.get(READY_PATH).expect("HTTPS with the CA root");
    assert_eq!(status, 200);
    let url = format!("{}{READY_PATH}", node.url());
    let untrusted = serve_support::http_get(&url, None);
    assert!(
        untrusted.is_err(),
        "the internal CA must not be trusted without its root: {untrusted:?}"
    );

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    outcome.assert_stdout_contains(&format!(
        "tenko {VERSION} ready at https://localhost:{}/",
        node.port
    ));
    outcome.assert_stdout_contains(&format!(
        "internal CA root (install it on admin clients): {}",
        ca_file.display()
    ));
    outcome.assert_stderr_contains(&step_marker("tls", "ready in "));
    outcome.assert_stderr_contains("internal CA");
}

#[test]
fn roles_all_runs_the_controller_dns_and_probe_roles() {
    let port = serve_support::free_port();
    let mut node = Node::new()
        .with_args(&["--roles", "all"])
        .with_config(&format!(
            "[dns]
listen = [\"127.0.0.1:{port}\"]
workers = 1"
        ));
    let mut server = node.start();
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    outcome.assert_stderr_contains(
        "dhcp: not implemented in Phase 2; this node runs the controller, dns, probe role(s)",
    );
    outcome.assert_stderr_contains(&step_marker("dns", "ready in "));
    outcome.assert_stdout_contains(&format!("dns role answering on 127.0.0.1:{port}"));
    outcome.assert_stderr_contains("dns role stopped");
}
