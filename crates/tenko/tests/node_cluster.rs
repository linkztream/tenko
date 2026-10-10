//! Black-box tests of the node transport with the real binary: a controller (`tenko serve`
//! with the internal CA and a cluster port on the loopback) and a probe node (`tenko node
//! enrol`, then `tenko serve --roles probe`) as separate processes, each with its own data
//! directory. They cover enrolment end to end, a wrong CA fingerprint, single-use tokens,
//! the node process heartbeating and delivering a batch to the reconciler, the buffer
//! replaying after the controller restarts, revocation closing the connection, and a
//! controller of another installation being refused. Version negotiation and expiry are
//! covered in-process by `crates/tenko-cluster/tests/transport.rs`.

mod serve_support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use serve_support::{Node, Outcome, Proc, Transport, api::Api, free_port, run, tenko};
use tempfile::TempDir;

/// How long a node may take to connect, to deliver or to notice something.
const WAIT: Duration = Duration::from_secs(90);

/// A batch the node injects: two documentation addresses seen by ARP.
const BATCH: &str = r#"{
  "method": "arp",
  "complete": false,
  "collected_at": "2026-10-10T08:00:05Z",
  "sightings": [
    {"observed_at": "2026-10-10T08:00:01Z",
     "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}},
    {"observed_at": "2026-10-10T08:00:02Z",
     "subject": {"type": "address", "data": {"ip": "192.0.2.31"}}}
  ]
}"#;

/// A controller with the internal CA on `localhost` and a cluster port of its own.
struct Controller {
    node: Node,
    server: Option<Proc>,
    cluster_port: u16,
    fingerprint: String,
}

impl Controller {
    /// Starts it, completes setup and signs the command-line client in.
    fn start() -> Self {
        let cluster_port = free_port();
        let mut node = Node::new()
            .with_transport(Transport::InternalCa)
            .with_config(&format!(
                "[cluster]\nlisten = [\"127.0.0.1:{cluster_port}\"]\nheartbeat_secs = 1\n"
            ));
        let server = node.start();
        node.setup_and_login(&server);
        let fingerprint = fingerprint(&server);
        Self {
            node,
            server: Some(server),
            cluster_port,
            fingerprint,
        }
    }

    fn url(&self) -> String {
        self.node.url()
    }

    /// A new enrolment token for a probe, through `tenko node enrol-token`.
    fn token(&self) -> String {
        let created = self
            .node
            .client(&["node", "enrol-token", "--roles", "probe", "--json"]);
        created.assert_code(0);
        let body = created.json();
        assert_eq!(body["ca_fingerprint"], self.fingerprint.as_str());
        assert!(
            body["command"]
                .as_str()
                .is_some_and(|command| command.starts_with("tenko node enrol --controller")),
            "{body}"
        );
        body["token"].as_str().expect("a token").to_owned()
    }

    fn api(&self) -> Api {
        let mut api = Api::new(&self.node);
        api.login_password();
        api
    }

    /// Stops the server gracefully.
    fn stop(&mut self) -> Outcome {
        let mut server = self.server.take().expect("a running server");
        let outcome = server.stop();
        outcome.assert_graceful_shutdown();
        outcome
    }

    /// Starts the server again on the same data directory and ports.
    fn restart(&mut self) {
        assert!(self.server.is_none(), "stop the server first");
        let port = self.node.port;
        let server = self.node.start();
        assert_eq!(self.node.port, port, "the API moved to another port");
        self.server = Some(server);
    }
}

/// The SHA-256 fingerprint of the CA root the server printed at readiness.
fn fingerprint(server: &Proc) -> String {
    let line = server
        .wait_stdout_line(Duration::from_secs(30), |line| {
            line.contains("SHA-256 fingerprint: ")
        })
        .unwrap_or_else(|| panic!("no fingerprint was printed\n{}", server.diagnostics()));
    line.rsplit(' ')
        .next()
        .expect("a fingerprint")
        .trim()
        .to_owned()
}

/// A probe node: a data directory of its own.
struct Probe {
    dir: TempDir,
}

impl Probe {
    fn new() -> Self {
        Self {
            dir: tempfile::Builder::new()
                .prefix("tenko-probe-")
                .tempdir()
                .expect("temporary directory"),
        }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = tenko();
        command.args(args).arg("--data-dir").arg(self.data_dir());
        command
    }

    /// `tenko node enrol` with the token, the fingerprint and further arguments.
    fn enrol(&self, controller: &Controller, token: &str, fingerprint: &str) -> Outcome {
        let url = controller.url();
        run(
            self.command(&[
                "node",
                "enrol",
                "--controller",
                &url,
                "--token",
                token,
                "--ca-fingerprint",
                fingerprint,
                "--name",
                "probe-dmz",
                "--address",
                "192.0.2.20",
            ]),
            None,
        )
    }

    /// `tenko serve --roles probe`, stopped by closing its standard input.
    fn serve(&self) -> Proc {
        let mut command = self.command(&["serve", "--roles", "probe", "--stop-on-eof"]);
        command.env("TENKO_LOG__LEVEL", "info");
        Proc::spawn(command)
    }

    fn status(&self) -> Value {
        let status = run(self.command(&["node", "status", "--json"]), None);
        status.assert_code(0);
        status.json()
    }

    fn inject(&self) -> Outcome {
        let file = self.dir.path().join("batch.json");
        std::fs::write(&file, BATCH).expect("write the batch");
        run(
            self.command(&["node", "inject", "--file", file.to_str().expect("UTF-8")]),
            None,
        )
    }

    fn identity_path(&self) -> PathBuf {
        self.data_dir().join("node").join("identity.json")
    }
}

/// Polls `check` until it holds.
#[track_caller]
fn wait_until(what: &str, mut check: impl FnMut() -> bool, diagnostics: impl Fn() -> String) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}\n{}",
            diagnostics()
        );
        thread::sleep(Duration::from_millis(200));
    }
}

/// The facts of a probe source at the controller.
fn facts(api: &Api, node: u64) -> Vec<Value> {
    let reply = api.get(&format!("/observations?source=probe:{node}:arp"));
    reply.expect(200)["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn node_view(api: &Api, node: u64) -> (u16, Value) {
    let reply = api.get(&format!("/nodes/{node}"));
    let status = reply.status;
    let body = if status == 200 {
        reply.json()
    } else {
        Value::Null
    };
    (status, body)
}

fn process_state(probe: &Probe) -> String {
    probe.status()["process"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn exists(path: &Path) -> bool {
    path.exists()
}

#[test]
fn a_probe_enrols_connects_and_delivers_observations() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    let token = controller.token();
    let enrolled = probe.enrol(&controller, &token, &controller.fingerprint);
    enrolled
        .assert_code(0)
        .assert_stdout_contains("enrolled as node 1001 (probe-dmz) with role(s) probe")
        .assert_stdout_contains(&format!("localhost:{}", controller.cluster_port));
    assert!(exists(&probe.identity_path()));

    let mut node = probe.serve();
    node.wait_stdout_line(WAIT, |line| line.contains("node 1001 (probe-dmz) running"))
        .unwrap_or_else(|| panic!("the node did not start\n{}", node.diagnostics()));
    node.wait_stderr_line(WAIT, |line| line.contains("connected to the controller"))
        .unwrap_or_else(|| panic!("the node did not connect\n{}", node.diagnostics()));

    let api = controller.api();
    wait_until(
        "the controller to see the node connected",
        || node_view(&api, 1001).1["connected"] == true,
        || node.diagnostics(),
    );
    let (_, view) = node_view(&api, 1001);
    assert_eq!(view["name"], "probe-dmz");
    assert_eq!(view["roles"], serde_json::json!(["probe"]));
    assert_eq!(view["address"], "192.0.2.20");
    assert_eq!(view["protocol"]["agreed"], 1);
    let list = api.get("/nodes").expect(200);
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    // The summary of the status is refreshed every few seconds.
    wait_until(
        "the status to count the node and its connection",
        || {
            let status = api.get("/system/status").expect(200);
            status["cluster"]["nodes"] == 1 && status["cluster"]["connected"] == 1
        },
        || node.diagnostics(),
    );
    let status = api.get("/system/status").expect(200);
    assert_eq!(
        status["cluster"]["versions"][serve_support::VERSION],
        1,
        "{status}"
    );

    let checked = run(probe.command(&["node", "status", "--check"]), None);
    checked
        .assert_code(0)
        .assert_stdout_contains("check: connected")
        .assert_stdout_contains("node process: connected");

    probe.inject().assert_code(0);
    wait_until(
        "the batch to reach the reconciler",
        || facts(&api, 1001).len() == 2,
        || node.diagnostics(),
    );
    for action in ["cluster.enrolment.create", "cluster.node.enrol"] {
        let audit = api.get(&format!("/audit?action={action}")).expect(200);
        assert!(
            audit["items"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "no {action} record: {audit}"
        );
    }

    let stopped = node.stop();
    stopped
        .assert_code(0)
        .assert_stderr_contains("tenko node stopped");
    assert_eq!(process_state(&probe), "stopped");
    controller.stop();
}

#[test]
fn a_wrong_fingerprint_is_refused_and_a_token_works_once() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    let token = controller.token();
    let wrong = "ab".repeat(32);
    let refused = probe.enrol(&controller, &token, &wrong);
    refused
        .assert_code(9)
        .assert_stderr_contains("do not trust it");
    assert!(
        !exists(&probe.identity_path()),
        "a refused enrolment wrote files"
    );

    // The token was not presented, so it still works once.
    probe
        .enrol(&controller, &token, &controller.fingerprint)
        .assert_code(0);
    let second = Probe::new();
    let again = second.enrol(&controller, &token, &controller.fingerprint);
    again
        .assert_code(6)
        .assert_stderr_contains("cluster.enrolment.used");
    assert!(!exists(&second.identity_path()));

    // An enrolled node does not enrol again by accident.
    let twice = probe.enrol(&controller, &controller.token(), &controller.fingerprint);
    twice.assert_code(2).assert_stderr_contains("--force");
    controller.stop();
}

#[test]
fn an_unenrolled_probe_node_does_not_start() {
    let probe = Probe::new();
    let served = run(probe.command(&["serve", "--roles", "probe"]), None);
    served
        .assert_code(3)
        .assert_stderr_contains("cluster.node.not_enrolled");
    assert!(!probe.data_dir().exists(), "the data directory was created");
}

#[test]
fn the_buffer_replays_after_the_controller_restarts() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    probe
        .enrol(&controller, &controller.token(), &controller.fingerprint)
        .assert_code(0);
    let mut node = probe.serve();
    node.wait_stderr_line(WAIT, |line| line.contains("connected to the controller"))
        .unwrap_or_else(|| panic!("the node did not connect\n{}", node.diagnostics()));

    controller.stop();
    wait_until(
        "the node to notice the outage",
        || process_state(&probe) != "connected",
        || node.diagnostics(),
    );
    probe.inject().assert_code(0);
    wait_until(
        "the batch to wait in the buffer",
        || probe.status()["process"]["buffer"]["batches"] == 1,
        || node.diagnostics(),
    );

    controller.restart();
    let api = controller.api();
    wait_until(
        "the replay",
        || facts(&api, 1001).len() == 2,
        || node.diagnostics(),
    );
    wait_until(
        "the buffer to empty",
        || probe.status()["process"]["buffer"]["batches"] == 0,
        || node.diagnostics(),
    );
    node.stop().assert_code(0);
    controller.stop();
}

#[test]
fn revocation_closes_the_connection() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    probe
        .enrol(&controller, &controller.token(), &controller.fingerprint)
        .assert_code(0);
    let mut node = probe.serve();
    let api = controller.api();
    wait_until(
        "the node to connect",
        || node_view(&api, 1001).1["connected"] == true,
        || node.diagnostics(),
    );

    api.delete("/nodes/1001", None).expect(204);
    node.wait_stderr_line(WAIT, |line| line.contains("cluster.node.revoked"))
        .unwrap_or_else(|| {
            panic!(
                "the node did not learn it was revoked\n{}",
                node.diagnostics()
            )
        });
    wait_until(
        "the node process to report the revocation",
        || process_state(&probe) == "revoked",
        || node.diagnostics(),
    );
    assert_eq!(node_view(&api, 1001).0, 404);
    let checked = run(probe.command(&["node", "status", "--check"]), None);
    checked
        .assert_code(7)
        .assert_stdout_contains("cluster.node.revoked");
    node.stop().assert_code(0);
    controller.stop();
}

#[test]
fn a_controller_of_another_installation_is_refused() {
    let mut home = Controller::start();
    let mut foreign = Controller::start();
    assert_ne!(home.fingerprint, foreign.fingerprint);
    let probe = Probe::new();
    probe
        .enrol(&home, &home.token(), &home.fingerprint)
        .assert_code(0);

    // Point the node at the other controller's cluster port.
    let path = probe.identity_path();
    let mut identity: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("identity")).expect("JSON");
    identity["endpoints"] = serde_json::json!([format!("localhost:{}", foreign.cluster_port)]);
    std::fs::write(&path, serde_json::to_vec_pretty(&identity).expect("JSON")).expect("write");
    let checked = run(probe.command(&["node", "status", "--check"]), None);
    checked
        .assert_code(7)
        .assert_stdout_contains("cluster.tls.foreign_ca");

    // Enrolling with the other controller's token but this controller's fingerprint fails
    // before the token is presented.
    let other = Probe::new();
    other
        .enrol(&foreign, &foreign.token(), &home.fingerprint)
        .assert_code(9);
    home.stop();
    foreign.stop();
}
