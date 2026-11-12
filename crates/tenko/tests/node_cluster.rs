//! Black-box tests of the node transport with the real binary: a controller (`tenko serve`
//! with the internal CA and a cluster port on the loopback) and a probe node (`tenko node
//! enroll`, then `tenko serve --roles probe`) as separate processes, each with its own data
//! directory. They cover enrollment end to end, a wrong CA fingerprint, single-use tokens,
//! the node process heartbeating and delivering a batch to the reconciler, the buffer
//! replaying after the controller restarts, revocation closing the connection, and a
//! controller of another installation being refused. Version negotiation and expiry are
//! covered in-process by `crates/tenko-cluster/tests/transport.rs`.

mod serve_support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::Value;
use serve_support::{Node, Outcome, Proc, Transport, api::Api, run, tenko};
use tempfile::TempDir;
use tenko_core::testing::{free_port, wait_until_within};

/// How long a node may take to connect, to deliver or to notice something.
const WAIT: Duration = Duration::from_secs(90);

/// A batch the node injects: two documentation addresses seen by ARP. Its times are a few seconds before
/// now, so that no purge or age window of the controller treats it as old whatever the
/// calendar says.
fn batch() -> String {
    let now = tenko_core::Timestamp::now();
    let ago = |secs: u64| {
        now.checked_sub(Duration::from_secs(secs))
            .expect("a time before now")
    };
    format!(
        r#"{{
  "method": "arp",
  "complete": false,
  "collected_at": "{}",
  "sightings": [
    {{"observed_at": "{}",
     "subject": {{"type": "address", "data": {{"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}}}}},
    {{"observed_at": "{}",
     "subject": {{"type": "address", "data": {{"ip": "192.0.2.31"}}}}}}
  ]
}}"#,
        ago(5),
        ago(9),
        ago(8)
    )
}

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
        let cluster_port = free_port().release();
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

    /// A new enrollment token for a probe, through `tenko node enroll-token`.
    fn token(&self) -> String {
        let created = self
            .node
            .client(&["node", "enroll-token", "--roles", "probe", "--json"]);
        created.assert_code(0);
        let body = created.json();
        assert_eq!(body["ca_fingerprint"], self.fingerprint.as_str());
        assert!(
            body["command"]
                .as_str()
                .is_some_and(|command| command.starts_with("tenko node enroll --controller")),
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

    /// `tenko node enroll` with the token, `--ca-fingerprint` when given, and further
    /// arguments.
    fn enroll(&self, controller: &Controller, token: &str, fingerprint: Option<&str>) -> Outcome {
        let url = controller.url();
        let mut args = vec!["node", "enroll", "--controller", &url, "--token", token];
        if let Some(fingerprint) = fingerprint {
            args.extend(["--ca-fingerprint", fingerprint]);
        }
        args.extend(["--name", "probe-dmz", "--address", "192.0.2.20"]);
        run(self.command(&args), None)
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
        std::fs::write(&file, batch()).expect("write the batch");
        run(
            self.command(&["node", "inject", "--file", file.to_str().expect("UTF-8")]),
            None,
        )
    }

    fn identity_path(&self) -> PathBuf {
        self.data_dir().join("node").join("identity.json")
    }
}

/// Waits until `check` holds; a timeout shows the output of `server`.
#[track_caller]
fn wait_for_state(server: &Proc, what: &str, mut check: impl FnMut() -> bool) {
    wait_until_within(what, WAIT, || {
        if check() {
            Ok(())
        } else {
            Err(server.diagnostics())
        }
    });
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
fn a_probe_enrolls_connects_and_delivers_observations() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    let token = controller.token();
    // The token carries the CA fingerprint: no flag, and no trust on first use.
    assert!(token.starts_with("tnk2."), "{token}");
    let enrolled = probe.enroll(&controller, &token, None);
    assert!(
        !enrolled.stderr.contains("warning"),
        "a tnk2 token warned: {}",
        enrolled.stderr
    );
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
    wait_for_state(&node, "the controller to see the node connected", || {
        node_view(&api, 1001).1["connected"] == true
    });
    let (_, view) = node_view(&api, 1001);
    assert_eq!(view["name"], "probe-dmz");
    assert_eq!(view["roles"], serde_json::json!(["probe"]));
    assert_eq!(view["address"], "192.0.2.20");
    assert_eq!(view["protocol"]["agreed"], 1);
    let list = api.get("/nodes").expect(200);
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    // The summary of the status is refreshed every few seconds.
    wait_for_state(
        &node,
        "the status to count the node and its connection",
        || {
            let status = api.get("/system/status").expect(200);
            status["cluster"]["nodes"] == 1 && status["cluster"]["connected"] == 1
        },
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
    wait_for_state(&node, "the batch to reach the reconciler", || {
        facts(&api, 1001).len() == 2
    });
    for action in ["cluster.enrollment.create", "cluster.node.enroll"] {
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
    // A flag that disagrees with the token's fingerprint stops before the network.
    let refused = probe.enroll(&controller, &token, Some(&wrong));
    refused
        .assert_code(9)
        .assert_stderr_contains("must agree")
        .assert_stderr_contains("abababab");
    // A token of 0.0.11 (no fingerprint) is checked against the flag, as before.
    let (tnk1, _) = token.rsplit_once('.').expect("four parts");
    let tnk1 = tnk1.replacen("tnk2.", "tnk1.", 1);
    let refused = probe.enroll(&controller, &tnk1, Some(&wrong));
    refused
        .assert_code(9)
        .assert_stderr_contains("do not trust it");
    assert!(
        !exists(&probe.identity_path()),
        "a refused enrollment wrote files"
    );

    // The token was not presented, so it still works once: in the format of 0.0.11 and
    // without the flag it is trusted on first use, with the warning.
    let first_use = probe.enroll(&controller, &tnk1, None);
    first_use
        .assert_code(0)
        .assert_stderr_contains("warning: the token carries no CA fingerprint")
        .assert_stderr_contains(&controller.fingerprint);
    let second = Probe::new();
    let again = second.enroll(&controller, &token, Some(&controller.fingerprint));
    again
        .assert_code(6)
        .assert_stderr_contains("cluster.enrollment.used");
    assert!(!exists(&second.identity_path()));

    // An enrolled node does not enroll again by accident.
    let twice = probe.enroll(&controller, &controller.token(), None);
    twice.assert_code(2).assert_stderr_contains("--force");
    controller.stop();
}

#[test]
fn the_token_variable_of_0_0_11_is_still_read() {
    let probe = Probe::new();
    let enroll = |old: Option<&str>| {
        let mut command = probe.command(&["node", "enroll", "--controller", "https://127.0.0.1:9"]);
        command.env_remove("TENKO_ENROLL_TOKEN");
        command.env_remove("TENKO_ENROL_TOKEN"); // spelling: alias until 0.0.13
        if let Some(token) = old {
            command.env("TENKO_ENROL_TOKEN", token); // spelling: alias until 0.0.13
        }
        run(command, None)
    };
    enroll(None)
        .assert_code(2)
        .assert_stderr_contains("no enrollment token");
    // The old name is read: the token it carries is parsed (and refused for its form).
    enroll(Some("not-a-token"))
        .assert_code(2)
        .assert_stderr_contains("copy the token exactly");
    assert!(!exists(&probe.identity_path()));
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
        .enroll(&controller, &controller.token(), None)
        .assert_code(0);
    let mut node = probe.serve();
    node.wait_stderr_line(WAIT, |line| line.contains("connected to the controller"))
        .unwrap_or_else(|| panic!("the node did not connect\n{}", node.diagnostics()));

    controller.stop();
    wait_for_state(&node, "the node to notice the outage", || {
        process_state(&probe) != "connected"
    });
    probe.inject().assert_code(0);
    wait_for_state(&node, "the batch to wait in the buffer", || {
        probe.status()["process"]["buffer"]["batches"] == 1
    });

    controller.restart();
    let api = controller.api();
    wait_for_state(&node, "the replay", || facts(&api, 1001).len() == 2);
    wait_for_state(&node, "the buffer to empty", || {
        probe.status()["process"]["buffer"]["batches"] == 0
    });
    node.stop().assert_code(0);
    controller.stop();
}

#[test]
fn revocation_closes_the_connection() {
    let mut controller = Controller::start();
    let probe = Probe::new();
    probe
        .enroll(&controller, &controller.token(), None)
        .assert_code(0);
    let mut node = probe.serve();
    let api = controller.api();
    wait_for_state(&node, "the node to connect", || {
        node_view(&api, 1001).1["connected"] == true
    });

    api.delete("/nodes/1001", None).expect(204);
    node.wait_stderr_line(WAIT, |line| line.contains("cluster.node.revoked"))
        .unwrap_or_else(|| {
            panic!(
                "the node did not learn it was revoked\n{}",
                node.diagnostics()
            )
        });
    wait_for_state(&node, "the node process to report the revocation", || {
        process_state(&probe) == "revoked"
    });
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
    probe.enroll(&home, &home.token(), None).assert_code(0);

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
        .enroll(&foreign, &foreign.token(), Some(&home.fingerprint))
        .assert_code(9)
        .assert_stderr_contains("must agree");
    // A token taken to the wrong controller stops at that controller's CA root, naming the
    // first characters of both fingerprints.
    other
        .enroll(&home, &foreign.token(), None)
        .assert_code(9)
        .assert_stderr_contains("but the token names")
        .assert_stderr_contains(&home.fingerprint[..8])
        .assert_stderr_contains(&foreign.fingerprint[..8]);
    assert!(!exists(&other.identity_path()));
    home.stop();
    foreign.stop();
}
