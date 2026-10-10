//! Black-box tests of the scanner with the real binary: `tenko node scan` (status, the kill
//! switch, runs on demand with `--dry-run`, refusals), and a probe node whose scanner runs
//! inside `tenko serve --roles probe` and whose on-demand batch reaches the controller's
//! reconciler. Every scan here covers `127.0.0.1/32` only and talks to listeners of the
//! test on the loopback; the methods that would reach a real network (mDNS, LLMNR,
//! reverse DNS) are switched off in the configuration.

mod serve_support;

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use serve_support::{Node, Outcome, Proc, Transport, api::Api, free_port, run, tenko};
use tempfile::TempDir;

/// How long a node may take to connect or to deliver.
const WAIT: Duration = Duration::from_secs(90);

/// A scan configuration over the loopback only: `tcp_connect` on `port`, every method that
/// would send to another host switched off.
fn scan_config(port: u16) -> String {
    format!(
        "[scan]\n\
         prefixes = [\"127.0.0.1/32\"]\n\
         rate = \"unlimited\"\n\
         per_host_interval_ms = 0\n\
         [scan.icmp]\nenabled = false\n\
         [scan.mdns]\nenabled = false\n\
         [scan.llmnr]\nenabled = false\n\
         [scan.reverse_dns]\nenabled = false\n\
         [scan.tcp_connect]\nports = [{port}]\ntargets = \"all\"\ntimeout_ms = 1000\n"
    )
}

/// A TCP listener on the loopback that answers like a TLS server: the head of a recorded
/// `ServerHello`.
fn tls_listener() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut hello = [0u8; 512];
                let _ = stream.read(&mut hello);
                let _ = stream.write_all(&[0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56]);
            });
        }
    });
    port
}

/// A node directory with a configuration file.
struct Site {
    dir: TempDir,
}

impl Site {
    fn new(config: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("tenko-scan-")
            .tempdir()
            .expect("temporary directory");
        std::fs::write(dir.path().join("tenko.toml"), config).expect("write the configuration");
        Self { dir }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = tenko();
        command
            .args(args)
            .arg("--data-dir")
            .arg(self.data_dir())
            .env("TENKO_CONFIG", self.dir.path().join("tenko.toml"));
        command
    }

    fn scan(&self, args: &[&str]) -> Outcome {
        let mut all = vec!["node", "scan"];
        all.extend_from_slice(args);
        run(self.command(&all), None)
    }
}

fn method<'a>(status: &'a Value, name: &str) -> &'a Value {
    status["status"]["methods"]
        .as_array()
        .and_then(|methods| methods.iter().find(|m| m["method"] == name))
        .unwrap_or_else(|| panic!("no method {name} in {status}"))
}

#[test]
fn status_without_a_running_scanner_shows_the_configuration_and_the_host() {
    let site = Site::new(&scan_config(9));
    let status = site.scan(&["status", "--json"]);
    status.assert_code(0);
    let body = status.json();
    assert_eq!(body["running"], false);
    assert_eq!(
        body["status"]["prefixes"],
        serde_json::json!(["127.0.0.1/32"])
    );
    assert_eq!(body["status"]["per_second"], Value::Null, "unlimited");
    assert_eq!(method(&body, "tcp_connect")["state"], "idle");
    assert_eq!(method(&body, "mdns")["state"], "disabled");
    let syn = method(&body, "tcp_syn");
    assert_eq!(syn["state"], "unavailable");
    assert!(
        syn["availability"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("raw sockets")),
        "{syn}"
    );
    let text = site.scan(&["status"]);
    text.assert_code(0)
        .assert_stdout_contains("not running on this node")
        .assert_stdout_contains("prefixes:       127.0.0.1/32")
        .assert_stdout_contains("tcp_connect");
}

#[test]
fn a_dry_run_reports_open_ports_with_the_tls_hint() {
    let port = tls_listener();
    let site = Site::new(&scan_config(port));
    let ran = site.scan(&["run", "tcp-connect", "--dry-run"]);
    ran.assert_code(0)
        .assert_stdout_contains("tcp_connect: complete, 1 sighting(s), 1 probe(s)")
        .assert_stdout_contains(&format!("services 127.0.0.1 {port}/tls"))
        .assert_stdout_contains("dry run: nothing was queued");
    let json = site.scan(&[
        "run",
        "tcp_connect",
        "--dry-run",
        "--json",
        "--target",
        "127.0.0.1",
    ]);
    json.assert_code(0);
    let body = json.json();
    assert_eq!(
        body["run"]["outcome"], "partial",
        "a target makes a run partial"
    );
    assert_eq!(body["batch"]["complete"], false);
    assert_eq!(
        body["batch"]["sightings"][0]["subject"]["data"]["tls_tcp"],
        serde_json::json!([port])
    );
}

#[test]
fn runs_are_refused_outside_the_scope_without_enrolment_and_for_unknown_methods() {
    let site = Site::new(&scan_config(9));
    site.scan(&["run", "ping"])
        .assert_code(2)
        .assert_stderr_contains("not a method");
    site.scan(&["run", "tcp_connect", "--dry-run", "--target", "192.0.2.1"])
        .assert_code(2)
        .assert_stderr_contains("scan.out_of_scope");
    site.scan(&["run", "tcp_connect"])
        .assert_code(2)
        .assert_stderr_contains("not enrolled");
    site.scan(&["run", "mdns", "--dry-run"])
        .assert_code(2)
        .assert_stderr_contains("switched off");
    site.scan(&["run", "tcp_syn", "--dry-run"])
        .assert_code(2)
        .assert_stderr_contains("scan.unavailable");
}

#[test]
fn the_kill_switch_holds_every_run_until_it_is_off() {
    let port = tls_listener();
    let site = Site::new(&scan_config(port));
    site.scan(&["stop", "--reason", "change window"])
        .assert_code(0)
        .assert_stdout_contains("kill switch on");
    assert!(site.data_dir().join("scan").join("stop").exists());
    site.scan(&["run", "tcp_connect", "--dry-run"])
        .assert_code(2)
        .assert_stderr_contains("scan.stopped");
    let status = site.scan(&["status", "--json"]);
    assert_eq!(status.json()["status"]["kill_switch"], true);
    site.scan(&["resume"])
        .assert_code(0)
        .assert_stdout_contains("kill switch off");
    site.scan(&["resume"])
        .assert_code(0)
        .assert_stdout_contains("was not on");
    site.scan(&["run", "tcp_connect", "--dry-run"])
        .assert_code(0);
}

/// A controller with the internal CA and a cluster port on the loopback.
struct Controller {
    node: Node,
    server: Option<Proc>,
    fingerprint: String,
}

impl Controller {
    fn start() -> Self {
        let cluster_port = free_port();
        let mut node = Node::new()
            .with_transport(Transport::InternalCa)
            .with_config(&format!(
                "[cluster]\nlisten = [\"127.0.0.1:{cluster_port}\"]\nheartbeat_secs = 1\n"
            ));
        let server = node.start();
        node.setup_and_login(&server);
        let line = server
            .wait_stdout_line(Duration::from_secs(30), |line| {
                line.contains("SHA-256 fingerprint: ")
            })
            .unwrap_or_else(|| panic!("no fingerprint was printed\n{}", server.diagnostics()));
        let fingerprint = line
            .rsplit(' ')
            .next()
            .expect("fingerprint")
            .trim()
            .to_owned();
        Self {
            node,
            server: Some(server),
            fingerprint,
        }
    }

    fn token(&self) -> String {
        let created = self
            .node
            .client(&["node", "enrol-token", "--roles", "probe", "--json"]);
        created.assert_code(0);
        created.json()["token"].as_str().expect("token").to_owned()
    }

    fn api(&self) -> Api {
        let mut api = Api::new(&self.node);
        api.login_password();
        api
    }

    fn stop(&mut self) {
        if let Some(mut server) = self.server.take() {
            server.stop().assert_graceful_shutdown();
        }
    }
}

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

fn exists(path: &Path) -> bool {
    path.exists()
}

#[test]
fn the_probe_process_runs_the_scanner_and_an_on_demand_batch_reaches_the_controller() {
    let port = tls_listener();
    let mut controller = Controller::start();
    let site = Site::new(&scan_config(port));
    let token = controller.token();
    let url = controller.node.url();
    run(
        site.command(&[
            "node",
            "enrol",
            "--controller",
            &url,
            "--token",
            &token,
            "--ca-fingerprint",
            &controller.fingerprint,
            "--name",
            "probe-lab",
        ]),
        None,
    )
    .assert_code(0);

    let mut command = site.command(&["serve", "--roles", "probe", "--stop-on-eof"]);
    command.env("TENKO_LOG__LEVEL", "info");
    let mut node = Proc::spawn(command);
    node.wait_stderr_line(WAIT, |line| line.contains("scanner started"))
        .unwrap_or_else(|| panic!("the scanner did not start\n{}", node.diagnostics()));
    node.wait_stderr_line(WAIT, |line| line.contains("connected to the controller"))
        .unwrap_or_else(|| panic!("the node did not connect\n{}", node.diagnostics()));
    let status_file = site.data_dir().join("scan").join("status.json");
    wait_until(
        "the scan status file",
        || exists(&status_file),
        || node.diagnostics(),
    );
    let status = site.scan(&["status", "--json"]);
    status.assert_code(0);
    let body = status.json();
    assert_eq!(body["running"], true, "{body}");
    assert_eq!(method(&body, "reverse_dns")["state"], "disabled");

    site.scan(&["run", "tcp_connect"])
        .assert_code(0)
        .assert_stdout_contains("queued for the controller");
    let api = controller.api();
    wait_until(
        "the services fact at the controller",
        || {
            let reply = api.get("/observations?source=probe:1001:tcp_connect");
            reply.status == 200
                && reply.json()["items"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty())
        },
        || node.diagnostics(),
    );
    let facts = api
        .get("/observations?source=probe:1001:tcp_connect")
        .expect(200);
    let fact = &facts["items"][0];
    assert_eq!(fact["subject"]["type"], "services", "{fact}");
    assert_eq!(
        fact["observed"]["data"]["open_tcp"],
        serde_json::json!([port])
    );
    assert_eq!(
        fact["observed"]["data"]["tls_tcp"],
        serde_json::json!([port])
    );
    assert!(
        fact["expires_at"].is_string(),
        "the sighting carries its lifetime"
    );

    let stopped = node.stop();
    stopped
        .assert_code(0)
        .assert_stderr_contains("scanner stopped")
        .assert_stderr_contains("tenko node stopped");
    controller.stop();
}

#[test]
fn a_controller_with_the_probe_role_runs_the_scanner_in_process() {
    let mut node = Node::new()
        .with_args(&["--roles", "controller,probe"])
        .with_config(&scan_config(9));
    let mut server = node.start();
    server
        .wait_stderr_line(WAIT, |line| {
            line.contains("probe role: scanner over 127.0.0.1/32")
        })
        .unwrap_or_else(|| panic!("the scanner did not start\n{}", server.diagnostics()));
    let status_file = node.data_dir().join("scan").join("status.json");
    wait_until(
        "the scan status file",
        || exists(&status_file),
        || server.diagnostics(),
    );
    let status: Value =
        serde_json::from_slice(&std::fs::read(&status_file).expect("read")).expect("status");
    assert_eq!(status["prefixes"], serde_json::json!(["127.0.0.1/32"]));
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    outcome.assert_stderr_contains("scanner stopped");
}

#[test]
fn a_run_whose_batch_cannot_be_queued_fails() {
    let port = tls_listener();
    let site = Site::new(&scan_config(port));
    // An enrolled node whose buffer directory cannot be created: a file is in its way.
    let node = site.data_dir().join("node");
    std::fs::create_dir_all(&node).expect("node directory");
    std::fs::write(node.join("identity.json"), "{}").expect("identity");
    std::fs::write(node.join("buffer"), "not a directory").expect("blocker");
    site.scan(&["run", "tcp_connect"])
        .assert_code(1)
        .assert_stderr_contains("the batch could not be queued");
    let json = site.scan(&["run", "tcp_connect", "--json"]);
    json.assert_code(1);
    assert_eq!(json.json()["queued"], false);
}
