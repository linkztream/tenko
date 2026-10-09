//! Installation from the UI on a single native node, against the real binary (OPS-24): a
//! mock release source serves a manifest and the release file; the test is the service
//! manager that starts the server again when it exits with status 12.
//!
//! The release is this same build installed as version 0.0.2: debug builds started with
//! `TENKO_TEST_VERSION_FROM_LAYOUT=1` take their version from the layout directory they run
//! from. Release builds ignore the variable.

#![cfg_attr(
    feature = "release-signatures",
    allow(
        dead_code,
        reason = "the install flows do not run while signatures are required"
    )
)]

mod serve_support;

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, run, wait_for_setup_token};
use sha2::{Digest as _, Sha256};
use tenko_api::dto::release::current_platform;

/// The version the test installs.
const NEW: &str = "0.0.2";

/// How long an install may take until the server exits for its restart.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(120);

fn binary_name() -> &'static str {
    if cfg!(windows) { "tenko.exe" } else { "tenko" }
}

fn asset_name() -> String {
    let extension = if cfg!(windows) { ".exe" } else { "" };
    format!("tenko-{NEW}-{}{extension}", current_platform())
}

/// A release source on the loopback interface: `/releases.json` and the release file.
struct ReleaseSource {
    port: u16,
}

impl ReleaseSource {
    fn start(manifest: Vec<u8>, file: Arc<Vec<u8>>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the release source");
        let port = listener.local_addr().expect("address").port();
        let manifest = Arc::new(manifest);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (manifest, file) = (Arc::clone(&manifest), Arc::clone(&file));
                thread::spawn(move || serve_one(stream, &manifest, &file));
            }
        });
        Self { port }
    }

    fn manifest_url(&self) -> String {
        format!("http://127.0.0.1:{}/releases.json", self.port)
    }
}

fn serve_one(mut stream: TcpStream, manifest: &[u8], file: &[u8]) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_or(true, |read| read == 0) || line == "\r\n" {
            break;
        }
    }
    let path = request.split_whitespace().nth(1).unwrap_or_default();
    let (status, body, kind) = if path == "/releases.json" {
        ("200 OK", manifest, "application/json")
    } else if path == format!("/{}", asset_name()) {
        ("200 OK", file, "application/octet-stream")
    } else {
        ("404 Not Found", &b"not found"[..], "text/plain")
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// The manifest that offers this build as version 0.0.2.
fn manifest(file: &[u8]) -> Vec<u8> {
    let sha256 = Sha256::digest(file)
        .iter()
        .fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
    let document = json!({
        "schema": 1,
        "project": "tenko",
        "releases": [{
            "version": NEW,
            "date": "2026-10-10",
            "notes": "### Fixed\n\n- A release for the install test.",
            "security": true,
            "assets": [{
                "platform": current_platform(),
                "name": asset_name(),
                "url": asset_name(),
                "sha256": sha256,
                "size": file.len(),
            }],
        }],
    });
    serde_json::to_vec_pretty(&document).expect("JSON")
}

/// The binary the service manager starts: `<data_dir>/updates/current/tenko`.
fn current_binary(node: &Node) -> PathBuf {
    node.data_dir()
        .join("updates")
        .join("current")
        .join(binary_name())
}

fn current_version(node: &Node) -> String {
    let target = std::fs::read_link(node.data_dir().join("updates").join("current"))
        .expect("the current link");
    target
        .file_name()
        .expect("a version directory")
        .to_string_lossy()
        .into_owned()
}

/// `tenko serve` from the layout, as the service manager runs it.
fn serve_from_layout(node: &Node) -> Proc {
    let mut command = Command::new(current_binary(node));
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("TENKO_")
            || matches!(
                upper.as_str(),
                "RUST_LOG" | "NOTIFY_SOCKET" | "INVOCATION_ID" | "HTTP_PROXY" | "HTTPS_PROXY"
            )
        {
            command.env_remove(&name);
        }
    }
    command
        .env("TENKO_SUPERVISED", "1")
        .env("TENKO_TEST_VERSION_FROM_LAYOUT", "1")
        .arg("serve")
        .arg("--config")
        .arg(node.config_path())
        .arg("--stop-on-eof");
    Proc::spawn(command)
}

#[track_caller]
fn wait_ready(server: &Proc) {
    assert!(
        server
            .wait_stdout_line(serve_support::READY_TIMEOUT, |line| line
                .contains(" ready at "))
            .is_some(),
        "the server did not become ready\n{}",
        server.diagnostics()
    );
}

/// A node that runs from the layout with the release source configured, signed in.
fn installed_node(source: &ReleaseSource) -> (Node, Proc, Api) {
    let node = Node::new();
    let mut layout = serve_support::tenko();
    layout
        .args(["upgrade", "layout", "--data-dir"])
        .arg(node.data_dir());
    let outcome = run(layout, None);
    outcome
        .assert_code(0)
        .assert_stdout_contains("created the layout");
    let config = format!(
        "{}\n[updates]\nsource_url = \"{}\"\nready_timeout_secs = 60\n",
        node.config_text(),
        source.manifest_url()
    );
    std::fs::write(node.config_path(), config).expect("write tenko.toml");
    let server = serve_from_layout(&node);
    wait_ready(&server);
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    (node, server, api)
}

/// Checks the source and starts the install of 0.0.2; returns the job id.
fn install(api: &Api) -> String {
    // A new manifest is one event on the `admin` topic, which the UI's notice follows.
    let mut events = api.events("topics=admin");
    let status = api.post("/system/updates/check", &json!({})).ok();
    let event = events.next_matching(Duration::from_secs(30), |event| event.event == "admin");
    assert!(event.is_some(), "no admin event for the new manifest");
    assert_eq!(status["running"], "0.0.1", "{status}");
    assert_eq!(status["latest"], NEW, "{status}");
    assert_eq!(status["update_available"], true);
    assert_eq!(status["security"], true);
    assert_eq!(status["install"]["policy"], "ui");
    assert_eq!(
        status["install"]["from_source"], true,
        "{}",
        status["install"]
    );
    let notes = status["releases"][0]["notes"].as_str().unwrap_or_default();
    assert!(notes.contains("install test"), "{notes}");
    let started = api
        .post("/system/updates/install", &json!({ "version": NEW }))
        .expect(202);
    assert_eq!(started["version"], NEW);
    started["job_id"].as_str().expect("a job id").to_owned()
}

#[track_caller]
fn wait_for_audit(api: &Api, action: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let audit = api.get(&format!("/audit?action={action}")).ok();
        if let Some(item) = audit["items"].as_array().and_then(|items| items.first()) {
            return item.clone();
        }
        assert!(Instant::now() < deadline, "no audit record {action}");
        thread::sleep(Duration::from_millis(200));
    }
}

fn exits_for_restart(server: &mut Proc) {
    let outcome = server.finish(INSTALL_TIMEOUT);
    assert_eq!(
        outcome.code,
        Some(12),
        "the server exits with status 12 to be restarted\n{}",
        outcome.diagnostics()
    );
}

fn release_file() -> Arc<Vec<u8>> {
    Arc::new(std::fs::read(env!("CARGO_BIN_EXE_tenko")).expect("the binary"))
}

// With the feature `release-signatures` (on in `--all-features` runs) no release installs
// until signing exists (API-19); the last test covers that case instead.
#[cfg(not(feature = "release-signatures"))]
#[test]
fn a_release_is_installed_from_the_ui_and_confirmed() {
    let file = release_file();
    let source = ReleaseSource::start(manifest(&file), Arc::clone(&file));
    let (node, mut server, api) = installed_node(&source);
    let job = install(&api);
    exits_for_restart(&mut server);
    assert_eq!(current_version(&node), NEW);
    assert!(
        node.data_dir()
            .join("updates")
            .join(NEW)
            .join("release.json")
            .is_file()
    );

    // The service manager starts the new version, which confirms itself once ready.
    let mut server = serve_from_layout(&node);
    wait_ready(&server);
    let mut api = Api::new(&node);
    api.login_password();
    let status = api.get("/system/updates").ok();
    assert_eq!(status["running"], NEW, "{status}");
    assert_eq!(status["update_available"], false);
    assert_eq!(status["attempt"]["state"], "confirmed", "{status}");
    assert_eq!(status["attempt"]["from"], "0.0.1");
    assert_eq!(status["attempt"]["job_id"], job.as_str());
    let finished = api.get(&format!("/jobs/{job}")).ok();
    assert_eq!(finished["job"]["state"], "succeeded", "{finished}");
    let record = wait_for_audit(&api, "sys.update.confirm");
    assert_eq!(record["draft"]["details"]["context"]["to"], NEW, "{record}");
    // What is new for the administrator: they saw nothing before, so nothing is shown.
    let whats_new = api.get("/system/updates/whats-new").ok();
    assert_eq!(whats_new["running"], NEW);
    assert_eq!(whats_new["show"], false);
    server.stop().assert_code(0);
}

#[cfg(not(feature = "release-signatures"))]
#[test]
fn a_release_that_does_not_start_is_switched_back() {
    let file = release_file();
    let source = ReleaseSource::start(manifest(&file), Arc::clone(&file));
    let (node, mut server, api) = installed_node(&source);
    install(&api);
    exits_for_restart(&mut server);
    assert_eq!(current_version(&node), NEW);

    // The new version cannot bind its port: it switches back and asks for a restart.
    let blocker = TcpListener::bind(("127.0.0.1", node.port)).expect("hold the server port");
    let mut failing = serve_from_layout(&node);
    let outcome = failing.finish(serve_support::READY_TIMEOUT);
    assert_eq!(outcome.code, Some(12), "{}", outcome.diagnostics());
    assert!(
        outcome
            .stderr
            .contains("switched back to the previous version"),
        "{}",
        outcome.diagnostics()
    );
    drop(blocker);
    assert_eq!(current_version(&node), "0.0.1");

    let mut server = serve_from_layout(&node);
    wait_ready(&server);
    let mut api = Api::new(&node);
    api.login_password();
    let status = api.get("/system/updates").ok();
    assert_eq!(status["running"], "0.0.1", "{status}");
    assert_eq!(status["attempt"]["state"], "rolled_back", "{status}");
    assert_eq!(status["attempt"]["reason"], "start.api.bind", "{status}");
    assert_eq!(
        status["update_available"], true,
        "the release is still offered"
    );
    let record = wait_for_audit(&api, "sys.update.rollback");
    assert_eq!(
        record["draft"]["details"]["context"]["reason"],
        "start.api.bind"
    );
    server.stop().assert_code(0);
}

#[test]
fn a_release_with_the_wrong_checksum_is_not_switched_to() {
    let file = release_file();
    let mut manifest: Value = serde_json::from_slice(&manifest(&file)).expect("JSON");
    manifest["releases"][0]["assets"][0]["sha256"] = json!("0".repeat(64));
    let source = ReleaseSource::start(serde_json::to_vec(&manifest).expect("JSON"), file);
    let (node, mut server, api) = installed_node(&source);
    let job = install(&api);
    let finished = api.wait_for_job(&job, INSTALL_TIMEOUT);
    assert_eq!(finished["job"]["state"], "rolled_back", "{finished}");
    assert_eq!(
        finished["job"]["error"]["code"], "update.checksum_mismatch",
        "{finished}"
    );
    assert_eq!(current_version(&node), "0.0.1");
    assert!(server.is_running(), "a failed install does not restart");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let status = api.get("/system/updates").ok();
        if status["attempt"]["state"] == "failed" || Instant::now() > deadline {
            break status;
        }
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(status["attempt"]["state"], "failed", "{status}");
    assert_eq!(
        status["attempt"]["reason"], "update.checksum_mismatch",
        "{status}"
    );
    assert!(
        !node
            .data_dir()
            .join("updates")
            .join(NEW)
            .join(binary_name())
            .exists(),
        "a file that does not match is not kept"
    );
    server.stop().assert_code(0);
}

#[cfg(feature = "release-signatures")]
#[test]
fn without_verifiable_signatures_no_release_is_installed() {
    let file = release_file();
    let source = ReleaseSource::start(manifest(&file), Arc::clone(&file));
    let (node, mut server, api) = installed_node(&source);
    let job = install(&api);
    let finished = api.wait_for_job(&job, INSTALL_TIMEOUT);
    assert_eq!(finished["job"]["state"], "rolled_back", "{finished}");
    assert_eq!(
        finished["job"]["error"]["code"], "update.signature_unverified",
        "{finished}"
    );
    assert_eq!(current_version(&node), "0.0.1");
    assert!(server.is_running(), "a refused release does not restart");
    server.stop().assert_code(0);
}
