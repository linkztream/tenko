//! `tenko plugin` against the real binary: the bundled sample plugin passes the conformance
//! suite when the host starts it as `tenko plugin run sample`, exactly like a third-party
//! plugin, and the list shows it; and a running server runs a sample connector created
//! through the API, as its own supervised process, and stops it with the server.

mod serve_support;

use std::{process::Command, time::Duration};

use serde_json::json;
use serve_support::{Node, api::Api, wait_for_setup_token};

fn tenko() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tenko"));
    command.env_remove("TENKO_CONFIG");
    command
}

#[test]
fn the_bundled_sample_passes_the_conformance_suite() {
    let output = tenko()
        .args([
            "plugin",
            "test",
            "--bundled",
            "sample",
            "--json",
            "--timeout",
            "10",
        ])
        .output()
        .expect("tenko runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("a JSON report");
    assert_eq!(report["plugin"], "sample");
    let checks = report["checks"].as_array().expect("checks");
    assert!(checks.len() >= 12, "{stdout}");
    assert!(
        checks.iter().all(|check| check["outcome"] == "pass"),
        "{stdout}"
    );
}

#[test]
fn the_list_shows_the_bundled_sample() {
    let dir = tempfile::tempdir().expect("dir");
    let output = tenko()
        .args(["plugin", "list", "--plugins-dir"])
        .arg(dir.path())
        .output()
        .expect("tenko runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("sample") && line.contains("bundled")),
        "{stdout}"
    );
}

#[test]
fn an_unknown_bundled_plugin_is_a_usage_error() {
    let output = tenko()
        .args(["plugin", "run", "no-such-plugin"])
        .output()
        .expect("tenko runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no bundled plugin"));
}

#[test]
fn a_server_runs_a_sample_connector_created_through_the_api() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);

    let plugins = api.get("/connectors/plugins").ok();
    assert_eq!(plugins["items"][0]["name"], "sample", "{plugins}");
    let created = api
        .post(
            "/connectors",
            &json!({ "plugin": "sample", "name": "Lab sample", "settings": { "hosts": 5 } }),
        )
        .expect(201);
    let id = created["id"].as_str().expect("id").to_owned();

    let mut state = String::new();
    for _ in 0..100 {
        let view = api.get(&format!("/connectors/{id}")).ok();
        state = view["health"]["process"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if state == "running" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(state, "running");

    let run = api
        .post(&format!("/connectors/{id}/run"), &json!({}))
        .expect(202);
    let job = run["job"].as_str().expect("job").to_owned();
    let detail = api.wait_for_job(&job, Duration::from_secs(60));
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");
    let view = api.get(&format!("/connectors/{id}")).ok();
    assert_eq!(view["last_run"]["outcome"], "succeeded", "{view}");
    assert_eq!(view["last_run"]["observations"], 5, "{view}");

    let check = api
        .post(&format!("/connectors/{id}/check"), &json!({}))
        .ok();
    assert_eq!(check["health"], "healthy", "{check}");

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    outcome.assert_stderr_contains("plugin started");
    outcome.assert_stderr_contains("connector plugins stopped");
}
