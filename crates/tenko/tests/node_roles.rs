//! The roles of a node against the real binary (OPS-01): the file's roles seed the stored
//! set, a change through `PUT /nodes/{id}/roles` makes a supervised server stop with exit
//! status 12 and the next start runs the stored set, an unsupervised server waits for a
//! restart by hand, `--roles` pins the roles, and the probe role switched on at runtime is
//! in the system status once the restart applies it.
//!
//! The servers run without the variables a service manager passes on (`INVOCATION_ID`,
//! `JOURNAL_STREAM`, `NOTIFY_SOCKET`), so that only `TENKO_SUPERVISED=1` decides whether a
//! server counts as supervised. The dhcp role is the one switched: without `[dhcp] listen`
//! it builds its tables and opens no port.

mod serve_support;

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, wait_for_setup_token};

/// How long a supervised server may take to stop by itself after a role change.
const RESTART_TIMEOUT: Duration = Duration::from_secs(60);

/// Starts the node, supervised when `supervised`, with `args` after `serve`.
#[track_caller]
fn start(node: &mut Node, supervised: bool, args: &[&str]) -> Proc {
    node.start_by(|node| {
        node.write_config();
        let mut command = node.serve_command();
        command.args(args);
        for name in [
            "INVOCATION_ID",
            "JOURNAL_STREAM",
            "NOTIFY_SOCKET",
            "TENKO_SUPERVISED",
        ] {
            command.env_remove(name);
        }
        if supervised {
            command.env("TENKO_SUPERVISED", "1");
        }
        Proc::spawn(command)
    })
}

/// The node id of the server, from its status.
fn own_id(api: &Api) -> u64 {
    api.get("/system/status").ok()["node"]["id"]
        .as_u64()
        .expect("node id")
}

/// The roles of the node once its stored set is seeded.
fn seeded(api: &Api, id: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let roles = api.get(&format!("/nodes/{id}/roles")).ok();
        if roles["stored"] == true {
            return roles;
        }
        assert!(Instant::now() < deadline, "never seeded: {roles}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn warning_codes(api: &Api) -> Vec<String> {
    api.get("/system/status").ok()["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|warning| warning["code"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn a_supervised_server_restarts_itself_to_apply_its_roles() {
    let mut node = Node::new();
    let mut server = start(&mut node, true, &[]);
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    let id = own_id(&api);

    // The file's roles are the stored set from the first start.
    let before = seeded(&api, id);
    assert_eq!(before["configured"], json!(["controller"]));
    assert_eq!(before["running"], json!(["controller"]));
    assert_eq!(before["origin"], "seed");
    assert_eq!(before["pinned"], false);
    assert_eq!(before["restart"], "none");

    let changed = api
        .put(
            &format!("/nodes/{id}/roles"),
            &json!({ "roles": ["controller", "dhcp"] }),
        )
        .ok();
    assert_eq!(changed["configured"], json!(["controller", "dhcp"]));
    assert_eq!(changed["running"], json!(["controller"]));
    assert_eq!(changed["restart"], "scheduled");
    let cookie = api.cookie().map(str::to_owned);
    let outcome = server.finish(RESTART_TIMEOUT);
    assert_eq!(
        outcome.code,
        Some(12),
        "the server stops for its restart\n{}",
        outcome.diagnostics()
    );
    assert!(
        outcome
            .stderr
            .contains("the roles of this node changed to controller,dhcp"),
        "{}",
        outcome.diagnostics()
    );

    // The supervisor starts it again: the stored set decides over the file's.
    let mut server = start(&mut node, true, &[]);
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    let after = api.get(&format!("/nodes/{id}/roles")).ok();
    assert_eq!(after["running"], json!(["controller", "dhcp"]));
    assert_eq!(after["restart"], "none");
    let status = api.get("/system/status").ok();
    let roles = status["node"]["roles"].as_array().expect("roles");
    assert!(roles.contains(&json!("dhcp")), "{status}");
    let audit = api.get("/audit?action=nodes.roles").ok();
    assert_eq!(
        audit["items"].as_array().expect("items").len(),
        1,
        "{audit}"
    );
    server.stop().assert_code(0);
}

#[test]
fn an_unsupervised_server_waits_and_roles_on_the_command_line_pin() {
    let mut node = Node::new();
    let mut server = start(&mut node, false, &[]);
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    let id = own_id(&api);
    seeded(&api, id);

    let changed = api
        .put(
            &format!("/nodes/{id}/roles"),
            &json!({ "roles": ["controller", "dhcp"] }),
        )
        .ok();
    assert_eq!(changed["restart"], "required");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !warning_codes(&api).contains(&"node.roles.restart_required".to_owned()) {
        assert!(Instant::now() < deadline, "no restart notice");
        std::thread::sleep(Duration::from_millis(100));
    }
    let cookie = api.cookie().map(str::to_owned);
    server.stop().assert_code(0);

    // `--roles` pins the roles: the stored set is not used and cannot be changed.
    let mut server = start(&mut node, false, &["--roles", "controller"]);
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    let pinned = api.get(&format!("/nodes/{id}/roles")).ok();
    assert_eq!(pinned["pinned"], true);
    assert_eq!(pinned["running"], json!(["controller"]));
    assert_eq!(pinned["configured"], json!(["controller", "dhcp"]));
    assert_eq!(pinned["restart"], "none");
    let refused = api.put(
        &format!("/nodes/{id}/roles"),
        &json!({ "roles": ["controller"] }),
    );
    assert_eq!(refused.status, 409, "{}", refused.text);
    assert_eq!(refused.code().as_deref(), Some("node.roles.pinned"));
    server
        .stop()
        .assert_code(0)
        .assert_stderr_contains("roles controller (pinned by --roles)");
}

/// A `[scan]` section over the loopback only, every method that would send to another host
/// switched off, for the node that gets the probe role.
const LOOPBACK_SCAN: &str = "[scan]\n\
     prefixes = [\"127.0.0.1/32\"]\n\
     [scan.icmp]\nenabled = false\n\
     [scan.mdns]\nenabled = false\n\
     [scan.llmnr]\nenabled = false\n\
     [scan.reverse_dns]\nenabled = false\n\
     [scan.tcp_connect]\nports = [9]\ntimeout_ms = 1000\n";

/// The roles `GET /system/status` lists for the node.
fn status_roles(api: &Api) -> Vec<Value> {
    api.get("/system/status").ok()["node"]["roles"]
        .as_array()
        .expect("roles")
        .clone()
}

#[test]
fn the_probe_role_switched_on_at_runtime_is_in_the_status_after_the_restart() {
    let mut node = Node::new().with_config(LOOPBACK_SCAN);
    let mut server = start(&mut node, true, &[]);
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    let id = own_id(&api);
    seeded(&api, id);
    assert!(!status_roles(&api).contains(&json!("probe")));

    // The Nodes page switches the role on: stored at once, run from the next start.
    let changed = api
        .put(
            &format!("/nodes/{id}/roles"),
            &json!({ "roles": ["controller", "probe"] }),
        )
        .ok();
    assert_eq!(changed["configured"], json!(["controller", "probe"]));
    assert_eq!(changed["running"], json!(["controller"]));
    assert_eq!(changed["restart"], "scheduled");
    let cookie = api.cookie().map(str::to_owned);
    let outcome = server.finish(RESTART_TIMEOUT);
    assert_eq!(
        outcome.code,
        Some(12),
        "the server stops for its restart\n{}",
        outcome.diagnostics()
    );

    // After the restart the controller runs the probe in process, and the status lists it.
    let mut server = start(&mut node, true, &[]);
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    let after = api.get(&format!("/nodes/{id}/roles")).ok();
    assert_eq!(after["running"], json!(["controller", "probe"]));
    let roles = status_roles(&api);
    assert!(roles.contains(&json!("controller")), "{roles:?}");
    assert!(roles.contains(&json!("probe")), "{roles:?}");
    let probes = api.get("/scans/probes").ok();
    assert_eq!(probes["items"][0]["node"], json!(id), "{probes}");
    assert_eq!(probes["items"][0]["in_process"], true, "{probes}");
    server.stop().assert_code(0);
}
