//! The module switch against the real binary (OPS-25): with IPAM off, the IPAM routes
//! answer 404 like unknown paths, import and moves are gone with them, the status reports
//! the running modules, and the installation's choice applies at the next start.

mod serve_support;

use serde_json::json;
use serve_support::{Node, Proc, api::Api, wait_for_setup_token};

/// Writes the node's configuration with `top` among the top-level keys and starts it.
fn start_with(node: &mut Node, top: &str) -> Proc {
    loop {
        let text = node.config_text().replacen(
            "roles = \"controller\"
",
            &format!(
                "roles = \"controller\"
{top}
"
            ),
            1,
        );
        std::fs::write(node.config_path(), text).expect("write tenko.toml");
        let mut server = Proc::spawn(node.serve_command());
        if server
            .wait_stdout_line(serve_support::READY_TIMEOUT, |line| {
                line.contains(" ready at ")
            })
            .is_some()
        {
            return server;
        }
        let outcome = server.finish(serve_support::STOP_TIMEOUT);
        assert!(
            outcome.stderr.contains("start.api.bind"),
            "the server did not start
{}",
            outcome.diagnostics()
        );
        node.port = serve_support::free_port();
    }
}

fn assert_ipam_absent(api: &Api) {
    for path in ["/prefixes", "/addresses", "/hosts", "/vrfs", "/search?q=x"] {
        let reply = api.get(path);
        assert_eq!(reply.status, 404, "{path}: {}", reply.text);
        assert_eq!(
            reply.code().as_deref(),
            Some("sys.route_not_found"),
            "{path}"
        );
    }
    let import = api.upload("/imports", &[("hosts.csv", b"name\n")]);
    assert_eq!(import.status, 404, "{}", import.text);
    let moves = api.post("/moves", &json!({}));
    assert_eq!(moves.status, 404, "{}", moves.text);
    // The platform stays.
    assert_eq!(api.get("/jobs").status, 200);
    assert_eq!(api.get("/audit").status, 200);
}

#[test]
fn a_pinned_set_without_ipam_registers_no_ipam_route() {
    let mut node = Node::new();
    let mut server = start_with(&mut node, "modules = [\"dns\", \"discovery\"]");
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));

    assert_ipam_absent(&api);
    let status = api.get("/system/status").ok();
    assert_eq!(status["modules"], json!(["dns", "discovery"]));
    let modules = api.get("/system/modules").ok();
    assert_eq!(modules["running"], json!(["dns", "discovery"]));
    assert_eq!(modules["pinned"], true);
    assert_eq!(modules["restart"], "none");
    let refused = api.put("/system/modules", &json!({ "modules": ["ipam"] }));
    assert_eq!(refused.status, 409, "{}", refused.text);
    assert_eq!(refused.code().as_deref(), Some("modules.pinned"));

    let outcome = server.stop();
    outcome
        .assert_code(0)
        .assert_stderr_contains("the IPAM module is off");
}

#[test]
fn the_installation_choice_applies_at_the_next_start() {
    let mut node = Node::new();
    let mut server = start_with(&mut node, "");
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    assert_eq!(api.get("/prefixes").status, 200);
    let all = json!(["ipam", "dns", "dhcp", "discovery"]);
    assert_eq!(api.get("/system/modules").ok()["running"], all);

    // Without a service manager the change waits for a restart.
    let changed = api
        .put("/system/modules", &json!({ "modules": ["discovery"] }))
        .ok();
    assert_eq!(changed["configured"], json!(["discovery"]));
    assert_eq!(changed["running"], all);
    assert_eq!(changed["restart"], "required");
    let status = api.get("/system/status").ok();
    let warnings: Vec<&str> = status["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|warning| warning["code"].as_str())
        .collect();
    assert!(
        warnings.contains(&"sys.modules.restart_required"),
        "{warnings:?}"
    );
    assert_eq!(
        api.get("/prefixes").status,
        200,
        "still running until the restart"
    );
    let cookie = api.cookie().map(str::to_owned);
    server.stop().assert_code(0);

    let mut server = start_with(&mut node, "");
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    assert_ipam_absent(&api);
    let modules = api.get("/system/modules").ok();
    assert_eq!(modules["running"], json!(["discovery"]));
    assert_eq!(modules["pinned"], false);
    assert_eq!(modules["restart"], "none");
    // The change is in the audit log with the old and the new set.
    let audit = api.get("/audit?action=sys.modules.update").ok();
    let items = audit["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{audit}");
    server.stop().assert_code(0);
}
