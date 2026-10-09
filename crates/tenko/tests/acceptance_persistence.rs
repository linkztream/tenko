//! Persistence of a real `tenko serve` across a graceful restart on the same data
//! directory, through the public API: every object reads back the same, the session of
//! the browser survives, the audit chain verifies (through the API and `tenko audit
//! verify`) and has grown only by what was written, setup stays closed, and the event
//! stream of the restarted server delivers an event for a new change.
//!
//! `serve_restart.rs` covers the store and the key-encryption key (hard kill, missing or
//! foreign keys); this test covers what an operator sees.

mod serve_support;

use serde_json::{Value, json};
use serve_support::{Node, READY_TIMEOUT, api::Api, wait_for_setup_token};

/// The objects an operator created before the restart, by path.
fn populate(api: &Api) -> Vec<String> {
    let mut paths = Vec::new();
    api.post(
        "/custom-fields",
        &json!({ "key": "rack", "kind": { "type": "text" }, "applies_to": ["prefix", "host"] }),
    )
    .expect(201);
    paths.push("/custom-fields/rack".to_owned());
    let prefix = api
        .post(
            "/prefixes",
            &json!({
                "cidr": "192.0.2.0/24",
                "description": "office",
                "tags": ["lab", "wired"],
                "custom": { "rack": { "type": "text", "value": "R2" } },
            }),
        )
        .expect(201);
    let prefix_id = prefix["item"]["id"].as_str().expect("an id").to_owned();
    paths.push(format!("/prefixes/{prefix_id}"));
    let host = api
        .post(
            "/hosts",
            &json!({
                "name": "nas01",
                "mode": "static",
                "interfaces": [{ "name": "eth0", "mac": "00-00-5E-00-53-01" }],
            }),
        )
        .expect(201);
    let host_id = host["item"]["id"].as_str().expect("an id").to_owned();
    paths.push(format!("/hosts/{host_id}"));
    let interface = api.get(&format!("/hosts/{host_id}/interfaces")).expect(200)["items"][0]["id"]
        .as_str()
        .expect("an interface")
        .to_owned();
    paths.push(format!("/interfaces/{interface}"));
    let address = api
        .post(
            &format!("/prefixes/{prefix_id}/next-free-address"),
            &json!({ "interface": interface, "dns_name": "nas01.example.test" }),
        )
        .expect(201);
    let address_id = address["item"]["id"].as_str().expect("an id").to_owned();
    assert_eq!(address["item"]["ip"], "192.0.2.1");
    paths.push(format!("/addresses/{address_id}"));
    // An update and a soft delete with restore, so history exists too.
    let revision =
        api.get(&format!("/prefixes/{prefix_id}")).expect(200)["meta"]["revision"].as_u64();
    api.patch(
        &format!("/prefixes/{prefix_id}"),
        &json!({ "description": "office, ground floor" }),
        revision,
    )
    .expect(200);
    paths.push(format!("/prefixes/{prefix_id}/history"));
    paths
}

fn snapshot(api: &Api, paths: &[String]) -> Vec<Value> {
    paths.iter().map(|path| api.get(path).expect(200)).collect()
}

/// The parts of a list or history answer that must not change: everything but the
/// revision the page was read at.
fn stable(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut()
        && object.contains_key("items")
    {
        object.remove("revision");
    }
    value
}

#[test]
fn objects_sessions_and_the_audit_chain_survive_a_restart_and_events_flow() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    let paths = populate(&api);
    let before = snapshot(&api, &paths);
    let chain = api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "{chain}");
    let checked = chain["checked"].as_u64().expect("a count");
    let session = api.get("/auth/session").expect(200);
    let cookie = api.cookie().map(str::to_owned);

    server.stop().assert_graceful_shutdown();
    let mut server = node.start();
    // Setup stays closed: no new token.
    let ready = server.stdout_text();
    assert!(
        !ready.contains("Setup token: "),
        "a set-up node prints no setup token\n{ready}"
    );

    // The browser's session is still valid.
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    let again = api.get("/auth/session").expect(200);
    assert_eq!(again["session_id"], session["session_id"]);
    assert_eq!(api.get("/setup").expect(200)["open"], false);

    // Every object reads back the same.
    let after = snapshot(&api, &paths);
    for ((path, old), new) in paths.iter().zip(&before).zip(&after) {
        assert_eq!(
            stable(old),
            stable(new),
            "{path} changed across the restart"
        );
    }

    // The chain verifies and holds the same records: a restart writes none.
    let chain = api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "{chain}");
    assert_eq!(chain["checked"].as_u64(), Some(checked), "{chain}");
    node.login().assert_code(0);
    let report = node.client(&["audit", "verify", "--json"]);
    report.assert_code(0);
    assert_eq!(report.json()["intact"], true);

    // The event stream of the restarted server: a new prefix arrives as an `ipam` event
    // whose id is the revision of the change.
    let revision = api.get("/prefixes").expect(200)["revision"]
        .as_u64()
        .expect("a list revision");
    let mut events = api.events(&format!("topics=ipam&from={revision}"));
    let created = api
        .post("/prefixes", &json!({ "cidr": "203.0.113.0/24" }))
        .expect(201);
    let id = created["item"]["id"].as_str().expect("an id").to_owned();
    let event = events
        .next_matching(READY_TIMEOUT, |event| {
            event.event == "ipam"
                && event.json()["objects"]
                    .as_array()
                    .is_some_and(|objects| objects.iter().any(|o| o["id"] == id.as_str()))
        })
        .unwrap_or_else(|| panic!("no event for the new prefix\n{}", server.diagnostics()));
    let event_id: u64 = event
        .id
        .as_deref()
        .and_then(|id| id.parse().ok())
        .expect("a numeric event id");
    assert!(event_id > revision, "{event_id} after {revision}");
    assert_eq!(event.json()["topic"], "ipam");
    drop(events);

    // The new write is audited after the old records, still intact.
    let chain = api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "{chain}");
    assert!(chain["checked"].as_u64().expect("a count") > checked);

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
}
