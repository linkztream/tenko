//! Acceptance of the Kea export (WP9.3, MIG-16) through the real binary: one node with the
//! DHCP module, a network with a pool, a scope with options, a reserved host and a policy
//! made through the API, plus a DHCPv6 scope with a pool, then
//! `tenko dhcp export --format kea --leases --out <dir>` in a separate process writes
//! `kea-dhcp4.json`, `kea-leases4.csv`, `kea-dhcp6.json`, `kea-leases6.csv` and
//! `kea-export-report.json`, and without `--out` prints the whole answer.
//!
//! This is the binary half of E30; the Kea half (`kea-dhcp4 -t`, `kea-dhcp6 -t` and a Kea
//! server handing out the exported reservations) runs in the lab rows `export.kea*` of
//! `deploy/compose/lab-dhcp`.

mod serve_support;

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one node through the whole export, read top to bottom"
)]
fn the_export_writes_the_kea_files() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    node.login().assert_code(0);

    let prefix = api
        .post("/prefixes", &json!({ "cidr": "192.0.2.64/26" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        &format!("/prefixes/{prefix}/ranges"),
        &json!({ "first": "192.0.2.94", "last": "192.0.2.123", "role": "dhcp_pool" }),
    )
    .expect(201);
    api.post("/dhcp/scopes", &json!({ "prefix": prefix }))
        .expect(201);
    api.put(
        &format!("/dhcp/option-sets/scope:{prefix}"),
        &json!({ "values": [{ "code": 3, "typed": { "ipv4": { "values": ["192.0.2.66"] } } }] }),
    )
    .expect(200);
    let host_id = api
        .post(
            "/hosts",
            &json!({ "name": "printer", "mode": "reserved", "interfaces": [{ "name": "eth0", "mac": "00:00:5e:00:53:45" }] }),
        )
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a host id")
        .to_owned();
    let interfaces = api.get(&format!("/hosts/{host_id}/interfaces")).expect(200);
    let interface = interfaces["items"][0]["id"]
        .as_str()
        .expect("an interface id")
        .to_owned();
    api.post(
        "/addresses",
        &json!({ "ip": "192.0.2.80", "interface": interface }),
    )
    .expect(201);

    // WP9.3, the DHCPv6 half: a scope on an IPv6 prefix with a pool.
    let prefix6 = api
        .post("/prefixes", &json!({ "cidr": "2001:db8:101::/64" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        &format!("/prefixes/{prefix6}/ranges"),
        &json!({ "first": "2001:db8:101::1000", "last": "2001:db8:101::1fff", "role": "dhcp_pool" }),
    )
    .expect(201);
    api.post(
        "/dhcp/scopes",
        &json!({ "prefix": prefix6, "v6": { "rapid_commit": false } }),
    )
    .expect(201);

    let out = tempfile::tempdir().expect("a directory");
    let dir = out.path().join("kea");
    let dir_text = dir.to_str().expect("a UTF-8 path").to_owned();
    node.client(&[
        "dhcp", "export", "--format", "kea", "--leases", "--out", &dir_text,
    ])
    .assert_code(0)
    .assert_stderr_contains("kea-dhcp4.json");
    let config: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("kea-dhcp4.json")).expect("kea-dhcp4.json"),
    )
    .expect("JSON");
    let subnet = &config["Dhcp4"]["subnet4"][0];
    assert_eq!(subnet["subnet"], "192.0.2.64/26");
    assert_eq!(subnet["pools"][0]["pool"], "192.0.2.94 - 192.0.2.123");
    assert_eq!(subnet["reservations"][0]["hw-address"], "00:00:5e:00:53:45");
    assert_eq!(subnet["reservations"][0]["ip-address"], "192.0.2.80");
    assert_eq!(subnet["option-data"][0]["data"], "192.0.2.66");
    let leases = std::fs::read_to_string(dir.join("kea-leases4.csv")).expect("kea-leases4.csv");
    assert!(leases.starts_with("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,"));
    let config6: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("kea-dhcp6.json")).expect("kea-dhcp6.json"),
    )
    .expect("JSON");
    let subnet6 = &config6["Dhcp6"]["subnet6"][0];
    assert_eq!(subnet6["subnet"], "2001:db8:101::/64");
    assert_eq!(
        subnet6["pools"][0]["pool"],
        "2001:db8:101::1000 - 2001:db8:101::1fff"
    );
    assert_eq!(subnet6["rapid-commit"], false);
    let leases6 = std::fs::read_to_string(dir.join("kea-leases6.csv")).expect("kea-leases6.csv");
    assert!(leases6.starts_with("address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,"));
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("kea-export-report.json"))
            .expect("kea-export-report.json"),
    )
    .expect("JSON");
    let codes: Vec<&str> = report["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code"))
        .collect();
    assert!(codes.contains(&"export.kea.history"), "{codes:?}");
    assert!(!dir.join("kea-dhcp-ddns.json").exists());

    // Without --out the whole answer goes to standard output, without the leases.
    let printed = node.client(&["dhcp", "export"]);
    printed.assert_code(0);
    let answer = printed.json();
    assert_eq!(answer["dhcp4"]["Dhcp4"]["subnet4"][0]["id"], 1);
    assert!(answer.get("leases4_csv").is_none());
    assert_eq!(answer["dhcp6"]["Dhcp6"]["subnet6"][0]["id"], 1);
    assert!(answer.get("leases6_csv").is_none());
    server.stop().assert_graceful_shutdown();
}
