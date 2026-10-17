//! Reverse zones from IPAM against the real binary (Phase 2 E17, DNS-22, plan section 2.6):
//! the RFC 2317 form for networks smaller than a /24.
//!
//! - Served parent: 192.0.2.64/26 is a network inside the supernet 192.0.2.0/24, and the
//!   zone `2.0.192.in-addr.arpa` is in Tenko. A reconciler run creates the zone
//!   `64/26.2.0.192.in-addr.arpa` for the prefix with the address's PTR record, and writes
//!   in the parent the delegation (NS) and the CNAME of every address of the block.
//! - Parent elsewhere: 198.51.100.128/25 has no parent zone in Tenko. Its zone
//!   `128/25.100.51.198.in-addr.arpa` gets its PTR record, and a proposal lists the lines
//!   to add to the parent where it is served.

mod serve_support;

use serde_json::{Value, json};
use serve_support::{Node, api::Api, wait_for_setup_token};

const ZONE: &str = "example.test";
const SERVED_PARENT: &str = "2.0.192.in-addr.arpa";
const SERVED_BLOCK: &str = "64/26.2.0.192.in-addr.arpa";
const OTHER_BLOCK: &str = "128/25.100.51.198.in-addr.arpa";

fn zone_body(apex: &str) -> Value {
    json!({
        "name": apex,
        "kind": "primary",
        "soa": { "mname": "ns1.example.test", "rname": "hostmaster.example.test" },
        "name_servers": ["ns1.example.test"],
    })
}

fn zones(api: &Api) -> Vec<Value> {
    api.list_all("/dns/zones")
}

fn zone(api: &Api, apex: &str) -> Value {
    zones(api)
        .into_iter()
        .find(|zone| zone["name"] == apex)
        .unwrap_or_else(|| panic!("no zone {apex}"))
}

fn rrsets(api: &Api, apex: &str) -> Vec<Value> {
    let id = zone(api, apex)["id"]
        .as_str()
        .expect("a zone id")
        .to_owned();
    api.list_all(&format!("/dns/zones/{id}/records"))
}

fn find<'a>(rrsets: &'a [Value], owner: &str, rtype: &str) -> Option<&'a Value> {
    rrsets
        .iter()
        .find(|rrset| rrset["name"] == owner && rrset["type"] == rtype)
}

#[test]
fn small_networks_get_rfc_2317_zones_with_glue_or_the_delegation_to_add() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    api.post("/dns/zones", &zone_body(ZONE)).expect(201);
    api.post("/dns/zones", &zone_body(SERVED_PARENT))
        .expect(201);
    api.post(
        "/prefixes",
        &json!({ "cidr": "192.0.2.0/24", "role": "supernet" }),
    )
    .expect(201);
    let served_prefix = api
        .post("/prefixes", &json!({ "cidr": "192.0.2.64/26" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    let other_prefix = api
        .post("/prefixes", &json!({ "cidr": "198.51.100.128/25" }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a prefix id")
        .to_owned();
    api.post(
        "/addresses",
        &json!({ "ip": "192.0.2.70", "dns_name": "cam.example.test" }),
    )
    .expect(201);
    api.post(
        "/addresses",
        &json!({ "ip": "198.51.100.130", "dns_name": "nas.example.test" }),
    )
    .expect(201);

    let run = api
        .post_unkeyed("/proposals/reconcile", &json!({}))
        .expect(200);
    assert!(run["dns"]["failures"].is_null(), "{run}");

    // The served block: its zone belongs to the prefix and holds the PTR record.
    let block = zone(&api, SERVED_BLOCK);
    assert_eq!(block["reverse_of"], served_prefix.as_str(), "{block}");
    let records = rrsets(&api, SERVED_BLOCK);
    let ptr = find(&records, "70.64/26.2.0.192.in-addr.arpa", "PTR").expect("the PTR");
    assert_eq!(ptr["origin"], "ipam");
    assert_eq!(ptr["records"][0]["target"], "cam.example.test");

    // The parent holds the delegation and one CNAME per address of the block.
    let parent = rrsets(&api, SERVED_PARENT);
    let ns = find(&parent, SERVED_BLOCK, "NS").expect("the delegation");
    assert_eq!(ns["origin"], "ipam");
    assert_eq!(ns["records"][0]["host"], "ns1.example.test");
    let cnames: Vec<&Value> = parent
        .iter()
        .filter(|rrset| rrset["type"] == "CNAME")
        .collect();
    assert_eq!(cnames.len(), 64);
    let cname = find(&parent, "70.2.0.192.in-addr.arpa", "CNAME").expect("the CNAME");
    assert_eq!(
        cname["records"][0]["target"],
        "70.64/26.2.0.192.in-addr.arpa"
    );

    // The other block: its zone and PTR, and the delegation as a proposal.
    let records = rrsets(&api, OTHER_BLOCK);
    let ptr = find(&records, "130.128/25.100.51.198.in-addr.arpa", "PTR").expect("the PTR");
    assert_eq!(ptr["records"][0]["target"], "nas.example.test");
    let proposals = api.list_all("/proposals?state=open");
    let delegation = proposals
        .iter()
        .find(|proposal| proposal["rule"] == "ipam.reconcile.dns_delegation")
        .unwrap_or_else(|| panic!("no delegation proposal: {proposals:?}"));
    assert_eq!(delegation["subject"]["prefix"], other_prefix.as_str());
    assert_eq!(delegation["params"]["parent"], "100.51.198.in-addr.arpa");
    let lines = delegation["params"]["lines"].as_str().expect("lines");
    assert!(
        lines.contains("128/25.100.51.198.in-addr.arpa. IN NS ns1.example.test."),
        "{lines}"
    );
    assert!(
        lines.contains(
            "$GENERATE 128-255 $.100.51.198.in-addr.arpa. IN CNAME $.128/25.100.51.198.in-addr.arpa."
        ),
        "{lines}"
    );

    // A second run changes nothing.
    let again = api
        .post_unkeyed("/proposals/reconcile", &json!({}))
        .expect(200);
    assert_eq!(again["dns"]["rrsets_changed"], 0, "{again}");
    assert_eq!(again["dns"]["zones_created"], 0, "{again}");
    server.stop().assert_graceful_shutdown();
}
