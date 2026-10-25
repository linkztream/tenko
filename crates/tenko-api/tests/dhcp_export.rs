//! The Kea export through the router (WP9.3, MIG-16): `GET /dhcp/export?format=kea` with
//! and without the leases, its audit record, the `Dhcp6` document of a DHCPv6 scope, the
//! unknown format and the disabled module.

mod dhcp_support;

use dhcp_support::App;
use serde_json::json;

#[tokio::test]
async fn the_export_holds_the_scope_its_pool_reservation_and_policy() {
    let app = App::new();
    let prefix = app.scope("192.0.2.64/26").await;
    app.range(&prefix, "192.0.2.94", "192.0.2.123", "dhcp_pool")
        .await;
    app.host("printer", "reserved", Some(0x45), "192.0.2.80")
        .await;
    app.send(
        "PUT",
        "/dhcp/option-sets/server",
        Some(
            json!({ "values": [{ "code": 6, "typed": { "ipv4": { "values": ["192.0.2.53"] } } }] }),
        ),
    )
    .await
    .assert_status(200);
    let class = app
        .send(
            "POST",
            "/dhcp/classes",
            Some(json!({ "name": "printers", "matches": [{ "vendor_class": { "value": "Printer", "prefix": true } }] })),
        )
        .await;
    class.assert_status(201);
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({
            "name": "printers",
            "scope": prefix,
            "order": 1,
            "condition": { "join": "or", "terms": [{ "class": class.text("id") }] },
            "action": { "ddns": { "enabled": true } },
        })),
    )
    .await
    .assert_status(201);

    let export = app.get("/dhcp/export?format=kea").await;
    export.assert_status(200);
    let dhcp4 = &export.body["dhcp4"]["Dhcp4"];
    let subnet = &dhcp4["subnet4"][0];
    assert_eq!(subnet["subnet"], "192.0.2.64/26");
    assert_eq!(subnet["id"], 1);
    assert_eq!(subnet["pools"][0]["pool"], "192.0.2.94 - 192.0.2.123");
    assert_eq!(
        subnet["reservations"],
        json!([{ "hw-address": "00:00:5e:00:53:45", "ip-address": "192.0.2.80", "hostname": "printer" }])
    );
    assert_eq!(dhcp4["option-data"][0]["name"], "domain-name-servers");
    let classes = dhcp4["client-classes"].as_array().expect("classes");
    assert!(classes.iter().any(|c| c["name"] == "printers"));
    assert!(
        classes
            .iter()
            .any(|c| c["name"] == "policy.192.0.2.64/26.printers")
    );
    assert_eq!(
        export.body["leases4_csv"],
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
    );
    let losses = export.body["losses"].as_array().expect("losses");
    let codes: Vec<&str> = losses
        .iter()
        .map(|entry| entry["code"].as_str().expect("code"))
        .collect();
    // The router runs no dhcp role, so the listeners are unknown; the policy's DDNS
    // action does not translate.
    assert!(
        codes.contains(&"export.kea.interfaces.unknown"),
        "{codes:?}"
    );
    assert!(codes.contains(&"export.kea.policy.ddns"), "{codes:?}");
    assert!(codes.contains(&"export.kea.history"), "{codes:?}");
    assert!(export.body.get("dhcp_ddns").is_none());

    let without = app.get("/dhcp/export?format=kea&leases=false").await;
    without.assert_status(200);
    assert!(without.body.get("leases4_csv").is_none());
    let actions = app.audit_actions().await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "dhcp.export")
            .count(),
        2
    );
}

#[tokio::test]
async fn a_dhcpv6_scope_has_its_own_document_and_lease_file() {
    let app = App::new();
    // Without a DHCPv6 scope there is no Dhcp6 document.
    let none = app.get("/dhcp/export?format=kea").await;
    none.assert_status(200);
    assert!(none.body.get("dhcp6").is_none());
    assert!(none.body.get("leases6_csv").is_none());

    let prefix = app.prefix("2001:db8:101::/64").await;
    app.range(
        &prefix,
        "2001:db8:101::1000",
        "2001:db8:101::1fff",
        "dhcp_pool",
    )
    .await;
    app.send(
        "POST",
        "/dhcp/scopes",
        Some(json!({
            "prefix": prefix,
            "lease": { "default_secs": 120, "min_secs": 120, "max_secs": 120 },
            "v6": { "preferred_secs": 60, "interface_id": "lab-lan6" },
        })),
    )
    .await
    .assert_status(201);
    app.send(
        "PUT",
        "/dhcp/option-sets/server",
        Some(json!({ "values": [
            { "space": "dhcp6", "code": 23, "typed": { "ipv6": { "values": ["2001:db8:100::53"] } } },
        ] })),
    )
    .await
    .assert_status(200);
    let interface = uuid::Uuid::now_v7().to_string();
    app.send(
        "POST",
        "/hosts",
        Some(
            json!({ "name": "lab6-reserved", "mode": "reserved", "interfaces": [
            { "id": interface, "name": "eth0", "duid": "0003000100005e005361" },
        ] }),
        ),
    )
    .await
    .assert_status(201);
    app.send(
        "POST",
        "/addresses",
        Some(json!({ "ip": "2001:db8:101::80", "interface": interface })),
    )
    .await
    .assert_status(201);

    let export = app.get("/dhcp/export?format=kea").await;
    export.assert_status(200);
    let dhcp6 = &export.body["dhcp6"]["Dhcp6"];
    let subnet = &dhcp6["subnet6"][0];
    assert_eq!(subnet["subnet"], "2001:db8:101::/64");
    assert_eq!(subnet["id"], 1);
    assert_eq!(
        subnet["pools"][0]["pool"],
        "2001:db8:101::1000 - 2001:db8:101::1fff"
    );
    assert_eq!(subnet["interface-id"], "lab-lan6");
    assert_eq!(subnet["valid-lifetime"], 120);
    assert_eq!(subnet["preferred-lifetime"], 60);
    assert_eq!(subnet["renew-timer"], 30);
    assert_eq!(subnet["rebind-timer"], 48);
    assert_eq!(subnet["rapid-commit"], true);
    assert_eq!(
        subnet["reservations"],
        json!([{ "duid": "00:03:00:01:00:00:5e:00:53:61", "ip-addresses": ["2001:db8:101::80"], "hostname": "lab6-reserved" }])
    );
    assert_eq!(dhcp6["option-data"][0]["name"], "dns-servers");
    assert_eq!(dhcp6["option-data"][0]["always-send"], true);
    // The IPv6 scope stays out of Dhcp4.
    assert_eq!(export.body["dhcp4"]["Dhcp4"]["subnet4"], json!([]));
    assert_eq!(
        export.body["leases6_csv"],
        "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id\n"
    );
    let codes: Vec<&str> = export.body["losses"]
        .as_array()
        .expect("losses")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code"))
        .collect();
    assert!(
        codes.contains(&"export.kea.v6.server_id.unknown"),
        "{codes:?}"
    );
    let without = app.get("/dhcp/export?format=kea&leases=false").await;
    without.assert_status(200);
    assert!(without.body.get("dhcp6").is_some());
    assert!(without.body.get("leases6_csv").is_none());
}

#[tokio::test]
async fn an_unknown_format_is_refused_and_the_module_must_run() {
    let app = App::new();
    app.get("/dhcp/export?format=isc")
        .await
        .assert_problem(400, "dhcp.export.format");
    let router = App::without_service();
    dhcp_support::send(&router, "GET", "/dhcp/export", None, &[])
        .await
        .assert_problem(409, "dhcp.module.disabled");
}
