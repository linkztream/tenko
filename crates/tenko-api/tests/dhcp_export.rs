//! The Kea export through the router (WP9.3, MIG-16): `GET /dhcp/export?format=kea` with
//! and without the leases, its audit record, the unknown format and the disabled module.

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
