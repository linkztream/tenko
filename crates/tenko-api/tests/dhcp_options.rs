//! The DHCP option catalog, custom definitions, option sets and the effective options of a
//! client through the router.

mod dhcp_support;

use dhcp_support::{App, MISSING};
use serde_json::{Value, json};

#[tokio::test]
async fn the_catalog_lists_the_built_in_and_the_server_managed_codes() {
    let app = App::new();
    let catalog = app.get("/dhcp/option-catalog").await;
    catalog.assert_status(200);
    let entries = catalog.body.as_array().expect("entries");
    let find = |code: u64| {
        entries
            .iter()
            .find(|entry| entry["code"] == code)
            .unwrap_or_else(|| panic!("code {code}"))
    };
    assert_eq!(find(6)["name"], "domain-name-servers");
    assert_eq!(find(6)["kind"], "ipv4_address");
    assert_eq!(find(6)["array"], true);
    assert_eq!(find(6)["server_managed"], false);
    assert_eq!(find(51)["server_managed"], true);
    let codes: Vec<u64> = entries
        .iter()
        .map(|e| e["code"].as_u64().expect("code"))
        .collect();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    assert_eq!(codes, sorted);
}

#[tokio::test]
async fn a_definition_is_created_changed_and_deleted_unless_used() {
    let app = App::new();
    let created = app
        .send(
            "POST",
            "/dhcp/option-defs",
            Some(json!({ "code": 224, "name": "site-flag", "kind": "u16" })),
        )
        .await;
    created.assert_status(201);
    assert_eq!(created.body["space"], "dhcp4");
    assert_eq!(created.body["used_by"], 0);
    let id = created.text("id");
    app.send(
        "POST",
        "/dhcp/option-defs",
        Some(json!({ "code": 224, "name": "other", "kind": "u8" })),
    )
    .await
    .assert_problem(409, "dhcp.option_def.exists");
    app.send(
        "POST",
        "/dhcp/option-defs",
        Some(json!({ "code": 6, "name": "dns", "kind": "ipv4_address", "array": true })),
    )
    .await
    .assert_problem(409, "dhcp.option.code_reserved");
    app.send(
        "POST",
        "/dhcp/option-defs",
        Some(json!({ "code": 225, "name": "bad", "kind": "string", "array": true })),
    )
    .await
    .assert_problem(400, "dhcp.option.invalid");
    // A vendor space carries its vendor class.
    app.send(
        "POST",
        "/dhcp/option-defs",
        Some(json!({ "space": "acme", "code": 1, "name": "acme-server", "kind": "ipv4_address", "vendor_class": "ACME" })),
    )
    .await
    .assert_status(201);
    assert_eq!(app.get("/dhcp/option-defs").await.items().len(), 2);

    let path = format!("/dhcp/option-defs/{id}");
    app.send_with(
        "PUT",
        "/dhcp/option-sets/server",
        Some(json!({ "values": [{ "code": 224, "typed": { "unsigned": [80] } }] })),
        &[],
    )
    .await
    .assert_status(200);
    assert_eq!(app.get(&path).await.body["used_by"], 1);
    app.send("PATCH", &path, Some(json!({ "kind": "u32" })))
        .await
        .assert_problem(409, "dhcp.option_def.in_use");
    app.send("PATCH", &path, Some(json!({ "description": "a flag" })))
        .await
        .assert_status(200);
    app.send("DELETE", &path, None)
        .await
        .assert_problem(409, "dhcp.option_def.in_use");
    app.send("DELETE", "/dhcp/option-sets/server", None)
        .await
        .assert_status(204);
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.option_def.not_found");
    assert_eq!(
        app.audit_actions().await,
        [
            "dhcp.option.def_create",
            "dhcp.option.def_create",
            "dhcp.option.set",
            "dhcp.option.def_update",
            "dhcp.option.set",
            "dhcp.option.def_delete",
        ]
    );
}

#[tokio::test]
async fn option_sets_take_wire_and_typed_values_checked_against_their_type() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    let path = format!("/dhcp/option-sets/scope:{prefix}");
    let empty = app.get(&path).await;
    empty.assert_status(200);
    assert_eq!(empty.etag(), "0");
    assert_eq!(empty.body["values"], json!([]));
    let set = app
        .send_with(
            "PUT",
            &path,
            Some(json!({ "values": [
                { "code": 3, "typed": { "ipv4": { "values": ["192.0.2.1"] } } },
                { "code": 6, "data": "c0000235c0000236" },
                { "code": 15, "typed": { "text": "example.test" } },
                { "code": 119, "typed": { "names": ["example.test", "lab.example.test"] } },
            ] })),
            &[("if-match", "\"0\"")],
        )
        .await;
    set.assert_status(200);
    assert_eq!(set.body["level"], "scope");
    assert_eq!(set.body["path"], format!("scope:{prefix}"));
    let values = set.body["values"].as_array().expect("values");
    assert_eq!(values[0]["data"], "c0000201");
    assert_eq!(values[1]["name"], "domain-name-servers");
    assert_eq!(
        values[1]["typed"],
        json!({ "ipv4": { "values": ["192.0.2.53", "192.0.2.54"] } })
    );
    assert_eq!(values[2]["typed"], json!({ "text": "example.test" }));
    let etag = set.etag();
    assert_eq!(app.get(&path).await.etag(), etag);

    for (body, status, code) in [
        (
            json!({ "values": [{ "code": 51, "data": "00000e10" }] }),
            409,
            "dhcp.option.code_reserved",
        ),
        (
            json!({ "values": [{ "code": 230, "data": "01" }] }),
            400,
            "dhcp.option.unknown",
        ),
        (
            json!({ "values": [{ "code": 3, "data": "c00002" }] }),
            400,
            "dhcp.option.invalid",
        ),
        (
            json!({ "values": [{ "code": 3 }] }),
            400,
            "dhcp.option.invalid",
        ),
        (
            json!({ "values": [{ "code": 26, "typed": { "unsigned": [70000] } }] }),
            400,
            "dhcp.option.invalid",
        ),
        (
            json!({ "values": [{ "code": 3, "data": "c0000201" }, { "code": 3, "data": "c0000202" }] }),
            400,
            "dhcp.option.invalid",
        ),
    ] {
        app.send("PUT", &path, Some(body))
            .await
            .assert_problem(status, code);
    }
    app.send_with(
        "PUT",
        &path,
        Some(json!({ "values": [] })),
        &[("if-match", "\"1\"")],
    )
    .await
    .assert_problem(412, "sys.store.precondition_failed");
    app.send(
        "PUT",
        &format!("/dhcp/option-sets/scope:{MISSING}"),
        Some(json!({ "values": [] })),
    )
    .await
    .assert_problem(404, "dhcp.scope.not_found");
    app.get(&format!("/dhcp/option-sets/policy:{MISSING}"))
        .await
        .assert_problem(404, "dhcp.policy.not_found");

    app.send("PUT", "/dhcp/option-sets/server", Some(json!({ "values": [{ "code": 42, "typed": { "ipv4": { "values": ["192.0.2.123"] } } }] })))
        .await
        .assert_status(200);
    let all = app.get("/dhcp/option-sets").await;
    assert_eq!(all.items().len(), 2);
    assert_eq!(all.items()[0]["path"], "server");
    let scopes = app.get("/dhcp/option-sets?level=scope").await;
    assert_eq!(scopes.items().len(), 1);
    app.send("DELETE", &path, None).await.assert_status(204);
    app.send("DELETE", &path, None).await.assert_status(204);
    assert_eq!(app.get(&path).await.body["values"], json!([]));
}

#[tokio::test]
async fn the_effective_options_merge_the_levels_and_the_reservation() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    app.range(&prefix, "192.0.2.100", "192.0.2.199", "dhcp_pool")
        .await;
    let reserved = app.host("printer", "reserved", Some(1), "192.0.2.20").await;
    let dns = |last: u8| json!({ "code": 6, "typed": { "ipv4": { "values": [format!("192.0.2.{last}")] } } });
    app.send(
        "PUT",
        "/dhcp/option-sets/server",
        Some(json!({ "values": [dns(53), { "code": 42, "data": "c000027b" }] })),
    )
    .await
    .assert_status(200);
    app.send(
        "PUT",
        &format!("/dhcp/option-sets/scope:{prefix}"),
        Some(json!({ "values": [{ "code": 3, "data": "c0000201" }, dns(54)] })),
    )
    .await
    .assert_status(200);
    app.send(
        "PUT",
        &format!("/dhcp/option-sets/host:{reserved}"),
        Some(json!({ "values": [dns(55)] })),
    )
    .await
    .assert_status(200);

    let path = format!("/dhcp/scopes/{prefix}/effective-options");
    let printer = app.get(&format!("{path}?mac=00:00:5e:00:53:01")).await;
    printer.assert_status(200);
    assert_eq!(printer.body["reservation"], reserved.as_str());
    let options = printer.body["options"].as_array().expect("options");
    let summary: Vec<(u64, String)> = options
        .iter()
        .map(|o| {
            (
                o["value"]["code"].as_u64().expect("code"),
                o["level"].as_str().expect("level").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (6, "host".to_owned()),
            (42, "server".to_owned()),
            (3, "scope".to_owned())
        ]
    );
    assert_eq!(
        options[0]["typed"],
        json!({ "ipv4": { "values": ["192.0.2.55"] } })
    );
    assert_eq!(options[0]["name"], "domain-name-servers");
    assert_eq!(options[0]["owner"], json!({ "host": reserved }));

    let stranger = app.get(&format!("{path}?mac=00:00:5e:00:53:77")).await;
    stranger.assert_status(200);
    assert_eq!(stranger.body["reservation"], Value::Null);
    assert_eq!(stranger.body["options"][0]["level"], "scope");
    assert_eq!(stranger.body["policies"], json!([]));
    app.get(&format!("{path}?client_id=zz"))
        .await
        .assert_problem(400, "sys.invalid_query");
    app.get(&format!("/dhcp/scopes/{MISSING}/effective-options"))
        .await
        .assert_problem(404, "dhcp.scope.not_found");
}

// WP8.6: the architecture and the host name reach the matcher of the effective view.
#[tokio::test]
async fn the_effective_options_take_the_architecture_and_the_host_name() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    let uefi = app
        .send(
            "POST",
            "/dhcp/classes",
            Some(json!({ "name": "uefi", "matches": [{ "architecture": { "code": 7 } }] })),
        )
        .await;
    uefi.assert_status(201);
    let laptops = app
        .send(
            "POST",
            "/dhcp/classes",
            Some(json!({
                "name": "laptops",
                "matches": [{ "host_name": { "value": "laptop", "prefix": true } }],
            })),
        )
        .await;
    laptops.assert_status(201);
    let policy = app
        .send(
            "POST",
            "/dhcp/policies",
            Some(json!({
                "name": "uefi-boot",
                "scope": prefix,
                "condition": { "join": "or", "terms": [{ "class": uefi.text("id") }] },
            })),
        )
        .await;
    policy.assert_status(201);
    let policy_id = policy.text("id");
    app.send(
        "PUT",
        &format!("/dhcp/option-sets/policy:{policy_id}"),
        Some(json!({ "values": [{ "code": 67, "typed": { "text": "ipxe.efi" } }] })),
    )
    .await
    .assert_status(200);

    let path = format!("/dhcp/scopes/{prefix}/effective-options?mac=00:00:5e:00:53:01");
    let firmware = app
        .get(&format!("{path}&architecture=7&host_name=laptop-7"))
        .await;
    firmware.assert_status(200);
    assert_eq!(firmware.body["policies"], json!([policy_id]));
    let classes = firmware.body["classes"].as_array().expect("classes");
    assert!(classes.contains(&json!(uefi.text("id"))), "{classes:?}");
    assert!(classes.contains(&json!(laptops.text("id"))), "{classes:?}");
    let boot = firmware.body["options"]
        .as_array()
        .expect("options")
        .iter()
        .find(|o| o["value"]["code"] == 67)
        .expect("option 67");
    assert_eq!(boot["level"], "policy");

    let bios = app.get(&format!("{path}&architecture=0")).await;
    bios.assert_status(200);
    assert_eq!(bios.body["policies"], json!([]));
    app.get(&format!("{path}&architecture=70000"))
        .await
        .assert_problem(400, "sys.invalid_query");
}
