//! The DHCP class, policy and MAC filter operations through the router.

mod dhcp_support;

use dhcp_support::{App, MISSING};
use serde_json::{Value, json};

fn pxe() -> Value {
    json!({
        "name": "pxe",
        "matches": [{ "vendor_class": { "value": "PXEClient", "prefix": true } }],
    })
}

#[tokio::test]
async fn a_class_is_created_read_changed_and_deleted_unless_named() {
    let app = App::new();
    let created = app.send("POST", "/dhcp/classes", Some(pxe())).await;
    created.assert_status(201);
    let id = created.text("id");
    assert_eq!(created.body["used_by"], 0);
    app.send("POST", "/dhcp/classes", Some(pxe()))
        .await
        .assert_problem(400, "dhcp.class.invalid");
    app.send(
        "POST",
        "/dhcp/classes",
        Some(json!({ "name": "empty", "matches": [] })),
    )
    .await
    .assert_problem(400, "dhcp.class.invalid");
    let path = format!("/dhcp/classes/{id}");
    let got = app.get(&path).await;
    got.assert_status(200);
    let changed = app
        .send_with(
            "PATCH",
            &path,
            Some(json!({ "matches": [{ "mac": { "pattern": "00:00:5e:00:53:*" } }] })),
            &[("if-match", &format!("\"{}\"", got.etag()))],
        )
        .await;
    changed.assert_status(200);
    assert_eq!(
        changed.body["matches"][0]["mac"]["pattern"],
        "00:00:5e:00:53:*"
    );
    assert_eq!(app.get("/dhcp/classes").await.items().len(), 1);

    let prefix = app.prefix("192.0.2.0/24").await;
    app.send(
        "POST",
        "/dhcp/scopes",
        Some(json!({ "prefix": prefix, "classes": [id] })),
    )
    .await
    .assert_status(201);
    assert_eq!(app.get(&path).await.body["used_by"], 1);
    let refused = app.send("DELETE", &path, None).await;
    refused.assert_problem(409, "dhcp.class.in_use");
    assert_eq!(refused.body["params"]["by"], format!("scope:{prefix}"));
    app.send(
        "PATCH",
        &format!("/dhcp/scopes/{prefix}"),
        Some(json!({ "classes": [] })),
    )
    .await
    .assert_status(200);
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.class.not_found");
    app.send(
        "POST",
        "/dhcp/scopes",
        Some(json!({ "prefix": app.prefix("198.51.100.0/24").await, "classes": [MISSING] })),
    )
    .await
    .assert_problem(404, "dhcp.class.not_found");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn policies_belong_to_a_scope_or_the_server_and_keep_their_order() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    let class = app
        .send("POST", "/dhcp/classes", Some(pxe()))
        .await
        .text("id");
    let condition = json!({ "join": "and", "terms": [{ "class": class }, { "not_match": { "architecture": { "code": 0 } } }] });
    let first = app
        .send(
            "POST",
            "/dhcp/policies",
            Some(json!({
                "name": "uefi",
                "scope": prefix,
                "condition": condition,
                "action": { "range": { "first": "192.0.2.150", "last": "192.0.2.159" }, "lease": {"default_secs": 600, "min_secs": 300, "max_secs": 900} },
            })),
        )
        .await;
    first.assert_status(201);
    assert_eq!(first.body["order"], 0);
    assert_eq!(first.body["enabled"], true);
    let second = app
        .send(
            "POST",
            "/dhcp/policies",
            Some(json!({ "name": "bios", "scope": prefix, "condition": condition })),
        )
        .await;
    second.assert_status(201);
    assert_eq!(second.body["order"], 1);
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({ "name": "server-wide", "condition": condition })),
    )
    .await
    .assert_status(201);
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({ "name": "uefi", "scope": prefix, "condition": condition })),
    )
    .await
    .assert_problem(400, "dhcp.policy.invalid");
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({ "name": "far", "scope": prefix, "condition": condition, "action": { "range": { "first": "203.0.113.1", "last": "203.0.113.9" } } })),
    )
    .await
    .assert_problem(400, "dhcp.pool.outside");
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({ "name": "lost", "scope": MISSING, "condition": condition })),
    )
    .await
    .assert_problem(404, "dhcp.scope.not_found");
    app.send(
        "POST",
        "/dhcp/policies",
        Some(json!({ "name": "ghost", "condition": { "join": "or", "terms": [{ "class": MISSING }] } })),
    )
    .await
    .assert_problem(404, "dhcp.class.not_found");

    let all = app.get("/dhcp/policies").await;
    let names: Vec<&str> = all.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|p| p["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["uefi", "bios", "server-wide"]);
    assert_eq!(app.get("/dhcp/policies?server=true").await.items().len(), 1);
    assert_eq!(
        app.get(&format!("/dhcp/policies?scope={prefix}"))
            .await
            .items()
            .len(),
        2
    );

    let path = format!("/dhcp/policies/{}", first.text("id"));
    let moved = app
        .send(
            "PATCH",
            &path,
            Some(json!({ "order": 5, "enabled": false })),
        )
        .await;
    moved.assert_status(200);
    assert_eq!(moved.body["order"], 5);
    assert_eq!(moved.body["enabled"], false);
    // The class a policy names stays.
    app.send("DELETE", &format!("/dhcp/classes/{class}"), None)
        .await
        .assert_problem(409, "dhcp.class.in_use");
    app.send(
        "PUT",
        &format!("/dhcp/option-sets/policy:{}", first.text("id")),
        Some(json!({ "values": [{ "code": 67, "typed": { "text": "boot.efi" } }] })),
    )
    .await
    .assert_status(200);
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.policy.not_found");
    app.get(&format!("/dhcp/option-sets/policy:{}", first.text("id")))
        .await
        .assert_problem(404, "dhcp.policy.not_found");
}

#[tokio::test]
async fn filters_hold_one_entry_per_pattern() {
    let app = App::new();
    let created = app
        .send(
            "POST",
            "/dhcp/filters",
            Some(json!({ "mac": "00-00-5E-00-53-*", "kind": "deny", "note": "lab devices" })),
        )
        .await;
    created.assert_status(201);
    assert_eq!(created.body["mac"], "00:00:5e:00:53:*");
    let id = created.text("id");
    app.send(
        "POST",
        "/dhcp/filters",
        Some(json!({ "mac": "00:00:5e:00:53:*", "kind": "allow" })),
    )
    .await
    .assert_problem(409, "dhcp.filter.exists");
    app.send(
        "POST",
        "/dhcp/filters",
        Some(json!({ "mac": "not-a-mac", "kind": "allow" })),
    )
    .await
    .assert_status(400);
    let second = app
        .send(
            "POST",
            "/dhcp/filters",
            Some(json!({ "mac": "00:00:5e:00:53:01", "kind": "allow" })),
        )
        .await;
    second.assert_status(201);
    app.send(
        "PATCH",
        &format!("/dhcp/filters/{}", second.text("id")),
        Some(json!({ "mac": "00:00:5e:00:53:*" })),
    )
    .await
    .assert_problem(409, "dhcp.filter.exists");
    let path = format!("/dhcp/filters/{id}");
    let changed = app
        .send("PATCH", &path, Some(json!({ "kind": "allow", "note": "" })))
        .await;
    changed.assert_status(200);
    assert_eq!(changed.body["kind"], "allow");
    assert_eq!(changed.body["note"], Value::Null);
    assert_eq!(app.get("/dhcp/filters").await.items().len(), 2);
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.filter.not_found");
    assert_eq!(
        app.audit_actions().await,
        [
            "dhcp.filter.create",
            "dhcp.filter.create",
            "dhcp.filter.update",
            "dhcp.filter.delete"
        ]
    );
}
