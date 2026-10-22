//! The DHCP settings, scope, exclusion, utilization, pool and shared network operations
//! through the router, over the configuration service and the IPAM service on one
//! in-memory store.

mod dhcp_support;

use dhcp_support::{App, MISSING, send};
use serde_json::{Value, json};

#[tokio::test]
async fn the_settings_start_from_the_defaults_and_change_with_if_match() {
    let app = App::new();
    let got = app.get("/dhcp/settings").await;
    got.assert_status(200);
    assert_eq!(got.etag(), "0");
    assert_eq!(got.body["lease"]["default_secs"], 86_400);
    assert_eq!(got.body["authoritative"], true);
    assert_eq!(got.body["effective_conflict_detection"], true);
    assert_eq!(got.body["effective_history_days"], 30);

    let changed = app
        .send_with(
            "PUT",
            "/dhcp/settings",
            Some(json!({
                "lease": {"default_secs": 3600, "min_secs": 600, "max_secs": 7200},
                "history_days": 14,
            })),
            &[("if-match", "\"0\"")],
        )
        .await;
    changed.assert_status(200);
    assert_eq!(changed.body["lease"]["default_secs"], 3600);
    assert_eq!(changed.body["effective_history_days"], 14);
    let etag = changed.etag();
    assert_ne!(etag, "0");
    app.send_with(
        "PUT",
        "/dhcp/settings",
        Some(json!({ "authoritative": false })),
        &[("if-match", "\"0\"")],
    )
    .await
    .assert_problem(412, "sys.store.precondition_failed");
    app.send(
        "PUT",
        "/dhcp/settings",
        Some(json!({ "lease": {"default_secs": 10, "min_secs": 60, "max_secs": 7200} })),
    )
    .await
    .assert_problem(400, "dhcp.lease_times.invalid");
    app.send("PUT", "/dhcp/settings", Some(json!({ "history_days": 0 })))
        .await
        .assert_problem(400, "dhcp.settings.invalid");
    assert_eq!(app.audit_actions().await, ["dhcp.settings.update"]);
}

#[tokio::test]
async fn a_scope_is_created_read_listed_changed_and_deleted() {
    let app = App::new();
    let prefix = app.prefix("192.0.2.0/24").await;
    let created = app
        .send(
            "POST",
            "/dhcp/scopes",
            Some(json!({
                "prefix": prefix,
                "server_id": "192.0.2.1",
                "description": "office",
            })),
        )
        .await;
    created.assert_status(201);
    assert_eq!(created.body["prefix"], prefix.as_str());
    assert_eq!(created.body["cidr"], "192.0.2.0/24");
    assert_eq!(created.body["enabled"], true);
    assert_eq!(created.body["restricted"], false);
    assert_eq!(created.body["pools"], 0);
    let etag = created.etag();

    let path = format!("/dhcp/scopes/{prefix}");
    let got = app.get(&path).await;
    got.assert_status(200);
    assert_eq!(got.etag(), etag);
    assert_eq!(got.body["description"], "office");

    let list = app.get("/dhcp/scopes").await;
    list.assert_status(200);
    assert_eq!(list.items().len(), 1);

    let changed = app
        .send_with(
            "PATCH",
            &path,
            Some(json!({ "enabled": false, "lease": {"default_secs": 600, "min_secs": 300, "max_secs": 900} })),
            &[("if-match", &format!("\"{etag}\""))],
        )
        .await;
    changed.assert_status(200);
    assert_eq!(changed.body["enabled"], false);
    assert_eq!(changed.body["lease"]["default_secs"], 600);
    app.send_with(
        "PATCH",
        &path,
        Some(json!({ "enabled": true })),
        &[("if-match", &format!("\"{etag}\""))],
    )
    .await
    .assert_problem(412, "sys.store.precondition_failed");
    app.send("PATCH", &path, Some(json!({ "clear_lease": true })))
        .await
        .assert_status(200);
    assert_eq!(app.get(&path).await.body["lease"], Value::Null);

    app.send("PATCH", &path, Some(json!({ "server_id": "2001:db8::1" })))
        .await
        .assert_problem(400, "dhcp.scope.invalid");
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.scope.not_found");
    app.send("DELETE", &path, None)
        .await
        .assert_problem(404, "dhcp.scope.not_found");
    assert_eq!(
        app.audit_actions().await,
        [
            "dhcp.scope.create",
            "dhcp.scope.update",
            "dhcp.scope.update",
            "dhcp.scope.delete"
        ]
    );
}

#[tokio::test]
async fn a_scope_serves_one_network_that_ipam_keeps_while_it_exists() {
    let app = App::new();
    let supernet = app
        .prefix_with(json!({ "cidr": "198.51.100.0/24", "role": "supernet" }))
        .await;
    app.send("POST", "/dhcp/scopes", Some(json!({ "prefix": supernet })))
        .await
        .assert_problem(409, "dhcp.scope.not_network");
    app.send("POST", "/dhcp/scopes", Some(json!({ "prefix": MISSING })))
        .await
        .assert_problem(404, "ipam.not_found");

    let prefix = app.scope("192.0.2.0/24").await;
    app.send("POST", "/dhcp/scopes", Some(json!({ "prefix": prefix })))
        .await
        .assert_problem(409, "dhcp.scope.exists");
    // IPAM refuses to delete the prefix or to make it a supernet while the scope exists.
    app.send("DELETE", &format!("/prefixes/{prefix}?cascade=true"), None)
        .await
        .assert_problem(409, "dhcp.scope.attached");
    app.send(
        "PATCH",
        &format!("/prefixes/{prefix}"),
        Some(json!({ "role": "supernet" })),
    )
    .await
    .assert_problem(409, "dhcp.scope.attached");
    app.send("DELETE", &format!("/dhcp/scopes/{prefix}"), None)
        .await
        .assert_status(204);
    app.send("DELETE", &format!("/prefixes/{prefix}"), None)
        .await
        .assert_status(200);
}

#[tokio::test]
async fn exclusions_are_added_listed_and_deleted() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    let path = format!("/dhcp/scopes/{prefix}/exclusions");
    let created = app
        .send(
            "POST",
            &path,
            Some(json!({ "first": "192.0.2.50", "last": "192.0.2.59", "description": "printers" })),
        )
        .await;
    created.assert_status(201);
    let id = created.text("id");
    assert_eq!(created.body["scope"], prefix.as_str());
    app.send(
        "POST",
        &path,
        Some(json!({ "first": "192.0.2.20", "last": "192.0.2.10" })),
    )
    .await
    .assert_problem(400, "dhcp.exclusion.invalid");
    app.send(
        "POST",
        &path,
        Some(json!({ "first": "203.0.113.1", "last": "203.0.113.2" })),
    )
    .await
    .assert_problem(400, "dhcp.exclusion.invalid");
    app.send(
        "POST",
        &format!("/dhcp/scopes/{MISSING}/exclusions"),
        Some(json!({ "first": "192.0.2.1", "last": "192.0.2.2" })),
    )
    .await
    .assert_problem(404, "dhcp.scope.not_found");
    let list = app.get(&path).await;
    list.assert_status(200);
    assert_eq!(list.items().len(), 1);
    assert_eq!(list.items()[0]["first"], "192.0.2.50");
    app.send("DELETE", &format!("{path}/{id}"), None)
        .await
        .assert_status(204);
    app.send("DELETE", &format!("{path}/{id}"), None)
        .await
        .assert_problem(404, "dhcp.exclusion.not_found");
    assert_eq!(app.get(&path).await.items().len(), 0);
}

#[tokio::test]
async fn pools_are_ipam_ranges_with_dhcp_settings() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    let pool = app
        .range(&prefix, "192.0.2.100", "192.0.2.199", "dhcp_pool")
        .await;
    let infra = app
        .range(&prefix, "192.0.2.1", "192.0.2.9", "infrastructure")
        .await;
    let list = app.get("/dhcp/pools").await;
    list.assert_status(200);
    let items = list.items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["range"], pool.as_str());
    assert_eq!(items[0]["size"], 100);
    assert_eq!(items[0]["revision"], 0);
    assert_eq!(
        app.get(&format!("/dhcp/pools?scope={prefix}"))
            .await
            .items()
            .len(),
        1
    );

    let path = format!("/dhcp/pools/{pool}");
    let set = app
        .send_with(
            "PUT",
            &path,
            Some(json!({ "lease": {"default_secs": 1800, "min_secs": 900, "max_secs": 3600} })),
            &[("if-match", "\"0\"")],
        )
        .await;
    set.assert_status(200);
    assert_eq!(set.body["settings"]["lease"]["default_secs"], 1800);
    let etag = set.etag();
    assert_eq!(app.get(&path).await.etag(), etag);
    app.send("PUT", &format!("/dhcp/pools/{infra}"), Some(json!({})))
        .await
        .assert_problem(409, "dhcp.pool.not_pool");
    app.send("PUT", &format!("/dhcp/pools/{MISSING}"), Some(json!({})))
        .await
        .assert_problem(404, "dhcp.pool.not_found");
    app.send("PUT", &path, Some(json!({ "classes": [MISSING] })))
        .await
        .assert_problem(404, "dhcp.class.not_found");
    app.get(&format!("/dhcp/pools/{infra}"))
        .await
        .assert_problem(404, "dhcp.pool.not_found");
    app.send("DELETE", &path, None).await.assert_status(204);
    app.send("DELETE", &path, None)
        .await
        .assert_problem(404, "dhcp.pool.not_found");
    assert_eq!(app.get(&path).await.body["settings"], Value::Null);
    assert_eq!(
        app.audit_actions().await,
        ["dhcp.scope.create", "dhcp.pool.update", "dhcp.pool.delete"]
    );
}

#[tokio::test]
async fn the_utilization_counts_the_pool_against_exclusions_and_hosts() {
    let app = App::new();
    let prefix = app.scope("192.0.2.0/24").await;
    app.range(&prefix, "192.0.2.100", "192.0.2.199", "dhcp_pool")
        .await;
    app.send(
        "POST",
        &format!("/dhcp/scopes/{prefix}/exclusions"),
        Some(json!({ "first": "192.0.2.190", "last": "192.0.2.199" })),
    )
    .await
    .assert_status(201);
    // A static server inside the pool is never offered.
    app.host("server", "static", Some(2), "192.0.2.150").await;
    let figures = app.get(&format!("/dhcp/scopes/{prefix}/utilization")).await;
    figures.assert_status(200);
    assert_eq!(figures.body["pool_size"], 89);
    assert_eq!(figures.body["free"], 89);
    assert_eq!(figures.body["leased"], 0);
    assert_eq!(figures.body["utilization"], 0.0);
    app.get(&format!("/dhcp/scopes/{MISSING}/utilization"))
        .await
        .assert_problem(404, "dhcp.scope.not_found");
}

#[tokio::test]
async fn shared_networks_group_scopes_and_stay_while_used() {
    let app = App::new();
    let created = app
        .send(
            "POST",
            "/dhcp/shared-networks",
            Some(json!({ "name": "office-link", "interface": "eth1" })),
        )
        .await;
    created.assert_status(201);
    let id = created.text("id");
    app.send(
        "POST",
        "/dhcp/shared-networks",
        Some(json!({ "name": "office-link" })),
    )
    .await
    .assert_problem(400, "dhcp.shared_network.invalid");
    app.send(
        "POST",
        "/dhcp/shared-networks",
        Some(json!({ "name": "Not A Name" })),
    )
    .await
    .assert_problem(400, "dhcp.shared_network.invalid");
    let a = app.prefix("192.0.2.0/25").await;
    let b = app.prefix("192.0.2.128/25").await;
    for prefix in [&a, &b] {
        app.send(
            "POST",
            "/dhcp/scopes",
            Some(json!({ "prefix": prefix, "shared_network": id })),
        )
        .await
        .assert_status(201);
    }
    app.send(
        "POST",
        "/dhcp/scopes",
        Some(json!({ "prefix": app.prefix("203.0.113.0/24").await, "shared_network": MISSING })),
    )
    .await
    .assert_problem(404, "dhcp.shared_network.not_found");
    let path = format!("/dhcp/shared-networks/{id}");
    let got = app.get(&path).await;
    got.assert_status(200);
    assert_eq!(got.body["scopes"].as_array().expect("scopes").len(), 2);
    let changed = app
        .send_with(
            "PATCH",
            &path,
            Some(json!({ "interface": "" })),
            &[("if-match", &format!("\"{}\"", got.etag()))],
        )
        .await;
    changed.assert_status(200);
    assert_eq!(changed.body["interface"], Value::Null);
    assert_eq!(app.get("/dhcp/shared-networks").await.items().len(), 1);
    app.send("DELETE", &path, None)
        .await
        .assert_problem(409, "dhcp.shared_network.in_use");
    for prefix in [&a, &b] {
        app.send(
            "PATCH",
            &format!("/dhcp/scopes/{prefix}"),
            Some(json!({ "shared_network": "00000000-0000-0000-0000-000000000000" })),
        )
        .await
        .assert_status(200);
    }
    app.send("DELETE", &path, None).await.assert_status(204);
    app.get(&path)
        .await
        .assert_problem(404, "dhcp.shared_network.not_found");
}

#[tokio::test]
async fn without_the_service_the_routes_say_the_module_is_off() {
    let router = dhcp_support::App::without_service();
    for (method, path) in [
        ("GET", "/dhcp/settings".to_owned()),
        ("GET", "/dhcp/scopes".to_owned()),
        ("GET", format!("/dhcp/scopes/{MISSING}")),
        ("GET", "/dhcp/pools".to_owned()),
        ("GET", "/dhcp/classes".to_owned()),
    ] {
        send(&router, method, &path, None, &[])
            .await
            .assert_problem(409, "dhcp.module.disabled");
    }
    // The routes of later packages are declared and answer 501; the lease routes answer
    // through the dhcp role, which this server does not run (WP7.5).
    send(&router, "GET", "/dhcp/reservations", None, &[])
        .await
        .assert_problem(501, "sys.not_implemented");
    send(&router, "GET", "/dhcp/leases", None, &[])
        .await
        .assert_problem(409, "dhcp.node.not_dhcp");
}

#[tokio::test]
async fn pages_follow_the_cursor() {
    let app = App::new();
    for third in 0..5 {
        app.scope(&format!("192.0.2.{}/27", third * 32)).await;
    }
    let first = app.get("/dhcp/scopes?limit=2").await;
    first.assert_status(200);
    assert_eq!(first.items().len(), 2);
    let cursor = first.text("next_cursor");
    let second = app
        .get(&format!("/dhcp/scopes?limit=2&cursor={cursor}"))
        .await;
    assert_eq!(second.items().len(), 2);
    let third = app
        .get(&format!(
            "/dhcp/scopes?limit=2&cursor={}",
            second.text("next_cursor")
        ))
        .await;
    assert_eq!(third.items().len(), 1);
    assert_eq!(third.body["next_cursor"], Value::Null);
    let cidrs: Vec<String> = [first, second, third]
        .iter()
        .flat_map(dhcp_support::Reply::items)
        .map(|item| item["cidr"].as_str().expect("cidr").to_owned())
        .collect();
    assert_eq!(
        cidrs,
        [
            "192.0.2.0/27",
            "192.0.2.32/27",
            "192.0.2.64/27",
            "192.0.2.96/27",
            "192.0.2.128/27"
        ]
    );
}
