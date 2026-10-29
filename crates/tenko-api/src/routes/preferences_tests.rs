//! Route tests of the personal preferences: own data only, sessions only, the schema, the
//! size and count bounds, the unknown key, nothing audited, and the removal with the account.

use serde_json::{Value, json};
use tenko_auth::{
    model::PREFERENCES,
    preferences::{MAX_DOCUMENT_BYTES, MAX_KEYS},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store as _};

use crate::routes::auth::testkit::{Credential::*, Harness};

fn layout() -> Value {
    json!({
        "version": 1,
        "order": ["ip", "dns_name", "mode"],
        "hidden": ["mac"],
        "widths": { "ip": 140, "dns_name": 220 },
        "sort": { "column": "ip", "desc": true }
    })
}

/// The installation, the administrator's session, and a second person (an operator) with
/// a session of their own.
async fn two_people() -> (Harness, String, String, String) {
    let (harness, admin) = Harness::installed().await;
    let user = harness
        .create_user(&admin, "operator-1", "5937", &["operator"])
        .await;
    let id = user["id"].as_str().expect("an id").to_owned();
    let operator = harness.login("operator-1", "5937").await;
    (harness, admin, operator, id)
}

#[tokio::test]
async fn a_person_writes_reads_and_removes_their_own_layouts() {
    let (harness, admin, _, _) = two_people().await;
    let empty = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    empty.assert_status(200);
    assert_eq!(empty.body["items"], json!([]));
    assert!(empty.body["next_cursor"].is_null());

    let put = harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            Some(&layout()),
        )
        .await;
    put.assert_status(200);
    assert_eq!(put.body["key"], "table:addresses");
    assert_eq!(put.body["value"], layout());
    assert!(put.body["updated_at"].is_string());
    harness
        .call(
            "PUT",
            "/auth/preferences/table:dhcp-leases",
            Cookie(&admin),
            Some(&json!({ "version": 1 })),
        )
        .await
        .assert_status(200);

    // Replacing a key keeps one row; the list is ordered by key.
    let changed = json!({ "version": 1, "hidden": [] });
    harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            Some(&changed),
        )
        .await
        .assert_status(200);
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    list.assert_status(200);
    let keys: Vec<&str> = list.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["key"].as_str().expect("a key"))
        .collect();
    assert_eq!(keys, ["table:addresses", "table:dhcp-leases"]);
    assert_eq!(list.body["items"][0]["value"], changed);

    harness
        .call(
            "DELETE",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            None,
        )
        .await
        .assert_status(204);
    harness
        .call(
            "DELETE",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            None,
        )
        .await
        .assert_problem(404, "auth.preference.not_found");
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);

    // A layout is not a change of the installation: nothing is audited.
    let actions = harness.audit_actions().await;
    assert!(
        actions.iter().all(|action| !action.contains("preference")),
        "{actions:?}"
    );
}

#[tokio::test]
async fn one_person_never_sees_or_changes_another_persons_layouts() {
    let (harness, admin, operator, _) = two_people().await;
    harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            Some(&layout()),
        )
        .await
        .assert_status(200);

    // The operator has none, and the same key is their own.
    let theirs = harness
        .call("GET", "/auth/preferences", Cookie(&operator), None)
        .await;
    theirs.assert_status(200);
    assert_eq!(theirs.body["items"], json!([]));
    harness
        .call(
            "DELETE",
            "/auth/preferences/table:addresses",
            Cookie(&operator),
            None,
        )
        .await
        .assert_problem(404, "auth.preference.not_found");
    let own = json!({ "version": 1, "order": ["mac", "ip"] });
    harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&operator),
            Some(&own),
        )
        .await
        .assert_status(200);

    // Each reads only their own document; the administrator's role reaches no further.
    let admins = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(admins.body["items"][0]["value"], layout());
    let operators = harness
        .call("GET", "/auth/preferences", Cookie(&operator), None)
        .await;
    assert_eq!(operators.body["items"][0]["value"], own);
    harness
        .call(
            "DELETE",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            None,
        )
        .await
        .assert_status(204);
    let operators = harness
        .call("GET", "/auth/preferences", Cookie(&operator), None)
        .await;
    assert_eq!(operators.body["items"][0]["value"], own, "untouched");
}

#[tokio::test]
async fn tokens_and_anonymous_requests_are_refused() {
    let (harness, admin) = Harness::installed().await;
    let created = harness
        .call(
            "POST",
            "/auth/tokens",
            Cookie(&admin),
            Some(&json!({ "name": "layouts", "expires_in_days": 30 })),
        )
        .await;
    created.assert_status(201);
    let token = created.body["token"].as_str().expect("a token").to_owned();
    for credential in [Bearer(&token), Anonymous] {
        harness
            .call("GET", "/auth/preferences", credential, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call(
                "PUT",
                "/auth/preferences/table:addresses",
                credential,
                Some(&layout()),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call(
                "DELETE",
                "/auth/preferences/table:addresses",
                credential,
                None,
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
    }
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(list.body["items"], json!([]), "the token wrote nothing");
}

#[tokio::test]
async fn the_document_and_the_key_follow_the_schema() {
    let (harness, admin) = Harness::installed().await;
    let put = |key: &'static str, body: Value| {
        let harness = &harness;
        let admin = admin.clone();
        async move {
            harness
                .call(
                    "PUT",
                    &format!("/auth/preferences/{key}"),
                    Cookie(&admin),
                    Some(&body),
                )
                .await
        }
    };
    // Unknown fields, at the top and inside the sort, and a missing version.
    put(
        "table:addresses",
        json!({ "version": 1, "html": "<b>x</b>" }),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    put(
        "table:addresses",
        json!({ "version": 1, "sort": { "column": "ip", "by": 1 } }),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    put("table:addresses", json!({ "order": [] }))
        .await
        .assert_problem(400, "sys.invalid_request");
    put(
        "table:addresses",
        json!({ "version": 1, "widths": { "ip": "wide" } }),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    // Values outside the bounds name their field.
    for (body, field) in [
        (json!({ "version": 2 }), "version"),
        (json!({ "version": 1, "order": ["ip", "ip"] }), "order"),
        (json!({ "version": 1, "hidden": ["<script>"] }), "hidden"),
        (json!({ "version": 1, "widths": { "ip": 1201 } }), "widths"),
        (json!({ "version": 1, "widths": { "ip": 8 } }), "widths"),
        (json!({ "version": 1, "sort": { "column": "" } }), "sort"),
    ] {
        let reply = put("table:addresses", body).await;
        reply.assert_problem(400, "auth.invalid_request");
        assert_eq!(reply.body["errors"][0]["field"], field, "{}", reply.body);
    }
    // Keys are `table:<id>`.
    for key in [
        "addresses",
        "table:",
        "table:Addresses",
        "theme:dark",
        "table:a%20b",
    ] {
        let reply = harness
            .call(
                "PUT",
                &format!("/auth/preferences/{key}"),
                Cookie(&admin),
                Some(&layout()),
            )
            .await;
        reply.assert_problem(400, "auth.invalid_request");
        assert_eq!(reply.body["errors"][0]["field"], "key", "{key}");
        harness
            .call(
                "DELETE",
                &format!("/auth/preferences/{key}"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_problem(400, "auth.invalid_request");
    }
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(list.body["items"], json!([]), "nothing was stored");
}

#[tokio::test]
async fn a_document_over_16_kib_is_refused() {
    let (harness, admin) = Harness::installed().await;
    let ids: Vec<String> = (0..128).map(|i| format!("{i:0>64}")).collect();
    let body = json!({ "version": 1, "order": ids, "hidden": ids });
    assert!(body.to_string().len() > MAX_DOCUMENT_BYTES);
    let reply = harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            Some(&body),
        )
        .await;
    reply.assert_problem(413, "auth.preference.too_large");
    assert_eq!(reply.body["params"]["max_bytes"], "16384", "{}", reply.body);
    // Just under the limit is stored.
    let ids: Vec<String> = (0..120).map(|i| format!("{i:0>64}")).collect();
    let body = json!({ "version": 1, "order": ids, "hidden": ids[..100] });
    assert!(body.to_string().len() <= MAX_DOCUMENT_BYTES);
    harness
        .call(
            "PUT",
            "/auth/preferences/table:addresses",
            Cookie(&admin),
            Some(&body),
        )
        .await
        .assert_status(200);
}

#[tokio::test]
async fn a_person_stores_at_most_64_keys() {
    let (harness, admin) = Harness::installed().await;
    let small = json!({ "version": 1 });
    for n in 0..MAX_KEYS {
        harness
            .call(
                "PUT",
                &format!("/auth/preferences/table:t{n}"),
                Cookie(&admin),
                Some(&small),
            )
            .await
            .assert_status(200);
    }
    let reply = harness
        .call(
            "PUT",
            "/auth/preferences/table:one-more",
            Cookie(&admin),
            Some(&small),
        )
        .await;
    reply.assert_problem(409, "auth.preference.limit");
    assert_eq!(reply.body["params"]["max_keys"], "64", "{}", reply.body);
    // An existing key can still be replaced, and a removal makes room.
    harness
        .call(
            "PUT",
            "/auth/preferences/table:t3",
            Cookie(&admin),
            Some(&layout()),
        )
        .await
        .assert_status(200);
    harness
        .call("DELETE", "/auth/preferences/table:t0", Cookie(&admin), None)
        .await
        .assert_status(204);
    harness
        .call(
            "PUT",
            "/auth/preferences/table:one-more",
            Cookie(&admin),
            Some(&small),
        )
        .await
        .assert_status(200);
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(
        list.body["items"].as_array().expect("items").len(),
        MAX_KEYS
    );
}

#[tokio::test]
async fn deleting_an_account_removes_its_layouts() {
    let (harness, admin, operator, id) = two_people().await;
    harness
        .call(
            "PUT",
            "/auth/preferences/table:hosts",
            Cookie(&operator),
            Some(&layout()),
        )
        .await
        .assert_status(200);
    harness
        .call(
            "PUT",
            "/auth/preferences/table:hosts",
            Cookie(&admin),
            Some(&layout()),
        )
        .await
        .assert_status(200);
    harness
        .call("DELETE", &format!("/users/{id}"), Cookie(&admin), None)
        .await
        .assert_status(204);
    let view = harness
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let rows = view
        .scan_typed(&PREFERENCES, KeyRange::all(), 100, false)
        .expect("the table");
    assert_eq!(rows.len(), 1, "only the administrator's row is left");
    let list = harness
        .call("GET", "/auth/preferences", Cookie(&admin), None)
        .await;
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
}
