//! Route tests of the mirrored sources (WP14.1, E73): the push with each refusal it answers,
//! the management operations a session reaches and a token does not, the losses and the
//! diff. The service runs over the harness's store and auth service; its floor between two
//! pushes is zero here (the harness runs on the real clock) except where the floor itself is
//! tested.

use std::{io::Write as _, sync::Arc};

use axum::{
    Extension,
    body::Body,
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_migrate::mirror::MirrorService;
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store as _, tables};

use crate::{
    API_BASE,
    modules::ModuleSet,
    routes::auth::testkit::{Credential::*, Harness, Reply},
};

const FIXTURE: &str = include_str!("../../../tenko-core/tests/fixtures/mirror/snapshot.json");

async fn harness(floor: u64) -> (Harness, String) {
    let (plain, admin) = Harness::installed().await;
    let env = plain.env;
    let service =
        Arc::new(MirrorService::new(env.store.clone(), Arc::clone(&env.service)).with_floor(floor));
    let harness = Harness::wired(env, move |state| {
        crate::api_with(state, ModuleSet::ALL)
            .0
            .layer(Extension(service))
    });
    (harness, admin)
}

/// Creates a mirror and returns its id and token.
async fn mirror(harness: &Harness, admin: &str, name: &str) -> (String, String) {
    let reply = harness
        .call(
            "POST",
            "/migrate/mirrors",
            Cookie(admin),
            Some(&json!({ "name": name, "kind": "windows-dhcp", "token_expires_in_days": 30 })),
        )
        .await;
    reply.assert_status(201);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    (
        reply.body["mirror"]["id"]
            .as_str()
            .expect("an id")
            .to_owned(),
        reply.body["token"].as_str().expect("the token").to_owned(),
    )
}

/// The fixture with another sequence.
fn snapshot(sequence: u64) -> String {
    FIXTURE.replacen("\"sequence\": 1,", &format!("\"sequence\": {sequence},"), 1)
}

async fn push(
    harness: &Harness,
    id: &str,
    token: &str,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> Reply {
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{API_BASE}/migrate/mirrors/{id}/snapshot"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    harness
        .send(request.body(body.into()).expect("a request"))
        .await
}

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).expect("gzip");
    encoder.finish().expect("gzip")
}

#[tokio::test]
async fn a_push_is_accepted_once_per_sequence_and_refused_with_its_code() {
    let (harness, admin) = harness(0).await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let accepted = push(&harness, &id, &token, snapshot(1), &[]).await;
    accepted.assert_status(200);
    assert_eq!(accepted.body, json!({ "sequence": 1, "changed": true }));
    let gzipped = push(
        &harness,
        &id,
        &token,
        gzip(&snapshot(2)),
        &[("content-encoding", "gzip")],
    )
    .await;
    gzipped.assert_status(200);
    assert_eq!(gzipped.body["changed"], false, "the same content");

    push(&harness, &id, &token, snapshot(2), &[])
        .await
        .assert_problem(409, "migrate.mirror.sequence");
    push(&harness, &id, &token, "", &[("content-length", "9000000")])
        .await
        .assert_problem(413, "migrate.mirror.too_large");
    let invalid = push(
        &harness,
        &id,
        &token,
        snapshot(3).replacen("\"192.0.2.110\"", "\"192.0.2.0.1\"", 1),
        &[],
    )
    .await;
    invalid.assert_problem(422, "migrate.mirror.invalid");
    assert_eq!(invalid.body["params"]["path"], "dhcp.leases[0].ip");
    push(
        &harness,
        &id,
        &token,
        snapshot(3),
        &[("content-encoding", "br")],
    )
    .await
    .assert_problem(400, "sys.invalid_request");

    // Nothing of a refused push is kept, and the refusals are audited once a minute.
    let stored = harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/snapshot"),
            Cookie(&admin),
            None,
        )
        .await;
    stored.assert_status(200);
    assert_eq!(stored.body["sequence"], 1);
    let view = harness
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let refusals = view
        .scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == "migrate.mirror.refuse")
        .count();
    assert_eq!(refusals, 1);
}

#[tokio::test]
async fn the_push_is_the_token_s_own_and_the_token_reaches_nothing_else() {
    let (harness, admin) = harness(0).await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let (other, other_token) = mirror(&harness, &admin, "dc2").await;
    push(&harness, &id, &other_token, snapshot(1), &[])
        .await
        .assert_problem(403, "auth.forbidden");
    push(&harness, &other, &token, snapshot(1), &[])
        .await
        .assert_problem(403, "auth.forbidden");
    let by_session = harness
        .call(
            "PUT",
            &format!("/migrate/mirrors/{id}/snapshot"),
            Cookie(&admin),
            Some(&serde_json::from_str::<Value>(&snapshot(1)).expect("json")),
        )
        .await;
    by_session.assert_problem(403, "auth.forbidden");
    push(&harness, &id, "tnk_not-a-token", snapshot(1), &[])
        .await
        .assert_status(401);
    for (method, path) in [
        ("GET", format!("/migrate/mirrors/{id}")),
        ("GET", format!("/migrate/mirrors/{id}/snapshot")),
        ("GET", format!("/migrate/mirrors/{id}/losses")),
        ("GET", "/migrate/mirrors".to_owned()),
        ("DELETE", format!("/migrate/mirrors/{id}")),
    ] {
        let reply = harness.call(method, &path, Bearer(&token), None).await;
        assert_eq!(
            reply.status.as_u16(),
            403,
            "{method} {path}: {}",
            reply.body
        );
    }

    harness
        .call(
            "PATCH",
            &format!("/migrate/mirrors/{id}"),
            Cookie(&admin),
            Some(&json!({ "enabled": false })),
        )
        .await
        .assert_status(200);
    push(&harness, &id, &token, snapshot(1), &[])
        .await
        .assert_problem(403, "migrate.mirror.disabled");

    let renewed = harness
        .call(
            "POST",
            &format!("/migrate/mirrors/{id}/token"),
            Cookie(&admin),
            Some(&json!({})),
        )
        .await;
    renewed.assert_status(201);
    push(&harness, &id, &token, snapshot(1), &[])
        .await
        .assert_status(401);
    harness
        .call(
            "DELETE",
            &format!("/migrate/mirrors/{id}"),
            Cookie(&admin),
            None,
        )
        .await
        .assert_status(204);
    let new_token = renewed.body["token"].as_str().expect("token");
    push(&harness, &id, new_token, snapshot(1), &[])
        .await
        .assert_status(401);
}

#[tokio::test]
async fn a_push_faster_than_the_floor_is_refused_with_retry_after() {
    let (harness, admin) = harness(10).await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    push(&harness, &id, &token, snapshot(1), &[])
        .await
        .assert_status(200);
    let refused = push(&harness, &id, &token, snapshot(2), &[]).await;
    refused.assert_problem(429, "migrate.mirror.rate");
    let retry: u64 = refused
        .header("retry-after")
        .expect("Retry-After")
        .parse()
        .expect("seconds");
    assert!((1..=10).contains(&retry), "{retry}");
}

#[tokio::test]
async fn the_card_the_losses_and_the_diff_read_the_latest_snapshot() {
    let (harness, admin) = harness(0).await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/losses"),
            Cookie(&admin),
            None,
        )
        .await
        .assert_problem(404, "migrate.mirror.no_snapshot");
    push(&harness, &id, &token, snapshot(1), &[])
        .await
        .assert_status(200);

    let list = harness
        .call("GET", "/migrate/mirrors", Cookie(&admin), None)
        .await;
    list.assert_status(200);
    let card = &list.body["items"][0];
    assert_eq!(
        (
            &card["name"],
            &card["stale"],
            &card["losses_open"],
            &card["counts"]["leases"]
        ),
        (&json!("dc1"), &json!(false), &json!(4), &json!(60))
    );
    assert_eq!(card["source"]["server"], "dc1.corp.example.test");

    let losses = harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/losses"),
            Cookie(&admin),
            None,
        )
        .await;
    losses.assert_status(200);
    let key = losses.body["entries"][0]["key"].clone();
    harness
        .call(
            "POST",
            &format!("/migrate/mirrors/{id}/losses/ack"),
            Cookie(&admin),
            Some(&json!({ "keys": [key] })),
        )
        .await
        .assert_status(200);
    harness
        .call(
            "POST",
            &format!("/migrate/mirrors/{id}/losses/ack"),
            Cookie(&admin),
            Some(&json!({ "keys": ["no such entry"] })),
        )
        .await
        .assert_problem(400, "sys.invalid_request");

    let diff = harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/scopes/192.0.2.0%2F24/diff"),
            Cookie(&admin),
            None,
        )
        .await;
    diff.assert_status(200);
    assert_eq!(diff.body["losses_open"], 3);
    assert_eq!(diff.body["rows"][0]["kind"], "prefix");
    harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/scopes/198.51.100.0%2F24/diff"),
            Cookie(&admin),
            None,
        )
        .await
        .assert_problem(404, "migrate.mirror.scope_not_found");
}
