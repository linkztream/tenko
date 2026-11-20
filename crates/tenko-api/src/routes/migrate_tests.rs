//! Route tests of the mirrored sources (WP14.1, E73): how the push and the management
//! operations answer over HTTP, each refusal with its status and code. What the service does
//! behind them is `crates/tenko-migrate/tests/mirror_service.rs`. The service runs on the
//! harness's clock, so the floor between pushes and the minute between audited refusals are
//! the test's, not the machine's.

use std::{io::Write as _, sync::Arc, time::Duration};

use axum::{
    Extension,
    body::Body,
    http::{Request, header},
};
use serde_json::json;
use tenko_auth::clock::Clock;
use tenko_migrate::mirror::MirrorService;
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store as _, tables};

use crate::{
    API_BASE,
    modules::ModuleSet,
    routes::auth::testkit::{Credential::*, Harness, Reply},
};

const FIXTURE: &str = include_str!("../../../tenko-core/tests/fixtures/mirror/snapshot.json");

async fn harness() -> (Harness, String) {
    let (plain, admin) = Harness::installed().await;
    let env = plain.env;
    let clock: Arc<dyn Clock> = env.clock.clone();
    let service =
        Arc::new(MirrorService::new(env.store.clone(), Arc::clone(&env.service)).with_clock(clock));
    let harness = Harness::wired(env, move |state| {
        crate::api_with(state, ModuleSet::ALL)
            .0
            .layer(Extension(service))
    });
    (harness, admin)
}

/// Moves the service's clock past the floor between two pushes.
fn later(harness: &Harness, secs: u64) {
    harness.env.clock.advance(Duration::from_secs(secs));
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
    credential: &str,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> Reply {
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{API_BASE}/migrate/mirrors/{id}/snapshot"))
        .header(header::AUTHORIZATION, format!("Bearer {credential}"))
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

async fn refusals(harness: &Harness) -> usize {
    let view = harness
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == "migrate.mirror.refuse")
        .count()
}

#[tokio::test]
async fn a_push_answers_with_its_status_and_code() {
    let (harness, admin) = harness().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let accepted = push(&harness, &id, &token, snapshot(1), &[]).await;
    accepted.assert_status(200);
    assert_eq!(accepted.body, json!({ "sequence": 1, "changed": true }));
    later(&harness, 10);
    let gzipped = push(
        &harness,
        &id,
        &token,
        gzip(&snapshot(2)),
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(gzipped.body, json!({ "sequence": 2, "changed": false }));

    later(&harness, 10);
    let replay = push(&harness, &id, &token, snapshot(2), &[]).await;
    replay.assert_problem(409, "migrate.mirror.sequence");
    assert_eq!(
        (
            &replay.body["params"]["sequence"],
            &replay.body["params"]["last"]
        ),
        (&json!("2"), &json!("2"))
    );
    later(&harness, 10);
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
    later(&harness, 10);
    push(
        &harness,
        &id,
        &token,
        snapshot(3),
        &[("content-encoding", "br")],
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    // A body above the bound without a declared length: the read stops at the bound.
    later(&harness, 10);
    let chunks = (0..9).map(|_| Ok::<_, std::io::Error>(vec![b' '; 1 << 20]));
    let streamed = push(
        &harness,
        &id,
        &token,
        Body::from_stream(futures::stream::iter(chunks)),
        &[],
    )
    .await;
    streamed.assert_problem(413, "migrate.mirror.too_large");
    // Within the floor: 429 with the seconds to wait.
    let fast = push(&harness, &id, &token, snapshot(9), &[]).await;
    fast.assert_problem(429, "migrate.mirror.rate");
    assert_eq!(fast.header("retry-after"), Some("10"));

    // Every refusal above came within one minute of the first: one audit record.
    assert_eq!(refusals(&harness).await, 1);
    later(&harness, 61);
    push(&harness, &id, &token, snapshot(2), &[])
        .await
        .assert_problem(409, "migrate.mirror.sequence");
    assert_eq!(refusals(&harness).await, 2);
}

#[tokio::test]
async fn a_node_decodes_one_push_at_a_time() {
    let (harness, admin) = harness().await;
    let (first, first_token) = mirror(&harness, &admin, "dc1").await;
    let (second, second_token) = mirror(&harness, &admin, "dc2").await;
    // The first body arrives in two parts; the second push comes while the first is read.
    let (part, parts) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let reading = Arc::new(tokio::sync::Notify::new());
    let body = futures::stream::unfold(
        (parts, Arc::clone(&reading)),
        |(mut parts, reading)| async move {
            reading.notify_one();
            let chunk = parts.recv().await?;
            Some((Ok::<_, std::io::Error>(chunk), (parts, reading)))
        },
    );
    let text = snapshot(1);
    let (start, rest) = text.split_at(10);
    let harness = &harness;
    let (slow, busy) = tokio::join!(
        push(harness, &first, &first_token, Body::from_stream(body), &[]),
        async move {
            reading.notified().await;
            let busy = push(harness, &second, &second_token, snapshot(1), &[]).await;
            part.send(start.as_bytes().to_vec()).await.expect("sent");
            part.send(rest.as_bytes().to_vec()).await.expect("sent");
            (busy, second, second_token)
        }
    );
    let (busy, second, second_token) = busy;
    busy.assert_problem(429, "migrate.mirror.rate");
    assert_eq!(busy.header("retry-after"), Some("2"));
    slow.assert_status(200);
    push(harness, &second, &second_token, snapshot(1), &[])
        .await
        .assert_status(200);
}

#[tokio::test]
async fn only_the_mirror_s_own_token_pushes() {
    let (harness, admin) = harness().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let (other, other_token) = mirror(&harness, &admin, "dc2").await;
    push(&harness, &id, &other_token, snapshot(1), &[])
        .await
        .assert_problem(403, "auth.forbidden");
    push(&harness, &other, &token, snapshot(1), &[])
        .await
        .assert_problem(403, "auth.forbidden");
    let personal = harness
        .call(
            "POST",
            "/auth/tokens",
            Cookie(&admin),
            Some(&json!({ "name": "automation", "expires_in_days": 30 })),
        )
        .await;
    personal.assert_status(201);
    let personal = personal.body["token"].as_str().expect("token").to_owned();
    push(&harness, &id, &personal, snapshot(1), &[])
        .await
        .assert_problem(403, "auth.forbidden");
    let by_session = harness
        .call(
            "PUT",
            &format!("/migrate/mirrors/{id}/snapshot"),
            Cookie(&admin),
            Some(&serde_json::from_str(&snapshot(1)).expect("json")),
        )
        .await;
    by_session.assert_problem(403, "auth.forbidden");

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
        .assert_problem(401, "auth.unauthenticated");
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
        .assert_problem(401, "auth.unauthenticated");
}

#[tokio::test]
async fn the_management_operations_answer_with_their_codes() {
    let (harness, admin) = harness().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let exists = harness
        .call(
            "POST",
            "/migrate/mirrors",
            Cookie(&admin),
            Some(&json!({ "name": "dc1", "kind": "windows-dhcp" })),
        )
        .await;
    exists.assert_problem(409, "migrate.mirror.exists");
    assert_eq!(exists.body["params"]["name"], "dc1");
    harness
        .call(
            "PATCH",
            &format!("/migrate/mirrors/{id}"),
            Cookie(&admin),
            Some(&json!({ "name": "dc 1" })),
        )
        .await
        .assert_problem(400, "migrate.mirror.invalid_settings");
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
    assert_eq!(list.body["items"][0]["losses_open"], 4);
    let losses = harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/losses"),
            Cookie(&admin),
            None,
        )
        .await;
    let key = losses.body["entries"][0]["key"].clone();
    harness
        .call(
            "POST",
            &format!("/migrate/mirrors/{id}/losses/ack"),
            Cookie(&admin),
            Some(&json!({ "sequence": 1, "keys": [key] })),
        )
        .await
        .assert_status(200);
    later(&harness, 10);
    push(
        &harness,
        &id,
        &token,
        snapshot(2).replacen(
            "is not carried; policies",
            "is not carried now; policies",
            1,
        ),
        &[],
    )
    .await
    .assert_status(200);
    harness
        .call(
            "POST",
            &format!("/migrate/mirrors/{id}/losses/ack"),
            Cookie(&admin),
            Some(&json!({ "sequence": 1, "keys": [key] })),
        )
        .await
        .assert_problem(409, "migrate.mirror.snapshot_moved");
    let diff = harness
        .call(
            "GET",
            &format!("/migrate/mirrors/{id}/scopes/192.0.2.0%2F24/diff"),
            Cookie(&admin),
            None,
        )
        .await;
    diff.assert_status(200);
    assert_eq!(diff.body["scope"], "192.0.2.0/24");
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
