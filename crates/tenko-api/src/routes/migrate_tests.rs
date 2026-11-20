//! Route tests of the mirrored sources (WP14.1, E73): how the push and the management
//! operations answer over HTTP, each refusal with its status and code. What the service does
//! behind them is `crates/tenko-migrate/tests/mirror_service.rs`. The service runs on the
//! harness's clock, so the floor between pushes and the minute between audited refusals are
//! the test's, not the machine's.

use std::{io::Write as _, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::Body,
    http::{Request, header},
};
use serde_json::json;
use tenko_auth::clock::Clock;
use tenko_core::Authenticator;
use tenko_migrate::mirror::MirrorService;
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, Store as _, tables};

use crate::{
    API_BASE,
    middleware::HttpConfig,
    modules::ModuleSet,
    routes::auth::testkit::{Credential::*, Harness, Reply, send_to},
    server,
    state::AppState,
    ui::UiSource,
};

const FIXTURE: &str = include_str!("../../../tenko-core/tests/fixtures/mirror/snapshot.json");

async fn harness() -> (Harness, String) {
    let (harness, admin, _) = harness_with_app().await;
    (harness, admin)
}

/// A harness over the API's routes, and the API listener's router as the server builds it
/// (`server::app`, with `middleware::outer` and its deadline for request bodies) over the
/// same environment and mirror service.
async fn harness_with_app() -> (Harness, String, Router) {
    let (plain, admin) = Harness::installed().await;
    let env = plain.env;
    let clock: Arc<dyn Clock> = env.clock.clone();
    let service =
        Arc::new(MirrorService::new(env.store.clone(), Arc::clone(&env.service)).with_clock(clock));
    let authenticator: Arc<dyn Authenticator> = env.service.clone();
    let mut state = AppState::new(env.store.clone());
    state.auth = Some(authenticator);
    state.authorizer = Some(env.service.authorizer());
    let app = server::app(state, &HttpConfig::default(), &UiSource::Embedded)
        .expect("the application")
        .layer(Extension(Arc::clone(&service)))
        .layer(Extension(env.service.clone()));
    let harness = Harness::wired(env, move |state| {
        crate::api_with(state, ModuleSet::ALL)
            .0
            .layer(Extension(service))
    });
    (harness, admin, app)
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

fn push_request(
    id: &str,
    credential: &str,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{API_BASE}/migrate/mirrors/{id}/snapshot"))
        .header(header::AUTHORIZATION, format!("Bearer {credential}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(body.into()).expect("a request")
}

async fn push(
    harness: &Harness,
    id: &str,
    credential: &str,
    body: impl Into<Body>,
    headers: &[(&str, &str)],
) -> Reply {
    harness
        .send(push_request(id, credential, body, headers))
        .await
}

/// A push through the server's own router.
async fn push_to(app: &Router, id: &str, credential: &str, body: impl Into<Body>) -> Reply {
    send_to(app.clone(), push_request(id, credential, body, &[])).await
}

/// The codes of the audited refusals of pushes, oldest first.
async fn refused_codes(harness: &Harness) -> Vec<String> {
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
        .map(|(_, record, _)| record.draft.details.context["code"].clone())
        .collect()
}

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).expect("gzip");
    encoder.finish().expect("gzip")
}

async fn refusals(harness: &Harness) -> usize {
    refused_codes(harness).await.len()
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

/// A body that arrives in the parts sent on the channel it returns, and a signal that the
/// route has started to read it.
fn slow_body() -> (
    Body,
    tokio::sync::mpsc::Sender<Vec<u8>>,
    Arc<tokio::sync::Notify>,
) {
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
    (Body::from_stream(body), part, reading)
}

#[tokio::test]
async fn a_slow_body_holds_one_push_of_its_mirror_and_no_other_mirror_s() {
    let (harness, admin, app) = harness_with_app().await;
    let (first, first_token) = mirror(&harness, &admin, "dc1").await;
    let (second, second_token) = mirror(&harness, &admin, "dc2").await;
    // Through the server's own router: the first body sends a few octets and then nothing.
    // Time stands still from here and moves on whenever nothing else is to be done: while
    // the first body is still arriving, its mirror's next push and the other mirror push,
    // and the first ends at the server's deadline for bodies.
    let (body, part, reading) = slow_body();
    part.send(b"{\"format\"".to_vec()).await.expect("sent");
    tokio::time::pause();
    let app = &app;
    let (slow, (again, other)) = tokio::join!(push_to(app, &first, &first_token, body), async {
        reading.notified().await;
        (
            push_to(app, &first, &first_token, snapshot(1)).await,
            push_to(app, &second, &second_token, snapshot(1)).await,
        )
    });
    // One push of a mirror in flight on the node: the second waits for no body.
    again.assert_problem(429, "migrate.mirror.rate");
    assert_eq!(again.header("retry-after"), Some("10"));
    // Had the first push held the node's decode while its body arrived, the other mirror
    // would have waited for it and been answered 429.
    other.assert_status(200);
    slow.assert_problem(408, "sys.body_timeout");
    drop(part);
    // The cut push is over: the mirror's next one is admitted.
    later(&harness, 10);
    push_to(app, &first, &first_token, snapshot(1))
        .await
        .assert_status(200);
}

#[tokio::test]
async fn a_push_cut_by_the_body_deadline_is_audited_as_such() {
    let (harness, admin, app) = harness_with_app().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let (body, part, _) = slow_body();
    part.send(b"{".to_vec()).await.expect("sent");
    tokio::time::pause();
    push_to(&app, &id, &token, body)
        .await
        .assert_problem(408, "sys.body_timeout");
    assert_eq!(refused_codes(&harness).await, ["sys.body_timeout"]);
    drop(part);
}

#[tokio::test]
async fn a_push_whose_connection_drops_lets_its_mirror_s_next_one_in() {
    let (harness, admin, app) = harness_with_app().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    let (body, part, reading) = slow_body();
    let dropped = tokio::spawn(send_to(app.clone(), push_request(&id, &token, body, &[])));
    reading.notified().await;
    dropped.abort();
    assert!(dropped.await.expect_err("aborted").is_cancelled());
    drop(part);
    later(&harness, 10);
    push_to(&app, &id, &token, snapshot(1))
        .await
        .assert_status(200);
}

#[tokio::test]
async fn a_finding_names_mirrors_that_share_a_name_by_their_ids() {
    let (harness, admin) = harness().await;
    let (first, first_token) = mirror(&harness, &admin, "dc").await;
    let (second, second_token) = mirror(&harness, &admin, "dc").await;
    push(&harness, &first, &first_token, snapshot(1), &[])
        .await
        .assert_status(200);
    push(&harness, &second, &second_token, snapshot(1), &[])
        .await
        .assert_status(200);
    later(&harness, 200);
    let status = harness
        .call("GET", "/system/status", Cookie(&admin), None)
        .await;
    status.assert_status(200);
    let stale = status.body["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .find(|warning| warning["code"] == "migrate.mirror.stale")
        .expect("the stale mirrors");
    let short = |id: &str| id[id.len() - 8..].to_owned();
    let mut ids = vec![first.clone(), second.clone()];
    ids.sort();
    let mut shown: Vec<String> = stale["params"]["ids"]
        .as_str()
        .expect("ids")
        .split(',')
        .map(str::to_owned)
        .collect();
    shown.sort();
    assert_eq!(shown, ids);
    let names = stale["params"]["mirrors"].as_str().expect("names");
    for id in [&first, &second] {
        assert!(names.contains(&format!("dc ({})", short(id))), "{names}");
    }
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
async fn a_mirror_token_bound_to_its_sources_pushes_from_nowhere_else() {
    let (harness, admin) = harness().await;
    let bound = harness
        .call(
            "POST",
            "/migrate/mirrors",
            Cookie(&admin),
            Some(&json!({ "name": "dc1", "kind": "windows-dhcp", "source_prefixes": ["192.0.2.0/24"] })),
        )
        .await;
    bound.assert_status(201);
    assert_eq!(
        bound.body["mirror"]["source_prefixes"],
        json!(["192.0.2.0/24"])
    );
    harness
        .call(
            "POST",
            "/migrate/mirrors",
            Cookie(&admin),
            Some(
                &json!({ "name": "dc2", "kind": "windows-dhcp", "source_prefixes": ["0.0.0.0/0"] }),
            ),
        )
        .await
        .assert_problem(400, "migrate.mirror.invalid_settings");
    // The harness's requests carry no client address, which is not inside the prefixes.
    let id = bound.body["mirror"]["id"].as_str().expect("id");
    let token = bound.body["token"].as_str().expect("token");
    assert!(token.starts_with("tnkc_"), "the constrained form");
    push(&harness, id, token, snapshot(1), &[])
        .await
        .assert_problem(401, "auth.unauthenticated");
}

#[tokio::test]
async fn the_management_operations_answer_with_their_codes() {
    let (harness, admin) = harness().await;
    let (id, token) = mirror(&harness, &admin, "dc1").await;
    harness
        .call(
            "PATCH",
            &format!("/migrate/mirrors/{id}"),
            Cookie(&admin),
            Some(&json!({ "name": " dc1" })),
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
