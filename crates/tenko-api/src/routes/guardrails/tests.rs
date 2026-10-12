//! Route tests of the guardrails: defaults, update with `ETag`, stale `If-Match`, limits,
//! authorization and audit.

use serde_json::{Value, json};
use tenko_auth::settings::Profile;
use tenko_auth::testing::TestEnv;
use tenko_core::Timestamp;

use crate::routes::auth::testkit::{Credential::Cookie, Harness};

const PIN: &str = "7391";
const PATH: &str = "/settings/guardrails";

async fn lab() -> (Harness, String) {
    let env = TestEnv::new().await;
    env.clock.set(Timestamp::now());
    let h = Harness::wired(env, |state| crate::api(state).0);
    let admin = h
        .env
        .setup(Profile::Home)
        .await
        .expect("setup succeeds")
        .secret
        .expose()
        .to_owned();
    (h, admin)
}

fn changed() -> Value {
    json!({
        "protected": [{"type": "port", "device": "sw-1", "port": 1}],
        "max_parallel": 2
    })
}

#[tokio::test]
async fn an_empty_store_answers_the_defaults_without_etag() {
    let (h, admin) = lab().await;
    let reply = h.call("GET", PATH, Cookie(&admin), None).await;
    reply.assert_status(200);
    assert_eq!(reply.body["max_parallel"], 10);
    assert_eq!(reply.body["protected"], json!([]));
    assert!(reply.header("etag").is_none());
}

#[tokio::test]
async fn a_change_is_stored_with_an_etag_and_audited_once() {
    let (h, admin) = lab().await;
    let reply = h.call("PUT", PATH, Cookie(&admin), Some(&changed())).await;
    reply.assert_status(200);
    let etag = reply.header("etag").expect("an ETag").to_owned();
    assert_eq!(reply.body, changed());
    let read = h.call("GET", PATH, Cookie(&admin), None).await;
    read.assert_status(200);
    assert_eq!(read.body, changed());
    assert_eq!(read.header("etag"), Some(etag.as_str()));
    let records: Vec<_> = h
        .audit()
        .await
        .into_iter()
        .filter(|draft| draft.action.as_str() == "connect.guardrails.update")
        .collect();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn a_stale_if_match_is_a_conflict() {
    let (h, admin) = lab().await;
    let first = h.call("PUT", PATH, Cookie(&admin), Some(&changed())).await;
    first.assert_status(200);
    let stale = h
        .call_with(
            "PUT",
            PATH,
            Cookie(&admin),
            Some(&changed()),
            &[("If-Match", "\"1\"")],
        )
        .await;
    stale.assert_problem(409, "sys.store.precondition_failed");
    let malformed = h
        .call_with(
            "PUT",
            PATH,
            Cookie(&admin),
            Some(&changed()),
            &[("If-Match", "abc")],
        )
        .await;
    malformed.assert_status(400);
}

#[tokio::test]
async fn a_value_outside_its_limits_is_refused() {
    let (h, admin) = lab().await;
    let mut body = changed();
    body["max_parallel"] = json!(0);
    let reply = h.call("PUT", PATH, Cookie(&admin), Some(&body)).await;
    reply.assert_problem(422, "connect.guardrails.invalid");
    assert_eq!(reply.body["params"]["field"], "max_parallel");
}

#[tokio::test]
async fn only_administrators_may_read_or_change() {
    let (h, admin) = lab().await;
    h.create_user(&admin, "alice", PIN, &["viewer"]).await;
    let alice = h.login("alice", PIN).await;
    h.call("GET", PATH, Cookie(&alice), None)
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("PUT", PATH, Cookie(&alice), Some(&changed()))
        .await
        .assert_problem(403, "auth.forbidden");
    assert!(
        h.audit()
            .await
            .iter()
            .all(|draft| { draft.action.as_str() != "connect.guardrails.update" })
    );
}
