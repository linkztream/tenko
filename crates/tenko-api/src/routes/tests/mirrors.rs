//! A takeover run's mirrors over the served router (ADR 0038): its delegated session reads the
//! mirrors its run created, pairs its two mirrors with each other, and deletes a mirror of an
//! earlier sitting, the last two within five minutes of its approval; a person's mirror routes
//! stay as they were.

use tenko_core::{
    MirrorId, Principal, SystemComponent,
    migrate::{Mirror, tables::MIRRORS},
};
use tenko_store::{ReadConsistency, ReadViewExt as _, WriteBatch};

use super::*;

/// The mirror creation of a delegated session for the plan's second DHCP server.
const DHCP2: &str = r#"{"name":"dhcp2.corp.example.test","kind":"windows-dhcp","source_prefixes":["192.0.2.30/32"]}"#;

/// An operator's mirror.
const LAB: &str = r#"{"name":"lab","kind":"windows-dhcp"}"#;

/// Creates a mirror with `body` through `credential`: its id and its token.
async fn create(app: &axum::Router, credential: Credential<'_>, body: &str) -> (String, String) {
    let created = send(
        app,
        from(SCRIPT, "POST", "/migrate/mirrors", credential, Some(body)),
    )
    .await;
    created.assert_status(201);
    let text = |field: &Value| field.as_str().expect("a string").to_owned();
    (
        text(&created.body["mirror"]["id"]),
        text(&created.body["token"]),
    )
}

/// Writes the mirror `id`'s row back after `change`.
async fn rewrite(env: &TestEnv, id: &str, change: impl FnOnce(&mut Mirror)) {
    let id: MirrorId = id.parse().expect("an id");
    let view = env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let (mut mirror, _) = view
        .get_typed(&MIRRORS, &id)
        .expect("read")
        .expect("the mirror");
    change(&mut mirror);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch.put_typed(&MIRRORS, &id, &mirror).expect("encode");
    env.store.propose(batch).await.expect("commit");
}

/// An operator's mirror, another run's and a missing one answer the session's GET, PATCH and
/// DELETE with the same 404, byte for byte; only the audit says which. Its own mirror reads,
/// past the five minutes too, and the answer holds no part of the token its create was shown.
#[tokio::test]
async fn a_delegated_session_reaches_its_runs_mirrors_only() {
    let (env, admin, app) = served().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let (own, token) = create(&app, Bearer(&secret), DHCP1).await;
    let (theirs, _) = create(&app, Bearer(&secret), DHCP2).await;
    rewrite(&env, &theirs, |mirror| {
        mirror.created.by = Principal::User {
            id: tenko_core::UserId::generate(),
            session: tenko_core::SessionId::generate(),
            strength: tenko_core::AuthStrength::Password,
            delegation: Some(tenko_core::DelegationId::generate()),
        };
    })
    .await;
    let (operators, _) = create(&app, Cookie(&admin), LAB).await;
    let mut answers = Vec::new();
    let mut reach = |reply: Reply| {
        reply.assert_problem(404, "migrate.mirror.not_found");
        answers.push(reply.text);
    };
    for id in [&operators, &theirs] {
        let path = format!("/migrate/mirrors/{id}");
        for method in ["GET", "PATCH", "DELETE"] {
            let body = (method == "PATCH").then_some("{}");
            reach(send(&app, from(SCRIPT, method, &path, Bearer(&secret), body)).await);
        }
    }
    // A later sitting's first refusal is recorded on its own: a missing mirror.
    send(
        &app,
        from(SCRIPT, "POST", "/auth/logout", Bearer(&secret), None),
    )
    .await
    .assert_status(204);
    let later = delegated(&env, &admin, "192.0.2.11").await;
    let bearer = Bearer(later.secret.expose());
    let path = format!("/migrate/mirrors/{}", MirrorId::generate());
    for method in ["GET", "PATCH", "DELETE"] {
        let body = (method == "PATCH").then_some("{}");
        reach(send(&app, from("192.0.2.11", method, &path, bearer, body)).await);
    }
    assert!(
        answers.iter().all(|text| *text == answers[0]),
        "{answers:?}"
    );
    assert_eq!(refusals_found(&env).await, ["missing", "outside_run"]);
    approve_at(&env, later.secret.expose(), six_minutes_ago()).await;
    let path = format!("/migrate/mirrors/{own}");
    let read = send(&app, from("192.0.2.11", "GET", &path, bearer, None)).await;
    read.assert_status(200);
    let chars: Vec<char> = token.chars().collect();
    for part in chars.windows(8) {
        let part: String = part.iter().collect();
        assert!(!read.text.contains(&part), "{part}");
    }
}

/// The session pairs its run's two mirrors with the body `{"partner"}` alone, within five
/// minutes of its approval and in a plan of two DHCP servers: any other change, another
/// partner and a later time are refused, and a person still renames a run mirror.
#[tokio::test]
async fn a_run_pairs_its_two_mirrors_and_nothing_else() {
    let (env, admin, app) = served().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let (one, _) = create(&app, Bearer(&secret), DHCP1).await;
    let (two, _) = create(&app, Bearer(&secret), DHCP2).await;
    let (operators, _) = create(&app, Cookie(&admin), LAB).await;
    let path = format!("/migrate/mirrors/{one}");
    let change = |credential: Credential<'_>, body: &Value| {
        from(SCRIPT, "PATCH", &path, credential, Some(&body.to_string()))
    };
    let pair = json!({ "partner": two });
    for body in [
        json!({ "name": "dhcp1" }),
        json!({ "enabled": false }),
        json!({ "interval_secs": 120 }),
        json!({}),
        json!({ "partner": null }),
        json!({ "partner": one }),
        json!({ "partner": operators }),
        json!({ "partner": two, "name": "dhcp1" }),
    ] {
        let reply = send(&app, change(Bearer(&secret), &body)).await;
        assert_refused(&reply, "plan");
    }
    // A plan of one DHCP server pairs nothing.
    let plans = &tenko_core::migrate::tables::RUN_PLANS;
    let view = env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let (plan, _) = view
        .get_typed(plans, &session.delegation)
        .expect("read")
        .expect("the plan");
    let put_plan = |plan: &tenko_core::migrate::plan::TakeoverPlan| {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch
            .put_typed(plans, &session.delegation, plan)
            .expect("encode");
        env.store.propose(batch)
    };
    let mut alone = plan.clone();
    alone.dhcp_servers.truncate(1);
    put_plan(&alone).await.expect("commit");
    assert_refused(&send(&app, change(Bearer(&secret), &pair)).await, "plan");
    put_plan(&plan).await.expect("commit");
    approve_at(&env, &secret, six_minutes_ago()).await;
    assert_refused(
        &send(&app, change(Bearer(&secret), &pair)).await,
        "condition",
    );
    approve_at(&env, &secret, Timestamp::now()).await;
    send(&app, change(Bearer(&secret), &pair))
        .await
        .assert_status(200);
    for (id, partner) in [(&one, &two), (&two, &one)] {
        let path = format!("/migrate/mirrors/{id}");
        let read = send(&app, from(SCRIPT, "GET", &path, Cookie(&admin), None)).await;
        assert_eq!(read.body["partner"], partner.as_str(), "{}", read.text);
    }
    let renamed = send(&app, change(Cookie(&admin), &json!({ "name": "dhcp1" }))).await;
    renamed.assert_status(200);
    assert_eq!(renamed.body["name"], "dhcp1");
}

/// A sitting never deletes the mirror its own session made, also when the mirror's stamp lies
/// up to the clock tolerance before the approval (a clock set back); a mirror another session
/// of the run made at the same time is deleted.
#[tokio::test]
async fn a_sitting_never_deletes_the_mirror_its_session_made() {
    let (env, admin, app) = served().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let (id, _) = create(&app, Bearer(&secret), DHCP1).await;
    let path = format!("/migrate/mirrors/{id}");
    let delete = || from(SCRIPT, "DELETE", &path, Bearer(&secret), None);
    let approved = Timestamp::now();
    approve_at(&env, &secret, approved).await;
    let before = approved
        .checked_sub(Duration::from_secs(3))
        .expect("a time");
    rewrite(&env, &id, |mirror| mirror.created.at = before).await;
    assert_refused(&send(&app, delete()).await, "condition");
    rewrite(&env, &id, |mirror| {
        if let Principal::User { session, .. } = &mut mirror.created.by {
            *session = tenko_core::SessionId::generate();
        }
    })
    .await;
    send(&app, delete()).await.assert_status(204);
}

/// The session deletes a mirror of its run that an earlier sitting made, within five minutes
/// of its approval: the old token's push is refused, and the server's mirror is made again. It
/// never deletes a mirror its own sitting made, and a person deletes a run mirror at any time.
#[tokio::test]
async fn a_run_deletes_its_mirrors_within_five_minutes_of_an_approval() {
    let (env, admin, app) = served().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let (id, token) = create(&app, Bearer(&secret), DHCP1).await;
    let path = format!("/migrate/mirrors/{id}");
    let delete = |path: &str| from(SCRIPT, "DELETE", path, Bearer(&secret), None);
    let kept = || from(SCRIPT, "GET", &path, Cookie(&admin), None);
    assert_refused(&send(&app, delete(&path)).await, "condition");
    send(&app, kept()).await.assert_status(200);
    // As an earlier sitting of the run made it, an hour ago.
    rewrite(&env, &id, |mirror| {
        mirror.created.at = Timestamp::now()
            .checked_sub(Duration::from_secs(3_600))
            .expect("a time");
        if let Principal::User { session, .. } = &mut mirror.created.by {
            *session = tenko_core::SessionId::generate();
        }
    })
    .await;
    approve_at(&env, &secret, six_minutes_ago()).await;
    assert_refused(&send(&app, delete(&path)).await, "condition");
    send(&app, kept()).await.assert_status(200);
    approve_at(&env, &secret, Timestamp::now()).await;
    let snapshot = format!("{path}/snapshot");
    let push = || from("192.0.2.30", "PUT", &snapshot, Bearer(&token), Some("{}"));
    let accepted = send(&app, push()).await;
    assert!(!refused_as_unauthenticated(&accepted), "{}", accepted.text);
    send(&app, delete(&path)).await.assert_status(204);
    let refused = send(&app, push()).await;
    assert!(refused_as_unauthenticated(&refused), "{}", refused.text);
    let (again, _) = create(&app, Bearer(&secret), DHCP1).await;
    let again = format!("/migrate/mirrors/{again}");
    assert_refused(&send(&app, delete(&again)).await, "condition");
    approve_at(&env, &secret, six_minutes_ago()).await;
    send(&app, from(SCRIPT, "DELETE", &again, Cookie(&admin), None))
        .await
        .assert_status(204);
}
