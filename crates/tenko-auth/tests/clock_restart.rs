//! Approvals and delegated sessions on the process guard as a restart leaves it
//! (`tenko_core::clock::restore`): after each sequence that leaves the clock behind with issuing
//! held, whatever the hold's own jump says, every step is refused; after a forward start gap,
//! which holds no issuing, a person uses them within their life. A file of its own, since the
//! process guard is shared by the tests of one process.

use std::time::Duration;

use tenko_auth::{
    AuthError,
    approval::Refusal,
    service::SecretString,
    settings::Profile,
    testing::{
        TestEnv,
        approval::{ROOT_SHA256, Script},
    },
};
use tenko_core::{
    Credentials, Timestamp,
    clock::{Reason, Saved, SavedHold, restore},
};

const HOUR_MS: i64 = 3_600_000;

/// The guard's file after a hold of `jump_ms`, written `ago` before this start.
fn saved(ago: Duration, jump_ms: i64, destroy: bool) -> Saved {
    let at = Timestamp::now().checked_sub(ago).expect("a time");
    Saved {
        last_trusted_at: at,
        held: Some(SavedHold {
            reason: Reason::Jump,
            jump_ms,
            since: at,
            destroy,
            issue: true,
            forward_ms: 0,
            forward_from: None,
        }),
    }
}

/// Whether, on the guard restored from `saved`, a waiting approval and a delegated session
/// are refused: both, or neither (they are used).
async fn refused_after(saved: Option<Saved>) -> bool {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&admin).await.expect("the administrator");
    // Another address than the waiting request's, which one request every ten seconds bounds.
    let source = "192.0.2.52".parse().expect("an address");
    let delegated = env
        .delegate(&admin, &Script::default(), source)
        .await
        .expect("a delegated session");
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    restore(saved);
    let approval = env
        .service
        .look_up_approval(&admin, &code, &ROOT_SHA256)
        .await;
    let session = env
        .service
        .authenticate_from(
            &Credentials::Bearer(delegated.secret.expose().to_owned()),
            Some(source),
            env.now(),
        )
        .await;
    restore(None);
    let held =
        |error: Option<&AuthError>| matches!(error, Some(AuthError::Approval(Refusal::ClockHeld)));
    let refused = held(approval.as_ref().err());
    assert_eq!(
        refused,
        held(session.as_ref().err()),
        "{approval:?} {session:?}"
    );
    refused
}

/// A further step of six seconds after the destruction wait of a step back: the hold's jump is
/// that step alone.
#[tokio::test]
async fn a_further_step_after_the_wait_refuses() {
    assert!(refused_after(Some(saved(Duration::ZERO, -6_000, true))).await);
}

/// A restart of ten seconds after the wait of a step back of an hour: a forward start gap that
/// keeps issuing held.
#[tokio::test]
async fn a_restart_after_the_wait_refuses() {
    assert!(refused_after(Some(saved(Duration::from_secs(10), -HOUR_MS, false))).await);
}

/// A restart of three hours during the wait of a step back of an hour: a forward start gap that
/// keeps issuing held.
#[tokio::test]
async fn a_long_restart_during_the_wait_refuses() {
    assert!(refused_after(Some(saved(Duration::from_secs(3 * 3_600), -HOUR_MS, true))).await);
}

/// A restart of a minute without a hold: a forward start gap, which holds destruction only.
#[tokio::test]
async fn a_forward_start_gap_lets_a_person_use_them() {
    let gap = Saved {
        last_trusted_at: Timestamp::now()
            .checked_sub(Duration::from_secs(60))
            .expect("a time"),
        held: None,
    };
    assert!(!refused_after(Some(gap)).await);
}
