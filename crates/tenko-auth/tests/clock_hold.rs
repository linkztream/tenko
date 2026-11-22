//! The authentication service and the clock guard (`tenko_core::clock`): a held clock refuses
//! what looks over and removes nothing by its time, and a clock set back never lengthens an
//! approval, a delegated session or a recent sign-in.

use std::time::Duration;

use tenko_auth::{
    AuthError, LoginOutcome, NewSession,
    approval::{APPROVALS, Refusal},
    model::SESSIONS,
    secret::hash_secret,
    service::{PasswordLogin, SecretString},
    settings::Profile,
    testing::{
        TestEnv,
        approval::{ROOT_SHA256, Script},
        env::{ADMIN, ADMIN_PASSWORD, CLIENT},
    },
};
use tenko_core::{
    Credentials, Timestamp,
    clock::{Held, Reason, Release, testing},
};
use tenko_store::{ReadConsistency, ReadViewExt, Store};

const DAY: u64 = 86_400;

fn held(reason: Reason, jump_ms: i64) -> Held {
    Held {
        reason,
        jump_ms,
        since: Timestamp::UNIX_EPOCH,
        release: Release::Wait,
        until: None,
    }
}

/// Held after a forward jump of an hour.
fn forward() -> testing::Override {
    testing::hold(held(Reason::Jump, 3_600_000))
}

/// Set back by `minutes` and not confirmed: destruction waited, issuing still holds.
fn set_back(minutes: i64) -> testing::Override {
    testing::hold_issuing(held(Reason::Jump, -minutes * 60_000))
}

fn session_of(session: &NewSession) -> Credentials {
    Credentials::Session(session.secret.expose().to_owned())
}

async fn stored(env: &TestEnv, session: &NewSession) -> bool {
    env.store
        .read(ReadConsistency::Local)
        .await
        .expect("view")
        .get_typed(&SESSIONS, &hash_secret(session.secret.expose()))
        .expect("read")
        .is_some()
}

async fn login(env: &TestEnv) -> NewSession {
    let outcome = env
        .service
        .login_password(
            &env.public_ctx(),
            Some("test-agent"),
            &PasswordLogin {
                user_name: ADMIN.to_owned(),
                password: SecretString::new(ADMIN_PASSWORD),
                provider: None,
            },
        )
        .await
        .expect("the sign-in succeeds");
    match outcome {
        LoginOutcome::Session(session) => session,
        LoginOutcome::SecondFactor { .. } => panic!("a second factor was asked"),
    }
}

#[tokio::test]
async fn a_held_clock_refuses_an_expired_session_and_keeps_it() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    env.clock.advance(Duration::from_secs(30 * DAY));
    let expired = |result: Result<_, AuthError>| matches!(result, Err(AuthError::SessionExpired));
    {
        let _held = forward();
        let result = env
            .service
            .authenticate_credentials(&session_of(&admin), env.now())
            .await;
        assert!(expired(result));
        assert!(stored(&env, &admin).await, "kept while held");
    }
    let result = env
        .service
        .authenticate_credentials(&session_of(&admin), env.now())
        .await;
    assert!(expired(result));
    assert!(!stored(&env, &admin).await, "removed on a trusted clock");
}

#[tokio::test]
async fn a_held_clock_removes_no_ended_session_at_a_login() {
    let (env, _) = TestEnv::installed(Profile::Home).await;
    let first = login(&env).await;
    env.clock.advance(Duration::from_secs(30 * DAY));
    let _held = forward();
    login(&env).await;
    assert!(stored(&env, &first).await);
}

#[tokio::test]
async fn a_sign_in_after_the_clock_is_never_recent() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let ctx = env.session_ctx(&admin).await.expect("the administrator");
    let back = env
        .now()
        .checked_sub(Duration::from_secs(3_600))
        .expect("a time");
    assert!(matches!(
        env.service
            .require_fresh_session(&ctx.clone().at(back))
            .await,
        Err(AuthError::StepUpRequired { .. })
    ));
    env.service
        .require_fresh_session(&ctx)
        .await
        .expect("fresh on the clock of the sign-in");
}

fn refusal<T: std::fmt::Debug>(result: Result<T, AuthError>) -> Refusal {
    match result {
        Err(AuthError::Approval(refusal)) => refusal,
        other => panic!("not an approval refusal: {other:?}"),
    }
}

#[tokio::test]
async fn a_clock_set_back_ends_an_approval_early_at_every_step() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&admin).await.expect("the administrator");
    let script = Script::default();
    let body = script.request();
    let ticket = env
        .service
        .request_approval(&env.public_ctx(), body.as_bytes())
        .await
        .expect("a request");
    let code = SecretString::new(script.code(&body, ticket.id));
    let collect = script.collect(&ticket);
    // Requested a moment ago by this clock, eleven minutes ago by the clock before the step.
    let back = set_back(11);
    assert_eq!(
        refusal(
            env.service
                .look_up_approval(&admin, &code, &ROOT_SHA256)
                .await
        ),
        Refusal::Code
    );
    assert_eq!(
        refusal(
            env.service
                .approve(&admin, ticket.id, &code, &ROOT_SHA256)
                .await
        ),
        Refusal::Expired
    );
    drop(back);
    env.service
        .approve(&admin, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect("approved on the clock as it is");
    let back = set_back(11);
    assert_eq!(
        refusal(
            env.service
                .collect_approval(&env.public_ctx(), ticket.id, collect.as_bytes())
                .await
        ),
        Refusal::Expired
    );
    drop(back);
    // A forward start gap judges as usual.
    let _gap = testing::hold(held(Reason::StartGap, 11 * 60_000));
    env.service
        .collect_approval(&env.public_ctx(), ticket.id, collect.as_bytes())
        .await
        .expect("collected");
}

#[tokio::test]
async fn a_clock_set_back_ends_a_delegated_session_early() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&admin).await.expect("the administrator");
    let source = CLIENT.parse().expect("an address");
    let session = env
        .delegate(&admin, &Script::default(), source)
        .await
        .expect("a delegated session");
    let bearer = Credentials::Bearer(session.secret.expose().to_owned());
    let gap = testing::hold(held(Reason::StartGap, 16 * 60_000));
    env.service
        .authenticate_from(&bearer, Some(source), env.now())
        .await
        .expect("a forward start gap judges as usual");
    drop(gap);
    // Its idle limit is fifteen minutes: a step back of sixteen means it is over.
    let _back = set_back(16);
    assert!(matches!(
        env.service
            .authenticate_from(&bearer, Some(source), env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));
}

/// The sweep that removes ended approvals waits while the clock is held: on a paused clock,
/// past the first sweep, a request that is ten minutes old is still stored two pending
/// lifetimes later.
#[tokio::test(start_paused = true)]
async fn a_held_clock_removes_no_ended_approval() {
    let (env, _) = TestEnv::installed(Profile::Home).await;
    let _held = forward();
    tokio::time::sleep(Duration::from_secs(61)).await;
    let old = Timestamp::now()
        .checked_sub(tenko_auth::approval::PENDING_LIFETIME)
        .expect("a time");
    let ticket = env
        .service
        .request_approval(
            &env.public_ctx().at(old),
            Script::default().request().as_bytes(),
        )
        .await
        .expect("a request");
    tokio::time::sleep(tenko_auth::approval::PENDING_LIFETIME * 2).await;
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert!(
        view.get_typed(&APPROVALS, &ticket.id)
            .expect("read")
            .is_some()
    );
}
