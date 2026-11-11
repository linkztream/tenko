//! Known devices (IAM-05, TGL-07): the mark a browser holds after a completed sign-in lets
//! it pass the account-wide delay of that account, and nothing else, end to end over
//! `MemStore`.

use std::{net::IpAddr, time::Duration};

use tenko_auth::{
    AuthError, LoginOutcome, NewSession,
    model::{KNOWN_DEVICES, LOCKS, USER_KNOWN_DEVICES},
    service::{
        CodeLogin, DeviceMarks, PasswordChange, PasswordLogin, TotpEnrollFinish, UserUpdate,
        types::SecretString, unlock_offline,
    },
    settings::Profile,
    testing::{
        TestEnv,
        env::{ADMIN, ADMIN_PASSWORD},
    },
    totp::{self, TotpParams},
};
use tenko_core::{RequestCtx, SystemComponent, UserId};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables};

/// A second account, so that a mark of another account can be presented.
const OTHER_USER: &str = "boris";
const OTHER_PASSWORD: &str = "lantern harbor quartz 4821";
const NEW_PASSPHRASE: &str = "copper meadow violin 7302";
const WRONG: &str = "not the password at all";
/// The network the real user first signs in from.
const HOME: &str = "198.51.100.10";
/// A network the account has never completed a sign-in from.
const CAFE: &str = "198.51.100.20";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn ctx_from(env: &TestEnv, source: &str) -> RequestCtx {
    RequestCtx::system(SystemComponent::Api)
        .at(env.now())
        .with_source_ip(ip(source))
}

async fn login(
    env: &TestEnv,
    source: &str,
    name: &str,
    password: &str,
    marks: &DeviceMarks,
) -> Result<LoginOutcome, AuthError> {
    env.service
        .login_password_from(
            &ctx_from(env, source),
            Some("test-agent"),
            marks,
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(password),
                provider: None,
            },
        )
        .await
}

fn session(outcome: Result<LoginOutcome, AuthError>) -> NewSession {
    match outcome {
        Ok(LoginOutcome::Session(session)) => session,
        other => panic!("expected a session, got {other:?}"),
    }
}

/// The marks of the device cookie a sign-in set, as the browser sends them back.
fn marks_of(session: &NewSession) -> DeviceMarks {
    let cookie = session
        .device
        .as_ref()
        .expect("a completed sign-in sets the device cookie")
        .set_cookie(true);
    let value = cookie
        .strip_prefix("__Host-tenko_device=")
        .and_then(|rest| rest.split(';').next())
        .expect("the cookie's value");
    DeviceMarks::parse(value)
}

fn no_marks() -> DeviceMarks {
    DeviceMarks::default()
}

/// Whether the answer is the account-wide delay's.
fn throttled(outcome: &Result<LoginOutcome, AuthError>) -> Option<u64> {
    match outcome {
        Err(AuthError::Throttled { retry_after }) => Some(retry_after.unwrap_or(0)),
        _ => None,
    }
}

/// Fails once from each of `networks` fresh networks: the account-wide delay grows to its
/// ceiling of a minute after 15 failures.
async fn raise_the_delay(env: &TestEnv, name: &str, networks: u8) {
    for n in 1..=networks {
        let answer = login(env, &format!("203.0.113.{n}"), name, WRONG, &no_marks()).await;
        if let Some(secs) = throttled(&answer) {
            env.clock.advance(Duration::from_secs(secs));
            let again = login(env, &format!("203.0.113.{n}"), name, WRONG, &no_marks()).await;
            assert!(
                matches!(again, Err(AuthError::InvalidCredentials)),
                "{again:?}"
            );
        } else {
            assert!(
                matches!(answer, Err(AuthError::InvalidCredentials)),
                "{answer:?}"
            );
        }
    }
}

async fn device_rows(env: &TestEnv, user: UserId) -> usize {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let index = view
        .scan_typed(&USER_KNOWN_DEVICES, KeyRange::all(), 10_000, false)
        .expect("index")
        .into_iter()
        .filter(|((owner, _), _, _)| *owner == user)
        .count();
    let records = view
        .scan_typed(&KNOWN_DEVICES, KeyRange::all(), 10_000, false)
        .expect("records")
        .into_iter()
        .filter(|(_, record, _)| record.user == user)
        .count();
    assert_eq!(index, records, "every record has its index row");
    records
}

async fn audit_contexts(env: &TestEnv, action: &str, key: &str) -> Vec<String> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == action)
        .filter_map(|(_, record, _)| record.draft.details.context.get(key).cloned())
        .collect()
}

async fn admin_id(env: &TestEnv, admin: &NewSession) -> UserId {
    env.session_ctx(admin)
        .await
        .expect("ctx")
        .principal
        .user()
        .expect("a user")
}

/// The real user signs in once at home; while guesses from many networks hold the account
/// back, the same browser signs in from a new network at once, and a browser without the
/// mark waits.
#[tokio::test]
async fn a_known_device_passes_the_account_wide_delay_from_a_new_network() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    let first = session(login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await);
    let marks = marks_of(&first);
    assert_eq!(marks.len(), 1);
    raise_the_delay(&env, ADMIN, 15).await;

    let without = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &no_marks()).await;
    assert!(throttled(&without).is_some(), "{without:?}");
    let with = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &marks).await;
    let renewed = session(with);
    // The renewed mark replaces the old one: a copy of the old one no longer passes.
    let stale = login(&env, "198.51.100.30", ADMIN, ADMIN_PASSWORD, &marks).await;
    assert!(throttled(&stale).is_some(), "{stale:?}");
    let fresh = login(
        &env,
        "198.51.100.30",
        ADMIN,
        ADMIN_PASSWORD,
        &marks_of(&renewed),
    )
    .await;
    assert!(matches!(fresh, Ok(LoginOutcome::Session(_))), "{fresh:?}");
    // One device, renewed, not several.
    assert_eq!(
        device_rows(&env, admin_id(&env, &first).await).await,
        1,
        "the renewals keep one device"
    );
}

/// A mark of another account, a forged value and an ended mark are read and ignored: the
/// answer is the one without a mark, for an account and for a name that is none, and
/// nothing is counted on the other account's mark.
#[tokio::test]
async fn a_mark_of_another_account_a_forged_or_an_ended_one_is_no_mark() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    let other = env.add_admin(OTHER_USER, OTHER_PASSWORD).await;
    let borrowed = marks_of(&session(
        login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await,
    ));
    let forged = DeviceMarks::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let own = marks_of(&session(
        login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await,
    ));
    for name in [ADMIN, "nobody-here"] {
        raise_the_delay(&env, name, 15).await;
        let bare = login(&env, CAFE, name, WRONG, &no_marks()).await;
        let expected = throttled(&bare).expect("held back");
        for marks in [&borrowed, &forged] {
            let answer = login(&env, CAFE, name, WRONG, marks).await;
            assert_eq!(throttled(&answer), Some(expected), "{name}: {answer:?}");
        }
    }
    // An ended mark: 30 days later it no longer passes.
    env.clock.advance(Duration::from_secs(30 * 86_400));
    raise_the_delay(&env, ADMIN, 15).await;
    let ended = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &own).await;
    assert!(throttled(&ended).is_some(), "{ended:?}");
    // The other account's mark was never charged.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let charged: Vec<u32> = view
        .scan_typed(&KNOWN_DEVICES, KeyRange::all(), 100, false)
        .expect("records")
        .into_iter()
        .filter(|(_, record, _)| record.user == other)
        .map(|(_, record, _)| record.failures)
        .collect();
    assert_eq!(charged, [0]);
}

/// A stolen mark gives its thief the lock threshold of wrong guesses past the delay (8 with
/// the defaults), from as many networks as they like; the eighth spends it on every
/// controller. The account is not locked: the real user still signs in from home.
#[tokio::test]
async fn a_stolen_mark_is_spent_after_the_lock_threshold_and_locks_nothing() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    let id = admin_id(&env, &admin).await;
    let stolen = marks_of(&session(
        login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await,
    ));
    raise_the_delay(&env, ADMIN, 15).await;
    for n in 1..=8u8 {
        let guess = login(&env, &format!("192.0.2.{n}"), ADMIN, WRONG, &stolen).await;
        assert!(
            matches!(guess, Err(AuthError::InvalidCredentials)),
            "guess {n} passes the delay: {guess:?}"
        );
    }
    let ninth = login(&env, "192.0.2.9", ADMIN, WRONG, &stolen).await;
    assert!(throttled(&ninth).is_some(), "the mark is spent: {ninth:?}");
    assert_eq!(device_rows(&env, id).await, 0);
    assert_eq!(
        audit_contexts(&env, "auth.login.password", "known_device").await,
        [
            "used", "used", "used", "used", "used", "used", "used", "spent"
        ]
    );
    // Nothing is locked; the real user's known network still signs in.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let locks = view
        .scan_typed(&LOCKS, KeyRange::all(), 100, false)
        .expect("locks");
    assert_eq!(locks.len(), 0, "no lock is stored");
    let home = login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await;
    assert!(matches!(home, Ok(LoginOutcome::Session(_))), "{home:?}");
}

/// The mark holds at the second factor too: password and code from a new network during
/// the delay complete at once.
#[tokio::test]
async fn a_known_device_passes_the_delay_at_the_second_factor() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    let seed = enroll_totp(&env, &admin).await;
    env.clock.advance(Duration::from_secs(90));
    let first = login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await;
    let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) = first else {
        panic!("a second factor: {first:?}");
    };
    let marks = marks_of(&session(
        code(&env, HOME, &challenge_id, &seed, &no_marks()).await,
    ));
    env.clock.advance(Duration::from_secs(30));
    raise_the_delay(&env, ADMIN, 15).await;
    let step = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &marks).await;
    let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) = step else {
        panic!("the password passes with the mark: {step:?}");
    };
    // A code without the mark waits; with it the sign-in completes.
    let held = code(&env, CAFE, &challenge_id, &seed, &no_marks()).await;
    assert!(throttled(&held).is_some(), "{held:?}");
    let done = code(&env, CAFE, &challenge_id, &seed, &marks).await;
    assert!(matches!(done, Ok(LoginOutcome::Session(_))), "{done:?}");
}

/// A password change and an administrator's reset end every mark of the account, as does
/// signing it out everywhere; the offline unlock leaves them.
#[tokio::test]
async fn a_password_change_a_reset_and_signing_out_everywhere_end_the_marks() {
    // Home: the administrator administers without a second factor.
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let other = env.add_admin(OTHER_USER, OTHER_PASSWORD).await;
    let admin_ctx = env.session_ctx(&admin).await.expect("ctx");

    // The offline unlock keeps them.
    session(login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await);
    unlock_offline(env.store.as_ref(), OTHER_USER, env.now())
        .await
        .expect("unlocked");
    assert_eq!(device_rows(&env, other).await, 1);

    // Signed out everywhere.
    env.service
        .revoke_user_sessions(&admin_ctx, other)
        .await
        .expect("signed out");
    assert_eq!(device_rows(&env, other).await, 0);

    // An administrator's reset.
    let marks = marks_of(&session(
        login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await,
    ));
    env.service
        .update_user(
            &RequestCtx {
                now: env.now(),
                ..admin_ctx.clone()
            },
            other,
            &UserUpdate {
                password: Some(SecretString::new(NEW_PASSPHRASE)),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("reset");
    assert_eq!(device_rows(&env, other).await, 0);
    env.accept_password(other).await;
    raise_the_delay(&env, OTHER_USER, 15).await;
    let after = login(&env, CAFE, OTHER_USER, NEW_PASSPHRASE, &marks).await;
    assert!(
        throttled(&after).is_some(),
        "the reset ended the mark: {after:?}"
    );

    // The person's own password change.
    env.clock.advance(Duration::from_secs(3_600));
    let own = session(login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await);
    let id = admin_id(&env, &admin).await;
    assert_eq!(device_rows(&env, id).await, 1);
    env.service
        .change_password(
            &env.session_ctx(&own).await.expect("ctx"),
            &PasswordChange {
                current_password: Some(SecretString::new(ADMIN_PASSWORD)),
                new_password: SecretString::new(NEW_PASSPHRASE),
                remove_factors: false,
            },
        )
        .await
        .expect("changed");
    assert_eq!(device_rows(&env, id).await, 0);
}

/// An account keeps ten marks; the eleventh removes the one used longest ago.
#[tokio::test]
async fn an_account_keeps_at_most_ten_marks() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    let id = admin_id(&env, &admin).await;
    let mut all = Vec::new();
    for n in 1..=12u8 {
        env.clock.advance(Duration::from_secs(1));
        all.push(marks_of(&session(
            login(&env, HOME, ADMIN, ADMIN_PASSWORD, &no_marks()).await,
        )));
        assert_eq!(device_rows(&env, id).await, usize::from(n).min(10));
    }
    let listed = env
        .service
        .list_known_devices(&env.session_ctx(&admin).await.expect("ctx"), &all[11])
        .await
        .expect("listed");
    assert_eq!(listed.len(), 10);
    assert!(
        listed[0].current,
        "the newest first, and it is this browser"
    );
    assert!(listed[1..].iter().all(|device| !device.current));
    raise_the_delay(&env, ADMIN, 15).await;
    let evicted = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &all[0]).await;
    assert!(throttled(&evicted).is_some(), "{evicted:?}");
    let kept = login(&env, CAFE, ADMIN, ADMIN_PASSWORD, &all[2]).await;
    assert!(matches!(kept, Ok(LoginOutcome::Session(_))), "{kept:?}");
}

/// A browser shared by two accounts keeps a mark of each: signing in to one renews its own
/// and carries every other value along as it came, so the answer does not tell whether a
/// carried value is still a mark.
#[tokio::test]
async fn a_shared_browser_keeps_a_mark_of_each_account() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    env.add_admin(OTHER_USER, OTHER_PASSWORD).await;
    let first = session(login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await);
    let cookie = first.device.as_ref().expect("a cookie").set_cookie(true);
    let value = cookie
        .strip_prefix("__Host-tenko_device=")
        .and_then(|rest| rest.split(';').next())
        .expect("a value");
    let carried = DeviceMarks::parse(&format!(
        "{value}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ));
    let both = marks_of(&session(
        login(&env, HOME, ADMIN, ADMIN_PASSWORD, &carried).await,
    ));
    assert_eq!(
        both.len(),
        3,
        "the new mark, the other account's and the forged value"
    );
    raise_the_delay(&env, OTHER_USER, 15).await;
    let other = login(&env, CAFE, OTHER_USER, OTHER_PASSWORD, &both).await;
    assert!(matches!(other, Ok(LoginOutcome::Session(_))), "{other:?}");
}

/// The person and an administrator see the known devices and forget them; the hourly
/// sweep removes ended ones.
#[tokio::test]
async fn known_devices_are_listed_forgotten_and_swept() {
    // Home: the administrator administers without a second factor.
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let other = env.add_admin(OTHER_USER, OTHER_PASSWORD).await;
    let own = session(login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await);
    let marks = marks_of(&own);
    let ctx = env.session_ctx(&own).await.expect("ctx");
    let listed = env
        .service
        .list_known_devices(&ctx, &marks)
        .await
        .expect("listed");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].current);
    assert_eq!(listed[0].known_since, listed[0].last_sign_in);
    let admin_ctx = env.session_ctx(&admin).await.expect("ctx");
    let seen = env
        .service
        .user_known_devices(&admin_ctx, other)
        .await
        .expect("an administrator lists them");
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].current);
    // A person cannot reach another account's device.
    let foreign = env
        .service
        .forget_known_devices(&admin_ctx, Some(seen[0].id))
        .await;
    assert!(
        matches!(foreign, Err(AuthError::NotFound { .. })),
        "{foreign:?}"
    );
    assert_eq!(
        env.service
            .forget_known_devices(&ctx, Some(listed[0].id))
            .await
            .expect("forgotten"),
        1
    );
    assert_eq!(device_rows(&env, other).await, 0);
    assert_eq!(
        audit_contexts(&env, "auth.known_device.remove", "known_devices").await,
        ["1"]
    );

    session(login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await);
    assert_eq!(
        env.service
            .forget_user_known_devices(&admin_ctx, other, None)
            .await
            .expect("an administrator forgets them"),
        1
    );
    session(login(&env, HOME, OTHER_USER, OTHER_PASSWORD, &no_marks()).await);
    assert_eq!(
        env.service
            .prune_known_devices(env.now())
            .await
            .expect("swept"),
        0
    );
    // A record without its row in the index, which no removal of the account would find,
    // is swept at once.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let (digest, record, _) = view
        .scan_typed(&KNOWN_DEVICES, KeyRange::all(), 10, false)
        .expect("records")
        .into_iter()
        .next()
        .expect("the mark");
    let orphan = vec![7u8; 32];
    let mut batch = tenko_store::WriteBatch::new(
        tenko_core::Principal::system(SystemComponent::Auth),
        env.now(),
    );
    batch
        .put_typed(&KNOWN_DEVICES, &orphan, &record)
        .expect("encode");
    env.store.propose(batch).await.expect("an orphan");
    assert_eq!(
        env.service
            .prune_known_devices(env.now())
            .await
            .expect("swept"),
        1
    );
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert!(
        view.get_typed(&KNOWN_DEVICES, &digest)
            .expect("read")
            .is_some()
    );
    assert!(
        view.get_typed(&KNOWN_DEVICES, &orphan)
            .expect("read")
            .is_none()
    );
    env.clock.advance(Duration::from_secs(30 * 86_400));
    assert_eq!(
        env.service
            .prune_known_devices(env.now())
            .await
            .expect("swept"),
        1
    );
    assert_eq!(device_rows(&env, other).await, 0);
}

async fn code(
    env: &TestEnv,
    source: &str,
    challenge: &str,
    seed: &[u8],
    marks: &DeviceMarks,
) -> Result<LoginOutcome, AuthError> {
    let now = u64::try_from(env.now().0.unix_timestamp()).expect("time");
    env.service
        .login_totp_from(
            &ctx_from(env, source),
            None,
            marks,
            &CodeLogin {
                challenge_id: challenge.to_owned(),
                code: SecretString::new(totp::code_at(seed, &TotpParams::default(), now).as_str()),
            },
        )
        .await
}

async fn enroll_totp(env: &TestEnv, session: &NewSession) -> Vec<u8> {
    let ctx = env.session_ctx(session).await.expect("ctx");
    let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
    let seed = tenko_auth::encoding::base32_decode(enrollment.secret.expose()).expect("seed");
    let now = u64::try_from(env.now().0.unix_timestamp()).expect("time");
    env.service
        .totp_enroll_finish(
            &ctx,
            &TotpEnrollFinish {
                enrollment_id: enrollment.enrollment_id,
                code: SecretString::new(totp::code_at(&seed, &TotpParams::default(), now).as_str()),
            },
        )
        .await
        .expect("enrolled");
    seed
}
