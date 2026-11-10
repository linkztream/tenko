//! The sign-in lock (IAM-05, TGL-07), the bound on password hashing, PINs from before the
//! six-digit minimum and the administrator's credential rule, end to end over `MemStore`.

use std::{net::IpAddr, sync::Arc, time::Duration};

use tenko_auth::{
    AuthConfig, AuthError, AuthService, LoginOutcome,
    model::{
        ALARMS, AlarmKind, LOCKS, PIN_RULE_SINCE, PasswordKind, StoredPassword, USERS, UserRecord,
    },
    password::{
        hash::{HashStrength, hash_password},
        policy::{PolicyViolation, normalize},
    },
    roles::RoleName,
    service::{
        CodeLogin, PasswordChange, PasswordLogin, SetupAdmin, SetupRequest, TotpEnrollFinish,
        UserCreate, UserUpdate, WebAuthnLoginFinish, WebAuthnLoginStart, WebAuthnRegisterFinish,
        WebAuthnRegisterStart, types::SecretString, unlock_offline,
    },
    settings::Profile,
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ADMIN_PIN, HOST, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{Principal, RequestCtx, SystemComponent, Timestamp};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};

/// The second administrator's name; with it, [`ADMIN`] is not the last administrator.
const SECOND: &str = "boris";
const ATTACKER: &str = "192.0.2.66";
const OTHER: &str = "198.51.100.7";
const WRONG: &str = "not the password at all";
const NEW_PASSPHRASE: &str = "lantern harbor quartz 4821";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn ctx_from(env: &TestEnv, source: &str) -> RequestCtx {
    RequestCtx::system(SystemComponent::Api)
        .at(env.now())
        .with_source_ip(ip(source))
}

async fn login_on(
    service: &AuthService,
    ctx: &RequestCtx,
    name: &str,
    password: &str,
) -> Result<LoginOutcome, AuthError> {
    service
        .login_password(
            ctx,
            Some("test-agent"),
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(password),
                provider: None,
            },
        )
        .await
}

async fn login(
    env: &TestEnv,
    source: &str,
    name: &str,
    password: &str,
) -> Result<LoginOutcome, AuthError> {
    login_on(&env.service, &ctx_from(env, source), name, password).await
}

/// A wrong sign-in that waits out any wait first; returns the waits it met, in seconds.
async fn fail_waiting(env: &TestEnv, source: &str, name: &str) -> Vec<u64> {
    let mut waits = Vec::new();
    loop {
        match login(env, source, name, WRONG).await {
            Err(AuthError::InvalidCredentials) => return waits,
            Err(AuthError::Throttled {
                retry_after: Some(secs),
            }) => {
                waits.push(secs);
                env.clock.advance(Duration::from_secs(secs));
            }
            other => panic!("unexpected answer {other:?}"),
        }
    }
}

/// Adds the administrator [`SECOND`], so that [`ADMIN`] is not the last.
async fn second_admin(env: &TestEnv, _admin: &tenko_auth::NewSession) -> tenko_core::UserId {
    env.add_admin(SECOND, NEW_PASSPHRASE).await
}

async fn alarms(env: &TestEnv, kind: AlarmKind) -> usize {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&ALARMS, KeyRange::all(), 10_000, false)
        .expect("alarms")
        .into_iter()
        .filter(|(_, alarm, _)| alarm.kind == kind)
        .count()
}

async fn locks_of(env: &TestEnv, name: &str) -> usize {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&LOCKS, KeyRange::all(), 10_000, false)
        .expect("locks")
        .into_iter()
        .filter(|((key, _), lock, _)| key == name && env.now() < lock.until)
        .count()
}

async fn audit_count(env: &TestEnv, action: &str) -> usize {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == action)
        .count()
}

async fn write(env: &TestEnv, apply: impl FnOnce(&mut WriteBatch)) {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    apply(&mut batch);
    env.store.propose(batch).await.expect("commit");
}

async fn user_named(env: &TestEnv, name: &str) -> UserRecord {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&USERS, KeyRange::all(), 100, false)
        .expect("users")
        .into_iter()
        .map(|(_, user, _)| user)
        .find(|user| user.name == name)
        .expect("the user")
}

/// Gives the account `name` a PIN stored as before the six-digit minimum: a PIN that no
/// sign-in has confirmed.
async fn old_pin(env: &TestEnv, name: &str, pin: &str) {
    let mut user = user_named(env, name).await;
    user.password = Some(StoredPassword {
        hash: hash_password(&normalize(pin), HashStrength::Baseline).expect("hash"),
        kind: PasswordKind::Pin,
        changed_at: env.now(),
        policy_checked_at: None,
        pin_grace_from: None,
        pin_expiry_noticed_at: None,
        admin_rule_met: false,
    });
    user.password_change_required = false;
    write(env, |batch| {
        batch.put_typed(&USERS, &user.id, &user).expect("encode");
    })
    .await;
}

/// Sets the day the installation first ran with the six-digit minimum.
async fn rule_since(env: &TestEnv, at: Timestamp) {
    write(env, |batch| {
        batch.put_typed(&PIN_RULE_SINCE, &(), &at).expect("encode");
    })
    .await;
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n * 86_400)
}

// ---------------------------------------------------------------------------------------
// The lock
// ---------------------------------------------------------------------------------------

/// From one network an account has three attempts, then waits of 10 s, 30 s, 3 min,
/// 5 min and 10 min, then a lock of 30 minutes; a name that does not exist meets exactly
/// the same answers, on this controller and on another one that reads the stored lock.
#[tokio::test]
async fn a_locked_name_answers_alike_whether_the_account_exists_or_not() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    let mut sequences = Vec::new();
    for name in [ADMIN, "nobody-here"] {
        let mut waits = Vec::new();
        for _ in 0..8 {
            waits.extend(fail_waiting(&env, ATTACKER, name).await);
        }
        let locked = login(&env, ATTACKER, name, ADMIN_PASSWORD).await;
        sequences.push((waits, format!("{locked:?}")));
    }
    assert_eq!(sequences[0], sequences[1]);
    assert_eq!(sequences[0].0, [10, 30, 180, 300, 600]);
    assert!(
        sequences[0]
            .1
            .contains("Throttled { retry_after: Some(1800) }"),
        "{}",
        sequences[0].1
    );
    assert_eq!(locks_of(&env, ADMIN).await, 1);
    assert_eq!(locks_of(&env, "nobody-here").await, 1);

    // Another controller over the same store, with nothing in memory.
    let other = AuthService::new(env.store.clone(), env.vault.clone(), AuthConfig::default())
        .await
        .expect("a second controller");
    let ctx = ctx_from(&env, ATTACKER);
    let known = login_on(&other, &ctx, ADMIN, ADMIN_PASSWORD).await;
    let unknown = login_on(&other, &ctx, "nobody-here", WRONG).await;
    // Each answers the rest of its own lock: the account's lock began 1,120 seconds (the
    // waits of the second name) before the other.
    assert!(
        matches!(
            known,
            Err(AuthError::Throttled {
                retry_after: Some(680)
            })
        ),
        "{known:?}"
    );
    assert!(
        matches!(
            unknown,
            Err(AuthError::Throttled {
                retry_after: Some(1_800)
            })
        ),
        "{unknown:?}"
    );
    // It ends by itself.
    env.clock.advance(Duration::from_secs(1_800));
    login(&env, ATTACKER, ADMIN, ADMIN_PASSWORD)
        .await
        .expect("the lock ended");
}

/// A lock reached from one network does not keep the account out from another.
#[tokio::test]
async fn one_network_cannot_lock_the_account_for_another() {
    let (env, admin) = TestEnv::installed(Profile::Hardened).await;
    second_admin(&env, &admin).await;
    for _ in 0..8 {
        fail_waiting(&env, ATTACKER, ADMIN).await;
    }
    assert!(matches!(
        login(&env, ATTACKER, ADMIN, ADMIN_PASSWORD).await,
        Err(AuthError::Throttled { .. })
    ));
    login(&env, OTHER, ADMIN, ADMIN_PASSWORD)
        .await
        .expect("another network signs in");
    // The lock of Hardened raised its alarm and is audited.
    assert_eq!(alarms(&env, AlarmKind::AccountLocked).await, 1);
    assert_eq!(audit_count(&env, "auth.user.lock").await, 1);
}

/// Across networks an account gets a delay of at most one minute once it fails as often as
/// one network may, and the alarm is raised then.
#[tokio::test]
async fn the_account_wide_delay_has_a_ceiling_and_raises_the_alarm() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    let mut longest = 0;
    for n in 1..=24u8 {
        let source = format!("203.0.113.{n}");
        longest = longest.max(
            fail_waiting(&env, &source, ADMIN)
                .await
                .into_iter()
                .max()
                .unwrap_or(0),
        );
        if n == 7 {
            assert_eq!(alarms(&env, AlarmKind::SignInFailures).await, 0);
        }
        if n == 8 {
            assert_eq!(alarms(&env, AlarmKind::SignInFailures).await, 1);
        }
    }
    assert_eq!(longest, 60, "the account-wide ceiling");
    assert_eq!(
        alarms(&env, AlarmKind::SignInFailures).await,
        2,
        "again at 16"
    );
}

/// The last administrator is never locked by the network: its waits repeat the last one,
/// no lock is stored, and the alarm is still raised.
#[tokio::test]
async fn the_last_administrator_is_never_locked_by_the_network() {
    let (env, _) = TestEnv::installed(Profile::Hardened).await;
    let mut waits = Vec::new();
    for _ in 0..20 {
        waits.extend(fail_waiting(&env, ATTACKER, ADMIN).await);
    }
    assert!(waits.iter().all(|secs| *secs <= 600), "{waits:?}");
    assert_eq!(waits.iter().filter(|secs| **secs == 600).count(), 13);
    assert_eq!(locks_of(&env, ADMIN).await, 0);
    assert_eq!(alarms(&env, AlarmKind::AccountLocked).await, 0);
    assert!(alarms(&env, AlarmKind::SignInFailures).await >= 1);
    env.clock.advance(Duration::from_secs(600));
    login(&env, ATTACKER, ADMIN, ADMIN_PASSWORD)
        .await
        .expect("the last administrator signs in after the last wait");
}

/// The addresses of one IPv6 /64 are one network for the lock.
#[tokio::test]
async fn ipv6_clients_of_one_64_share_their_lock() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    for n in 1..=8 {
        fail_waiting(&env, &format!("2001:db8:1:2::{n}"), ADMIN).await;
    }
    assert!(matches!(
        login(&env, "2001:db8:1:2::99", ADMIN, ADMIN_PASSWORD).await,
        Err(AuthError::Throttled {
            retry_after: Some(1_800)
        })
    ));
    login(&env, "2001:db8:1:3::1", ADMIN, ADMIN_PASSWORD)
        .await
        .expect("the next /64 is another network");
}

/// An administrator's offline unlock lifts the stored locks of the account.
#[tokio::test]
async fn the_offline_unlock_lifts_the_stored_locks() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    for _ in 0..8 {
        fail_waiting(&env, ATTACKER, SECOND).await;
    }
    assert_eq!(locks_of(&env, SECOND).await, 1);
    let done = unlock_offline(env.store.as_ref(), "BORIS", env.now())
        .await
        .expect("unlocked");
    assert_eq!(done.name, SECOND);
    assert_eq!(done.lifted, 1);
    assert!(!done.pin_renewed);
    assert_eq!(locks_of(&env, SECOND).await, 0);
    // A controller started afterwards lets the account in from that network.
    let restarted = AuthService::new(env.store.clone(), env.vault.clone(), AuthConfig::default())
        .await
        .expect("a restarted controller");
    login_on(
        &restarted,
        &ctx_from(&env, ATTACKER),
        SECOND,
        NEW_PASSPHRASE,
    )
    .await
    .expect("signs in");
    assert!(matches!(
        unlock_offline(env.store.as_ref(), "nobody", env.now()).await,
        Err(AuthError::NotFound { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// Passkeys and second factors
// ---------------------------------------------------------------------------------------

async fn register_passkey(env: &TestEnv, session: &tenko_auth::NewSession) -> SoftAuthenticator {
    let ctx = env.session_ctx(session).await.expect("ctx");
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let options = env
        .service
        .webauthn_register_start(
            &ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key: false,
            },
        )
        .await
        .expect("register start");
    let credential = authenticator.register(&options.public_key, ORIGIN);
    env.service
        .webauthn_register_finish(
            &ctx,
            &WebAuthnRegisterFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
        .expect("register finish");
    authenticator
}

async fn passkey_login(
    env: &TestEnv,
    authenticator: &mut SoftAuthenticator,
    source: &str,
) -> Result<tenko_auth::NewSession, AuthError> {
    let ctx = ctx_from(env, source);
    let options = env
        .service
        .webauthn_login_start(
            &ctx,
            &WebAuthnLoginStart {
                user_name: None,
                challenge_id: None,
            },
        )
        .await?;
    let credential = authenticator.assert(&options.public_key, ORIGIN);
    env.service
        .webauthn_login_finish(
            &ctx,
            None,
            &WebAuthnLoginFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
}

/// A passkey signs in through the lock of its network, except under Hardened, where the
/// lock holds for it as well.
#[tokio::test]
async fn a_passkey_passes_the_lock_except_under_hardened() {
    for (profile, passes) in [(Profile::Standard, true), (Profile::Hardened, false)] {
        let (env, admin) = TestEnv::installed(profile).await;
        second_admin(&env, &admin).await;
        let mut authenticator = register_passkey(&env, &admin).await;
        for _ in 0..8 {
            fail_waiting(&env, ATTACKER, ADMIN).await;
        }
        let outcome = passkey_login(&env, &mut authenticator, ATTACKER).await;
        if passes {
            outcome.expect("the passkey passes the lock");
        } else {
            assert!(
                matches!(outcome, Err(AuthError::Throttled { .. })),
                "{profile:?}: {outcome:?}"
            );
            // From another network the passkey still signs in.
            passkey_login(&env, &mut authenticator, OTHER)
                .await
                .expect("another network");
        }
    }
}

/// A second-factor challenge opened before the lock cannot go on guessing codes once the
/// lock holds.
#[tokio::test]
async fn a_second_factor_opened_before_the_lock_cannot_go_on() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
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
    env.clock.advance(Duration::from_secs(60));
    let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) =
        login(&env, ATTACKER, ADMIN, ADMIN_PASSWORD).await
    else {
        panic!("a second-factor challenge");
    };
    // The lock is reached meanwhile (here on another controller, which stores it).
    let until = env
        .now()
        .checked_add(Duration::from_secs(1_800))
        .expect("time");
    write(&env, |batch| {
        batch
            .put_typed(
                &LOCKS,
                &(ADMIN.to_owned(), ATTACKER.to_owned()),
                &tenko_auth::model::AccountLock {
                    since: env.now(),
                    until,
                    until_unlock: false,
                    network: Some(ATTACKER.to_owned()),
                },
            )
            .expect("encode");
    })
    .await;
    let code = totp::code_at(
        &seed,
        &TotpParams::default(),
        u64::try_from(env.now().0.unix_timestamp()).expect("time"),
    );
    let answer = env
        .service
        .login_totp(
            &ctx_from(&env, ATTACKER),
            None,
            &CodeLogin {
                challenge_id,
                code: SecretString::new(code.as_str()),
            },
        )
        .await;
    assert!(
        matches!(answer, Err(AuthError::Throttled { .. })),
        "{answer:?}"
    );
}

// ---------------------------------------------------------------------------------------
// The bound on hashing and the setup throttle
// ---------------------------------------------------------------------------------------

/// With the memory for one computation, concurrent sign-ins beyond it are refused at once
/// with a wait of one second, before any memory is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_hashing_beyond_its_memory_is_refused_at_once() {
    let env = Arc::new(
        TestEnv::with_config(AuthConfig {
            password_hash_memory_mib: 19,
            ..AuthConfig::default()
        })
        .await,
    );
    env.setup(Profile::Standard).await.expect("setup");
    let attempts: Vec<_> = (1..=8u8)
        .map(|n| {
            let env = Arc::clone(&env);
            tokio::spawn(async move {
                login(
                    &env,
                    &format!("203.0.113.{n}"),
                    &format!("nobody{n}"),
                    WRONG,
                )
                .await
            })
        })
        .collect();
    let mut refused = 0;
    let mut verified = 0;
    for attempt in attempts {
        match attempt.await.expect("joined") {
            Err(AuthError::Throttled {
                retry_after: Some(1),
            }) => refused += 1,
            Err(AuthError::InvalidCredentials) => verified += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(refused >= 1, "refused {refused}, verified {verified}");
    assert!(verified >= 1, "refused {refused}, verified {verified}");
}

/// Wrong setup tokens slow down only the network that sends them.
#[tokio::test]
async fn setup_attempts_are_throttled_per_network() {
    let env = TestEnv::new().await;
    let token = env
        .service
        .prepare_setup()
        .await
        .expect("open")
        .expect("a token");
    let request = |setup_token: &str| SetupRequest {
        setup_token: SecretString::new(setup_token),
        profile: Profile::Standard,
        admin: SetupAdmin {
            name: ADMIN.to_owned(),
            display_name: None,
            password: SecretString::new(ADMIN_PASSWORD),
        },
        host_name: HOST.to_owned(),
        language: "en".to_owned(),
    };
    for _ in 0..5 {
        assert!(matches!(
            env.service
                .complete_setup(&ctx_from(&env, ATTACKER), None, &request("WRONG-TOKEN"))
                .await,
            Err(AuthError::SetupTokenInvalid)
        ));
    }
    env.service
        .complete_setup(&ctx_from(&env, ATTACKER), None, &request("WRONG-TOKEN"))
        .await
        .expect_err("still wrong");
    assert!(matches!(
        env.service
            .complete_setup(&ctx_from(&env, ATTACKER), None, &request(token.expose()))
            .await,
        Err(AuthError::Throttled { .. })
    ));
    env.service
        .complete_setup(&ctx_from(&env, OTHER), None, &request(token.expose()))
        .await
        .expect("another network completes setup");
}

// ---------------------------------------------------------------------------------------
// PINs and the administrator's credential
// ---------------------------------------------------------------------------------------

/// A PIN has at least six digits.
#[tokio::test]
async fn a_pin_has_at_least_six_digits() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
    let refused = env
        .service
        .create_user(
            &ctx,
            &UserCreate {
                name: "dana".to_owned(),
                display_name: None,
                password: Some(SecretString::new("48127")),
                roles: vec![RoleName::Viewer],
                language: None,
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(AuthError::PasswordPolicy(violations))
            if violations.contains(&PolicyViolation::TooShort { min: 6 })),
        "{refused:?}"
    );
    env.pin_user(&admin, "erin", vec![RoleName::Viewer]).await;
}

/// A PIN from before the minimum keeps signing in, but a short one must be changed before
/// anything else, and one of six digits or more is confirmed by the sign-in.
#[tokio::test]
async fn old_pins_are_confirmed_or_must_be_changed_at_sign_in() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    rule_since(&env, env.now()).await;
    env.pin_user(&admin, "dana", vec![RoleName::Viewer]).await;
    env.pin_user(&admin, "erin", vec![RoleName::Viewer]).await;
    old_pin(&env, "dana", "4812").await;
    old_pin(&env, "erin", "593618").await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
    let listed = env.service.list_users(&ctx).await.expect("users");
    for name in ["dana", "erin"] {
        let user = listed.iter().find(|user| user.name == name).expect(name);
        assert!(user.password_change_required, "{name} is marked");
        assert_eq!(
            user.pin_expires_at,
            env.now().checked_add(days(30)),
            "{name} shows the end of its period"
        );
    }

    let Ok(LoginOutcome::Session(short)) = login(&env, OTHER, "dana", "4812").await else {
        panic!("the old short PIN still signs in");
    };
    assert!(short.info.flags.password_change_required);
    let Ok(LoginOutcome::Session(long)) = login(&env, OTHER, "erin", "593618").await else {
        panic!("the old long PIN signs in");
    };
    assert!(!long.info.flags.password_change_required);

    let listed = env.service.list_users(&ctx).await.expect("users");
    let erin = listed
        .iter()
        .find(|user| user.name == "erin")
        .expect("erin");
    assert!(!erin.password_change_required, "confirmed by the sign-in");
    assert_eq!(erin.pin_expires_at, None);
    let dana = listed
        .iter()
        .find(|user| user.name == "dana")
        .expect("dana");
    assert!(dana.password_change_required);
    assert!(dana.pin_expires_at.is_some(), "still unconfirmed");
}

/// After its period an unconfirmed PIN answers like a wrong one (hashed, counted and
/// audited), and the sweep raises one alarm for it.
#[tokio::test]
async fn an_unconfirmed_pin_stops_after_its_period() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    rule_since(&env, env.now()).await;
    env.pin_user(&admin, "dana", vec![RoleName::Viewer]).await;
    old_pin(&env, "dana", "4812").await;
    env.clock
        .advance(days(30).saturating_sub(Duration::from_secs(1)));
    assert_eq!(
        env.service
            .sweep_unconfirmed_pins(env.now())
            .await
            .expect("sweep"),
        0
    );
    env.clock.advance(Duration::from_secs(1));
    let failed_before = audit_count(&env, "auth.login.password").await;
    assert!(matches!(
        login(&env, OTHER, "dana", "4812").await,
        Err(AuthError::InvalidCredentials)
    ));
    assert_eq!(
        audit_count(&env, "auth.login.password").await,
        failed_before + 1
    );
    assert_eq!(
        env.service
            .sweep_unconfirmed_pins(env.now())
            .await
            .expect("sweep"),
        1
    );
    assert_eq!(
        env.service
            .sweep_unconfirmed_pins(env.now())
            .await
            .expect("sweep"),
        0
    );
    assert_eq!(alarms(&env, AlarmKind::PinExpired).await, 1);
    // An administrator's reset gives a working PIN again, with no mark.
    let Ok(LoginOutcome::Session(admin)) = login(&env, OTHER, ADMIN, ADMIN_PASSWORD).await else {
        panic!("the administrator signs in");
    };
    let ctx = env.session_ctx(&admin).await.expect("ctx");
    let dana = user_named(&env, "dana").await;
    let reset = env
        .service
        .update_user(
            &ctx,
            dana.id,
            &UserUpdate {
                password: Some(SecretString::new("720459")),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("reset");
    assert_eq!(reset.pin_expires_at, None);
    login(&env, OTHER, "dana", "720459")
        .await
        .expect("the reset PIN signs in");
}

/// The last administrator's old PIN expires as well; `tenko user unlock` starts a new
/// period, and the change it then must make ends in a password, not a PIN.
#[tokio::test]
async fn the_last_administrators_old_pin_expires_and_the_offline_unlock_renews_it() {
    let (env, _) = TestEnv::installed(Profile::Home).await;
    rule_since(&env, env.now()).await;
    old_pin(&env, ADMIN, "4812").await;
    env.clock.advance(days(31));
    assert!(matches!(
        login(&env, OTHER, ADMIN, "4812").await,
        Err(AuthError::InvalidCredentials)
    ));
    let done = unlock_offline(env.store.as_ref(), ADMIN, env.now())
        .await
        .expect("unlocked");
    assert!(done.pin_renewed);
    env.clock.advance(Duration::from_secs(10));
    let Ok(LoginOutcome::Session(session)) = login(&env, OTHER, ADMIN, "4812").await else {
        panic!("the renewed PIN signs in");
    };
    assert!(session.info.flags.password_change_required);
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let change = |new: &str| PasswordChange {
        current_password: Some(SecretString::new("4812")),
        new_password: SecretString::new(new),
        remove_factors: false,
    };
    let refused = env.service.change_password(&ctx, &change("593618")).await;
    assert!(
        matches!(&refused, Err(AuthError::PasswordPolicy(violations))
            if violations.contains(&PolicyViolation::DigitsOnly)),
        "{refused:?}"
    );
    env.service
        .change_password(&ctx, &change(NEW_PASSPHRASE))
        .await
        .expect("a password");
    let admin = user_named(&env, ADMIN).await;
    assert_eq!(
        admin.password.map(|password| password.kind),
        Some(PasswordKind::Password)
    );
}

/// The first administrator, a new administrator and an administrator's reset take a
/// password of at least 12 characters that is not digits only, never a PIN, in every
/// profile; an account that signs in with a PIN cannot be made an administrator.
#[tokio::test]
async fn an_administrator_never_signs_in_with_a_pin() {
    // First-run setup under Home.
    let env = TestEnv::new().await;
    let token = env
        .service
        .prepare_setup()
        .await
        .expect("open")
        .expect("a token");
    let refused = env
        .service
        .complete_setup(
            &env.public_ctx(),
            None,
            &SetupRequest {
                setup_token: SecretString::new(token.expose()),
                profile: Profile::Home,
                admin: SetupAdmin {
                    name: ADMIN.to_owned(),
                    display_name: None,
                    password: SecretString::new(ADMIN_PIN),
                },
                host_name: HOST.to_owned(),
                language: "en".to_owned(),
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(AuthError::PasswordPolicy(violations))
            if violations.contains(&PolicyViolation::DigitsOnly)
                && violations.contains(&PolicyViolation::TooShort { min: 12 })),
        "{refused:?}"
    );

    let (env, admin) = TestEnv::installed(Profile::Home).await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
    // A new administrator.
    let refused = env
        .service
        .create_user(
            &ctx,
            &UserCreate {
                name: SECOND.to_owned(),
                display_name: None,
                password: Some(SecretString::new("739158624073")),
                roles: vec![RoleName::Admin],
                language: None,
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(AuthError::PasswordPolicy(violations))
            if violations == &[PolicyViolation::DigitsOnly]),
        "{refused:?}"
    );
    let boris = second_admin(&env, &admin).await;
    // An administrator's reset.
    let refused = env
        .service
        .update_user(
            &ctx,
            boris,
            &UserUpdate {
                password: Some(SecretString::new(ADMIN_PIN)),
                ..UserUpdate::default()
            },
            None,
        )
        .await;
    assert!(
        matches!(refused, Err(AuthError::PasswordPolicy(_))),
        "{refused:?}"
    );
    // The admin role for an account that signs in with a PIN.
    let dana = env.pin_user(&admin, "dana", vec![RoleName::Viewer]).await;
    let refused = env
        .service
        .set_user_roles(&ctx, dana, &[RoleName::Admin], None)
        .await;
    assert!(
        matches!(&refused, Err(AuthError::Invalid { field: "roles", reason })
            if reason.contains("PIN")),
        "{refused:?}"
    );
    // A PIN remains a choice for an ordinary user under Home.
    env.service
        .set_user_roles(&ctx, dana, &[RoleName::Operator], None)
        .await
        .expect("an ordinary role");
}

// ---------------------------------------------------------------------------------------
// Fairness of the lock and of the hashing bound
// ---------------------------------------------------------------------------------------

/// Writes the stored settings of the installation with `apply` applied.
async fn with_settings(
    env: &TestEnv,
    apply: impl FnOnce(&mut tenko_auth::settings::SecuritySettings),
) {
    let mut settings = env.service.settings();
    apply(&mut settings);
    write(env, |batch| {
        batch
            .put_typed(&tenko_auth::model::SETTINGS, &(), &settings)
            .expect("encode");
    })
    .await;
}

/// Failures from many networks raise the account-wide delay, but a network the account
/// signed in from lately is not held back by it: the attacker cannot take every slot the
/// delay frees.
#[tokio::test]
async fn a_known_network_is_not_held_back_by_the_account_wide_delay() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    second_admin(&env, &admin).await;
    // The real user signed in from OTHER before the attack.
    login(&env, OTHER, SECOND, NEW_PASSPHRASE)
        .await
        .expect("signs in");
    for n in 1..=12u8 {
        fail_waiting(&env, &format!("203.0.113.{n}"), SECOND).await;
    }
    // The next failure sets the account-wide delay; a new network meets it.
    assert!(matches!(
        login(&env, "203.0.113.200", SECOND, WRONG).await,
        Err(AuthError::Throttled { .. })
    ));
    // The known network signs in at once.
    login(&env, OTHER, SECOND, NEW_PASSPHRASE)
        .await
        .expect("the known network is not held back");
}

/// The last administrator meets no account-wide delay at the password, but its second
/// factor does: codes guessed from many networks are slowed down without a lock.
#[tokio::test]
async fn the_last_administrators_second_factor_has_the_account_wide_delay() {
    let (env, admin) = TestEnv::installed(Profile::Standard).await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
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
    env.clock.advance(Duration::from_secs(60));
    let now = u64::try_from(env.now().0.unix_timestamp()).expect("time");
    let valid: Vec<String> = [now - 60, now - 30, now, now + 30, now + 60]
        .into_iter()
        .map(|at| {
            totp::code_at(&seed, &TotpParams::default(), at)
                .as_str()
                .to_owned()
        })
        .collect();
    let wrong = (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|code| !valid.contains(code))
        .expect("a wrong code");
    let mut answers = Vec::new();
    let mut challenge: Option<String> = None;
    for n in 1..=10u8 {
        if n % 4 == 1 {
            let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) =
                login(&env, ATTACKER, ADMIN, ADMIN_PASSWORD).await
            else {
                panic!("a challenge");
            };
            challenge = Some(challenge_id);
        }
        let answer = env
            .service
            .login_totp(
                &ctx_from(&env, &format!("2001:db8:7:{n}::1")),
                None,
                &CodeLogin {
                    challenge_id: challenge.clone().expect("a challenge"),
                    code: SecretString::new(wrong.as_str()),
                },
            )
            .await;
        answers.push(format!("{answer:?}"));
    }
    // Eight failures pass free, the ninth sets the delay, the tenth meets it.
    assert!(
        answers[..9]
            .iter()
            .all(|a| a.contains("InvalidCredentials")),
        "{answers:?}"
    );
    assert!(answers[9].contains("Throttled"), "{answers:?}");
    // The password step of the last administrator stays free from a new network.
    assert!(matches!(
        login(&env, "198.51.100.200", ADMIN, ADMIN_PASSWORD).await,
        Ok(LoginOutcome::SecondFactor { .. })
    ));
}

/// Under Hardened the lock of a second network raises no second alarm while the first
/// holds.
#[tokio::test]
async fn one_alarm_while_the_account_holds_a_lock() {
    let (env, admin) = TestEnv::installed(Profile::Hardened).await;
    second_admin(&env, &admin).await;
    for source in [ATTACKER, OTHER] {
        for _ in 0..8 {
            fail_waiting(&env, source, SECOND).await;
        }
    }
    assert_eq!(locks_of(&env, SECOND).await, 2);
    assert_eq!(alarms(&env, AlarmKind::AccountLocked).await, 1);
    assert_eq!(audit_count(&env, "auth.user.lock").await, 2);
    // Ended locks are removed by the sweep.
    env.clock.advance(Duration::from_secs(1_801));
    assert!(
        env.service
            .prune_ended_locks(env.now())
            .await
            .expect("prune")
            >= 2
    );
    assert_eq!(locks_of(&env, SECOND).await, 0);
}

/// A digits-only secret has at least six digits under every preset, and an account is
/// made an administrator only with a password seen to meet the administrator rule.
#[tokio::test]
async fn short_numeric_secrets_and_weak_passwords_do_not_slip_through() {
    let (env, admin) = TestEnv::installed(Profile::Home).await;
    with_settings(&env, |settings| {
        settings.password_policy = tenko_auth::password::policy::PasswordPolicy::Custom(
            serde_json::from_value(serde_json::json!({ "min_length": 4 })).expect("custom"),
        );
    })
    .await;
    let ctx = env.session_ctx(&admin).await.expect("ctx");
    let create = |name: &str, password: &str| UserCreate {
        name: name.to_owned(),
        display_name: None,
        password: Some(SecretString::new(password)),
        roles: vec![RoleName::Viewer],
        language: None,
    };
    let refused = env.service.create_user(&ctx, &create("dana", "4817")).await;
    assert!(
        matches!(&refused, Err(AuthError::PasswordPolicy(violations))
            if violations.contains(&PolicyViolation::TooShort { min: 6 })),
        "{refused:?}"
    );
    let erin = env
        .service
        .create_user(&ctx, &create("erin", "quiet otter"))
        .await
        .expect("an 11-character password under this preset");
    let refused = env
        .service
        .set_user_roles(&ctx, erin.id, &[RoleName::Admin], None)
        .await;
    assert!(
        matches!(&refused, Err(AuthError::Invalid { field: "roles", .. })),
        "{refused:?}"
    );
    let finn = env
        .service
        .create_user(&ctx, &create("finn", "plover quartz mitten ember"))
        .await
        .expect("a long password");
    env.service
        .set_user_roles(&ctx, finn.id, &[RoleName::Admin], None)
        .await
        .expect("a password that meets the rule");
}
