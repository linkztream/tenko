//! Sign-ins on a Raft store whose disk is short of room (`docs/cluster.md` section 12.12):
//! the real `AuthService` on a `RaftStore` held below its margin, and below its reserve, by
//! the free space its test hook stands in for.

use std::{fs, net::IpAddr, sync::Arc, time::Duration};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use tenko_auth::{
    AuthError, LoginOutcome, NewSession,
    model::{ALARMS, KNOWN_DEVICES, LOCKS, SESSIONS, USERS, UserRecord},
    password::{hash::PasswordHash, policy::normalize},
    service::{
        CodeLogin, PasswordLogin, TotpEnrollFinish, WebAuthnLoginFinish, WebAuthnLoginStart,
        WebAuthnRegisterFinish, WebAuthnRegisterStart, types::SecretString,
    },
    settings::Profile,
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{Coded, Principal, RequestCtx, SystemComponent, testing::wait_until_async};
use tenko_store::{
    KeyRange, Pressure, ReadConsistency, ReadViewExt, Store, StoreError, WriteBatch,
    api::DISK_FLOOR_BYTES,
    raft::{RaftStore, RaftStoreConfig},
    tables,
    test_hooks::FREE_BYTES,
};
use tenko_vault::{KekRing, MemKek, StoreVault};

type Env = TestEnv<RaftStore, StoreVault>;

const SECOND: &str = "boris";
const SECOND_PASSWORD: &str = "lantern harbor quartz 4821";
const ATTACKER: &str = "192.0.2.66";
const WRONG: &str = "not the password at all";

/// A Standard installation on a single-voter Raft store, with a second administrator so
/// that [`ADMIN`] is not the last one (the last one never locks).
async fn installed() -> (Env, NewSession) {
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    let raft = Arc::new(RaftStore::open_temp(config).await.expect("open"));
    let store: Arc<dyn Store> = raft.clone();
    let ring = KekRing::new(Arc::new(MemKek::generate("disk-margin-1")));
    let vault = Arc::new(StoreVault::open(store, ring).await.expect("the vault"));
    let env = TestEnv::over(raft, vault).await;
    let session = env.setup(Profile::Standard).await.expect("setup");
    env.add_admin(SECOND, SECOND_PASSWORD).await;
    (env, session)
}

/// Makes the store see `free` bytes and waits until it shows `pressure`.
async fn free_space(env: &Env, free: u64, pressure: Pressure) {
    let file = env.store.config().data_dir.join(FREE_BYTES);
    fs::write(file, free.to_string()).expect("the free space");
    wait_until_async("the store reads its free space", async || {
        let safety = env.store.safety().expect("safety");
        safety.free_bytes == free && safety.pressure == pressure
    })
    .await;
}

async fn below_the_margin(env: &Env) {
    let reserve = env.store.safety().expect("safety").reserve_bytes;
    free_space(env, reserve / 2 * 3, Pressure::Margin).await;
}

async fn below_the_reserve(env: &Env) {
    free_space(env, DISK_FLOOR_BYTES + 1024 * 1024, Pressure::Reserve).await;
}

async fn room(env: &Env) {
    free_space(env, u64::MAX, Pressure::Normal).await;
}

fn ctx_from(env: &Env, source: &str) -> RequestCtx {
    let ip: IpAddr = source.parse().expect("an address");
    RequestCtx::system(SystemComponent::Api)
        .at(env.now())
        .with_source_ip(ip)
}

async fn login(env: &Env, source: &str, password: &str) -> Result<LoginOutcome, AuthError> {
    env.service
        .login_password(
            &ctx_from(env, source),
            Some("test-agent"),
            &PasswordLogin {
                user_name: ADMIN.to_owned(),
                password: SecretString::new(password),
                provider: None,
            },
        )
        .await
}

/// A wrong sign-in that waits out any wait first.
async fn fail(env: &Env, source: &str) -> Result<(), AuthError> {
    loop {
        match login(env, source, WRONG).await {
            Err(AuthError::InvalidCredentials) => return Ok(()),
            Err(AuthError::Throttled {
                retry_after: Some(secs),
            }) => env.clock.advance(Duration::from_secs(secs)),
            Err(other) => return Err(other),
            Ok(_) => panic!("a wrong password signed in"),
        }
    }
}

async fn rows<K, V>(env: &Env, table: &tenko_core::table::TableDef<K, V>) -> Vec<V>
where
    K: tenko_core::codec::key::KeyCodec,
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(table, KeyRange::all(), 10_000, false)
        .expect("rows")
        .into_iter()
        .map(|(_, value, _)| value)
        .collect()
}

async fn admin(env: &Env) -> UserRecord {
    rows(env, &USERS)
        .await
        .into_iter()
        .find(|user| user.name == ADMIN)
        .expect("the administrator")
}

fn signed_in(outcome: &Result<LoginOutcome, AuthError>) {
    assert!(
        matches!(outcome, Ok(LoginOutcome::Session(_))),
        "{outcome:?}"
    );
}

/// A password sign-in from a new browser (a new known-device row), and one whose stored
/// hash is rehashed (a fourth row), pass below the margin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_a_password_sign_in_passes_with_its_new_browser_and_its_rehash() {
    let (env, _) = installed().await;
    // A hash weaker than the profile's, so that the next sign-in rehashes it.
    let mut user = admin(&env).await;
    let weak = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(1024, 1, 1, Some(32)).expect("params"),
    )
    .hash_password_with_salt(normalize(ADMIN_PASSWORD).as_bytes(), b"disk-margin-salt")
    .expect("a hash")
    .to_string();
    let password = user.password.as_mut().expect("a password");
    password.hash = PasswordHash::from_phc(weak.clone()).expect("a PHC string");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch.put_typed(&USERS, &user.id, &user).expect("encode");
    env.store.propose(batch).await.expect("the weak hash");
    let sessions = rows(&env, &SESSIONS).await.len();
    let devices = rows(&env, &KNOWN_DEVICES).await.len();

    below_the_margin(&env).await;
    signed_in(&login(&env, "192.0.2.10", ADMIN_PASSWORD).await);
    assert_eq!(rows(&env, &SESSIONS).await.len(), sessions + 1);
    assert_eq!(
        rows(&env, &KNOWN_DEVICES).await.len(),
        devices + 1,
        "the new browser's mark"
    );
    let rehashed = admin(&env).await;
    assert_ne!(
        rehashed.password.expect("a password").hash.as_str(),
        weak,
        "rehashed"
    );
    env.store.shutdown().await.expect("shutdown");
}

/// The password step and the second factor pass below the margin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_a_sign_in_with_a_second_factor_passes() {
    let (env, session) = installed().await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
    let seed = tenko_auth::encoding::base32_decode(enrollment.secret.expose()).expect("seed");
    let code = || {
        let now = u64::try_from(env.now().0.unix_timestamp()).expect("time");
        SecretString::new(totp::code_at(&seed, &TotpParams::default(), now).as_str())
    };
    env.service
        .totp_enroll_finish(
            &ctx,
            &TotpEnrollFinish {
                enrollment_id: enrollment.enrollment_id,
                code: code(),
            },
        )
        .await
        .expect("enrolled");
    // The enrollment's code is used: the sign-in takes the next step's.
    env.clock.advance(Duration::from_secs(30));

    below_the_margin(&env).await;
    let Ok(LoginOutcome::SecondFactor { challenge_id, .. }) =
        login(&env, "192.0.2.10", ADMIN_PASSWORD).await
    else {
        panic!("a second factor is asked for");
    };
    signed_in(
        &env.service
            .login_totp(
                &ctx_from(&env, "192.0.2.10"),
                Some("test-agent"),
                &CodeLogin {
                    challenge_id,
                    code: code(),
                },
            )
            .await,
    );
    env.store.shutdown().await.expect("shutdown");
}

/// The break-glass account signs in with its hardware key below the margin: the alarm that
/// goes with it rides in the same completed sign-in's budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_a_break_glass_sign_in_passes_with_its_alarm() {
    let (env, _) = installed().await;
    let id = env.add_admin("emergency", ADMIN_PASSWORD).await;
    let Ok(LoginOutcome::Session(session)) = env
        .service
        .login_password(
            &ctx_from(&env, "192.0.2.10"),
            Some("test-agent"),
            &PasswordLogin {
                user_name: "emergency".to_owned(),
                password: SecretString::new(ADMIN_PASSWORD),
                provider: None,
            },
        )
        .await
    else {
        panic!("a password sign-in before the designation");
    };
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let options = env
        .service
        .webauthn_register_start(
            &ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key: true,
            },
        )
        .await
        .expect("start");
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate);
    let credential = key.register(&options.public_key, ORIGIN);
    env.service
        .webauthn_register_finish(
            &ctx,
            &WebAuthnRegisterFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
        .expect("hardware key");
    // The designation itself needs a strong session of another administrator; the row is
    // what the sign-in reads.
    let mut user = rows(&env, &USERS)
        .await
        .into_iter()
        .find(|user| user.id == id)
        .expect("the account");
    user.break_glass = true;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch.put_typed(&USERS, &user.id, &user).expect("encode");
    env.store.propose(batch).await.expect("designated");

    below_the_margin(&env).await;
    let options = env
        .service
        .webauthn_login_start(
            &env.public_ctx(),
            &WebAuthnLoginStart {
                user_name: None,
                challenge_id: None,
            },
        )
        .await
        .expect("start");
    let credential = key.assert(&options.public_key, ORIGIN);
    let glass = env
        .service
        .webauthn_login_finish(
            &env.public_ctx(),
            None,
            &WebAuthnLoginFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
        .expect("a break-glass sign-in within the completed budget");
    assert!(glass.info.flags.break_glass);
    assert!(!rows(&env, &ALARMS).await.is_empty(), "the alarm");
    env.store.shutdown().await.expect("shutdown");
}

/// Wrong passwords below the margin are recorded within the failures' budget, raise the
/// alarm and lock the account, which still holds against the right password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_wrong_passwords_are_recorded_alarmed_and_lock() {
    let (env, _) = installed().await;
    let failed = || async {
        rows(&env, &tables::AUDIT)
            .await
            .into_iter()
            .filter(|record| {
                record.draft.action.as_str() == "auth.login.password"
                    && record.draft.details.context.contains_key("user_name")
            })
            .count()
    };
    let before = failed().await;
    below_the_margin(&env).await;
    let mut tries = 0;
    while rows(&env, &LOCKS).await.is_empty() {
        fail(&env, ATTACKER)
            .await
            .expect("a failure within the budget");
        tries += 1;
        assert!(tries < 50, "no lock after {tries} failures");
    }
    assert_eq!(failed().await, before + tries, "one record per failure");
    assert!(!rows(&env, &ALARMS).await.is_empty(), "the alarm");
    assert!(
        matches!(
            login(&env, ATTACKER, ADMIN_PASSWORD).await,
            Err(AuthError::Throttled { .. })
        ),
        "the lock holds"
    );
    env.store.shutdown().await.expect("shutdown");
}

/// Below the reserve a right and a wrong password get the same answer, and the failures
/// come back as one summary record once the disk has room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_reserve_a_right_and_a_wrong_password_answer_alike_and_are_summed_up() {
    let (env, _) = installed().await;
    below_the_reserve(&env).await;
    let right = login(&env, "192.0.2.10", ADMIN_PASSWORD)
        .await
        .expect_err("refused for room");
    let wrong = fail(&env, ATTACKER).await.expect_err("refused for room");
    for answer in [&right, &wrong] {
        assert!(
            matches!(answer, AuthError::Store(StoreError::DiskReserve { .. })),
            "{answer:?}"
        );
        assert_eq!(answer.http_status(), 507);
        assert!(answer.to_string().contains("12.12"), "{answer}");
    }
    assert_eq!(right.code(), wrong.code());

    room(&env).await;
    let summary = wait_until_async("the summary record", async || {
        rows(&env, &tables::AUDIT)
            .await
            .into_iter()
            .find(|record| record.draft.details.context.contains_key("summary"))
    })
    .await;
    let context = &summary.draft.details.context;
    assert_eq!(summary.draft.action.as_str(), "auth.login.password");
    assert_eq!(context["attempts"], "1");
    assert_eq!(context["accounts"], ADMIN);
    assert!(context["networks"].starts_with("192.0.2."), "{context:?}");
    env.store.shutdown().await.expect("shutdown");
}
