//! Sign-ins on a Raft store whose disk is short of room (`docs/cluster.md` section 12.12):
//! the real `AuthService` on a `RaftStore` held below its margin, and below its reserve, by
//! the free space its test hook stands in for. Each account may take a share of the
//! completed sign-ins' budget a minute; every test runs inside one minute.

use std::{fs, net::IpAddr, ops::RangeInclusive, sync::Arc, time::Duration};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use tenko_auth::{
    AuthError, LoginOutcome, NewSession,
    model::{ALARMS, KNOWN_DEVICES, LOCKS, SESSIONS, USERS, UserRecord},
    password::{hash::PasswordHash, policy::normalize},
    roles::RoleName,
    service::{
        CodeLogin, GrantCreate, PasswordLogin, TotpEnrollFinish, WebAuthnLoginFinish,
        WebAuthnLoginStart, WebAuthnRegisterFinish, WebAuthnRegisterStart, types::SecretString,
    },
    settings::Profile,
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{
    Anchors, Coded, ObjectRef, Principal, RequestCtx, ScopeRule, SystemComponent, TableName,
    UserId, VrfId, audit::AuditOutcome, testing::wait_until_async,
};
use tenko_store::{
    AnchorResolver, KeyRange, Pressure, ReadConsistency, ReadView, ReadViewExt, Store, StoreError,
    WriteBatch,
    api::{DISK_FLOOR_BYTES, SIGN_IN_ACCOUNT_BYTES_PER_MINUTE, SIGN_IN_BYTES_PER_MINUTE},
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
    login_as(env, source, ADMIN, password).await
}

async fn login_as(
    env: &Env,
    source: &str,
    name: &str,
    password: &str,
) -> Result<LoginOutcome, AuthError> {
    env.service
        .login_password(
            &ctx_from(env, source),
            Some("test-agent"),
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(password),
                provider: None,
            },
        )
        .await
}

/// A wrong sign-in that waits out any wait first.
async fn fail(env: &Env, source: &str) -> Result<(), AuthError> {
    fail_as(env, source, ADMIN).await
}

async fn fail_as(env: &Env, source: &str, name: &str) -> Result<(), AuthError> {
    loop {
        match login_as(env, source, name, WRONG).await {
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

fn refused_for_room<T: std::fmt::Debug>(outcome: &Result<T, AuthError>) {
    assert!(
        matches!(
            outcome,
            Err(AuthError::Store(StoreError::DiskReserve { .. }))
        ),
        "{outcome:?}"
    );
}

/// Signs in through `sign_in` until the store refuses it for room, after a number of
/// sign-ins in `range`: the count measured from the size of the path's writes, give or take
/// two.
async fn until_refused<T>(
    range: RangeInclusive<u32>,
    mut sign_in: impl AsyncFnMut() -> Result<T, AuthError>,
) {
    let mut passed = 0;
    loop {
        match sign_in().await {
            Ok(_) => passed += 1,
            Err(refusal) => {
                assert!(
                    matches!(refusal, AuthError::Store(StoreError::DiskReserve { .. })),
                    "{refusal:?}"
                );
                break;
            }
        }
        assert!(passed <= *range.end(), "{passed} sign-ins passed");
    }
    assert!(range.contains(&passed), "{passed} sign-ins passed");
}

/// The password step of a second-factor account: its challenge.
async fn challenge(env: &Env) -> Result<String, AuthError> {
    match login(env, "192.0.2.10", ADMIN_PASSWORD).await? {
        LoginOutcome::SecondFactor { challenge_id, .. } => Ok(challenge_id),
        LoginOutcome::Session(_) => panic!("a second factor is asked for"),
    }
}

/// Enrolls TOTP for the session's account; answers the seed.
async fn enroll_totp(env: &Env, session: &NewSession) -> Vec<u8> {
    let ctx = env.session_ctx(session).await.expect("ctx");
    let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
    let seed = tenko_auth::encoding::base32_decode(enrollment.secret.expose()).expect("seed");
    env.service
        .totp_enroll_finish(
            &ctx,
            &TotpEnrollFinish {
                enrollment_id: enrollment.enrollment_id,
                code: code(env, &seed),
            },
        )
        .await
        .expect("enrolled");
    seed
}

fn code(env: &Env, seed: &[u8]) -> SecretString {
    let now = u64::try_from(env.now().0.unix_timestamp()).expect("time");
    SecretString::new(totp::code_at(seed, &TotpParams::default(), now).as_str())
}

async fn login_totp(
    env: &Env,
    challenge_id: String,
    code: SecretString,
) -> Result<NewSession, AuthError> {
    let outcome = env
        .service
        .login_totp(
            &ctx_from(env, "192.0.2.10"),
            Some("test-agent"),
            &CodeLogin { challenge_id, code },
        )
        .await?;
    let LoginOutcome::Session(session) = outcome else {
        panic!("a session");
    };
    Ok(session)
}

/// Registers a key for the session's account.
async fn register_key(env: &Env, session: &NewSession, security_key: bool) -> SoftAuthenticator {
    let ctx = env.session_ctx(session).await.expect("ctx");
    let options = env
        .service
        .webauthn_register_start(
            &ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key,
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
        .expect("registered");
    key
}

/// A passkey sign-in, or with `challenge_id` the passkey step of a password sign-in.
async fn passkey(
    env: &Env,
    key: &mut SoftAuthenticator,
    challenge_id: Option<String>,
) -> Result<NewSession, AuthError> {
    let options = env
        .service
        .webauthn_login_start(
            &env.public_ctx(),
            &WebAuthnLoginStart {
                user_name: None,
                challenge_id,
            },
        )
        .await?;
    let credential = key.assert(&options.public_key, ORIGIN);
    env.service
        .webauthn_login_finish(
            &env.public_ctx(),
            None,
            &WebAuthnLoginFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
}

/// The second account signs in, its share untouched.
async fn second_signs_in(env: &Env) {
    signed_in(&login_as(env, "192.0.2.20", SECOND, SECOND_PASSWORD).await);
}

/// The failed password sign-ins on record that tried `name`.
async fn failures_of(env: &Env, name: &str) -> usize {
    rows(env, &tables::AUDIT)
        .await
        .into_iter()
        .filter(|record| {
            record.draft.action.as_str() == "auth.login.password"
                && record
                    .draft
                    .details
                    .context
                    .get("user_name")
                    .map(String::as_str)
                    == Some(name)
        })
        .count()
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

/// Password sign-ins of one account pass below the margin until its share is spent; then
/// its right and its wrong password both answer 507, while a wrong password for another
/// account or an unknown name answers 401 and is recorded, and the other account signs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_an_accounts_password_sign_ins_stop_at_its_share_alike_right_or_wrong() {
    let (env, _) = installed().await;
    below_the_margin(&env).await;
    // About 1.1 KiB each: 30 measured.
    until_refused(28..=32, async || {
        login(&env, "192.0.2.10", ADMIN_PASSWORD).await
    })
    .await;
    refused_for_room(&fail(&env, ATTACKER).await);
    fail_as(&env, "192.0.2.67", "nobody")
        .await
        .expect("an unknown name answers 401");
    let before = failures_of(&env, SECOND).await;
    fail_as(&env, "192.0.2.68", SECOND)
        .await
        .expect("another account answers 401");
    assert_eq!(
        failures_of(&env, SECOND).await,
        before + 1,
        "and is recorded"
    );
    second_signs_in(&env).await;
    env.store.shutdown().await.expect("shutdown");
}

/// The password step and the second-factor code pass below the margin until the account's
/// share is spent; then a wrong code answers 507 too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_sign_ins_with_a_code_stop_at_the_accounts_share() {
    let (env, session) = installed().await;
    let seed = enroll_totp(&env, &session).await;
    below_the_margin(&env).await;
    // Each code takes the challenge of the step before, so one challenge is left unused
    // whichever step is refused. The floor and about 2.9 KiB each: 10 measured.
    let mut held = challenge(&env).await.expect("the first password step");
    until_refused(8..=12, async || {
        // The code of the step before is used.
        env.clock.advance(Duration::from_secs(30));
        let next = challenge(&env).await?;
        login_totp(&env, std::mem::replace(&mut held, next), code(&env, &seed)).await
    })
    .await;
    refused_for_room(&login_totp(&env, held, SecretString::new("000000")).await);
    second_signs_in(&env).await;
    env.store.shutdown().await.expect("shutdown");
}

/// The passkey step of a password sign-in passes below the margin until the account's share
/// is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_sign_ins_with_a_passkey_step_stop_at_the_accounts_share() {
    let (env, session) = installed().await;
    enroll_totp(&env, &session).await;
    let mut key = register_key(&env, &session, false).await;
    below_the_margin(&env).await;
    // The floor twice and about 1.9 KiB each: 11 measured.
    until_refused(9..=13, async || {
        let challenge_id = challenge(&env).await?;
        passkey(&env, &mut key, Some(challenge_id)).await
    })
    .await;
    second_signs_in(&env).await;
    env.store.shutdown().await.expect("shutdown");
}

/// Passkey sign-ins pass below the margin until the account's share is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_passkey_sign_ins_stop_at_the_accounts_share() {
    let (env, session) = installed().await;
    let mut key = register_key(&env, &session, false).await;
    below_the_margin(&env).await;
    // About 1.9 KiB each: 17 measured.
    until_refused(15..=19, async || passkey(&env, &mut key, None).await).await;
    second_signs_in(&env).await;
    env.store.shutdown().await.expect("shutdown");
}

/// The break-glass account signs in with its hardware key below the margin: the alarm that
/// goes with it rides in the same completed sign-in's budget, until the account's share is
/// spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_break_glass_sign_ins_pass_with_their_alarm_up_to_the_share() {
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
    let mut key = register_key(&env, &session, true).await;
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
    let glass = passkey(&env, &mut key, None)
        .await
        .expect("a break-glass sign-in within the completed budget");
    assert!(glass.info.flags.break_glass);
    assert!(!rows(&env, &ALARMS).await.is_empty(), "the alarm");
    // About 1.7 KiB each: 18 measured after the first.
    until_refused(16..=20, async || passkey(&env, &mut key, None).await).await;
    second_signs_in(&env).await;
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

/// A batch of `bytes` marked as `user`'s completed sign-in, as a peer could forward it.
#[allow(
    clippy::disallowed_methods,
    reason = "a synthetic sign-in that fills the budget to a byte"
)]
async fn marked(env: &Env, user: UserId, bytes: u64) {
    const ROWS: TableName = TableName::from_static("auth.disk_margin_rows");
    let key = user.uuid().as_bytes().to_vec();
    let mut batch = WriteBatch::completed_sign_in(user, env.now());
    let value = usize::try_from(bytes).expect("fits")
        - batch.payload_size()
        - ROWS.as_str().len()
        - key.len();
    batch.put(ROWS, key, vec![0_u8; value]);
    assert_eq!(batch.payload_size(), usize::try_from(bytes).expect("fits"));
    env.store.propose(batch).await.expect("a marked batch");
}

/// A refusal by an account's share takes nothing of the shared budget: with the budget one
/// byte short of its line, the account is refused and another still signs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_by_an_accounts_share_takes_nothing_from_the_shared_budget() {
    let (env, _) = installed().await;
    let admin = admin(&env).await.id;
    below_the_margin(&env).await;
    marked(&env, admin, SIGN_IN_ACCOUNT_BYTES_PER_MINUTE).await;
    marked(
        &env,
        UserId::generate(),
        SIGN_IN_BYTES_PER_MINUTE - SIGN_IN_ACCOUNT_BYTES_PER_MINUTE - 1,
    )
    .await;
    refused_for_room(&login(&env, "192.0.2.10", ADMIN_PASSWORD).await);
    second_signs_in(&env).await;
    env.store.shutdown().await.expect("shutdown");
}

const VRF: VrfId = VrfId::from_uuid(uuid::Uuid::from_u128(0x01));

/// The anchors of one VRF, so that a grant on it can be asked for.
struct OneVrf;

impl AnchorResolver for OneVrf {
    fn anchors(&self, _: &dyn ReadView, object: &ObjectRef) -> Result<Anchors, StoreError> {
        Ok(Anchors {
            object: Some(*object),
            vrf: Some(VRF),
            ..Anchors::default()
        })
    }
}

/// A grant refused below the margin is logged, not stored, like any refused action: it
/// takes nothing of the failed sign-ins' budget, so a wrong password is still recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_margin_a_refused_grant_is_not_stored_and_leaves_the_failures_budget() {
    let (env, _) = installed().await;
    env.service.set_anchor_resolver(Arc::new(OneVrf));
    // A person without grants: an administrator's row, its role taken away.
    let password = "copper meadow signal 7305";
    let id = env.add_admin("dana", password).await;
    let mut user = rows(&env, &USERS)
        .await
        .into_iter()
        .find(|user| user.id == id)
        .expect("the account");
    user.roles = Vec::new();
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), env.now());
    batch.put_typed(&USERS, &id, &user).expect("encode");
    env.store.propose(batch).await.expect("no role");
    let Ok(LoginOutcome::Session(signed)) = login_as(&env, "192.0.2.30", "dana", password).await
    else {
        panic!("a session");
    };
    let ctx = env.session_ctx(&signed).await.expect("ctx");
    let refusals = || async {
        rows(&env, &tables::AUDIT)
            .await
            .into_iter()
            .filter(|record| {
                matches!(&record.draft.outcome, AuditOutcome::Failed { code } if code == "auth.grant.exceeds_own")
            })
            .count()
    };
    let before = refusals().await;

    below_the_margin(&env).await;
    // Marked as failed sign-ins, these would spend the failures' 64 KiB several times.
    for _ in 0..400 {
        let refused = env
            .service
            .create_grant(
                &ctx,
                &GrantCreate {
                    subject: id,
                    role: RoleName::Viewer,
                    scope: ScopeRule::Vrf(VRF),
                    delegable: false,
                },
            )
            .await;
        assert_eq!(
            refused.expect_err("beyond its own"),
            AuthError::GrantExceedsOwn
        );
    }
    assert_eq!(refusals().await, before, "logged, not stored");
    let failures = failures_of(&env, SECOND).await;
    fail_as(&env, ATTACKER, SECOND)
        .await
        .expect("a wrong password answers 401");
    assert_eq!(
        failures_of(&env, SECOND).await,
        failures + 1,
        "and is recorded"
    );
    env.store.shutdown().await.expect("shutdown");
}
