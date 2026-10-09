//! Passwords and factors of the authentication service: changing a password, the policy
//! feedback, the breached-password check (IAM-04, TGL-06), fresh authentication for
//! sensitive factor changes, the last-factor guard, and the PIN preset (IAM-03, IAM-06,
//! IAM-07, TGL-01).

use std::{
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tenko_auth::{
    AuthConfig, AuthError, LoginOutcome, NewSession,
    encoding::base32_decode,
    hibp::{
        BreachMode, BuildOptions, HibpError, HibpFilter, HibpRangeSource, build_filter,
        sha1_hex_upper,
    },
    password::{
        PolicyViolation,
        policy::{CustomPolicy, PasswordPolicy},
    },
    roles::RoleName,
    service::{
        BreachStatus, CodeLogin, FRESH_AUTHENTICATION, PasswordChange, PasswordCheck,
        PasswordLogin, SetupAdmin, SetupRequest, TokenCreate, TotpEnrolFinish, UserCreate,
        UserInfo, WebAuthnLoginFinish, WebAuthnLoginStart, WebAuthnRegisterFinish,
        WebAuthnRegisterStart, types::SecretString,
    },
    settings::{MfaRequirement, Profile, SettingsPatch},
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ADMIN_PIN, HOST, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{AuthStrength, Coded, Credentials, RequestCtx};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};

const PASSPHRASE: &str = "marble comet violin saffron";
const BREACHED: &str = "correct horse battery staple";
const FRESH_PASSPHRASE: &str = "amber falcon quill nest seven";

// ---------------------------------------------------------------------------------------
// A range source that can be told what to answer
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Answer,
    Down,
    Garbled,
}

struct FakeSource {
    /// Prefix, suffix and count of every breached password.
    breached: Vec<(String, String, u64)>,
    behaviour: AtomicU8,
    seen: Mutex<Vec<String>>,
}

impl FakeSource {
    fn new(breached: &[(&str, u64)]) -> Arc<Self> {
        Arc::new(Self {
            breached: breached
                .iter()
                .map(|(password, count)| {
                    let hash = sha1_hex_upper(password);
                    (hash[..5].to_owned(), hash[5..].to_owned(), *count)
                })
                .collect(),
            behaviour: AtomicU8::new(Behaviour::Answer as u8),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn set(&self, behaviour: Behaviour) {
        self.behaviour.store(behaviour as u8, Ordering::SeqCst);
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }
}

#[async_trait]
impl HibpRangeSource for FakeSource {
    async fn range(&self, prefix: &str) -> Result<String, HibpError> {
        self.seen.lock().expect("lock").push(prefix.to_owned());
        let behaviour = self.behaviour.load(Ordering::SeqCst);
        if behaviour == Behaviour::Down as u8 {
            return Err(HibpError::Unavailable("simulated outage".to_owned()));
        }
        if behaviour == Behaviour::Garbled as u8 {
            return Ok("this is not a range response".to_owned());
        }
        // A padding entry (count 0) as the API sends with `Add-Padding`, then the matches.
        let mut body = format!("{}:0\r\n", "0".repeat(35));
        for (known, suffix, count) in &self.breached {
            if known == prefix {
                write!(body, "{suffix}:{count}\r\n").expect("writing to a string");
            }
        }
        Ok(body)
    }
}

/// An installation under `profile` whose online breach source is `source`.
async fn env_with(source: &Arc<FakeSource>, profile: Profile) -> (TestEnv, NewSession) {
    let online: Arc<dyn HibpRangeSource> = source.clone();
    let env = TestEnv::with_config(AuthConfig {
        hibp_online: Some(online),
        ..AuthConfig::default()
    })
    .await;
    let session = env.setup(profile).await.expect("setup succeeds");
    (env, session)
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn unix_seconds(env: &TestEnv) -> u64 {
    u64::try_from(env.now().0.unix_timestamp()).expect("the clock stands after the epoch")
}

async fn password_login(
    env: &TestEnv,
    user: &str,
    password: &str,
) -> Result<LoginOutcome, AuthError> {
    env.service
        .login_password(
            &env.public_ctx(),
            Some("test-agent"),
            &PasswordLogin {
                user_name: user.to_owned(),
                password: SecretString::new(password),
            },
        )
        .await
}

fn expect_session(outcome: LoginOutcome) -> NewSession {
    match outcome {
        LoginOutcome::Session(session) => session,
        LoginOutcome::SecondFactor { methods, .. } => {
            panic!("expected a session, got a second-factor challenge {methods:?}")
        }
    }
}

async fn login(env: &TestEnv, user: &str, password: &str) -> NewSession {
    expect_session(password_login(env, user, password).await.expect("login"))
}

fn credentials(session: &NewSession) -> Credentials {
    Credentials::Session(session.secret.expose().to_owned())
}

async fn ctx(env: &TestEnv, session: &NewSession) -> RequestCtx {
    env.session_ctx(session).await.expect("a request context")
}

async fn add_user(env: &TestEnv, name: &str, role: RoleName, password: &str) -> UserInfo {
    env.service
        .create_user(
            &env.public_ctx(),
            &UserCreate {
                name: name.to_owned(),
                display_name: None,
                password: Some(SecretString::new(password)),
                roles: vec![role],
                language: None,
            },
        )
        .await
        .expect("the user is created")
}

fn change(current: Option<&str>, new: &str) -> PasswordChange {
    PasswordChange {
        current_password: current.map(SecretString::new),
        new_password: SecretString::new(new),
    }
}

fn check(password: &str) -> PasswordCheck {
    PasswordCheck {
        password: SecretString::new(password),
        user_name: None,
        profile: None,
    }
}

async fn enrol_totp(env: &TestEnv, ctx: &RequestCtx) -> (Vec<u8>, Vec<String>) {
    let start = env
        .service
        .totp_enrol_start(ctx)
        .await
        .expect("enrolment starts");
    let seed = base32_decode(start.secret.expose()).expect("a base32 seed");
    let code = totp::code_at(&seed, &TotpParams::default(), unix_seconds(env));
    let enrolled = env
        .service
        .totp_enrol_finish(
            ctx,
            &TotpEnrolFinish {
                enrolment_id: start.enrolment_id,
                code: SecretString::new(code.as_str()),
            },
        )
        .await
        .expect("enrolment finishes");
    let codes = enrolled
        .recovery_codes
        .expect("the first factor brings recovery codes")
        .iter()
        .map(|code| code.expose().to_owned())
        .collect();
    (seed, codes)
}

async fn second_step(env: &TestEnv, user: &str, password: &str) -> String {
    env.clock.advance(Duration::from_secs(60));
    let LoginOutcome::SecondFactor { challenge_id, .. } = password_login(env, user, password)
        .await
        .expect("first step")
    else {
        panic!("expected a second-factor challenge");
    };
    challenge_id
}

async fn totp_login(env: &TestEnv, user: &str, password: &str, seed: &[u8]) -> NewSession {
    let challenge_id = second_step(env, user, password).await;
    let code = totp::code_at(seed, &TotpParams::default(), unix_seconds(env));
    expect_session(
        env.service
            .login_totp(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id,
                    code: SecretString::new(code.as_str()),
                },
            )
            .await
            .expect("the code is accepted"),
    )
}

async fn register_passkey(env: &TestEnv, ctx: &RequestCtx) -> SoftAuthenticator {
    let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    let options = env
        .service
        .webauthn_register_start(
            ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key: false,
            },
        )
        .await
        .expect("registration starts");
    let credential = authenticator.register(&options.public_key, ORIGIN);
    env.service
        .webauthn_register_finish(
            ctx,
            &WebAuthnRegisterFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await
        .expect("registration finishes");
    authenticator
}

async fn passkey_login(
    env: &TestEnv,
    authenticator: &mut SoftAuthenticator,
    user: &str,
) -> NewSession {
    let options = env
        .service
        .webauthn_login_start(
            &env.public_ctx(),
            &WebAuthnLoginStart {
                user_name: Some(user.to_owned()),
                challenge_id: None,
            },
        )
        .await
        .expect("login starts");
    let credential = authenticator.assert(&options.public_key, ORIGIN);
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
        .expect("passkey login")
}

async fn put_operator_secret(env: &TestEnv) {
    env.vault
        .put_operator(
            &env.public_ctx(),
            SecretSpec::new(SecretPurpose::from_static("connect.test")),
            SecretBytes::from(b"fake".to_vec()),
        )
        .await
        .expect("an operator secret");
}

async fn audit_of(env: &TestEnv, action: &str) -> Vec<tenko_core::audit::AuditRecord> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .filter(|record| record.draft.action.as_str() == action)
        .collect()
}

fn violations_of(error: AuthError) -> Vec<PolicyViolation> {
    match error {
        AuthError::PasswordPolicy(violations) => violations,
        other => panic!("expected a password policy refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Changing the password
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_wrong_or_missing_current_password_is_refused() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let other = login(&env, ADMIN, ADMIN_PASSWORD).await;
    let ctx = ctx(&env, &session).await;
    for current in [Some("not the current password"), Some(""), None] {
        assert_eq!(
            env.service
                .change_password(&ctx, &change(current, FRESH_PASSPHRASE))
                .await
                .expect_err("refused"),
            AuthError::PasswordIncorrect,
            "{current:?}"
        );
    }
    // Nothing changed: the old password still logs in, and no session was ended.
    login(&env, ADMIN, ADMIN_PASSWORD).await;
    for alive in [&session, &other] {
        env.service
            .authenticate_credentials(&credentials(alive), env.now())
            .await
            .expect("the session survived");
    }
    assert_eq!(audit_of(&env, "auth.password.change").await, []);
    assert_eq!(
        AuthError::PasswordIncorrect.code(),
        "auth.password.incorrect"
    );
}

#[tokio::test]
async fn repeated_wrong_current_passwords_are_throttled() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    let mut throttled = None;
    for attempt in 1..=10 {
        match env
            .service
            .change_password(&ctx, &change(Some("a wrong guess here"), FRESH_PASSPHRASE))
            .await
        {
            Err(AuthError::PasswordIncorrect) => {}
            Err(AuthError::Throttled { retry_after }) => {
                throttled = Some((attempt, retry_after));
                break;
            }
            other => panic!("attempt {attempt}: unexpected {other:?}"),
        }
    }
    let (attempt, retry_after) = throttled.expect("delays start after the free attempts");
    assert!(attempt <= 8, "throttled only at attempt {attempt}");
    assert!(retry_after.is_some_and(|seconds| seconds >= 1));
    // Even the right password waits.
    assert!(matches!(
        env.service
            .change_password(&ctx, &change(Some(ADMIN_PASSWORD), FRESH_PASSPHRASE))
            .await,
        Err(AuthError::Throttled { .. })
    ));
    env.clock.advance(Duration::from_secs(120));
    let ctx = self::ctx(&env, &session).await;
    env.service
        .change_password(&ctx, &change(Some(ADMIN_PASSWORD), FRESH_PASSPHRASE))
        .await
        .expect("after the delay the right password works");
}

#[tokio::test]
async fn a_successful_change_ends_the_other_sessions_but_keeps_the_current_one() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let second = login(&env, ADMIN, ADMIN_PASSWORD).await;
    let third = login(&env, ADMIN, ADMIN_PASSWORD).await;
    let ctx = ctx(&env, &session).await;
    let changed = env
        .service
        .change_password(&ctx, &change(Some(ADMIN_PASSWORD), FRESH_PASSPHRASE))
        .await
        .expect("change");
    assert_eq!(changed.sessions_revoked, 2);
    assert_eq!(changed.breach_check, BreachStatus::Unavailable);
    env.service
        .authenticate_credentials(&credentials(&session), env.now())
        .await
        .expect("the current session stays");
    for ended in [&second, &third] {
        assert!(matches!(
            env.service
                .authenticate_credentials(&credentials(ended), env.now())
                .await,
            Err(AuthError::Unauthenticated)
        ));
    }
    assert!(matches!(
        password_login(&env, ADMIN, ADMIN_PASSWORD).await,
        Err(AuthError::InvalidCredentials)
    ));
    let fresh = login(&env, ADMIN, FRESH_PASSPHRASE).await;
    assert_eq!(fresh.info.strength, AuthStrength::Password);
    // The audit record counts the ended sessions and keeps every password out.
    let records = audit_of(&env, "auth.password.change").await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].draft.details.context["sessions_revoked"], "2");
    let json = serde_json::to_string(&records[0]).expect("json");
    assert!(!json.contains(ADMIN_PASSWORD) && !json.contains(FRESH_PASSPHRASE));
}

#[tokio::test]
async fn policy_violations_come_back_with_the_whole_list() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    let cases: [(&str, Vec<PolicyViolation>); 4] = [
        ("short one", vec![PolicyViolation::TooShort { min: 12 }]),
        ("aaaaaaaaaaaaaaaa", vec![PolicyViolation::Trivial]),
        (
            "1234",
            vec![
                PolicyViolation::TooShort { min: 12 },
                PolicyViolation::Trivial,
            ],
        ),
        (
            "my admin secret phrase",
            vec![PolicyViolation::ContextSpecific {
                context: tenko_auth::password::policy::ContextKind::UserName,
            }],
        ),
    ];
    for (password, expected) in cases {
        let error = env
            .service
            .change_password(&ctx, &change(Some(ADMIN_PASSWORD), password))
            .await
            .expect_err("refused");
        assert_eq!(error.code(), "auth.password.policy");
        assert_eq!(error.http_status(), 422);
        assert_eq!(error.field_errors().len(), expected.len(), "{password:?}");
        assert_eq!(violations_of(error), expected, "{password:?}");
    }
    // The refusals changed nothing.
    login(&env, ADMIN, ADMIN_PASSWORD).await;
    assert_eq!(audit_of(&env, "auth.password.change").await, []);
}

#[tokio::test]
async fn the_pin_preset_reports_its_own_violations() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let ctx = ctx(&env, &session).await;
    for (pin, expected) in [
        ("12", PolicyViolation::TooShort { min: 4 }),
        ("48a2", PolicyViolation::PinDigitsOnly),
        ("5555", PolicyViolation::Trivial),
    ] {
        let violations = violations_of(
            env.service
                .change_password(&ctx, &change(Some(ADMIN_PIN), pin))
                .await
                .expect_err("refused"),
        );
        assert!(violations.contains(&expected), "{pin:?}: {violations:?}");
    }
    env.service
        .change_password(&ctx, &change(Some(ADMIN_PIN), "9157"))
        .await
        .expect("a valid PIN");
}

// ---------------------------------------------------------------------------------------
// The breached-password check (IAM-04, TGL-06)
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_breached_password_is_refused_with_its_count() {
    let source = FakeSource::new(&[(BREACHED, 42), ("password", 9_000_000)]);
    let (env, session) = env_with(&source, Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    let violations = violations_of(
        env.service
            .change_password(&ctx, &change(Some(ADMIN_PASSWORD), BREACHED))
            .await
            .expect_err("refused"),
    );
    assert_eq!(violations, [PolicyViolation::Breached { count: Some(42) }]);
    // Breached and too short at once: both are reported.
    let violations = violations_of(
        env.service
            .change_password(&ctx, &change(Some(ADMIN_PASSWORD), "password"))
            .await
            .expect_err("refused"),
    );
    assert!(violations.contains(&PolicyViolation::TooShort { min: 12 }));
    assert!(violations.contains(&PolicyViolation::Breached {
        count: Some(9_000_000)
    }));

    // The live feedback says the same, and a clean password is accepted.
    let result = env
        .service
        .check_password(Some(&ctx), &check(BREACHED))
        .await
        .expect("check");
    assert!(!result.acceptable);
    assert_eq!(result.breach_check, BreachStatus::Breached);
    assert_eq!(
        result.violations,
        [PolicyViolation::Breached { count: Some(42) }]
    );
    assert_eq!(result.policy, PasswordPolicy::Standard);
    let clean = env
        .service
        .check_password(Some(&ctx), &check(FRESH_PASSPHRASE))
        .await
        .expect("check");
    assert!(clean.acceptable && clean.violations.is_empty());
    assert_eq!(clean.breach_check, BreachStatus::Clean);

    // Nothing changed, and an administrator cannot set it for someone either.
    login(&env, ADMIN, ADMIN_PASSWORD).await;
    let refused = env
        .service
        .create_user(
            &env.public_ctx(),
            &UserCreate {
                name: "vera".to_owned(),
                display_name: None,
                password: Some(SecretString::new(BREACHED)),
                roles: vec![RoleName::Viewer],
                language: None,
            },
        )
        .await
        .expect_err("refused");
    assert_eq!(
        violations_of(refused),
        [PolicyViolation::Breached { count: Some(42) }]
    );
}

#[tokio::test]
async fn a_breached_password_cannot_complete_setup() {
    let source = FakeSource::new(&[(BREACHED, 7)]);
    let online: Arc<dyn HibpRangeSource> = source.clone();
    let env = TestEnv::with_config(AuthConfig {
        hibp_online: Some(online),
        ..AuthConfig::default()
    })
    .await;
    let token = env
        .service
        .prepare_setup()
        .await
        .expect("prepare")
        .expect("open");
    let request = |password: &str| SetupRequest {
        setup_token: SecretString::new(token.expose()),
        profile: Profile::Standard,
        admin: SetupAdmin {
            name: ADMIN.to_owned(),
            display_name: None,
            password: SecretString::new(password),
        },
        host_name: HOST.to_owned(),
        language: "en".to_owned(),
    };
    let error = env
        .service
        .complete_setup(&env.public_ctx(), None, &request(BREACHED))
        .await
        .expect_err("refused");
    assert_eq!(
        violations_of(error),
        [PolicyViolation::Breached { count: Some(7) }]
    );
    assert!(env.service.setup_state().await.expect("state").open);
    env.service
        .complete_setup(&env.public_ctx(), None, &request(ADMIN_PASSWORD))
        .await
        .expect("setup with a clean password");
}

#[tokio::test]
async fn an_unavailable_source_fails_open_and_says_so() {
    let source = FakeSource::new(&[(BREACHED, 42)]);
    let (env, session) = env_with(&source, Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    for behaviour in [Behaviour::Down, Behaviour::Garbled] {
        source.set(behaviour);
        let result = env
            .service
            .check_password(Some(&ctx), &check(BREACHED))
            .await
            .expect("check");
        assert!(result.acceptable, "TGL-06 fails open");
        assert_eq!(result.violations, []);
        assert_eq!(result.breach_check, BreachStatus::Unavailable);
    }
    let changed = env
        .service
        .change_password(&ctx, &change(Some(ADMIN_PASSWORD), BREACHED))
        .await
        .expect("the change goes through while the check is down");
    assert_eq!(changed.breach_check, BreachStatus::Unavailable);

    // Once the source answers again, the same password is refused.
    source.set(Behaviour::Answer);
    let ctx = self::ctx(&env, &session).await;
    assert_eq!(
        violations_of(
            env.service
                .change_password(&ctx, &change(Some(BREACHED), BREACHED))
                .await
                .expect_err("refused again"),
        ),
        [PolicyViolation::Breached { count: Some(42) }]
    );
}

#[tokio::test]
async fn without_any_source_the_check_is_unavailable_not_clean() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    let result = env
        .service
        .check_password(Some(&ctx), &check(FRESH_PASSPHRASE))
        .await
        .expect("check");
    assert!(result.acceptable);
    assert_eq!(result.breach_check, BreachStatus::Unavailable);
}

#[tokio::test]
async fn the_lab_profile_reports_off_and_never_contacts_the_source() {
    let source = FakeSource::new(&[("1357", 99)]);
    let (env, session) = env_with(&source, Profile::Lab).await;
    let ctx = ctx(&env, &session).await;
    let result = env
        .service
        .check_password(Some(&ctx), &check("1357"))
        .await
        .expect("check");
    assert!(result.acceptable);
    assert_eq!(result.breach_check, BreachStatus::Off);
    assert_eq!(result.violations, []);
    let changed = env
        .service
        .change_password(&ctx, &change(Some(ADMIN_PIN), "1357"))
        .await
        .expect("a breached PIN passes while the check is off");
    assert_eq!(changed.breach_check, BreachStatus::Off);
    assert_eq!(
        source.seen(),
        Vec::<String>::new(),
        "nothing left the process"
    );
}

#[tokio::test]
async fn switching_the_check_off_stops_the_requests() {
    let source = FakeSource::new(&[(BREACHED, 42)]);
    let (env, session) = env_with(&source, Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    env.service
        .check_password(Some(&ctx), &check(FRESH_PASSPHRASE))
        .await
        .expect("check");
    let requests = source.seen().len();
    assert!(requests >= 1);
    env.service
        .update_security_settings(
            &env.public_ctx(),
            &SettingsPatch {
                breach_check: Some(BreachMode::Off),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    let result = env
        .service
        .check_password(Some(&ctx), &check(BREACHED))
        .await
        .expect("check");
    assert_eq!(result.breach_check, BreachStatus::Off);
    assert!(result.acceptable);
    assert_eq!(source.seen().len(), requests);
}

#[tokio::test]
async fn the_source_only_ever_receives_a_five_character_prefix() {
    let source = FakeSource::new(&[(BREACHED, 42)]);
    let (env, session) = env_with(&source, Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    let used = [ADMIN_PASSWORD, BREACHED, FRESH_PASSPHRASE, PASSPHRASE];
    env.service
        .check_password(Some(&ctx), &check(BREACHED))
        .await
        .expect("check");
    env.service
        .check_password(Some(&ctx), &check(FRESH_PASSPHRASE))
        .await
        .expect("check");
    env.service
        .change_password(&ctx, &change(Some(ADMIN_PASSWORD), FRESH_PASSPHRASE))
        .await
        .expect("change");
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;

    let seen = source.seen();
    assert!(seen.len() >= used.len(), "{seen:?}");
    for prefix in &seen {
        assert_eq!(prefix.len(), 5, "{prefix}");
        assert!(
            prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
            "{prefix}"
        );
    }
    let expected: std::collections::BTreeSet<String> = used
        .iter()
        .map(|password| sha1_hex_upper(password)[..5].to_owned())
        .collect();
    let actual: std::collections::BTreeSet<String> = seen.into_iter().collect();
    assert_eq!(actual, expected, "one prefix per password that was checked");
}

/// An offline corpus that holds the SHA-1 of each password.
fn corpus_of(passwords: &[&str]) -> Arc<HibpFilter> {
    let mut text = String::new();
    for password in passwords {
        writeln!(text, "{}:5", sha1_hex_upper(password)).expect("writing to a string");
    }
    let mut bytes = Vec::new();
    build_filter(text.as_bytes(), &mut bytes, &BuildOptions { min_count: 1 }).expect("a filter");
    Arc::new(HibpFilter::from_bytes(bytes).expect("a filter"))
}

async fn env_with_corpus(
    source: &Arc<FakeSource>,
    corpus: &Arc<HibpFilter>,
    profile: Profile,
) -> (TestEnv, NewSession) {
    let online: Arc<dyn HibpRangeSource> = source.clone();
    let env = TestEnv::with_config(AuthConfig {
        hibp_online: Some(online),
        hibp_offline: Some(corpus.clone()),
        ..AuthConfig::default()
    })
    .await;
    let session = env.setup(profile).await.expect("setup succeeds");
    (env, session)
}

#[tokio::test]
async fn hardened_prefers_the_offline_corpus_and_sends_nothing() {
    let source = FakeSource::new(&[(BREACHED, 42)]);
    let corpus = corpus_of(&[BREACHED]);
    let (env, session) = env_with_corpus(&source, &corpus, Profile::Hardened).await;
    let ctx = ctx(&env, &session).await;
    let result = env
        .service
        .check_password(Some(&ctx), &check(BREACHED))
        .await
        .expect("check");
    assert_eq!(result.breach_check, BreachStatus::Breached);
    assert_eq!(
        result.violations,
        [PolicyViolation::Breached { count: None }],
        "the offline corpus holds no counts"
    );
    let clean = env
        .service
        .check_password(Some(&ctx), &check(FRESH_PASSPHRASE))
        .await
        .expect("check");
    assert_eq!(clean.breach_check, BreachStatus::Clean);
    assert_eq!(
        violations_of(
            env.service
                .change_password(&ctx, &change(Some(ADMIN_PASSWORD), BREACHED))
                .await
                .expect_err("refused"),
        ),
        [PolicyViolation::Breached { count: None }]
    );
    assert_eq!(
        source.seen(),
        Vec::<String>::new(),
        "nothing left the process"
    );
}

#[tokio::test]
async fn the_online_check_falls_back_to_the_offline_corpus() {
    let source = FakeSource::new(&[]);
    let corpus = corpus_of(&[BREACHED]);
    let (env, session) = env_with_corpus(&source, &corpus, Profile::Standard).await;
    let ctx = ctx(&env, &session).await;
    source.set(Behaviour::Down);
    let result = env
        .service
        .check_password(Some(&ctx), &check(BREACHED))
        .await
        .expect("check");
    assert_eq!(result.breach_check, BreachStatus::Breached);
    assert!(!result.acceptable);
    assert!(
        !source.seen().is_empty(),
        "the online source was tried first"
    );
}

#[tokio::test]
async fn offline_mode_without_a_corpus_is_unavailable_and_asks_nobody() {
    let source = FakeSource::new(&[(BREACHED, 42)]);
    let (env, session) = env_with(&source, Profile::Standard).await;
    env.service
        .update_security_settings(
            &env.public_ctx(),
            &SettingsPatch {
                breach_check: Some(BreachMode::Offline),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    let requests = source.seen().len();
    let result = env
        .service
        .check_password(Some(&ctx(&env, &session).await), &check(BREACHED))
        .await
        .expect("check");
    assert_eq!(result.breach_check, BreachStatus::Unavailable);
    assert!(result.acceptable, "TGL-06 fails open");
    assert_eq!(source.seen().len(), requests);
}

// ---------------------------------------------------------------------------------------
// check_password before and after setup
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_policy_check_is_public_before_setup_and_applies_the_profiles_preset() {
    let env = TestEnv::new().await;
    let with_profile = |password: &str, profile: Option<Profile>| PasswordCheck {
        password: SecretString::new(password),
        user_name: None,
        profile,
    };
    let result = env
        .service
        .check_password(None, &with_profile("abc", Some(Profile::Home)))
        .await
        .expect("check");
    assert_eq!(result.policy, PasswordPolicy::Pin);
    assert!(result.violations.contains(&PolicyViolation::PinDigitsOnly));
    assert!(!result.acceptable);

    let result = env
        .service
        .check_password(None, &with_profile("short pass", Some(Profile::Hardened)))
        .await
        .expect("check");
    assert_eq!(result.policy, PasswordPolicy::Hardened);
    assert_eq!(result.violations, [PolicyViolation::TooShort { min: 16 }]);

    // Without a profile the Standard preset applies; the system context works too.
    let result = env
        .service
        .check_password(Some(&env.public_ctx()), &with_profile("short pass", None))
        .await
        .expect("check");
    assert_eq!(result.policy, PasswordPolicy::Standard);
    assert_eq!(result.violations, [PolicyViolation::TooShort { min: 12 }]);

    let good = env
        .service
        .check_password(None, &with_profile(ADMIN_PASSWORD, Some(Profile::Hardened)))
        .await
        .expect("check");
    assert!(good.acceptable);
    // No range source is configured, and Lab asks for none.
    assert_eq!(good.breach_check, BreachStatus::Unavailable);
    let lab = env
        .service
        .check_password(None, &with_profile("1357", Some(Profile::Lab)))
        .await
        .expect("check");
    assert_eq!(lab.breach_check, BreachStatus::Off);

    // The words around a user name count when the caller names the account.
    let named = env
        .service
        .check_password(
            None,
            &PasswordCheck {
                password: SecretString::new(ADMIN_PASSWORD),
                user_name: Some("plover".to_owned()),
                profile: None,
            },
        )
        .await
        .expect("check");
    assert!(!named.acceptable);
    assert_eq!(named.violations.len(), 1);
}

#[tokio::test]
async fn the_policy_check_needs_a_session_after_setup() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    assert!(matches!(
        env.service
            .check_password(None, &check("whatever it is"))
            .await,
        Err(AuthError::Unauthenticated)
    ));
    // The system context belongs to no user.
    assert!(matches!(
        env.service
            .check_password(Some(&env.public_ctx()), &check("whatever it is"))
            .await,
        Err(AuthError::Unauthenticated)
    ));
    let ctx = ctx(&env, &session).await;
    // The caller's installation decides; a profile in the request is ignored.
    let result = env
        .service
        .check_password(
            Some(&ctx),
            &PasswordCheck {
                password: SecretString::new("1357"),
                user_name: None,
                profile: Some(Profile::Lab),
            },
        )
        .await
        .expect("check");
    assert_eq!(result.policy, PasswordPolicy::Standard);
    assert!(!result.acceptable);

    // The caller's own names count as context.
    let own = env
        .service
        .check_password(Some(&ctx), &check("my admin secret phrase"))
        .await
        .expect("check");
    assert!(own.violations.iter().any(|violation| matches!(
        violation,
        PolicyViolation::ContextSpecific {
            context: tenko_auth::password::policy::ContextKind::UserName
        }
    )));

    // A personal token may ask as well.
    let viewer = login(&env, "vera", PASSPHRASE).await;
    let viewer_ctx = self::ctx(&env, &viewer).await;
    let token = env
        .service
        .create_token(
            &viewer_ctx,
            &TokenCreate {
                name: "checker".to_owned(),
                expires_in_days: None,
            },
        )
        .await
        .expect("token");
    let token_ctx = env
        .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
        .await
        .expect("token context");
    env.service
        .check_password(Some(&token_ctx), &check("whatever it is"))
        .await
        .expect("a token may use the check");
}

// ---------------------------------------------------------------------------------------
// Fresh authentication and the last factor
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn factor_changes_need_a_fresh_authentication() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    let first = login(&env, "vera", PASSPHRASE).await;
    let ctx = ctx(&env, &first).await;
    let (seed, _) = enrol_totp(&env, &ctx).await;
    register_passkey(&env, &ctx).await;
    register_passkey(&env, &ctx).await;
    let session = totp_login(&env, "vera", PASSPHRASE, &seed).await;
    let credentials_before = env.service.list_credentials(&ctx).await.expect("list");
    assert_eq!(credentials_before.len(), 2);

    // Just inside the window the changes are allowed.
    env.clock
        .advance(FRESH_AUTHENTICATION.saturating_sub(Duration::from_secs(2)));
    let inside = self::ctx(&env, &session).await;
    env.service
        .regenerate_recovery_codes(&inside)
        .await
        .expect("still fresh");

    // Past five minutes since the login, every one of them asks for a new login.
    env.clock.advance(Duration::from_secs(3));
    let stale = self::ctx(&env, &session).await;
    let step_up = AuthError::StepUpRequired { required: "fresh" };
    assert_eq!(
        env.service
            .regenerate_recovery_codes(&stale)
            .await
            .expect_err("stale"),
        step_up
    );
    assert_eq!(
        env.service.remove_totp(&stale).await.expect_err("stale"),
        step_up
    );
    let first_id = credentials_before[0].id.clone();
    assert_eq!(
        env.service
            .delete_credential(&stale, &first_id)
            .await
            .expect_err("stale"),
        step_up
    );
    assert_eq!(
        env.service
            .delete_credential(&stale, "unknown")
            .await
            .expect_err("stale"),
        step_up,
        "freshness is checked before the credential is looked up"
    );
    assert_eq!(
        env.service
            .list_credentials(&stale)
            .await
            .expect("list")
            .len(),
        2
    );

    // A new login restores them.
    let renewed = totp_login(&env, "vera", PASSPHRASE, &seed).await;
    let fresh = self::ctx(&env, &renewed).await;
    env.service
        .delete_credential(&fresh, &first_id)
        .await
        .expect("fresh");
    assert_eq!(
        env.service
            .delete_credential(&fresh, &first_id)
            .await
            .expect_err("gone"),
        AuthError::NotFound { kind: "credential" }
    );
    env.service.remove_totp(&fresh).await.expect("fresh");
    assert_eq!(
        env.service
            .remove_totp(&fresh)
            .await
            .expect_err("none left"),
        AuthError::TotpNotEnrolled
    );
}

#[tokio::test]
async fn recovery_codes_are_replaced_and_the_old_ones_stop_working() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    let first = login(&env, "vera", PASSPHRASE).await;
    let ctx = ctx(&env, &first).await;
    // Without TOTP or a passkey there is nothing for recovery codes to recover.
    assert!(matches!(
        env.service.regenerate_recovery_codes(&ctx).await,
        Err(AuthError::Invalid {
            field: "recovery_codes",
            ..
        })
    ));
    assert_eq!(
        env.service.remove_totp(&ctx).await.expect_err("no TOTP"),
        AuthError::TotpNotEnrolled
    );
    let (seed, old_codes) = enrol_totp(&env, &ctx).await;
    assert_eq!(old_codes.len(), 10);

    let session = totp_login(&env, "vera", PASSPHRASE, &seed).await;
    let session_ctx = self::ctx(&env, &session).await;
    let new_codes = env
        .service
        .regenerate_recovery_codes(&session_ctx)
        .await
        .expect("regenerate");
    let new_codes: Vec<String> = new_codes
        .codes
        .iter()
        .map(|code| code.expose().to_owned())
        .collect();
    assert_eq!(new_codes.len(), 10);
    assert!(new_codes.iter().all(|code| !old_codes.contains(code)));

    let challenge_id = second_step(&env, "vera", PASSPHRASE).await;
    let login_with = |code: &str| CodeLogin {
        challenge_id: challenge_id.clone(),
        code: SecretString::new(code),
    };
    assert!(matches!(
        env.service
            .login_recovery(&env.public_ctx(), None, &login_with(&old_codes[0]))
            .await,
        Err(AuthError::InvalidCredentials)
    ));
    let recovered = expect_session(
        env.service
            .login_recovery(&env.public_ctx(), None, &login_with(&new_codes[0]))
            .await
            .expect("a new code works"),
    );
    assert_eq!(recovered.info.strength, AuthStrength::PasswordTotp);
}

#[tokio::test]
async fn a_standard_administrator_keeps_a_second_factor() {
    let (env, setup) = TestEnv::installed(Profile::Standard).await;
    let (seed, _) = enrol_totp(&env, &ctx(&env, &setup).await).await;
    let strong = totp_login(&env, ADMIN, ADMIN_PASSWORD, &seed).await;
    let ctx = ctx(&env, &strong).await;
    // TOTP is the only way to reach the strength the profile asks of an administrator.
    assert_eq!(
        env.service
            .remove_totp(&ctx)
            .await
            .expect_err("last factor"),
        AuthError::LastFactor
    );
    // A passkey satisfies the requirement as well, so then TOTP may go.
    let mut key = register_passkey(&env, &ctx).await;
    env.service
        .remove_totp(&ctx)
        .await
        .expect("a passkey remains");
    let id = env.service.list_credentials(&ctx).await.expect("list")[0]
        .id
        .clone();
    assert_eq!(
        env.service
            .delete_credential(&ctx, &id)
            .await
            .expect_err("last factor"),
        AuthError::LastFactor
    );
    // The passkey still logs the administrator in.
    let session = passkey_login(&env, &mut key, ADMIN).await;
    assert!(session.info.strength >= AuthStrength::PasswordTotp);
}

#[tokio::test]
async fn hardened_keeps_a_passkey_for_administrators_and_two_factors_for_everyone() {
    let (env, setup) = TestEnv::installed(Profile::Hardened).await;
    let ctx = ctx(&env, &setup).await;
    register_passkey(&env, &ctx).await;
    register_passkey(&env, &ctx).await;
    let ids: Vec<String> = env
        .service
        .list_credentials(&ctx)
        .await
        .expect("list")
        .into_iter()
        .map(|credential| credential.id)
        .collect();
    env.service
        .delete_credential(&ctx, &ids[0])
        .await
        .expect("one of two");
    assert_eq!(
        env.service
            .delete_credential(&ctx, &ids[1])
            .await
            .expect_err("last"),
        AuthError::LastFactor
    );

    // Every account needs two factors under Hardened, so a viewer keeps their TOTP.
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    let viewer = login(&env, "vera", PASSPHRASE).await;
    assert!(viewer.info.flags.mfa_enrolment_required);
    let (seed, _) = enrol_totp(&env, &self::ctx(&env, &viewer).await).await;
    let strong = totp_login(&env, "vera", PASSPHRASE, &seed).await;
    assert_eq!(
        env.service
            .remove_totp(&self::ctx(&env, &strong).await)
            .await
            .expect_err("last factor"),
        AuthError::LastFactor
    );
}

#[tokio::test]
async fn an_operator_secret_makes_the_totp_of_a_pin_administrator_indispensable() {
    let (env, setup) = TestEnv::installed(Profile::Home).await;
    let ctx = ctx(&env, &setup).await;
    let (seed, _) = enrol_totp(&env, &ctx).await;
    let fresh = totp_login(&env, ADMIN, ADMIN_PIN, &seed).await;
    assert_eq!(fresh.info.strength, AuthStrength::PasswordTotp);
    // Once the vault holds an operator secret a PIN alone no longer serves an administrator
    // (IAM-07), so the second factor is what keeps the account usable.
    put_operator_secret(&env).await;
    assert_eq!(
        env.service
            .remove_totp(&self::ctx(&env, &fresh).await)
            .await
            .expect_err("IAM-07"),
        AuthError::LastFactor
    );
}

// ---------------------------------------------------------------------------------------
// PINs
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_pin_logs_in_as_pin_and_switching_the_preset_flags_a_change() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    assert_eq!(session.info.strength, AuthStrength::Pin);
    let before = login(&env, ADMIN, ADMIN_PIN).await;
    assert_eq!(before.info.strength, AuthStrength::Pin);
    assert!(!before.info.flags.password_change_required);

    let admin = ctx(&env, &session).await;
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                password_policy: Some(PasswordPolicy::Standard),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("switch the preset");
    let after = login(&env, ADMIN, ADMIN_PIN).await;
    assert_eq!(
        after.info.strength,
        AuthStrength::Pin,
        "the stored password is still a PIN"
    );
    assert!(after.info.flags.password_change_required);
    let authenticated = env
        .service
        .authenticate_credentials(&credentials(&after), env.now())
        .await
        .expect("session");
    assert!(authenticated.flags.password_change_required);

    // Choosing a password under the new preset clears the flag and raises the strength.
    let after_ctx = ctx(&env, &after).await;
    env.service
        .change_password(&after_ctx, &change(Some(ADMIN_PIN), ADMIN_PASSWORD))
        .await
        .expect("change");
    let password = login(&env, ADMIN, ADMIN_PASSWORD).await;
    assert_eq!(password.info.strength, AuthStrength::Password);
    assert!(!password.info.flags.password_change_required);
    assert!(matches!(
        password_login(&env, ADMIN, ADMIN_PIN).await,
        Err(AuthError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn a_password_set_under_a_strong_preset_is_not_a_pin() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    assert_eq!(session.info.strength, AuthStrength::Password);
    let again = login(&env, ADMIN, ADMIN_PASSWORD).await;
    assert_eq!(again.info.strength, AuthStrength::Password);
    assert!(!again.info.flags.password_change_required);
}

#[tokio::test]
async fn a_custom_preset_cannot_stand_in_for_the_pin_preset() {
    let (env, setup) = TestEnv::installed(Profile::Standard).await;
    let (seed, _) = enrol_totp(&env, &ctx(&env, &setup).await).await;
    let strong = totp_login(&env, ADMIN, ADMIN_PASSWORD, &seed).await;
    put_operator_secret(&env).await;
    let admin = ctx(&env, &strong).await;
    let equivalent_to_a_pin = SettingsPatch {
        password_policy: Some(PasswordPolicy::Custom(CustomPolicy {
            min_length: 4,
            max_length: 64,
            pattern: Some("\\d+".to_owned()),
        })),
        mfa: Some(MfaRequirement::Optional),
        ..SettingsPatch::default()
    };
    let outcome = env
        .service
        .update_security_settings(&admin, &equivalent_to_a_pin, None)
        .await;
    assert_eq!(
        outcome.expect_err("IAM-07 applies to every preset that allows a PIN"),
        AuthError::PinCoupling
    );
}

// ---------------------------------------------------------------------------------------
// PINs under a Custom preset (IAM-07)
// ---------------------------------------------------------------------------------------

/// A Home installation whose preset is Custom with a minimum of six characters and no
/// pattern, so that both numeric and mixed secrets are valid.
async fn home_with_a_six_character_preset() -> (TestEnv, NewSession) {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    env.service
        .update_security_settings(
            &ctx(&env, &session).await,
            &SettingsPatch {
                password_policy: Some(PasswordPolicy::Custom(CustomPolicy {
                    min_length: 6,
                    max_length: 64,
                    pattern: None,
                })),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("a Custom preset is allowed while the vault holds no operator secret");
    (env, session)
}

#[tokio::test]
async fn a_short_numeric_secret_is_a_pin_whatever_the_preset() {
    let (env, session) = home_with_a_six_character_preset().await;
    let mut current = ADMIN_PIN;
    let cases = [
        ("483920", AuthStrength::Pin),
        ("ab3d9x", AuthStrength::Password),
        ("483920174856", AuthStrength::Password),
    ];
    for (secret, strength) in cases {
        env.service
            .change_password(&ctx(&env, &session).await, &change(Some(current), secret))
            .await
            .expect("change");
        let again = login(&env, ADMIN, secret).await;
        assert_eq!(again.info.strength, strength, "{secret}");
        current = secret;
    }
}

#[tokio::test]
async fn a_short_numeric_secret_does_not_administer_once_the_vault_holds_a_secret() {
    let (env, session) = home_with_a_six_character_preset().await;
    env.service
        .change_password(
            &ctx(&env, &session).await,
            &change(Some(ADMIN_PIN), "483920"),
        )
        .await
        .expect("change");
    let numeric = login(&env, ADMIN, "483920").await;
    put_operator_secret(&env).await;
    assert!(matches!(
        env.service.list_users(&ctx(&env, &numeric).await).await,
        Err(AuthError::Denied(_))
    ));
    // A secret that is not a PIN in substance serves again.
    env.service
        .change_password(
            &ctx(&env, &numeric).await,
            &change(Some("483920"), "ab3d9x"),
        )
        .await
        .expect("change");
    let mixed = login(&env, ADMIN, "ab3d9x").await;
    env.service
        .list_users(&ctx(&env, &mixed).await)
        .await
        .expect("a password session administers");
}
