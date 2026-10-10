//! User and settings administration of the authentication service: creating, changing,
//! disabling, unlocking and deleting users, the last-administrator guard, and the security
//! settings with their audit trail (IAM-05, IAM-07, IAM-08, IAM-19, API-10, TGL-01 to TGL-07).

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use tenko_auth::{
    AuthConfig, AuthError, AuthService, LoginOutcome, NewSession,
    clock::{Clock, MockClock},
    encoding::base32_decode,
    hibp::BreachMode,
    lockout::LockoutMode,
    model::{
        ALARMS, AlarmKind, CREDENTIAL_IDS, CREDENTIALS, SESSIONS, TOKENS, USER_NAMES,
        USER_SESSIONS, USER_TOKENS, USERS,
    },
    password::{
        PolicyViolation,
        policy::{CustomPolicy, PasswordPolicy},
    },
    roles::RoleName,
    service::{
        BreakGlassChange, CodeLogin, PasswordChange, PasswordLogin, SecuritySettingsView,
        SetupAdmin, SetupRequest, TokenCreate, TotpEnrolFinish, UserCreate, UserInfo, UserUpdate,
        WebAuthnLoginFinish, WebAuthnLoginStart, WebAuthnRegisterFinish, WebAuthnRegisterStart,
        types::SecretString,
    },
    settings::{
        MfaRequirement, Profile, RevealPolicy, RevealStepUp, SessionLifetime, SettingsPatch,
        TokenMaxLifetime,
    },
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ADMIN_PIN, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{
    AuthStrength, Coded, Credentials, DenyReason, ObjectKind, ObjectRef, Principal, RequestCtx,
    Revision, SessionId, SystemComponent, UserId,
    audit::{AuditOutcome, AuditRecord},
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, KeyRange, MemStore, ReadConsistency, ReadView,
    ReadViewExt, Store, StoreError, StoreStatus, WatchFilter, WriteBatch, tables,
};
use tenko_vault::{MemVault, SecretBytes, SecretPurpose, SecretSpec, Vault};
use tokio::sync::Barrier;

const PASSPHRASE: &str = "marble comet violin saffron";

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

fn new_user(name: &str, roles: &[RoleName], password: Option<&str>) -> UserCreate {
    UserCreate {
        name: name.to_owned(),
        display_name: None,
        password: password.map(SecretString::new),
        roles: roles.to_vec(),
        language: None,
    }
}

async fn create(env: &TestEnv, admin: &RequestCtx, request: &UserCreate) -> UserInfo {
    env.service
        .create_user(admin, request)
        .await
        .expect("the user is created")
}

async fn disable(env: &TestEnv, admin: &RequestCtx, id: UserId, disabled: bool) -> UserInfo {
    env.service
        .update_user(
            admin,
            id,
            &UserUpdate {
                disabled: Some(disabled),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("the account is updated")
}

fn denied_reason<T: std::fmt::Debug>(result: Result<T, AuthError>) -> DenyReason {
    match result {
        Err(AuthError::Denied(denied)) => denied.reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

async fn audit_records(env: &TestEnv) -> Vec<AuditRecord> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

async fn audit_of(env: &TestEnv, action: &str) -> Vec<AuditRecord> {
    audit_records(env)
        .await
        .into_iter()
        .filter(|record| record.draft.action.as_str() == action)
        .collect()
}

async fn enrol_totp(env: &TestEnv, ctx: &RequestCtx) -> Vec<u8> {
    let start = env
        .service
        .totp_enrol_start(ctx)
        .await
        .expect("enrolment starts");
    let seed = base32_decode(start.secret.expose()).expect("a base32 seed");
    let code = totp::code_at(&seed, &TotpParams::default(), unix_seconds(env));
    env.service
        .totp_enrol_finish(
            ctx,
            &TotpEnrolFinish {
                enrolment_id: start.enrolment_id,
                code: SecretString::new(code.as_str()),
            },
        )
        .await
        .expect("enrolment finishes");
    seed
}

async fn totp_login(env: &TestEnv, user: &str, password: &str, seed: &[u8]) -> NewSession {
    env.clock.advance(Duration::from_secs(60));
    let LoginOutcome::SecondFactor { challenge_id, .. } = password_login(env, user, password)
        .await
        .expect("first step")
    else {
        panic!("expected a second-factor challenge");
    };
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

/// A Standard installation and a two-factor session of its administrator.
async fn standard_with_strong_admin() -> (TestEnv, NewSession) {
    let (env, setup) = TestEnv::installed(Profile::Standard).await;
    let seed = enrol_totp(&env, &ctx(&env, &setup).await).await;
    let strong = totp_login(&env, ADMIN, ADMIN_PASSWORD, &seed).await;
    assert_eq!(strong.info.strength, AuthStrength::PasswordTotp);
    (env, strong)
}

async fn register_passkey(
    env: &TestEnv,
    ctx: &RequestCtx,
    authenticator: &mut SoftAuthenticator,
) -> Result<(), AuthError> {
    let options = env
        .service
        .webauthn_register_start(
            ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key: false,
            },
        )
        .await?;
    let credential = authenticator.register(&options.public_key, ORIGIN);
    env.service
        .webauthn_register_finish(
            ctx,
            &WebAuthnRegisterFinish {
                ceremony_id: options.ceremony_id,
                credential,
            },
        )
        .await?;
    Ok(())
}

async fn passkey_login(
    env: &TestEnv,
    authenticator: &mut SoftAuthenticator,
) -> Result<NewSession, AuthError> {
    let options = env
        .service
        .webauthn_login_start(&env.public_ctx(), &WebAuthnLoginStart::default())
        .await?;
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

/// The number of rows in the user, session, token, credential and vault tables.
async fn row_counts(env: &TestEnv) -> [usize; 9] {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let scan = KeyRange::all;
    [
        view.scan_typed(&USERS, scan(), 1_000, false)
            .expect("users")
            .len(),
        view.scan_typed(&USER_NAMES, scan(), 1_000, false)
            .expect("names")
            .len(),
        view.scan_typed(&SESSIONS, scan(), 1_000, false)
            .expect("sessions")
            .len(),
        view.scan_typed(&USER_SESSIONS, scan(), 1_000, false)
            .expect("session index")
            .len(),
        view.scan_typed(&TOKENS, scan(), 1_000, false)
            .expect("tokens")
            .len(),
        view.scan_typed(&USER_TOKENS, scan(), 1_000, false)
            .expect("token index")
            .len(),
        view.scan_typed(&CREDENTIALS, scan(), 1_000, false)
            .expect("credentials")
            .len(),
        view.scan_typed(&CREDENTIAL_IDS, scan(), 1_000, false)
            .expect("credential ids")
            .len(),
        view.scan(&tenko_vault::tables::SECRETS, scan(), 1_000, false)
            .expect("secrets")
            .len(),
    ]
}

fn password_change(current: &str, new: &str) -> PasswordChange {
    PasswordChange {
        current_password: Some(SecretString::new(current)),
        new_password: SecretString::new(new),
    }
}

fn patch_lockout(mode: LockoutMode) -> SettingsPatch {
    SettingsPatch {
        lockout: Some(mode),
        ..SettingsPatch::default()
    }
}

/// The changes of an audit record as field to (old, new), both parsed as JSON.
fn changes_of(record: &AuditRecord) -> BTreeMap<String, (Value, Value)> {
    // Toggle values are JSON text; other changes are plain words, which stay strings.
    let parse = |text: &Option<String>| -> Value {
        text.as_deref().map_or(Value::Null, |text| {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
        })
    };
    record
        .draft
        .details
        .changes
        .iter()
        .map(|change| {
            (
                change.field.clone(),
                (parse(&change.old), parse(&change.new)),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Creating users
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn creating_a_user_returns_the_account_and_audits_it() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let info = create(
        &env,
        &admin,
        &UserCreate {
            name: "  Olga ".to_owned(),
            display_name: Some(" Olga Operator ".to_owned()),
            password: None,
            roles: vec![RoleName::Viewer, RoleName::Operator, RoleName::Viewer],
            language: Some("sv".to_owned()),
        },
    )
    .await;
    assert_eq!(info.name, "Olga", "trimmed, case kept");
    assert_eq!(info.display_name, "Olga Operator");
    assert_eq!(info.roles, vec![RoleName::Operator, RoleName::Viewer]);
    assert_eq!(info.language.as_deref(), Some("sv"));
    assert!(!info.disabled && !info.break_glass && info.lock.is_none());
    assert!(!info.factors.password && !info.factors.totp);
    assert_eq!((info.factors.webauthn, info.factors.recovery_codes), (0, 0));
    assert!(
        !info.password_change_required,
        "no initial password to change"
    );
    assert_eq!(info.created_at, env.now());
    assert_eq!(info.last_login_at, None);

    assert_eq!(
        env.service.get_user(&admin, info.id).await.expect("get"),
        info
    );
    let names: Vec<String> = env
        .service
        .list_users(&admin)
        .await
        .expect("list")
        .into_iter()
        .map(|user| user.name)
        .collect();
    assert_eq!(names, ["admin", "Olga"], "sorted case-insensitively");

    let records = audit_of(&env, "auth.user.create").await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].principal, admin.principal);
    assert_eq!(records[0].draft.objects, [ObjectRef::from(info.id)]);
    assert_eq!(records[0].draft.details.context["name"], "Olga");
    assert_eq!(records[0].draft.details.context["roles"], "operator,viewer");
}

#[tokio::test]
async fn the_display_name_defaults_to_the_login_name() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let info = create(&env, &admin, &new_user("vera", &[RoleName::Viewer], None)).await;
    assert_eq!(info.display_name, "vera");
}

#[tokio::test]
async fn user_names_are_unique_case_insensitively() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    create(
        &env,
        &admin,
        &new_user("Alice", &[RoleName::Viewer], Some("6402")),
    )
    .await;
    // A name beyond ASCII: case folding has to work for it as well.
    create(
        &env,
        &admin,
        &new_user("\u{c5}sa", &[RoleName::Viewer], None),
    )
    .await;
    for name in [
        "Alice",
        "ALICE",
        "alice",
        "  alice  ",
        "Admin",
        "ADMIN",
        "\u{e5}sa",
        "\u{c5}SA",
    ] {
        assert_eq!(
            env.service
                .create_user(&admin, &new_user(name, &[RoleName::Viewer], None))
                .await
                .expect_err("the name is taken"),
            AuthError::UserNameTaken,
            "{name:?}"
        );
    }
    assert_eq!(env.service.list_users(&admin).await.expect("list").len(), 3);
    // Logging in is case-insensitive in the same way.
    for spelling in ["alice", "ALICE", " Alice "] {
        login(&env, spelling, "6402").await;
    }
}

#[tokio::test]
async fn invalid_names_and_values_are_refused() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let too_long = "x".repeat(65);
    for name in [
        "",
        "   ",
        "two words",
        "tab\tname",
        "line\nbreak",
        "nul\0name",
        "a\u{a0}b",
        too_long.as_str(),
    ] {
        match env
            .service
            .create_user(&admin, &new_user(name, &[RoleName::Viewer], None))
            .await
        {
            Err(AuthError::Invalid { field: "name", .. }) => {}
            other => panic!("{name:?}: expected an invalid name, got {other:?}"),
        }
    }
    create(
        &env,
        &admin,
        &new_user(&"y".repeat(64), &[RoleName::Viewer], None),
    )
    .await;

    let no_roles = new_user("nora", &[], None);
    assert!(matches!(
        env.service.create_user(&admin, &no_roles).await,
        Err(AuthError::Invalid { field: "roles", .. })
    ));
    let mut bad_language = new_user("nora", &[RoleName::Viewer], None);
    bad_language.language = Some("de".to_owned());
    assert!(matches!(
        env.service.create_user(&admin, &bad_language).await,
        Err(AuthError::Invalid {
            field: "language",
            ..
        })
    ));
    let long_display = "d".repeat(129);
    for display in ["   ", "bad\nname", long_display.as_str()] {
        let mut request = new_user("nora", &[RoleName::Viewer], None);
        request.display_name = Some(display.to_owned());
        assert!(
            matches!(
                env.service.create_user(&admin, &request).await,
                Err(AuthError::Invalid {
                    field: "display_name",
                    ..
                })
            ),
            "{display:?}"
        );
    }
    // None of the refusals left an account behind.
    create(&env, &admin, &new_user("nora", &[RoleName::Viewer], None)).await;
}

#[tokio::test]
async fn an_initial_password_forces_a_change() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let info = create(
        &env,
        &admin,
        &new_user("pelle", &[RoleName::Operator], Some("6402")),
    )
    .await;
    assert!(info.password_change_required);
    assert!(info.factors.password);

    let first = login(&env, "pelle", "6402").await;
    assert!(first.info.flags.password_change_required);
    let authenticated = env
        .service
        .authenticate_credentials(&credentials(&first), env.now())
        .await
        .expect("the session works");
    assert!(authenticated.flags.password_change_required);

    let user_ctx = ctx(&env, &first).await;
    env.service
        .change_password(
            &user_ctx,
            &PasswordChange {
                current_password: Some(SecretString::new("6402")),
                new_password: SecretString::new("8305"),
            },
        )
        .await
        .expect("the user chooses their own password");
    assert!(
        !env.service
            .get_user(&admin, info.id)
            .await
            .expect("get")
            .password_change_required
    );
    let second = login(&env, "pelle", "8305").await;
    assert!(!second.info.flags.password_change_required);
}

#[tokio::test]
async fn an_initial_password_must_meet_the_policy_and_a_refusal_creates_nothing() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    for (password, violation) in [
        ("12", PolicyViolation::TooShort { min: 4 }),
        ("12ab", PolicyViolation::PinDigitsOnly),
        ("0000", PolicyViolation::Trivial),
    ] {
        match env
            .service
            .create_user(
                &admin,
                &new_user("pelle", &[RoleName::Viewer], Some(password)),
            )
            .await
        {
            Err(AuthError::PasswordPolicy(violations)) => {
                assert!(
                    violations.contains(&violation),
                    "{password:?}: {violations:?}"
                );
            }
            other => panic!("{password:?}: expected a policy refusal, got {other:?}"),
        }
    }
    assert_eq!(env.service.list_users(&admin).await.expect("list").len(), 1);
    create(
        &env,
        &admin,
        &new_user("pelle", &[RoleName::Viewer], Some("6402")),
    )
    .await;
}

// ---------------------------------------------------------------------------------------
// Changing users
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_update_with_a_stale_revision_conflicts() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(&env, &admin, &new_user("carl", &[RoleName::Viewer], None)).await;
    let stale: Revision = user.revision;
    let rename = |name: &str| UserUpdate {
        display_name: Some(name.to_owned()),
        ..UserUpdate::default()
    };
    let updated = env
        .service
        .update_user(&admin, user.id, &rename("Carl C."), Some(stale))
        .await
        .expect("the current revision is accepted");
    assert_eq!(updated.display_name, "Carl C.");
    assert_ne!(updated.revision, stale);

    assert_eq!(
        env.service
            .update_user(&admin, user.id, &rename("Carl D."), Some(stale))
            .await
            .expect_err("stale"),
        AuthError::Conflict
    );
    assert_eq!(
        env.service
            .set_user_roles(&admin, user.id, &[RoleName::Operator], Some(stale))
            .await
            .expect_err("stale"),
        AuthError::Conflict
    );
    let unchanged = env.service.get_user(&admin, user.id).await.expect("get");
    assert_eq!(unchanged.display_name, "Carl C.");
    assert_eq!(unchanged.roles, [RoleName::Viewer]);

    // The current revision, or none at all, goes through.
    env.service
        .update_user(&admin, user.id, &rename("Carl D."), Some(updated.revision))
        .await
        .expect("current");
    let last = env
        .service
        .update_user(&admin, user.id, &rename("Carl E."), None)
        .await
        .expect("no precondition");
    assert_eq!(last.display_name, "Carl E.");
}

#[tokio::test]
async fn updates_validate_their_values_and_know_the_user() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(&env, &admin, &new_user("carl", &[RoleName::Viewer], None)).await;
    let with_language = env
        .service
        .update_user(
            &admin,
            user.id,
            &UserUpdate {
                language: Some("sv".to_owned()),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("language");
    assert_eq!(with_language.language.as_deref(), Some("sv"));
    let cleared = env
        .service
        .update_user(
            &admin,
            user.id,
            &UserUpdate {
                language: Some(String::new()),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("an empty string removes the language");
    assert_eq!(cleared.language, None);
    for request in [
        UserUpdate {
            language: Some("de".to_owned()),
            ..UserUpdate::default()
        },
        UserUpdate {
            display_name: Some("  ".to_owned()),
            ..UserUpdate::default()
        },
    ] {
        assert!(matches!(
            env.service
                .update_user(&admin, user.id, &request, None)
                .await,
            Err(AuthError::Invalid { .. })
        ));
    }
    assert_eq!(
        env.service
            .update_user(&admin, UserId::generate(), &UserUpdate::default(), None)
            .await
            .expect_err("unknown"),
        AuthError::NotFound { kind: "user" }
    );
    let records = audit_of(&env, "auth.user.update").await;
    assert_eq!(records.len(), 2, "only successful updates are recorded");
    assert_eq!(
        changes_of(&records[0])["language"],
        (Value::Null, json!("sv"))
    );
}

#[tokio::test]
async fn an_administrator_password_reset_forces_a_change_and_ends_the_sessions() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(
        &env,
        &admin,
        &new_user("pelle", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let old = login(&env, "pelle", "6402").await;
    let reset = env
        .service
        .update_user(
            &admin,
            user.id,
            &UserUpdate {
                password: Some(SecretString::new("9157")),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("reset");
    assert!(reset.password_change_required);
    assert!(
        env.service
            .authenticate_credentials(&credentials(&old), env.now())
            .await
            .is_err()
    );
    assert!(matches!(
        password_login(&env, "pelle", "6402").await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        login(&env, "pelle", "9157")
            .await
            .info
            .flags
            .password_change_required
    );
    // The audit record names the change but never the value.
    let record = &audit_of(&env, "auth.user.update").await[0];
    let json = serde_json::to_string(record).expect("json");
    assert!(!json.contains("9157"));
}

#[tokio::test]
async fn role_changes_are_audited_and_validated() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(&env, &admin, &new_user("olga", &[RoleName::Viewer], None)).await;
    let updated = env
        .service
        .set_user_roles(
            &admin,
            user.id,
            &[RoleName::Operator, RoleName::Operator],
            None,
        )
        .await
        .expect("roles");
    assert_eq!(updated.roles, [RoleName::Operator]);
    assert!(matches!(
        env.service.set_user_roles(&admin, user.id, &[], None).await,
        Err(AuthError::Invalid { field: "roles", .. })
    ));
    assert_eq!(
        env.service
            .set_user_roles(&admin, UserId::generate(), &[RoleName::Viewer], None)
            .await
            .expect_err("unknown"),
        AuthError::NotFound { kind: "user" }
    );
    let records = audit_of(&env, "auth.user.roles").await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].draft.details.changes[0].field, "roles",
        "{:?}",
        records[0].draft.details.changes
    );
    assert_eq!(
        records[0].draft.details.changes[0].old.as_deref(),
        Some("viewer")
    );
    assert_eq!(
        records[0].draft.details.changes[0].new.as_deref(),
        Some("operator")
    );
    assert_eq!(env.service.roles().len(), 4);
}

// ---------------------------------------------------------------------------------------
// Disabling, deleting and the last administrator
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn disabling_a_user_ends_their_sessions_and_blocks_new_ones() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(
        &env,
        &admin,
        &new_user("dora", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let first = login(&env, "dora", "6402").await;
    let second = login(&env, "dora", "6402").await;
    let other = login(&env, ADMIN, ADMIN_PIN).await;
    let disabled = disable(&env, &admin, user.id, true).await;
    assert!(disabled.disabled);
    for ended in [&first, &second] {
        assert!(matches!(
            env.service
                .authenticate_credentials(&credentials(ended), env.now())
                .await,
            Err(AuthError::Unauthenticated)
        ));
    }
    // Other accounts keep their sessions.
    env.service
        .authenticate_credentials(&credentials(&other), env.now())
        .await
        .expect("untouched");
    assert!(matches!(
        password_login(&env, "dora", "6402").await,
        Err(AuthError::InvalidCredentials)
    ));
    let enabled = disable(&env, &admin, user.id, false).await;
    assert!(!enabled.disabled);
    login(&env, "dora", "6402").await;
    assert!(
        env.service
            .authenticate_credentials(&credentials(&first), env.now())
            .await
            .is_err(),
        "enabling does not revive an ended session"
    );
    let records = audit_of(&env, "auth.user.update").await;
    assert_eq!(
        changes_of(&records[0])["disabled"],
        (json!(false), json!(true))
    );
}

#[tokio::test]
async fn an_administrator_cannot_disable_or_delete_themselves() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let me = admin.principal.user().expect("a user");
    // A second administrator, so that the last-administrator guard is not the reason.
    create(
        &env,
        &admin,
        &new_user("boris", &[RoleName::Admin], Some("6402")),
    )
    .await;
    assert!(matches!(
        env.service
            .update_user(
                &admin,
                me,
                &UserUpdate {
                    disabled: Some(true),
                    ..UserUpdate::default()
                },
                None,
            )
            .await,
        Err(AuthError::Invalid {
            field: "disabled",
            ..
        })
    ));
    assert!(matches!(
        env.service.delete_user(&admin, me).await,
        Err(AuthError::Invalid { field: "id", .. })
    ));
    let info = env.service.get_user(&admin, me).await.expect("still there");
    assert!(!info.disabled);
    env.service
        .authenticate_credentials(&credentials(&session), env.now())
        .await
        .expect("the session survived");
}

#[tokio::test]
async fn the_last_administrator_cannot_be_disabled_demoted_or_deleted() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let me = admin.principal.user().expect("a user");
    // The system passes authorization and is nobody's own account, so only the guard stops it.
    let system = env.public_ctx();
    let disable_request = UserUpdate {
        disabled: Some(true),
        ..UserUpdate::default()
    };
    let guard = AuthError::LastAdministrator;
    assert_eq!(
        env.service
            .update_user(&system, me, &disable_request, None)
            .await
            .expect_err("disable"),
        guard
    );
    assert_eq!(
        env.service
            .delete_user(&system, me)
            .await
            .expect_err("delete"),
        guard
    );
    assert_eq!(
        env.service
            .set_user_roles(&system, me, &[RoleName::Viewer], None)
            .await
            .expect_err("demote"),
        guard
    );
    // An administrator who demotes themselves is the last one too.
    assert_eq!(
        env.service
            .set_user_roles(&admin, me, &[RoleName::Operator], None)
            .await
            .expect_err("self-demotion"),
        guard
    );
    // Keeping the admin role next to another one is fine.
    env.service
        .set_user_roles(&admin, me, &[RoleName::Admin, RoleName::Viewer], None)
        .await
        .expect("still an administrator");

    // A second administrator lifts the guard for one of them, and a disabled one does not count.
    let boris = create(
        &env,
        &admin,
        &new_user("boris", &[RoleName::Admin], Some("6402")),
    )
    .await;
    disable(&env, &admin, boris.id, true).await;
    assert_eq!(
        env.service
            .update_user(&system, me, &disable_request, None)
            .await
            .expect_err("a disabled administrator does not count"),
        guard
    );
    disable(&env, &admin, boris.id, false).await;
    env.service
        .set_user_roles(&system, boris.id, &[RoleName::Viewer], None)
        .await
        .expect("another administrator remains");
    assert_eq!(
        env.service
            .delete_user(&system, me)
            .await
            .expect_err("last again"),
        guard
    );
}

#[tokio::test]
async fn deleting_a_user_removes_their_sessions_tokens_credentials_and_seed() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let carol = create(
        &env,
        &admin,
        &new_user("carol", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let carol_session = login(&env, "carol", "6402").await;
    let carol_ctx = ctx(&env, &carol_session).await;
    let token = env
        .service
        .create_token(
            &carol_ctx,
            &TokenCreate {
                name: "job".to_owned(),
                expires_in_days: None,
            },
        )
        .await
        .expect("token");
    enrol_totp(&env, &carol_ctx).await;
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    register_passkey(&env, &carol_ctx, &mut key)
        .await
        .expect("passkey");

    // Users, names, sessions, session index, tokens, token index, credentials, credential
    // ids and vault secrets (the TOTP seed).
    assert_eq!(row_counts(&env).await, [2, 2, 2, 2, 1, 1, 1, 1, 1]);

    env.service
        .delete_user(&admin, carol.id)
        .await
        .expect("delete");
    assert_eq!(
        row_counts(&env).await,
        [1, 1, 1, 1, 0, 0, 0, 0, 0],
        "only the administrator and the administrator's session remain"
    );

    assert!(matches!(
        env.service
            .authenticate_credentials(&credentials(&carol_session), env.now())
            .await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service
            .authenticate_credentials(
                &Credentials::Bearer(token.token.expose().to_owned()),
                env.now()
            )
            .await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        password_login(&env, "carol", "6402").await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        passkey_login(&env, &mut key).await.is_err(),
        "the passkey is gone too"
    );
    assert_eq!(
        env.service
            .get_user(&admin, carol.id)
            .await
            .expect_err("gone"),
        AuthError::NotFound { kind: "user" }
    );
    let records = audit_of(&env, "auth.user.delete").await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].draft.objects, [ObjectRef::from(carol.id)]);
    assert_eq!(records[0].draft.details.context["name"], "carol");

    // The name is free again and the new account is a different one.
    let again = create(&env, &admin, &new_user("carol", &[RoleName::Viewer], None)).await;
    assert_ne!(again.id, carol.id);
}

#[tokio::test]
async fn deleting_an_unknown_user_finds_nothing() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    assert_eq!(
        env.service
            .delete_user(&admin, UserId::generate())
            .await
            .expect_err("unknown"),
        AuthError::NotFound { kind: "user" }
    );
}

// ---------------------------------------------------------------------------------------
// Lockout, unlock and sessions
// ---------------------------------------------------------------------------------------

/// Fails logins for `name` until the account carries a persisted lock.
async fn lock_account(env: &TestEnv, id: UserId, name: &str) {
    for _ in 0..40 {
        match password_login(env, name, "not the password at all").await {
            Err(AuthError::InvalidCredentials) => {}
            Err(AuthError::Throttled { retry_after }) => {
                env.clock
                    .advance(Duration::from_secs(retry_after.unwrap_or(60)));
            }
            other => panic!("unexpected {other:?}"),
        }
        let info = env
            .service
            .get_user(&env.public_ctx(), id)
            .await
            .expect("get");
        if info.lock.is_some() {
            return;
        }
    }
    panic!("the account was not locked after forty failures");
}

#[tokio::test]
async fn unlocking_clears_a_persisted_lock() {
    let (env, strong) = standard_with_strong_admin().await;
    let admin = ctx(&env, &strong).await;
    let user = create(
        &env,
        &admin,
        &new_user("lena", &[RoleName::Viewer], Some(PASSPHRASE)),
    )
    .await;
    lock_account(&env, user.id, "lena").await;

    let admin = ctx(&env, &strong).await;
    let locked = env.service.get_user(&admin, user.id).await.expect("get");
    let lock = locked.lock.expect("a persisted lock");
    assert!(!lock.until_unlock, "Standard locks temporarily");
    assert!(lock.until > env.now());
    assert!(matches!(
        password_login(&env, "lena", PASSPHRASE).await,
        Err(AuthError::Throttled { .. })
    ));

    let unlocked = env
        .service
        .unlock_user(&admin, user.id)
        .await
        .expect("unlock");
    assert_eq!(unlocked.lock, None);
    assert_eq!(
        env.service
            .get_user(&admin, user.id)
            .await
            .expect("get")
            .lock,
        None
    );
    // The right password works at once, and the failure count starts again.
    login(&env, "lena", PASSPHRASE).await;
    assert!(matches!(
        password_login(&env, "lena", "not the password at all").await,
        Err(AuthError::InvalidCredentials)
    ));
    let counts = [
        audit_of(&env, "auth.user.lock").await.len(),
        audit_of(&env, "auth.user.unlock").await.len(),
    ];
    assert_eq!(counts, [1, 1]);
    // Unlocking an unlocked account changes nothing and writes nothing.
    env.service
        .unlock_user(&admin, user.id)
        .await
        .expect("idempotent");
    assert_eq!(audit_of(&env, "auth.user.unlock").await.len(), 1);
}

#[tokio::test]
async fn revoking_all_sessions_of_a_user_ends_each_of_them() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(
        &env,
        &admin,
        &new_user("mats", &[RoleName::Viewer], Some("6402")),
    )
    .await;
    let first = login(&env, "mats", "6402").await;
    let second = login(&env, "mats", "6402").await;
    assert_eq!(
        env.service
            .revoke_user_sessions(&admin, user.id)
            .await
            .expect("revoke"),
        2
    );
    for ended in [&first, &second] {
        assert!(
            env.service
                .authenticate_credentials(&credentials(ended), env.now())
                .await
                .is_err()
        );
    }
    env.service
        .authenticate_credentials(&credentials(&session), env.now())
        .await
        .expect("the administrator's session is untouched");
    assert_eq!(
        env.service
            .revoke_user_sessions(&admin, user.id)
            .await
            .expect("again"),
        0
    );
    assert_eq!(
        env.service
            .revoke_user_sessions(&admin, UserId::generate())
            .await
            .expect_err("unknown"),
        AuthError::NotFound { kind: "user" }
    );
    login(&env, "mats", "6402").await;
    let records = audit_of(&env, "auth.session.revoke").await;
    assert_eq!(records[0].draft.details.context["sessions"], "2");
}

// ---------------------------------------------------------------------------------------
// Roles that may read but not administer
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn operators_may_read_users_and_settings_but_cannot_administer() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let me = admin.principal.user().expect("a user");
    create(
        &env,
        &admin,
        &new_user("olga", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let operator_session = login(&env, "olga", "6402").await;
    let operator = ctx(&env, &operator_session).await;

    assert_eq!(
        env.service.list_users(&operator).await.expect("list").len(),
        2
    );
    assert_eq!(
        env.service.get_user(&operator, me).await.expect("get").name,
        ADMIN
    );
    env.service
        .security_settings(&operator)
        .await
        .expect("settings");

    let missing = DenyReason::MissingPermission;
    assert_eq!(
        denied_reason(
            env.service
                .create_user(&operator, &new_user("eve", &[RoleName::Admin], None))
                .await
        ),
        missing
    );
    assert_eq!(
        denied_reason(
            env.service
                .update_user(&operator, me, &UserUpdate::default(), None)
                .await
        ),
        missing
    );
    assert_eq!(
        denied_reason(env.service.delete_user(&operator, me).await),
        missing
    );
    assert_eq!(
        denied_reason(env.service.unlock_user(&operator, me).await),
        missing
    );
    assert_eq!(
        denied_reason(env.service.revoke_user_sessions(&operator, me).await),
        missing
    );
    assert_eq!(
        denied_reason(
            env.service
                .set_user_roles(&operator, me, &[RoleName::Viewer], None)
                .await
        ),
        missing
    );
    assert_eq!(
        denied_reason(
            env.service
                .set_break_glass(
                    &operator,
                    &BreakGlassChange {
                        user_id: me,
                        enabled: true
                    }
                )
                .await
        ),
        missing
    );
    assert_eq!(env.service.list_users(&admin).await.expect("list").len(), 2);
}

#[tokio::test]
async fn viewers_cannot_read_users_or_settings() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let me = admin.principal.user().expect("a user");
    create(
        &env,
        &admin,
        &new_user("vera", &[RoleName::Viewer], Some("6402")),
    )
    .await;
    let viewer = ctx(&env, &login(&env, "vera", "6402").await).await;
    let missing = DenyReason::MissingPermission;
    assert_eq!(
        denied_reason(env.service.list_users(&viewer).await),
        missing
    );
    assert_eq!(
        denied_reason(env.service.get_user(&viewer, me).await),
        missing
    );
    assert_eq!(
        denied_reason(env.service.security_settings(&viewer).await),
        missing
    );
    assert_eq!(
        denied_reason(
            env.service
                .update_security_settings(&viewer, &SettingsPatch::default(), None)
                .await
        ),
        missing
    );
}

#[tokio::test]
async fn a_standard_administrator_needs_two_factors_for_administration() {
    let (env, setup) = TestEnv::installed(Profile::Standard).await;
    let weak = ctx(&env, &setup).await;
    assert_eq!(
        denied_reason(env.service.list_users(&weak).await),
        DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        }
    );
    assert_eq!(
        denied_reason(env.service.security_settings(&weak).await),
        DenyReason::StepUpRequired {
            required: AuthStrength::PasswordTotp
        }
    );
    let seed = enrol_totp(&env, &weak).await;
    let strong = ctx(&env, &totp_login(&env, ADMIN, ADMIN_PASSWORD, &seed).await).await;
    env.service
        .list_users(&strong)
        .await
        .expect("two factors suffice");
}

// ---------------------------------------------------------------------------------------
// Security settings
// ---------------------------------------------------------------------------------------

/// The matrix of SECURITY-PROFILES.md: toggle id, setting and the value per profile in the
/// order Home, Standard, Hardened, Lab.
fn expected_toggles() -> Vec<(&'static str, &'static str, [Value; 4])> {
    let day = 86_400;
    let hour = 3_600;
    vec![
        (
            "TGL-01",
            "password_policy",
            [
                json!({"preset": "pin"}),
                json!({"preset": "standard"}),
                json!({"preset": "hardened"}),
                json!({"preset": "pin"}),
            ],
        ),
        (
            "TGL-02",
            "mfa",
            [
                json!("optional"),
                json!("administrators"),
                json!("everyone"),
                json!("optional"),
            ],
        ),
        (
            "TGL-03",
            "passkey_for_admins",
            [json!(false), json!(false), json!(true), json!(false)],
        ),
        (
            "TGL-04",
            "session",
            [
                json!({"absolute_secs": 30 * day, "idle_secs": 7 * day}),
                json!({"absolute_secs": 12 * hour, "idle_secs": hour}),
                json!({"absolute_secs": 8 * hour, "idle_secs": 15 * 60}),
                json!({"absolute_secs": 30 * day, "idle_secs": 7 * day}),
            ],
        ),
        (
            "TGL-05",
            "token_max_days",
            [json!(365), json!(90), json!(30), Value::Null],
        ),
        (
            "TGL-06",
            "breach_check",
            [
                json!("online"),
                json!("online"),
                json!("offline_preferred"),
                json!("off"),
            ],
        ),
        (
            "TGL-07",
            "lockout",
            [
                json!("progressive_delay"),
                json!("delay_then_temporary_lock"),
                json!("lock_until_unlock"),
                json!("off"),
            ],
        ),
        (
            "TGL-21",
            "audit_export",
            [
                json!("local"),
                json!("optional"),
                json!("required"),
                json!("local"),
            ],
        ),
        (
            "TGL-23",
            "updates",
            [
                json!({"check": true, "install": "ui"}),
                json!({"check": true, "install": "ui_step_up"}),
                json!({"check": true, "install": "upload_only"}),
                json!({"check": true, "install": "ui"}),
            ],
        ),
    ]
}

#[tokio::test]
async fn the_settings_view_reports_each_profile_as_the_matrix_says() {
    let expected = expected_toggles();
    for (index, profile) in [
        Profile::Home,
        Profile::Standard,
        Profile::Hardened,
        Profile::Lab,
    ]
    .into_iter()
    .enumerate()
    {
        let (env, _) = TestEnv::installed(profile).await;
        let view = env
            .service
            .security_settings(&env.public_ctx())
            .await
            .expect("view");
        assert_eq!(view.settings, profile.defaults());
        assert!(view.revision.is_some());
        assert!(!view.vault_has_operator_secrets);
        let ids: Vec<&str> = view
            .toggles
            .iter()
            .map(|toggle| toggle.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "TGL-01", "TGL-02", "TGL-03", "TGL-04", "TGL-05", "TGL-06", "TGL-07", "TGL-21",
                "TGL-23", "TGL-24"
            ]
        );
        for (toggle, (id, setting, values)) in view.toggles.iter().zip(&expected) {
            assert_eq!(&toggle.id, id);
            assert_eq!(&toggle.setting, setting);
            assert_eq!(toggle.value, values[index], "{profile:?} {id}");
            assert_eq!(toggle.profile_default, values[index], "{profile:?} {id}");
            assert!(!toggle.deviates, "{profile:?} {id}");
        }
        let weaker: Vec<&str> = view
            .toggles
            .iter()
            .filter(|toggle| toggle.weaker_than_home)
            .map(|toggle| toggle.id.as_str())
            .collect();
        if profile == Profile::Lab {
            assert_eq!(weaker, ["TGL-05", "TGL-06", "TGL-07"]);
        } else {
            assert!(weaker.is_empty(), "{profile:?}: {weaker:?}");
        }
        assert_eq!(view.banner.lab, profile == Profile::Lab, "{profile:?}");
        assert_eq!(
            view.banner.weaker_than_home,
            profile == Profile::Lab,
            "{profile:?}"
        );
        assert_eq!(view.banner.deviations, Vec::<String>::new());
    }
}

fn find<'a>(view: &'a SecuritySettingsView, id: &str) -> &'a tenko_auth::settings::ToggleState {
    view.toggles
        .iter()
        .find(|toggle| toggle.id == id)
        .expect("a toggle")
}

#[tokio::test]
async fn changed_toggles_deviate_and_weak_ones_raise_the_banner() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let view = env
        .service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                lockout: Some(LockoutMode::Off),
                session: Some(SessionLifetime {
                    absolute_secs: 90 * 86_400,
                    idle_secs: 7 * 86_400,
                }),
                token_max_lifetime: Some(TokenMaxLifetime::Days(30)),
                mfa: Some(MfaRequirement::Everyone),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    assert_eq!(view.settings.profile, Profile::Home);
    // Every change deviates from Home; only the weaker ones are warned about.
    for (id, weaker) in [
        ("TGL-02", false),
        ("TGL-04", true),
        ("TGL-05", false),
        ("TGL-07", true),
    ] {
        let toggle = find(&view, id);
        assert!(toggle.deviates, "{id}");
        assert_eq!(toggle.weaker_than_home, weaker, "{id}");
    }
    for id in ["TGL-01", "TGL-03", "TGL-06"] {
        assert!(!find(&view, id).deviates, "{id}");
    }
    assert_eq!(
        view.banner.deviations,
        ["TGL-02", "TGL-04", "TGL-05", "TGL-07"]
    );
    assert!(view.banner.weaker_than_home);
    assert!(!view.banner.lab);

    // The lax breached-password check warns as well.
    let view = env
        .service
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
    assert!(find(&view, "TGL-06").weaker_than_home);
    assert_eq!(find(&view, "TGL-06").value, json!("off"));
}

#[tokio::test]
async fn a_settings_change_writes_one_audit_record_with_each_changed_toggle() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let before = audit_records(&env).await.len();
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                lockout: Some(LockoutMode::Off),
                token_max_lifetime: Some(TokenMaxLifetime::Days(30)),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    let records = audit_records(&env).await;
    assert_eq!(records.len(), before + 1, "exactly one record");
    let record = records.last().expect("a record");
    assert_eq!(record.draft.action.as_str(), "auth.settings.update");
    assert_eq!(
        record.principal, admin.principal,
        "NEVER-03: the acting principal"
    );
    assert_eq!(
        record.draft.objects,
        [ObjectRef::singleton(ObjectKind::Settings)]
    );
    assert_eq!(record.draft.details.context["profile"], "home");
    let changes = changes_of(record);
    assert_eq!(
        changes.keys().map(String::as_str).collect::<Vec<_>>(),
        ["TGL-05", "TGL-07"]
    );
    assert_eq!(changes["TGL-05"], (json!(365), json!(30)));
    assert_eq!(
        changes["TGL-07"],
        (json!("progressive_delay"), json!("off"))
    );
}

#[tokio::test]
async fn switching_the_profile_records_the_profile_and_every_changed_toggle() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                profile: Some(Profile::Standard),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    let records = audit_of(&env, "auth.settings.update").await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].draft.details.context["profile"], "standard");
    let changes = changes_of(&records[0]);
    assert_eq!(changes["profile"], (json!("home"), json!("standard")));
    assert_eq!(
        changes["TGL-01"],
        (json!({"preset": "pin"}), json!({"preset": "standard"}))
    );
    assert_eq!(
        changes["TGL-02"],
        (json!("optional"), json!("administrators"))
    );
    assert_eq!(changes["TGL-05"], (json!(365), json!(90)));
    assert_eq!(changes["TGL-07"].1, json!("delay_then_temporary_lock"));
    // Toggles that kept their value are not listed.
    for unchanged in ["TGL-03", "TGL-06"] {
        assert!(!changes.contains_key(unchanged), "{unchanged}");
    }
    assert_eq!(env.service.settings().profile, Profile::Standard);
}

#[tokio::test]
async fn a_patch_that_changes_nothing_writes_nothing() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let before = env.service.security_settings(&admin).await.expect("view");
    let records = audit_records(&env).await.len();
    for patch in [
        SettingsPatch::default(),
        patch_lockout(LockoutMode::ProgressiveDelay),
        SettingsPatch {
            profile: Some(Profile::Home),
            ..SettingsPatch::default()
        },
    ] {
        let view = env
            .service
            .update_security_settings(&admin, &patch, before.revision)
            .await
            .expect("accepted");
        assert_eq!(view, before);
    }
    assert_eq!(audit_records(&env).await.len(), records);
}

#[tokio::test]
async fn a_settings_update_with_a_stale_revision_conflicts() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let first = env.service.security_settings(&admin).await.expect("view");
    let stale = first.revision.expect("a revision after setup");
    let changed = env
        .service
        .update_security_settings(&admin, &patch_lockout(LockoutMode::Off), Some(stale))
        .await
        .expect("current revision");
    let current = changed.revision.expect("a revision");
    assert_ne!(current, stale);

    for patch in [
        patch_lockout(LockoutMode::LockUntilUnlock),
        SettingsPatch::default(),
    ] {
        assert_eq!(
            env.service
                .update_security_settings(&admin, &patch, Some(stale))
                .await
                .expect_err("stale"),
            AuthError::Conflict
        );
    }
    assert_eq!(env.service.settings().lockout, LockoutMode::Off);
    env.service
        .update_security_settings(
            &admin,
            &patch_lockout(LockoutMode::LockUntilUnlock),
            Some(current),
        )
        .await
        .expect("current");
    assert_eq!(audit_of(&env, "auth.settings.update").await.len(), 2);
}

#[tokio::test]
async fn invalid_settings_are_refused_and_change_nothing() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let before = env.service.security_settings(&admin).await.expect("view");
    let session_patch = |absolute_secs, idle_secs| SettingsPatch {
        session: Some(SessionLifetime {
            absolute_secs,
            idle_secs,
        }),
        ..SettingsPatch::default()
    };
    let cases = [
        ("session", session_patch(0, 0)),
        ("session", session_patch(3_600, 0)),
        ("session", session_patch(600, 3_600)),
        (
            "token_max_days",
            SettingsPatch {
                token_max_lifetime: Some(TokenMaxLifetime::Days(0)),
                ..SettingsPatch::default()
            },
        ),
        (
            "password_policy",
            SettingsPatch {
                password_policy: Some(PasswordPolicy::Custom(CustomPolicy {
                    min_length: 3,
                    max_length: 64,
                    pattern: None,
                })),
                ..SettingsPatch::default()
            },
        ),
    ];
    for (field, patch) in cases {
        match env
            .service
            .update_security_settings(&admin, &patch, None)
            .await
        {
            Err(AuthError::Invalid { field: actual, .. }) => assert_eq!(actual, field),
            other => panic!("{field}: expected an invalid value, got {other:?}"),
        }
    }
    assert_eq!(
        env.service.security_settings(&admin).await.expect("view"),
        before
    );
    assert_eq!(audit_of(&env, "auth.settings.update").await, []);
    // Idle equal to absolute is the longest idle time that is allowed.
    env.service
        .update_security_settings(&admin, &session_patch(3_600, 3_600), None)
        .await
        .expect("equal lifetimes");
}

#[tokio::test]
async fn operators_cannot_change_settings() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    create(
        &env,
        &admin,
        &new_user("olga", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let operator = ctx(&env, &login(&env, "olga", "6402").await).await;
    assert_eq!(
        denied_reason(
            env.service
                .update_security_settings(&operator, &patch_lockout(LockoutMode::Off), None)
                .await
        ),
        DenyReason::MissingPermission
    );
    assert_eq!(
        env.service.settings().lockout,
        LockoutMode::ProgressiveDelay
    );
    assert_eq!(audit_of(&env, "auth.settings.update").await, []);
}

#[tokio::test]
async fn settings_are_unavailable_for_change_before_setup() {
    let env = TestEnv::new().await;
    let system = env.public_ctx();
    let view = env.service.security_settings(&system).await.expect("view");
    assert_eq!(view.revision, None);
    assert!(matches!(
        env.service
            .update_security_settings(&system, &patch_lockout(LockoutMode::Off), None)
            .await,
        Err(AuthError::Unavailable(_))
    ));
}

// ---------------------------------------------------------------------------------------
// IAM-07 in the settings
// ---------------------------------------------------------------------------------------

fn pin_with(mfa: MfaRequirement) -> SettingsPatch {
    SettingsPatch {
        password_policy: Some(PasswordPolicy::Pin),
        mfa: Some(mfa),
        ..SettingsPatch::default()
    }
}

#[tokio::test]
async fn the_pin_preset_with_optional_mfa_is_refused_while_an_operator_secret_exists() {
    let (env, strong) = standard_with_strong_admin().await;
    put_operator_secret(&env).await;
    let admin = ctx(&env, &strong).await;
    assert!(
        env.service
            .security_settings(&admin)
            .await
            .expect("view")
            .vault_has_operator_secrets
    );
    let before = env.service.settings();

    assert_eq!(
        env.service
            .update_security_settings(&admin, &pin_with(MfaRequirement::Optional), None)
            .await
            .expect_err("IAM-07"),
        AuthError::PinCoupling
    );
    // The profiles whose preset is a PIN with optional MFA are refused as well.
    for profile in [Profile::Home, Profile::Lab] {
        let patch = SettingsPatch {
            profile: Some(profile),
            ..SettingsPatch::default()
        };
        assert_eq!(
            env.service
                .update_security_settings(&admin, &patch, None)
                .await
                .expect_err("IAM-07"),
            AuthError::PinCoupling,
            "{profile:?}"
        );
    }
    assert_eq!(env.service.settings(), before);
    // Each refusal is audited as a failed change (refused guardrails are audited).
    let refused = audit_of(&env, "auth.settings.update").await;
    assert_eq!(refused.len(), 3);
    assert!(refused.iter().all(|record| {
        record.draft.outcome
            == AuditOutcome::Failed {
                code: "settings.pin_coupling".into(),
            }
    }));

    // The PIN as a second factor next to another one is allowed.
    let view = env
        .service
        .update_security_settings(&admin, &pin_with(MfaRequirement::Everyone), None)
        .await
        .expect("a PIN with two-factor login for everyone");
    assert_eq!(view.settings.password_policy, PasswordPolicy::Pin);
    assert_eq!(view.settings.mfa, MfaRequirement::Everyone);
    // ...and the coupling holds when MFA is relaxed again.
    assert_eq!(
        env.service
            .update_security_settings(
                &admin,
                &SettingsPatch {
                    mfa: Some(MfaRequirement::Optional),
                    ..SettingsPatch::default()
                },
                None,
            )
            .await
            .expect_err("IAM-07"),
        AuthError::PinCoupling
    );
    assert_eq!(env.service.settings().mfa, MfaRequirement::Everyone);
    let records = audit_of(&env, "auth.settings.update").await;
    let applied = records
        .iter()
        .filter(|record| record.draft.outcome == AuditOutcome::Success)
        .count();
    assert_eq!(applied, 1);
    assert_eq!(records.len(), 5, "three refusals, one change, one refusal");
}

#[tokio::test]
async fn the_pin_preset_with_optional_mfa_is_allowed_while_the_vault_has_no_operator_secret() {
    let (env, strong) = standard_with_strong_admin().await;
    // A system secret (the TOTP seed of the administrator) does not count (Q3).
    assert!(
        !env.service
            .security_settings(&ctx(&env, &strong).await)
            .await
            .expect("view")
            .vault_has_operator_secrets
    );
    let admin = ctx(&env, &strong).await;
    let view = env
        .service
        .update_security_settings(&admin, &pin_with(MfaRequirement::Optional), None)
        .await
        .expect("allowed without operator secrets");
    assert_eq!(view.settings.password_policy, PasswordPolicy::Pin);
    assert_eq!(view.settings.mfa, MfaRequirement::Optional);
}

#[tokio::test]
async fn a_passkey_session_keeps_its_rights_when_the_vault_gets_an_operator_secret() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let pin_admin = ctx(&env, &session).await;
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    register_passkey(&env, &pin_admin, &mut key)
        .await
        .expect("passkey");
    let passkey = passkey_login(&env, &mut key).await.expect("passkey login");
    assert_eq!(passkey.info.strength, AuthStrength::Passkey);
    put_operator_secret(&env).await;
    // The PIN session lost its administrative rights with the vault's first secret.
    assert_eq!(
        denied_reason(env.service.list_users(&pin_admin).await),
        DenyReason::StepUpRequired {
            required: AuthStrength::Password
        }
    );
    assert_eq!(
        denied_reason(
            env.service
                .update_security_settings(&pin_admin, &SettingsPatch::default(), None)
                .await
        ),
        DenyReason::StepUpRequired {
            required: AuthStrength::Password
        }
    );
    // The passkey session keeps them.
    let strong = ctx(&env, &passkey).await;
    env.service
        .list_users(&strong)
        .await
        .expect("a passkey suffices");
}

/// A Home or Lab installation (the PIN preset with optional MFA) and the context of a
/// passkey session of its administrator. A PIN session loses its administrative rights once
/// the vault holds an operator secret, and it would not serve after MFA is required for
/// everyone; a passkey session keeps its rights in both cases.
async fn pin_installation_with_a_passkey_session(profile: Profile) -> (TestEnv, RequestCtx) {
    let (env, setup) = TestEnv::installed(profile).await;
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    register_passkey(&env, &ctx(&env, &setup).await, &mut key)
        .await
        .expect("passkey");
    let passkey = passkey_login(&env, &mut key).await.expect("passkey login");
    let admin = ctx(&env, &passkey).await;
    (env, admin)
}

/// The same installation after its vault got an operator secret.
async fn pin_installation_with_an_operator_secret(profile: Profile) -> (TestEnv, RequestCtx) {
    let (env, admin) = pin_installation_with_a_passkey_session(profile).await;
    put_operator_secret(&env).await;
    assert!(
        env.service
            .security_settings(&admin)
            .await
            .expect("view")
            .vault_has_operator_secrets
    );
    (env, admin)
}

async fn change_settings(
    env: &TestEnv,
    admin: &RequestCtx,
    patch: &SettingsPatch,
) -> Result<SecuritySettingsView, AuthError> {
    env.service
        .update_security_settings(admin, patch, None)
        .await
}

/// The audit trail of the settings updates: the toggles each applied change touched, oldest
/// first, and the number of changes refused by the PIN coupling rule. Any other outcome
/// fails the test.
async fn settings_updates(env: &TestEnv) -> (Vec<Vec<String>>, usize) {
    let mut applied = Vec::new();
    let mut refused = 0;
    for record in audit_of(env, "auth.settings.update").await {
        match &record.draft.outcome {
            AuditOutcome::Success => applied.push(changes_of(&record).into_keys().collect()),
            AuditOutcome::Failed { code } if code == "settings.pin_coupling" => refused += 1,
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    (applied, refused)
}

fn pin_like_custom_preset() -> PasswordPolicy {
    PasswordPolicy::Custom(CustomPolicy {
        min_length: 4,
        max_length: 64,
        pattern: Some("\\d+".to_owned()),
    })
}

#[tokio::test]
async fn toggles_other_than_the_policy_and_mfa_change_freely_under_a_pin_profile_with_an_operator_secret()
 {
    // Home and Lab let a PIN stand alone already; the secret in the vault must not freeze
    // the toggles that have nothing to do with it.
    for profile in [Profile::Home, Profile::Lab] {
        let (env, admin) = pin_installation_with_an_operator_secret(profile).await;
        let initial = env.service.settings();
        let reveal = RevealPolicy::new(RevealStepUp::Fresh, false);

        let view = change_settings(
            &env,
            &admin,
            &SettingsPatch {
                secret_reveal: Some(reveal),
                ..SettingsPatch::default()
            },
        )
        .await
        .expect("TGL-24 is not held to the coupling rule");
        assert_eq!(view.settings.secret_reveal(), reveal, "{profile:?}");
        assert_eq!(env.service.settings().secret_reveal(), reveal);

        change_settings(&env, &admin, &patch_lockout(LockoutMode::LockUntilUnlock))
            .await
            .expect("TGL-07 is not held to the coupling rule");
        assert_eq!(env.service.settings().lockout, LockoutMode::LockUntilUnlock);

        // Sending the profile again resets the toggles, and leaves the policy and MFA alone.
        change_settings(
            &env,
            &admin,
            &SettingsPatch {
                profile: Some(profile),
                ..SettingsPatch::default()
            },
        )
        .await
        .expect("a profile switch that keeps the policy and MFA");
        assert_eq!(env.service.settings(), initial, "{profile:?}");

        let (applied, refused) = settings_updates(&env).await;
        assert_eq!(
            applied,
            [vec!["TGL-24"], vec!["TGL-07"], vec!["TGL-07", "TGL-24"]],
            "{profile:?}"
        );
        assert_eq!(refused, 0, "{profile:?}");
    }
}

#[tokio::test]
async fn mfa_for_everyone_passes_with_an_operator_secret_and_relaxing_it_again_is_refused() {
    let (env, admin) = pin_installation_with_an_operator_secret(Profile::Home).await;
    let view = change_settings(
        &env,
        &admin,
        &SettingsPatch {
            mfa: Some(MfaRequirement::Everyone),
            ..SettingsPatch::default()
        },
    )
    .await
    .expect("a PIN next to another factor");
    assert_eq!(view.settings.password_policy, PasswordPolicy::Pin);
    assert_eq!(view.settings.mfa, MfaRequirement::Everyone);

    // Relaxing MFA would let the PIN stand alone, and so would a switch to the profile.
    for patch in [
        SettingsPatch {
            mfa: Some(MfaRequirement::Optional),
            ..SettingsPatch::default()
        },
        SettingsPatch {
            profile: Some(Profile::Home),
            ..SettingsPatch::default()
        },
    ] {
        assert_eq!(
            change_settings(&env, &admin, &patch)
                .await
                .expect_err("IAM-07"),
            AuthError::PinCoupling,
            "{patch:?}"
        );
    }
    assert_eq!(env.service.settings(), view.settings);
    assert_eq!(env.service.settings().mfa, MfaRequirement::Everyone);
    let (applied, refused) = settings_updates(&env).await;
    assert_eq!(applied, [vec!["TGL-02"]]);
    assert_eq!(refused, 2);
}

#[tokio::test]
async fn a_preset_that_still_admits_a_pin_is_refused_with_an_operator_secret_and_the_standard_preset_passes()
 {
    let (env, admin) = pin_installation_with_an_operator_secret(Profile::Home).await;
    let custom = SettingsPatch {
        password_policy: Some(pin_like_custom_preset()),
        ..SettingsPatch::default()
    };
    // TGL-01 changes, and the result still lets a PIN stand alone.
    assert_eq!(
        change_settings(&env, &admin, &custom)
            .await
            .expect_err("IAM-07"),
        AuthError::PinCoupling
    );
    assert_eq!(env.service.settings().password_policy, PasswordPolicy::Pin);
    assert_eq!(settings_updates(&env).await, (Vec::<Vec<String>>::new(), 1));

    let view = change_settings(
        &env,
        &admin,
        &SettingsPatch {
            password_policy: Some(PasswordPolicy::Standard),
            ..SettingsPatch::default()
        },
    )
    .await
    .expect("a preset that admits no PIN");
    assert_eq!(view.settings.password_policy, PasswordPolicy::Standard);
    assert_eq!(view.settings.mfa, MfaRequirement::Optional);
    let (applied, refused) = settings_updates(&env).await;
    assert_eq!(applied, [vec!["TGL-01"]]);
    assert_eq!(refused, 1);
}

#[tokio::test]
async fn every_settings_change_passes_while_the_vault_has_no_operator_secret() {
    let (env, admin) = pin_installation_with_a_passkey_session(Profile::Home).await;
    assert!(
        !env.service
            .security_settings(&admin)
            .await
            .expect("view")
            .vault_has_operator_secrets
    );
    let patches = [
        SettingsPatch {
            secret_reveal: Some(RevealPolicy::new(RevealStepUp::Fresh, false)),
            ..SettingsPatch::default()
        },
        patch_lockout(LockoutMode::LockUntilUnlock),
        SettingsPatch {
            profile: Some(Profile::Home),
            ..SettingsPatch::default()
        },
        SettingsPatch {
            mfa: Some(MfaRequirement::Everyone),
            ..SettingsPatch::default()
        },
        // Relaxing MFA lets the PIN stand alone, which is allowed without a secret.
        SettingsPatch {
            mfa: Some(MfaRequirement::Optional),
            ..SettingsPatch::default()
        },
        SettingsPatch {
            password_policy: Some(pin_like_custom_preset()),
            ..SettingsPatch::default()
        },
        SettingsPatch {
            password_policy: Some(PasswordPolicy::Standard),
            ..SettingsPatch::default()
        },
        // From Standard to Home: the PIN preset with optional MFA.
        SettingsPatch {
            profile: Some(Profile::Home),
            ..SettingsPatch::default()
        },
    ];
    for (index, patch) in patches.iter().enumerate() {
        change_settings(&env, &admin, patch)
            .await
            .unwrap_or_else(|error| panic!("change {index} ({patch:?}): {error:?}"));
    }
    let (applied, refused) = settings_updates(&env).await;
    assert_eq!(applied.len(), patches.len());
    assert_eq!(refused, 0);
    assert_eq!(env.service.settings().profile, Profile::Home);
    assert_eq!(env.service.settings().password_policy, PasswordPolicy::Pin);
    assert_eq!(env.service.settings().mfa, MfaRequirement::Optional);
}

// ---------------------------------------------------------------------------------------
// Concurrent requests
// ---------------------------------------------------------------------------------------

/// A store that holds every proposal at a gate until two are waiting, so that two requests
/// read the same state before either of them writes. A request that is serialized behind
/// the other one never reaches the gate together with it, so the wait is bounded.
struct GatedStore {
    inner: Arc<MemStore>,
    gate: Barrier,
    armed: AtomicBool,
}

#[async_trait::async_trait]
impl Store for GatedStore {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        if self.armed.load(Ordering::SeqCst) {
            let _ = tokio::time::timeout(Duration::from_secs(1), self.gate.wait()).await;
        }
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// A Home installation over a [`GatedStore`] with two administrators, `admin` and `boris`.
struct Gated {
    service: Arc<AuthService>,
    store: Arc<GatedStore>,
    system: RequestCtx,
    admins: [UserInfo; 2],
}

/// A service over a [`GatedStore`] before setup, and the system context to call it with.
async fn gated_service() -> (Arc<AuthService>, Arc<GatedStore>, RequestCtx) {
    let mem = Arc::new(MemStore::default());
    let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(mem.clone()));
    let store = Arc::new(GatedStore {
        inner: mem,
        gate: Barrier::new(2),
        armed: AtomicBool::new(false),
    });
    let service = AuthService::new(store.clone(), vault, AuthConfig::default())
        .await
        .expect("the service starts");
    let system = RequestCtx::system(SystemComponent::Api).at(MockClock::fixed().now());
    (service, store, system)
}

fn home_setup(token: &str, admin: &str) -> SetupRequest {
    SetupRequest {
        setup_token: SecretString::new(token),
        profile: Profile::Home,
        admin: SetupAdmin {
            name: admin.to_owned(),
            display_name: None,
            password: SecretString::new(ADMIN_PIN),
        },
        host_name: "tenko.example.test".to_owned(),
        language: "en".to_owned(),
    }
}

async fn gated_installation() -> Gated {
    let (service, store, system) = gated_service().await;
    let token = service
        .prepare_setup()
        .await
        .expect("prepare")
        .expect("setup is open");
    service
        .complete_setup(&system, None, &home_setup(token.expose(), ADMIN))
        .await
        .expect("setup");
    let first = service
        .list_users(&system)
        .await
        .expect("list")
        .pop()
        .expect("the first administrator");
    let second = service
        .create_user(
            &system,
            &new_user("boris", &[RoleName::Admin], Some("6402")),
        )
        .await
        .expect("a second administrator");
    Gated {
        service,
        store,
        system,
        admins: [first, second],
    }
}

#[tokio::test]
async fn two_concurrent_setups_complete_exactly_once() {
    let (service, store, system) = gated_service().await;
    let token = service
        .prepare_setup()
        .await
        .expect("prepare")
        .expect("setup is open");
    let first = home_setup(token.expose(), "first");
    let second = home_setup(token.expose(), "second");
    store.armed.store(true, Ordering::SeqCst);
    let (a, b) = tokio::join!(
        service.complete_setup(&system, None, &first),
        service.complete_setup(&system, None, &second)
    );
    store.armed.store(false, Ordering::SeqCst);
    assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
    assert!(
        matches!(a, Err(AuthError::SetupClosed)) || matches!(b, Err(AuthError::SetupClosed)),
        "the loser is told that setup is closed"
    );
    let users = service.list_users(&system).await.expect("list");
    assert_eq!(users.len(), 1, "one installation, one first administrator");
    assert!(service.is_installed().await.expect("installed"));
}

#[derive(Clone, Copy, Debug)]
enum Removal {
    Demote,
    Disable,
    Delete,
}

/// Two concurrent requests that each remove one of the two administrators; returns how many
/// active administrators remain.
async fn remove_both_administrators_at_once(removal: Removal) -> usize {
    let gated = gated_installation().await;
    let remove = |id: UserId| {
        let service = gated.service.clone();
        let system = gated.system.clone();
        async move {
            match removal {
                Removal::Demote => service
                    .set_user_roles(&system, id, &[RoleName::Viewer], None)
                    .await
                    .map(|_| ()),
                Removal::Disable => service
                    .update_user(
                        &system,
                        id,
                        &UserUpdate {
                            disabled: Some(true),
                            ..UserUpdate::default()
                        },
                        None,
                    )
                    .await
                    .map(|_| ()),
                Removal::Delete => service.delete_user(&system, id).await,
            }
        }
    };
    gated.store.armed.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(remove(gated.admins[0].id), remove(gated.admins[1].id));
    gated.store.armed.store(false, Ordering::SeqCst);
    let removed = [first, second]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    assert!(removed >= 1, "{removal:?}: at least one request succeeds");
    gated
        .service
        .list_users(&gated.system)
        .await
        .expect("list")
        .iter()
        .filter(|user| user.roles.contains(&RoleName::Admin) && !user.disabled)
        .count()
}

#[tokio::test]
async fn concurrent_demotions_cannot_remove_the_last_administrator() {
    assert!(remove_both_administrators_at_once(Removal::Demote).await >= 1);
}

#[tokio::test]
async fn concurrent_disables_cannot_remove_the_last_administrator() {
    assert!(remove_both_administrators_at_once(Removal::Disable).await >= 1);
}

#[tokio::test]
async fn concurrent_deletions_cannot_remove_the_last_administrator() {
    assert!(remove_both_administrators_at_once(Removal::Delete).await >= 1);
}

#[tokio::test]
async fn concurrent_logins_of_one_account_both_succeed() {
    let gated = gated_installation().await;
    let login_admin = || {
        let service = gated.service.clone();
        let system = gated.system.clone();
        async move {
            service
                .login_password(
                    &system,
                    None,
                    &PasswordLogin {
                        user_name: ADMIN.to_owned(),
                        password: SecretString::new(ADMIN_PIN),
                    },
                )
                .await
        }
    };
    gated.store.armed.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(login_admin(), login_admin());
    gated.store.armed.store(false, Ordering::SeqCst);
    for outcome in [first, second] {
        assert!(
            matches!(outcome, Ok(LoginOutcome::Session(_))),
            "a concurrent login must not fail: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn concurrent_creations_of_one_name_yield_exactly_one_user() {
    let gated = gated_installation().await;
    let create_dora = || {
        let service = gated.service.clone();
        let system = gated.system.clone();
        async move {
            service
                .create_user(&system, &new_user("dora", &[RoleName::Viewer], None))
                .await
        }
    };
    gated.store.armed.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(create_dora(), create_dora());
    gated.store.armed.store(false, Ordering::SeqCst);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .any(|result| matches!(result, Err(AuthError::UserNameTaken)))
    );
    let dora = gated
        .service
        .list_users(&gated.system)
        .await
        .expect("list")
        .into_iter()
        .filter(|user| user.name == "dora")
        .count();
    assert_eq!(dora, 1);
}

#[tokio::test]
async fn concurrent_updates_with_the_same_revision_conflict() {
    let gated = gated_installation().await;
    let target = gated.admins[1].clone();
    let rename = |name: &'static str| {
        let service = gated.service.clone();
        let system = gated.system.clone();
        let (id, revision) = (target.id, target.revision);
        async move {
            service
                .update_user(
                    &system,
                    id,
                    &UserUpdate {
                        display_name: Some(name.to_owned()),
                        ..UserUpdate::default()
                    },
                    Some(revision),
                )
                .await
        }
    };
    gated.store.armed.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(rename("One"), rename("Two"));
    gated.store.armed.store(false, Ordering::SeqCst);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .any(|result| matches!(result, Err(AuthError::Conflict)))
    );
}

// ---------------------------------------------------------------------------------------
// Lockout per profile (IAM-05, TGL-07)
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_hardened_lock_waits_for_an_administrator_and_raises_an_alarm() {
    let (env, setup) = TestEnv::installed(Profile::Hardened).await;
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    register_passkey(&env, &ctx(&env, &setup).await, &mut key)
        .await
        .expect("passkey");
    let passkey = passkey_login(&env, &mut key).await.expect("passkey login");
    let lena = create(
        &env,
        &env.public_ctx(),
        &new_user("lena", &[RoleName::Viewer], Some(PASSPHRASE)),
    )
    .await;
    lock_account(&env, lena.id, "lena").await;

    let locked = env
        .service
        .get_user(&env.public_ctx(), lena.id)
        .await
        .expect("get")
        .lock
        .expect("a persisted lock");
    assert!(
        locked.until_unlock,
        "TGL-07 Hardened: an administrator unlocks"
    );
    assert_eq!(
        locked.until.saturating_since(locked.since),
        Duration::from_secs(30 * 60),
        "and the lock lifts by itself after the policy's duration"
    );
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let alarms = view
        .scan_typed(&ALARMS, KeyRange::all(), 100, false)
        .expect("alarms");
    assert!(
        alarms
            .iter()
            .any(|(_, alarm, _)| alarm.kind == AlarmKind::AccountLocked
                && alarm.user == Some(lena.id)),
        "the lock raises an alarm"
    );

    // The right password does not help, and waiting a while does not either.
    env.clock.advance(Duration::from_secs(10 * 60));
    assert!(matches!(
        password_login(&env, "lena", PASSPHRASE).await,
        Err(AuthError::Throttled { .. })
    ));
    let admin = ctx(&env, &passkey).await;
    env.service
        .unlock_user(&admin, lena.id)
        .await
        .expect("unlock");
    login(&env, "lena", PASSPHRASE).await;
}

#[tokio::test]
async fn progressive_delay_never_locks_an_account() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let dora = create(
        &env,
        &admin,
        &new_user("dora", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let mut delayed = 0;
    for _ in 0..25 {
        match password_login(&env, "dora", "5827").await {
            Err(AuthError::InvalidCredentials) => {}
            Err(AuthError::Throttled { retry_after }) => {
                delayed += 1;
                env.clock
                    .advance(Duration::from_secs(retry_after.expect("a delay")));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(delayed > 0, "delays start after the free attempts");
    assert_eq!(
        env.service
            .get_user(&admin, dora.id)
            .await
            .expect("get")
            .lock,
        None
    );
    env.clock.advance(Duration::from_secs(120));
    login(&env, "dora", "6402").await;
}

#[tokio::test]
async fn the_lab_profile_has_no_lockout_at_all() {
    let (env, session) = TestEnv::installed(Profile::Lab).await;
    let admin = ctx(&env, &session).await;
    create(
        &env,
        &admin,
        &new_user("dora", &[RoleName::Operator], Some("6402")),
    )
    .await;
    for _ in 0..40 {
        assert!(matches!(
            password_login(&env, "dora", "5827").await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    login(&env, "dora", "6402").await;
}

// ---------------------------------------------------------------------------------------
// Lifetimes that the calendar cannot hold
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_absurd_session_lifetime_is_refused_or_the_session_still_works() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let outcome = env
        .service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                session: Some(SessionLifetime {
                    absolute_secs: 1_000_000_000_000,
                    idle_secs: 1_000_000_000_000,
                }),
                ..SettingsPatch::default()
            },
            None,
        )
        .await;
    if outcome.is_err() {
        // Refusing an absurd lifetime is a correct way to keep the invariant.
        return;
    }
    let fresh = login(&env, ADMIN, ADMIN_PIN).await;
    env.service
        .authenticate_credentials(&credentials(&fresh), env.now())
        .await
        .expect("a session created under the accepted setting must work");
}

// ---------------------------------------------------------------------------------------
// Attribution (IAM-19, NEVER-02, NEVER-03)
// ---------------------------------------------------------------------------------------

/// Runs `action` and checks that it wrote an audit record with the `expected` action and
/// that every record it wrote names `actor` as the principal and succeeded.
async fn audited<T>(
    env: &TestEnv,
    actor: &Principal,
    expected: &str,
    action: impl Future<Output = T>,
) -> T {
    let before = audit_records(env).await.len();
    let output = action.await;
    let records = audit_records(env).await;
    let written = &records[before..];
    let names: Vec<&str> = written
        .iter()
        .map(|record| record.draft.action.as_str())
        .collect();
    assert!(names.contains(&expected), "{expected}: wrote {names:?}");
    for record in written {
        assert_eq!(&record.principal, actor, "{expected}: {names:?}");
        assert_eq!(record.draft.outcome, AuditOutcome::Success, "{expected}");
    }
    output
}

#[tokio::test]
async fn administrative_changes_are_audited_with_the_acting_administrator() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let actor = admin.principal.clone();
    let olga = audited(
        &env,
        &actor,
        "auth.user.create",
        env.service.create_user(
            &admin,
            &new_user("olga", &[RoleName::Operator], Some("6402")),
        ),
    )
    .await
    .expect("create");
    login(&env, "olga", "6402").await;
    audited(
        &env,
        &actor,
        "auth.user.update",
        env.service.update_user(
            &admin,
            olga.id,
            &UserUpdate {
                display_name: Some("Olga O.".to_owned()),
                ..UserUpdate::default()
            },
            None,
        ),
    )
    .await
    .expect("update");
    audited(
        &env,
        &actor,
        "auth.user.roles",
        env.service
            .set_user_roles(&admin, olga.id, &[RoleName::Viewer], None),
    )
    .await
    .expect("roles");
    audited(
        &env,
        &actor,
        "auth.session.revoke",
        env.service.revoke_user_sessions(&admin, olga.id),
    )
    .await
    .expect("revoke");
    audited(
        &env,
        &actor,
        "auth.settings.update",
        env.service
            .update_security_settings(&admin, &patch_lockout(LockoutMode::Off), None),
    )
    .await
    .expect("settings");
    audited(
        &env,
        &actor,
        "auth.user.delete",
        env.service.delete_user(&admin, olga.id),
    )
    .await
    .expect("delete");

    // Unlocking an account that is not locked changes nothing and records nothing.
    let before = audit_records(&env).await.len();
    env.service
        .unlock_user(&admin, admin.principal.user().expect("a user"))
        .await
        .expect("unlock");
    assert_eq!(audit_records(&env).await.len(), before);
}

#[tokio::test]
async fn self_service_changes_are_audited_with_the_acting_user() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let me = ctx(&env, &session).await;
    let actor = me.principal.clone();
    audited(
        &env,
        &actor,
        "auth.password.change",
        env.service
            .change_password(&me, &password_change(ADMIN_PIN, "9157")),
    )
    .await
    .expect("password");

    let start = env.service.totp_enrol_start(&me).await.expect("start");
    let seed = base32_decode(start.secret.expose()).expect("seed");
    let code = totp::code_at(&seed, &TotpParams::default(), unix_seconds(&env));
    audited(
        &env,
        &actor,
        "auth.totp.enrol",
        env.service.totp_enrol_finish(
            &me,
            &TotpEnrolFinish {
                enrolment_id: start.enrolment_id,
                code: SecretString::new(code.as_str()),
            },
        ),
    )
    .await
    .expect("enrol");
    audited(
        &env,
        &actor,
        "auth.recovery.regenerate",
        env.service.regenerate_recovery_codes(&me),
    )
    .await
    .expect("recovery codes");
    audited(
        &env,
        &actor,
        "auth.totp.remove",
        env.service.remove_totp(&me),
    )
    .await
    .expect("remove");

    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    audited(
        &env,
        &actor,
        "auth.webauthn.register",
        register_passkey(&env, &me, &mut key),
    )
    .await
    .expect("register");
    let credential = env.service.list_credentials(&me).await.expect("list")[0]
        .id
        .clone();
    audited(
        &env,
        &actor,
        "auth.webauthn.remove",
        env.service.delete_credential(&me, &credential),
    )
    .await
    .expect("delete credential");

    let created = audited(
        &env,
        &actor,
        "auth.token.create",
        env.service.create_token(
            &me,
            &TokenCreate {
                name: "audited".to_owned(),
                expires_in_days: None,
            },
        ),
    )
    .await
    .expect("token");
    audited(
        &env,
        &actor,
        "auth.token.revoke",
        env.service.revoke_token(&me, created.info.id),
    )
    .await
    .expect("revoke token");

    let other = login(&env, ADMIN, "9157").await;
    audited(
        &env,
        &actor,
        "auth.session.revoke",
        env.service.revoke_session(&me, other.info.session_id),
    )
    .await
    .expect("revoke session");
    audited(&env, &actor, "auth.logout", env.service.logout(&me))
        .await
        .expect("logout");
}

// ---------------------------------------------------------------------------------------
// Stable error codes (API-08)
// ---------------------------------------------------------------------------------------

fn assert_coded(error: &AuthError, code: &str, status: u16) {
    assert_eq!(error.code(), code, "{error}");
    assert_eq!(error.http_status(), status, "{error}");
}

#[tokio::test]
async fn refusals_carry_stable_codes_statuses_and_parameters() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let me = admin.principal.user().expect("a user");
    create(
        &env,
        &admin,
        &new_user("olga", &[RoleName::Operator], Some("6402")),
    )
    .await;
    let taken = env
        .service
        .create_user(&admin, &new_user("OLGA", &[RoleName::Viewer], None))
        .await
        .expect_err("taken");
    assert_coded(&taken, "users.name_taken", 409);

    let last = env
        .service
        .set_user_roles(&admin, me, &[RoleName::Viewer], None)
        .await
        .expect_err("last administrator");
    assert_coded(&last, "users.last_administrator", 409);

    let unknown = env
        .service
        .get_user(&admin, UserId::generate())
        .await
        .expect_err("unknown");
    assert_coded(&unknown, "users.not_found", 404);
    assert_eq!(unknown.params()["kind"], "user");

    let invalid = env
        .service
        .create_user(&admin, &new_user("two words", &[RoleName::Viewer], None))
        .await
        .expect_err("invalid");
    assert_coded(&invalid, "auth.invalid_request", 400);
    assert_eq!(invalid.params()["field"], "name");
    assert_eq!(invalid.field_errors()[0].field, "name");

    let weak = env
        .service
        .create_user(&admin, &new_user("pelle", &[RoleName::Viewer], Some("12")))
        .await
        .expect_err("weak");
    assert_coded(&weak, "auth.password.policy", 422);
    let codes: Vec<String> = weak
        .field_errors()
        .into_iter()
        .map(|error| error.code.into_owned())
        .collect();
    assert!(
        codes.contains(&"auth.password.too_short".to_owned()),
        "{codes:?}"
    );

    let lifetime = env
        .service
        .create_token(
            &admin,
            &TokenCreate {
                name: "long".to_owned(),
                expires_in_days: Some(366),
            },
        )
        .await
        .expect_err("above the maximum");
    assert_coded(&lifetime, "auth.token.lifetime_exceeded", 422);
    assert_eq!(lifetime.params()["max_days"], "365");

    let operator = ctx(&env, &login(&env, "olga", "6402").await).await;
    let forbidden = env
        .service
        .create_user(&operator, &new_user("eve", &[RoleName::Admin], None))
        .await
        .expect_err("forbidden");
    assert_coded(&forbidden, "auth.forbidden", 403);
    assert_eq!(forbidden.params()["kind"], "user");
    assert_eq!(forbidden.params()["action"], "administer");
}

#[tokio::test]
async fn a_stale_revision_and_an_unknown_account_have_their_own_codes() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(&env, &admin, &new_user("carl", &[RoleName::Viewer], None)).await;
    let stale = user.revision;
    let touched = env
        .service
        .update_user(
            &admin,
            user.id,
            &UserUpdate {
                display_name: Some("Carl".to_owned()),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("update");
    assert_ne!(touched.revision, stale);
    let conflict = env
        .service
        .update_user(&admin, user.id, &UserUpdate::default(), Some(stale))
        .await
        .expect_err("stale");
    assert_coded(&conflict, "auth.conflict", 409);

    // A principal the index does not know is unauthenticated, not forbidden.
    let ghost = RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::HardwareKey,
    })
    .at(env.now());
    let unauthenticated = env
        .service
        .list_users(&ghost)
        .await
        .expect_err("an unknown user");
    assert_coded(&unauthenticated, "auth.unauthenticated", 401);
}

// ---------------------------------------------------------------------------------------
// Expired sessions
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn expired_sessions_are_neither_listed_nor_counted() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = ctx(&env, &session).await;
    let user = create(
        &env,
        &admin,
        &new_user("dora", &[RoleName::Operator], Some("6402")),
    )
    .await;
    login(&env, "dora", "6402").await;
    // Home lets a session idle for seven days; nobody presents the forgotten one again, so
    // nothing deletes it. The administrator keeps working in between.
    env.clock.advance(Duration::from_secs(6 * 86_400));
    ctx(&env, &session).await;
    env.clock.advance(Duration::from_secs(2 * 86_400));
    let again = login(&env, "dora", "6402").await;
    let listed = env
        .service
        .list_sessions(&ctx(&env, &again).await)
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "only the live session is listed: {listed:?}"
    );
    assert_eq!(
        env.service
            .revoke_user_sessions(&ctx(&env, &session).await, user.id)
            .await
            .expect("revoke"),
        1
    );
}
