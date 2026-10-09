//! Personal API tokens (IAM-10, TGL-05): default and maximum lifetime per profile, how a
//! token authenticates, expiry, revocation, and the rule that only an interactive session
//! that meets the profile may create one.

use std::{collections::BTreeSet, time::Duration};

use tenko_auth::{
    AuthError, LoginOutcome, NewSession,
    encoding::base32_decode,
    model::{TOKENS, USER_TOKENS},
    roles::RoleName,
    secret::{TOKEN_PREFIX, hash_secret},
    service::{
        CodeLogin, CreatedToken, PasswordChange, PasswordLogin, TokenCreate, TotpEnrolFinish,
        UserCreate, UserInfo, UserUpdate, WebAuthnLoginFinish, WebAuthnLoginStart,
        WebAuthnRegisterFinish, WebAuthnRegisterStart, types::SecretString,
    },
    settings::{Profile, SettingsPatch, TokenMaxLifetime},
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ORIGIN},
    },
    totp::{self, TotpParams},
};
use tenko_core::{
    Action, ApiTokenId, AuthStrength, Credentials, DenyReason, ObjectKind, ObjectRef, Principal,
    RequestCtx, audit::AuditRecord,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};

const PASSPHRASE: &str = "marble comet violin saffron";
const PIN: &str = "7391";
const DAY: u64 = 86_400;

fn password_for(profile: Profile) -> &'static str {
    if profile.defaults().password_policy.is_pin() {
        PIN
    } else {
        PASSPHRASE
    }
}

fn bearer(created: &CreatedToken) -> Credentials {
    Credentials::Bearer(created.token.expose().to_owned())
}

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

/// Creates a user as the system, which passes every authorization check.
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

/// Enrols TOTP for the session's user and returns the seed.
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

/// Logs in with the password and a TOTP code of a later time step.
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

/// A session that meets the profile's requirement for a non-administrator: a password
/// session where that suffices, otherwise one that used TOTP as well.
async fn strong_session(env: &TestEnv, user: &str, password: &str) -> NewSession {
    let first = expect_session(password_login(env, user, password).await.expect("login"));
    if !first.info.flags.mfa_enrolment_required {
        return first;
    }
    let ctx = env.session_ctx(&first).await.expect("ctx");
    let seed = enrol_totp(env, &ctx).await;
    totp_login(env, user, password, &seed).await
}

/// An installation under `profile` and a session of a user that may create tokens.
async fn token_env(profile: Profile) -> (TestEnv, NewSession) {
    let (env, _) = TestEnv::installed(profile).await;
    add_user(&env, "tina", RoleName::Operator, password_for(profile)).await;
    let session = strong_session(&env, "tina", password_for(profile)).await;
    (env, session)
}

async fn make_token(
    env: &TestEnv,
    session: &NewSession,
    name: &str,
    days: Option<u32>,
) -> Result<CreatedToken, AuthError> {
    let ctx = env.session_ctx(session).await.expect("ctx");
    env.service
        .create_token(
            &ctx,
            &TokenCreate {
                name: name.to_owned(),
                expires_in_days: days,
            },
        )
        .await
}

async fn set_disabled(env: &TestEnv, admin: &RequestCtx, id: tenko_core::UserId, disabled: bool) {
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
        .expect("the account is updated");
}

fn after(env: &TestEnv, days: u32) -> Option<tenko_core::Timestamp> {
    env.now()
        .checked_add(Duration::from_secs(u64::from(days) * DAY))
}

async fn audit_records(env: &TestEnv) -> Vec<AuditRecord> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

async fn register(
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
    user_name: &str,
) -> Result<NewSession, AuthError> {
    let options = env
        .service
        .webauthn_login_start(
            &env.public_ctx(),
            &WebAuthnLoginStart {
                user_name: Some(user_name.to_owned()),
                challenge_id: None,
            },
        )
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

fn prefix_object() -> ObjectRef {
    ObjectRef::singleton(ObjectKind::Prefix)
}

// ---------------------------------------------------------------------------------------
// Lifetime (TGL-05)
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_default_expiry_is_the_profile_maximum() {
    let cases = [
        (Profile::Home, Some(365)),
        (Profile::Standard, Some(90)),
        (Profile::Hardened, Some(30)),
        (Profile::Lab, None),
    ];
    for (profile, maximum) in cases {
        let (env, session) = token_env(profile).await;
        let created = make_token(&env, &session, "ci", None)
            .await
            .expect("a token with the default lifetime");
        let expected = maximum.map(|days| after(&env, days).expect("in range"));
        assert_eq!(created.info.expires_at, expected, "{profile:?}");
        assert_eq!(created.info.created_at, env.now(), "{profile:?}");
        assert_eq!(created.info.name, "ci");
    }
}

#[tokio::test]
async fn more_than_the_maximum_is_refused_and_the_maximum_itself_is_allowed() {
    let cases = [
        (Profile::Home, 365_u32),
        (Profile::Standard, 90),
        (Profile::Hardened, 30),
    ];
    for (profile, maximum) in cases {
        let (env, session) = token_env(profile).await;
        for requested in [maximum + 1, maximum * 2, u32::MAX] {
            assert_eq!(
                make_token(&env, &session, "too long", Some(requested))
                    .await
                    .expect_err("above the maximum"),
                AuthError::TokenLifetime {
                    max_days: u64::from(maximum)
                },
                "{profile:?} {requested}"
            );
        }
        let at_maximum = make_token(&env, &session, "edge", Some(maximum))
            .await
            .expect("the maximum itself");
        assert_eq!(
            at_maximum.info.expires_at,
            after(&env, maximum),
            "{profile:?}"
        );
        let short = make_token(&env, &session, "short", Some(1))
            .await
            .expect("a shorter lifetime");
        assert_eq!(short.info.expires_at, after(&env, 1), "{profile:?}");
        // Refused requests created nothing.
        let ctx = env.session_ctx(&session).await.expect("ctx");
        assert_eq!(env.service.list_tokens(&ctx).await.expect("list").len(), 2);
    }
}

#[tokio::test]
async fn lab_allows_any_lifetime_and_tokens_without_expiry() {
    let (env, session) = token_env(Profile::Lab).await;
    let long = make_token(&env, &session, "long", Some(36_500))
        .await
        .expect("a 100 year lifetime");
    assert_eq!(long.info.expires_at, after(&env, 36_500));
    let forever = make_token(&env, &session, "forever", None)
        .await
        .expect("no maximum");
    assert_eq!(forever.info.expires_at, None);
    // A token without expiry keeps working.
    env.clock.advance(Duration::from_secs(3_650 * DAY));
    env.service
        .authenticate_credentials(&bearer(&forever), env.now())
        .await
        .expect("still valid after ten years");
}

#[tokio::test]
async fn zero_days_is_invalid_in_every_profile() {
    for profile in Profile::ALL {
        let (env, session) = token_env(profile).await;
        match make_token(&env, &session, "zero", Some(0)).await {
            Err(AuthError::Invalid {
                field: "expires_in_days",
                ..
            }) => {}
            other => panic!("{profile:?}: expected an invalid lifetime, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_changed_maximum_applies_to_the_next_token() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                token_max_lifetime: Some(TokenMaxLifetime::Days(7)),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    assert_eq!(
        make_token(&env, &admin_session, "week", Some(8))
            .await
            .expect_err("above the new maximum"),
        AuthError::TokenLifetime { max_days: 7 }
    );
    let default = make_token(&env, &admin_session, "default", None)
        .await
        .expect("token");
    assert_eq!(default.info.expires_at, after(&env, 7));
    // Unlimited removes the maximum.
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                token_max_lifetime: Some(TokenMaxLifetime::Unlimited),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    let forever = make_token(&env, &admin_session, "forever", None)
        .await
        .expect("token");
    assert_eq!(forever.info.expires_at, None);
}

// ---------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_token_authenticates_as_a_token_principal_with_the_owners_roles() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let viewer = add_user(&env, "vera", RoleName::Viewer, PIN).await;
    let session = expect_session(password_login(&env, "vera", PIN).await.expect("login"));
    let created = make_token(&env, &session, "reader", None)
        .await
        .expect("token");
    assert!(created.token.expose().starts_with(TOKEN_PREFIX));

    let authenticated = env
        .service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("the token authenticates");
    assert_eq!(
        authenticated.principal,
        Principal::Token {
            id: created.info.id,
            owner: viewer.id
        }
    );
    assert_eq!(authenticated.user, Some(viewer.id));
    assert_eq!(authenticated.roles, BTreeSet::from(["viewer".to_owned()]));
    assert_eq!(authenticated.expires_at, created.info.expires_at);
    assert_eq!(authenticated.strength, session.info.strength);

    let authorizer = env.service.authorizer();
    assert!(
        authorizer
            .check(&authenticated.principal, Action::Read, &prefix_object())
            .is_ok()
    );
    let denied = authorizer
        .check(&authenticated.principal, Action::Update, &prefix_object())
        .expect_err("a viewer's token cannot write");
    assert_eq!(denied.reason, DenyReason::MissingPermission);

    // Roles are the owner's current roles, not a copy taken at creation.
    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    env.service
        .set_user_roles(&admin, viewer.id, &[RoleName::Operator], None)
        .await
        .expect("promote");
    let promoted = env
        .service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("the token authenticates");
    assert_eq!(promoted.roles, BTreeSet::from(["operator".to_owned()]));
    assert!(
        authorizer
            .check(&promoted.principal, Action::Update, &prefix_object())
            .is_ok()
    );
}

#[tokio::test]
async fn unknown_and_malformed_tokens_are_refused() {
    let (env, session) = token_env(Profile::Home).await;
    let created = make_token(&env, &session, "real", None)
        .await
        .expect("token");
    let real = created.token.expose().to_owned();
    let mut flipped = real.clone();
    flipped.pop();
    flipped.push(if real.ends_with('A') { 'B' } else { 'A' });
    let long = format!("{TOKEN_PREFIX}{}", "x".repeat(200));
    for presented in [
        flipped.as_str(),
        "",
        "tnk_",
        "not-a-token",
        real.trim_start_matches(TOKEN_PREFIX),
        long.as_str(),
    ] {
        assert!(
            matches!(
                env.service
                    .authenticate_credentials(&Credentials::Bearer(presented.to_owned()), env.now())
                    .await,
                Err(AuthError::Unauthenticated)
            ),
            "{presented:?}"
        );
    }
    // A token is not a session cookie, nor the other way round.
    assert!(
        env.service
            .authenticate_credentials(&Credentials::Session(real), env.now())
            .await
            .is_err()
    );
    assert!(
        env.service
            .authenticate_credentials(
                &Credentials::Bearer(session.secret.expose().to_owned()),
                env.now()
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_token_expires_exactly_at_its_expiry() {
    let (env, session) = token_env(Profile::Home).await;
    let default = make_token(&env, &session, "year", None)
        .await
        .expect("token");
    let one_day = make_token(&env, &session, "day", Some(1))
        .await
        .expect("token");
    let expiry = default.info.expires_at.expect("a default expiry");
    assert_eq!(Some(expiry), after(&env, 365));

    // The one-day token is valid until the last nanosecond before its expiry.
    env.clock
        .advance(Duration::from_nanos(DAY * 1_000_000_000 - 1));
    env.service
        .authenticate_credentials(&bearer(&one_day), env.now())
        .await
        .expect("valid one nanosecond before the expiry");
    env.clock.advance(Duration::from_nanos(1));
    assert_eq!(Some(env.now()), one_day.info.expires_at);
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&one_day), env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));

    // The year token is unaffected until its own end.
    env.clock.advance(Duration::from_secs(364 * DAY - 1));
    env.service
        .authenticate_credentials(&bearer(&default), env.now())
        .await
        .expect("valid one second before the expiry");
    env.clock.advance(Duration::from_secs(1));
    assert_eq!(env.now(), expiry);
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&default), env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));
    // Nothing brings an expired token back.
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&default), env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));
}

#[tokio::test]
async fn the_last_use_is_recorded_at_most_once_an_hour() {
    let (env, session) = token_env(Profile::Home).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let created = make_token(&env, &session, "poller", None)
        .await
        .expect("token");
    assert_eq!(created.info.last_used_at, None);
    let first_use = env.now();
    env.service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("first use");
    let listed = env.service.list_tokens(&ctx).await.expect("list");
    assert_eq!(listed[0].last_used_at, Some(first_use));

    env.clock.advance(Duration::from_secs(59 * 60));
    env.service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("second use");
    let listed = env.service.list_tokens(&ctx).await.expect("list");
    assert_eq!(
        listed[0].last_used_at,
        Some(first_use),
        "no write within the hour"
    );

    env.clock.advance(Duration::from_secs(2 * 60));
    env.service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("third use");
    let listed = env.service.list_tokens(&ctx).await.expect("list");
    assert_eq!(listed[0].last_used_at, Some(env.now()));
}

#[tokio::test]
async fn the_token_of_a_disabled_owner_is_refused() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let owner = add_user(&env, "olga", RoleName::Operator, PIN).await;
    let session = expect_session(password_login(&env, "olga", PIN).await.expect("login"));
    let created = make_token(&env, &session, "job", None)
        .await
        .expect("token");
    let principal = env
        .service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("works while the owner is enabled")
        .principal;

    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    env.service
        .update_user(
            &admin,
            owner.id,
            &UserUpdate {
                disabled: Some(true),
                ..UserUpdate::default()
            },
            None,
        )
        .await
        .expect("disable");
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&created), env.now())
            .await,
        Err(AuthError::Unauthenticated)
    ));
    let denied = env
        .service
        .authorizer()
        .check(&principal, Action::Read, &prefix_object())
        .expect_err("the authorizer refuses a disabled owner's token");
    assert_eq!(denied.reason, DenyReason::Unauthenticated);
}

#[tokio::test]
async fn a_token_stays_revoked_when_its_owner_is_enabled_again() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let owner = add_user(&env, "olga", RoleName::Operator, PIN).await;
    let session = expect_session(password_login(&env, "olga", PIN).await.expect("login"));
    let created = make_token(&env, &session, "job", None)
        .await
        .expect("token");
    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    set_disabled(&env, &admin, owner.id, true).await;
    assert!(
        env.service
            .authenticate_credentials(&bearer(&created), env.now())
            .await
            .is_err()
    );
    set_disabled(&env, &admin, owner.id, false).await;
    // The session did not come back, and neither may the token that was issued before.
    assert!(
        env.service
            .authenticate_credentials(&bearer(&created), env.now())
            .await
            .is_err(),
        "a token issued before the account was disabled works again"
    );
}

// ---------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_revoked_token_is_refused_and_the_others_keep_working() {
    let (env, session) = token_env(Profile::Home).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let first = make_token(&env, &session, "first", None)
        .await
        .expect("token");
    let second = make_token(&env, &session, "second", None)
        .await
        .expect("token");
    env.service
        .revoke_token(&ctx, first.info.id)
        .await
        .expect("revoke");
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&first), env.now())
            .await,
        Err(AuthError::Unauthenticated)
    ));
    env.service
        .authenticate_credentials(&bearer(&second), env.now())
        .await
        .expect("the other token still works");
    let listed = env.service.list_tokens(&ctx).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, second.info.id);
    // Revoking twice, or an id that never existed, finds nothing.
    for id in [first.info.id, ApiTokenId::generate()] {
        assert_eq!(
            env.service
                .revoke_token(&ctx, id)
                .await
                .expect_err("nothing to revoke"),
            AuthError::NotFound { kind: "token" }
        );
    }
    let revoked = audit_records(&env)
        .await
        .into_iter()
        .filter(|record| record.draft.action.as_str() == "auth.token.revoke")
        .count();
    assert_eq!(revoked, 1);
}

#[tokio::test]
async fn an_administrator_revokes_another_users_token_but_a_non_administrator_cannot() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let viewer = add_user(&env, "vera", RoleName::Viewer, PIN).await;
    add_user(&env, "olga", RoleName::Operator, PIN).await;
    let viewer_session = expect_session(password_login(&env, "vera", PIN).await.expect("login"));
    let operator_session = expect_session(password_login(&env, "olga", PIN).await.expect("login"));
    let created = make_token(&env, &viewer_session, "reader", None)
        .await
        .expect("token");

    // An operator sees nothing to revoke: the token is not theirs and they do not administer.
    let operator = env.session_ctx(&operator_session).await.expect("ctx");
    assert_eq!(
        env.service
            .revoke_token(&operator, created.info.id)
            .await
            .expect_err("not allowed"),
        AuthError::NotFound { kind: "token" }
    );
    env.service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("the token survived");

    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    env.service
        .revoke_token(&admin, created.info.id)
        .await
        .expect("an administrator revokes it");
    assert!(
        env.service
            .authenticate_credentials(&bearer(&created), env.now())
            .await
            .is_err()
    );
    let viewer_ctx = env.session_ctx(&viewer_session).await.expect("ctx");
    let remaining = env.service.list_tokens(&viewer_ctx).await.expect("list");
    assert_eq!(remaining, []);

    // The record names the administrator as the actor and the owner as the object.
    let records = audit_records(&env).await;
    let record = records
        .iter()
        .find(|record| record.draft.action.as_str() == "auth.token.revoke")
        .expect("an audit record");
    assert_eq!(record.principal, admin.principal);
    assert!(record.draft.objects.contains(&ObjectRef::from(viewer.id)));
    assert!(
        record
            .draft
            .objects
            .contains(&ObjectRef::from(created.info.id))
    );
}

#[tokio::test]
async fn an_owner_revokes_their_own_token() {
    let (env, _) = TestEnv::installed(Profile::Home).await;
    add_user(&env, "olga", RoleName::Operator, PIN).await;
    let session = expect_session(password_login(&env, "olga", PIN).await.expect("login"));
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let created = make_token(&env, &session, "mine", None)
        .await
        .expect("token");
    env.service
        .revoke_token(&ctx, created.info.id)
        .await
        .expect("revoke");
    assert!(
        env.service
            .authenticate_credentials(&bearer(&created), env.now())
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------------------
// Who may create a token
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_token_cannot_create_tokens_or_change_the_account() {
    let (env, session) = token_env(Profile::Home).await;
    let created = make_token(&env, &session, "bot", None)
        .await
        .expect("token");
    let ctx = env
        .ctx_for(&bearer(&created))
        .await
        .expect("a context for the token");
    assert!(matches!(ctx.principal, Principal::Token { .. }));
    assert!(matches!(
        env.service
            .create_token(
                &ctx,
                &TokenCreate {
                    name: "offspring".to_owned(),
                    expires_in_days: None,
                },
            )
            .await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service.regenerate_recovery_codes(&ctx).await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service.remove_totp(&ctx).await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service.totp_enrol_start(&ctx).await,
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        env.service
            .change_password(
                &ctx,
                &PasswordChange {
                    current_password: Some(SecretString::new(PIN)),
                    new_password: SecretString::new("5820"),
                },
            )
            .await,
        Err(AuthError::Unauthenticated)
    ));
    // Nothing was created behind the refusals.
    let owner_ctx = env.session_ctx(&session).await.expect("ctx");
    assert_eq!(
        env.service
            .list_tokens(&owner_ctx)
            .await
            .expect("list")
            .len(),
        1
    );
}

#[tokio::test]
async fn a_token_cannot_end_the_owners_sessions() {
    let (env, session) = token_env(Profile::Home).await;
    let created = make_token(&env, &session, "bot", None)
        .await
        .expect("token");
    let token_ctx = env.ctx_for(&bearer(&created)).await.expect("ctx");
    let result = env
        .service
        .revoke_session(&token_ctx, session.info.session_id)
        .await;
    assert!(
        result.is_err(),
        "a bearer token ended an interactive session of its owner"
    );
    env.service
        .authenticate_credentials(
            &Credentials::Session(session.secret.expose().to_owned()),
            env.now(),
        )
        .await
        .expect("the session survives");
}

#[tokio::test]
async fn a_token_cannot_revoke_the_owners_other_tokens() {
    let (env, session) = token_env(Profile::Home).await;
    let acting = make_token(&env, &session, "acting", None)
        .await
        .expect("token");
    let victim = make_token(&env, &session, "victim", None)
        .await
        .expect("token");
    let token_ctx = env.ctx_for(&bearer(&acting)).await.expect("ctx");
    let result = env.service.revoke_token(&token_ctx, victim.info.id).await;
    assert!(
        result.is_err(),
        "a bearer token revoked another token of its owner"
    );
    env.service
        .authenticate_credentials(&bearer(&victim), env.now())
        .await
        .expect("the other token still works");
}

#[tokio::test]
async fn a_token_may_revoke_itself() {
    let (env, session) = token_env(Profile::Home).await;
    let acting = make_token(&env, &session, "acting", None)
        .await
        .expect("token");
    let token_ctx = env.ctx_for(&bearer(&acting)).await.expect("ctx");
    env.service
        .revoke_token(&token_ctx, acting.info.id)
        .await
        .expect("a client may log itself out");
    assert!(matches!(
        env.service
            .authenticate_credentials(&bearer(&acting), env.now())
            .await,
        Err(AuthError::Unauthenticated)
    ));
}

#[tokio::test]
async fn a_session_below_the_required_strength_cannot_create_a_token() {
    // Standard: administrators need two factors; the setup session has a password only.
    let (env, admin_session) = TestEnv::installed(Profile::Standard).await;
    assert_eq!(
        make_token(&env, &admin_session, "admin token", None)
            .await
            .expect_err("a password session is not enough"),
        AuthError::StepUpRequired {
            required: "password_totp"
        }
    );
    let ctx = env.session_ctx(&admin_session).await.expect("ctx");
    let seed = enrol_totp(&env, &ctx).await;
    let strong = totp_login(&env, ADMIN, ADMIN_PASSWORD, &seed).await;
    assert_eq!(strong.info.strength, AuthStrength::PasswordTotp);
    let created = make_token(&env, &strong, "admin token", None)
        .await
        .expect("a two-factor session may create a token");
    assert_eq!(created.info.expires_at, after(&env, 90));
    // A viewer needs nothing beyond the password under Standard.
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    let viewer = expect_session(
        password_login(&env, "vera", PASSPHRASE)
            .await
            .expect("login"),
    );
    make_token(&env, &viewer, "viewer token", None)
        .await
        .expect("a password session suffices for a viewer");
}

#[tokio::test]
async fn hardened_needs_a_passkey_for_administrators_and_two_factors_for_everyone_else() {
    let (env, admin_session) = TestEnv::installed(Profile::Hardened).await;
    assert_eq!(
        make_token(&env, &admin_session, "admin token", None)
            .await
            .expect_err("a password session is not enough"),
        AuthError::StepUpRequired {
            required: "passkey"
        }
    );
    add_user(&env, "vera", RoleName::Viewer, PASSPHRASE).await;
    let viewer_password = expect_session(
        password_login(&env, "vera", PASSPHRASE)
            .await
            .expect("login"),
    );
    assert_eq!(
        make_token(&env, &viewer_password, "viewer token", None)
            .await
            .expect_err("a password session is not enough"),
        AuthError::StepUpRequired {
            required: "password_totp"
        }
    );

    // With a passkey session the administrator may create one, capped at 30 days.
    let ctx = env.session_ctx(&admin_session).await.expect("ctx");
    let mut key = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
    register(&env, &ctx, &mut key).await.expect("register");
    let passkey = passkey_login(&env, &mut key, ADMIN)
        .await
        .expect("passkey login");
    assert_eq!(passkey.info.strength, AuthStrength::Passkey);
    let created = make_token(&env, &passkey, "admin token", None)
        .await
        .expect("a passkey session may create a token");
    assert_eq!(created.info.expires_at, after(&env, 30));
    assert!(matches!(
        make_token(&env, &passkey, "too long", Some(31)).await,
        Err(AuthError::TokenLifetime { max_days: 30 })
    ));
}

#[tokio::test]
async fn an_operator_secret_in_the_vault_raises_the_bar_for_a_pin_session() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    make_token(&env, &session, "before", None)
        .await
        .expect("a PIN session may create a token while the vault holds no operator secret");
    env.vault
        .put_operator(
            &env.public_ctx(),
            SecretSpec::new(SecretPurpose::from_static("connect.test")),
            SecretBytes::from(b"fake".to_vec()),
        )
        .await
        .expect("an operator secret");
    assert_eq!(
        make_token(&env, &session, "after", None)
            .await
            .expect_err("IAM-07"),
        AuthError::StepUpRequired {
            required: "password"
        }
    );
    // Accounts that cannot reach the vault are not affected.
    add_user(&env, "vera", RoleName::Viewer, PIN).await;
    let viewer = expect_session(password_login(&env, "vera", PIN).await.expect("login"));
    make_token(&env, &viewer, "viewer token", None)
        .await
        .expect("a PIN session may still create a viewer's token");
}

#[tokio::test]
async fn token_names_must_be_visible_text() {
    let (env, session) = token_env(Profile::Home).await;
    for name in ["", "   ", "line\nbreak"] {
        assert!(
            matches!(
                make_token(&env, &session, name, None).await,
                Err(AuthError::Invalid { .. })
            ),
            "{name:?}"
        );
    }
    let padded = make_token(&env, &session, "  nightly  ", None)
        .await
        .expect("a padded name");
    assert_eq!(padded.info.name, "nightly");
}

#[tokio::test]
async fn an_invalid_token_name_is_reported_for_the_name_field() {
    let (env, session) = token_env(Profile::Home).await;
    match make_token(&env, &session, "", None).await {
        Err(AuthError::Invalid { field, .. }) => assert_eq!(field, "name"),
        other => panic!("expected an invalid name, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_token_secret_is_stored_only_as_its_hash() {
    let (env, session) = token_env(Profile::Home).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let created = make_token(&env, &session, "stored", None)
        .await
        .expect("token");
    env.service
        .authenticate_credentials(&bearer(&created), env.now())
        .await
        .expect("first use writes the last-use time");
    let secret = created.token.expose().to_owned();
    let hash = hash_secret(&secret);

    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let rows = view
        .scan_typed(&TOKENS, KeyRange::all(), 100, false)
        .expect("tokens");
    assert_eq!(rows.len(), 1);
    let (key, record, _) = &rows[0];
    assert_eq!(key, &hash, "the row is keyed by SHA-256 of the token");
    assert!(
        !serde_json::to_string(record)
            .expect("json")
            .contains(&secret),
        "the record holds no token"
    );
    assert_eq!(record.prefix, created.info.prefix);
    assert!(secret.starts_with(&record.prefix));
    assert!(record.prefix.len() < secret.len(), "only a prefix is kept");
    let owner = ctx.principal.user().expect("a user");
    let index = view
        .scan_typed(&USER_TOKENS, KeyRange::all(), 100, false)
        .expect("index");
    assert_eq!(index.len(), 1);
    assert_eq!(index[0].0, (owner, record.id));
    assert_eq!(index[0].1, hash);

    for audit in audit_records(&env).await {
        let json = serde_json::to_string(&audit).expect("json");
        assert!(!json.contains(&secret), "audit record {}", audit.seq);
    }
    let created_records: Vec<_> = audit_records(&env)
        .await
        .into_iter()
        .filter(|record| record.draft.action.as_str() == "auth.token.create")
        .collect();
    assert_eq!(created_records.len(), 1);
    assert_eq!(
        created_records[0]
            .draft
            .details
            .context
            .get("name")
            .map(String::as_str),
        Some("stored")
    );
}

#[tokio::test]
async fn tokens_are_listed_per_owner_only() {
    let (env, _) = TestEnv::installed(Profile::Home).await;
    add_user(&env, "olga", RoleName::Operator, PIN).await;
    add_user(&env, "vera", RoleName::Viewer, PIN).await;
    let olga = expect_session(password_login(&env, "olga", PIN).await.expect("login"));
    let vera = expect_session(password_login(&env, "vera", PIN).await.expect("login"));
    let mine = make_token(&env, &olga, "olga-1", None)
        .await
        .expect("token");
    make_token(&env, &vera, "vera-1", None)
        .await
        .expect("token");
    make_token(&env, &vera, "vera-2", None)
        .await
        .expect("token");
    let olga_ctx = env.session_ctx(&olga).await.expect("ctx");
    let listed = env.service.list_tokens(&olga_ctx).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], mine.info);
    let vera_ctx = env.session_ctx(&vera).await.expect("ctx");
    assert_eq!(
        env.service
            .list_tokens(&vera_ctx)
            .await
            .expect("list")
            .len(),
        2
    );
}

#[tokio::test]
async fn a_token_always_expires_while_a_maximum_is_configured() {
    let (env, admin_session) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&admin_session).await.expect("ctx");
    let outcome = env
        .service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                token_max_lifetime: Some(TokenMaxLifetime::Days(4_000_000_000)),
                ..SettingsPatch::default()
            },
            None,
        )
        .await;
    if outcome.is_err() {
        // Refusing an absurd maximum is a correct way to keep the invariant.
        return;
    }
    for requested in [None, Some(4_000_000_000_u32)] {
        if let Ok(created) = make_token(&env, &admin_session, "far", requested).await {
            assert!(
                created.info.expires_at.is_some(),
                "requested {requested:?}: the token never expires although TGL-05 sets a maximum"
            );
        }
    }
}
