//! End-to-end flows of the authentication service over `MemStore` and `MemVault`: setup,
//! sessions, password login and lockout, TOTP and recovery codes, passkeys, break-glass.

use std::time::Duration;

use tenko_auth::{
    AuthError, LoginOutcome,
    encoding::base32_decode,
    model::{ALARMS, AlarmKind},
    service::{
        BreakGlassChange, CodeLogin, PasswordLogin, SecondFactorMethod, SetupAdmin, SetupRequest,
        TotpEnrollFinish, UserCreate, WebAuthnLoginFinish, WebAuthnLoginStart,
        WebAuthnRegisterFinish, WebAuthnRegisterStart, types::SecretString,
    },
    settings::{Profile, SessionLifetime, SettingsPatch},
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN, ADMIN_PASSWORD, ADMIN_PIN, HOST, ORIGIN},
    },
    totp::{self, TotpParams},
    webauthn::WebAuthnError,
};
use tenko_core::{AuthStrength, Credentials, Principal, RequestCtx};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables};

fn session_credentials(session: &tenko_auth::NewSession) -> Credentials {
    Credentials::Session(session.secret.expose().to_owned())
}

async fn audit_actions(env: &TestEnv) -> Vec<String> {
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft.action.as_str().to_owned())
        .collect()
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

fn expect_session(outcome: LoginOutcome) -> tenko_auth::NewSession {
    match outcome {
        LoginOutcome::Session(session) => session,
        LoginOutcome::SecondFactor { methods, .. } => {
            panic!("expected a session, got a second-factor challenge {methods:?}")
        }
    }
}

#[tokio::test]
async fn setup_runs_once_and_logs_the_administrator_in() {
    let env = TestEnv::new().await;
    let state = env.service.setup_state().await.expect("state");
    assert!(state.open);
    assert_eq!(state.profiles.len(), 4);
    let token = env
        .service
        .prepare_setup()
        .await
        .expect("prepare")
        .expect("open");
    let request = |token: &str, host: &str, password: &str| SetupRequest {
        setup_token: SecretString::new(token),
        profile: Profile::Standard,
        admin: SetupAdmin {
            name: ADMIN.to_owned(),
            display_name: None,
            password: SecretString::new(password),
        },
        host_name: host.to_owned(),
        language: "sv".to_owned(),
    };
    let ctx = env.public_ctx();
    assert_eq!(
        env.service
            .complete_setup(
                &ctx,
                None,
                &request("AAAAA-AAAAA-AAAAA-AAAAA", HOST, ADMIN_PASSWORD)
            )
            .await
            .expect_err("wrong token")
            .code_str(),
        "auth.setup.token_invalid"
    );
    assert!(matches!(
        env.service
            .complete_setup(
                &ctx,
                None,
                &request(token.expose(), "192.0.2.1", ADMIN_PASSWORD)
            )
            .await,
        Err(AuthError::InvalidHostName(_))
    ));
    assert!(matches!(
        env.service
            .complete_setup(&ctx, None, &request(token.expose(), HOST, "short"))
            .await,
        Err(AuthError::PasswordPolicy(_))
    ));
    let session = env
        .service
        .complete_setup(
            &ctx,
            Some("agent"),
            &request(token.expose(), HOST, ADMIN_PASSWORD),
        )
        .await
        .expect("setup");
    assert_eq!(session.info.user.name, ADMIN);
    assert_eq!(session.info.profile, Profile::Standard);
    assert_eq!(session.info.default_language.as_deref(), Some("sv"));
    // Standard requires MFA for administrators: the password session must enroll a factor.
    assert_eq!(session.info.strength, AuthStrength::Password);
    assert_eq!(session.info.required_strength, AuthStrength::PasswordTotp);
    assert!(session.info.flags.mfa_enrollment_required);
    assert!(session.set_cookie.contains("HttpOnly"));
    assert!(session.set_cookie.contains("SameSite=Strict"));
    assert!(session.set_cookie.contains("Secure"));
    assert!(session.set_cookie.starts_with("tenko_session="));

    assert!(!env.service.setup_state().await.expect("state").open);
    assert!(
        env.service
            .prepare_setup()
            .await
            .expect("prepare")
            .is_none()
    );
    assert!(matches!(
        env.service
            .complete_setup(&ctx, None, &request(token.expose(), HOST, ADMIN_PASSWORD))
            .await,
        Err(AuthError::SetupClosed)
    ));
    assert!(
        audit_actions(&env)
            .await
            .contains(&"auth.setup.complete".to_owned())
    );
    assert_eq!(env.service.relying_party().expect("rp").rp_id(), HOST);
}

trait CodeStr {
    fn code_str(&self) -> &'static str;
}

impl CodeStr for AuthError {
    fn code_str(&self) -> &'static str {
        tenko_core::Coded::code(self)
    }
}

#[tokio::test]
async fn sessions_expire_idle_and_absolute_and_end_at_logout() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let credentials = session_credentials(&session);
    let ctx = env.session_ctx(&session).await.expect("authenticated");
    assert!(matches!(
        ctx.principal,
        Principal::User {
            strength: AuthStrength::Pin,
            ..
        }
    ));
    // Activity within the idle window keeps the session alive.
    for _ in 0..3 {
        env.clock.advance(Duration::from_secs(6 * 86_400));
        env.session_ctx(&session).await.expect("still alive");
    }
    // Tightening TGL-04 applies to existing sessions at once.
    let admin = env.session_ctx(&session).await.expect("ctx");
    env.service
        .update_security_settings(
            &admin,
            &SettingsPatch {
                session: Some(SessionLifetime {
                    absolute_secs: 3_600,
                    idle_secs: 600,
                }),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("settings");
    assert!(matches!(
        env.service
            .authenticate_credentials(&credentials, env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));

    // A new session: idle expiry after 10 minutes without activity.
    let fresh = expect_session(password_login(&env, ADMIN, ADMIN_PIN).await.expect("login"));
    env.clock.advance(Duration::from_secs(601));
    assert!(matches!(
        env.service
            .authenticate_credentials(&session_credentials(&fresh), env.now())
            .await,
        Err(AuthError::SessionExpired)
    ));

    // Logout removes the session.
    let other = expect_session(password_login(&env, ADMIN, ADMIN_PIN).await.expect("login"));
    let ctx = env.session_ctx(&other).await.expect("ctx");
    let cleared = env.service.logout(&ctx).await.expect("logout");
    assert!(cleared.contains("Max-Age=0"));
    assert!(matches!(
        env.service
            .authenticate_credentials(&session_credentials(&other), env.now())
            .await,
        Err(AuthError::Unauthenticated)
    ));
    let actions = audit_actions(&env).await;
    assert!(actions.contains(&"auth.logout".to_owned()));
    assert!(actions.contains(&"auth.settings.update".to_owned()));
}

#[tokio::test]
async fn sessions_are_listed_and_revoked_and_stored_hashed() {
    let (env, first) = TestEnv::installed(Profile::Home).await;
    let second = expect_session(password_login(&env, ADMIN, ADMIN_PIN).await.expect("login"));
    let ctx = env.session_ctx(&second).await.expect("ctx");
    let sessions = env.service.list_sessions(&ctx).await.expect("list");
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.iter().filter(|s| s.current).count(), 1);
    // Only the hash of the secret is stored.
    assert!(
        env.service
            .session_exists(&first.secret.hash())
            .await
            .expect("hash")
    );
    assert!(
        !env.service
            .session_exists(first.secret.expose().as_bytes())
            .await
            .expect("plain")
    );
    env.service
        .revoke_session(&ctx, first.info.session_id)
        .await
        .expect("revoke");
    assert!(
        env.service
            .authenticate_credentials(&session_credentials(&first), env.now())
            .await
            .is_err()
    );
    assert_eq!(
        env.service.list_sessions(&ctx).await.expect("list").len(),
        1
    );
}

#[tokio::test]
async fn failed_logins_are_throttled_then_locked() {
    let (env, _) = TestEnv::installed(Profile::Standard).await;
    // Unknown and known accounts answer alike.
    assert!(matches!(
        password_login(&env, "nobody", "wrong").await,
        Err(AuthError::InvalidCredentials)
    ));
    let mut throttled = 0;
    let mut locked = false;
    for _ in 0..30 {
        match password_login(&env, ADMIN, "not the password at all").await {
            Err(AuthError::InvalidCredentials) => {}
            Err(AuthError::Throttled { retry_after }) => {
                throttled += 1;
                env.clock
                    .advance(Duration::from_secs(retry_after.unwrap_or(60)));
            }
            other => panic!("unexpected {other:?}"),
        }
        let view = env.store.read(ReadConsistency::Local).await.expect("view");
        let user = view
            .scan_typed(&tenko_auth::model::USERS, KeyRange::all(), 10, false)
            .expect("users")
            .into_iter()
            .find(|(_, user, _)| user.name == ADMIN)
            .expect("admin")
            .1;
        if user.lock.is_some() {
            locked = true;
            break;
        }
    }
    assert!(throttled > 0, "progressive delays apply before the lock");
    assert!(locked, "Standard locks after ten failures");
    // While locked, even the right password is refused without a hint.
    assert!(matches!(
        password_login(&env, ADMIN, ADMIN_PASSWORD).await,
        Err(AuthError::Throttled { .. })
    ));
    // The lock lifts after its duration.
    env.clock.advance(Duration::from_secs(15 * 60 + 1));
    assert!(password_login(&env, ADMIN, ADMIN_PASSWORD).await.is_ok());
    let actions = audit_actions(&env).await;
    assert!(actions.contains(&"auth.user.lock".to_owned()));
    assert!(
        actions
            .iter()
            .filter(|a| *a == "auth.login.password")
            .count()
            >= 10
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One flow from enrollment to recovery.
async fn totp_enrollment_then_two_step_login_and_recovery() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
    assert!(
        enrollment
            .otpauth_uri
            .expose()
            .starts_with("otpauth://totp/")
    );
    let seconds = |env: &TestEnv| u64::try_from(env.now().0.unix_timestamp()).expect("time");
    // A wrong code does not enroll.
    assert!(matches!(
        env.service
            .totp_enroll_finish(
                &ctx,
                &TotpEnrollFinish {
                    enrollment_id: enrollment.enrollment_id.clone(),
                    code: SecretString::new("000000"),
                },
            )
            .await,
        Err(AuthError::TotpCodeMismatch)
    ));
    let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
    let seed = base32_decode(enrollment.secret.expose()).expect("seed");
    let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
    let enrolled = env
        .service
        .totp_enroll_finish(
            &ctx,
            &TotpEnrollFinish {
                enrollment_id: enrollment.enrollment_id.clone(),
                code: SecretString::new(code.as_str()),
            },
        )
        .await
        .expect("enroll");
    let recovery = enrolled
        .recovery_codes
        .expect("first factor brings recovery codes");
    assert_eq!(recovery.len(), 10);
    assert!(
        enrolled.reauthenticate,
        "enrollment does not raise the session"
    );

    // The seed is in the vault, not in the user record.
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let secrets = view
        .scan(&tenko_vault::tables::SECRETS, KeyRange::all(), 10, false)
        .expect("secrets");
    assert_eq!(secrets.len(), 1, "one TOTP seed in the vault");

    // Password login now asks for the second factor.
    env.clock.advance(Duration::from_secs(60));
    let LoginOutcome::SecondFactor {
        challenge_id,
        methods,
    } = password_login(&env, ADMIN, ADMIN_PASSWORD)
        .await
        .expect("step one")
    else {
        panic!("expected a second-factor challenge");
    };
    assert!(methods.contains(&SecondFactorMethod::Totp));
    assert!(methods.contains(&SecondFactorMethod::Recovery));
    let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
    let session = expect_session(
        env.service
            .login_totp(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id: challenge_id.clone(),
                    code: SecretString::new(code.as_str()),
                },
            )
            .await
            .expect("totp"),
    );
    assert_eq!(session.info.strength, AuthStrength::PasswordTotp);
    assert!(!session.info.flags.mfa_enrollment_required);
    // The challenge is single use, and the same code cannot be replayed.
    assert!(
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
            .is_err()
    );
    let LoginOutcome::SecondFactor { challenge_id, .. } =
        password_login(&env, ADMIN, ADMIN_PASSWORD)
            .await
            .expect("step one")
    else {
        panic!("expected a challenge");
    };
    assert!(matches!(
        env.service
            .login_totp(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id: challenge_id.clone(),
                    code: SecretString::new(code.as_str()),
                },
            )
            .await,
        Err(AuthError::InvalidCredentials)
    ));
    // A recovery code works once.
    let first_code = recovery[0].expose().to_owned();
    let recovered = expect_session(
        env.service
            .login_recovery(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id,
                    code: SecretString::new(first_code.as_str()),
                },
            )
            .await
            .expect("recovery"),
    );
    assert_eq!(recovered.info.strength, AuthStrength::PasswordTotp);
    let LoginOutcome::SecondFactor { challenge_id, .. } =
        password_login(&env, ADMIN, ADMIN_PASSWORD)
            .await
            .expect("step one")
    else {
        panic!("expected a challenge");
    };
    assert!(
        env.service
            .login_recovery(
                &env.public_ctx(),
                None,
                &CodeLogin {
                    challenge_id,
                    code: SecretString::new(first_code.as_str()),
                },
            )
            .await
            .is_err()
    );
    let actions = audit_actions(&env).await;
    for action in ["auth.totp.enroll", "auth.login.totp", "auth.login.recovery"] {
        assert!(actions.contains(&action.to_owned()), "{action}");
    }
}

/// Registers a credential for the session's user and returns the authenticator.
async fn register(
    env: &TestEnv,
    ctx: &RequestCtx,
    mut authenticator: SoftAuthenticator,
    security_key: bool,
) -> Result<SoftAuthenticator, AuthError> {
    let options = env
        .service
        .webauthn_register_start(
            ctx,
            &WebAuthnRegisterStart {
                label: Some("Test key".to_owned()),
                security_key,
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
    Ok(authenticator)
}

async fn passkey_login(
    env: &TestEnv,
    authenticator: &mut SoftAuthenticator,
    user_name: Option<&str>,
) -> Result<tenko_auth::NewSession, AuthError> {
    let options = env
        .service
        .webauthn_login_start(
            &env.public_ctx(),
            &WebAuthnLoginStart {
                user_name: user_name.map(str::to_owned),
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

#[tokio::test]
async fn passkeys_register_and_log_in_without_a_user_name() {
    let (env, session) = TestEnv::installed(Profile::Hardened).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    // Hardened: the password session must enroll a passkey and log in with it.
    assert!(session.info.flags.mfa_enrollment_required);
    assert_eq!(session.info.required_strength, AuthStrength::Passkey);
    let mut authenticator = register(
        &env,
        &ctx,
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None),
        false,
    )
    .await
    .expect("register");
    let credentials = env.service.list_credentials(&ctx).await.expect("list");
    assert_eq!(credentials.len(), 1);
    assert!(!credentials[0].hardware_key);

    let passkey = passkey_login(&env, &mut authenticator, None)
        .await
        .expect("login");
    assert_eq!(passkey.info.strength, AuthStrength::Passkey);
    assert!(!passkey.info.flags.mfa_enrollment_required);
    // The counter moved: a replayed assertion with the same counter is refused.
    let named = passkey_login(&env, &mut authenticator, Some(ADMIN))
        .await
        .expect("named login");
    assert_eq!(named.info.user.name, ADMIN);
    // The authorizer now lets the admin act.
    let admin = env.session_ctx(&named).await.expect("ctx");
    env.service
        .list_users(&admin)
        .await
        .expect("admin may list users");
    // ...while the password session may not.
    assert!(matches!(
        env.service.list_users(&ctx).await,
        Err(AuthError::Denied(_))
    ));
}

#[tokio::test]
async fn break_glass_needs_an_attested_hardware_key_and_raises_alarms() {
    let (env, session) = TestEnv::installed(Profile::Home).await;
    let admin = env.session_ctx(&session).await.expect("ctx");
    // A second account that becomes the break-glass account.
    let user = env
        .service
        .create_user(
            &admin,
            &UserCreate {
                name: "emergency".to_owned(),
                display_name: None,
                password: Some(SecretString::new("7391")),
                roles: vec![tenko_auth::roles::RoleName::Admin],
                language: None,
            },
        )
        .await
        .expect("create");
    let emergency = expect_session(
        password_login(&env, "emergency", "7391")
            .await
            .expect("password login before designation"),
    );
    let emergency_ctx = env.session_ctx(&emergency).await.expect("ctx");
    // A synced passkey cannot serve as a security key.
    let synced = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate)
        .backup(true, true);
    assert!(matches!(
        register(&env, &emergency_ctx, synced, true).await,
        Err(AuthError::WebAuthn(WebAuthnError::BackupEligibleRefused))
    ));
    // Without a hardware key the account cannot be designated.
    let designate = BreakGlassChange {
        user_id: user.id,
        enabled: true,
    };
    // The PIN session of the admin is not strong enough to designate.
    assert!(matches!(
        env.service.set_break_glass(&admin, &designate).await,
        Err(AuthError::StepUpRequired { .. })
    ));
    // The admin logs in with a passkey first.
    let mut admin_key = register(
        &env,
        &admin,
        SoftAuthenticator::new(SoftKeyAlg::Ed25519, SoftAttestation::None),
        false,
    )
    .await
    .expect("admin passkey");
    let strong = passkey_login(&env, &mut admin_key, Some(ADMIN))
        .await
        .expect("login");
    let strong_ctx = env.session_ctx(&strong).await.expect("ctx");
    assert!(matches!(
        env.service.set_break_glass(&strong_ctx, &designate).await,
        Err(AuthError::Invalid { .. })
    ));
    let mut hardware = register(
        &env,
        &emergency_ctx,
        SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::PackedCertificate),
        true,
    )
    .await
    .expect("hardware key");
    let info = env
        .service
        .set_break_glass(&strong_ctx, &designate)
        .await
        .expect("designate");
    assert!(info.break_glass);
    assert_eq!(info.factors.hardware_keys, 1);
    // Its sessions ended, and the password no longer logs it in.
    assert!(
        env.service
            .authenticate_credentials(&session_credentials(&emergency), env.now())
            .await
            .is_err()
    );
    assert!(matches!(
        password_login(&env, "emergency", "7391").await,
        Err(AuthError::InvalidCredentials)
    ));
    // The hardware key logs it in, with a short session and an alarm.
    let glass = passkey_login(&env, &mut hardware, None)
        .await
        .expect("break-glass login");
    assert_eq!(glass.info.strength, AuthStrength::HardwareKey);
    assert!(glass.info.flags.break_glass);
    assert!(
        glass.info.absolute_expires_at.saturating_since(env.now()) <= Duration::from_secs(3_600)
    );
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let alarms: Vec<AlarmKind> = view
        .scan_typed(&ALARMS, KeyRange::all(), 100, false)
        .expect("alarms")
        .into_iter()
        .map(|(_, alarm, _)| alarm.kind)
        .collect();
    assert!(alarms.contains(&AlarmKind::BreakGlassLogin));
    assert!(
        audit_actions(&env)
            .await
            .contains(&"auth.login.break_glass".to_owned())
    );
}

/// The wrong-code and replay rules of the login ceremonies: wrong second-factor codes count
/// toward the account's lock across challenges, and a finished ceremony is refused by every
/// service instance that shares the store.
mod ceremony_rules {
    use std::sync::Arc;

    use tenko_auth::{
        AuthConfig, AuthService,
        challenge::CeremonyKey,
        lockout::{LockoutMode, LockoutPolicy},
        model::USERS,
    };
    use tenko_vault::Vault;

    use super::*;

    fn seconds(env: &TestEnv) -> u64 {
        u64::try_from(env.now().0.unix_timestamp()).expect("time")
    }

    /// Enrolls TOTP for the session's user and returns the seed.
    async fn enroll_totp(env: &TestEnv, ctx: &RequestCtx) -> Vec<u8> {
        let enrollment = env.service.totp_enroll_start(ctx).await.expect("start");
        let seed = base32_decode(enrollment.secret.expose()).expect("seed");
        let code = totp::code_at(&seed, &TotpParams::default(), seconds(env));
        env.service
            .totp_enroll_finish(
                ctx,
                &TotpEnrollFinish {
                    enrollment_id: enrollment.enrollment_id,
                    code: SecretString::new(code.as_str()),
                },
            )
            .await
            .expect("enroll");
        seed
    }

    /// A six-digit code that no step within the verification window accepts.
    fn wrong_code(env: &TestEnv, seed: &[u8]) -> String {
        let params = TotpParams::default();
        let now = seconds(env);
        let valid: Vec<String> = [now - 60, now - 30, now, now + 30, now + 60]
            .into_iter()
            .map(|at| totp::code_at(seed, &params, at).as_str().to_owned())
            .collect();
        (0..1_000_000_u32)
            .map(|n| format!("{n:06}"))
            .find(|code| !valid.contains(code))
            .expect("a wrong code exists")
    }

    async fn locked(env: &TestEnv) -> bool {
        let view = env.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(&USERS, KeyRange::all(), 10, false)
            .expect("users")
            .into_iter()
            .find(|(_, user, _)| user.name == ADMIN)
            .expect("admin")
            .1
            .active_lock(env.now())
            .is_some()
    }

    /// A password login that waits out any delay and returns the second-factor challenge.
    async fn challenge(env: &TestEnv) -> String {
        loop {
            match password_login(env, ADMIN, ADMIN_PASSWORD).await {
                Ok(LoginOutcome::SecondFactor { challenge_id, .. }) => return challenge_id,
                Err(AuthError::Throttled { retry_after }) => {
                    env.clock
                        .advance(Duration::from_secs(retry_after.unwrap_or(60)));
                }
                other => panic!("expected a challenge, got {other:?}"),
            }
        }
    }

    /// Sends one wrong code until it is counted. A delayed attempt spends its challenge: the helper waits and
    /// signs in with the password again for a new one.
    async fn one_wrong_code(env: &TestEnv, seed: &[u8], challenge_id: &mut String) {
        loop {
            let result = env
                .service
                .login_totp(
                    &env.public_ctx(),
                    None,
                    &CodeLogin {
                        challenge_id: challenge_id.clone(),
                        code: SecretString::new(wrong_code(env, seed).as_str()),
                    },
                )
                .await;
            match result {
                Err(AuthError::InvalidCredentials) => return,
                Err(AuthError::Throttled { retry_after }) => {
                    assert!(!locked(env).await, "a locked account gets no further code");
                    env.clock
                        .advance(Duration::from_secs(retry_after.unwrap_or(60)));
                    *challenge_id = challenge(env).await;
                }
                other => panic!("expected a refused code, got {other:?}"),
            }
        }
    }

    /// Cycles of a correct password and three wrong codes until the account locks; returns
    /// the number of wrong codes counted.
    async fn wrong_codes_until_locked(env: &TestEnv, seed: &[u8]) -> u32 {
        let mut wrong = 0;
        for _ in 0..20 {
            let mut challenge_id = challenge(env).await;
            for _ in 0..3 {
                one_wrong_code(env, seed, &mut challenge_id).await;
                wrong += 1;
                if locked(env).await {
                    return wrong;
                }
            }
        }
        panic!("no lock after {wrong} wrong codes");
    }

    async fn wrong_codes_lock_the_account(profile: Profile) {
        let (env, session) = TestEnv::installed(profile).await;
        let ctx = env.session_ctx(&session).await.expect("ctx");
        let seed = enroll_totp(&env, &ctx).await;
        let policy = LockoutPolicy::for_mode(env.service.settings().lockout);
        assert!(
            policy.lock_after > 3,
            "the lock needs more than one challenge"
        );

        let wrong = wrong_codes_until_locked(&env, &seed).await;
        assert_eq!(wrong, policy.lock_after, "{profile:?}");

        // Locked: the right password and a right code are both refused.
        assert!(matches!(
            password_login(&env, ADMIN, ADMIN_PASSWORD).await,
            Err(AuthError::Throttled { .. })
        ));
        let actions = audit_actions(&env).await;
        assert!(actions.contains(&"auth.user.lock".to_owned()));
        let view = env.store.read(ReadConsistency::Local).await.expect("view");
        let alarms = view
            .scan_typed(&ALARMS, KeyRange::all(), 100, false)
            .expect("alarms")
            .into_iter()
            .filter(|(_, alarm, _)| alarm.kind == AlarmKind::AccountLocked)
            .count();
        let expected = usize::from(policy.mode == LockoutMode::LockUntilUnlock);
        assert_eq!(alarms, expected, "{profile:?}");
    }

    #[tokio::test]
    async fn wrong_codes_across_challenges_lock_the_account_under_standard() {
        wrong_codes_lock_the_account(Profile::Standard).await;
    }

    #[tokio::test]
    async fn wrong_codes_across_challenges_lock_the_account_under_hardened() {
        wrong_codes_lock_the_account(Profile::Hardened).await;
    }

    #[tokio::test]
    async fn a_complete_login_clears_the_counter_and_a_password_alone_does_not() {
        let (env, session) = TestEnv::installed(Profile::Standard).await;
        let ctx = env.session_ctx(&session).await.expect("ctx");
        let seed = enroll_totp(&env, &ctx).await;
        let policy = LockoutPolicy::for_mode(env.service.settings().lockout);
        assert_eq!(policy.free_attempts, 5);

        // Four wrong codes, then a complete login: the four are forgotten, so five more
        // wrong codes stay within the free attempts.
        let mut challenge_id = challenge(&env).await;
        for _ in 0..4 {
            one_wrong_code(&env, &seed, &mut challenge_id).await;
        }
        env.clock.advance(Duration::from_secs(30));
        let challenge_id = challenge(&env).await;
        let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
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
                .expect("complete login"),
        );
        let challenge_id = challenge(&env).await;
        for _ in 0..5 {
            assert!(matches!(
                env.service
                    .login_totp(
                        &env.public_ctx(),
                        None,
                        &CodeLogin {
                            challenge_id: challenge_id.clone(),
                            code: SecretString::new(wrong_code(&env, &seed).as_str()),
                        },
                    )
                    .await,
                Err(AuthError::InvalidCredentials)
            ));
        }

        // A correct password does not clear them: the next wrong code is the sixth failure
        // and the attempt after it waits.
        let challenge_id = challenge(&env).await;
        assert!(matches!(
            env.service
                .login_totp(
                    &env.public_ctx(),
                    None,
                    &CodeLogin {
                        challenge_id: challenge_id.clone(),
                        code: SecretString::new(wrong_code(&env, &seed).as_str()),
                    },
                )
                .await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            password_login(&env, ADMIN, ADMIN_PASSWORD).await,
            Err(AuthError::Throttled { .. })
        ));
    }

    /// The installation's ceremony key, as every controller derives it.
    fn cluster_ceremony_key() -> CeremonyKey {
        CeremonyKey::from_cluster_key(&[0x5a; 32])
    }

    /// A second service instance over the same store and vault, with the same ceremony
    /// key: another controller, or this one after a restart (nothing in local memory).
    async fn second_instance(env: &TestEnv) -> Arc<AuthService> {
        let vault: Arc<dyn Vault> = env.vault.clone();
        let other = AuthService::new(env.store.clone(), vault, AuthConfig::default())
            .await
            .expect("a second instance starts");
        other.set_ceremony_key(cluster_ceremony_key());
        other
    }

    #[tokio::test]
    async fn a_replayed_passkey_login_is_refused_by_another_instance() {
        let (env, session) = TestEnv::installed(Profile::Standard).await;
        env.service.set_ceremony_key(cluster_ceremony_key());
        let ctx = env.session_ctx(&session).await.expect("ctx");
        // No signature counter: the authenticator data of a replay is accepted as is, so
        // only the record of the used ceremony refuses it.
        let mut authenticator = register(
            &env,
            &ctx,
            SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None).counter(false),
            false,
        )
        .await
        .expect("register");
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
        let finish = WebAuthnLoginFinish {
            ceremony_id: options.ceremony_id,
            credential: authenticator.assert(&options.public_key, ORIGIN),
        };
        env.service
            .webauthn_login_finish(&env.public_ctx(), None, &finish)
            .await
            .expect("the first finish signs in");

        let other = second_instance(&env).await;
        assert!(matches!(
            other
                .webauthn_login_finish(&env.public_ctx(), None, &finish)
                .await,
            Err(AuthError::ChallengeInvalid)
        ));
        assert!(matches!(
            env.service
                .webauthn_login_finish(&env.public_ctx(), None, &finish)
                .await,
            Err(AuthError::ChallengeInvalid)
        ));
    }

    #[tokio::test]
    async fn used_challenges_are_refused_by_an_instance_with_an_empty_memory() {
        let (env, session) = TestEnv::installed(Profile::Standard).await;
        env.service.set_ceremony_key(cluster_ceremony_key());
        let ctx = env.session_ctx(&session).await.expect("ctx");

        // TOTP enrollment: the replay is refused as a used ceremony, before the factor.
        let enrollment = env.service.totp_enroll_start(&ctx).await.expect("start");
        let seed = base32_decode(enrollment.secret.expose()).expect("seed");
        let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
        let enroll = TotpEnrollFinish {
            enrollment_id: enrollment.enrollment_id,
            code: SecretString::new(code.as_str()),
        };
        env.service
            .totp_enroll_finish(&ctx, &enroll)
            .await
            .expect("enroll");

        // Passkey registration: refused as a used ceremony, not as a duplicate credential.
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
            .expect("start");
        let register = WebAuthnRegisterFinish {
            ceremony_id: options.ceremony_id,
            credential: authenticator.register(&options.public_key, ORIGIN),
        };
        env.service
            .webauthn_register_finish(&ctx, &register)
            .await
            .expect("register");

        // A second-factor challenge spent on the passkey step.
        env.clock.advance(Duration::from_secs(60));
        let challenge_id = challenge(&env).await;
        env.service
            .webauthn_login_start(
                &env.public_ctx(),
                &WebAuthnLoginStart {
                    user_name: None,
                    challenge_id: Some(challenge_id.clone()),
                },
            )
            .await
            .expect("the passkey step starts");

        let other = second_instance(&env).await;
        assert!(matches!(
            other.totp_enroll_finish(&ctx, &enroll).await,
            Err(AuthError::ChallengeInvalid)
        ));
        assert!(matches!(
            other.webauthn_register_finish(&ctx, &register).await,
            Err(AuthError::ChallengeInvalid)
        ));
        assert!(matches!(
            other
                .webauthn_login_start(
                    &env.public_ctx(),
                    &WebAuthnLoginStart {
                        user_name: None,
                        challenge_id: Some(challenge_id.clone()),
                    },
                )
                .await,
            Err(AuthError::ChallengeInvalid)
        ));
        let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
        assert!(matches!(
            other
                .login_totp(
                    &env.public_ctx(),
                    None,
                    &CodeLogin {
                        challenge_id,
                        code: SecretString::new(code.as_str()),
                    },
                )
                .await,
            Err(AuthError::ChallengeInvalid)
        ));
        // A code login that completed is refused on the other instance too.
        let challenge_id = challenge(&env).await;
        env.clock.advance(Duration::from_secs(30));
        let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
        let login = CodeLogin {
            challenge_id,
            code: SecretString::new(code.as_str()),
        };
        expect_session(
            env.service
                .login_totp(&env.public_ctx(), None, &login)
                .await
                .expect("totp"),
        );
        assert!(matches!(
            other.login_totp(&env.public_ctx(), None, &login).await,
            Err(AuthError::ChallengeInvalid)
        ));
    }
}
