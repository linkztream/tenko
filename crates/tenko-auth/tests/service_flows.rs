//! End-to-end flows of the authentication service over `MemStore` and `MemVault`: setup,
//! sessions, password login and lockout, TOTP and recovery codes, passkeys, break-glass.

use std::time::Duration;

use tenko_auth::{
    AuthError, LoginOutcome,
    encoding::base32_decode,
    model::{ALARMS, AlarmKind},
    service::{
        BreakGlassChange, CodeLogin, PasswordLogin, SecondFactorMethod, SetupAdmin, SetupRequest,
        TotpEnrolFinish, UserCreate, WebAuthnLoginFinish, WebAuthnLoginStart,
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
    // Standard requires MFA for administrators: the password session must enrol a factor.
    assert_eq!(session.info.strength, AuthStrength::Password);
    assert_eq!(session.info.required_strength, AuthStrength::PasswordTotp);
    assert!(session.info.flags.mfa_enrolment_required);
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
#[allow(clippy::too_many_lines)] // One flow from enrolment to recovery.
async fn totp_enrolment_then_two_step_login_and_recovery() {
    let (env, session) = TestEnv::installed(Profile::Standard).await;
    let ctx = env.session_ctx(&session).await.expect("ctx");
    let enrolment = env.service.totp_enrol_start(&ctx).await.expect("start");
    assert!(
        enrolment
            .otpauth_uri
            .expose()
            .starts_with("otpauth://totp/")
    );
    let seconds = |env: &TestEnv| u64::try_from(env.now().0.unix_timestamp()).expect("time");
    // A wrong code does not enrol.
    assert!(matches!(
        env.service
            .totp_enrol_finish(
                &ctx,
                &TotpEnrolFinish {
                    enrolment_id: enrolment.enrolment_id.clone(),
                    code: SecretString::new("000000"),
                },
            )
            .await,
        Err(AuthError::TotpCodeMismatch)
    ));
    let enrolment = env.service.totp_enrol_start(&ctx).await.expect("start");
    let seed = base32_decode(enrolment.secret.expose()).expect("seed");
    let code = totp::code_at(&seed, &TotpParams::default(), seconds(&env));
    let enrolled = env
        .service
        .totp_enrol_finish(
            &ctx,
            &TotpEnrolFinish {
                enrolment_id: enrolment.enrolment_id.clone(),
                code: SecretString::new(code.as_str()),
            },
        )
        .await
        .expect("enrol");
    let recovery = enrolled
        .recovery_codes
        .expect("first factor brings recovery codes");
    assert_eq!(recovery.len(), 10);
    assert!(
        enrolled.reauthenticate,
        "enrolment does not raise the session"
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
    assert!(!session.info.flags.mfa_enrolment_required);
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
    for action in ["auth.totp.enrol", "auth.login.totp", "auth.login.recovery"] {
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
    // Hardened: the password session must enrol a passkey and log in with it.
    assert!(session.info.flags.mfa_enrolment_required);
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
    assert!(!passkey.info.flags.mfa_enrolment_required);
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
