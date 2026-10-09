//! Self-service: the current session and the user's other sessions, password, TOTP,
//! WebAuthn credentials, recovery codes and personal tokens.

use std::time::Duration;

use tenko_core::{
    Action, ApiTokenId, AuthStrength, ObjectKind, ObjectRef, Principal, RequestCtx, Revision,
    SessionId, UserId, secret::SecretClass,
};
use tenko_store::{KeyRange, ReadViewExt, WriteBatch};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec};
use zeroize::Zeroizing;

use super::{
    AuthService, FRESH_AUTHENTICATION, LIST_LIMIT, actions, blocking, effective_expiry,
    login::hash_strength,
    types::{
        BreachStatus, CreatedToken, CredentialInfo, FactorEnrolled, PasswordChange,
        PasswordChanged, PasswordCheck, PasswordCheckResult, RecoveryCodes, SecretString,
        SessionInfo, SessionSummary, TokenCreate, TokenInfo, TotpEnrolFinish, TotpEnrolment,
        WebAuthnRegisterFinish, WebAuthnRegisterOptions, WebAuthnRegisterStart,
    },
};
use crate::{
    challenge::Pending,
    encoding::{base32_encode, base64url_decode, base64url_encode, hex_encode},
    error::AuthError,
    hibp::BreachOutcome,
    lockout::{LockoutPolicy, ThrottleKey},
    model::{
        CREDENTIAL_IDS, CREDENTIALS, CredentialRecord, INSTALLATION, PasswordKind, SESSIONS,
        StoredPassword, TOKENS, TokenRecord, TotpFactor, USER_TOKENS, USERS, UserRecord,
    },
    password::{
        PolicyViolation,
        hash::{hash_password, verify_password},
        policy::{PasswordContext, normalize},
    },
    random, recovery,
    roles::satisfies,
    secret::new_api_token,
    settings::{Profile, SecuritySettings},
    totp::{self, TotpParams},
    webauthn::{CredentialDescriptor, RegistrationPolicy, UserVerification},
};

/// Digits-only secrets shorter than this count as PINs whatever the preset (IAM-07).
const PIN_LIKE_BELOW: usize = 12;

/// Whether a normalized secret is a PIN in substance: digits only and short. Such a secret
/// logs in with [`AuthStrength::Pin`] under any preset, so the PIN coupling rule cannot be
/// sidestepped with a Custom preset.
pub(super) fn is_pin_like(normalized: &str) -> bool {
    !normalized.is_empty()
        && normalized.chars().count() < PIN_LIKE_BELOW
        && normalized.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether a preset accepts a PIN-like secret: the PIN preset, or a Custom preset that
/// accepts a non-trivial digits-only secret shorter than [`PIN_LIKE_BELOW`].
pub(super) fn admits_pin(policy: &crate::password::policy::PasswordPolicy) -> bool {
    if policy.is_pin() {
        return true;
    }
    let length = policy.min_length().max(4);
    if length >= PIN_LIKE_BELOW {
        return false;
    }
    let digits: String = "7391586240".chars().cycle().take(length).collect();
    policy
        .check(
            &digits,
            &PasswordContext {
                user_name: "",
                display_name: None,
                host_name: None,
            },
        )
        .is_empty()
}

/// Longest label of a credential or name of a token.
const MAX_LABEL_CHARS: usize = 64;

/// The identity of a password for the context-specific checks.
#[allow(clippy::struct_field_names)] // The names mirror `PasswordContext`.
pub(super) struct PasswordOwner<'a> {
    pub user_name: &'a str,
    pub display_name: Option<&'a str>,
    pub host_name: Option<&'a str>,
}

pub(super) fn credential_info(record: &CredentialRecord) -> CredentialInfo {
    CredentialInfo {
        id: base64url_encode(&record.credential_id),
        label: record.label.clone(),
        alg: record.alg,
        aaguid: hex_encode(&record.aaguid),
        created_at: record.created_at,
        last_used_at: record.last_used_at,
        backup_eligible: record.backup_eligible,
        backup_state: record.backup_state,
        hardware_key: record.hardware_key,
        attestation: record.attestation.clone(),
    }
}

fn token_info(record: &TokenRecord) -> TokenInfo {
    TokenInfo {
        id: record.id,
        name: record.name.clone(),
        prefix: record.prefix.clone(),
        created_at: record.created_at,
        expires_at: record.expires_at,
        last_used_at: record.last_used_at,
    }
}

fn label(field: &'static str, input: Option<&str>, fallback: &str) -> Result<String, AuthError> {
    let text = input.map_or(fallback, str::trim);
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(AuthError::invalid(field, "visible characters are required"));
    }
    Ok(text.chars().take(MAX_LABEL_CHARS).collect())
}

impl AuthService {
    /// Checks a candidate password against the settings: the preset's rules and, per
    /// TGL-06, the breached-password corpus. An unavailable breach check fails open and is
    /// reported.
    pub(super) async fn evaluate_password(
        &self,
        settings: &SecuritySettings,
        password: &str,
        owner: &PasswordOwner<'_>,
    ) -> (Vec<PolicyViolation>, BreachStatus) {
        let mut violations = settings.password_policy.check(
            password,
            &PasswordContext {
                user_name: owner.user_name,
                display_name: owner.display_name,
                host_name: owner.host_name,
            },
        );
        let status = if settings.breach_check == crate::hibp::BreachMode::Off {
            BreachStatus::Off
        } else {
            let normalized = normalize(password);
            match self.breach_checker(settings).check(&normalized).await {
                BreachOutcome::Clean => BreachStatus::Clean,
                BreachOutcome::Breached { count } => {
                    violations.push(PolicyViolation::Breached { count });
                    BreachStatus::Breached
                }
                BreachOutcome::Unavailable => {
                    tracing::warn!("breached-password check unavailable; password accepted");
                    BreachStatus::Unavailable
                }
            }
        };
        (violations, status)
    }

    /// Checks and hashes a new password.
    pub(super) async fn new_password(
        &self,
        settings: &SecuritySettings,
        password: &SecretString,
        owner: &PasswordOwner<'_>,
        now: tenko_core::Timestamp,
    ) -> Result<(StoredPassword, BreachStatus), AuthError> {
        let (violations, status) = self
            .evaluate_password(settings, password.expose(), owner)
            .await;
        if !violations.is_empty() {
            return Err(AuthError::PasswordPolicy(violations));
        }
        let normalized = normalize(password.expose());
        let kind = if settings.password_policy.is_pin() || is_pin_like(&normalized) {
            PasswordKind::Pin
        } else {
            PasswordKind::Password
        };
        let strength = hash_strength(settings);
        let hash = blocking(move || hash_password(&normalized, strength)).await??;
        Ok((
            StoredPassword {
                hash,
                kind,
                changed_at: now,
            },
            status,
        ))
    }

    async fn host_name(&self) -> Result<Option<String>, AuthError> {
        Ok(self
            .view()
            .await?
            .get_typed(&INSTALLATION, &())?
            .map(|(installation, _)| installation.host_name))
    }

    /// The user and session record of a session principal.
    async fn current(
        &self,
        ctx: &RequestCtx,
    ) -> Result<(UserRecord, Revision, Vec<u8>, crate::model::SessionRecord), AuthError> {
        let (user_id, session_id, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), user_id)?;
        let (hash, session) = Self::load_session(view.as_ref(), user_id, session_id)?
            .ok_or(AuthError::Unauthenticated)?;
        Ok((user, revision, hash, session))
    }

    pub(super) fn require_fresh(
        session: &crate::model::SessionRecord,
        now: tenko_core::Timestamp,
    ) -> Result<(), AuthError> {
        if now.saturating_since(session.authenticated_at) > FRESH_AUTHENTICATION {
            return Err(AuthError::StepUpRequired { required: "fresh" });
        }
        Ok(())
    }

    /// Checks that the session of `ctx` authenticated within the last five minutes, for
    /// actions that need a step-up outside this service (the installs of TGL-23).
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for anything but a session,
    /// [`AuthError::StepUpRequired`] when its authentication is older.
    pub async fn require_fresh_session(&self, ctx: &RequestCtx) -> Result<(), AuthError> {
        let (_, _, _, session) = self.current(ctx).await?;
        Self::require_fresh(&session, ctx.now)
    }

    /// `GET /auth/session` (IAM-08).
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for anything but a session.
    pub async fn current_session(&self, ctx: &RequestCtx) -> Result<SessionInfo, AuthError> {
        let (user, _, _, session) = self.current(ctx).await?;
        self.session_info(&user, &session).await
    }

    /// `GET /auth/sessions`: the user's sessions.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] or a store error.
    pub async fn list_sessions(&self, ctx: &RequestCtx) -> Result<Vec<SessionSummary>, AuthError> {
        let user = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
        let current = match ctx.principal {
            Principal::User { session, .. } => Some(session),
            _ => None,
        };
        let settings = self.settings();
        let view = self.view().await?;
        let mut sessions: Vec<SessionSummary> = Self::user_sessions(view.as_ref(), user)?
            .into_iter()
            .filter(|(_, record)| effective_expiry(record, &settings).0 > ctx.now)
            .map(|(_, record)| SessionSummary {
                id: record.id,
                created_at: record.created_at,
                last_seen_at: record.last_seen_at,
                expires_at: effective_expiry(&record, &settings).0,
                strength: record.strength,
                source_ip: record.source_ip.map(|ip| ip.to_string()),
                user_agent: record.user_agent.clone(),
                current: Some(record.id) == current,
            })
            .collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        Ok(sessions)
    }

    /// `DELETE /auth/sessions/{id}`: ends one of the user's sessions.
    ///
    /// # Errors
    ///
    /// [`AuthError::NotFound`] for a session of another user, or a store error.
    pub async fn revoke_session(&self, ctx: &RequestCtx, id: SessionId) -> Result<(), AuthError> {
        // Ending sessions is interactive: a personal token may not end its owner's sessions.
        let (user, _, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        let found = Self::load_session(view.as_ref(), user, id)?
            .ok_or(AuthError::NotFound { kind: "session" })?;
        let mut batch = WriteBatch::for_request(ctx);
        Self::stage_revoke(&mut batch, std::slice::from_ref(&found));
        batch.audit(Self::audit(
            actions::SESSION_REVOKE,
            vec![ObjectRef::from(user), ObjectRef::from(id)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(())
    }

    /// `POST /auth/password/check`: live policy and breach feedback. Before setup it
    /// applies the preset of `request.profile`; afterwards the caller's settings.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] after setup without a session or token.
    pub async fn check_password(
        &self,
        ctx: Option<&RequestCtx>,
        request: &PasswordCheck,
    ) -> Result<PasswordCheckResult, AuthError> {
        let installed = self.is_installed().await?;
        let (settings, own_name, display_name) = if installed {
            let ctx = ctx.ok_or(AuthError::Unauthenticated)?;
            let user_id = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
            let (user, _) = Self::load_user(self.view().await?.as_ref(), user_id)?;
            (self.settings(), Some(user.name), Some(user.display_name))
        } else {
            (
                request.profile.unwrap_or(Profile::Standard).defaults(),
                None,
                None,
            )
        };
        let user_name = request.user_name.clone().or(own_name).unwrap_or_default();
        let host_name = self.host_name().await?;
        let (violations, breach_check) = self
            .evaluate_password(
                &settings,
                request.password.expose(),
                &PasswordOwner {
                    user_name: &user_name,
                    display_name: display_name.as_deref(),
                    host_name: host_name.as_deref(),
                },
            )
            .await;
        Ok(PasswordCheckResult {
            acceptable: violations.is_empty(),
            violations,
            breach_check,
            policy: settings.password_policy,
        })
    }

    /// `POST /auth/password`: changes the user's password and ends their other sessions.
    ///
    /// # Errors
    ///
    /// [`AuthError::PasswordIncorrect`], [`AuthError::PasswordPolicy`],
    /// [`AuthError::Throttled`], or [`AuthError::BreakGlassHardwareKeyOnly`].
    pub async fn change_password(
        &self,
        ctx: &RequestCtx,
        request: &PasswordChange,
    ) -> Result<PasswordChanged, AuthError> {
        let (user, revision, _, session) = self.current(ctx).await?;
        if user.break_glass {
            return Err(AuthError::BreakGlassHardwareKeyOnly);
        }
        let settings = self.settings();
        if let Some(stored) = &user.password {
            let policy = LockoutPolicy::for_mode(settings.lockout);
            let account = ThrottleKey::account(&user.name);
            self.throttle
                .check(&account, &policy, ctx.now)
                .map_err(|retry| AuthError::Throttled {
                    retry_after: retry.after.map(|after| after.as_secs().max(1)),
                })?;
            let current = request
                .current_password
                .as_ref()
                .ok_or(AuthError::PasswordIncorrect)?;
            let candidate = normalize(current.expose());
            let hash = stored.hash.clone();
            if !blocking(move || verify_password(&candidate, &hash)).await?? {
                self.throttle.record_failure(&account, &policy, ctx.now);
                return Err(AuthError::PasswordIncorrect);
            }
            self.throttle.record_success(&account);
        }
        let host_name = self.host_name().await?;
        let (password, breach_check) = self
            .new_password(
                &settings,
                &request.new_password,
                &PasswordOwner {
                    user_name: &user.name,
                    display_name: Some(&user.display_name),
                    host_name: host_name.as_deref(),
                },
                ctx.now,
            )
            .await?;
        let mut updated = user.clone();
        updated.password = Some(password);
        updated.password_change_required = false;
        let view = self.view().await?;
        let others: Vec<_> = Self::user_sessions(view.as_ref(), user.id)?
            .into_iter()
            .filter(|(_, record)| record.id != session.id)
            .collect();
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&USERS, &user.id, Some(revision));
        batch.put_typed(&USERS, &user.id, &updated)?;
        Self::stage_revoke(&mut batch, &others);
        batch.audit(
            Self::audit(
                actions::PASSWORD_CHANGE,
                vec![ObjectRef::from(user.id)],
                ctx,
            )
            .with_context("sessions_revoked", others.len().to_string()),
        );
        self.commit(batch).await?;
        Ok(PasswordChanged {
            breach_check,
            sessions_revoked: others.len(),
        })
    }

    /// `POST /auth/totp/enroll/start`: a new seed, shown once, kept in memory until the
    /// user proves it.
    ///
    /// # Errors
    ///
    /// [`AuthError::TotpAlreadyEnrolled`] or [`AuthError::Unauthenticated`].
    pub async fn totp_enrol_start(&self, ctx: &RequestCtx) -> Result<TotpEnrolment, AuthError> {
        let (user, _, _, session) = self.current(ctx).await?;
        if user.totp.is_some() {
            return Err(AuthError::TotpAlreadyEnrolled);
        }
        let secret = totp::generate_secret()?;
        let params = TotpParams::default();
        let host_name = self.host_name().await?;
        let account = match &host_name {
            Some(host) => format!("{}@{host}", user.name),
            None => user.name.clone(),
        };
        let uri = totp::otpauth_uri(&secret, &params, "Tenko DDI", &account);
        let encoded = Zeroizing::new(base32_encode(&secret));
        let enrolment_id = self.ceremonies.open(
            Pending::TotpEnrolment {
                user: user.id,
                session: session.id,
                secret,
            },
            ctx.now,
        )?;
        Ok(TotpEnrolment {
            enrolment_id,
            secret: SecretString::new(encoded.as_str()),
            otpauth_uri: SecretString::new(uri.as_str()),
            params,
        })
    }

    /// `POST /auth/totp/enroll/finish`: stores the seed in the vault together with the user
    /// record (one batch) and creates recovery codes when the account has none.
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`], [`AuthError::TotpCodeMismatch`].
    pub async fn totp_enrol_finish(
        &self,
        ctx: &RequestCtx,
        request: &TotpEnrolFinish,
    ) -> Result<FactorEnrolled, AuthError> {
        let (user, revision, _, session) = self.current(ctx).await?;
        let Pending::TotpEnrolment {
            user: owner,
            session: started_in,
            secret,
        } = self.ceremonies.take(&request.enrolment_id, ctx.now)?
        else {
            return Err(AuthError::ChallengeInvalid);
        };
        if owner != user.id || started_in != session.id {
            return Err(AuthError::ChallengeInvalid);
        }
        if user.totp.is_some() {
            return Err(AuthError::TotpAlreadyEnrolled);
        }
        let now_secs = u64::try_from(ctx.now.0.unix_timestamp()).unwrap_or(0);
        let step = totp::verify(
            &secret,
            &TotpParams::default(),
            request.code.expose(),
            now_secs,
            None,
        )
        .ok_or(AuthError::TotpCodeMismatch)?;
        let mut batch = WriteBatch::for_request(ctx);
        let secret_ref = self
            .vault
            .stage_put(
                &mut batch,
                ctx,
                SecretClass::System,
                SecretSpec::new(SecretPurpose::from_static("auth.totp"))
                    .owned_by(ObjectRef::from(user.id))
                    .labelled(format!("TOTP seed of {}", user.name)),
                &SecretBytes::from(secret),
            )
            .map_err(|error| AuthError::internal(format!("vault: {error}")))?;
        let mut updated = user.clone();
        updated.totp = Some(TotpFactor {
            secret: secret_ref,
            enrolled_at: ctx.now,
            last_used_step: Some(step),
        });
        let recovery_codes = Self::fresh_recovery_codes(&mut updated)?;
        batch.expect_typed(&USERS, &user.id, Some(revision));
        batch.put_typed(&USERS, &user.id, &updated)?;
        batch.audit(Self::audit(
            actions::TOTP_ENROL,
            vec![ObjectRef::from(user.id)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(FactorEnrolled {
            recovery_codes,
            credential: None,
            reauthenticate: session.strength < self.required_for(&updated),
        })
    }

    /// Recovery codes for an account that has none yet.
    fn fresh_recovery_codes(user: &mut UserRecord) -> Result<Option<Vec<SecretString>>, AuthError> {
        if user.recovery_codes_left() > 0 {
            return Ok(None);
        }
        let generated = recovery::generate()?;
        user.recovery_codes.clone_from(&generated.stored);
        Ok(Some(
            generated
                .display
                .iter()
                .map(|code| SecretString::new(code.as_str()))
                .collect(),
        ))
    }

    /// Whether removing one factor still leaves the account able to reach its required
    /// strength.
    fn keeps_required_strength(&self, user: &UserRecord, totp: bool, credentials: usize) -> bool {
        let required = self.required_for(user);
        let first = match user.password.as_ref().map(|password| password.kind) {
            Some(PasswordKind::Pin) => Some(AuthStrength::Pin),
            Some(PasswordKind::Password) => Some(AuthStrength::Password),
            None => None,
        };
        let best = [
            first,
            (totp && first.is_some()).then_some(AuthStrength::PasswordTotp),
            (credentials > 0).then_some(AuthStrength::Passkey),
        ]
        .into_iter()
        .flatten()
        .max();
        best.is_some_and(|best| satisfies(best, required))
    }

    /// `DELETE /auth/totp`: needs a fresh authentication and another way to meet the
    /// profile.
    ///
    /// # Errors
    ///
    /// [`AuthError::StepUpRequired`], [`AuthError::TotpNotEnrolled`],
    /// [`AuthError::LastFactor`].
    pub async fn remove_totp(&self, ctx: &RequestCtx) -> Result<(), AuthError> {
        let (user, revision, _, session) = self.current(ctx).await?;
        Self::require_fresh(&session, ctx.now)?;
        let Some(factor) = user.totp.clone() else {
            return Err(AuthError::TotpNotEnrolled);
        };
        let view = self.view().await?;
        let credentials = Self::user_credentials(view.as_ref(), user.id)?.len();
        if !self.keeps_required_strength(&user, false, credentials) {
            return Err(AuthError::LastFactor);
        }
        let mut updated = user.clone();
        updated.totp = None;
        let mut batch = WriteBatch::for_request(ctx);
        self.vault.stage_delete(&mut batch, ctx, factor.secret);
        batch.expect_typed(&USERS, &user.id, Some(revision));
        batch.put_typed(&USERS, &user.id, &updated)?;
        batch.audit(Self::audit(
            actions::TOTP_REMOVE,
            vec![ObjectRef::from(user.id)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(())
    }

    /// `POST /auth/webauthn/register/start`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unavailable`] before a host name exists, [`AuthError::Invalid`] for a
    /// bad label.
    pub async fn webauthn_register_start(
        &self,
        ctx: &RequestCtx,
        request: &WebAuthnRegisterStart,
    ) -> Result<WebAuthnRegisterOptions, AuthError> {
        let rp = self.relying_party()?;
        let (user, _, _, session) = self.current(ctx).await?;
        let hardware_key = request.security_key || user.break_glass;
        let label = label(
            "label",
            request.label.as_deref(),
            if hardware_key {
                "Security key"
            } else {
                "Passkey"
            },
        )?;
        let view = self.view().await?;
        let exclude = Self::user_credentials(view.as_ref(), user.id)?
            .into_iter()
            .map(|record| CredentialDescriptor::new(&record.credential_id, record.transports))
            .collect();
        let challenge = random::array::<32>()?;
        let policy = RegistrationPolicy {
            user_verification: UserVerification::Required,
            hardware_key_required: hardware_key,
        };
        let public_key = rp.creation_options(
            &user.user_handle(),
            &user.name,
            &user.display_name,
            &challenge,
            exclude,
            &policy,
        );
        let ceremony_id = self.ceremonies.open(
            Pending::WebAuthnRegister {
                challenge,
                user: user.id,
                session: session.id,
                label,
                hardware_key,
            },
            ctx.now,
        )?;
        Ok(WebAuthnRegisterOptions {
            ceremony_id,
            public_key,
        })
    }

    /// `POST /auth/webauthn/register/finish`.
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`], the [`crate::webauthn::WebAuthnError`] of a refused
    /// registration (including a synced passkey for a security-key registration).
    pub async fn webauthn_register_finish(
        &self,
        ctx: &RequestCtx,
        request: &WebAuthnRegisterFinish,
    ) -> Result<FactorEnrolled, AuthError> {
        let (user, revision, _, session) = self.current(ctx).await?;
        let Pending::WebAuthnRegister {
            challenge,
            user: owner,
            session: started_in,
            label,
            hardware_key,
        } = self.ceremonies.take(&request.ceremony_id, ctx.now)?
        else {
            return Err(AuthError::ChallengeInvalid);
        };
        if owner != user.id || started_in != session.id {
            return Err(AuthError::ChallengeInvalid);
        }
        let rp = self.relying_party()?;
        let registered = rp.finish_registration(
            &request.credential,
            &challenge,
            &RegistrationPolicy {
                user_verification: UserVerification::Required,
                hardware_key_required: hardware_key || user.break_glass,
            },
            ctx.now,
        )?;
        let view = self.view().await?;
        if view
            .get_typed(&CREDENTIAL_IDS, &registered.credential_id)?
            .is_some()
        {
            return Err(crate::webauthn::WebAuthnError::CredentialExists.into());
        }
        let record = CredentialRecord {
            credential_id: registered.credential_id.clone(),
            user: user.id,
            label,
            public_key: registered.public_key,
            alg: registered.alg,
            sign_count: registered.sign_count,
            aaguid: registered.aaguid,
            backup_eligible: registered.backup_eligible,
            backup_state: registered.backup_state,
            attestation: registered.attestation,
            hardware_key: registered.hardware_key,
            transports: registered.transports,
            created_at: ctx.now,
            last_used_at: None,
        };
        let mut updated = user.clone();
        let recovery_codes = Self::fresh_recovery_codes(&mut updated)?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&CREDENTIAL_IDS, &record.credential_id, None);
        batch.put_typed(&CREDENTIAL_IDS, &record.credential_id, &user.id)?;
        batch.put_typed(
            &CREDENTIALS,
            &(user.id, record.credential_id.clone()),
            &record,
        )?;
        if recovery_codes.is_some() {
            batch.expect_typed(&USERS, &user.id, Some(revision));
            batch.put_typed(&USERS, &user.id, &updated)?;
        }
        batch.audit(
            Self::audit(
                actions::WEBAUTHN_REGISTER,
                vec![ObjectRef::from(user.id)],
                ctx,
            )
            .with_context("label", record.label.clone())
            .with_context("hardware_key", record.hardware_key.to_string())
            .with_context("backup_eligible", record.backup_eligible.to_string()),
        );
        self.commit(batch).await?;
        Ok(FactorEnrolled {
            recovery_codes,
            credential: Some(credential_info(&record)),
            reauthenticate: session.strength < self.required_for(&updated),
        })
    }

    /// `GET /auth/webauthn/credentials`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] or a store error.
    pub async fn list_credentials(
        &self,
        ctx: &RequestCtx,
    ) -> Result<Vec<CredentialInfo>, AuthError> {
        let user = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
        let view = self.view().await?;
        Ok(Self::user_credentials(view.as_ref(), user)?
            .iter()
            .map(credential_info)
            .collect())
    }

    /// `DELETE /auth/webauthn/credentials/{id}` (`id` in base64url).
    ///
    /// # Errors
    ///
    /// [`AuthError::StepUpRequired`], [`AuthError::NotFound`], [`AuthError::LastFactor`].
    pub async fn delete_credential(&self, ctx: &RequestCtx, id: &str) -> Result<(), AuthError> {
        let (user, _, _, session) = self.current(ctx).await?;
        Self::require_fresh(&session, ctx.now)?;
        let credential_id =
            base64url_decode(id).map_err(|_| AuthError::NotFound { kind: "credential" })?;
        let view = self.view().await?;
        let credentials = Self::user_credentials(view.as_ref(), user.id)?;
        let Some(record) = credentials
            .iter()
            .find(|record| record.credential_id == credential_id)
        else {
            return Err(AuthError::NotFound { kind: "credential" });
        };
        let remaining = credentials.len() - 1;
        let hardware_left = credentials
            .iter()
            .filter(|other| other.hardware_key && other.credential_id != credential_id)
            .count();
        if (user.break_glass && hardware_left == 0)
            || !self.keeps_required_strength(&user, user.totp.is_some(), remaining)
        {
            return Err(AuthError::LastFactor);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.delete_typed(&CREDENTIALS, &(user.id, credential_id.clone()));
        batch.delete_typed(&CREDENTIAL_IDS, &credential_id);
        batch.audit(
            Self::audit(
                actions::WEBAUTHN_REMOVE,
                vec![ObjectRef::from(user.id)],
                ctx,
            )
            .with_context("label", record.label.clone()),
        );
        self.commit(batch).await?;
        Ok(())
    }

    /// `POST /auth/recovery-codes`: replaces the recovery codes; shown once.
    ///
    /// # Errors
    ///
    /// [`AuthError::StepUpRequired`] without a fresh authentication, [`AuthError::Invalid`]
    /// for an account without TOTP or a passkey.
    pub async fn regenerate_recovery_codes(
        &self,
        ctx: &RequestCtx,
    ) -> Result<RecoveryCodes, AuthError> {
        let (user, revision, _, session) = self.current(ctx).await?;
        Self::require_fresh(&session, ctx.now)?;
        let view = self.view().await?;
        let credentials = Self::user_credentials(view.as_ref(), user.id)?.len();
        if !user.has_strong_factor(credentials) {
            return Err(AuthError::invalid(
                "recovery_codes",
                "enrol TOTP or a passkey before recovery codes",
            ));
        }
        let generated = recovery::generate()?;
        let mut updated = user.clone();
        updated.recovery_codes.clone_from(&generated.stored);
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&USERS, &user.id, Some(revision));
        batch.put_typed(&USERS, &user.id, &updated)?;
        batch.audit(Self::audit(
            actions::RECOVERY_REGENERATE,
            vec![ObjectRef::from(user.id)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(RecoveryCodes {
            codes: generated
                .display
                .iter()
                .map(|code| SecretString::new(code.as_str()))
                .collect(),
        })
    }

    /// `GET /auth/tokens`: the caller's personal tokens.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] or a store error.
    pub async fn list_tokens(&self, ctx: &RequestCtx) -> Result<Vec<TokenInfo>, AuthError> {
        let user = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
        let view = self.view().await?;
        let mut tokens = Vec::new();
        for (_, hash, _) in view.scan_typed(
            &USER_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(user,))),
            LIST_LIMIT,
            false,
        )? {
            if let Some((record, _)) = view.get_typed(&TOKENS, &hash)? {
                tokens.push(token_info(&record));
            }
        }
        Ok(tokens)
    }

    /// `POST /auth/tokens` (IAM-10): the token is shown once; its expiry is capped by
    /// TGL-05. Only an interactive session that meets the profile may create one.
    ///
    /// # Errors
    ///
    /// [`AuthError::TokenLifetime`], [`AuthError::StepUpRequired`], [`AuthError::Invalid`].
    pub async fn create_token(
        &self,
        ctx: &RequestCtx,
        request: &TokenCreate,
    ) -> Result<CreatedToken, AuthError> {
        let (user, _, _, session) = self.current(ctx).await?;
        if session.break_glass {
            return Err(AuthError::BreakGlassHardwareKeyOnly);
        }
        let required = self.required_for(&user);
        if !satisfies(session.strength, required) {
            return Err(AuthError::StepUpRequired {
                required: required.as_str(),
            });
        }
        let name = label("name", Some(&request.name), "")?;
        let settings = self.settings();
        let days = match (settings.token_max_days, request.expires_in_days) {
            (_, Some(0)) => {
                return Err(AuthError::invalid("expires_in_days", "at least one day"));
            }
            (Some(max), Some(days)) if days > max => {
                return Err(AuthError::TokenLifetime {
                    max_days: u64::from(max),
                });
            }
            (Some(max), None) => Some(max),
            (_, requested) => requested,
        };
        let expires_at = match days {
            None => None,
            Some(days) => Some(
                ctx.now
                    .checked_add(Duration::from_secs(u64::from(days) * 86_400))
                    .ok_or_else(|| {
                        AuthError::invalid("expires_in_days", "too far in the future")
                    })?,
            ),
        };
        let token = new_api_token()?;
        let record = TokenRecord {
            id: ApiTokenId::generate(),
            owner: user.id,
            name,
            created_at: ctx.now,
            expires_at,
            last_used_at: None,
            issued_with: session.strength,
            prefix: token.expose().chars().take(12).collect(),
        };
        let hash = token.hash();
        let mut batch = WriteBatch::for_request(ctx);
        batch.put_typed(&TOKENS, &hash, &record)?;
        batch.put_typed(&USER_TOKENS, &(user.id, record.id), &hash)?;
        let mut draft = Self::audit(
            actions::TOKEN_CREATE,
            vec![ObjectRef::from(user.id), ObjectRef::from(record.id)],
            ctx,
        )
        .with_context("name", record.name.clone());
        if let Some(expires_at) = expires_at {
            draft = draft.with_context("expires_at", expires_at.to_rfc3339());
        }
        batch.audit(draft);
        self.commit(batch).await?;
        Ok(CreatedToken {
            token: SecretString::new(token.expose()),
            info: token_info(&record),
        })
    }

    /// `DELETE /auth/tokens/{id}`: by its owner, or by an administrator.
    ///
    /// # Errors
    ///
    /// [`AuthError::NotFound`] or a store error.
    pub async fn revoke_token(&self, ctx: &RequestCtx, id: ApiTokenId) -> Result<(), AuthError> {
        let caller = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
        // A token may revoke itself (a client logging out), but no other token.
        if let Principal::Token { id: own, .. } = ctx.principal
            && own != id
        {
            return Err(AuthError::NotFound { kind: "token" });
        }
        let view = self.view().await?;
        // The owner's own token, or, for an administrator, anybody's.
        let mut found = view
            .get_typed(&USER_TOKENS, &(caller, id))?
            .map(|(hash, _)| (caller, hash));
        if found.is_none()
            && self
                .authorized(
                    ctx,
                    Action::Administer,
                    ObjectRef::new(ObjectKind::ApiToken, id.0),
                )
                .is_ok()
        {
            for (key, hash, _) in
                view.scan_typed(&USER_TOKENS, KeyRange::all(), LIST_LIMIT * 10, false)?
            {
                if key.1 == id {
                    found = Some((key.0, hash));
                    break;
                }
            }
        }
        let (owner, hash): (UserId, Vec<u8>) =
            found.ok_or(AuthError::NotFound { kind: "token" })?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.delete_typed(&TOKENS, &hash);
        batch.delete_typed(&USER_TOKENS, &(owner, id));
        batch.audit(Self::audit(
            actions::TOKEN_REVOKE,
            vec![ObjectRef::from(owner), ObjectRef::from(id)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(())
    }

    /// Re-reads a session record (tests and handlers that need the stored state).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn session_record(
        &self,
        user: UserId,
        session: SessionId,
    ) -> Result<Option<crate::model::SessionRecord>, AuthError> {
        let view = self.view().await?;
        Ok(Self::load_session(view.as_ref(), user, session)?.map(|(_, record)| record))
    }

    /// Whether a session row exists for the hash (tests).
    #[doc(hidden)]
    pub async fn session_exists(&self, hash: &[u8]) -> Result<bool, AuthError> {
        Ok(self
            .view()
            .await?
            .get_typed(&SESSIONS, &hash.to_vec())?
            .is_some())
    }
}
