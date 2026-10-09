//! Login ceremonies: password, TOTP and recovery code, WebAuthn (passkeys, security keys and
//! break-glass), and logout.

use std::time::Duration;

use tenko_core::{
    AuthStrength, MessageKey, ObjectRef, Principal, RequestCtx, Revision, SystemComponent, UserId,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::{ReadViewExt, WriteBatch};

use super::{
    AuthService, LoginOutcome, NewSession, actions, blocking,
    types::{
        CodeLogin, PasswordLogin, SecondFactorMethod, WebAuthnLoginFinish, WebAuthnLoginOptions,
        WebAuthnLoginStart,
    },
};
use crate::{
    challenge::{MAX_CODE_ATTEMPTS, Pending},
    error::AuthError,
    lockout::{LockoutMode, LockoutPolicy, Retry, ThrottleKey},
    model::{
        ALARMS, AccountLock, AlarmKind, AlarmRecord, CREDENTIAL_IDS, CREDENTIALS, PasswordKind,
        USERS, UserRecord,
    },
    password::{
        hash::{HashStrength, dummy_verify, hash_password, needs_rehash, verify_password},
        policy::{PasswordContext, normalize},
    },
    random, recovery,
    roles::satisfies,
    settings::{Profile, SecuritySettings},
    totp::{self, TotpParams},
    webauthn::{
        AssertionPolicy, CredentialDescriptor, StoredKey, UserVerification, WebAuthnError,
        assertion_credential_id,
    },
};

/// Longest user name kept as a throttle key or audit context.
const MAX_NAME_CHARS: usize = 128;

/// The rate limit of the break-glass account: it is never locked out (IAM-09).
fn break_glass_policy() -> LockoutPolicy {
    LockoutPolicy {
        mode: LockoutMode::ProgressiveDelay,
        free_attempts: 3,
        base_delay: Duration::from_secs(30),
        max_delay: Duration::from_secs(600),
        lock_after: 0,
        lock_duration: Duration::ZERO,
        reset_after: Duration::from_secs(3_600),
    }
}

fn break_glass_key(user: UserId) -> ThrottleKey {
    ThrottleKey::Account(format!("\u{1}break-glass:{user}"))
}

/// The Argon2id parameters for the settings: stronger under the Hardened profile.
pub(super) fn hash_strength(settings: &SecuritySettings) -> HashStrength {
    if settings.profile == Profile::Hardened {
        HashStrength::Hardened
    } else {
        HashStrength::Baseline
    }
}

fn throttled(retry: Retry) -> AuthError {
    AuthError::Throttled {
        retry_after: retry.after.map(|after| after.as_secs().max(1)),
    }
}

fn truncated(name: &str) -> String {
    name.trim().chars().take(MAX_NAME_CHARS).collect()
}

fn on_behalf_of(user: UserId) -> Principal {
    Principal::System {
        component: SystemComponent::Auth,
        on_behalf_of: Some(user),
    }
}

/// The second factors a password login must continue with: TOTP when enrolled, a passkey
/// when TOTP is enrolled or the password alone is below the required strength, and
/// recovery codes as a fallback for either.
fn second_factor_methods(
    user: &UserRecord,
    credentials: usize,
    first: AuthStrength,
    required: AuthStrength,
) -> Vec<SecondFactorMethod> {
    let mut methods = Vec::new();
    if user.totp.is_some() {
        methods.push(SecondFactorMethod::Totp);
    }
    if credentials > 0 && (user.totp.is_some() || !satisfies(first, required)) {
        methods.push(SecondFactorMethod::Webauthn);
    }
    if !methods.is_empty() && user.recovery_codes_left() > 0 {
        methods.push(SecondFactorMethod::Recovery);
    }
    methods
}

impl AuthService {
    /// After a correct password: rehashes with the current parameters when needed and flags
    /// a password that no longer meets the policy.
    async fn after_password(
        &self,
        view: &dyn tenko_store::ReadView,
        user: &UserRecord,
        stored: &crate::model::StoredPassword,
        normalized: zeroize::Zeroizing<String>,
        strength: HashStrength,
        settings: &SecuritySettings,
    ) -> Result<UserRecord, AuthError> {
        let mut updated = user.clone();
        if needs_rehash(&stored.hash, strength) {
            let candidate = normalized.clone();
            let rehashed = blocking(move || hash_password(&candidate, strength)).await??;
            if let Some(password) = updated.password.as_mut() {
                password.hash = rehashed;
            }
        }
        let host_name = view
            .get_typed(&crate::model::INSTALLATION, &())?
            .map(|(installation, _)| installation.host_name);
        let violations = settings.password_policy.check(
            normalized.as_str(),
            &PasswordContext {
                user_name: &user.name,
                display_name: Some(&user.display_name),
                host_name: host_name.as_deref(),
            },
        );
        if !violations.is_empty() {
            updated.password_change_required = true;
        }
        Ok(updated)
    }

    fn check_throttle(
        &self,
        account: &ThrottleKey,
        ctx: &RequestCtx,
        policy: &LockoutPolicy,
    ) -> Result<(), AuthError> {
        self.throttle
            .check(account, policy, ctx.now)
            .map_err(throttled)?;
        if policy.mode != LockoutMode::Off
            && let Some(ip) = ctx.source_ip
        {
            self.throttle
                .check(
                    &ThrottleKey::source(ip),
                    &LockoutPolicy::source_policy(),
                    ctx.now,
                )
                .map_err(throttled)?;
        }
        Ok(())
    }

    fn stage_alarm(
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        kind: AlarmKind,
        user: Option<UserId>,
    ) -> Result<(), AuthError> {
        let message = match kind {
            AlarmKind::BreakGlassLogin => MessageKey::from_static("auth.alarm.break_glass_login"),
            AlarmKind::BreakGlassFailure => {
                MessageKey::from_static("auth.alarm.break_glass_failure")
            }
            AlarmKind::AccountLocked => MessageKey::from_static("auth.alarm.account_locked"),
        };
        tracing::warn!(?kind, user = ?user, source = ?ctx.source_ip, "security alarm");
        batch.put_typed(
            &ALARMS,
            &uuid::Uuid::now_v7(),
            &AlarmRecord {
                at: ctx.now,
                kind,
                message,
                user,
                source_ip: ctx.source_ip,
            },
        )?;
        Ok(())
    }

    /// Records a failed login: in memory first, then one audit record (and a lock when the
    /// policy says so). Always answers [`AuthError::InvalidCredentials`].
    async fn login_failed(
        &self,
        ctx: &RequestCtx,
        account: &ThrottleKey,
        user: Option<(&UserRecord, Revision)>,
        action: AuditAction,
        attempted: &str,
        policy: &LockoutPolicy,
    ) -> AuthError {
        let outcome = self.throttle.record_failure(account, policy, ctx.now);
        if policy.mode != LockoutMode::Off
            && let Some(ip) = ctx.source_ip
        {
            self.throttle.record_failure(
                &ThrottleKey::source(ip),
                &LockoutPolicy::source_policy(),
                ctx.now,
            );
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), ctx.now);
        batch.request = Some(ctx.request);
        let objects = user
            .map(|(user, _)| vec![ObjectRef::from(user.id)])
            .unwrap_or_default();
        batch.audit(
            AuditDraft::failed(action, objects.clone(), &AuthError::InvalidCredentials)
                .with_source_ip(ctx.source_ip)
                .with_context("user_name", truncated(attempted)),
        );
        if let (Some(until), Some((user, revision))) = (outcome.locked_until, user) {
            let mut locked = user.clone();
            locked.lock = Some(AccountLock {
                since: ctx.now,
                until,
                until_unlock: policy.mode == LockoutMode::LockUntilUnlock,
            });
            batch.expect_typed(&USERS, &user.id, Some(revision));
            if let Err(error) = batch.put_typed(&USERS, &user.id, &locked) {
                tracing::error!(%error, "could not encode a locked user");
            }
            batch.audit(
                AuditDraft::success(actions::USER_LOCK, objects)
                    .with_source_ip(ctx.source_ip)
                    .with_context("until", until.to_rfc3339()),
            );
            if outcome.alert
                && let Err(error) =
                    Self::stage_alarm(&mut batch, ctx, AlarmKind::AccountLocked, Some(user.id))
            {
                tracing::error!(%error, "could not stage an alarm");
            }
        }
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a failed login");
        }
        AuthError::InvalidCredentials
    }

    fn find_user_versioned(
        view: &dyn tenko_store::ReadView,
        name: &str,
    ) -> Result<Option<(UserRecord, Revision)>, AuthError> {
        let Some((id, _)) =
            view.get_typed(&crate::model::USER_NAMES, &UserRecord::name_key(name))?
        else {
            return Ok(None);
        };
        Ok(view.get_typed(&USERS, &id)?)
    }

    /// `POST /auth/login/password` (IAM-03, IAM-05).
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] before any verification while the throttle holds,
    /// [`AuthError::InvalidCredentials`] for any wrong or unknown credential.
    pub async fn login_password(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        request: &PasswordLogin,
    ) -> Result<LoginOutcome, AuthError> {
        let settings = self.settings();
        let policy = LockoutPolicy::for_mode(settings.lockout);
        let account = ThrottleKey::account(&truncated(&request.user_name));
        self.check_throttle(&account, ctx, &policy)?;

        let view = self.view().await?;
        let found = Self::find_user_versioned(view.as_ref(), &request.user_name)?;
        let normalized = normalize(request.password.expose());
        let strength = hash_strength(&settings);
        let usable = found
            .filter(|(user, _)| !user.disabled && !user.break_glass && user.password.is_some());
        let Some((user, revision)) = usable else {
            let dummy = normalized.clone();
            blocking(move || dummy_verify(&dummy, strength)).await?;
            return Err(self
                .login_failed(
                    ctx,
                    &account,
                    None,
                    actions::LOGIN_PASSWORD,
                    &request.user_name,
                    &policy,
                )
                .await);
        };
        if let Some(lock) = user.active_lock(ctx.now) {
            return Err(AuthError::Throttled {
                retry_after: Some(lock.until.saturating_since(ctx.now).as_secs().max(1)),
            });
        }
        let Some(stored) = user.password.clone() else {
            return Err(AuthError::InvalidCredentials);
        };
        let candidate = normalized.clone();
        let hash = stored.hash.clone();
        let verified = blocking(move || verify_password(&candidate, &hash)).await??;
        if !verified {
            return Err(self
                .login_failed(
                    ctx,
                    &account,
                    Some((&user, revision)),
                    actions::LOGIN_PASSWORD,
                    &request.user_name,
                    &policy,
                )
                .await);
        }
        self.throttle.record_success(&account);

        let updated = self
            .after_password(
                view.as_ref(),
                &user,
                &stored,
                normalized,
                strength,
                &settings,
            )
            .await?;
        let first = match stored.kind {
            PasswordKind::Pin => AuthStrength::Pin,
            PasswordKind::Password => AuthStrength::Password,
        };
        let credentials = Self::user_credentials(view.as_ref(), user.id)?.len();
        let methods = second_factor_methods(&user, credentials, first, self.required_for(&user));

        let mut batch = WriteBatch::new(on_behalf_of(user.id), ctx.now);
        batch.request = Some(ctx.request);
        // Only a changed record is written, so concurrent logins of one account do not
        // conflict over the user row.
        if updated != user {
            batch.expect_typed(&USERS, &user.id, Some(revision));
            batch.put_typed(&USERS, &user.id, &updated)?;
        }
        if !methods.is_empty() {
            return self
                .open_second_factor(ctx, batch, &updated, first, methods)
                .await;
        }
        let (secret, record) = self.stage_session(
            &mut batch,
            &self.settings(),
            &updated,
            first,
            ctx.now,
            ctx.source_ip,
            user_agent,
            false,
        )?;
        batch.audit(Self::audit(
            actions::LOGIN_PASSWORD,
            vec![ObjectRef::from(user.id), ObjectRef::from(record.id)],
            ctx,
        ));
        Ok(LoginOutcome::Session(
            self.complete_login(batch, &updated, secret, record).await?,
        ))
    }

    /// Records the password step and opens the second-factor challenge.
    async fn open_second_factor(
        &self,
        ctx: &RequestCtx,
        mut batch: WriteBatch,
        user: &UserRecord,
        first: AuthStrength,
        methods: Vec<SecondFactorMethod>,
    ) -> Result<LoginOutcome, AuthError> {
        batch.audit(
            Self::audit(actions::LOGIN_PASSWORD, vec![ObjectRef::from(user.id)], ctx)
                .with_context("second_factor", "required"),
        );
        self.commit(batch).await?;
        let challenge_id = self.ceremonies.open(
            Pending::SecondFactor {
                user: user.id,
                first,
                attempts: 0,
            },
            ctx.now,
        )?;
        Ok(LoginOutcome::SecondFactor {
            challenge_id,
            methods,
        })
    }

    /// Takes a second-factor challenge and loads its user.
    async fn second_factor(
        &self,
        ctx: &RequestCtx,
        challenge_id: &str,
    ) -> Result<(Pending, UserRecord, Revision), AuthError> {
        let pending = self.ceremonies.take(challenge_id, ctx.now)?;
        let Pending::SecondFactor { user, .. } = &pending else {
            return Err(AuthError::ChallengeInvalid);
        };
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), *user)?;
        if user.disabled || user.break_glass {
            return Err(AuthError::InvalidCredentials);
        }
        Ok((pending, user, revision))
    }

    /// A wrong second-factor code: the challenge stays open for a few more attempts.
    async fn second_factor_failed(
        &self,
        ctx: &RequestCtx,
        challenge_id: &str,
        pending: Pending,
        user: &UserRecord,
        revision: Revision,
        action: AuditAction,
    ) -> AuthError {
        if let Pending::SecondFactor {
            user: id,
            first,
            attempts,
        } = pending
            && attempts + 1 < MAX_CODE_ATTEMPTS
        {
            self.ceremonies.put_back(
                challenge_id.to_owned(),
                Pending::SecondFactor {
                    user: id,
                    first,
                    attempts: attempts + 1,
                },
                ctx.now,
            );
        }
        let policy = LockoutPolicy::for_mode(self.settings().lockout);
        self.login_failed(
            ctx,
            &ThrottleKey::account(&truncated(&user.name)),
            Some((user, revision)),
            action,
            &user.name,
            &policy,
        )
        .await
    }

    /// `POST /auth/login/totp` (IAM-06).
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`], [`AuthError::Throttled`],
    /// [`AuthError::InvalidCredentials`] for a wrong or replayed code.
    pub async fn login_totp(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        request: &CodeLogin,
    ) -> Result<LoginOutcome, AuthError> {
        let (pending, user, revision) = self.second_factor(ctx, &request.challenge_id).await?;
        let policy = LockoutPolicy::for_mode(self.settings().lockout);
        let account = ThrottleKey::account(&truncated(&user.name));
        self.check_throttle(&account, ctx, &policy)?;
        let Some(factor) = user.totp.clone() else {
            return Err(AuthError::TotpNotEnrolled);
        };
        let seed = self
            .vault
            .get_system(&RequestCtx::system(SystemComponent::Auth), factor.secret)
            .await
            .map_err(|error| AuthError::internal(format!("vault: {error}")))?;
        let now_secs = u64::try_from(ctx.now.0.unix_timestamp()).unwrap_or(0);
        let Some(step) = totp::verify(
            seed.expose(),
            &TotpParams::default(),
            request.code.expose(),
            now_secs,
            factor.last_used_step,
        ) else {
            return Err(self
                .second_factor_failed(
                    ctx,
                    &request.challenge_id,
                    pending,
                    &user,
                    revision,
                    actions::LOGIN_TOTP,
                )
                .await);
        };
        self.throttle.record_success(&account);
        let mut updated = user.clone();
        if let Some(totp) = updated.totp.as_mut() {
            totp.last_used_step = Some(step);
        }
        self.finish_second_factor(
            ctx,
            user_agent,
            updated,
            revision,
            actions::LOGIN_TOTP,
            None,
        )
        .await
    }

    /// `POST /auth/login/recovery` (IAM-06): spends one recovery code.
    ///
    /// # Errors
    ///
    /// As [`AuthService::login_totp`].
    pub async fn login_recovery(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        request: &CodeLogin,
    ) -> Result<LoginOutcome, AuthError> {
        let (pending, user, revision) = self.second_factor(ctx, &request.challenge_id).await?;
        let policy = LockoutPolicy::for_mode(self.settings().lockout);
        let account = ThrottleKey::account(&truncated(&user.name));
        self.check_throttle(&account, ctx, &policy)?;
        let Some(index) = recovery::find(request.code.expose(), &user.recovery_codes) else {
            return Err(self
                .second_factor_failed(
                    ctx,
                    &request.challenge_id,
                    pending,
                    &user,
                    revision,
                    actions::LOGIN_RECOVERY,
                )
                .await);
        };
        self.throttle.record_success(&account);
        let mut updated = user.clone();
        if let Some(code) = updated.recovery_codes.get_mut(index) {
            code.used_at = Some(ctx.now);
        }
        let left = updated.recovery_codes_left();
        self.finish_second_factor(
            ctx,
            user_agent,
            updated,
            revision,
            actions::LOGIN_RECOVERY,
            Some(("recovery_codes_left", left.to_string())),
        )
        .await
    }

    async fn finish_second_factor(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        user: UserRecord,
        revision: Revision,
        action: AuditAction,
        context: Option<(&str, String)>,
    ) -> Result<LoginOutcome, AuthError> {
        let mut batch = WriteBatch::new(on_behalf_of(user.id), ctx.now);
        batch.request = Some(ctx.request);
        // The used TOTP step or recovery code: a concurrent second login with the same code
        // conflicts here.
        batch.expect_typed(&USERS, &user.id, Some(revision));
        batch.put_typed(&USERS, &user.id, &user)?;
        let (secret, record) = self.stage_session(
            &mut batch,
            &self.settings(),
            &user,
            AuthStrength::PasswordTotp,
            ctx.now,
            ctx.source_ip,
            user_agent,
            false,
        )?;
        let mut draft = Self::audit(
            action,
            vec![ObjectRef::from(user.id), ObjectRef::from(record.id)],
            ctx,
        );
        if let Some((key, value)) = context {
            draft = draft.with_context(key, value);
        }
        batch.audit(draft);
        Ok(LoginOutcome::Session(
            self.complete_login(batch, &user, secret, record).await?,
        ))
    }

    /// `POST /auth/webauthn/login/start`: a discoverable login, a login for a named
    /// account, or the passkey step of a password login.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unavailable`] before a host name exists, [`AuthError::ChallengeInvalid`]
    /// for an unknown password challenge.
    pub async fn webauthn_login_start(
        &self,
        ctx: &RequestCtx,
        request: &WebAuthnLoginStart,
    ) -> Result<WebAuthnLoginOptions, AuthError> {
        let rp = self.relying_party()?;
        let view = self.view().await?;
        let (user, continuation) = if let Some(challenge_id) = &request.challenge_id {
            match self.ceremonies.take(challenge_id, ctx.now)? {
                Pending::SecondFactor { user, .. } => (Some(user), true),
                _ => return Err(AuthError::ChallengeInvalid),
            }
        } else if let Some(name) = &request.user_name {
            // An unknown name gets the same answer as a discoverable login.
            let found = Self::find_user(view.as_ref(), name)?.filter(|user| !user.disabled);
            (found.map(|user| user.id), false)
        } else {
            (None, false)
        };
        let mut allow = Vec::new();
        let mut hardware = false;
        if let Some(id) = user {
            let (record, _) = Self::load_user(view.as_ref(), id)?;
            hardware = record.break_glass;
            allow = Self::user_credentials(view.as_ref(), id)?
                .into_iter()
                .filter(|credential| !hardware || credential.hardware_key)
                .map(|credential| {
                    CredentialDescriptor::new(&credential.credential_id, credential.transports)
                })
                .collect();
        }
        let challenge = random::array::<32>()?;
        let policy = AssertionPolicy {
            user_verification: if continuation {
                UserVerification::Preferred
            } else {
                UserVerification::Required
            },
            hardware_key_required: hardware,
        };
        let discoverable = allow.is_empty();
        let public_key = rp.request_options(&challenge, allow, &policy);
        let ceremony_id = self.ceremonies.open(
            Pending::WebAuthnLogin {
                challenge,
                user,
                discoverable,
                continuation,
            },
            ctx.now,
        )?;
        Ok(WebAuthnLoginOptions {
            ceremony_id,
            public_key,
        })
    }

    /// `POST /auth/webauthn/login/finish` (IAM-06, IAM-09).
    ///
    /// # Errors
    ///
    /// [`AuthError::ChallengeInvalid`], [`AuthError::InvalidCredentials`] for an unknown
    /// credential or a failed signature, [`AuthError::BreakGlassHardwareKeyOnly`],
    /// [`AuthError::Throttled`] for the break-glass rate limit, or the [`WebAuthnError`] of
    /// a malformed response.
    pub async fn webauthn_login_finish(
        &self,
        ctx: &RequestCtx,
        user_agent: Option<&str>,
        request: &WebAuthnLoginFinish,
    ) -> Result<NewSession, AuthError> {
        let Pending::WebAuthnLogin {
            challenge,
            user: expected,
            discoverable,
            continuation,
        } = self.ceremonies.take(&request.ceremony_id, ctx.now)?
        else {
            return Err(AuthError::ChallengeInvalid);
        };
        let credential_id = assertion_credential_id(&request.credential)?;
        let view = self.view().await?;
        let Some((owner, _)) = view.get_typed(&CREDENTIAL_IDS, &credential_id)? else {
            return Err(self.webauthn_failed(ctx, None).await);
        };
        if expected.is_some_and(|expected| expected != owner) {
            return Err(self.webauthn_failed(ctx, None).await);
        }
        let (user, revision) = Self::load_user(view.as_ref(), owner)?;
        if user.disabled {
            return Err(self.webauthn_failed(ctx, Some((&user, revision))).await);
        }
        if user.break_glass {
            self.throttle
                .check(&break_glass_key(user.id), &break_glass_policy(), ctx.now)
                .map_err(throttled)?;
        }
        let Some((credential, credential_revision)) =
            view.get_typed(&CREDENTIALS, &(owner, credential_id.clone()))?
        else {
            return Err(self.webauthn_failed(ctx, Some((&user, revision))).await);
        };
        if user.break_glass && !credential.hardware_key {
            self.webauthn_failed(ctx, Some((&user, revision))).await;
            return Err(AuthError::BreakGlassHardwareKeyOnly);
        }
        let verified = self
            .verify_login(
                ctx,
                &request.credential,
                &challenge,
                &credential,
                (&user, revision),
                discoverable,
                continuation,
            )
            .await?;
        if user.break_glass {
            self.throttle.record_success(&break_glass_key(user.id));
        }
        let strength = if !verified.user_verified {
            AuthStrength::PasswordTotp
        } else if credential.hardware_key {
            AuthStrength::HardwareKey
        } else {
            AuthStrength::Passkey
        };

        let mut updated_credential = credential.clone();
        updated_credential.sign_count = verified.sign_count;
        updated_credential.backup_state = verified.backup_state;
        updated_credential.last_used_at = Some(ctx.now);
        let mut batch = WriteBatch::new(on_behalf_of(user.id), ctx.now);
        batch.request = Some(ctx.request);
        batch.expect_typed(
            &CREDENTIALS,
            &(owner, credential_id.clone()),
            Some(credential_revision),
        );
        batch.put_typed(&CREDENTIALS, &(owner, credential_id), &updated_credential)?;
        let (secret, record) = self.stage_session(
            &mut batch,
            &self.settings(),
            &user,
            strength,
            ctx.now,
            ctx.source_ip,
            user_agent,
            user.break_glass,
        )?;
        let action = if user.break_glass {
            Self::stage_alarm(&mut batch, ctx, AlarmKind::BreakGlassLogin, Some(user.id))?;
            actions::LOGIN_BREAK_GLASS
        } else {
            actions::LOGIN_WEBAUTHN
        };
        batch.audit(
            Self::audit(
                action,
                vec![ObjectRef::from(user.id), ObjectRef::from(record.id)],
                ctx,
            )
            .with_context("credential", updated_credential.label.clone())
            .with_context("strength", strength.as_str()),
        );
        self.complete_login(batch, &user, secret, record).await
    }

    /// Verifies the assertion of a WebAuthn login against the stored credential and the
    /// account's user handle. Failures are audited (and alarmed for break-glass).
    #[allow(clippy::too_many_arguments)]
    async fn verify_login(
        &self,
        ctx: &RequestCtx,
        response: &crate::webauthn::AuthenticationResponse,
        challenge: &[u8],
        credential: &crate::model::CredentialRecord,
        (user, revision): (&UserRecord, Revision),
        discoverable: bool,
        continuation: bool,
    ) -> Result<crate::webauthn::VerifiedAssertion, AuthError> {
        let rp = self.relying_party()?;
        let policy = AssertionPolicy {
            user_verification: if continuation && !user.break_glass {
                UserVerification::Preferred
            } else {
                UserVerification::Required
            },
            hardware_key_required: user.break_glass,
        };
        let verified = match rp.finish_assertion(
            response,
            challenge,
            &StoredKey {
                credential_id: &credential.credential_id,
                public_key: &credential.public_key,
                sign_count: credential.sign_count,
                backup_eligible: credential.backup_eligible,
            },
            &policy,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                let failure = self.webauthn_failed(ctx, Some((user, revision))).await;
                return Err(match error {
                    WebAuthnError::SignatureInvalid
                    | WebAuthnError::CounterRegression
                    | WebAuthnError::CredentialMismatch => failure,
                    WebAuthnError::BackupEligibleRefused => AuthError::BreakGlassHardwareKeyOnly,
                    other => AuthError::WebAuthn(other),
                });
            }
        };
        let handle = user.user_handle();
        match &verified.user_handle {
            Some(returned) if returned.as_slice() != handle.as_slice() => {
                return Err(self.webauthn_failed(ctx, Some((user, revision))).await);
            }
            None if discoverable => {
                return Err(self.webauthn_failed(ctx, Some((user, revision))).await);
            }
            _ => {}
        }
        Ok(verified)
    }

    /// A failed WebAuthn login: audited, and for the break-glass account rate limited and
    /// alarmed.
    async fn webauthn_failed(
        &self,
        ctx: &RequestCtx,
        user: Option<(&UserRecord, Revision)>,
    ) -> AuthError {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), ctx.now);
        batch.request = Some(ctx.request);
        let objects = user
            .map(|(user, _)| vec![ObjectRef::from(user.id)])
            .unwrap_or_default();
        let break_glass = user.is_some_and(|(user, _)| user.break_glass);
        let action = if break_glass {
            actions::LOGIN_BREAK_GLASS
        } else {
            actions::LOGIN_WEBAUTHN
        };
        batch.audit(
            AuditDraft::failed(action, objects, &AuthError::InvalidCredentials)
                .with_source_ip(ctx.source_ip),
        );
        if let Some((user, _)) = user.filter(|(user, _)| user.break_glass) {
            self.throttle
                .record_failure(&break_glass_key(user.id), &break_glass_policy(), ctx.now);
            if let Err(error) =
                Self::stage_alarm(&mut batch, ctx, AlarmKind::BreakGlassFailure, Some(user.id))
            {
                tracing::error!(%error, "could not stage an alarm");
            }
        }
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a failed WebAuthn login");
        }
        AuthError::InvalidCredentials
    }

    /// `POST /auth/logout`: ends the session of the request.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] without a session, or a store error.
    pub async fn logout(&self, ctx: &RequestCtx) -> Result<String, AuthError> {
        let (user, session, _) = Self::session_principal(ctx)?;
        let view = self.view().await?;
        if let Some(found) = Self::load_session(view.as_ref(), user, session)? {
            let mut batch = WriteBatch::for_request(ctx);
            Self::stage_revoke(&mut batch, std::slice::from_ref(&found));
            batch.audit(Self::audit(
                actions::LOGOUT,
                vec![ObjectRef::from(user), ObjectRef::from(session)],
                ctx,
            ));
            self.commit(batch).await?;
        }
        Ok(self.clear_cookie())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_glass_is_rate_limited_but_never_locked() {
        let policy = break_glass_policy();
        assert_eq!(policy.mode, LockoutMode::ProgressiveDelay);
        assert!(policy.delay_after(10) <= Duration::from_secs(600));
        assert_ne!(
            break_glass_key(UserId::generate()),
            ThrottleKey::account("break-glass")
        );
    }

    #[test]
    fn hardened_hashes_harder() {
        assert_eq!(
            hash_strength(&Profile::Hardened.defaults()),
            HashStrength::Hardened
        );
        assert_eq!(
            hash_strength(&Profile::Home.defaults()),
            HashStrength::Baseline
        );
    }
}
