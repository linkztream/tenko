//! Administration: users, roles, the break-glass designation and the security settings.

use tenko_core::{
    Action, AuthStrength, ObjectKind, ObjectRef, RequestCtx, Revision, Timestamp, UserId,
    audit::FieldChange,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    AuthService, LIST_LIMIT,
    account::PasswordOwner,
    actions,
    types::{
        BreakGlassChange, FactorSummary, RoleInfo, SecuritySettingsView, UserCreate, UserInfo,
        UserUpdate,
    },
};
use crate::{
    error::AuthError,
    lockout::ThrottleKey,
    model::{
        CREDENTIAL_IDS, CREDENTIALS, CredentialRecord, INSTALLATION, LAST_LOGINS, SETTINGS, TOKENS,
        USER_NAMES, USER_TOKENS, USERS, UserRecord,
    },
    roles::{RoleName, satisfies},
    settings::{SettingsPatch, changes},
};

/// The counter that orders changes to the set of administrators.
const ADMINS: tenko_core::CounterKey = tenko_core::CounterKey::new("auth.admins");

/// Longest user name.
const MAX_NAME_CHARS: usize = 64;
/// Languages built into the UI (API-08).
pub(super) const LANGUAGES: [&str; 2] = ["en", "sv"];

/// Checks a login name: 1 to 64 characters, no whitespace or control characters.
pub(super) fn valid_user_name(name: &str) -> Result<String, AuthError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AuthError::invalid(
            "name",
            "1 to 64 characters without spaces or control characters",
        ));
    }
    Ok(name.to_owned())
}

pub(super) fn valid_language(language: &str) -> Result<String, AuthError> {
    if LANGUAGES.contains(&language) {
        Ok(language.to_owned())
    } else {
        Err(AuthError::invalid(
            "language",
            "supported languages are en and sv",
        ))
    }
}

fn valid_roles(roles: &[RoleName]) -> Result<Vec<RoleName>, AuthError> {
    let mut roles = roles.to_vec();
    roles.sort();
    roles.dedup();
    if roles.is_empty() {
        return Err(AuthError::invalid("roles", "at least one role"));
    }
    Ok(roles)
}

fn display_name(input: Option<&str>, name: &str) -> Result<String, AuthError> {
    let text = input.map_or(name, str::trim);
    if text.is_empty() || text.chars().count() > 128 || text.chars().any(char::is_control) {
        return Err(AuthError::invalid(
            "display_name",
            "1 to 128 visible characters",
        ));
    }
    Ok(text.to_owned())
}

fn user_info(
    user: &UserRecord,
    revision: Revision,
    credentials: &[CredentialRecord],
    last_login_at: Option<Timestamp>,
    now: Timestamp,
) -> UserInfo {
    UserInfo {
        id: user.id,
        name: user.name.clone(),
        display_name: user.display_name.clone(),
        roles: user.roles.clone(),
        disabled: user.disabled,
        break_glass: user.break_glass,
        lock: user.active_lock(now),
        factors: FactorSummary {
            password: user.password.is_some(),
            totp: user.totp.is_some(),
            webauthn: credentials.len(),
            hardware_keys: credentials.iter().filter(|c| c.hardware_key).count(),
            recovery_codes: user.recovery_codes_left(),
        },
        password_change_required: user.password_change_required,
        language: user.language.clone(),
        created_at: user.created_at,
        last_login_at,
        revision,
    }
}

impl AuthService {
    fn user_object(id: UserId) -> ObjectRef {
        ObjectRef::from(id)
    }

    fn info(view: &dyn ReadView, id: UserId, now: Timestamp) -> Result<UserInfo, AuthError> {
        let (user, revision) = Self::load_user(view, id)?;
        let credentials = Self::user_credentials(view, id)?;
        let last_login = view.get_typed(&LAST_LOGINS, &id)?.map(|(at, _)| at);
        Ok(user_info(&user, revision, &credentials, last_login, now))
    }

    /// A password set by an administrator for another account, checked against the policy.
    async fn reset_password(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        user: &UserRecord,
        password: &crate::service::types::SecretString,
    ) -> Result<crate::model::StoredPassword, AuthError> {
        if ctx.principal.user() == Some(user.id) {
            return Err(AuthError::invalid(
                "password",
                "change your own password with the current one (POST /auth/password)",
            ));
        }
        let host_name = view
            .get_typed(&INSTALLATION, &())?
            .map(|(installation, _)| installation.host_name);
        let (stored, _) = self
            .new_password(
                &self.settings(),
                password,
                &PasswordOwner {
                    user_name: &user.name,
                    display_name: Some(&user.display_name),
                    host_name: host_name.as_deref(),
                },
                ctx.now,
            )
            .await?;
        Ok(stored)
    }

    /// Adds the removal of every personal token of a user to a batch.
    fn stage_token_removal(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        id: UserId,
    ) -> Result<(), AuthError> {
        for (key, hash, _) in view.scan_typed(
            &USER_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(id,))),
            LIST_LIMIT,
            false,
        )? {
            batch.delete_typed(&TOKENS, &hash);
            batch.delete_typed(&USER_TOKENS, &key);
        }
        Ok(())
    }

    /// Serializes changes to the set of administrators: the batch expects the current value
    /// of the `auth.admins` counter and bumps it, so two concurrent changes that each leave
    /// one administrator cannot both commit (the second fails with a conflict and, retried,
    /// sees the first).
    fn guard_admins(view: &dyn ReadView, batch: &mut WriteBatch) -> Result<(), AuthError> {
        let current = view.counter(&ADMINS)?;
        batch.expect_counter(ADMINS, current);
        batch.bump(ADMINS);
        Ok(())
    }

    /// Active administrators other than `except` (break-glass accounts do not count).
    fn other_admins(view: &dyn ReadView, except: UserId) -> Result<usize, AuthError> {
        Ok(view
            .scan_typed(&USERS, KeyRange::all(), LIST_LIMIT, false)?
            .into_iter()
            .filter(|(id, user, _)| {
                *id != except && user.is_admin() && !user.disabled && !user.break_glass
            })
            .count())
    }

    /// `GET /users`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the read permission, or a store error.
    pub async fn list_users(&self, ctx: &RequestCtx) -> Result<Vec<UserInfo>, AuthError> {
        self.authorize(ctx, Action::Read, ObjectRef::singleton(ObjectKind::User))
            .await?;
        let view = self.view().await?;
        let mut users = Vec::new();
        for (id, user, revision) in view.scan_typed(&USERS, KeyRange::all(), LIST_LIMIT, false)? {
            let credentials = Self::user_credentials(view.as_ref(), id)?;
            let last_login = view.get_typed(&LAST_LOGINS, &id)?.map(|(at, _)| at);
            users.push(user_info(
                &user,
                revision,
                &credentials,
                last_login,
                ctx.now,
            ));
        }
        users.sort_by_key(|user| user.name.to_lowercase());
        Ok(users)
    }

    /// `GET /users/{id}`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn get_user(&self, ctx: &RequestCtx, id: UserId) -> Result<UserInfo, AuthError> {
        self.authorize(ctx, Action::Read, Self::user_object(id))
            .await?;
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `POST /users`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::UserNameTaken`], [`AuthError::Invalid`],
    /// [`AuthError::PasswordPolicy`].
    pub async fn create_user(
        &self,
        ctx: &RequestCtx,
        request: &UserCreate,
    ) -> Result<UserInfo, AuthError> {
        self.authorize(
            ctx,
            Action::Administer,
            ObjectRef::singleton(ObjectKind::User),
        )
        .await?;
        let name = valid_user_name(&request.name)?;
        let display_name = display_name(request.display_name.as_deref(), &name)?;
        let roles = valid_roles(&request.roles)?;
        let language = request
            .language
            .as_deref()
            .map(valid_language)
            .transpose()?;
        let view = self.view().await?;
        let key = UserRecord::name_key(&name);
        if view.get_typed(&USER_NAMES, &key)?.is_some() {
            return Err(AuthError::UserNameTaken);
        }
        let host_name = view
            .get_typed(&INSTALLATION, &())?
            .map(|(installation, _)| installation.host_name);
        let password = match &request.password {
            Some(password) => Some(
                self.new_password(
                    &self.settings(),
                    password,
                    &PasswordOwner {
                        user_name: &name,
                        display_name: Some(&display_name),
                        host_name: host_name.as_deref(),
                    },
                    ctx.now,
                )
                .await?
                .0,
            ),
            None => None,
        };
        let user = UserRecord {
            password_change_required: password.is_some(),
            password,
            language,
            ..UserRecord::new(name, display_name, roles, ctx.now)
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&USER_NAMES, &key, None);
        batch.put_typed(&USER_NAMES, &key, &user.id)?;
        batch.put_typed(&USERS, &user.id, &user)?;
        batch.audit(
            Self::audit(actions::USER_CREATE, vec![Self::user_object(user.id)], ctx)
                .with_context("name", user.name.clone())
                .with_context("roles", role_list(&user.roles)),
        );
        match self.commit(batch).await {
            Err(AuthError::Conflict) => return Err(AuthError::UserNameTaken),
            other => other?,
        };
        Self::info(self.view().await?.as_ref(), user.id, ctx.now)
    }

    /// `PATCH /users/{id}`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::NotFound`], [`AuthError::Conflict`] when
    /// `expect` is stale, [`AuthError::LastAdministrator`].
    pub async fn update_user(
        &self,
        ctx: &RequestCtx,
        id: UserId,
        request: &UserUpdate,
        expect: Option<Revision>,
    ) -> Result<UserInfo, AuthError> {
        self.authorize(ctx, Action::Administer, Self::user_object(id))
            .await?;
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        if expect.is_some_and(|expected| expected != revision) {
            return Err(AuthError::Conflict);
        }
        let mut updated = user.clone();
        let mut fields = Vec::new();
        if let Some(name) = &request.display_name {
            updated.display_name = display_name(Some(name), &user.name)?;
            fields.push(change(
                "display_name",
                &user.display_name,
                &updated.display_name,
            ));
        }
        if let Some(language) = &request.language {
            updated.language = if language.is_empty() {
                None
            } else {
                Some(valid_language(language)?)
            };
            fields.push(FieldChange {
                object: None,
                field: "language".to_owned(),
                old: user.language.clone(),
                new: updated.language.clone(),
            });
        }
        let mut revoke = false;
        if let Some(disabled) = request.disabled {
            if disabled && ctx.principal.user() == Some(id) {
                return Err(AuthError::invalid(
                    "disabled",
                    "you cannot disable your own account",
                ));
            }
            if disabled
                && user.is_admin()
                && !user.break_glass
                && Self::other_admins(view.as_ref(), id)? == 0
            {
                return Err(AuthError::LastAdministrator);
            }
            updated.disabled = disabled;
            revoke |= disabled;
            fields.push(change(
                "disabled",
                &user.disabled.to_string(),
                &disabled.to_string(),
            ));
        }
        if let Some(password) = &request.password {
            if user.break_glass {
                return Err(AuthError::BreakGlassHardwareKeyOnly);
            }
            updated.password = Some(
                self.reset_password(ctx, view.as_ref(), &user, password)
                    .await?,
            );
            updated.password_change_required = true;
            revoke = true;
            fields.push(FieldChange {
                object: None,
                field: "password".to_owned(),
                old: None,
                new: Some("reset".to_owned()),
            });
        }
        if updated == user {
            return Self::info(view.as_ref(), id, ctx.now);
        }
        let mut batch = WriteBatch::for_request(ctx);
        if user.is_admin() && updated.disabled != user.disabled {
            Self::guard_admins(view.as_ref(), &mut batch)?;
        }
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.put_typed(&USERS, &id, &updated)?;
        if revoke {
            Self::stage_revoke(&mut batch, &Self::user_sessions(view.as_ref(), id)?);
        }
        if updated.disabled && !user.disabled {
            // The personal tokens of a disabled account end with it, as its sessions do.
            Self::stage_token_removal(view.as_ref(), &mut batch, id)?;
        }
        let mut draft = Self::audit(actions::USER_UPDATE, vec![Self::user_object(id)], ctx);
        draft.details.changes = fields;
        batch.audit(draft);
        self.commit(batch).await?;
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `DELETE /users/{id}`: removes the account with its sessions, tokens, credentials
    /// and TOTP seed. Audit records keep the id.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::NotFound`], [`AuthError::LastAdministrator`],
    /// [`AuthError::Invalid`] for the caller's own account.
    pub async fn delete_user(&self, ctx: &RequestCtx, id: UserId) -> Result<(), AuthError> {
        self.authorize(ctx, Action::Administer, Self::user_object(id))
            .await?;
        if ctx.principal.user() == Some(id) {
            return Err(AuthError::invalid(
                "id",
                "you cannot delete your own account",
            ));
        }
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        if user.is_admin() && !user.break_glass && Self::other_admins(view.as_ref(), id)? == 0 {
            return Err(AuthError::LastAdministrator);
        }
        let mut batch = WriteBatch::for_request(ctx);
        if user.is_admin() {
            Self::guard_admins(view.as_ref(), &mut batch)?;
        }
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.delete_typed(&USERS, &id);
        batch.delete_typed(&USER_NAMES, &UserRecord::name_key(&user.name));
        Self::stage_revoke(&mut batch, &Self::user_sessions(view.as_ref(), id)?);
        Self::stage_token_removal(view.as_ref(), &mut batch, id)?;
        batch.delete_typed(&LAST_LOGINS, &id);
        for credential in Self::user_credentials(view.as_ref(), id)? {
            batch.delete_typed(&CREDENTIAL_IDS, &credential.credential_id);
            batch.delete_typed(&CREDENTIALS, &(id, credential.credential_id));
        }
        if let Some(totp) = &user.totp {
            self.vault.stage_delete(&mut batch, ctx, totp.secret);
        }
        batch.audit(
            Self::audit(actions::USER_DELETE, vec![Self::user_object(id)], ctx)
                .with_context("name", user.name.clone()),
        );
        self.commit(batch).await?;
        self.throttle.unlock(&ThrottleKey::account(&user.name));
        Ok(())
    }

    /// `POST /users/{id}/unlock` (IAM-05).
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn unlock_user(&self, ctx: &RequestCtx, id: UserId) -> Result<UserInfo, AuthError> {
        self.authorize(ctx, Action::Administer, Self::user_object(id))
            .await?;
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        self.throttle.unlock(&ThrottleKey::account(&user.name));
        if user.lock.is_some() {
            let mut updated = user.clone();
            updated.lock = None;
            let mut batch = WriteBatch::for_request(ctx);
            batch.expect_typed(&USERS, &id, Some(revision));
            batch.put_typed(&USERS, &id, &updated)?;
            batch.audit(Self::audit(
                actions::USER_UNLOCK,
                vec![Self::user_object(id)],
                ctx,
            ));
            self.commit(batch).await?;
        }
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `DELETE /users/{id}/sessions`: ends every session of the user.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn revoke_user_sessions(
        &self,
        ctx: &RequestCtx,
        id: UserId,
    ) -> Result<usize, AuthError> {
        self.authorize(ctx, Action::Administer, Self::user_object(id))
            .await?;
        let view = self.view().await?;
        Self::load_user(view.as_ref(), id)?;
        let sessions = Self::user_sessions(view.as_ref(), id)?;
        let settings = self.settings();
        let live = sessions
            .iter()
            .filter(|(_, session)| super::effective_expiry(session, &settings).0 > ctx.now)
            .count();
        let mut batch = WriteBatch::for_request(ctx);
        Self::stage_revoke(&mut batch, &sessions);
        batch.audit(
            Self::audit(actions::SESSION_REVOKE, vec![Self::user_object(id)], ctx)
                .with_context("sessions", live.to_string()),
        );
        self.commit(batch).await?;
        Ok(live)
    }

    /// `PUT /users/{id}/roles`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::LastAdministrator`], [`AuthError::Conflict`],
    /// [`AuthError::Invalid`] for the break-glass account (always `admin`).
    pub async fn set_user_roles(
        &self,
        ctx: &RequestCtx,
        id: UserId,
        roles: &[RoleName],
        expect: Option<Revision>,
    ) -> Result<UserInfo, AuthError> {
        self.authorize(ctx, Action::Administer, Self::user_object(id))
            .await?;
        let roles = valid_roles(roles)?;
        let view = self.view().await?;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        if expect.is_some_and(|expected| expected != revision) {
            return Err(AuthError::Conflict);
        }
        if user.break_glass {
            return Err(AuthError::invalid(
                "roles",
                "the break-glass account is always admin",
            ));
        }
        if user.is_admin()
            && !roles.contains(&RoleName::Admin)
            && !user.disabled
            && Self::other_admins(view.as_ref(), id)? == 0
        {
            return Err(AuthError::LastAdministrator);
        }
        let mut updated = user.clone();
        updated.roles.clone_from(&roles);
        let mut batch = WriteBatch::for_request(ctx);
        if user.is_admin() != updated.is_admin() {
            Self::guard_admins(view.as_ref(), &mut batch)?;
        }
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.put_typed(&USERS, &id, &updated)?;
        batch.audit(
            Self::audit(actions::USER_ROLES, vec![Self::user_object(id)], ctx).with_change(change(
                "roles",
                &role_list(&user.roles),
                &role_list(&roles),
            )),
        );
        self.commit(batch).await?;
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `GET /roles`.
    pub fn roles(&self) -> Vec<RoleInfo> {
        RoleName::ALL
            .into_iter()
            .map(|name| RoleInfo {
                name,
                description: name.description().to_owned(),
            })
            .collect()
    }

    /// `PUT /system/break-glass` (IAM-09): designates the break-glass account, which then
    /// logs in with an attested, non-backup-eligible security key only, is rate limited
    /// instead of locked out, and raises an alarm at every use. Needs a fresh, strong
    /// authentication of the administrator, and the account must already hold a hardware
    /// security key.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::StepUpRequired`], [`AuthError::Invalid`] when the
    /// account has no hardware key.
    pub async fn set_break_glass(
        &self,
        ctx: &RequestCtx,
        request: &BreakGlassChange,
    ) -> Result<UserInfo, AuthError> {
        self.authorize(
            ctx,
            Action::Administer,
            ObjectRef::singleton(ObjectKind::System),
        )
        .await?;
        let (caller, session_id, strength) = Self::session_principal(ctx)?;
        if !satisfies(strength, AuthStrength::PasswordTotp) {
            return Err(AuthError::StepUpRequired {
                required: AuthStrength::PasswordTotp.as_str(),
            });
        }
        let view = self.view().await?;
        let (_, session) = Self::load_session(view.as_ref(), caller, session_id)?
            .ok_or(AuthError::Unauthenticated)?;
        Self::require_fresh(&session, ctx.now)?;
        let id = request.user_id;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        if user.break_glass == request.enabled {
            return Self::info(view.as_ref(), id, ctx.now);
        }
        let credentials = Self::user_credentials(view.as_ref(), id)?;
        let mut updated = user.clone();
        let mut batch = WriteBatch::for_request(ctx);
        Self::guard_admins(view.as_ref(), &mut batch)?;
        if request.enabled {
            if !credentials.iter().any(|credential| credential.hardware_key) {
                return Err(AuthError::invalid(
                    "user_id",
                    "register an attested hardware security key for the account first",
                ));
            }
            if !user.break_glass && user.is_admin() && Self::other_admins(view.as_ref(), id)? == 0 {
                return Err(AuthError::LastAdministrator);
            }
            updated.break_glass = true;
            updated.roles = vec![RoleName::Admin];
            // Its password sessions and tokens end: from now on only the key logs it in.
            Self::stage_revoke(&mut batch, &Self::user_sessions(view.as_ref(), id)?);
            Self::stage_token_removal(view.as_ref(), &mut batch, id)?;
        } else {
            updated.break_glass = false;
            Self::stage_revoke(
                &mut batch,
                &Self::user_sessions(view.as_ref(), id)?
                    .into_iter()
                    .filter(|(_, record)| record.break_glass)
                    .collect::<Vec<_>>(),
            );
        }
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.put_typed(&USERS, &id, &updated)?;
        batch.audit(
            Self::audit(actions::BREAK_GLASS_SET, vec![Self::user_object(id)], ctx).with_change(
                change(
                    "break_glass",
                    &user.break_glass.to_string(),
                    &updated.break_glass.to_string(),
                ),
            ),
        );
        self.commit(batch).await?;
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    async fn settings_view(&self) -> Result<SecuritySettingsView, AuthError> {
        let stored = self.stored_settings().await?;
        let (settings, revision) = match stored {
            Some((settings, revision)) => (settings, Some(revision)),
            None => (self.settings(), None),
        };
        Ok(SecuritySettingsView {
            toggles: settings.toggles(),
            banner: settings.banner(),
            settings,
            vault_has_operator_secrets: self.has_operator_secrets().await?,
            revision,
        })
    }

    /// `GET /settings/security`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or a store error.
    pub async fn security_settings(
        &self,
        ctx: &RequestCtx,
    ) -> Result<SecuritySettingsView, AuthError> {
        self.authorize(
            ctx,
            Action::Read,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        self.settings_view().await
    }

    /// `PATCH /settings/security`: applies a profile and toggles, audited with the old and
    /// new value of each changed toggle. Refuses the PIN preset as a sole factor while the
    /// vault holds operator secrets (IAM-07).
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::Conflict`] when `expect` is stale,
    /// [`AuthError::Invalid`], [`AuthError::PinCoupling`], [`AuthError::Unavailable`]
    /// before setup.
    pub async fn update_security_settings(
        &self,
        ctx: &RequestCtx,
        patch: &SettingsPatch,
        expect: Option<Revision>,
    ) -> Result<SecuritySettingsView, AuthError> {
        self.authorize(
            ctx,
            Action::Update,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        let (current, revision) = self
            .stored_settings()
            .await?
            .ok_or(AuthError::Unavailable("setup has not completed"))?;
        if expect.is_some_and(|expected| expected != revision) {
            return Err(AuthError::Conflict);
        }
        let next = patch.apply(&current);
        next.validate()?;
        // With MFA for administrators or for everyone, the accounts that can reach the vault
        // need a second factor already; only "optional" leaves a PIN on its own.
        if super::account::admits_pin(&next.password_policy)
            && next.mfa == crate::settings::MfaRequirement::Optional
            && self.has_operator_secrets().await?
        {
            let mut batch = WriteBatch::for_request(ctx);
            batch.idempotency = None;
            batch.audit(
                tenko_core::audit::AuditDraft::failed(
                    actions::SETTINGS_UPDATE,
                    vec![ObjectRef::singleton(ObjectKind::Settings)],
                    &AuthError::PinCoupling,
                )
                .with_source_ip(ctx.source_ip),
            );
            if let Err(error) = self.store.propose(batch).await {
                tracing::warn!(%error, "could not record a refused settings change");
            }
            return Err(AuthError::PinCoupling);
        }
        if next != current {
            let mut batch = WriteBatch::for_request(ctx);
            batch.expect_typed(&SETTINGS, &(), Some(revision));
            batch.put_typed(&SETTINGS, &(), &next)?;
            let mut draft = Self::audit(
                actions::SETTINGS_UPDATE,
                vec![ObjectRef::singleton(ObjectKind::Settings)],
                ctx,
            )
            .with_context("profile", next.profile.as_str());
            draft.details.changes = changes(&current, &next);
            batch.audit(draft);
            self.commit(batch).await?;
        }
        self.settings_view().await
    }
}

fn change(field: &str, old: &str, new: &str) -> FieldChange {
    FieldChange {
        object: None,
        field: field.to_owned(),
        old: Some(old.to_owned()),
        new: Some(new.to_owned()),
    }
}

fn role_list(roles: &[RoleName]) -> String {
    roles
        .iter()
        .map(|role| role.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_names_are_checked() {
        assert_eq!(valid_user_name("  admin ").expect("valid"), "admin");
        assert!(valid_user_name("").is_err());
        assert!(valid_user_name("two words").is_err());
        assert!(valid_user_name(&"x".repeat(65)).is_err());
        assert!(valid_language("sv").is_ok());
        assert!(valid_language("de").is_err());
        assert!(valid_roles(&[]).is_err());
        assert_eq!(
            valid_roles(&[RoleName::Viewer, RoleName::Admin, RoleName::Viewer]).expect("roles"),
            vec![RoleName::Admin, RoleName::Viewer]
        );
    }
}
