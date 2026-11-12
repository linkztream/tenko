//! Administration: users, roles, the break-glass designation and the security settings.

use tenko_core::{
    Action, AuthStrength, ObjectKind, ObjectRef, RequestCtx, Revision, Timestamp, UserId,
    audit::{AuditDraft, FieldChange},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    AuthService, LIST_LIMIT,
    account::PasswordOwner,
    actions,
    end::EndReason,
    types::{
        BreakGlassChange, FactorSummary, RoleInfo, SecuritySettingsView, UserCreate, UserInfo,
        UserUpdate,
    },
};
use crate::{
    authz::AuthImage,
    error::AuthError,
    model::{
        AccountLock, CREDENTIAL_IDS, CREDENTIALS, CredentialRecord, INSTALLATION, LAST_LOGINS,
        LOCKS, SETTINGS, USER_NAMES, USERS, UserRecord,
    },
    roles::{RoleName, satisfies},
    settings::{AuditExport, MfaRequirement, SecuritySettings, SettingsPatch, changes},
};

/// The counter that orders changes to the set of administrators.
const ADMINS: tenko_core::CounterKey = tenko_core::CounterKey::new("auth.admins");

/// Longest user name.
const MAX_NAME_CHARS: usize = 64;

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

/// Checks a language against the active set of the authorization index: the built-in
/// languages and the active language packs (API-21).
pub(super) fn valid_language(language: &str, image: &AuthImage) -> Result<String, AuthError> {
    if image.is_language(language) {
        Ok(language.to_owned())
    } else {
        Err(AuthError::invalid(
            "language",
            format!("supported languages are {}", image.languages().join(", ")),
        ))
    }
}

/// Sorts and deduplicates global roles. An empty list is valid: the account then acts
/// through scoped grants only (IAM-01).
pub(super) fn valid_roles(roles: &[RoleName]) -> Vec<RoleName> {
    let mut roles = roles.to_vec();
    roles.sort();
    roles.dedup();
    roles
}

pub(super) fn display_name(input: Option<&str>, name: &str) -> Result<String, AuthError> {
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
    lock: Option<AccountLock>,
    pin_expires_at: Option<Timestamp>,
) -> UserInfo {
    UserInfo {
        id: user.id,
        name: user.name.clone(),
        display_name: user.display_name.clone(),
        roles: user.roles.clone(),
        disabled: user.disabled,
        break_glass: user.break_glass,
        lock,
        factors: FactorSummary {
            password: user.password.is_some(),
            totp: user.totp.is_some(),
            webauthn: credentials.len(),
            hardware_keys: credentials.iter().filter(|c| c.hardware_key).count(),
            recovery_codes: user.recovery_codes_left(),
        },
        // A PIN from before the six-digit minimum counts as one to change until a sign-in
        // shows it is long enough.
        password_change_required: user.password_change_required
            || user
                .password
                .as_ref()
                .is_some_and(crate::model::StoredPassword::unconfirmed_pin),
        pin_expires_at,
        language: user.language.clone(),
        created_at: user.created_at,
        last_login_at,
        revision,
        kind: user.kind,
        owner: user.owner,
    }
}

/// Adds the unlock of `user` to `batch`: every stored lock of the name is removed, the lock
/// of a record from before locks were per network is cleared, and `unlocked_at` is set so
/// that every controller forgets the account's waits and locks in memory. Returns whether
/// any lock was stored.
fn stage_unlock(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    user: &UserRecord,
    revision: Revision,
    now: Timestamp,
) -> Result<bool, AuthError> {
    let mut locked = user.lock.is_some();
    for (key, _) in AuthService::stored_locks(view, &user.name)? {
        batch.delete_typed(&LOCKS, &key);
        locked = true;
    }
    let mut updated = user.clone();
    updated.lock = None;
    updated.unlocked_at = Some(now);
    batch.expect_typed(&USERS, &user.id, Some(revision));
    batch.put_typed(&USERS, &user.id, &updated)?;
    Ok(locked)
}

/// An account is given the admin role only with a secret that meets the administrator rule
/// (a password of at least 12 characters that is not digits only), or with none (a passkey
/// account): an account that signs in with a PIN, or with a password not yet seen to meet
/// the rule, is refused.
///
/// # Errors
///
/// [`AuthError::Invalid`] on `roles` naming what to do first.
fn refuse_pin_administrator(user: &UserRecord) -> Result<(), AuthError> {
    let Some(password) = user.password.as_ref() else {
        return Ok(());
    };
    if password.kind == crate::model::PasswordKind::Pin {
        return Err(AuthError::invalid(
            "roles",
            "this account signs in with a PIN; give it a password of at least 12 characters \
             that is not digits only before making it an administrator",
        ));
    }
    if !password.admin_rule_met {
        return Err(AuthError::invalid(
            "roles",
            "this account's password is not known to have at least 12 characters and not only \
             digits; set such a password, or sign in with it once, before making it an \
             administrator",
        ));
    }
    Ok(())
}

/// Removes the stored locks of `name` that a first batch could not hold (more than a
/// listing's worth), in further batches until none is left.
async fn delete_remaining_locks(
    store: &dyn tenko_store::Store,
    name: &str,
    now: Timestamp,
) -> Result<(), AuthError> {
    // Each round removes a listing's worth; the rounds are bounded so a store that keeps
    // refusing cannot hold the request forever.
    for _ in 0..1_000 {
        let view = store.read(tenko_store::ReadConsistency::Local).await?;
        let locks = AuthService::stored_locks(view.as_ref(), name)?;
        if locks.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Auth),
            now,
        );
        for (key, _) in &locks {
            batch.delete_typed(&LOCKS, key);
        }
        store.propose(batch).await?;
    }
    Ok(())
}

/// What [`unlock_offline`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUnlock {
    /// The account, by its stored name.
    pub name: String,
    /// The locks that held at the time and were lifted.
    pub lifted: usize,
    /// The account's PIN from before the six-digit minimum had passed the end of its
    /// period; a new period started, and the PIN must be changed at the next sign-in.
    pub pin_renewed: bool,
}

/// Unlocks the account named `name` in the store of a stopped controller (`tenko user
/// unlock`): removes every stored lock of the name and sets `unlocked_at`, in one batch
/// with the audit record `auth.user.unlock` (context `via: offline`). A PIN from before the
/// six-digit minimum whose period has ended gets a new period and must be changed at the
/// next sign-in. Any account can be unlocked this way, an administrator included; the waits
/// a running server kept in memory end with that server.
///
/// # Errors
///
/// [`AuthError::NotFound`] for an unknown name, or the store's error.
pub async fn unlock_offline(
    store: &dyn tenko_store::Store,
    name: &str,
    now: Timestamp,
) -> Result<OfflineUnlock, AuthError> {
    let view = store.read(tenko_store::ReadConsistency::Local).await?;
    let Some((id, _)) = view.get_typed(&crate::model::USER_NAMES, &UserRecord::name_key(name))?
    else {
        return Err(AuthError::NotFound { kind: "user" });
    };
    let (mut user, revision) = AuthService::load_user(view.as_ref(), id)?;
    let pin_renewed =
        AuthService::pin_expiry_of(view.as_ref(), &user)?.is_some_and(|end| now >= end);
    if pin_renewed {
        if let Some(password) = user.password.as_mut() {
            password.pin_grace_from = Some(now);
            password.pin_expiry_noticed_at = None;
        }
        user.password_change_required = true;
    }
    let lifted = AuthService::stored_locks(view.as_ref(), &user.name)?
        .iter()
        .filter(|(_, lock)| now < lock.until)
        .count()
        + usize::from(user.legacy_lock(now).is_some());
    let mut batch = WriteBatch::new(
        tenko_core::Principal::System {
            component: tenko_core::SystemComponent::Auth,
            on_behalf_of: None,
        },
        now,
    );
    stage_unlock(&mut batch, view.as_ref(), &user, revision, now)?;
    batch.audit(
        AuditDraft::success(actions::USER_UNLOCK, vec![ObjectRef::from(user.id)])
            .with_context("via", "offline")
            .with_context("locks", lifted.to_string())
            .with_context("pin_renewed", pin_renewed.to_string()),
    );
    match store.propose(batch).await {
        Ok(_) => {
            delete_remaining_locks(store, &user.name, now).await?;
            Ok(OfflineUnlock {
                name: user.name,
                lifted,
                pin_renewed,
            })
        }
        Err(tenko_store::StoreError::PreconditionFailed(_)) => Err(AuthError::Conflict),
        Err(error) => Err(error.into()),
    }
}

impl AuthService {
    fn user_object(id: UserId) -> ObjectRef {
        ObjectRef::from(id)
    }

    /// The end of the period of the account's unconfirmed PIN, if it has one.
    fn pin_expiry_of(
        view: &dyn ReadView,
        user: &UserRecord,
    ) -> Result<Option<Timestamp>, AuthError> {
        let Some(stored) = user
            .password
            .as_ref()
            .filter(|stored| stored.unconfirmed_pin())
        else {
            return Ok(None);
        };
        Ok(stored.pin_expires_at(
            super::pins::pin_rule_since(view)?,
            super::pins::stored_pin_days(view)?,
        ))
    }

    fn info(view: &dyn ReadView, id: UserId, now: Timestamp) -> Result<UserInfo, AuthError> {
        let (user, revision) = Self::load_user(view, id)?;
        let credentials = Self::user_credentials(view, id)?;
        let last_login = view.get_typed(&LAST_LOGINS, &id)?.map(|(at, _)| at);
        let lock = Self::shown_lock(view, &user, now)?;
        let expires = Self::pin_expiry_of(view, &user)?;
        Ok(user_info(
            &user,
            revision,
            &credentials,
            last_login,
            lock,
            expires,
        ))
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
                    administers: user.is_admin(),
                },
                ctx.now,
            )
            .await?;
        Ok(stored)
    }

    /// Whether `user` may be disabled (or enabled again) by the caller: not the caller's own
    /// account, not the last administrator, and for the break-glass account only with the
    /// step-up its designation needs.
    async fn check_disable(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        user: &UserRecord,
        disabled: bool,
    ) -> Result<(), AuthError> {
        if user.break_glass && disabled != user.disabled {
            self.require_break_glass_step_up(ctx).await?;
        }
        if disabled && ctx.principal.user() == Some(user.id) {
            return Err(AuthError::invalid(
                "disabled",
                "you cannot disable your own account",
            ));
        }
        if disabled && Self::guarded(user) && Self::other_admins(view, user.id)? == 0 {
            return Err(AuthError::LastAdministrator);
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

    /// Active administrators other than `except`: people who can sign in and administer.
    /// Break-glass accounts do not count, and neither do service accounts, which act through
    /// tokens, and tokens never administer.
    fn other_admins(view: &dyn ReadView, except: UserId) -> Result<usize, AuthError> {
        Ok(view
            .scan_typed(&USERS, KeyRange::all(), LIST_LIMIT, false)?
            .into_iter()
            .filter(|(id, user, _)| {
                *id != except
                    && user.is_admin()
                    && !user.disabled
                    && !user.break_glass
                    && !user.is_service()
            })
            .count())
    }

    /// Whether the last-administrator guard holds for `user`: a person with the admin role
    /// other than the break-glass account. Removing anyone else never takes the last person
    /// who administers.
    fn guarded(user: &UserRecord) -> bool {
        user.is_admin() && !user.break_glass && !user.is_service()
    }

    /// The step-up a change that can remove the break-glass account needs (IAM-09): a
    /// session of at least password and TOTP that authenticated within the last five
    /// minutes, as designating or releasing the account needs.
    async fn require_break_glass_step_up(&self, ctx: &RequestCtx) -> Result<(), AuthError> {
        let (caller, session_id, strength) = Self::session_principal(ctx)?;
        if !satisfies(strength, AuthStrength::PasswordTotp) {
            return Err(AuthError::StepUpRequired {
                required: AuthStrength::PasswordTotp.as_str(),
            });
        }
        let view = self.view().await?;
        let (_, session) = Self::load_session(view.as_ref(), caller, session_id)?
            .ok_or(AuthError::Unauthenticated)?;
        Self::require_fresh(&session, ctx.now)
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
            let lock = Self::shown_lock(view.as_ref(), &user, ctx.now)?;
            let expires = Self::pin_expiry_of(view.as_ref(), &user)?;
            users.push(user_info(
                &user,
                revision,
                &credentials,
                last_login,
                lock,
                expires,
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
        let roles = valid_roles(&request.roles);
        let language = request
            .language
            .as_deref()
            .map(|language| valid_language(language, &self.index.image()))
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
                        administers: roles.contains(&RoleName::Admin),
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
                Some(valid_language(language, &self.index.image())?)
            };
            fields.push(FieldChange {
                object: None,
                field: "language".to_owned(),
                old: user.language.clone(),
                new: updated.language.clone(),
            });
        }
        // A disabled account acts nowhere, and a reset answers a compromised one.
        let mut ends = None;
        if let Some(disabled) = request.disabled {
            self.check_disable(ctx, view.as_ref(), &user, disabled)
                .await?;
            updated.disabled = disabled;
            ends = disabled.then_some(EndReason::Disable);
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
            if user.is_service() {
                return Err(AuthError::ServiceAccountNoLogin);
            }
            if !user.source.is_local() {
                return Err(super::account::directory_has_no_password("password"));
            }
            updated.password = Some(
                self.reset_password(ctx, view.as_ref(), &user, password)
                    .await?,
            );
            updated.password_change_required = true;
            ends = Some(EndReason::PasswordReset);
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
        let end = ends
            .map(|reason| self.stage_account_end(view.as_ref(), &mut batch, &mut updated, reason))
            .transpose()?;
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.put_typed(&USERS, &id, &updated)?;
        // A delegation needs its source: grants issued under a disabled account's end too.
        let grants = if updated.disabled && !user.disabled {
            Self::stage_grant_removal(view.as_ref(), &mut batch, id)?
        } else {
            0
        };
        let mut draft = Self::audit(actions::USER_UPDATE, vec![Self::user_object(id)], ctx);
        draft.details.changes = fields;
        if grants > 0 {
            draft = draft.with_context("grants_revoked", grants.to_string());
        }
        if let Some(end) = &end {
            draft = end.annotate(draft);
        }
        batch.audit(draft);
        let committed = self.commit(batch).await?;
        if let Some(end) = &end {
            self.finish_account_end(end, committed.revision, ctx.now)
                .await;
        }
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `DELETE /users/{id}`: removes the account with its sessions, tokens, credentials,
    /// TOTP seed and preferences. Audit records keep the id.
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
        if user.break_glass {
            self.require_break_glass_step_up(ctx).await?;
        }
        if Self::guarded(&user) && Self::other_admins(view.as_ref(), id)? == 0 {
            return Err(AuthError::LastAdministrator);
        }
        let mut batch = WriteBatch::for_request(ctx);
        if user.is_admin() {
            Self::guard_admins(view.as_ref(), &mut batch)?;
        }
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.delete_typed(&USERS, &id);
        batch.delete_typed(&USER_NAMES, &UserRecord::name_key(&user.name));
        let end = self.stage_account_end(
            view.as_ref(),
            &mut batch,
            &mut user.clone(),
            EndReason::Delete,
        )?;
        let grants = Self::stage_grant_removal(view.as_ref(), &mut batch, id)?;
        batch.delete_typed(&LAST_LOGINS, &id);
        Self::stage_preference_removal(view.as_ref(), &mut batch, id)?;
        for credential in Self::user_credentials(view.as_ref(), id)? {
            batch.delete_typed(&CREDENTIAL_IDS, &credential.credential_id);
            batch.delete_typed(&CREDENTIALS, &(id, credential.credential_id));
        }
        if let Some(totp) = &user.totp {
            self.vault.stage_delete(&mut batch, ctx, totp.secret);
        }
        let mut draft = end.annotate(
            Self::audit(actions::USER_DELETE, vec![Self::user_object(id)], ctx)
                .with_context("name", user.name.clone()),
        );
        if grants > 0 {
            draft = draft.with_context("grants_revoked", grants.to_string());
        }
        batch.audit(draft);
        let committed = self.commit(batch).await?;
        self.finish_account_end(&end, committed.revision, ctx.now)
            .await;
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
        self.throttle.unlock_account(&user.name);
        // The record is written even without a persisted lock: the other controllers clear
        // their in-memory throttle when they see `unlocked_at` change (WP3.2). Only lifting
        // a persisted lock is an audited change of the account.
        let mut batch = WriteBatch::for_request(ctx);
        if stage_unlock(&mut batch, view.as_ref(), &user, revision, ctx.now)? {
            batch.audit(Self::audit(
                actions::USER_UNLOCK,
                vec![Self::user_object(id)],
                ctx,
            ));
        }
        self.commit(batch).await?;
        delete_remaining_locks(self.store.as_ref(), &user.name, ctx.now).await?;
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `DELETE /users/{id}/sessions`: ends every session of the user and forgets the
    /// account's known devices, so it is signed out everywhere; its tokens stay. Returns how
    /// many sessions had not expired.
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
        let (mut user, revision) = Self::load_user(view.as_ref(), id)?;
        let mut batch = WriteBatch::for_request(ctx);
        let end = self.stage_account_end(
            view.as_ref(),
            &mut batch,
            &mut user,
            EndReason::SignOutEverywhere,
        )?;
        batch.expect_typed(&USERS, &id, Some(revision));
        batch.put_typed(&USERS, &id, &user)?;
        batch.audit(
            end.annotate(
                Self::audit(actions::SESSION_REVOKE, vec![Self::user_object(id)], ctx)
                    .with_context("sessions", end.sessions.to_string()),
            ),
        );
        let committed = self.commit(batch).await?;
        self.finish_account_end(&end, committed.revision, ctx.now)
            .await;
        Ok(end.sessions)
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
        let roles = valid_roles(roles);
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
        if Self::guarded(&user)
            && !roles.contains(&RoleName::Admin)
            && !user.disabled
            && Self::other_admins(view.as_ref(), id)? == 0
        {
            return Err(AuthError::LastAdministrator);
        }
        if roles.contains(&RoleName::Admin) && !user.is_admin() {
            refuse_pin_administrator(&user)?;
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
        self.require_break_glass_step_up(ctx).await?;
        let view = self.view().await?;
        let id = request.user_id;
        let (user, revision) = Self::load_user(view.as_ref(), id)?;
        if user.break_glass == request.enabled {
            return Self::info(view.as_ref(), id, ctx.now);
        }
        let credentials = Self::user_credentials(view.as_ref(), id)?;
        let mut updated = user.clone();
        let mut batch = WriteBatch::for_request(ctx);
        Self::guard_admins(view.as_ref(), &mut batch)?;
        let mut end = None;
        if request.enabled {
            if !credentials.iter().any(|credential| credential.hardware_key) {
                return Err(AuthError::invalid(
                    "user_id",
                    "register an attested hardware security key for the account first",
                ));
            }
            // Under Hardened the break-glass key must be one that a configured attestation
            // root confirms, also when the account becomes break-glass after its keys were
            // registered (IAM-09, ADR 0010).
            if self.settings().profile == crate::settings::Profile::Hardened
                && !credentials.iter().any(|credential| {
                    credential.hardware_key
                        && matches!(
                            credential.attestation,
                            crate::webauthn::AttestationKind::Certificate { anchored: true, .. }
                        )
                })
            {
                return Err(AuthError::invalid(
                    "user_id",
                    "under the Hardened profile the break-glass account needs a security key that \
                     an attestation root of [auth] attestation_roots confirms",
                ));
            }
            if !user.break_glass && user.is_admin() && Self::other_admins(view.as_ref(), id)? == 0 {
                return Err(AuthError::LastAdministrator);
            }
            updated.break_glass = true;
            updated.roles = vec![RoleName::Admin];
            // From now on only the key signs it in.
            end = Some(self.stage_account_end(
                view.as_ref(),
                &mut batch,
                &mut updated,
                EndReason::BreakGlass,
            )?);
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
        let mut draft = Self::audit(actions::BREAK_GLASS_SET, vec![Self::user_object(id)], ctx)
            .with_change(change(
                "break_glass",
                &user.break_glass.to_string(),
                &updated.break_glass.to_string(),
            ));
        if let Some(end) = &end {
            draft = end.annotate(draft);
        }
        batch.audit(draft);
        let committed = self.commit(batch).await?;
        if let Some(end) = &end {
            self.finish_account_end(end, committed.revision, ctx.now)
                .await;
        }
        Self::info(self.view().await?.as_ref(), id, ctx.now)
    }

    /// `PUT /settings/default-language` (API-21): the default UI language of the
    /// installation, a built-in language or an active language pack. Audited with the old
    /// and the new tag.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the update permission on settings,
    /// [`AuthError::Invalid`] (field `language`) for a tag that is not active,
    /// [`AuthError::Unavailable`] before setup, [`AuthError::Conflict`] on a concurrent
    /// change.
    pub async fn set_default_language(
        &self,
        ctx: &RequestCtx,
        language: &str,
    ) -> Result<String, AuthError> {
        self.authorize(
            ctx,
            Action::Update,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        let language = valid_language(language.trim(), &self.index.image())?;
        let view = self.view().await?;
        let (mut installation, revision) = view
            .get_typed(&INSTALLATION, &())?
            .ok_or(AuthError::Unavailable("setup has not completed"))?;
        if installation.language != language {
            let old = std::mem::replace(&mut installation.language, language.clone());
            let mut batch = WriteBatch::for_request(ctx);
            batch.expect_typed(&INSTALLATION, &(), Some(revision));
            batch.put_typed(&INSTALLATION, &(), &installation)?;
            batch.audit(
                Self::audit(
                    actions::INSTALLATION_LANGUAGE,
                    vec![ObjectRef::singleton(ObjectKind::Settings)],
                    ctx,
                )
                .with_change(change("language", &old, &language)),
            );
            self.commit(batch).await?;
        }
        Ok(language)
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
    /// new value of each changed toggle.
    ///
    /// The PIN coupling rule (IAM-07): a PIN may be the only factor only while the vault
    /// holds no operator secret. The change is refused, and audited as failed, exactly when
    /// it changes the password policy (TGL-01) or the MFA requirement (TGL-02), the result
    /// lets a PIN stand alone (a preset that admits a PIN with optional MFA), and the vault
    /// holds an operator secret. Any other change passes, also under settings that already
    /// let a PIN stand alone.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::Conflict`] when `expect` is stale,
    /// [`AuthError::Invalid`], [`AuthError::PinCoupling`], [`AuthError::AuditExportRequired`]
    /// when the change starts to require the audit export while no sink is enabled (TGL-21),
    /// [`AuthError::Unavailable`] before setup, [`AuthError::StepUpRequired`] for a session
    /// that did not authenticate within the last five minutes.
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
        // The settings decide every other step-up (TGL-23, TGL-24), so changing them needs
        // a fresh authentication itself.
        self.require_fresh_person(ctx).await?;
        let (current, revision) = self
            .stored_settings()
            .await?
            .ok_or(AuthError::Unavailable("setup has not completed"))?;
        if expect.is_some_and(|expected| expected != revision) {
            return Err(AuthError::Conflict);
        }
        let next = patch.apply(&current);
        next.validate()?;
        // TGL-21: a change that starts to require the audit export needs an enabled sink
        // first. A sink that fails or is disabled later is the status warning's business.
        if next.audit_export() == AuditExport::Required
            && current.audit_export() != AuditExport::Required
            && crate::audit_export::status::required_unmet(
                self.view().await?.as_ref(),
                AuditExport::Required,
            )?
        {
            self.record_refused_settings_change(ctx, &AuthError::AuditExportRequired)
                .await;
            return Err(AuthError::AuditExportRequired);
        }
        // With MFA for administrators or for everyone, the accounts that can reach the vault
        // need a second factor already; only "optional" leaves a PIN on its own. A change that
        // leaves TGL-01 and TGL-02 as they are cannot let a PIN stand alone, also where one
        // already may, so it is not held to the rule. The cheap conditions come first; the
        // vault is read last.
        if pin_stands_alone(&next)
            && (next.password_policy != current.password_policy || next.mfa != current.mfa)
            && self.has_operator_secrets().await?
        {
            self.record_refused_settings_change(ctx, &AuthError::PinCoupling)
                .await;
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

    /// Records a refused settings change as a failed audit record (refused guardrails are
    /// audited); a store error is logged, not returned, because the refusal stands anyway.
    async fn record_refused_settings_change(&self, ctx: &RequestCtx, error: &AuthError) {
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(
            tenko_core::audit::AuditDraft::failed(
                actions::SETTINGS_UPDATE,
                vec![ObjectRef::singleton(ObjectKind::Settings)],
                error,
            )
            .with_source_ip(ctx.source_ip),
        );
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused settings change");
        }
    }
}

/// Whether the settings let a PIN be the only factor: a preset that admits a PIN, and MFA
/// that is optional for everyone.
fn pin_stands_alone(settings: &SecuritySettings) -> bool {
    super::account::admits_pin(&settings.password_policy)
        && settings.mfa == MfaRequirement::Optional
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
        let image = AuthImage::default();
        assert!(valid_language("sv", &image).is_ok());
        assert!(valid_language("de", &image).is_err());
        assert_eq!(valid_roles(&[]), Vec::<RoleName>::new());
        assert_eq!(
            valid_roles(&[RoleName::Viewer, RoleName::Admin, RoleName::Viewer]),
            vec![RoleName::Admin, RoleName::Viewer]
        );
    }
}
