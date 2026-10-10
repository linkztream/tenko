//! Scoped access: grants and their delegation (IAM-01), service accounts and their scoped
//! tokens (IAM-10), and the MFA policy per role (IAM-06). `docs/access.md` describes the
//! behaviour; ADR 0015 the decisions.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};

use tenko_core::{
    Action, Anchors, ApiTokenId, AuthStrength, ObjectKind, ObjectRef, Principal, RequestCtx,
    ScopeRule, Timestamp, UserId, audit::AuditDraft,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    AuthService, LIST_LIMIT, actions,
    admin::{display_name, valid_roles, valid_user_name},
    types::{
        CreatedToken, GrantCreate, GrantView, GrantsRevoked, RolePolicyUpdate, RolePolicyView,
        SecretString, ServiceAccountCreate, SubjectSummary, TokenInfo, TokenRequest, UserInfo,
    },
};
use crate::{
    error::AuthError,
    grants::{describe, grantable_role, grantable_rule, rule_exists, rule_object, rule_within},
    model::{
        GRANTS, GrantId, GrantRecord, ROLE_POLICIES, RolePolicy, SCOPED_TOKENS, ScopedTokenRecord,
        TokenGrant, TokenScope, USER_NAMES, USER_SCOPED_TOKENS, USERS, UserKind, UserRecord,
    },
    roles::{RoleName, default_policy, satisfies},
    secret::new_api_token,
};

/// Most grants read for a listing or a cascade.
const MAX_GRANTS: usize = 100_000;

/// The holder or owner summary of a user record.
fn subject_summary(user: &UserRecord) -> SubjectSummary {
    SubjectSummary {
        id: user.id,
        name: user.name.clone(),
        display_name: user.display_name.clone(),
        kind: user.kind,
    }
}

/// The listing of a scoped token.
pub(super) fn scoped_token_info(record: &ScopedTokenRecord) -> TokenInfo {
    TokenInfo {
        id: record.id,
        name: record.name.clone(),
        prefix: record.prefix.clone(),
        created_at: record.created_at,
        expires_at: record.expires_at,
        last_used_at: record.last_used_at,
        scoped: true,
        grants: record.grants.clone(),
        scopes: record.scopes.clone(),
    }
}

/// Every grant issued under `root`, directly or through delegated grants, in issue order.
fn descendants(all: &[GrantRecord], root: GrantId) -> Vec<GrantId> {
    let mut children: HashMap<GrantId, Vec<GrantId>> = HashMap::new();
    for grant in all {
        if let Some(parent) = grant.parent {
            children.entry(parent).or_default().push(grant.id);
        }
    }
    let mut out = Vec::new();
    let mut queue = vec![root];
    let mut seen = BTreeSet::from([root]);
    while let Some(next) = queue.pop() {
        for child in children.get(&next).into_iter().flatten() {
            if seen.insert(*child) {
                out.push(*child);
                queue.push(*child);
            }
        }
    }
    out
}

impl AuthService {
    /// The anchors of the object a rule names, through `view`.
    fn rule_anchors(&self, view: &dyn ReadView, rule: &ScopeRule) -> Option<Anchors> {
        self.scope.anchors_in(view, &rule_object(rule))
    }

    /// Checks that a rule can be granted and names an existing VRF, site or prefix.
    fn validate_rule(&self, view: &dyn ReadView, rule: &ScopeRule) -> Result<(), AuthError> {
        if !grantable_rule(rule) {
            return Err(AuthError::GrantInvalidScope(
                "a grant covers a VRF, a site or a prefix".into(),
            ));
        }
        if !self.scope.is_wired() {
            return Err(AuthError::ScopeUnavailable);
        }
        let exists = self
            .rule_anchors(view, rule)
            .is_some_and(|anchors| rule_exists(rule, &anchors));
        if exists {
            Ok(())
        } else {
            Err(AuthError::GrantInvalidScope(
                format!("{} does not exist", describe(rule)).into(),
            ))
        }
    }

    /// Whether `inner` lies inside `outer`, with anchors read through `view`.
    fn within(&self, view: &dyn ReadView, inner: &ScopeRule, outer: &ScopeRule) -> bool {
        rule_within(inner, outer, &|object: &ObjectRef| {
            self.scope.anchors_in(view, object)
        })
    }

    fn all_grants(view: &dyn ReadView) -> Result<Vec<GrantRecord>, AuthError> {
        Ok(view
            .scan_typed(&GRANTS, KeyRange::all(), MAX_GRANTS, false)?
            .into_iter()
            .map(|(_, grant, _)| grant)
            .collect())
    }

    fn grant_view(view: &dyn ReadView, grant: &GrantRecord) -> Result<GrantView, AuthError> {
        let subject = view.get_typed(&USERS, &grant.subject)?.map_or_else(
            || SubjectSummary {
                id: grant.subject,
                name: String::new(),
                display_name: String::new(),
                kind: UserKind::Person,
            },
            |(user, _)| subject_summary(&user),
        );
        Ok(GrantView {
            id: grant.id,
            subject,
            role: grant.role,
            scope: grant.scope.clone(),
            delegable: grant.delegable,
            granted_by: grant.granted_by,
            granted_at: grant.granted_at,
            parent: grant.parent,
        })
    }

    /// Whether the caller administers users (and so every grant).
    fn administers_users(&self, ctx: &RequestCtx) -> bool {
        self.authorized(
            ctx,
            Action::Administer,
            ObjectRef::singleton(ObjectKind::User),
        )
        .is_ok()
    }

    /// The interactive caller of a delegation: a session that meets its account's
    /// requirement. Tokens never create or revoke grants.
    fn delegating_user(&self, ctx: &RequestCtx) -> Result<UserId, AuthError> {
        let (id, _, strength) = Self::session_principal(ctx).map_err(|_| {
            AuthError::Denied(tenko_core::Denied {
                action: Action::Administer,
                object: ObjectRef::singleton(ObjectKind::User),
                reason: tenko_core::DenyReason::MissingPermission,
            })
        })?;
        let required = self.index.image().required_strength(id, Action::Update);
        if satisfies(strength, required) {
            Ok(id)
        } else {
            Err(AuthError::StepUpRequired {
                required: required.as_str(),
            })
        }
    }

    /// `GET /access/grants`: every grant for an administrator, or the caller's own grants
    /// and the grants issued under them; `subject` narrows the list to one holder.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] without a user, or a store error.
    pub async fn list_grants(
        &self,
        ctx: &RequestCtx,
        subject: Option<UserId>,
    ) -> Result<Vec<GrantView>, AuthError> {
        let caller = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
        let view = self.view().await?;
        let all = Self::all_grants(view.as_ref())?;
        let everything = self
            .authorized(ctx, Action::Read, ObjectRef::singleton(ObjectKind::User))
            .is_ok();
        let visible: BTreeSet<GrantId> = if everything {
            all.iter().map(|grant| grant.id).collect()
        } else {
            let own: Vec<GrantId> = all
                .iter()
                .filter(|grant| grant.subject == caller)
                .map(|grant| grant.id)
                .collect();
            own.iter()
                .copied()
                .chain(own.iter().flat_map(|id| descendants(&all, *id)))
                .collect()
        };
        let mut out = Vec::new();
        for grant in &all {
            if visible.contains(&grant.id) && subject.is_none_or(|subject| grant.subject == subject)
            {
                out.push(Self::grant_view(view.as_ref(), grant)?);
            }
        }
        out.sort_by(|a, b| {
            a.subject
                .name
                .to_lowercase()
                .cmp(&b.subject.name.to_lowercase())
                .then(a.granted_at.cmp(&b.granted_at))
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// `POST /access/grants` (IAM-01): an administrator grants any scope; the holder of a
    /// delegable grant grants a role no higher over a scope inside it, and the new grant
    /// ends with that one.
    ///
    /// # Errors
    ///
    /// [`AuthError::GrantInvalidRole`], [`AuthError::GrantInvalidScope`],
    /// [`AuthError::GrantDuplicate`], [`AuthError::GrantExceedsOwn`] for a delegation
    /// beyond the caller's grants, [`AuthError::NotFound`] for an unknown subject,
    /// [`AuthError::ScopeUnavailable`] without IPAM.
    pub async fn create_grant(
        &self,
        ctx: &RequestCtx,
        request: &GrantCreate,
    ) -> Result<GrantView, AuthError> {
        let admin = self.administers_users(ctx);
        let caller = if admin {
            ctx.principal.user()
        } else {
            Some(self.delegating_user(ctx)?)
        };
        if !grantable_role(request.role) {
            return Err(AuthError::GrantInvalidRole {
                role: request.role.as_str(),
            });
        }
        let view = self.view().await?;
        let (subject, _) = Self::load_user(view.as_ref(), request.subject)?;
        if subject.break_glass {
            return Err(AuthError::invalid(
                "subject",
                "the break-glass account holds the admin role only",
            ));
        }
        self.validate_rule(view.as_ref(), &request.scope)?;
        let all = Self::all_grants(view.as_ref())?;
        if all.iter().any(|grant| {
            grant.subject == request.subject
                && grant.role == request.role
                && grant.scope == request.scope
        }) {
            return Err(AuthError::GrantDuplicate);
        }
        let parent = if admin {
            None
        } else {
            let caller = caller.ok_or(AuthError::Unauthenticated)?;
            let found = all.iter().find(|grant| {
                grant.subject == caller
                    && grant.delegable
                    && grant.role.covers(request.role)
                    && self.within(view.as_ref(), &request.scope, &grant.scope)
            });
            let Some(grant) = found else {
                self.record_refusal(ctx, actions::GRANT_CREATE, request.subject, &request.scope)
                    .await;
                return Err(AuthError::GrantExceedsOwn);
            };
            Some(grant.id)
        };
        let record = GrantRecord {
            id: GrantId::generate(),
            subject: request.subject,
            role: request.role,
            scope: request.scope.clone(),
            delegable: request.delegable,
            granted_by: caller,
            granted_at: ctx.now,
            parent,
        };
        let mut batch = WriteBatch::for_request(ctx);
        if let Some(parent) = parent {
            // A concurrent revocation of the delegating grant makes this batch fail.
            let revision = view
                .get_typed(&GRANTS, &parent)?
                .map(|(_, revision)| revision);
            batch.expect_typed(&GRANTS, &parent, revision);
        }
        batch.expect_typed(&GRANTS, &record.id, None);
        batch.put_typed(&GRANTS, &record.id, &record)?;
        let mut draft = Self::audit(
            actions::GRANT_CREATE,
            vec![ObjectRef::from(request.subject)],
            ctx,
        )
        .with_context("grant", record.id.to_string())
        .with_context("role", record.role.as_str())
        .with_context("scope", describe(&record.scope))
        .with_context("delegable", record.delegable.to_string());
        if let Some(parent) = parent {
            draft = draft.with_context("parent", parent.to_string());
        }
        batch.audit(draft);
        self.commit(batch).await?;
        Self::grant_view(view.as_ref(), &record)
    }

    /// Records a refused grant change in the audit log (NEVER-02).
    async fn record_refusal(
        &self,
        ctx: &RequestCtx,
        action: tenko_core::audit::AuditAction,
        subject: UserId,
        scope: &ScopeRule,
    ) {
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::failed(
                action,
                vec![ObjectRef::from(subject)],
                &AuthError::GrantExceedsOwn,
            )
            .with_source_ip(ctx.source_ip)
            .with_context("scope", describe(scope)),
        );
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a refused grant");
        }
    }

    /// `DELETE /access/grants/{id}`: revokes a grant and every grant issued under it, in one
    /// batch. An administrator revokes any grant; a holder revokes its own grants and the
    /// grants issued under them.
    ///
    /// # Errors
    ///
    /// [`AuthError::NotFound`] for a grant the caller does not see.
    pub async fn revoke_grant(
        &self,
        ctx: &RequestCtx,
        id: GrantId,
    ) -> Result<GrantsRevoked, AuthError> {
        let admin = self.administers_users(ctx);
        let caller = if admin {
            ctx.principal.user()
        } else {
            Some(self.delegating_user(ctx)?)
        };
        let view = self.view().await?;
        let all = Self::all_grants(view.as_ref())?;
        let target = all
            .iter()
            .find(|grant| grant.id == id)
            .ok_or(AuthError::NotFound { kind: "grant" })?;
        if !admin {
            let caller = caller.ok_or(AuthError::Unauthenticated)?;
            let own: Vec<GrantId> = all
                .iter()
                .filter(|grant| grant.subject == caller)
                .map(|grant| grant.id)
                .collect();
            let reachable = own.contains(&id)
                || own
                    .iter()
                    .any(|grant| descendants(&all, *grant).contains(&id));
            if !reachable {
                return Err(AuthError::NotFound { kind: "grant" });
            }
        }
        let mut revoked = vec![id];
        revoked.extend(descendants(&all, id));
        let by_id: BTreeMap<GrantId, &GrantRecord> =
            all.iter().map(|grant| (grant.id, grant)).collect();
        let mut subjects: BTreeSet<UserId> = BTreeSet::new();
        let mut batch = WriteBatch::for_request(ctx);
        for grant in &revoked {
            batch.delete_typed(&GRANTS, grant);
            if let Some(record) = by_id.get(grant) {
                subjects.insert(record.subject);
            }
        }
        batch.audit(
            Self::audit(
                actions::GRANT_REVOKE,
                subjects
                    .iter()
                    .map(|subject| ObjectRef::from(*subject))
                    .collect(),
                ctx,
            )
            .with_context("grant", id.to_string())
            .with_context("scope", describe(&target.scope))
            .with_context(
                "revoked",
                revoked
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        );
        self.commit(batch).await?;
        Ok(GrantsRevoked { revoked })
    }

    /// `GET /access/subjects`: the people and service accounts a grant can name, for an
    /// administrator or the holder of a delegable grant.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] for anybody else.
    pub async fn grant_subjects(&self, ctx: &RequestCtx) -> Result<Vec<SubjectSummary>, AuthError> {
        let reads_users = self
            .authorized(ctx, Action::Read, ObjectRef::singleton(ObjectKind::User))
            .is_ok();
        if !reads_users {
            let caller = ctx.principal.user().ok_or(AuthError::Unauthenticated)?;
            let delegates = self
                .index
                .image()
                .grants_of(caller)
                .iter()
                .any(|grant| grant.delegable);
            if !delegates {
                self.authorize(ctx, Action::Read, ObjectRef::singleton(ObjectKind::User))
                    .await?;
            }
        }
        let view = self.view().await?;
        let mut out: Vec<SubjectSummary> = view
            .scan_typed(&USERS, KeyRange::all(), LIST_LIMIT, false)?
            .into_iter()
            .filter(|(_, user, _)| !user.break_glass && !user.disabled)
            .map(|(_, user, _)| subject_summary(&user))
            .collect();
        out.sort_by_key(|subject| subject.name.to_lowercase());
        Ok(out)
    }

    /// `GET /access/service-accounts` (IAM-10).
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the read permission on users.
    pub async fn list_service_accounts(
        &self,
        ctx: &RequestCtx,
    ) -> Result<Vec<UserInfo>, AuthError> {
        Ok(self
            .list_users(ctx)
            .await?
            .into_iter()
            .filter(|user| user.kind == UserKind::Service)
            .collect())
    }

    /// `POST /access/service-accounts` (IAM-10): an account without password, passkey or
    /// session, owned by the administrator who creates it. It acts through scoped tokens.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`], [`AuthError::UserNameTaken`], [`AuthError::Invalid`].
    pub async fn create_service_account(
        &self,
        ctx: &RequestCtx,
        request: &ServiceAccountCreate,
    ) -> Result<UserInfo, AuthError> {
        self.authorize(
            ctx,
            Action::Administer,
            ObjectRef::singleton(ObjectKind::User),
        )
        .await?;
        let name = valid_user_name(&request.name)?;
        let display = display_name(request.display_name.as_deref(), &name)?;
        let roles = valid_roles(&request.roles);
        let view = self.view().await?;
        let key = UserRecord::name_key(&name);
        if view.get_typed(&USER_NAMES, &key)?.is_some() {
            return Err(AuthError::UserNameTaken);
        }
        let account = UserRecord {
            kind: UserKind::Service,
            owner: ctx.principal.user(),
            ..UserRecord::new(name, display, roles, ctx.now)
        };
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(&USER_NAMES, &key, None);
        batch.put_typed(&USER_NAMES, &key, &account.id)?;
        batch.put_typed(&USERS, &account.id, &account)?;
        batch.audit(
            Self::audit(
                actions::SERVICE_ACCOUNT_CREATE,
                vec![ObjectRef::from(account.id)],
                ctx,
            )
            .with_context("name", account.name.clone())
            .with_context(
                "roles",
                account
                    .roles
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        );
        match self.commit(batch).await {
            Err(AuthError::Conflict) => return Err(AuthError::UserNameTaken),
            other => other?,
        };
        self.get_user(ctx, account.id).await
    }

    /// The service account `id`, after the administrator check.
    async fn service_account(
        &self,
        ctx: &RequestCtx,
        id: UserId,
    ) -> Result<(UserRecord, std::sync::Arc<dyn ReadView>), AuthError> {
        self.authorize(ctx, Action::Administer, ObjectRef::from(id))
            .await?;
        let view = self.view().await?;
        let user = view
            .get_typed(&USERS, &id)?
            .map(|(user, _)| user)
            .filter(UserRecord::is_service)
            .ok_or(AuthError::NotFound {
                kind: "service_account",
            })?;
        Ok((user, view))
    }

    /// `GET /access/service-accounts/{id}/tokens`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn list_account_tokens(
        &self,
        ctx: &RequestCtx,
        id: UserId,
    ) -> Result<Vec<TokenInfo>, AuthError> {
        let (_, view) = self.service_account(ctx, id).await?;
        Self::scoped_tokens_of(view.as_ref(), id)
    }

    /// The scoped tokens of an owner.
    pub(super) fn scoped_tokens_of(
        view: &dyn ReadView,
        owner: UserId,
    ) -> Result<Vec<TokenInfo>, AuthError> {
        let mut tokens = Vec::new();
        for (_, hash, _) in view.scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(owner,))),
            LIST_LIMIT,
            false,
        )? {
            if let Some((record, _)) = view.get_typed(&SCOPED_TOKENS, &hash)? {
                tokens.push(scoped_token_info(&record));
            }
        }
        Ok(tokens)
    }

    /// `POST /access/service-accounts/{id}/tokens` (IAM-10): a scoped token of the service
    /// account, shown once. Its grants must lie inside the account's roles and grants.
    ///
    /// # Errors
    ///
    /// As [`AuthService::create_token_with`], and [`AuthError::NotFound`] for an account that is
    /// not a service account.
    pub async fn create_account_token(
        &self,
        ctx: &RequestCtx,
        id: UserId,
        request: &TokenRequest,
    ) -> Result<CreatedToken, AuthError> {
        let (account, view) = self.service_account(ctx, id).await?;
        let (creator, _, strength) = Self::session_principal(ctx)?;
        self.issue_scoped_token(ctx, view.as_ref(), &account, creator, strength, request)
            .await
    }

    /// `DELETE /access/service-accounts/{id}/tokens/{token}`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] or [`AuthError::NotFound`].
    pub async fn revoke_account_token(
        &self,
        ctx: &RequestCtx,
        id: UserId,
        token: ApiTokenId,
    ) -> Result<(), AuthError> {
        let (_, view) = self.service_account(ctx, id).await?;
        let (hash, _) = view
            .get_typed(&USER_SCOPED_TOKENS, &(id, token))?
            .ok_or(AuthError::NotFound { kind: "token" })?;
        let mut batch = WriteBatch::for_request(ctx);
        batch.delete_typed(&SCOPED_TOKENS, &hash);
        batch.delete_typed(&USER_SCOPED_TOKENS, &(id, token));
        batch.audit(Self::audit(
            actions::TOKEN_REVOKE,
            vec![ObjectRef::from(id), ObjectRef::from(token)],
            ctx,
        ));
        self.commit(batch).await?;
        Ok(())
    }

    /// Checks the grants and scopes of a scoped token against its owner: every global
    /// grant needs a global role of the owner that covers it, every scoped grant a global
    /// role or a grant of the owner that covers its role over a scope that contains it; the
    /// special scopes need an owner who reads the system, or a service account.
    fn validate_token_grants(
        &self,
        view: &dyn ReadView,
        owner: &UserRecord,
        request: &TokenRequest,
    ) -> Result<(Vec<TokenGrant>, Vec<TokenScope>), AuthError> {
        let mut grants: Vec<TokenGrant> = Vec::new();
        for grant in request.grants.iter().flatten() {
            let global = owner.roles.iter().any(|held| held.covers(grant.role));
            match &grant.scope {
                None => {
                    if !global {
                        return Err(AuthError::GrantExceedsOwn);
                    }
                }
                Some(rule) => {
                    if !grantable_role(grant.role) {
                        return Err(AuthError::GrantInvalidRole {
                            role: grant.role.as_str(),
                        });
                    }
                    self.validate_rule(view, rule)?;
                    let inside = global
                        || self.index.image().grants_of(owner.id).iter().any(|held| {
                            held.role.covers(grant.role) && self.within(view, rule, &held.scope)
                        });
                    if !inside {
                        return Err(AuthError::GrantExceedsOwn);
                    }
                }
            }
            if !grants.contains(grant) {
                grants.push(grant.clone());
            }
        }
        let mut scopes: Vec<TokenScope> = request.scopes.clone();
        scopes.sort();
        scopes.dedup();
        if !scopes.is_empty()
            && !owner.is_service()
            && !owner
                .roles
                .iter()
                .any(|role| role.allows(Action::Read, ObjectKind::System))
        {
            return Err(AuthError::GrantExceedsOwn);
        }
        if grants.is_empty() && scopes.is_empty() {
            return Err(AuthError::invalid(
                "grants",
                "a scoped token needs at least one grant or scope",
            ));
        }
        Ok((grants, scopes))
    }

    /// Creates a scoped token for `owner` (IAM-10): checked against TGL-05, the session's
    /// strength and the owner's grants; shown once.
    pub(super) async fn issue_scoped_token(
        &self,
        ctx: &RequestCtx,
        view: &dyn ReadView,
        owner: &UserRecord,
        creator: UserId,
        strength: AuthStrength,
        request: &TokenRequest,
    ) -> Result<CreatedToken, AuthError> {
        let required = self.index.image().required_strength(creator, Action::Read);
        if !satisfies(strength, required) {
            return Err(AuthError::StepUpRequired {
                required: required.as_str(),
            });
        }
        let name = request.name.trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(AuthError::invalid(
                "name",
                "visible characters are required",
            ));
        }
        let name: String = name.chars().take(64).collect();
        let (grants, scopes) = self.validate_token_grants(view, owner, request)?;
        let expires_at = token_expiry(&self.settings(), request.expires_in_days, ctx.now)?;
        let token = new_api_token()?;
        let record = ScopedTokenRecord {
            id: ApiTokenId::generate(),
            owner: owner.id,
            name,
            created_at: ctx.now,
            created_by: creator,
            expires_at,
            last_used_at: None,
            issued_with: strength,
            prefix: token.expose().chars().take(12).collect(),
            grants,
            scopes,
        };
        let hash = token.hash();
        let mut batch = WriteBatch::for_request(ctx);
        batch.put_typed(&SCOPED_TOKENS, &hash, &record)?;
        batch.put_typed(&USER_SCOPED_TOKENS, &(owner.id, record.id), &hash)?;
        let mut draft = Self::audit(
            actions::TOKEN_CREATE,
            vec![ObjectRef::from(owner.id), ObjectRef::from(record.id)],
            ctx,
        )
        .with_context("name", record.name.clone())
        .with_context("scoped", "true")
        .with_context(
            "grants",
            record
                .grants
                .iter()
                .map(|grant| match &grant.scope {
                    Some(rule) => format!("{}@{}", grant.role, describe(rule)),
                    None => grant.role.as_str().to_owned(),
                })
                .collect::<Vec<_>>()
                .join(","),
        )
        .with_context(
            "scopes",
            record
                .scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        if let Some(expires_at) = expires_at {
            draft = draft.with_context("expires_at", expires_at.to_rfc3339());
        }
        batch.audit(draft);
        self.commit(batch).await?;
        Ok(CreatedToken {
            token: SecretString::new(token.expose()),
            info: scoped_token_info(&record),
        })
    }

    /// `GET /access/role-policies` (IAM-06): the MFA requirement of every role.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the read permission on settings.
    pub async fn role_policies(&self, ctx: &RequestCtx) -> Result<Vec<RolePolicyView>, AuthError> {
        self.authorize(
            ctx,
            Action::Read,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        let image = self.index.image();
        Ok(RoleName::ALL
            .into_iter()
            .map(|role| policy_view(role, image.settings(), image.policy(role)))
            .collect())
    }

    /// `PUT /access/role-policies/{role}`: stores the MFA requirement of a role; the
    /// requirement in force is the stricter of it and the profile's.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the update permission on settings.
    pub async fn set_role_policy(
        &self,
        ctx: &RequestCtx,
        role: RoleName,
        request: &RolePolicyUpdate,
    ) -> Result<RolePolicyView, AuthError> {
        self.authorize(
            ctx,
            Action::Update,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        let view = self.view().await?;
        let key = role.as_str().to_owned();
        let old = view
            .get_typed(&ROLE_POLICIES, &key)?
            .map(|(policy, _)| policy.mfa);
        if old != Some(request.mfa) {
            let mut batch = WriteBatch::for_request(ctx);
            batch.put_typed(
                &ROLE_POLICIES,
                &key,
                &RolePolicy {
                    role,
                    mfa: request.mfa,
                    updated_at: ctx.now,
                    updated_by: ctx.principal.user(),
                },
            )?;
            batch.audit(
                Self::audit(
                    actions::ROLE_POLICY_UPDATE,
                    vec![ObjectRef::singleton(ObjectKind::Settings)],
                    ctx,
                )
                .with_change(tenko_core::audit::FieldChange {
                    object: None,
                    field: format!("mfa.{role}"),
                    old: old.map(|mfa| mfa.as_str().to_owned()),
                    new: Some(request.mfa.as_str().to_owned()),
                }),
            );
            self.commit(batch).await?;
        }
        let image = self.index.image();
        Ok(policy_view(role, image.settings(), Some(request.mfa)))
    }

    /// `DELETE /access/role-policies/{role}`: the role follows the profile again.
    ///
    /// # Errors
    ///
    /// [`AuthError::Denied`] without the update permission on settings.
    pub async fn clear_role_policy(
        &self,
        ctx: &RequestCtx,
        role: RoleName,
    ) -> Result<RolePolicyView, AuthError> {
        self.authorize(
            ctx,
            Action::Update,
            ObjectRef::singleton(ObjectKind::Settings),
        )
        .await?;
        let view = self.view().await?;
        let key = role.as_str().to_owned();
        if let Some((old, _)) = view.get_typed(&ROLE_POLICIES, &key)? {
            let mut batch = WriteBatch::for_request(ctx);
            batch.delete_typed(&ROLE_POLICIES, &key);
            batch.audit(
                Self::audit(
                    actions::ROLE_POLICY_UPDATE,
                    vec![ObjectRef::singleton(ObjectKind::Settings)],
                    ctx,
                )
                .with_change(tenko_core::audit::FieldChange {
                    object: None,
                    field: format!("mfa.{role}"),
                    old: Some(old.mfa.as_str().to_owned()),
                    new: None,
                }),
            );
            self.commit(batch).await?;
        }
        let image = self.index.image();
        Ok(policy_view(role, image.settings(), None))
    }

    /// Adds the removal of every grant a user holds, and of the grants issued under them, to
    /// a batch (the account is deleted).
    pub(super) fn stage_grant_removal(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        id: UserId,
    ) -> Result<usize, AuthError> {
        let all = Self::all_grants(view)?;
        let mut removed: BTreeSet<GrantId> = BTreeSet::new();
        for grant in all.iter().filter(|grant| grant.subject == id) {
            removed.insert(grant.id);
            removed.extend(descendants(&all, grant.id));
        }
        for grant in &removed {
            batch.delete_typed(&GRANTS, grant);
        }
        Ok(removed.len())
    }

    /// Adds the removal of every scoped token of a user to a batch.
    pub(super) fn stage_scoped_token_removal(
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        id: UserId,
    ) -> Result<(), AuthError> {
        for (key, hash, _) in view.scan_typed(
            &USER_SCOPED_TOKENS,
            KeyRange::prefix(tenko_core::codec::encode_key(&(id,))),
            LIST_LIMIT,
            false,
        )? {
            batch.delete_typed(&SCOPED_TOKENS, &hash);
            batch.delete_typed(&USER_SCOPED_TOKENS, &key);
        }
        Ok(())
    }

    /// The scoped token `id` of `owner` with its hash, if there is one.
    pub(super) fn scoped_token_hash(
        view: &dyn ReadView,
        owner: UserId,
        id: ApiTokenId,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(view
            .get_typed(&USER_SCOPED_TOKENS, &(owner, id))?
            .map(|(hash, _)| hash))
    }

    /// Whether `principal` is a scoped token.
    pub fn is_scoped_token(&self, principal: &Principal) -> bool {
        matches!(principal, Principal::Token { id, .. }
            if matches!(self.index.image().token(*id), Some(crate::authz::TokenAuthz::Scoped { .. })))
    }
}

/// The policy view of one role.
fn policy_view(
    role: RoleName,
    settings: &crate::settings::SecuritySettings,
    stored: Option<crate::model::RoleMfa>,
) -> RolePolicyView {
    let profile_default = default_policy(role, settings);
    RolePolicyView {
        role,
        mfa: stored.map_or(profile_default, |stored| stored.max(profile_default)),
        profile_default,
        stored,
    }
}

/// The expiry of a new token under TGL-05.
pub(super) fn token_expiry(
    settings: &crate::settings::SecuritySettings,
    requested: Option<u32>,
    now: Timestamp,
) -> Result<Option<Timestamp>, AuthError> {
    let days = match (settings.token_max_days, requested) {
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
    days.map(|days| {
        now.checked_add(Duration::from_secs(u64::from(days) * 86_400))
            .ok_or_else(|| AuthError::invalid("expires_in_days", "too far in the future"))
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use tenko_core::{PrefixId, SiteId};

    use super::*;
    use crate::{model::RoleMfa, settings::Profile};

    fn grant(id: u128, parent: Option<u128>) -> GrantRecord {
        GrantRecord {
            id: GrantId::from_uuid(uuid::Uuid::from_u128(id)),
            subject: UserId::generate(),
            role: RoleName::Viewer,
            scope: ScopeRule::Site {
                id: SiteId::generate(),
                subtree: true,
            },
            delegable: true,
            granted_by: None,
            granted_at: Timestamp::UNIX_EPOCH,
            parent: parent.map(|parent| GrantId::from_uuid(uuid::Uuid::from_u128(parent))),
        }
    }

    #[test]
    fn revocation_cascades_through_every_delegation_level() {
        let all = vec![
            grant(1, None),
            grant(2, Some(1)),
            grant(3, Some(2)),
            grant(4, Some(1)),
            grant(5, None),
        ];
        let id = |n: u128| GrantId::from_uuid(uuid::Uuid::from_u128(n));
        let mut below = descendants(&all, id(1));
        below.sort();
        assert_eq!(below, vec![id(2), id(3), id(4)]);
        assert_eq!(descendants(&all, id(2)), vec![id(3)]);
        assert_eq!(descendants(&all, id(5)), Vec::<GrantId>::new());
    }

    #[test]
    fn a_policy_never_lowers_the_profile() {
        let hardened = Profile::Hardened.defaults();
        let view = policy_view(RoleName::Admin, &hardened, Some(RoleMfa::Optional));
        assert_eq!(view.profile_default, RoleMfa::Passkey);
        assert_eq!(view.mfa, RoleMfa::Passkey);
        let home = Profile::Home.defaults();
        let view = policy_view(RoleName::Viewer, &home, Some(RoleMfa::Passkey));
        assert_eq!(
            (view.mfa, view.profile_default),
            (RoleMfa::Passkey, RoleMfa::Optional)
        );
        assert_eq!(policy_view(RoleName::Viewer, &home, None).stored, None);
        let _ = PrefixId::generate();
    }

    #[test]
    fn token_lifetimes_follow_tgl_05() {
        let now = Timestamp::UNIX_EPOCH;
        let standard = Profile::Standard.defaults();
        assert!(token_expiry(&standard, Some(0), now).is_err());
        assert!(matches!(
            token_expiry(&standard, Some(91), now),
            Err(AuthError::TokenLifetime { max_days: 90 })
        ));
        assert_eq!(
            token_expiry(&standard, None, now).expect("expiry"),
            now.checked_add(Duration::from_secs(90 * 86_400))
        );
        let lab = Profile::Lab.defaults();
        assert_eq!(token_expiry(&lab, None, now).expect("expiry"), None);
    }
}
