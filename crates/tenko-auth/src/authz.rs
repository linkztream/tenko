//! The [`Authorizer`] of Tenko DDI: global roles, scoped grants (IAM-01), scoped tokens and
//! service accounts (IAM-10), the strength rules of TGL-02, TGL-03 and the MFA policy per
//! role (IAM-06), and the PIN coupling rule (IAM-07: the index follows
//! `vault.operator_index`, so the first operator secret takes effect at once). The index also
//! keeps the active language set (`i18n.packs`, API-21), so the language check of users and
//! setup reads no table.
//!
//! Authorization runs on every request and must not touch the store, so the roles, grants,
//! tokens, policies and settings it needs are kept in a derived index ([`AuthIndex`]) that
//! the store builds at registration and keeps current in revision order (ADR 0011,
//! decision 8): a role change, a revoked grant or a disabled account takes effect with the
//! commit that made it.
//!
//! # How a decision is made (ADR 0015)
//!
//! 1. **Reach.** For the action and the object kind, a global role that allows it reaches
//!    everywhere ([`Reach::Global`]); otherwise the scoped grants whose role allows it reach
//!    the objects their rules cover ([`Reach::Scoped`]); otherwise the principal is refused
//!    with `auth.forbidden`. Imports, connectors, nodes, secrets, settings, users and the
//!    system are reached by global roles only. A scoped token reaches the intersection of
//!    its own grants and its owner's: one layer of rules each, and an object must be covered
//!    by both.
//! 2. **Strength.** A session must meet the strictest of the profile's requirement (TGL-02,
//!    TGL-03), the PIN coupling rule and the MFA policy of every role the user holds at any
//!    scope; otherwise `auth.step_up_required`.
//! 3. **Scope.** With a scoped reach, the object's anchors ([`tenko_store::AnchorResolver`],
//!    implemented over the IPAM indexes) must be covered: one anchor for a read
//!    ([`AnchorMode::Any`]), the whole object for a create, change or delete
//!    ([`AnchorMode::All`]); otherwise `auth.out_of_scope`. Tenants, VRFs, sites and custom
//!    field definitions are read as context by every scoped principal ([`is_context_kind`]).
//!    A check against [`anywhere`] passes when some grant reaches the kind (the caller then
//!    filters a list or checks each planned object); a check against the nil identifier of a
//!    scoped kind is refused, so a caller that does neither leaks nothing.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, OnceLock},
    task::{Context, Poll, Waker},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use tenko_core::{
    Action, AnchorMode, Anchors, ApiTokenId, AuthStrength, Authorizer, CounterKey, Denied,
    DenyReason, ObjectKind, ObjectRef, Principal, Revision, ScopeFilter, ScopeRule, TableName,
    UserId,
    i18n::{BUILT_IN_LANGUAGES, PACKS},
};
use tenko_store::{
    AnchorResolver, ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadConsistency, ReadView,
    ReadViewExt, Store, StoreError, Versioned, WatchFilter, downcast_image,
};
use uuid::Uuid;

use tenko_vault::tables::OPERATOR_INDEX;

use crate::{
    model::{
        GRANTS, GrantRecord, ROLE_POLICIES, RoleMfa, SCOPED_TOKENS, TOKENS, TokenGrant, TokenScope,
        USERS, UserKind,
    },
    roles::{RoleName, interactive_only, required_strength, satisfies},
    settings::SecuritySettings,
};

/// The metrics endpoint as an object of authorization: a token with the `metrics` scope
/// may read it and nothing else; every other principal reads it as the system.
pub const METRICS_OBJECT: ObjectRef =
    ObjectRef::new(ObjectKind::System, Uuid::from_u128(0x006d_6574_7269_6373));

/// The audit log as an object of authorization: a token with the `audit:read` scope may
/// read it; every other principal reads it as the system.
pub const AUDIT_OBJECT: ObjectRef =
    ObjectRef::new(ObjectKind::System, Uuid::from_u128(0x0061_7564_6974));

/// The identifier of [`anywhere`].
pub const ANYWHERE: Uuid = Uuid::max();

/// An object of `kind` somewhere in the principal's reach: the check passes when a global
/// role or any scoped grant allows the action on the kind. The caller then filters a list
/// object by object or checks every object a planned write touches.
pub const fn anywhere(kind: ObjectKind) -> ObjectRef {
    ObjectRef::new(kind, ANYWHERE)
}

/// Whether scoped grants reach objects of `kind`. Imports, connectors, nodes, secrets,
/// settings, users, sessions, tokens and the system are global-only in Phase 1; the DNS
/// kinds and the DHCP kinds other than `dhcp_scope` are global-only too. A DHCP scope
/// follows its prefix's grants (IAM-01; WP7.0): its anchors are the prefix's.
pub const fn is_scoped_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::DhcpScope
            | ObjectKind::Tenant
            | ObjectKind::Vrf
            | ObjectKind::Site
            | ObjectKind::Vlan
            | ObjectKind::Prefix
            | ObjectKind::Range
            | ObjectKind::Address
            | ObjectKind::Host
            | ObjectKind::Interface
            | ObjectKind::CustomField
            | ObjectKind::Job
            | ObjectKind::Observation
            | ObjectKind::Proposal
    )
}

/// Kinds every scoped principal may read as context: the containers whose names label what
/// it works with (tenants, VRFs, sites) and the custom field definitions of its forms.
/// Changing them still needs a rule that covers them.
pub const fn is_context_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Tenant | ObjectKind::Vrf | ObjectKind::Site | ObjectKind::CustomField
    )
}

/// The anchor mode of an action: any anchor for a read, the whole object otherwise.
pub const fn mode_of(action: Action) -> AnchorMode {
    match action {
        Action::Read => AnchorMode::Any,
        _ => AnchorMode::All,
    }
}

/// What authorization needs to know about a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthz {
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// Disabled accounts are refused.
    pub disabled: bool,
    /// The break-glass account.
    pub break_glass: bool,
    /// A person or a service account.
    pub kind: UserKind,
    /// The Argon2 cost of the stored password, if the account has one (the dummy
    /// verification of an unknown name follows the strongest).
    pub password_cost: Option<crate::password::hash::HashCost>,
}

impl UserAuthz {
    /// Whether the account is a person who administers: the admin role, enabled, not the
    /// break-glass account and not a service account.
    fn administers(&self) -> bool {
        self.roles.contains(&RoleName::Admin)
            && !self.disabled
            && !self.break_glass
            && self.kind != UserKind::Service
    }
}

/// What authorization needs to know about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAuthz {
    /// A personal token: it acts with its owner's roles and grants.
    Personal {
        /// The owner.
        owner: UserId,
        /// The strength of the sign-in that created it.
        issued_with: AuthStrength,
    },
    /// A scoped token: the intersection of its grants and its owner's.
    Scoped {
        /// The owner.
        owner: UserId,
        /// Its grants.
        grants: Vec<TokenGrant>,
        /// Its special scopes.
        scopes: Vec<TokenScope>,
        /// The strength of the sign-in that created it.
        issued_with: AuthStrength,
    },
}

impl TokenAuthz {
    /// The owner.
    pub fn owner(&self) -> UserId {
        match self {
            Self::Personal { owner, .. } | Self::Scoped { owner, .. } => *owner,
        }
    }

    /// The strength of the sign-in that created the token. A token acts only while it
    /// meets its owner's requirement, which may have risen since.
    pub fn issued_with(&self) -> AuthStrength {
        match self {
            Self::Personal { issued_with, .. } | Self::Scoped { issued_with, .. } => *issued_with,
        }
    }
}

/// One built image of the index.
#[derive(Debug, Clone, Default)]
pub struct AuthImage {
    revision: Revision,
    users: Arc<HashMap<UserId, UserAuthz>>,
    settings: SecuritySettings,
    operator_secrets: bool,
    /// Tags of the active uploaded language packs; the built-in languages are always active.
    languages: BTreeSet<String>,
    /// Scoped grants by subject.
    grants: Arc<HashMap<UserId, Vec<GrantRecord>>>,
    /// Tokens by id, personal and scoped.
    tokens: Arc<HashMap<ApiTokenId, TokenAuthz>>,
    /// Token ids by the hash that keys their row, for deletions.
    token_hashes: Arc<HashMap<Vec<u8>, ApiTokenId>>,
    /// Stored MFA policies.
    policies: BTreeMap<RoleName, RoleMfa>,
}

impl AuthImage {
    /// The user's authorization data.
    pub fn user(&self, id: UserId) -> Option<&UserAuthz> {
        self.users.get(&id)
    }

    /// Whether `id` is the last administrator: a person who administers (the admin role,
    /// enabled, neither break-glass nor a service account) while no other such person
    /// exists. The network never locks this account (TGL-07).
    pub fn is_last_admin(&self, id: UserId) -> bool {
        self.users.get(&id).is_some_and(UserAuthz::administers)
            && !self
                .users
                .iter()
                .any(|(other, user)| *other != id && user.administers())
    }

    /// The strongest Argon2 cost among the stored passwords, component by component.
    pub fn strongest_password_cost(&self) -> Option<crate::password::hash::HashCost> {
        self.users
            .values()
            .filter_map(|user| user.password_cost)
            .reduce(crate::password::hash::HashCost::at_least)
    }

    /// The security settings.
    pub fn settings(&self) -> &SecuritySettings {
        &self.settings
    }

    /// Whether the vault holds an operator secret (the condition of IAM-07).
    pub fn operator_secrets(&self) -> bool {
        self.operator_secrets
    }

    /// The scoped grants a user holds.
    pub fn grants_of(&self, id: UserId) -> &[GrantRecord] {
        self.grants.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Every scoped grant, by subject.
    pub fn all_grants(&self) -> impl Iterator<Item = &GrantRecord> {
        self.grants.values().flatten()
    }

    /// A token, personal or scoped.
    pub fn token(&self, id: ApiTokenId) -> Option<&TokenAuthz> {
        self.tokens.get(&id)
    }

    /// The stored MFA policy of a role, if one is set.
    pub fn policy(&self, role: RoleName) -> Option<RoleMfa> {
        self.policies.get(&role).copied()
    }

    /// Every role a user holds: global roles and the roles of scoped grants.
    pub fn held_roles(&self, id: UserId) -> Vec<RoleName> {
        let mut roles: Vec<RoleName> = self
            .user(id)
            .map(|user| user.roles.clone())
            .unwrap_or_default();
        roles.extend(self.grants_of(id).iter().map(|grant| grant.role));
        roles.sort();
        roles.dedup();
        roles
    }

    /// The weakest session strength that may act for the user: the profile's requirement
    /// (TGL-02, TGL-03), the PIN coupling rule (IAM-07) and the MFA policy of every role the
    /// user holds at any scope (IAM-06).
    pub fn required_strength(&self, id: UserId, action: Action) -> AuthStrength {
        let roles = self.held_roles(id);
        let mut required = required_strength(&roles, &self.settings, action, self.operator_secrets);
        for role in roles {
            if let Some(policy) = self.policy(role) {
                required = required.max(policy.strength());
            }
        }
        required
    }

    /// Whether users may choose the language `tag`: a built-in language or an active pack.
    pub fn is_language(&self, tag: &str) -> bool {
        BUILT_IN_LANGUAGES.contains(&tag) || self.languages.contains(tag)
    }

    /// The languages users may choose: the built-in ones, then the active packs by tag.
    pub fn languages(&self) -> Vec<String> {
        BUILT_IN_LANGUAGES
            .iter()
            .map(|tag| (*tag).to_owned())
            .chain(
                self.languages
                    .iter()
                    .filter(|tag| !BUILT_IN_LANGUAGES.contains(&tag.as_str()))
                    .cloned(),
            )
            .collect()
    }

    fn load_languages(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.languages = view
            .scan_typed(&PACKS, KeyRange::all(), MAX_PACKS, false)?
            .into_iter()
            .filter(|(_, pack, _)| pack.is_active())
            .map(|(tag, _, _)| tag)
            .collect();
        Ok(())
    }

    fn load_operator_secrets(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.operator_secrets = !view
            .scan(OPERATOR_INDEX.name(), KeyRange::all(), 1, false)?
            .is_empty();
        Ok(())
    }

    fn load_user(&mut self, view: &dyn ReadView, id: UserId) -> Result<(), StoreError> {
        let users = Arc::make_mut(&mut self.users);
        match view.get_typed(&USERS, &id)? {
            Some((user, _)) => {
                users.insert(id, user_authz(user));
            }
            None => {
                users.remove(&id);
            }
        }
        Ok(())
    }

    fn load_settings(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.settings = view
            .get_typed(&crate::model::SETTINGS, &())?
            .map(|(settings, _)| settings)
            .unwrap_or_default();
        Ok(())
    }

    fn load_grants(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        let mut grants: HashMap<UserId, Vec<GrantRecord>> = HashMap::new();
        for (_, grant, _) in view.scan_typed(&GRANTS, KeyRange::all(), MAX_ROWS, false)? {
            grants.entry(grant.subject).or_default().push(grant);
        }
        self.grants = Arc::new(grants);
        Ok(())
    }

    fn load_policies(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.policies = view
            .scan_typed(
                &ROLE_POLICIES,
                KeyRange::all(),
                RoleName::ALL.len() + 1,
                false,
            )?
            .into_iter()
            .map(|(_, policy, _)| (policy.role, policy.mfa))
            .collect();
        Ok(())
    }

    fn load_token(
        &mut self,
        view: &dyn ReadView,
        table: &TableName,
        hash: Vec<u8>,
    ) -> Result<(), StoreError> {
        let found = if table == TOKENS.name() {
            view.get_typed(&TOKENS, &hash)?.map(|(record, _)| {
                (
                    record.id,
                    TokenAuthz::Personal {
                        owner: record.owner,
                        issued_with: record.issued_with,
                    },
                )
            })
        } else {
            view.get_typed(&SCOPED_TOKENS, &hash)?.map(|(record, _)| {
                (
                    record.id,
                    TokenAuthz::Scoped {
                        owner: record.owner,
                        grants: record.grants,
                        scopes: record.scopes,
                        issued_with: record.issued_with,
                    },
                )
            })
        };
        let tokens = Arc::make_mut(&mut self.tokens);
        let hashes = Arc::make_mut(&mut self.token_hashes);
        if let Some(old) = hashes.remove(&hash) {
            tokens.remove(&old);
        }
        if let Some((id, token)) = found {
            tokens.insert(id, token);
            hashes.insert(hash, id);
        }
        Ok(())
    }

    /// Removes the token stored under `hash`, so that it is refused.
    fn remove_token(&mut self, hash: &[u8]) {
        if let Some(id) = Arc::make_mut(&mut self.token_hashes).remove(hash) {
            Arc::make_mut(&mut self.tokens).remove(&id);
        }
    }

    fn load_tokens(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        let mut tokens = HashMap::new();
        let mut hashes = HashMap::new();
        for (hash, record, _) in view.scan_typed(&TOKENS, KeyRange::all(), MAX_ROWS, false)? {
            hashes.insert(hash, record.id);
            tokens.insert(
                record.id,
                TokenAuthz::Personal {
                    owner: record.owner,
                    issued_with: record.issued_with,
                },
            );
        }
        for (hash, record, _) in
            view.scan_typed(&SCOPED_TOKENS, KeyRange::all(), MAX_ROWS, false)?
        {
            hashes.insert(hash, record.id);
            tokens.insert(
                record.id,
                TokenAuthz::Scoped {
                    owner: record.owner,
                    grants: record.grants,
                    scopes: record.scopes,
                    issued_with: record.issued_with,
                },
            );
        }
        self.tokens = Arc::new(tokens);
        self.token_hashes = Arc::new(hashes);
        Ok(())
    }
}

fn user_authz(user: crate::model::UserRecord) -> UserAuthz {
    UserAuthz {
        password_cost: user
            .password
            .as_ref()
            .and_then(|password| crate::password::hash::HashCost::of_hash(&password.hash)),
        roles: user.roles,
        disabled: user.disabled,
        break_glass: user.break_glass,
        kind: user.kind,
    }
}

impl IndexImage for AuthImage {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn memory_bytes(&self) -> usize {
        self.users.len() * (std::mem::size_of::<UserAuthz>() + 32)
            + self.grants.values().map(Vec::len).sum::<usize>()
                * (std::mem::size_of::<GrantRecord>() + 16)
            + self.tokens.len() * (std::mem::size_of::<TokenAuthz>() + 64)
    }
}

/// The derived index of user roles, grants, tokens, policies and security settings.
#[derive(Debug, Default)]
pub struct AuthIndex {
    live: ArcSwap<AuthImage>,
}

impl AuthIndex {
    /// An empty index; the store fills it at registration.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current image.
    pub fn image(&self) -> Arc<AuthImage> {
        self.live.load_full()
    }
}

/// Largest number of users read when the index is built.
const MAX_USERS: usize = 1_000_000;
/// Largest number of grants or tokens read when the index is built.
const MAX_ROWS: usize = 1_000_000;
/// Largest number of language packs read when the index is built.
const MAX_PACKS: usize = 10_000;

/// The tables the authorization index derives from: a commit that changes none of them changes
/// no decision of authorization.
pub fn authorization_tables() -> [TableName; 8] {
    [
        USERS.name().clone(),
        crate::model::SETTINGS.name().clone(),
        OPERATOR_INDEX.name().clone(),
        PACKS.name().clone(),
        GRANTS.name().clone(),
        ROLE_POLICIES.name().clone(),
        TOKENS.name().clone(),
        SCOPED_TOKENS.name().clone(),
    ]
}

impl DerivedIndex for AuthIndex {
    fn name(&self) -> &'static str {
        "auth.index"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables(authorization_tables())
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let mut image = AuthImage {
            revision: view.revision(),
            ..AuthImage::default()
        };
        let mut users = HashMap::new();
        for (id, user, _) in view.scan_typed(&USERS, KeyRange::all(), MAX_USERS, false)? {
            users.insert(id, user_authz(user));
        }
        image.users = Arc::new(users);
        image.load_settings(view)?;
        image.load_operator_secrets(view)?;
        image.load_languages(view)?;
        image.load_grants(view)?;
        image.load_policies(view)?;
        image.load_tokens(view)?;
        Ok(Box::new(image))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<AuthImage>(image) {
            self.live.store(Arc::from(image));
        }
    }

    /// Applies one change set. When an entry cannot be read or decoded, the whole index is
    /// built again from `view`; when that fails too, the image fails closed for what it
    /// could not read: a user or a token that did not load is removed (refused), the grants
    /// are emptied when they did not reload, and the vault counts as holding an operator
    /// secret (the stricter PIN rule). Settings and role policies that did not reload keep
    /// their previous value, since no value is known to be stricter without them.
    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let mut image = AuthImage::clone(&self.live.load());
        image.revision = changes.revision;
        let mut grants = false;
        let mut policies = false;
        let mut failed = false;
        for change in &changes.changes {
            let table = &change.table;
            let result = if table == USERS.name() {
                match USERS.decode_key(&change.key) {
                    Ok(id) => image.load_user(view, id).inspect_err(|_| {
                        Arc::make_mut(&mut image.users).remove(&id);
                    }),
                    Err(error) => Err(error.into()),
                }
            } else if table == crate::model::SETTINGS.name() {
                image.load_settings(view)
            } else if table == OPERATOR_INDEX.name() {
                image.load_operator_secrets(view).inspect_err(|_| {
                    image.operator_secrets = true;
                })
            } else if table == PACKS.name() {
                image.load_languages(view)
            } else if table == GRANTS.name() {
                grants = true;
                Ok(())
            } else if table == ROLE_POLICIES.name() {
                policies = true;
                Ok(())
            } else if table == TOKENS.name() || table == SCOPED_TOKENS.name() {
                match TOKENS.decode_key(&change.key) {
                    Ok(hash) => image
                        .load_token(view, table, hash.clone())
                        .inspect_err(|_| {
                            image.remove_token(&hash);
                        }),
                    Err(error) => Err(error.into()),
                }
            } else {
                Ok(())
            };
            if let Err(error) = result {
                failed = true;
                tracing::error!(%error, revision = %changes.revision, "auth index update failed");
            }
        }
        // Grants and policies are few: reloaded whole, once per change set.
        if grants && let Err(error) = image.load_grants(view) {
            failed = true;
            image.grants = Arc::new(HashMap::new());
            tracing::error!(%error, revision = %changes.revision, "auth index grants not reloaded");
        }
        if policies && let Err(error) = image.load_policies(view) {
            failed = true;
            tracing::error!(%error, revision = %changes.revision, "auth index policies not reloaded");
        }
        if failed {
            match self.build(view) {
                Ok(rebuilt) => {
                    self.install(rebuilt);
                    return;
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        revision = %changes.revision,
                        "auth index not rebuilt; what did not load is refused"
                    );
                }
            }
        }
        self.live.store(Arc::new(image));
    }
}

/// How far a principal's permissions reach for one action on one kind of object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// A global role (or a global token grant within one) allows it on every object.
    Global,
    /// Only scoped grants allow it: an object must be covered by every layer, one layer for
    /// a user (the rules of its grants) and two for a scoped token (its own rules and its
    /// owner's). Each layer is a [`ScopeFilter::Only`].
    Scoped(Vec<ScopeFilter>),
    /// Nothing allows it.
    Denied,
}

impl Reach {
    /// Whether an object with these anchors is reached for an action of this mode.
    pub fn admits(&self, anchors: &Anchors, mode: AnchorMode) -> bool {
        match self {
            Self::Global => true,
            Self::Denied => false,
            Self::Scoped(layers) => layers.iter().all(|layer| layer.admits(anchors, mode)),
        }
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Denied, _) | (_, Self::Denied) => Self::Denied,
            (Self::Global, reach) | (reach, Self::Global) => reach,
            (Self::Scoped(mut layers), Self::Scoped(more)) => {
                layers.extend(more);
                Self::Scoped(layers)
            }
        }
    }
}

/// The reach of a user's global roles and scoped grants.
pub fn user_reach(
    user: &UserAuthz,
    grants: &[GrantRecord],
    action: Action,
    kind: ObjectKind,
) -> Reach {
    if user.roles.iter().any(|role| role.allows(action, kind)) {
        return Reach::Global;
    }
    if !is_scoped_kind(kind) {
        return Reach::Denied;
    }
    let rules: Vec<ScopeRule> = grants
        .iter()
        .filter(|grant| grant.role.allows(action, kind))
        .map(|grant| grant.scope.clone())
        .collect();
    if rules.is_empty() {
        Reach::Denied
    } else {
        Reach::Scoped(vec![ScopeFilter::Only(rules)])
    }
}

/// The reach of a scoped token's own grants, before the owner's are applied.
pub fn token_grants_reach(grants: &[TokenGrant], action: Action, kind: ObjectKind) -> Reach {
    if grants
        .iter()
        .any(|grant| grant.scope.is_none() && grant.role.allows(action, kind))
    {
        return Reach::Global;
    }
    if !is_scoped_kind(kind) {
        return Reach::Denied;
    }
    let rules: Vec<ScopeRule> = grants
        .iter()
        .filter(|grant| grant.role.allows(action, kind))
        .filter_map(|grant| grant.scope.clone())
        .collect();
    if rules.is_empty() {
        Reach::Denied
    } else {
        Reach::Scoped(vec![ScopeFilter::Only(rules)])
    }
}

/// The resolver of anchors and the store it reads, set by the server when IPAM starts
/// (`AuthService::set_anchor_resolver`). Without it a scoped principal is refused on every
/// object it would need anchors for.
#[derive(Default)]
pub struct ScopeSupport {
    wiring: ArcSwapOption<ScopeWiring>,
}

impl std::fmt::Debug for ScopeSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeSupport")
            .field("wired", &self.wiring.load().is_some())
            .finish()
    }
}

struct ScopeWiring {
    resolver: Arc<dyn AnchorResolver>,
    store: Arc<dyn Store>,
}

impl ScopeSupport {
    /// Wires the resolver and the store it reads.
    pub fn set(&self, resolver: Arc<dyn AnchorResolver>, store: Arc<dyn Store>) {
        self.wiring
            .store(Some(Arc::new(ScopeWiring { resolver, store })));
    }

    /// Whether a resolver is wired.
    pub fn is_wired(&self) -> bool {
        self.wiring.load().is_some()
    }

    /// The anchors of an object as the resolver finds them in the local copy of the store;
    /// `None` without a resolver or when the resolver fails.
    pub fn anchors(&self, object: &ObjectRef) -> Option<Anchors> {
        let wiring = self.wiring.load_full()?;
        let view = LazyView::new(Arc::clone(&wiring.store));
        wiring.resolver.anchors(&view, object).ok()
    }

    /// The anchors of an object read through `view`.
    pub fn anchors_in(&self, view: &dyn ReadView, object: &ObjectRef) -> Option<Anchors> {
        let wiring = self.wiring.load_full()?;
        wiring.resolver.anchors(view, object).ok()
    }
}

/// A read view opened on first use: the IPAM resolver answers most kinds from memory, so a
/// check usually opens no read transaction. Opening polls the store's local read once; a
/// store that cannot answer at once (it never happens for a local read today) makes every
/// read fail, and the check is refused.
struct LazyView {
    store: Arc<dyn Store>,
    view: OnceLock<Option<Arc<dyn ReadView>>>,
}

impl LazyView {
    fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            view: OnceLock::new(),
        }
    }

    fn open(&self) -> Result<&Arc<dyn ReadView>, StoreError> {
        self.view
            .get_or_init(|| {
                let mut read = self.store.read(ReadConsistency::Local);
                match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                    Poll::Ready(Ok(view)) => Some(view),
                    Poll::Ready(Err(error)) => {
                        tracing::debug!(%error, "no local view for an authorization check");
                        None
                    }
                    Poll::Pending => None,
                }
            })
            .as_ref()
            .ok_or(StoreError::Timeout)
    }
}

impl ReadView for LazyView {
    fn revision(&self) -> Revision {
        self.open().map_or(Revision::ZERO, |view| view.revision())
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        self.open()?.get(table, key)
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(bytes::Bytes, Versioned)>, StoreError> {
        self.open()?.scan(table, range, limit, reverse)
    }

    fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
        self.open()?.counter(counter)
    }
}

/// Role-based and scoped authorization over the [`AuthIndex`].
#[derive(Debug, Clone)]
pub struct RbacAuthorizer {
    index: Arc<AuthIndex>,
    scope: Arc<ScopeSupport>,
}

impl RbacAuthorizer {
    /// An authorizer over the index without anchors: scoped principals are refused on
    /// every object that needs them.
    pub fn new(index: Arc<AuthIndex>) -> Self {
        Self::with_scope(index, Arc::new(ScopeSupport::default()))
    }

    /// An authorizer over the index that finds anchors through `scope`.
    pub fn with_scope(index: Arc<AuthIndex>, scope: Arc<ScopeSupport>) -> Self {
        Self { index, scope }
    }

    /// The reach of a principal for an action on a kind, after the strength check.
    ///
    /// # Errors
    ///
    /// The reason of a refusal that does not depend on the object: unauthenticated,
    /// missing permission or a step-up.
    pub fn reach(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<Reach, DenyReason> {
        let image = self.index.image();
        let kind = object.kind;
        match principal {
            Principal::System { .. } => Ok(Reach::Global),
            // Probes and peers get their own grants with enrollment (Slice 2).
            Principal::Node { .. } => Err(DenyReason::MissingPermission),
            Principal::User { id, strength, .. } => {
                let user = image
                    .user(*id)
                    .filter(|user| !user.disabled && user.kind == UserKind::Person)
                    .ok_or(DenyReason::Unauthenticated)?;
                let reach = user_reach(user, image.grants_of(*id), action, kind);
                if reach == Reach::Denied {
                    return Err(DenyReason::MissingPermission);
                }
                let required = image.required_strength(*id, action);
                if satisfies(*strength, required) {
                    Ok(reach)
                } else {
                    Err(DenyReason::StepUpRequired { required })
                }
            }
            Principal::Token { id, owner } => {
                let user = image
                    .user(*owner)
                    .filter(|user| !user.disabled && !user.break_glass)
                    .ok_or(DenyReason::Unauthenticated)?;
                let token = image
                    .token(*id)
                    .filter(|token| token.owner() == *owner)
                    .ok_or(DenyReason::Unauthenticated)?;
                if interactive_only(action, kind) {
                    return Err(DenyReason::MissingPermission);
                }
                // The owner's requirement may have risen since the token was issued (a
                // profile, a setting, a role policy, an operator secret); a token issued
                // below it acts no more until a stronger sign-in creates a new one.
                let required = image.required_strength(*owner, action);
                if !satisfies(token.issued_with(), required) {
                    return Err(DenyReason::StepUpRequired { required });
                }
                let owner_reach = user_reach(user, image.grants_of(*owner), action, kind);
                let reach = match token {
                    // Service accounts act through scoped tokens only.
                    TokenAuthz::Personal { .. } if user.kind == UserKind::Service => {
                        return Err(DenyReason::Unauthenticated);
                    }
                    TokenAuthz::Personal { .. } => owner_reach,
                    TokenAuthz::Scoped { grants, scopes, .. } => {
                        if action == Action::Read
                            && special_scope(object).is_some_and(|scope| scopes.contains(&scope))
                            && (user.kind == UserKind::Service
                                || user
                                    .roles
                                    .iter()
                                    .any(|role| role.allows(Action::Read, ObjectKind::System)))
                        {
                            return Ok(Reach::Global);
                        }
                        token_grants_reach(grants, action, kind).intersect(owner_reach)
                    }
                };
                if reach == Reach::Denied {
                    Err(DenyReason::MissingPermission)
                } else {
                    Ok(reach)
                }
            }
        }
    }

    fn decide(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), DenyReason> {
        let reach = self.reach(principal, action, object)?;
        if reach == Reach::Global || object.id == ANYWHERE {
            return Ok(());
        }
        if action == Action::Read && is_context_kind(object.kind) {
            return Ok(());
        }
        if object.id.is_nil() {
            return Err(DenyReason::OutOfScope);
        }
        let anchors = self.scope.anchors(object).ok_or(DenyReason::OutOfScope)?;
        if reach.admits(&anchors, mode_of(action)) {
            Ok(())
        } else {
            Err(DenyReason::OutOfScope)
        }
    }

    /// The rules of a scoped token's own layer that lie inside the owner's layer, the
    /// one-filter form of an intersection ([`Authorizer::scope`]).
    fn narrow(&self, layers: Vec<ScopeFilter>) -> ScopeFilter {
        let mut layers = layers.into_iter();
        let Some(ScopeFilter::Only(rules)) = layers.next() else {
            return ScopeFilter::Nothing;
        };
        let rest: Vec<ScopeFilter> = layers.collect();
        let anchors = |object: &ObjectRef| self.scope.anchors(object);
        let kept: Vec<ScopeRule> = rules
            .into_iter()
            .filter(|rule| {
                rest.iter().all(|layer| match layer {
                    ScopeFilter::All => true,
                    ScopeFilter::Nothing => false,
                    ScopeFilter::Only(outer) => outer
                        .iter()
                        .any(|outer| crate::grants::rule_within(rule, outer, &anchors)),
                })
            })
            .collect();
        if kept.is_empty() {
            ScopeFilter::Nothing
        } else {
            ScopeFilter::Only(kept)
        }
    }
}

/// The special token scope that reads `object`, if it is one of the special objects.
fn special_scope(object: &ObjectRef) -> Option<TokenScope> {
    if *object == METRICS_OBJECT {
        Some(TokenScope::Metrics)
    } else if *object == AUDIT_OBJECT {
        Some(TokenScope::AuditRead)
    } else {
        None
    }
}

impl Authorizer for RbacAuthorizer {
    fn check(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        let decided = self.decide(principal, action, object);
        // The check journal of a keyed request (`crate::journal`): a passed check is noted,
        // and for a scoped kind the principal's scope too, which computing it notes.
        if decided.is_ok() && crate::journal::note_check(principal, action, object) {
            let _ = self.scope(principal, action, object.kind);
        }
        decided.map_err(|reason| Denied {
            action,
            object: *object,
            reason,
        })
    }

    fn scope(&self, principal: &Principal, action: Action, kind: ObjectKind) -> ScopeFilter {
        let filter = match self.reach(principal, action, &anywhere(kind)) {
            Ok(Reach::Global) => ScopeFilter::All,
            Ok(Reach::Scoped(mut layers)) if layers.len() == 1 => {
                layers.pop().unwrap_or(ScopeFilter::Nothing)
            }
            Ok(Reach::Scoped(layers)) => self.narrow(layers),
            Ok(Reach::Denied) | Err(_) => ScopeFilter::Nothing,
        };
        crate::journal::note_scope(principal, action, kind, &filter);
        filter
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        Principal, SystemComponent, Timestamp,
        i18n::{PackRecord, PackState},
    };
    use tenko_store::{MemStore, Store, WriteBatch};

    use super::*;

    /// A read view over a store that fails its point reads of users and tokens, and every
    /// scan when asked:
    /// a store error, or a row this build cannot decode, as the index meets it.
    struct FailingView {
        inner: Arc<dyn ReadView>,
        scans_fail: bool,
    }

    impl ReadView for FailingView {
        fn revision(&self) -> Revision {
            self.inner.revision()
        }

        fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
            // The rows an update reads one by one: users and tokens.
            if table == USERS.name() || table == TOKENS.name() {
                return Err(StoreError::Storage("injected read failure".to_owned()));
            }
            self.inner.get(table, key)
        }

        fn scan(
            &self,
            table: &TableName,
            range: KeyRange,
            limit: usize,
            reverse: bool,
        ) -> Result<Vec<(bytes::Bytes, Versioned)>, StoreError> {
            if self.scans_fail {
                return Err(StoreError::Storage("injected scan failure".to_owned()));
            }
            self.inner.scan(table, range, limit, reverse)
        }

        fn counter(&self, counter: &CounterKey) -> Result<u64, StoreError> {
            self.inner.counter(counter)
        }
    }

    fn batch() -> WriteBatch {
        WriteBatch::new(
            Principal::system(SystemComponent::Auth),
            Timestamp::UNIX_EPOCH,
        )
    }

    fn change_of(table: &TableName, key: bytes::Bytes) -> ChangeSet {
        ChangeSet {
            revision: Revision(1_000),
            principal: Principal::system(SystemComponent::Auth),
            at: Timestamp::UNIX_EPOCH,
            changes: vec![tenko_store::Change {
                table: table.clone(),
                key,
                deleted: false,
            }],
        }
    }

    /// An index over a store with one administrator, one personal token of hers and one
    /// grant of hers.
    async fn indexed() -> (
        Arc<MemStore>,
        Arc<AuthIndex>,
        crate::model::UserRecord,
        Vec<u8>,
    ) {
        let store = Arc::new(MemStore::default());
        let index = Arc::new(AuthIndex::new());
        store.register_index(index.clone()).expect("register");
        let user = crate::model::UserRecord::new(
            "ada".to_owned(),
            "Ada".to_owned(),
            vec![RoleName::Admin],
            Timestamp::UNIX_EPOCH,
        );
        let hash = vec![7_u8; 32];
        let mut write = batch();
        write.put_typed(&USERS, &user.id, &user).expect("user");
        write
            .put_typed(
                &TOKENS,
                &hash,
                &crate::model::TokenRecord {
                    id: ApiTokenId::generate(),
                    owner: user.id,
                    name: "t".to_owned(),
                    created_at: Timestamp::UNIX_EPOCH,
                    expires_at: None,
                    last_used_at: None,
                    issued_with: AuthStrength::Password,
                    prefix: "tnk_".to_owned(),
                    generation: 0,
                },
            )
            .expect("token");
        write
            .put_typed(
                &GRANTS,
                &crate::model::GrantId::generate(),
                &GrantRecord {
                    id: crate::model::GrantId::generate(),
                    subject: user.id,
                    role: RoleName::Operator,
                    scope: ScopeRule::Vrf(tenko_core::VrfId::generate()),
                    delegable: false,
                    granted_by: None,
                    granted_at: Timestamp::UNIX_EPOCH,
                    parent: None,
                },
            )
            .expect("grant");
        store.propose(write).await.expect("commit");
        assert!(index.image().user(user.id).is_some());
        assert_eq!(index.image().grants_of(user.id).len(), 1);
        (store, index, user, hash)
    }

    #[tokio::test]
    async fn an_update_that_cannot_be_read_refuses_what_it_could_not_load() {
        let (store, index, user, hash) = indexed().await;
        // The user is disabled; the update reaches the index, but nothing can be read.
        let mut disabled = user.clone();
        disabled.disabled = true;
        let mut write = batch();
        write.put_typed(&USERS, &user.id, &disabled).expect("user");
        store.propose(write).await.expect("commit");
        let view = FailingView {
            inner: store.read(ReadConsistency::Local).await.expect("view"),
            scans_fail: true,
        };
        // Back to the image before the disable, as an index that missed it would hold.
        index.install(Box::new({
            let mut before = AuthImage::clone(&index.image());
            Arc::make_mut(&mut before.users).insert(user.id, user_authz(user.clone()));
            before
        }));
        index.apply(&change_of(USERS.name(), USERS.key(&user.id)), &view);
        assert!(
            index.image().user(user.id).is_none(),
            "a user that did not load is refused, not served from the old state"
        );

        let token = index
            .image()
            .token_hashes
            .get(&hash)
            .copied()
            .expect("token");
        index.apply(&change_of(TOKENS.name(), TOKENS.key(&hash)), &view);
        assert!(index.image().token(token).is_none(), "the token is refused");

        index.apply(
            &change_of(
                GRANTS.name(),
                GRANTS.key(&crate::model::GrantId::generate()),
            ),
            &view,
        );
        assert!(
            index.image().grants_of(user.id).is_empty(),
            "grants fail closed"
        );

        index.apply(
            &change_of(OPERATOR_INDEX.name(), bytes::Bytes::from_static(b"k")),
            &view,
        );
        assert!(
            index.image().operator_secrets(),
            "the stricter PIN rule holds"
        );
    }

    #[tokio::test]
    async fn an_update_that_cannot_be_read_rebuilds_the_index_when_it_can() {
        let (store, index, user, _) = indexed().await;
        let mut disabled = user.clone();
        disabled.disabled = true;
        let mut write = batch();
        write.put_typed(&USERS, &user.id, &disabled).expect("user");
        store.propose(write).await.expect("commit");
        index.install(Box::new({
            let mut before = AuthImage::clone(&index.image());
            Arc::make_mut(&mut before.users).insert(user.id, user_authz(user.clone()));
            before
        }));
        // Point reads fail, scans work: the rebuild reads the disable.
        let view = FailingView {
            inner: store.read(ReadConsistency::Local).await.expect("view"),
            scans_fail: false,
        };
        index.apply(&change_of(USERS.name(), USERS.key(&user.id)), &view);
        let image = index.image();
        assert!(image.user(user.id).is_some_and(|loaded| loaded.disabled));
        assert_eq!(image.grants_of(user.id).len(), 1, "the rest is intact");
    }

    async fn put_pack(store: &MemStore, tag: &str, state: PackState) {
        let mut batch = WriteBatch::new(
            Principal::system(SystemComponent::Languages),
            Timestamp::UNIX_EPOCH,
        );
        batch
            .put_typed(
                &PACKS,
                &tag.to_owned(),
                &PackRecord {
                    tag: tag.to_owned(),
                    state,
                    display_name: String::new(),
                },
            )
            .expect("encode");
        store.propose(batch).await.expect("commit");
    }

    #[tokio::test]
    async fn the_language_set_follows_the_active_packs() {
        let store = MemStore::default();
        put_pack(&store, "fr", PackState::Active).await;
        let index = Arc::new(AuthIndex::new());
        store.register_index(index.clone()).expect("register");
        let image = index.image();
        assert!(image.is_language("en") && image.is_language("sv"));
        assert!(image.is_language("fr"), "built from the table");
        assert_eq!(image.languages(), ["en", "sv", "fr"]);

        put_pack(&store, "de", PackState::Uploaded).await;
        assert!(!index.image().is_language("de"), "uploaded is not active");
        put_pack(&store, "de", PackState::Active).await;
        assert!(index.image().is_language("de"), "applied in revision order");
        put_pack(&store, "fr", PackState::Previewed).await;
        assert!(!index.image().is_language("fr"));
        // A pack that overrides a built-in language never removes it.
        put_pack(&store, "sv", PackState::Uploaded).await;
        assert_eq!(index.image().languages(), ["en", "sv", "de"]);
        assert!(AuthImage::default().is_language("sv"));
    }

    #[test]
    fn the_special_objects_are_distinct_system_objects() {
        assert_eq!(METRICS_OBJECT.kind, ObjectKind::System);
        assert_eq!(AUDIT_OBJECT.kind, ObjectKind::System);
        assert_ne!(METRICS_OBJECT, AUDIT_OBJECT);
        assert!(!METRICS_OBJECT.id.is_nil() && METRICS_OBJECT.id != ANYWHERE);
        assert_eq!(special_scope(&METRICS_OBJECT), Some(TokenScope::Metrics));
        assert_eq!(special_scope(&AUDIT_OBJECT), Some(TokenScope::AuditRead));
        assert_eq!(
            special_scope(&ObjectRef::singleton(ObjectKind::System)),
            None
        );
    }

    #[test]
    fn global_only_kinds_are_never_scoped() {
        for kind in [
            ObjectKind::Import,
            ObjectKind::Connector,
            ObjectKind::Node,
            ObjectKind::Secret,
            ObjectKind::Settings,
            ObjectKind::User,
            ObjectKind::System,
            ObjectKind::Session,
            ObjectKind::ApiToken,
        ] {
            assert!(!is_scoped_kind(kind), "{kind}");
            assert!(!is_context_kind(kind), "{kind}");
        }
        for &kind in ObjectKind::ALL {
            if is_context_kind(kind) {
                assert!(is_scoped_kind(kind), "{kind}");
            }
        }
    }

    #[test]
    fn reaches_intersect() {
        let only = |n: u128| {
            ScopeFilter::Only(vec![ScopeRule::Object(ObjectRef::new(
                ObjectKind::Host,
                Uuid::from_u128(n),
            ))])
        };
        assert_eq!(Reach::Global.intersect(Reach::Global), Reach::Global);
        assert_eq!(
            Reach::Global.intersect(Reach::Scoped(vec![only(1)])),
            Reach::Scoped(vec![only(1)])
        );
        assert_eq!(
            Reach::Scoped(vec![only(1)]).intersect(Reach::Denied),
            Reach::Denied
        );
        let both = Reach::Scoped(vec![only(1)]).intersect(Reach::Scoped(vec![only(2)]));
        assert_eq!(both, Reach::Scoped(vec![only(1), only(2)]));
        let one = Anchors::of(ObjectRef::new(ObjectKind::Host, Uuid::from_u128(1)));
        assert!(
            !both.admits(&one, AnchorMode::Any),
            "both layers must cover"
        );
        assert!(Reach::Scoped(vec![only(1)]).admits(&one, AnchorMode::All));
    }
}
