//! Principals, request context and authorization (plan section 2.1, IAM-19, NEVER-03).
//!
//! Every write names its principal; there is no anonymous change. Background work runs as
//! [`Principal::System`], optionally on behalf of the user who started it.

use std::{collections::BTreeMap, fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    error::Coded,
    id::{ApiTokenId, NodeId, PrefixId, RequestId, SessionId, SiteId, TenantId, UserId, VrfId},
    names::IdempotencyKey,
    object::{ObjectKind, ObjectRef},
    timestamp::Timestamp,
};

/// Who performs an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    /// A user with an interactive session.
    User {
        /// The user.
        id: UserId,
        /// The session the request arrived on.
        session: SessionId,
        /// How strongly the session was authenticated.
        strength: AuthStrength,
    },
    /// A personal API token (IAM-10).
    Token {
        /// The token.
        id: ApiTokenId,
        /// The user who owns the token.
        owner: UserId,
    },
    /// A component of Tenko itself.
    System {
        /// The acting component.
        component: SystemComponent,
        /// The user whose request started the work, if any.
        #[serde(default)]
        on_behalf_of: Option<UserId>,
    },
    /// A cluster node: a probe or a peer controller (Slice 2).
    Node {
        /// The node.
        id: NodeId,
    },
}

impl Principal {
    /// A system principal acting on its own.
    pub const fn system(component: SystemComponent) -> Self {
        Principal::System {
            component,
            on_behalf_of: None,
        }
    }

    /// The user behind this principal: the session user, the token owner or the user a
    /// system component acts for.
    pub fn user(&self) -> Option<UserId> {
        match self {
            Principal::User { id, .. } => Some(*id),
            Principal::Token { owner, .. } => Some(*owner),
            Principal::System { on_behalf_of, .. } => *on_behalf_of,
            Principal::Node { .. } => None,
        }
    }

    /// The authentication strength of an interactive session.
    pub fn strength(&self) -> Option<AuthStrength> {
        match self {
            Principal::User { strength, .. } => Some(*strength),
            _ => None,
        }
    }

    /// A stable subject string that scopes per-principal state such as idempotency keys:
    /// `user:<id>`, `token:<id>`, `system:<component>` or `node:<id>`. Sessions of the same
    /// user share the subject.
    pub fn subject(&self) -> String {
        match self {
            Principal::User { id, .. } => format!("user:{id}"),
            Principal::Token { id, .. } => format!("token:{id}"),
            Principal::System { component, .. } => format!("system:{}", component.as_str()),
            Principal::Node { id } => format!("node:{id}"),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.subject())
    }
}

/// Components that act as [`Principal::System`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SystemComponent {
    /// First-run setup (API-10).
    Setup,
    /// The API platform.
    Api,
    /// Authentication and sessions.
    Auth,
    /// The vault.
    Vault,
    /// The store itself (snapshot and purge, maintenance).
    Store,
    /// The IPAM domain.
    Ipam,
    /// Import and export.
    Import,
    /// The job engine.
    Jobs,
    /// The intent and observation reconciler (Slice 2).
    Reconciler,
    /// A connector (Slice 2).
    Connector,
    /// Discovery (Slice 2).
    Scan,
    /// Cluster management (enrolment, membership).
    Cluster,
    /// The audit export (Slice 3, IAM-18): sinks, cursors and checkpoints.
    AuditExport,
    /// Backups and restores (Slice 3, OPS-07).
    Backup,
    /// Language packs (Slice 3, API-21).
    Languages,
    /// The leader supervisor: taking office and the epoch of leader-only work (Slice 3).
    Leader,
    /// The DNS module (Phase 2): the zone service, the DNS actuator, dynamic updates.
    Dns,
    // WP7.0
    /// The DHCP module (Phase 3): lease commits, expiry, DDNS change sets, the
    /// configuration service.
    Dhcp,
}

impl SystemComponent {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SystemComponent::Setup => "setup",
            SystemComponent::Api => "api",
            SystemComponent::Auth => "auth",
            SystemComponent::Vault => "vault",
            SystemComponent::Store => "store",
            SystemComponent::Ipam => "ipam",
            SystemComponent::Import => "import",
            SystemComponent::Jobs => "jobs",
            SystemComponent::Reconciler => "reconciler",
            SystemComponent::Connector => "connector",
            SystemComponent::Scan => "scan",
            SystemComponent::Cluster => "cluster",
            SystemComponent::AuditExport => "audit_export",
            SystemComponent::Backup => "backup",
            SystemComponent::Languages => "languages",
            SystemComponent::Leader => "leader",
            SystemComponent::Dns => "dns",
            SystemComponent::Dhcp => "dhcp",
        }
    }
}

/// How a session was authenticated, weakest first, so `>=` compares strength (IAM-03,
/// IAM-06).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrength {
    /// PIN preset (lab use).
    Pin,
    /// Password only.
    Password,
    /// Password plus TOTP or a recovery code.
    PasswordTotp,
    /// A passkey (platform or synced authenticator).
    Passkey,
    /// A hardware security key (attested, not backup-eligible).
    HardwareKey,
}

impl AuthStrength {
    /// The serde name of the variant (`pin`, `password`, `password_totp`, `passkey`,
    /// `hardware_key`), the one form used in error parameters and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::Password => "password",
            Self::PasswordTotp => "password_totp",
            Self::Passkey => "passkey",
            Self::HardwareKey => "hardware_key",
        }
    }
}

/// Context of one request or unit of background work, passed to every domain call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestCtx {
    /// Who acts.
    pub principal: Principal,
    /// Identifier of the request, carried into write batches and audit records.
    pub request: RequestId,
    /// The time the request is processed at; domain code uses this, never the clock.
    pub now: Timestamp,
    /// The client address, when the request came over the network.
    pub source_ip: Option<IpAddr>,
    /// The client's idempotency key (API-04).
    pub idempotency: Option<IdempotencyKey>,
}

impl RequestCtx {
    /// A context with a new request id and the current time.
    pub fn new(principal: Principal) -> Self {
        Self {
            principal,
            request: RequestId::generate(),
            now: Timestamp::now(),
            source_ip: None,
            idempotency: None,
        }
    }

    /// A context for a system component acting on its own.
    pub fn system(component: SystemComponent) -> Self {
        Self::new(Principal::system(component))
    }

    /// Sets the client address.
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the idempotency key.
    #[must_use]
    pub fn with_idempotency(mut self, key: IdempotencyKey) -> Self {
        self.idempotency = Some(key);
        self
    }

    /// Sets the processing time.
    #[must_use]
    pub fn at(mut self, now: Timestamp) -> Self {
        self.now = now;
        self
    }
}

/// What a principal wants to do with an object. Roles map to sets of actions; the audit
/// log records the finer-grained [`AuditAction`](crate::audit::AuditAction).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read the object.
    Read,
    /// Create an object of this kind.
    Create,
    /// Change the object, including lock, status and restore.
    Update,
    /// Soft-delete the object.
    Delete,
    /// Run or cancel jobs, imports and scans against the object, or complete manual steps.
    Execute,
    /// Approve or reject proposals.
    Approve,
    /// Reveal a secret (IAM-16, Slice 2).
    Reveal,
    /// Administer users, roles, tokens, settings and the system.
    Administer,
}

impl Action {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Execute => "execute",
            Action::Approve => "approve",
            Action::Reveal => "reveal",
            Action::Administer => "administer",
        }
    }
}

/// Decides whether a principal may act (implemented by `tenko-auth`).
pub trait Authorizer: Send + Sync {
    /// Checks one action on one object.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] with the reason.
    fn check(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied>;

    /// The objects of `kind` the principal may act on, for filtering lists and event
    /// streams. Slice 1 always returns [`ScopeFilter::All`] or [`ScopeFilter::Nothing`].
    fn scope(&self, principal: &Principal, action: Action, kind: ObjectKind) -> ScopeFilter;
}

/// Why an action was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    /// No valid session or token.
    Unauthenticated,
    /// The principal's roles do not grant the action.
    MissingPermission,
    /// The action needs a stronger or fresher authentication (IAM-06, IAM-09).
    StepUpRequired {
        /// The minimum strength.
        required: AuthStrength,
    },
    /// The object is outside the principal's scope (IAM-01, Slice 3).
    OutOfScope,
}

/// An authorization failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{action} on {object} denied: {reason:?}", action = .action.as_str())]
pub struct Denied {
    /// The attempted action.
    pub action: Action,
    /// The object.
    pub object: ObjectRef,
    /// Why it was denied.
    pub reason: DenyReason,
}

impl Coded for Denied {
    fn code(&self) -> &'static str {
        match self.reason {
            DenyReason::Unauthenticated => "auth.unauthenticated",
            DenyReason::MissingPermission => "auth.forbidden",
            DenyReason::StepUpRequired { .. } => "auth.step_up_required",
            DenyReason::OutOfScope => "auth.out_of_scope",
        }
    }

    fn http_status(&self) -> u16 {
        match self.reason {
            DenyReason::Unauthenticated => 401,
            _ => 403,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        let mut params = BTreeMap::from([
            ("action", self.action.as_str().to_owned()),
            ("kind", self.object.kind.as_str().to_owned()),
        ]);
        if let DenyReason::StepUpRequired { required } = self.reason {
            params.insert("required", required.as_str().to_owned());
        }
        params
    }
}

/// The set of objects a principal may see or change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "rules", rename_all = "snake_case")]
pub enum ScopeFilter {
    /// Every object of the kind.
    All,
    /// No object of the kind.
    Nothing,
    /// Objects matching any of the rules (Slice 3).
    Only(Vec<ScopeRule>),
}

impl ScopeFilter {
    /// Whether the filter lets everything through.
    pub fn is_all(&self) -> bool {
        matches!(self, ScopeFilter::All)
    }

    /// Whether an object with these anchors is inside the scope (IAM-01).
    ///
    /// `All` admits everything and `Nothing` nothing. For `Only(rules)`, a tenant, VRF,
    /// site or object rule covers the object as a whole; a prefix rule covers one prefix
    /// chain of [`Anchors::prefixes`]. With [`AnchorMode::Any`] (reads) one covering rule
    /// suffices. With [`AnchorMode::All`] (create, update, delete) the object must be
    /// covered as a whole, or every prefix chain must be covered by some prefix rule: a
    /// scoped operator cannot change a host that also sits in a prefix outside the scope.
    /// A write that moves an object is checked against its anchors before and after the
    /// change.
    pub fn admits(&self, anchors: &Anchors, mode: AnchorMode) -> bool {
        let rules = match self {
            ScopeFilter::All => return true,
            ScopeFilter::Nothing => return false,
            ScopeFilter::Only(rules) => rules,
        };
        if rules.iter().any(|rule| rule.covers_whole(anchors)) {
            return true;
        }
        let covered = |chain: &Vec<PrefixId>| rules.iter().any(|rule| rule.covers_chain(chain));
        match mode {
            AnchorMode::Any => anchors.prefixes.iter().any(covered),
            AnchorMode::All => !anchors.prefixes.is_empty() && anchors.prefixes.iter().all(covered),
        }
    }
}

/// One rule of a scoped grant (IAM-01, Slice 3).
///
/// A rule with `subtree: true` covers the site or prefix and everything below it; with
/// `subtree: false` it covers the site or prefix itself and the objects directly in it,
/// not those of a child site or a child prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeRule {
    /// Objects of a tenant.
    Tenant(TenantId),
    /// Objects of a VRF.
    Vrf(VrfId),
    /// Objects of a site, and with `subtree` those of its child sites.
    Site {
        /// The site.
        id: SiteId,
        /// Whether child sites are included.
        subtree: bool,
    },
    /// A prefix and the objects directly in it, and with `subtree` everything inside it.
    Prefix {
        /// The prefix.
        id: PrefixId,
        /// Whether child prefixes are included.
        subtree: bool,
    },
    /// One object.
    Object(ObjectRef),
}

impl ScopeRule {
    /// Whether the rule covers the object as a whole (tenant, VRF, site or object rules).
    fn covers_whole(&self, anchors: &Anchors) -> bool {
        match self {
            ScopeRule::Tenant(tenant) => anchors.tenant == Some(*tenant),
            ScopeRule::Vrf(vrf) => anchors.vrf == Some(*vrf),
            ScopeRule::Site { id, subtree: true } => anchors.sites.contains(id),
            ScopeRule::Site { id, subtree: false } => anchors.sites.first() == Some(id),
            ScopeRule::Object(object) => anchors.object.as_ref() == Some(object),
            ScopeRule::Prefix { .. } => false,
        }
    }

    /// Whether a prefix rule covers one prefix chain (the most specific prefix first).
    fn covers_chain(&self, chain: &[PrefixId]) -> bool {
        match self {
            ScopeRule::Prefix { id, subtree: true } => chain.contains(id),
            ScopeRule::Prefix { id, subtree: false } => chain.first() == Some(id),
            _ => false,
        }
    }
}

/// Where an object sits in the scope dimensions of IAM-01, as an `AnchorResolver`
/// (`tenko_store::AnchorResolver`, implemented over the prefix tree by `tenko-ipam`) finds
/// it: a prefix anchors to itself and its ancestors, its VRF, tenant and site; an address or
/// a range to its most specific prefix; a host to its site and the prefixes of its
/// addresses; an interface to its host; a VLAN to its site; observations and proposals to
/// the prefix of their subject address; a job to its targets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Anchors {
    /// The object itself, for [`ScopeRule::Object`].
    pub object: Option<ObjectRef>,
    /// The tenant.
    pub tenant: Option<TenantId>,
    /// The VRF.
    pub vrf: Option<VrfId>,
    /// The object's site first, then its ancestors up to the root; empty without a site.
    pub sites: Vec<SiteId>,
    /// One chain per prefix the object lies in, each with the most specific prefix first
    /// and then its ancestors up to the root: one chain for a prefix (starting with itself),
    /// an address or a range, one per address prefix for a host, none for an object outside
    /// the prefix tree.
    pub prefixes: Vec<Vec<PrefixId>>,
}

impl Anchors {
    /// The anchors of an object that has nothing but itself.
    pub fn of(object: ObjectRef) -> Self {
        Self {
            object: Some(object),
            ..Self::default()
        }
    }
}

/// How many anchors of an object must be in scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorMode {
    /// One is enough: reading an object.
    Any,
    /// The whole object, or every prefix chain: creating, changing or deleting it.
    All,
}

/// An authorizer that allows everything. Only for tests and only with the `testing`
/// feature; production always uses `tenko-auth`.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

#[cfg(any(test, feature = "testing"))]
impl Authorizer for AllowAll {
    fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
        Ok(())
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::All
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{from_cbor, to_cbor},
        id::HostId,
    };

    fn user() -> Principal {
        Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        }
    }

    #[test]
    fn principals_serialize_with_a_kind_tag() {
        let principal = user();
        let json = serde_json::to_value(&principal).expect("json");
        assert_eq!(json["kind"], "user");
        assert_eq!(json["strength"], "passkey");
        let back: Principal = serde_json::from_value(json).expect("json");
        assert_eq!(back, principal);
        let system = Principal::system(SystemComponent::Jobs);
        let back: Principal = from_cbor(&to_cbor(&system).expect("cbor")).expect("cbor");
        assert_eq!(back, system);
        assert_eq!(system.subject(), "system:jobs");
    }

    #[test]
    fn strength_orders_weakest_first() {
        assert!(AuthStrength::Pin < AuthStrength::Password);
        assert!(AuthStrength::PasswordTotp < AuthStrength::Passkey);
        assert!(AuthStrength::Passkey < AuthStrength::HardwareKey);
        assert_eq!(user().strength(), Some(AuthStrength::Passkey));
    }

    #[test]
    fn token_principal_acts_for_its_owner() {
        let owner = UserId::generate();
        let token = Principal::Token {
            id: ApiTokenId::generate(),
            owner,
        };
        assert_eq!(token.user(), Some(owner));
        assert!(token.subject().starts_with("token:"));
    }

    #[test]
    fn denied_maps_to_codes() {
        let object = ObjectRef::singleton(ObjectKind::Settings);
        let denied = Denied {
            action: Action::Administer,
            object,
            reason: DenyReason::StepUpRequired {
                required: AuthStrength::HardwareKey,
            },
        };
        assert_eq!(denied.code(), "auth.step_up_required");
        assert_eq!(denied.http_status(), 403);
        assert_eq!(denied.params()["kind"], "settings");
        let unauthenticated = Denied {
            reason: DenyReason::Unauthenticated,
            ..denied
        };
        assert_eq!(unauthenticated.http_status(), 401);
    }

    fn ids() -> (TenantId, VrfId, [SiteId; 2], [PrefixId; 3]) {
        (
            TenantId::generate(),
            VrfId::generate(),
            [SiteId::generate(), SiteId::generate()],
            [
                PrefixId::generate(),
                PrefixId::generate(),
                PrefixId::generate(),
            ],
        )
    }

    fn prefix(id: PrefixId, subtree: bool) -> ScopeFilter {
        ScopeFilter::Only(vec![ScopeRule::Prefix { id, subtree }])
    }

    #[test]
    fn prefix_rules_follow_subtree_semantics() {
        let (_, _, _, [root, child, other]) = ids();
        // An address directly in `child`, which lies in `root`.
        let anchors = Anchors {
            prefixes: vec![vec![child, root]],
            ..Anchors::default()
        };
        for mode in [AnchorMode::Any, AnchorMode::All] {
            assert!(prefix(root, true).admits(&anchors, mode));
            assert!(prefix(child, false).admits(&anchors, mode));
            assert!(!prefix(root, false).admits(&anchors, mode));
            assert!(!prefix(other, true).admits(&anchors, mode));
        }
        assert!(ScopeFilter::All.admits(&anchors, AnchorMode::All));
        assert!(!ScopeFilter::Nothing.admits(&anchors, AnchorMode::Any));
        assert!(!ScopeFilter::Only(Vec::new()).admits(&anchors, AnchorMode::Any));
    }

    #[test]
    fn writes_need_every_prefix_chain_and_reads_need_one() {
        let (_, _, _, [root, child, other]) = ids();
        // A host with one address under `root` and one in the unrelated `other`.
        let host = Anchors {
            prefixes: vec![vec![child, root], vec![other]],
            ..Anchors::default()
        };
        let scoped = prefix(root, true);
        assert!(scoped.admits(&host, AnchorMode::Any));
        assert!(!scoped.admits(&host, AnchorMode::All));
        let both = ScopeFilter::Only(vec![
            ScopeRule::Prefix {
                id: root,
                subtree: true,
            },
            ScopeRule::Prefix {
                id: other,
                subtree: false,
            },
        ]);
        assert!(both.admits(&host, AnchorMode::All));
        // Prefix rules never admit a write to an object outside the prefix tree.
        assert!(!scoped.admits(&Anchors::default(), AnchorMode::All));
    }

    #[test]
    fn tenant_vrf_site_and_object_rules_cover_the_whole_object() {
        let (tenant, vrf, [site, parent], [first, ..]) = ids();
        let object = ObjectRef::new(ObjectKind::Host, HostId::generate().0);
        let anchors = Anchors {
            object: Some(object),
            tenant: Some(tenant),
            vrf: Some(vrf),
            sites: vec![site, parent],
            prefixes: vec![vec![first]],
        };
        for rule in [
            ScopeRule::Tenant(tenant),
            ScopeRule::Vrf(vrf),
            ScopeRule::Site {
                id: parent,
                subtree: true,
            },
            ScopeRule::Site {
                id: site,
                subtree: false,
            },
            ScopeRule::Object(object),
        ] {
            let filter = ScopeFilter::Only(vec![rule.clone()]);
            assert!(filter.admits(&anchors, AnchorMode::All), "{rule:?}");
            assert!(filter.admits(&anchors, AnchorMode::Any), "{rule:?}");
        }
        let parent_only = ScopeFilter::Only(vec![ScopeRule::Site {
            id: parent,
            subtree: false,
        }]);
        assert!(!parent_only.admits(&anchors, AnchorMode::Any));
        assert!(
            ScopeFilter::Only(vec![ScopeRule::Object(object)])
                .admits(&Anchors::of(object), AnchorMode::All)
        );
        assert!(
            !ScopeFilter::Only(vec![ScopeRule::Tenant(TenantId::generate())])
                .admits(&anchors, AnchorMode::Any)
        );
    }

    #[test]
    fn scope_rules_and_components_serialize_with_stable_names() {
        let (_, _, _, [first, ..]) = ids();
        let rule = ScopeRule::Prefix {
            id: first,
            subtree: true,
        };
        let json = serde_json::to_value(&rule).expect("json");
        assert_eq!(json["kind"], "prefix");
        assert_eq!(json["value"]["subtree"], true);
        let back: ScopeRule = from_cbor(&to_cbor(&rule).expect("cbor")).expect("cbor");
        assert_eq!(back, rule);
        assert_eq!(SystemComponent::AuditExport.as_str(), "audit_export");
        assert_eq!(
            serde_json::to_value(SystemComponent::Leader).expect("json"),
            "leader"
        );
    }

    #[test]
    fn allow_all_allows() {
        let object = ObjectRef::singleton(ObjectKind::System);
        assert!(AllowAll.check(&user(), Action::Read, &object).is_ok());
        assert!(
            AllowAll
                .scope(&user(), Action::Read, ObjectKind::Host)
                .is_all()
        );
    }

    #[test]
    fn request_ctx_builders() {
        let ctx = RequestCtx::system(SystemComponent::Import)
            .with_source_ip("192.0.2.10".parse().expect("ip"))
            .with_idempotency(IdempotencyKey::new("k1").expect("key"));
        assert_eq!(ctx.source_ip, Some("192.0.2.10".parse().expect("ip")));
        assert_eq!(
            ctx.idempotency.as_ref().map(IdempotencyKey::as_str),
            Some("k1")
        );
    }
}
