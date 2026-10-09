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
}

/// One rule of a scoped grant (IAM-01, Slice 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ScopeRule {
    /// Objects of a tenant.
    Tenant(TenantId),
    /// Objects of a VRF.
    Vrf(VrfId),
    /// Objects of a site and its child sites.
    Site(SiteId),
    /// A prefix and everything inside it.
    Prefix(PrefixId),
    /// One object.
    Object(ObjectRef),
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
    use crate::codec::{from_cbor, to_cbor};

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
