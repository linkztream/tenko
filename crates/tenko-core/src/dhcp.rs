//! The DHCP model (Phase 3 plan, sections 2 and 3.1; ADR 0019): server settings, scopes,
//! shared networks, pool settings, exclusions, option definitions and option sets, classes,
//! policies, MAC filters and leases as rows of the replicated store, with their validation,
//! the store tables of the `dhcp` namespace, the authorization scopes, the error codes and
//! the audit actions.
//!
//! These are plain data and rules. The configuration service (WP7.4) writes the
//! configuration; the `dhcp` role (WP7.2, WP7.3) writes leases through the `LeaseStore`
//! trait of `tenko-dhcp` and serves from in-memory tables fed from these rows; it never
//! reads the store while it answers (plan section 2.2).
//!
//! # One model with IPAM
//!
//! A scope is keyed by the IPAM prefix it serves (P3-Q4). Pools are IPAM ranges of role
//! `dhcp_pool`, whose `lease_secs` is the pool's lease time; [`PoolSettings`] adds options
//! and classes to a pool when someone sets them. Reservations are IPAM hosts of mode
//! `reserved`: there is no reservation table, the role derives them from `ipam.hosts`,
//! `ipam.interfaces` and `ipam.addresses`; reservation-level options are the option set
//! owned by the interface.
//!
//! | Item | Contents |
//! |---|---|
//! | [`option`] | [`OptionSpace`], [`OptionKind`], [`OptionDef`], [`OptionValue`], [`OptionData`], [`OptionSet`], [`OptionOwner`], the catalog |
//! | [`class`] | [`Class`], [`Match`], [`MacPattern`], [`Policy`], [`Condition`], [`PolicyAction`], [`Filter`] |
//! | [`lease`] | [`Lease`], [`ClientKey`], [`BindingState`], [`LeaseEvent`], [`Lease6`] |
//! | this module | [`DhcpSettings`], [`Scope`], [`LeaseTimes`], [`DdnsPolicy`], [`SharedNetwork`], [`PoolSettings`], [`ExclusionRange`], [`ReservationWarning`] |
//! | [`tables`] | the tables of section 3.2 and the tables of the `dhcp` node role |
//! | [`codes`] | the `dhcp.*` error codes, [`DhcpError`] |
//! | [`audit`] | the `dhcp.*` audit actions |
//! | [`events`] | the event kinds of the SSE topic `dhcp` |
//! | [`DhcpScope`] | the scopes `dhcp.read` and `dhcp.write` |

use std::{collections::BTreeMap, fmt, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Coded, CodedError,
    dns::ZoneId,
    error::FieldError,
    id::{HostId, PrefixId, RangeId},
    ipam::{Prefix, PrefixRole, Range, RangeRole, Stamp},
    object::{ObjectKind, ObjectRef},
};

pub mod class;
pub mod history;
pub mod lease;
pub mod option;

pub use class::{
    AddressRange, Class, Condition, Filter, FilterKind, FilterVerdict, Join, MacPattern, Match,
    Policy, PolicyAction, Term, filter_verdict,
};
pub use history::{HistoryNames, HistoryRow, LeanEvent};
pub use lease::{
    BindingState, ClientKey, DdnsState, Fingerprint, Lease, Lease6, Lease6Event, Lease6Kind,
    LeaseEvent, LeaseEventKind, LeaseRef, MovingClient, MovingLease, PoolShare, Relay6Info,
    RelayInfo, write_identity, write_identity6,
};
pub use option::{
    CATALOG_V4, CATALOG_V6, Catalog6Entry, CatalogEntry, OptionData, OptionDef, OptionKind,
    OptionLevel, OptionOwner, OptionSet, OptionSetRef, OptionSpace, OptionValue, SERVER_MANAGED_V4,
    SERVER_MANAGED_V6, StaticRoute, catalog_v4, catalog_v6, kind_of, merge,
};

crate::id_type! {
    /// Identifier of a shared network (a superscope).
    SharedNetworkId,
    /// Identifier of an explicit exclusion range.
    ExclusionId,
    /// Identifier of a custom option definition.
    OptionDefId,
    /// Identifier of a class.
    ClassId,
    /// Identifier of a policy.
    PolicyId,
    /// Identifier of a MAC filter entry.
    FilterId,
}

macro_rules! dhcp_object_refs {
    ($($id:ident => $kind:ident),+ $(,)?) => {$(
        impl From<$id> for ObjectRef {
            fn from(id: $id) -> Self {
                ObjectRef::new(ObjectKind::$kind, id.0)
            }
        }
    )+};
}

dhcp_object_refs! {
    ClassId => DhcpClass,
    PolicyId => DhcpPolicy,
    OptionDefId => DhcpOptionDef,
    FilterId => DhcpFilter,
}

/// A scope as an object of authorization: kind `dhcp_scope` with the prefix's identifier,
/// so a scoped grant on the prefix reaches it (IAM-01).
pub const fn scope_object(prefix: PrefixId) -> ObjectRef {
    ObjectRef::new(ObjectKind::DhcpScope, prefix.0)
}

/// The server-wide DHCP configuration (settings, shared networks, server-level options and
/// policies) as an object of authorization: the `dhcp_scope` singleton, which no scoped
/// grant reaches, so only global roles change it.
pub const fn server_object() -> ObjectRef {
    ObjectRef::singleton(ObjectKind::DhcpScope)
}

/// The secret purpose of the failover shared secret (IAM-16, NEVER-01); declared for the
/// node-sync subset and used in Phase 5 (plan section 2.11).
pub const FAILOVER_PURPOSE: &str = "dhcp.failover";

/// The SSE topic of the DHCP module.
pub const TOPIC: &str = "dhcp";

/// The kinds of the DHCP model as objects of authorization and audit (plan section 3.4).
pub const OBJECT_KINDS: [ObjectKind; 5] = [
    ObjectKind::DhcpScope,
    ObjectKind::DhcpClass,
    ObjectKind::DhcpPolicy,
    ObjectKind::DhcpOptionDef,
    ObjectKind::DhcpFilter,
];

// ---------------------------------------------------------------------------------------
// Errors

/// Stable error codes of the `dhcp` namespace (API-08). Stable once merged.
pub mod codes {
    /// The prefix has no scope (404). Params: `prefix`.
    pub const SCOPE_NOT_FOUND: &str = "dhcp.scope.not_found";
    /// The prefix has a scope already (409). Params: `prefix`.
    pub const SCOPE_EXISTS: &str = "dhcp.scope.exists";
    /// The prefix is a supernet, not a network a scope can serve (409). Params: `prefix`.
    pub const SCOPE_NOT_NETWORK: &str = "dhcp.scope.not_network";
    /// The scope settings are invalid (400). Params: `field`, `reason`.
    pub const SCOPE_INVALID: &str = "dhcp.scope.invalid";
    /// IPAM refuses to delete a prefix that a scope serves (409; the rule of reverse
    /// zones). Params: `prefix`.
    pub const SCOPE_ATTACHED: &str = "dhcp.scope.attached";
    /// The shared network does not exist (404). Params: `id`.
    pub const SHARED_NETWORK_NOT_FOUND: &str = "dhcp.shared_network.not_found";
    /// The shared network settings are invalid (400). Params: `field`, `reason`.
    pub const SHARED_NETWORK_INVALID: &str = "dhcp.shared_network.invalid";
    /// The shared network still has scopes (409). Params: `id`.
    pub const SHARED_NETWORK_IN_USE: &str = "dhcp.shared_network.in_use";
    /// The range has no pool settings, or is no IPAM range (404). Params: `range`.
    pub const POOL_NOT_FOUND: &str = "dhcp.pool.not_found";
    /// A pool or a policy range lies outside its scope's prefix (400). Params: `range`,
    /// `prefix`.
    pub const POOL_OUTSIDE: &str = "dhcp.pool.outside";
    /// The range is not a DHCP pool: its IPAM role is not `dhcp_pool` (409). Params:
    /// `range`, `role`.
    pub const POOL_NOT_POOL: &str = "dhcp.pool.not_pool";
    /// The exclusion range does not exist (404). Params: `id`.
    pub const EXCLUSION_NOT_FOUND: &str = "dhcp.exclusion.not_found";
    /// The exclusion range is unordered or outside its scope's prefix (400). Params:
    /// `field`, `reason`.
    pub const EXCLUSION_INVALID: &str = "dhcp.exclusion.invalid";
    /// An option value or definition is invalid (400). Params: `field` or `space` and
    /// `code`, `reason`.
    pub const OPTION_INVALID: &str = "dhcp.option.invalid";
    /// The code is defined by the built-in catalog or set by the server itself (409).
    /// Params: `space`, `code`, `reason`.
    pub const OPTION_CODE_RESERVED: &str = "dhcp.option.code_reserved";
    /// The code has no definition in its space (400). Params: `space`, `code`.
    pub const OPTION_UNKNOWN: &str = "dhcp.option.unknown";
    /// The option definition does not exist (404). Params: `id`.
    pub const OPTION_DEF_NOT_FOUND: &str = "dhcp.option_def.not_found";
    /// A definition for this space and code exists already (409). Params: `space`,
    /// `code`.
    pub const OPTION_DEF_EXISTS: &str = "dhcp.option_def.exists";
    /// The definition is still used by an option set (409). Params: `id`, `by`.
    pub const OPTION_DEF_IN_USE: &str = "dhcp.option_def.in_use";
    /// The class does not exist (404). Params: `id`.
    pub const CLASS_NOT_FOUND: &str = "dhcp.class.not_found";
    /// The class is invalid (400). Params: `field`, `reason`.
    pub const CLASS_INVALID: &str = "dhcp.class.invalid";
    /// The class is still named by a scope, a pool or a policy (409). Params: `id`, `by`.
    pub const CLASS_IN_USE: &str = "dhcp.class.in_use";
    /// The policy does not exist (404). Params: `id`.
    pub const POLICY_NOT_FOUND: &str = "dhcp.policy.not_found";
    /// The policy is invalid (400). Params: `field`, `reason`.
    pub const POLICY_INVALID: &str = "dhcp.policy.invalid";
    /// The filter entry does not exist (404). Params: `id`.
    pub const FILTER_NOT_FOUND: &str = "dhcp.filter.not_found";
    /// The filter entry is invalid (400). Params: `field`, `reason`.
    pub const FILTER_INVALID: &str = "dhcp.filter.invalid";
    /// An entry for this pattern exists already (409). Params: `mac`.
    pub const FILTER_EXISTS: &str = "dhcp.filter.exists";
    /// The server settings are invalid (400). Params: `field`, `reason`.
    pub const SETTINGS_INVALID: &str = "dhcp.settings.invalid";
    /// Lease times are invalid (400): min, default and max out of order, T1 not below T2,
    /// T2 not below the default. Params: `field`, `reason`.
    pub const LEASE_TIMES_INVALID: &str = "dhcp.lease_times.invalid";
    /// DDNS settings are invalid (400). Params: `field`, `reason`.
    pub const DDNS_INVALID: &str = "dhcp.ddns.invalid";
    /// No lease holds the address (404). Params: `addr`.
    pub const LEASE_NOT_FOUND: &str = "dhcp.lease.not_found";
    /// The lease is not in a state the operation accepts (409): releasing a lease that is
    /// not active. Params: `addr`, `state`.
    pub const LEASE_STATE: &str = "dhcp.lease.state";
    /// A reserved host has no MAC address, client identifier or DUID, so no reservation can
    /// exist (409, IPAM-18). Params: `host`.
    pub const RESERVATION_NO_IDENTITY: &str = "dhcp.reservation.no_identity";
    /// Two reservations claim one address or one client in a scope (409, IPAM-23).
    /// Params: `address` or `client`, `hosts`.
    pub const RESERVATION_CONFLICT: &str = "dhcp.reservation.conflict";
    /// The store refused the lease write (503, P3-Q14): the client is not answered with a
    /// promise that is not durable. Params: `reason`.
    pub const STORE_REFUSED: &str = "dhcp.store_refused";
    /// The node does not run the `dhcp` role (409). Params: `node`.
    pub const NODE_NOT_DHCP: &str = "dhcp.node.not_dhcp";
    /// The DHCP module is switched off in this installation (409, OPS-25).
    pub const MODULE_DISABLED: &str = "dhcp.module.disabled";
    /// The export format is not known (400). Params: `format`.
    pub const EXPORT_FORMAT: &str = "dhcp.export.format";

    /// Every code of the namespace, for the contracts document and its test.
    pub const ALL: [&str; 38] = [
        SCOPE_NOT_FOUND,
        SCOPE_EXISTS,
        SCOPE_NOT_NETWORK,
        SCOPE_INVALID,
        SCOPE_ATTACHED,
        SHARED_NETWORK_NOT_FOUND,
        SHARED_NETWORK_INVALID,
        SHARED_NETWORK_IN_USE,
        POOL_NOT_FOUND,
        POOL_OUTSIDE,
        POOL_NOT_POOL,
        EXCLUSION_NOT_FOUND,
        EXCLUSION_INVALID,
        OPTION_INVALID,
        OPTION_CODE_RESERVED,
        OPTION_UNKNOWN,
        OPTION_DEF_NOT_FOUND,
        OPTION_DEF_EXISTS,
        OPTION_DEF_IN_USE,
        CLASS_NOT_FOUND,
        CLASS_INVALID,
        CLASS_IN_USE,
        POLICY_NOT_FOUND,
        POLICY_INVALID,
        FILTER_NOT_FOUND,
        FILTER_INVALID,
        FILTER_EXISTS,
        SETTINGS_INVALID,
        LEASE_TIMES_INVALID,
        DDNS_INVALID,
        LEASE_NOT_FOUND,
        LEASE_STATE,
        RESERVATION_NO_IDENTITY,
        RESERVATION_CONFLICT,
        STORE_REFUSED,
        NODE_NOT_DHCP,
        MODULE_DISABLED,
        EXPORT_FORMAT,
    ];
}

/// An error of the DHCP model: a stable code, an HTTP status and parameters.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.detail)]
pub struct DhcpError(Box<CodedError>);

impl fmt::Debug for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DhcpError({}: {})", self.0.code, self.0.detail)
    }
}

impl DhcpError {
    /// An error with a code, a status and an English detail.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self(Box::new(CodedError::new(code, status, detail)))
    }

    /// Adds a parameter.
    #[must_use]
    pub fn with_param(self, key: &str, value: impl Into<String>) -> Self {
        Self(Box::new(self.0.with_param(key, value)))
    }

    /// Adds a field error.
    #[must_use]
    pub fn with_field(self, field: &str) -> Self {
        let code = self.code();
        Self(Box::new(
            self.0.with_field_error(FieldError::new(field, code)),
        ))
    }

    /// An invalid setting (`code` is the `*.invalid` code of the object), 400.
    pub fn invalid(code: &'static str, field: &str, reason: &str) -> Self {
        Self::new(code, 400, format!("{field}: {reason}"))
            .with_param("field", field)
            .with_param("reason", reason)
            .with_field(field)
    }

    /// `dhcp.option.code_reserved`.
    pub fn code_reserved(space: &OptionSpace, code: u16, reason: &str) -> Self {
        Self::new(
            codes::OPTION_CODE_RESERVED,
            409,
            format!("option {space} {code}: {reason}"),
        )
        .with_param("space", space.as_str())
        .with_param("code", code.to_string())
        .with_param("reason", reason)
    }

    /// The captured error.
    pub fn as_coded_error(&self) -> &CodedError {
        &self.0
    }
}

impl Coded for DhcpError {
    fn code(&self) -> &'static str {
        match &self.0.code {
            std::borrow::Cow::Borrowed(code) => code,
            std::borrow::Cow::Owned(_) => crate::error::codes::INTERNAL,
        }
    }
    fn http_status(&self) -> u16 {
        self.0.status
    }
    fn field_errors(&self) -> Vec<FieldError> {
        self.0.errors.clone()
    }
    fn to_coded_error(&self) -> CodedError {
        (*self.0).clone()
    }
}

// ---------------------------------------------------------------------------------------
// Authorization scopes

/// The scopes of the DHCP module (ADR 0015, ADR 0019 point 10): `dhcp.read` reads the
/// configuration and the leases (reading leases or history is audited as
/// `dhcp.lease.read`); `dhcp.write` creates, changes and deletes the configuration and
/// releases leases. The viewer holds `dhcp.read`, the operator and the administrator both,
/// the auditor none.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub enum DhcpScope {
    /// Read the DHCP configuration and leases.
    #[serde(rename = "dhcp.read")]
    Read,
    /// Change the DHCP configuration and release leases.
    #[serde(rename = "dhcp.write")]
    Write,
}

impl DhcpScope {
    /// Every scope.
    pub const ALL: [DhcpScope; 2] = [DhcpScope::Read, DhcpScope::Write];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            DhcpScope::Read => "dhcp.read",
            DhcpScope::Write => "dhcp.write",
        }
    }

    /// The scope an action on a kind needs; `None` for a kind outside the DHCP model and
    /// for approvals, reveals and administration, which no DHCP scope grants.
    pub const fn required(action: crate::Action, kind: ObjectKind) -> Option<DhcpScope> {
        use crate::Action;
        match kind {
            ObjectKind::DhcpScope
            | ObjectKind::DhcpClass
            | ObjectKind::DhcpPolicy
            | ObjectKind::DhcpOptionDef
            | ObjectKind::DhcpFilter => match action {
                Action::Read => Some(DhcpScope::Read),
                Action::Create | Action::Update | Action::Delete | Action::Execute => {
                    Some(DhcpScope::Write)
                }
                Action::Approve | Action::Reveal | Action::Administer => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for DhcpScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------------------
// Lease times and DDNS

/// The longest lease the model accepts: one year. An infinite lease (RFC 2131's
/// `0xffffffff`) is not offered.
pub const MAX_LEASE_SECS: u32 = 365 * 24 * 3600;

/// Lease times in seconds (plan section 3.1). T1 and T2 default to half and seven eighths
/// of the granted time (RFC 2131, section 4.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct LeaseTimes {
    /// The time granted when the client asks for none.
    pub default_secs: u32,
    /// The shortest time granted.
    pub min_secs: u32,
    /// The longest time granted.
    pub max_secs: u32,
    /// The renewal time (option 58); none for half the granted time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t1_secs: Option<u32>,
    /// The rebinding time (option 59); none for seven eighths of the granted time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t2_secs: Option<u32>,
}

impl Default for LeaseTimes {
    /// One day, between one hour and seven days.
    fn default() -> Self {
        Self {
            default_secs: 86_400,
            min_secs: 3_600,
            max_secs: 604_800,
            t1_secs: None,
            t2_secs: None,
        }
    }
}

impl LeaseTimes {
    /// Lease times of one fixed length.
    pub const fn fixed(secs: u32) -> Self {
        Self {
            default_secs: secs,
            min_secs: secs,
            max_secs: secs,
            t1_secs: None,
            t2_secs: None,
        }
    }

    /// Checks the order: `0 < min <= default <= max <= MAX_LEASE_SECS`, and
    /// `t1 < t2 < default` where they are set. `field` names the place in the request.
    ///
    /// # Errors
    ///
    /// `dhcp.lease_times.invalid` naming the field.
    pub fn validate(&self, field: &str) -> Result<(), DhcpError> {
        let invalid = |name: &str, reason: &str| {
            Err(DhcpError::invalid(
                codes::LEASE_TIMES_INVALID,
                &format!("{field}.{name}"),
                reason,
            ))
        };
        if self.min_secs == 0 {
            return invalid("min_secs", "a lease lasts at least one second");
        }
        if self.min_secs > self.default_secs || self.default_secs > self.max_secs {
            return invalid("default_secs", "min, default and max are out of order");
        }
        if self.max_secs > MAX_LEASE_SECS {
            return invalid("max_secs", "a lease lasts at most one year");
        }
        let t1 = self.t1_secs.unwrap_or(self.default_secs / 2);
        let t2 = self.t2_secs.unwrap_or(self.default_secs / 8 * 7);
        if self.t1_secs.is_some() && t1 >= t2 {
            return invalid("t1_secs", "T1 is below T2");
        }
        if self.t2_secs.is_some() && t2 >= self.default_secs {
            return invalid("t2_secs", "T2 is below the lease time");
        }
        Ok(())
    }

    /// The time to grant for a request of `requested` seconds: the default without a
    /// request, else the request bounded by min and max. The engine's `grant_time` caps it
    /// further with a failover partner (Phase 5).
    pub fn grant(&self, requested: Option<u32>) -> u32 {
        requested.map_or(self.default_secs, |asked| {
            asked.clamp(self.min_secs, self.max_secs)
        })
    }

    /// T1 and T2 for a granted time: the configured values scaled down when the grant is
    /// shorter than the default, else half and seven eighths.
    pub fn renewal_times(&self, granted: u32) -> (u32, u32) {
        let scale = |value: Option<u32>, numerator: u64, denominator: u64| {
            let value = value.map_or_else(
                || u64::from(granted) * numerator / denominator,
                |set| u64::from(set) * u64::from(granted) / u64::from(self.default_secs.max(1)),
            );
            u32::try_from(value).unwrap_or(u32::MAX)
        };
        (scale(self.t1_secs, 1, 2), scale(self.t2_secs, 7, 8))
    }
}

/// What happens when the name a client asks for is held by another client (RFC 4703).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DdnsConflict {
    /// The DHCID protects the name: the second client gets no name (RFC 4703). The only
    /// choice under Hardened.
    #[default]
    Protect,
    /// The last client wins and the records move.
    Replace,
}

/// The DDNS settings of a scope (ADR 0020).
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches of ADR 0020, each a column of the settings page"
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct DdnsPolicy {
    /// Whether the server writes names for the scope's clients.
    #[serde(default)]
    pub enabled: bool,
    /// The forward zone the names go under; none: the zone of the scope's `domain-name`
    /// option, if Tenko serves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_zone: Option<ZoneId>,
    /// Whether PTR records are written in the reverse zone Tenko keeps for the address.
    #[serde(default = "yes")]
    pub reverse: bool,
    /// The TTL of the records; none: a third of the lease time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Name protection.
    #[serde(default)]
    pub conflict: DdnsConflict,
    /// Whether a client that asks to write its A record itself (option 81 flag S clear)
    /// may do so; Tenko writes it otherwise (ADR 0020, point 4).
    #[serde(default)]
    pub client_may_update_a: bool,
    /// Whether clients without option 81 get their option 12 name ("update for legacy
    /// clients", DHCP-13).
    #[serde(default = "yes")]
    pub legacy_clients: bool,
    /// Whether a name outside the forward zone is refused rather than cut to its first
    /// label under the zone.
    #[serde(default)]
    pub refuse_foreign: bool,
}

const fn yes() -> bool {
    true
}

impl Default for DdnsPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            forward_zone: None,
            reverse: true,
            ttl: None,
            conflict: DdnsConflict::Protect,
            client_may_update_a: false,
            legacy_clients: true,
            refuse_foreign: false,
        }
    }
}

impl DdnsPolicy {
    /// Checks the settings: a TTL of at most one week. Whether the profile allows
    /// `replace` (not under Hardened) is the configuration service's check (WP8.3).
    ///
    /// # Errors
    ///
    /// `dhcp.ddns.invalid` naming the field.
    pub fn validate(&self, field: &str) -> Result<(), DhcpError> {
        if self.ttl.is_some_and(|ttl| ttl > 604_800) {
            return Err(DhcpError::invalid(
                codes::DDNS_INVALID,
                &format!("{field}.ttl"),
                "a DDNS TTL is at most one week",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Settings, scopes, shared networks, pools, exclusions

/// The server-level settings (`dhcp.settings`, one row). Server-level options are the
/// option set of [`OptionOwner::Server`]; node-local settings (listeners, workers, the
/// offer lifetime, the probe and decline timers) are `[dhcp]` in `tenko.toml` (WP7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DhcpSettings {
    /// Lease times of scopes that set none.
    #[serde(default)]
    pub lease: LeaseTimes,
    /// Whether scopes are authoritative unless they say otherwise (NAK for addresses of
    /// other networks, RFC 2131).
    #[serde(default = "yes")]
    pub authoritative: bool,
    /// DDNS settings new scopes start from.
    #[serde(default)]
    pub ddns: DdnsPolicy,
    /// Conflict detection (TGL-16): none follows the security profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_detection: Option<bool>,
    /// Lease history retention in days (P3-Q13): none follows the security profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_days: Option<u32>,
    /// Last change; none before the first write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Stamp>,
}

impl Default for DhcpSettings {
    fn default() -> Self {
        Self {
            lease: LeaseTimes::default(),
            authoritative: true,
            ddns: DdnsPolicy::default(),
            conflict_detection: None,
            history_days: None,
            updated: None,
        }
    }
}

impl DhcpSettings {
    /// Checks the settings.
    ///
    /// # Errors
    ///
    /// The codes of the lease and DDNS checks, or `dhcp.settings.invalid` for a history
    /// retention of 0 or more than ten years.
    pub fn validate(&self) -> Result<(), DhcpError> {
        self.lease.validate("lease")?;
        self.ddns.validate("ddns")?;
        if self
            .history_days
            .is_some_and(|days| days == 0 || days > 3_650)
        {
            return Err(DhcpError::invalid(
                codes::SETTINGS_INVALID,
                "history_days",
                "1 to 3650 days",
            ));
        }
        Ok(())
    }
}

/// A scope (`dhcp.scopes`, key: the prefix): an IPAM network with a DHCP policy (P3-Q4).
/// Its options are the option set of [`OptionOwner::Scope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Scope {
    /// The prefix served, which is also the key.
    pub prefix: PrefixId,
    /// Whether the scope serves clients.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Lease times; none: the server's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<LeaseTimes>,
    /// Whether the scope is authoritative; none: the server's setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative: Option<bool>,
    /// The server identifier (option 54) for the scope's clients; none: the address of the
    /// listener that received the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "198.51.100.10")]
    pub server_id: Option<IpAddr>,
    /// DDNS.
    #[serde(default)]
    pub ddns: DdnsPolicy,
    /// The shared network the scope belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_network: Option<SharedNetworkId>,
    /// Only clients that match an allow filter are served (DHCP-08, TGL-17).
    #[serde(default)]
    pub restricted: bool,
    /// The classes the scope admits; empty: every client.
    #[serde(default)]
    pub classes: Vec<ClassId>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    // WP9.1: what a scope on an IPv6 prefix adds for DHCPv6.
    /// The DHCPv6 settings of a scope on an IPv6 prefix; none: the defaults of
    /// [`Scope6Settings`]. Refused on an IPv4 prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Scope6Settings>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

// WP9.1: the DHCPv6 settings of a scope (plan section 2.3: a scope is a prefix with a DHCP
// policy; the IPv6 prefix adds these).
/// What a scope on an IPv6 prefix adds for DHCPv6 (RFC 8415). The valid lifetime of an
/// address is the scope's (or the pool's) lease time; T1 and T2 come from the same lease
/// times and are kept below the preferred lifetime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Scope6Settings {
    /// The preferred lifetime in seconds; none: five eighths of the valid lifetime, as ISC
    /// dhcpd does. Never above the valid lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_secs: Option<u32>,
    /// Whether a SOLICIT with the Rapid Commit option is answered with a REPLY that
    /// commits the lease (RFC 8415 section 18.3.1); none: yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rapid_commit: Option<bool>,
    /// The Interface-Id (option 18) a relay sends for the link of this scope, as text: a
    /// relayed request that carries it selects the scope before its link address does
    /// (RFC 8415 section 13.1; the lightweight relays of RFC 6221 send a link address of
    /// zero and the Interface-Id). None: the link address alone selects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<String>,
}

impl Scope6Settings {
    /// Whether rapid commit is allowed.
    pub fn rapid_commit(&self) -> bool {
        self.rapid_commit.unwrap_or(true)
    }

    /// The preferred lifetime for a granted valid lifetime of `valid` seconds.
    pub fn preferred(&self, valid: u32) -> u32 {
        let default = u32::try_from(u64::from(valid) * 5 / 8).unwrap_or(valid);
        self.preferred_secs.unwrap_or(default).min(valid)
    }

    /// Checks the settings.
    ///
    /// # Errors
    ///
    /// `dhcp.scope.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DhcpError> {
        if self.preferred_secs == Some(0) {
            return Err(DhcpError::invalid(
                codes::SCOPE_INVALID,
                "v6.preferred_secs",
                "at least one second",
            ));
        }
        if let Some(id) = &self.interface_id
            && (id.is_empty() || id.len() > 128 || id.chars().any(char::is_control))
        {
            return Err(DhcpError::invalid(
                codes::SCOPE_INVALID,
                "v6.interface_id",
                "1 to 128 printable characters",
            ));
        }
        Ok(())
    }
}

impl Scope {
    /// The option set reference of the scope.
    pub fn options(&self) -> OptionSetRef {
        OptionOwner::Scope(self.prefix)
    }

    /// Checks a scope against its prefix: the prefix is the one named and a network (not a
    /// supernet); the server identifier is of the prefix's family; valid lease times and
    /// DDNS settings; no class twice. That no other scope serves the prefix is the key's
    /// uniqueness (`dhcp.scope.exists`).
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_network`, `dhcp.scope.invalid` naming the field, or the codes of
    /// the lease and DDNS checks.
    pub fn validate(&self, prefix: &Prefix) -> Result<(), DhcpError> {
        let invalid = |field: &str, reason: &str| {
            Err(DhcpError::invalid(codes::SCOPE_INVALID, field, reason))
        };
        if prefix.id != self.prefix {
            return invalid("prefix", "the scope names another prefix");
        }
        if prefix.role != PrefixRole::Network {
            return Err(DhcpError::new(
                codes::SCOPE_NOT_NETWORK,
                409,
                format!("{} is a supernet; a scope serves a network", prefix.cidr),
            )
            .with_param("prefix", prefix.cidr.to_string()));
        }
        if let Some(server_id) = self.server_id
            && server_id.is_ipv4() != matches!(prefix.cidr, IpNet::V4(_))
        {
            return invalid(
                "server_id",
                "the server identifier is of the prefix's family",
            );
        }
        if let Some(lease) = &self.lease {
            lease.validate("lease")?;
        }
        // WP9.1: the DHCPv6 settings belong to an IPv6 prefix.
        if let Some(v6) = &self.v6 {
            if matches!(prefix.cidr, IpNet::V4(_)) {
                return invalid(
                    "v6",
                    "the DHCPv6 settings are for a scope on an IPv6 prefix",
                );
            }
            v6.validate()?;
        }
        self.ddns.validate("ddns")?;
        for (index, class) in self.classes.iter().enumerate() {
            if self.classes[..index].contains(class) {
                return invalid("classes", "a class appears twice");
            }
        }
        Ok(())
    }
}

/// Several scopes on one link (`dhcp.shared_networks`; Windows superscopes, Kea shared
/// networks, DHCP-01 and DHCP-04): a request selected to one scope of the group may be
/// served from any of them. Its options are the option set of
/// [`OptionOwner::SharedNetwork`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SharedNetwork {
    /// Identifier.
    pub id: SharedNetworkId,
    /// The name, unique: 1 to 64 characters of `a-z`, `0-9` and `-`.
    pub name: String,
    /// The listener interface of a directly attached link; none for a relayed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

impl SharedNetwork {
    /// Checks the name and the interface (1 to 64 characters).
    ///
    /// # Errors
    ///
    /// `dhcp.shared_network.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DhcpError> {
        if !option::valid_name(&self.name) {
            return Err(DhcpError::invalid(
                codes::SHARED_NETWORK_INVALID,
                "name",
                "1 to 64 characters of a-z, 0-9 and -",
            ));
        }
        if self
            .interface
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > 64)
        {
            return Err(DhcpError::invalid(
                codes::SHARED_NETWORK_INVALID,
                "interface",
                "1 to 64 characters",
            ));
        }
        Ok(())
    }
}

/// What DHCP adds to an IPAM range of role `dhcp_pool` (`dhcp.pools`, key: the range):
/// classes and a lease time. The pool's options are the option set of
/// [`OptionOwner::Pool`]. A pool without a row serves with the scope's settings and the
/// range's `lease_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PoolSettings {
    /// The range, which is also the key.
    pub range: RangeId,
    /// The classes the pool admits; empty: every client the scope admits.
    #[serde(default)]
    pub classes: Vec<ClassId>,
    /// Lease times; none: the range's `lease_secs`, else the scope's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<LeaseTimes>,
    /// Last change.
    pub updated: Stamp,
}

impl PoolSettings {
    /// Checks pool settings against the range and the scope's prefix: the range is the one
    /// named, of role `dhcp_pool` or (WP9.2) `dhcp_pd_pool`, inside the prefix; valid lease
    /// times. The classes of a delegation pool are stored and, like every class, matched
    /// for DHCPv4 only.
    ///
    /// # Errors
    ///
    /// `dhcp.pool.not_pool`, `dhcp.pool.outside` or the code of the lease check.
    pub fn validate(&self, range: &Range, prefix: &Prefix) -> Result<(), DhcpError> {
        if range.id != self.range
            || !matches!(range.role, RangeRole::DhcpPool | RangeRole::DhcpPdPool)
        {
            return Err(
                DhcpError::new(codes::POOL_NOT_POOL, 409, "the range is not a DHCP pool")
                    .with_param("range", range.id.to_string()),
            );
        }
        if range.prefix != prefix.id
            || !prefix.cidr.contains(&range.first)
            || !prefix.cidr.contains(&range.last)
        {
            return Err(DhcpError::new(
                codes::POOL_OUTSIDE,
                400,
                format!("the pool lies outside {}", prefix.cidr),
            )
            .with_param("range", range.id.to_string())
            .with_param("prefix", prefix.cidr.to_string()));
        }
        if let Some(lease) = &self.lease {
            lease.validate("lease")?;
        }
        Ok(())
    }
}

/// An explicit exclusion range of a scope (`dhcp.exclusions`, key: scope and id). The
/// other exclusions are implicit: the prefix's ranges of role `reserved` and
/// `infrastructure`, and every address IPAM holds for a host that is not `dynamic`
/// (plan section 2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExclusionRange {
    /// Identifier.
    pub id: ExclusionId,
    /// The scope.
    pub scope: PrefixId,
    /// The first address excluded.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub first: IpAddr,
    /// The last address excluded.
    #[schema(value_type = String, example = "192.0.2.19")]
    pub last: IpAddr,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
}

impl ExclusionRange {
    /// Checks the range: ordered, of one family, inside the scope's prefix.
    ///
    /// # Errors
    ///
    /// `dhcp.exclusion.invalid` naming the field.
    pub fn validate(&self, prefix: &Prefix) -> Result<(), DhcpError> {
        let invalid = |field: &str, reason: &str| {
            Err(DhcpError::invalid(codes::EXCLUSION_INVALID, field, reason))
        };
        if prefix.id != self.scope {
            return invalid("scope", "the exclusion names another prefix");
        }
        if self.first.is_ipv4() != self.last.is_ipv4() || self.first > self.last {
            return invalid("last", "the first address is not after the last");
        }
        if !prefix.cidr.contains(&self.first) || !prefix.cidr.contains(&self.last) {
            return invalid("first", "the range lies outside the scope's prefix");
        }
        Ok(())
    }

    /// Whether `address` is excluded by the range.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.first <= address && address <= self.last
    }
}

// ---------------------------------------------------------------------------------------
// Reservations (derived from IPAM)

/// A reservation as the configuration image derives it from IPAM (plan section 2.3): a
/// host of mode `reserved`, one of its interfaces with a client identity, and an address of
/// that interface inside a served prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationCandidate {
    /// The host.
    pub host: HostId,
    /// The scope the address lies in.
    pub scope: PrefixId,
    /// The address.
    pub address: IpAddr,
    /// The client identity (`ClientKey::identity`); none when the interface has no MAC
    /// address and no client identifier.
    pub identity: Option<Vec<u8>>,
}

/// What the reservation check finds (IPAM-18, IPAM-23). A reservation inside a pool is
/// allowed: it wins over the pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReservationWarning {
    /// A `reserved` host without a MAC address, client identifier or DUID: no reservation
    /// exists until it has one (`dhcp.reservation.no_identity`).
    NoIdentity {
        /// The host.
        host: HostId,
    },
    /// Two hosts reserve one address (`dhcp.reservation.conflict`).
    AddressCollision {
        /// The address.
        #[schema(value_type = String)]
        address: IpAddr,
        /// The hosts, sorted.
        hosts: Vec<HostId>,
    },
    /// Two hosts present one client identity in a scope (`dhcp.reservation.conflict`).
    ClientCollision {
        /// The scope.
        scope: PrefixId,
        /// The hosts, sorted.
        hosts: Vec<HostId>,
    },
}

/// Checks derived reservations: hosts without identity, addresses reserved twice, a client
/// identity reserved twice in one scope. Pure, for the image build of WP7.4 and the IPAM
/// views.
pub fn check_reservations(candidates: &[ReservationCandidate]) -> Vec<ReservationWarning> {
    let mut warnings = Vec::new();
    let mut by_address: BTreeMap<IpAddr, Vec<HostId>> = BTreeMap::new();
    let mut by_client: BTreeMap<(PrefixId, Vec<u8>), Vec<HostId>> = BTreeMap::new();
    let mut no_identity: Vec<HostId> = Vec::new();
    for candidate in candidates {
        let hosts = by_address.entry(candidate.address).or_default();
        if !hosts.contains(&candidate.host) {
            hosts.push(candidate.host);
        }
        match &candidate.identity {
            Some(identity) => {
                let hosts = by_client
                    .entry((candidate.scope, identity.clone()))
                    .or_default();
                if !hosts.contains(&candidate.host) {
                    hosts.push(candidate.host);
                }
            }
            None if !no_identity.contains(&candidate.host) => no_identity.push(candidate.host),
            None => {}
        }
    }
    no_identity.sort();
    warnings.extend(
        no_identity
            .into_iter()
            .map(|host| ReservationWarning::NoIdentity { host }),
    );
    for (address, mut hosts) in by_address {
        if hosts.len() > 1 {
            hosts.sort();
            warnings.push(ReservationWarning::AddressCollision { address, hosts });
        }
    }
    for ((scope, _), mut hosts) in by_client {
        if hosts.len() > 1 {
            hosts.sort();
            warnings.push(ReservationWarning::ClientCollision { scope, hosts });
        }
    }
    warnings
}

// ---------------------------------------------------------------------------------------
// Tables

/// The store tables of the `dhcp` namespace (plan section 3.2).
///
/// | Table | Key | Value |
/// |---|---|---|
/// | `dhcp.settings` | `()` | [`DhcpSettings`] |
/// | `dhcp.scopes` | [`PrefixId`] | [`Scope`] |
/// | `dhcp.shared_networks` | [`SharedNetworkId`] | [`SharedNetwork`] |
/// | `dhcp.pools` | [`RangeId`] | [`PoolSettings`] |
/// | `dhcp.exclusions` | ([`PrefixId`], [`ExclusionId`]) | [`ExclusionRange`] |
/// | `dhcp.option_defs` | [`OptionDefId`] | [`OptionDef`] |
/// | `dhcp.option_sets` | [`OptionOwner`] | [`OptionSet`] |
/// | `dhcp.classes` | [`ClassId`] | [`Class`] |
/// | `dhcp.policies` | [`PolicyId`] | [`Policy`] |
/// | `dhcp.filters` | [`FilterId`] | [`Filter`] |
/// | `dhcp.leases` | ([`VrfId`](crate::VrfId), `Ipv4Addr`) | [`Lease`] |
/// | `dhcp.leases.by_client` | ([`PrefixId`], client identity octets) | [`LeaseRef`] |
/// | `dhcp.history` | ([`Timestamp`](crate::Timestamp), [`VrfId`](crate::VrfId), `Ipv4Addr`) | [`LeaseEvent`] |
///
/// `dhcp.leases6` and `dhcp.history6` came with WP9.1 and `dhcp.pd_pools` follows with
/// WP9.2; the plan's `dhcp.host_options` is the option set of [`OptionOwner::Host`] in
/// `dhcp.option_sets`.
pub mod tables {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        Class, ClassId, DhcpSettings, ExclusionId, ExclusionRange, Filter, FilterId, Lease, Lease6,
        Lease6Event, LeaseRef, MovingClient, OptionDef, OptionDefId, OptionOwner, OptionSet,
        Policy, PolicyId, PoolSettings, Scope, SharedNetwork, SharedNetworkId,
    };
    use crate::{
        Timestamp,
        id::{JobId, PrefixId, RangeId, VrfId},
        names::TableName,
        table::TableDef,
    };

    /// The server-level settings.
    pub static SETTINGS: TableDef<(), DhcpSettings> = TableDef::new("dhcp.settings");
    /// Scopes, by prefix.
    pub static SCOPES: TableDef<PrefixId, Scope> = TableDef::new("dhcp.scopes");
    /// Shared networks.
    pub static SHARED_NETWORKS: TableDef<SharedNetworkId, SharedNetwork> =
        TableDef::new("dhcp.shared_networks");
    /// Pool settings, by range.
    pub static POOLS: TableDef<RangeId, PoolSettings> = TableDef::new("dhcp.pools");
    /// Explicit exclusion ranges, by scope.
    pub static EXCLUSIONS: TableDef<(PrefixId, ExclusionId), ExclusionRange> =
        TableDef::new("dhcp.exclusions");
    /// Custom option definitions.
    pub static OPTION_DEFS: TableDef<OptionDefId, OptionDef> = TableDef::new("dhcp.option_defs");
    /// Option sets, by owner.
    pub static OPTION_SETS: TableDef<OptionOwner, OptionSet> = TableDef::new("dhcp.option_sets");
    /// Classes.
    pub static CLASSES: TableDef<ClassId, Class> = TableDef::new("dhcp.classes");
    /// Policies.
    pub static POLICIES: TableDef<PolicyId, Policy> = TableDef::new("dhcp.policies");
    /// MAC filters.
    pub static FILTERS: TableDef<FilterId, Filter> = TableDef::new("dhcp.filters");
    /// DHCPv4 leases, by VRF and address.
    pub static LEASES: TableDef<(VrfId, Ipv4Addr), Lease> = TableDef::new("dhcp.leases");
    /// The client index of the leases: scope and client identity
    /// ([`super::ClientKey::identity`]).
    pub static LEASES_BY_CLIENT: TableDef<(PrefixId, Vec<u8>), LeaseRef> =
        TableDef::new("dhcp.leases.by_client");
    /// Lease history, bounded by retention (P3-Q13): the lean row of ADR 0031, or the whole
    /// event of a row written before it ([`super::HistoryRow`]).
    pub static HISTORY: TableDef<(Timestamp, VrfId, Ipv4Addr), super::HistoryRow> =
        TableDef::new("dhcp.history");
    // WP9.1: the DHCPv6 leases and their history (additive, no format change).
    /// DHCPv6 leases, by VRF and address (an `IA_PD` prefix by its first address). The
    /// role derives its client index from the rows; there is no `by_client` table.
    pub static LEASES6: TableDef<(VrfId, Ipv6Addr), Lease6> = TableDef::new("dhcp.leases6");
    /// DHCPv6 lease history, bounded by the same retention as `dhcp.history`.
    pub static HISTORY6: TableDef<(Timestamp, VrfId, Ipv6Addr), Lease6Event> =
        TableDef::new("dhcp.history6");

    /// The clients move jobs are moving, by job (ADR 0027): written by the move job and
    /// served in the role's configuration image.
    pub static MOVING: TableDef<JobId, MovingClient> = TableDef::new("dhcp.moving");

    /// The tables a node with the `dhcp` role receives through node sync: every table of the
    /// namespace except `dhcp.history` (plan section 3.2). Declared now and consumed by no
    /// node in Phase 3: the one node runs the role in the controller's process and reads
    /// the store directly (plan section 2.12); the fed `dhcp` node is Phase 5.
    pub static NODE_TABLES: [TableName; 14] = [
        TableName::from_static("dhcp.settings"),
        TableName::from_static("dhcp.scopes"),
        TableName::from_static("dhcp.shared_networks"),
        TableName::from_static("dhcp.pools"),
        TableName::from_static("dhcp.exclusions"),
        TableName::from_static("dhcp.option_defs"),
        TableName::from_static("dhcp.option_sets"),
        TableName::from_static("dhcp.classes"),
        TableName::from_static("dhcp.policies"),
        TableName::from_static("dhcp.filters"),
        TableName::from_static("dhcp.leases"),
        TableName::from_static("dhcp.leases.by_client"),
        // WP9.1: the DHCPv6 leases.
        TableName::from_static("dhcp.leases6"),
        // The clients of move jobs (ADR 0027).
        TableName::from_static("dhcp.moving"),
    ];

    /// The IPAM tables a `dhcp` node also receives, filtered to the rows its reservations
    /// and pools derive from (plan section 3.2): the prefixes that have a scope, their
    /// ranges, the hosts of mode `reserved`, their interfaces and their addresses inside a
    /// served prefix. Declared for Phase 5, when node sync gains row filters; consumed by
    /// no node now.
    pub static NODE_IPAM_TABLES: [TableName; 5] = [
        TableName::from_static("ipam.prefixes"),
        TableName::from_static("ipam.ranges"),
        TableName::from_static("ipam.hosts"),
        TableName::from_static("ipam.interfaces"),
        TableName::from_static("ipam.addresses"),
    ];

    /// Every table of the namespace.
    pub fn all() -> [&'static TableName; 16] {
        [
            SETTINGS.name(),
            SCOPES.name(),
            SHARED_NETWORKS.name(),
            POOLS.name(),
            EXCLUSIONS.name(),
            OPTION_DEFS.name(),
            OPTION_SETS.name(),
            CLASSES.name(),
            POLICIES.name(),
            FILTERS.name(),
            LEASES.name(),
            LEASES_BY_CLIENT.name(),
            HISTORY.name(),
            // WP9.1: the DHCPv6 leases and their history.
            LEASES6.name(),
            HISTORY6.name(),
            // The clients of move jobs (ADR 0027).
            MOVING.name(),
        ]
    }
}

// ---------------------------------------------------------------------------------------
// Audit actions and events

/// The audit actions of the DHCP module. Each change of the configuration writes one in
/// the same batch as the change (IAM-18); lease commits by the role are not audited one by
/// one (they are the lease history), operator actions on leases are.
pub mod audit {
    use crate::audit::AuditAction;

    /// The server settings changed.
    pub const SETTINGS_UPDATE: AuditAction = AuditAction::from_static("dhcp.settings.update");
    /// A scope was created.
    pub const SCOPE_CREATE: AuditAction = AuditAction::from_static("dhcp.scope.create");
    /// A scope changed.
    pub const SCOPE_UPDATE: AuditAction = AuditAction::from_static("dhcp.scope.update");
    /// A scope was deleted.
    pub const SCOPE_DELETE: AuditAction = AuditAction::from_static("dhcp.scope.delete");
    /// A shared network was created.
    pub const SHARED_NETWORK_CREATE: AuditAction =
        AuditAction::from_static("dhcp.shared_network.create");
    /// A shared network changed.
    pub const SHARED_NETWORK_UPDATE: AuditAction =
        AuditAction::from_static("dhcp.shared_network.update");
    /// A shared network was deleted.
    pub const SHARED_NETWORK_DELETE: AuditAction =
        AuditAction::from_static("dhcp.shared_network.delete");
    /// A pool's settings were set or changed.
    pub const POOL_UPDATE: AuditAction = AuditAction::from_static("dhcp.pool.update");
    /// A pool's settings were removed.
    pub const POOL_DELETE: AuditAction = AuditAction::from_static("dhcp.pool.delete");
    /// An exclusion range was created.
    pub const EXCLUSION_CREATE: AuditAction = AuditAction::from_static("dhcp.exclusion.create");
    /// An exclusion range was deleted.
    pub const EXCLUSION_DELETE: AuditAction = AuditAction::from_static("dhcp.exclusion.delete");
    /// A custom option definition was created.
    pub const OPTION_DEF_CREATE: AuditAction = AuditAction::from_static("dhcp.option.def_create");
    /// A custom option definition changed.
    pub const OPTION_DEF_UPDATE: AuditAction = AuditAction::from_static("dhcp.option.def_update");
    /// A custom option definition was deleted.
    pub const OPTION_DEF_DELETE: AuditAction = AuditAction::from_static("dhcp.option.def_delete");
    /// The options of a level changed (a set replaced or cleared).
    pub const OPTION_SET: AuditAction = AuditAction::from_static("dhcp.option.set");
    /// A class was created.
    pub const CLASS_CREATE: AuditAction = AuditAction::from_static("dhcp.class.create");
    /// A class changed.
    pub const CLASS_UPDATE: AuditAction = AuditAction::from_static("dhcp.class.update");
    /// A class was deleted.
    pub const CLASS_DELETE: AuditAction = AuditAction::from_static("dhcp.class.delete");
    /// A policy was created.
    pub const POLICY_CREATE: AuditAction = AuditAction::from_static("dhcp.policy.create");
    /// A policy changed (including its order).
    pub const POLICY_UPDATE: AuditAction = AuditAction::from_static("dhcp.policy.update");
    /// A policy was deleted.
    pub const POLICY_DELETE: AuditAction = AuditAction::from_static("dhcp.policy.delete");
    /// A MAC filter entry was created.
    pub const FILTER_CREATE: AuditAction = AuditAction::from_static("dhcp.filter.create");
    /// A MAC filter entry changed.
    pub const FILTER_UPDATE: AuditAction = AuditAction::from_static("dhcp.filter.update");
    /// A MAC filter entry was deleted.
    pub const FILTER_DELETE: AuditAction = AuditAction::from_static("dhcp.filter.delete");
    /// An operator released a lease (the address returns to the pool).
    pub const LEASE_RELEASE: AuditAction = AuditAction::from_static("dhcp.lease.release");
    /// Leases or lease history were read (personal data, plan section 2.1).
    pub const LEASE_READ: AuditAction = AuditAction::from_static("dhcp.lease.read");
    /// A client declined an address (DHCP-06); the address is held.
    pub const DECLINE: AuditAction = AuditAction::from_static("dhcp.decline");
    /// The configuration was exported (MIG-16).
    pub const EXPORT: AuditAction = AuditAction::from_static("dhcp.export");
    /// The retention service purged lease history (P3-Q13).
    pub const HISTORY_PURGE: AuditAction = AuditAction::from_static("dhcp.history.purge");

    /// Every action of the module, for the contracts document and its test.
    pub const ALL: [&AuditAction; 29] = [
        &SETTINGS_UPDATE,
        &SCOPE_CREATE,
        &SCOPE_UPDATE,
        &SCOPE_DELETE,
        &SHARED_NETWORK_CREATE,
        &SHARED_NETWORK_UPDATE,
        &SHARED_NETWORK_DELETE,
        &POOL_UPDATE,
        &POOL_DELETE,
        &EXCLUSION_CREATE,
        &EXCLUSION_DELETE,
        &OPTION_DEF_CREATE,
        &OPTION_DEF_UPDATE,
        &OPTION_DEF_DELETE,
        &OPTION_SET,
        &CLASS_CREATE,
        &CLASS_UPDATE,
        &CLASS_DELETE,
        &POLICY_CREATE,
        &POLICY_UPDATE,
        &POLICY_DELETE,
        &FILTER_CREATE,
        &FILTER_UPDATE,
        &FILTER_DELETE,
        &LEASE_RELEASE,
        &LEASE_READ,
        &DECLINE,
        &EXPORT,
        &HISTORY_PURGE,
    ];
}

/// The `kind` values of events on the [`TOPIC`] topic (plan section 3.4). Lease events are
/// sampled to at most 50 per second per subscriber, with a count of the dropped ones.
pub mod events {
    /// A lease changed (data: address, state, client, scope).
    pub const LEASE_CHANGED: &str = "dhcp.lease.changed";
    /// Lease events were dropped by sampling (data: the count since the last event).
    pub const LEASES_SAMPLED: &str = "dhcp.lease.sampled";
    /// The configuration changed (data: the object reference).
    pub const CONFIG_CHANGED: &str = "dhcp.config.changed";
    /// A conflict was found before an offer or by a DECLINE (data: address, scope).
    pub const CONFLICT: &str = "dhcp.conflict";
    /// The role stopped or started accepting lease writes (P3-Q14).
    pub const STORE_STATE: &str = "dhcp.store_state";
}

#[cfg(test)]
mod tests;
