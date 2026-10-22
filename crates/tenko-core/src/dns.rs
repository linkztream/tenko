//! The DNS model (Phase 2 plan, sections 2 and 3): zones, RRsets, views, forwarders, ACLs,
//! keys and block lists as rows of the replicated store, with their validation, the store
//! tables of the `dns` namespace, the authorization scopes, the error codes and the audit
//! actions.
//!
//! These are plain data and rules. The zone service (WP4.2) writes them through the store;
//! the engine (`tenko-dns`) builds its index from them and never writes (plan section 2.4).
//!
//! | Item | Contents |
//! |---|---|
//! | [`name`] | [`DnsName`], [`ScopeName`], [`Rtype`] |
//! | [`rdata`] | [`Rdata`] (wire form) and [`RecordData`] (typed view), TXT splitting (DNS-24) |
//! | [`rrset`] | [`RrSet`], [`RrSetKey`] and the RRset rules |
//! | this module | [`Zone`] and its policies, [`View`], [`ForwardRule`], [`Acl`], [`KeyMeta`], [`DnssecKeyMeta`], [`BlockList`], [`ListVersion`], [`JournalEntry`], [`SignState`] |
//! | [`tables`] | the tables of section 3.2 and the tables of the `dns` node role |
//! | [`codes`] | the `dns.*` error codes, [`DnsError`] |
//! | [`audit`] | the `dns.*` audit actions |
//! | [`DnsScope`] | the scopes `dns.read`, `dns.write` and `dns.keys` |

use std::{fmt, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Coded, CodedError,
    error::FieldError,
    id::{JobId, PrefixId, Revision, TenantId},
    ipam::Stamp,
    object::{ObjectKind, ObjectRef},
    secret::SecretRef,
    serde_util::HexBytes,
    timestamp::Timestamp,
};

pub mod name;
pub mod rdata;
pub mod rrset;

pub use name::{DnsName, Rtype, ScopeName};
pub use rdata::{Rdata, RecordData, SvcParam, TextBytes, split_txt};
pub use rrset::{MAX_TTL, RrSet, RrSetKey, check_apex, check_node};

crate::id_type! {
    /// Identifier of a zone.
    ZoneId,
    /// Identifier of a view (DNS-20).
    ViewId,
    /// Identifier of a forwarding rule (DNS-02).
    ForwardRuleId,
    /// Identifier of a DNS access list.
    AclId,
    /// Identifier of a TSIG or DNSSEC key's metadata.
    DnsKeyId,
    /// Identifier of a block list (DNS-15).
    BlockListId,
}

macro_rules! dns_object_refs {
    ($($id:ident => $kind:ident),+ $(,)?) => {$(
        impl From<$id> for ObjectRef {
            fn from(id: $id) -> Self {
                ObjectRef::new(ObjectKind::$kind, id.0)
            }
        }
    )+};
}

dns_object_refs! {
    ZoneId => Zone,
    ViewId => DnsView,
    ForwardRuleId => DnsForwarder,
    AclId => DnsAcl,
    DnsKeyId => DnsKey,
    BlockListId => DnsList,
}

/// The name of a TSIG key (RFC 8945): a DNS name.
pub type KeyName = DnsName;

/// The secret purpose of TSIG keys in the vault (node sync, `Config.Secrets`).
pub const TSIG_PURPOSE: &str = "tsig";

/// The secret purpose of DNSSEC private keys in the vault; nodes receive public parts
/// only (plan section 3.2).
pub const DNSSEC_PURPOSE: &str = "dnssec";

/// The SSE topic of the DNS module.
pub const TOPIC: &str = "dns";

/// The kinds of the DNS model as objects of authorization and audit.
pub const OBJECT_KINDS: [ObjectKind; 6] = [
    ObjectKind::Zone,
    ObjectKind::DnsView,
    ObjectKind::DnsForwarder,
    ObjectKind::DnsAcl,
    ObjectKind::DnsKey,
    ObjectKind::DnsList,
];

// ---------------------------------------------------------------------------------------
// Errors

/// Stable error codes of the `dns` namespace (API-08). Stable once merged.
pub mod codes {
    /// The zone does not exist (404). Params: `id`.
    pub const ZONE_NOT_FOUND: &str = "dns.zone.not_found";
    /// A zone of this name exists already in the scope (409). Params: `name`.
    pub const ZONE_EXISTS: &str = "dns.zone.exists";
    /// The zone settings are invalid (400). Params: `field`, `reason`.
    pub const ZONE_INVALID: &str = "dns.zone.invalid";
    /// A record or RRset breaks a rule of its type (400). Params: `name`, `type`, `reason`.
    pub const RECORD_INVALID: &str = "dns.record.invalid";
    /// RRsets of one owner name conflict (409): a CNAME beside other data, data beside a
    /// delegation, a type twice. Params: `name`, `type`, `reason`.
    pub const RECORD_CONFLICT: &str = "dns.record.conflict";
    /// The writer may not replace the RRset of another origin (409, plan section 2.5).
    /// Params: `name`, `type`, `origin`.
    pub const RECORD_ORIGIN: &str = "dns.record.origin";
    /// A zone file does not parse or holds what the import refuses (422). Params: `line`,
    /// `reason`.
    pub const ZONE_FILE_INVALID: &str = "dns.zonefile.invalid";
    /// The view does not exist (404). Params: `id`.
    pub const VIEW_NOT_FOUND: &str = "dns.view.not_found";
    /// The view settings are invalid (400). Params: `field`, `reason`.
    pub const VIEW_INVALID: &str = "dns.view.invalid";
    /// The forwarding rule does not exist (404). Params: `id`.
    pub const FORWARDER_NOT_FOUND: &str = "dns.forwarder.not_found";
    /// The forwarding rule is invalid (400). Params: `field`, `reason`.
    pub const FORWARDER_INVALID: &str = "dns.forwarder.invalid";
    /// The access list does not exist (404). Params: `id`.
    pub const ACL_NOT_FOUND: &str = "dns.acl.not_found";
    /// The access list is still named by a zone or view (409). Params: `id`, `by`.
    pub const ACL_IN_USE: &str = "dns.acl.in_use";
    /// The key does not exist (404). Params: `name`.
    pub const KEY_NOT_FOUND: &str = "dns.key.not_found";
    /// A key of this name exists already (409). Params: `name`.
    pub const KEY_EXISTS: &str = "dns.key.exists";
    /// The block list does not exist (404). Params: `id`.
    pub const LIST_NOT_FOUND: &str = "dns.list.not_found";
    /// The block list settings are invalid (400). Params: `field`, `reason`.
    pub const LIST_INVALID: &str = "dns.list.invalid";
    /// A dynamic update was refused (403): no or a wrong TSIG key, outside the ACL, or a
    /// prerequisite failed. Params: `zone`, `reason`.
    pub const UPDATE_REFUSED: &str = "dns.update.refused";
    /// A zone transfer was refused (403): outside the transfer ACL or without the required
    /// TSIG key. Params: `zone`, `reason`.
    pub const TRANSFER_REFUSED: &str = "dns.transfer.refused";
    /// The node does not run the `dns` role (409). Params: `node`.
    pub const NODE_NOT_DNS: &str = "dns.node.not_dns";
    /// The DNS module is switched off in this installation (409, OPS-25).
    pub const MODULE_DISABLED: &str = "dns.module.disabled";
    // WP6.4: the view codes the view service adds.
    /// The view, its zone scope or the zone is still named (409): a view named by a
    /// forwarding rule, a zone scope or a zone named by a view. Params: `id`, `by`.
    pub const VIEW_IN_USE: &str = "dns.view.in_use";

    // WP6.1: the codes of zone transfers.
    /// The zone's records come from a zone transfer and are read-only (409): a secondary
    /// zone, or the generated members of a catalog zone. Params: `zone`.
    pub const ZONE_SECONDARY: &str = "dns.zone.secondary";
    /// A zone transfer in failed: no answer, a refusal, a malformed or incomplete answer;
    /// the last error of a primary in the transfer status. Params: `zone`, `server`,
    /// `reason`.
    pub const TRANSFER_FAILED: &str = "dns.transfer.failed";
    /// The answer of a primary failed TSIG verification (BADKEY, BADSIG, BADTIME or an
    /// unsigned message). Params: `zone`, `server`, `reason`.
    pub const TRANSFER_TSIG: &str = "dns.transfer.tsig";

    // WP6.3: DNSSEC.
    /// The zone is not signed online, so its keys cannot roll (409). Params: `zone`,
    /// `mode`.
    pub const DNSSEC_NOT_ONLINE: &str = "dns.dnssec.not_online";
    /// A key rollover of the zone runs already (409). Params: `zone`, `job`.
    pub const DNSSEC_ROLLOVER_RUNNING: &str = "dns.dnssec.rollover_running";
    /// The zone could not be signed: a key is missing from the vault or does not load
    /// (500). Params: `zone`, `reason`.
    pub const DNSSEC_SIGNING_FAILED: &str = "dns.dnssec.signing_failed";

    // Backlog: the tenant's default zone.
    /// The default zone of a tenant is not one it may have (409): the zone does not
    /// exist, is not a primary zone, is a reverse zone, or belongs to another tenant.
    /// Params: `zone`, `reason` (`missing`, `not_primary`, `reverse`, `other_tenant`).
    pub const DEFAULT_ZONE_INVALID: &str = "dns.default_zone.invalid";
    // dns-visibility: the blocking view.
    /// The node's query log is off, so the blocking view has nothing to count (409).
    /// Params: `node`.
    pub const BLOCKING_LOG_OFF: &str = "dns.blocking.log_off";

    /// Every code of the namespace, for the contracts document and its test.
    pub const ALL: [&str; 30] = [
        ZONE_NOT_FOUND,
        ZONE_EXISTS,
        ZONE_INVALID,
        RECORD_INVALID,
        RECORD_CONFLICT,
        RECORD_ORIGIN,
        ZONE_FILE_INVALID,
        VIEW_NOT_FOUND,
        VIEW_INVALID,
        FORWARDER_NOT_FOUND,
        FORWARDER_INVALID,
        ACL_NOT_FOUND,
        ACL_IN_USE,
        KEY_NOT_FOUND,
        KEY_EXISTS,
        LIST_NOT_FOUND,
        LIST_INVALID,
        UPDATE_REFUSED,
        TRANSFER_REFUSED,
        NODE_NOT_DNS,
        MODULE_DISABLED,
        // WP6.4
        VIEW_IN_USE,
        ZONE_SECONDARY,
        TRANSFER_FAILED,
        TRANSFER_TSIG,
        DNSSEC_NOT_ONLINE,
        DNSSEC_ROLLOVER_RUNNING,
        DNSSEC_SIGNING_FAILED,
        // Backlog
        DEFAULT_ZONE_INVALID,
        // dns-visibility
        BLOCKING_LOG_OFF,
    ];
}

/// An error of the DNS model: a stable code, an HTTP status and parameters.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.detail)]
pub struct DnsError(Box<CodedError>);

impl fmt::Debug for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsError({}: {})", self.0.code, self.0.detail)
    }
}

impl DnsError {
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

    /// `dns.record.invalid` for an RRset.
    pub fn record_invalid(name: &DnsName, rtype: Rtype, reason: &str) -> Self {
        Self::new(
            codes::RECORD_INVALID,
            400,
            format!("{name} {rtype}: {reason}"),
        )
        .with_param("name", name.as_str())
        .with_param("type", rtype.to_string())
        .with_param("reason", reason)
    }

    /// `dns.record.conflict` between the RRsets of one owner.
    pub fn record_conflict(name: &DnsName, rtype: Rtype, reason: &str) -> Self {
        Self::new(
            codes::RECORD_CONFLICT,
            409,
            format!("{name} {rtype}: {reason}"),
        )
        .with_param("name", name.as_str())
        .with_param("type", rtype.to_string())
        .with_param("reason", reason)
    }

    /// An invalid setting of a zone, view, forwarder or list (`code` is the `*.invalid`
    /// code of the object).
    pub fn invalid(code: &'static str, field: &str, reason: &str) -> Self {
        Self::new(code, 400, format!("{field}: {reason}"))
            .with_param("field", field)
            .with_param("reason", reason)
            .with_field(field)
    }

    /// The captured error.
    pub fn as_coded_error(&self) -> &CodedError {
        &self.0
    }
}

impl Coded for DnsError {
    fn code(&self) -> &'static str {
        match &self.0.code {
            std::borrow::Cow::Borrowed(code) => code,
            std::borrow::Cow::Owned(_) => crate::error::codes::INTERNAL,
        }
    }
    fn http_status(&self) -> u16 {
        self.0.status
    }
    fn params(&self) -> std::collections::BTreeMap<&'static str, String> {
        // Parameter names are owned strings here; `to_coded_error` below carries them.
        std::collections::BTreeMap::new()
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

/// The scopes of the DNS module (ADR 0015, ADR 0017): named sets of actions on the DNS
/// object kinds that a role carries. `dns.read` reads zones, records, views, forwarders,
/// access lists and block lists; `dns.write` creates, changes, deletes and runs them
/// (imports, transfers, cache flushes); `dns.keys` is every action on TSIG and DNSSEC keys.
/// The viewer holds `dns.read`, the operator `dns.read` and `dns.write`, the administrator
/// all three; a scoped token reaches them through the roles of its grants.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub enum DnsScope {
    /// Read the DNS configuration.
    #[serde(rename = "dns.read")]
    Read,
    /// Change the DNS configuration.
    #[serde(rename = "dns.write")]
    Write,
    /// Manage TSIG and DNSSEC keys.
    #[serde(rename = "dns.keys")]
    Keys,
}

impl DnsScope {
    /// Every scope.
    pub const ALL: [DnsScope; 3] = [DnsScope::Read, DnsScope::Write, DnsScope::Keys];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            DnsScope::Read => "dns.read",
            DnsScope::Write => "dns.write",
            DnsScope::Keys => "dns.keys",
        }
    }

    /// The scope an action on a kind needs; `None` for a kind outside the DNS model and for
    /// approvals, reveals and administration, which no DNS scope grants.
    pub const fn required(action: crate::Action, kind: ObjectKind) -> Option<DnsScope> {
        use crate::Action;
        match kind {
            ObjectKind::DnsKey => match action {
                Action::Read
                | Action::Create
                | Action::Update
                | Action::Delete
                | Action::Execute => Some(DnsScope::Keys),
                Action::Approve | Action::Reveal | Action::Administer => None,
            },
            ObjectKind::Zone
            | ObjectKind::DnsView
            | ObjectKind::DnsForwarder
            | ObjectKind::DnsAcl
            | ObjectKind::DnsList => match action {
                Action::Read => Some(DnsScope::Read),
                Action::Create | Action::Update | Action::Delete | Action::Execute => {
                    Some(DnsScope::Write)
                }
                Action::Approve | Action::Reveal | Action::Administer => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for DnsScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------------------
// Zones

/// What a zone is (DNS-01, DNS-09, DNS-21).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    /// Tenko holds the data.
    Primary,
    /// Tenko copies the data from primaries by zone transfer.
    Secondary,
    /// Tenko learns the zone's name servers from primaries and refers to them.
    Stub,
    /// Queries for the zone go to the servers of [`Zone::source`].
    Forward,
    /// A response policy zone (DNS-15), local or transferred.
    Rpz,
}

/// A scope of a zone (DNS-20): one version of the zone's data that views choose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct ZoneScope {
    /// The scope name, unique in the zone.
    pub name: ScopeName,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ZoneScope {
    /// The default scope.
    pub fn default_scope() -> Self {
        Self {
            name: ScopeName::DEFAULT,
            description: None,
        }
    }
}

/// How the SOA serial moves on a change (DNS-07).
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
pub enum SerialPolicy {
    /// Seconds since 1970, at least one above the previous serial.
    Unixtime,
    /// The previous serial plus one.
    Counter,
    /// `YYYYMMDDnn`, falling back to plus one when `nn` runs out.
    #[default]
    DateCounter,
}

// Backlog: the tenant's default zone.
/// The DNS settings of a tenant (`dns` on the tenant, `PATCH /tenants/{id}` with
/// `If-Match`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct TenantDns {
    /// The default zone: a primary forward zone of the tenant, or one without a tenant.
    /// The reverse zones IPAM creates for the tenant's prefixes take their SOA values and
    /// name servers from it and follow it when they change (`docs/dns.md` section 7).
    /// Without it, the tenant's first forward zone serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub default_zone: Option<ZoneId>,
}

impl TenantDns {
    /// Whether nothing is set.
    pub fn is_empty(&self) -> bool {
        self.default_zone.is_none()
    }
}

/// The SOA values of a zone apart from the serial.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct SoaDefaults {
    /// The primary name server.
    pub mname: DnsName,
    /// The mailbox of the responsible person as a name (`hostmaster.example.test`).
    pub rname: DnsName,
    /// Refresh interval in seconds.
    #[serde(default = "default_refresh")]
    pub refresh: u32,
    /// Retry interval in seconds.
    #[serde(default = "default_retry")]
    pub retry: u32,
    /// Expiry in seconds.
    #[serde(default = "default_expire")]
    pub expire: u32,
    /// TTL of negative answers in seconds (RFC 2308).
    #[serde(default = "default_minimum")]
    pub minimum: u32,
    /// TTL of the SOA record itself, and the default TTL of new RRsets.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

const fn default_refresh() -> u32 {
    3600
}
const fn default_retry() -> u32 {
    900
}
const fn default_expire() -> u32 {
    1_209_600
}
const fn default_minimum() -> u32 {
    300
}
const fn default_ttl() -> u32 {
    3600
}

impl SoaDefaults {
    /// The defaults for a primary server and a responsible mailbox.
    pub fn new(mname: DnsName, rname: DnsName) -> Self {
        Self {
            mname,
            rname,
            refresh: default_refresh(),
            retry: default_retry(),
            expire: default_expire(),
            minimum: default_minimum(),
            ttl: default_ttl(),
        }
    }

    /// Checks the bounds: every value at most 2^31 - 1, refresh and retry above zero, the
    /// expiry at least the refresh interval plus the retry interval.
    ///
    /// # Errors
    ///
    /// `dns.zone.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid =
            |field: &str, reason: &str| Err(DnsError::invalid(codes::ZONE_INVALID, field, reason));
        for (field, value) in [
            ("soa.refresh", self.refresh),
            ("soa.retry", self.retry),
            ("soa.expire", self.expire),
            ("soa.minimum", self.minimum),
            ("soa.ttl", self.ttl),
        ] {
            if value > MAX_TTL {
                return invalid(field, "at most 2147483647 seconds");
            }
        }
        if self.refresh == 0 || self.retry == 0 {
            return invalid("soa.refresh", "refresh and retry are above zero");
        }
        if u64::from(self.expire) < u64::from(self.refresh) + u64::from(self.retry) {
            return invalid("soa.expire", "the expiry is at least refresh plus retry");
        }
        if self.mname.is_root() || self.mname.is_wildcard() {
            return invalid("soa.mname", "the primary server is a host name");
        }
        if self.rname.is_root() || self.rname.is_wildcard() {
            return invalid("soa.rname", "the mailbox is a name of two or more labels");
        }
        Ok(())
    }
}

/// A server that receives NOTIFY for a zone (RFC 1996).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct NotifyTarget {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.53")]
    pub address: IpAddr,
    /// The port.
    #[serde(default = "default_dns_port")]
    pub port: u16,
    /// The TSIG key to sign the NOTIFY with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyName>,
}

const fn default_dns_port() -> u16 {
    53
}

const fn yes() -> bool {
    true
}

/// Who may transfer a zone and who is notified (DNS-09, DNS-19, TGL-10).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct TransferPolicy {
    /// The access lists that may transfer; none means nobody.
    #[serde(default)]
    pub allow: Vec<AclId>,
    /// The servers notified when the serial changes.
    #[serde(default)]
    pub notify: Vec<NotifyTarget>,
    /// Transfers need a TSIG key (TGL-10).
    #[serde(default = "yes")]
    pub require_tsig: bool,
    /// Transfers run over TLS (XoT, RFC 9103).
    #[serde(default)]
    pub xot: bool,
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            notify: Vec::new(),
            require_tsig: true,
            xot: false,
        }
    }
}

/// Who may change a zone by dynamic update (DNS-11, TGL-09). Named `DnsUpdatePolicy` in
/// the OpenAPI document, apart from the software-update policy of the system settings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[schema(as = DnsUpdatePolicy)]
pub struct UpdatePolicy {
    /// The access lists that may update; none means nobody.
    #[serde(default)]
    pub allowed: Vec<AclId>,
    /// Updates need a TSIG key (TGL-09).
    #[serde(default = "yes")]
    pub require_tsig: bool,
    /// A dynamic update may replace an RRset whose origin is `ipam` (plan section 2.5).
    #[serde(default)]
    pub may_replace_ipam: bool,
    // WP8.3: whether Tenko DHCP writes names into the zone (ADR 0020 point 6, P3-Q6).
    /// Whether Tenko DHCP may write the names of its clients into the zone (ADR 0020; the
    /// internal path, which TGL-09 does not govern). None follows the security profile:
    /// Home and Lab allow, Standard and Hardened do not until the operator allows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
}

// WP8.3: the effective DHCP switch of a zone.
impl UpdatePolicy {
    /// Whether Tenko DHCP may write into the zone; `profile_allows` is the profile's
    /// default (true under Home and Lab).
    pub fn dhcp_allowed(&self, profile_allows: bool) -> bool {
        self.dhcp.unwrap_or(profile_allows)
    }
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            require_tsig: true,
            may_replace_ipam: false,
            dhcp: None,
        }
    }
}

/// Whether and how a zone is signed (DNS-12, plan section 2.7).
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
pub enum DnssecMode {
    /// Not signed.
    #[default]
    Off,
    /// Signed by the controllers with keys in the vault.
    Online,
    /// Served as imported, already signed; the expiry is watched.
    Imported,
}

/// A DNSSEC signing algorithm Tenko signs with.
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
pub enum DnssecAlgorithm {
    /// ECDSA P-256 with SHA-256, algorithm 13 (the default).
    #[default]
    EcdsaP256Sha256,
    /// Ed25519, algorithm 15.
    Ed25519,
}

impl DnssecAlgorithm {
    /// The algorithm number (RFC 8624).
    pub const fn number(self) -> u8 {
        match self {
            DnssecAlgorithm::EcdsaP256Sha256 => 13,
            DnssecAlgorithm::Ed25519 => 15,
        }
    }
}

/// How a signed zone proves non-existence.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Denial {
    /// NSEC (RFC 4034).
    #[default]
    Nsec,
    /// NSEC3 without opt-out (RFC 5155, RFC 9276).
    Nsec3 {
        /// Extra hash iterations; RFC 9276 recommends 0.
        #[serde(default)]
        iterations: u16,
        /// The salt; RFC 9276 recommends none.
        #[serde(default)]
        salt: HexBytes,
    },
}

/// The signing settings of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct DnssecPolicy {
    /// Off, online or imported.
    #[serde(default)]
    pub mode: DnssecMode,
    /// The algorithm of new keys.
    #[serde(default)]
    pub algorithm: DnssecAlgorithm,
    /// NSEC or NSEC3.
    #[serde(default)]
    pub denial: Denial,
    /// How long a signature is valid, in days.
    #[serde(default = "default_validity")]
    pub signature_validity_days: u16,
    /// How long before the expiry a signature is renewed, in days.
    #[serde(default = "default_resign")]
    pub resign_before_days: u16,
    // WP6.3: the combined signing key and the rollover schedule.
    /// One combined signing key (CSK) instead of a KSK and a ZSK.
    #[serde(default)]
    pub csk: bool,
    /// Days between scheduled ZSK rollovers; none rolls only when asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zsk_rollover_days: Option<u16>,
}

const fn default_validity() -> u16 {
    14
}
const fn default_resign() -> u16 {
    7
}

impl Default for DnssecPolicy {
    fn default() -> Self {
        Self {
            mode: DnssecMode::Off,
            algorithm: DnssecAlgorithm::default(),
            denial: Denial::Nsec,
            signature_validity_days: default_validity(),
            resign_before_days: default_resign(),
            csk: false,
            zsk_rollover_days: None,
        }
    }
}

/// A server Tenko transfers a secondary zone from, or sends the queries of a forward or
/// stub zone to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct PrimaryServer {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.53")]
    pub address: IpAddr,
    /// The port.
    #[serde(default = "default_dns_port")]
    pub port: u16,
    /// The TSIG key of transfers and NOTIFY.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyName>,
    /// Transfers run over TLS (XoT); `tls_name` is then the server's certificate name.
    #[serde(default)]
    pub xot: bool,
    /// The name in the server's certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_name: Option<String>,
}

/// Where the data of a secondary, stub, forward or transferred RPZ zone comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct SecondarySource {
    /// The servers, tried in order.
    pub primaries: Vec<PrimaryServer>,
}

/// A zone (DNS-01): its name, kind, scopes and policies. The records are rows of
/// `dns.rrsets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Zone {
    /// Identifier.
    pub id: ZoneId,
    /// The apex name.
    pub name: DnsName,
    /// What the zone is.
    pub kind: ZoneKind,
    /// The owning tenant; none for an installation-wide zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    /// The scopes; always holds `default`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<ZoneScope>,
    /// How the serial moves.
    #[serde(default)]
    pub serial: SerialPolicy,
    /// The SOA values.
    pub soa: SoaDefaults,
    /// Zone transfers and NOTIFY.
    #[serde(default)]
    pub transfer: TransferPolicy,
    /// Dynamic updates.
    #[serde(default)]
    pub update: UpdatePolicy,
    /// Signing.
    #[serde(default)]
    pub dnssec: DnssecPolicy,
    /// The servers of a secondary, stub, forward or transferred RPZ zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SecondarySource>,
    /// The IPAM prefix whose reverse zone this is (plan section 2.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse_of: Option<PrefixId>,
    // WP6.1: catalog zones (RFC 9432).
    /// A catalog zone (RFC 9432). On a secondary zone: its members become secondary zones
    /// of this installation with the catalog's primaries and leave with it. On a primary
    /// zone: Tenko writes its members, every primary zone of the same tenant (or without a
    /// tenant) whose `transfer.allow` is not empty, catalog zones excepted.
    #[serde(default)]
    pub catalog: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
    /// Last change.
    pub updated: Stamp,
}

fn default_scopes() -> Vec<ZoneScope> {
    vec![ZoneScope::default_scope()]
}

impl Zone {
    /// Checks a zone: the name is not a wildcard; the scopes hold `default` and no name
    /// twice; the SOA values are in bounds; a secondary, stub or forward zone names at
    /// least one server and a primary zone none; `reverse_of` only on a name under
    /// `in-addr.arpa` or `ip6.arpa`; online signing only for a primary zone.
    ///
    /// # Errors
    ///
    /// `dns.zone.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid =
            |field: &str, reason: &str| Err(DnsError::invalid(codes::ZONE_INVALID, field, reason));
        if self.name.is_wildcard() {
            return invalid("name", "a zone apex is not a wildcard");
        }
        if !self
            .scopes
            .iter()
            .any(|scope| scope.name == ScopeName::DEFAULT)
        {
            return invalid("scopes", "every zone has the scope `default`");
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if self.scopes[..index]
                .iter()
                .any(|other| other.name == scope.name)
            {
                return invalid("scopes", "a scope name appears twice");
            }
        }
        self.soa.validate()?;
        let servers = self
            .source
            .as_ref()
            .map_or(0, |source| source.primaries.len());
        match self.kind {
            ZoneKind::Secondary | ZoneKind::Stub | ZoneKind::Forward if servers == 0 => {
                return invalid("source", "this kind of zone needs at least one server");
            }
            ZoneKind::Primary if servers > 0 => {
                return invalid("source", "a primary zone has no source servers");
            }
            _ => {}
        }
        if self.reverse_of.is_some() {
            let in_addr = DnsName::new("in-addr.arpa").ok();
            let ip6 = DnsName::new("ip6.arpa").ok();
            let reverse = [in_addr, ip6]
                .iter()
                .flatten()
                .any(|suffix| self.name.is_subdomain_of(suffix) && &self.name != suffix);
            if !reverse {
                return invalid("reverse_of", "only a reverse zone belongs to a prefix");
            }
        }
        if self.dnssec.mode == DnssecMode::Online && self.kind != ZoneKind::Primary {
            return invalid("dnssec.mode", "only a primary zone is signed online");
        }
        // WP6.1: a catalog zone is a primary or a secondary zone.
        if self.catalog && !matches!(self.kind, ZoneKind::Primary | ZoneKind::Secondary) {
            return invalid(
                "catalog",
                "only a primary or a secondary zone is a catalog zone",
            );
        }
        if self.dnssec.resign_before_days >= self.dnssec.signature_validity_days {
            return invalid(
                "dnssec.resign_before_days",
                "signatures are renewed before they expire",
            );
        }
        Ok(())
    }

    /// Whether the zone has a scope.
    pub fn has_scope(&self, scope: &ScopeName) -> bool {
        self.scopes.iter().any(|candidate| &candidate.name == scope)
    }
}

/// Who owns an RRset (plan section 2.5, P2-Q12).
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
pub enum Origin {
    /// The API, the UI or a zone file.
    #[default]
    Manual,
    /// The DNS actuator of IPAM.
    Ipam,
    /// An RFC 2136 update; [`RrSet::key`] names its TSIG key.
    Dynamic,
    /// Tenko DHCP (Phase 3).
    Dhcp,
    /// Active Directory (Phase 4).
    Ad,
    /// A zone transfer in (WP6.1): the records of a secondary zone, and the members Tenko
    /// writes into a primary catalog zone; read-only for every other writer.
    Transfer,
    // WP6.3: the rows of the signer.
    /// The DNSSEC signer (DNSKEY, CDS, CDNSKEY, NSEC, NSEC3, NSEC3PARAM, RRSIG): written
    /// only by the signing service, refused for every other writer.
    Dnssec,
}

impl Origin {
    /// Whether a writer of this origin may replace an RRset of `existing` origin in a zone
    /// with `policy`. A person (manual) may replace anything; the reconciler restores an
    /// `ipam` RRset that a person changed. The actuator touches `ipam` RRsets only. Dynamic
    /// updates, DHCP and AD replace `ipam` RRsets only when the zone policy allows. The
    /// signer replaces only its own rows, and no other writer replaces them.
    pub fn may_replace(self, existing: Origin, policy: &UpdatePolicy) -> bool {
        // WP6.1: what a transfer wrote only a transfer replaces, and it replaces anything.
        if self == Origin::Transfer {
            return true;
        }
        if existing == Origin::Transfer {
            return false;
        }
        match self {
            Origin::Manual | Origin::Transfer => existing != Origin::Dnssec,
            Origin::Ipam => existing == Origin::Ipam,
            Origin::Dynamic | Origin::Dhcp | Origin::Ad => match existing {
                Origin::Ipam => policy.may_replace_ipam,
                Origin::Dnssec => false,
                _ => true,
            },
            // WP6.3: the signer owns its rows only.
            Origin::Dnssec => existing == Origin::Dnssec,
        }
    }
}

/// Addresses and prefixes inside internally tagged enums, written as text in every format.
///
/// Serde reads an internally tagged enum through a buffer that reports a human-readable
/// format, while CBOR writes `IpAddr` and `IpNet` in their binary form, so such a value
/// written to the store did not read back. As text it reads back in CBOR and JSON alike.
mod text {
    use std::{fmt::Display, str::FromStr};

    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(D::Error::custom)
    }

    /// The same for a list.
    pub(super) mod list {
        use std::{fmt::Display, str::FromStr};

        use serde::{Deserialize, Deserializer, Serializer, de::Error, ser::SerializeSeq};

        pub(in super::super) fn serialize<T: Display, S: Serializer>(
            values: &[T],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(Some(values.len()))?;
            for value in values {
                seq.serialize_element(&value.to_string())?;
            }
            seq.end()
        }

        pub(in super::super) fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
        where
            T: FromStr,
            T::Err: Display,
            D: Deserializer<'de>,
        {
            Vec::<String>::deserialize(deserializer)?
                .iter()
                .map(|text| text.parse().map_err(D::Error::custom))
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------------------
// Views

/// A transport a query arrives on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueryTransport {
    /// UDP on port 53.
    Udp,
    /// TCP on port 53.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS (RFC 8484).
    Doh,
}

/// One test of a view (DNS-20). A view matches a query when all its rules match.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "test", rename_all = "snake_case")]
pub enum MatchRule {
    /// The client address is in one of the prefixes.
    ClientSubnet {
        /// The prefixes.
        #[schema(value_type = Vec<String>, example = json!(["192.0.2.0/24"]))]
        #[serde(with = "text::list")]
        prefixes: Vec<IpNet>,
    },
    /// The query arrived on one of the transports.
    Transport {
        /// The transports.
        transports: Vec<QueryTransport>,
    },
    /// The query arrived on one of the server's addresses.
    Interface {
        /// The local addresses.
        #[schema(value_type = Vec<String>, example = json!(["192.0.2.53"]))]
        #[serde(with = "text::list")]
        addresses: Vec<IpAddr>,
    },
    /// The query type is one of these.
    Qtype {
        /// The types.
        types: Vec<Rtype>,
    },
    /// The time of day (UTC) is within the window; a window whose start is after its end
    /// wraps midnight.
    TimeOfDay {
        /// The first minute of the day, 0 to 1439.
        from_minute: u16,
        /// The last minute of the day, 0 to 1439.
        to_minute: u16,
    },
    /// The query name is at or below one of these names.
    Qname {
        /// The suffixes.
        suffixes: Vec<DnsName>,
    },
}

impl MatchRule {
    /// Checks the rule: a list is not empty, minutes are below 1440.
    ///
    /// # Errors
    ///
    /// `dns.view.invalid` naming the rule.
    pub fn validate(&self) -> Result<(), DnsError> {
        let empty = match self {
            MatchRule::ClientSubnet { prefixes } => prefixes.is_empty(),
            MatchRule::Transport { transports } => transports.is_empty(),
            MatchRule::Interface { addresses } => addresses.is_empty(),
            MatchRule::Qtype { types } => types.is_empty(),
            MatchRule::Qname { suffixes } => suffixes.is_empty(),
            MatchRule::TimeOfDay {
                from_minute,
                to_minute,
            } => {
                if *from_minute >= 1440 || *to_minute >= 1440 {
                    return Err(DnsError::invalid(
                        codes::VIEW_INVALID,
                        "rules",
                        "minutes of the day are 0 to 1439",
                    ));
                }
                false
            }
        };
        if empty {
            return Err(DnsError::invalid(
                codes::VIEW_INVALID,
                "rules",
                "a rule lists at least one value",
            ));
        }
        Ok(())
    }

    /// Whether the minute of the day (UTC) is in a time window.
    pub fn minute_in_window(minute: u16, from: u16, to: u16) -> bool {
        if from <= to {
            (from..=to).contains(&minute)
        } else {
            minute >= from || minute <= to
        }
    }
}

/// The weight of one zone scope in a view (DNS-20): among the scopes a view maps for one
/// zone, a query picks one in proportion to the weights.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct ScopeWeight {
    /// The zone.
    pub zone: ZoneId,
    /// The scope of the zone.
    pub scope: ScopeName,
    /// The weight, 1 to 1000.
    pub weight: u16,
}

/// A view (DNS-20): rules that select queries, and the zone scopes they see. Views are
/// tried in `order`; the first match wins; a query no view matches uses the default scope
/// of every zone (the implicit default view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct View {
    /// Identifier.
    pub id: ViewId,
    /// A unique name, 1 to 64 characters.
    pub name: String,
    /// The tests; none matches every query.
    #[serde(default)]
    pub rules: Vec<MatchRule>,
    /// The scopes this view sees per zone; a zone not listed is seen in its default scope.
    #[serde(default)]
    pub scope_map: Vec<ScopeWeight>,
    /// The position among the views, lower first.
    pub order: u32,
    /// The access list that decides which clients of this view may recurse (DNS-02,
    /// TGL-22): names outside the zones go to the forwarder only for the clients it allows.
    /// Absent: the profile's default (Home and Standard: the prefixes IPAM knows and
    /// loopback; Hardened: no client; Lab: every client).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recursion: Option<AclId>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl View {
    /// Checks a view: the name, each rule, weights from 1 to 1000 and no zone scope twice.
    ///
    /// # Errors
    ///
    /// `dns.view.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        check_object_name(codes::VIEW_INVALID, &self.name)?;
        for rule in &self.rules {
            rule.validate()?;
        }
        for (index, entry) in self.scope_map.iter().enumerate() {
            if !(1..=1000).contains(&entry.weight) {
                return Err(DnsError::invalid(
                    codes::VIEW_INVALID,
                    "scope_map",
                    "weights are 1 to 1000",
                ));
            }
            if self.scope_map[..index]
                .iter()
                .any(|other| other.zone == entry.zone && other.scope == entry.scope)
            {
                return Err(DnsError::invalid(
                    codes::VIEW_INVALID,
                    "scope_map",
                    "a zone scope appears twice",
                ));
            }
        }
        Ok(())
    }
}

fn check_object_name(code: &'static str, name: &str) -> Result<(), DnsError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 || trimmed != name {
        return Err(DnsError::invalid(
            code,
            "name",
            "1 to 64 characters without surrounding spaces",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(DnsError::invalid(
            code,
            "name",
            "control characters are not allowed",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Forwarders

/// How queries reach an upstream resolver (TGL-14).
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
pub enum ForwardTransport {
    /// UDP with TCP fallback, port 53.
    #[default]
    Plain,
    /// DNS over TLS, port 853.
    Dot,
    /// DNS over HTTPS, port 443.
    Doh,
}

impl ForwardTransport {
    /// The default port.
    pub const fn default_port(self) -> u16 {
        match self {
            ForwardTransport::Plain => 53,
            ForwardTransport::Dot => 853,
            ForwardTransport::Doh => 443,
        }
    }
}

/// An upstream resolver of a forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Upstream {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.1")]
    pub address: IpAddr,
    /// The port; the transport's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The URL path of a DoH upstream; `/dns-query` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// A forwarding rule (DNS-02, DNS-21): queries at or below `suffix` go to the upstreams.
/// The longest matching suffix wins; the root suffix `.` is the default forwarder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ForwardRule {
    /// Identifier.
    pub id: ForwardRuleId,
    /// The names the rule covers.
    pub suffix: DnsName,
    /// The upstreams, 1 to 16.
    pub upstreams: Vec<Upstream>,
    /// How they are reached.
    #[serde(default)]
    pub transport: ForwardTransport,
    /// The name in the upstreams' certificates, for DoT and DoH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_name: Option<String>,
    /// The view the rule applies in; all views when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ForwardRule {
    /// Checks a rule: 1 to 16 upstreams; DoT and DoH name the TLS name; a path only for
    /// DoH, starting with `/`.
    ///
    /// # Errors
    ///
    /// `dns.forwarder.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        let invalid = |field: &str, reason: &str| {
            Err(DnsError::invalid(codes::FORWARDER_INVALID, field, reason))
        };
        if self.upstreams.is_empty() || self.upstreams.len() > 16 {
            return invalid("upstreams", "a rule has 1 to 16 upstreams");
        }
        if self.transport != ForwardTransport::Plain
            && self
                .tls_name
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
        {
            return invalid(
                "tls_name",
                "DoT and DoH upstreams need the certificate name",
            );
        }
        for upstream in &self.upstreams {
            match (&upstream.path, self.transport) {
                (Some(path), ForwardTransport::Doh) if !path.starts_with('/') => {
                    return invalid("upstreams", "a DoH path starts with `/`");
                }
                (Some(_), ForwardTransport::Plain | ForwardTransport::Dot) => {
                    return invalid("upstreams", "only a DoH upstream has a path");
                }
                _ => {}
            }
            if upstream.port == Some(0) {
                return invalid("upstreams", "port 0 is not a port");
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Access lists and keys

/// One entry of an access list; the first entry that matches decides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AclEntry {
    /// Clients in a prefix.
    Prefix {
        /// The prefix.
        #[schema(value_type = String, example = "192.0.2.0/24")]
        #[serde(with = "text")]
        prefix: IpNet,
        /// The entry refuses instead of allowing.
        #[serde(default)]
        deny: bool,
    },
    /// Requests signed with a TSIG key.
    Key {
        /// The key.
        name: KeyName,
        /// The entry refuses instead of allowing.
        #[serde(default)]
        deny: bool,
    },
    /// Every request.
    Any {
        /// The entry refuses instead of allowing.
        #[serde(default)]
        deny: bool,
    },
}

/// A named access list for transfers, updates, recursion and queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Acl {
    /// Identifier.
    pub id: AclId,
    /// A unique name, 1 to 64 characters.
    pub name: String,
    /// The entries, in order.
    pub entries: Vec<AclEntry>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Acl {
    /// Whether a request from `client`, signed with `key` if any, is allowed: the first
    /// matching entry decides; no match refuses.
    pub fn allows(&self, client: IpAddr, key: Option<&KeyName>) -> bool {
        for entry in &self.entries {
            match entry {
                AclEntry::Prefix { prefix, deny } if prefix.contains(&client) => return !deny,
                AclEntry::Key { name, deny } if key == Some(name) => return !deny,
                AclEntry::Any { deny } => return !deny,
                _ => {}
            }
        }
        false
    }
}

/// A TSIG algorithm (RFC 8945). HMAC-SHA256 is the default; HMAC-SHA1 is accepted for
/// Windows DNS (risk R51).
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
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    /// `hmac-sha256`.
    #[default]
    HmacSha256,
    /// `hmac-sha384`.
    HmacSha384,
    /// `hmac-sha512`.
    HmacSha512,
    /// `hmac-sha1`, for peers that know nothing better.
    HmacSha1,
}

impl TsigAlgorithm {
    /// The algorithm's name as it appears on the wire.
    pub const fn wire_name(self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
            TsigAlgorithm::HmacSha1 => "hmac-sha1",
        }
    }
}

/// The metadata of a TSIG key; the secret is an operator secret in the vault with the
/// purpose [`TSIG_PURPOSE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KeyMeta {
    /// Identifier.
    pub id: DnsKeyId,
    /// The key name, unique.
    pub name: KeyName,
    /// The algorithm.
    pub algorithm: TsigAlgorithm,
    /// The secret in the vault.
    pub secret: SecretRef,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
}

/// The role of a DNSSEC key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Key-signing key: signs the DNSKEY set; its DS stands in the parent.
    Ksk,
    /// Zone-signing key: signs everything else.
    Zsk,
    /// Combined signing key.
    Csk,
}

/// Where a DNSSEC key stands in its life (RFC 6781, RFC 7583).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Generated, not published.
    Generated,
    /// The DNSKEY is published, nothing is signed with it yet.
    Published,
    /// It signs.
    Active,
    /// It no longer signs; the DNSKEY stays until caches have forgotten its signatures.
    Retired,
    /// Withdrawn.
    Removed,
}

/// The metadata of one DNSSEC key of a zone; the private key is a system secret in the
/// vault with the purpose [`DNSSEC_PURPOSE`] and never leaves the controllers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecKeyMeta {
    /// Identifier.
    pub id: DnsKeyId,
    /// The zone.
    pub zone: ZoneId,
    /// KSK, ZSK or CSK.
    pub role: KeyRole,
    /// The algorithm.
    pub algorithm: DnssecAlgorithm,
    /// The key tag (RFC 4034, appendix B).
    pub key_tag: u16,
    /// The public key as in the DNSKEY record.
    pub public_key: HexBytes,
    /// The private key in the vault.
    pub secret: SecretRef,
    /// The state.
    pub state: KeyState,
    /// Creation.
    pub created: Stamp,
    /// When the DNSKEY was published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<Timestamp>,
    /// When it started to sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<Timestamp>,
    /// When it stopped signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<Timestamp>,
}

/// The signing state of one zone (`dns.sign_state`), kept by the signing service on the
/// controllers and never sent to nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignState {
    /// The zone.
    pub zone: ZoneId,
    /// The keys.
    pub keys: Vec<DnssecKeyMeta>,
    /// The serial last signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_serial: Option<u32>,
    /// When the zone was last signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_signed: Option<Timestamp>,
    /// When the next re-signing is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_resign: Option<Timestamp>,
    // WP6.3: where the signer stands and what runs.
    /// The store revision whose changes the signed data includes: the signer watches the
    /// store from here after a restart or a change of leader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_revision: Option<Revision>,
    /// When the earliest signature of the zone expires (online and imported zones).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    /// The key rollover that runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_job: Option<JobId>,
}

// ---------------------------------------------------------------------------------------
// Block lists

/// Where a block list comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListSource {
    /// Fetched by a controller from a URL the operator entered (P2-Q6).
    Url {
        /// The URL, `https://` or `http://`.
        url: String,
    },
    /// Uploaded by the operator.
    Upload,
}

/// The file format of a block list.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ListFormat {
    /// A hosts file (`0.0.0.0 ads.example.test`).
    Hosts,
    /// One domain per line.
    Domains,
}

/// What a blocked name answers (DNS-15); every blocked answer carries the extended error of
/// RFC 8914.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockAction {
    /// NXDOMAIN.
    Nxdomain,
    /// NOERROR without data.
    Nodata,
    /// An address record of this address.
    Redirect {
        /// The address answered.
        #[schema(value_type = String, example = "192.0.2.80")]
        #[serde(with = "text")]
        address: IpAddr,
    },
}

/// What a list does with the names it holds.
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
pub enum ListKind {
    /// The names and the names under them are blocked with the list's action.
    #[default]
    Block,
    /// The names and the names under them are never blocked, by any list or RPZ zone;
    /// the clients of its `exempt` prefixes are never blocked at all.
    Allow,
}

/// A block list (DNS-15, DNS-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BlockList {
    /// Identifier.
    pub id: BlockListId,
    /// A unique name, 1 to 64 characters.
    pub name: String,
    /// A block list or an allow list.
    #[serde(default)]
    pub kind: ListKind,
    /// Where it comes from.
    pub source: ListSource,
    /// The file format.
    pub format: ListFormat,
    /// How often a URL list is fetched, in hours (1 to 168).
    #[serde(default = "default_interval")]
    pub interval_hours: u16,
    /// What a blocked name answers.
    pub action: BlockAction,
    /// Whether the list is applied.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Clients exempt from the list (at most 1,000 prefixes): a block list does not block
    /// them; an allow list exempts them from every list and RPZ zone.
    #[schema(value_type = Vec<String>, example = json!(["192.0.2.10/32"]))]
    #[serde(default, with = "text::list", skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<IpNet>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

const fn default_interval() -> u16 {
    24
}

impl BlockList {
    /// Checks a list: the name, an `http` or `https` URL, an interval of 1 to 168 hours, at
    /// most 1,000 exempt prefixes.
    ///
    /// # Errors
    ///
    /// `dns.list.invalid` naming the field.
    pub fn validate(&self) -> Result<(), DnsError> {
        check_object_name(codes::LIST_INVALID, &self.name)?;
        if let ListSource::Url { url } = &self.source
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err(DnsError::invalid(
                codes::LIST_INVALID,
                "source.url",
                "an http or https URL",
            ));
        }
        if !(1..=168).contains(&self.interval_hours) {
            return Err(DnsError::invalid(
                codes::LIST_INVALID,
                "interval_hours",
                "1 to 168 hours",
            ));
        }
        if self.exempt.len() > 1_000 {
            return Err(DnsError::invalid(
                codes::LIST_INVALID,
                "exempt",
                "at most 1000 prefixes",
            ));
        }
        Ok(())
    }
}

/// One compiled version of a block list (`dns.list_versions`), distributed to the nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListVersion {
    /// The list.
    pub list: BlockListId,
    /// The version, counting up from 1 per list.
    pub revision: u64,
    /// The compiled matcher (the format belongs to the policy engine, WP5.2).
    pub compiled: HexBytes,
    /// How many names it blocks.
    pub entries: u64,
    /// When the source was read.
    pub fetched: Timestamp,
    /// The HTTP entity tag of the fetched source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

// ---------------------------------------------------------------------------------------
// Journal

/// One record of a journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalRecord {
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The data.
    pub rdata: Rdata,
}

/// One serial step of a zone scope (`dns.journal`): what IXFR sends (RFC 1995). The journal
/// is bounded by entries and days; a request older than its first entry gets AXFR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalEntry {
    /// The zone.
    pub zone: ZoneId,
    /// The scope.
    pub scope: ScopeName,
    /// The serial before.
    pub from_serial: u32,
    /// The serial after.
    pub to_serial: u32,
    /// The store revision the step was planned against: the revision of the read view
    /// whose SOA the change replaced. A batch is committed only while that SOA is
    /// unchanged, so the value is strictly increasing per zone scope and below the
    /// revision that committed the step (which a batch cannot know before it commits).
    pub revision: Revision,
    /// When.
    pub at: Timestamp,
    /// Records removed.
    pub removed: Vec<JournalRecord>,
    /// Records added.
    pub added: Vec<JournalRecord>,
}

// ---------------------------------------------------------------------------------------
// Store tables

/// The tables of the `dns` namespace (plan section 3.2).
///
/// | Table | Key | Value |
/// |---|---|---|
/// | `dns.zones` | [`ZoneId`] | [`Zone`] |
/// | `dns.rrsets` | [`RrSetKey`] (zone, scope, name, type) | [`RrSet`] |
/// | `dns.views` | [`ViewId`] | [`View`] |
/// | `dns.forwarders` | [`ForwardRuleId`] | [`ForwardRule`] |
/// | `dns.acls` | [`AclId`] | [`Acl`] |
/// | `dns.keys.meta` | [`KeyName`] | [`KeyMeta`] |
/// | `dns.lists` | [`BlockListId`] | [`BlockList`] |
/// | `dns.list_versions` | ([`BlockListId`], version) | [`ListVersion`] |
/// | `dns.journal` | ([`ZoneId`], [`ScopeName`], [`Revision`]) | [`JournalEntry`] |
/// | `dns.sign_state` | [`ZoneId`] | [`SignState`] |
pub mod tables {
    use super::{
        Acl, AclId, BlockList, BlockListId, ForwardRule, ForwardRuleId, JournalEntry, KeyMeta,
        KeyName, ListVersion, RrSet, RrSetKey, ScopeName, SignState, View, ViewId, Zone, ZoneId,
    };
    use crate::{id::Revision, names::TableName, table::TableDef};

    /// Zones.
    pub static ZONES: TableDef<ZoneId, Zone> = TableDef::new("dns.zones");
    /// RRsets.
    pub static RRSETS: TableDef<RrSetKey, RrSet> = TableDef::new("dns.rrsets");
    /// Views.
    pub static VIEWS: TableDef<ViewId, View> = TableDef::new("dns.views");
    /// Forwarding rules.
    pub static FORWARDERS: TableDef<ForwardRuleId, ForwardRule> = TableDef::new("dns.forwarders");
    /// Access lists.
    pub static ACLS: TableDef<AclId, Acl> = TableDef::new("dns.acls");
    /// TSIG key metadata.
    pub static KEYS_META: TableDef<KeyName, KeyMeta> = TableDef::new("dns.keys.meta");
    /// Block lists.
    pub static LISTS: TableDef<BlockListId, BlockList> = TableDef::new("dns.lists");
    /// Compiled block list versions.
    pub static LIST_VERSIONS: TableDef<(BlockListId, u64), ListVersion> =
        TableDef::new("dns.list_versions");
    /// The serial history of each zone scope, for IXFR.
    pub static JOURNAL: TableDef<(ZoneId, ScopeName, Revision), JournalEntry> =
        TableDef::new("dns.journal");
    /// The signing state of each signed zone (controllers only).
    pub static SIGN_STATE: TableDef<ZoneId, SignState> = TableDef::new("dns.sign_state");

    /// The tables a node with the `dns` role receives through node sync: every table of the
    /// namespace except `dns.sign_state`, which only the signing service on the controllers
    /// reads (plan section 3.2). Declared now and consumed by no node in Phase 2: the one
    /// node of Phase 2 runs the role in the controller's process and reads the store
    /// directly (plan section 2.10); the node-file feed is Phase 5.
    pub static NODE_TABLES: [TableName; 9] = [
        TableName::from_static("dns.zones"),
        TableName::from_static("dns.rrsets"),
        TableName::from_static("dns.views"),
        TableName::from_static("dns.forwarders"),
        TableName::from_static("dns.acls"),
        TableName::from_static("dns.keys.meta"),
        TableName::from_static("dns.lists"),
        TableName::from_static("dns.list_versions"),
        TableName::from_static("dns.journal"),
    ];

    /// Every table of the namespace.
    pub fn all() -> [&'static TableName; 10] {
        [
            ZONES.name(),
            RRSETS.name(),
            VIEWS.name(),
            FORWARDERS.name(),
            ACLS.name(),
            KEYS_META.name(),
            LISTS.name(),
            LIST_VERSIONS.name(),
            JOURNAL.name(),
            SIGN_STATE.name(),
        ]
    }
}

// ---------------------------------------------------------------------------------------
// Audit actions and events

/// The audit actions of the DNS module. Each change of the DNS configuration writes one in
/// the same batch as the change (IAM-18).
pub mod audit {
    use crate::audit::AuditAction;

    /// A zone was created.
    pub const ZONE_CREATE: AuditAction = AuditAction::from_static("dns.zone.create");
    /// A zone's settings changed.
    pub const ZONE_UPDATE: AuditAction = AuditAction::from_static("dns.zone.update");
    /// A zone was deleted.
    pub const ZONE_DELETE: AuditAction = AuditAction::from_static("dns.zone.delete");
    /// A zone file was exported (MIG-15).
    pub const ZONE_EXPORT: AuditAction = AuditAction::from_static("dns.zone.export");
    /// RRsets changed through the API or the UI (one batch).
    pub const RECORD_CHANGE: AuditAction = AuditAction::from_static("dns.record.change");
    /// RRsets were imported from a zone file.
    pub const RECORD_IMPORT: AuditAction = AuditAction::from_static("dns.record.import");
    /// The DNS actuator of IPAM changed RRsets.
    pub const RECORD_ACTUATE: AuditAction = AuditAction::from_static("dns.record.actuate");
    /// A TSIG key was created or imported.
    pub const KEY_CREATE: AuditAction = AuditAction::from_static("dns.key.create");
    /// A TSIG key was deleted.
    pub const KEY_DELETE: AuditAction = AuditAction::from_static("dns.key.delete");
    /// A DNSSEC key rollover started or moved on.
    pub const KEY_ROLLOVER: AuditAction = AuditAction::from_static("dns.key.rollover");
    /// A dynamic update was applied.
    pub const UPDATE_APPLY: AuditAction = AuditAction::from_static("dns.update.apply");
    /// A dynamic update was refused.
    pub const UPDATE_REFUSE: AuditAction = AuditAction::from_static("dns.update.refuse");
    /// A view was created.
    pub const VIEW_CREATE: AuditAction = AuditAction::from_static("dns.view.create");
    /// A view changed.
    pub const VIEW_UPDATE: AuditAction = AuditAction::from_static("dns.view.update");
    /// A view was deleted.
    pub const VIEW_DELETE: AuditAction = AuditAction::from_static("dns.view.delete");
    /// A forwarding rule was created.
    pub const FORWARDER_CREATE: AuditAction = AuditAction::from_static("dns.forwarder.create");
    /// A forwarding rule changed.
    pub const FORWARDER_UPDATE: AuditAction = AuditAction::from_static("dns.forwarder.update");
    /// A forwarding rule was deleted.
    pub const FORWARDER_DELETE: AuditAction = AuditAction::from_static("dns.forwarder.delete");
    /// An access list was created.
    pub const ACL_CREATE: AuditAction = AuditAction::from_static("dns.acl.create");
    /// An access list changed.
    pub const ACL_UPDATE: AuditAction = AuditAction::from_static("dns.acl.update");
    /// An access list was deleted.
    pub const ACL_DELETE: AuditAction = AuditAction::from_static("dns.acl.delete");
    /// A block list was created.
    pub const LIST_CREATE: AuditAction = AuditAction::from_static("dns.list.create");
    /// A block list changed.
    pub const LIST_UPDATE: AuditAction = AuditAction::from_static("dns.list.update");
    /// A block list was deleted.
    pub const LIST_DELETE: AuditAction = AuditAction::from_static("dns.list.delete");
    /// A new version of a block list was compiled.
    pub const LIST_COMPILE: AuditAction = AuditAction::from_static("dns.list.compile");
    /// A fetch of a block list was started by hand.
    pub const LIST_FETCH: AuditAction = AuditAction::from_static("dns.list.fetch");
    /// The file of an uploaded block list was handed in.
    pub const LIST_UPLOAD: AuditAction = AuditAction::from_static("dns.list.upload");
    /// A zone transfer in was started by hand.
    pub const TRANSFER_TRIGGER: AuditAction = AuditAction::from_static("dns.transfer.trigger");
    /// A node's cache was flushed.
    pub const CACHE_FLUSH: AuditAction = AuditAction::from_static("dns.cache.flush");
    /// A page of a node's query log was read (personal data, P2-Q7).
    pub const LOG_READ: AuditAction = AuditAction::from_static("dns.log.read");
    /// A node's query log was stopped (the kill switch).
    pub const LOG_STOP: AuditAction = AuditAction::from_static("dns.log.stop");
    /// A node's query log was started again.
    pub const LOG_START: AuditAction = AuditAction::from_static("dns.log.start");
    // WP6.1: zone transfers.
    /// A zone was transferred out (AXFR or IXFR) to a client: the client, the key and the
    /// serials.
    pub const ZONE_TRANSFER_OUT: AuditAction = AuditAction::from_static("dns.zone.transfer_out");
    /// A zone transfer in was written (secondary zones, the members of a catalog zone).
    pub const ZONE_TRANSFER_IN: AuditAction = AuditAction::from_static("dns.zone.transfer_in");

    // cache-browse: the listing of a node's cache.
    /// A page of a node's cache was read (the names clients asked, personal data, P2-Q7).
    pub const CACHE_READ: AuditAction = AuditAction::from_static("dns.cache.read");

    // WP6.3: the state changes of the signer and of rollovers.
    /// The signer started to sign a zone (its keys generated or taken up again).
    pub const DNSSEC_ENABLE: AuditAction = AuditAction::from_static("dns.dnssec.enable");
    /// The signer removed the rows it generated (the zone is unsigned or imported).
    pub const DNSSEC_DISABLE: AuditAction = AuditAction::from_static("dns.dnssec.disable");
    /// A DNSSEC key was generated, its private key in the vault.
    pub const DNSSEC_KEY_CREATE: AuditAction = AuditAction::from_static("dns.dnssec.key_create");
    /// A DNSSEC key changed its state (published, active, retired, removed).
    pub const DNSSEC_KEY_STATE: AuditAction = AuditAction::from_static("dns.dnssec.key_state");
    /// A step of a key rollover ran (started, waiting, finished).
    pub const DNSSEC_ROLLOVER: AuditAction = AuditAction::from_static("dns.dnssec.rollover");

    // dns-visibility: the blocking view.
    /// The figures of the blocking view were read from a node's query log (the names and
    /// the clients, personal data like the log).
    pub const BLOCKING_STATS: AuditAction = AuditAction::from_static("dns.blocking.stats");
    /// A node's block lists were paused (for some minutes or until resumed).
    pub const BLOCKING_PAUSE: AuditAction = AuditAction::from_static("dns.blocking.pause");
    /// The pause of a node's block lists was ended.
    pub const BLOCKING_RESUME: AuditAction = AuditAction::from_static("dns.blocking.resume");
    /// A name was added to an allow list from the blocking view.
    pub const BLOCKING_ALLOW: AuditAction = AuditAction::from_static("dns.blocking.allow");

    /// Every action of the module, for the contracts document and its test.
    pub const ALL: [&AuditAction; 44] = [
        &ZONE_CREATE,
        &ZONE_UPDATE,
        &ZONE_DELETE,
        &ZONE_EXPORT,
        &RECORD_CHANGE,
        &RECORD_IMPORT,
        &RECORD_ACTUATE,
        &KEY_CREATE,
        &KEY_DELETE,
        &KEY_ROLLOVER,
        &UPDATE_APPLY,
        &UPDATE_REFUSE,
        &VIEW_CREATE,
        &VIEW_UPDATE,
        &VIEW_DELETE,
        &FORWARDER_CREATE,
        &FORWARDER_UPDATE,
        &FORWARDER_DELETE,
        &ACL_CREATE,
        &ACL_UPDATE,
        &ACL_DELETE,
        &LIST_CREATE,
        &LIST_UPDATE,
        &LIST_DELETE,
        &LIST_COMPILE,
        &LIST_FETCH,
        &LIST_UPLOAD,
        &TRANSFER_TRIGGER,
        &CACHE_FLUSH,
        &LOG_READ,
        &LOG_STOP,
        &LOG_START,
        &ZONE_TRANSFER_OUT,
        &ZONE_TRANSFER_IN,
        // cache-browse: the listing of a node's cache.
        &CACHE_READ,
        &DNSSEC_ENABLE,
        &DNSSEC_DISABLE,
        &DNSSEC_KEY_CREATE,
        &DNSSEC_KEY_STATE,
        &DNSSEC_ROLLOVER,
        // dns-visibility
        &BLOCKING_STATS,
        &BLOCKING_PAUSE,
        &BLOCKING_RESUME,
        &BLOCKING_ALLOW,
    ];
}

/// The `kind` values of events on the [`TOPIC`] topic.
pub mod events {
    /// A zone or its records changed (data: the zone reference).
    pub const ZONE_CHANGED: &str = "dns.zone.changed";
    /// A zone's serial moved (data: the zone reference and the serial).
    pub const ZONE_SERIAL: &str = "dns.zone.serial";
    /// A zone transfer started, ended or failed.
    pub const TRANSFER: &str = "dns.transfer";
    /// A zone was signed, or signing failed.
    pub const SIGNING: &str = "dns.signing";
}

#[cfg(test)]
mod tests;
