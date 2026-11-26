//! Mirrored sources (ADR 0033, `docs/plans/windows-takeover-plan.md` sections 2.1 to 2.5;
//! MIG-01, MIG-08, IAM-10): the push, its bounds and validation, the sequence and the hash,
//! the freshness, the loss report with its acknowledgments, and the diff of a mirrored scope
//! against Tenko's.
//!
//! | Module | What |
//! |---|---|
//! | [`body`] | a push body to a checked [`MirrorSnapshot`](tenko_core::ir::MirrorSnapshot): the bounds before anything is allocated, gzip, the strict parse with the path of the first error |
//! | [`service`] | [`MirrorService`]: the rows, the push, the freshness in memory, the losses, the findings and the metrics |
//! | [`diff`] | the rows of the diff of plan section 2.5 |
//! | [`prepare`] | Tenko's own copy of a mirrored scope, switched off, for a takeover run |
//!
//! The answers of the service are the types of the API (they derive `ToSchema`); the routes
//! of `tenko-api` add the request wrappers and nothing else.

pub mod body;
pub mod diff;
pub mod prepare;
pub mod service;

use std::{collections::BTreeMap, fmt};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_auth::AuthError;
use tenko_core::{
    Coded, MirrorId, PrefixId,
    error::codes::{BODY_TIMEOUT, INVALID_REQUEST},
    ir::{LossEntry, MirrorOrigin, SnapshotInvalid},
    migrate::{LossAck, Mirror, codes},
};
use tenko_store::StoreError;
use utoipa::ToSchema;

pub use service::{Finding, MirrorService};

/// A mirrored source with its freshness (plan section 2.4): the row and what the card shows.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorItem {
    /// The row, with the freshness this controller holds in memory.
    #[serde(flatten)]
    pub mirror: Mirror,
    /// Seconds since the last accepted push; none before the first push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,
    /// Whether the mirror is stale: no push for three intervals.
    pub stale: bool,
    /// When the mirror's token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<tenko_core::Timestamp>,
    /// The client prefixes the mirror's token is accepted from; empty for anywhere.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub source_prefixes: Vec<IpNet>,
    /// The sequence of the stored snapshot, written at `stored_at`: its leases are from that
    /// push, which may be older than the last one (`last_sequence`) by up to ten minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_sequence: Option<u64>,
    /// How many changed configurations can be stored at once now, of `change_reserve`; one
    /// more every ten minutes.
    #[serde(default)]
    pub changes_left: u32,
    /// How many changed configurations a full reserve stores at once (`CHANGE_RESERVE`).
    #[serde(default)]
    pub change_reserve: u32,
    /// Whether this controller holds a changed configuration that is not stored yet.
    #[serde(default)]
    pub change_held: bool,
    /// When the changed configuration this controller holds is stored at the earliest: by
    /// the first push from then on whose configuration still differs. None when it holds
    /// none, and while the node's clock guard holds its clock, which has to be trusted first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_change_due: Option<tenko_core::Timestamp>,
    /// The counts of the stored snapshot: scopes, reservations, leases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<SnapshotCounts>,
    /// The server the latest snapshot names and the adapter's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<MirrorOrigin>,
    /// How many loss entries of the latest snapshot are not acknowledged.
    pub losses_open: u32,
    /// The scopes of the latest snapshot, by network.
    #[serde(default)]
    pub scopes: Vec<MirroredScope>,
    /// The SHA-256 fingerprint of this installation's certificate authority root, which the
    /// exporter pins; set by the API while it serves a certificate of the internal authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

/// A scope of a mirror's latest snapshot, as the Scopes tab lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MirroredScope {
    /// The network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// The source's name of the scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the source serves it.
    pub active: bool,
}

/// What the latest snapshot of a mirror holds, in numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotCounts {
    /// Scopes.
    pub scopes: u32,
    /// Reservations over every scope.
    pub reservations: u32,
    /// Leases.
    pub leases: u32,
    /// Loss entries.
    pub losses: u32,
}

/// `PATCH /migrate/mirrors/{id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MirrorPatch {
    /// A new name; the service account keeps the name it was created with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether pushes are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The expected interval between pushes, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u32>,
    /// The other mirror of a pair (plan section 2.15), set on both rows at once; `null`
    /// takes the pair apart on both. Refused for the mirror itself, a mirror that does not
    /// exist and a mirror already paired with another (`migrate.mirror.partner`).
    #[serde(
        default,
        deserialize_with = "tenko_ipam::command::nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, nullable)]
    pub partner: Option<Option<MirrorId>>,
}

/// The answer of a push: `200 {"sequence", "changed"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotAccepted {
    /// The accepted sequence.
    pub sequence: u64,
    /// Whether the snapshot differs from the stored one (a changed push writes a row and an
    /// audit record; an unchanged one writes nothing).
    pub changed: bool,
}

/// One entry of the loss report with its acknowledgment (`GET /migrate/mirrors/{id}/losses`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorLossItem {
    /// The entry's key, for the acknowledgment.
    pub key: String,
    /// The entry.
    pub entry: LossEntry,
    /// The scope the entry belongs to, when its location names an address of one; an entry
    /// without one belongs to every scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub scope: Option<IpNet>,
    /// The acknowledgment that holds for the entry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<LossAck>,
}

/// The loss report of the latest snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorLosses {
    /// The mirror.
    pub mirror: MirrorId,
    /// The snapshot's sequence.
    pub sequence: u64,
    /// The entries.
    pub entries: Vec<MirrorLossItem>,
}

/// What a row of the diff is about (plan section 2.5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    /// The network as an IPAM prefix.
    Prefix,
    /// A pool range.
    Pool,
    /// An exclusion range.
    Exclusion,
    /// The lease time.
    LeaseTime,
    /// An option at the server, scope or reservation level.
    Option,
    /// A reservation.
    Reservation,
    /// The DDNS settings.
    Ddns,
    /// The MAC filters: whether the scope is restricted to the allow list, and the entries.
    Filter,
    /// A configuration difference between the mirror and its partner (plan section 2.15):
    /// the item names what differs (`pool 192.0.2.100-192.0.2.199`, `scope:6`,
    /// `reservation 192.0.2.10`).
    Partner,
}

/// What the prepare would do about a row.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffAction {
    /// Create it in Tenko.
    Create,
    /// Change Tenko's to the mirror's.
    Update,
    /// Remove it from Tenko's scope.
    Remove,
    /// Attach to the IPAM host that already holds the reservation's MAC address, client
    /// identifier or address.
    Attach,
    /// Nothing: the two agree.
    Keep,
    /// The operator decides: a server option Tenko's server set already holds, or two IPAM
    /// hosts that disagree about a reservation; the prepare does not run while such a row
    /// stands.
    Decide,
}

/// One row of the diff of a mirrored scope against Tenko's scope of the same network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiffRow {
    /// What the row is about.
    pub kind: DiffKind,
    /// The item: a range (`192.0.2.100-192.0.2.199`), an option (`scope:6`), a reservation
    /// (`192.0.2.10`), a setting.
    pub item: String,
    /// The mirror's value, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
    /// Tenko's value, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenko: Option<String>,
    /// The partner mirror's value, as text, for a row of kind `partner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<String>,
    /// What the prepare would do.
    pub action: DiffAction,
    /// Why the operator must decide, for `decide`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The diff of a mirrored scope (`GET /migrate/mirrors/{id}/scopes/{cidr}/diff`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeDiff {
    /// The mirror.
    pub mirror: MirrorId,
    /// The scope.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
    /// The snapshot's sequence.
    pub sequence: u64,
    /// Whether the source's scope is active in the snapshot.
    pub source_active: bool,
    /// Tenko's scope of the network, when it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenko_scope: Option<PrefixId>,
    /// Whether Tenko's scope is enabled.
    pub tenko_enabled: bool,
    /// The partner mirror, for a paired mirror.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<MirrorId>,
    /// The sequence of the partner's snapshot the `partner` rows compare with; none while
    /// the partner holds no snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_sequence: Option<u64>,
    /// The rows; empty when the two agree.
    pub rows: Vec<DiffRow>,
    /// How many loss entries of the scope are not acknowledged.
    pub losses_open: u32,
}

/// The answer of a prepare: Tenko's scope of the network, switched off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ScopePrepared {
    /// The IPAM prefix Tenko's scope is keyed by; a rebuild names a new one.
    pub prefix: PrefixId,
}

/// Why the service refused.
#[derive(Debug)]
pub enum MirrorError {
    /// No such mirror (404).
    NotFound(MirrorId),
    /// The mirror's service account name (`mirror-<id>`) is taken (409).
    Exists(String),
    /// A setting is invalid (400).
    Settings {
        /// The field.
        field: String,
        /// Why.
        reason: String,
    },
    /// The mirror is disabled and refuses pushes (403).
    Disabled(MirrorId),
    /// The sequence is not above the last accepted one (409).
    Sequence {
        /// The pushed sequence.
        sequence: u64,
        /// The last accepted one.
        last: u64,
    },
    /// The body is above a bound (413).
    TooLarge {
        /// The bound in octets.
        limit: usize,
    },
    /// The envelope does not validate (422).
    Invalid(SnapshotInvalid),
    /// A push came faster than the floor (429).
    Rate {
        /// Seconds until the next push is admitted.
        retry_after: u64,
    },
    /// Another read of a stored snapshot held the node's one too long (429).
    Busy {
        /// Seconds after which to try again.
        retry_after: u64,
    },
    /// The mirror holds no snapshot yet (404).
    NoSnapshot(MirrorId),
    /// The snapshot holds no such scope (404).
    ScopeNotFound(MirrorId, IpNet),
    /// The request names something the snapshot does not hold (400).
    Request(String),
    /// The request was made from an older snapshot than the latest (409).
    SnapshotMoved {
        /// The snapshot the request was made from.
        sequence: u64,
        /// The latest snapshot.
        latest: u64,
    },
    /// The mirror's row changed under every attempt to write it (409).
    Conflict(MirrorId),
    /// The push's body did not arrive within the server's deadline for request bodies (408;
    /// the server answers it, the refusal is audited as this).
    BodyTimeout,
    /// The installation holds as many mirrors as it may (409).
    Limit {
        /// The most mirrors.
        max: usize,
    },
    /// The push names another server than the one the mirror is bound to (409). The answer
    /// names the pushed server only; the audit record names both.
    Source {
        /// The mirror.
        id: MirrorId,
        /// The server it is bound to.
        bound: String,
        /// The server the push names.
        server: String,
    },
    /// A pairing is refused (409).
    Partner {
        /// The mirror.
        id: MirrorId,
        /// The partner asked for.
        partner: MirrorId,
        /// Why.
        reason: &'static str,
    },
    /// The account and token of the mirror.
    Auth(AuthError),
    /// A step of a takeover run is refused (409): `migrate.takeover.diff` with the diff row or
    /// the snapshot's field Tenko does not take, or `migrate.takeover.scope_enabled` with the
    /// network of Tenko's scope that is switched on.
    Takeover {
        /// The code.
        code: &'static str,
        /// What the refusal names.
        item: String,
    },
    /// The scope has open loss entries (409 `migrate.takeover.losses`).
    Losses {
        /// The scope.
        scope: IpNet,
        /// How many.
        count: u32,
    },
    /// Someone else changed the run's switched-off scope (409, a code of [`Self::Takeover`]);
    /// `item` names the kind of object.
    Touched {
        /// The code.
        code: &'static str,
        /// The kind of object.
        item: &'static str,
    },
    /// The rows of the diff, and the IPAM and DHCP writes of the prepare.
    Dhcp(tenko_dhcp::config::ConfigError),
    /// The store.
    Store(StoreError),
}

impl MirrorError {
    pub(crate) fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid(SnapshotInvalid {
            path: path.into(),
            reason: std::borrow::Cow::Owned(reason.into()),
        })
    }
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "no mirror {id}"),
            Self::Exists(name) => write!(f, "an account named {name} exists"),
            Self::Settings { field, reason } => write!(f, "invalid `{field}`: {reason}"),
            Self::Disabled(id) => write!(f, "the mirror {id} is disabled"),
            Self::Sequence { sequence, last } => write!(
                f,
                "the sequence {sequence} is not above the last accepted {last}"
            ),
            Self::TooLarge { limit } => write!(f, "the body is above {limit} octets"),
            Self::Invalid(invalid) => invalid.fmt(f),
            Self::Rate { retry_after } => write!(
                f,
                "a push came faster than the floor; retry in {retry_after} s"
            ),
            Self::Busy { retry_after } => write!(
                f,
                "another read of a stored snapshot runs on this node; retry in {retry_after} s"
            ),
            Self::NoSnapshot(id) => write!(f, "the mirror {id} holds no snapshot yet"),
            Self::ScopeNotFound(id, scope) => {
                write!(f, "the snapshot of mirror {id} holds no scope {scope}")
            }
            Self::Request(detail) => f.write_str(detail),
            Self::SnapshotMoved { sequence, latest } => write!(
                f,
                "the request was made from the snapshot {sequence}, the latest is {latest}"
            ),
            Self::Conflict(id) => {
                write!(f, "the mirror {id} changed under every attempt to write it")
            }
            Self::Limit { max } => {
                write!(f, "the installation holds {max} mirrors, the most it may")
            }
            Self::BodyTimeout => f.write_str("the body did not arrive in time"),
            Self::Source { id, server, .. } => write!(
                f,
                "the mirror {id} is bound to another server than {server}; replace the token to bind it anew"
            ),
            Self::Partner {
                id,
                partner,
                reason,
            } => write!(
                f,
                "the mirror {id} cannot be paired with {partner}: {reason}"
            ),
            Self::Takeover { code, item } if *code == codes::TAKEOVER_SCOPE_ENABLED => write!(
                f,
                "Tenko's scope {item} is switched on, so it is neither rebuilt nor removed: switch it off in Tenko first"
            ),
            Self::Takeover { item, .. } => write!(
                f,
                "the mirrored scope holds {item}, which Tenko does not prepare as it stands: change it on the Windows server, then run the script again"
            ),
            Self::Losses { scope, count } => write!(
                f,
                "the scope {scope} has {count} open losses: acknowledge them on the Losses tab of the mirrored source in Tenko, then run the script again"
            ),
            Self::Touched { item, .. } => write!(
                f,
                "someone else changed Tenko's switched-off scope ({item}), so the run's session neither rebuilds nor removes it: an administrator's session removes it with DELETE /api/v1/migrate/runs/<run>/scopes/<network>"
            ),
            Self::Auth(error) => error.fmt(f),
            Self::Dhcp(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MirrorError {}

impl Coded for MirrorError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => codes::MIRROR_NOT_FOUND,
            Self::Exists(_) => codes::MIRROR_EXISTS,
            Self::Settings { .. } => codes::MIRROR_INVALID_SETTINGS,
            Self::Disabled(_) => codes::MIRROR_DISABLED,
            Self::Sequence { .. } => codes::MIRROR_SEQUENCE,
            Self::TooLarge { .. } => codes::MIRROR_TOO_LARGE,
            Self::Invalid(invalid) => invalid.code(),
            Self::Rate { .. } => codes::MIRROR_RATE,
            Self::Busy { .. } => codes::MIRROR_BUSY,
            Self::NoSnapshot(_) => codes::MIRROR_NO_SNAPSHOT,
            Self::ScopeNotFound(..) => codes::MIRROR_SCOPE_NOT_FOUND,
            Self::Request(_) => INVALID_REQUEST,
            Self::SnapshotMoved { .. } => codes::MIRROR_SNAPSHOT_MOVED,
            Self::Conflict(_) => codes::MIRROR_CONFLICT,
            Self::Limit { .. } => codes::MIRROR_LIMIT,
            Self::BodyTimeout => BODY_TIMEOUT,
            Self::Source { .. } => codes::MIRROR_SOURCE,
            Self::Partner { .. } => codes::MIRROR_PARTNER,
            Self::Takeover { code, .. } | Self::Touched { code, .. } => code,
            Self::Losses { .. } => codes::TAKEOVER_LOSSES,
            Self::Auth(error) => error.code(),
            Self::Dhcp(error) => error.code(),
            Self::Store(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::NotFound(_) | Self::NoSnapshot(_) | Self::ScopeNotFound(..) => 404,
            Self::Exists(_)
            | Self::Sequence { .. }
            | Self::SnapshotMoved { .. }
            | Self::Conflict(_)
            | Self::Limit { .. }
            | Self::Source { .. }
            | Self::Partner { .. }
            | Self::Takeover { .. }
            | Self::Losses { .. }
            | Self::Touched { .. } => 409,
            Self::BodyTimeout => 408,
            Self::Settings { .. } | Self::Request(_) => 400,
            Self::Disabled(_) => 403,
            Self::TooLarge { .. } => 413,
            Self::Invalid(invalid) => invalid.http_status(),
            Self::Rate { .. } | Self::Busy { .. } => 429,
            Self::Auth(error) => error.http_status(),
            Self::Dhcp(error) => error.http_status(),
            Self::Store(error) => error.http_status(),
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        let id = |id: &MirrorId| BTreeMap::from([("id", id.to_string())]);
        match self {
            Self::NotFound(mirror)
            | Self::Disabled(mirror)
            | Self::NoSnapshot(mirror)
            | Self::Conflict(mirror) => id(mirror),
            Self::Exists(name) => BTreeMap::from([("name", name.clone())]),
            Self::Settings { field, reason } => {
                BTreeMap::from([("field", field.clone()), ("reason", reason.clone())])
            }
            Self::Sequence { sequence, last } => BTreeMap::from([
                ("sequence", sequence.to_string()),
                ("last", last.to_string()),
            ]),
            Self::TooLarge { limit } => BTreeMap::from([("limit", limit.to_string())]),
            Self::Invalid(invalid) => invalid.params(),
            Self::Rate { retry_after } | Self::Busy { retry_after } => {
                BTreeMap::from([("retry_after", retry_after.to_string())])
            }
            Self::ScopeNotFound(mirror, scope) => {
                BTreeMap::from([("id", mirror.to_string()), ("scope", scope.to_string())])
            }
            Self::Request(_) | Self::BodyTimeout => BTreeMap::new(),
            Self::SnapshotMoved { sequence, latest } => BTreeMap::from([
                ("sequence", sequence.to_string()),
                ("latest", latest.to_string()),
            ]),
            Self::Limit { max } => BTreeMap::from([("max", max.to_string())]),
            Self::Source { id, server, .. } => {
                BTreeMap::from([("id", id.to_string()), ("server", server.clone())])
            }
            Self::Partner {
                id,
                partner,
                reason,
            } => BTreeMap::from([
                ("id", id.to_string()),
                ("partner", partner.to_string()),
                ("reason", (*reason).to_owned()),
            ]),
            Self::Takeover { item, .. } => BTreeMap::from([("item", item.clone())]),
            Self::Touched { item, .. } => BTreeMap::from([("item", (*item).to_owned())]),
            Self::Losses { scope, count } => {
                BTreeMap::from([("scope", scope.to_string()), ("count", count.to_string())])
            }
            Self::Auth(error) => error.params(),
            Self::Dhcp(error) => error.params(),
            Self::Store(error) => error.params(),
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::Invalid(invalid) => invalid.title(),
            Self::Auth(error) => error.title(),
            _ => "Mirrored source",
        }
    }

    // The IPAM and DHCP errors carry their parameters in their own form.
    fn to_coded_error(&self) -> tenko_core::CodedError {
        match self {
            Self::Dhcp(error) => error.to_coded_error(),
            _ => (self.params().into_iter()).fold(
                tenko_core::CodedError::new(self.code(), self.http_status(), self.to_string())
                    .with_title(self.title()),
                |error, (key, value)| error.with_param(key, value),
            ),
        }
    }
}

impl From<StoreError> for MirrorError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<tenko_core::codec::CodecError> for MirrorError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::Store(error.into())
    }
}

impl From<tenko_dhcp::config::ConfigError> for MirrorError {
    fn from(error: tenko_dhcp::config::ConfigError) -> Self {
        Self::Dhcp(error)
    }
}

impl From<tenko_ipam::IpamError> for MirrorError {
    fn from(error: tenko_ipam::IpamError) -> Self {
        Self::Dhcp(tenko_dhcp::config::ConfigError::from_coded(
            error.to_coded_error(),
        ))
    }
}

impl From<AuthError> for MirrorError {
    fn from(error: AuthError) -> Self {
        match error {
            // A field of the token's terms (the source prefixes) is a setting of the mirror.
            AuthError::Invalid { field, reason } => Self::Settings {
                field: field.to_owned(),
                reason: reason.to_string(),
            },
            other => Self::Auth(other),
        }
    }
}
