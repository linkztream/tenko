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
//!
//! The answers of the service are the types of the API (they derive `ToSchema`); the routes
//! of `tenko-api` add the request wrappers and nothing else.

pub mod body;
pub mod diff;
pub mod service;

use std::{collections::BTreeMap, fmt};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_auth::AuthError;
use tenko_core::{
    Coded, MirrorId, PrefixId,
    error::codes::INVALID_REQUEST,
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
    /// The counts of the latest snapshot: scopes, reservations, leases.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
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
    /// The rows; empty when the two agree.
    pub rows: Vec<DiffRow>,
    /// How many loss entries of the scope are not acknowledged.
    pub losses_open: u32,
}

/// Why the service refused.
#[derive(Debug)]
pub enum MirrorError {
    /// No such mirror (404).
    NotFound(MirrorId),
    /// A mirror or service account of this name exists (409).
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
    /// The account and token of the mirror.
    Auth(AuthError),
    /// The rows of the diff.
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
            Self::Exists(name) => write!(f, "a mirror or an account named {name} exists"),
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
            Self::NoSnapshot(_) => codes::MIRROR_NO_SNAPSHOT,
            Self::ScopeNotFound(..) => codes::MIRROR_SCOPE_NOT_FOUND,
            Self::Request(_) => INVALID_REQUEST,
            Self::SnapshotMoved { .. } => codes::MIRROR_SNAPSHOT_MOVED,
            Self::Conflict(_) => codes::MIRROR_CONFLICT,
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
            | Self::Conflict(_) => 409,
            Self::Settings { .. } | Self::Request(_) => 400,
            Self::Disabled(_) => 403,
            Self::TooLarge { .. } => 413,
            Self::Invalid(invalid) => invalid.http_status(),
            Self::Rate { .. } => 429,
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
            Self::Rate { retry_after } => {
                BTreeMap::from([("retry_after", retry_after.to_string())])
            }
            Self::ScopeNotFound(mirror, scope) => {
                BTreeMap::from([("id", mirror.to_string()), ("scope", scope.to_string())])
            }
            Self::Request(_) => BTreeMap::new(),
            Self::SnapshotMoved { sequence, latest } => BTreeMap::from([
                ("sequence", sequence.to_string()),
                ("latest", latest.to_string()),
            ]),
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

impl From<AuthError> for MirrorError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::Invalid {
                field: "name",
                reason,
            } => Self::Settings {
                field: "name".to_owned(),
                reason: format!("the service account's name: {reason}"),
            },
            other => Self::Auth(other),
        }
    }
}
