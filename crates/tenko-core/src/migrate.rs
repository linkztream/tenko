//! Mirrored sources and takeovers (`docs/plans/windows-takeover-plan.md` sections 2 and 3,
//! ADR 0033 and ADR 0034; MIG-01, MIG-04, MIG-08): the rows of the `migrate` namespace, its
//! tables, error codes, audit actions, metric families, findings and authorization scopes.
//!
//! A **mirrored source** ([`Mirror`]) is a source that pushes its content to Tenko instead of
//! being polled: an exporter on the source's host sends an
//! [`ir::MirrorSnapshot`](crate::ir::MirrorSnapshot) every interval with a token whose only
//! right is that push (`TokenScope::Mirror` in `tenko-auth`, wire form `mirror:<id>`). The
//! latest accepted envelope is one row of `migrate.snapshots` ([`Snapshot`]); a push whose
//! hash equals the stored one writes nothing. A **takeover** ([`Takeover`]) records what the
//! takeover job of one scope did, with the before-images it needs to roll back. A **loss
//! acknowledgment** ([`LossAck`]) says that an administrator saw one entry of the loss
//! report; it holds while the entry recurs unchanged.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `migrate.mirrors` | [`MirrorId`] | [`Mirror`] |
//! | `migrate.snapshots` | [`MirrorId`] | [`Snapshot`] |
//! | `migrate.takeovers` | [`TakeoverId`] | [`Takeover`] |
//! | `migrate.loss_acks` | ([`MirrorId`], the entry's key) | [`LossAck`] |
//!
//! These are contracts (WP14.0). WP14.1 builds the push, the freshness, the losses and the
//! diff on them; WP14.2 the prepare, the takeover and the flip.

use std::fmt;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub use crate::id::{MirrorId, TakeoverId};
pub use crate::ir::mirror::{
    MAX_BODY_BYTES, MAX_INFLATED_BYTES, MAX_LEASES, MAX_LOSSES, MAX_RESERVATIONS, MAX_SCOPES,
};
use crate::{
    dns::{DnsName, RrSet, RrSetKey},
    id::{ApiTokenId, JobId, UserId},
    ipam::Stamp,
    ir::{MirrorSnapshot, mirror::SourceKindLabel},
    object::{ObjectKind, ObjectRef},
    serde_util::HexBytes,
    timestamp::Timestamp,
};

/// The interval an exporter is expected to push at, in seconds (plan section 2.1).
pub const DEFAULT_INTERVAL_SECS: u32 = 60;

/// The shortest and longest expected intervals an administrator may set.
pub const MIN_INTERVAL_SECS: u32 = 10;
/// See [`MIN_INTERVAL_SECS`].
pub const MAX_INTERVAL_SECS: u32 = 3_600;

/// The floor between two pushes of one mirror, in seconds: a faster push is refused with
/// 429 `migrate.mirror.rate`.
pub const MIN_PUSH_INTERVAL_SECS: u32 = 10;

/// A mirror is stale after this many missed intervals (section 2.4).
pub const STALE_AFTER_INTERVALS: u32 = 3;

/// A takeover needs a push younger than this, in seconds (section 2.7, step 1).
pub const FRESH_SECS: u32 = 120;

/// How long the takeover waits for a push that shows the source's scope inactive, in
/// seconds (section 2.7, step 2).
pub const WAIT_SECS: u32 = 600;

/// The takeover writes lease rows in batches of this size (section 2.7, step 4).
pub const LEASE_BATCH: usize = 1_000;

/// The finding `migrate.mirror.token_expiring` is raised this many days ahead (WT-Q11).
pub const TOKEN_EXPIRING_DAYS: u32 = 14;

/// The mirror row is written with the freshness at most this often, in seconds; between
/// writes the freshness lives in the leader's memory (section 2.4).
pub const FRESHNESS_WRITE_SECS: u32 = 600;

/// The length of the name of a mirror.
pub const MAX_NAME_LEN: usize = 64;

/// The SSE topic of the module.
pub const TOPIC: &str = "migrate";

/// The kinds of the module as objects of authorization and audit.
pub const OBJECT_KINDS: [ObjectKind; 2] = [ObjectKind::Mirror, ObjectKind::Takeover];

/// A mirrored source (section 2.1): one row per source, with the freshness the leader
/// writes at most every [`FRESHNESS_WRITE_SECS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Mirror {
    /// Identifier.
    pub id: MirrorId,
    /// The name an administrator gave it, unique among mirrors.
    pub name: String,
    /// The kind of source (`windows-dhcp`).
    pub kind: SourceKindLabel,
    /// Whether pushes are accepted; a disabled mirror refuses them with 403 and raises no
    /// staleness finding.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The scoped token whose only special scope is `mirror:<id>` (section 2.1, rule 2).
    pub token: ApiTokenId,
    /// The service account `mirror-<name>` that owns the token; it holds no grants.
    pub account: UserId,
    /// The expected interval between pushes, in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u32,
    /// The sequence of the last accepted push; a push must carry a higher one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    /// The SHA-256 of the last accepted envelope in canonical CBOR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hash: Option<HexBytes>,
    /// When the last push was accepted, changed or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push: Option<Timestamp>,
    /// When the snapshot last changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_change: Option<Timestamp>,
    /// Creation.
    pub created: Stamp,
    /// Last change of the row.
    pub updated: Stamp,
}

const fn yes() -> bool {
    true
}

const fn default_interval() -> u32 {
    DEFAULT_INTERVAL_SECS
}

impl Mirror {
    /// Checks the row: a name of 1 to [`MAX_NAME_LEN`] printable characters and an interval
    /// within [`MIN_INTERVAL_SECS`] and [`MAX_INTERVAL_SECS`].
    ///
    /// # Errors
    ///
    /// [`MigrateError::Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), MigrateError> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
            return Err(MigrateError::invalid("name", "1 to 64 characters"));
        }
        if name != self.name || name.chars().any(char::is_control) {
            return Err(MigrateError::invalid(
                "name",
                "no leading or trailing space and no control character",
            ));
        }
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&self.interval_secs) {
            return Err(MigrateError::invalid(
                "interval_secs",
                "10 to 3,600 seconds",
            ));
        }
        Ok(())
    }

    /// The name of the service account that owns the mirror's token.
    pub fn account_name(name: &str) -> String {
        format!("mirror-{name}")
    }

    /// After how many seconds without a push the mirror is stale (section 2.4).
    pub const fn stale_after_secs(&self) -> u64 {
        (self.interval_secs as u64) * (STALE_AFTER_INTERVALS as u64)
    }

    /// Whether the mirror is stale at `now`: enabled, pushed at least once, and the last
    /// push older than [`Mirror::stale_after_secs`]. A mirror that never pushed is not
    /// stale (it is new); the card shows that it waits.
    pub fn is_stale(&self, now: Timestamp) -> bool {
        self.enabled
            && self
                .last_push
                .is_some_and(|last| now.saturating_since(last).as_secs() > self.stale_after_secs())
    }

    /// Whether a push at `now` is fresh enough for a takeover (section 2.7, step 1).
    pub fn is_fresh(&self, now: Timestamp) -> bool {
        self.last_push
            .is_some_and(|last| now.saturating_since(last).as_secs() <= u64::from(FRESH_SECS))
    }
}

/// The latest accepted envelope of a mirror (`migrate.snapshots`, section 2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Snapshot {
    /// The mirror.
    pub mirror: MirrorId,
    /// The envelope's sequence.
    pub sequence: u64,
    /// The SHA-256 of the envelope in canonical CBOR, the value the next push is compared
    /// with.
    pub hash: HexBytes,
    /// When the push was accepted, by the node's clock.
    pub received: Timestamp,
    /// The envelope as pushed.
    pub envelope: MirrorSnapshot,
}

/// Where a takeover ended (section 2.7, step 6, and section 2.10).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TakeoverState {
    /// The job completed: the scope is enabled and serves.
    Done,
    /// The job failed in steps 3 to 5 and the rollback restored the state before it.
    RolledBack,
    /// The reverse action ran after a completed takeover: the scope is disabled, its leases
    /// and records kept (`dhcp.scope.revert`).
    Reverted,
}

impl TakeoverState {
    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::RolledBack => "rolled_back",
            Self::Reverted => "reverted",
        }
    }
}

/// What a takeover counted (section 2.7, step 6; the audit record carries the same).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TakeoverCounts {
    /// Mirrored leases that became `dhcp.leases` rows.
    #[serde(default)]
    pub leases_adopted: u32,
    /// Mirrored leases whose identity was guessed (section 2.8).
    #[serde(default)]
    pub leases_guessed: u32,
    /// Mirrored leases skipped, each listed in [`Takeover::skipped`].
    #[serde(default)]
    pub leases_skipped: u32,
    /// Declined leases that became `abandoned` rows.
    #[serde(default)]
    pub leases_declined: u32,
    /// Forward names (A and DHCID) adopted as `dhcp` records.
    #[serde(default)]
    pub names_adopted: u32,
    /// PTR records adopted as `dhcp` records.
    #[serde(default)]
    pub ptrs_adopted: u32,
    /// Names with a DHCID that no mirrored lease or reservation explains, left frozen.
    #[serde(default)]
    pub names_frozen: u32,
    /// Names skipped for another reason, each listed in [`Takeover::skipped`].
    #[serde(default)]
    pub names_skipped: u32,
}

/// One item a takeover skipped, with the reason (section 2.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SkippedItem {
    /// The item: an address (`192.0.2.50`) or a name (`laptop.corp.example.test`).
    pub item: String,
    /// The stable reason code, one of [`codes::SKIP_CODES`].
    pub code: String,
}

/// The before-image of one RRset a takeover changed: the key and the RRset as it was, none
/// when the takeover created it (section 2.7, step 6). The rollback restores these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RrSetImage {
    /// The RRset.
    pub key: RrSetKey,
    /// The RRset before the change; none when there was none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<RrSet>,
}

/// The record of a takeover (`migrate.takeovers`, section 2.7, step 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Takeover {
    /// Identifier.
    pub id: TakeoverId,
    /// The mirror the scope was taken over from.
    pub mirror: MirrorId,
    /// The scope, by network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub scope: IpNet,
    /// The sequence of the snapshot the takeover used: the push that showed the source's
    /// scope inactive.
    pub sequence: u64,
    /// Where it ended.
    pub state: TakeoverState,
    /// The counts.
    #[serde(default)]
    pub counts: TakeoverCounts,
    /// The addresses adopted as lease rows.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub adopted_leases: Vec<std::net::IpAddr>,
    /// The forward names adopted as `dhcp` records.
    #[serde(default)]
    pub adopted_names: Vec<DnsName>,
    /// The names left frozen, for the `release` action.
    #[serde(default)]
    pub frozen_names: Vec<DnsName>,
    /// What was skipped, with the reasons.
    #[serde(default)]
    pub skipped: Vec<SkippedItem>,
    /// The before-images of every RRset the takeover changed.
    #[serde(default)]
    pub before: Vec<RrSetImage>,
    /// The job that ran it.
    pub job: JobId,
    /// When the state was reached.
    pub at: Timestamp,
    /// Who started the job.
    pub by: UserId,
}

/// An acknowledged loss entry (`migrate.loss_acks`, section 2.3): the entry's key within the
/// mirror and the hash of the entry when it was acknowledged. The acknowledgment holds while
/// the entry recurs with the same hash and lapses when the entry changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LossAck {
    /// The mirror.
    pub mirror: MirrorId,
    /// The entry's key: its location and code (`LossEntry::key`).
    pub key: String,
    /// The SHA-256 of the entry in canonical CBOR when it was acknowledged.
    pub entry_hash: HexBytes,
    /// Who acknowledged it.
    pub by: UserId,
    /// When.
    pub at: Timestamp,
}

/// A mirror as an object of authorization and audit.
pub const fn mirror_object(id: MirrorId) -> ObjectRef {
    ObjectRef::new(ObjectKind::Mirror, id.0)
}

/// A takeover as an object of authorization and audit.
pub const fn takeover_object(id: TakeoverId) -> ObjectRef {
    ObjectRef::new(ObjectKind::Takeover, id.0)
}

// ---------------------------------------------------------------------------------------
// Authorization

/// The authorization scopes of the module (plan section 3.2): administrators manage mirrors
/// and run the scope actions, operators read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub enum MigrateScope {
    /// Read mirrors, snapshots, losses, diffs and takeovers.
    #[serde(rename = "migrate.read")]
    Read,
    /// Create, change and delete mirrors, acknowledge losses, run the prepare, the takeover
    /// and the revert.
    #[serde(rename = "migrate.write")]
    Write,
}

impl MigrateScope {
    /// Every scope.
    pub const ALL: [MigrateScope; 2] = [MigrateScope::Read, MigrateScope::Write];

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            MigrateScope::Read => "migrate.read",
            MigrateScope::Write => "migrate.write",
        }
    }

    /// The scope an action on a kind needs; `None` for a kind outside the module and for
    /// approvals, reveals and administration (the token of a mirror is minted under
    /// `Action::Administer`, which no scope grants).
    pub const fn required(action: crate::Action, kind: ObjectKind) -> Option<MigrateScope> {
        use crate::Action;
        match kind {
            ObjectKind::Mirror | ObjectKind::Takeover => match action {
                Action::Read => Some(MigrateScope::Read),
                Action::Create | Action::Update | Action::Delete | Action::Execute => {
                    Some(MigrateScope::Write)
                }
                Action::Approve | Action::Reveal | Action::Administer => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for MigrateScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------------------
// Errors

/// Stable error codes of the `migrate` namespace (API-08, plan section 3.2). Stable once
/// merged.
pub mod codes {
    /// No such mirror (404). Params: `id`.
    pub const MIRROR_NOT_FOUND: &str = "migrate.mirror.not_found";
    /// A mirror of this name exists (409). Params: `name`.
    pub const MIRROR_EXISTS: &str = "migrate.mirror.exists";
    /// A mirror's settings are invalid (400). Params: `field`, `reason`.
    pub const MIRROR_INVALID_SETTINGS: &str = "migrate.mirror.invalid_settings";
    /// The push's sequence is not above the last accepted one: a replay (409). Params:
    /// `sequence`, `last`.
    pub const MIRROR_SEQUENCE: &str = "migrate.mirror.sequence";
    /// The push body is above the bound (413). Params: `limit`.
    pub const MIRROR_TOO_LARGE: &str = "migrate.mirror.too_large";
    /// The envelope does not validate (422). Params: `path`, `reason`.
    pub const MIRROR_INVALID: &str = "migrate.mirror.invalid";
    /// A push came faster than the floor (429). Params: `retry_after`.
    pub const MIRROR_RATE: &str = "migrate.mirror.rate";
    /// The mirror is stale: no push for three intervals (409 on an action that needs it;
    /// also the finding). Params: `id`, `age`.
    pub const MIRROR_STALE: &str = "migrate.mirror.stale";
    /// The source's scope is active again while Tenko's scope serves (409; also the
    /// finding). Params: `id`, `scope`.
    pub const MIRROR_SCOPE_ACTIVE: &str = "migrate.mirror.scope_active";
    /// The mirror's token expires within fourteen days (the finding). Params: `id`,
    /// `expires_at`.
    pub const MIRROR_TOKEN_EXPIRING: &str = "migrate.mirror.token_expiring";
    /// The mirror is disabled and refuses pushes (403). Params: `id`.
    pub const MIRROR_DISABLED: &str = "migrate.mirror.disabled";
    /// The mirror holds no snapshot yet (404). Params: `id`.
    pub const MIRROR_NO_SNAPSHOT: &str = "migrate.mirror.no_snapshot";
    /// The snapshot holds no such scope (404). Params: `id`, `scope`.
    pub const MIRROR_SCOPE_NOT_FOUND: &str = "migrate.mirror.scope_not_found";
    /// No such takeover (404). Params: `id`.
    pub const TAKEOVER_NOT_FOUND: &str = "migrate.takeover.not_found";
    /// The mirror's last push is older than the freshness bound (409). Params: `id`, `age`.
    pub const TAKEOVER_NOT_FRESH: &str = "migrate.takeover.not_fresh";
    /// The source's scope is still active in the latest push (409). Params: `scope`.
    pub const TAKEOVER_SOURCE_ACTIVE: &str = "migrate.takeover.source_active";
    /// The prepare's diff is not empty for pools, exclusions or reservations (409). Params:
    /// `scope`, `rows`.
    pub const TAKEOVER_DIFF: &str = "migrate.takeover.diff";
    /// A zone the takeover needs is missing, not a primary zone or takes no DHCP updates
    /// (409). Params: `zone`, `reason`.
    pub const TAKEOVER_ZONE: &str = "migrate.takeover.zone";
    /// The scope has unacknowledged loss entries (409). Params: `scope`, `count`.
    pub const TAKEOVER_LOSSES: &str = "migrate.takeover.losses";
    /// No push showed the source's scope inactive within the wait (409). Params: `scope`,
    /// `waited`.
    pub const TAKEOVER_WAIT_TIMEOUT: &str = "migrate.takeover.wait_timeout";
    /// Tenko's scope is enabled, so a prepare or a takeover cannot run (409). Params:
    /// `scope`.
    pub const TAKEOVER_SCOPE_ENABLED: &str = "migrate.takeover.scope_enabled";
    /// A takeover or a prepare of the scope runs already (409). Params: `scope`, `job`.
    pub const TAKEOVER_RUNNING: &str = "migrate.takeover.running";

    /// Every code of the module, for the contracts document and its test.
    pub const ALL: [&str; 22] = [
        MIRROR_NOT_FOUND,
        MIRROR_EXISTS,
        MIRROR_INVALID_SETTINGS,
        MIRROR_SEQUENCE,
        MIRROR_TOO_LARGE,
        MIRROR_INVALID,
        MIRROR_RATE,
        MIRROR_STALE,
        MIRROR_SCOPE_ACTIVE,
        MIRROR_TOKEN_EXPIRING,
        MIRROR_DISABLED,
        MIRROR_NO_SNAPSHOT,
        MIRROR_SCOPE_NOT_FOUND,
        TAKEOVER_NOT_FOUND,
        TAKEOVER_NOT_FRESH,
        TAKEOVER_SOURCE_ACTIVE,
        TAKEOVER_DIFF,
        TAKEOVER_ZONE,
        TAKEOVER_LOSSES,
        TAKEOVER_WAIT_TIMEOUT,
        TAKEOVER_SCOPE_ENABLED,
        TAKEOVER_RUNNING,
    ];

    /// The reasons a takeover skips an item (plan section 2.8), the `code` of a
    /// [`SkippedItem`](super::SkippedItem).
    pub mod skip {
        /// The lease's address is outside the Tenko pool and not a reservation.
        pub const OUTSIDE_POOL: &str = "migrate.skip.outside_pool";
        /// The address is reserved for another client in Tenko.
        pub const RESERVED_OTHER: &str = "migrate.skip.reserved_other";
        /// Tenko holds an active row of another client at the address.
        pub const HELD_OTHER: &str = "migrate.skip.held_other";
        /// The name's RRsets have an origin the takeover never adopts (`manual`, `ipam`,
        /// `ad`, `dnssec`).
        pub const ORIGIN: &str = "migrate.skip.origin";
        /// The name holds a CNAME.
        pub const CNAME: &str = "migrate.skip.cname";
        /// The A RRset holds other addresses than the lease's.
        pub const OTHER_ADDRESSES: &str = "migrate.skip.other_addresses";
        /// The name holds no DHCID RRset.
        pub const NO_DHCID: &str = "migrate.skip.no_dhcid";
        /// The name is outside every zone Tenko serves.
        pub const FOREIGN_NAME: &str = "migrate.skip.foreign_name";
        /// The name is not a valid host name label (WT-Q10).
        pub const INVALID_NAME: &str = "migrate.skip.invalid_name";
    }

    /// Every skip reason.
    pub const SKIP_CODES: [&str; 9] = [
        skip::OUTSIDE_POOL,
        skip::RESERVED_OTHER,
        skip::HELD_OTHER,
        skip::ORIGIN,
        skip::CNAME,
        skip::OTHER_ADDRESSES,
        skip::NO_DHCID,
        skip::FOREIGN_NAME,
        skip::INVALID_NAME,
    ];
}

/// The codes of the loss entries a mirrored source writes (plan sections 2.2 and 2.9; the
/// `code` of a [`LossEntry`](crate::ir::LossEntry)). The exporter writes one entry per item
/// it does not carry, with the cmdlet as the location's `sheet` and the object's key as its
/// `column`; the prepare writes the last two for what it derives no record from.
pub mod losses {
    /// A policy (WT-Q2).
    pub const POLICY: &str = "migrate.loss.policy";
    /// A MAC filter entry (WT-Q2).
    pub const FILTER: &str = "migrate.loss.filter";
    /// A superscope (WT-Q2).
    pub const SUPERSCOPE: &str = "migrate.loss.superscope";
    /// A failover relationship.
    pub const FAILOVER: &str = "migrate.loss.failover";
    /// A scope with an offer delay, which Tenko does not have.
    pub const SCOPE_DELAY: &str = "migrate.loss.scope_delay";
    /// A scope that serves BOOTP only.
    pub const BOOTP_ONLY: &str = "migrate.loss.bootp_only";
    /// A lease in a state the mirror does not carry.
    pub const LEASE_STATE: &str = "migrate.loss.lease_state";
    /// A reservation whose name is not a host name: kept as the IPAM host's name, no record
    /// derived (WT-Q10; written by the prepare).
    pub const RESERVATION_NAME: &str = "migrate.loss.reservation_name";
    /// A reservation whose fully qualified name is outside every zone Tenko serves: kept as
    /// the host's name, no record derived (section 2.9; written by the prepare).
    pub const FOREIGN_NAME: &str = "migrate.loss.foreign_name";

    /// Every loss code.
    pub const ALL: [&str; 9] = [
        POLICY,
        FILTER,
        SUPERSCOPE,
        FAILOVER,
        SCOPE_DELAY,
        BOOTP_ONLY,
        LEASE_STATE,
        RESERVATION_NAME,
        FOREIGN_NAME,
    ];
}

/// The errors of the module's rows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrateError {
    /// A row's settings are invalid.
    #[error("invalid `{field}`: {reason}")]
    Invalid {
        /// The field.
        field: String,
        /// Why.
        reason: String,
    },
}

impl MigrateError {
    /// An invalid field.
    pub fn invalid(field: &str, reason: &str) -> Self {
        Self::Invalid {
            field: field.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl crate::Coded for MigrateError {
    fn code(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => codes::MIRROR_INVALID_SETTINGS,
        }
    }

    fn http_status(&self) -> u16 {
        400
    }

    fn params(&self) -> std::collections::BTreeMap<&'static str, String> {
        match self {
            Self::Invalid { field, reason } => std::collections::BTreeMap::from([
                ("field", field.clone()),
                ("reason", reason.clone()),
            ]),
        }
    }

    fn field_errors(&self) -> Vec<crate::FieldError> {
        match self {
            Self::Invalid { field, .. } => {
                vec![crate::FieldError::new(field.clone(), self.code())]
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Audit

/// The audit actions of the module (plan section 2.12).
pub mod audit {
    use crate::audit::AuditAction;

    /// A mirror was created (administrator, interactive session).
    pub const MIRROR_CREATE: AuditAction = AuditAction::from_static("migrate.mirror.create");
    /// A mirror changed.
    pub const MIRROR_UPDATE: AuditAction = AuditAction::from_static("migrate.mirror.update");
    /// A mirror was deleted, with its service account and token.
    pub const MIRROR_DELETE: AuditAction = AuditAction::from_static("migrate.mirror.delete");
    /// The mirror's token was replaced; the old one stopped at once.
    pub const MIRROR_TOKEN: AuditAction = AuditAction::from_static("migrate.mirror.token");
    /// A push changed the snapshot: the sequence, the counts, the hash, the losses.
    pub const MIRROR_PUSH: AuditAction = AuditAction::from_static("migrate.mirror.push");
    /// A push was refused: the code and the client address, at most once a minute per
    /// mirror.
    pub const MIRROR_REFUSE: AuditAction = AuditAction::from_static("migrate.mirror.refuse");
    /// Loss entries were acknowledged.
    pub const MIRROR_LOSSES_ACK: AuditAction =
        AuditAction::from_static("migrate.mirror.losses_ack");

    /// Every action of the module, for the contracts document and its test. The scope
    /// actions (`dhcp.scope.prepare`, `dhcp.scope.takeover`, `dhcp.scope.revert`) are in
    /// [`crate::dhcp::audit`] and the zone actions (`dns.zone.flip`, `dns.zone.release`) in
    /// [`crate::dns::audit`], in the namespaces of what they change.
    pub const ALL: [&AuditAction; 7] = [
        &MIRROR_CREATE,
        &MIRROR_UPDATE,
        &MIRROR_DELETE,
        &MIRROR_TOKEN,
        &MIRROR_PUSH,
        &MIRROR_REFUSE,
        &MIRROR_LOSSES_ACK,
    ];
}

// ---------------------------------------------------------------------------------------
// Metrics and findings

/// The metric families of the module (plan section 2.12, OPS-21), declared once so that
/// the push route and the freshness service register the same names. Counter names carry
/// no `_total`: the encoder adds it.
pub mod metrics {
    use crate::metrics::Desc;

    /// Pushes by mirror and outcome (`changed`, `unchanged`, `refused`).
    pub const PUSHES: Desc = Desc::counter(
        "tenko_migrate_mirror_pushes",
        "Pushes of mirrored sources by outcome",
    )
    .labels(&["mirror", "outcome"]);

    /// Seconds since the last accepted push of a mirror (a gauge the freshness service
    /// writes on a timer).
    pub const AGE: Desc = Desc::gauge(
        "tenko_migrate_mirror_age_seconds",
        "Seconds since the last accepted push of a mirrored source",
    )
    .labels(&["mirror"]);

    /// The outcomes of [`PUSHES`], in label order.
    pub const PUSH_OUTCOMES: [&str; 3] = ["changed", "unchanged", "refused"];
}

/// The names of the health findings the module adds to `GET /system/status` and the mirror
/// card (plan section 2.12).
pub mod findings {
    /// No push for three intervals: a warning, an error once a scope of the mirror was
    /// taken over.
    pub const MIRROR_STALE: &str = super::codes::MIRROR_STALE;
    /// A source's scope is active again while Tenko's scope serves it: two servers answer
    /// one network (an error).
    pub const MIRROR_SCOPE_ACTIVE: &str = super::codes::MIRROR_SCOPE_ACTIVE;
    /// The mirror's token expires within fourteen days (WT-Q11).
    pub const MIRROR_TOKEN_EXPIRING: &str = super::codes::MIRROR_TOKEN_EXPIRING;

    /// Every finding.
    pub const ALL: [&str; 3] = [MIRROR_STALE, MIRROR_SCOPE_ACTIVE, MIRROR_TOKEN_EXPIRING];
}

// ---------------------------------------------------------------------------------------
// Tables

/// The tables of the module (plan section 3.1). All of them are in the replicated store
/// and none in the node subset: a data-plane node never reads a mirror.
pub mod tables {
    use super::{LossAck, Mirror, Snapshot, Takeover};
    use crate::{
        id::{MirrorId, TakeoverId},
        names::TableName,
        table::TableDef,
    };

    /// Mirrors, by id.
    pub static MIRRORS: TableDef<MirrorId, Mirror> = TableDef::new("migrate.mirrors");
    /// The latest accepted snapshot of each mirror.
    pub static SNAPSHOTS: TableDef<MirrorId, Snapshot> = TableDef::new("migrate.snapshots");
    /// Takeover records, by id.
    pub static TAKEOVERS: TableDef<TakeoverId, Takeover> = TableDef::new("migrate.takeovers");
    /// Acknowledged loss entries, by mirror and entry key.
    pub static LOSS_ACKS: TableDef<(MirrorId, String), LossAck> =
        TableDef::new("migrate.loss_acks");

    /// Every table of the module.
    pub fn all() -> [&'static TableName; 4] {
        [
            MIRRORS.name(),
            SNAPSHOTS.name(),
            TAKEOVERS.name(),
            LOSS_ACKS.name(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, names::is_valid_name, principal::Principal};

    fn stamp() -> Stamp {
        Stamp::new(
            "2026-11-01T12:00:00Z".parse().expect("time"),
            Principal::system(crate::SystemComponent::Api),
        )
    }

    fn mirror() -> Mirror {
        Mirror {
            id: MirrorId::generate(),
            name: "dhcp-lab".to_owned(),
            kind: SourceKindLabel::new(SourceKindLabel::WINDOWS_DHCP).expect("label"),
            enabled: true,
            token: ApiTokenId::generate(),
            account: UserId::generate(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            last_sequence: None,
            last_hash: None,
            last_push: None,
            last_change: None,
            created: stamp(),
            updated: stamp(),
        }
    }

    #[test]
    fn names_are_in_the_namespace() {
        for table in tables::all() {
            assert_eq!(table.namespace(), "migrate", "{table}");
        }
        let mut names: Vec<&str> = tables::all().iter().map(|t| t.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), tables::all().len());
        for code in codes::ALL
            .iter()
            .chain(codes::SKIP_CODES.iter())
            .chain(losses::ALL.iter())
        {
            assert!(
                is_valid_name(code) && code.starts_with("migrate."),
                "{code}"
            );
        }
        let mut all: Vec<&str> = codes::ALL.to_vec();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), codes::ALL.len());
        for action in audit::ALL {
            assert!(action.as_str().starts_with("migrate."), "{action}");
        }
        for finding in findings::ALL {
            assert!(is_valid_name(finding), "{finding}");
        }
        assert!(is_valid_name("migrate.mirror.push"));
        assert_eq!(TOPIC, "migrate");
        for kind in OBJECT_KINDS {
            assert_eq!(kind.as_str().parse::<ObjectKind>(), Ok(kind));
        }
        assert_eq!(ObjectKind::Mirror.as_str(), "mirror");
        assert_eq!(ObjectKind::Takeover.as_str(), "takeover");
        assert_eq!(metrics::PUSHES.name, "tenko_migrate_mirror_pushes");
        assert_eq!(metrics::AGE.name, "tenko_migrate_mirror_age_seconds");
    }

    #[test]
    fn scopes_follow_the_actions() {
        for kind in OBJECT_KINDS {
            assert_eq!(
                MigrateScope::required(Action::Read, kind),
                Some(MigrateScope::Read)
            );
            for action in [
                Action::Create,
                Action::Update,
                Action::Delete,
                Action::Execute,
            ] {
                assert_eq!(
                    MigrateScope::required(action, kind),
                    Some(MigrateScope::Write)
                );
            }
            for action in [Action::Approve, Action::Reveal, Action::Administer] {
                assert_eq!(MigrateScope::required(action, kind), None);
            }
        }
        assert_eq!(MigrateScope::required(Action::Read, ObjectKind::Zone), None);
        assert_eq!(
            serde_json::to_string(&MigrateScope::Write).expect("json"),
            "\"migrate.write\""
        );
    }

    #[test]
    fn a_mirror_validates_and_knows_its_freshness() {
        let mut mirror = mirror();
        mirror.validate().expect("valid");
        assert_eq!(mirror.stale_after_secs(), 180);
        let now: Timestamp = "2026-11-01T12:10:00Z".parse().expect("time");
        assert!(!mirror.is_stale(now), "a mirror that never pushed waits");
        assert!(!mirror.is_fresh(now));
        mirror.last_push = "2026-11-01T12:08:30Z".parse().ok();
        assert!(!mirror.is_stale(now));
        assert!(mirror.is_fresh(now));
        mirror.last_push = "2026-11-01T12:06:00Z".parse().ok();
        assert!(mirror.is_stale(now));
        assert!(!mirror.is_fresh(now));
        mirror.enabled = false;
        assert!(!mirror.is_stale(now), "a disabled mirror is never stale");

        mirror.name = String::new();
        assert!(mirror.validate().is_err());
        mirror.name = " lab".to_owned();
        assert!(mirror.validate().is_err());
        mirror.name = "lab".to_owned();
        mirror.interval_secs = 5;
        assert!(mirror.validate().is_err());
        assert_eq!(Mirror::account_name("lab"), "mirror-lab");
    }

    #[test]
    fn the_rows_round_trip_through_the_tables() {
        let mirror = mirror();
        let bytes = tables::MIRRORS.encode(&mirror).expect("cbor");
        assert_eq!(tables::MIRRORS.decode(&bytes).expect("decode"), mirror);
        let ack = LossAck {
            mirror: mirror.id,
            key: "Get-DhcpServerv4Policy/Name=Printers".to_owned(),
            entry_hash: HexBytes(vec![7; 32]),
            by: UserId::generate(),
            at: "2026-11-01T12:00:00Z".parse().expect("time"),
        };
        let key = tables::LOSS_ACKS.key(&(ack.mirror, ack.key.clone()));
        assert_eq!(
            tables::LOSS_ACKS.decode_key(&key).expect("key"),
            (ack.mirror, ack.key.clone())
        );
        let bytes = tables::LOSS_ACKS.encode(&ack).expect("cbor");
        assert_eq!(tables::LOSS_ACKS.decode(&bytes).expect("decode"), ack);
        assert_eq!(TakeoverState::RolledBack.as_str(), "rolled_back");
        assert_eq!(
            serde_json::to_string(&TakeoverState::Reverted).expect("json"),
            "\"reverted\""
        );
    }
}
