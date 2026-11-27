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
//! | `migrate.runs` | the run's [`DelegationId`](crate::DelegationId) | [`run::RunRecord`] |
//! | `migrate.run_plans` | the run's [`DelegationId`](crate::DelegationId) | its [`plan::TakeoverPlan`] |
//! | `migrate.run_domains` | the domain's name | the open run's [`DelegationId`](crate::DelegationId) |
//!
//! These are contracts (WP14.0). WP14.1 builds the push, the freshness, the losses and the
//! diff on them; WP14.2 the prepare, the takeover and the flip.

use std::{fmt, time::Duration};

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

/// A snapshot whose configuration is unchanged but whose leases changed is written at most
/// this often, in seconds (section 2.4), and a mirror's reserve of configuration writes
/// gains one this often; one value for both keeps the stored leases at most this old. The
/// controller that received a push holds its newest envelope in memory meanwhile.
pub const LEASES_WRITE_SECS: u32 = 600;

/// The most changed configurations of a mirror stored in a row: the reserve of
/// [`Mirror::change_reserve_full_at`], refilled by one every [`LEASES_WRITE_SECS`].
pub const CHANGE_RESERVE: u32 = 30;

/// The longest name of a mirror, in characters.
pub const MAX_NAME_LEN: usize = 64;

/// The most mirrors an installation holds (409 `migrate.mirror.limit`). A mirror stands for
/// one DHCP server being migrated: a few in a small domain, a few dozen at most in a large
/// one, so 32 is not reached by accident. It bounds what every controller holds in memory
/// (each mirror's newest leases), and every mirror keeps its own metric series.
pub const MAX_MIRRORS: usize = 32;

/// The shortest IPv4 source prefix of a mirror's token: a list of shorter ones could cover
/// the whole address space (two /1 prefixes) and bind nothing.
pub const MIN_SOURCE_PREFIX_V4: u8 = 16;

/// The shortest IPv6 source prefix of a mirror's token, for the same reason.
pub const MIN_SOURCE_PREFIX_V6: u8 = 48;

/// The prefix of a mirror's service account name: `mirror-<id>`.
pub const ACCOUNT_PREFIX: &str = "mirror-";

/// The SSE topic of the module.
pub const TOPIC: &str = "migrate";

/// The kinds of the module as objects of authorization and audit.
pub const OBJECT_KINDS: [ObjectKind; 2] = [ObjectKind::Mirror, ObjectKind::Takeover];

/// A mirrored source (section 2.1): one row per source, with the freshness a controller
/// writes at most every [`Mirror::freshness_write_secs`] while pushes arrive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Mirror {
    /// Identifier.
    pub id: MirrorId,
    /// The name an administrator gave it, shown and used to address it in the CLI; unique
    /// among mirrors, and nothing else derives from it.
    pub name: String,
    /// The kind of source (`windows-dhcp`).
    pub kind: SourceKindLabel,
    /// Whether pushes are accepted; a disabled mirror refuses them with 403 and raises no
    /// staleness finding.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The scoped token whose only special scope is `mirror:<id>` (section 2.1, rule 2).
    pub token: ApiTokenId,
    /// The service account `mirror-<id>` that owns the token; it holds no grants.
    pub account: UserId,
    /// The expected interval between pushes, in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u32,
    /// The sequence of the last accepted push; a push must carry a higher one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    /// The SHA-256 of the stored snapshot's configuration in canonical CBOR (everything but
    /// the leases, their loss entries, the sequence and the time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hash: Option<HexBytes>,
    /// The SHA-256 of the stored snapshot's leases with their loss entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases_hash: Option<HexBytes>,
    /// When the last push was accepted, changed or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push: Option<Timestamp>,
    /// When a changed configuration was last stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_change: Option<Timestamp>,
    /// When the reserve of configuration writes is full again ([`CHANGE_RESERVE`]); none
    /// is full. Written only with a stored configuration, and cleared with the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_reserve_full_at: Option<Timestamp>,
    /// When the snapshot row was last written: its leases are from then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_at: Option<Timestamp>,
    /// The server the mirror is bound to: the `source.server` of the first push its token
    /// made (section 2.15). A push naming another server is refused with
    /// `migrate.mirror.source` until the token is replaced, which clears the binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The other mirror of a pair of DHCP servers that share their scopes (section 2.15),
    /// set on both rows at once by an administrator; never a match of server names, since
    /// two partners name each other differently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<MirrorId>,
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
    /// Checks the row: a name of 1 to [`MAX_NAME_LEN`] characters, spaces allowed but not
    /// at either end, without a character [`crate::text::is_hidden`] holds for, and an
    /// interval within [`MIN_INTERVAL_SECS`] and [`MAX_INTERVAL_SECS`].
    ///
    /// # Errors
    ///
    /// [`MigrateError::Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), MigrateError> {
        if self.name.trim().is_empty() || self.name.chars().count() > MAX_NAME_LEN {
            return Err(MigrateError::invalid("name", "1 to 64 characters"));
        }
        if self.name.trim() != self.name || self.name.chars().any(crate::text::is_hidden) {
            return Err(MigrateError::invalid(
                "name",
                "no space at either end and no control or format character",
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

    /// The name of the service account that owns the token of the mirror `id`: by its id, so
    /// that a rename touches nothing else.
    pub fn account_name(id: MirrorId) -> String {
        format!("{ACCOUNT_PREFIX}{id}")
    }

    /// The short form of the mirror `id` that the card, the findings and the CLI show beside
    /// a name, which is not unique: its last eight hexadecimal digits (the random end of
    /// the identifier, where its start is the creation time).
    pub fn short_id(id: MirrorId) -> String {
        let text = id.to_string();
        text[text.len() - 8..].to_owned()
    }

    /// After how many seconds without a push the mirror is stale (section 2.4).
    pub const fn stale_after_secs(&self) -> u64 {
        (self.interval_secs as u64) * (STALE_AFTER_INTERVALS as u64)
    }

    /// The row is written with the freshness at most this often while pushes arrive: half
    /// of [`Mirror::stale_after_secs`], so that another controller or a restarted one reads
    /// a mirror that pushes as fresh, and a sequence at most this far behind (section 2.14).
    pub const fn freshness_write_secs(&self) -> u64 {
        self.stale_after_secs() / 2
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

    /// The reserve's full time after a configuration write at `now`, or none when the
    /// reserve is spent. A full time ahead of `now` holds rather than refills, so that a
    /// controller whose clock is behind cannot spend a reserve again; an overflow is no write.
    pub fn spend_change(&self, now: Timestamp) -> Option<Timestamp> {
        let next = self.change_base(now).checked_add(Self::change_step())?;
        (next <= now.checked_add(Self::change_step() * CHANGE_RESERVE)?).then_some(next)
    }

    /// How many changed configurations can be stored at `now`, from 0 to [`CHANGE_RESERVE`].
    pub fn changes_left(&self, now: Timestamp) -> u32 {
        now.checked_add(Self::change_step() * CHANGE_RESERVE)
            .map_or(0, |full| {
                let left = full.saturating_since(self.change_base(now)).as_secs()
                    / u64::from(LEASES_WRITE_SECS);
                u32::try_from(left).unwrap_or(0)
            })
    }

    /// The earliest time at or after `now` at which a changed configuration can be stored.
    pub fn change_due(&self, now: Timestamp) -> Timestamp {
        self.change_reserve_full_at
            .and_then(|full| full.checked_sub(Self::change_step() * (CHANGE_RESERVE - 1)))
            .map_or(now, |due| due.max(now))
    }

    fn change_base(&self, now: Timestamp) -> Timestamp {
        self.change_reserve_full_at
            .map_or(now, |full| full.max(now))
    }

    fn change_step() -> Duration {
        Duration::from_secs(u64::from(LEASES_WRITE_SECS))
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
    /// The SHA-256 in canonical CBOR of the envelope's configuration (without the leases,
    /// their loss entries, the `sequence` and `taken_at`), as [`Mirror::last_hash`].
    pub hash: HexBytes,
    /// When the push was accepted, by the node's clock: the configuration and the leases are
    /// from then, and while the controllers' clocks agree may be up to [`LEASES_WRITE_SECS`]
    /// and one interval older than the newest push.
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
    /// The partner's push the takeover used beside the mirror's, for a paired mirror
    /// (section 2.15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<TakeoverPartner>,
    /// The job that ran it.
    pub job: JobId,
    /// When the state was reached. For `Done` this is no earlier than the moment the
    /// source's servers were made silent (plan section 2.17): a push of the mirror or of
    /// its partner accepted after it raises `migrate.mirror.scope_active`.
    pub at: Timestamp,
    /// Who started the job.
    pub by: UserId,
}

/// The partner's push a takeover used (section 2.15): the mirror, the sequence and the hash
/// of its leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TakeoverPartner {
    /// The partner's mirror.
    pub mirror: MirrorId,
    /// The sequence of its push.
    pub sequence: u64,
    /// The SHA-256 of that push's leases with their loss entries, as [`Mirror::leases_hash`].
    pub leases_hash: HexBytes,
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
    /// An account of the mirror's service account name (`mirror-<id>`) exists (409).
    /// Params: `name`.
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
    /// A source answers again after a takeover silenced it (409; also the finding). Params:
    /// `id`, `scope`.
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
    /// The scope is not ready: its diff holds a row, or its snapshot a value, that the step
    /// does not take, or someone else changed Tenko's scope (409). Params: `item`.
    pub const TAKEOVER_DIFF: &str = "migrate.takeover.diff";
    /// A zone the takeover needs is missing, not a primary zone or takes no DHCP updates
    /// (409). Params: `zone`, `reason`.
    pub const TAKEOVER_ZONE: &str = "migrate.takeover.zone";
    /// The scope has unacknowledged loss entries (409). Params: `scope`, `count`.
    pub const TAKEOVER_LOSSES: &str = "migrate.takeover.losses";
    /// No push showed the source's scope inactive within the wait (409). Params: `scope`,
    /// `waited`.
    pub const TAKEOVER_WAIT_TIMEOUT: &str = "migrate.takeover.wait_timeout";
    /// Tenko's scope is enabled, so a prepare or a takeover cannot run, or someone else
    /// changed it, so a run's session does not remove it (409). Params: `item`.
    pub const TAKEOVER_SCOPE_ENABLED: &str = "migrate.takeover.scope_enabled";
    /// A takeover or a prepare of the scope runs already (409). Params: `scope`, `job`.
    pub const TAKEOVER_RUNNING: &str = "migrate.takeover.running";

    /// The latest snapshot is not the one the request was made from: a newer push came in
    /// between (409). Params: `sequence`, `latest`.
    pub const MIRROR_SNAPSHOT_MOVED: &str = "migrate.mirror.snapshot_moved";
    /// A write of the mirror's row met a concurrent change and could not be repeated (409).
    /// Params: `id`.
    pub const MIRROR_CONFLICT: &str = "migrate.mirror.conflict";
    /// The installation holds as many mirrors as it may (409). Params: `max`.
    pub const MIRROR_LIMIT: &str = "migrate.mirror.limit";
    /// The profile requires source prefixes and the mirror's token has none (the finding;
    /// its pushes are refused like an unknown token's). Params: `mirrors`, `ids`.
    pub const MIRROR_UNBOUND: &str = "migrate.mirror.unbound";
    /// The push names another server than the one the mirror is bound to (409, audited as a
    /// refused push, whose record names the bound server; the answer does not). Params: `id`,
    /// `server`.
    pub const MIRROR_SOURCE: &str = "migrate.mirror.source";
    /// A pairing of two mirrors is refused: the mirror itself, a mirror that does not exist,
    /// or one already paired with another (409). Params: `id`, `partner`, `reason`.
    pub const MIRROR_PARTNER: &str = "migrate.mirror.partner";
    /// Another read of a stored snapshot held the node's one for two seconds (429, with
    /// `Retry-After`). Params: `retry_after`.
    pub const MIRROR_BUSY: &str = "migrate.mirror.busy";
    /// The domain has an open takeover run with another plan (409). Params: `run`.
    pub const RUN_PLAN: &str = "migrate.run.plan";
    /// No such takeover run, or for a delegated session one outside its own run (404).
    pub const RUN_NOT_FOUND: &str = "migrate.run.not_found";
    /// The run still has a mirror or an unserved zone, which a person deletes before closing it
    /// (409). Params: `mirrors`, `zones`.
    pub const RUN_BUSY: &str = "migrate.run.busy";
    /// The run's window cannot be bound to the configurations sent (409); the detail says what
    /// to do. Params: `reason` (`missing`, `hash`, `losses`, `pair`, `zones`, `extra`) and
    /// `server`, `zone` or, for `extra`, `servers`.
    pub const RUN_BINDING: &str = "migrate.run.binding";
    /// The security profile refuses a plan that serves its zones from Tenko (409).
    pub const RUN_PROFILE: &str = "migrate.run.profile";
    /// The run's access list `takeover-<run>` holds other entries than the addresses of the
    /// plan's domain controllers, or a person's list holds its name, so the run's flip does not
    /// use it (409); the detail says what to do. Params: `name`.
    pub const RUN_ACL: &str = "migrate.run.acl";
    /// A person changed the transfer settings of a zone the run created, which the run's flip
    /// does not write over (409); the detail says what to do. Params: `zone`.
    pub const RUN_TRANSFER: &str = "migrate.run.transfer";

    /// Every code of the module, for the contracts document and its test.
    pub const ALL: [&str; 36] = [
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
        MIRROR_SNAPSHOT_MOVED,
        MIRROR_CONFLICT,
        MIRROR_LIMIT,
        MIRROR_UNBOUND,
        MIRROR_SOURCE,
        MIRROR_PARTNER,
        MIRROR_BUSY,
        RUN_PLAN,
        RUN_NOT_FOUND,
        RUN_BUSY,
        RUN_BINDING,
        RUN_PROFILE,
        RUN_ACL,
        RUN_TRANSFER,
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
/// `column` (an address of the scope it belongs to first, `192.0.2.0:81` for an option of
/// that scope; none for an entry of the whole server); the prepare writes
/// [`RESERVATION_NAME`] and [`FOREIGN_NAME`] for what it derives no record from.
///
/// A code outside [`ALL`] is accepted, shown and must be acknowledged like any other, and
/// counts as configuration: only [`LEASE_STATE`] is an entry of the lease side.
pub mod losses {
    /// A policy (WT-Q2).
    pub const POLICY: &str = "migrate.loss.policy";
    /// A MAC filter entry Tenko cannot match (not a MAC address pattern): not carried.
    pub const FILTER: &str = "migrate.loss.filter";
    /// A reservation that the source's allow list does not list: the source does not serve
    /// it, and Tenko serves a reservation on a restricted scope whatever the allow list says.
    pub const FILTER_RESERVATION: &str = "migrate.loss.filter_reservation";
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
    /// An option a policy sets (WT-Q2).
    pub const OPTION_POLICY: &str = "migrate.loss.option_policy";
    /// An option Tenko computes itself (T1 and T2 from the lease time).
    pub const OPTION_MANAGED: &str = "migrate.loss.option_managed";
    /// An option definition of a type Tenko has no kind for.
    pub const OPTION_DEF_TYPE: &str = "migrate.loss.option_def_type";
    /// The default value of an option definition; Tenko has no option defaults.
    pub const OPTION_DEF_DEFAULT: &str = "migrate.loss.option_def_default";
    /// A scope that keeps its DNS records when a lease expires (ADR 0020).
    pub const DDNS_KEEP_ON_EXPIRY: &str = "migrate.loss.ddns_keep_on_expiry";
    /// A scope that registers names under a DNS suffix of its own.
    pub const DDNS_SUFFIX: &str = "migrate.loss.ddns_suffix";
    /// A reservation that answers BOOTP only.
    pub const RESERVATION_BOOTP: &str = "migrate.loss.reservation_bootp";

    /// Every loss code.
    pub const ALL: [&str; 17] = [
        POLICY,
        FILTER,
        SUPERSCOPE,
        FAILOVER,
        SCOPE_DELAY,
        BOOTP_ONLY,
        LEASE_STATE,
        RESERVATION_NAME,
        FOREIGN_NAME,
        FILTER_RESERVATION,
        OPTION_POLICY,
        OPTION_MANAGED,
        OPTION_DEF_TYPE,
        OPTION_DEF_DEFAULT,
        DDNS_KEEP_ON_EXPIRY,
        DDNS_SUFFIX,
        RESERVATION_BOOTP,
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
    /// A takeover run was created at the first collect of its domain.
    pub const RUN_CREATE: AuditAction = AuditAction::from_static("migrate.run.create");
    /// A later collect with an equal plan joined the open run of its domain.
    pub const RUN_JOIN: AuditAction = AuditAction::from_static("migrate.run.join");
    /// A person closed a run: its rows and its sittings' sessions are gone.
    pub const RUN_CLOSE: AuditAction = AuditAction::from_static("migrate.run.close");
    /// A person started a run's window, binding its mirrors' configurations.
    pub const RUN_WINDOW: AuditAction = AuditAction::from_static("migrate.run.window");

    /// Every action of the module, for the contracts document and its test. The scope
    /// actions (`dhcp.scope.prepare`, `dhcp.scope.takeover`, `dhcp.scope.revert`) are in
    /// [`crate::dhcp::audit`] and the zone actions (`dns.zone.flip`, `dns.zone.release`) in
    /// [`crate::dns::audit`], in the namespaces of what they change.
    pub const ALL: [&AuditAction; 11] = [
        &MIRROR_CREATE,
        &MIRROR_UPDATE,
        &MIRROR_DELETE,
        &MIRROR_TOKEN,
        &MIRROR_PUSH,
        &MIRROR_REFUSE,
        &MIRROR_LOSSES_ACK,
        &RUN_CREATE,
        &RUN_JOIN,
        &RUN_CLOSE,
        &RUN_WINDOW,
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

    /// The outcomes of [`PUSHES`], in label order; `changed` counts every push whose
    /// configuration differs from the stored one, held or stored.
    pub const PUSH_OUTCOMES: [&str; 3] = ["changed", "unchanged", "refused"];
}

/// The names of the health findings the module adds to `GET /system/status` and the mirror
/// card (plan section 2.12).
pub mod findings {
    /// No push for three intervals (a warning); none once the scope of the mirror or of its
    /// partner is taken over, when the source's servers are silent and a stale mirror is the
    /// expected state (plan section 2.17).
    pub const MIRROR_STALE: &str = super::codes::MIRROR_STALE;
    /// A push of the mirror or of its partner accepted after a takeover's recorded silence
    /// ([`Takeover::at`](super::Takeover::at) of a record in the state `Done`): a Windows server
    /// answers beside Tenko again (an error).
    pub const MIRROR_SCOPE_ACTIVE: &str = super::codes::MIRROR_SCOPE_ACTIVE;
    /// The mirror's token expires within fourteen days (WT-Q11).
    pub const MIRROR_TOKEN_EXPIRING: &str = super::codes::MIRROR_TOKEN_EXPIRING;
    /// Under Hardened, an enabled mirror whose token has no source prefix: its pushes are
    /// refused until the token is replaced with prefixes (a warning).
    pub const MIRROR_UNBOUND: &str = super::codes::MIRROR_UNBOUND;

    /// Every finding.
    pub const ALL: [&str; 4] = [
        MIRROR_STALE,
        MIRROR_SCOPE_ACTIVE,
        MIRROR_TOKEN_EXPIRING,
        MIRROR_UNBOUND,
    ];
}

// ---------------------------------------------------------------------------------------
// Tables

/// The tables of the module (plan section 3.1). All of them are in the replicated store
/// and none in the node subset: a data-plane node never reads a mirror.
pub mod tables {
    use super::{LossAck, Mirror, Snapshot, Takeover, plan::TakeoverPlan, run::RunRecord};
    use crate::{
        id::{DelegationId, MirrorId, TakeoverId},
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
    /// Open takeover runs, by id ([`super::run`]).
    pub static RUNS: TableDef<DelegationId, RunRecord> = TableDef::new("migrate.runs");
    /// The plan of each open run, as its first sitting's approval fixed it.
    pub static RUN_PLANS: TableDef<DelegationId, TakeoverPlan> = TableDef::new("migrate.run_plans");
    /// The open run of each domain, by the domain's name: one per domain.
    pub static RUN_DOMAINS: TableDef<String, DelegationId> = TableDef::new("migrate.run_domains");

    /// Every table of the module.
    pub fn all() -> [&'static TableName; 7] {
        [
            MIRRORS.name(),
            SNAPSHOTS.name(),
            TAKEOVERS.name(),
            LOSS_ACKS.name(),
            RUNS.name(),
            RUN_PLANS.name(),
            RUN_DOMAINS.name(),
        ]
    }
}

// The plan a takeover script asks a person to approve (ADR 0038).
pub mod plan;
// The record of a takeover run (ADR 0038).
pub mod run;

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
            leases_hash: None,
            last_push: None,
            last_change: None,
            change_reserve_full_at: None,
            stored_at: None,
            server: None,
            partner: None,
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

        assert_eq!(
            mirror.freshness_write_secs(),
            90,
            "half the stale threshold"
        );

        for name in [
            "",
            "  ",
            " lab",
            "lab ",
            "dc\u{202E}1",
            "dc\n1",
            &"x".repeat(65),
        ] {
            mirror.name = name.to_owned();
            let refused = mirror.validate().expect_err(name);
            assert_eq!(crate::Coded::code(&refused), codes::MIRROR_INVALID_SETTINGS);
        }
        for name in ["Office DHCP 1", &"x".repeat(64)] {
            mirror.name = name.to_owned();
            mirror.validate().expect(name);
        }
        mirror.interval_secs = 5;
        assert!(mirror.validate().is_err());
        assert_eq!(
            Mirror::account_name(mirror.id),
            format!("mirror-{}", mirror.id)
        );
        let id: MirrorId = "0190d1c2-0000-7000-8000-00000000abcd"
            .parse()
            .expect("an id");
        assert_eq!(Mirror::short_id(id), "0000abcd");
    }

    #[test]
    fn the_rows_round_trip_through_the_tables() {
        let unpaired = mirror();
        let bytes = tables::MIRRORS.encode(&unpaired).expect("cbor");
        assert_eq!(tables::MIRRORS.decode(&bytes).expect("decode"), unpaired);
        let mirror = Mirror {
            server: Some("dc1.corp.example.test".to_owned()),
            partner: Some(MirrorId::generate()),
            ..unpaired
        };
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
