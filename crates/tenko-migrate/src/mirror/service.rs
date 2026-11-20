//! The mirror service (plan sections 2.1 to 2.4 and 2.12, ADR 0033 decisions 1, 3, 5 to 8).
//!
//! The rows live in the replicated store; the freshness lives in this controller's memory
//! ([`Memory`]): the time of the last push, the last accepted sequence, the newest envelope,
//! the floor between two pushes and the last refusal that was audited. What a push writes
//! (plan section 2.4, ADR 0033 decision 6):
//!
//! - a changed configuration (everything but the leases, their loss entries, the sequence and
//!   the time; a scope that turned inactive among it) writes the snapshot, the row and
//!   `migrate.mirror.push` at once;
//! - changed leases alone write the snapshot and the row at most every
//!   [`LEASES_WRITE_SECS`], without an audit record; the stored leases are from
//!   [`Mirror::stored_at`], and a prepare or a takeover takes the newest leases from a push made
//!   for it;
//! - otherwise the row is written with the freshness at most every
//!   [`Mirror::freshness_write_secs`], half the stale threshold, so that another controller
//!   or a restarted one reads a pushing mirror as fresh and a sequence at most that far behind
//!   (section 2.14, decision 8).
//!
//! The memory of a mirror belongs to its token: a new token starts a new series of
//! sequences, so a token that pushed an absurd sequence cannot hold the mirror after it is
//! replaced. Every time the service reads comes from its clock, never from the request.
//!
//! A write of a row meets a concurrent change only when another request wrote the row
//! between the read and the commit; the service reads again and repeats the operation, at
//! most [`ATTEMPTS`] times, so that the answer always says what happened to this request.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use ipnet::IpNet;
use tenko_auth::{
    AuthError, AuthService,
    clock::{Clock, SystemClock},
    service::{MirrorTokenTerms, types::CreatedToken},
    settings::Profile,
};
use tenko_core::{
    ApiTokenId, CounterKey, MirrorId, Principal, RequestCtx, Revision, Timestamp, UserId,
    audit::AuditDraft,
    codec::{canonical_sha256, encode_key},
    ipam::Stamp,
    ir::{LossEntry, MirrorOrigin, MirrorSnapshot, SourceKindLabel, dhcp::IrLease},
    metrics::{GaugeVec, Registry},
    migrate::{
        DEFAULT_INTERVAL_SECS, LEASES_WRITE_SECS, LossAck, MAX_MIRRORS, MIN_PUSH_INTERVAL_SECS,
        MIN_SOURCE_PREFIX_V4, MIN_SOURCE_PREFIX_V6, Mirror, Snapshot, TOKEN_EXPIRING_DAYS,
        TakeoverState, audit, findings, losses, metrics, mirror_object, tables,
    },
    serde_util::{HexBytes, to_hex},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WriteBatch,
};

use super::{
    MirrorError, MirrorItem, MirrorLossItem, MirrorLosses, MirrorPatch, MirroredScope, ScopeDiff,
    SnapshotAccepted, SnapshotCounts,
};

/// The mirrors with metric series (three push outcomes and one age each): every mirror an
/// installation may hold.
#[allow(
    clippy::cast_possible_truncation,
    reason = "MAX_MIRRORS is a small constant"
)]
const MIRROR_SLOTS: u16 = MAX_MIRRORS as u16;

/// Bumped by every creation of a mirror, which expects the value it read, so that two
/// creations cannot pass the count of [`MAX_MIRRORS`] together.
const CREATIONS: CounterKey = CounterKey::new("migrate.mirror_creations");

/// A refused push is audited at most this often per mirror (plan section 2.12).
const REFUSAL_AUDIT_SECS: u64 = 60;

/// How often a write that met a concurrent change of its row is read and tried again.
pub const ATTEMPTS: usize = 3;

/// How long a push waits for the node's one decode before it is answered 429; also its
/// `Retry-After`.
pub const DECODE_WAIT_SECS: u64 = 2;

/// The index of each outcome in [`metrics::PUSH_OUTCOMES`].
const CHANGED: usize = 0;
const UNCHANGED: usize = 1;
const REFUSED: usize = 2;

/// `tenko_migrate_mirror_pushes_total{mirror, outcome}`, set from memory by the metrics timer.
pub static PUSHES: GaugeVec = GaugeVec::new(metrics::PUSHES);

/// `tenko_migrate_mirror_age_seconds{mirror}`, set by the metrics timer.
pub static AGE: GaugeVec = GaugeVec::new(metrics::AGE);

/// Seals the module's metric families and registers them.
pub fn register_metrics(registry: &Registry) {
    PUSHES.seal_slots(MIRROR_SLOTS * 3);
    AGE.seal_slots(MIRROR_SLOTS);
    registry.register(&PUSHES);
    registry.register(&AGE);
}

/// What the freshness of one mirror holds in this controller's memory.
#[derive(Debug, Default)]
struct Memory {
    /// The token whose pushes `pushed` and `sequence` follow.
    token: Option<ApiTokenId>,
    /// The last push let through the floor, accepted or not.
    admitted: Option<Timestamp>,
    /// Whether an admitted push is still in flight ([`InFlight`]).
    in_flight: bool,
    /// The last accepted push.
    pushed: Option<Timestamp>,
    /// The last accepted sequence.
    sequence: Option<u64>,
    /// The leases of the last accepted push, stored or not, and until when they are held.
    newest: Option<(Arc<NewestLeases>, Timestamp)>,
    /// The last refusal written to the audit log.
    refusal_audited: Option<Timestamp>,
    /// Pushes by outcome, in the order of `metrics::PUSH_OUTCOMES`.
    outcomes: [u64; 3],
    /// What the stored snapshot holds.
    summary: Option<Arc<Summary>>,
}

/// A push of a mirror in flight on this controller, from its admission until it ends in any
/// way (answered, refused, cut by the body deadline, or dropped with its connection): while
/// it lives, the mirror's next push is refused, so that one token holds at most one body on
/// a controller.
#[derive(Debug)]
pub struct InFlight<'a> {
    service: &'a MirrorService,
    id: MirrorId,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(memory) = self.service.memory().get_mut(&self.id) {
            memory.in_flight = false;
        }
    }
}

/// What the card, the losses and the findings read of a stored snapshot, kept beside the
/// time it was written so that a card does not decode the snapshot.
#[derive(Debug)]
struct Summary {
    /// The snapshot's sequence.
    sequence: u64,
    /// When it was written ([`Mirror::stored_at`]).
    stored_at: Timestamp,
    counts: SnapshotCounts,
    source: MirrorOrigin,
    /// Per loss entry, in the snapshot's order: its key, its hash and its scope.
    losses: Vec<(String, Vec<u8>, Option<IpNet>)>,
    scopes: Vec<MirroredScope>,
}

impl Summary {
    fn of(snapshot: &MirrorSnapshot, stored_at: Timestamp) -> Result<Self, MirrorError> {
        let scopes: Vec<MirroredScope> = snapshot
            .dhcp
            .scopes
            .iter()
            .map(|scope| MirroredScope {
                cidr: scope.cidr,
                name: scope.name.clone(),
                active: scope.active,
            })
            .collect();
        let losses = snapshot
            .losses
            .entries
            .iter()
            .map(|entry| Ok((entry.key(), entry_hash(entry)?, entry_scope(entry, &scopes))))
            .collect::<Result<_, MirrorError>>()?;
        Ok(Self {
            sequence: snapshot.sequence,
            stored_at,
            counts: SnapshotCounts {
                scopes: count(snapshot.dhcp.scopes.len()),
                reservations: count(snapshot.reservation_count()),
                leases: count(snapshot.dhcp.leases.len()),
                losses: count(snapshot.losses.entries.len()),
            },
            source: snapshot.source.clone(),
            losses,
            scopes,
        })
    }

    /// The record `migrate.mirror.push` of a push of `id` whose configuration hashes to
    /// `hash`, with its counts.
    fn audited(&self, ctx: &RequestCtx, id: MirrorId, hash: &[u8]) -> AuditDraft {
        AuditDraft::success(audit::MIRROR_PUSH, vec![mirror_object(id)])
            .with_source_ip(ctx.source_ip)
            .with_context("sequence", self.sequence.to_string())
            .with_context("scopes", self.counts.scopes.to_string())
            .with_context("reservations", self.counts.reservations.to_string())
            .with_context("leases", self.counts.leases.to_string())
            .with_context("losses", self.counts.losses.to_string())
            .with_context("hash", to_hex(hash))
    }

    /// The entries no acknowledgment holds for, within `scope` when given (an entry without
    /// a scope counts for every scope).
    fn open(&self, acks: &BTreeMap<String, LossAck>, scope: Option<IpNet>) -> u32 {
        count(
            self.losses
                .iter()
                .filter(|(key, hash, of)| {
                    scope.is_none_or(|scope| of.is_none_or(|of| of == scope))
                        && acks.get(key).is_none_or(|ack| ack.entry_hash.0 != *hash)
                })
                .count(),
        )
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The two hashes of a snapshot (plan section 2.4): its configuration, which is the envelope
/// without the leases, their loss entries, the sequence and the time; and its leases with
/// their loss entries.
///
/// # Errors
///
/// A codec error.
pub fn content_hashes(snapshot: &MirrorSnapshot) -> Result<(Vec<u8>, Vec<u8>), MirrorError> {
    // Every field named, so that a new one has to be placed on one side.
    let tenko_core::ir::dhcp::DhcpIr {
        server_options,
        server_ddns,
        option_defs,
        classes,
        scopes,
        superscopes,
        policies,
        filters,
        failover,
        leases,
    } = &snapshot.dhcp;
    let (lease_losses, other_losses): (Vec<&LossEntry>, Vec<&LossEntry>) = snapshot
        .losses
        .entries
        .iter()
        .partition(|entry| entry.code == losses::LEASE_STATE);
    let configuration = canonical_sha256(&(
        snapshot.format,
        &snapshot.source,
        (server_options, server_ddns, option_defs, classes, scopes),
        (superscopes, policies, filters, failover),
        other_losses,
    ))?;
    let leases = canonical_sha256(&(leases, lease_losses))?;
    Ok((configuration.to_vec(), leases.to_vec()))
}

fn entry_hash(entry: &LossEntry) -> Result<Vec<u8>, MirrorError> {
    Ok(canonical_sha256(entry)?.to_vec())
}

/// The scope a loss entry belongs to: the scope holding the first address its location's
/// column names, as the exporter writes it (`192.0.2.198`, `192.0.2.0:81` for an option of
/// a scope) or as `Key=address` (`ScopeId=192.0.2.0`); none when it names none, and such an
/// entry belongs to every scope.
pub(crate) fn entry_scope(entry: &LossEntry, scopes: &[MirroredScope]) -> Option<IpNet> {
    let column = entry.location.column.as_deref()?;
    column
        .split(',')
        .filter_map(|part| {
            let value = part.split_once('=').map_or(part, |(_, value)| value).trim();
            value.parse::<IpAddr>().ok().or_else(|| {
                // An address followed by `:<code>`; an IPv6 address takes the last colon.
                [value.split_once(':'), value.rsplit_once(':')]
                    .into_iter()
                    .find_map(|split| split?.0.parse().ok())
            })
        })
        .find_map(|ip| {
            scopes
                .iter()
                .find(|scope| scope.cidr.contains(&ip))
                .map(|scope| scope.cidr)
        })
}

/// Binds the mirror to the server a push names when it is bound to none, and says so; a
/// push naming another server than the bound one is refused (plan section 2.15: a mirror is
/// the one server's of its token's first accepted push). Host names compare without case.
fn bind(mirror: &mut Mirror, server: &str) -> Result<bool, MirrorError> {
    match &mirror.server {
        Some(bound) if !bound.eq_ignore_ascii_case(server) => Err(MirrorError::Source {
            id: mirror.id,
            bound: bound.clone(),
            server: server.to_owned(),
        }),
        Some(_) => Ok(false),
        None => {
            mirror.server = Some(server.to_owned());
            Ok(true)
        }
    }
}

/// A health finding of the mirrors (plan section 2.12): the code and the mirrors it holds
/// for, by id and name (names are not unique).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// One of `tenko_core::migrate::findings::ALL`.
    pub code: &'static str,
    /// The mirrors, by id and name.
    pub mirrors: Vec<(MirrorId, String)>,
}

/// The newest leases of a mirror on the controller that took its last push, stored or not
/// (plan section 2.4): what the prepare and the takeover need of a push, the leases and the
/// loss entries of leases, with the push's sequence and times. Held until
/// [`Mirror::stale_after_secs`] after the push, and dropped when the token is replaced,
/// when the mirror is disabled and when it is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewestLeases {
    /// The push's sequence.
    pub sequence: u64,
    /// When the source read them, by its own clock.
    pub taken_at: Timestamp,
    /// When this controller accepted the push.
    pub received: Timestamp,
    /// The leases.
    pub leases: Vec<IrLease>,
    /// The loss entries of leases (`migrate.loss.lease_state`).
    pub losses: Vec<LossEntry>,
}

impl NewestLeases {
    /// The lease side of an envelope accepted at `received`; the rest is dropped.
    fn of(envelope: MirrorSnapshot, received: Timestamp) -> Self {
        let (losses, _): (Vec<LossEntry>, Vec<LossEntry>) = envelope
            .losses
            .entries
            .into_iter()
            .partition(|entry| entry.code == losses::LEASE_STATE);
        Self {
            sequence: envelope.sequence,
            taken_at: envelope.taken_at,
            received,
            leases: envelope.dhcp.leases,
            losses,
        }
    }
}

/// A new mirror.
#[derive(Debug, Clone)]
pub struct NewMirror {
    /// The name.
    pub name: String,
    /// The kind of source.
    pub kind: SourceKindLabel,
    /// The expected interval; 60 s when absent.
    pub interval_secs: Option<u32>,
    /// The token's lifetime and source prefixes.
    pub token: MirrorTokenTerms,
}

/// The mirror service. Shared as `Arc<MirrorService>`; the API reaches it as a request
/// extension.
pub struct MirrorService {
    store: Arc<dyn Store>,
    auth: Arc<AuthService>,
    memory: Mutex<HashMap<MirrorId, Memory>>,
    clock: Arc<dyn Clock>,
    decoding: tokio::sync::Semaphore,
}

impl std::fmt::Debug for MirrorService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorService").finish_non_exhaustive()
    }
}

/// Whether a store error is a concurrent change of a row the batch expected.
fn is_conflict(error: &MirrorError) -> bool {
    matches!(error, MirrorError::Store(StoreError::PreconditionFailed(_)))
}

impl MirrorService {
    /// A service over `store`, minting the mirrors' credentials through `auth`, on the
    /// system clock.
    pub fn new(store: Arc<dyn Store>, auth: Arc<AuthService>) -> Self {
        Self {
            store,
            auth,
            memory: Mutex::new(HashMap::new()),
            clock: Arc::new(SystemClock),
            decoding: tokio::sync::Semaphore::new(1),
        }
    }

    /// The service on another clock (the tests' clock).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn memory(&self) -> MutexGuard<'_, HashMap<MirrorId, Memory>> {
        self.memory.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, MirrorError> {
        Ok(self.store.read(ReadConsistency::Local).await?)
    }

    fn row(view: &dyn ReadView, id: MirrorId) -> Result<(Mirror, Revision), MirrorError> {
        view.get_typed(&tables::MIRRORS, &id)?
            .ok_or(MirrorError::NotFound(id))
    }

    fn rows(view: &dyn ReadView) -> Result<Vec<Mirror>, MirrorError> {
        let mut rows: Vec<Mirror> = view
            .scan_typed(&tables::MIRRORS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, mirror, _)| mirror)
            .collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rows)
    }

    /// The row with the freshness this controller holds in memory for the row's token.
    fn fresh(&self, mut mirror: Mirror) -> Mirror {
        if let Some(memory) = self
            .memory()
            .get(&mirror.id)
            .filter(|memory| memory.token == Some(mirror.token))
        {
            mirror.last_push = mirror.last_push.max(memory.pushed);
            mirror.last_sequence = mirror.last_sequence.max(memory.sequence);
        }
        mirror
    }

    /// The summary of a stored snapshot, from memory when it is of that write.
    fn summary_of(&self, snapshot: &Snapshot) -> Result<Arc<Summary>, MirrorError> {
        let mut memory = self.memory();
        let memory = memory.entry(snapshot.mirror).or_default();
        if let Some(summary) = memory
            .summary
            .clone()
            .filter(|summary| summary.stored_at == snapshot.received)
        {
            return Ok(summary);
        }
        let summary = Arc::new(Summary::of(&snapshot.envelope, snapshot.received)?);
        memory.summary = Some(Arc::clone(&summary));
        Ok(summary)
    }

    /// The summary of the mirror's stored snapshot, if it has one: from memory when this
    /// controller wrote it or read it last.
    fn summary(
        &self,
        view: &dyn ReadView,
        mirror: &Mirror,
    ) -> Result<Option<Arc<Summary>>, MirrorError> {
        let Some(stored_at) = mirror.stored_at else {
            return Ok(None);
        };
        if let Some(summary) = self
            .memory()
            .get(&mirror.id)
            .and_then(|memory| memory.summary.clone())
            .filter(|summary| summary.stored_at == stored_at)
        {
            return Ok(Some(summary));
        }
        match view.get_typed(&tables::SNAPSHOTS, &mirror.id)? {
            Some((snapshot, _)) => Ok(Some(self.summary_of(&snapshot)?)),
            None => Ok(None),
        }
    }

    /// Every acknowledgment of a mirror; their number is bounded by the entries of the
    /// latest snapshot, because an acknowledgment pass removes those of entries gone.
    fn acks(view: &dyn ReadView, id: MirrorId) -> Result<BTreeMap<String, LossAck>, MirrorError> {
        Ok(view
            .scan_typed(
                &tables::LOSS_ACKS,
                KeyRange::prefix(encode_key(&(id,))),
                usize::MAX,
                false,
            )?
            .into_iter()
            .map(|((_, key), ack, _)| (key, ack))
            .collect())
    }

    fn item(&self, view: &dyn ReadView, mirror: Mirror) -> Result<MirrorItem, MirrorError> {
        let now = self.now();
        let mirror = self.fresh(mirror);
        let summary = self.summary(view, &mirror)?;
        let losses_open = match &summary {
            Some(summary) => summary.open(&Self::acks(view, mirror.id)?, None),
            None => 0,
        };
        let token = AuthService::scoped_token(view, mirror.account, mirror.token)?;
        Ok(MirrorItem {
            age_secs: mirror
                .last_push
                .map(|at| now.saturating_since(at).as_secs()),
            stale: mirror.is_stale(now),
            token_expires_at: token.as_ref().and_then(|token| token.expires_at),
            source_prefixes: token.map(|token| token.source_prefixes).unwrap_or_default(),
            stored_sequence: summary.as_ref().map(|summary| summary.sequence),
            counts: summary.as_ref().map(|summary| summary.counts),
            source: summary.as_ref().map(|summary| summary.source.clone()),
            scopes: summary
                .as_ref()
                .map(|summary| summary.scopes.clone())
                .unwrap_or_default(),
            ca_fingerprint: None,
            losses_open,
            mirror,
        })
    }

    /// Every mirror, by name.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list(&self) -> Result<Vec<MirrorItem>, MirrorError> {
        let view = self.view().await?;
        Self::rows(view.as_ref())?
            .into_iter()
            .map(|mirror| self.item(view.as_ref(), mirror))
            .collect()
    }

    /// One mirror.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], a store error.
    pub async fn get(&self, id: MirrorId) -> Result<MirrorItem, MirrorError> {
        let view = self.view().await?;
        let (mirror, _) = Self::row(view.as_ref(), id)?;
        self.item(view.as_ref(), mirror)
    }

    fn hardened(&self) -> bool {
        self.auth.settings().profile == Profile::Hardened
    }

    /// Refuses, under the Hardened profile, a token for a mirror without a source prefix
    /// (minted, or kept by a mirror that is enabled).
    fn sources_required(&self, prefixes: usize) -> Result<(), MirrorError> {
        if prefixes == 0 && self.hardened() {
            return Err(MirrorError::Settings {
                field: "source_prefixes".to_owned(),
                reason: "the Hardened profile requires at least one source prefix for a mirror"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Checks the source prefixes of a mirror's new token: under Hardened at least one, and
    /// none shorter than [`MIN_SOURCE_PREFIX_V4`] or [`MIN_SOURCE_PREFIX_V6`], so that the
    /// list binds the token to something (two /1 prefixes would cover every address). An
    /// entry that is no prefix at all is refused by the token's minting, with its reason.
    fn check_sources(&self, prefixes: &[String]) -> Result<(), MirrorError> {
        self.sources_required(prefixes.len())?;
        for entry in prefixes {
            let entry = entry.trim();
            let Some(prefix) = entry
                .parse::<IpNet>()
                .ok()
                .or_else(|| entry.parse::<IpAddr>().ok().map(IpNet::from))
            else {
                continue;
            };
            let short = match prefix {
                IpNet::V4(net) => net.prefix_len() < MIN_SOURCE_PREFIX_V4,
                // An IPv4-mapped prefix is the IPv4 prefix it covers, as the binding reads it.
                IpNet::V6(net) if net.addr().to_ipv4_mapped().is_some() => {
                    net.prefix_len() < 96 + MIN_SOURCE_PREFIX_V4
                }
                IpNet::V6(net) => net.prefix_len() < MIN_SOURCE_PREFIX_V6,
            };
            if short {
                return Err(MirrorError::Settings {
                    field: "source_prefixes".to_owned(),
                    reason: format!(
                        "{entry} is shorter than a /{MIN_SOURCE_PREFIX_V4} (IPv4) or a /{MIN_SOURCE_PREFIX_V6} (IPv6) and binds too little"
                    ),
                });
            }
        }
        Ok(())
    }

    fn settings(mirror: &Mirror) -> Result<(), MirrorError> {
        mirror.validate().map_err(|error| match error {
            tenko_core::migrate::MigrateError::Invalid { field, reason } => {
                MirrorError::Settings { field, reason }
            }
        })
    }

    async fn commit(&self, batch: WriteBatch) -> Result<(), MirrorError> {
        self.store.propose(batch).await?;
        Ok(())
    }

    /// Creates a mirror with its service account and token (plan section 2.1, rule 2);
    /// audited as `migrate.mirror.create`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Settings`] (also for no source prefix under the Hardened profile),
    /// [`MirrorError::Exists`] naming the account when a person created an account of that
    /// name, the minting's errors (a session that signed in within five minutes, the source
    /// prefixes), a store error.
    pub async fn create(
        &self,
        ctx: &RequestCtx,
        new: NewMirror,
    ) -> Result<(MirrorItem, CreatedToken), MirrorError> {
        let stamp = Stamp::new(ctx.now, ctx.principal.clone());
        let mut mirror = Mirror {
            id: MirrorId::generate(),
            name: new.name,
            kind: new.kind,
            enabled: true,
            token: ApiTokenId::generate(),
            account: UserId::generate(),
            interval_secs: new.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS),
            last_sequence: None,
            last_hash: None,
            leases_hash: None,
            last_push: None,
            last_change: None,
            stored_at: None,
            server: None,
            partner: None,
            created: stamp.clone(),
            updated: stamp,
        };
        Self::settings(&mirror)?;
        self.check_sources(&new.token.source_prefixes)?;
        let account = Mirror::account_name(mirror.id);
        for _ in 0..ATTEMPTS {
            let view = self.view().await?;
            if Self::rows(view.as_ref())?.len() >= MAX_MIRRORS {
                return Err(MirrorError::Limit { max: MAX_MIRRORS });
            }
            let mut batch = WriteBatch::for_request(ctx);
            // Creations go one after the other: a creation the count let through fails at its
            // commit when another committed in between, and counts again.
            batch.expect_counter(CREATIONS, view.counter(&CREATIONS)?);
            batch.bump(CREATIONS);
            let credentials = self
                .auth
                .stage_mirror_account(ctx, view.as_ref(), &mut batch, mirror.id, &new.token)
                .await
                .map_err(|error| match error {
                    AuthError::UserNameTaken => MirrorError::Exists(account.clone()),
                    other => other.into(),
                })?;
            mirror.account = credentials.account;
            mirror.token = credentials.token.info.id;
            batch.expect_typed(&tables::MIRRORS, &mirror.id, None);
            batch.put_typed(&tables::MIRRORS, &mirror.id, &mirror)?;
            batch.audit(
                AuditDraft::success(audit::MIRROR_CREATE, vec![mirror_object(mirror.id)])
                    .with_source_ip(ctx.source_ip)
                    .with_context("name", mirror.name.clone())
                    .with_context("kind", mirror.kind.to_string())
                    .with_context("interval_secs", mirror.interval_secs.to_string()),
            );
            match self.commit(batch).await {
                // Another creation, or an account of the name, came first: the next pass
                // counts again and names the account.
                Err(error) if is_conflict(&error) => continue,
                result => result?,
            }
            let item = self.item(self.view().await?.as_ref(), mirror)?;
            return Ok((
                MirrorItem {
                    token_expires_at: credentials.token.info.expires_at,
                    ..item
                },
                credentials.token,
            ));
        }
        Err(MirrorError::Conflict(mirror.id))
    }

    /// Reads the mirror's row, lets `change` stage a write of it, and commits; a write that
    /// met a concurrent change of the row is read and staged again.
    async fn rewrite<T>(
        &self,
        ctx: &RequestCtx,
        id: MirrorId,
        mut change: impl FnMut(&dyn ReadView, &mut Mirror, &mut WriteBatch) -> Result<T, MirrorError>,
    ) -> Result<(Mirror, T), MirrorError> {
        for _ in 0..ATTEMPTS {
            let view = self.view().await?;
            let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
            let mut batch = WriteBatch::for_request(ctx);
            let out = change(view.as_ref(), &mut mirror, &mut batch)?;
            batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
            match self.commit(batch).await {
                Err(error) if is_conflict(&error) => {}
                result => return result.map(|()| (mirror, out)),
            }
        }
        Err(MirrorError::Conflict(id))
    }

    /// Stages the pairing of `mirror` with `partner` (or the end of its pair for `None`) on
    /// both rows, each expected at the revision it was read at (plan section 2.15): the
    /// partner's row is written beside the mirror's, which the caller writes. A pair is what
    /// an administrator chose; nothing compares server names.
    fn pair(
        view: &dyn ReadView,
        mirror: &mut Mirror,
        partner: Option<MirrorId>,
        batch: &mut WriteBatch,
        stamp: &Stamp,
    ) -> Result<(), MirrorError> {
        let refuse = |partner, reason| MirrorError::Partner {
            id: mirror.id,
            partner,
            reason,
        };
        let other = match partner {
            None => mirror.partner,
            Some(partner) if partner == mirror.id => {
                return Err(refuse(partner, "a mirror cannot be its own partner"));
            }
            Some(partner) if mirror.partner.is_some_and(|paired| paired != partner) => {
                return Err(refuse(partner, "the mirror is paired with another mirror"));
            }
            Some(partner) => Some(partner),
        };
        if let Some(other) = other {
            match view.get_typed(&tables::MIRRORS, &other)? {
                Some((mut row, revision)) => {
                    let wanted = partner.map(|_| mirror.id);
                    if partner.is_some() && row.partner.is_some_and(|paired| paired != mirror.id) {
                        return Err(refuse(other, "the partner is paired with another mirror"));
                    }
                    if row.partner != wanted {
                        row.partner = wanted;
                        row.updated = stamp.clone();
                        batch.expect_typed(&tables::MIRRORS, &other, Some(revision));
                        batch.put_typed(&tables::MIRRORS, &other, &row)?;
                    }
                }
                None if partner.is_some() => {
                    return Err(refuse(other, "no mirror of that id exists"));
                }
                None => {}
            }
        }
        mirror.partner = partner;
        Ok(())
    }

    /// Changes a mirror; audited as `migrate.mirror.update` (one record naming both mirrors
    /// when the pair changes).
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Settings`] (also for enabling a mirror whose
    /// token has no source prefix under the Hardened profile), [`MirrorError::Partner`],
    /// [`MirrorError::Conflict`], a store error.
    pub async fn update(
        &self,
        ctx: &RequestCtx,
        id: MirrorId,
        patch: MirrorPatch,
    ) -> Result<MirrorItem, MirrorError> {
        let (mirror, ()) = self
            .rewrite(ctx, id, |view, mirror, batch| {
                let stamp = Stamp::new(ctx.now, ctx.principal.clone());
                let mut objects = vec![mirror_object(id)];
                if let Some(partner) = patch.partner {
                    if let Some(other) = partner.or(mirror.partner)
                        && other != id
                    {
                        objects.push(mirror_object(other));
                    }
                    Self::pair(view, mirror, partner, batch, &stamp)?;
                }
                if patch.enabled == Some(true) {
                    let token = AuthService::scoped_token(view, mirror.account, mirror.token)?;
                    self.sources_required(token.map_or(0, |token| token.source_prefixes.len()))?;
                }
                let mut draft = AuditDraft::success(audit::MIRROR_UPDATE, objects)
                    .with_source_ip(ctx.source_ip);
                if let Some(partner) = patch.partner {
                    draft = draft.with_context(
                        "partner",
                        partner.map_or_else(|| "none".to_owned(), |partner| partner.to_string()),
                    );
                }
                if let Some(name) = &patch.name {
                    draft = draft.with_context("name", name.clone());
                    mirror.name.clone_from(name);
                }
                if let Some(enabled) = patch.enabled {
                    draft = draft.with_context("enabled", enabled.to_string());
                    mirror.enabled = enabled;
                }
                if let Some(interval) = patch.interval_secs {
                    draft = draft.with_context("interval_secs", interval.to_string());
                    mirror.interval_secs = interval;
                }
                Self::settings(mirror)?;
                mirror.updated = stamp;
                batch.put_typed(&tables::MIRRORS, &id, mirror)?;
                batch.audit(draft);
                Ok(())
            })
            .await?;
        if !mirror.enabled {
            self.drop_newest(id);
        }
        self.item(self.view().await?.as_ref(), mirror)
    }

    /// Drops the newest leases this controller holds for `id`.
    fn drop_newest(&self, id: MirrorId) {
        if let Some(memory) = self.memory().get_mut(&id) {
            memory.newest = None;
        }
    }

    /// Deletes a mirror with its snapshot, its acknowledgments, its account and its token;
    /// the takeover records stay. Audited as `migrate.mirror.delete`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Conflict`], a store error.
    pub async fn delete(&self, ctx: &RequestCtx, id: MirrorId) -> Result<(), MirrorError> {
        self.rewrite(ctx, id, |view, mirror, batch| {
            // The partner's row forgets the pair in the same batch.
            Self::pair(
                view,
                mirror,
                None,
                batch,
                &Stamp::new(ctx.now, ctx.principal.clone()),
            )?;
            batch.delete_typed(&tables::MIRRORS, &id);
            batch.delete_typed(&tables::SNAPSHOTS, &id);
            for key in Self::acks(view, id)?.into_keys() {
                batch.delete_typed(&tables::LOSS_ACKS, &(id, key));
            }
            self.auth
                .stage_mirror_account_removal(ctx, view, batch, mirror.account)?;
            batch.audit(
                AuditDraft::success(audit::MIRROR_DELETE, vec![mirror_object(id)])
                    .with_source_ip(ctx.source_ip)
                    .with_context("name", mirror.name.clone()),
            );
            Ok(())
        })
        .await?;
        self.memory().remove(&id);
        Ok(())
    }

    /// Replaces the mirror's token; the old one stops at the commit, and the last accepted
    /// sequence goes with it, so that the new token starts a series of its own. Audited as
    /// `migrate.mirror.token`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Settings`] for no source prefix under the
    /// Hardened profile, the minting's errors, [`MirrorError::Conflict`], a store error.
    pub async fn replace_token(
        &self,
        ctx: &RequestCtx,
        id: MirrorId,
        terms: &MirrorTokenTerms,
    ) -> Result<(MirrorItem, CreatedToken), MirrorError> {
        self.check_sources(&terms.source_prefixes)?;
        // Minting awaits the session's check, so this write repeats on its own.
        let mut written = None;
        for _ in 0..ATTEMPTS {
            let view = self.view().await?;
            let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
            let mut batch = WriteBatch::for_request(ctx);
            let token = self
                .auth
                .stage_mirror_token(
                    ctx,
                    view.as_ref(),
                    &mut batch,
                    mirror.account,
                    id,
                    mirror.token,
                    terms,
                )
                .await?;
            mirror.token = token.info.id;
            mirror.last_sequence = None;
            // The new token binds the mirror anew with its first push.
            mirror.server = None;
            mirror.updated = Stamp::new(ctx.now, ctx.principal.clone());
            batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
            batch.put_typed(&tables::MIRRORS, &id, &mirror)?;
            batch.audit(
                AuditDraft::success(audit::MIRROR_TOKEN, vec![mirror_object(id)])
                    .with_source_ip(ctx.source_ip),
            );
            match self.commit(batch).await {
                Err(error) if is_conflict(&error) => {}
                result => {
                    result?;
                    written = Some((mirror, token));
                    break;
                }
            }
        }
        let (mirror, token) = written.ok_or(MirrorError::Conflict(id))?;
        // Nothing reads the old token's leases any more.
        self.drop_newest(id);
        let item = self.item(self.view().await?.as_ref(), mirror)?;
        Ok((
            MirrorItem {
                token_expires_at: token.info.expires_at,
                ..item
            },
            token,
        ))
    }

    /// The node's one decode of a push body: the route takes it once the body is read, and
    /// holds it through the inflate, the decode and the write, so that the memory a decode
    /// may take (`body::DECODE_ALLOCATION_BOUND`) is taken once on a node, however many
    /// mirrors and controllers push, and a body that arrives slowly holds no one else.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Rate`] when another push held it for [`DECODE_WAIT_SECS`].
    pub async fn decoding(&self) -> Result<tokio::sync::SemaphorePermit<'_>, MirrorError> {
        tokio::time::timeout(
            Duration::from_secs(DECODE_WAIT_SECS),
            self.decoding.acquire(),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(MirrorError::Rate {
            retry_after: DECODE_WAIT_SECS,
        })
    }

    /// Lets a push of `id` through before its body is read: the mirror exists, is enabled,
    /// its token is bound to source prefixes when the profile is Hardened (a token without
    /// them is refused as one from outside its prefixes is, so that a mirror created before
    /// the switch to Hardened stops; the finding `migrate.mirror.unbound` names it), no other
    /// push of it is in flight on this controller, and its last admitted push is at least
    /// [`MIN_PUSH_INTERVAL_SECS`] old. The push holds the answer until it ends.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::Disabled`], [`MirrorError::Auth`],
    /// [`MirrorError::Rate`] (also while another push of the mirror is in flight).
    pub async fn admit(&self, id: MirrorId) -> Result<InFlight<'_>, MirrorError> {
        let view = self.view().await?;
        let (mirror, _) = Self::row(view.as_ref(), id)?;
        if !mirror.enabled {
            return Err(MirrorError::Disabled(id));
        }
        if self.hardened()
            && AuthService::scoped_token(view.as_ref(), mirror.account, mirror.token)?
                .is_none_or(|token| token.source_prefixes.is_empty())
        {
            return Err(MirrorError::Auth(AuthError::Unauthenticated));
        }
        let now = self.now();
        let mut memory = self.memory();
        let memory = memory.entry(id).or_default();
        let floor = u64::from(MIN_PUSH_INTERVAL_SECS);
        if memory.in_flight {
            return Err(MirrorError::Rate { retry_after: floor });
        }
        if let Some(last) = memory.admitted {
            let since = now.saturating_since(last).as_secs();
            if since < floor {
                return Err(MirrorError::Rate {
                    retry_after: floor - since,
                });
            }
        }
        memory.admitted = Some(now);
        memory.in_flight = true;
        Ok(InFlight { service: self, id })
    }

    /// Accepts a decoded push of `id` (plan section 2.1, rule 6; section 2.4) from the
    /// mirror's current token, as each attempt reads it, with a sequence above the last
    /// accepted one of that token. A changed configuration writes the snapshot, the row and
    /// `migrate.mirror.push` at once; changed leases alone write the snapshot and the row at
    /// most every [`LEASES_WRITE_SECS`]; otherwise the row is written at most every
    /// [`Mirror::freshness_write_secs`]. The envelope is held in memory as the newest either
    /// way.
    ///
    /// # Errors
    ///
    /// [`MirrorError::Auth`] when the request's token is no longer the mirror's,
    /// [`MirrorError::NotFound`], [`MirrorError::Disabled`], [`MirrorError::Sequence`] with
    /// the last accepted sequence, [`MirrorError::TooLarge`] for a snapshot the store's batch
    /// cannot hold, [`MirrorError::Conflict`], a store error.
    pub async fn push(
        &self,
        ctx: &RequestCtx,
        id: MirrorId,
        snapshot: MirrorSnapshot,
    ) -> Result<SnapshotAccepted, MirrorError> {
        let (hash, leases_hash) = content_hashes(&snapshot)?;
        let sequence = snapshot.sequence;
        let now = self.now();
        let summary = Arc::new(Summary::of(&snapshot, now)?);
        let mut snapshot = Some(snapshot);
        for _ in 0..ATTEMPTS {
            let view = self.view().await?;
            let (mut mirror, revision) = Self::row(view.as_ref(), id)?;
            // The token that authenticated the request must still be the row's: a push whose
            // body was still arriving when the token was replaced is a revoked token's.
            if !matches!(ctx.principal, Principal::Token { id: token, .. } if token == mirror.token)
            {
                return Err(MirrorError::Auth(AuthError::Unauthenticated));
            }
            if !mirror.enabled {
                return Err(MirrorError::Disabled(id));
            }
            if let Some(last) = self
                .fresh(mirror.clone())
                .last_sequence
                .filter(|last| sequence <= *last)
            {
                return Err(MirrorError::Sequence { sequence, last });
            }
            let bind = bind(&mut mirror, &summary.source.server)?;
            let since = |at: Option<Timestamp>| {
                at.map_or(u64::MAX, |at| now.saturating_since(at).as_secs())
            };
            let changed = mirror
                .last_hash
                .as_ref()
                .is_none_or(|stored| stored.0 != hash);
            let leases_due = mirror
                .leases_hash
                .as_ref()
                .is_none_or(|stored| stored.0 != leases_hash)
                && since(mirror.stored_at) >= u64::from(LEASES_WRITE_SECS);
            let stored = changed || leases_due;
            if stored || bind || since(mirror.last_push) >= mirror.freshness_write_secs() {
                mirror.last_sequence = Some(sequence);
                mirror.last_push = Some(now);
                let mut batch = WriteBatch::for_request(ctx);
                batch.expect_typed(&tables::MIRRORS, &id, Some(revision));
                if changed {
                    mirror.last_change = Some(now);
                    batch.audit(summary.audited(ctx, id, &hash));
                }
                if stored {
                    mirror.last_hash = Some(HexBytes(hash.clone()));
                    mirror.leases_hash = Some(HexBytes(leases_hash.clone()));
                    mirror.stored_at = Some(now);
                    let envelope = snapshot.take().ok_or(MirrorError::Conflict(id))?;
                    let row = Snapshot {
                        mirror: id,
                        sequence,
                        hash: HexBytes(hash.clone()),
                        received: now,
                        envelope,
                    };
                    let staged = batch.put_typed(&tables::SNAPSHOTS, &id, &row);
                    snapshot = Some(row.envelope);
                    staged?;
                }
                batch.put_typed(&tables::MIRRORS, &id, &mirror)?;
                match self.store.propose(batch).await {
                    Ok(_) => {}
                    // Another write of the row came first: read it again and decide anew.
                    Err(StoreError::PreconditionFailed(_)) => continue,
                    Err(StoreError::BatchTooLarge { limit, .. }) => {
                        return Err(MirrorError::TooLarge { limit });
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let until = now
                .checked_add(Duration::from_secs(mirror.stale_after_secs()))
                .unwrap_or(now);
            let newest = snapshot
                .take()
                .map(|envelope| (Arc::new(NewestLeases::of(envelope, now)), until));
            let mut memory = self.memory();
            let memory = memory.entry(id).or_default();
            if memory.token != Some(mirror.token) {
                memory.sequence = None;
                memory.token = Some(mirror.token);
            }
            memory.pushed = Some(now);
            memory.sequence = memory.sequence.max(Some(sequence));
            memory.newest = newest;
            memory.outcomes[if changed { CHANGED } else { UNCHANGED }] += 1;
            if stored {
                memory.summary = Some(Arc::clone(&summary));
            }
            return Ok(SnapshotAccepted { sequence, changed });
        }
        Err(MirrorError::Conflict(id))
    }

    /// The newest leases of `id` on this controller (plan section 2.4): those of the last
    /// push it accepted, stored or not, which a prepare or a takeover takes rather than the
    /// stored snapshot's. `None` on a controller that took no push of the mirror within
    /// [`Mirror::stale_after_secs`], or of a token that is no longer the mirror's.
    pub fn newest(&self, id: MirrorId, token: ApiTokenId) -> Option<Arc<NewestLeases>> {
        let now = self.now();
        self.memory()
            .get(&id)
            .filter(|memory| memory.token == Some(token))
            .and_then(|memory| memory.newest.clone())
            .filter(|(_, until)| now < *until)
            .map(|(leases, _)| leases)
    }

    /// Counts a refused push of `id` and writes `migrate.mirror.refuse` with the code and
    /// the client's address, at most once a minute per mirror. Nothing of the push is kept.
    pub async fn refused(&self, ctx: &RequestCtx, id: MirrorId, error: &MirrorError) {
        let now = self.now();
        {
            let mut memory = self.memory();
            let memory = memory.entry(id).or_default();
            memory.outcomes[REFUSED] += 1;
            if memory
                .refusal_audited
                .is_some_and(|at| now.saturating_since(at).as_secs() < REFUSAL_AUDIT_SECS)
            {
                return;
            }
            memory.refusal_audited = Some(now);
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.idempotency = None;
        batch.audit(
            AuditDraft::failed(audit::MIRROR_REFUSE, vec![mirror_object(id)], error)
                .with_source_ip(ctx.source_ip)
                .with_context("code", tenko_core::Coded::code(error)),
        );
        if let Err(store_error) = self.store.propose(batch).await {
            tracing::warn!(error = %store_error, mirror = %id, "could not record a refused push");
        }
    }

    async fn stored(&self, id: MirrorId) -> Result<(Arc<dyn ReadView>, Snapshot), MirrorError> {
        let view = self.view().await?;
        Self::row(view.as_ref(), id)?;
        let (snapshot, _) = view
            .get_typed(&tables::SNAPSHOTS, &id)?
            .ok_or(MirrorError::NoSnapshot(id))?;
        Ok((view, snapshot))
    }

    /// The latest snapshot as stored.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NotFound`], [`MirrorError::NoSnapshot`], a store error.
    pub async fn snapshot(&self, id: MirrorId) -> Result<Snapshot, MirrorError> {
        Ok(self.stored(id).await?.1)
    }

    /// The loss report of the latest snapshot with the acknowledgments that hold.
    ///
    /// # Errors
    ///
    /// As [`MirrorService::snapshot`].
    pub async fn losses(&self, id: MirrorId) -> Result<MirrorLosses, MirrorError> {
        let (view, snapshot) = self.stored(id).await?;
        let acks = Self::acks(view.as_ref(), id)?;
        let summary = self.summary_of(&snapshot)?;
        let entries = snapshot
            .envelope
            .losses
            .entries
            .into_iter()
            .zip(summary.losses.iter())
            .map(|(entry, (key, hash, scope))| MirrorLossItem {
                ack: acks
                    .get(key)
                    .filter(|ack| ack.entry_hash.0 == *hash)
                    .cloned(),
                scope: *scope,
                key: key.clone(),
                entry,
            })
            .collect();
        Ok(MirrorLosses {
            mirror: id,
            sequence: snapshot.sequence,
            entries,
        })
    }

    /// Acknowledges loss entries of the snapshot at `sequence` by their keys; an
    /// acknowledgment holds while the entry recurs unchanged. Acknowledgments of entries the
    /// snapshot no longer holds go in the same batch. Audited as `migrate.mirror.losses_ack`.
    ///
    /// # Errors
    ///
    /// [`MirrorError::SnapshotMoved`] when a newer snapshot came in after the one the request
    /// was made from, [`MirrorError::Request`] for a key the snapshot does not hold or no
    /// key at all, as [`MirrorService::snapshot`].
    pub async fn ack(
        &self,
        ctx: &RequestCtx,
        id: MirrorId,
        sequence: u64,
        keys: &[String],
    ) -> Result<(Vec<LossAck>, Revision), MirrorError> {
        let by = ctx
            .principal
            .user()
            .ok_or(MirrorError::Auth(AuthError::Unauthenticated))?;
        let (view, snapshot) = self.stored(id).await?;
        if snapshot.sequence != sequence {
            return Err(MirrorError::SnapshotMoved {
                sequence,
                latest: snapshot.sequence,
            });
        }
        if keys.is_empty() {
            return Err(MirrorError::Request("name at least one entry".to_owned()));
        }
        let summary = self.summary_of(&snapshot)?;
        let mut acks: BTreeMap<&str, LossAck> = BTreeMap::new();
        for key in keys {
            let (_, hash, _) = summary
                .losses
                .iter()
                .find(|(known, ..)| known == key)
                .ok_or_else(|| {
                    MirrorError::Request("a key names no entry of the snapshot".to_owned())
                })?;
            acks.insert(
                key,
                LossAck {
                    mirror: id,
                    key: key.clone(),
                    entry_hash: HexBytes(hash.clone()),
                    by,
                    at: self.now(),
                },
            );
        }
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(
            &tables::SNAPSHOTS,
            &id,
            view.get_typed(&tables::SNAPSHOTS, &id)?
                .map(|(_, revision)| revision),
        );
        for key in Self::acks(view.as_ref(), id)?.into_keys() {
            if !summary.losses.iter().any(|(known, ..)| *known == key) {
                batch.delete_typed(&tables::LOSS_ACKS, &(id, key));
            }
        }
        for ack in acks.values() {
            batch.put_typed(&tables::LOSS_ACKS, &(id, ack.key.clone()), ack)?;
        }
        batch.audit(
            AuditDraft::success(audit::MIRROR_LOSSES_ACK, vec![mirror_object(id)])
                .with_source_ip(ctx.source_ip)
                .with_context("sequence", sequence.to_string())
                .with_context("count", acks.len().to_string()),
        );
        let revision = match self.store.propose(batch).await {
            Ok(committed) => committed.revision,
            // A push changed the snapshot between the read and the commit.
            Err(StoreError::PreconditionFailed(_)) => {
                let latest = self.stored(id).await?.1.sequence;
                return Err(MirrorError::SnapshotMoved { sequence, latest });
            }
            Err(error) => return Err(error.into()),
        };
        Ok((acks.into_values().collect(), revision))
    }

    /// The diff of a mirrored scope against Tenko's scope of the same network.
    ///
    /// # Errors
    ///
    /// As [`MirrorService::snapshot`], and [`MirrorError::ScopeNotFound`].
    pub async fn diff(&self, id: MirrorId, scope: IpNet) -> Result<ScopeDiff, MirrorError> {
        let (view, snapshot) = self.stored(id).await?;
        let open = self
            .summary_of(&snapshot)?
            .open(&Self::acks(view.as_ref(), id)?, Some(scope));
        let partner = match Self::row(view.as_ref(), id)?.0.partner {
            Some(partner) => Some((
                partner,
                view.get_typed(&tables::SNAPSHOTS, &partner)?
                    .map(|(snapshot, _)| snapshot),
            )),
            None => None,
        };
        let partner = partner
            .as_ref()
            .map(|(partner, snapshot)| (*partner, snapshot.as_ref()));
        super::diff::diff(view.as_ref(), &snapshot, scope, open, partner)
    }

    /// The health findings of the mirrors (plan section 2.12): stale mirrors (an error once a
    /// scope of the mirror or of its partner is taken over), tokens that expire within
    /// [`TOKEN_EXPIRING_DAYS`] days, taken-over scopes the source serves again (on either
    /// mirror of a pair), and under Hardened the enabled mirrors whose token has no source
    /// prefix.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn findings(&self) -> Result<Vec<Finding>, MirrorError> {
        let now = self.now();
        let view = self.view().await?;
        // A scope taken over from a pair is taken over from both of its mirrors.
        let takeovers: Vec<(MirrorId, IpNet)> = view
            .scan_typed(&tables::TAKEOVERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, takeover, _)| takeover.state == TakeoverState::Done)
            .flat_map(|(_, takeover, _)| {
                let partner = takeover
                    .partner
                    .map(|partner| (partner.mirror, takeover.scope));
                std::iter::once((takeover.mirror, takeover.scope)).chain(partner)
            })
            .collect();
        let mut found: BTreeMap<&'static str, Vec<(MirrorId, String)>> = BTreeMap::new();
        let soon = Duration::from_secs(u64::from(TOKEN_EXPIRING_DAYS) * 86_400);
        let hardened = self.hardened();
        for mirror in Self::rows(view.as_ref())? {
            let mirror = self.fresh(mirror);
            // Its own takeovers and its partner's: either mirror of a pair answers for both.
            let taken_over: Vec<IpNet> = takeovers
                .iter()
                .filter(|(of, _)| *of == mirror.id || Some(*of) == mirror.partner)
                .map(|(_, scope)| *scope)
                .collect();
            let mut raise = |code| {
                found
                    .entry(code)
                    .or_default()
                    .push((mirror.id, mirror.name.clone()));
            };
            if mirror.is_stale(now) {
                raise(if taken_over.is_empty() {
                    findings::MIRROR_STALE
                } else {
                    findings::MIRROR_STALE_AFTER_TAKEOVER
                });
            }
            let token = AuthService::scoped_token(view.as_ref(), mirror.account, mirror.token)?;
            if token
                .as_ref()
                .and_then(|token| token.expires_at)
                .is_some_and(|end| end.saturating_since(now) <= soon)
            {
                raise(findings::MIRROR_TOKEN_EXPIRING);
            }
            if hardened
                && mirror.enabled
                && token.is_none_or(|token| token.source_prefixes.is_empty())
            {
                raise(findings::MIRROR_UNBOUND);
            }
            if let Some(summary) = self.summary(view.as_ref(), &mirror)?
                && summary
                    .scopes
                    .iter()
                    .any(|mirrored| mirrored.active && taken_over.contains(&mirrored.cidr))
            {
                raise(findings::MIRROR_SCOPE_ACTIVE);
            }
        }
        Ok(found
            .into_iter()
            .map(|(code, mirrors)| Finding { code, mirrors })
            .collect())
    }

    /// Sets the metric series of every mirror from memory: the pushes by outcome and the
    /// age of the last push; and drops the newest leases held past their age. Run by the
    /// metrics timer (every 30 s by default).
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn refresh_metrics(&self) -> Result<(), MirrorError> {
        let now = self.now();
        // The newest leases past their age go with this round.
        for memory in self.memory().values_mut() {
            if memory
                .newest
                .as_ref()
                .is_some_and(|(_, until)| *until <= now)
            {
                memory.newest = None;
            }
        }
        let view = self.view().await?;
        for mirror in Self::rows(view.as_ref())? {
            let mirror = self.fresh(mirror);
            let id = mirror.id.to_string();
            let outcomes = self
                .memory()
                .get(&mirror.id)
                .map(|memory| memory.outcomes)
                .unwrap_or_default();
            for (outcome, total) in metrics::PUSH_OUTCOMES.into_iter().zip(outcomes) {
                PUSHES.set_labels_total(&[id.as_str(), outcome], total);
            }
            if let Some(at) = mirror.last_push {
                #[allow(clippy::cast_precision_loss, reason = "seconds of an age")]
                AGE.set_labels(&[id.as_str()], now.saturating_since(at).as_secs() as f64);
            }
        }
        PUSHES.sweep();
        AGE.sweep();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_indices_name_their_series() {
        assert_eq!(metrics::PUSH_OUTCOMES[CHANGED], "changed");
        assert_eq!(metrics::PUSH_OUTCOMES[UNCHANGED], "unchanged");
        assert_eq!(metrics::PUSH_OUTCOMES[REFUSED], "refused");
    }
}
