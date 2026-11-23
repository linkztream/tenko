//! Zone transfers and NOTIFY (WP6.1; RFC 5936, RFC 1995, RFC 1996, RFC 9103, RFC 9432).
//!
//! | Module | What |
//! |---|---|
//! | [`access`] | who may transfer a zone out or NOTIFY it in, under the security profile |
//! | [`health`] | the findings of the transfer settings: weaker than the profile, deny wins |
//! | [`message`] | the messages of transfers and NOTIFY: the writer and the reader |
//! | [`out`] | AXFR and IXFR out on the role's TCP and DoT listeners, IXFR over UDP, NOTIFY in |
//! | [`notify`] | NOTIFY out from the leader when a serial changes, with retries |
//! | [`inbound`] | the transfer client: SOA check, IXFR with the AXFR fallback, TSIG, XoT |
//! | [`catalog_zone`] | the members of a catalog zone (RFC 9432), read and written |
//!
//! The listeners of the `dns` role hand a message to the transfer path ([`TransferSink`])
//! before the resolver sees it when [`classify`] says it is one: an AXFR or IXFR query or a
//! NOTIFY. Over TCP and DoT the path answers with a stream of messages the connection
//! writes in order; over UDP it answers an IXFR with the SOA only (RFC 1995 section 2) and
//! a NOTIFY with its acknowledgment. The path reads the zone rows and the TSIG keys from a
//! [`Directory`] kept current from the store, the records from the index, and the IXFR
//! deltas from the journal through [`JournalSource`]; it writes nothing but its audit
//! records ([`TransferAudit`]). A NOTIFY for a secondary zone reaches the leader's
//! secondary service through [`NotifyHandler`], which refreshes the zone and writes the
//! result through the store like every other change (plan section 2.4).

pub mod access;
pub mod catalog_zone;
pub mod health;
#[path = "in.rs"]
pub mod inbound;
pub mod message;
pub mod notify;
pub mod out;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, PoisonError, TryLockError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use tenko_core::{
    RequestCtx, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft},
    dns::{
        JournalEntry, KeyMeta, KeyName, QueryTransport, ScopeName, Zone, ZoneId, audit,
        tables::{JOURNAL, KEYS_META, ZONES},
    },
    metrics::{CounterVec, Desc, Registry},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt, Store, StoreError, WatchFilter, WriteBatch,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    respond::Conn,
    tsig::{Keyring, TsigKey},
    wire::{self, HEADER_LEN},
    zone::{ZoneService, follow::Follow},
};

/// What a message on the transfer path asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A full transfer (RFC 5936).
    Axfr,
    /// An incremental transfer (RFC 1995).
    Ixfr,
    /// A NOTIFY (RFC 1996).
    Notify,
    /// A query for an SOA signed with TSIG: a secondary's refresh check, answered and
    /// signed by the transfer path (the resolver refuses signed queries).
    SignedSoa,
}

/// What a message is for the transfer path, from its header and question type only; no
/// allocation. `None` for everything the resolver answers.
pub fn classify(message: &[u8]) -> Option<Kind> {
    let header = wire::parse_header(message)?;
    if header.qr || header.qdcount != 1 {
        return None;
    }
    if header.opcode == message::OPCODE_NOTIFY {
        return Some(Kind::Notify);
    }
    if header.opcode != message::OPCODE_QUERY {
        return None;
    }
    let end = wire::skip_name(message, HEADER_LEN)?;
    let qtype = u16::from_be_bytes([*message.get(end)?, *message.get(end + 1)?]);
    match qtype {
        message::TYPE_AXFR => Some(Kind::Axfr),
        message::TYPE_IXFR => Some(Kind::Ixfr),
        message::TYPE_SOA if header.arcount > 0 => {
            matches!(crate::tsig::find(message), Ok(Some(_))).then_some(Kind::SignedSoa)
        }
        _ => None,
    }
}

/// The transfer path the listeners hand messages to (`server::Hooks::transfers`).
pub trait TransferSink: Send + Sync {
    /// Answers a message of [`classify`] that came over UDP into `out`; `false` sends
    /// nothing. Runs on a UDP worker: it must not block.
    fn datagram(&self, message: &[u8], conn: &Conn, out: &mut Vec<u8>) -> bool;

    /// Answers a message of [`classify`] that came over TCP or DoT (`tls` when this node
    /// ended TLS itself: XoT, RFC 9103) with the messages of the answer, in order; the
    /// connection writes each as it arrives and goes on reading when the channel closes.
    fn stream(self: Arc<Self>, message: Vec<u8>, conn: Conn, tls: bool) -> mpsc::Receiver<Vec<u8>>;
}

/// Where a NOTIFY for a secondary zone goes: the leader's secondary service.
pub trait NotifyHandler: Send + Sync {
    /// A primary of `zone` at `from` says its serial is now `serial` (when it said);
    /// `signed` when the NOTIFY was signed with that primary's own key, so that its source
    /// is known. An unsigned NOTIFY may be spoofed: the service backs off from one that brings
    /// nothing new.
    fn notified(&self, zone: ZoneId, from: IpAddr, serial: Option<u32>, signed: bool);
}

/// The audit records of transfers out, written off the transfer path.
pub trait TransferAudit: Send + Sync {
    /// Records one transfer, or one refusal.
    fn record(&self, draft: AuditDraft);

    /// Records a refusal of `conn`'s client, on its own (`draft`, with the worth of its
    /// source address) or folded into the minute's summary of `kind`, so that a scan cannot
    /// fill the log; true when on its own. This default records every one on its own.
    fn refused(&self, kind: Refused, conn: &Conn, draft: &dyn Fn() -> AuditDraft) -> bool {
        let _ = kind;
        self.record(with_source(draft(), conn));
        true
    }
}

/// A refusal the audit log records under a budget, by its action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A zone transfer or a signed SOA query (`dns.zone.transfer_out`, denied).
    Transfer = 0,
    /// A dynamic update (`dns.update.refuse`).
    Update = 1,
    /// A TKEY negotiation (`dns.gss.refuse`).
    Gss = 2,
}

impl Refused {
    const ALL: [Self; 3] = [Self::Transfer, Self::Update, Self::Gss];

    /// The action of its records.
    pub fn action(self) -> AuditAction {
        match self {
            Self::Transfer => audit::ZONE_TRANSFER_OUT,
            Self::Update => audit::UPDATE_REFUSE,
            Self::Gss => audit::GSS_REFUSE,
        }
    }
}

/// `draft` with the worth of the client's address: `verified` over TCP and TLS, whose
/// handshake proves the address can receive (behind a proxy, the proxy's word), `claimed`
/// over UDP, where any sender may write it.
pub fn with_source(draft: AuditDraft, conn: &Conn) -> AuditDraft {
    let source = if conn.transport == QueryTransport::Udp {
        "claimed"
    } else {
        "verified"
    };
    draft.with_context("source", source)
}

/// The journal entries an IXFR answer is built from.
#[async_trait::async_trait]
pub trait JournalSource: Send + Sync {
    /// The entries of a zone scope, oldest first.
    async fn entries(&self, zone: ZoneId, scope: &ScopeName) -> Result<Vec<JournalEntry>, String>;
}

/// The journal in the store of this process (Phase 2: the role runs in the controller's
/// process; a `dns` node of Phase 5 reads its node-sync copy of `dns.journal`).
#[derive(Clone)]
pub struct StoreJournal {
    store: Arc<dyn Store>,
}

impl StoreJournal {
    /// The journal of `store`.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl JournalSource for StoreJournal {
    async fn entries(&self, zone: ZoneId, scope: &ScopeName) -> Result<Vec<JournalEntry>, String> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let range = KeyRange::prefix(tenko_core::codec::key::encode_key(&(zone, scope.clone())));
        Ok(view
            .scan_typed(&JOURNAL, range, usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, entry, _)| entry)
            .collect())
    }
}

/// The client a refusal counts for: its address, or for a verified IPv6 source its /64, one
/// link on which a host picks its own interface identifiers, so that one host or one link
/// is one client however many addresses it takes. A claimed source stays an address: it is
/// only a claim, and its budget is apart.
fn client_of(client: IpAddr, claimed: bool) -> IpAddr {
    match access::canonical(client) {
        IpAddr::V6(address) if !claimed => IpAddr::V6(std::net::Ipv6Addr::from(
            address.to_bits() & !u128::from(u64::MAX),
        )),
        address => address,
    }
}

/// Refusals recorded on their own in one minute, of all clients and kinds together, for
/// each kind of source: claimed (UDP) and verified (TCP and TLS) have a budget each.
pub const REFUSALS_PER_MINUTE: usize = 10;

/// Clients [`RefusalLimiter`] remembers as recorded, for each kind of source: every client
/// recorded on its own within the hour, which [`REFUSALS_PER_MINUTE`] bounds, so no flood
/// makes it forget one before its hour ends.
pub const REFUSALS_REMEMBERED: usize = REFUSALS_PER_MINUTE * 60;

/// Clients a summary counts by address for each kind of source; the refusals of later
/// clients in its minute are counted as unlisted. A budget, not a property of the data,
/// since a sender over UDP names any source it likes: room for every host of a large
/// network that keeps being refused, at about 64 bytes each.
pub const SUMMARY_CLIENTS: usize = 4_096;

/// The verified clients a summary names, the most refused first: every transfer client and
/// update signer a zone usually has (secondaries, DHCP servers, administrators' hosts), at
/// most about 2 KiB of the record. A budget.
pub const SUMMARY_VERIFIED: usize = 32;

/// The claimed clients a summary names, the most refused first.
pub const SUMMARY_TOP: usize = 5;

/// How often the refusals folded since the last time are written as summaries.
pub const SUMMARY_PERIOD: Duration = Duration::from_secs(60);

/// Which refusals are recorded on their own: a client's first refusal within an hour, at
/// most [`REFUSALS_PER_MINUTE`] a minute in all; every other refusal is counted in its
/// kind's summary ([`RefusalLimiter::take`]). Claimed and verified sources keep apart
/// budgets, memories, summary rooms and locks, so no number of invented UDP sources costs
/// a verified source its record or its place in the summary. The minutes and the hour are
/// counted on a monotonic clock. A verified IPv6 source counts by its /64 ([`client_of`]).
/// A UDP refusal that finds its state held by another worker is counted for the summary
/// without waiting, so a flood never serializes the workers; a verified refusal waits for
/// its lock, which only refused requests over TCP and TLS take, for a map lookup each.
#[derive(Debug)]
pub struct RefusalLimiter {
    start: Instant,
    /// The state of claimed sources, then of verified ones.
    states: [Mutex<Budget>; 2],
    /// Claimed refusals per kind counted while their state was held.
    contended: [AtomicU64; 3],
}

#[derive(Debug, Default)]
struct Budget {
    /// The minute of `recorded`, counted from `start`.
    minute: u64,
    recorded: usize,
    /// The clients recorded on their own within the hour, with the minute of the record:
    /// at most [`REFUSALS_REMEMBERED`].
    seen: HashMap<IpAddr, u64>,
    /// Per kind, the refusals folded since the last summary, and since when (with a
    /// summary not written).
    folds: [Option<(Timestamp, Fold)>; 3],
}

impl Budget {
    fn fold(&mut self, kind: Refused, client: IpAddr) {
        self.folds[kind as usize]
            .get_or_insert_with(|| (Timestamp::now(), Fold::default()))
            .1
            .add(client, 1);
    }
}

/// The refusals of one kind from one kind of source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Fold {
    refusals: u64,
    /// Refusals per client, at most [`SUMMARY_CLIENTS`] clients.
    clients: HashMap<IpAddr, u64>,
    /// Refusals of clients past that room.
    unlisted: u64,
}

impl Fold {
    fn add(&mut self, client: IpAddr, count: u64) {
        self.refusals = self.refusals.saturating_add(count);
        if let Some(seen) = self.clients.get_mut(&client) {
            *seen = seen.saturating_add(count);
        } else if self.clients.len() < SUMMARY_CLIENTS {
            self.clients.insert(client, count);
        } else {
            self.unlisted = self.unlisted.saturating_add(count);
        }
    }

    fn merge(&mut self, other: Self) {
        // The unlisted ones here, the others through `add`.
        self.refusals = self.refusals.saturating_add(other.unlisted);
        self.unlisted = self.unlisted.saturating_add(other.unlisted);
        for (client, count) in other.clients {
            self.add(client, count);
        }
    }

    /// The `count` most refused clients with their refusals; an IPv6 client of verified
    /// sources is its /64.
    fn top(&self, count: usize, verified: bool) -> String {
        let mut top: Vec<(&IpAddr, &u64)> = self.clients.iter().collect();
        top.sort_unstable_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let top: Vec<String> = top
            .into_iter()
            .take(count)
            .map(|(client, refusals)| match client {
                IpAddr::V6(link) if verified => format!("{link}/64 {refusals}"),
                _ => format!("{client} {refusals}"),
            })
            .collect();
        top.join(", ")
    }
}

/// The refusals of one kind folded into one audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    kind: Refused,
    from: Timestamp,
    to: Timestamp,
    /// From claimed sources, then from verified ones.
    sources: [Fold; 2],
}

impl Summary {
    /// The refusals this summary counts.
    pub fn refusals(&self) -> u64 {
        self.sources
            .iter()
            .fold(0, |sum, fold| sum.saturating_add(fold.refusals))
    }

    /// The audit record: the time it covers and the refusals, then for verified sources and
    /// for claimed ones apart the refusals, the clients counted by address, the refusals of
    /// clients past that room, and the most refused clients ([`SUMMARY_VERIFIED`] verified,
    /// [`SUMMARY_TOP`] claimed).
    pub fn draft(&self) -> AuditDraft {
        let mut draft = AuditDraft::denied(self.kind.action(), Vec::new())
            .with_context("from", self.from.to_string())
            .with_context("to", self.to.to_string())
            .with_context("refusals", self.refusals().to_string());
        for (name, fold, listed, verified) in [
            ("verified", &self.sources[1], SUMMARY_VERIFIED, true),
            ("claimed", &self.sources[0], SUMMARY_TOP, false),
        ] {
            draft = draft
                .with_context(name, fold.refusals.to_string())
                .with_context(format!("{name}_clients"), fold.clients.len().to_string())
                .with_context(format!("{name}_unlisted"), fold.unlisted.to_string())
                .with_context(format!("{name}_top"), fold.top(listed, verified));
        }
        draft
    }
}

impl Default for RefusalLimiter {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            states: Default::default(),
            contended: Default::default(),
        }
    }
}

fn locked(state: &Mutex<Budget>) -> std::sync::MutexGuard<'_, Budget> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RefusalLimiter {
    /// Whether a refusal of `client` of `kind` is recorded on its own now; one that is not
    /// goes into the kind's summary. `claimed` when it came over UDP.
    pub fn due(&self, kind: Refused, client: IpAddr, claimed: bool) -> bool {
        self.due_at(kind, client, claimed, self.start.elapsed().as_secs() / 60)
    }

    fn due_at(&self, kind: Refused, client: IpAddr, claimed: bool, minute: u64) -> bool {
        let state = &self.states[usize::from(!claimed)];
        let mut budget = if claimed {
            match state.try_lock() {
                Ok(budget) => budget,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    self.contended[kind as usize].fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        } else {
            locked(state)
        };
        if minute > budget.minute {
            budget.minute = minute;
            budget.recorded = 0;
            budget.seen.retain(|_, at| *at + 60 > minute);
        }
        let client = client_of(client, claimed);
        if budget.recorded < REFUSALS_PER_MINUTE && !budget.seen.contains_key(&client) {
            budget.recorded += 1;
            let at = budget.minute;
            budget.seen.insert(client, at);
            return true;
        }
        budget.fold(kind, client);
        false
    }

    /// Counts a refusal in its kind's summary: one whose own record the store refused.
    pub fn fold(&self, kind: Refused, client: IpAddr, claimed: bool) {
        locked(&self.states[usize::from(!claimed)]).fold(kind, client_of(client, claimed));
    }

    /// The summaries of the refusals folded since the last call, each with the time it
    /// covers; at most one per kind.
    pub fn take(&self) -> Vec<Summary> {
        let mut states = self.states.each_ref().map(locked);
        let now = Timestamp::now();
        let mut out = Vec::new();
        for kind in Refused::ALL {
            let contended = self.contended[kind as usize].swap(0, Ordering::Relaxed);
            if contended > 0 {
                let (_, fold) =
                    states[0].folds[kind as usize].get_or_insert_with(|| (now, Fold::default()));
                fold.refusals = fold.refusals.saturating_add(contended);
                fold.unlisted = fold.unlisted.saturating_add(contended);
            }
            let [claimed, verified] = states
                .each_mut()
                .map(|budget| budget.folds[kind as usize].take());
            let from = [&claimed, &verified]
                .into_iter()
                .flatten()
                .map(|(from, _)| *from)
                .min();
            if let Some(from) = from {
                out.push(Summary {
                    kind,
                    from,
                    to: now,
                    sources: [claimed, verified]
                        .map(|fold| fold.map_or_else(Fold::default, |(_, fold)| fold)),
                });
            }
        }
        out
    }

    /// Keeps a summary the store refused: the next one of its kind starts at its time and
    /// counts its refusals too.
    pub fn keep(&self, summary: Summary) {
        for (state, mut fold) in self.states.iter().zip(summary.sources) {
            let mut budget = locked(state);
            let slot = &mut budget.folds[summary.kind as usize];
            if let Some((_, newer)) = slot.take() {
                fold.merge(newer);
            }
            if fold.refusals > 0 {
                *slot = Some((summary.from, fold));
            }
        }
    }
}

/// Audit records written to the store of this process as the DNS component, refusals
/// through a [`RefusalLimiter`] so that a scan cannot fill the audit log, with the summaries
/// written every [`SUMMARY_PERIOD`]. The writes run on the runtime the audit was made on:
/// the UDP workers that record refusals are plain threads without one. A write the store
/// refuses is logged at most once a minute; a refused summary is kept for the next.
pub struct StoreAudit {
    inner: Arc<Shared>,
}

struct Shared {
    store: Arc<dyn Store>,
    refusals: RefusalLimiter,
    runtime: Option<tokio::runtime::Handle>,
    /// The minute (from the limiter's start, plus one) of the last failure logged.
    logged: AtomicU64,
}

impl StoreAudit {
    /// Records into `store`, on the runtime of the caller, which also writes the summaries.
    pub fn new(store: Arc<dyn Store>) -> Self {
        let inner = Arc::new(Shared {
            store,
            refusals: RefusalLimiter::default(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            logged: AtomicU64::new(0),
        });
        if let Some(runtime) = &inner.runtime {
            let shared = Arc::downgrade(&inner);
            runtime.spawn(async move {
                let mut ticks = tokio::time::interval(SUMMARY_PERIOD);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticks.tick().await;
                loop {
                    ticks.tick().await;
                    let Some(shared) = shared.upgrade() else {
                        return;
                    };
                    shared.flush().await;
                }
            });
        }
        Self { inner }
    }

    /// Writes the summaries of the refusals folded since the last time (every
    /// [`SUMMARY_PERIOD`] on its own).
    pub async fn flush(&self) {
        self.inner.flush().await;
    }
}

impl Shared {
    async fn flush(&self) {
        for summary in self.refusals.take() {
            if let Err(error) = write(self.store.as_ref(), summary.draft()).await {
                self.failed(&error, summary.refusals());
                self.refusals.keep(summary);
            }
        }
    }

    /// Logs a refused write, once a minute at most; true when it logged.
    fn failed(&self, error: &StoreError, refusals: u64) -> bool {
        let minute = self.refusals.start.elapsed().as_secs() / 60 + 1;
        let log = self.logged.swap(minute, Ordering::Relaxed) != minute;
        if log {
            tracing::warn!(%error, refusals, "an audit record of the DNS role could not be written (the summaries of refusals are kept and written later)");
        }
        log
    }
}

async fn write(store: &dyn Store, draft: AuditDraft) -> Result<(), StoreError> {
    let cx = RequestCtx::system(SystemComponent::Dns);
    let mut batch = WriteBatch::for_request(&cx);
    batch.audit(draft);
    store.propose(batch).await.map(drop)
}

impl StoreAudit {
    /// Writes `draft` off the caller's thread; a refusal (`kind`, client, over UDP) whose
    /// record the store refuses is counted in its kind's summary instead.
    fn write_later(&self, draft: AuditDraft, refusal: Option<(Refused, IpAddr, bool)>) {
        let Some(runtime) = tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.inner.runtime.clone())
        else {
            tracing::warn!(action = %draft.action, "an audit record of the transfer path has no runtime to be written on");
            return;
        };
        let shared = Arc::clone(&self.inner);
        runtime.spawn(async move {
            if let Err(error) = write(shared.store.as_ref(), draft).await {
                shared.failed(&error, u64::from(refusal.is_some()));
                if let Some((kind, client, claimed)) = refusal {
                    shared.refusals.fold(kind, client, claimed);
                }
            }
        });
    }
}

impl TransferAudit for StoreAudit {
    fn record(&self, draft: AuditDraft) {
        self.write_later(draft, None);
    }

    fn refused(&self, kind: Refused, conn: &Conn, draft: &dyn Fn() -> AuditDraft) -> bool {
        let (client, claimed) = (conn.client.ip(), conn.transport == QueryTransport::Udp);
        let due = self.inner.refusals.due(kind, client, claimed);
        if due {
            self.write_later(with_source(draft(), conn), Some((kind, client, claimed)));
        }
        due
    }
}

/// The zone rows and TSIG keys the transfer path reads, swapped whole.
#[derive(Debug, Default)]
pub struct Directory {
    zones: ArcSwap<ZoneTable>,
    keys: Keyring,
}

/// The zones by apex in lowercase wire form and by id.
#[derive(Debug, Default)]
pub struct ZoneTable {
    by_apex: HashMap<Box<[u8]>, Arc<Zone>>,
    by_id: HashMap<ZoneId, Arc<Zone>>,
}

impl ZoneTable {
    /// The table of `zones`.
    pub fn new(zones: impl IntoIterator<Item = Zone>) -> Self {
        let mut table = Self::default();
        for zone in zones {
            let zone = Arc::new(zone);
            table
                .by_apex
                .insert(zone.name.to_wire().into(), Arc::clone(&zone));
            table.by_id.insert(zone.id, zone);
        }
        table
    }

    /// The zone whose apex is `apex` (lowercase wire form).
    pub fn by_apex(&self, apex: &[u8]) -> Option<&Arc<Zone>> {
        self.by_apex.get(apex)
    }

    /// The zone of an id.
    pub fn by_id(&self, id: ZoneId) -> Option<&Arc<Zone>> {
        self.by_id.get(&id)
    }
}

impl Directory {
    /// A directory of `zones` and `keys` (tests and tools; the role follows the store).
    pub fn new(
        zones: impl IntoIterator<Item = Zone>,
        keys: impl IntoIterator<Item = TsigKey>,
    ) -> Self {
        let directory = Self::default();
        directory.zones.store(Arc::new(ZoneTable::new(zones)));
        directory.keys.replace(keys);
        directory
    }

    /// The zones.
    pub fn zones(&self) -> arc_swap::Guard<Arc<ZoneTable>> {
        self.zones.load()
    }

    /// The TSIG keys.
    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Reads the zones and the keys again: the keys' secrets come from the vault through
    /// the zone service, reused from `cache` while a key's secret reference is unchanged.
    ///
    /// # Errors
    ///
    /// The store's or the vault's error as text.
    pub async fn load(
        &self,
        zones: &ZoneService,
        cache: &mut HashMap<KeyName, (KeyMeta, Arc<TsigKey>)>,
    ) -> Result<(), String> {
        let view = zones.view(None).await.map_err(|error| error.to_string())?;
        let rows: Vec<Zone> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, zone, _)| zone)
            .collect();
        let metas: Vec<KeyMeta> = view
            .scan_typed(&KEYS_META, KeyRange::all(), usize::MAX, false)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(_, key, _)| key)
            .collect();
        drop(view);
        cache.retain(|name, (meta, _)| metas.iter().any(|m| &m.name == name && m == meta));
        for meta in &metas {
            if cache.contains_key(&meta.name) {
                continue;
            }
            match zones.tsig_key(meta).await {
                Ok(key) => {
                    cache.insert(meta.name.clone(), (meta.clone(), Arc::new(key)));
                }
                Err(error) => {
                    tracing::warn!(key = %meta.name, %error, "a TSIG key could not be read from the vault");
                }
            }
        }
        self.zones.store(Arc::new(ZoneTable::new(rows)));
        self.keys
            .replace_shared(cache.values().map(|(_, key)| Arc::clone(key)));
        Ok(())
    }

    /// Keeps the directory current until `stop`: read at once, then again after every
    /// change of the zones or keys and at least every 30 seconds.
    pub async fn follow(self: Arc<Self>, zones: Arc<ZoneService>, stop: CancellationToken) {
        let mut cache = HashMap::new();
        let mut follow = Follow::new(
            Arc::clone(zones.store()),
            WatchFilter::tables([ZONES.name().clone(), KEYS_META.name().clone()]),
            "the transfer path's zones and keys",
        );
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                _ = follow.next() => {}
                () = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
            if let Err(error) = self.load(&zones, &mut cache).await {
                tracing::warn!(%error, "the zones and keys of the transfer path could not be read");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Metrics

/// `tenko_dns_xfr_total{kind,outcome}`: transfers and NOTIFY messages by kind and outcome.
pub const XFR: Desc = Desc::counter("tenko_dns_xfr", "DNS zone transfers and NOTIFY messages")
    .labels(&["kind", "outcome"]);

/// `tenko_dns_xfr_bytes_total{direction}`: octets of transfer messages.
pub const XFR_BYTES: Desc = Desc::counter(
    "tenko_dns_xfr_bytes",
    "Octets of DNS zone transfer messages",
)
.labels(&["direction"]);

/// The `kind` label values, in the order of [`MetricKind`].
pub const KINDS: [&str; 6] = [
    "axfr_out",
    "ixfr_out",
    "axfr_in",
    "ixfr_in",
    "notify_out",
    "notify_in",
];

/// The `outcome` label values, in the order of [`Outcome`].
pub const OUTCOMES: [&str; 4] = ["ok", "current", "refused", "failed"];

/// A kind of the transfer counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MetricKind {
    /// AXFR answered (an IXFR answered in AXFR form counts here).
    AxfrOut = 0,
    /// IXFR answered with a delta or the SOA.
    IxfrOut = 1,
    /// AXFR received.
    AxfrIn = 2,
    /// IXFR received.
    IxfrIn = 3,
    /// NOTIFY sent.
    NotifyOut = 4,
    /// NOTIFY received.
    NotifyIn = 5,
}

/// An outcome of the transfer counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Outcome {
    /// Done.
    Ok = 0,
    /// The copy was current; nothing moved.
    Current = 1,
    /// Refused (access lists, TSIG, the other side).
    Refused = 2,
    /// Failed (no answer, a malformed answer).
    Failed = 3,
}

static SERIES: [[&str; 2]; 24] = {
    let mut rows = [["", ""]; 24];
    let mut kind = 0;
    while kind < 6 {
        let mut outcome = 0;
        while outcome < 4 {
            rows[kind * 4 + outcome] = [KINDS[kind], OUTCOMES[outcome]];
            outcome += 1;
        }
        kind += 1;
    }
    rows
};

/// [`XFR`].
pub static XFR_COUNTER: CounterVec = CounterVec::new(XFR);

/// [`XFR_BYTES`] by direction: 0 out, 1 in.
pub static XFR_BYTES_COUNTER: CounterVec = CounterVec::fixed(XFR_BYTES, &[&["out"], &["in"]]);

/// Counts one transfer or NOTIFY.
pub fn count(kind: MetricKind, outcome: Outcome) {
    XFR_COUNTER.inc(kind as u16 * 4 + outcome as u16);
}

/// Counts octets of transfer messages: `inbound` for received ones.
pub fn count_bytes(inbound: bool, bytes: usize) {
    XFR_BYTES_COUNTER.add(u16::from(inbound), u64::try_from(bytes).unwrap_or(u64::MAX));
}

/// Seals the transfer families.
pub fn seal_metrics() {
    let series: Vec<&[&str]> = SERIES.iter().map(|row| &row[..]).collect();
    XFR_COUNTER.seal(&series);
    XFR_BYTES_COUNTER.add(0, 0);
}

/// Seals the transfer families and registers them with `registry`.
pub fn register_metrics(registry: &Registry) {
    seal_metrics();
    registry.register(&XFR_COUNTER);
    registry.register(&XFR_BYTES_COUNTER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::write_query;

    #[test]
    fn the_transfer_path_takes_axfr_ixfr_and_notify_only() {
        let mut out = Vec::new();
        write_query(&mut out, 1, "example.test", 252, None);
        assert_eq!(classify(&out), Some(Kind::Axfr));
        write_query(&mut out, 1, "example.test", 251, None);
        assert_eq!(classify(&out), Some(Kind::Ixfr));
        write_query(&mut out, 1, "example.test", 1, None);
        assert_eq!(classify(&out), None);
        message::write_request(
            &mut out,
            1,
            message::OPCODE_NOTIFY,
            b"\x04test\x00",
            6,
            None,
        );
        assert_eq!(classify(&out), Some(Kind::Notify));
        out[2] |= 0x80;
        assert_eq!(classify(&out), None, "a response is not for the path");
        assert_eq!(classify(&[0; 3]), None);
    }

    /// The UDP workers are plain threads: a refusal recorded there is written all the same,
    /// on the runtime the audit was made on.
    #[tokio::test]
    async fn an_audit_recorded_on_a_thread_without_a_runtime_is_written() {
        use futures::StreamExt as _;
        let store = Arc::new(tenko_store::MemStore::default());
        let mut changes = store.watch(None, WatchFilter::all()).expect("watch");
        let audit = Arc::new(StoreAudit::new(Arc::clone(&store) as Arc<dyn Store>));
        let worker = Arc::clone(&audit);
        std::thread::spawn(move || {
            worker.record(AuditDraft::success(
                tenko_core::dns::audit::TRANSFER_TRIGGER,
                Vec::new(),
            ));
        })
        .join()
        .expect("the worker");
        let written = tokio::time::timeout(Duration::from_secs(30), changes.next())
            .await
            .expect("the record is written");
        assert!(matches!(written, Some(Ok(_))), "{written:?}");
    }

    fn due(limiter: &RefusalLimiter, client: IpAddr, minute: u64) -> bool {
        limiter.due_at(Refused::Update, client, true, minute)
    }

    fn context<'a>(draft: &'a AuditDraft, key: &str) -> &'a str {
        draft.details.context.get(key).map_or("", String::as_str)
    }

    #[test]
    fn a_clients_first_refusal_of_the_hour_is_recorded_and_the_rest_summarized() {
        let limiter = RefusalLimiter::default();
        let client = IpAddr::from([192, 0, 2, 7]);
        assert!(due(&limiter, client, 0));
        assert!(!due(&limiter, client, 0), "once an hour per client");
        let mapped = IpAddr::from(std::net::Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
        assert!(
            !due(&limiter, mapped, 0),
            "a mapped address is the same client"
        );
        assert!(!due(&limiter, client, 59));
        assert!(due(&limiter, client, 60), "the next hour");
        let summary = limiter.take();
        assert_eq!(summary.len(), 1, "one summary per kind");
        let draft = summary[0].draft();
        assert_eq!(draft.action, audit::UPDATE_REFUSE);
        assert_eq!(context(&draft, "refusals"), "3");
        assert_eq!(context(&draft, "claimed"), "3");
        assert_eq!(context(&draft, "claimed_clients"), "1");
        assert_eq!(context(&draft, "claimed_top"), "192.0.2.7 3");
        assert_eq!(context(&draft, "verified"), "0");
        assert!(limiter.take().is_empty(), "nothing folded since");
    }

    /// 100,000 invented UDP sources in a minute, refused transfers and TKEY negotiations
    /// beside them, and 1,000 sources over TCP write ten records of their own of each kind
    /// of source and one summary per action: twenty-three in all. A summary counts every
    /// refusal, and lists the first clients and the top five.
    #[test]
    fn a_flood_over_both_transports_writes_twenty_three_records_a_minute() {
        let limiter = RefusalLimiter::default();
        let recorded = (0..100_000u32)
            .filter(|n| due(&limiter, IpAddr::from(n.to_be_bytes()), 0))
            .count();
        assert_eq!(recorded, REFUSALS_PER_MINUTE);
        for _ in 0..3 {
            due(&limiter, IpAddr::from([198, 51, 100, 1]), 0);
        }
        // The same minute's refused transfers and TKEY negotiations: a summary each.
        for kind in [Refused::Transfer, Refused::Gss] {
            for n in 0..1_000u32 {
                limiter.due_at(kind, IpAddr::from((n | 0x0a00_0000).to_be_bytes()), true, 0);
            }
        }
        let verified = (0..1_000u32)
            .filter(|n| limiter.due_at(Refused::Update, spoofed(*n), false, 0))
            .count();
        assert_eq!(verified, REFUSALS_PER_MINUTE);
        let summaries = limiter.take();
        assert_eq!(
            recorded + verified + summaries.len(),
            23,
            "the records of the minute"
        );
        let draft = summaries[Refused::Update as usize].draft();
        assert_eq!(context(&draft, "refusals"), "100983");
        assert_eq!(context(&draft, "claimed"), "99993");
        assert_eq!(context(&draft, "verified"), "990");
        assert_eq!(
            context(&draft, "claimed_clients"),
            SUMMARY_CLIENTS.to_string()
        );
        let unlisted: u64 = context(&draft, "claimed_unlisted").parse().expect("count");
        assert_eq!(unlisted, 99_993 - SUMMARY_CLIENTS as u64);
        let top: Vec<&str> = context(&draft, "claimed_top").split(", ").collect();
        assert_eq!(top.len(), SUMMARY_TOP);
        assert_eq!(top[0], "0.0.0.10 1");
    }

    /// The memory holds every client recorded within the hour, so a flood that takes most
    /// of each minute's budget does not make it forget a real client early; and it never
    /// holds more than an hour of records.
    #[test]
    fn the_memory_of_recorded_clients_holds_an_hour_and_no_more() {
        let limiter = RefusalLimiter::default();
        let client = IpAddr::from([192, 0, 2, 7]);
        let mut spoofed = 0u32;
        assert!(due(&limiter, client, 0));
        for minute in 0..120 {
            for _ in 0..REFUSALS_PER_MINUTE - 1 {
                spoofed += 1;
                due(
                    &limiter,
                    IpAddr::from((spoofed | 0x0a00_0000).to_be_bytes()),
                    minute,
                );
            }
            assert_eq!(
                due(&limiter, client, minute),
                minute == 60,
                "minute {minute}"
            );
            let held = limiter.states[0].lock().expect("state").seen.len();
            assert!(held <= REFUSALS_REMEMBERED, "{held} at minute {minute}");
        }
    }

    /// A record of its own says whether its client's address is real (TCP or TLS) or only
    /// claimed (UDP).
    #[tokio::test]
    async fn a_refusal_recorded_on_its_own_says_whether_its_source_is_real() {
        use futures::StreamExt as _;
        let store = Arc::new(tenko_store::MemStore::default());
        let mut changes = store.watch(None, WatchFilter::all()).expect("watch");
        let audit = StoreAudit::new(Arc::clone(&store) as Arc<dyn Store>);
        let local = "192.0.2.1:53".parse().expect("address");
        for (last, transport, source) in [
            (7, QueryTransport::Udp, "claimed"),
            (8, QueryTransport::Tcp, "verified"),
        ] {
            let client = std::net::SocketAddr::from(([192, 0, 2, last], 5353));
            let conn = crate::update::conn(client, local, transport);
            let draft = || AuditDraft::denied(audit::UPDATE_REFUSE, Vec::new());
            assert!(audit.refused(Refused::Update, &conn, &draft));
            tokio::time::timeout(Duration::from_secs(30), changes.next())
                .await
                .expect("the record is written");
            let view = store.read(ReadConsistency::Local).await.expect("view");
            let (_, record, _) = view
                .scan_typed(
                    &tenko_store::tables::AUDIT,
                    KeyRange::all(),
                    usize::MAX,
                    true,
                )
                .expect("audit")
                .into_iter()
                .next()
                .expect("a record");
            assert_eq!(context(&record.draft, "source"), source);
        }
    }

    #[test]
    fn a_refusal_counted_while_another_worker_holds_the_state_is_summarized() {
        let limiter = RefusalLimiter::default();
        let held = limiter.states[0].lock().expect("state");
        assert!(!due(&limiter, IpAddr::from([192, 0, 2, 7]), 0));
        drop(held);
        let draft = limiter.take()[0].draft();
        assert_eq!(context(&draft, "refusals"), "1");
        assert_eq!(context(&draft, "claimed_unlisted"), "1");
    }

    /// The largest summary record, measured: both rooms full of the longest addresses with
    /// the largest counts; and a kept summary merged with as large a newer one keeps its
    /// room, so its memory stays bounded however long the store refuses it.
    #[test]
    fn the_largest_summary_record_stays_under_four_kib() {
        let full = |base: u16| Fold {
            refusals: u64::MAX,
            clients: (0..SUMMARY_CLIENTS)
                .map(|n| {
                    let last = u16::try_from(n).expect("an address") | base;
                    let address = [0xfedc; 7].into_iter().chain([last]).collect::<Vec<u16>>();
                    let address: [u16; 8] = address.try_into().expect("eight groups");
                    (IpAddr::from(address), u64::MAX / 2)
                })
                .collect(),
            unlisted: u64::MAX,
        };
        let now = Timestamp::now();
        let summary = Summary {
            kind: Refused::Transfer,
            from: now,
            to: now,
            sources: [full(0x8000), full(0x9000)],
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Dns));
        batch.audit(summary.draft());
        let size = batch.payload_size();
        eprintln!("the largest summary record: {size} bytes");
        assert!(size <= 4_096, "{size} bytes");
        let mut kept = full(0x8000);
        kept.merge(full(0xa000));
        assert_eq!(kept.clients.len(), SUMMARY_CLIENTS);
    }

    fn spoofed(n: u32) -> IpAddr {
        IpAddr::from((n | 0x0a00_0000).to_be_bytes())
    }

    /// One UDP refusal sent in a secondary's name, and a flood that takes every claimed
    /// record of the minute, leave the secondary's own refusal over TCP its record; and a
    /// verified refusal never waits on the lock a UDP flood holds, nor loses its address.
    #[test]
    fn a_claimed_source_never_costs_a_verified_one_its_record() {
        let limiter = RefusalLimiter::default();
        let secondary = IpAddr::from([192, 0, 2, 53]);
        assert!(limiter.due_at(Refused::Transfer, secondary, true, 0));
        for n in 0..1_000 {
            limiter.due_at(Refused::Transfer, spoofed(n), true, 0);
        }
        let held = limiter.states[0].lock().expect("state");
        assert!(limiter.due_at(Refused::Transfer, secondary, false, 0));
        assert!(!limiter.due_at(Refused::Transfer, secondary, false, 0));
        drop(held);
        let draft = limiter.take()[0].draft();
        assert_eq!(context(&draft, "verified_top"), "192.0.2.53 1");
    }

    /// Fifteen spoofed UDP packets a minute (ten sources that take the claimed records, five
    /// that fill the claimed top) keep no verified refusal out of the log by address: its
    /// first is recorded on its own, the later ones are listed in every summary.
    /// One host on an IPv6 link connects from ten fresh addresses a minute for an hour, and
    /// from 32 more twice each: its addresses are one client, its /64, so a real secondary's
    /// first refusal in the last minute is recorded on its own and its next one listed.
    #[test]
    fn fresh_addresses_of_one_link_count_as_one_verified_client() {
        let limiter = RefusalLimiter::default();
        let link = |n: u16| IpAddr::from(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 1, n));
        let secondary = IpAddr::from(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0x53, 0, 0, 0, 0x53,
        ));
        for minute in 0..60u16 {
            for n in 0..10 {
                limiter.due_at(
                    Refused::Transfer,
                    link(minute * 10 + n),
                    false,
                    minute.into(),
                );
            }
            for n in 0..32 {
                for _ in 0..2 {
                    limiter.due_at(Refused::Transfer, link(1_000 + n), false, minute.into());
                }
            }
            if minute < 59 {
                limiter.take();
            }
        }
        assert!(limiter.due_at(Refused::Transfer, secondary, false, 59));
        assert!(!limiter.due_at(Refused::Transfer, secondary, false, 59));
        let draft = limiter.take()[0].draft();
        let top = context(&draft, "verified_top");
        assert!(top.contains("2001:db8:0:53::/64 1"), "{top}");
        assert_eq!(context(&draft, "verified_clients"), "2", "{top}");
    }

    #[test]
    fn fifteen_spoofed_packets_a_minute_keep_no_verified_refusal_from_the_summary() {
        let limiter = RefusalLimiter::default();
        let secondary = IpAddr::from([192, 0, 2, 53]);
        for minute in 0..3u32 {
            for n in 0..10 {
                limiter.due_at(
                    Refused::Transfer,
                    spoofed(minute * 100 + n),
                    true,
                    minute.into(),
                );
            }
            for n in 1..=5 {
                limiter.due_at(
                    Refused::Transfer,
                    IpAddr::from([0, 0, 0, n]),
                    true,
                    minute.into(),
                );
            }
            let recorded = limiter.due_at(Refused::Transfer, secondary, false, minute.into());
            assert_eq!(recorded, minute == 0, "minute {minute}");
            let summaries = limiter.take();
            let draft = summaries[0].draft();
            assert_eq!(
                context(&draft, "claimed_top").split(", ").count(),
                SUMMARY_TOP
            );
            if minute > 0 {
                assert_eq!(context(&draft, "verified_top"), "192.0.2.53 1");
            }
        }
    }

    /// On a Raft store below its disk margin, which refuses every audit record: a refusal
    /// is answered at once and counted in its kind's summary, the summary is kept (one per
    /// kind, however many flushes the store refuses), the failures are logged once in the
    /// minute, and the summary is written with its own time once the disk has room.
    #[tokio::test]
    async fn below_the_disk_margin_a_refusal_summary_is_kept_and_written_with_room() {
        use tenko_core::testing::wait_until_async;
        use tenko_store::{
            Pressure,
            raft::{RaftStore, RaftStoreConfig},
            test_hooks::FREE_BYTES,
        };
        let mut config = RaftStoreConfig::new("unused");
        config.fsync_probe_samples = 0;
        let raft = Arc::new(RaftStore::open_temp(config).await.expect("open"));
        let free = async |bytes: u64, pressure: Pressure| {
            let file = raft.config().data_dir.join(FREE_BYTES);
            std::fs::write(file, bytes.to_string()).expect("the free space");
            wait_until_async("the store reads its free space", async || {
                let safety = raft.safety().expect("safety");
                safety.free_bytes == bytes && safety.pressure == pressure
            })
            .await;
        };
        let reserve = raft.safety().expect("safety").reserve_bytes;
        free(reserve / 2 * 3, Pressure::Margin).await;

        let audit = StoreAudit::new(Arc::clone(&raft) as Arc<dyn Store>);
        let conn = crate::update::conn(
            "192.0.2.7:5353".parse().expect("client"),
            "192.0.2.1:53".parse().expect("local"),
            QueryTransport::Udp,
        );
        let draft = || AuditDraft::denied(audit::UPDATE_REFUSE, Vec::new());
        assert!(
            audit.refused(Refused::Update, &conn, &draft),
            "its own record"
        );
        assert!(!audit.refused(Refused::Update, &conn, &draft));
        assert!(!audit.refused(Refused::Update, &conn, &draft));
        let kept = || {
            audit.inner.refusals.states[0].lock().expect("state").folds[Refused::Update as usize]
                .clone()
        };
        let folded = || kept().map_or(0, |(_, fold)| fold.refusals);
        // The refused record of its own joins the summary.
        wait_until_async("the refused record folded", async || folded() == 3).await;
        audit.flush().await;
        audit.flush().await;
        assert_eq!(folded(), 3, "kept once");
        assert!(
            !audit.inner.failed(&StoreError::NoQuorum, 0),
            "the minute's failures are logged once"
        );
        let (from, _) = kept().expect("kept");

        free(u64::MAX, Pressure::Normal).await;
        audit.flush().await;
        let view = raft.read(ReadConsistency::Local).await.expect("view");
        let records: Vec<AuditDraft> = view
            .scan_typed(
                &tenko_store::tables::AUDIT,
                KeyRange::all(),
                usize::MAX,
                false,
            )
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record.draft)
            .filter(|draft| draft.action == audit::UPDATE_REFUSE)
            .collect();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(context(&records[0], "refusals"), "3");
        assert_eq!(context(&records[0], "from"), from.to_string());
    }

    #[test]
    fn the_transfer_families_encode() {
        let registry = Registry::new();
        register_metrics(&registry);
        count(MetricKind::IxfrOut, Outcome::Ok);
        count_bytes(false, 512);
        let mut text = String::new();
        tenko_core::metrics::encode(&registry.snapshot(), &mut text);
        tenko_core::metrics::check(&text).expect("valid OpenMetrics");
        assert!(text.contains("tenko_dns_xfr_total{kind=\"ixfr_out\",outcome=\"ok\"}"));
        assert!(text.contains("tenko_dns_xfr_bytes_total{direction=\"out\"}"));
    }
}
