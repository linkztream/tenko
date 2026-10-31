//! Leases as observations (plan section 2.8, ADR 0031): the lease tables are the observation
//! source `dhcp:<node>` ([`ObservationSource::DhcpLease`]), read through [`LeaseFacts`], a
//! view that presents each lease row as the facts it stands for. The `dhcp` role writes no
//! fact rows (it did from WP8.1 to ADR 0030: four facts and their index rows per change, a
//! copy of what the lease row holds).
//!
//! # The facts of a lease
//!
//! | Subject | Fact | Current while |
//! |---|---|---|
//! | `address:<vrf>/<ip>` | `Observed::Address` with the lease's address and the client's MAC | the binding holds (`active` until its end) |
//! | `name:<ip>` | `Observed::Name` with the client's FQDN (option 81), else its host name (option 12) | the binding holds and the client sent a name |
//! | `address:<vrf>/<ip>` | `Observed::Address` with the MAC address that answered the conflict probe (an ARP answer), else none (ICMP, a DECLINE) | the row is `abandoned` (a conflict, WP8.5), until its hold ends |
//! | `os:<ip>` | `Observed::Os` with the guess of the lease's fingerprint (options 55, 60, 77, 81, 93) and its confidence | the binding holds and the [`LeaseClassifier`] knows the fingerprint (WP8.2) |
//! | `vendor:<mac>` | `Observed::Vendor` with the vendor class of option 60 | the binding holds, the client has a MAC address and sent a vendor class (WP8.2) |
//!
//! A DHCPv6 address lease (WP9.1) gives the address and name facts by the same rules: the
//! address fact of its IPv6 address carries the client's MAC address from its link-layer
//! address (the Client Link-Layer Address option a relay added, RFC 6939, else its DUID-LLT
//! or DUID-LL), so that the reconciler sees the DHCPv4 and the DHCPv6 address of one device
//! under one MAC (DHCP-11); the name fact is the name of RFC 4704. A delegated prefix (WP9.2,
//! an `IA_PD` binding) is no address in use: its fact is `Observed::Network` with the prefix
//! as the subnet, under the subject `network:dhcp-pd/<vrf>/<prefix>/<length>`, named by the
//! router's link-layer address or DUID. The reconciler reads network facts of network
//! controllers only, so a delegation never becomes a proposal.
//!
//! # The rules of the view
//!
//! The rules of [`super::ingest()`] became the rules of the view: the lease row is the fact.
//!
//! - **Times.** A fact's `last_seen` (and `received_at`) is the row's client transaction
//!   time, its `first_seen` the row's grant time (`granted`, the first grant of the current
//!   binding; a row of an earlier version reads as granted at its `cltt`), its revision the
//!   row's.
//! - **Current.** A binding fact expires at the binding's end (`ends` of an `active` row), so
//!   a binding that runs out takes its facts with it without a write; a conflict's address
//!   fact at the end of its hold. A row that no longer binds (released, expired, reset) stands
//!   for facts that expired at its client transaction time or its end, whichever came
//!   first; an `abandoned` row (a conflict or a decline) for the conflict's address fact
//!   until its hold ends; a `free` or `backup` row for none.
//! - **Retention.** A row whose facts ended longer ago than the observation retention
//!   ([`ObserveConfig::retention`], 30 days; the reconciler hands over the setting in force
//!   with [`LeaseFacts::set_retention`]) is not presented at all, as a stored fact whose last
//!   sighting is older is purged; the build at start leaves such rows out too. Lease rows
//!   are never deleted, so without the cut a released address would show for ever.
//! - **Sightings.** A sighting counts once per refresh interval ([`ObserveConfig::refresh`]):
//!   a binding held from its grant to its last transaction counts one sighting plus one per
//!   interval in between.
//! - **The observation id** is derived from the source, the subject, the grant time and the
//!   reported attributes: it changes when the binding or what it reports changes, as the
//!   ingest's id did.
//! - Two rows of one node that give the same subject (the name of one address in two VRFs,
//!   the vendor of one MAC address on two leases) give one fact: the current one, else the
//!   most recently seen.
//!
//! # The view
//!
//! [`LeaseFacts`] keeps one compact entry per lease row of `dhcp.leases` and `dhcp.leases6`
//! (the node, the state, the times, the MAC address, the name, the vendor class, the OS
//! guess) and builds the facts when they are read. It is built from the lease tables when it
//! starts and follows the lease changes of the store's journal ([`Store::watch`], the stream
//! the API's event stream reads), off the store's apply path; a stream that ends with
//! `Lagged` or `Compacted` (a snapshot install, a follower that fell behind) rebuilds it from
//! the tables. [`LeaseFacts::caught_up`] waits until it has followed a revision, so a reader
//! with a read view sees the leases of that view. [`LeaseFacts::changes`] wakes the
//! reconciler after a lease change, as the fact changes did.
//!
//! The guess comes from the classifier the server hands the view ([`LeaseFacts::set_classifier`],
//! the rule table of `tenko_dhcp::fingerprint`) before it starts; without one there is no OS
//! fact.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, OnceLock, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use futures::{FutureExt as _, StreamExt as _};
use tenko_core::{
    MacAddr, NodeId, ObservationId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Fingerprint, Lease, Lease6, Lease6Kind, tables},
    observe::{NetworkDhcp, ObservationSource, Observed},
};
use tenko_store::{
    ChangeSet, KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, WatchFilter,
};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use super::{
    ObserveConfig,
    model::{FactSubject, ObservedFact, observed_ips, observed_macs, observed_name},
};

/// Rows read per page when the view is built.
const PAGE: usize = 4_096;

/// How long a reader waits for the view to follow the revision of its read view.
pub const CATCH_UP_WAIT: Duration = Duration::from_secs(1);

/// Change sets the follower takes from the stream before it reads their rows.
const DRAIN: usize = 4_096;

/// An OS guess for a lease's fingerprint (DHCP-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsReading {
    /// The guess as a person reads it, such as `Windows 10 or 11`.
    pub guess: String,
    /// How strong the match is, 0 to 100.
    pub confidence: u8,
}

/// Maps a lease's fingerprint to an OS guess: the rule table of `tenko_dhcp::fingerprint`
/// (P3-Q15), handed to [`LeaseFacts::set_classifier`] by the server.
pub trait LeaseClassifier: Send + Sync {
    /// The guess, or `None` when no rule knows the fingerprint.
    fn os(&self, fingerprint: &Fingerprint) -> Option<OsReading>;
}

/// The vendor class a lease reports (option 60), without surrounding blanks; `None` when
/// the client sent none or only blanks.
pub fn lease_vendor(lease: &Lease) -> Option<String> {
    lease
        .fingerprint
        .as_ref()
        .and_then(|fingerprint| fingerprint.vendor_class.as_deref())
        .map(str::trim)
        .filter(|vendor| !vendor.is_empty())
        .map(str::to_owned)
}

/// The client's MAC address, when its hardware type is Ethernet (of an abandoned row: the
/// MAC address that answered the conflict probe, when ARP gave one).
pub fn lease_mac(lease: &Lease) -> Option<MacAddr> {
    lease.client.mac().map(MacAddr::new)
}

/// The name a lease reports: the FQDN of option 81, else the host name of option 12,
/// without a trailing dot; `None` when the client sent neither or only blanks.
pub fn lease_name(lease: &Lease) -> Option<String> {
    [lease.fqdn.as_deref(), lease.hostname.as_deref()]
        .into_iter()
        .flatten()
        .map(|name| name.trim().trim_end_matches('.'))
        .find(|name| !name.is_empty())
        .map(str::to_owned)
}

/// What a row binds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// A DHCPv4 address.
    V4,
    /// A DHCPv6 address (`IA_NA`).
    V6,
    /// A delegated prefix (`IA_PD`): its length and who holds it.
    Delegation { prefix_len: u8, holder: Box<str> },
}

/// What the view keeps of one lease row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    node: NodeId,
    state: BindingState,
    cltt: Timestamp,
    ends: Timestamp,
    granted: Timestamp,
    revision: Revision,
    mac: Option<MacAddr>,
    name: Option<Box<str>>,
    vendor: Option<Box<str>>,
    os: Option<(Box<str>, u8)>,
}

/// The entries by VRF and address (a delegated prefix by its first address).
#[derive(Debug, Default)]
struct Image {
    revision: Revision,
    entries: HashMap<(VrfId, IpAddr), Entry>,
}

/// What a subject query names: a MAC address, an IP address or a lowercase name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Naming {
    /// Facts that name this MAC address.
    Mac(MacAddr),
    /// Facts that name this IP address.
    Ip(IpAddr),
    /// Facts whose name is this one, compared without case.
    Name(String),
}

impl Naming {
    /// Whether `fact` names it, as the index tables of the stored facts say.
    pub fn names(&self, fact: &ObservedFact) -> bool {
        match self {
            Naming::Mac(mac) => observed_macs(&fact.observed).contains(mac),
            Naming::Ip(ip) => observed_ips(&fact.observed).contains(ip),
            Naming::Name(name) => observed_name(&fact.observed)
                .is_some_and(|own| own.trim().eq_ignore_ascii_case(name.trim())),
        }
    }
}

/// The lease view of every DHCP node (see the module documentation).
pub struct LeaseFacts {
    config: ObserveConfig,
    image: RwLock<Image>,
    classifier: OnceLock<Arc<dyn LeaseClassifier>>,
    /// The revision the view has followed to.
    followed: watch::Sender<Revision>,
    /// Whether a follower runs.
    following: AtomicBool,
    /// Builds of the view from the tables (the start, a lag, a snapshot install).
    builds: AtomicU64,
    /// Woken after a lease change.
    changes: Notify,
    /// The observation retention in seconds ([`ObserveConfig::retention`]): a row that
    /// ended longer ago is not presented.
    retention: AtomicU64,
}

impl std::fmt::Debug for LeaseFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseFacts")
            .field("config", &self.config)
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl LeaseFacts {
    /// An empty view under `config`; [`LeaseFacts::build`] or [`LeaseFacts::spawn`] fills it.
    pub fn new(config: ObserveConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            image: RwLock::new(Image::default()),
            classifier: OnceLock::new(),
            followed: watch::channel(Revision::ZERO).0,
            following: AtomicBool::new(false),
            builds: AtomicU64::new(0),
            changes: Notify::new(),
            retention: AtomicU64::new(config.retention.as_secs()),
        })
    }

    // The retention of the stored facts, applied to the lease rows.
    /// Sets the observation retention (the reconciler hands over the setting in force,
    /// [`ObserveConfig::retention`], the one its purge of the stored facts uses): a row whose
    /// facts ended longer ago than that is not presented, as a stored fact whose last
    /// sighting is older is purged.
    pub fn set_retention(&self, retention: Duration) {
        self.retention.store(retention.as_secs(), Ordering::Relaxed);
    }

    /// The observation retention in force.
    pub fn retention(&self) -> Duration {
        Duration::from_secs(self.retention.load(Ordering::Relaxed))
    }

    /// Whether the facts of `entry` are within the retention at `now`: a binding or a
    /// conflict that has not ended, or one that ended (at its end, or for a row that no
    /// longer binds at its client transaction time or its end, whichever came first) at most
    /// the retention ago.
    fn retained(&self, entry: &Entry, now: Timestamp) -> bool {
        let ended = match entry.state {
            BindingState::Active | BindingState::Abandoned => entry.ends,
            _ => entry.cltt.min(entry.ends),
        };
        ended >= now || now.saturating_since(ended) <= self.retention()
    }

    /// Sets the classifier of the fingerprints, once (later calls change nothing); `true`
    /// when this call set it. Set it before the follower starts: a followed view's entries
    /// read before keep no guess until their row changes; a view without a follower is
    /// built again by its next reader.
    pub fn set_classifier(&self, classifier: Arc<dyn LeaseClassifier>) -> bool {
        let set = self.classifier.set(classifier).is_ok();
        if set && !self.is_following() {
            self.write().revision = Revision::ZERO;
        }
        set
    }

    /// The revision the view has followed to.
    pub fn revision(&self) -> Revision {
        *self.followed.borrow()
    }

    /// Builds of the view from the lease tables since it was made.
    pub fn builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }

    /// Whether a follower keeps the view current ([`LeaseFacts::spawn`]).
    pub fn is_following(&self) -> bool {
        self.following.load(Ordering::Acquire)
    }

    /// Woken after every batch of lease changes the view took in: the reconciler's light
    /// run (the waiting moves).
    pub fn changes(&self) -> &Notify {
        &self.changes
    }

    /// The number of lease rows the view holds.
    pub fn len(&self) -> usize {
        self.read().entries.len()
    }

    /// Whether the view holds no lease row.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Image> {
        self.image.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Image> {
        self.image.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Builds the view from the lease tables of `view` and installs it whole.
    ///
    /// # Errors
    ///
    /// A storage or decoding failure of the scan.
    pub fn build(&self, view: &dyn ReadView) -> Result<(), StoreError> {
        let mut entries = HashMap::new();
        // The rows past the retention are not kept (the start's cut, as the readers' own).
        let now = Timestamp::now();
        let mut range = KeyRange::all();
        loop {
            let page = view.scan_typed(&tables::LEASES, range.clone(), PAGE, false)?;
            let full = page.len() == PAGE;
            let last = page.last().map(|(key, _, _)| tables::LEASES.key(key));
            for ((vrf, addr), lease, revision) in page {
                if let Some(entry) = self.entry4(&lease, revision)
                    && self.retained(&entry, now)
                {
                    entries.insert((vrf, IpAddr::V4(addr)), entry);
                }
            }
            match (full, last) {
                (true, Some(last)) => range = KeyRange::all().after(last),
                _ => break,
            }
        }
        let mut range = KeyRange::all();
        loop {
            let page = view.scan_typed(&tables::LEASES6, range.clone(), PAGE, false)?;
            let full = page.len() == PAGE;
            let last = page.last().map(|(key, _, _)| tables::LEASES6.key(key));
            for ((vrf, addr), lease, revision) in page {
                if let Some(entry) = entry6(&lease, revision)
                    && self.retained(&entry, now)
                {
                    entries.insert((vrf, IpAddr::V6(addr)), entry);
                }
            }
            match (full, last) {
                (true, Some(last)) => range = KeyRange::all().after(last),
                _ => break,
            }
        }
        let revision = view.revision();
        *self.write() = Image { revision, entries };
        self.builds.fetch_add(1, Ordering::Relaxed);
        self.followed.send_replace(revision);
        self.changes.notify_one();
        Ok(())
    }

    /// Starts the follower on the runtime: it builds the view from `store` and follows its
    /// lease changes until `stop` fires or the store shuts down.
    pub fn spawn(
        self: &Arc<Self>,
        store: Arc<dyn Store>,
        stop: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        self.following.store(true, Ordering::Release);
        tokio::spawn(Arc::clone(self).follow(store, stop))
    }

    /// The follower (see the module documentation).
    async fn follow(self: Arc<Self>, store: Arc<dyn Store>, stop: CancellationToken) {
        self.following.store(true, Ordering::Release);
        let mut retry = Duration::from_millis(100);
        loop {
            if stop.is_cancelled() {
                break;
            }
            match self.follow_once(store.as_ref(), &stop).await {
                Ok(Followed::Stopped) => break,
                Ok(Followed::Rebuild) => retry = Duration::from_millis(100),
                Err(error) => {
                    tracing::warn!(%error, "the lease view could not follow the store; it tries again");
                    tokio::select! {
                        () = stop.cancelled() => break,
                        () = tokio::time::sleep(retry) => {}
                    }
                    retry = (retry * 2).min(Duration::from_secs(5));
                }
            }
        }
        self.following.store(false, Ordering::Release);
    }

    /// One build and the following of the journal from it, until the stream ends.
    async fn follow_once(
        &self,
        store: &dyn Store,
        stop: &CancellationToken,
    ) -> Result<Followed, StoreError> {
        let view = store.read(ReadConsistency::Local).await?;
        self.build(view.as_ref())?;
        let from = view.revision();
        drop(view);
        let mut stream = store.watch(Some(from), WatchFilter::all())?;
        loop {
            let first = tokio::select! {
                () = stop.cancelled() => return Ok(Followed::Stopped),
                next = stream.next() => next,
            };
            let Some(first) = first else {
                // The store shuts down.
                return Ok(Followed::Stopped);
            };
            let mut sets = Vec::new();
            let mut failed = None;
            match first {
                Ok(set) => sets.push(set),
                Err(error) => failed = Some(error),
            }
            while failed.is_none() && sets.len() < DRAIN {
                match stream.next().now_or_never() {
                    Some(Some(Ok(set))) => sets.push(set),
                    Some(Some(Err(error))) => failed = Some(error),
                    Some(None) | None => break,
                }
            }
            if !sets.is_empty() {
                self.apply(store, &sets).await?;
            }
            if let Some(error) = failed {
                tracing::info!(%error, "the lease view rebuilds from the lease tables");
                return Ok(Followed::Rebuild);
            }
        }
    }

    /// Takes in the lease rows a run of change sets wrote, read from a view at least as new.
    async fn apply(&self, store: &dyn Store, sets: &[ChangeSet]) -> Result<(), StoreError> {
        let Some(last) = sets.last().map(|set| set.revision) else {
            return Ok(());
        };
        let mut keys4 = Vec::new();
        let mut keys6 = Vec::new();
        for change in sets.iter().flat_map(|set| &set.changes) {
            if change.table == *tables::LEASES.name() {
                if let Ok(key) = tables::LEASES.decode_key(&change.key) {
                    keys4.push(key);
                }
            } else if change.table == *tables::LEASES6.name()
                && let Ok(key) = tables::LEASES6.decode_key(&change.key)
            {
                keys6.push(key);
            }
        }
        if keys4.is_empty() && keys6.is_empty() {
            self.advance(last);
            return Ok(());
        }
        let view = store.read(ReadConsistency::AtLeast(last)).await?;
        let mut rows = Vec::with_capacity(keys4.len() + keys6.len());
        for (vrf, addr) in keys4 {
            let entry = view
                .get_typed(&tables::LEASES, &(vrf, addr))?
                .and_then(|(lease, revision)| self.entry4(&lease, revision));
            rows.push(((vrf, IpAddr::V4(addr)), entry));
        }
        for (vrf, addr) in keys6 {
            let entry = view
                .get_typed(&tables::LEASES6, &(vrf, addr))?
                .and_then(|(lease, revision)| entry6(&lease, revision));
            rows.push(((vrf, IpAddr::V6(addr)), entry));
        }
        drop(view);
        {
            let mut image = self.write();
            for (key, entry) in rows {
                match entry {
                    Some(entry) => {
                        // A later row never gives way to an earlier read of it.
                        if image
                            .entries
                            .get(&key)
                            .is_none_or(|held| held.revision <= entry.revision)
                        {
                            image.entries.insert(key, entry);
                        }
                    }
                    None => {
                        image.entries.remove(&key);
                    }
                }
            }
            image.revision = image.revision.max(last);
        }
        self.advance(last);
        self.changes.notify_one();
        Ok(())
    }

    fn advance(&self, revision: Revision) {
        self.followed.send_if_modified(|held| {
            if revision > *held {
                *held = revision;
                true
            } else {
                false
            }
        });
    }

    /// Waits until the view has followed `revision` (the revision of a reader's view), at
    /// most [`CATCH_UP_WAIT`]. `false` when it has not by then: the reader then reads the
    /// view as it is (its leases a little behind its read view), never fails its request,
    /// and the wait is logged at debug with the lag in revisions. A view without a follower
    /// answers at once.
    pub async fn caught_up(&self, revision: Revision) -> bool {
        if !self.is_following() {
            return self.revision() >= revision;
        }
        let mut followed = self.followed.subscribe();
        let wait = followed.wait_for(|held| *held >= revision);
        if matches!(tokio::time::timeout(CATCH_UP_WAIT, wait).await, Ok(Ok(_))) {
            return true;
        }
        let held = self.revision();
        tracing::debug!(
            wanted = revision.get(),
            followed = held.get(),
            lag = revision.get().saturating_sub(held.get()),
            "the lease view had not followed the reader's view in time; the reader reads it as it is"
        );
        false
    }

    /// Makes sure the view covers `view` when no follower keeps it current (a tool, a test):
    /// builds it from `view` when it is older. A followed view is left to its follower.
    ///
    /// # Errors
    ///
    /// A storage or decoding failure of the build.
    pub fn ensure(&self, view: &dyn ReadView) -> Result<(), StoreError> {
        if self.is_following() || self.read().revision >= view.revision() {
            return Ok(());
        }
        self.build(view)
    }

    /// Every fact the leases stand for, current or not, at `now`.
    pub fn facts(&self, now: Timestamp) -> Vec<ObservedFact> {
        self.select(now, |_| true)
    }

    /// The facts that name `naming`, at `now`.
    pub fn facts_naming(&self, naming: &Naming, now: Timestamp) -> Vec<ObservedFact> {
        self.select(now, |fact| naming.names(fact))
    }

    /// The fact of one subject of one source, as the view gives it.
    pub fn fact(&self, source_key: &str, subject: &FactSubject) -> Option<ObservedFact> {
        let subject_key = subject.key();
        self.facts(Timestamp::now())
            .into_iter()
            .find(|fact| fact.source_key == source_key && fact.subject_key == subject_key)
    }

    /// The facts of every entry that `keep` passes, one per source and subject.
    fn select(&self, now: Timestamp, keep: impl Fn(&ObservedFact) -> bool) -> Vec<ObservedFact> {
        let image = self.read();
        let mut out = Vec::with_capacity(image.entries.len() * 2);
        // Subjects that two rows may share (a name or an OS of one address in two VRFs, the
        // vendor of one MAC address): the current fact, else the latest, wins.
        let mut shared: HashMap<(String, String), usize> = HashMap::new();
        let mut facts = Vec::with_capacity(4);
        for ((vrf, ip), entry) in &image.entries {
            if !self.retained(entry, now) {
                continue;
            }
            facts.clear();
            self.facts_of(*vrf, *ip, entry, now, &mut facts);
            for fact in facts.drain(..) {
                if !keep(&fact) {
                    continue;
                }
                if matches!(
                    fact.subject,
                    FactSubject::Address { .. } | FactSubject::Network { .. }
                ) {
                    out.push(fact);
                    continue;
                }
                let key = (fact.source_key.clone(), fact.subject_key.clone());
                if let Some(&index) = shared.get(&key) {
                    let held = &out[index];
                    let better = (fact.is_current(now), fact.last_seen)
                        > (held.is_current(now), held.last_seen);
                    if better {
                        out[index] = fact;
                    }
                } else {
                    shared.insert(key, out.len());
                    out.push(fact);
                }
            }
        }
        out
    }

    /// The facts one entry stands for (see the module documentation).
    #[allow(
        clippy::too_many_lines,
        reason = "the facts of one row, one after the other, read best together"
    )]
    fn facts_of(
        &self,
        vrf: VrfId,
        ip: IpAddr,
        entry: &Entry,
        now: Timestamp,
        out: &mut Vec<ObservedFact>,
    ) {
        let bound = entry.state == BindingState::Active;
        let conflict = entry.state == BindingState::Abandoned;
        if !(bound || conflict || ended(entry.state)) {
            return;
        }
        // A binding's facts end with it; the facts of a row that no longer binds ended at
        // its last transaction or its end, whichever came first.
        let until = if bound {
            entry.ends
        } else {
            entry.cltt.min(entry.ends)
        };
        let source = ObservationSource::DhcpLease { node: entry.node };
        let source_key = format!("dhcp:{}", entry.node);
        let last_seen = entry.cltt.min(now);
        let first_seen = entry.granted.min(last_seen);
        let refresh = self.config.refresh.max(Duration::from_secs(1));
        let span = last_seen.saturating_since(first_seen);
        let sightings = u32::try_from(span.as_nanos() / refresh.as_nanos())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let counted_at = first_seen
            .checked_add(refresh.saturating_mul(sightings.saturating_sub(1)))
            .unwrap_or(last_seen)
            .min(last_seen);
        let fact = |observed: Observed, expires: Timestamp| {
            let subject = FactSubject::of(&observed);
            let subject_key = subject.key();
            let observation = observation_id(&source_key, &subject_key, first_seen, &observed);
            ObservedFact {
                source: source.clone(),
                source_key: source_key.clone(),
                subject,
                subject_key,
                observed,
                observation,
                first_seen,
                last_seen,
                received_at: last_seen,
                expires_at: Some(expires),
                sightings,
                counted_at: Some(counted_at),
                revision: entry.revision,
            }
        };
        if let Kind::Delegation { prefix_len, holder } = &entry.kind {
            let IpAddr::V6(first) = ip else {
                return;
            };
            let subnet = ipnet::Ipv6Net::new(first, (*prefix_len).min(128))
                .map(|net| ipnet::IpNet::V6(net.trunc()))
                .ok();
            out.push(fact(
                Observed::Network {
                    controller: format!("dhcp-pd/{vrf}/{first}/{prefix_len}"),
                    name: format!("delegated to {holder}"),
                    subnet,
                    vlan: None,
                    dhcp: NetworkDhcp::Server,
                    management: false,
                },
                until,
            ));
            return;
        }
        // The address fact: the client's MAC address while it binds, the answering MAC
        // address of a conflict until its hold ends.
        let address_until = if conflict { entry.ends } else { until };
        out.push(fact(
            Observed::Address {
                vrf,
                ip,
                mac: entry.mac,
            },
            address_until,
        ));
        if let Some(name) = &entry.name {
            out.push(fact(
                Observed::Name {
                    ip,
                    placeholder: tenko_core::observe::is_placeholder_name(name),
                    name: name.to_string(),
                },
                until,
            ));
        }
        if let Some((guess, confidence)) = &entry.os {
            out.push(fact(
                Observed::Os {
                    ip,
                    guess: guess.to_string(),
                    confidence: *confidence,
                },
                until,
            ));
        }
        if let (Some(mac), Some(vendor)) = (entry.mac, &entry.vendor) {
            out.push(fact(
                Observed::Vendor {
                    mac,
                    vendor: vendor.to_string(),
                },
                until,
            ));
        }
    }

    /// The entry of a DHCPv4 row.
    fn entry4(&self, lease: &Lease, revision: Revision) -> Option<Entry> {
        if !(lease.state == BindingState::Active
            || lease.state == BindingState::Abandoned
            || ended(lease.state))
        {
            return None;
        }
        let conflict = lease.state == BindingState::Abandoned;
        let os = (!conflict)
            .then(|| {
                self.classifier
                    .get()
                    .zip(lease.fingerprint.as_ref())
                    .and_then(|(classifier, fingerprint)| classifier.os(fingerprint))
            })
            .flatten()
            .filter(|reading| !reading.guess.trim().is_empty())
            .map(|reading| (reading.guess.into_boxed_str(), reading.confidence.min(100)));
        Some(Entry {
            kind: Kind::V4,
            node: lease.node,
            state: lease.state,
            cltt: lease.cltt,
            ends: lease.ends,
            granted: lease.granted_at(),
            revision,
            mac: lease_mac(lease),
            // A conflict names the address that answered, not the decliner's names.
            name: (!conflict)
                .then(|| lease_name(lease))
                .flatten()
                .map(String::into_boxed_str),
            vendor: (!conflict)
                .then(|| lease_vendor(lease))
                .flatten()
                .map(String::into_boxed_str),
            os,
        })
    }
}

/// How a follow of the journal ended.
enum Followed {
    /// `stop` fired or the store shut down.
    Stopped,
    /// The stream lagged or the journal was compacted past it: build again.
    Rebuild,
}

/// Whether a state is the end of a binding that the row still records (released, expired,
/// reset): its facts expired, the view keeps them as the history of the address.
const fn ended(state: BindingState) -> bool {
    matches!(
        state,
        BindingState::Released | BindingState::Expired | BindingState::Reset
    )
}

/// The entry of a DHCPv6 row.
fn entry6(lease: &Lease6, revision: Revision) -> Option<Entry> {
    if !(lease.state == BindingState::Active
        || lease.state == BindingState::Abandoned
        || ended(lease.state))
    {
        return None;
    }
    let conflict = lease.state == BindingState::Abandoned;
    let kind = match lease.kind {
        Lease6Kind::Na => Kind::V6,
        Lease6Kind::Pd => {
            if conflict {
                return None;
            }
            let holder = match lease.mac() {
                Some(mac) => MacAddr::new(mac).to_string(),
                None => format!("DUID {}", hex(lease.duid.as_bytes())),
            };
            Kind::Delegation {
                prefix_len: lease.prefix_len,
                holder: holder.into_boxed_str(),
            }
        }
    };
    Some(Entry {
        kind,
        node: lease.node,
        state: lease.state,
        cltt: lease.cltt,
        ends: lease.ends,
        granted: lease.granted_at(),
        revision,
        // An abandoned row (a DECLINE) is a conflict without a MAC address.
        mac: lease.mac().filter(|_| !conflict).map(MacAddr::new),
        name: lease
            .fqdn
            .as_deref()
            .filter(|_| !conflict && lease.kind == Lease6Kind::Na)
            .map(|name| name.trim().trim_end_matches('.'))
            .filter(|name| !name.is_empty())
            .map(Box::from),
        vendor: None,
        os: None,
    })
}

/// The observation id of a fact the view gives: stable for one binding reporting the same
/// attributes, new when either changes (FNV-1a over the parts, as a UUID).
fn observation_id(
    source_key: &str,
    subject_key: &str,
    first_seen: Timestamp,
    observed: &Observed,
) -> ObservationId {
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u128::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(PRIME);
    };
    feed(source_key.as_bytes());
    feed(subject_key.as_bytes());
    feed(&first_seen.unix_nanos().to_be_bytes());
    match observed {
        Observed::Address { mac, .. } => {
            feed(mac.map(MacAddr::octets).unwrap_or_default().as_slice());
        }
        Observed::Name { name, .. } | Observed::Network { name, .. } => feed(name.as_bytes()),
        Observed::Os {
            guess, confidence, ..
        } => {
            feed(guess.as_bytes());
            feed(&[*confidence]);
        }
        Observed::Vendor { vendor, .. } => feed(vendor.as_bytes()),
        _ => {}
    }
    // A UUID of version 8 (custom) and the RFC 9562 variant.
    let hash = (hash & !(0xf_u128 << 76) | (0x8_u128 << 76)) & !(0x3_u128 << 62) | (0x2_u128 << 62);
    ObservationId::from_uuid(uuid::Uuid::from_u128(hash))
}

/// Lower-case hexadecimal octets.
fn hex(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(octets.len() * 2);
    for octet in octets {
        let _ = write!(out, "{octet:02x}");
    }
    out
}

#[cfg(test)]
mod tests;
