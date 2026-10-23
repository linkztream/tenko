//! The iterative engine of the recursive resolver (WP10.1, recursion plan section 2.1,
//! DNS-03, DNS-08): RFC 1034 section 5.3.3 as resolvers run it today, over an
//! [`Authority`] (one exchange with one server: [`net::NetAuthority`] on the network,
//! [`crate::recursion::MemAuthority`] in the tests) and an [`InfraCache`]
//! ([`crate::infra::Infra`]).
//!
//! **One client query** ([`Engine::resolve`]) runs as a small state machine:
//!
//! 1. *Joined* when the same name, type, class and view is in flight ([`join`]): one
//!    resolution answers every one of them.
//! 2. *Failed already* when the failure cache holds the key (RFC 9520): SERVFAIL with the
//!    stored extended error, no query sent.
//! 3. *Local* when the name is under a special-use or locally served zone ([`local`]).
//! 4. *Walking*: from the closest zone cut the infrastructure cache holds (the root at
//!    worst, from the hints until priming answered), a server of the cut is asked; its
//!    answer is read as RFC 2181 section 5.4 ranks it within the bailiwick of RFC 9471
//!    ([`message::classify`]): an answer ends the walk, a CNAME or DNAME restarts it for
//!    the target (the whole chain goes into the answer with every TTL), a referral moves it
//!    down one cut (the NS set and the in-domain glue cached, sibling glue used and marked
//!    unconfirmed, other addresses ignored), NXDOMAIN or NODATA ends it, and a lame answer
//!    (REFUSED, SERVFAIL, a non-authoritative answer, an upward referral) marks the server
//!    lame for the zone for the infrastructure TTL and moves to the next server.
//! 5. *Minimised* (WP10.3, RFC 9156 section 3 in the relaxed mode of REC-Q8,
//!    [`Minimiser`]): each cut's servers are asked for the cut and one label more of the
//!    name (four times, then more labels at a time, at most ten minimised steps), with the
//!    original type or A for the types a server may refuse ([`minimised_type`]); a referral
//!    moves the walk down, an answer or NODATA asks one label more of the same servers. In
//!    the relaxed mode an NXDOMAIN or a lame answer to a minimised question is asked again
//!    with the full name of the same servers, and when that answer is no NXDOMAIN (the
//!    server is not RFC 8020 clean) the zone is asked with the full name for the
//!    infrastructure TTL (the cut's `minimise_fallback`); `strict` never falls back and
//!    takes the NXDOMAIN for the name (RFC 8020); `off` asks the full name. The minimised
//!    answers fill the infrastructure cache only; the answer cache gets the final answer.
//! 6. *Name-server addresses*: a cut whose servers have no address gets them by
//!    sub-queries through the same walk, at most 3, 2, 1, 0 lookups at the depths 0, 1, 2,
//!    3 (Unbound's fetch policy) and at most `budget_depth` levels; a lookup that needs
//!    itself is a loop and the cut has no reachable server (extended error 22).
//!
//! **The work budget** (REC-Q12, [`WorkBudget`]): queries sent (sub-queries and the
//! retries of the fallback ladder included), CNAME and DNAME links, the depth of the
//! name-server lookups, attempts per server and the wall clock. The bound hit is counted
//! ([`Counters`]) and the failure cached through [`FailureCache`] with its extended error.
//!
//! **Server selection** ([`crate::infra::ServerTable`]): the cut's addresses of the
//! families in force (REC-Q9), not lame for the zone, not marked unreachable; the ones
//! asked least for this query first, then the fastest smoothed round-trip time (one never
//! measured first), servers in back-off last, one choice in 16 at random among the rest;
//! the timeout of an attempt is four times the server's smoothed time between 300 ms and
//! `timeout_ms`. Each exchange carries 0x20 (unless the server broke it twice: then lower
//! case for the infrastructure TTL; a mismatch is retried in lower case at once), EDNS with
//! 1,232 octets and DO (unless the server is known to answer FORMERR to it), the client
//! cookie of this node for the server and the server cookie it sent last.
//!
//! **Priming** (RFC 8109, [`Engine::prime`]): at start, before the root's NS set expires,
//! after a change of the hints file and after a flush, `./NS` is asked of the hints'
//! servers; the answer becomes the root's cut. While it fails the hints stay the root's
//! servers and priming is tried again with a back-off from one second to five minutes;
//! [`RecursionReport::problems`] names `priming_failed`.
//!
//! The engine runs on the forwarder's task pool and allocates freely; the worker never
//! reaches it (recursion plan section 2.10).

pub mod hints;
pub mod join;
pub mod local;
pub mod message;
pub mod net;

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    dns::{DnsName, ExtendedError, ViewId},
};

use self::{
    hints::Hints,
    join::Joins,
    local::LocalZones,
    message::{Composed, GlueKind, Rr, Step, types},
};
use crate::{
    cache::CacheKey,
    infra::{ServerFigures, ServerTable},
    metrics, name,
    recursion::{
        AddressOrigin, Authority, AuthorityError, AuthorityQuery, AuthorityTransport, BudgetBound,
        FailureCache, FailureCause, InfraCache, InfraSizes, Minimisation, Outbound,
        RecursionSettings, WorkBudget, ZoneCut,
        infra::{EdnsSupport, UNREACHABLE_REPROBE},
    },
};

/// The DNS class IN.
const CLASS_IN: u16 = 1;

/// The most priming exchanges of one priming run.
const PRIMING_TRIES: usize = 6;

/// The longest back-off of a failing priming.
const PRIMING_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// The longest a learnt NS set or address is kept, whatever its TTL (one day).
const MAX_INFRA_TTL: u32 = 86_400;

/// The engine's settings: `[dns.recursion]` and the profile, as the role maps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSettings {
    /// The resolver's settings.
    pub recursion: RecursionSettings,
    /// A root hints file; `None`: the shipped hints.
    pub hints: Option<PathBuf>,
    /// Locally served zones resolved all the same.
    pub local_zones_except: Vec<DnsName>,
    /// Count in the engine's metrics.
    pub metrics: bool,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            recursion: RecursionSettings::default(),
            hints: None,
            local_zones_except: Vec::new(),
            metrics: true,
        }
    }
}

/// What the engine counted since it started.
#[derive(Debug, Default)]
pub struct Counters {
    answered: AtomicU64,
    servfail: AtomicU64,
    budget: AtomicU64,
    timeout: AtomicU64,
    local: AtomicU64,
    failure_hits: AtomicU64,
    joined: AtomicU64,
    subqueries: AtomicU64,
    bound_queries: AtomicU64,
    bound_restarts: AtomicU64,
    bound_depth: AtomicU64,
    bound_time: AtomicU64,
    primings_ok: AtomicU64,
    primings_failed: AtomicU64,
    unwanted_flushes: AtomicU64,
    // WP10.3: QNAME minimisation.
    minimised: AtomicU64,
    minimise_retries: AtomicU64,
    minimise_fallbacks: AtomicU64,
}

/// A copy of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterValues {
    /// Client queries answered by recursion (NOERROR or NXDOMAIN).
    pub answered: u64,
    /// Client queries answered SERVFAIL (no reachable authority, a network error).
    pub servfail: u64,
    /// Client queries that hit the queries, restarts or depth bound.
    pub budget: u64,
    /// Client queries that hit the wall clock bound.
    pub timeout: u64,
    /// Client queries answered from the locally served zones.
    pub local: u64,
    /// Client queries answered from the failure cache.
    pub failure_hits: u64,
    /// Client queries joined to a resolution in flight.
    pub joined: u64,
    /// Queries sent to authorities.
    pub subqueries: u64,
    /// Resolutions that hit the queries bound.
    pub bound_queries: u64,
    /// Resolutions that hit the restarts bound.
    pub bound_restarts: u64,
    /// Resolutions that hit the depth bound.
    pub bound_depth: u64,
    /// Resolutions that hit the wall clock bound.
    pub bound_time: u64,
    /// Primings that succeeded.
    pub primings_ok: u64,
    /// Primings that failed.
    pub primings_failed: u64,
    /// Unwanted answers across the node.
    pub unwanted: u64,
    /// Flushes of the answer cache for unwanted answers.
    pub unwanted_flushes: u64,
}

/// The last priming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimingReport {
    /// When it ended.
    pub at: Timestamp,
    /// Whether a root server answered.
    pub ok: bool,
    /// How long it took.
    pub duration: Duration,
}

#[derive(Debug)]
struct Priming {
    last: Option<PrimingReport>,
    next_at: Instant,
    backoff: Duration,
    in_flight: bool,
    expires: Option<Instant>,
    checked_hints: Instant,
}

/// One root server in the status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootServer {
    /// Its name.
    pub name: DnsName,
    /// An address of it.
    pub address: IpAddr,
    /// The smoothed round-trip time of the address.
    pub srtt: Option<Duration>,
}

/// The engine's part of the node status (`GET /nodes/{id}/dns/recursion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionReport {
    /// Where the hints came from: `shipped` or the file.
    pub hints_source: String,
    /// The date of the hints.
    pub hints_date: String,
    /// The last priming.
    pub priming: Option<PrimingReport>,
    /// When the root's NS set expires, from now.
    pub root_expires_in: Option<Duration>,
    /// The root's servers in use.
    pub root: Vec<RootServer>,
    /// The infrastructure cache's sizes.
    pub infra: InfraSizes,
    /// The bounds of the infrastructure cache: zone cuts, server addresses.
    pub infra_bounds: (usize, usize),
    /// The counters.
    pub counters: CounterValues,
    /// The work budget in force.
    pub budget: WorkBudget,
    /// What is wrong: `priming_failed`.
    pub problems: Vec<String>,
}

/// One address of a server of a cut in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfraAddressView {
    /// The address.
    pub address: IpAddr,
    /// Where it came from.
    pub origin: AddressOrigin,
    /// Seconds left.
    pub ttl: u32,
    /// The figures.
    pub figures: ServerFigures,
    /// Its EDNS support.
    pub edns: EdnsSupport,
    /// Asked over TCP only.
    pub tcp_only: bool,
    /// Lame for the cut's zone.
    pub lame: bool,
}

/// One server of a cut in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfraServerView {
    /// The name.
    pub name: DnsName,
    /// The addresses known.
    pub addresses: Vec<InfraAddressView>,
}

/// One zone cut in the listing (`GET /nodes/{id}/dns/infra`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfraCutView {
    /// The zone.
    pub zone: DnsName,
    /// Its servers.
    pub servers: Vec<InfraServerView>,
    /// The DS state's name.
    pub ds: &'static str,
    /// Seconds left.
    pub ttl: u32,
}

/// How a resolution ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered from the authorities (NOERROR or NXDOMAIN).
    Answered,
    /// Answered from a locally served zone.
    Local,
    /// Refused: a class other than IN.
    Refused,
    /// SERVFAIL for this cause; `cached` when the failure cache answered.
    Failed {
        /// Why.
        cause: FailureCause,
        /// From the failure cache.
        cached: bool,
    },
}

/// The outcome of a resolution, shared by the joined queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The answer in the form of an authority's answer ([`message::compose`]).
    pub message: Vec<u8>,
    /// Its RCODE.
    pub rcode: u8,
    /// How it ended.
    pub outcome: Outcome,
    /// Queries sent to authorities.
    pub subqueries: u16,
}

impl Resolved {
    /// The extended error of a failure.
    pub fn ede(&self) -> Option<ExtendedError> {
        match self.outcome {
            Outcome::Failed { cause, .. } => Some(cause.ede()),
            _ => None,
        }
    }

    /// Whether the answer cache may keep it.
    pub fn cacheable(&self) -> bool {
        matches!(self.outcome, Outcome::Answered | Outcome::Local)
    }
}

/// A client's question.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    /// The name, lowercase wire form.
    pub qname: &'a [u8],
    /// The type.
    pub qtype: u16,
    /// The class.
    pub qclass: u16,
    /// The view (the join and the failure cache key on it, as the answer cache does).
    pub view: Option<ViewId>,
}

/// The state of one client query's resolution.
#[derive(Debug)]
struct Work {
    budget: WorkBudget,
    deadline: Instant,
    sent: u16,
    lower_case: Vec<IpAddr>,
    /// The name-server lookups in progress, for the loop check.
    stack: Vec<Vec<u8>>,
    /// The CNAME and DNAME links followed.
    links: u8,
}

impl Work {
    fn new(budget: WorkBudget, now: Instant) -> Self {
        Self {
            budget,
            deadline: now + budget.wall,
            sent: 0,
            lower_case: Vec::new(),
            stack: Vec::new(),
            links: 0,
        }
    }

    fn check(&self, now: Instant) -> Result<(), FailureCause> {
        if now >= self.deadline {
            return Err(FailureCause::Budget(BudgetBound::Time));
        }
        if self.sent >= self.budget.queries {
            return Err(FailureCause::Budget(BudgetBound::Queries));
        }
        Ok(())
    }
}

/// A finished walk.
#[derive(Debug)]
struct Found {
    rcode: u8,
    answer: Vec<Rr>,
    authority: Vec<Rr>,
    cut: Option<ZoneCut>,
}

/// A failed walk with the chain so far.
#[derive(Debug)]
struct Failed {
    cause: FailureCause,
    chain: Vec<Rr>,
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The engine; see the module documentation.
pub struct Engine<A> {
    authority: A,
    infra: Arc<dyn InfraCache>,
    servers: Arc<ServerTable>,
    failures: Arc<dyn FailureCache>,
    settings: RecursionSettings,
    metrics: bool,
    hints: Mutex<Hints>,
    local: LocalZones,
    secret: [u8; 16],
    priming: Mutex<Priming>,
    joins: Joins<Resolved>,
    counters: Counters,
    delegation: AtomicBool,
    // WP10.3: the names minimised questions showed to exist without a cut.
    names: Mutex<KnownNames>,
}

// WP10.3: QNAME minimisation's memory.
/// The names a minimised question showed to exist without being a cut (an answer, NODATA
/// or an alias), so that the next walk through them does not ask them again: by name,
/// until when and when used last; bounded like the infrastructure cache's servers.
#[derive(Debug, Default)]
struct KnownNames {
    names: HashMap<Vec<u8>, (Instant, u64)>,
    tick: u64,
}

impl<A> std::fmt::Debug for Engine<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<A: Authority> Engine<A> {
    /// The engine over `authority`, `infra`, `servers` and `failures`, with `hints` and
    /// the settings.
    pub fn new(
        authority: A,
        infra: Arc<dyn InfraCache>,
        servers: Arc<ServerTable>,
        failures: Arc<dyn FailureCache>,
        hints: Hints,
        settings: &EngineSettings,
    ) -> Self {
        let mut secret = [0u8; 16];
        crate::outbound::random_fill(&mut secret);
        let except: Vec<Vec<u8>> = settings
            .local_zones_except
            .iter()
            .map(DnsName::to_wire)
            .collect();
        let now = Instant::now();
        let engine = Self {
            authority,
            infra,
            servers,
            failures,
            settings: settings.recursion.clone(),
            metrics: settings.metrics,
            hints: Mutex::new(hints),
            local: LocalZones::new(&except),
            secret,
            priming: Mutex::new(Priming {
                last: None,
                next_at: now,
                backoff: Duration::ZERO,
                in_flight: false,
                expires: None,
                checked_hints: now,
            }),
            joins: Joins::default(),
            counters: Counters::default(),
            delegation: AtomicBool::new(false),
            names: Mutex::new(KnownNames::default()),
        };
        engine.install_hints(now);
        engine
    }

    /// The infrastructure cache.
    pub fn infra(&self) -> &Arc<dyn InfraCache> {
        &self.infra
    }

    /// The figures of the servers.
    pub fn servers(&self) -> &Arc<ServerTable> {
        &self.servers
    }

    /// The settings.
    pub fn settings(&self) -> &RecursionSettings {
        &self.settings
    }

    /// The authority the engine asks.
    pub fn authority(&self) -> &A {
        &self.authority
    }

    /// Whether answers carry the delegation that was followed (its NS records in the
    /// authority section and their addresses in the additional section), so that the RPZ
    /// triggers NSDNAME and NSIP match it (E41). The forwarder sets it while an RPZ zone
    /// of the catalog has such triggers.
    pub fn carry_delegation(&self, on: bool) {
        self.delegation.store(on, Ordering::Relaxed);
    }

    fn lock_priming(&self) -> std::sync::MutexGuard<'_, Priming> {
        self.priming.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn hints(&self) -> Hints {
        self.hints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Puts the hints into the infrastructure cache as the root's cut when it has none.
    fn install_hints(&self, now: Instant) -> bool {
        if self.infra.cut(&DnsName::root(), now).is_some() {
            return false;
        }
        let hints = self.hints();
        let names: Vec<DnsName> = hints.servers.iter().map(|(name, _)| name.clone()).collect();
        if names.is_empty() {
            return false;
        }
        let ttl = hints.ttl.max(1);
        self.infra.put_cut(&DnsName::root(), names, ttl, now);
        for (name, addresses) in &hints.servers {
            let addresses: Vec<(IpAddr, u32)> =
                addresses.iter().map(|address| (*address, ttl)).collect();
            self.infra
                .put_addresses(name, &addresses, AddressOrigin::Hints, now);
        }
        true
    }

    /// The client cookie of this node for `server` (RFC 7873 section 4.1, RFC 9018: a
    /// keyed hash of the server's address under the node's secret).
    pub fn client_cookie(&self, server: IpAddr) -> [u8; 8] {
        let octets: Vec<u8> = match server {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        crate::cookie::siphash24(&self.secret, &octets).to_be_bytes()
    }

    fn family_allowed(&self, address: IpAddr) -> bool {
        match self.settings.outbound {
            Outbound::V4 => address.is_ipv4(),
            Outbound::V6 => address.is_ipv6(),
            Outbound::Auto | Outbound::Both => true,
        }
    }

    fn count(&self, counter: fn(&Counters) -> &AtomicU64) {
        counter(&self.counters).fetch_add(1, Ordering::Relaxed);
    }

    /// The counters.
    pub fn counters(&self) -> CounterValues {
        let c = &self.counters;
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        CounterValues {
            answered: read(&c.answered),
            servfail: read(&c.servfail),
            budget: read(&c.budget),
            timeout: read(&c.timeout),
            local: read(&c.local),
            failure_hits: read(&c.failure_hits),
            joined: read(&c.joined),
            subqueries: read(&c.subqueries),
            bound_queries: read(&c.bound_queries),
            bound_restarts: read(&c.bound_restarts),
            bound_depth: read(&c.bound_depth),
            bound_time: read(&c.bound_time),
            primings_ok: read(&c.primings_ok),
            primings_failed: read(&c.primings_failed),
            unwanted: self.servers.unwanted_total(),
            unwanted_flushes: read(&c.unwanted_flushes),
        }
    }

    // WP10.3: the minimisation's counters.
    /// Queries sent with a minimised name (RFC 9156), minimised questions asked again with
    /// the full name, and zones remembered as asked with the full name.
    pub fn minimisation_counters(&self) -> [u64; 3] {
        let c = &self.counters;
        [&c.minimised, &c.minimise_retries, &c.minimise_fallbacks]
            .map(|counter| counter.load(Ordering::Relaxed))
    }

    /// Counts a flush of the answer cache for unwanted answers.
    pub fn count_unwanted_flush(&self) {
        self.count(|c| &c.unwanted_flushes);
    }

    // WP10.3: 0 a minimised query, 1 a retry with the full name, 2 a fallback remembered.
    fn count_minimisation(&self, what: u8) {
        match what {
            0 => self.count(|c| &c.minimised),
            1 => self.count(|c| &c.minimise_retries),
            _ => self.count(|c| &c.minimise_fallbacks),
        }
    }

    // -----------------------------------------------------------------------------------
    // Priming

    /// Whether a priming is due at `now` (none in flight, the time come); reads the hints
    /// file again once a minute and primes at once when it changed.
    pub fn priming_due(&self, now: Instant) -> bool {
        let reload = {
            let mut priming = self.lock_priming();
            if now.saturating_duration_since(priming.checked_hints) >= Duration::from_secs(60) {
                priming.checked_hints = now;
                true
            } else {
                false
            }
        };
        if reload {
            self.reload_hints(now);
        }
        let priming = self.lock_priming();
        !priming.in_flight && now >= priming.next_at
    }

    fn reload_hints(&self, now: Instant) {
        let current = self.hints();
        if !current.changed() {
            return;
        }
        let hints::HintsSource::File(path, _) = &current.source else {
            return;
        };
        match Hints::from_file(path) {
            Ok(hints) => {
                tracing::info!(file = %path.display(), "the root hints file changed: priming again");
                *self.hints.lock().unwrap_or_else(PoisonError::into_inner) = hints;
                self.infra.flush(Some(&DnsName::root()));
                self.install_hints(now);
                self.lock_priming().next_at = now;
            }
            Err(error) => {
                tracing::warn!(%error, "the changed root hints file cannot be read; the hints in use stay");
            }
        }
    }

    /// Asks the root servers for the root's NS set (RFC 8109) and makes the answer the
    /// root's cut. Returns how long it took.
    ///
    /// # Errors
    ///
    /// [`FailureCause::NoReachableAuthority`] when no root server of the hints answered.
    pub async fn prime(&self) -> Result<Duration, FailureCause> {
        {
            let mut priming = self.lock_priming();
            if priming.in_flight {
                return Err(FailureCause::NoReachableAuthority);
            }
            priming.in_flight = true;
        }
        let started = Instant::now();
        let result = self.prime_now(started).await;
        let now = Instant::now();
        let duration = now.saturating_duration_since(started);
        let mut priming = self.lock_priming();
        priming.in_flight = false;
        priming.last = Some(PrimingReport {
            at: Timestamp::now(),
            ok: result.is_ok(),
            duration,
        });
        match result {
            Ok(ttl) => {
                let ttl = Duration::from_secs(u64::from(ttl));
                priming.expires = Some(now + ttl);
                // Before the NS set runs out: a tenth of its TTL early, at most an hour.
                let margin = (ttl / 10).min(Duration::from_secs(3600));
                priming.next_at = now + ttl.saturating_sub(margin).max(Duration::from_secs(1));
                priming.backoff = Duration::ZERO;
                drop(priming);
                self.count(|c| &c.primings_ok);
                if self.metrics {
                    metrics::PRIMING_COUNTER.inc(0);
                }
                tracing::debug!(?duration, "the root servers answered the priming query");
                Ok(duration)
            }
            Err(cause) => {
                priming.backoff = (priming.backoff * 2)
                    .max(Duration::from_secs(1))
                    .min(PRIMING_MAX_BACKOFF);
                priming.next_at = now + priming.backoff;
                let backoff = priming.backoff;
                drop(priming);
                self.count(|c| &c.primings_failed);
                if self.metrics {
                    metrics::PRIMING_COUNTER.inc(1);
                }
                tracing::warn!(
                    ?backoff,
                    "no root server of the hints answered the priming query; the hints stay in use"
                );
                Err(cause)
            }
        }
    }

    /// One priming run: returns the root NS set's TTL.
    async fn prime_now(&self, started: Instant) -> Result<u32, FailureCause> {
        let hints = self.hints();
        let mut addresses: Vec<IpAddr> = hints
            .addresses()
            .map(|(_, address)| address)
            .filter(|address| self.family_allowed(*address))
            .filter(|address| !self.infra.server(*address, started).is_unreachable(started))
            .collect();
        // Spread the priming over the root servers: the fastest known first, the unknown in
        // a random order.
        let offset = usize::from(crate::outbound::random_u16()) % addresses.len().max(1);
        addresses.rotate_left(offset);
        addresses.sort_by_key(|address| {
            let srtt = self.servers.srtt_micros(*address);
            (self.servers.down(*address, started), srtt)
        });
        let root = DnsName::root().to_wire();
        let mut buf = Vec::new();
        for address in addresses.into_iter().take(PRIMING_TRIES) {
            let now = Instant::now();
            let timeout = self.servers.timeout(address, self.settings.timeout);
            let state = self.infra.server(address, now);
            let query = AuthorityQuery {
                server: SocketAddr::new(address, 53),
                qname: &root,
                qtype: types::NS,
                qclass: CLASS_IN,
                edns: state.edns != EdnsSupport::No,
                tcp: state.tcp_only,
                mix_case: false,
                client_cookie: Some(self.client_cookie(address)),
                server_cookie: state.cookie,
                fresh_port: self.settings.fresh_port,
                deadline: now + timeout,
            };
            let result = self.authority.exchange(&query, &mut buf).await;
            let exchange = match result {
                Ok(exchange) => exchange,
                Err(error) => {
                    self.note_error(address, &error, timeout, query.tcp);
                    continue;
                }
            };
            self.note_exchange(address, &exchange, query.edns);
            let Some(parsed) = message::parse(&buf) else {
                continue;
            };
            let ns: Vec<&Rr> = parsed
                .answer
                .iter()
                .filter(|rr| rr.rtype == types::NS && rr.owner == root)
                .collect();
            if parsed.rcode != 0 || ns.is_empty() {
                continue;
            }
            let ttl = ns
                .iter()
                .map(|rr| rr.ttl)
                .min()
                .unwrap_or(0)
                .clamp(1, MAX_INFRA_TTL * 7);
            let names: Vec<DnsName> = ns
                .iter()
                .filter_map(|rr| rr.target())
                .filter_map(|wire| DnsName::from_wire(&wire).ok().map(|(name, _)| name))
                .collect();
            let now = Instant::now();
            for name in &names {
                let wire = name.to_wire();
                let found: Vec<(IpAddr, u32)> = parsed
                    .additional
                    .iter()
                    .filter(|rr| rr.owner == wire)
                    .filter_map(|rr| rr.address().map(|address| (address, rr.ttl.min(ttl))))
                    .collect();
                self.infra
                    .put_addresses(name, &found, AddressOrigin::Glue, now);
            }
            self.infra.put_cut(&DnsName::root(), names, ttl, now);
            return Ok(ttl);
        }
        Err(FailureCause::NoReachableAuthority)
    }

    /// Primes now if a priming is due; for the forwarder's housekeeping.
    pub async fn prime_if_due(&self) {
        if self.priming_due(Instant::now()) {
            let _ = self.prime().await;
        }
    }

    // -----------------------------------------------------------------------------------
    // The client query

    /// Resolves a client's question; identical questions in flight share one resolution.
    pub async fn resolve(&self, question: Question<'_>) -> Arc<Resolved> {
        let key = CacheKey::new(
            question.view,
            question.qname,
            question.qtype,
            question.qclass,
        );
        let (resolved, joined) = self
            .joins
            .run(key.as_bytes(), || self.resolve_now(question, &key))
            .await;
        if joined {
            self.count(|c| &c.joined);
        }
        resolved
    }

    /// One resolution, the join table aside.
    async fn resolve_now(&self, question: Question<'_>, key: &CacheKey) -> Resolved {
        let started = Instant::now();
        let qname = question.qname;
        let compose = |rcode: u8, answer: &[Rr], authority: &[Rr], additional: &[Rr]| {
            message::compose(&Composed {
                qname,
                qtype: question.qtype,
                qclass: question.qclass,
                rcode,
                answer,
                authority,
                additional,
            })
        };
        if let Some(cause) = self.failures.lookup(key, started) {
            self.count(|c| &c.failure_hits);
            if self.metrics {
                metrics::FAILURE_CACHE_HIT_COUNTER.inc();
            }
            return Resolved {
                message: compose(2, &[], &[], &[]),
                rcode: 2,
                outcome: Outcome::Failed {
                    cause,
                    cached: true,
                },
                subqueries: 0,
            };
        }
        if question.qclass != CLASS_IN {
            return Resolved {
                message: compose(5, &[], &[], &[]),
                rcode: 5,
                outcome: Outcome::Refused,
                subqueries: 0,
            };
        }
        let mut work = Work::new(self.settings.budget, started);
        let result = self.iterate(qname, question.qtype, 0, &mut work).await;
        let subqueries = work.sent;
        self.counters
            .subqueries
            .fetch_add(u64::from(subqueries), Ordering::Relaxed);
        let resolved = match result {
            Ok(found) => {
                let local = found.cut.is_none() && subqueries == 0;
                let (authority, additional) = self.delegation_records(&found);
                Resolved {
                    message: compose(found.rcode, &found.answer, &authority, &additional),
                    rcode: found.rcode,
                    outcome: if local {
                        Outcome::Local
                    } else {
                        Outcome::Answered
                    },
                    subqueries,
                }
            }
            Err(failed) => {
                self.failures.record(key, failed.cause, Instant::now());
                Resolved {
                    message: compose(2, &failed.chain, &[], &[]),
                    rcode: 2,
                    outcome: Outcome::Failed {
                        cause: failed.cause,
                        cached: false,
                    },
                    subqueries,
                }
            }
        };
        self.tally(&resolved, started);
        resolved
    }

    /// Counts a resolution in the counters and the metrics.
    fn tally(&self, resolved: &Resolved, started: Instant) {
        let subqueries = resolved.subqueries;
        let outcome_index = match resolved.outcome {
            Outcome::Answered | Outcome::Refused => {
                self.count(|c| &c.answered);
                0
            }
            Outcome::Local => {
                self.count(|c| &c.local);
                4
            }
            Outcome::Failed { cause, .. } => match cause {
                FailureCause::Budget(BudgetBound::Time) => {
                    self.count(|c| &c.timeout);
                    self.count(|c| &c.bound_time);
                    3
                }
                FailureCause::Budget(bound) => {
                    self.count(|c| &c.budget);
                    let counter: fn(&Counters) -> &AtomicU64 = match bound {
                        BudgetBound::Queries => |c| &c.bound_queries,
                        BudgetBound::Restarts => |c| &c.bound_restarts,
                        BudgetBound::Depth | BudgetBound::Time => |c| &c.bound_depth,
                    };
                    self.count(counter);
                    2
                }
                _ => {
                    self.count(|c| &c.servfail);
                    1
                }
            },
        };
        if self.metrics {
            metrics::RECURSION_COUNTER.inc(outcome_index);
            metrics::RECURSION_LATENCY
                .observe(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
            if subqueries > 0 {
                metrics::RECURSION_SUBQUERY_HISTOGRAM.observe(u64::from(subqueries));
            }
        }
    }

    /// The NS records and addresses of the cut an answer came from, when answers carry
    /// the delegation.
    fn delegation_records(&self, found: &Found) -> (Vec<Rr>, Vec<Rr>) {
        let mut authority = found.authority.clone();
        let mut additional = Vec::new();
        // WP10.2: a negative answer carries the delegation only when it is the SOA's zone
        // (RFC 2308 section 2.2): a resolver reading it, delv among them, refuses an NS of
        // another zone beside the SOA. The last cut of a walk that ended at a server
        // authoritative for a child as well is an ancestor, not the zone.
        let soa_owner = found
            .authority
            .iter()
            .find(|rr| rr.rtype == types::SOA)
            .map(|rr| rr.owner.as_slice());
        let negative = found.rcode != 0 || soa_owner.is_some();
        let Some(cut) = found.cut.as_ref().filter(|cut| {
            self.delegation.load(Ordering::Relaxed)
                && (!negative || soa_owner == Some(cut.zone.to_wire().as_slice()))
        }) else {
            return (authority, additional);
        };
        let now = Instant::now();
        let ttl = u32::try_from(cut.expires.saturating_duration_since(now).as_secs())
            .unwrap_or(u32::MAX)
            .max(1);
        let zone = cut.zone.to_wire();
        for server in &cut.servers {
            authority.push(Rr {
                owner: zone.clone(),
                rtype: types::NS,
                class: CLASS_IN,
                ttl,
                data: server.to_wire(),
            });
            if let Some(known) = self.infra.name_server(server, now) {
                for address in known.addresses {
                    let left =
                        u32::try_from(address.expires.saturating_duration_since(now).as_secs())
                            .unwrap_or(u32::MAX)
                            .max(1);
                    let (rtype, data) = match address.address {
                        IpAddr::V4(v4) => (types::A, v4.octets().to_vec()),
                        IpAddr::V6(v6) => (types::AAAA, v6.octets().to_vec()),
                    };
                    additional.push(Rr {
                        owner: server.to_wire(),
                        rtype,
                        class: CLASS_IN,
                        ttl: left,
                        data,
                    });
                }
            }
        }
        (authority, additional)
    }

    // -----------------------------------------------------------------------------------
    // The walk

    /// Resolves `qname`/`qtype` at `depth` (0 the client's question), following CNAME and
    /// DNAME records.
    fn iterate<'a>(
        &'a self,
        qname: &'a [u8],
        qtype: u16,
        depth: u8,
        work: &'a mut Work,
    ) -> Boxed<'a, Result<Found, Failed>> {
        Box::pin(async move {
            let mut chain: Vec<Rr> = Vec::new();
            let mut name = qname.to_vec();
            let mut seen: Vec<Vec<u8>> = vec![name.clone()];
            loop {
                if let Some((zone, kind)) = self.local.find(&name) {
                    let (rcode, answer, authority) = local::answer(zone, kind, &name, qtype);
                    chain.extend(answer);
                    return Ok(Found {
                        rcode,
                        answer: chain,
                        authority,
                        cut: None,
                    });
                }
                match self.walk(&name, qtype, depth, work).await {
                    Err(cause) => return Err(Failed { cause, chain }),
                    // WP10.2: a positive answer keeps its denial records for the validator.
                    Ok((Step::Answer { records, denials }, cut)) => {
                        chain.extend(records);
                        if links(&chain) > usize::from(work.budget.restarts) {
                            // A chain longer than the budget, even in one answer.
                            return Err(Failed {
                                cause: FailureCause::Budget(BudgetBound::Restarts),
                                chain,
                            });
                        }
                        return Ok(Found {
                            rcode: 0,
                            answer: chain,
                            authority: denials,
                            cut: Some(cut),
                        });
                    }
                    Ok((
                        Step::Negative {
                            rcode,
                            records,
                            authority,
                        },
                        cut,
                    )) => {
                        chain.extend(records);
                        if links(&chain) > usize::from(work.budget.restarts) {
                            return Err(Failed {
                                cause: FailureCause::Budget(BudgetBound::Restarts),
                                chain,
                            });
                        }
                        return Ok(Found {
                            rcode,
                            answer: chain,
                            authority,
                            cut: Some(cut),
                        });
                    }
                    Ok((Step::Alias { records, target }, _)) => {
                        chain.extend(records);
                        work.links = u8::try_from(links(&chain)).unwrap_or(u8::MAX);
                        if seen.contains(&target) || work.links > work.budget.restarts {
                            // A loop, or a chain longer than the budget: the chain so far.
                            return Err(Failed {
                                cause: FailureCause::Budget(BudgetBound::Restarts),
                                chain,
                            });
                        }
                        seen.push(target.clone());
                        name = target;
                    }
                    Ok((Step::Referral(_) | Step::Lame(_), _)) => {
                        return Err(Failed {
                            cause: FailureCause::NoReachableAuthority,
                            chain,
                        });
                    }
                }
            }
        })
    }

    /// The closest cut the infrastructure cache holds for the wire name `name`, the root
    /// from the hints at worst.
    fn closest_cut(&self, name: &[u8], qtype: u16, now: Instant) -> Option<ZoneCut> {
        let labels = name::label_count(name);
        // DS is the parent's: start above a cut at the name itself (RFC 4035 section 4.2).
        let first = usize::from(qtype == types::DS && labels > 0);
        for skip in first..=labels {
            let suffix = name::suffix(name, skip);
            let Ok((zone, _)) = DnsName::from_wire(suffix) else {
                continue;
            };
            if let Some(cut) = self.infra.cut(&zone, now) {
                return Some(cut);
            }
        }
        if self.install_hints(now) {
            // The root's NS set was gone (expired or flushed): prime again soon.
            let mut priming = self.lock_priming();
            if priming.next_at > now {
                priming.next_at = now;
            }
            drop(priming);
            return self.infra.cut(&DnsName::root(), now);
        }
        None
    }

    /// Walks from the closest cut down to the server that answers `name`/`qtype`, asking
    /// each cut's servers only for the labels they need (WP10.3, RFC 9156).
    async fn walk(
        &self,
        name: &[u8],
        qtype: u16,
        depth: u8,
        work: &mut Work,
    ) -> Result<(Step, ZoneCut), FailureCause> {
        let mut cut = self
            .closest_cut(name, qtype, Instant::now())
            .ok_or(FailureCause::NoReachableAuthority)?;
        // WP10.3: QNAME minimisation.
        let mut labels = Minimiser::new(self.settings.minimisation, name, qtype);
        loop {
            let zone = cut.zone.to_wire();
            let now = Instant::now();
            let (asked, asked_type) =
                labels.next(&zone, cut.minimise_fallback.is_some(), &|name| {
                    self.known_name(name, now)
                });
            let shorter = asked.len() != name.len();
            if shorter {
                self.count_minimisation(0);
            }
            let mut step = self
                .ask_zone(&cut, &zone, asked, asked_type, depth, work, shorter)
                .await?;
            if shorter {
                match &step {
                    Step::Referral(_) => {}
                    // Strict: a name below a name that does not exist does not exist
                    // either (RFC 8020), and nothing falls back.
                    Step::Negative { rcode: 3, .. }
                        if self.settings.minimisation == Minimisation::Strict =>
                    {
                        return Ok((step, cut));
                    }
                    // Relaxed: the full name, for this zone; a server that denied a name
                    // whose descendant exists, or failed on the shorter question, is not
                    // asked minimised again for the infrastructure TTL.
                    Step::Negative { rcode: 3, .. } | Step::Lame(_) => {
                        self.count_minimisation(1);
                        step = self
                            .ask_zone(&cut, &zone, name, qtype, depth, work, false)
                            .await?;
                        if !matches!(step, Step::Negative { rcode: 3, .. }) {
                            tracing::debug!(zone = %cut.zone, "a server broke on a minimised question: the full name for the zone from now on");
                            self.count_minimisation(2);
                            self.infra.set_minimise_fallback(
                                &cut.zone,
                                Instant::now() + self.infra_ttl(),
                            );
                        }
                    }
                    // The name exists and is no cut: one label more of the same servers,
                    // and the name is not asked again while the memory holds it.
                    _ => {
                        self.learn_name(asked, Instant::now());
                        continue;
                    }
                }
            }
            let Step::Referral(referral) = step else {
                return Ok((step, cut));
            };
            let now = Instant::now();
            let Ok((child, _)) = DnsName::from_wire(&referral.zone) else {
                return Err(FailureCause::NoReachableAuthority);
            };
            let ttl = referral.ttl.min(MAX_INFRA_TTL);
            let hosts: Vec<DnsName> = referral
                .ns
                .iter()
                .filter_map(Rr::target)
                .filter_map(|wire| DnsName::from_wire(&wire).ok().map(|(name, _)| name))
                .collect();
            if hosts.is_empty() {
                return Err(FailureCause::NoReachableAuthority);
            }
            for host in &hosts {
                let wire = host.to_wire();
                for kind in [GlueKind::InDomain, GlueKind::Sibling] {
                    let found: Vec<(IpAddr, u32)> = referral
                        .glue
                        .iter()
                        .filter(|(owner, _, _, glue)| *owner == wire && *glue == kind)
                        .map(|(_, address, glue_ttl, _)| (*address, (*glue_ttl).min(ttl)))
                        .collect();
                    let origin = match kind {
                        GlueKind::InDomain => AddressOrigin::Glue,
                        GlueKind::Sibling => AddressOrigin::SiblingGlue,
                    };
                    self.infra.put_addresses(host, &found, origin, now);
                }
            }
            let id = self.infra.put_cut(&child, hosts.clone(), ttl, now);
            labels.referred(&referral.zone);
            cut = self.infra.cut(&child, now).unwrap_or(ZoneCut {
                id,
                zone: child,
                servers: hosts,
                expires: now + Duration::from_secs(u64::from(ttl.max(1))),
                ds: crate::recursion::DsState::Unknown,
                minimise_fallback: None,
            });
        }
    }

    /// The addresses of `cut`'s servers that may be asked now, with the attempts each had
    /// for this question.
    fn candidates(
        &self,
        cut: &ZoneCut,
        work: &Work,
        attempts: &HashMap<IpAddr, u8>,
        now: Instant,
    ) -> Vec<(IpAddr, u8)> {
        let mut out: Vec<(IpAddr, u8)> = Vec::new();
        for server in &cut.servers {
            let Some(known) = self.infra.name_server(server, now) else {
                continue;
            };
            for address in known.addresses {
                let address = address.address;
                if !self.family_allowed(address) || out.iter().any(|(seen, _)| *seen == address) {
                    continue;
                }
                let attempts = attempts.get(&address).copied().unwrap_or(0);
                if attempts >= work.budget.attempts {
                    continue;
                }
                let state = self.infra.server(address, now);
                if state.is_lame(&cut.zone, now)
                    || (self.settings.outbound == Outbound::Auto && state.is_unreachable(now))
                {
                    continue;
                }
                out.push((address, attempts));
            }
        }
        out
    }

    /// The candidate to ask: the least asked, then not in back-off, then the fastest; one
    /// choice in 16 at random among those least asked.
    fn choose(&self, candidates: &[(IpAddr, u8)], now: Instant) -> Option<IpAddr> {
        let fewest = candidates.iter().map(|(_, attempts)| *attempts).min()?;
        let mut pool: Vec<(bool, u64, IpAddr)> = candidates
            .iter()
            .filter(|(_, attempts)| *attempts == fewest)
            .map(|(address, _)| {
                (
                    self.servers.down(*address, now),
                    self.servers.srtt_micros(*address),
                    *address,
                )
            })
            .collect();
        pool.sort_unstable();
        let up = pool.iter().filter(|(down, _, _)| !down).count();
        if up > 1 && crate::outbound::random_u32().is_multiple_of(16) {
            let pick = usize::try_from(crate::outbound::random_u32()).unwrap_or(0) % up;
            return Some(pool[pick].2);
        }
        pool.first().map(|(_, _, address)| *address)
    }

    /// Asks `cut`'s servers for `name`/`qtype` until one gives an answer that is not lame.
    /// A lame answer to a `minimised` question under relaxed minimisation ends the step
    /// without marking the server: the walk asks the full name instead (WP10.3).
    #[allow(
        clippy::too_many_arguments,
        reason = "the question, the cut and the state of one resolution"
    )]
    async fn ask_zone(
        &self,
        cut: &ZoneCut,
        zone: &[u8],
        name: &[u8],
        qtype: u16,
        depth: u8,
        work: &mut Work,
        minimised: bool,
    ) -> Result<Step, FailureCause> {
        let mut fetched: Vec<DnsName> = Vec::new();
        // Whether every attempt of this step failed for want of a route (extended error
        // 23) rather than a server's fault (22).
        let mut network_only = true;
        let mut asked = false;
        // Attempts per server for this question (REC-Q12: three).
        let mut attempts: HashMap<IpAddr, u8> = HashMap::new();
        let mut buf = Vec::new();
        loop {
            let now = Instant::now();
            work.check(now)?;
            let candidates = self.candidates(cut, work, &attempts, now);
            let Some(address) = self.choose(&candidates, now) else {
                if self.fetch_addresses(cut, depth, work, &mut fetched).await? {
                    continue;
                }
                return Err(if network_only && asked {
                    FailureCause::Network
                } else {
                    FailureCause::NoReachableAuthority
                });
            };
            asked = true;
            *attempts.entry(address).or_insert(0) += 1;
            match self.exchange(address, name, qtype, work, &mut buf).await {
                Err(AuthorityError::Malformed("0x20")) => {
                    // Asked again in lower case at once: the mismatch costs no attempt.
                    if let Some(count) = attempts.get_mut(&address) {
                        *count = count.saturating_sub(1);
                    }
                    network_only = false;
                }
                Err(AuthorityError::Unreachable(_)) => {}
                Err(_) => network_only = false,
                Ok(tcp) => {
                    network_only = false;
                    let Some(parsed) = message::parse(&buf) else {
                        self.count_authority(tcp, "malformed");
                        continue;
                    };
                    let step = message::classify(&parsed, zone, name, qtype);
                    match &step {
                        // WP10.3: the walk falls back to the full name.
                        Step::Lame(_)
                            if minimised && self.settings.minimisation == Minimisation::Relaxed =>
                        {
                            self.count_authority(tcp, "lame");
                            return Ok(step);
                        }
                        Step::Lame(reason) => {
                            self.count_authority(tcp, "lame");
                            tracing::debug!(server = %address, zone = %cut.zone, reason, "a lame answer");
                            let until = Instant::now() + self.infra_ttl();
                            let zone = cut.zone.clone();
                            self.infra.update_server(address, now, &mut |state| {
                                state.lame.retain(|(lame, _)| *lame != zone);
                                state.lame.push((zone.clone(), until));
                            });
                        }
                        Step::Referral(_) => {
                            self.count_authority(tcp, "referral");
                            return Ok(step);
                        }
                        _ => {
                            self.count_authority(tcp, "ok");
                            return Ok(step);
                        }
                    }
                }
            }
        }
    }

    fn infra_ttl(&self) -> Duration {
        self.settings.infra.ttl
    }

    fn count_authority(&self, tcp: bool, outcome: &str) {
        if self.metrics
            && let Some(index) = metrics::authority_index(tcp, outcome)
        {
            metrics::AUTHORITY_QUERY_COUNTER.inc(index);
        }
    }

    /// Looks up the addresses of `cut`'s servers that have none, within the fetch policy;
    /// returns whether some were found.
    async fn fetch_addresses(
        &self,
        cut: &ZoneCut,
        depth: u8,
        work: &mut Work,
        fetched: &mut Vec<DnsName>,
    ) -> Result<bool, FailureCause> {
        let allowed = usize::from(work.budget.lookups_at(depth));
        if fetched.len() >= allowed {
            return Ok(false);
        }
        let now = Instant::now();
        let waiting: Vec<DnsName> = cut
            .servers
            .iter()
            .filter(|server| !fetched.contains(server))
            .filter(|server| {
                // No address of a family in force.
                self.infra.name_server(server, now).is_none_or(|known| {
                    !known
                        .addresses
                        .iter()
                        .any(|address| self.family_allowed(address.address))
                })
            })
            .filter(|server| !work.stack.contains(&server.to_wire()))
            .cloned()
            .collect();
        if waiting.is_empty() {
            return Ok(false);
        }
        if depth.saturating_add(1) > work.budget.depth {
            return Err(FailureCause::Budget(BudgetBound::Depth));
        }
        let families: &[u16] = match self.settings.outbound {
            Outbound::V4 => &[types::A],
            Outbound::V6 => &[types::AAAA],
            Outbound::Auto | Outbound::Both => &[types::A, types::AAAA],
        };
        for server in waiting {
            if fetched.len() >= allowed {
                break;
            }
            fetched.push(server.clone());
            let wire = server.to_wire();
            work.stack.push(wire.clone());
            let mut found: Vec<(IpAddr, u32)> = Vec::new();
            for qtype in families {
                // AAAA only when A gave nothing, or IPv6 is the only family.
                if *qtype == types::AAAA && !found.is_empty() {
                    break;
                }
                match self.iterate(&wire, *qtype, depth + 1, work).await {
                    Ok(answer) => found.extend(
                        answer
                            .answer
                            .iter()
                            .filter(|rr| rr.rtype == *qtype)
                            .filter_map(|rr| rr.address().map(|address| (address, rr.ttl))),
                    ),
                    Err(Failed {
                        cause:
                            cause @ FailureCause::Budget(BudgetBound::Queries | BudgetBound::Time),
                        ..
                    }) => {
                        work.stack.pop();
                        return Err(cause);
                    }
                    Err(_) => {}
                }
            }
            work.stack.pop();
            if !found.is_empty() {
                let found: Vec<(IpAddr, u32)> = found
                    .into_iter()
                    .map(|(address, ttl)| (address, ttl.min(MAX_INFRA_TTL)))
                    .collect();
                self.infra.put_addresses(
                    &server,
                    &found,
                    AddressOrigin::Authoritative,
                    Instant::now(),
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One exchange with `address` for `name`/`qtype`, with the server's capabilities and
    /// cookies, writing the answer into `buf`; what it learnt goes into the caches.
    async fn exchange(
        &self,
        address: IpAddr,
        name: &[u8],
        qtype: u16,
        work: &mut Work,
        buf: &mut Vec<u8>,
    ) -> Result<bool, AuthorityError> {
        let now = Instant::now();
        let state = self.infra.server(address, now);
        let mix = self.servers.mixes_case(address, now) && !work.lower_case.contains(&address);
        let mut sent_name = name.to_vec();
        if mix {
            mix_case(&mut sent_name);
        }
        let timeout = self.servers.timeout(address, self.settings.timeout);
        let deadline = (now + timeout).min(work.deadline);
        let query = AuthorityQuery {
            server: SocketAddr::new(address, 53),
            qname: &sent_name,
            qtype,
            qclass: CLASS_IN,
            edns: state.edns != EdnsSupport::No,
            tcp: state.tcp_only || self.servers.tcp_forced(address, now),
            mix_case: mix,
            client_cookie: Some(self.client_cookie(address)),
            server_cookie: state.cookie,
            fresh_port: self.settings.fresh_port,
            deadline,
        };
        work.sent = work.sent.saturating_add(1);
        let result = self.authority.exchange(&query, buf).await;
        match result {
            Ok(exchange) => {
                // The ladder's retries are queries too.
                let extra = u16::from(exchange.truncated) + u16::from(query.edns && !exchange.edns);
                work.sent = work.sent.saturating_add(extra);
                self.note_exchange(address, &exchange, query.edns);
                Ok(exchange.transport == AuthorityTransport::Tcp)
            }
            Err(error) => {
                if matches!(error, AuthorityError::Malformed("0x20")) {
                    // Retry this server in lower case at once; two strikes and it is asked
                    // so for the infrastructure TTL.
                    self.servers.broke_case(address, now);
                    if work.lower_case.contains(&address) {
                        // Broken in lower case as well: a failure like any other.
                        self.note_error(address, &error, timeout, query.tcp);
                        return Err(AuthorityError::Malformed("the answer's question"));
                    }
                    work.lower_case.push(address);
                    self.count_authority(query.tcp, "malformed");
                    return Err(error);
                }
                self.note_error(address, &error, timeout, query.tcp);
                Err(error)
            }
        }
    }

    /// What an answered exchange taught about the server.
    fn note_exchange(
        &self,
        address: IpAddr,
        exchange: &crate::recursion::Exchange,
        asked_edns: bool,
    ) {
        let now = Instant::now();
        self.servers.answered(address, exchange.rtt, now);
        let tcp_only = self.servers.truncation(address, exchange.truncated, now);
        if self.metrics {
            metrics::AUTHORITY_LATENCY
                .observe(u64::try_from(exchange.rtt.as_micros()).unwrap_or(u64::MAX));
            if exchange.truncated {
                self.count_authority(false, "tc");
            }
        }
        let cookie = exchange.server_cookie;
        let edns = exchange.edns;
        self.infra.update_server(address, now, &mut |state| {
            if edns {
                state.edns = EdnsSupport::Yes;
            } else if asked_edns {
                state.edns = EdnsSupport::No;
            }
            if cookie.is_some() {
                state.cookie = cookie;
            }
            if tcp_only {
                state.tcp_only = true;
            }
            state.unreachable_until = None;
        });
    }

    /// What a failed exchange taught about the server.
    fn note_error(&self, address: IpAddr, error: &AuthorityError, timeout: Duration, tcp: bool) {
        let now = Instant::now();
        self.servers.failed(address, timeout, now);
        self.count_authority(tcp, error.outcome());
        let unreachable = matches!(error, AuthorityError::Unreachable(_))
            && address.is_ipv6()
            && self.settings.outbound == Outbound::Auto;
        self.infra.update_server(address, now, &mut |state| {
            state.last_failure = Some(now);
            if unreachable {
                state.unreachable_until = Some(now + UNREACHABLE_REPROBE);
            }
        });
        tracing::debug!(server = %address, %error, "an authority exchange failed");
    }

    // -----------------------------------------------------------------------------------
    // The status

    /// The engine's part of the status.
    pub fn report(&self) -> RecursionReport {
        let now = Instant::now();
        let hints = self.hints();
        let priming = self.lock_priming();
        let last = priming.last;
        let expires = priming.expires;
        drop(priming);
        let mut root = Vec::new();
        if let Some(cut) = self.infra.cut(&DnsName::root(), now) {
            for server in &cut.servers {
                if let Some(known) = self.infra.name_server(server, now) {
                    for address in known.addresses {
                        root.push(RootServer {
                            name: server.clone(),
                            address: address.address,
                            srtt: self.servers.figures(address.address, now).srtt,
                        });
                    }
                }
            }
        }
        let mut problems = Vec::new();
        if last.is_some_and(|last| !last.ok) {
            problems.push("priming_failed".to_owned());
        }
        let bounds = self.settings.infra;
        RecursionReport {
            hints_source: hints.source.describe(),
            hints_date: hints.date,
            priming: last,
            root_expires_in: expires.map(|at| at.saturating_duration_since(now)),
            root,
            infra: self.infra.sizes(),
            infra_bounds: (bounds.cuts, bounds.servers),
            counters: self.counters(),
            budget: self.settings.budget,
            problems,
        }
    }

    /// A page of the infrastructure cache: the cuts at or below `suffix`, after `after`, at
    /// most `limit`, each with its servers and their figures.
    pub fn infra_page(
        &self,
        suffix: Option<&DnsName>,
        after: Option<&DnsName>,
        limit: usize,
    ) -> Vec<InfraCutView> {
        let now = Instant::now();
        let secs = |at: Instant| {
            u32::try_from(at.saturating_duration_since(now).as_secs()).unwrap_or(u32::MAX)
        };
        self.infra
            .list(suffix, after, limit, now)
            .into_iter()
            .map(|cut| InfraCutView {
                servers: cut
                    .servers
                    .iter()
                    .map(|server| InfraServerView {
                        name: server.clone(),
                        addresses: self
                            .infra
                            .name_server(server, now)
                            .map(|known| known.addresses)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|address| {
                                let state = self.infra.server(address.address, now);
                                InfraAddressView {
                                    address: address.address,
                                    origin: address.origin,
                                    ttl: secs(address.expires),
                                    figures: self.servers.figures(address.address, now),
                                    edns: state.edns,
                                    tcp_only: state.tcp_only,
                                    lame: state.is_lame(&cut.zone, now),
                                }
                            })
                            .collect(),
                    })
                    .collect(),
                ds: cut.ds.as_str(),
                ttl: secs(cut.expires),
                zone: cut.zone,
            })
            .collect()
    }

    /// Flushes the infrastructure cache, or the cuts and names at or below `suffix`; the
    /// root's servers come back from the hints and are primed again. Returns the entries
    /// removed.
    pub fn flush_infra(&self, suffix: Option<&DnsName>) -> usize {
        let removed = self.infra.flush(suffix);
        // WP10.3: the names known to exist go with the cuts.
        {
            let mut known = self.names.lock().unwrap_or_else(PoisonError::into_inner);
            match suffix {
                None => known.names.clear(),
                Some(suffix) => {
                    let suffix = suffix.to_wire();
                    known
                        .names
                        .retain(|name, _| !name::is_within(name, &suffix));
                }
            }
        }
        if suffix.is_none() {
            self.servers.clear();
        }
        let now = Instant::now();
        if self.install_hints(now) {
            self.lock_priming().next_at = now;
        }
        removed
    }

    /// Removes the failures of the failure cache, or those at or below `suffix` (lowercase
    /// wire form), with the answer cache's flush. Returns how many.
    pub fn flush_failures(&self, suffix: Option<&[u8]>) -> usize {
        self.failures.flush(suffix)
    }

    /// The failure cache.
    pub fn failures(&self) -> &Arc<dyn FailureCache> {
        &self.failures
    }

    // WP10.3: QNAME minimisation's memory.
    /// Whether a minimised question showed `name` to exist without a cut, within the
    /// infrastructure TTL.
    fn known_name(&self, name: &[u8], now: Instant) -> bool {
        let mut known = self.names.lock().unwrap_or_else(PoisonError::into_inner);
        known.tick += 1;
        let tick = known.tick;
        match known.names.get_mut(name) {
            Some((until, used)) if *until > now => {
                *used = tick;
                true
            }
            _ => false,
        }
    }

    /// Remembers that `name` exists without a cut for the infrastructure TTL.
    fn learn_name(&self, name: &[u8], now: Instant) {
        let until = now + self.infra_ttl();
        let bound = self.settings.infra.servers.max(16);
        let mut known = self.names.lock().unwrap_or_else(PoisonError::into_inner);
        known.tick += 1;
        let tick = known.tick;
        known.names.insert(name.to_vec(), (until, tick));
        crate::infra::trim(&mut known.names, bound, |(_, used)| *used);
    }

    /// Starts a priming now (`dns.recursion.prime`); false when one is in flight.
    pub fn prime_now_requested(&self) -> bool {
        let mut priming = self.lock_priming();
        if priming.in_flight {
            return false;
        }
        priming.next_at = Instant::now();
        true
    }
}

// WP10.3: QNAME minimisation (RFC 9156 section 3, REC-Q8).
/// The minimising steps that add one label each (RFC 9156 `MINIMISE_ONE_LAB`).
pub const MINIMISE_ONE_LABEL: u8 = 4;

/// The most minimising steps of one walk (RFC 9156 `MAX_MINIMISE_COUNT`).
pub const MAX_MINIMISE: u8 = 10;

/// The type of a minimised question: the original type, or A for the types a server may
/// refuse or answer from another zone at a name that is not the one asked (DS, ANY, the
/// DNSSEC and the meta types), as RFC 9156 section 2.1 allows.
pub fn minimised_type(qtype: u16) -> u16 {
    if matches!(
        qtype,
        0 | types::DS | types::RRSIG | types::NSEC | types::NSEC3 | 41
    ) || (128..=255).contains(&qtype)
    {
        types::A
    } else {
        qtype
    }
}

/// The name each step of a walk asks (RFC 9156 section 3): the zone cut and one more label
/// for the first [`MINIMISE_ONE_LABEL`] steps, then more labels at a time so that at most
/// [`MAX_MINIMISE`] steps are minimised; the full name when the mode is off, when the cut's
/// servers are remembered as breaking on minimised questions (relaxed only), or once the
/// next step would reach it.
#[derive(Debug)]
pub struct Minimiser<'a> {
    mode: Minimisation,
    name: &'a [u8],
    qtype: u16,
    labels: usize,
    /// The labels of the name asked last.
    child: usize,
    /// The minimising steps so far.
    count: u8,
}

impl<'a> Minimiser<'a> {
    /// The minimiser of a walk for `name`/`qtype`.
    pub fn new(mode: Minimisation, name: &'a [u8], qtype: u16) -> Self {
        Self {
            mode,
            name,
            qtype,
            labels: name::label_count(name),
            child: 0,
            count: 0,
        }
    }

    /// The question for the servers of `zone`, whose minimisation `fallback` says broke;
    /// the names `known` says exist without a cut are not asked again.
    pub fn next(
        &mut self,
        zone: &[u8],
        fallback: bool,
        known: &dyn Fn(&[u8]) -> bool,
    ) -> (&'a [u8], u16) {
        self.child = self.child.max(name::label_count(zone));
        while self.child + 1 < self.labels
            && known(name::suffix(self.name, self.labels - self.child - 1))
        {
            self.child += 1;
        }
        let full = (self.name, self.qtype);
        if self.mode == Minimisation::Off
            || (fallback && self.mode == Minimisation::Relaxed)
            || self.count >= MAX_MINIMISE
            || self.child >= self.labels
        {
            return full;
        }
        let left = self.labels - self.child;
        let add = if self.count < MINIMISE_ONE_LABEL {
            1
        } else {
            left.div_ceil(usize::from(MAX_MINIMISE - self.count))
        };
        let child = self.child + add;
        if child >= self.labels {
            self.child = self.labels;
            return full;
        }
        self.child = child;
        self.count += 1;
        (
            name::suffix(self.name, self.labels - child),
            minimised_type(self.qtype),
        )
    }

    /// A referral to `zone`: the next step adds labels from it.
    pub fn referred(&mut self, zone: &[u8]) {
        self.child = name::label_count(zone);
    }
}
// WP10.3: end.

/// The CNAME links of a chain (a DNAME counts by the CNAME it stands for).
fn links(chain: &[Rr]) -> usize {
    chain.iter().filter(|rr| rr.rtype == types::CNAME).count()
}

/// Gives the letters of an uncompressed wire name a random case (0x20).
pub fn mix_case(name: &mut [u8]) {
    let mut bits = [0u8; 32];
    crate::outbound::random_fill(&mut bits);
    let mut index = 0usize;
    let mut pos = 0;
    while let Some(&len) = name.get(pos) {
        if len == 0 || len & 0xc0 != 0 {
            return;
        }
        let end = (pos + 1 + usize::from(len)).min(name.len());
        for octet in &mut name[pos + 1..end] {
            if octet.is_ascii_alphabetic() {
                let bit = (bits[(index / 8) % bits.len()] >> (index % 8)) & 1;
                index += 1;
                if bit == 1 {
                    octet.make_ascii_uppercase();
                } else {
                    octet.make_ascii_lowercase();
                }
            }
        }
        pos = end;
    }
}

/// Adds the extended error `ede` (RFC 8914, no text) to the OPT record of `answer`, which
/// must be its last record; nothing when it has none.
pub fn add_ede(answer: &mut Vec<u8>, ede: ExtendedError) {
    let Some(header) = crate::wire::parse_header(answer) else {
        return;
    };
    let Some(mut pos) = crate::wire::questions_end(answer, header.qdcount) else {
        return;
    };
    let total =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    for _ in 0..total {
        let Some(record) = crate::wire::read_record(answer, pos) else {
            return;
        };
        if record.rtype == crate::wire::TYPE_OPT && record.end() == answer.len() {
            let Ok(rdlen) = u16::try_from(record.rdlen + 6) else {
                return;
            };
            let at = record.rdata - 2;
            answer[at..at + 2].copy_from_slice(&rdlen.to_be_bytes());
            answer.extend_from_slice(&crate::wire::OPTION_EXTENDED_ERROR.to_be_bytes());
            answer.extend_from_slice(&2u16.to_be_bytes());
            answer.extend_from_slice(&ede.code().to_be_bytes());
            return;
        }
        pos = record.end();
    }
}

#[cfg(test)]
mod tests;
