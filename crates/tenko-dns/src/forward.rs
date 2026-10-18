//! The resolver side's forwarder (WP5.1, plan section 2.8, DNS-02, DNS-23): queries outside
//! the authoritative zones go to upstream resolvers chosen by forwarding rule, through a
//! cache with serve-stale and prefetch, for the clients the recursion access list allows.
//! It replaced the plain forwarder of Slice 4 (P2-Q16) behind the same [`ForwardSink`].
//!
//! **On the query path** ([`ForwardSink::intake`], nothing allocated):
//!
//! 1. The recursion check (TGL-22): the access list of the client's view (`View.recursion`)
//!    decides; a view without one, and the implicit default view, follow the profile's
//!    default ([`RecursionDefault`]: the prefixes IPAM knows and loopback, no client, or
//!    every client). A view whose list is gone allows no client. A refused client gets
//!    REFUSED with the extended error "Prohibited" (18).
//! 2. A name no rule, no stub zone and no configured upstream covers is REFUSED with
//!    "Not Authoritative" (20).
//! 3. The cache answers a fresh entry ([`Cache::answer`]); else the query is copied and
//!    handed over ([`ForwardSink::submit`], a queue of [`QUEUE`]; a full queue drops it).
//!
//! **Off the query path** (a dispatcher on tokio running up to [`IN_FLIGHT`] queries):
//!
//! 1. The route: the stub zone with the longest apex at or above the name when it is at
//!    least as long as the rule's suffix, else the rule the resolver chose (the longest
//!    suffix of the query's view, then of all views; a root rule `.` in the store is the
//!    default forwarder), else the upstreams of `[dns] forwarders`. The store's root rule
//!    therefore wins over the configuration.
//! 2. The upstream set of the route ([`Pools`]) asks within the budget
//!    (`forward_timeout_ms`, `forward_retries`), and its answer goes into the cache.
//! 3. Serve-stale (RFC 8767): when the cache holds an expired entry within the stale window
//!    and the upstreams fail, are all in back-off, or take longer than the stale budget, the
//!    client gets the stale entry with a TTL of 30 seconds; the upstream query goes on in
//!    the background and refreshes the entry when it answers.
//! 4. The answer is relayed with the client's id, its question as sent, RA, AD clear, and
//!    this node's OPT record (the client's cookie); a UDP answer over the client's limit is
//!    cut to the header and question with TC. When nothing answers, SERVFAIL.
//!
//! **Stub zones** (zones of kind stub): the zone's `source` servers are asked for the NS
//! set of the apex; the name servers' addresses come from the glue, else from A and AAAA
//! queries through the forwarder's own routes; the queries for names in the zone go to
//! those addresses, which are learnt again when the NS set's TTL (30 seconds to one day)
//! has passed. A stub zone whose servers cannot be learnt answers SERVFAIL and is listed in
//! the status with the reason ([`Forwarder::stubs`]); learnt servers that expired keep
//! serving while a new attempt fails. A name server is asked on port 53, or on the port of
//! the source server with its address.
//!
//! **Housekeeping** every 200 ms: the prefetch queue of the cache is asked again; every
//! minute the entries past their stale window are purged and the upstream sets of rules
//! and stub zones that are gone are dropped.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tenko_core::dns::{
    DnsName, ForwardRule, ForwardRuleId, ForwardTransport, QueryTransport, ViewId, Zone, ZoneId,
};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    authoritative::{EDE_NOT_AUTHORITATIVE, EDE_PROHIBITED, rcode},
    cache::{self, Cache, CacheKey, CacheSettings, Client, ClientEdns, Flushed, Hit},
    catalog::{Catalog, CatalogHandle},
    codec::{Codec, DomainCodec, Request},
    log::{QueryLogEntry, QueryLogSink},
    metrics,
    name::{self, NameBuf},
    outbound::Question,
    pool::{Budget, MemberHealth, PoolKey, Pools, UpstreamSet, UpstreamSpec},
    respond::{ForwardQuery, ForwardSink, Intake, IntakeQuery, ReplyPath},
    upstream::UpstreamError,
    wire::{self, HEADER_LEN, MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD},
};

/// The default time an upstream has to answer one attempt.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2_000);

/// The default number of attempts after the first.
pub const DEFAULT_RETRIES: u8 = 2;

/// The default time a client waits for an upstream before a stale answer (RFC 8767's
/// suggested client response timer).
pub const DEFAULT_STALE_BUDGET: Duration = Duration::from_millis(1_800);

/// Forwarded queries waiting for the dispatcher before new ones are dropped.
pub const QUEUE: usize = 4_096;

/// Forwarded queries in flight at once.
pub const IN_FLIGHT: usize = 1_024;

/// The shortest and longest time a stub zone's learnt name servers are used.
pub const STUB_TTL: (u32, u32) = (30, 86_400);

/// The time before a stub zone whose servers could not be learnt is tried again.
pub const STUB_RETRY: Duration = Duration::from_secs(30);

/// The housekeeping period (the prefetch queue).
const HOUSEKEEPING: Duration = Duration::from_millis(200);

/// The purge period.
const PURGE: Duration = Duration::from_secs(60);

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Who may recurse when a view names no recursion access list (TGL-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecursionDefault {
    /// The prefixes IPAM knows and loopback (the Home and Standard profiles).
    #[default]
    KnownPrefixes,
    /// No client: every view must name its list (the Hardened profile).
    Nobody,
    /// Every client: an open resolver (the Lab profile).
    Anyone,
}

/// Who may recurse: the profile's default and the prefixes IPAM knows, both kept current
/// by the role (the profile can change at setup, the prefixes at any time) and read on the
/// query path without a lock.
#[derive(Debug, Default)]
pub struct RecursionPolicy {
    default: std::sync::atomic::AtomicU8,
    prefixes: ArcSwap<Vec<IpNet>>,
}

impl RecursionPolicy {
    /// A policy with `default` and no known prefix.
    pub fn new(default: RecursionDefault) -> Self {
        let policy = Self::default();
        policy.set_default(default);
        policy
    }

    /// The default for views without a recursion access list.
    pub fn default_rule(&self) -> RecursionDefault {
        match self.default.load(Ordering::Relaxed) {
            1 => RecursionDefault::Nobody,
            2 => RecursionDefault::Anyone,
            _ => RecursionDefault::KnownPrefixes,
        }
    }

    /// Changes the default.
    pub fn set_default(&self, default: RecursionDefault) {
        let value = match default {
            RecursionDefault::KnownPrefixes => 0,
            RecursionDefault::Nobody => 1,
            RecursionDefault::Anyone => 2,
        };
        self.default.store(value, Ordering::Relaxed);
    }

    /// Replaces the prefixes IPAM knows.
    pub fn set_prefixes(&self, prefixes: Vec<IpNet>) {
        self.prefixes.store(Arc::new(prefixes));
    }

    /// Whether a known prefix holds `address`.
    pub fn known(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        self.prefixes
            .load()
            .iter()
            .any(|prefix| prefix.contains(&address))
    }

    /// The number of known prefixes.
    pub fn prefix_count(&self) -> usize {
        self.prefixes.load().len()
    }

    /// Whether the default allows `client` (a view without an access list).
    pub fn allows_by_default(&self, client: IpAddr) -> bool {
        match self.default_rule() {
            RecursionDefault::Anyone => true,
            RecursionDefault::Nobody => false,
            RecursionDefault::KnownPrefixes => {
                let client = client.to_canonical();
                client.is_loopback() || self.known(client)
            }
        }
    }
}

/// The settings of the forwarder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSettings {
    /// The default upstreams (`[dns] forwarders`); empty: only rules and stub zones forward.
    pub upstreams: Vec<UpstreamSpec>,
    /// The time one attempt has.
    pub timeout: Duration,
    /// Attempts after the first.
    pub retries: u8,
    /// The server's EDNS UDP size (`edns.udp_size`), the upper bound of a UDP answer.
    pub udp_size: u16,
    /// Count forwarded answers in the engine's metrics.
    pub metrics: bool,
    /// The cache; `None` keeps none.
    pub cache: Option<CacheSettings>,
    /// The time a client waits for an upstream before it gets a stale answer.
    pub stale_budget: Duration,
    /// The CA (PEM) DoT and DoH certificates are checked against, instead of the system's
    /// roots.
    pub upstream_ca: Option<Vec<u8>>,
}

impl Default for ForwardSettings {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            udp_size: SERVER_UDP_PAYLOAD,
            metrics: true,
            cache: Some(CacheSettings::default()),
            stale_budget: DEFAULT_STALE_BUDGET,
            upstream_ca: None,
        }
    }
}

/// What the forwarder counted since it started.
#[derive(Debug, Default)]
struct ForwardCounters {
    submitted: AtomicU64,
    dropped: AtomicU64,
    answered: AtomicU64,
    failed: AtomicU64,
    timeouts: AtomicU64,
    refused: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    prefetched: AtomicU64,
}

/// A copy of the counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardStats {
    /// Queries handed over.
    pub submitted: u64,
    /// Queries dropped because the queue was full.
    pub dropped: u64,
    /// Answers relayed from an upstream.
    pub answered: u64,
    /// Queries answered with SERVFAIL because nothing answered.
    pub failed: u64,
    /// Queries whose upstream attempts all failed or timed out.
    pub timeouts: u64,
    /// Queries refused (recursion not allowed, no upstream).
    pub refused: u64,
    /// Answers from the cache on the query path.
    pub hits: u64,
    /// Queries the cache could not answer.
    pub misses: u64,
    /// Stale answers.
    pub stale: u64,
    /// Entries prefetched.
    pub prefetched: u64,
}

impl ForwardStats {
    /// The share of cache lookups that hit, when there were any.
    #[allow(clippy::cast_precision_loss, reason = "a ratio for people")]
    pub fn hit_ratio(&self) -> Option<f64> {
        let lookups = self.hits + self.misses;
        (lookups > 0).then(|| self.hits as f64 / lookups as f64)
    }
}

/// The state of one stub zone, for the status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubReport {
    /// The zone's apex.
    pub zone: DnsName,
    /// The name servers' addresses learnt, `address:port`.
    pub servers: Vec<String>,
    /// Why the last attempt to learn them failed.
    pub error: Option<String>,
}

#[derive(Debug, Default)]
struct StubState {
    specs: Vec<UpstreamSpec>,
    expires: Option<Instant>,
    retry_at: Option<Instant>,
    error: Option<String>,
}

struct Submitted {
    query: ForwardQuery,
    at: Instant,
}

struct Shared {
    settings: ForwardSettings,
    catalog: CatalogHandle,
    log: Option<Arc<dyn QueryLogSink>>,
    counters: ForwardCounters,
    cache: Option<Cache>,
    pools: Pools,
    recursion: Arc<RecursionPolicy>,
    stubs: tokio::sync::Mutex<HashMap<ZoneId, StubState>>,
    stub_reports: Mutex<BTreeMap<ZoneId, StubReport>>,
}

/// The forwarder; see the module documentation.
pub struct Forwarder {
    queue: mpsc::Sender<Submitted>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarder")
            .field("upstreams", &self.shared.settings.upstreams)
            .field("cache", &self.shared.cache)
            .finish_non_exhaustive()
    }
}

/// The route of a query.
#[derive(Debug, Clone)]
enum Route {
    Default,
    Rule(Box<ForwardRule>),
    Stub(Box<Zone>),
}

/// Whether the lowercase wire name `qname` is at or below `suffix`, without allocating.
pub fn within(qname: &[u8], suffix: &DnsName) -> bool {
    if suffix.is_root() {
        return true;
    }
    let (have, want) = (name::label_count(qname), suffix.label_count());
    if want > have {
        return false;
    }
    let mut tail = name::suffix(qname, have - want);
    for label in suffix.labels() {
        let Some(&len) = tail.first() else {
            return false;
        };
        let len = usize::from(len);
        if tail.len() < 1 + len || !tail[1..=len].eq_ignore_ascii_case(label.as_bytes()) {
            return false;
        }
        tail = &tail[1 + len..];
    }
    true
}

/// The stub zone with the longest apex at or above `qname`.
fn stub_for<'a>(catalog: &'a Catalog, qname: &[u8]) -> Option<&'a Zone> {
    catalog
        .stub_zones()
        .filter(|zone| within(qname, &zone.name))
        .max_by_key(|zone| zone.name.label_count())
}

fn route(catalog: &Catalog, qname: &[u8], rule: Option<ForwardRuleId>) -> Route {
    let rule = rule.and_then(|id| catalog.forward_rule(id));
    match (stub_for(catalog, qname), rule) {
        (Some(stub), Some(rule)) if stub.name.label_count() >= rule.suffix.label_count() => {
            Route::Stub(Box::new(stub.clone()))
        }
        (Some(stub), None) => Route::Stub(Box::new(stub.clone())),
        (_, Some(rule)) => Route::Rule(Box::new(rule.clone())),
        (None, None) => Route::Default,
    }
}

impl Forwarder {
    /// Starts the dispatcher and the housekeeping on the current tokio runtime; they end
    /// when `stop` is cancelled. `log` gets one entry per forwarded query; `recursion` is
    /// the default and the prefixes IPAM knows, which the role keeps current.
    pub fn start(
        settings: ForwardSettings,
        catalog: CatalogHandle,
        log: Option<Arc<dyn QueryLogSink>>,
        recursion: Arc<RecursionPolicy>,
        stop: CancellationToken,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        if settings.metrics {
            metrics::seal();
        }
        let (sender, receiver) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared {
            cache: settings.cache.map(Cache::new),
            pools: Pools::new(settings.upstream_ca.clone()),
            settings,
            catalog,
            log,
            counters: ForwardCounters::default(),
            recursion,
            stubs: tokio::sync::Mutex::new(HashMap::new()),
            stub_reports: Mutex::new(BTreeMap::new()),
        });
        let forwarder = Arc::new(Self {
            queue: sender,
            shared: Arc::clone(&shared),
        });
        let task = tokio::spawn(async move {
            tokio::join!(
                dispatch(Arc::clone(&shared), receiver, stop.clone()),
                housekeeping(shared, stop)
            );
        });
        (forwarder, task)
    }

    /// The configured default upstreams.
    pub fn upstreams(&self) -> &[UpstreamSpec] {
        &self.shared.settings.upstreams
    }

    /// The settings.
    pub fn settings(&self) -> &ForwardSettings {
        &self.shared.settings
    }

    /// The cache, when there is one.
    pub fn cache(&self) -> Option<&Cache> {
        self.shared.cache.as_ref()
    }

    /// Empties the cache, or the entries at or below `suffix`; `None` without a cache.
    pub fn flush(&self, suffix: Option<&DnsName>) -> Option<Flushed> {
        let suffix = suffix.map(DnsName::to_wire);
        self.shared
            .cache
            .as_ref()
            .map(|cache| cache.flush(suffix.as_deref()))
    }

    /// The counters.
    pub fn stats(&self) -> ForwardStats {
        let counters = &self.shared.counters;
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ForwardStats {
            submitted: read(&counters.submitted),
            dropped: read(&counters.dropped),
            answered: read(&counters.answered),
            failed: read(&counters.failed),
            timeouts: read(&counters.timeouts),
            refused: read(&counters.refused),
            hits: read(&counters.hits),
            misses: read(&counters.misses),
            stale: read(&counters.stale),
            prefetched: read(&counters.prefetched),
        }
    }

    /// The stub zones the forwarder has tried, with their servers or the reason they failed.
    pub fn stubs(&self) -> Vec<StubReport> {
        let catalog = self.shared.catalog.load();
        let reports = self
            .shared
            .stub_reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        catalog
            .stub_zones()
            .map(|zone| {
                reports
                    .get(&zone.id)
                    .cloned()
                    .unwrap_or_else(|| StubReport {
                        zone: zone.name.clone(),
                        servers: Vec::new(),
                        error: None,
                    })
            })
            .collect()
    }

    /// The views whose recursion access list does not exist: they allow no client.
    pub fn recursion_problems(&self) -> Vec<String> {
        let catalog = self.shared.catalog.load();
        let mut problems = Vec::new();
        for view in catalog.view_rows() {
            if let Some(acl) = view.recursion
                && catalog.acl(acl).is_none()
            {
                problems.push(format!(
                    "view `{}` names recursion access list {acl}, which does not exist: no \
                     client of the view may recurse",
                    view.name
                ));
            }
        }
        problems
    }

    /// The upstream sets built so far, by rule label, with each upstream's state.
    pub fn upstream_health(&self) -> Vec<(String, Vec<MemberHealth>)> {
        let catalog = self.shared.catalog.load();
        let mut keys = vec![PoolKey::Default];
        keys.extend(catalog.forward_rules().map(|rule| PoolKey::Rule(rule.id)));
        keys.extend(catalog.stub_zones().map(|zone| PoolKey::Stub(zone.id)));
        keys.into_iter()
            .filter_map(|key| self.shared.pools.held(key))
            .map(|set| (set.rule().to_owned(), set.health()))
            .collect()
    }

    /// The recursion policy the check reads.
    pub fn recursion(&self) -> &RecursionPolicy {
        &self.shared.recursion
    }
}

impl Shared {
    fn recursion_allowed(&self, catalog: &Catalog, view: Option<ViewId>, client: IpAddr) -> bool {
        let client = client.to_canonical();
        if let Some(list) = view
            .and_then(|view| catalog.view(view))
            .and_then(|view| view.recursion)
        {
            return catalog
                .acl(list)
                .is_some_and(|acl| acl.allows(client, None));
        }
        self.recursion.allows_by_default(client)
    }

    fn budget(&self) -> Budget {
        Budget {
            timeout: self.settings.timeout,
            retries: self.settings.retries,
        }
    }

    /// The upstream set of a route.
    async fn set_for(self: &Arc<Self>, route: &Route) -> Result<Arc<UpstreamSet>, String> {
        match route {
            Route::Stub(zone) => self.stub_set(zone).await,
            other => self.direct_set(other),
        }
    }

    /// The upstream set of the default forwarder or a rule (a stub zone has none).
    fn direct_set(&self, route: &Route) -> Result<Arc<UpstreamSet>, String> {
        match route {
            Route::Default => self
                .pools
                .get(PoolKey::Default, "default", &self.settings.upstreams),
            Route::Rule(rule) => self.pools.get(
                PoolKey::Rule(rule.id),
                rule.suffix.as_str(),
                &UpstreamSpec::of_rule(rule),
            ),
            Route::Stub(zone) => Err(format!("stub zone {} has no direct upstreams", zone.name)),
        }
    }

    /// The set of a stub zone's name servers, learnt when needed.
    async fn stub_set(self: &Arc<Self>, zone: &Zone) -> Result<Arc<UpstreamSet>, String> {
        let label = format!("stub:{}", zone.name);
        let mut states = self.stubs.lock().await;
        let now = Instant::now();
        let state = states.entry(zone.id).or_default();
        let fresh = state.expires.is_some_and(|expires| expires > now);
        let waiting = state.retry_at.is_some_and(|retry| retry > now);
        if !fresh && !waiting {
            match self.learn(zone).await {
                Ok((specs, ttl)) => {
                    state.specs = specs;
                    state.expires = Some(now + Duration::from_secs(u64::from(ttl)));
                    state.retry_at = None;
                    state.error = None;
                }
                Err(error) => {
                    tracing::warn!(zone = %zone.name, %error, "the name servers of a stub zone could not be learnt");
                    state.retry_at = Some(now + STUB_RETRY);
                    state.error = Some(error);
                }
            }
            self.stub_reports
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    zone.id,
                    StubReport {
                        zone: zone.name.clone(),
                        servers: state
                            .specs
                            .iter()
                            .map(|spec| spec.address.to_string())
                            .collect(),
                        error: state.error.clone(),
                    },
                );
        }
        if state.specs.is_empty() {
            return Err(state
                .error
                .clone()
                .unwrap_or_else(|| "the stub zone's name servers are not known".to_owned()));
        }
        let specs = state.specs.clone();
        drop(states);
        self.pools.get(PoolKey::Stub(zone.id), &label, &specs)
    }

    /// Asks a stub zone's source servers for the NS set of its apex and finds the name
    /// servers' addresses. Returns them with the TTL to keep them.
    async fn learn(self: &Arc<Self>, zone: &Zone) -> Result<(Vec<UpstreamSpec>, u32), String> {
        let primaries: Vec<UpstreamSpec> = zone
            .source
            .as_ref()
            .map(|source| {
                source
                    .primaries
                    .iter()
                    .map(|primary| UpstreamSpec {
                        address: std::net::SocketAddr::new(primary.address, primary.port),
                        transport: ForwardTransport::Plain,
                        tcp_only: false,
                        tls_name: None,
                        path: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if primaries.is_empty() {
            return Err("the stub zone names no server to ask".to_owned());
        }
        let source = self.pools.get(
            PoolKey::StubSource(zone.id),
            &format!("stub-source:{}", zone.name),
            &primaries,
        )?;
        let apex = zone.name.to_wire();
        let mut answer = Vec::new();
        source
            .query(
                &Question {
                    qname: &apex,
                    qtype: TYPE_NS,
                    qclass: CLASS_IN,
                    rd: false,
                    cd: false,
                    dnssec_ok: false,
                },
                self.budget(),
                &mut answer,
            )
            .await
            .map_err(|error| {
                format!("the zone's servers did not answer for its NS set: {error}")
            })?;
        let (servers, glue, ttl) = parse_ns(&answer, &apex).ok_or_else(|| {
            "the answer of the zone's servers has no NS set for the apex".to_owned()
        })?;
        let mut addresses: Vec<IpAddr> = Vec::new();
        for server in &servers {
            let known: Vec<IpAddr> = glue
                .iter()
                .filter(|(owner, _)| owner == server)
                .map(|(_, address)| *address)
                .collect();
            if known.is_empty() {
                addresses.extend(self.addresses_of(server).await);
            } else {
                addresses.extend(known);
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err("no address was found for the zone's name servers".to_owned());
        }
        let specs = addresses
            .into_iter()
            .take(crate::pool::MAX_MEMBERS)
            .map(|address| UpstreamSpec {
                // A name server that is one of the source servers keeps that server's port.
                address: primaries
                    .iter()
                    .find(|primary| primary.address.ip() == address)
                    .map_or(std::net::SocketAddr::new(address, 53), |primary| {
                        primary.address
                    }),
                transport: ForwardTransport::Plain,
                tcp_only: false,
                tls_name: None,
                path: None,
            })
            .collect();
        Ok((specs, ttl.clamp(STUB_TTL.0, STUB_TTL.1)))
    }

    /// The A and AAAA addresses of a name, asked through the forwarder's rule for it or
    /// the default upstreams (never through a stub zone).
    async fn addresses_of(self: &Arc<Self>, name: &[u8]) -> Vec<IpAddr> {
        let catalog = self.catalog.load_full();
        let route = match catalog
            .forwarders()
            .find(name, None)
            .and_then(|id| catalog.forward_rule(id))
        {
            Some(rule) => Route::Rule(Box::new(rule.clone())),
            None => Route::Default,
        };
        let Ok(set) = self.direct_set(&route) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let mut answer = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            let question = Question {
                qname: name,
                qtype,
                qclass: CLASS_IN,
                rd: true,
                cd: false,
                dnssec_ok: false,
            };
            if set
                .query(&question, self.budget(), &mut answer)
                .await
                .is_ok()
            {
                found.extend(addresses_in(&answer));
            }
        }
        found
    }

    /// Asks `set` for `question`, puts the answer into the cache under `key` and returns it.
    async fn fetch(
        self: Arc<Self>,
        set: Arc<UpstreamSet>,
        question: OwnedQuestion,
        key: Option<CacheKey>,
        rule: Option<ForwardRuleId>,
    ) -> Result<Vec<u8>, UpstreamError> {
        let mut answer = Vec::new();
        set.query(&question.as_question(), self.budget(), &mut answer)
            .await?;
        if let (Some(cache), Some(key)) = (&self.cache, &key) {
            cache.insert(key, &answer, Instant::now(), rule);
        }
        Ok(answer)
    }

    fn count(&self, counter: fn(&ForwardCounters) -> &AtomicU64) {
        counter(&self.counters).fetch_add(1, Ordering::Relaxed);
    }
}

/// A question the forwarder owns, for the tasks that outlive a client's query.
#[derive(Debug, Clone)]
struct OwnedQuestion {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
    rd: bool,
    cd: bool,
    dnssec_ok: bool,
}

impl OwnedQuestion {
    fn as_question(&self) -> Question<'_> {
        Question {
            qname: &self.qname,
            qtype: self.qtype,
            qclass: self.qclass,
            rd: self.rd,
            cd: self.cd,
            dnssec_ok: self.dnssec_ok,
        }
    }
}

/// The NS targets of `apex` in the answer section, the A and AAAA glue of the additional
/// section and the NS set's TTL.
#[allow(clippy::type_complexity, reason = "three parts of one answer")]
fn parse_ns(message: &[u8], apex: &[u8]) -> Option<(Vec<Vec<u8>>, Vec<(Vec<u8>, IpAddr)>, u32)> {
    let header = wire::parse_header(message)?;
    let mut pos = wire::questions_end(message, header.qdcount)?;
    let mut servers = Vec::new();
    let mut glue = Vec::new();
    let mut ttl = u32::MAX;
    let mut owner = NameBuf::root();
    let mut target = NameBuf::root();
    let total =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    for index in 0..total {
        let record = wire::read_record(message, pos)?;
        wire::read_name(message, record.start, &mut owner)?;
        let section_answer_or_authority =
            index < usize::from(header.ancount) + usize::from(header.nscount);
        if section_answer_or_authority
            && record.rtype == TYPE_NS
            && owner.as_wire().eq_ignore_ascii_case(apex)
        {
            wire::read_name(message, record.rdata, &mut target)?;
            servers.push(target.as_wire().to_vec());
            ttl = ttl.min(record.ttl);
        } else if !section_answer_or_authority
            && let Some(address) = address_of(record.rtype, record.data(message))
        {
            glue.push((owner.as_wire().to_vec(), address));
        }
        pos = record.end();
    }
    (!servers.is_empty()).then_some((servers, glue, ttl))
}

fn address_of(rtype: u16, data: &[u8]) -> Option<IpAddr> {
    match (rtype, data.len()) {
        (TYPE_A, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
        (TYPE_AAAA, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
        _ => None,
    }
}

/// The A and AAAA addresses in the answer section of a message.
fn addresses_in(message: &[u8]) -> Vec<IpAddr> {
    let Some(header) = wire::parse_header(message) else {
        return Vec::new();
    };
    let Some(mut pos) = wire::questions_end(message, header.qdcount) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for _ in 0..header.ancount {
        let Some(record) = wire::read_record(message, pos) else {
            break;
        };
        if let Some(address) = address_of(record.rtype, record.data(message)) {
            found.push(address);
        }
        pos = record.end();
    }
    found
}

impl ForwardSink for Forwarder {
    fn submit(&self, query: ForwardQuery) {
        self.shared.count(|counters| &counters.submitted);
        if self
            .queue
            .try_send(Submitted {
                query,
                at: Instant::now(),
            })
            .is_err()
        {
            self.shared.count(|counters| &counters.dropped);
        }
    }

    fn intake(&self, query: &IntakeQuery<'_>, out: &mut Vec<u8>) -> Intake {
        let shared = &self.shared;
        let catalog = shared.catalog.load();
        if !shared.recursion_allowed(&catalog, query.view, query.client.ip()) {
            shared.count(|counters| &counters.refused);
            return Intake::Refuse {
                ede: EDE_PROHIBITED,
            };
        }
        let request = query.request;
        let qname = request.qname.as_wire();
        if query.rule.is_none()
            && shared.settings.upstreams.is_empty()
            && stub_for(&catalog, qname).is_none()
        {
            shared.count(|counters| &counters.refused);
            return Intake::Refuse {
                ede: EDE_NOT_AUTHORITATIVE,
            };
        }
        let Some(cache) = &shared.cache else {
            return Intake::Forward;
        };
        let Some(question_end) = wire::questions_end(query.message, 1) else {
            return Intake::Forward;
        };
        let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
        let key = CacheKey::new(
            query.view,
            qname,
            request.qtype,
            request.qclass,
            dnssec_ok,
            request.cd,
        );
        let client = Client {
            message: query.message,
            question_end,
            id: request.id,
            rd: request.rd,
            cd: request.cd,
            edns: request.edns.map(|edns| ClientEdns {
                udp_size: query.udp_size,
                dnssec_ok: edns.dnssec_ok,
                cookie: query.cookie,
            }),
            max_len: query.max_len,
        };
        let view = metrics::view_index(query.view.is_some());
        match cache.answer(&key, query.now, &client, out) {
            Hit::Fresh { rcode } => {
                shared.count(|counters| &counters.hits);
                if shared.settings.metrics {
                    metrics::CACHE_HIT_COUNTER.inc(view);
                }
                Intake::Answered {
                    rcode: u16::from(rcode),
                }
            }
            Hit::Expired | Hit::Miss => {
                shared.count(|counters| &counters.misses);
                if shared.settings.metrics {
                    metrics::CACHE_MISS_COUNTER.inc(view);
                }
                Intake::Forward
            }
        }
    }
}

async fn dispatch(
    shared: Arc<Shared>,
    mut receiver: mpsc::Receiver<Submitted>,
    stop: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(IN_FLIGHT));
    loop {
        let submitted = tokio::select! {
            () = stop.cancelled() => return,
            submitted = receiver.recv() => match submitted {
                Some(submitted) => submitted,
                None => return,
            },
        };
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            handle(&shared, submitted).await;
            drop(permit);
        });
    }
}

async fn housekeeping(shared: Arc<Shared>, stop: CancellationToken) {
    let mut tick = tokio::time::interval(HOUSEKEEPING);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut purge_at = Instant::now() + PURGE;
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = tick.tick() => {}
        }
        if let Some(cache) = &shared.cache {
            for (key, rule) in cache.take_prefetch() {
                tokio::spawn(prefetch(Arc::clone(&shared), key, rule));
            }
        }
        let now = Instant::now();
        if now >= purge_at {
            purge_at = now + PURGE;
            if let Some(cache) = &shared.cache {
                cache.purge(now);
            }
            let catalog = shared.catalog.load_full();
            shared.pools.retain(|key| match key {
                PoolKey::Default => true,
                PoolKey::Rule(id) => catalog.forward_rule(*id).is_some(),
                PoolKey::Stub(id) | PoolKey::StubSource(id) => catalog.stub_zone(*id).is_some(),
            });
        }
    }
}

/// Asks the upstream again for an entry the cache queued before it expires.
async fn prefetch(shared: Arc<Shared>, key: CacheKey, rule: Option<ForwardRuleId>) {
    let Some(cache) = &shared.cache else {
        return;
    };
    let catalog = shared.catalog.load_full();
    let qname = key.qname().to_vec();
    let rule = catalog.forwarders().find(&qname, key.view()).or(rule);
    let route = route(&catalog, &qname, rule);
    let Ok(set) = shared.set_for(&route).await else {
        cache.prefetch_failed(&key);
        return;
    };
    let question = OwnedQuestion {
        qname,
        qtype: key.qtype(),
        qclass: key.qclass(),
        rd: true,
        cd: key.cd(),
        dnssec_ok: key.dnssec_ok(),
    };
    let rule_id = match &route {
        Route::Rule(rule) => Some(rule.id),
        _ => None,
    };
    match Arc::clone(&shared)
        .fetch(set, question, Some(key.clone()), rule_id)
        .await
    {
        Ok(_) => shared.count(|counters| &counters.prefetched),
        Err(_) => cache.prefetch_failed(&key),
    }
}

/// How a forwarded query was answered.
enum Outcome {
    Upstream(Vec<u8>),
    Stale,
    Failed,
}

#[allow(clippy::too_many_lines, reason = "one query from hand-over to answer")]
async fn handle(shared: &Arc<Shared>, submitted: Submitted) {
    let Submitted { query, at } = submitted;
    let codec = DomainCodec::new();
    let mut request = Request::default();
    if codec.parse(&query.message, &mut request).is_err() {
        return;
    }
    let Some(question_end) = wire::questions_end(&query.message, 1) else {
        return;
    };
    let catalog = shared.catalog.load_full();
    let qname = request.qname.as_wire().to_vec();
    let route = route(&catalog, &qname, query.rule);
    let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
    let key = shared.cache.as_ref().map(|_| {
        CacheKey::new(
            query.view,
            &qname,
            request.qtype,
            request.qclass,
            dnssec_ok,
            request.cd,
        )
    });
    let question = OwnedQuestion {
        qname,
        qtype: request.qtype,
        qclass: request.qclass,
        rd: true,
        cd: request.cd,
        dnssec_ok,
    };
    let rule_id = match &route {
        Route::Rule(rule) => Some(rule.id),
        _ => None,
    };
    let has_stale = |now: Instant| match (&shared.cache, &key) {
        (Some(cache), Some(key)) => cache.has_stale(key, now),
        _ => false,
    };
    let outcome = match shared.set_for(&route).await {
        Err(error) => {
            tracing::debug!(%error, "a forwarded query has no usable upstream");
            if has_stale(Instant::now()) {
                Outcome::Stale
            } else {
                Outcome::Failed
            }
        }
        Ok(set) => {
            let now = Instant::now();
            let stale = has_stale(now);
            if stale && set.all_down(now) {
                Outcome::Stale
            } else if stale {
                let mut task =
                    tokio::spawn(Arc::clone(shared).fetch(set, question, key.clone(), rule_id));
                tokio::select! {
                    joined = &mut task => match joined {
                        Ok(Ok(answer)) => Outcome::Upstream(answer),
                        _ => Outcome::Stale,
                    },
                    // The upstream query goes on and refreshes the entry when it answers.
                    () = tokio::time::sleep(shared.settings.stale_budget) => Outcome::Stale,
                }
            } else if let Ok(answer) = Arc::clone(shared)
                .fetch(set, question, key.clone(), rule_id)
                .await
            {
                Outcome::Upstream(answer)
            } else {
                shared.count(|counters| &counters.timeouts);
                // An entry may have come in from another query meanwhile.
                if has_stale(Instant::now()) {
                    Outcome::Stale
                } else {
                    Outcome::Failed
                }
            }
        }
    };
    let max_len = if query.transport == QueryTransport::Udp {
        request.udp_len(shared.settings.udp_size)
    } else {
        MAX_MESSAGE_LEN
    };
    let client = Client {
        message: &query.message,
        question_end,
        id: request.id,
        rd: request.rd,
        cd: request.cd,
        edns: request.edns.map(|edns| ClientEdns {
            udp_size: shared.settings.udp_size,
            dnssec_ok: edns.dnssec_ok,
            cookie: query.cookie,
        }),
        max_len,
    };
    let mut out = Vec::with_capacity(512);
    let mut cached = false;
    let written = match outcome {
        Outcome::Upstream(answer) => cache::relay(&answer, &client, &mut out),
        Outcome::Stale => match (&shared.cache, &key) {
            (Some(cache), Some(key)) => {
                let written = cache.answer_stale(key, Instant::now(), &client, &mut out);
                if written.is_some() {
                    cached = true;
                    shared.count(|counters| &counters.stale);
                    if shared.settings.metrics {
                        metrics::CACHE_STALE_COUNTER.inc();
                    }
                }
                written
            }
            _ => None,
        },
        Outcome::Failed => None,
    };
    let code = if let Some(code) = written {
        if !cached {
            shared.count(|counters| &counters.answered);
        }
        u16::from(code)
    } else {
        shared.count(|counters| &counters.failed);
        match short_answer(&query.message, rcode::SERVFAIL) {
            Some(failed) => out = failed,
            None => return,
        }
        rcode::SERVFAIL
    };
    match &query.reply {
        ReplyPath::Udp(socket) => {
            let _ = socket.send_to(&out, query.client);
        }
        ReplyPath::Tcp(sender) => {
            let _ = sender.send(out).await;
        }
    }
    let micros = u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX);
    if shared.settings.metrics {
        metrics::QUERY_COUNTER.inc(metrics::query_index(
            query.transport,
            query.view.is_some(),
            code,
        ));
        metrics::QUERY_LATENCY.observe(metrics::proto_index(query.transport), micros);
    }
    if let Some(log) = &shared.log {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .saturating_sub(u128::from(micros));
        log.record(&QueryLogEntry {
            at_micros: u64::try_from(since).unwrap_or(u64::MAX),
            client: query.client.ip(),
            transport: query.transport,
            qname: request.qname.as_wire(),
            qtype: request.qtype,
            rcode: code,
            view: query.view,
            blocked: None,
            cached,
            duration_micros: u32::try_from(micros).unwrap_or(u32::MAX),
        });
    }
}

/// A header-and-question answer to the client's message with `code` (SERVFAIL).
fn short_answer(message: &[u8], code: u16) -> Option<Vec<u8>> {
    let header = wire::parse_header(message)?;
    let end = wire::questions_end(message, 1)?;
    let mut out = Vec::with_capacity(end);
    out.extend_from_slice(&message[..2]);
    out.push(0x80 | (header.opcode << 3) | u8::from(header.rd));
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the low four bits of the RCODE"
    )]
    out.push(0x80 | (code & 0x0f) as u8);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&message[HEADER_LEN..end]);
    Some(out)
}

#[cfg(test)]
mod tests;
