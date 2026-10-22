//! The infrastructure cache ([`InfraCache`], recursion plan section 2.2): per zone cut the
//! NS set with its TTL and the DS state once validated; per name server name its addresses
//! with their TTLs and where they came from; per server address its capabilities (EDNS,
//! TCP), its server cookie, its lameness per zone, its unwanted-answer count and its last
//! failure. The round-trip times stay in the pool ([`crate::pool`]), keyed by
//! [`crate::pool::PoolKey::Delegation`].
//!
//! It is read on the runtime only, never on the worker, so implementations may allocate
//! and lock freely. It holds no client data. [`MemInfra`] is the reference: correct,
//! bounded and simple (a least-recently-used scan on overflow).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, ExtendedError};

use super::{CutId, authority::ServerCookie};

/// The default infrastructure TTL (`[dns.recursion] infra_ttl_secs`, Unbound's 900): how
/// long a learnt capability, lameness or unreachability holds.
pub const INFRA_TTL: Duration = Duration::from_secs(900);

/// How long an IPv6 address that failed at once (no IPv6 route) is skipped before it is
/// tried again (recursion plan section 2.1, REC-Q9).
pub const UNREACHABLE_REPROBE: Duration = Duration::from_secs(6 * 3600);

/// The bounds of the infrastructure cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfraBounds {
    /// Zone cuts at most.
    pub cuts: usize,
    /// Server addresses at most (name server names count against it too).
    pub servers: usize,
    /// The infrastructure TTL.
    pub ttl: Duration,
}

impl InfraBounds {
    /// The Home profile's bounds.
    pub const HOME: Self = Self {
        cuts: 1_000,
        servers: 2_000,
        ttl: INFRA_TTL,
    };

    /// The bounds of the other profiles.
    pub const STANDARD: Self = Self {
        cuts: 10_000,
        servers: 20_000,
        ttl: INFRA_TTL,
    };
}

impl Default for InfraBounds {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Where a name server's address came from (the bailiwick rule of section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressOrigin {
    /// The root hints, before priming confirmed them.
    Hints,
    /// Sibling glue (a server in a sibling zone of the same parent): used for the step and
    /// unconfirmed until its own authority answers.
    SiblingGlue,
    /// In-domain glue of a referral (RFC 9471).
    Glue,
    /// An authoritative answer for the name server's own name.
    Authoritative,
}

impl AddressOrigin {
    /// The stable name (the API's `origin`).
    pub const fn as_str(self) -> &'static str {
        match self {
            AddressOrigin::Hints => "hints",
            AddressOrigin::SiblingGlue => "sibling_glue",
            AddressOrigin::Glue => "glue",
            AddressOrigin::Authoritative => "authoritative",
        }
    }
}

/// One address of a name server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerAddress {
    /// The address.
    pub address: IpAddr,
    /// Where it came from.
    pub origin: AddressOrigin,
    /// When it expires (its TTL).
    pub expires: Instant,
}

/// A name server name and its addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServer {
    /// The name.
    pub name: DnsName,
    /// The addresses, A and AAAA.
    pub addresses: Vec<ServerAddress>,
}

/// The DNSSEC state of a zone cut, once the validator walked it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DsState {
    /// Not validated yet.
    #[default]
    Unknown,
    /// A DS chain proves the zone's keys: the validated DNSKEY set (record data), until
    /// the smaller of its TTL and its signatures' expiry.
    Secure {
        /// The validated DNSKEY records' data.
        keys: Arc<[Vec<u8>]>,
        /// Valid until.
        until: Instant,
    },
    /// The parent proves there is no DS (or only unsupported algorithms): the zone and
    /// everything below it are insecure until the proof expires.
    Insecure {
        /// Valid until.
        until: Instant,
    },
    /// The chain to the zone fails.
    Bogus {
        /// The extended error that names the fault.
        ede: ExtendedError,
        /// Until (the failure time of RFC 9520).
        until: Instant,
    },
}

impl DsState {
    /// The stable name (the API's `ds`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            DsState::Unknown => "unknown",
            DsState::Secure { .. } => "secure",
            DsState::Insecure { .. } => "insecure",
            DsState::Bogus { .. } => "bogus",
        }
    }

    /// The state at `now`: a state past its time is unknown.
    #[must_use]
    pub fn at(&self, now: Instant) -> Self {
        match self {
            DsState::Secure { until, .. }
            | DsState::Insecure { until }
            | DsState::Bogus { until, .. }
                if *until <= now =>
            {
                DsState::Unknown
            }
            other => other.clone(),
        }
    }
}

/// A zone cut: a delegation the resolver followed (the root after priming).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneCut {
    /// The identifier (the key of its upstream set).
    pub id: CutId,
    /// The zone.
    pub zone: DnsName,
    /// The names of its name servers.
    pub servers: Vec<DnsName>,
    /// When the NS set expires.
    pub expires: Instant,
    /// The DNSSEC state.
    pub ds: DsState,
    /// QNAME minimisation falls back to the full name for this zone until then (RFC 9156
    /// relaxed mode, section 2.6).
    pub minimise_fallback: Option<Instant>,
}

/// Whether a server takes EDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EdnsSupport {
    /// Not learnt yet: ask with EDNS.
    #[default]
    Unknown,
    /// It answered a query with EDNS.
    Yes,
    /// It answered FORMERR or NOTIMP to EDNS (RFC 6891 section 6.2.2).
    No,
}

/// What the resolver learnt about one server address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerState {
    /// The address.
    pub address: IpAddr,
    /// Its EDNS support.
    pub edns: EdnsSupport,
    /// It truncates every UDP answer, or it is flooded with unwanted answers: ask over
    /// TCP.
    pub tcp_only: bool,
    /// The server cookie it last sent.
    pub cookie: Option<ServerCookie>,
    /// The zones it is lame for, each until a time.
    pub lame: Vec<(DnsName, Instant)>,
    /// Unwanted answers in the current hour (recursion plan section 2.1).
    pub unwanted: u32,
    /// Unreachable (a family without a route) until then.
    pub unreachable_until: Option<Instant>,
    /// Its last failure.
    pub last_failure: Option<Instant>,
}

impl ServerState {
    /// A server nothing is known about.
    pub fn unknown(address: IpAddr) -> Self {
        Self {
            address,
            edns: EdnsSupport::Unknown,
            tcp_only: false,
            cookie: None,
            lame: Vec::new(),
            unwanted: 0,
            unreachable_until: None,
            last_failure: None,
        }
    }

    /// Whether it is lame for `zone` at `now`.
    pub fn is_lame(&self, zone: &DnsName, now: Instant) -> bool {
        self.lame
            .iter()
            .any(|(lame, until)| lame == zone && *until > now)
    }

    /// Whether it is skipped as unreachable at `now`.
    pub fn is_unreachable(&self, now: Instant) -> bool {
        self.unreachable_until.is_some_and(|until| until > now)
    }
}

/// The sizes of the infrastructure cache, for the status and the gauge
/// `tenko_dns_infra_entries{kind}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InfraSizes {
    /// Zone cuts.
    pub cuts: usize,
    /// Server addresses.
    pub servers: usize,
    /// Name server names.
    pub names: usize,
}

/// The infrastructure cache; see the module documentation.
pub trait InfraCache: Send + Sync {
    /// The cut with the longest zone at or above `name` that has not expired (the root at
    /// worst once primed).
    fn closest_cut(&self, name: &DnsName, now: Instant) -> Option<ZoneCut>;

    /// The cut of exactly `zone`.
    fn cut(&self, zone: &DnsName, now: Instant) -> Option<ZoneCut>;

    /// Stores the NS set of `zone` for `ttl` seconds (a referral, or the priming answer
    /// for the root) and returns the cut's identifier; a known cut keeps its identifier
    /// and its DS state.
    fn put_cut(&self, zone: &DnsName, servers: Vec<DnsName>, ttl: u32, now: Instant) -> CutId;

    /// Sets the DNSSEC state of `zone`'s cut.
    fn set_ds(&self, zone: &DnsName, ds: DsState);

    /// Remembers that QNAME minimisation falls back to the full name for `zone` until
    /// `until`.
    fn set_minimise_fallback(&self, zone: &DnsName, until: Instant);

    /// The addresses of a name server that have not expired.
    fn name_server(&self, name: &DnsName, now: Instant) -> Option<NameServer>;

    /// Stores addresses (with their TTLs in seconds) of a name server. An address from a
    /// more trusted origin replaces one from a less trusted origin; a less trusted one
    /// never replaces a more trusted one that has not expired (RFC 2181 section 5.4.1).
    fn put_addresses(
        &self,
        name: &DnsName,
        addresses: &[(IpAddr, u32)],
        origin: AddressOrigin,
        now: Instant,
    );

    /// What is known about a server address (an unknown server is
    /// [`ServerState::unknown`]).
    fn server(&self, address: IpAddr, now: Instant) -> ServerState;

    /// Changes what is known about a server address.
    fn update_server(
        &self,
        address: IpAddr,
        now: Instant,
        update: &mut dyn FnMut(&mut ServerState),
    );

    /// A page of the cuts at or below `suffix` (every cut when `None`), in the order of
    /// their zone names' text, after `after`, at most `limit` (the API's listing).
    fn list(
        &self,
        suffix: Option<&DnsName>,
        after: Option<&DnsName>,
        limit: usize,
        now: Instant,
    ) -> Vec<ZoneCut>;

    /// Removes every cut, name and server, or the cuts and names at or below `suffix`.
    /// Returns the entries removed.
    fn flush(&self, suffix: Option<&DnsName>) -> usize;

    /// The sizes.
    fn sizes(&self) -> InfraSizes;
}

#[derive(Debug, Default)]
struct Inner {
    cuts: HashMap<DnsName, (ZoneCut, u64)>,
    names: HashMap<DnsName, (NameServer, u64)>,
    servers: HashMap<IpAddr, (ServerState, u64)>,
    tick: u64,
    next_id: u64,
}

impl Inner {
    fn tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
}

/// Drops the least recently used entries of `map` until it holds at most `bound`.
fn evict<K: Clone + Eq + std::hash::Hash, V>(map: &mut HashMap<K, (V, u64)>, bound: usize) {
    while map.len() > bound {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, (_, used))| *used)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        map.remove(&oldest);
    }
}

/// The reference [`InfraCache`]; see the module documentation.
#[derive(Debug, Default)]
pub struct MemInfra {
    bounds: InfraBounds,
    inner: Mutex<Inner>,
}

impl MemInfra {
    /// An empty cache with `bounds`.
    pub fn new(bounds: InfraBounds) -> Self {
        Self {
            bounds,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The bounds.
    pub fn bounds(&self) -> InfraBounds {
        self.bounds
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl InfraCache for MemInfra {
    fn closest_cut(&self, name: &DnsName, now: Instant) -> Option<ZoneCut> {
        let mut candidate = Some(name.clone());
        while let Some(zone) = candidate {
            if let Some(cut) = self.cut(&zone, now) {
                return Some(cut);
            }
            candidate = zone.parent();
        }
        None
    }

    fn cut(&self, zone: &DnsName, now: Instant) -> Option<ZoneCut> {
        let mut inner = self.lock();
        let tick = inner.tick();
        let (cut, used) = inner.cuts.get_mut(zone)?;
        if cut.expires <= now {
            return None;
        }
        *used = tick;
        let mut cut = cut.clone();
        cut.ds = cut.ds.at(now);
        cut.minimise_fallback = cut.minimise_fallback.filter(|until| *until > now);
        Some(cut)
    }

    fn put_cut(&self, zone: &DnsName, servers: Vec<DnsName>, ttl: u32, now: Instant) -> CutId {
        let mut inner = self.lock();
        let tick = inner.tick();
        let expires = now + Duration::from_secs(u64::from(ttl));
        if let Some((cut, used)) = inner.cuts.get_mut(zone) {
            cut.servers = servers;
            cut.expires = expires;
            *used = tick;
            return cut.id;
        }
        inner.next_id += 1;
        let id = CutId(inner.next_id);
        inner.cuts.insert(
            zone.clone(),
            (
                ZoneCut {
                    id,
                    zone: zone.clone(),
                    servers,
                    expires,
                    ds: DsState::Unknown,
                    minimise_fallback: None,
                },
                tick,
            ),
        );
        evict(&mut inner.cuts, self.bounds.cuts);
        id
    }

    fn set_ds(&self, zone: &DnsName, ds: DsState) {
        if let Some((cut, _)) = self.lock().cuts.get_mut(zone) {
            cut.ds = ds;
        }
    }

    fn set_minimise_fallback(&self, zone: &DnsName, until: Instant) {
        if let Some((cut, _)) = self.lock().cuts.get_mut(zone) {
            cut.minimise_fallback = Some(until);
        }
    }

    fn name_server(&self, name: &DnsName, now: Instant) -> Option<NameServer> {
        let mut inner = self.lock();
        let tick = inner.tick();
        let (server, used) = inner.names.get_mut(name)?;
        *used = tick;
        let addresses: Vec<ServerAddress> = server
            .addresses
            .iter()
            .copied()
            .filter(|address| address.expires > now)
            .collect();
        (!addresses.is_empty()).then(|| NameServer {
            name: name.clone(),
            addresses,
        })
    }

    fn put_addresses(
        &self,
        name: &DnsName,
        addresses: &[(IpAddr, u32)],
        origin: AddressOrigin,
        now: Instant,
    ) {
        let mut inner = self.lock();
        let tick = inner.tick();
        let entry = inner.names.entry(name.clone()).or_insert_with(|| {
            (
                NameServer {
                    name: name.clone(),
                    addresses: Vec::new(),
                },
                tick,
            )
        });
        entry.1 = tick;
        let known = &mut entry.0.addresses;
        known.retain(|address| address.expires > now);
        // A more trusted, live origin keeps the set.
        if known.iter().any(|address| address.origin > origin) {
            return;
        }
        known.retain(|address| address.origin >= origin);
        for (address, ttl) in addresses {
            let expires = now + Duration::from_secs(u64::from(*ttl));
            match known.iter_mut().find(|known| known.address == *address) {
                Some(known) => {
                    known.origin = origin;
                    known.expires = expires;
                }
                None => known.push(ServerAddress {
                    address: *address,
                    origin,
                    expires,
                }),
            }
        }
        evict(&mut inner.names, self.bounds.servers);
    }

    fn server(&self, address: IpAddr, now: Instant) -> ServerState {
        let mut inner = self.lock();
        let tick = inner.tick();
        match inner.servers.get_mut(&address) {
            Some((state, used)) => {
                *used = tick;
                let mut state = state.clone();
                state.lame.retain(|(_, until)| *until > now);
                state
            }
            None => ServerState::unknown(address),
        }
    }

    fn update_server(
        &self,
        address: IpAddr,
        _now: Instant,
        update: &mut dyn FnMut(&mut ServerState),
    ) {
        let mut inner = self.lock();
        let tick = inner.tick();
        let entry = inner
            .servers
            .entry(address)
            .or_insert_with(|| (ServerState::unknown(address), tick));
        entry.1 = tick;
        update(&mut entry.0);
        evict(&mut inner.servers, self.bounds.servers);
    }

    fn list(
        &self,
        suffix: Option<&DnsName>,
        after: Option<&DnsName>,
        limit: usize,
        now: Instant,
    ) -> Vec<ZoneCut> {
        let inner = self.lock();
        let mut cuts: Vec<ZoneCut> = inner
            .cuts
            .values()
            .map(|(cut, _)| cut)
            .filter(|cut| cut.expires > now)
            .filter(|cut| suffix.is_none_or(|suffix| cut.zone.is_subdomain_of(suffix)))
            .filter(|cut| after.is_none_or(|after| cut.zone.as_str() > after.as_str()))
            .cloned()
            .collect();
        cuts.sort_by(|a, b| a.zone.as_str().cmp(b.zone.as_str()));
        cuts.truncate(limit);
        for cut in &mut cuts {
            cut.ds = cut.ds.at(now);
        }
        cuts
    }

    fn flush(&self, suffix: Option<&DnsName>) -> usize {
        let mut inner = self.lock();
        match suffix {
            None => {
                let removed = inner.cuts.len() + inner.names.len() + inner.servers.len();
                inner.cuts.clear();
                inner.names.clear();
                inner.servers.clear();
                removed
            }
            Some(suffix) => {
                let before = inner.cuts.len() + inner.names.len();
                inner.cuts.retain(|zone, _| !zone.is_subdomain_of(suffix));
                inner.names.retain(|name, _| !name.is_subdomain_of(suffix));
                before - inner.cuts.len() - inner.names.len()
            }
        }
    }

    fn sizes(&self) -> InfraSizes {
        let inner = self.lock();
        InfraSizes {
            cuts: inner.cuts.len(),
            servers: inner.servers.len(),
            names: inner.names.len(),
        }
    }
}
