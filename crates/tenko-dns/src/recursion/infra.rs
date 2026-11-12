//! The infrastructure cache ([`InfraCache`], recursion plan section 2.2): per zone cut the
//! NS set with its TTL and the DS state once validated; per name server name its addresses
//! with their TTLs and where they came from; per server address its capabilities (EDNS,
//! TCP), its server cookie, its lameness per zone, its unwanted-answer count and its last
//! failure. The round-trip times stay in the pool ([`crate::pool`]), keyed by
//! [`crate::pool::PoolKey::Delegation`].
//!
//! It is read on the runtime only, never on the worker. It holds no client data. The node's
//! implementation is [`crate::infra::Infra`].

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::dns::{DnsName, ExtendedError};

use super::{CutId, authority::ServerCookie};

/// The default infrastructure TTL (`[dns.recursion] infra_ttl_secs`, Unbound's 900): how
/// long a learned capability, lameness or unreachability holds.
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
    /// QNAME minimization falls back to the full name for this zone until then (RFC 9156
    /// relaxed mode, section 2.6).
    pub minimize_fallback: Option<Instant>,
}

/// Whether a server takes EDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EdnsSupport {
    /// Not learned yet: ask with EDNS.
    #[default]
    Unknown,
    /// It answered a query with EDNS.
    Yes,
    /// It answered FORMERR or NOTIMP to EDNS (RFC 6891 section 6.2.2).
    No,
}

/// The most zones one server address is remembered lame for. Past it the zone marked
/// earliest goes: the zones come from what peers answer, so a peer that makes the resolver
/// meet many of them must not grow the entry (it is copied on every read of the address).
pub const MAX_LAME_PER_SERVER: usize = 16;

/// The zones a server address is lame for, each until a time: at most
/// [`MAX_LAME_PER_SERVER`], shared, so that a copy of the server's state is a reference
/// count and not a copy of the names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LameZones(Option<Arc<[(DnsName, Instant)]>>);

impl LameZones {
    fn entries(&self) -> &[(DnsName, Instant)] {
        self.0.as_deref().unwrap_or_default()
    }

    /// Whether `zone` is marked at `now`.
    pub fn contains(&self, zone: &DnsName, now: Instant) -> bool {
        self.entries()
            .iter()
            .any(|(lame, until)| lame == zone && *until > now)
    }

    /// Zones held, expired ones included until the next change.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    /// Marks `zone` until `until`, dropping what expired before `now` and, at the bound,
    /// the zone marked earliest.
    pub fn mark(&mut self, zone: &DnsName, until: Instant, now: Instant) {
        let mut kept: Vec<(DnsName, Instant)> = self
            .entries()
            .iter()
            .filter(|(lame, expires)| *expires > now && lame != zone)
            .cloned()
            .collect();
        if kept.len() >= MAX_LAME_PER_SERVER {
            kept.sort_unstable_by_key(|(_, expires)| *expires);
            kept.drain(..=kept.len() - MAX_LAME_PER_SERVER);
        }
        kept.push((zone.clone(), until));
        self.0 = Some(kept.into());
    }

    /// Drops what expired before `now`; nothing is rebuilt when nothing expired.
    pub fn expire(&mut self, now: Instant) {
        let live = self
            .entries()
            .iter()
            .filter(|(_, until)| *until > now)
            .count();
        if live == self.len() {
            return;
        }
        self.0 = (live > 0).then(|| {
            self.entries()
                .iter()
                .filter(|(_, until)| *until > now)
                .cloned()
                .collect()
        });
    }
}

/// What the resolver learned about one server address.
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
    pub lame: LameZones,
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
            lame: LameZones::default(),
            unwanted: 0,
            unreachable_until: None,
            last_failure: None,
        }
    }

    /// Whether it is lame for `zone` at `now`.
    pub fn is_lame(&self, zone: &DnsName, now: Instant) -> bool {
        self.lame.contains(zone, now)
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

    /// Remembers that QNAME minimization falls back to the full name for `zone` until
    /// `until`.
    fn set_minimize_fallback(&self, zone: &DnsName, until: Instant);

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
