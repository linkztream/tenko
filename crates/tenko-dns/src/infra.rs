//! The infrastructure cache of the recursive resolver (WP10.1, recursion plan section 2.2):
//! [`Infra`], the [`InfraCache`] the engine ([`crate::recurse`]) runs on, and
//! [`ServerTable`], the bookkeeping of every authority server address it asked.
//!
//! - **Zone cuts.** Per cut the NS set with its TTL, the DS state slot WP10.2 fills and the
//!   minimisation fallback slot of WP10.3; at most `cuts` of them (1,000 under the Home
//!   profile, 10,000 under the others).
//! - **Name servers.** Per name-server name its A and AAAA addresses with their TTLs and
//!   where they came from ([`AddressOrigin`]: the hints, sibling glue, in-domain glue, an
//!   authoritative answer); a less trusted origin never replaces a more trusted one that
//!   has not expired (RFC 2181 section 5.4.1).
//! - **Server addresses.** Per address what the resolver learnt ([`ServerState`]): EDNS and
//!   TCP capability, the server cookie, lameness per zone, the unreachable mark of an
//!   address family without a route; together with names, at most `servers` entries.
//! - **Figures** ([`ServerTable`], [`servers`]): per address the smoothed round-trip time
//!   (an EWMA with weight 1/8, as the upstream pool keeps it), the p50 and p99 of the last
//!   minute, failures in a row and the back-off, the 0x20 strikes, the unwanted answers of
//!   the current hour and the TCP hour they cause.
//!
//! Every entry lives at most the infrastructure TTL (`[dns.recursion] infra_ttl_secs`, 900
//! seconds) beyond what its own TTL allows for learnt capabilities and lameness. Over a
//! bound the least recently used sixteenth goes at once, so an insert at the bound costs one
//! scan per sixteenth of the bound rather than one per insert. The cache is read and written
//! on the runtime only, never on the worker; it holds no client data.

pub mod servers;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

pub use servers::{ServerFigures, ServerTable};
use tenko_core::dns::DnsName;

use crate::recursion::{
    AddressOrigin, CutId, DsState, InfraBounds, InfraCache, InfraSizes, NameServer, ServerState,
    ZoneCut, infra::ServerAddress,
};

/// One entry with its last use.
#[derive(Debug)]
struct Used<T> {
    value: T,
    used: u64,
}

#[derive(Debug, Default)]
struct Inner {
    cuts: HashMap<DnsName, Used<ZoneCut>>,
    names: HashMap<DnsName, Used<NameServer>>,
    /// Each with the time its EDNS and TCP capabilities were learnt.
    servers: HashMap<IpAddr, Used<(ServerState, Instant)>>,
    tick: u64,
    next_id: u64,
}

impl Inner {
    fn tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
}

/// Forgets the EDNS and TCP capabilities of `state`, learnt at `learnt`, once the
/// infrastructure TTL has passed (RFC 6891 section 6.2.2: probe again later).
fn age_capabilities(state: &mut ServerState, learnt: Instant, ttl: Duration, now: Instant) {
    if learnt + ttl <= now {
        state.edns = crate::recursion::infra::EdnsSupport::Unknown;
        state.tcp_only = false;
    }
}

/// Drops the least recently used sixteenth of `map` (at least one entry) when it holds more
/// than `bound`.
pub(crate) fn trim<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    bound: usize,
    used: impl Fn(&V) -> u64,
) {
    if map.len() <= bound {
        return;
    }
    let excess = map.len() - bound;
    let drop = excess.max(bound / 16).max(1).min(map.len());
    let mut ticks: Vec<u64> = map.values().map(&used).collect();
    let (_, cut, _) = ticks.select_nth_unstable(drop - 1);
    let cut = *cut;
    let mut left = drop;
    map.retain(|_, value| {
        if left > 0 && used(value) <= cut {
            left -= 1;
            false
        } else {
            true
        }
    });
}

/// The infrastructure cache; see the module documentation.
#[derive(Debug)]
pub struct Infra {
    bounds: InfraBounds,
    inner: Mutex<Inner>,
}

impl Infra {
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

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drops what expired: cuts past their TTL, addresses past theirs, server states with
    /// nothing left to remember. Returns the entries removed.
    pub fn purge(&self, now: Instant) -> usize {
        let mut inner = self.lock();
        let before = inner.cuts.len() + inner.names.len() + inner.servers.len();
        inner.cuts.retain(|_, cut| cut.value.expires > now);
        inner.names.retain(|_, name| {
            name.value.addresses.retain(|address| address.expires > now);
            !name.value.addresses.is_empty()
        });
        let ttl = self.bounds.ttl;
        inner.servers.retain(|_, entry| {
            let (state, learnt) = &mut entry.value;
            age_capabilities(state, *learnt, ttl, now);
            state.lame.retain(|(_, until)| *until > now);
            if state.unreachable_until.is_some_and(|until| until <= now) {
                state.unreachable_until = None;
            }
            let fresh = state.last_failure.is_some_and(|at| at + ttl > now);
            fresh
                || !state.lame.is_empty()
                || state.unreachable_until.is_some()
                || state.cookie.is_some()
                || state.tcp_only
                || state.edns != crate::recursion::infra::EdnsSupport::Unknown
        });
        before - inner.cuts.len() - inner.names.len() - inner.servers.len()
    }
}

impl Default for Infra {
    fn default() -> Self {
        Self::new(InfraBounds::default())
    }
}

impl InfraCache for Infra {
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
        let entry = inner.cuts.get_mut(zone)?;
        if entry.value.expires <= now {
            return None;
        }
        entry.used = tick;
        let mut cut = entry.value.clone();
        cut.ds = cut.ds.at(now);
        cut.minimise_fallback = cut.minimise_fallback.filter(|until| *until > now);
        Some(cut)
    }

    fn put_cut(&self, zone: &DnsName, servers: Vec<DnsName>, ttl: u32, now: Instant) -> CutId {
        let mut inner = self.lock();
        let tick = inner.tick();
        let expires = now + Duration::from_secs(u64::from(ttl));
        if let Some(entry) = inner.cuts.get_mut(zone) {
            entry.value.servers = servers;
            entry.value.expires = expires;
            entry.used = tick;
            return entry.value.id;
        }
        inner.next_id += 1;
        let id = CutId(inner.next_id);
        inner.cuts.insert(
            zone.clone(),
            Used {
                value: ZoneCut {
                    id,
                    zone: zone.clone(),
                    servers,
                    expires,
                    ds: DsState::Unknown,
                    minimise_fallback: None,
                },
                used: tick,
            },
        );
        trim(&mut inner.cuts, self.bounds.cuts, |entry| entry.used);
        id
    }

    fn set_ds(&self, zone: &DnsName, ds: DsState) {
        if let Some(entry) = self.lock().cuts.get_mut(zone) {
            entry.value.ds = ds;
        }
    }

    fn set_minimise_fallback(&self, zone: &DnsName, until: Instant) {
        if let Some(entry) = self.lock().cuts.get_mut(zone) {
            entry.value.minimise_fallback = Some(until);
        }
    }

    fn name_server(&self, name: &DnsName, now: Instant) -> Option<NameServer> {
        let mut inner = self.lock();
        let tick = inner.tick();
        let entry = inner.names.get_mut(name)?;
        entry.used = tick;
        let addresses: Vec<ServerAddress> = entry
            .value
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
        if addresses.is_empty() {
            return;
        }
        let mut inner = self.lock();
        let tick = inner.tick();
        let entry = inner.names.entry(name.clone()).or_insert_with(|| Used {
            value: NameServer {
                name: name.clone(),
                addresses: Vec::new(),
            },
            used: tick,
        });
        entry.used = tick;
        let known = &mut entry.value.addresses;
        known.retain(|address| address.expires > now);
        // A more trusted origin that has not expired keeps the set (RFC 2181 5.4.1).
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
        let bound = self.bounds.servers;
        trim(&mut inner.names, bound, |entry| entry.used);
    }

    fn server(&self, address: IpAddr, now: Instant) -> ServerState {
        let mut inner = self.lock();
        let tick = inner.tick();
        let ttl = self.bounds.ttl;
        match inner.servers.get_mut(&address) {
            Some(entry) => {
                entry.used = tick;
                let (stored, learnt) = &mut entry.value;
                age_capabilities(stored, *learnt, ttl, now);
                let mut state = stored.clone();
                state.lame.retain(|(_, until)| *until > now);
                if state.unreachable_until.is_some_and(|until| until <= now) {
                    state.unreachable_until = None;
                }
                state
            }
            None => ServerState::unknown(address),
        }
    }

    fn update_server(
        &self,
        address: IpAddr,
        now: Instant,
        update: &mut dyn FnMut(&mut ServerState),
    ) {
        let mut inner = self.lock();
        let tick = inner.tick();
        let ttl = self.bounds.ttl;
        let entry = inner.servers.entry(address).or_insert_with(|| Used {
            value: (ServerState::unknown(address), now),
            used: tick,
        });
        entry.used = tick;
        let (state, learnt) = &mut entry.value;
        age_capabilities(state, *learnt, ttl, now);
        state.lame.retain(|(_, until)| *until > now);
        let before = (state.edns, state.tcp_only);
        update(state);
        if (state.edns, state.tcp_only) != before {
            *learnt = now;
        }
        let bound = self.bounds.servers;
        trim(&mut inner.servers, bound, |entry| entry.used);
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
            .map(|entry| &entry.value)
            .filter(|cut| cut.expires > now)
            .filter(|cut| suffix.is_none_or(|suffix| cut.zone.is_subdomain_of(suffix)))
            .filter(|cut| after.is_none_or(|after| cut.zone.as_str() > after.as_str()))
            .cloned()
            .collect();
        drop(inner);
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

#[cfg(test)]
mod tests;
