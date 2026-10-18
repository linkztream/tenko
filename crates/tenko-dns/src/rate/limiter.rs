//! The limiter of the `dns` role: RRL and per-client query limits on fixed tables.

use std::{
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use ipnet::IpNet;
use tenko_core::metrics::{Counter, CounterVec, Registry};

use super::{RateDecision, RateLimiter, ResponseKey, ResponseKind};
use crate::metrics::{CLIENT_LIMITED, RRL_DROPPED, RRL_SLIPPED};

/// `tenko_dns_rrl_dropped{kind}`, in the order of [`ResponseKind::index`].
pub static RRL_DROPPED_COUNTER: CounterVec = CounterVec::fixed(
    RRL_DROPPED,
    &[
        &["answer"],
        &["nodata"],
        &["nxdomain"],
        &["referral"],
        &["error"],
    ],
);

/// `tenko_dns_rrl_slipped`.
pub static RRL_SLIPPED_COUNTER: Counter = Counter::new(RRL_SLIPPED);

/// `tenko_dns_client_limited`.
pub static CLIENT_LIMITED_COUNTER: Counter = Counter::new(CLIENT_LIMITED);

/// Registers the limiter's families with `registry`.
pub fn register_metrics(registry: &Registry) {
    RRL_DROPPED_COUNTER.add(0, 0);
    RRL_SLIPPED_COUNTER.add(0);
    CLIENT_LIMITED_COUNTER.add(0);
    registry.register(&RRL_DROPPED_COUNTER);
    registry.register(&RRL_SLIPPED_COUNTER);
    registry.register(&CLIENT_LIMITED_COUNTER);
}

/// The RRL settings (`[dns.limits]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrlSettings {
    /// Identical positive answers, NODATA and referrals per second per client prefix.
    pub responses_per_second: u32,
    /// NXDOMAIN and error responses per second per client prefix.
    pub errors_per_second: u32,
    /// Seconds a key may run into debt (BIND's `window`).
    pub window_secs: u32,
    /// Every `slip`-th limited response is sent truncated; 0 never, 1 always.
    pub slip: u32,
    /// The IPv4 prefix length clients are grouped by.
    pub ipv4_prefix: u8,
    /// The IPv6 prefix length clients are grouped by.
    pub ipv6_prefix: u8,
}

impl Default for RrlSettings {
    fn default() -> Self {
        Self {
            responses_per_second: 10,
            errors_per_second: 5,
            window_secs: 15,
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    }
}

/// The per-client query limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimit {
    /// Queries per second per client address (IPv6 per /64).
    pub queries_per_second: u32,
    /// Queries a client may send at once above the rate.
    pub burst: u32,
}

/// The settings of the limiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitSettings {
    /// RRL, when on.
    pub rrl: Option<RrlSettings>,
    /// The per-client limit, when on.
    pub client: Option<ClientLimit>,
    /// Clients never limited.
    pub exempt: Vec<IpNet>,
    /// Slots of each table (rounded up to a power of two, at least 1,024).
    pub table: usize,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            rrl: None,
            client: None,
            exempt: Vec::new(),
            table: 65_536,
        }
    }
}

const SHARDS: usize = 64;

#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    /// The key's hash; 0 is an empty slot.
    tag: u64,
    /// Milliseconds since the limiter started, at the last update.
    at: u64,
    /// Thousandths of a token.
    balance: i64,
    /// Limited responses since the key's last answer.
    limited: u32,
}

/// One fixed table of token buckets.
#[derive(Debug)]
struct Table {
    shards: Box<[Mutex<Box<[Bucket]>>]>,
    per_shard: usize,
}

/// What a bucket said.
enum Take {
    Ok,
    /// Limited; the count of limited responses so far.
    Limited(u32),
}

impl Table {
    fn new(slots: usize) -> Self {
        let slots = slots.max(1_024).next_power_of_two();
        let per_shard = slots / SHARDS;
        Self {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(vec![Bucket::default(); per_shard].into_boxed_slice()))
                .collect(),
            per_shard,
        }
    }

    /// Takes one token of the key `hash` from a bucket filling at `rate` per second, at
    /// most `cap` thousandths, at least `-floor` thousandths.
    fn take(&self, hash: u64, now_ms: u64, rate: u32, cap: i64, floor: i64) -> Take {
        let tag = hash | 1;
        #[allow(clippy::cast_possible_truncation, reason = "masked to the table")]
        let shard = (hash as usize) % SHARDS;
        #[allow(clippy::cast_possible_truncation, reason = "masked to the table")]
        let slot = ((hash >> 32) as usize) % self.per_shard;
        let mut buckets = self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let bucket = &mut buckets[slot];
        if bucket.tag == tag {
            let elapsed = i64::try_from(now_ms.saturating_sub(bucket.at)).unwrap_or(i64::MAX);
            bucket.balance = bucket
                .balance
                .saturating_add(elapsed.saturating_mul(i64::from(rate)))
                .min(cap);
            // A thread that read the clock earlier and took the lock later adds nothing.
            bucket.at = bucket.at.max(now_ms);
        } else {
            *bucket = Bucket {
                tag,
                at: now_ms,
                balance: cap,
                limited: 0,
            };
        }
        bucket.balance -= 1_000;
        if bucket.balance >= 0 {
            bucket.limited = 0;
            return Take::Ok;
        }
        bucket.balance = bucket.balance.max(-floor);
        bucket.limited = bucket.limited.saturating_add(1);
        Take::Limited(bucket.limited)
    }
}

/// RRL and the per-client limit of the `dns` role.
pub struct Limiter {
    settings: LimitSettings,
    start: Instant,
    hasher: std::collections::hash_map::RandomState,
    rrl: Option<Table>,
    clients: Option<Table>,
    exempt_known: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
}

impl std::fmt::Debug for Limiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limiter")
            .field("settings", &self.settings)
            .field("exempt_known", &self.exempt_known.is_some())
            .finish_non_exhaustive()
    }
}

fn prefix_bits(client: IpAddr, v4: u8, v6: u8) -> (u8, u128) {
    match client.to_canonical() {
        IpAddr::V4(address) => {
            let bits = u128::from(address.to_bits());
            let keep = 32 - u32::from(v4.min(32));
            (4, if keep >= 32 { 0 } else { bits >> keep << keep })
        }
        IpAddr::V6(address) => {
            let bits = address.to_bits();
            let keep = 128 - u32::from(v6.min(128));
            (6, if keep >= 128 { 0 } else { bits >> keep << keep })
        }
    }
}

impl Limiter {
    /// A limiter with `settings`.
    pub fn new(settings: LimitSettings) -> Self {
        let rrl = settings.rrl.map(|_| Table::new(settings.table));
        let clients = settings.client.map(|_| Table::new(settings.table));
        Self {
            settings,
            start: Instant::now(),
            hasher: std::collections::hash_map::RandomState::new(),
            rrl,
            clients,
            exempt_known: None,
        }
    }

    /// The same limiter, which also exempts the clients `known` says yes to (the prefixes
    /// IPAM knows and loopback).
    #[must_use]
    pub fn with_known_exempt(mut self, known: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>) -> Self {
        self.exempt_known = Some(known);
        self
    }

    /// The settings.
    pub fn settings(&self) -> &LimitSettings {
        &self.settings
    }

    fn exempt(&self, client: IpAddr) -> bool {
        let client = client.to_canonical();
        self.settings
            .exempt
            .iter()
            .any(|prefix| prefix.contains(&client))
            || self
                .exempt_known
                .as_ref()
                .is_some_and(|known| known(client))
    }

    fn now_ms(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.start).as_millis()).unwrap_or(u64::MAX)
    }
}

impl RateLimiter for Limiter {
    fn admit_query(&self, client: IpAddr, now: Instant) -> bool {
        let (Some(table), Some(limit)) = (&self.clients, self.settings.client) else {
            return true;
        };
        if self.exempt(client) {
            return true;
        }
        let (family, bits) = prefix_bits(client, 32, 64);

        let rate = limit.queries_per_second.max(1);
        let cap = i64::from(rate.saturating_add(limit.burst)) * 1_000;
        match table.take(
            self.hasher.hash_one((family, bits)),
            self.now_ms(now),
            rate,
            cap,
            0,
        ) {
            Take::Ok => true,
            Take::Limited(_) => {
                CLIENT_LIMITED_COUNTER.inc();
                false
            }
        }
    }

    fn admit_response(&self, client: IpAddr, key: &ResponseKey<'_>, now: Instant) -> RateDecision {
        let (Some(table), Some(rrl)) = (&self.rrl, self.settings.rrl) else {
            return RateDecision::Send;
        };
        if !key.udp || self.exempt(client) {
            return RateDecision::Send;
        }
        let (family, bits) = prefix_bits(client, rrl.ipv4_prefix, rrl.ipv6_prefix);
        let mut hasher = self.hasher.build_hasher();
        (family, bits, key.kind.index()).hash(&mut hasher);
        match key.kind {
            ResponseKind::Answer | ResponseKind::NoData => {
                key.name.hash(&mut hasher);
                key.qtype.hash(&mut hasher);
            }
            ResponseKind::NxDomain | ResponseKind::Referral => key.name.hash(&mut hasher),
            ResponseKind::Error => {}
        }
        let rate = match key.kind {
            ResponseKind::NxDomain | ResponseKind::Error => rrl.errors_per_second,
            _ => rrl.responses_per_second,
        }
        .max(1);
        let cap = i64::from(rate) * 1_000;
        let floor = cap.saturating_mul(i64::from(rrl.window_secs.max(1)));
        match table.take(hasher.finish(), self.now_ms(now), rate, cap, floor) {
            Take::Ok => RateDecision::Send,
            Take::Limited(count) => {
                if rrl.slip > 0 && count % rrl.slip == 0 {
                    RRL_SLIPPED_COUNTER.inc();
                    RateDecision::Slip
                } else {
                    RRL_DROPPED_COUNTER.inc(key.kind.index());
                    RateDecision::Drop
                }
            }
        }
    }
}
