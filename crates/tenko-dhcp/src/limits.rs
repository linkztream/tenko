//! The limits per client and per scope that keep one client or one link from taking a pool
//! (`dhcp.settings.limits`, `docs/dhcp.md` section 14.9), and what the node tells the
//! operator when one refuses.
//!
//! - **Per client.** A DHCPv4 MAC address holds at most `leases_per_mac` active bindings in
//!   a scope (with its shared network) across its client identifiers; a DHCPv6 DUID at most
//!   `addresses_per_duid` `IA_NA` and `prefixes_per_duid` `IA_PD` bindings across its IAIDs
//!   and messages. A client over a limit gets no new binding (a DISCOVER or SOLICIT gets no
//!   address, a REQUEST for a new one is dropped) and the bindings it holds keep renewing; a
//!   client with a reservation is never limited.
//! - **Per scope.** A scope offers an address to at most `offers_per_second` new clients a
//!   second (a client without a lease there), with a burst of [`BURST_SECS`] seconds' worth,
//!   in a token bucket per scope ([`OfferRate`], fixed at start, one atomic word each).
//! - **Conflict marks** (no setting). An address a conflict probe found in use is abandoned
//!   for the decline hold time only while one answering MAC address has marked fewer than
//!   [`CONFLICTS_PER_MAC`] addresses in the last hour and the scope's addresses abandoned by
//!   conflicts in the last day are fewer than an eighth ([`CONFLICT_SHARE`]) of its pool;
//!   beyond either the address is only skipped for that offer ([`ConflictBudget`]).
//! - **The renewal cache** (`renew_cache_percent`). A renewal within that share of its
//!   lease time, counted from its last commit, is answered from the stored lease for the
//!   time it has left: no commit and no history row, and never past the committed end.
//!
//! Unset limits follow the security profile ([`Limits::of_profile`]); zero turns one off.
//! Every refusal counts `tenko_dhcp_limited_total{limit}` and goes to the [`LimitLog`]
//! (the health row [`REFUSED`] names the client, the scope, the limit and the count).

use std::{
    collections::HashMap,
    hash::BuildHasher as _,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    PrefixId, Timestamp,
    dhcp::DhcpLimits,
    metrics::{Counter, CounterVec},
};

use crate::{conflict::DeclineLimit, guard::DhcpProfile, metrics as families};

/// The health row while a limit refuses clients.
pub const REFUSED: &str = "dhcp.limit.refused";

/// The seconds of offers a scope's bucket holds: the burst a power cut's DISCOVERs get.
pub const BURST_SECS: u64 = 10;

/// Addresses one answering MAC address may have abandoned by conflict marks per hour.
pub const CONFLICTS_PER_MAC: u32 = 2;

/// The share of a scope's pool conflict marks may abandon within a day: one in eight.
pub const CONFLICT_SHARE: u64 = 8;

/// The refusals the log keeps.
pub const MAX_LOGGED: usize = 32;

/// The renewal cache of every profile: a renewal within the first quarter of its lease is
/// answered from the stored lease (ISC dhcpd's default threshold).
pub const RENEW_CACHE_PERCENT: u8 = 25;

/// The limits in force (zero: off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// DHCPv4 active bindings per MAC address and scope.
    pub leases_per_mac: u32,
    /// DHCPv6 `IA_NA` bindings per DUID and scope.
    pub addresses_per_duid: u32,
    /// DHCPv6 `IA_PD` bindings per DUID and scope.
    pub prefixes_per_duid: u32,
    /// New clients offered an address per scope and second.
    pub offers_per_second: u32,
    /// The renewal cache, percent of the lease time.
    pub renew_cache_percent: u8,
}

impl Limits {
    /// The limits of a profile. Lab sets none, so that the load tools of the benches, which
    /// send 100,000 clients from 256 MAC addresses, are not limited: not values for
    /// production. Hardened halves the per-client limits of Home and Standard; Standard's
    /// offer rate is higher for larger links. The per-client limits stay above what a
    /// legitimate client holds: a network boot chain takes up to four DHCPv4 bindings of one
    /// MAC address (firmware, loader, installer, installed system), a dual-boot machine one
    /// more, and a wireless bridge one per client behind it.
    pub const fn of_profile(profile: DhcpProfile) -> Self {
        match profile {
            DhcpProfile::Lab => Self {
                leases_per_mac: 0,
                addresses_per_duid: 0,
                prefixes_per_duid: 0,
                offers_per_second: 0,
                renew_cache_percent: RENEW_CACHE_PERCENT,
            },
            DhcpProfile::Home => Self {
                leases_per_mac: 16,
                addresses_per_duid: 16,
                prefixes_per_duid: 8,
                offers_per_second: 100,
                renew_cache_percent: RENEW_CACHE_PERCENT,
            },
            DhcpProfile::Standard => Self {
                leases_per_mac: 16,
                addresses_per_duid: 16,
                prefixes_per_duid: 8,
                offers_per_second: 200,
                renew_cache_percent: RENEW_CACHE_PERCENT,
            },
            DhcpProfile::Hardened => Self {
                leases_per_mac: 8,
                addresses_per_duid: 8,
                prefixes_per_duid: 4,
                offers_per_second: 100,
                renew_cache_percent: RENEW_CACHE_PERCENT,
            },
        }
    }

    /// The stored limits over the profile's.
    pub fn resolve(stored: &DhcpLimits, profile: DhcpProfile) -> Self {
        let base = Self::of_profile(profile);
        Self {
            leases_per_mac: stored.leases_per_mac.unwrap_or(base.leases_per_mac),
            addresses_per_duid: stored.addresses_per_duid.unwrap_or(base.addresses_per_duid),
            prefixes_per_duid: stored.prefixes_per_duid.unwrap_or(base.prefixes_per_duid),
            offers_per_second: stored.offers_per_second.unwrap_or(base.offers_per_second),
            renew_cache_percent: stored
                .renew_cache_percent
                .unwrap_or(base.renew_cache_percent),
        }
    }
}

/// A limit that refused a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    /// `leases_per_mac`.
    LeasesPerMac = 0,
    /// `addresses_per_duid`.
    AddressesPerDuid = 1,
    /// `prefixes_per_duid`.
    PrefixesPerDuid = 2,
    /// `offers_per_second`.
    OffersPerSecond = 3,
    /// [`CONFLICTS_PER_MAC`].
    ConflictsPerMac = 4,
    /// [`CONFLICT_SHARE`].
    ConflictShare = 5,
}

/// The `limit` label of each [`Limit`], in its order.
pub const LIMIT_LABELS: [&str; 6] = [
    "leases_per_mac",
    "addresses_per_duid",
    "prefixes_per_duid",
    "offers_per_second",
    "conflicts_per_mac",
    "conflict_share",
];

impl Limit {
    /// The setting's name, or the rule's.
    pub fn label(self) -> &'static str {
        LIMIT_LABELS[self as usize]
    }
}

/// `tenko_dhcp_limited_total{limit}`.
pub static LIMITED: CounterVec = CounterVec::fixed(
    families::LIMITED,
    &[
        &["leases_per_mac"],
        &["addresses_per_duid"],
        &["prefixes_per_duid"],
        &["offers_per_second"],
        &["conflicts_per_mac"],
        &["conflict_share"],
    ],
);

/// `tenko_dhcp_renewals_cached_total`: renewals answered from the stored lease.
pub static RENEWALS_CACHED: Counter = Counter::new(families::RENEWALS_CACHED);

/// A refusal the log keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The limit.
    pub limit: Limit,
    /// The client: a MAC address or a DUID; empty for a limit of the scope.
    pub client: Vec<u8>,
    /// The scope.
    pub scope: PrefixId,
    /// The limit's value.
    pub cap: u32,
    /// What the client (or the scope) held at the last refusal.
    pub held: u32,
    /// Refusals.
    pub count: u64,
    /// The first refusal.
    pub first: Timestamp,
    /// The last refusal.
    pub last: Timestamp,
}

impl Refusal {
    /// The client in text: a MAC address with colons, a DUID in hexadecimal.
    pub fn client_text(&self) -> String {
        let hex: Vec<String> = self
            .client
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect();
        if self.client.len() == 6 {
            hex.join(":")
        } else {
            hex.concat()
        }
    }
}

/// The refusals of a node's limits as its status reports them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitReport {
    /// The limits in force.
    pub limits: Option<Limits>,
    /// The refusals since the start, the most frequent first (at most [`MAX_LOGGED`]), each
    /// with its scope's network when the image has the scope.
    pub refusals: Vec<(Refusal, Option<ipnet::IpNet>)>,
    /// Refusals not kept.
    pub unlogged: u64,
}

/// The refusals a health row names; the rest are counted.
const NAMED: usize = 5;

impl LimitReport {
    /// The health row [`REFUSED`] while a limit refused clients.
    pub fn warnings(&self) -> Vec<crate::relay::RelayWarning> {
        if self.refusals.is_empty() {
            return Vec::new();
        }
        let named: Vec<String> = self
            .refusals
            .iter()
            .take(NAMED)
            .map(|(refusal, network)| {
                let scope = network
                    .map_or_else(|| refusal.scope.to_string(), |network| network.to_string());
                match refusal.limit {
                    Limit::OffersPerSecond => format!(
                        "new clients of {scope} beyond {} a second ({} refused): a burst waits \
                         for the scope's offer rate, not for its pool",
                        refusal.cap, refusal.count
                    ),
                    Limit::ConflictShare => format!(
                        "conflict marks in {scope} past an eighth of its pool ({} of {}, {} \
                         refused): the addresses were skipped for one offer, not abandoned",
                        refusal.held, refusal.cap, refusal.count
                    ),
                    _ => format!(
                        "{} in {scope} by {} (holds {} of {}, refused {} time(s))",
                        if refusal.client.is_empty() {
                            "a client".to_owned()
                        } else {
                            refusal.client_text()
                        },
                        refusal.limit.label(),
                        refusal.held,
                        refusal.cap,
                        refusal.count
                    ),
                }
            })
            .collect();
        let more = self.refusals.len().saturating_sub(NAMED);
        let more = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        let total: u64 = self
            .refusals
            .iter()
            .map(|(refusal, _)| refusal.count)
            .sum::<u64>()
            .saturating_add(self.unlogged);
        let mut params = std::collections::BTreeMap::new();
        params.insert("refused".to_owned(), total.to_string());
        params.insert(
            "limits".to_owned(),
            self.refusals
                .iter()
                .take(NAMED)
                .map(|(refusal, _)| refusal.limit.label())
                .collect::<Vec<_>>()
                .join(", "),
        );
        params.insert(
            "clients".to_owned(),
            self.refusals
                .iter()
                .take(NAMED)
                .filter(|(refusal, _)| !refusal.client.is_empty())
                .map(|(refusal, _)| refusal.client_text())
                .collect::<Vec<_>>()
                .join(", "),
        );
        vec![crate::relay::RelayWarning {
            code: REFUSED,
            detail: format!(
                "limits per client or per scope refused requests: {}{more}; raise or turn off \
                 a limit under the DHCP settings (limits) when these are legitimate clients",
                named.join("; ")
            ),
            params,
        }]
    }
}

/// The refusals of one node.
#[derive(Debug, Default)]
pub struct LimitLog {
    entries: Mutex<Vec<Refusal>>,
    unlogged: AtomicU64,
}

impl LimitLog {
    /// Notes a refusal by `limit` of `client` (empty for a limit of the scope) in `scope`,
    /// which held `held` of `cap`, and counts it.
    pub fn refuse(
        &self,
        limit: Limit,
        client: &[u8],
        scope: PrefixId,
        (cap, held): (u32, u32),
        now: Timestamp,
    ) {
        LIMITED.inc(limit as u16);
        let Ok(mut entries) = self.entries.try_lock() else {
            self.unlogged.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.limit == limit && entry.scope == scope && entry.client == client)
        {
            entry.count = entry.count.saturating_add(1);
            entry.cap = cap;
            entry.held = held;
            entry.last = now;
            return;
        }
        let entry = || Refusal {
            limit,
            client: client.to_vec(),
            scope,
            cap,
            held,
            count: 1,
            first: now,
            last: now,
        };
        if entries.len() < MAX_LOGGED {
            if entries.capacity() == 0 {
                entries.reserve_exact(MAX_LOGGED);
            }
            entries.push(entry());
            return;
        }
        // Full: an entry not refused for an hour gives way first, then one refused once.
        self.unlogged.fetch_add(1, Ordering::Relaxed);
        let stale =
            |entry: &Refusal| now.saturating_since(entry.last) >= Duration::from_secs(3_600);
        if let Some(weakest) = entries
            .iter_mut()
            .min_by_key(|entry| (!stale(entry), entry.count, entry.last))
            && (stale(weakest) || weakest.count == 1)
        {
            *weakest = entry();
        }
    }

    /// The refusals, the most frequent first, and those not kept.
    pub fn report(&self) -> (Vec<Refusal>, u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        entries.sort_by(|a, b| b.count.cmp(&a.count).then(b.last.cmp(&a.last)));
        (entries, self.unlogged.load(Ordering::Relaxed))
    }
}

/// The token buckets of the offer rate: fixed at start, one word per slot, a scope's slot by
/// the hash of its prefix (two scopes that share a slot share their rate, which only makes
/// it stricter). A word holds the tokens in thousandths (bit 62 marks a used slot) and the
/// millisecond of the last refill.
#[derive(Debug)]
pub struct OfferRate {
    slots: Box<[AtomicU64]>,
    origin: Instant,
    hasher: std::hash::RandomState,
}

const SLOTS: usize = 1_024;
const USED: u64 = 1 << 62;
const TOKENS_MASK: u64 = (1 << 32) - 1;

impl Default for OfferRate {
    fn default() -> Self {
        Self {
            slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            origin: Instant::now(),
            hasher: std::hash::RandomState::new(),
        }
    }
}

impl OfferRate {
    /// Takes one offer of `scope` at `rate` per second: false when the bucket is empty.
    /// Never allocates or blocks.
    pub fn take(&self, scope: PrefixId, rate: u32) -> bool {
        if rate == 0 {
            return true;
        }
        let now =
            u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX) & 0xffff_ffff;
        self.take_at(scope, rate, now)
    }

    /// Gives one offer of `scope` back (at most to the bucket's size).
    pub fn refund(&self, scope: PrefixId, rate: u32) {
        if rate == 0 {
            return;
        }
        let cap = u64::from(rate) * BURST_SECS * 1_000;
        let slot = self.slot(scope);
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            if current & USED == 0 {
                return;
            }
            let tokens = (current >> 32) & (TOKENS_MASK >> 2);
            let next = USED | ((tokens + 1_000).min(cap) << 32) | (current & TOKENS_MASK);
            match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return,
                Err(seen) => current = seen,
            }
        }
    }

    fn slot(&self, scope: PrefixId) -> &AtomicU64 {
        &self.slots[usize::try_from(self.hasher.hash_one(scope) % SLOTS as u64).unwrap_or(0)]
    }

    fn take_at(&self, scope: PrefixId, rate: u32, now: u64) -> bool {
        let rate = u64::from(rate);
        let cap = rate * BURST_SECS * 1_000;
        let slot = self.slot(scope);
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let (tokens, last) = ((current >> 32) & (TOKENS_MASK >> 2), current & TOKENS_MASK);
            let filled = if current & USED == 0 {
                cap
            } else {
                // Milliseconds wrap after 49 days; a gap of more than 24 days fills.
                let elapsed = now.wrapping_sub(last) & TOKENS_MASK;
                if elapsed > 1 << 31 {
                    cap
                } else {
                    (tokens + elapsed * rate).min(cap)
                }
            };
            if filled < 1_000 {
                return false;
            }
            let next = USED | ((filled - 1_000) << 32) | now;
            match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
    }
}

/// The conflict marks of each answering MAC address and of each scope.
#[derive(Debug)]
pub struct ConflictBudget {
    per_mac: DeclineLimit,
    per_scope: Mutex<HashMap<PrefixId, Marks>>,
}

/// The conflict marks of a scope in the last 24 hours, by hour.
#[derive(Debug, Clone, Copy, Default)]
struct Marks {
    hours: [u32; 24],
    hour: u64,
}

impl Marks {
    fn roll(&mut self, hour: u64) {
        let gap = hour.saturating_sub(self.hour);
        if gap >= 24 {
            self.hours = [0; 24];
        } else {
            for step in 1..=gap {
                self.hours[usize::try_from((self.hour + step) % 24).unwrap_or(0)] = 0;
            }
        }
        self.hour = hour;
    }

    fn total(&self) -> u64 {
        self.hours.iter().map(|count| u64::from(*count)).sum()
    }
}

impl Default for ConflictBudget {
    fn default() -> Self {
        Self {
            per_mac: DeclineLimit::new(1_024, CONFLICTS_PER_MAC, Duration::from_secs(3_600)),
            per_scope: Mutex::new(HashMap::new()),
        }
    }
}

impl ConflictBudget {
    /// Whether a conflict answered by `mac` may abandon an address of `scope`, whose pools
    /// hold `pool` addresses; counts it when it may. The limit that refuses otherwise, with
    /// the count it reached.
    ///
    /// # Errors
    ///
    /// The limit and what was held: [`Limit::ConflictsPerMac`] or [`Limit::ConflictShare`].
    pub fn mark(
        &self,
        scope: PrefixId,
        pool: u64,
        mac: Option<[u8; 6]>,
        now: Timestamp,
    ) -> Result<(), (Limit, u32, u32)> {
        let share = (pool / CONFLICT_SHARE).max(1);
        let hour = u64::try_from(now.unix_nanos().max(0) / 3_600_000_000_000).unwrap_or(0);
        let mut scopes = self
            .per_scope
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let marks = scopes.entry(scope).or_default();
        marks.roll(hour);
        let held = marks.total();
        if held >= share {
            return Err((
                Limit::ConflictShare,
                u32::try_from(share).unwrap_or(u32::MAX),
                u32::try_from(held).unwrap_or(u32::MAX),
            ));
        }
        if let Some(mac) = mac
            && !self.per_mac.allow(&mac, Instant::now())
        {
            return Err((Limit::ConflictsPerMac, CONFLICTS_PER_MAC, CONFLICTS_PER_MAC));
        }
        marks.hours[usize::try_from(hour % 24).unwrap_or(0)] += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profiles_and_the_stored_values() {
        assert_eq!(Limits::of_profile(DhcpProfile::Lab).leases_per_mac, 0);
        assert_eq!(Limits::of_profile(DhcpProfile::Home).leases_per_mac, 16);
        assert_eq!(Limits::of_profile(DhcpProfile::Hardened).leases_per_mac, 8);
        for profile in [
            DhcpProfile::Lab,
            DhcpProfile::Home,
            DhcpProfile::Standard,
            DhcpProfile::Hardened,
        ] {
            assert_eq!(
                Limits::of_profile(profile).renew_cache_percent,
                RENEW_CACHE_PERCENT
            );
        }
        let stored = DhcpLimits {
            leases_per_mac: Some(0),
            offers_per_second: Some(5),
            ..DhcpLimits::default()
        };
        let limits = Limits::resolve(&stored, DhcpProfile::Hardened);
        assert_eq!(limits.leases_per_mac, 0);
        assert_eq!(limits.offers_per_second, 5);
        assert_eq!(limits.addresses_per_duid, 8);
    }

    #[test]
    fn a_bucket_holds_ten_seconds_and_refills_at_the_rate() {
        let rate = OfferRate::default();
        let scope = PrefixId::generate();
        let taken = (0..2_000)
            .filter(|_| rate.take_at(scope, 100, 1_000))
            .count();
        assert_eq!(taken, 1_000);
        assert!(!rate.take_at(scope, 100, 1_000));
        // 50 ms at 100 a second: five more.
        let more = (0..10).filter(|_| rate.take_at(scope, 100, 1_050)).count();
        assert_eq!(more, 5);
        // A rate of zero is no limit.
        assert!(rate.take_at(scope, 0, 1_050) || rate.take(scope, 0));
    }

    #[test]
    fn conflict_marks_stop_at_the_mac_and_the_share() {
        let budget = ConflictBudget::default();
        let scope = PrefixId::generate();
        let now = Timestamp::now();
        let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x66];
        assert!(budget.mark(scope, 100, Some(mac), now).is_ok());
        assert!(budget.mark(scope, 100, Some(mac), now).is_ok());
        assert_eq!(
            budget.mark(scope, 100, Some(mac), now),
            Err((Limit::ConflictsPerMac, 2, 2))
        );
        // Other answers: the share of a pool of 100 is 12.
        let mut other = mac;
        for n in 0..10u8 {
            other[5] = n;
            assert!(budget.mark(scope, 100, Some(other), now).is_ok());
        }
        assert_eq!(
            budget.mark(scope, 100, None, now),
            Err((Limit::ConflictShare, 12, 12))
        );
        // A day later the marks are gone.
        let later = now
            .checked_add(Duration::from_secs(25 * 3_600))
            .expect("later");
        assert!(budget.mark(scope, 100, None, later).is_ok());
    }

    #[test]
    fn the_health_row_names_the_client_the_scope_the_limit_and_the_count() {
        let log = LimitLog::default();
        let scope = PrefixId::generate();
        let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
        log.refuse(Limit::LeasesPerMac, &mac, scope, (16, 16), Timestamp::now());
        log.refuse(
            Limit::OffersPerSecond,
            &[],
            scope,
            (100, 100),
            Timestamp::now(),
        );
        let (entries, unlogged) = log.report();
        let network: ipnet::IpNet = "192.0.2.0/24".parse().expect("net");
        let report = LimitReport {
            limits: None,
            refusals: entries
                .into_iter()
                .map(|entry| (entry, Some(network)))
                .collect(),
            unlogged,
        };
        let rows = report.warnings();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, REFUSED);
        assert!(
            rows[0]
                .detail
                .contains("00:00:5e:00:53:01 in 192.0.2.0/24 by leases_per_mac (holds 16 of 16"),
            "{rows:?}"
        );
        assert!(rows[0].detail.contains("not for its pool"), "{rows:?}");
        assert_eq!(rows[0].params["refused"], "2");
        assert_eq!(LimitReport::default().warnings(), Vec::new());
    }

    #[test]
    fn the_log_names_the_client_and_counts() {
        let log = LimitLog::default();
        let scope = PrefixId::generate();
        let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
        for _ in 0..3 {
            log.refuse(Limit::LeasesPerMac, &mac, scope, (16, 16), Timestamp::now());
        }
        let (entries, unlogged) = log.report();
        assert_eq!(unlogged, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].count, 3);
        assert_eq!(entries[0].client_text(), "00:00:5e:00:53:01");
    }
}
