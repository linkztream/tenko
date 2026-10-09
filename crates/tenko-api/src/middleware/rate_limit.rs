//! Keyed token-bucket rate limiting for the HTTP API.
//!
//! Two independent limiters share one implementation:
//!
//! - the per-address limiter is keyed by the client IP address and runs before
//!   authentication, which protects the login path;
//! - the per-principal limiter is keyed by the subject string of the authenticated principal
//!   (for example `user:<uuid>` or `token:<id>`) and runs after authentication.
//!
//! [`RateLimiter`] only decides. It takes the current time as an argument, so the middleware
//! passes `Instant::now()` and tests drive time explicitly. Turning a refusal into a 429
//! response with a `Retry-After` header (see [`RetryAfter::seconds`]) is up to the caller.
//!
//! # Algorithm
//!
//! Each key owns a token bucket of [`Quota::burst`] tokens that refills at
//! [`Quota::per_second`] tokens per second. A request takes one token. When the bucket holds
//! less than one token the request is refused together with the time until one token is
//! available. A key seen for the first time starts with a full bucket.
//!
//! # Keys
//!
//! - IPv4 addresses are used as they are.
//! - IPv6 addresses are masked to [`RateLimitConfig::ipv6_prefix_len`] bits, so one client
//!   that holds a whole prefix cannot get a fresh bucket per address.
//! - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are treated as the IPv4 address, which
//!   keeps dual-stack listeners from splitting one client over two buckets.
//! - Principals are keyed by their subject string.
//!
//! # Storage and memory bound
//!
//! Each limiter is a separate map, generic over the key type: `IpAddr` for addresses and
//! `Box<str>` for subjects. The subject map is looked up by `&str`, so a known principal costs
//! no allocation, and the address path allocates nothing beyond the map entry itself.
//!
//! A map is split into 16 shards, each a `Mutex<HashMap<_, Bucket>>`. The shard is chosen by a
//! randomly keyed hash of the key, so an attacker cannot aim traffic at one shard. A mutex
//! that was poisoned by a panic elsewhere is recovered, because the request path must never
//! panic.
//!
//! Each shard holds at most `max_keys / 16` buckets (at least 1). When a new key arrives at a
//! full shard, buckets that have refilled completely are dropped first (a fresh bucket for
//! them is indistinguishable from the old one); if the shard is still full, the bucket that
//! was updated longest ago is evicted. A request is never refused because a map is full.
//! Making room costs a pass over one shard, so a flood of distinct keys makes each new key
//! scan its shard under the shard lock; the cost is bounded by `max_keys / 16` entries.
//!
//! [`RateLimiter::purge_idle`] drops completely refilled buckets and is meant to run
//! periodically from a background task.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Number of shards per limiter.
const SHARDS: usize = 16;

/// Smallest accepted `max_keys`: at least one bucket per shard.
const MIN_MAX_KEYS: usize = SHARDS;

/// Default sustained rate and burst per client address.
const DEFAULT_PER_IP: Quota = Quota {
    per_second: 20,
    burst: 100,
};

/// Default sustained rate and burst per principal.
const DEFAULT_PER_PRINCIPAL: Quota = Quota {
    per_second: 50,
    burst: 200,
};

/// Default IPv6 prefix length that groups clients into one bucket.
const DEFAULT_IPV6_PREFIX_LEN: u8 = 64;

/// Default bound on tracked keys per limiter.
const DEFAULT_MAX_KEYS: usize = 100_000;

/// Sustained rate and burst of one limiter.
///
/// Serialized as `{ "per_second": 20, "burst": 100 }`. Both values must be at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Tokens added to a bucket per second: the sustained request rate per key. At least 1.
    pub per_second: u32,
    /// Capacity of a bucket: how many requests a key may send at once. At least 1.
    pub burst: u32,
}

impl Quota {
    /// Checks both values, naming the quota as `name` in the message.
    fn validate(self, name: &str) -> Result<(), String> {
        if self.per_second == 0 {
            return Err(format!("{name}.per_second must be at least 1"));
        }
        if self.burst == 0 {
            return Err(format!("{name}.burst must be at least 1"));
        }
        Ok(())
    }

    /// The quota with both values raised to at least 1.
    fn sanitized(self) -> Self {
        Self {
            per_second: self.per_second.max(1),
            burst: self.burst.max(1),
        }
    }
}

/// Configuration of both limiters.
///
/// Every field has a default, so a partial document is accepted. A quota set to `null` (or
/// `None`) switches that limiter off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Master switch. When `false`, every request passes. Default `true`.
    pub enabled: bool,
    /// Quota per client address, applied before authentication. `None` switches the limiter
    /// off. Default 20 requests per second with a burst of 100.
    pub per_ip: Option<Quota>,
    /// Quota per authenticated principal. `None` switches the limiter off. Default 50
    /// requests per second with a burst of 200.
    pub per_principal: Option<Quota>,
    /// IPv6 clients are grouped by this many leading bits. Valid range 1 to 128. Default 64.
    pub ipv6_prefix_len: u8,
    /// Upper bound on the keys tracked by each limiter, which bounds memory. At least 16.
    /// Default 100 000.
    pub max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip: Some(DEFAULT_PER_IP),
            per_principal: Some(DEFAULT_PER_PRINCIPAL),
            ipv6_prefix_len: DEFAULT_IPV6_PREFIX_LEN,
            max_keys: DEFAULT_MAX_KEYS,
        }
    }
}

impl RateLimitConfig {
    /// Checks that every value is in range: quotas of at least 1, an IPv6 prefix length of 1
    /// to 128 and `max_keys` of at least 16.
    ///
    /// # Errors
    ///
    /// Returns a message that names the first offending field.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(quota) = self.per_ip {
            quota.validate("per_ip")?;
        }
        if let Some(quota) = self.per_principal {
            quota.validate("per_principal")?;
        }
        if !(1..=128).contains(&self.ipv6_prefix_len) {
            return Err(format!(
                "ipv6_prefix_len must be between 1 and 128, got {}",
                self.ipv6_prefix_len
            ));
        }
        if self.max_keys < MIN_MAX_KEYS {
            return Err(format!(
                "max_keys must be at least {MIN_MAX_KEYS}, got {}",
                self.max_keys
            ));
        }
        Ok(())
    }

    /// The configuration with every out-of-range value moved to the nearest valid one.
    fn sanitized(mut self) -> Self {
        self.per_ip = self.per_ip.map(Quota::sanitized);
        self.per_principal = self.per_principal.map(Quota::sanitized);
        self.ipv6_prefix_len = self.ipv6_prefix_len.clamp(1, 128);
        self.max_keys = self.max_keys.max(MIN_MAX_KEYS);
        self
    }
}

/// How long the client should wait before retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub Duration);

impl RetryAfter {
    /// The wait in whole seconds for the `Retry-After` header: rounded up, and at least 1.
    pub fn seconds(self) -> u64 {
        let whole = self.0.as_secs();
        let rounded = if self.0.subsec_nanos() > 0 {
            whole.saturating_add(1)
        } else {
            whole
        };
        rounded.max(1)
    }
}

/// Which limiter refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// The per-address limiter, applied before authentication.
    Ip,
    /// The per-principal limiter, applied after authentication.
    Principal,
}

impl LimitScope {
    /// A stable lowercase name for logs and problem details: `"ip"` or `"principal"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Principal => "principal",
        }
    }
}

/// The state of one key.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens held as of `updated`. Fractional, because refill is continuous.
    tokens: f64,
    /// The latest time this bucket was brought up to date. Never moves backwards.
    updated: Instant,
}

impl Bucket {
    /// A full bucket, as a key seen for the first time gets.
    fn full(quota: Quota, now: Instant) -> Self {
        Self {
            tokens: f64::from(quota.burst),
            updated: now,
        }
    }

    /// The tokens the bucket holds at `now`, without changing it. A `now` before `updated`
    /// adds nothing.
    fn refilled(&self, quota: Quota, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        (self.tokens + elapsed * f64::from(quota.per_second)).min(f64::from(quota.burst))
    }

    /// Whether the bucket is full at `now`, so that dropping it changes nothing.
    fn is_idle(&self, quota: Quota, now: Instant) -> bool {
        self.refilled(quota, now) >= f64::from(quota.burst)
    }

    /// Refills the bucket to `now` and takes one token, or reports the wait for one.
    fn take(&mut self, quota: Quota, now: Instant) -> Result<(), RetryAfter> {
        let tokens = self.refilled(quota, now);
        self.updated = self.updated.max(now);
        if tokens >= 1.0 {
            self.tokens = tokens - 1.0;
            Ok(())
        } else {
            self.tokens = tokens;
            let wait = (1.0 - tokens) / f64::from(quota.per_second);
            Err(RetryAfter(
                Duration::try_from_secs_f64(wait).unwrap_or(Duration::from_secs(1)),
            ))
        }
    }
}

/// Locks a shard. A poisoned mutex is recovered: the buckets are plain numbers, so whatever a
/// panicking thread left behind is still a usable state.
fn lock<K>(shard: &Mutex<HashMap<K, Bucket>>) -> MutexGuard<'_, HashMap<K, Bucket>> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Token buckets for one limiter, spread over [`SHARDS`] independently locked maps.
struct KeyedBuckets<K> {
    /// The quota every bucket in this limiter follows.
    quota: Quota,
    /// Most buckets one shard may hold.
    shard_cap: usize,
    /// Randomly keyed hasher that picks the shard.
    hasher: RandomState,
    /// The shards.
    shards: [Mutex<HashMap<K, Bucket>>; SHARDS],
}

impl<K: Hash + Eq> KeyedBuckets<K> {
    /// An empty limiter that tracks at most about `max_keys` keys.
    fn new(quota: Quota, max_keys: usize) -> Self {
        Self {
            quota,
            shard_cap: (max_keys / SHARDS).max(1),
            hasher: RandomState::new(),
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    /// The shard that owns `key`.
    fn shard_index<Q: Hash + ?Sized>(&self, key: &Q) -> usize {
        let slot = self.hasher.hash_one(key) % SHARDS as u64;
        usize::try_from(slot).unwrap_or(0)
    }

    /// Takes one token for `key`. `to_owned` builds the stored key, and runs only when the key
    /// is new.
    fn check<Q>(
        &self,
        key: &Q,
        to_owned: impl FnOnce(&Q) -> K,
        now: Instant,
    ) -> Result<(), RetryAfter>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut map = lock(&self.shards[self.shard_index(key)]);
        if let Some(bucket) = map.get_mut(key) {
            return bucket.take(self.quota, now);
        }
        if map.len() >= self.shard_cap {
            self.make_room(&mut map, now);
        }
        let mut bucket = Bucket::full(self.quota, now);
        let verdict = bucket.take(self.quota, now);
        map.insert(to_owned(key), bucket);
        verdict
    }

    /// Frees at least one slot in a full shard: first every completely refilled bucket, then,
    /// if that was not enough, the bucket that was updated longest ago.
    fn make_room(&self, map: &mut HashMap<K, Bucket>, now: Instant) {
        let mut oldest: Option<Instant> = None;
        map.retain(|_, bucket| {
            if bucket.is_idle(self.quota, now) {
                return false;
            }
            oldest = Some(oldest.map_or(bucket.updated, |seen| seen.min(bucket.updated)));
            true
        });
        if map.len() >= self.shard_cap
            && let Some(oldest) = oldest
        {
            map.extract_if(|_, bucket| bucket.updated == oldest).next();
        }
    }

    /// Drops every completely refilled bucket and returns how many there were.
    fn purge_idle(&self, now: Instant) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut map = lock(shard);
                let before = map.len();
                map.retain(|_, bucket| !bucket.is_idle(self.quota, now));
                before - map.len()
            })
            .sum()
    }

    /// The number of tracked keys.
    fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).len()).sum()
    }
}

/// The rate limiter of the HTTP API: one limiter per client address and one per principal.
///
/// The limiter is shared between requests (typically behind an `Arc`) and all methods take
/// `&self`. See the module documentation for the algorithm and the memory bound.
pub struct RateLimiter {
    /// The effective configuration, after clamping.
    config: RateLimitConfig,
    /// Mask applied to IPv6 addresses to form their key.
    ipv6_mask: u128,
    /// The per-address limiter, absent when disabled.
    per_ip: Option<KeyedBuckets<IpAddr>>,
    /// The per-principal limiter, absent when disabled.
    per_principal: Option<KeyedBuckets<Box<str>>>,
}

impl RateLimiter {
    /// Builds a limiter from `config`.
    ///
    /// The configuration is expected to have passed [`RateLimitConfig::validate`]. Values that
    /// would fail validation are clamped into range instead of causing a panic (quotas to at
    /// least 1, the IPv6 prefix length into 1 to 128, `max_keys` to at least 16), and
    /// [`config`](Self::config) reports the values in effect.
    pub fn new(config: RateLimitConfig) -> Self {
        let config = config.sanitized();
        let ipv6_mask = !u128::MAX
            .checked_shr(u32::from(config.ipv6_prefix_len))
            .unwrap_or(0);
        let (per_ip, per_principal) = if config.enabled {
            (
                config
                    .per_ip
                    .map(|quota| KeyedBuckets::new(quota, config.max_keys)),
                config
                    .per_principal
                    .map(|quota| KeyedBuckets::new(quota, config.max_keys)),
            )
        } else {
            (None, None)
        };
        Self {
            config,
            ipv6_mask,
            per_ip,
            per_principal,
        }
    }

    /// The configuration in effect.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Takes one token for the client address `ip` at time `now`.
    ///
    /// Always passes when the limiter is disabled. An IPv4-mapped IPv6 address counts as its
    /// IPv4 address, and other IPv6 addresses count as their prefix.
    ///
    /// # Errors
    ///
    /// Returns the [`RetryAfter`] wait when the client has no token left.
    pub fn check_ip(&self, ip: IpAddr, now: Instant) -> Result<(), RetryAfter> {
        match &self.per_ip {
            Some(buckets) => buckets.check(&self.ip_key(ip), |key| *key, now),
            None => Ok(()),
        }
    }

    /// Takes one token for the principal with the given subject at time `now`.
    ///
    /// Always passes when the limiter is disabled.
    ///
    /// # Errors
    ///
    /// Returns the [`RetryAfter`] wait when the principal has no token left.
    pub fn check_principal(&self, subject: &str, now: Instant) -> Result<(), RetryAfter> {
        match &self.per_principal {
            Some(buckets) => buckets.check(subject, |subject| Box::from(subject), now),
            None => Ok(()),
        }
    }

    /// Drops the buckets that have refilled completely, in both limiters, and returns how many
    /// were dropped. A dropped key starts over with a full bucket, which is what it holds
    /// anyway. Meant to be called periodically.
    pub fn purge_idle(&self, now: Instant) -> usize {
        self.per_ip
            .as_ref()
            .map_or(0, |buckets| buckets.purge_idle(now))
            + self
                .per_principal
                .as_ref()
                .map_or(0, |buckets| buckets.purge_idle(now))
    }

    /// The number of keys tracked by both limiters together.
    pub fn tracked_keys(&self) -> usize {
        self.per_ip.as_ref().map_or(0, KeyedBuckets::len)
            + self.per_principal.as_ref().map_or(0, KeyedBuckets::len)
    }

    /// The bucket key of a client address.
    fn ip_key(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
                || IpAddr::V6(Ipv6Addr::from(u128::from(v6) & self.ipv6_mask)),
                IpAddr::V4,
            ),
        }
    }
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    fn quota(per_second: u32, burst: u32) -> Quota {
        Quota { per_second, burst }
    }

    /// A configuration with the given quotas and defaults elsewhere.
    fn config(per_ip: Option<Quota>, per_principal: Option<Quota>) -> RateLimitConfig {
        RateLimitConfig {
            per_ip,
            per_principal,
            ..RateLimitConfig::default()
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address parses")
    }

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    /// Asserts that `wait` is within one millisecond of `expected_ms`.
    fn assert_wait_about(wait: Duration, expected_ms: u64) {
        let range = ms(expected_ms.saturating_sub(1))..=ms(expected_ms + 1);
        assert!(
            range.contains(&wait),
            "wait {wait:?} is not about {expected_ms} ms"
        );
    }

    /// `2001:db8:0:<net>::1`, one address in each distinct /64.
    fn net64(net: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, net, 0, 0, 0, 1))
    }

    fn hit(buckets: &KeyedBuckets<IpAddr>, key: IpAddr, now: Instant) -> bool {
        buckets.check(&key, |key| *key, now).is_ok()
    }

    /// Addresses that the given limiter maps to one shard.
    fn same_shard_ips(buckets: &KeyedBuckets<IpAddr>, count: usize) -> Vec<IpAddr> {
        let mut groups: Vec<Vec<IpAddr>> = vec![Vec::new(); SHARDS];
        for net in 0..512 {
            let candidate = net64(net);
            groups[buckets.shard_index(&candidate)].push(candidate);
        }
        let mut group = groups
            .into_iter()
            .find(|group| group.len() >= count)
            .expect("some shard holds enough candidates");
        group.truncate(count);
        group
    }

    #[test]
    fn burst_passes_then_requests_are_refused() {
        let limiter = RateLimiter::new(config(Some(quota(10, 5)), None));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        for n in 1..=5 {
            assert!(
                limiter.check_ip(client, t0).is_ok(),
                "request {n} is inside the burst"
            );
        }
        assert!(limiter.check_ip(client, t0).is_err());
        assert!(limiter.check_ip(client, t0).is_err());
    }

    #[test]
    fn refusal_reports_the_wait_for_one_token() {
        let limiter = RateLimiter::new(config(Some(quota(10, 1)), None));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        assert!(limiter.check_ip(client, t0).is_ok());

        let refused = limiter.check_ip(client, t0).expect_err("bucket is empty");
        assert_wait_about(refused.0, 100);
        assert_eq!(refused.seconds(), 1);

        // After 40 ms 0.4 tokens are back, so 60 ms remain.
        let refused = limiter
            .check_ip(client, t0 + ms(40))
            .expect_err("still short of a token");
        assert_wait_about(refused.0, 60);
    }

    #[test]
    fn retry_after_seconds_rounds_up_and_is_at_least_one() {
        assert_eq!(RetryAfter(Duration::ZERO).seconds(), 1);
        assert_eq!(RetryAfter(Duration::from_nanos(1)).seconds(), 1);
        assert_eq!(RetryAfter(ms(100)).seconds(), 1);
        assert_eq!(RetryAfter(ms(1000)).seconds(), 1);
        assert_eq!(RetryAfter(ms(1001)).seconds(), 2);
        assert_eq!(RetryAfter(ms(2500)).seconds(), 3);
        assert_eq!(RetryAfter(Duration::from_secs(60)).seconds(), 60);
        assert_eq!(RetryAfter(Duration::MAX).seconds(), u64::MAX);
    }

    #[test]
    fn slowest_quota_waits_at_most_one_second() {
        let limiter = RateLimiter::new(config(Some(quota(1, 1)), None));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        assert!(limiter.check_ip(client, t0).is_ok());
        let refused = limiter.check_ip(client, t0).expect_err("bucket is empty");
        assert_wait_about(refused.0, 1000);
        assert_eq!(refused.seconds(), 1);
    }

    #[test]
    fn tokens_refill_as_time_passes() {
        let limiter = RateLimiter::new(config(Some(quota(10, 2)), None));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        assert!(limiter.check_ip(client, t0).is_ok());
        assert!(limiter.check_ip(client, t0).is_ok());
        assert!(limiter.check_ip(client, t0).is_err());

        // 101 ms at 10 per second is a little over one token.
        let t1 = t0 + ms(101);
        assert!(limiter.check_ip(client, t1).is_ok());
        assert!(limiter.check_ip(client, t1).is_err());

        // A long pause refills to the burst and no further.
        let t2 = t1 + Duration::from_secs(60);
        assert!(limiter.check_ip(client, t2).is_ok());
        assert!(limiter.check_ip(client, t2).is_ok());
        assert!(limiter.check_ip(client, t2).is_err());
    }

    #[test]
    fn addresses_have_independent_buckets() {
        let limiter = RateLimiter::new(config(Some(quota(1, 1)), None));
        let t0 = Instant::now();
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_ok());
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_err());
        assert!(limiter.check_ip(ip("192.0.2.2"), t0).is_ok());
        assert!(limiter.check_ip(ip("198.51.100.1"), t0).is_ok());
        assert!(limiter.check_ip(ip("2001:db8::1"), t0).is_ok());
        assert!(limiter.check_ip(ip("203.0.113.9"), t0).is_ok());
        assert_eq!(limiter.tracked_keys(), 5);
    }

    #[test]
    fn ipv6_addresses_in_one_64_share_a_bucket() {
        let limiter = RateLimiter::new(config(Some(quota(1, 1)), None));
        let t0 = Instant::now();
        assert!(limiter.check_ip(ip("2001:db8:0:1::1"), t0).is_ok());
        assert!(limiter.check_ip(ip("2001:db8:0:1:ffff::2"), t0).is_err());
        assert_eq!(limiter.tracked_keys(), 1);

        // A neighboring /64 has a bucket of its own.
        assert!(limiter.check_ip(ip("2001:db8:0:2::1"), t0).is_ok());
        assert_eq!(limiter.tracked_keys(), 2);
    }

    #[test]
    fn ipv6_prefix_length_is_configurable() {
        let t0 = Instant::now();

        let mut wide = config(Some(quota(1, 1)), None);
        wide.ipv6_prefix_len = 48;
        let limiter = RateLimiter::new(wide);
        assert!(limiter.check_ip(ip("2001:db8:0:1::1"), t0).is_ok());
        assert!(limiter.check_ip(ip("2001:db8:0:2::1"), t0).is_err());
        assert!(limiter.check_ip(ip("2001:db8:1::1"), t0).is_ok());

        let mut exact = config(Some(quota(1, 1)), None);
        exact.ipv6_prefix_len = 128;
        let limiter = RateLimiter::new(exact);
        assert!(limiter.check_ip(ip("2001:db8::1"), t0).is_ok());
        assert!(limiter.check_ip(ip("2001:db8::2"), t0).is_ok());
        assert!(limiter.check_ip(ip("2001:db8::1"), t0).is_err());
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_ipv4_address() {
        for prefix_len in [1, 64, 128] {
            let mut cfg = config(Some(quota(1, 1)), None);
            cfg.ipv6_prefix_len = prefix_len;
            let limiter = RateLimiter::new(cfg);
            let t0 = Instant::now();
            assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_ok());
            assert!(
                limiter.check_ip(ip("::ffff:192.0.2.1"), t0).is_err(),
                "prefix {prefix_len}"
            );
            assert_eq!(limiter.tracked_keys(), 1);
        }
    }

    #[test]
    fn principal_limiter_is_independent_of_the_ip_limiter() {
        let limiter = RateLimiter::new(config(Some(quota(1, 1)), Some(quota(1, 1))));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        let subject = "user:0190d1c2-7a3b-7c4d-8e5f-0123456789ab";

        // Exhausting the address leaves the principal untouched.
        assert!(limiter.check_ip(client, t0).is_ok());
        assert!(limiter.check_ip(client, t0).is_err());
        assert!(limiter.check_principal(subject, t0).is_ok());

        // Exhausting the principal leaves a fresh address untouched.
        assert!(limiter.check_principal(subject, t0).is_err());
        assert!(limiter.check_ip(ip("198.51.100.1"), t0).is_ok());
        assert_eq!(limiter.tracked_keys(), 3);
    }

    #[test]
    fn principals_have_independent_buckets() {
        let limiter = RateLimiter::new(config(None, Some(quota(2, 2))));
        let t0 = Instant::now();
        for _ in 0..2 {
            assert!(limiter.check_principal("user:alice", t0).is_ok());
        }
        assert!(limiter.check_principal("user:alice", t0).is_err());
        assert!(limiter.check_principal("user:bob", t0).is_ok());
        assert!(limiter.check_principal("token:ci", t0).is_ok());

        let refused = limiter
            .check_principal("user:alice", t0)
            .expect_err("bucket is empty");
        assert_wait_about(refused.0, 500);
    }

    #[test]
    fn disabled_limiter_always_passes() {
        let mut cfg = config(Some(quota(1, 1)), Some(quota(1, 1)));
        cfg.enabled = false;
        let limiter = RateLimiter::new(cfg);
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_ok());
            assert!(limiter.check_principal("user:alice", t0).is_ok());
        }
        assert_eq!(limiter.tracked_keys(), 0);
        assert_eq!(limiter.purge_idle(t0), 0);
    }

    #[test]
    fn missing_quota_switches_only_that_limiter_off() {
        let t0 = Instant::now();

        let no_ip = RateLimiter::new(config(None, Some(quota(1, 1))));
        for _ in 0..100 {
            assert!(no_ip.check_ip(ip("192.0.2.1"), t0).is_ok());
        }
        assert!(no_ip.check_principal("user:alice", t0).is_ok());
        assert!(no_ip.check_principal("user:alice", t0).is_err());

        let no_principal = RateLimiter::new(config(Some(quota(1, 1)), None));
        for _ in 0..100 {
            assert!(no_principal.check_principal("user:alice", t0).is_ok());
        }
        assert!(no_principal.check_ip(ip("192.0.2.1"), t0).is_ok());
        assert!(no_principal.check_ip(ip("192.0.2.1"), t0).is_err());
        assert_eq!(no_principal.tracked_keys(), 1);
    }

    #[test]
    fn purge_idle_removes_only_refilled_buckets() {
        let limiter = RateLimiter::new(config(Some(quota(10, 3)), Some(quota(10, 3))));
        let t0 = Instant::now();
        let drained = ip("192.0.2.1");
        let barely_used = ip("192.0.2.2");
        for _ in 0..3 {
            assert!(limiter.check_ip(drained, t0).is_ok());
        }
        assert!(limiter.check_ip(barely_used, t0).is_ok());
        assert!(limiter.check_principal("user:alice", t0).is_ok());
        assert_eq!(limiter.tracked_keys(), 3);

        // After 150 ms the barely used buckets are full again; the drained one holds 1.5.
        let t1 = t0 + ms(150);
        assert_eq!(limiter.purge_idle(t1), 2);
        assert_eq!(limiter.tracked_keys(), 1);

        // The drained bucket survived with its state: 1.5 tokens allow one request only.
        assert!(limiter.check_ip(drained, t1).is_ok());
        assert!(limiter.check_ip(drained, t1).is_err());

        // Much later it is full as well, and nothing is left to remember.
        assert_eq!(limiter.purge_idle(t1 + Duration::from_secs(10)), 1);
        assert_eq!(limiter.tracked_keys(), 0);
        assert_eq!(limiter.purge_idle(t1 + Duration::from_secs(10)), 0);
    }

    #[test]
    fn full_shards_evict_instead_of_refusing() {
        let mut cfg = config(Some(quota(1, 1)), Some(quota(1, 1)));
        cfg.max_keys = 16;
        let limiter = RateLimiter::new(cfg);
        let t0 = Instant::now();
        for net in 0..1000 {
            assert!(limiter.check_ip(net64(net), t0).is_ok(), "address {net}");
            assert!(
                limiter.check_principal(&format!("user:{net}"), t0).is_ok(),
                "principal {net}"
            );
            assert!(
                limiter.tracked_keys() <= 32,
                "tracked {}",
                limiter.tracked_keys()
            );
        }
        assert!(limiter.tracked_keys() > 0);
    }

    #[test]
    fn eviction_drops_the_bucket_updated_longest_ago() {
        // 32 keys over 16 shards: two buckets per shard.
        let buckets = KeyedBuckets::<IpAddr>::new(quota(1, 1), 32);
        assert_eq!(buckets.shard_cap, 2);
        let keys = same_shard_ips(&buckets, 3);
        let (first, second, third) = (keys[0], keys[1], keys[2]);
        let t0 = Instant::now();

        assert!(hit(&buckets, first, t0));
        assert!(hit(&buckets, second, t0 + ms(10)));
        assert_eq!(buckets.len(), 2);

        // The shard is full; the third key pushes out `first`, the oldest.
        assert!(hit(&buckets, third, t0 + ms(20)));
        assert_eq!(buckets.len(), 2);

        // `second` kept its drained bucket, `first` starts over.
        assert!(!hit(&buckets, second, t0 + ms(30)));
        assert!(hit(&buckets, first, t0 + ms(30)));
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn eviction_drops_refilled_buckets_before_old_ones() {
        let buckets = KeyedBuckets::<IpAddr>::new(quota(1, 2), 32);
        let keys = same_shard_ips(&buckets, 3);
        let (old_drained, newer_refilled, newcomer) = (keys[0], keys[1], keys[2]);
        let t0 = Instant::now();

        // Empty at t0, so 1.6 of 2 tokens at t0 + 1.6 s: not idle.
        assert!(hit(&buckets, old_drained, t0));
        assert!(hit(&buckets, old_drained, t0));
        // One token left at t0 + 0.5 s, so 2.1 of 2 tokens at t0 + 1.6 s: idle.
        assert!(hit(&buckets, newer_refilled, t0 + ms(500)));

        // The sweep drops the idle bucket, which makes room without evicting the oldest.
        assert!(hit(&buckets, newcomer, t0 + ms(1600)));
        assert_eq!(buckets.len(), 2);
        assert!(hit(&buckets, old_drained, t0 + ms(1600)));
        assert!(
            !hit(&buckets, old_drained, t0 + ms(1600)),
            "the drained bucket was kept"
        );
    }

    #[test]
    fn default_config_round_trips_through_json() {
        let config = RateLimitConfig::default();
        let text = serde_json::to_string(&config).expect("serializes");
        let back: RateLimitConfig = serde_json::from_str(&text).expect("parses");
        assert_eq!(back, config);

        assert_eq!(
            serde_json::to_value(&config).expect("serializes"),
            json!({
                "enabled": true,
                "per_ip": { "per_second": 20, "burst": 100 },
                "per_principal": { "per_second": 50, "burst": 200 },
                "ipv6_prefix_len": 64,
                "max_keys": 100_000,
            })
        );
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let empty: RateLimitConfig = serde_json::from_str("{}").expect("parses");
        assert_eq!(empty, RateLimitConfig::default());

        let partial: RateLimitConfig = serde_json::from_value(json!({
            "enabled": false,
            "per_ip": { "per_second": 5, "burst": 10 },
        }))
        .expect("parses");
        assert!(!partial.enabled);
        assert_eq!(partial.per_ip, Some(quota(5, 10)));
        assert_eq!(
            partial.per_principal,
            RateLimitConfig::default().per_principal
        );
        assert_eq!(partial.ipv6_prefix_len, 64);
        assert_eq!(partial.max_keys, 100_000);

        let off: RateLimitConfig =
            serde_json::from_value(json!({ "per_principal": null })).expect("parses");
        assert_eq!(off.per_principal, None);
        assert_eq!(off.per_ip, RateLimitConfig::default().per_ip);
    }

    #[test]
    fn quota_uses_the_documented_json_shape() {
        let parsed: Quota =
            serde_json::from_str(r#"{ "per_second": 20, "burst": 100 }"#).expect("parses");
        assert_eq!(parsed, quota(20, 100));
        assert!(serde_json::from_str::<Quota>(r#"{ "per_second": 20 }"#).is_err());
        assert!(serde_json::from_str::<Quota>(r#"{ "per_second": -1, "burst": 1 }"#).is_err());
    }

    #[test]
    fn validate_accepts_the_edges_of_the_valid_range() {
        let mut cfg = config(Some(quota(1, 1)), Some(quota(u32::MAX, u32::MAX)));
        cfg.ipv6_prefix_len = 1;
        cfg.max_keys = 16;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.ipv6_prefix_len = 128;
        assert_eq!(cfg.validate(), Ok(()));
        assert_eq!(config(None, None).validate(), Ok(()));
    }

    #[test]
    fn validate_names_the_offending_field() {
        let error = |mutate: fn(&mut RateLimitConfig)| {
            let mut cfg = RateLimitConfig::default();
            mutate(&mut cfg);
            cfg.validate().expect_err("configuration is invalid")
        };
        assert!(error(|c| c.per_ip = Some(quota(0, 10))).contains("per_ip.per_second"));
        assert!(error(|c| c.per_ip = Some(quota(10, 0))).contains("per_ip.burst"));
        assert!(
            error(|c| c.per_principal = Some(quota(0, 10))).contains("per_principal.per_second")
        );
        assert!(error(|c| c.per_principal = Some(quota(10, 0))).contains("per_principal.burst"));
        assert!(error(|c| c.ipv6_prefix_len = 0).contains("ipv6_prefix_len"));
        assert!(error(|c| c.ipv6_prefix_len = 129).contains("ipv6_prefix_len"));
        assert!(error(|c| c.max_keys = 15).contains("max_keys"));
        assert!(error(|c| c.max_keys = 0).contains("max_keys"));
    }

    #[test]
    fn new_clamps_invalid_values_instead_of_panicking() {
        let invalid = RateLimitConfig {
            enabled: true,
            per_ip: Some(quota(0, 0)),
            per_principal: Some(quota(0, 5)),
            ipv6_prefix_len: 0,
            max_keys: 0,
        };
        assert!(invalid.validate().is_err());
        let limiter = RateLimiter::new(invalid);

        let effective = limiter.config();
        assert_eq!(effective.per_ip, Some(quota(1, 1)));
        assert_eq!(effective.per_principal, Some(quota(1, 5)));
        assert_eq!(effective.ipv6_prefix_len, 1);
        assert_eq!(effective.max_keys, 16);
        assert_eq!(effective.validate(), Ok(()));

        let t0 = Instant::now();
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_ok());
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_err());

        let too_wide = RateLimiter::new(RateLimitConfig {
            ipv6_prefix_len: 200,
            ..RateLimitConfig::default()
        });
        assert_eq!(too_wide.config().ipv6_prefix_len, 128);
        assert!(too_wide.check_ip(ip("2001:db8::1"), t0).is_ok());
    }

    #[test]
    fn valid_config_is_kept_as_given() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_ip: Some(quota(7, 9)),
            per_principal: None,
            ipv6_prefix_len: 56,
            max_keys: 4096,
        };
        assert_eq!(RateLimiter::new(cfg.clone()).config(), &cfg);
    }

    #[test]
    fn time_going_backwards_neither_panics_nor_adds_tokens() {
        let limiter = RateLimiter::new(config(Some(quota(10, 2)), Some(quota(10, 2))));
        let t0 = Instant::now();
        let late = t0 + Duration::from_secs(10);
        let client = ip("192.0.2.1");

        assert!(limiter.check_ip(client, late).is_ok());
        // An earlier `now` refills nothing: one token is left, then none.
        assert!(limiter.check_ip(client, t0).is_ok());
        assert!(limiter.check_ip(client, t0).is_err());
        // The bucket did not travel back in time either, so `late` is not ten seconds later.
        assert!(limiter.check_ip(client, late).is_err());

        // A key first seen at an earlier time works as well.
        assert!(limiter.check_principal("user:alice", late).is_ok());
        assert!(limiter.check_principal("user:alice", t0).is_ok());
        assert!(limiter.check_principal("user:alice", t0).is_err());
        assert_eq!(limiter.purge_idle(t0), 0);
    }

    #[test]
    fn poisoned_shards_are_recovered() {
        let limiter = RateLimiter::new(config(Some(quota(1, 1)), Some(quota(1, 1))));
        let t0 = Instant::now();
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_ok());

        let ip_buckets = limiter.per_ip.as_ref().expect("per-address limiter is on");
        let principal_buckets = limiter
            .per_principal
            .as_ref()
            .expect("per-principal limiter is on");
        for shard in &ip_buckets.shards {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _guard = shard.lock().expect("not yet poisoned");
                panic!("poison the shard");
            }));
            assert!(outcome.is_err());
        }
        for shard in &principal_buckets.shards {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _guard = shard.lock().expect("not yet poisoned");
                panic!("poison the shard");
            }));
            assert!(outcome.is_err());
        }
        assert!(ip_buckets.shards.iter().all(Mutex::is_poisoned));

        // Existing state survives, new keys work, and the maintenance calls do not panic.
        assert!(limiter.check_ip(ip("192.0.2.1"), t0).is_err());
        assert!(limiter.check_ip(ip("192.0.2.2"), t0).is_ok());
        assert!(limiter.check_principal("user:alice", t0).is_ok());
        assert_eq!(limiter.tracked_keys(), 3);
        assert_eq!(limiter.purge_idle(t0 + Duration::from_secs(10)), 3);
    }

    #[test]
    fn concurrent_callers_share_one_bucket() {
        let limiter = RateLimiter::new(config(Some(quota(1, 50)), None));
        let t0 = Instant::now();
        let client = ip("192.0.2.1");
        let passed = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        if limiter.check_ip(client, t0).is_ok() {
                            passed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        // Time stands still, so exactly the burst gets through.
        assert_eq!(passed.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn limiter_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RateLimiter>();
        assert_send_sync::<RateLimitConfig>();
    }

    #[test]
    fn debug_output_shows_the_config_only() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let text = format!("{limiter:?}");
        assert!(text.starts_with("RateLimiter"));
        assert!(text.contains("ipv6_prefix_len: 64"));
    }

    #[test]
    fn scopes_have_stable_names() {
        assert_eq!(LimitScope::Ip.as_str(), "ip");
        assert_eq!(LimitScope::Principal.as_str(), "principal");
    }
}
