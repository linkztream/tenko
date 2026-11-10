//! Progressive lockout with in-memory throttling (IAM-05, TGL-07).
//!
//! A flood of failed logins must never reach the replicated store, and it must not cost a
//! password verification either. [`Throttle`] therefore lives in memory and is consulted
//! first. The service calls it in this order:
//!
//! 1. [`Throttle::check`] before anything else. On `Err(Retry)` the attempt is refused
//!    without verifying the password.
//! 2. The credential is verified only when `check` allowed the attempt.
//! 3. [`Throttle::record_success`] or [`Throttle::record_failure`]. Only when the
//!    [`FailureOutcome`] carries `locked_until` does the service persist a lock (and raise an
//!    alarm when `alert` is set).
//!
//! A login of several steps is one attempt for the account's keys. A wrong password and a
//! wrong second-factor code (TOTP or recovery code) both count as a failure on them, so the
//! policy's lock is reached after its number of failures across any number of challenges. A
//! correct password alone is not a success: the keys are forgotten only when the whole login
//! completes, when the last factor has passed and the session is written.
//!
//! Three kinds of key are tracked side by side ([`ThrottleKey`]):
//!
//! - [`ThrottleKey::AccountSource`], an account seen from one client network (an IPv4
//!   address or an IPv6 /64): the attempts, the waits and the lock of [`LockPolicy`]. One
//!   network cannot lock an account for the others.
//! - [`ThrottleKey::Account`], the account across every network: a delay with a short
//!   ceiling once the account fails more often than one network may ([`LockPolicy::account_wide`]),
//!   which keeps a distributed guess slow without locking anyone out.
//! - [`ThrottleKey::Source`], a client network across every account, with
//!   [`LockoutPolicy::source_policy`], which slows password spraying.
//!
//! Unknown account names are keyed exactly like known ones, so throttling reveals nothing
//! about which accounts exist.
//!
//! # Time
//!
//! Every method takes `now` from the caller (a [`Clock`](crate::clock::Clock)), so the
//! module itself never reads the system time and tests need no sleeping.
//!
//! # Memory
//!
//! The table holds at most `capacity` keys. A new key at capacity evicts entries that have
//! expired first, then the entry with the oldest last failure; an entry that is currently
//! locked is evicted last. Eviction scans the table, which is acceptable because
//! [`Throttle::record_failure`] is only reached after a credential verification, which costs
//! orders of magnitude more. The service should bound the length of the user names it
//! turns into keys.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv6Addr},
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;
use time::PrimitiveDateTime;
use utoipa::ToSchema;

/// The latest representable instant. Sums that would pass it saturate here, which stands for
/// "never" (a lock that has no end, a delay that does not elapse).
const FAR_FUTURE: Timestamp = Timestamp(PrimitiveDateTime::MAX.assume_utc());

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// How failed logins are punished (TGL-07).
///
/// The security presets map onto the modes as Home to `ProgressiveDelay`, Standard to
/// `DelayThenTemporaryLock`, Hardened to `LockUntilUnlock` and Lab to `Off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LockoutMode {
    /// No delay and no lock. Nothing is tracked.
    Off,
    /// Each failure beyond the free attempts doubles the delay before the next attempt. The
    /// account is never locked.
    ProgressiveDelay,
    /// Progressive delays, then a temporary lock that lifts by itself.
    DelayThenTemporaryLock,
    /// Progressive delays, then a lock that an administrator lifts. It also lifts by itself
    /// after the policy's lock duration, so an attacker cannot lock an account forever. Each
    /// such lock raises an alarm.
    LockUntilUnlock,
}

impl LockoutMode {
    /// The stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ProgressiveDelay => "progressive_delay",
            Self::DelayThenTemporaryLock => "delay_then_temporary_lock",
            Self::LockUntilUnlock => "lock_until_unlock",
        }
    }

    /// Whether the mode ever locks.
    const fn locks(self) -> bool {
        matches!(self, Self::DelayThenTemporaryLock | Self::LockUntilUnlock)
    }
}

/// The longest wait schedule a [`LockPolicy`] may hold.
pub const MAX_WAITS: usize = 10;

/// A fixed list of waits, the delays of a [`LockPolicy`] in place of doubling. Copyable, so
/// [`LockoutPolicy`] stays a plain value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    waits: [Duration; MAX_WAITS],
    len: usize,
}

impl Schedule {
    /// No schedule: the policy doubles its base delay.
    pub const NONE: Self = Self {
        waits: [Duration::ZERO; MAX_WAITS],
        len: 0,
    };

    /// A schedule of up to [`MAX_WAITS`] waits; longer lists are cut there.
    pub fn new(waits: &[Duration]) -> Self {
        let mut schedule = Self::NONE;
        for (slot, wait) in schedule.waits.iter_mut().zip(waits) {
            *slot = *wait;
        }
        schedule.len = waits.len().min(MAX_WAITS);
        schedule
    }

    /// The waits.
    pub fn waits(&self) -> &[Duration] {
        &self.waits[..self.len]
    }

    /// Whether the schedule is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The numbers behind a [`LockoutMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// What happens to failed logins.
    pub mode: LockoutMode,
    /// Failures before delays start. Failure `n <= free_attempts` has no delay.
    pub free_attempts: u32,
    /// The first delay. It doubles with every further failure. Unused with a schedule.
    pub base_delay: Duration,
    /// The longest delay. Unused with a schedule.
    pub max_delay: Duration,
    /// The delays in order, when set: failure `free_attempts + k` waits `schedule[k - 1]`,
    /// and the last wait repeats.
    pub schedule: Schedule,
    /// The failure that locks. Used by the modes that lock; a value of 0 counts as 1, so a
    /// locking mode never degrades into no lock at all.
    pub lock_after: u32,
    /// How long a lock holds. For [`LockoutMode::LockUntilUnlock`] this is the timeout after
    /// which the lock lifts by itself. Unused by the modes that do not lock.
    pub lock_duration: Duration,
    /// An entry with no failure for this long is forgotten. Fixed per key by the policy in
    /// force at its last failure.
    pub reset_after: Duration,
}

impl LockoutPolicy {
    /// The policy of an account seen from one network under `mode` with the default
    /// [`LockPolicy`]: three attempts, waits of 10 s, 30 s, 3 min, 5 min and 10 min, then a
    /// lock of 30 minutes in the modes that lock. `Off` delays and locks nothing.
    pub fn for_mode(mode: LockoutMode) -> Self {
        LockPolicy::default().per_source(mode)
    }

    /// The policy for [`ThrottleKey::Source`]: per client network and independent of the
    /// account, so one network trying many accounts (password spraying) is slowed down even
    /// though no single account fails often. 20 free attempts, then 1 s doubling up to 30 s,
    /// never a lock, forgotten after 15 minutes.
    ///
    /// It does not depend on the account mode; the service decides whether to apply it.
    pub fn source_policy() -> Self {
        Self {
            mode: LockoutMode::ProgressiveDelay,
            free_attempts: 20,
            base_delay: SECOND,
            max_delay: 30 * SECOND,
            schedule: Schedule::NONE,
            lock_after: 0,
            lock_duration: Duration::ZERO,
            reset_after: 15 * MINUTE,
        }
    }

    /// The delay before the next attempt after `failures` consecutive failures.
    ///
    /// Failure `n <= free_attempts` gives zero. After that a schedule gives its waits in
    /// order and repeats the last one; without one the delay is
    /// `min(base_delay * 2^(n - free_attempts - 1), max_delay)`. The arithmetic saturates, so
    /// no failure count overflows. Mode `Off` always gives zero.
    pub fn delay_after(&self, failures: u32) -> Duration {
        if self.mode == LockoutMode::Off || failures <= self.free_attempts {
            return Duration::ZERO;
        }
        let beyond = failures - self.free_attempts - 1;
        if let Some(last) = self.schedule.waits().last() {
            let index = usize::try_from(beyond).unwrap_or(usize::MAX);
            return self.schedule.waits().get(index).copied().unwrap_or(*last);
        }
        let mut doublings = beyond;
        let mut delay = self.base_delay;
        // Terminates within about 95 rounds: from a non-zero start the delay saturates at
        // `Duration::MAX`, which is not below any `max_delay`. A zero delay stays zero.
        while doublings > 0 && !delay.is_zero() && delay < self.max_delay {
            delay = delay.saturating_mul(2);
            doublings -= 1;
        }
        delay.min(self.max_delay)
    }
}

/// The lock policy an administrator sets (TGL-07, IAM-05): how many attempts an account
/// gets from one network, the waits after them, the lock that follows, the account-wide
/// ceiling and whether a passkey sign-in respects the lock. The mode ([`LockoutMode`])
/// decides whether the lock is applied at all.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LockPolicy {
    /// Attempts an account has from one network before the first wait (1 to 20).
    pub attempts: u32,
    /// The waits between the next attempts, in seconds, in order (1 to 10 entries, each 1 s
    /// to one day). The account is locked for that network after the last one, in the modes
    /// that lock; in the others the last wait repeats.
    pub waits_secs: Vec<u32>,
    /// How long the lock holds, in seconds (one minute to one day). It always ends by itself.
    pub lock_secs: u32,
    /// The ceiling of the account-wide delay, in seconds (0 to 600; 0 switches the delay
    /// off). The delay starts once the account fails, across every network, as often as
    /// one network may before its lock; that is also when the alarm is raised.
    pub account_max_delay_secs: u32,
    /// Whether the lock also holds for a passkey sign-in (Hardened). Otherwise a passkey,
    /// which cannot be guessed, signs in through the lock.
    pub passkey_holds_lock: bool,
}

impl Default for LockPolicy {
    /// The default of Home, Standard and Lab: three attempts, waits of 10 s, 30 s, 3 min,
    /// 5 min and 10 min, a lock of 30 minutes, an account-wide ceiling of one minute, and a
    /// passkey that passes the lock.
    fn default() -> Self {
        Self {
            attempts: 3,
            waits_secs: vec![10, 30, 180, 300, 600],
            lock_secs: 1_800,
            account_max_delay_secs: 60,
            passkey_holds_lock: false,
        }
    }
}

impl LockPolicy {
    /// The most attempts before the first wait.
    pub const MAX_ATTEMPTS: u32 = 20;
    /// The longest wait and the longest lock: one day.
    pub const MAX_SECS: u32 = 86_400;
    /// The shortest lock: one minute.
    pub const MIN_LOCK_SECS: u32 = 60;
    /// The highest account-wide ceiling: ten minutes.
    pub const MAX_ACCOUNT_DELAY_SECS: u32 = 600;

    /// The default of the Hardened profile: the numbers of [`LockPolicy::default`], and the
    /// lock holds for a passkey as well.
    pub fn hardened() -> Self {
        Self {
            passkey_holds_lock: true,
            ..Self::default()
        }
    }

    /// Whether this policy is weaker than `baseline` in any respect: more attempts before
    /// the first wait or before the lock, less waiting in total, a shorter lock, a lower
    /// account-wide ceiling, or a passkey that passes a lock the baseline holds.
    pub fn weaker_than(&self, baseline: &Self) -> bool {
        let total = |policy: &Self| -> u64 {
            policy
                .waits_secs
                .iter()
                .take(MAX_WAITS)
                .map(|secs| u64::from(*secs))
                .sum()
        };
        self.attempts > baseline.attempts
            || self.lock_threshold() > baseline.lock_threshold()
            || total(self) < total(baseline)
            || self.lock_secs < baseline.lock_secs
            || self.account_max_delay_secs < baseline.account_max_delay_secs
            || (baseline.passkey_holds_lock && !self.passkey_holds_lock)
    }

    /// The failure from one network that locks the account: the attempts plus the waits.
    pub fn lock_threshold(&self) -> u32 {
        let waits = u32::try_from(self.waits_secs.len().min(MAX_WAITS)).unwrap_or(u32::MAX);
        self.attempts.saturating_add(waits)
    }

    fn waits(&self) -> Vec<Duration> {
        self.waits_secs
            .iter()
            .take(MAX_WAITS)
            .map(|secs| Duration::from_secs(u64::from(*secs)))
            .collect()
    }

    /// The policy of [`ThrottleKey::AccountSource`] under `mode`. Failures are forgotten
    /// after the lock's duration without a failure, or twice the longest wait if that is
    /// longer, so waiting out the schedule never resets it.
    pub fn per_source(&self, mode: LockoutMode) -> LockoutPolicy {
        if mode == LockoutMode::Off {
            return LockoutPolicy {
                mode,
                free_attempts: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                schedule: Schedule::NONE,
                lock_after: 0,
                lock_duration: Duration::ZERO,
                reset_after: Duration::ZERO,
            };
        }
        let waits = self.waits();
        let longest = waits.iter().max().copied().unwrap_or(Duration::ZERO);
        let lock = Duration::from_secs(u64::from(self.lock_secs));
        LockoutPolicy {
            mode,
            free_attempts: self.attempts.saturating_sub(1),
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            schedule: Schedule::new(&waits),
            lock_after: self.lock_threshold(),
            lock_duration: lock,
            reset_after: lock.max(longest.saturating_mul(2)),
        }
    }

    /// The policy of [`ThrottleKey::Account`]: no delay up to the lock threshold, then 1 s
    /// doubling up to `account_max_delay_secs`, never a lock, forgotten after the lock's
    /// duration (at least an hour) without a failure. Under `Off`, or with a ceiling of 0,
    /// the failures are still counted (for the alarm) but never delay.
    pub fn account_wide(&self, mode: LockoutMode) -> LockoutPolicy {
        let ceiling = Duration::from_secs(u64::from(self.account_max_delay_secs));
        let delays = mode != LockoutMode::Off && !ceiling.is_zero();
        LockoutPolicy {
            mode: LockoutMode::ProgressiveDelay,
            free_attempts: if delays {
                self.lock_threshold()
            } else {
                u32::MAX
            },
            base_delay: SECOND.min(ceiling),
            max_delay: ceiling,
            schedule: Schedule::NONE,
            lock_after: 0,
            lock_duration: Duration::ZERO,
            reset_after: Duration::from_secs(u64::from(self.lock_secs)).max(HOUR),
        }
    }

    /// Whether account-wide failure number `failures` raises the alarm: at the lock
    /// threshold, and again each time the count doubles, so a long attack is reported
    /// without one alarm per attempt.
    pub fn alarms_at(&self, failures: u32) -> bool {
        let threshold = self.lock_threshold().max(1);
        failures >= threshold
            && failures.is_multiple_of(threshold)
            && (failures / threshold).is_power_of_two()
    }

    /// Checks the bounds of every number.
    ///
    /// # Errors
    ///
    /// [`crate::AuthError::Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), crate::AuthError> {
        let invalid = |reason: &'static str| crate::AuthError::invalid("lockout_policy", reason);
        if self.attempts == 0 || self.attempts > Self::MAX_ATTEMPTS {
            return Err(invalid("attempts must be 1 to 20"));
        }
        if self.waits_secs.is_empty() || self.waits_secs.len() > MAX_WAITS {
            return Err(invalid("waits_secs must hold 1 to 10 waits"));
        }
        if self
            .waits_secs
            .iter()
            .any(|secs| *secs == 0 || *secs > Self::MAX_SECS)
        {
            return Err(invalid("every wait must be 1 second to one day"));
        }
        if self.lock_secs < Self::MIN_LOCK_SECS || self.lock_secs > Self::MAX_SECS {
            return Err(invalid("lock_secs must be one minute to one day"));
        }
        if self.account_max_delay_secs > Self::MAX_ACCOUNT_DELAY_SECS {
            return Err(invalid("account_max_delay_secs must be 0 to 600"));
        }
        Ok(())
    }
}

/// The client network of an address, as the throttle keys it: an IPv4 address as it is, an
/// IPv6 address cut to its /64 (one subscriber or one link). An IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`) is the IPv4 address.
pub fn source_network(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}

/// The stand-in network of a request whose client address is not known.
pub const UNKNOWN_SOURCE: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// What is throttled: an account, a client network, or an account seen from one network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThrottleKey {
    /// A user name, lowercased, across every network. Also used for names that do not
    /// exist, so the throttle does not reveal which accounts exist. Build it with
    /// [`ThrottleKey::account`].
    Account(String),
    /// A client network ([`source_network`]). Build it with [`ThrottleKey::source`].
    Source(IpAddr),
    /// A user name, lowercased, seen from one client network: the key the lock is counted
    /// on. Build it with [`ThrottleKey::account_source`].
    AccountSource(String, IpAddr),
    /// The rate limit of the break-glass account. A variant of its own, so that no typed
    /// user name can reach it.
    BreakGlass(tenko_core::UserId),
    /// Wrong setup tokens from one client network. A variant of its own, like
    /// [`ThrottleKey::BreakGlass`].
    Setup(IpAddr),
}

impl ThrottleKey {
    /// The key of an account: the user name, lowercased.
    pub fn account(user_name: &str) -> Self {
        Self::Account(user_name.to_lowercase())
    }

    /// The key of a client network: an IPv4 address, or the /64 of an IPv6 address. An
    /// IPv4-mapped IPv6 address is the same client as the IPv4 address.
    pub fn source(addr: IpAddr) -> Self {
        Self::Source(source_network(addr))
    }

    /// The key of an account seen from the network of `addr` ([`UNKNOWN_SOURCE`] when the
    /// address is not known).
    pub fn account_source(user_name: &str, addr: Option<IpAddr>) -> Self {
        Self::AccountSource(
            user_name.to_lowercase(),
            addr.map_or(UNKNOWN_SOURCE, source_network),
        )
    }

    /// The key of setup attempts from the network of `addr`.
    pub fn setup(addr: Option<IpAddr>) -> Self {
        Self::Setup(addr.map_or(UNKNOWN_SOURCE, source_network))
    }

    /// The account name of an account key.
    fn account_name(&self) -> Option<&str> {
        match self {
            Self::Account(name) | Self::AccountSource(name, _) => Some(name),
            Self::Source(_) | Self::BreakGlass(_) | Self::Setup(_) => None,
        }
    }
}

/// The next attempt is not allowed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    /// How long until an attempt is allowed again: the rest of the delay, or the rest of the
    /// lock. `None` when there is no known end: the lock lasts until an administrator unlocks
    /// it (its timeout is beyond the representable time range).
    pub after: Option<Duration>,
}

/// The result of [`Throttle::record_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcome {
    /// Consecutive failures of the key including this one. Mode `Off` does not track and
    /// reports 0.
    pub failures: u32,
    /// The earliest next attempt is `now + delay`. While a lock holds it is at least the rest
    /// of the lock.
    pub delay: Duration,
    /// Set exactly once, on the failure that locks. The service persists it on the user
    /// record. A failure counted while the key is already locked does not extend the lock and
    /// reports `None`.
    pub locked_until: Option<Timestamp>,
    /// True when a [`LockoutMode::LockUntilUnlock`] lock starts: the service raises an alarm.
    pub alert: bool,
}

/// `at + duration`, saturating at [`FAR_FUTURE`].
fn add_saturating(at: Timestamp, duration: Duration) -> Timestamp {
    at.checked_add(duration).unwrap_or(FAR_FUTURE)
}

/// The time left until `until`, or `None` when `until` stands for "never".
fn remaining(until: Timestamp, now: Timestamp) -> Option<Duration> {
    (until != FAR_FUTURE).then(|| until.saturating_since(now))
}

/// What the table remembers about one key.
#[derive(Debug, Clone, Copy)]
struct Tracked {
    failures: u32,
    last_failure: Timestamp,
    locked_until: Option<Timestamp>,
    /// From this instant the entry no longer exists: the end of the lock, or the last
    /// failure plus the policy's `reset_after`.
    forget_at: Timestamp,
}

impl Tracked {
    fn new(now: Timestamp) -> Self {
        Self {
            failures: 0,
            last_failure: now,
            locked_until: None,
            forget_at: now,
        }
    }

    fn is_live(&self, now: Timestamp) -> bool {
        now < self.forget_at
    }

    /// The end of the lock, if one holds at `now`.
    fn active_lock(&self, now: Timestamp) -> Option<Timestamp> {
        self.locked_until.filter(|&until| now < until)
    }

    /// Whether an attempt at `now` is allowed. A guarded key ignores its lock and is held
    /// by the delay alone.
    fn verdict(&self, policy: &LockoutPolicy, now: Timestamp, guarded: bool) -> Result<(), Retry> {
        if !guarded && let Some(until) = self.active_lock(now) {
            return Err(Retry {
                after: remaining(until, now),
            });
        }
        let delay = policy.delay_after(self.failures);
        if delay.is_zero() {
            return Ok(());
        }
        let next = add_saturating(self.last_failure, delay);
        if now < next {
            // The wait never exceeds one delay, even when the clock has been set back.
            return Err(Retry {
                after: Some(next.saturating_since(now).min(delay)),
            });
        }
        Ok(())
    }

    /// Ranks entries for eviction, smallest first: unlocked entries by their last failure,
    /// then locked ones by the end of their lock. Without `now` every entry that has a lock
    /// counts as locked.
    fn eviction_rank(&self, now: Option<Timestamp>) -> (bool, Timestamp) {
        match self.locked_until {
            Some(until) if now.is_none_or(|n| n < until) => (true, until),
            _ => (false, self.last_failure),
        }
    }
}

type Table = HashMap<ThrottleKey, Tracked>;

/// The in-memory failure table. Cheap to share: methods take `&self`.
///
/// The table sits behind one short-held mutex; nothing slow runs under it, and a poisoned
/// mutex is recovered rather than propagated.
pub struct Throttle {
    capacity: usize,
    entries: Mutex<Table>,
}

impl fmt::Debug for Throttle {
    // Keys are user names and client addresses, so only the sizes are shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Throttle")
            .field("capacity", &self.capacity)
            .field("tracked", &self.len())
            .finish_non_exhaustive()
    }
}

impl Throttle {
    /// A throttle that tracks at most `capacity` keys (at least one).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether an attempt for `key` is allowed at `now`. Call it before verifying any
    /// credential. It never counts anything; it only drops an entry that has expired.
    ///
    /// Mode `Off` always allows. Otherwise the attempt is refused while a lock holds (even if
    /// the mode has been relaxed since the lock started) and while
    /// `now < last_failure + delay`; at exactly `last_failure + delay` it is allowed. A lock
    /// that has timed out lifts and the failure counter starts again.
    ///
    /// # Errors
    ///
    /// [`Retry`] when the attempt is not allowed yet.
    pub fn check(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
    ) -> Result<(), Retry> {
        self.check_as(key, policy, now, false)
    }

    /// [`Throttle::check`] for a key the last-administrator guard covers: a lock the key
    /// holds (from before the guard applied) is ignored, the delay still holds.
    ///
    /// # Errors
    ///
    /// [`Retry`] while the delay holds.
    pub fn check_guarded(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
    ) -> Result<(), Retry> {
        self.check_as(key, policy, now, true)
    }

    /// The lock `key` holds at `now`, if any, ignoring its delay.
    pub fn lock_of(&self, key: &ThrottleKey, now: Timestamp) -> Option<Retry> {
        let table = self.table();
        let tracked = table.get(key).filter(|tracked| tracked.is_live(now))?;
        tracked.active_lock(now).map(|until| Retry {
            after: remaining(until, now),
        })
    }

    fn check_as(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
        guarded: bool,
    ) -> Result<(), Retry> {
        if policy.mode == LockoutMode::Off {
            return Ok(());
        }
        let mut table = self.table();
        let Some(tracked) = table.get(key) else {
            return Ok(());
        };
        if tracked.is_live(now) {
            return tracked.verdict(policy, now, guarded);
        }
        table.remove(key);
        Ok(())
    }

    /// Counts a failed attempt for `key` at `now` and reports what follows from it.
    ///
    /// Mode `Off` does not track at all: nothing is stored, `failures` is 0, there is no delay
    /// and no lock. In the other modes the entry is created (making room if the table is
    /// full), and the failure that reaches `lock_after` starts the lock in the modes that
    /// lock. Only that one failure reports `locked_until`.
    pub fn record_failure(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
    ) -> FailureOutcome {
        self.record_failure_as(key, policy, now, false)
    }

    /// [`Throttle::record_failure`] for a key the last-administrator guard covers: the
    /// failure is counted and delays as usual, but it never locks, and a lock the key holds
    /// does not stop the count. The last wait of the schedule repeats instead.
    pub fn record_failure_guarded(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
    ) -> FailureOutcome {
        self.record_failure_as(key, policy, now, true)
    }

    fn record_failure_as(
        &self,
        key: &ThrottleKey,
        policy: &LockoutPolicy,
        now: Timestamp,
        guarded: bool,
    ) -> FailureOutcome {
        if policy.mode == LockoutMode::Off {
            return FailureOutcome {
                failures: 0,
                delay: Duration::ZERO,
                locked_until: None,
                alert: false,
            };
        }
        let mut table = self.table();
        if table.get(key).is_some_and(|tracked| !tracked.is_live(now)) {
            table.remove(key);
        }
        if !table.contains_key(key) {
            Self::make_room(&mut table, self.capacity, Some(now));
        }
        let tracked = table
            .entry(key.clone())
            .or_insert_with(|| Tracked::new(now));
        tracked.failures = tracked.failures.saturating_add(1);
        let failures = tracked.failures;

        if guarded {
            tracked.locked_until = None;
        }
        if let Some(until) = tracked.active_lock(now) {
            // Already locked: the lock neither restarts nor grows, and raises no second alarm.
            return FailureOutcome {
                failures,
                delay: until.saturating_since(now),
                locked_until: None,
                alert: false,
            };
        }

        tracked.last_failure = now;
        let delay = policy.delay_after(failures);
        if !guarded && policy.mode.locks() && failures >= policy.lock_after.max(1) {
            let until = add_saturating(now, policy.lock_duration);
            tracked.locked_until = Some(until);
            tracked.forget_at = until;
            return FailureOutcome {
                failures,
                delay: delay.max(until.saturating_since(now)),
                locked_until: Some(until),
                alert: policy.mode == LockoutMode::LockUntilUnlock,
            };
        }
        tracked.forget_at = add_saturating(now, policy.reset_after);
        FailureOutcome {
            failures,
            delay,
            locked_until: None,
            alert: false,
        }
    }

    /// Forgets `key` after a successful login: counter, delay and any lock.
    ///
    /// Call it once the login has completed (the last factor passed), never after a first
    /// factor that a second one follows. Call it for the account keys only. A success must
    /// not wipe the failures of the client network, or one valid account would clear the
    /// spraying counter of its network.
    pub fn record_success(&self, key: &ThrottleKey) {
        self.table().remove(key);
    }

    /// Administrator unlock: forgets `key` (counter, delay and lock).
    pub fn unlock(&self, key: &ThrottleKey) {
        self.table().remove(key);
    }

    /// Administrator unlock of an account: forgets every key of `user_name` (any case), the
    /// account-wide one and one per network. Scans the table, which an unlock can afford.
    pub fn unlock_account(&self, user_name: &str) {
        let name = user_name.to_lowercase();
        self.table()
            .retain(|key, _| key.account_name() != Some(name.as_str()));
    }

    /// Seeds a persisted lock after a restart: `key` is locked until `until`. A lock that
    /// has already ended is dropped by the next access. An existing lock is never shortened.
    ///
    /// The table must be large enough for the locks being restored; when it is full, other
    /// entries make room by the usual eviction order.
    pub fn restore_lock(&self, key: ThrottleKey, until: Timestamp) {
        let mut table = self.table();
        if let Some(tracked) = table.get_mut(&key) {
            let until = tracked.locked_until.map_or(until, |held| held.max(until));
            tracked.locked_until = Some(until);
            tracked.forget_at = until;
            return;
        }
        Self::make_room(&mut table, self.capacity, None);
        table.insert(
            key,
            Tracked {
                failures: 0,
                last_failure: until,
                locked_until: Some(until),
                forget_at: until,
            },
        );
    }

    /// The number of tracked keys, including entries that have expired but were not yet
    /// dropped by an access.
    pub fn len(&self) -> usize {
        self.table().len()
    }

    /// Whether no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.table().is_empty()
    }

    /// Frees one slot for a new key when the table is full: expired entries first (when the
    /// time is known), then the entry with the oldest last failure, locked entries last.
    fn make_room(table: &mut Table, capacity: usize, now: Option<Timestamp>) {
        if table.len() < capacity {
            return;
        }
        if let Some(now) = now {
            table.retain(|_, tracked| tracked.is_live(now));
        }
        while table.len() >= capacity {
            let victim = table
                .iter()
                .min_by_key(|(_, tracked)| tracked.eviction_rank(now))
                .map(|(key, _)| key.clone());
            match victim {
                Some(key) => {
                    table.remove(&key);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn at(unix_secs: i128) -> Timestamp {
        Timestamp::from_unix_nanos(unix_secs * 1_000_000_000).expect("in range")
    }

    #[test]
    fn mode_names_are_stable() {
        let names: Vec<_> = [
            LockoutMode::Off,
            LockoutMode::ProgressiveDelay,
            LockoutMode::DelayThenTemporaryLock,
            LockoutMode::LockUntilUnlock,
        ]
        .map(LockoutMode::as_str)
        .into();
        assert_eq!(
            names,
            [
                "off",
                "progressive_delay",
                "delay_then_temporary_lock",
                "lock_until_unlock"
            ]
        );
    }

    /// A doubling policy: `free` free failures, then `base` doubling up to 60 s.
    fn doubling(free: u32, base: Duration) -> LockoutPolicy {
        LockoutPolicy {
            mode: LockoutMode::ProgressiveDelay,
            free_attempts: free,
            base_delay: base,
            max_delay: secs(60),
            schedule: Schedule::NONE,
            lock_after: 0,
            lock_duration: Duration::ZERO,
            reset_after: secs(900),
        }
    }

    #[test]
    fn delay_schedule_of_doubling_policies() {
        let policy = doubling(5, secs(1));
        let delays: Vec<u64> = (1..=14).map(|n| policy.delay_after(n).as_secs()).collect();
        assert_eq!(delays, [0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 60, 60, 60]);

        let strict = doubling(3, secs(2));
        let delays: Vec<u64> = (1..=8).map(|n| strict.delay_after(n).as_secs()).collect();
        assert_eq!(delays, [0, 0, 0, 2, 4, 8, 16, 32]);
    }

    #[test]
    fn a_schedule_gives_its_waits_in_order_then_repeats_the_last() {
        let policy = LockoutPolicy::for_mode(LockoutMode::ProgressiveDelay);
        let delays: Vec<u64> = (1..=9).map(|n| policy.delay_after(n).as_secs()).collect();
        assert_eq!(delays, [0, 0, 10, 30, 180, 300, 600, 600, 600]);
        assert_eq!(policy.delay_after(u32::MAX), secs(600));
        let long: Vec<Duration> = (1..=12).map(secs).collect();
        assert_eq!(Schedule::new(&long).waits().len(), MAX_WAITS);
        assert!(Schedule::NONE.is_empty());
    }

    #[test]
    fn delay_never_overflows_for_huge_failure_counts() {
        let mut policy = doubling(5, secs(1));
        assert_eq!(policy.delay_after(u32::MAX), secs(60));

        // The smallest base against the largest cap: saturates instead of wrapping.
        policy.free_attempts = 0;
        policy.base_delay = Duration::from_nanos(1);
        policy.max_delay = Duration::MAX;
        assert_eq!(policy.delay_after(u32::MAX), Duration::MAX);
        assert_eq!(policy.delay_after(1), Duration::from_nanos(1));
        assert_eq!(policy.delay_after(2), Duration::from_nanos(2));

        // A base beyond the cap is clamped to it.
        policy.base_delay = Duration::MAX;
        policy.max_delay = secs(5);
        assert_eq!(policy.delay_after(1), secs(5));
        assert_eq!(policy.delay_after(u32::MAX), secs(5));
        policy.max_delay = Duration::MAX;
        assert_eq!(policy.delay_after(u32::MAX), Duration::MAX);
    }

    #[test]
    fn zero_base_delay_never_delays_and_terminates() {
        let mut policy = doubling(5, secs(1));
        policy.free_attempts = 0;
        policy.base_delay = Duration::ZERO;
        assert_eq!(policy.delay_after(u32::MAX), Duration::ZERO);
    }

    #[test]
    fn free_attempts_cover_every_failure_count() {
        let mut policy = doubling(5, secs(1));
        policy.free_attempts = u32::MAX;
        assert_eq!(policy.delay_after(u32::MAX), Duration::ZERO);
        policy.free_attempts = 0;
        assert_eq!(policy.delay_after(0), Duration::ZERO);
        assert_eq!(policy.delay_after(1), secs(1));
    }

    #[test]
    fn mode_off_has_no_delay() {
        let policy = LockoutPolicy::for_mode(LockoutMode::Off);
        assert_eq!(policy.delay_after(u32::MAX), Duration::ZERO);
        let mut custom = LockoutPolicy::for_mode(LockoutMode::ProgressiveDelay);
        custom.mode = LockoutMode::Off;
        assert_eq!(custom.delay_after(100), Duration::ZERO);
    }

    #[test]
    fn sums_saturate_at_the_end_of_time() {
        let now = at(1_791_547_200);
        assert_eq!(
            add_saturating(now, secs(60)).saturating_since(now),
            secs(60)
        );
        assert_eq!(add_saturating(now, Duration::MAX), FAR_FUTURE);
        assert_eq!(add_saturating(FAR_FUTURE, secs(1)), FAR_FUTURE);
        assert_eq!(remaining(FAR_FUTURE, now), None);
        assert_eq!(remaining(add_saturating(now, secs(5)), now), Some(secs(5)));
    }

    #[test]
    fn throttle_survives_a_huge_policy_without_panicking() {
        let throttle = Throttle::new(4);
        let mut policy = LockoutPolicy::for_mode(LockoutMode::LockUntilUnlock);
        policy.lock_after = 1;
        policy.lock_duration = Duration::MAX;
        policy.reset_after = Duration::MAX;
        let key = ThrottleKey::account("alice");
        let now = at(1_791_547_200);
        let outcome = throttle.record_failure(&key, &policy, now);
        assert_eq!(outcome.locked_until, Some(FAR_FUTURE));
        assert_eq!(
            throttle.check(&key, &policy, now),
            Err(Retry { after: None })
        );
    }

    #[test]
    fn eviction_ranks_locked_entries_last() {
        let now = at(1_000);
        let mut unlocked = Tracked::new(now);
        unlocked.last_failure = at(900);
        let mut locked = Tracked::new(now);
        locked.last_failure = at(100);
        locked.locked_until = Some(at(2_000));
        assert!(unlocked.eviction_rank(Some(now)) < locked.eviction_rank(Some(now)));
        // Once the lock has ended the entry ranks by its last failure again.
        assert!(locked.eviction_rank(Some(at(3_000))) < unlocked.eviction_rank(Some(at(3_000))));
    }

    #[test]
    fn capacity_is_at_least_one() {
        let throttle = Throttle::new(0);
        let policy = LockoutPolicy::for_mode(LockoutMode::ProgressiveDelay);
        let now = at(1_000);
        throttle.record_failure(&ThrottleKey::account("a"), &policy, now);
        throttle.record_failure(&ThrottleKey::account("b"), &policy, now);
        assert_eq!(throttle.len(), 1);
    }

    #[test]
    fn debug_output_hides_the_keys() {
        let throttle = Throttle::new(8);
        let policy = LockoutPolicy::for_mode(LockoutMode::ProgressiveDelay);
        throttle.record_failure(&ThrottleKey::account("secret-name"), &policy, at(1_000));
        let shown = format!("{throttle:?}");
        assert!(!shown.contains("secret-name"));
        assert!(shown.contains("tracked: 1"));
    }

    #[test]
    fn throttle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Throttle>();
    }
}
