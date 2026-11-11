//! The guard of every sign-in step (IAM-05, TGL-07): the lock checks, the record of a
//! failure, and the bound on password hashing.
//!
//! # The lock
//!
//! An attempt is keyed three ways ([`crate::lockout`]): the account seen from the client's
//! network (an IPv4 address or an IPv6 /64) carries the attempts, the waits and the lock of
//! the [`LockPolicy`]; the account across every network carries a delay with a short ceiling
//! and the alarm; the network across every account slows spraying. A lock reached on one
//! controller is stored in [`LOCKS`] under the name and the network, in the batch that
//! records the failure, so it holds on every controller; it is stored for names that do not
//! exist as well, so a locked name answers the same whether the account exists or not.
//!
//! The last administrator (the one person left who administers) is never locked by the
//! network: its failures still wait out the schedule, whose last wait then repeats, but no
//! lock is reached, stored or enforced. The account-wide delay applies to it as to every
//! account, and never locks. The alarm applies too. `tenko user unlock` lifts the locks of any account on a stopped
//! controller.
//!
//! A network from which the account completed a sign-in in the last 30 days is a known
//! network of the account ([`KnownNetworks`], in memory per controller), and a browser that
//! completed one holds a mark of a known device (`super::devices`, stored): the account-wide
//! delay holds back neither, so failures from elsewhere cannot keep the real user out by
//! taking each turn the delay frees. A mark has a budget of failures of its own.
//!
//! # Hashing
//!
//! Argon2id takes tens of megabytes per computation, in the process that also serves DNS
//! and DHCP. [`HashGate`] bounds the memory of the computations in flight: each takes its
//! cost in MiB from a budget (`[auth] password_hash_memory_mib`), and an attempt that finds
//! the budget spent is refused at once with `auth.throttled`, before any memory is taken.
//! One network has at most one sign-in computation in flight, and a share of the budget is
//! kept for known networks, so a flood from many networks cannot take every computation.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    ObjectRef, Principal, RequestCtx, Revision, SystemComponent,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};
use tokio::sync::Semaphore;

use super::{AuthService, actions};
use crate::{
    error::AuthError,
    lockout::{LockPolicy, LockoutMode, LockoutPolicy, Retry, ThrottleKey, UNKNOWN_SOURCE},
    model::{AccountLock, AlarmKind, LOCKS, UserRecord},
    password::hash::{HashCost, HashStrength},
    settings::SecuritySettings,
};

/// The key of a stored lock: the lowercase name and the client network as text.
pub(super) type LockKey = (String, String);

/// The most stored locks one name holds at once.
pub(super) const MAX_STORED_LOCKS: usize = 256;

/// Longest user name kept as a throttle key or audit context.
pub(super) const MAX_NAME_CHARS: usize = 128;

/// A user name as the throttle and the audit keep it: trimmed and cut at
/// [`MAX_NAME_CHARS`] characters.
pub(super) fn truncated(name: &str) -> String {
    name.trim().chars().take(MAX_NAME_CHARS).collect()
}

/// The answer to an attempt that must wait: whole seconds, rounded up, so a client that
/// waits as told does not arrive before the turn.
pub(super) fn throttled(retry: Retry) -> AuthError {
    AuthError::Throttled {
        retry_after: retry
            .after
            .map(|after| (after.as_secs() + u64::from(after.subsec_nanos() > 0)).max(1)),
    }
}

/// The text form of the client network of an address, the second part of a [`LOCKS`] key.
pub(super) fn network_text(source: Option<IpAddr>) -> String {
    source
        .map_or(UNKNOWN_SOURCE, crate::lockout::source_network)
        .to_string()
}

/// The derived default of `[auth] password_hash_memory_mib`: 64 MiB, the memory of one
/// computation at the Hardened parameters, for each processor the host reports, at least 2
/// and at most 8. A computation with one lane runs on one processor, so more at once only
/// waits for a processor while holding its memory.
pub fn default_hash_memory_mib() -> u32 {
    let processors = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 8);
    let processors = u32::try_from(processors).unwrap_or(8);
    processors * HashCost::of_strength(HashStrength::Hardened).mib()
}

/// Who a computation is for, as the gate sees it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Slot {
    /// The client network of an unauthenticated attempt: at most one computation of it at
    /// once. `None` for a computation an authenticated request or setup asks for.
    network: Option<IpAddr>,
    /// The attempt comes from a known network of the account, or is not a sign-in: it may
    /// use the share of the budget kept for those.
    known: bool,
}

impl Slot {
    /// A sign-in attempt from `source`.
    pub(super) fn sign_in(source: Option<IpAddr>, known: bool) -> Self {
        Self {
            network: Some(source.map_or(UNKNOWN_SOURCE, crate::lockout::source_network)),
            known,
        }
    }

    /// A computation for an authenticated request (a password change, a new password) or
    /// for setup, which a valid token already admitted.
    pub(super) const fn trusted() -> Self {
        Self {
            network: None,
            known: true,
        }
    }
}

/// The sign-in computations in flight per network; an entry leaves when its last
/// computation ends.
type InFlight = Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, u8>>>;

/// Sign-in computations one network may have in flight at once: two, so that two people
/// behind one address sign in together, while concurrent guesses gain little.
const PER_NETWORK: u8 = 2;

/// Removes a network from [`InFlight`] when dropped.
struct NetworkSlot {
    in_flight: InFlight,
    network: IpAddr,
}

impl Drop for NetworkSlot {
    fn drop(&mut self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = in_flight.get_mut(&self.network) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                in_flight.remove(&self.network);
            }
        }
    }
}

/// The bound on password hashing: a budget in MiB that the computations in flight share.
#[derive(Debug)]
pub(super) struct HashGate {
    permits: Arc<Semaphore>,
    budget_mib: u32,
    in_flight: InFlight,
}

impl HashGate {
    /// A gate with `budget_mib` MiB (at least 1).
    pub(super) fn new(budget_mib: u32) -> Self {
        let budget_mib = budget_mib.max(1);
        Self {
            permits: Arc::new(Semaphore::new(budget_mib as usize)),
            budget_mib,
            in_flight: InFlight::default(),
        }
    }

    /// The MiB an attempt from a network that is not known must leave free: a quarter of
    /// the budget, at most one computation at the Hardened parameters. A budget too small
    /// for the reserve beside a computation keeps none.
    fn reserve(&self) -> u32 {
        (self.budget_mib / 4).min(HashCost::of_strength(HashStrength::Hardened).mib())
    }

    /// The MiB `cost` takes from the budget: its memory, at least 1, at most the whole
    /// budget (a computation larger than the budget runs alone).
    fn share(&self, cost: HashCost) -> u32 {
        cost.mib().clamp(1, self.budget_mib)
    }

    /// The MiB not taken now.
    #[cfg(test)]
    fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Runs `task`, a computation of `cost`, on the blocking pool, holding its share of the
    /// budget until the computation ends (also when the request is dropped meanwhile).
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] at once when the budget is spent, or an internal error if
    /// the task panicked.
    pub(super) async fn run<T: Send + 'static>(
        &self,
        cost: HashCost,
        slot: Slot,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AuthError> {
        let busy = || {
            tracing::debug!("password hashing budget spent; attempt refused");
            AuthError::Throttled {
                retry_after: Some(1),
            }
        };
        let share = self.share(cost);
        // A network already computing waits for its result: concurrent attempts cannot
        // multiply its guesses or crowd out other networks.
        let network = match slot.network {
            Some(network) => {
                let mut in_flight = self
                    .in_flight
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let count = in_flight.entry(network).or_insert(0);
                if *count >= PER_NETWORK {
                    return Err(busy());
                }
                *count += 1;
                Some(NetworkSlot {
                    in_flight: Arc::clone(&self.in_flight),
                    network,
                })
            }
            None => None,
        };
        // A network that is not known leaves the reserve free, when the budget has room
        // for the reserve beside this computation at all.
        let reserve = self.reserve();
        if !slot.known
            && share + reserve <= self.budget_mib
            && self.permits.available_permits() < (share + reserve) as usize
        {
            return Err(busy());
        }
        let permit = Arc::clone(&self.permits)
            .try_acquire_many_owned(share)
            .map_err(|_| busy())?;
        tokio::task::spawn_blocking(move || {
            let result = task();
            drop(permit);
            drop(network);
            result
        })
        .await
        .map_err(|_| AuthError::internal("password hashing task failed"))
    }
}

/// How long the dummy verification took last, smoothed: what a verification of a weaker
/// stored hash is padded to, so a known name answers no faster than an unknown one.
#[derive(Debug, Default)]
pub(super) struct DummyTiming {
    nanos: AtomicU64,
}

impl DummyTiming {
    /// Adds a measured dummy verification: three quarters of the old value and a quarter of
    /// the new one, the first sample as it is.
    pub(super) fn record(&self, took: Duration) {
        let sample = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        // A lost update between two concurrent samples only skips one of them.
        let old = self.nanos.load(Ordering::Relaxed);
        let next = if old == 0 {
            sample
        } else {
            old / 4 * 3 + sample / 4
        };
        self.nanos.store(next, Ordering::Relaxed);
    }

    /// The smoothed duration, zero before the first sample.
    pub(super) fn get(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }
}

/// The networks from which each account completed a sign-in lately, in memory: the
/// account-wide delay does not apply to them.
#[derive(Debug, Default)]
pub(super) struct KnownNetworks {
    entries: std::sync::Mutex<std::collections::HashMap<(String, IpAddr), tenko_core::Timestamp>>,
}

impl KnownNetworks {
    /// Entries kept at most; at capacity the ended ones go first, then the oldest.
    const CAPACITY: usize = 100_000;
    /// How long a network stays known after a completed sign-in.
    const KEPT: Duration = Duration::from_secs(30 * 86_400);

    fn key(name: &str, source: Option<IpAddr>) -> (String, IpAddr) {
        (
            UserRecord::name_key(name),
            source.map_or(UNKNOWN_SOURCE, crate::lockout::source_network),
        )
    }

    /// Whether the account `name` completed a sign-in from the network of `source` within
    /// the last 30 days.
    pub(super) fn contains(
        &self,
        name: &str,
        source: Option<IpAddr>,
        now: tenko_core::Timestamp,
    ) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&Self::key(name, source))
            .is_some_and(|until| now < *until)
    }

    /// Notes a completed sign-in of `name` from the network of `source`.
    pub(super) fn note(&self, name: &str, source: Option<IpAddr>, now: tenko_core::Timestamp) {
        let until = now.checked_add(Self::KEPT).unwrap_or(now);
        let key = Self::key(name, source);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= Self::CAPACITY && !entries.contains_key(&key) {
            entries.retain(|_, until| now < *until);
            if entries.len() >= Self::CAPACITY
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, until);
    }

    /// Forgets every network of `name` (the account was deleted or renamed).
    pub(super) fn forget(&self, name: &str) {
        let name = UserRecord::name_key(name);
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(key, _), _| *key != name);
    }
}

/// One sign-in attempt as the lock sees it.
#[derive(Debug, Clone)]
pub(super) struct Attempt {
    /// The user name as typed, trimmed and cut (the keys lowercase it).
    pub(super) name: String,
    /// The client address.
    pub(super) source: Option<IpAddr>,
    /// The last-administrator guard covers the account.
    pub(super) guarded: bool,
    /// The account completed a sign-in from this network lately.
    pub(super) known: bool,
    /// The mark of a known device of the account that the request carries
    /// ([`AuthService::recognize_device`]).
    pub(super) device: Option<super::devices::DeviceUse>,
    /// The mode of TGL-07.
    pub(super) mode: LockoutMode,
    /// The numbers of TGL-07.
    pub(super) policy: LockPolicy,
}

impl Attempt {
    /// Whether the account-wide delay lets the attempt pass: it comes from a known network,
    /// or carries the mark of a known device.
    pub(super) fn exempt(&self) -> bool {
        self.known || self.device.is_some()
    }

    fn per_source_key(&self) -> ThrottleKey {
        ThrottleKey::account_source(&self.name, self.source)
    }

    fn account_key(&self) -> ThrottleKey {
        ThrottleKey::account(&self.name)
    }

    fn per_source(&self) -> LockoutPolicy {
        self.policy.per_source(self.mode)
    }

    fn lock_key(&self) -> (String, String) {
        (UserRecord::name_key(&self.name), network_text(self.source))
    }
}

impl AuthService {
    /// The attempt on the account named `name` (the record when it exists) from the client
    /// of `ctx`, under `settings`.
    pub(super) fn attempt(
        &self,
        name: &str,
        user: Option<&UserRecord>,
        ctx: &RequestCtx,
        settings: &SecuritySettings,
    ) -> Attempt {
        let image = self.index.image();
        Attempt {
            name: truncated(name),
            source: ctx.source_ip,
            guarded: user.is_some_and(|user| image.is_last_admin(user.id)),
            known: self.known_networks.contains(name, ctx.source_ip, ctx.now),
            device: None,
            mode: settings.lockout,
            policy: settings.lockout_policy(),
        }
    }

    /// The stored lock of `name` for the network of `source` that holds at `now`.
    pub(super) fn stored_lock(
        view: &dyn ReadView,
        name: &str,
        source: Option<IpAddr>,
        now: tenko_core::Timestamp,
    ) -> Result<Option<AccountLock>, AuthError> {
        let key = (UserRecord::name_key(name), network_text(source));
        Ok(view
            .get_typed(&LOCKS, &key)?
            .map(|(lock, _)| lock)
            .filter(|lock| now < lock.until))
    }

    /// Every stored lock of `name`, ended or not, with its key.
    pub(super) fn stored_locks(
        view: &dyn ReadView,
        name: &str,
    ) -> Result<Vec<(LockKey, AccountLock)>, AuthError> {
        let range = KeyRange::prefix(tenko_core::codec::encode_key(
            &(UserRecord::name_key(name),),
        ));
        Ok(view
            .scan_typed(&LOCKS, range, super::LIST_LIMIT, false)?
            .into_iter()
            .map(|(key, lock, _)| (key, lock))
            .collect())
    }

    /// The lock of `name` shown to administrators: the stored lock that ends last, or the
    /// lock of a record from before locks were per network.
    pub(super) fn shown_lock(
        view: &dyn ReadView,
        user: &UserRecord,
        now: tenko_core::Timestamp,
    ) -> Result<Option<AccountLock>, AuthError> {
        let stored = Self::stored_locks(view, &user.name)?
            .into_iter()
            .map(|(_, lock)| lock)
            .filter(|lock| now < lock.until)
            .max_by_key(|lock| lock.until);
        Ok(stored.or_else(|| user.legacy_lock(now)))
    }

    /// Checks an attempt before any credential is verified: the waits and the lock of the
    /// account from this network, the spraying delay of the network, the stored lock, and
    /// last the account-wide delay, whose turn an allowed attempt takes. The last
    /// administrator is held by the waits, the spraying delay and the account-wide delay,
    /// never by a lock.
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] with the time to wait.
    pub(super) fn check_attempt(
        &self,
        view: &dyn ReadView,
        attempt: &Attempt,
        now: tenko_core::Timestamp,
    ) -> Result<Option<crate::lockout::Turn>, AuthError> {
        if attempt.mode == LockoutMode::Off {
            return Ok(None);
        }
        let per_source = attempt.per_source();
        let key = attempt.per_source_key();
        if attempt.guarded {
            self.throttle.check_guarded(&key, &per_source, now)
        } else {
            self.throttle.check(&key, &per_source, now)
        }
        .map_err(throttled)?;
        if let Some(ip) = attempt.source {
            self.throttle
                .check(
                    &ThrottleKey::source(ip),
                    &LockoutPolicy::source_policy(),
                    now,
                )
                .map_err(throttled)?;
        }
        if !attempt.guarded
            && let Some(lock) = Self::stored_lock(view, &attempt.name, attempt.source, now)?
        {
            return Err(throttled(Retry {
                after: Some(lock.until.saturating_since(now)),
            }));
        }
        // The account-wide delay holds back every network the account has not completed a
        // sign-in from lately and every browser without a mark of the account, at the
        // password and at the second factor, for every account: limits per network do not
        // stop guesses from endlessly many networks. It never locks. It comes last, because
        // an allowed attempt takes its turn.
        if attempt.exempt() {
            return Ok(None);
        }
        self.throttle
            .admit(
                &attempt.account_key(),
                &attempt.policy.account_wide(attempt.mode),
                now,
            )
            .map_err(throttled)
    }

    /// Gives back the account-wide turn of an attempt that was refused before its
    /// credential was checked, or whose correct password opened a second factor (each code
    /// then takes a turn of its own).
    pub(super) fn give_back_turn(&self, attempt: &Attempt, turn: Option<crate::lockout::Turn>) {
        if let Some(turn) = turn {
            self.throttle.give_back(&attempt.account_key(), turn);
        }
    }

    /// Passes `result` on, giving the attempt's turn back first when the bound on password
    /// hashing refused the computation: nothing was checked.
    pub(super) fn turn_back_if_refused<T>(
        &self,
        attempt: &Attempt,
        turn: Option<crate::lockout::Turn>,
        result: Result<T, AuthError>,
    ) -> Result<T, AuthError> {
        if matches!(result, Err(AuthError::Throttled { .. })) {
            self.give_back_turn(attempt, turn);
        }
        result
    }

    /// Whether a passkey sign-in must respect the lock (the policy says so, as under
    /// Hardened) and the account is locked for this network.
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] while the lock holds.
    pub(super) fn check_passkey(
        &self,
        view: &dyn ReadView,
        attempt: &Attempt,
        now: tenko_core::Timestamp,
    ) -> Result<(), AuthError> {
        if attempt.mode == LockoutMode::Off || !attempt.policy.passkey_holds_lock || attempt.guarded
        {
            return Ok(());
        }
        if let Some(retry) = self.throttle.lock_of(&attempt.per_source_key(), now) {
            return Err(throttled(retry));
        }
        if let Some(lock) = Self::stored_lock(view, &attempt.name, attempt.source, now)? {
            return Err(throttled(Retry {
                after: Some(lock.until.saturating_since(now)),
            }));
        }
        Ok(())
    }

    /// The login completed from this network: its waits and lock in memory are forgotten,
    /// and the network becomes a known one of the account. The account-wide count stays
    /// until it decays, so a success during a distributed attack does not hand the attacker
    /// fresh attempts.
    pub(super) fn attempt_succeeded(&self, attempt: &Attempt, now: tenko_core::Timestamp) {
        self.throttle.record_success(&attempt.per_source_key());
        self.known_networks.note(&attempt.name, attempt.source, now);
    }

    /// Records a failed attempt: in memory first, then one audit record, the stored lock
    /// when one is reached, and the alarms. Always answers [`AuthError::InvalidCredentials`].
    pub(super) async fn login_failed(
        &self,
        ctx: &RequestCtx,
        attempt: &Attempt,
        user: Option<(&UserRecord, Revision)>,
        action: AuditAction,
    ) -> AuthError {
        let per_source = attempt.per_source();
        let key = attempt.per_source_key();
        let outcome = if attempt.guarded {
            self.throttle
                .record_failure_guarded(&key, &per_source, ctx.now)
        } else {
            self.throttle.record_failure(&key, &per_source, ctx.now)
        };
        let account_wide = (attempt.mode != LockoutMode::Off).then(|| {
            self.throttle.record_failure(
                &attempt.account_key(),
                &attempt.policy.account_wide(attempt.mode),
                ctx.now,
            )
        });
        if attempt.mode != LockoutMode::Off
            && let Some(ip) = attempt.source
        {
            self.throttle.record_failure(
                &ThrottleKey::source(ip),
                &LockoutPolicy::source_policy(),
                ctx.now,
            );
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), ctx.now);
        batch.request = Some(ctx.request);
        let objects = user
            .map(|(user, _)| vec![ObjectRef::from(user.id)])
            .unwrap_or_default();
        let mut draft = AuditDraft::failed(action, objects.clone(), &AuthError::InvalidCredentials)
            .with_source_ip(ctx.source_ip)
            .with_context("user_name", attempt.name.clone());
        // A failure with the mark of a known device counts on the mark; at its budget the
        // mark is spent.
        if attempt.mode != LockoutMode::Off
            && let Some(mark) = self.count_mark_failure(attempt, ctx.now).await
        {
            draft = draft.with_context("known_device", mark.as_str());
        }
        batch.audit(draft);
        if let Some(until) = outcome.locked_until {
            let first = match self.stage_lock(&mut batch, ctx, attempt, until).await {
                Ok(first) => first,
                Err(error) => {
                    tracing::error!(%error, "could not stage a sign-in lock");
                    false
                }
            };
            if let Some((user, _)) = user {
                batch.audit(
                    AuditDraft::success(actions::USER_LOCK, objects.clone())
                        .with_source_ip(ctx.source_ip)
                        .with_context("until", until.to_rfc3339())
                        .with_context("network", network_text(ctx.source_ip)),
                );
                // One alarm while the account holds a lock, not one per network.
                if outcome.alert
                    && first
                    && let Err(error) =
                        Self::stage_alarm(&mut batch, ctx, AlarmKind::AccountLocked, Some(user.id))
                {
                    tracing::error!(%error, "could not stage an alarm");
                }
            }
        }
        if let (Some(wide), Some((user, _))) = (account_wide, user)
            && attempt.policy.alarms_at(wide.failures)
            && let Err(error) =
                Self::stage_alarm(&mut batch, ctx, AlarmKind::SignInFailures, Some(user.id))
        {
            tracing::error!(%error, "could not stage an alarm");
        }
        if let Err(error) = self.store.propose(batch).await {
            tracing::warn!(%error, "could not record a failed login");
        }
        AuthError::InvalidCredentials
    }

    /// Adds the stored lock of the attempt to `batch`, and removes the ended locks of the
    /// same name, so the table holds no more than the locks that hold. A name holds at most
    /// [`MAX_STORED_LOCKS`] stored locks; beyond them a network's lock stays in the memory of
    /// the controller that reached it. Returns whether this is the only lock that holds for
    /// the name (the alarm is raised once, not per network).
    async fn stage_lock(
        &self,
        batch: &mut WriteBatch,
        ctx: &RequestCtx,
        attempt: &Attempt,
        until: tenko_core::Timestamp,
    ) -> Result<bool, AuthError> {
        let view = self.view().await?;
        let mut holding = 0;
        for (key, lock) in Self::stored_locks(view.as_ref(), &attempt.name)? {
            if lock.until <= ctx.now {
                batch.delete_typed(&LOCKS, &key);
            } else if key != attempt.lock_key() {
                holding += 1;
            }
        }
        if holding >= MAX_STORED_LOCKS {
            return Ok(false);
        }
        batch.put_typed(
            &LOCKS,
            &attempt.lock_key(),
            &AccountLock {
                since: ctx.now,
                until,
                until_unlock: attempt.mode == LockoutMode::LockUntilUnlock,
                network: Some(network_text(attempt.source)),
            },
        )?;
        Ok(holding == 0)
    }

    /// Runs a password computation of `cost` under the hashing bound.
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] when the bound is reached.
    pub(super) async fn hashing<T: Send + 'static>(
        &self,
        cost: HashCost,
        slot: Slot,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AuthError> {
        self.hash_gate.run(cost, slot, task).await
    }

    /// The cost of the dummy verification: the current profile's parameters or the
    /// strongest stored, whichever is more, component by component.
    pub(super) fn dummy_cost(&self, strength: HashStrength) -> HashCost {
        let current = HashCost::of_strength(strength);
        self.index
            .image()
            .strongest_password_cost()
            .map_or(current, |stored| stored.at_least(current))
            .for_dummy()
    }

    /// Runs the dummy verification of an unknown name and notes how long it took.
    ///
    /// # Errors
    ///
    /// [`AuthError::Throttled`] when the bound is reached.
    pub(super) async fn dummy_verification(
        &self,
        normalized: zeroize::Zeroizing<String>,
        strength: HashStrength,
        slot: Slot,
    ) -> Result<(), AuthError> {
        let cost = self.dummy_cost(strength);
        let started = Instant::now();
        self.hashing(cost, slot, move || {
            crate::password::hash::dummy_verify_at(&normalized, cost);
        })
        .await?;
        self.dummy_timing.record(started.elapsed());
        Ok(())
    }

    /// Waits until a verification that started at `started` with a stored hash of `cost` has
    /// taken as long as the dummy verification, when its hash is weaker than the dummy's.
    pub(super) async fn pad_to_dummy(
        &self,
        started: Instant,
        cost: Option<HashCost>,
        strength: HashStrength,
    ) {
        let dummy = self.dummy_cost(strength);
        if cost.is_some_and(|cost| cost.for_dummy() == dummy) {
            return;
        }
        let target = self.dummy_timing.get();
        let elapsed = started.elapsed();
        if target > elapsed {
            tokio::time::sleep(target.saturating_sub(elapsed)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cost(mib: u32) -> HashCost {
        HashCost {
            m_kib: mib * 1024,
            t: 1,
            p: 1,
        }
    }

    #[tokio::test]
    async fn a_spent_budget_refuses_at_once_and_frees_when_the_work_ends() {
        let gate = Arc::new(HashGate::new(100));
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let held = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                gate.run(cost(64), Slot::trusted(), move || {
                    let _ = wait.recv();
                })
                .await
            })
        };
        // Wait until the first computation holds its share.
        for _ in 0..1_000 {
            if gate.available() == 36 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(gate.available(), 36);
        let refused = gate.run(cost(64), Slot::trusted(), || ()).await;
        assert!(matches!(
            refused,
            Err(AuthError::Throttled {
                retry_after: Some(1)
            })
        ));
        // A smaller computation still fits.
        gate.run(cost(19), Slot::trusted(), || ())
            .await
            .expect("fits the rest");
        release.send(()).expect("the task waits");
        held.await.expect("joined").expect("ran");
        assert_eq!(gate.available(), 100);
        gate.run(cost(64), Slot::trusted(), || ())
            .await
            .expect("fits again");
    }

    #[tokio::test]
    async fn one_network_computes_once_at_a_time_and_unknown_networks_leave_a_reserve() {
        let gate = Arc::new(HashGate::new(256));
        let network: IpAddr = "2001:db8:1:2::1".parse().expect("ip");
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let held = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                gate.run(cost(19), Slot::sign_in(Some(network), false), move || {
                    let _ = wait.recv();
                })
                .await
            })
        };
        for _ in 0..1_000 {
            if gate.available() == 237 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(gate.available(), 237);
        // A second address of the same /64 computes beside it; a third waits.
        let same: IpAddr = "2001:db8:1:2::99".parse().expect("ip");
        let (release_second, wait_second) = std::sync::mpsc::channel::<()>();
        let second = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                gate.run(cost(19), Slot::sign_in(Some(same), false), move || {
                    let _ = wait_second.recv();
                })
                .await
            })
        };
        for _ in 0..1_000 {
            if gate.available() == 218 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(gate.available(), 218);
        assert!(matches!(
            gate.run(cost(19), Slot::sign_in(Some(same), false), || ())
                .await,
            Err(AuthError::Throttled { .. })
        ));
        release_second.send(()).expect("the task waits");
        second.await.expect("joined").expect("ran");
        // Another network computes.
        let other: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        gate.run(cost(19), Slot::sign_in(Some(other), false), || ())
            .await
            .expect("another network");
        release.send(()).expect("the task waits");
        held.await.expect("joined").expect("ran");
        gate.run(cost(19), Slot::sign_in(Some(same), false), || ())
            .await
            .expect("the network is free again");

        // An unknown network leaves 64 MiB (a quarter of 256) for known ones.
        let small = HashGate::new(256);
        let take = small
            .permits
            .clone()
            .try_acquire_many_owned(180)
            .expect("take most of the budget");
        assert!(matches!(
            small
                .run(cost(19), Slot::sign_in(Some(other), false), || ())
                .await,
            Err(AuthError::Throttled { .. })
        ));
        small
            .run(cost(19), Slot::sign_in(Some(other), true), || ())
            .await
            .expect("a known network uses the reserve");
        drop(take);
    }

    #[test]
    fn a_network_stays_known_for_thirty_days_and_is_forgotten_on_request() {
        let known = KnownNetworks::default();
        let at = |secs: i128| {
            tenko_core::Timestamp::from_unix_nanos(secs * 1_000_000_000).expect("in range")
        };
        let home: IpAddr = "192.0.2.10".parse().expect("ip");
        known.note("Alice", Some(home), at(1_000));
        assert!(known.contains("alice", Some(home), at(1_000)));
        assert!(!known.contains("alice", Some("192.0.2.11".parse().expect("ip")), at(1_000)));
        assert!(!known.contains("alice", Some(home), at(1_000 + 30 * 86_400)));
        known.forget("ALICE");
        assert!(!known.contains("alice", Some(home), at(1_001)));
    }

    #[test]
    fn a_computation_larger_than_the_budget_takes_all_of_it() {
        let gate = HashGate::new(32);
        assert_eq!(gate.share(cost(64)), 32);
        assert_eq!(
            gate.share(HashCost {
                m_kib: 1,
                t: 1,
                p: 1
            }),
            1
        );
        assert_eq!(HashGate::new(0).share(cost(1)), 1);
    }

    #[test]
    fn the_default_budget_follows_the_processors_and_the_hardened_memory() {
        let budget = default_hash_memory_mib();
        assert_eq!(budget % 64, 0);
        assert!((128..=512).contains(&budget), "{budget}");
    }

    #[test]
    fn the_dummy_timing_smooths_its_samples() {
        let timing = DummyTiming::default();
        assert_eq!(timing.get(), Duration::ZERO);
        timing.record(Duration::from_millis(100));
        assert_eq!(timing.get(), Duration::from_millis(100));
        timing.record(Duration::from_millis(20));
        assert_eq!(timing.get(), Duration::from_millis(80));
    }

    #[tokio::test]
    async fn the_dummy_follows_the_strongest_stored_hash() {
        use crate::{settings::Profile, testing::TestEnv};
        let hardened = HashCost::of_strength(HashStrength::Hardened);
        let baseline = HashCost::of_strength(HashStrength::Baseline);
        // An administrator hashed under Hardened: after a switch to a profile that hashes
        // at the baseline, an unknown name still costs what that account's hash costs.
        let (env, _) = TestEnv::installed(Profile::Hardened).await;
        assert_eq!(env.service.dummy_cost(HashStrength::Baseline), hardened);
        let (env, _) = TestEnv::installed(Profile::Standard).await;
        assert_eq!(env.service.dummy_cost(HashStrength::Baseline), baseline);
        assert_eq!(env.service.dummy_cost(HashStrength::Hardened), hardened);
        // A stored cost beyond what Tenko makes is capped for the dummy.
        let huge = HashCost {
            m_kib: u32::MAX,
            t: 100,
            p: 100,
        };
        assert_eq!(
            huge.for_dummy(),
            HashCost {
                m_kib: HashCost::MAX_DUMMY_KIB,
                t: HashCost::MAX_DUMMY_PASSES,
                p: HashCost::MAX_DUMMY_LANES,
            }
        );
    }

    #[test]
    fn networks_are_written_as_text() {
        assert_eq!(
            network_text(Some("192.0.2.7".parse().expect("ip"))),
            "192.0.2.7"
        );
        assert_eq!(
            network_text(Some("2001:db8:1:2:a:b:c:d".parse().expect("ip"))),
            "2001:db8:1:2::"
        );
        assert_eq!(network_text(None), "::");
    }
}
