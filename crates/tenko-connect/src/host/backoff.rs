//! Restart policy of a supervised plugin: exponential backoff with jitter and a circuit
//! breaker.
//!
//! [`Restarts`] is a pure state machine: the supervisor tells it what happened and when
//! (`now` is passed in, randomness too), and it answers when to start the plugin again.
//!
//! After a crash, a failed handshake or a missed health check, the next start is delayed by
//! `initial * factor^(attempt - 1)`, capped at `max` and reduced by a random share of up to
//! `jitter_permille` so that many instances do not restart in lockstep. The defaults are a
//! first delay of 1 s, a factor of 2, 20 percent jitter and a cap of 5 minutes. A plugin
//! that stays healthy for `reset_after` (60 s by default) is considered recovered and its
//! failure count starts over.
//!
//! The circuit breaker covers plugins that never recover: when `threshold` failures
//! (5 by default) fall within `window` (10 minutes), restarts stop for `open_for`
//! (15 minutes). After that, exactly one trial start is allowed (the circuit is half open):
//! if it fails the circuit opens again, and if it runs healthy for `reset_after` the circuit
//! closes and the history is forgotten.

use std::{collections::VecDeque, time::Duration};

use tokio::time::Instant;

/// How far ahead an instant is placed when the requested delay does not fit in an
/// [`Instant`] (about 30 years, the same horizon tokio uses for "never").
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// Exponential backoff between restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Delay before the first restart.
    pub initial: Duration,
    /// Upper bound of the delay.
    pub max: Duration,
    /// Factor applied per consecutive failure (at least 1).
    pub factor: u32,
    /// Randomized share of the delay in permille (0 to 1,000).
    pub jitter_permille: u16,
    /// A plugin that runs healthy this long has its failure count reset.
    pub reset_after: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(300),
            factor: 2,
            jitter_permille: 200,
            reset_after: Duration::from_secs(60),
        }
    }
}

impl BackoffPolicy {
    /// The delay before restart number `attempt` (from 1), with `random` choosing the
    /// jitter.
    ///
    /// The base delay is `initial * factor^(attempt - 1)`, computed in milliseconds
    /// without overflow and capped at `max`. The jitter takes away up to
    /// `jitter_permille` of the base, so the result lies in `[base - jitter, base]` and
    /// is a pure function of the arguments. An `attempt` of 0 counts as 1, a `factor` of 0
    /// as 1, and a `jitter_permille` above 1,000 as 1,000.
    pub fn delay(&self, attempt: u32, random: u64) -> Duration {
        let exponent = attempt.max(1) - 1;
        let factor = u128::from(self.factor.max(1));
        let base = self
            .initial
            .as_millis()
            .saturating_mul(factor.saturating_pow(exponent))
            .min(self.max.as_millis());
        let jitter = base.saturating_mul(u128::from(self.jitter_permille.min(1000))) / 1000;
        let offset = u128::from(random) % (jitter + 1);
        millis_to_duration(base - jitter + offset)
    }
}

/// The circuit breaker: too many failures in a window stop restarts for a while.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitPolicy {
    /// Failures within `window` that open the circuit (0 disables the breaker).
    pub threshold: u32,
    /// The window failures are counted in.
    pub window: Duration,
    /// How long an open circuit stays open before one trial start.
    pub open_for: Duration,
}

impl Default for CircuitPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(600),
            open_for: Duration::from_secs(900),
        }
    }
}

/// The state of the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Restarts follow the backoff.
    Closed,
    /// No restarts until the instant.
    Open {
        /// When one trial start is allowed.
        until: Instant,
    },
    /// One trial start is running or allowed.
    HalfOpen,
}

/// What to do after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Start again at the instant.
    RetryAt {
        /// When.
        at: Instant,
        /// The restart number, from 1.
        attempt: u32,
    },
    /// The circuit opened: no start before the instant.
    OpenUntil(Instant),
}

/// The restart state machine of one plugin instance.
#[derive(Debug, Clone)]
pub struct Restarts {
    backoff: BackoffPolicy,
    circuit: CircuitPolicy,
    /// Failure instants inside the window, oldest first, at most `threshold` of them (the
    /// most recent ones are all the breaker needs).
    failures: VecDeque<Instant>,
    consecutive: u32,
    running_since: Option<Instant>,
    state: CircuitState,
}

impl Restarts {
    /// A machine with the given policies, closed and without failures.
    pub fn new(backoff: BackoffPolicy, circuit: CircuitPolicy) -> Self {
        Self {
            backoff,
            circuit,
            failures: VecDeque::new(),
            consecutive: 0,
            running_since: None,
            state: CircuitState::Closed,
        }
    }

    /// The plugin completed its handshake and runs: `now` is the start of the healthy run.
    pub fn on_started(&mut self, now: Instant) {
        self.running_since = Some(now);
    }

    /// The plugin crashed, failed its handshake or stopped answering.
    ///
    /// The run ends and the failure is recorded; failures older than the window are
    /// forgotten. The answer is one of:
    ///
    /// - [`Decision::OpenUntil`] when the circuit was half open (the trial start failed),
    ///   or when the failures within the window reach the threshold. The circuit is then
    ///   open for `open_for` from `now`. A failure reported while the circuit is still open
    ///   keeps the existing deadline.
    /// - [`Decision::RetryAt`] otherwise, after the backoff delay for the number of
    ///   consecutive failures.
    pub fn on_failure(&mut self, now: Instant, random: u64) -> Decision {
        self.running_since = None;
        self.record_failure(now);
        self.consecutive = self.consecutive.saturating_add(1);

        match self.state(now) {
            CircuitState::Open { until } => return Decision::OpenUntil(until),
            CircuitState::HalfOpen => return self.open(now),
            CircuitState::Closed => {}
        }

        let threshold = self.threshold();
        if threshold > 0 && self.failures.len() >= threshold {
            return self.open(now);
        }

        Decision::RetryAt {
            at: add_saturating(now, self.backoff.delay(self.consecutive, random)),
            attempt: self.consecutive,
        }
    }

    /// The plugin answered its health check.
    ///
    /// When the current run has lasted at least `reset_after`, the plugin counts as
    /// recovered: the consecutive failures and the failure window are forgotten, and a
    /// half-open circuit closes.
    pub fn on_healthy(&mut self, now: Instant) {
        let Some(started) = self.running_since else {
            return;
        };
        if now.saturating_duration_since(started) < self.backoff.reset_after {
            return;
        }
        self.consecutive = 0;
        self.failures.clear();
        if self.state(now) == CircuitState::HalfOpen {
            self.state = CircuitState::Closed;
        }
    }

    /// Whether the plugin may be started at `now`.
    ///
    /// A closed or half-open circuit allows it. An open circuit allows it once its deadline
    /// has passed, and becomes half open for that one trial start. Otherwise the error
    /// carries the instant at which the next start is allowed.
    ///
    /// # Errors
    ///
    /// The deadline of the open circuit when `now` is before it.
    pub fn may_start(&mut self, now: Instant) -> Result<(), Instant> {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open { until } if now >= until => {
                self.state = CircuitState::HalfOpen;
                Ok(())
            }
            CircuitState::Open { until } => Err(until),
        }
    }

    /// The state of the circuit at `now`: an open circuit whose deadline has passed reads
    /// as half open (the stored state changes with [`Restarts::may_start`]).
    pub fn state(&self, now: Instant) -> CircuitState {
        match self.state {
            CircuitState::Open { until } if now >= until => CircuitState::HalfOpen,
            state => state,
        }
    }

    /// Failures since the last reset.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive
    }

    /// Forgets every failure and closes the circuit (an operator re-enabled the instance).
    pub fn reset(&mut self) {
        self.failures.clear();
        self.consecutive = 0;
        self.running_since = None;
        self.state = CircuitState::Closed;
    }

    /// The threshold as a count of entries.
    fn threshold(&self) -> usize {
        usize::try_from(self.circuit.threshold).unwrap_or(usize::MAX)
    }

    /// Adds a failure to the window and drops what the breaker no longer needs: failures
    /// strictly older than `now - window`, and all but the latest `threshold` entries.
    fn record_failure(&mut self, now: Instant) {
        self.failures.push_back(now);
        while self
            .failures
            .front()
            .is_some_and(|&at| now.saturating_duration_since(at) > self.circuit.window)
        {
            self.failures.pop_front();
        }
        let keep = self.threshold();
        while self.failures.len() > keep {
            self.failures.pop_front();
        }
    }

    /// Opens the circuit for `open_for` from `now`.
    fn open(&mut self, now: Instant) -> Decision {
        let until = add_saturating(now, self.circuit.open_for);
        self.state = CircuitState::Open { until };
        Decision::OpenUntil(until)
    }
}

/// A duration from whole milliseconds, saturating at [`Duration::MAX`].
fn millis_to_duration(millis: u128) -> Duration {
    let Ok(secs) = u64::try_from(millis / 1000) else {
        return Duration::MAX;
    };
    let nanos = u32::try_from((millis % 1000) * 1_000_000).unwrap_or(0);
    Duration::new(secs, nanos)
}

/// `now + delay` without the overflow panic of `Instant + Duration`: a delay that does not
/// fit lands about 30 years ahead.
fn add_saturating(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay)
        .or_else(|| now.checked_add(FAR_FUTURE))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    const fn millis(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The default policy without jitter, so that delays are exact.
    fn plain() -> BackoffPolicy {
        BackoffPolicy {
            jitter_permille: 0,
            ..BackoffPolicy::default()
        }
    }

    /// A machine with the default backoff (no jitter) and a breaker of `threshold`
    /// failures in 100 seconds, open for 900 seconds.
    fn machine(threshold: u32) -> Restarts {
        Restarts::new(
            plain(),
            CircuitPolicy {
                threshold,
                window: secs(100),
                open_for: secs(900),
            },
        )
    }

    /// A deterministic pseudo-random sequence (splitmix64).
    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The deadline of a failure that must open the circuit.
    fn opened(decision: Decision) -> Instant {
        match decision {
            Decision::OpenUntil(until) => until,
            other @ Decision::RetryAt { .. } => panic!("the circuit should open, got {other:?}"),
        }
    }

    #[test]
    fn defaults_match_the_documented_policy() {
        let backoff = BackoffPolicy::default();
        assert_eq!(backoff.initial, secs(1));
        assert_eq!(backoff.factor, 2);
        assert_eq!(backoff.jitter_permille, 200);
        assert_eq!(backoff.max, secs(300));
        assert_eq!(backoff.reset_after, secs(60));
        let circuit = CircuitPolicy::default();
        assert_eq!(circuit.threshold, 5);
        assert_eq!(circuit.window, secs(600));
        assert_eq!(circuit.open_for, secs(900));
    }

    #[test]
    fn delay_grows_exponentially_and_stops_at_the_cap() {
        let policy = plain();
        let expected = [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300];
        for (index, want) in expected.into_iter().enumerate() {
            let attempt = u32::try_from(index + 1).unwrap();
            assert_eq!(policy.delay(attempt, 0), secs(want), "attempt {attempt}");
        }
    }

    #[test]
    fn delay_does_not_overflow() {
        let policy = BackoffPolicy {
            factor: u32::MAX,
            ..plain()
        };
        assert_eq!(policy.delay(u32::MAX, 7), policy.max);
        assert_eq!(policy.delay(200, 7), policy.max);

        let huge = BackoffPolicy {
            max: Duration::MAX,
            jitter_permille: 1000,
            ..plain()
        };
        let delay = huge.delay(u32::MAX, u64::MAX);
        assert!(delay > secs(300));
    }

    #[test]
    fn delay_honours_initial_above_max_and_zero_initial() {
        let capped = BackoffPolicy {
            initial: secs(500),
            ..plain()
        };
        assert_eq!(capped.delay(1, 0), secs(300));
        let zero = BackoffPolicy {
            initial: Duration::ZERO,
            ..BackoffPolicy::default()
        };
        assert_eq!(zero.delay(5, 12345), Duration::ZERO);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let policy = BackoffPolicy::default();
        // Attempt 3: base 4,000 ms, jitter 800 ms.
        let (low, high) = (millis(3200), millis(4000));
        let mut state = 1;
        for _ in 0..10_000 {
            let delay = policy.delay(3, splitmix(&mut state));
            assert!((low..=high).contains(&delay), "{delay:?}");
        }
        for random in 0..2000 {
            let delay = policy.delay(3, random);
            assert!((low..=high).contains(&delay), "{delay:?}");
        }
        assert!((low..=high).contains(&policy.delay(3, u64::MAX)));
    }

    #[test]
    fn jitter_covers_the_whole_range() {
        let policy = BackoffPolicy::default();
        assert_eq!(policy.delay(3, 0), millis(3200));
        assert_eq!(policy.delay(3, 800), millis(4000));
        assert_eq!(policy.delay(3, 801), millis(3200));
        assert_eq!(policy.delay(3, 400), millis(3600));
    }

    #[test]
    fn jitter_is_deterministic() {
        let policy = BackoffPolicy::default();
        for random in [0, 1, 799, 123_456_789, u64::MAX] {
            assert_eq!(policy.delay(4, random), policy.delay(4, random));
        }
    }

    #[test]
    fn jitter_above_a_thousand_permille_is_clamped() {
        let policy = BackoffPolicy {
            jitter_permille: u16::MAX,
            ..plain()
        };
        let mut state = 7;
        for _ in 0..1000 {
            assert!(policy.delay(2, splitmix(&mut state)) <= secs(2));
        }
        assert_eq!(policy.delay(2, 0), Duration::ZERO);
        assert_eq!(policy.delay(2, 2000), secs(2));
    }

    #[test]
    fn attempt_zero_counts_as_one() {
        let policy = plain();
        assert_eq!(policy.delay(0, 0), policy.delay(1, 0));
        assert_eq!(policy.delay(0, 0), secs(1));
    }

    #[test]
    fn factor_zero_counts_as_one() {
        let policy = BackoffPolicy {
            factor: 0,
            ..plain()
        };
        for attempt in [0, 1, 2, 10, u32::MAX] {
            assert_eq!(policy.delay(attempt, 0), secs(1), "attempt {attempt}");
        }
    }

    #[test]
    fn failures_back_off_exponentially() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        for (index, want) in [1_u64, 2, 4, 8].into_iter().enumerate() {
            let attempt = u32::try_from(index + 1).unwrap();
            let now = t0 + secs(50 * u64::from(attempt));
            assert_eq!(
                restarts.on_failure(now, 0),
                Decision::RetryAt {
                    at: now + secs(want),
                    attempt,
                }
            );
        }
        assert_eq!(restarts.consecutive_failures(), 4);
    }

    #[test]
    fn retry_time_uses_the_random_value() {
        let mut restarts = Restarts::new(BackoffPolicy::default(), CircuitPolicy::default());
        let t0 = Instant::now();
        let expected = BackoffPolicy::default().delay(1, 123);
        assert_ne!(expected, secs(1));
        assert_eq!(
            restarts.on_failure(t0, 123),
            Decision::RetryAt {
                at: t0 + expected,
                attempt: 1,
            }
        );
    }

    #[test]
    fn a_long_healthy_run_resets_the_failure_count() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        for _ in 0..3 {
            restarts.on_failure(t0, 0);
        }
        assert_eq!(restarts.consecutive_failures(), 3);

        restarts.on_started(t0 + secs(10));
        restarts.on_healthy(t0 + secs(69) + millis(999));
        assert_eq!(restarts.consecutive_failures(), 3);
        restarts.on_healthy(t0 + secs(70));
        assert_eq!(restarts.consecutive_failures(), 0);

        assert_eq!(
            restarts.on_failure(t0 + secs(80), 0),
            Decision::RetryAt {
                at: t0 + secs(81),
                attempt: 1,
            }
        );
    }

    #[test]
    fn a_short_healthy_run_does_not_reset() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        restarts.on_failure(t0 + secs(5), 0);
        restarts.on_started(t0 + secs(10));
        restarts.on_healthy(t0 + secs(20));
        restarts.on_healthy(t0 + secs(40));
        assert_eq!(restarts.consecutive_failures(), 2);
        assert_eq!(
            restarts.on_failure(t0 + secs(45), 0),
            Decision::RetryAt {
                at: t0 + secs(45) + secs(4),
                attempt: 3,
            }
        );
    }

    #[test]
    fn a_health_check_without_a_started_run_changes_nothing() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        restarts.on_healthy(t0 + secs(1000));
        assert_eq!(restarts.consecutive_failures(), 1);
    }

    #[test]
    fn a_failure_ends_the_healthy_run() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        restarts.on_started(t0);
        restarts.on_failure(t0 + secs(5), 0);
        restarts.on_healthy(t0 + secs(500));
        assert_eq!(restarts.consecutive_failures(), 1);
    }

    #[test]
    fn the_circuit_opens_at_the_threshold_within_the_window() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        assert!(matches!(
            restarts.on_failure(t0, 0),
            Decision::RetryAt { attempt: 1, .. }
        ));
        assert!(matches!(
            restarts.on_failure(t0 + secs(10), 0),
            Decision::RetryAt { attempt: 2, .. }
        ));
        assert_eq!(restarts.state(t0 + secs(10)), CircuitState::Closed);

        let now = t0 + secs(20);
        let until = now + secs(900);
        assert_eq!(restarts.on_failure(now, 0), Decision::OpenUntil(until));
        assert_eq!(restarts.state(now), CircuitState::Open { until });
        assert_eq!(restarts.consecutive_failures(), 3);
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        restarts.on_failure(t0 + secs(50), 0);
        // The first failure is 101 s old: strictly older than the 100 s window.
        let decision = restarts.on_failure(t0 + secs(101), 0);
        assert!(matches!(decision, Decision::RetryAt { attempt: 3, .. }));
        assert_eq!(restarts.state(t0 + secs(101)), CircuitState::Closed);
        // Two failures remain in the window, so one more opens the circuit.
        assert!(matches!(
            restarts.on_failure(t0 + secs(102), 0),
            Decision::OpenUntil(_)
        ));
    }

    #[test]
    fn a_failure_exactly_one_window_old_still_counts() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        restarts.on_failure(t0 + secs(50), 0);
        assert!(matches!(
            restarts.on_failure(t0 + secs(100), 0),
            Decision::OpenUntil(_)
        ));
    }

    #[test]
    fn slow_failures_never_open_the_circuit() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        for index in 0..20 {
            let decision = restarts.on_failure(t0 + secs(index * 60), 0);
            assert!(
                matches!(decision, Decision::RetryAt { .. }),
                "failure {index}"
            );
        }
        assert_eq!(restarts.state(t0 + secs(2000)), CircuitState::Closed);
    }

    #[test]
    fn may_start_waits_for_the_open_period() {
        let mut restarts = machine(1);
        let t0 = Instant::now();
        let until = opened(restarts.on_failure(t0, 0));
        assert_eq!(until, t0 + secs(900));

        let just_before = until - Duration::from_nanos(1);
        assert_eq!(restarts.may_start(t0), Err(until));
        assert_eq!(restarts.may_start(just_before), Err(until));
        assert_eq!(restarts.state(just_before), CircuitState::Open { until });

        assert_eq!(restarts.may_start(until), Ok(()));
        assert_eq!(restarts.state(t0), CircuitState::HalfOpen);
        // Further calls keep allowing the trial start.
        assert_eq!(restarts.may_start(until + secs(1)), Ok(()));
    }

    #[test]
    fn state_reads_half_open_after_the_deadline_without_mutating() {
        let mut restarts = machine(1);
        let t0 = Instant::now();
        let until = opened(restarts.on_failure(t0, 0));
        assert_eq!(restarts.state(until), CircuitState::HalfOpen);
        assert_eq!(restarts.state(until + secs(60)), CircuitState::HalfOpen);
        // The stored state is untouched: an earlier instant still reads as open.
        assert_eq!(restarts.state(t0 + secs(1)), CircuitState::Open { until });
        assert_eq!(restarts.may_start(t0 + secs(1)), Err(until));
    }

    #[test]
    fn a_closed_circuit_always_allows_a_start() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        assert_eq!(restarts.may_start(t0), Ok(()));
        restarts.on_failure(t0, 0);
        assert_eq!(restarts.may_start(t0), Ok(()));
        assert_eq!(restarts.state(t0), CircuitState::Closed);
    }

    #[test]
    fn a_failed_trial_start_opens_the_circuit_again() {
        // Two failures open the circuit; by the trial the window has forgotten them, so
        // only the half-open state can explain the new opening.
        let mut restarts = machine(2);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        let until = opened(restarts.on_failure(t0 + secs(1), 0));
        assert_eq!(restarts.may_start(until), Ok(()));
        restarts.on_started(until);

        let failed_at = until + secs(2);
        let reopened = failed_at + secs(900);
        assert_eq!(
            restarts.on_failure(failed_at, 0),
            Decision::OpenUntil(reopened)
        );
        assert_eq!(
            restarts.state(failed_at),
            CircuitState::Open { until: reopened }
        );
        assert_eq!(restarts.may_start(failed_at), Err(reopened));
        assert_eq!(restarts.may_start(reopened), Ok(()));
        assert_eq!(restarts.state(reopened), CircuitState::HalfOpen);
    }

    #[test]
    fn a_failure_after_the_deadline_without_may_start_counts_as_a_failed_trial() {
        let mut restarts = machine(2);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        let until = opened(restarts.on_failure(t0 + secs(1), 0));
        let failed_at = until + secs(5);
        assert_eq!(
            restarts.on_failure(failed_at, 0),
            Decision::OpenUntil(failed_at + secs(900))
        );
    }

    #[test]
    fn a_failure_while_open_keeps_the_deadline() {
        let mut restarts = machine(1);
        let t0 = Instant::now();
        let until = opened(restarts.on_failure(t0, 0));
        assert_eq!(
            restarts.on_failure(t0 + secs(30), 0),
            Decision::OpenUntil(until)
        );
        assert_eq!(restarts.state(t0 + secs(30)), CircuitState::Open { until });
    }

    #[test]
    fn a_healthy_trial_closes_the_circuit_after_the_reset_period() {
        let mut restarts = machine(2);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        let until = opened(restarts.on_failure(t0 + secs(1), 0));
        assert_eq!(restarts.may_start(until), Ok(()));
        restarts.on_started(until);

        restarts.on_healthy(until + secs(30));
        assert_eq!(restarts.state(until + secs(30)), CircuitState::HalfOpen);
        assert_eq!(restarts.consecutive_failures(), 2);

        restarts.on_healthy(until + secs(60));
        assert_eq!(restarts.state(until + secs(60)), CircuitState::Closed);
        assert_eq!(restarts.consecutive_failures(), 0);
        assert_eq!(restarts.may_start(until + secs(60)), Ok(()));

        // The history is gone: one failure retries, and it is the first attempt.
        assert!(matches!(
            restarts.on_failure(until + secs(70), 0),
            Decision::RetryAt { attempt: 1, .. }
        ));
    }

    #[test]
    fn a_healthy_trial_closes_the_circuit_without_may_start() {
        let mut restarts = machine(1);
        let t0 = Instant::now();
        let until = opened(restarts.on_failure(t0, 0));
        // The supervisor skipped may_start; the stored state is still Open but expired.
        restarts.on_started(until);
        restarts.on_healthy(until + secs(60));
        assert_eq!(restarts.state(until + secs(60)), CircuitState::Closed);
        assert_eq!(restarts.may_start(until + secs(60)), Ok(()));
    }

    #[test]
    fn health_checks_do_not_close_an_open_circuit_early() {
        let mut restarts = machine(1);
        let t0 = Instant::now();
        let until = opened(restarts.on_failure(t0, 0));
        restarts.on_started(t0);
        restarts.on_healthy(t0 + secs(100));
        assert_eq!(restarts.state(t0 + secs(100)), CircuitState::Open { until });
    }

    #[test]
    fn a_threshold_of_zero_disables_the_breaker() {
        let mut restarts = machine(0);
        let t0 = Instant::now();
        for index in 1..=100 {
            let decision = restarts.on_failure(t0, 0);
            assert!(
                matches!(decision, Decision::RetryAt { attempt, .. } if attempt == index),
                "failure {index}"
            );
            assert_eq!(restarts.state(t0), CircuitState::Closed);
            assert_eq!(restarts.may_start(t0), Ok(()));
        }
        assert_eq!(restarts.consecutive_failures(), 100);
    }

    #[test]
    fn reset_closes_the_circuit_and_forgets_everything() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        restarts.on_failure(t0, 0);
        restarts.on_failure(t0 + secs(1), 0);
        let until = opened(restarts.on_failure(t0 + secs(2), 0));
        assert_eq!(restarts.may_start(t0 + secs(3)), Err(until));

        restarts.on_started(t0 + secs(3));
        restarts.reset();
        assert_eq!(restarts.consecutive_failures(), 0);
        assert_eq!(restarts.state(t0 + secs(3)), CircuitState::Closed);
        assert_eq!(restarts.may_start(t0 + secs(3)), Ok(()));

        // The old failures are forgotten: two more do not open the circuit.
        assert!(matches!(
            restarts.on_failure(t0 + secs(4), 0),
            Decision::RetryAt { attempt: 1, .. }
        ));
        assert!(matches!(
            restarts.on_failure(t0 + secs(5), 0),
            Decision::RetryAt { attempt: 2, .. }
        ));
        // And the interrupted run no longer counts as healthy.
        restarts.on_healthy(t0 + secs(500));
        assert_eq!(restarts.consecutive_failures(), 2);
    }

    #[test]
    fn huge_policy_values_do_not_panic() {
        let mut restarts = Restarts::new(
            BackoffPolicy {
                initial: Duration::MAX,
                max: Duration::MAX,
                ..BackoffPolicy::default()
            },
            CircuitPolicy {
                threshold: 2,
                window: Duration::MAX,
                open_for: Duration::MAX,
            },
        );
        let t0 = Instant::now();
        let Decision::RetryAt { at, attempt: 1 } = restarts.on_failure(t0, 0) else {
            panic!("the first failure should retry");
        };
        assert!(at >= t0);
        let until = opened(restarts.on_failure(t0, 0));
        assert!(until > t0 + secs(86_400 * 365));
    }

    #[test]
    fn the_failure_log_stays_bounded() {
        let mut restarts = machine(3);
        let t0 = Instant::now();
        for index in 0..1000 {
            restarts.on_failure(t0 + millis(index), 0);
        }
        assert!(restarts.failures.len() <= 3);
        let mut disabled = machine(0);
        for index in 0..1000 {
            disabled.on_failure(t0 + millis(index), 0);
        }
        assert!(disabled.failures.is_empty());
    }
}
