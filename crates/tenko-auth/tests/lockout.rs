//! Integration tests of the progressive lockout (IAM-05, TGL-07). Time is driven by a mock
//! clock, so nothing sleeps.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tenko_auth::{
    clock::{Clock, MockClock},
    lockout::{FailureOutcome, LockoutMode, LockoutPolicy, Retry, Throttle, ThrottleKey},
};
use tenko_core::Timestamp;
use utoipa::PartialSchema;

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

const fn mins(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

fn plus(at: Timestamp, by: Duration) -> Timestamp {
    at.checked_add(by).expect("within the supported range")
}

fn minus(at: Timestamp, by: Duration) -> Timestamp {
    let nanos = i128::try_from(by.as_nanos()).expect("small duration");
    Timestamp::from_unix_nanos(at.unix_nanos() - nanos).expect("within the supported range")
}

fn account(name: &str) -> ThrottleKey {
    ThrottleKey::account(name)
}

fn policy(mode: LockoutMode) -> LockoutPolicy {
    LockoutPolicy::for_mode(mode)
}

/// One failed attempt the way the service makes it: check first, wait out a delay, then
/// record the failure.
fn attempt(
    throttle: &Throttle,
    key: &ThrottleKey,
    policy: &LockoutPolicy,
    clock: &MockClock,
) -> FailureOutcome {
    if let Err(Retry { after: Some(wait) }) = throttle.check(key, policy, clock.now()) {
        clock.advance(wait);
    }
    assert_eq!(
        throttle.check(key, policy, clock.now()),
        Ok(()),
        "the attempt is allowed once the delay has passed"
    );
    throttle.record_failure(key, policy, clock.now())
}

/// `n` failures at the same instant, ignoring delays. Returns the last outcome.
fn fail_at(
    throttle: &Throttle,
    key: &ThrottleKey,
    policy: &LockoutPolicy,
    now: Timestamp,
    n: u32,
) -> FailureOutcome {
    let mut last = None;
    for _ in 0..n {
        last = Some(throttle.record_failure(key, policy, now));
    }
    last.expect("at least one failure")
}

/// The delays reported by `failures` consecutive failures that wait out every delay. Also
/// checks that `check` refuses for exactly the reported delay.
fn run_schedule(mode: LockoutMode, failures: u32) -> Vec<u64> {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(mode);
    let key = account("alice");
    (1..=failures)
        .map(|n| {
            let outcome = attempt(&throttle, &key, &policy, &clock);
            assert_eq!(outcome.failures, n);
            assert_eq!(outcome.locked_until, None, "failure {n} does not lock");
            assert!(!outcome.alert);
            let verdict = throttle.check(&key, &policy, clock.now());
            if outcome.delay.is_zero() {
                assert_eq!(verdict, Ok(()), "failure {n} has no delay");
            } else {
                assert_eq!(
                    verdict,
                    Err(Retry {
                        after: Some(outcome.delay)
                    })
                );
            }
            outcome.delay.as_secs()
        })
        .collect()
}

/// A policy that holds every key for an hour after its last failure and remembers it for a
/// day, so a refusal from `check` shows that the key is still tracked.
fn long_hold() -> LockoutPolicy {
    LockoutPolicy {
        mode: LockoutMode::ProgressiveDelay,
        free_attempts: 0,
        base_delay: mins(60),
        max_delay: mins(60),
        lock_after: 0,
        lock_duration: Duration::ZERO,
        reset_after: mins(24 * 60),
    }
}

/// Like [`long_hold`], and the second failure locks for half an hour.
fn long_hold_locking() -> LockoutPolicy {
    LockoutPolicy {
        mode: LockoutMode::DelayThenTemporaryLock,
        lock_after: 2,
        lock_duration: mins(30),
        ..long_hold()
    }
}

fn held(throttle: &Throttle, key: &ThrottleKey, policy: &LockoutPolicy, now: Timestamp) -> bool {
    throttle.check(key, policy, now).is_err()
}

#[test]
fn presets_match_the_documented_values() {
    let home = policy(LockoutMode::ProgressiveDelay);
    assert_eq!(home.free_attempts, 5);
    assert_eq!(home.base_delay, secs(1));
    assert_eq!(home.max_delay, secs(60));
    assert_eq!(home.reset_after, mins(15));

    let standard = policy(LockoutMode::DelayThenTemporaryLock);
    assert_eq!(standard.free_attempts, 5);
    assert_eq!(standard.base_delay, secs(1));
    assert_eq!(standard.max_delay, secs(60));
    assert_eq!(standard.lock_after, 10);
    assert_eq!(standard.lock_duration, mins(15));
    assert_eq!(standard.reset_after, mins(60));

    let hardened = policy(LockoutMode::LockUntilUnlock);
    assert_eq!(hardened.free_attempts, 3);
    assert_eq!(hardened.base_delay, secs(2));
    assert_eq!(hardened.max_delay, secs(60));
    assert_eq!(hardened.lock_after, 5);
    assert_eq!(hardened.lock_duration, mins(30));
    assert_eq!(hardened.reset_after, mins(24 * 60));

    let lab = policy(LockoutMode::Off);
    assert_eq!(lab.mode, LockoutMode::Off);
    assert_eq!(lab.delay_after(u32::MAX), Duration::ZERO);

    let source = LockoutPolicy::source_policy();
    assert_eq!(source.free_attempts, 20);
    assert_eq!(source.base_delay, secs(1));
    assert_eq!(source.max_delay, secs(30));
    assert_eq!(source.reset_after, mins(15));
    assert_eq!(
        source.mode,
        LockoutMode::ProgressiveDelay,
        "the source policy never locks"
    );
}

#[test]
fn mode_names_round_trip_through_serde() {
    let modes = [
        LockoutMode::Off,
        LockoutMode::ProgressiveDelay,
        LockoutMode::DelayThenTemporaryLock,
        LockoutMode::LockUntilUnlock,
    ];
    for mode in modes {
        let json = serde_json::to_string(&mode).expect("serializes");
        assert_eq!(json, format!("\"{}\"", mode.as_str()));
        assert_eq!(
            serde_json::from_str::<LockoutMode>(&json).expect("parses"),
            mode
        );
    }
    assert!(serde_json::from_str::<LockoutMode>("\"progressive\"").is_err());
}

#[test]
fn mode_has_an_openapi_schema_listing_its_values() {
    let schema = serde_json::to_string(&LockoutMode::schema()).expect("serializes");
    for name in [
        "off",
        "progressive_delay",
        "delay_then_temporary_lock",
        "lock_until_unlock",
    ] {
        assert!(schema.contains(name), "{name} is in {schema}");
    }
}

#[test]
fn delay_schedule_progressive_delay() {
    // Failures 1..=5 are free, then 1 s doubling up to the 60 s cap.
    assert_eq!(
        run_schedule(LockoutMode::ProgressiveDelay, 18),
        [
            0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60, 60
        ]
    );
}

#[test]
fn delay_schedule_delay_then_temporary_lock() {
    // The tenth failure locks, so only nine delays exist.
    assert_eq!(
        run_schedule(LockoutMode::DelayThenTemporaryLock, 9),
        [0, 0, 0, 0, 0, 1, 2, 4, 8]
    );
}

#[test]
fn delay_schedule_lock_until_unlock() {
    // The fifth failure locks, so only four delays exist.
    assert_eq!(run_schedule(LockoutMode::LockUntilUnlock, 4), [0, 0, 0, 2]);
}

#[test]
fn delay_schedule_of_the_source_policy() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = LockoutPolicy::source_policy();
    let key = ThrottleKey::source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let delays: Vec<u64> = (1..=28)
        .map(|_| attempt(&throttle, &key, &policy, &clock).delay.as_secs())
        .collect();
    let mut expected = vec![0; 20];
    expected.extend([1, 2, 4, 8, 16, 30, 30, 30]);
    assert_eq!(delays, expected);
}

#[test]
fn mode_off_never_delays_locks_or_refuses() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::Off);
    let key = account("alice");
    for _ in 0..200 {
        let outcome = throttle.record_failure(&key, &policy, clock.now());
        assert_eq!(outcome.delay, Duration::ZERO);
        assert_eq!(outcome.locked_until, None);
        assert!(!outcome.alert);
        assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    }
    // Off does not track anything.
    assert!(throttle.is_empty());
}

#[test]
fn mode_off_ignores_state_left_by_a_stricter_mode() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let key = account("alice");
    let strict = policy(LockoutMode::LockUntilUnlock);
    assert!(
        fail_at(&throttle, &key, &strict, clock.now(), 5)
            .locked_until
            .is_some()
    );
    assert!(held(&throttle, &key, &strict, clock.now()));
    assert_eq!(
        throttle.check(&key, &policy(LockoutMode::Off), clock.now()),
        Ok(())
    );
    // The state itself is kept until the lock ends or an administrator unlocks.
    assert!(held(&throttle, &key, &strict, clock.now()));
}

#[test]
fn check_without_failures_allows() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    for mode in [
        LockoutMode::ProgressiveDelay,
        LockoutMode::DelayThenTemporaryLock,
        LockoutMode::LockUntilUnlock,
    ] {
        assert_eq!(
            throttle.check(&account("nobody"), &policy(mode), clock.now()),
            Ok(())
        );
    }
    assert!(throttle.is_empty(), "check never creates an entry");
}

#[test]
fn check_refuses_inside_the_delay_and_allows_exactly_at_the_boundary() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    let key = account("alice");
    let t0 = clock.now();
    // The eighth failure has a delay of 4 s.
    let outcome = fail_at(&throttle, &key, &policy, t0, 8);
    assert_eq!(outcome.delay, secs(4));

    let refused = |after: Duration| Err(Retry { after: Some(after) });
    assert_eq!(throttle.check(&key, &policy, t0), refused(secs(4)));
    assert_eq!(
        throttle.check(&key, &policy, t0),
        refused(secs(4)),
        "check does not count"
    );
    assert_eq!(
        throttle.check(&key, &policy, plus(t0, secs(3))),
        refused(secs(1))
    );
    let just_before = minus(plus(t0, secs(4)), Duration::from_nanos(1));
    assert_eq!(
        throttle.check(&key, &policy, just_before),
        refused(Duration::from_nanos(1))
    );
    assert_eq!(throttle.check(&key, &policy, plus(t0, secs(4))), Ok(()));
    assert_eq!(throttle.check(&key, &policy, plus(t0, secs(5))), Ok(()));
}

#[test]
fn a_new_failure_restarts_the_delay_from_that_moment() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    let key = account("alice");
    fail_at(&throttle, &key, &policy, clock.now(), 6); // 1 s delay
    clock.advance(secs(1));
    let outcome = throttle.record_failure(&key, &policy, clock.now()); // 2 s delay
    assert_eq!(outcome.delay, secs(2));
    clock.advance(secs(1));
    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry {
            after: Some(secs(1))
        })
    );
    clock.advance(secs(1));
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
}

#[test]
fn a_clock_set_back_never_holds_longer_than_one_delay() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    let key = account("alice");
    let t0 = clock.now();
    fail_at(&throttle, &key, &policy, plus(t0, mins(10)), 6); // 1 s delay
    assert_eq!(
        throttle.check(&key, &policy, t0),
        Err(Retry {
            after: Some(secs(1))
        })
    );
}

#[test]
fn temporary_lock_after_lock_after_failures() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    for n in 1..=9 {
        let outcome = attempt(&throttle, &key, &policy, &clock);
        assert_eq!(outcome.failures, n);
        assert_eq!(outcome.locked_until, None);
    }
    let outcome = attempt(&throttle, &key, &policy, &clock);
    let locked_at = clock.now();
    assert_eq!(outcome.failures, 10);
    assert_eq!(outcome.locked_until, Some(plus(locked_at, mins(15))));
    assert_eq!(outcome.delay, mins(15));
    assert!(!outcome.alert, "a temporary lock raises no alarm");

    let remaining = |after: Duration| Err(Retry { after: Some(after) });
    assert_eq!(
        throttle.check(&key, &policy, locked_at),
        remaining(mins(15))
    );
    assert_eq!(
        throttle.check(&key, &policy, plus(locked_at, mins(5))),
        remaining(mins(10))
    );
    let just_before = minus(plus(locked_at, mins(15)), Duration::from_nanos(1));
    assert_eq!(
        throttle.check(&key, &policy, just_before),
        remaining(Duration::from_nanos(1))
    );
}

#[test]
fn lock_lifts_after_the_lock_duration_and_the_counter_resets() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    let locked_at = clock.now();
    assert!(
        fail_at(&throttle, &key, &policy, locked_at, 10)
            .locked_until
            .is_some()
    );
    assert_eq!(throttle.len(), 1);

    clock.set(plus(locked_at, mins(15)));
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    assert!(
        throttle.is_empty(),
        "the lapsed lock is forgotten on access"
    );

    let outcome = throttle.record_failure(&key, &policy, clock.now());
    assert_eq!(outcome.failures, 1, "the counter starts again");
    assert_eq!(outcome.delay, Duration::ZERO);
    assert_eq!(outcome.locked_until, None);
}

#[test]
fn lock_lifts_even_when_nothing_accessed_it_in_between() {
    let throttle = Throttle::new(16);
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    let t0 = MockClock::fixed().now();
    fail_at(&throttle, &key, &policy, t0, 10);
    // The first access after a long time is a failure, not a check.
    let outcome = throttle.record_failure(&key, &policy, plus(t0, mins(16)));
    assert_eq!(outcome.failures, 1);
    assert_eq!(outcome.locked_until, None);
}

#[test]
fn lock_until_unlock_raises_the_alarm_once_per_lock() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::LockUntilUnlock);
    let key = account("alice");
    for n in 1..=4 {
        let outcome = attempt(&throttle, &key, &policy, &clock);
        assert_eq!(outcome.failures, n);
        assert!(!outcome.alert, "failure {n} does not lock");
    }
    let outcome = attempt(&throttle, &key, &policy, &clock);
    let locked_at = clock.now();
    assert_eq!(outcome.failures, 5);
    assert!(outcome.alert);
    assert_eq!(outcome.locked_until, Some(plus(locked_at, mins(30))));

    // A failure that is still counted while the lock holds neither extends the lock nor
    // alarms again.
    clock.advance(mins(10));
    let again = throttle.record_failure(&key, &policy, clock.now());
    assert_eq!(again.failures, 6);
    assert!(!again.alert);
    assert_eq!(again.locked_until, None);
    assert_eq!(again.delay, mins(20));
    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry {
            after: Some(mins(20))
        })
    );

    // The lock lifts by itself after its timeout; the next lock alarms again.
    clock.set(plus(locked_at, mins(30)));
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    for _ in 0..4 {
        assert!(!attempt(&throttle, &key, &policy, &clock).alert);
    }
    assert!(attempt(&throttle, &key, &policy, &clock).alert);
}

#[test]
fn an_unlock_clears_the_lock_and_the_counter() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::LockUntilUnlock);
    let key = account("alice");
    let other = account("bob");
    assert!(fail_at(&throttle, &key, &policy, clock.now(), 5).alert);
    fail_at(&throttle, &other, &policy, clock.now(), 4);
    assert!(held(&throttle, &key, &policy, clock.now()));

    throttle.unlock(&key);
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    assert_eq!(throttle.len(), 1, "only the unlocked key was forgotten");
    assert!(
        held(&throttle, &other, &policy, clock.now()),
        "other keys are untouched"
    );
    assert_eq!(
        throttle.record_failure(&key, &policy, clock.now()).failures,
        1
    );

    throttle.unlock(&account("never-seen"));
    assert_eq!(throttle.len(), 2);
}

#[test]
fn a_success_forgets_the_delay() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    let key = account("alice");
    fail_at(&throttle, &key, &policy, clock.now(), 8);
    assert!(held(&throttle, &key, &policy, clock.now()));

    throttle.record_success(&key);
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    assert!(throttle.is_empty());
    assert_eq!(
        throttle.record_failure(&key, &policy, clock.now()).failures,
        1
    );
}

#[test]
fn a_success_forgets_a_lock_too() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    fail_at(&throttle, &key, &policy, clock.now(), 10);
    assert!(held(&throttle, &key, &policy, clock.now()));
    throttle.record_success(&key);
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
}

#[test]
fn an_entry_is_forgotten_after_reset_after() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay); // reset after 15 minutes
    let (kept, dropped) = (account("kept"), account("dropped"));
    let t0 = clock.now();
    fail_at(&throttle, &kept, &policy, t0, 6);
    fail_at(&throttle, &dropped, &policy, t0, 6);

    // One instant before the reset the entries still exist; a failure continues the count.
    let almost = minus(plus(t0, mins(15)), Duration::from_nanos(1));
    assert_eq!(
        throttle.check(&dropped, &policy, almost),
        Ok(()),
        "the 1 s delay is over"
    );
    assert_eq!(throttle.len(), 2);
    assert_eq!(throttle.record_failure(&kept, &policy, almost).failures, 7);

    // At the reset the untouched entry is forgotten on access and counts from one again.
    let reset = plus(t0, mins(15));
    assert_eq!(throttle.check(&dropped, &policy, reset), Ok(()));
    assert_eq!(throttle.len(), 1);
    assert_eq!(
        throttle.record_failure(&dropped, &policy, reset).failures,
        1
    );
    // The key that failed again was kept alive by that failure.
    assert_eq!(throttle.record_failure(&kept, &policy, reset).failures, 8);
}

#[test]
fn the_reset_window_never_cuts_a_lock_short() {
    let throttle = Throttle::new(16);
    let policy = LockoutPolicy {
        reset_after: mins(5),
        ..self::policy(LockoutMode::DelayThenTemporaryLock)
    };
    let key = account("alice");
    let t0 = MockClock::fixed().now();
    fail_at(&throttle, &key, &policy, t0, 10); // locked for 15 minutes
    assert_eq!(
        throttle.check(&key, &policy, plus(t0, mins(10))),
        Err(Retry {
            after: Some(mins(5))
        })
    );
}

#[test]
fn a_lock_holds_after_the_mode_is_relaxed() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let key = account("alice");
    fail_at(
        &throttle,
        &key,
        &policy(LockoutMode::DelayThenTemporaryLock),
        clock.now(),
        10,
    );
    let relaxed = policy(LockoutMode::ProgressiveDelay);
    assert_eq!(
        throttle.check(&key, &relaxed, clock.now()),
        Err(Retry {
            after: Some(mins(15))
        })
    );
}

#[test]
fn a_lock_without_a_representable_end_has_no_retry_time() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = LockoutPolicy {
        lock_after: 1,
        lock_duration: Duration::MAX,
        ..self::policy(LockoutMode::LockUntilUnlock)
    };
    let key = account("alice");
    let outcome = throttle.record_failure(&key, &policy, clock.now());
    assert!(outcome.alert);
    assert!(outcome.locked_until.is_some());
    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry { after: None })
    );
    clock.advance(mins(60 * 24 * 365));
    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry { after: None })
    );
    throttle.unlock(&key);
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
}

#[test]
fn the_source_policy_is_independent_of_the_account_keys() {
    let throttle = Throttle::new(64);
    let clock = MockClock::fixed();
    let accounts = policy(LockoutMode::DelayThenTemporaryLock);
    let source_policy = LockoutPolicy::source_policy();
    let addr = ThrottleKey::source(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    let t0 = clock.now();

    // One address tries 25 different accounts once each: no account is delayed, the
    // address is.
    for i in 0..25 {
        let name = account(&format!("user{i}"));
        assert_eq!(throttle.check(&name, &accounts, t0), Ok(()));
        throttle.record_failure(&name, &accounts, t0);
        throttle.record_failure(&addr, &source_policy, t0);
    }
    for i in 0..25 {
        let name = account(&format!("user{i}"));
        assert_eq!(
            throttle.check(&name, &accounts, t0),
            Ok(()),
            "user{i} failed only once"
        );
    }
    assert_eq!(
        throttle.check(&addr, &source_policy, t0),
        Err(Retry {
            after: Some(secs(16))
        }),
        "the 25th failure of the address"
    );

    // The other direction: failures of one account leave the address alone.
    let other_addr = ThrottleKey::source(IpAddr::V6(Ipv6Addr::LOCALHOST));
    fail_at(&throttle, &account("alice"), &accounts, t0, 9);
    assert_eq!(throttle.check(&other_addr, &source_policy, t0), Ok(()));
    assert_eq!(
        throttle
            .record_failure(&other_addr, &source_policy, t0)
            .failures,
        1
    );
}

#[test]
fn the_source_policy_never_locks() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = LockoutPolicy::source_policy();
    let key = ThrottleKey::source(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
    for n in 1..=2_000 {
        let outcome = throttle.record_failure(&key, &policy, clock.now());
        assert_eq!(outcome.failures, n);
        assert_eq!(outcome.locked_until, None);
        assert!(!outcome.alert);
        assert!(outcome.delay <= secs(30));
    }
    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry {
            after: Some(secs(30))
        })
    );
    clock.advance(secs(30));
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
}

#[test]
fn source_keys_are_per_address() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = LockoutPolicy::source_policy();
    let v4 = ThrottleKey::source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let v4_other = ThrottleKey::source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
    let v6 = ThrottleKey::source(IpAddr::V6("2001:db8::1".parse().expect("valid address")));
    fail_at(&throttle, &v4, &policy, clock.now(), 25);
    assert!(held(&throttle, &v4, &policy, clock.now()));
    assert!(!held(&throttle, &v4_other, &policy, clock.now()));
    assert!(!held(&throttle, &v6, &policy, clock.now()));
}

#[test]
fn an_ipv4_mapped_address_is_the_same_client() {
    let mapped: IpAddr = "::ffff:192.0.2.1".parse().expect("valid address");
    let plain: IpAddr = "192.0.2.1".parse().expect("valid address");
    assert_eq!(ThrottleKey::source(mapped), ThrottleKey::source(plain));
    assert_ne!(mapped, plain);
}

#[test]
fn account_keys_are_lowercased() {
    assert_eq!(account("Alice"), ThrottleKey::Account("alice".to_owned()));
    assert_eq!(account("ALICE"), account("alice"));

    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    fail_at(&throttle, &account("Alice"), &policy, clock.now(), 3);
    assert_eq!(
        throttle
            .record_failure(&account("aLiCe"), &policy, clock.now())
            .failures,
        4
    );
    assert_eq!(throttle.len(), 1);
}

#[test]
fn unknown_account_names_are_throttled_exactly_like_known_ones() {
    // The throttle never learns whether an account exists, so both follow one schedule.
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let mut trails = Vec::new();
    for name in ["alice", "no-such-user"] {
        let throttle = Throttle::new(16);
        let clock = MockClock::fixed();
        let key = account(name);
        let mut trail = Vec::new();
        for _ in 0..10 {
            let outcome = attempt(&throttle, &key, &policy, &clock);
            trail.push((outcome, throttle.check(&key, &policy, clock.now())));
        }
        trails.push(trail);
    }
    let [known, unknown] = &trails[..] else {
        panic!("two trails");
    };
    assert_eq!(known, unknown);
    assert!(known.last().expect("ten failures").0.locked_until.is_some());
}

#[test]
fn eviction_drops_the_entry_with_the_oldest_last_failure() {
    let throttle = Throttle::new(3);
    let clock = MockClock::fixed();
    let policy = long_hold();
    let (a, b, c, d) = (account("a"), account("b"), account("c"), account("d"));
    throttle.record_failure(&a, &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&b, &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&c, &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&a, &policy, clock.now()); // a is the freshest now
    assert_eq!(throttle.len(), 3);

    clock.advance(mins(1));
    throttle.record_failure(&d, &policy, clock.now());
    assert_eq!(throttle.len(), 3, "the capacity holds");

    clock.advance(mins(1));
    let now = clock.now();
    assert!(
        !held(&throttle, &b, &policy, now),
        "b had the oldest last failure"
    );
    assert!(held(&throttle, &a, &policy, now));
    assert!(held(&throttle, &c, &policy, now));
    assert!(held(&throttle, &d, &policy, now));
}

#[test]
fn eviction_drops_expired_entries_before_older_live_ones() {
    let throttle = Throttle::new(3);
    let clock = MockClock::fixed();
    let long = long_hold();
    let short = LockoutPolicy {
        reset_after: mins(10),
        ..long_hold()
    };
    let (oldest, short_lived, newer, incoming) = (
        account("oldest"),
        account("short"),
        account("newer"),
        account("incoming"),
    );
    throttle.record_failure(&oldest, &long, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&short_lived, &short, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&newer, &long, clock.now());

    // The short-lived entry has expired by now; the oldest one has not.
    clock.advance(mins(18));
    throttle.record_failure(&incoming, &long, clock.now());
    assert_eq!(throttle.len(), 3);
    clock.advance(mins(1));
    let now = clock.now();
    assert!(
        held(&throttle, &oldest, &long, now),
        "the oldest live entry survived"
    );
    assert!(held(&throttle, &newer, &long, now));
    assert!(held(&throttle, &incoming, &long, now));
}

#[test]
fn locked_entries_are_evicted_last() {
    let throttle = Throttle::new(3);
    let clock = MockClock::fixed();
    let policy = long_hold_locking(); // the second failure locks for 30 minutes
    let (locked, b, c, d) = (account("locked"), account("b"), account("c"), account("d"));
    let t0 = clock.now();
    assert!(
        fail_at(&throttle, &locked, &policy, t0, 2)
            .locked_until
            .is_some()
    );
    clock.advance(mins(1));
    throttle.record_failure(&b, &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&c, &policy, clock.now());

    clock.advance(mins(1));
    throttle.record_failure(&d, &policy, clock.now());
    assert_eq!(throttle.len(), 3);
    clock.advance(mins(1));
    let now = clock.now();
    assert_eq!(
        throttle.check(&locked, &policy, now),
        Err(Retry {
            after: Some(mins(26))
        }),
        "the lock outlives the older, unlocked entries"
    );
    assert!(!held(&throttle, &b, &policy, now), "b was evicted instead");
    assert!(held(&throttle, &c, &policy, now));
    assert!(held(&throttle, &d, &policy, now));
}

#[test]
fn when_everything_is_locked_the_lock_that_ends_first_is_evicted() {
    let throttle = Throttle::new(2);
    let clock = MockClock::fixed();
    let policy = long_hold_locking();
    let (first, second, newcomer) = (account("first"), account("second"), account("newcomer"));
    assert!(
        fail_at(&throttle, &first, &policy, clock.now(), 2)
            .locked_until
            .is_some()
    );
    clock.advance(mins(1));
    assert!(
        fail_at(&throttle, &second, &policy, clock.now(), 2)
            .locked_until
            .is_some()
    );

    clock.advance(mins(1));
    throttle.record_failure(&newcomer, &policy, clock.now());
    assert_eq!(throttle.len(), 2);
    clock.advance(mins(1));
    let now = clock.now();
    assert!(!held(&throttle, &first, &policy, now));
    assert_eq!(
        throttle.check(&second, &policy, now),
        Err(Retry {
            after: Some(mins(28))
        })
    );
    assert!(held(&throttle, &newcomer, &policy, now));
}

#[test]
fn a_flood_of_new_keys_stays_within_the_capacity() {
    let throttle = Throttle::new(50);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::ProgressiveDelay);
    for i in 0..1_000 {
        throttle.record_failure(&account(&format!("guess{i}")), &policy, clock.now());
        clock.advance(Duration::from_millis(10));
        assert!(throttle.len() <= 50);
    }
    assert_eq!(throttle.len(), 50);
}

#[test]
fn a_restored_lock_refuses_until_it_ends() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    let until = plus(clock.now(), mins(10));
    throttle.restore_lock(key.clone(), until);
    assert_eq!(throttle.len(), 1);

    assert_eq!(
        throttle.check(&key, &policy, clock.now()),
        Err(Retry {
            after: Some(mins(10))
        })
    );
    assert_eq!(
        throttle.check(&key, &policy, minus(until, Duration::from_nanos(1))),
        Err(Retry {
            after: Some(Duration::from_nanos(1))
        })
    );
    assert_eq!(throttle.check(&key, &policy, until), Ok(()));
    assert!(throttle.is_empty());
}

#[test]
fn a_restored_lock_that_has_already_ended_is_dropped() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::LockUntilUnlock);
    let key = account("alice");
    throttle.restore_lock(key.clone(), minus(clock.now(), mins(1)));
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
    assert!(throttle.is_empty());

    throttle.restore_lock(key.clone(), minus(clock.now(), mins(1)));
    assert_eq!(
        throttle.record_failure(&key, &policy, clock.now()).failures,
        1
    );
}

#[test]
fn a_restored_lock_can_be_unlocked() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::LockUntilUnlock);
    let key = account("alice");
    throttle.restore_lock(key.clone(), plus(clock.now(), mins(30)));
    assert!(held(&throttle, &key, &policy, clock.now()));
    throttle.unlock(&key);
    assert_eq!(throttle.check(&key, &policy, clock.now()), Ok(()));
}

#[test]
fn a_restored_lock_never_shortens_an_existing_one() {
    let throttle = Throttle::new(16);
    let clock = MockClock::fixed();
    let policy = policy(LockoutMode::DelayThenTemporaryLock);
    let key = account("alice");
    let t0 = clock.now();
    fail_at(&throttle, &key, &policy, t0, 10); // locked until t0 + 15 min

    throttle.restore_lock(key.clone(), plus(t0, mins(5)));
    assert_eq!(
        throttle.check(&key, &policy, t0),
        Err(Retry {
            after: Some(mins(15))
        })
    );
    throttle.restore_lock(key.clone(), plus(t0, mins(20)));
    assert_eq!(
        throttle.check(&key, &policy, t0),
        Err(Retry {
            after: Some(mins(20))
        })
    );
    assert_eq!(throttle.len(), 1);
}

#[test]
fn a_restored_lock_survives_capacity_pressure() {
    let throttle = Throttle::new(2);
    let clock = MockClock::fixed();
    let policy = long_hold();
    let restored = account("restored");
    throttle.restore_lock(restored.clone(), plus(clock.now(), mins(30)));
    throttle.record_failure(&account("b"), &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&account("c"), &policy, clock.now());
    assert_eq!(throttle.len(), 2);
    assert!(held(&throttle, &restored, &policy, clock.now()));
    assert!(!held(&throttle, &account("b"), &policy, clock.now()));
}

#[test]
fn restoring_a_lock_into_a_full_table_evicts_the_oldest_unlocked_entry() {
    let throttle = Throttle::new(2);
    let clock = MockClock::fixed();
    let policy = long_hold();
    throttle.record_failure(&account("old"), &policy, clock.now());
    clock.advance(mins(1));
    throttle.record_failure(&account("new"), &policy, clock.now());
    throttle.restore_lock(account("restored"), plus(clock.now(), mins(30)));
    assert_eq!(throttle.len(), 2);
    assert!(!held(&throttle, &account("old"), &policy, clock.now()));
    assert!(held(&throttle, &account("new"), &policy, clock.now()));
    assert!(held(&throttle, &account("restored"), &policy, clock.now()));
}

#[test]
fn concurrent_failures_are_all_counted() {
    let throttle = Throttle::new(16);
    let policy = policy(LockoutMode::ProgressiveDelay);
    let key = account("alice");
    let now = MockClock::fixed().now();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..100 {
                    throttle.record_failure(&key, &policy, now);
                    let _ = throttle.check(&key, &policy, now);
                }
            });
        }
    });
    assert_eq!(throttle.record_failure(&key, &policy, now).failures, 801);
    assert_eq!(throttle.len(), 1);
}

#[test]
fn the_debug_output_does_not_show_user_names() {
    let throttle = Throttle::new(16);
    let policy = policy(LockoutMode::ProgressiveDelay);
    throttle.record_failure(&account("alice"), &policy, MockClock::fixed().now());
    let shown = format!("{throttle:?}");
    assert!(!shown.contains("alice"), "{shown}");
}
