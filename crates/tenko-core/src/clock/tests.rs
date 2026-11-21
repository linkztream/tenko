//! The guard driven by synthetic looks: a monotonic instant and a wall time that move together
//! unless a test steps the wall clock.

use std::time::{Duration, Instant};

use super::*;

const DAY_MS: i64 = 24 * 3_600 * 1_000;

/// The wall time of the first look of a node.
fn w0() -> Timestamp {
    Timestamp::from_unix_nanos(1_800_000_000_000_000_000).expect("in range")
}

/// [`w0`] moved by `ms`.
fn at(ms: i64) -> Timestamp {
    Timestamp::from_unix_nanos(w0().unix_nanos() + i128::from(ms) * 1_000_000).expect("in range")
}

/// A node whose clocks a test advances.
struct Sim {
    guard: Guard,
    t0: Instant,
    mono_ms: i64,
    wall_ms: i64,
}

impl Sim {
    /// A node that starts at `w0 + start_ms` from `saved`.
    fn new(saved: Option<Saved>, start_ms: i64) -> Self {
        let t0 = Instant::now();
        Self {
            guard: Guard::start(saved, t0, at(start_ms)),
            t0,
            mono_ms: 0,
            wall_ms: start_ms,
        }
    }

    /// Advances both clocks by `ms`, steps the wall clock by `step_ms`, and looks.
    fn look(&mut self, ms: i64, step_ms: i64) -> &Guard {
        self.mono_ms += ms;
        self.wall_ms += ms + step_ms;
        let mono = self.t0 + Duration::from_millis(u64::try_from(self.mono_ms).expect("forward"));
        self.guard.look_at(mono, at(self.wall_ms), mono);
        &self.guard
    }
}

#[test]
fn a_step_over_five_seconds_holds() {
    let mut small = Sim::new(None, 0);
    assert_eq!(small.look(1_000, 4_000).trusted(), Ok(()));

    let mut sim = Sim::new(None, 0);
    let held = sim.look(1_000, 6_000).trusted().unwrap_err();
    assert_eq!(
        (held.reason, held.jump_ms, held.release),
        (Reason::Jump, 6_000, Release::Wait)
    );
    assert_eq!(sim.guard.forward_hold(), Some(Duration::from_secs(6)));
    assert_eq!(sim.guard.plausible().unwrap_err().release, Release::Person);

    let mut back = Sim::new(None, 0);
    assert_eq!(
        back.look(1_000, -6_000).trusted().unwrap_err().jump_ms,
        -6_000
    );
    assert_eq!(back.guard.forward_hold(), None);
}

#[test]
fn steps_of_four_seconds_every_second_hold_within_a_minute() {
    let mut sim = Sim::new(None, 0);
    let first = (1..=60_i64)
        .find(|_| sim.look(1_000, 4_000).trusted().is_err())
        .expect("held within a minute");
    assert!(first <= 15, "held at look {first}");
    for _ in 0..30 {
        sim.look(1_000, 4_000);
    }
    assert_eq!(
        sim.guard.trusted().unwrap_err().jump_ms,
        4_000 * (first + 30),
        "measured from the clock before the first step"
    );
}

#[test]
fn a_drift_of_a_few_milliseconds_a_minute_never_holds() {
    let mut sim = Sim::new(None, 0);
    // One look a second for a day: 5 ms a minute, and a step of 400 ms once an hour.
    for second in 1..=86_400 {
        let step = match second {
            s if s % 3_600 == 0 => 400,
            s if s % 12 == 0 => 1,
            _ => 0,
        };
        assert_eq!(
            sim.look(1_000, step).trusted(),
            Ok(()),
            "at second {second}"
        );
    }
}

#[test]
fn j_is_measured_from_the_last_trusted_look() {
    let mut sim = Sim::new(None, 0);
    sim.look(1_000, 4_000);
    sim.look(1_000, 6_000);
    sim.look(1_000, 3_000);
    assert_eq!(sim.guard.trusted().unwrap_err().jump_ms, 13_000);
}

#[test]
fn a_step_that_returns_ends_the_hold() {
    let mut sim = Sim::new(None, 0);
    assert_eq!(
        sim.look(1_000, 60_000).trusted().unwrap_err().jump_ms,
        60_000
    );
    assert_eq!(sim.look(1_000, -59_000).trusted(), Ok(()));
    assert_eq!(sim.guard.plausible(), Ok(()));
    assert_eq!(sim.guard.saved().held, None);
}

#[test]
fn a_hold_ends_after_waiting_the_jump_and_issuing_stays_held() {
    let mut sim = Sim::new(None, 0);
    let held = sim.look(1_000, 60_000).trusted().unwrap_err();
    assert_eq!(held.until, Some(at(1_000 + 60_000 + 60_000)));
    assert_eq!(
        sim.look(59_000, 0).trusted().unwrap_err().release,
        Release::Wait
    );
    assert_eq!(sim.look(1_000, 0).trusted(), Ok(()));
    assert_eq!(sim.guard.forward_hold(), None);
    let issuing = sim.guard.plausible().unwrap_err();
    assert_eq!((issuing.release, issuing.until), (Release::Person, None));
    assert_eq!(sim.look(1_000, 0).trusted(), Ok(()), "trusted looks go on");
}

#[test]
fn a_growing_jump_restarts_the_wait() {
    let mut sim = Sim::new(None, 0);
    sim.look(1_000, 60_000);
    assert_eq!(
        sim.look(30_000, 60_000).trusted().unwrap_err().jump_ms,
        120_000
    );
    assert_eq!(
        sim.look(119_000, 0).trusted().unwrap_err().release,
        Release::Wait
    );
    assert_eq!(sim.look(1_000, 0).trusted(), Ok(()));
}

#[test]
fn growth_within_the_tolerance_keeps_the_wait_and_beyond_it_restarts_it() {
    // A hold of 60 s at second 1, then a further step at second 31.
    let mut within = Sim::new(None, 0);
    within.look(1_000, 60_000);
    within.look(30_000, 5_000);
    assert_eq!(
        within.look(34_000, 0).trusted().unwrap_err().jump_ms,
        65_000
    );
    assert_eq!(
        within.look(1_000, 0).trusted(),
        Ok(()),
        "65 s after the hold began"
    );

    let mut beyond = Sim::new(None, 0);
    beyond.look(1_000, 60_000);
    beyond.look(30_000, 6_000);
    assert_eq!(
        beyond.look(65_000, 0).trusted().unwrap_err().jump_ms,
        66_000
    );
    assert_eq!(
        beyond.look(1_000, 0).trusted(),
        Ok(()),
        "66 s after the growth"
    );
}

#[test]
fn steps_that_go_on_while_held_add_up_to_the_whole_jump_and_its_wait() {
    // 4 s every second for 100 s, then quiet: the baseline stays the last trusted look.
    let mut sim = Sim::new(None, 0);
    for _ in 0..100 {
        sim.look(1_000, 4_000);
    }
    assert_eq!(sim.guard.trusted().unwrap_err().jump_ms, 400_000);
    assert_eq!(
        sim.look(399_000, 0).trusted().unwrap_err().release,
        Release::Wait
    );
    assert_eq!(
        sim.look(1_000, 0).trusted(),
        Ok(()),
        "400 s after the last step"
    );
}

#[test]
fn a_jump_over_a_day_waits_for_a_person() {
    let mut sim = Sim::new(None, 0);
    let held = sim.look(1_000, DAY_MS + 1_000).trusted().unwrap_err();
    assert_eq!((held.release, held.until), (Release::Person, None));
    assert_eq!(
        sim.look(3 * DAY_MS, 0).trusted().unwrap_err().release,
        Release::Person
    );
}

#[test]
fn a_torn_look_is_dropped() {
    let t0 = Instant::now();
    let mut guard = Guard::start(None, t0, w0());
    // The wall clock read 10 s after the first monotonic read, the second 10 s later too.
    guard.look_at(t0, at(10_000), t0 + Duration::from_secs(10));
    assert_eq!(guard.trusted(), Ok(()));
    guard.look_at(t0, at(10_000), t0);
    assert_eq!(
        guard.trusted().unwrap_err().jump_ms,
        10_000,
        "the same reading, whole"
    );
}

#[test]
fn the_start_gap_holds_destruction_only() {
    let saved = Saved {
        last_trusted_at: at(-90_000),
        held: None,
    };
    let mut sim = Sim::new(Some(saved), 0);
    let held = sim.guard.trusted().unwrap_err();
    assert_eq!(
        (held.reason, held.jump_ms, held.release, held.until),
        (Reason::StartGap, 90_000, Release::Wait, Some(at(90_000)))
    );
    assert_eq!(sim.guard.plausible(), Ok(()));
    assert_eq!(sim.guard.forward_hold(), None);
    assert_eq!(sim.guard.saved().last_trusted_at, at(-90_000));
    assert_eq!(
        sim.look(89_000, 0).trusted().unwrap_err().reason,
        Reason::StartGap
    );
    assert_eq!(sim.look(1_000, 0).trusted(), Ok(()));
    assert_eq!(sim.guard.saved().held, None);

    let near = Saved {
        last_trusted_at: at(-4_000),
        held: None,
    };
    assert_eq!(Sim::new(Some(near), 0).guard.trusted(), Ok(()), "a restart");
}

#[test]
fn a_start_gap_over_a_day_waits_for_a_person() {
    let saved = Saved {
        last_trusted_at: at(-DAY_MS - 60_000),
        held: None,
    };
    let mut sim = Sim::new(Some(saved), 0);
    let held = sim.guard.trusted().unwrap_err();
    assert_eq!(
        (held.reason, held.release),
        (Reason::StartGap, Release::Person)
    );
    assert_eq!(
        sim.look(2 * DAY_MS, 0).trusted().unwrap_err().release,
        Release::Person
    );
}

#[test]
fn a_start_behind_the_last_trusted_time_holds_issuing_too() {
    let saved = Saved {
        last_trusted_at: at(120_000),
        held: None,
    };
    let mut sim = Sim::new(Some(saved), 0);
    assert_eq!(sim.guard.trusted().unwrap_err().jump_ms, -120_000);
    assert_eq!(sim.guard.plausible().unwrap_err().reason, Reason::StartGap);
    assert_eq!(sim.guard.forward_hold(), None);
    assert_eq!(sim.look(120_000, 0).trusted(), Ok(()));
    assert_eq!(sim.guard.plausible().unwrap_err().release, Release::Person);
}

#[test]
fn a_saved_hold_survives_a_restart_and_waits_again() {
    let mut first = Sim::new(None, 0);
    first.look(0, 60_000);
    let saved = first.guard.saved();
    assert_eq!(saved.last_trusted_at, w0());
    assert_eq!(
        saved.held.as_ref().map(|held| (held.reason, held.jump_ms)),
        Some((Reason::Jump, 60_000))
    );
    // Restarted at once, the clock still 60 s ahead of the last trusted look.
    let mut second = Sim::new(Some(saved), 60_000);
    let held = second.guard.trusted().unwrap_err();
    assert_eq!((held.reason, held.jump_ms), (Reason::Jump, 60_000));
    assert_eq!(second.guard.forward_hold(), Some(Duration::from_secs(60)));
    assert_eq!(
        second.look(59_000, 0).trusted().unwrap_err().release,
        Release::Wait
    );
    assert_eq!(second.look(1_000, 0).trusted(), Ok(()));
    assert_eq!(second.guard.plausible().unwrap_err().reason, Reason::Jump);
}

#[test]
fn a_saved_jump_restarted_after_downtime_does_not_widen_forward_hold() {
    let mut first = Sim::new(None, 0);
    first.look(1_000, 60_000);
    // Off for a week, then started with the clock still 60 s ahead.
    let second = Sim::new(Some(first.guard.saved()), 61_000 + 7 * DAY_MS);
    let held = second.guard.trusted().unwrap_err();
    assert_eq!(
        (held.reason, held.release),
        (Reason::StartGap, Release::Person)
    );
    assert_eq!(second.guard.forward_hold(), None);
    assert_eq!(
        second.guard.plausible().unwrap_err().reason,
        Reason::StartGap,
        "issuing stays held"
    );
}

#[test]
fn a_restart_after_the_wait_keeps_destruction_released_and_issuing_held() {
    let mut first = Sim::new(None, 0);
    first.look(1_000, 60_000);
    assert_eq!(first.look(60_000, 0).trusted(), Ok(()));
    let saved = first.guard.saved();
    assert_eq!(
        saved.held.as_ref().map(|held| (held.destroy, held.issue)),
        Some((false, true))
    );
    // A restart of two seconds.
    let mut second = Sim::new(Some(saved), 121_000 + 2_000);
    assert_eq!(second.guard.trusted(), Ok(()));
    assert_eq!(second.guard.forward_hold(), None);
    assert_eq!(second.guard.plausible().unwrap_err().reason, Reason::Jump);
    assert_eq!(second.look(1_000, 0).trusted(), Ok(()));
}

#[test]
fn a_start_gap_that_grew_keeps_issuing_held_across_a_restart() {
    let gap = Saved {
        last_trusted_at: at(-90_000),
        held: None,
    };
    let mut first = Sim::new(Some(gap), 0);
    assert_eq!(first.guard.plausible(), Ok(()));
    first.look(1_000, 60_000);
    assert_eq!(
        first.guard.plausible().unwrap_err().reason,
        Reason::StartGap
    );
    let mut second = Sim::new(Some(first.guard.saved()), 61_000 + 2_000);
    assert_eq!(
        second.guard.plausible().unwrap_err().reason,
        Reason::StartGap
    );
    assert_eq!(
        second.look(1_000, 0).trusted().unwrap_err().reason,
        Reason::StartGap
    );
}

#[test]
fn a_file_without_the_two_answers_holds_both() {
    let old = format!(
        r#"{{"last_trusted_at":"{}","held":{{"reason":"start_gap","jump_ms":90000,"since":"{}"}}}}"#,
        at(-90_000).to_rfc3339(),
        at(0).to_rfc3339()
    );
    let saved: Saved = serde_json::from_str(&old).expect("an older file");
    let held = saved.held.as_ref().expect("a hold");
    assert_eq!((held.destroy, held.issue), (true, true));
    let sim = Sim::new(Some(saved), 0);
    assert_eq!(sim.guard.trusted().unwrap_err().reason, Reason::StartGap);
    assert_eq!(sim.guard.plausible().unwrap_err().reason, Reason::StartGap);
}

#[test]
fn a_start_gap_is_not_released_by_a_step_back_of_the_gap() {
    let saved = Saved {
        last_trusted_at: at(-7 * DAY_MS),
        held: None,
    };
    let mut sim = Sim::new(Some(saved), 0);
    assert_eq!(sim.guard.trusted().unwrap_err().release, Release::Person);
    let held = sim.look(1_000, -7 * DAY_MS).trusted().unwrap_err();
    assert_eq!(
        (held.reason, held.release),
        (Reason::StartGap, Release::Person)
    );
    assert_eq!(
        sim.guard.plausible().unwrap_err().reason,
        Reason::StartGap,
        "a step during the hold holds issuing too"
    );
}

#[test]
fn confirm_ends_a_wait_early() {
    let mut sim = Sim::new(None, 0);
    sim.look(1_000, 60_000);
    sim.look(10_000, 0);
    sim.guard.confirm();
    assert_eq!(sim.guard.trusted(), Ok(()));
    assert_eq!(sim.guard.plausible(), Ok(()));
    assert_eq!(sim.guard.saved().held, None);
    assert_eq!(
        sim.look(1_000, 0).trusted(),
        Ok(()),
        "measured from the confirmed clock"
    );
}

#[test]
fn the_test_override_is_per_thread() {
    let held = Held {
        reason: Reason::Jump,
        jump_ms: 3_600_000,
        since: w0(),
        release: Release::Wait,
        until: None,
    };
    let jump = testing::hold(held.clone());
    assert_eq!(trusted_now(), Err(held.clone()));
    assert_eq!(forward_hold(), Some(Duration::from_secs(3_600)));
    let other = std::thread::spawn(|| (trusted_now().is_ok(), forward_hold()))
        .join()
        .expect("the other thread");
    assert_eq!(other, (true, None));
    drop(jump);
    assert!(trusted_now().is_ok());

    let _gap = testing::hold(Held {
        reason: Reason::StartGap,
        ..held.clone()
    });
    assert!(plausible_now().is_ok());
    assert_eq!(forward_hold(), None);
    assert_eq!(trusted_now().unwrap_err().reason, Reason::StartGap);
    confirm();
    assert!(trusted_now().is_ok(), "a confirm ends this thread's hold");

    let _issuing = testing::hold_issuing(Held {
        release: Release::Person,
        ..held
    });
    assert!(trusted_now().is_ok(), "the wait is over");
    assert_eq!(plausible_now().unwrap_err().release, Release::Person);
    assert_eq!(forward_hold(), None);
}
