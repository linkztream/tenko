//! The disk warning on built readings (time is the round's parameter), its tick on a paused
//! clock, and the task on the real store with its free-space hook and the real host monitor.

use std::sync::Arc;

use tenko_core::testing::wait_until_async;
use tenko_ipam::findings::{FindingAction, FindingLevel, FindingsConfig, HealthItem};
use tenko_store::{
    Store as _,
    raft::{RaftStore, RaftStoreConfig},
    test_hooks::FREE_BYTES,
};

use super::*;
use crate::dto::system::FindingSeverity;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// The store's margin in the runs below.
const MARGIN: u64 = 2 * GIB;

/// A watch fed one round a minute.
struct Run {
    watch: Watch,
    start: Instant,
    minute: u64,
    free: u64,
    margin: u64,
    normal: bool,
    /// The work the store does at the next readings: `Some(true)` builds a snapshot,
    /// `Some(false)` compacts.
    busy: Option<bool>,
    /// Whether the last round hid the finding behind the store's own warning.
    hidden: bool,
    host: Option<HostSample>,
}

impl Run {
    /// A run whose headroom starts at `headroom` bytes.
    fn new(headroom: u64) -> Self {
        Self {
            watch: Watch::default(),
            start: Instant::now(),
            minute: 0,
            free: MARGIN + headroom,
            margin: MARGIN,
            normal: true,
            busy: None,
            hidden: false,
            host: None,
        }
    }

    fn headroom(&self) -> u64 {
        self.free.saturating_sub(self.margin)
    }

    /// The next minute: the free space falls by `lost`, and the round reads it when `read`.
    fn tick(&mut self, lost: u64, read: bool) -> Option<Severity> {
        self.minute += 1;
        self.free = self.free.saturating_sub(lost);
        let reading = StoreSafety {
            pressure: if self.normal {
                Pressure::Normal
            } else {
                Pressure::Margin
            },
            compacting: self.busy == Some(false),
            snapshotting: self.busy == Some(true),
            ..safety(self.free, self.margin)
        };
        let now = self.start + Duration::from_secs(60 * self.minute);
        let (severity, hidden) =
            self.watch
                .round(now, read.then_some(&reading), self.host.as_ref());
        self.hidden = hidden;
        severity
    }

    /// The next minute with a reading after a loss of `lost`.
    fn step(&mut self, lost: u64) -> Option<Severity> {
        self.tick(lost, true)
    }

    /// `minutes` rounds that lose `per_hour` bytes an hour; the severity of each.
    fn fill(&mut self, per_hour: u64, minutes: u64) -> Vec<Option<Severity>> {
        (0..minutes).map(|_| self.step(per_hour / 60)).collect()
    }

    /// Rounds that lose `per_hour` until `severity` shows (or the headroom is gone): the
    /// minute it shows and the headroom then.
    fn until(&mut self, per_hour: u64, severity: Severity) -> Option<(u64, u64)> {
        while self.headroom() > 0 {
            if self.step(per_hour / 60) >= Some(severity) {
                return Some((self.minute, self.headroom()));
            }
        }
        None
    }
}

fn host(total: u64, available: u64) -> HostSample {
    HostSample {
        disk_total: Some(total),
        disk_available: Some(available),
        ..HostSample::blank(Timestamp::now())
    }
}

fn safety(free: u64, margin: u64) -> StoreSafety {
    StoreSafety {
        free_bytes: free,
        reserve_bytes: margin / 2,
        margin_bytes: margin,
        pressure: Pressure::Normal,
        compacting: false,
        snapshotting: false,
        snapshot_failed: false,
        stopped: None,
        restartable: false,
        free_unknown: false,
        running_secs: 0,
    }
}

#[test]
fn a_rate_needs_a_full_window_and_more_than_the_floor() {
    let mut run = Run::new(100 * GIB);
    run.fill(10 * GIB, 60);
    assert_eq!(run.watch.rate(HOUR), None, "no reading is an hour old");
    run.fill(10 * GIB, 1);
    assert!(run.watch.rate(HOUR).is_some());
    assert_eq!(run.watch.rate(DAY), None);
    // 63 MiB an hour is under the floor; a gain is no loss.
    let mut slow = Run::new(100 * GIB);
    slow.fill(63 * MIB, 120);
    assert_eq!(slow.watch.rate(HOUR), None);
    let mut gain = Run::new(100 * GIB);
    for _ in 0..120 {
        gain.free += GIB / 60;
        gain.step(0);
    }
    assert_eq!(gain.watch.rate(HOUR), None);
}

#[test]
fn act_and_error_by_the_hour_wait_their_hold() {
    let mut run = Run::new(100 * GIB);
    let severities = run.fill(10 * GIB, 76);
    assert!(
        severities[..75].iter().all(Option::is_none),
        "{severities:?}"
    );
    assert_eq!(
        severities[75],
        Some(Severity::Act),
        "15 minutes after the first rate"
    );
    let warning = run.watch.warning(Severity::Act, "/data");
    assert_eq!(warning.params["cause"], "hour");
    assert_eq!(warning.params["severity"], "act");
    let left: u64 = warning.params["seconds_left"].parse().expect("seconds");
    assert!((8 * 3_600..10 * 3_600).contains(&left), "{left}");
    assert!(
        warning.detail.starts_with("low disk space (")
            && warning.detail.contains(&format!("seconds_left {left}")),
        "{}",
        warning.detail
    );
    assert!(warning.detail.ends_with(NEXT_STEP), "{}", warning.detail);

    let mut fast = Run::new(15 * GIB);
    let severities = fast.fill(10 * GIB, 76);
    assert!(
        severities[..75].iter().all(Option::is_none),
        "{severities:?}"
    );
    assert_eq!(
        severities[75],
        Some(Severity::Error),
        "under 2 h, the fill held as long as `act` holds"
    );
}

/// One write with an hour of history, over five readings: "still filling" holds for it and the
/// ten minutes after, which neither `error` nor `act` waits out.
#[test]
fn one_write_after_an_hour_of_quiet_raises_nothing() {
    let mut run = Run::new(3 * GIB);
    run.fill(0, 61);
    let write: Vec<_> = (0..5).map(|_| run.step(2 * GIB / 5)).collect();
    assert!(
        run.watch.left(HOUR).is_some_and(|left| left < 3_600.0),
        "under an hour left at the hour's rate"
    );
    let after: Vec<_> = (0..70).map(|_| run.step(0)).collect();
    assert!(
        write.iter().chain(&after).all(Option::is_none),
        "{write:?} {after:?}"
    );
}

/// A snapshot written over twenty minutes, then removed, is the store's work, not a fill: the
/// rates skip its readings. A busy reading under the line raises `error` all the same.
#[test]
fn busy_readings_stay_out_of_the_rates_and_the_line_reads_them() {
    for snapshot in [false, true] {
        let mut run = Run::new(8 * GIB);
        run.fill(0, 61);
        run.busy = Some(snapshot);
        let seen: Vec<_> = (0..20).map(|_| run.step(3 * GIB / 10)).collect();
        run.busy = None;
        run.free += 20 * (3 * GIB / 10);
        let after: Vec<_> = (0..30).map(|_| run.step(0)).collect();
        assert!(
            seen.iter().chain(&after).all(Option::is_none),
            "{seen:?} {after:?}"
        );
    }

    let mut line = Run::new(0);
    (line.free, line.busy) = (MARGIN + MARGIN / 20, Some(false));
    assert_eq!(line.step(0), Some(Severity::Error));
    assert!(line.watch.ring.is_empty(), "no rate reads it");
}

#[test]
fn a_clear_holds_ten_minutes_and_a_line_keeps_its_band() {
    let mut run = Run::new(0);
    run.free = MARGIN + MARGIN / 20;
    assert_eq!(run.step(0), Some(Severity::Error), "under 1.1 x the margin");
    assert_eq!(
        run.watch.warning(Severity::Error, "/data").params["cause"],
        "line"
    );
    run.free = MARGIN + MARGIN / 5;
    for _ in 0..30 {
        assert_eq!(run.step(0), Some(Severity::Error), "inside the band");
    }
    run.free = MARGIN * 13 / 10;
    for _ in 0..5 {
        assert_eq!(run.step(0), Some(Severity::Error));
    }
    // Back into the band: the hold starts again.
    run.free = MARGIN + MARGIN / 5;
    run.step(0);
    run.free = MARGIN * 13 / 10;
    for _ in 0..10 {
        assert_eq!(run.step(0), Some(Severity::Error), "held");
    }
    assert_eq!(run.step(0), None, "ten minutes above 1.21 x the margin");

    // The level of the file system: 10 percent of 100 GiB, cleared at 11 GiB.
    let mut level = Run::new(100 * GIB);
    level.host = Some(host(100 * GIB, 9 * GIB));
    assert_eq!(
        level.step(0),
        Some(Severity::Review),
        "a level alone is to review"
    );
    assert_eq!(
        level.watch.warning(Severity::Review, "/data").params["cause"],
        "level"
    );
    level.host = Some(host(100 * GIB, 10 * GIB + GIB / 2));
    for _ in 0..20 {
        assert_eq!(level.step(0), Some(Severity::Review), "inside the band");
    }
    level.host = Some(host(100 * GIB, 11 * GIB));
    let severities: Vec<_> = (0..11).map(|_| level.step(0)).collect();
    assert_eq!(severities[9], Some(Severity::Review));
    assert_eq!(severities[10], None);
}

#[test]
fn readings_the_rates_may_not_use_are_not_stored() {
    assert_eq!(
        Reading::of(&safety(GIB, 0)),
        None,
        "before the first reading"
    );
    assert_eq!(
        Reading::of(&safety(u64::MAX, MARGIN)),
        None,
        "the initial free space"
    );
    let unknown = StoreSafety {
        free_unknown: true,
        ..safety(GIB, MARGIN)
    };
    assert_eq!(Reading::of(&unknown), None);
    assert_eq!(
        Reading::of(&safety(GIB, MARGIN)),
        Some(Reading {
            free: GIB,
            margin: MARGIN
        })
    );
    let mut run = Run::new(10 * GIB);
    run.step(0);
    run.tick(GIB, false);
    assert_eq!(
        run.watch.ring.len(),
        1,
        "a round without a reading stores none"
    );
}

/// Past the margin the store's own warning stands in place of the finding, while the rules run
/// on and the gauge keeps the severity: an alert on it does not resolve when the store starts
/// refusing writes.
#[test]
fn beyond_the_margin_the_store_speaks_and_the_gauge_keeps_the_severity() {
    let mut run = Run::new(0);
    run.free = MARGIN + MARGIN / 20;
    assert_eq!(run.step(0), Some(Severity::Error));
    assert!(!run.hidden);
    let raised = run.watch.raised_at;
    (run.free, run.normal) = (MARGIN - 1, false);
    let severity = run.step(0);
    assert_eq!(severity, Some(Severity::Error), "the rules run on");
    assert!(run.hidden, "the store's own warning");
    let state = AppState::default();
    let warning = publish(&state, &run.watch, (severity, true)).expect("a warning");
    assert!(!state.notices_list().contains(&warning), "not shown");
    assert!((gauge_value(severity, false) - 3.0).abs() < f64::EPSILON);
    (run.free, run.normal) = (MARGIN + MARGIN / 20, true);
    assert_eq!(run.step(0), Some(Severity::Error), "still raised");
    assert!(!run.hidden);
    assert_eq!(run.watch.raised_at, raised, "one episode");
}

/// A store that cannot read its free space mid-run raises its own error (`sys.store.disk_unknown`)
/// and holds its margin: the warning is not shown, no reading is stored, and the severity it
/// had comes back with its date once the store reads its disk again.
#[test]
fn a_free_space_that_cannot_be_read_mid_run_hides_the_warning_and_stores_nothing() {
    let mut run = Run::new(100 * GIB);
    assert_eq!(run.fill(10 * GIB, 76).last(), Some(&Some(Severity::Act)));
    let (raised, stored) = (run.watch.raised_at, run.watch.ring.len());
    let unknown = StoreSafety {
        free_unknown: true,
        pressure: Pressure::Margin,
        ..safety(run.free, MARGIN)
    };
    let state = AppState::default();
    for minute in 1..=5 {
        let now = run.start + Duration::from_secs(60 * (run.minute + minute));
        let round = run.watch.round(now, Some(&unknown), None);
        // The store refuses ordinary writes: the gauge says so, the rules raise nothing new.
        assert_eq!(round, (Some(Severity::Act), true));
        assert!(publish(&state, &run.watch, round).is_some());
        assert!((gauge_value(round.0, true) - 3.0).abs() < f64::EPSILON);
        assert!(state.notices_list().is_empty(), "not shown");
    }
    assert_eq!(run.watch.ring.len(), stored, "nothing stored");
    // The next good reading: the severity the figures give, no `error` left behind.
    run.minute += 5;
    assert_eq!(run.step(10 * GIB / 60), Some(Severity::Act));
    assert!(!run.hidden);
    assert!((gauge_value(Some(Severity::Act), false) - 2.0).abs() < f64::EPSILON);
    assert_eq!(run.watch.raised_at, raised, "one episode");
}

#[test]
fn fifty_megabytes_a_day_raise_nothing() {
    let mut run = Run::new(119 * GIB);
    assert!(
        run.fill(50_000_000 / 24, 3 * 1_440)
            .iter()
            .all(Option::is_none)
    );
}

#[test]
fn two_hundred_mebibytes_an_hour_raise_error_two_hours_ahead() {
    let mut run = Run::new(GIB);
    let (_, headroom) = run.until(200 * MIB, Severity::Error).expect("error");
    assert!(headroom >= 395 * MIB, "{} MiB left", headroom / MIB);
}

/// A fill shaped under the hourly floor gets `review` a week ahead and `act` a day ahead from
/// the day's rate.
#[test]
fn a_fill_under_the_hourly_floor_is_seen_by_the_day() {
    let mut run = Run::new(12 * GIB);
    let (review, _) = run.until(63 * MIB, Severity::Review).expect("review");
    let warning = run.watch.warning(Severity::Review, "/data");
    assert_eq!(warning.params["cause"], "day");
    assert!(warning.params.contains_key("seconds_left"));
    let bytes: u64 = warning.params["bytes"].parse().expect("bytes");
    assert!(
        (1_500..1_520).contains(&(bytes / MIB)),
        "the day's loss: {bytes}"
    );
    let (act, headroom) = run.until(63 * MIB, Severity::Act).expect("act");
    assert!(review < act);
    assert!(headroom >= 63 * MIB * 23, "{} MiB left", headroom / MIB);
    assert_eq!(run.watch.rate(HOUR), None, "never an hourly rate");
}

/// Readings dropped while the store is busy (four ticks of five) still give rates.
#[test]
fn readings_dropped_in_flight_leave_the_rates() {
    let mut run = Run::new(100 * GIB);
    let mut act = None;
    for _ in 0..90 {
        let read = run.minute % 5 == 4;
        if run.tick(10 * GIB / 60, read) == Some(Severity::Act) {
            act = Some(run.minute);
            break;
        }
    }
    assert!(act.is_some_and(|minute| minute <= 85), "{act:?}");
}

/// The margin grows with the data: the headroom shrinks faster than the free space.
#[test]
fn a_rising_margin_shortens_the_time_left() {
    let mut run = Run::new(30 * GIB);
    let severities: Vec<_> = (0..76)
        .map(|_| {
            run.margin += 5 * GIB / 2 / 60;
            run.step(GIB / 60)
        })
        .collect();
    assert_eq!(
        severities[75],
        Some(Severity::Act),
        "7.6 h at 3.5 GiB an hour"
    );
}

/// One large write (a backup of 5 GiB, deleted an hour later) raises nothing; a burst every
/// hour raises `act` by the day's rate.
#[test]
fn one_write_raises_nothing_and_hourly_bursts_raise_act_by_the_day() {
    let mut run = Run::new(117 * GIB);
    let mut seen = Vec::new();
    for minute in 1..=400 {
        let lost = if minute == 100 { 5 * GIB } else { 0 };
        if minute == 160 {
            run.free += 5 * GIB;
        }
        seen.push(run.step(lost));
    }
    assert!(seen.iter().all(Option::is_none), "{seen:?}");

    let mut bursts = Run::new(40 * GIB);
    let seen: Vec<_> = (1..=1_441)
        .map(|minute| bursts.step(if minute % 60 == 0 { GIB } else { 0 }))
        .collect();
    assert!(
        seen[..1_440].iter().all(Option::is_none),
        "nothing before a day"
    );
    assert_eq!(
        seen[1_440],
        Some(Severity::Act),
        "16 GiB left at 24 GiB a day"
    );
}

/// Free space that swings around the error line every 15 minutes for two hours raises once.
#[test]
fn a_swing_around_the_line_raises_once() {
    let mut run = Run::new(0);
    let mut raises = 0;
    let mut before = None;
    for minute in 0..120 {
        run.free = if (minute / 15) % 2 == 0 {
            MARGIN * 1_045 / 1_000
        } else {
            MARGIN * 1_155 / 1_000
        };
        let now = run.step(0);
        if now == Some(Severity::Error) && before.is_none() {
            raises += 1;
        }
        before = now;
    }
    assert_eq!(raises, 1);
    assert_eq!(before, Some(Severity::Error));
}

/// Many readings in a short time (a runtime that made up missed ticks) keep the day's oldest
/// reading: the ring is bounded by age, not by count.
#[test]
fn many_readings_keep_the_days_history() {
    let mut run = Run::new(100 * GIB);
    run.fill(2 * GIB / 24, 1_440);
    let after = run.start + Duration::from_secs(60 * run.minute);
    let reading = safety(run.free, run.margin);
    for second in 1..=2_000 {
        run.watch
            .round(after + Duration::from_secs(second), Some(&reading), None);
    }
    assert!(run.watch.rate(DAY).is_some());
}

/// The hour's rate raises `error` only while the headroom still shrinks: a large write that is
/// over leaves a short time left at the hour's rate, but no raise.
#[test]
fn error_by_the_hour_waits_for_a_fill_that_goes_on() {
    let mut run = Run::new(3 * GIB);
    run.step(0);
    run.step(2 * GIB);
    let seen: Vec<_> = (0..59).map(|_| run.step(0)).collect();
    assert!(
        run.watch.left(HOUR).is_some_and(|left| left < 7_200.0),
        "half an hour left at the hour's rate"
    );
    assert!(seen.iter().all(Option::is_none), "{seen:?}");
}

/// `act` by the day's rate and `review` clear only once the day's rate leaves more than twice
/// their time, ten minutes on.
#[test]
fn act_and_review_clear_by_the_days_rate() {
    let mut run = Run::new(30 * GIB);
    assert_eq!(run.fill(GIB, 1_441).last(), Some(&Some(Severity::Act)));
    let after = |run: &mut Run, minutes: u64| (0..minutes).map(|_| run.step(0)).last().flatten();
    assert_eq!(
        after(&mut run, 21 * 60 + 5),
        Some(Severity::Act),
        "the day's loss still over 3 GiB"
    );
    assert_eq!(
        after(&mut run, 2 * 60 + 20),
        Some(Severity::Review),
        "act cleared, review stays"
    );
    assert_eq!(after(&mut run, 35), None, "review cleared");
}

/// The sentence follows the rule that raised the severity it shows.
#[test]
fn the_cause_is_the_rule_that_raised_the_severity() {
    // `review` by the level while an hour's rate leaves between 24 and 48 hours.
    let mut level = Run::new(40 * GIB);
    level.host = Some(host(100 * GIB, 9 * GIB));
    level.fill(GIB, 61);
    assert!(
        level
            .watch
            .left(HOUR)
            .is_some_and(|left| left > 86_400.0 && left < 2.0 * 86_400.0)
    );
    assert_eq!(
        level.watch.warning(Severity::Review, "/d").params["cause"],
        "level"
    );
    // `error` by the hour's rate between 1.1 and 1.21 times the margin: the time is said.
    let mut hour = Run::new(GIB * 62 / 100);
    hour.until(GIB / 5, Severity::Error).expect("error");
    assert!(hour.free > MARGIN + MARGIN / 10, "above the line");
    let warning = hour.watch.warning(Severity::Error, "/d");
    assert_eq!(warning.params["cause"], "hour");
    assert!(warning.params.contains_key("seconds_left"));
    // `error` by the line during its clear hold keeps the line's sentence.
    let mut line = Run::new(0);
    line.host = Some(host(100 * GIB, 50 * GIB));
    line.free = MARGIN + MARGIN / 20;
    line.step(0);
    line.free = MARGIN * 13 / 10;
    assert_eq!(line.step(0), Some(Severity::Error), "in its clear hold");
    assert_eq!(
        line.watch.warning(Severity::Error, "/d").params["cause"],
        "line"
    );
    // A rate that eased during the clear hold, far from the margin: no time left to say, and
    // the file system's figures for the level's sentence.
    let mut eased = Run::new(40 * GIB);
    eased.host = Some(host(100 * GIB, 60 * GIB));
    eased.fill(10 * GIB, 76);
    eased.free += 20 * GIB;
    assert_eq!(eased.step(0), Some(Severity::Act), "in its clear hold");
    let warning = eased.watch.warning(Severity::Act, "/d");
    assert_eq!(warning.params["cause"], "hour");
    assert!(!warning.params.contains_key("seconds_left"));
    assert_eq!(warning.params["available"], (60 * GIB).to_string());
}

/// A missed tick is not made up: after a pause the task reads once, not once per tick missed.
#[tokio::test(start_paused = true)]
async fn a_missed_tick_is_not_made_up() {
    use futures::FutureExt as _;
    let mut tick = ticker();
    tick.tick().await;
    tokio::time::advance(10 * TICK).await;
    tick.tick().await;
    assert!(
        tick.tick().now_or_never().is_none(),
        "no burst of missed ticks"
    );
}

/// The task on the real store (its free-space hook) and the real host monitor: the warning
/// reaches the status, the findings, the diagnostics and the gauge; past the margin the
/// store's own warning speaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_real_store_raises_the_warning_on_every_surface() {
    let mut config = RaftStoreConfig::new("unused");
    config.fsync_probe_samples = 0;
    let store = RaftStore::open_temp(config).await.expect("open");
    let margin = wait_until_async("the store reads its disk", async || {
        store
            .safety()
            .map(|safety| safety.margin_bytes)
            .filter(|margin| *margin > 0)
    })
    .await;
    let hook = store.config().data_dir.join(FREE_BYTES);
    let near = margin + margin / 20;
    std::fs::write(&hook, near.to_string()).expect("the free space");
    wait_until_async("the store reads the hook", async || {
        store
            .safety()
            .is_some_and(|safety| safety.free_bytes == near && safety.pressure == Pressure::Normal)
    })
    .await;
    let state = AppState::new(Arc::new(store.clone()));
    state.host().set_data_dir(store.config().data_dir.clone());
    let (stop, stopped) = watch::channel(false);
    let task = spawn(state.clone(), stopped);
    let warning = wait_until_async("the warning is set", async || {
        state
            .notices_list()
            .into_iter()
            .find(|warning| warning.code == DISK_LOW)
    })
    .await;
    assert_eq!(warning.params["severity"], "error");
    assert_eq!(warning.params["cause"], "line");
    assert_eq!(warning.params["free"], near.to_string());

    let status = crate::routes::system::status_of(&state, Timestamp::now());
    assert!(status.warnings.contains(&warning));
    let findings = crate::findings::FindingsService::new(
        Arc::new(store.clone()),
        FindingsConfig::default(),
        false,
        state.events().clone(),
    );
    findings.set_health(&status.warnings, Timestamp::now());
    let id = HealthItem {
        code: warning.code.clone(),
        detail: String::new(),
        params: warning.params.clone(),
        level: FindingLevel::Act,
    }
    .id();
    let finding = findings.index().get(&id).expect("the finding");
    assert_eq!(finding.severity, FindingLevel::Act);
    assert_eq!(finding.action, FindingAction::None);
    assert_eq!(
        finding.since.to_string(),
        warning.params["raised_at"],
        "dated when it was raised"
    );
    let document = crate::routes::system::diagnostics::document(
        status,
        tenko_auth::settings::Profile::Lab,
        Vec::new(),
        Vec::new(),
        None,
    );
    assert!(
        document
            .findings
            .iter()
            .any(|finding| finding.code == DISK_LOW && finding.severity == FindingSeverity::Error)
    );
    let text = crate::routes::metrics::render_metrics(&state);
    assert!(text.contains("\ntenko_node_disk_low 3\n"), "{text}");
    stop.send(true).expect("stop");
    task.await.expect("the task ends");

    // Past the margin the store's own warning speaks; the reading says so.
    std::fs::write(&hook, (margin - 1).to_string()).expect("the free space");
    let reading = wait_until_async("the store enters its margin", async || {
        store
            .safety()
            .filter(|safety| safety.pressure != Pressure::Normal)
    })
    .await;
    let mut watch = Watch::default();
    assert_eq!(
        watch.round(Instant::now(), Some(&reading), None),
        (Some(Severity::Error), true),
        "the store's own warning stands in place"
    );
    store.shutdown().await.expect("shutdown");
}
