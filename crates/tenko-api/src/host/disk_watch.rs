//! The disk warning `node.disk.low` (`docs/observability.md` section 4): how long until the
//! store refuses new data at the rate its headroom shrinks, and the level of the data
//! directory's file system.
//!
//! The headroom is the free space of the store's data directory above the store's margin
//! (`docs/cluster.md` section 12.12): below the margin the store takes only writes that free
//! space. The margin grows with the data, so the headroom shrinks faster than the free space.
//! One task ([`spawn`]) reads the store's disk guard every [`TICK`] on the monotonic clock and
//! keeps a day of readings; [`Watch::round`] turns them into a severity, which the task sets
//! as a condition of the status (the findings and the diagnostics read it there) and as the
//! gauge `tenko_node_disk_low`.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    metrics::{Desc, Gauge},
};
use tenko_store::{Pressure, StoreSafety};
use tokio::{sync::watch, task::JoinHandle};

use super::{HostSample, low_disk_limit};
use crate::{dto::system::StatusWarning, routes::system::DISK_LOW, state::AppState};

/// How often the store's disk is read: picked; [`SPAN`] holds ten readings.
const TICK: Duration = Duration::from_secs(60);
/// The long window: follows from the daily cycle of DHCP load and of the age prunes.
const DAY: Duration = Duration::from_secs(24 * 3_600);
/// The short window: picked.
const HOUR: Duration = Duration::from_secs(3_600);
/// The span that tells whether the headroom still shrinks: picked.
const SPAN: Duration = Duration::from_secs(600);
/// The headroom still shrinks while the span lost at least this share of the hour's loss:
/// half the span's even share of the hour (the half picked), so a fill that slows to half its
/// rate still counts.
const SHARE: i64 = 12;
/// How long the hour's rate must ask for `act` or `error` while the headroom still shrinks:
/// the span and a write of five minutes (picked), so that a write shorter than that raises
/// nothing.
const HOLD: Duration = Duration::from_secs(900);
/// How long a severity's clear must hold before it clears: picked, equal to the span.
const CLEAR_HOLD: Duration = Duration::from_secs(600);
/// A window that lost less headroom has no rate: picked; less is the noise of logs and the
/// journal on the same file system.
const FLOOR: i64 = 64 * 1024 * 1024;
/// The time left in seconds that raises `review`, `act` and `error`: picked, what a person
/// needs (a larger volume; the next working day; on call, the shell). Each clears above twice
/// its time, picked: a rate is noisier than a reading.
const LEFT: [f64; 3] = [7.0 * 86_400.0, 86_400.0, 7_200.0];
/// The severity of a data directory's file system under its level ([`low_disk_limit`]): a
/// level alone is to review; what needs action is decided by the rates and the store's line.
const LEVEL: Severity = Severity::Review;
/// What a person does about it: no page frees disk space.
const NEXT_STEP: &str = "Free space outside Tenko's store: the system journal, backups (move them \
                         to another disk), and copies under upgrade-backups/ of versions you will \
                         not go back to. Never delete anything under store/.";

/// `tenko_node_disk_low`: the severity of the warning.
pub(crate) static DISK_LOW_GAUGE: Gauge = Gauge::new(Desc::gauge(
    "tenko_node_disk_low",
    "The disk warning node.disk.low: 0 none, 1 review, 2 act, 3 error; also while the store's own disk warning stands in its place.",
));

/// The rules that raise a severity, as its param `cause` names them: the hour's rate, the day's
/// rate, the free space near the store's margin (or unreadable), the file system's level.
const BY_HOUR: &str = "hour";
const BY_DAY: &str = "day";
const BY_LINE: &str = "line";
const BY_LEVEL: &str = "level";

/// The severity of `node.disk.low` (its param `severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The day's rate leaves under a week, or the level of the file system.
    Review,
    /// A day or less.
    Act,
    /// Two hours or less, or the store's margin is near.
    Error,
}

impl Severity {
    const ALL: [Self; 3] = [Self::Review, Self::Act, Self::Error];

    fn word(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Act => "act",
            Self::Error => "error",
        }
    }

    /// The severity a warning's `severity` param names.
    pub fn from_param(params: &BTreeMap<String, String>) -> Option<Self> {
        let word = params.get("severity")?;
        Self::ALL
            .into_iter()
            .find(|severity| severity.word() == word)
    }
}

/// One reading of the store's disk guard that the rates may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reading {
    /// Free bytes of the store's data directory.
    free: u64,
    /// The store's margin line.
    margin: u64,
}

impl Reading {
    /// The reading of `safety`; `None` before the guard read its disk (a margin of 0, or a free
    /// space of `u64::MAX`, its initial value, which it stores apart from the margin) and while
    /// it cannot read it (the guard then keeps its last value).
    fn of(safety: &StoreSafety) -> Option<Self> {
        (safety.margin_bytes > 0 && safety.free_bytes != u64::MAX && !safety.free_unknown)
            .then_some(Self {
                free: safety.free_bytes,
                margin: safety.margin_bytes,
            })
    }

    /// Free bytes above the margin, negative below it.
    fn headroom(self) -> i64 {
        signed(self.free).saturating_sub(signed(self.margin))
    }

    /// The line under which `error` is raised: the band above the margin in which a store that
    /// entered the margin stays there.
    fn line(self) -> u64 {
        with_band(self.margin)
    }
}

fn signed(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

/// `line` and the 10 percent above it that the store's guard waits for before it leaves a
/// state (`docs/cluster.md` section 12.12).
fn with_band(line: u64) -> u64 {
    line.saturating_add(line / 10)
}

/// The readings of one task and the severities they raised.
#[derive(Debug, Default)]
pub struct Watch {
    /// The time and headroom of each reading, oldest first: a day, and the newest older one.
    ring: VecDeque<(Instant, i64)>,
    /// The newest reading.
    last: Option<Reading>,
    /// The size and the available bytes of the data directory's file system.
    host: Option<(u64, u64)>,
    /// Per severity: the rule that raised it (`None` while it is not raised), and since when
    /// its clear holds.
    raised: [Option<&'static str>; 3],
    clearing: [Option<Instant>; 3],
    /// Since when the hour's rate asks for `act` while the headroom still shrinks.
    filling: Option<Instant>,
    /// When this episode's first severity was raised (the wall clock, for the finding).
    raised_at: Option<Timestamp>,
}

impl Watch {
    /// Takes the store's reading `safety` (`None` for a store without one) and the host's
    /// figures at `now`, and answers the severity its rules raise, and whether the store's own
    /// warning stands in place of the finding (its pressure is not normal, or it cannot read its
    /// free space). The rules run on meanwhile, on the readings the rates may use.
    pub fn round(
        &mut self,
        now: Instant,
        safety: Option<&StoreSafety>,
        host: Option<&HostSample>,
    ) -> (Option<Severity>, bool) {
        if let Some(reading) = safety.and_then(Reading::of) {
            // A reading taken while the store compacts or builds a snapshot measures its work (a
            // second copy beside the first), not what the disk holds: the rates skip it, the line
            // reads it.
            if safety.is_some_and(|safety| !safety.compacting && !safety.snapshotting) {
                self.ring.push_back((now, reading.headroom()));
                while self
                    .ring
                    .get(1)
                    .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= DAY)
                {
                    self.ring.pop_front();
                }
            }
            self.last = Some(reading);
        }
        let unknown = safety.is_some_and(|safety| safety.free_unknown);
        let hidden = unknown || safety.is_some_and(|safety| safety.pressure != Pressure::Normal);
        self.host = host.and_then(|host| Some((host.disk_total?, host.disk_available?)));
        let (hour, day) = (self.left(HOUR), self.left(DAY));
        let under = |left: Option<f64>, severity: Severity| {
            left.is_some_and(|left| left < LEFT[severity as usize])
        };
        let over = |left: Option<f64>, severity: Severity| {
            left.is_none_or(|left| left > 2.0 * LEFT[severity as usize])
        };
        let filling = self.still_filling();
        let since = self.filling.unwrap_or(now);
        self.filling = (filling && under(hour, Severity::Act)).then_some(since);
        let held = self
            .filling
            .is_some_and(|since| now.saturating_duration_since(since) >= HOLD);
        let line = self.last.map(|reading| (reading.free, reading.line()));
        let mut raise = [
            under(day, Severity::Review).then_some(BY_DAY),
            if held {
                Some(BY_HOUR)
            } else {
                under(day, Severity::Act).then_some(BY_DAY)
            },
            if held && under(hour, Severity::Error) {
                Some(BY_HOUR)
            } else {
                line.is_some_and(|(free, line)| free < line)
                    .then_some(BY_LINE)
            },
        ];
        let mut clear = [
            over(day, Severity::Review),
            over(hour, Severity::Act) && over(day, Severity::Act),
            over(hour, Severity::Error) && line.is_none_or(|(free, line)| free >= with_band(line)),
        ];
        if let Some((total, available)) = self.host {
            let limit = low_disk_limit(total);
            if available < limit {
                raise[LEVEL as usize].get_or_insert(BY_LEVEL);
            }
            clear[LEVEL as usize] &= available >= with_band(limit);
        }
        let states = self.raised.iter_mut().zip(&mut self.clearing);
        for ((cause, clearing), (raise, clear)) in states.zip(raise.into_iter().zip(clear)) {
            let since = clear
                .then(|| clearing.unwrap_or(now))
                .filter(|_| cause.is_some() && raise.is_none());
            if raise.is_some() {
                *cause = raise;
            } else if since.is_some_and(|since| now.saturating_duration_since(since) >= CLEAR_HOLD)
            {
                *cause = None;
            }
            *clearing = since.filter(|_| cause.is_some());
        }
        let severity = Severity::ALL
            .into_iter()
            .rev()
            .find(|severity| self.raised[*severity as usize].is_some());
        if severity.is_some() {
            self.raised_at.get_or_insert_with(Timestamp::now);
        } else {
            self.raised_at = None;
        }
        (severity, hidden)
    }

    /// The warning of `severity` for the data directory at `path`: the figures of the rule
    /// that raised it, which the UI words from the params, then what to do.
    pub fn warning(&self, severity: Severity, path: &str) -> StatusWarning {
        let mut params = BTreeMap::new();
        let mut set = |name: &str, value: String| {
            params.insert(name.to_owned(), value);
        };
        let cause = self.raised[severity as usize].unwrap_or(BY_LEVEL);
        set("severity", severity.word().to_owned());
        set("cause", cause.to_owned());
        if let Some(at) = self.raised_at {
            set("raised_at", at.to_string());
        }
        if let Some((total, available)) = self.host {
            set("total", total.to_string());
            set("available", available.to_string());
            set("limit", low_disk_limit(total).to_string());
        }
        if let Some(reading) = self.last {
            set("free", reading.free.to_string());
            set("margin", reading.margin.to_string());
        }
        // A rate that eased during the clear hold has no time left to say.
        let window = match cause {
            BY_HOUR => Some(HOUR),
            BY_DAY => Some(DAY),
            _ => None,
        };
        if let Some((window, left, rate)) =
            window.and_then(|window| Some((window, self.left(window)?, self.rate(window)?)))
        {
            set("bytes", whole(rate * window.as_secs_f64()).to_string());
            set("seconds_left", whole(left).to_string());
        }
        let figures: Vec<String> = params
            .iter()
            .map(|(name, value)| format!("{name} {value}"))
            .collect();
        params.insert("path".to_owned(), path.to_owned());
        StatusWarning {
            code: DISK_LOW.to_owned(),
            detail: format!("low disk space ({}). {NEXT_STEP}", figures.join(", ")),
            params,
        }
    }

    /// The headroom lost since the newest reading at least `window` before the newest one,
    /// and the seconds between them.
    fn lost(&self, window: Duration) -> Option<(i64, f64)> {
        let &(now, headroom) = self.ring.back()?;
        let &(then, before) = self
            .ring
            .iter()
            .rev()
            .find(|(at, _)| now.saturating_duration_since(*at) >= window)?;
        Some((
            before.saturating_sub(headroom),
            now.saturating_duration_since(then).as_secs_f64(),
        ))
    }

    /// Bytes of headroom lost a second over `window`; none below [`FLOOR`].
    #[allow(clippy::cast_precision_loss, reason = "a rate in bytes a second")]
    fn rate(&self, window: Duration) -> Option<f64> {
        let (lost, seconds) = self.lost(window).filter(|(lost, _)| *lost >= FLOOR)?;
        Some(lost as f64 / seconds)
    }

    /// Seconds until the headroom is gone at the rate over `window`.
    #[allow(clippy::cast_precision_loss, reason = "a time in seconds")]
    fn left(&self, window: Duration) -> Option<f64> {
        let rate = self.rate(window)?;
        let &(_, headroom) = self.ring.back()?;
        Some(headroom.max(0) as f64 / rate)
    }

    /// Whether the last [`SPAN`] lost at least its share of the last hour's loss.
    fn still_filling(&self) -> bool {
        match (self.lost(SPAN), self.lost(HOUR)) {
            (Some((span, _)), Some((hour, _))) => hour > 0 && span.saturating_mul(SHARE) >= hour,
            _ => false,
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a positive figure of a param"
)]
fn whole(value: f64) -> u64 {
    value.max(0.0).round() as u64
}

/// The tick of the task: a missed tick is not made up, since after a pause it would repeat
/// one moment's reading.
fn ticker() -> tokio::time::Interval {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

/// The gauge's value for a round's `severity`: it follows the rules also while the store's own
/// warning stands in place (`hidden`: the line has raised `error` by then, or the store cannot read
/// its free space and refuses writes, which raises nothing), so no `error` outlasts the gap.
fn gauge_value(severity: Option<Severity>, hidden: bool) -> f64 {
    let severity = if hidden {
        Some(Severity::Error)
    } else {
        severity
    };
    severity.map_or(0.0, |severity| f64::from(severity as u8) + 1.0)
}

/// Sets the gauge and the condition of the status from a round's `severity`, shown unless
/// `hidden`, and answers its warning.
fn publish(
    state: &AppState,
    disk: &Watch,
    (severity, hidden): (Option<Severity>, bool),
) -> Option<StatusWarning> {
    DISK_LOW_GAUGE.set(gauge_value(severity, hidden));
    let path = state
        .host()
        .data_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let warning = severity.map(|severity| disk.warning(severity, &path));
    match warning.as_ref().filter(|_| !hidden) {
        Some(warning) => state.set_notice(warning.clone()),
        None => state.clear_notice(DISK_LOW),
    }
    warning
}

/// Starts the task that reads the store's disk every [`TICK`] and keeps `node.disk.low` among
/// the conditions of the status and in its gauge, until `stop` changes.
pub fn spawn(state: AppState, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut disk = Watch::default();
        let mut shown = (None, false);
        let mut tick = ticker();
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stop.changed() => return,
            }
            let safety = state.store.safety();
            let host = state.host().current();
            let now = disk.round(Instant::now(), safety.as_ref(), host.as_ref());
            let warning = publish(&state, &disk, now);
            // The one place where a change of severity is seen.
            let severity = now.0;
            if now != shown {
                let word = severity.map(Severity::word);
                let detail = warning
                    .as_ref()
                    .map_or("cleared", |warning| warning.detail.as_str());
                if now.1 && !shown.1 {
                    tracing::info!(
                        code = DISK_LOW,
                        severity = word,
                        "the store's own disk warning stands in place of node.disk.low"
                    );
                } else if severity > shown.0 {
                    tracing::warn!(code = DISK_LOW, severity = word, "{detail}");
                } else {
                    tracing::info!(code = DISK_LOW, severity = word, "{detail}");
                }
                shown = now;
            }
        }
    })
}

#[cfg(test)]
mod tests;
