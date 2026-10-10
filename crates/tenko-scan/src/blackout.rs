//! Blackout windows (SCAN-06): times of the week when no method that sends packets runs,
//! such as office hours. Windows are written like `mon-fri 08:00-17:00` and read in a time
//! zone, by default the system's, so they follow daylight saving time.
//!
//! A window is `[<days>] <HH:MM>-<HH:MM>`, in any case and with extra spaces:
//!
//! * `<days>` is `daily` (the default when left out), `weekdays` (Monday to Friday),
//!   `weekends` (Saturday and Sunday), one day (`mon`, `tue`, `wed`, `thu`, `fri`, `sat`,
//!   `sun`), a range of days (`mon-fri`; `fri-mon` wraps over the weekend) or a comma list of
//!   days and ranges (`mon,wed,fri-sun`).
//! * The times run from `00:00` to `23:59`; `24:00` is allowed as the end. An end before the
//!   start crosses midnight: `sun 22:00-02:00` runs from Sunday 22:00 to Monday 02:00, and
//!   the day names the start. A window of zero length (`08:00-08:00`) is refused.
//!
//! The times are wall-clock times in the zone. A window lasts from its start to its end, each
//! resolved with the compatible rule of jiff (a time that falls in the gap of a spring
//! change moves forward, a time that occurs twice in an autumn change is the first one), so
//! it is shorter or longer on the days the clocks change.

use std::time::SystemTime;

use jiff::{
    Span, Timestamp,
    civil::{Date, Weekday},
    tz::TimeZone,
};

use crate::error::ScanError;

/// A window as people write it, quoted in error messages.
const EXAMPLE: &str = "mon-fri 08:00-17:00";

/// Windows are looked up this many days ahead of the day in question; a blackout that
/// lasts longer than this (`daily 00:00-24:00`) is reported up to about this far ahead.
const HORIZON_DAYS: i64 = 8;

/// Minutes in a day.
const DAY_MINUTES: u16 = 24 * 60;

/// The days of the week as bits, Monday being bit 0.
const ALL_DAYS: u8 = 0b111_1111;
const WEEKDAYS: u8 = 0b001_1111;
const WEEKENDS: u8 = 0b110_0000;

/// The blackout windows of a probe.
#[derive(Debug, Clone)]
pub struct Blackout {
    specs: Vec<String>,
    windows: Vec<Window>,
    zone: TimeZone,
    zone_name: String,
}

impl Default for Blackout {
    fn default() -> Self {
        Self {
            specs: Vec::new(),
            windows: Vec::new(),
            zone: TimeZone::system(),
            zone_name: SYSTEM_ZONE.to_owned(),
        }
    }
}

/// One window of the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    /// The days the window starts on, as bits with Monday as bit 0.
    days: u8,
    /// Start in minutes after midnight, 0 to 1439.
    start: u16,
    /// End in minutes after midnight, 0 to 1440. An end that is not after the start lies on
    /// the day after the one the window starts on, and so does 1440.
    end: u16,
}

/// The name of the zone when none is configured.
const SYSTEM_ZONE: &str = "system";

impl Blackout {
    /// Parses `specs` in the time zone `zone` (an IANA name such as `Europe/Stockholm`;
    /// `None` is the system time zone).
    ///
    /// # Errors
    ///
    /// `scan.config` for a window or a zone that does not parse.
    pub fn parse(specs: &[String], zone: Option<&str>) -> Result<Self, ScanError> {
        let (zone, zone_name) = resolve_zone(zone)?;
        let windows = specs
            .iter()
            .map(|spec| {
                parse_window(spec).map_err(|reason| {
                    ScanError::config(format!(
                        "invalid blackout window {}: {reason}; write a window as \
                         [days] HH:MM-HH:MM, for example \"{EXAMPLE}\"",
                        quote(spec)
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            specs: specs.to_vec(),
            windows,
            zone,
            zone_name,
        })
    }

    /// Whether there are no windows.
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// The time zone the windows are read in: its IANA name, or `system`.
    pub fn zone_name(&self) -> String {
        self.zone_name.clone()
    }

    /// The windows as they were written, for the status.
    pub fn windows(&self) -> &[String] {
        &self.specs
    }

    /// The end of the blackout that `at` falls in; `None` when `at` is outside every
    /// window. Overlapping and adjacent windows count as one, also across midnight and
    /// across days. A blackout that never ends is reported up to about a week and a half
    /// ahead; the caller looks again then.
    pub fn active_until(&self, at: SystemTime) -> Option<SystemTime> {
        if self.windows.is_empty() {
            return None;
        }
        let at = Timestamp::try_from(at).ok()?;
        let today = at.to_zoned(self.zone.clone()).date();
        let mut spans = self.spans(today, 2, HORIZON_DAYS + 1);
        spans.sort_unstable();
        let mut merged: Vec<(Timestamp, Timestamp)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
            .into_iter()
            .find(|(start, end)| *start <= at && at < *end)
            .map(|(_, end)| end.into())
    }

    /// The start of the next window that begins strictly after `at`, looking at most eight
    /// days ahead; `None` without windows. From outside a blackout this is the moment the
    /// next blackout begins.
    pub fn next_start(&self, at: SystemTime) -> Option<SystemTime> {
        if self.windows.is_empty() {
            return None;
        }
        let at = Timestamp::try_from(at).ok()?;
        let today = at.to_zoned(self.zone.clone()).date();
        self.spans(today, 0, HORIZON_DAYS)
            .into_iter()
            .map(|(start, _)| start)
            .filter(|start| *start > at)
            .min()
            .map(SystemTime::from)
    }

    /// Every instance of every window that starts on one of the days from `back` days
    /// before `around` to `ahead` days after it, as instants. Instances without length
    /// (a window that lies entirely in the gap of a spring change) are left out.
    fn spans(&self, around: Date, back: i64, ahead: i64) -> Vec<(Timestamp, Timestamp)> {
        let mut spans = Vec::new();
        let Ok(mut date) = around.checked_add(Span::new().days(-back)) else {
            return spans;
        };
        for _ in 0..=(back + ahead) {
            let day = weekday_bit(date.weekday());
            for window in self
                .windows
                .iter()
                .copied()
                .filter(|window| window.days & day != 0)
            {
                if let Some((start, end)) = self.instance(window, date)
                    && start < end
                {
                    spans.push((start, end));
                }
            }
            match date.tomorrow() {
                Ok(next) => date = next,
                Err(_) => break,
            }
        }
        spans
    }

    /// The instants a `window` that starts on `date` begins and ends.
    fn instance(&self, window: Window, date: Date) -> Option<(Timestamp, Timestamp)> {
        let start = self.resolve(date, window.start)?;
        let end_date = if window.end <= window.start || window.end == DAY_MINUTES {
            date.tomorrow().ok()?
        } else {
            date
        };
        let end = self.resolve(end_date, window.end % DAY_MINUTES)?;
        Some((start, end))
    }

    /// The instant of `minutes` after midnight on `date` in the zone.
    fn resolve(&self, date: Date, minutes: u16) -> Option<Timestamp> {
        let hour = i8::try_from(minutes / 60).ok()?;
        let minute = i8::try_from(minutes % 60).ok()?;
        self.zone
            .to_zoned(date.at(hour, minute, 0, 0))
            .ok()
            .map(|zoned| zoned.timestamp())
    }
}

/// The zone for `name`; the system zone for `None`, an empty name or `system`.
fn resolve_zone(name: Option<&str>) -> Result<(TimeZone, String), ScanError> {
    let name = name
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.eq_ignore_ascii_case(SYSTEM_ZONE));
    let Some(name) = name else {
        return Ok((TimeZone::system(), SYSTEM_ZONE.to_owned()));
    };
    match TimeZone::get(name) {
        Ok(zone) => {
            let canonical = zone.iana_name().unwrap_or(name).to_owned();
            Ok((zone, canonical))
        }
        Err(_) => Err(ScanError::config(format!(
            "unknown time zone {} for the blackout windows; use an IANA name such as \
             \"Europe/Stockholm\", or leave the zone out for the system time zone",
            quote(name)
        ))),
    }
}

/// The bit of a weekday in a day set.
fn weekday_bit(weekday: Weekday) -> u8 {
    1 << weekday.to_monday_zero_offset().clamp(0, 6)
}

/// `text` in double quotes with control characters escaped, for error messages.
fn quote(text: &str) -> String {
    let shown: String = text.chars().take(80).flat_map(char::escape_debug).collect();
    if text.chars().count() > 80 {
        format!("\"{shown}...\"")
    } else {
        format!("\"{shown}\"")
    }
}

/// Reads one window; the error is the reason, without the text of the window.
fn parse_window(spec: &str) -> Result<Window, String> {
    let lower = spec.trim().to_lowercase();
    if lower.is_empty() {
        return Err("the window is empty".to_owned());
    }
    // Day names hold no digits, so the first digit starts the time range.
    let Some(split) = lower.find(|c: char| c.is_ascii_digit()) else {
        return Err("there is no time of day".to_owned());
    };
    let days = parse_days(lower[..split].trim())?;
    let Some((from, to)) = lower[split..].split_once('-') else {
        return Err("the time range needs a start and an end, like 08:00-17:00".to_owned());
    };
    let start = parse_clock(from.trim(), false)?;
    let end = parse_clock(to.trim(), true)?;
    if start == end {
        return Err("the start and the end are the same, so the window has no length".to_owned());
    }
    Ok(Window { days, start, end })
}

/// Reads `HH:MM` as minutes after midnight; `24:00` only when `allow_24`.
fn parse_clock(text: &str, allow_24: bool) -> Result<u16, String> {
    let bad = || {
        format!(
            "\"{}\" is not a time between 00:00 and 23:59",
            text.escape_debug()
        )
    };
    let (hour, minute) = text.split_once(':').ok_or_else(bad)?;
    let digits = |part: &str, most: usize| {
        (1..=most).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
    };
    if !digits(hour, 2) || !digits(minute, 2) || minute.len() != 2 {
        return Err(bad());
    }
    let hour: u16 = hour.parse().map_err(|_| bad())?;
    let minute: u16 = minute.parse().map_err(|_| bad())?;
    if minute > 59 || hour > 24 {
        return Err(bad());
    }
    if hour == 24 {
        return match (minute, allow_24) {
            (0, true) => Ok(DAY_MINUTES),
            (0, false) => Err("24:00 is only allowed as an end".to_owned()),
            _ => Err(bad()),
        };
    }
    Ok(hour * 60 + minute)
}

/// Reads a list of days into a set of bits; nothing at all is every day.
fn parse_days(text: &str) -> Result<u8, String> {
    if text.is_empty() {
        return Ok(ALL_DAYS);
    }
    let mut days = 0;
    for item in text.split(',') {
        let item = item.trim();
        days |= match item {
            "" => return Err("the list of days has an empty entry".to_owned()),
            "daily" => ALL_DAYS,
            "weekdays" => WEEKDAYS,
            "weekends" => WEEKENDS,
            _ => match item.split_once('-') {
                Some((from, to)) => day_range(day_index(from.trim())?, day_index(to.trim())?),
                None => 1 << day_index(item)?,
            },
        };
    }
    Ok(days)
}

/// The days from `from` to `to` inclusive, wrapping over the end of the week.
fn day_range(from: u8, to: u8) -> u8 {
    let mut days = 0;
    let mut day = from;
    loop {
        days |= 1 << day;
        if day == to {
            return days;
        }
        day = (day + 1) % 7;
    }
}

/// Monday is 0 and Sunday is 6.
fn day_index(name: &str) -> Result<u8, String> {
    Ok(match name {
        "mon" => 0,
        "tue" => 1,
        "wed" => 2,
        "thu" => 3,
        "fri" => 4,
        "sat" => 5,
        "sun" => 6,
        _ => {
            return Err(format!(
                "unknown day \"{}\"; use mon, tue, wed, thu, fri, sat, sun, weekdays, weekends \
                 or daily, and separate several days with commas",
                name.escape_debug()
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use jiff::civil;
    use proptest::prelude::*;

    use super::*;

    const STOCKHOLM: &str = "Europe/Stockholm";

    fn blackout(specs: &[&str], zone: &str) -> Blackout {
        let specs: Vec<String> = specs.iter().map(|spec| (*spec).to_owned()).collect();
        Blackout::parse(&specs, Some(zone)).expect("the windows parse")
    }

    /// A local wall-clock time in `zone`; never used for times in a gap or a fold.
    fn local(
        zone: &str,
        (year, month, day): (i16, i8, i8),
        (hour, minute): (i8, i8),
    ) -> SystemTime {
        civil::date(year, month, day)
            .at(hour, minute, 0, 0)
            .in_tz(zone)
            .expect("a valid local time")
            .timestamp()
            .into()
    }

    /// An instant written in UTC.
    fn utc(text: &str) -> SystemTime {
        text.parse::<Timestamp>().expect("a valid instant").into()
    }

    /// Monday 2026-06-01 to Sunday 2026-06-07 are an ordinary week in summer time.
    fn stockholm(day: i8, hour: i8, minute: i8) -> SystemTime {
        local(STOCKHOLM, (2026, 6, day), (hour, minute))
    }

    fn error_of(spec: &str) -> ScanError {
        Blackout::parse(&[spec.to_owned()], Some("UTC")).expect_err("the window is refused")
    }

    #[test]
    fn office_hours_in_stockholm() {
        let office = blackout(&["mon-fri 08:00-17:00"], STOCKHOLM);
        assert_eq!(office.active_until(stockholm(1, 7, 59)), None);
        assert_eq!(
            office.active_until(stockholm(1, 8, 0)),
            Some(stockholm(1, 17, 0))
        );
        assert_eq!(
            office.active_until(stockholm(1, 12, 30)),
            Some(stockholm(1, 17, 0))
        );
        assert_eq!(
            office.active_until(stockholm(1, 16, 59)),
            Some(stockholm(1, 17, 0))
        );
        assert_eq!(office.active_until(stockholm(1, 17, 0)), None);
        assert_eq!(
            office.active_until(stockholm(5, 9, 0)),
            Some(stockholm(5, 17, 0))
        );
        assert_eq!(office.active_until(stockholm(6, 10, 0)), None, "Saturday");
        assert_eq!(office.active_until(stockholm(7, 10, 0)), None, "Sunday");
    }

    #[test]
    fn next_start_is_strictly_after() {
        let office = blackout(&["mon-fri 08:00-17:00"], STOCKHOLM);
        assert_eq!(
            office.next_start(stockholm(1, 6, 0)),
            Some(stockholm(1, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(1, 7, 59)),
            Some(stockholm(1, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(1, 8, 0)),
            Some(stockholm(2, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(1, 17, 0)),
            Some(stockholm(2, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(5, 17, 0)),
            Some(stockholm(8, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(6, 12, 0)),
            Some(stockholm(8, 8, 0))
        );
        assert_eq!(
            office.next_start(stockholm(7, 23, 59)),
            Some(stockholm(8, 8, 0))
        );
    }

    #[test]
    fn windows_are_read_in_the_configured_zone() {
        // 06:30 UTC is 08:30 in Stockholm in June.
        let at = utc("2026-06-01T06:30:00Z");
        let in_stockholm = blackout(&["mon-fri 08:00-17:00"], STOCKHOLM);
        assert_eq!(
            in_stockholm.active_until(at),
            Some(utc("2026-06-01T15:00:00Z"))
        );
        let in_utc = blackout(&["mon-fri 08:00-17:00"], "UTC");
        assert_eq!(in_utc.active_until(at), None);
        assert_eq!(in_utc.next_start(at), Some(utc("2026-06-01T08:00:00Z")));
        assert_eq!(
            in_utc.active_until(utc("2026-06-01T08:00:00Z")),
            Some(utc("2026-06-01T17:00:00Z"))
        );
    }

    #[test]
    fn window_crossing_midnight() {
        let night = blackout(&["sun 22:00-02:00"], STOCKHOLM);
        assert_eq!(night.active_until(stockholm(7, 21, 59)), None);
        assert_eq!(
            night.active_until(stockholm(7, 22, 0)),
            Some(stockholm(8, 2, 0))
        );
        assert_eq!(
            night.active_until(stockholm(7, 23, 30)),
            Some(stockholm(8, 2, 0))
        );
        assert_eq!(
            night.active_until(stockholm(8, 0, 0)),
            Some(stockholm(8, 2, 0))
        );
        assert_eq!(
            night.active_until(stockholm(8, 1, 59)),
            Some(stockholm(8, 2, 0))
        );
        assert_eq!(night.active_until(stockholm(8, 2, 0)), None);
        assert_eq!(
            night.active_until(stockholm(6, 23, 0)),
            None,
            "Saturday night"
        );
        // Sunday 2026-05-31 22:00 to Monday 2026-06-01 02:00 is the window of the week before.
        assert_eq!(
            night.active_until(stockholm(1, 1, 0)),
            Some(stockholm(1, 2, 0))
        );
        assert_eq!(
            night.active_until(stockholm(2, 1, 0)),
            None,
            "Tuesday night"
        );
        assert_eq!(
            night.next_start(stockholm(8, 3, 0)),
            Some(stockholm(14, 22, 0))
        );
        assert_eq!(
            night.next_start(stockholm(7, 23, 0)),
            Some(stockholm(14, 22, 0))
        );
    }

    #[test]
    fn end_at_midnight_and_twenty_four_hundred_are_the_same() {
        let a = blackout(&["daily 22:00-24:00"], STOCKHOLM);
        let b = blackout(&["daily 22:00-00:00"], STOCKHOLM);
        for hour in [21, 22, 23] {
            assert_eq!(
                a.active_until(stockholm(3, hour, 30)),
                b.active_until(stockholm(3, hour, 30))
            );
        }
        assert_eq!(
            a.active_until(stockholm(3, 23, 0)),
            Some(stockholm(4, 0, 0))
        );
    }

    #[test]
    fn touching_and_overlapping_windows_are_one_blackout() {
        let touching = blackout(&["mon-fri 08:00-12:00", "mon-fri 12:00-17:00"], STOCKHOLM);
        assert_eq!(
            touching.active_until(stockholm(2, 9, 0)),
            Some(stockholm(2, 17, 0))
        );
        assert_eq!(
            touching.active_until(stockholm(2, 12, 0)),
            Some(stockholm(2, 17, 0))
        );
        assert_eq!(touching.active_until(stockholm(2, 17, 0)), None);

        let overlapping = blackout(&["mon-fri 12:00-17:00", "mon-fri 08:00-13:00"], STOCKHOLM);
        assert_eq!(
            overlapping.active_until(stockholm(2, 8, 0)),
            Some(stockholm(2, 17, 0))
        );

        let nested = blackout(&["mon-fri 08:00-17:00", "mon-fri 10:00-11:00"], STOCKHOLM);
        assert_eq!(
            nested.active_until(stockholm(2, 10, 30)),
            Some(stockholm(2, 17, 0))
        );

        let gap = blackout(&["mon-fri 08:00-12:00", "mon-fri 13:00-17:00"], STOCKHOLM);
        assert_eq!(
            gap.active_until(stockholm(2, 9, 0)),
            Some(stockholm(2, 12, 0))
        );
        assert_eq!(gap.active_until(stockholm(2, 12, 30)), None);
        assert_eq!(
            gap.active_until(stockholm(2, 13, 0)),
            Some(stockholm(2, 17, 0))
        );
    }

    #[test]
    fn chains_run_through_midnight_and_across_days() {
        let across_midnight = blackout(&["daily 22:00-00:00", "daily 00:00-06:00"], STOCKHOLM);
        assert_eq!(
            across_midnight.active_until(stockholm(3, 23, 0)),
            Some(stockholm(4, 6, 0))
        );
        assert_eq!(
            across_midnight.active_until(stockholm(4, 5, 0)),
            Some(stockholm(4, 6, 0))
        );
        assert_eq!(across_midnight.active_until(stockholm(4, 6, 0)), None);

        let across_days = blackout(
            &["fri 20:00-24:00", "sat 00:00-08:00", "sat 08:00-10:00"],
            STOCKHOLM,
        );
        assert_eq!(
            across_days.active_until(stockholm(5, 21, 0)),
            Some(stockholm(6, 10, 0))
        );

        let crossing = blackout(&["fri 22:00-02:00", "sat 02:00-06:00"], STOCKHOLM);
        assert_eq!(
            crossing.active_until(stockholm(5, 23, 0)),
            Some(stockholm(6, 6, 0))
        );
        assert_eq!(
            crossing.active_until(stockholm(6, 3, 0)),
            Some(stockholm(6, 6, 0))
        );
    }

    #[test]
    fn a_blackout_without_end_is_reported_up_to_the_horizon() {
        let always = blackout(&["daily 00:00-24:00"], STOCKHOLM);
        let at = stockholm(3, 12, 0);
        let until = always.active_until(at).expect("always active");
        let ahead = until.duration_since(at).expect("later than at");
        assert!(
            ahead >= std::time::Duration::from_secs(7 * 24 * 3600),
            "{ahead:?}"
        );
        assert!(
            ahead <= std::time::Duration::from_secs(11 * 24 * 3600),
            "{ahead:?}"
        );
        assert!(always.next_start(at).expect("a next start") > at);
    }

    fn active_days(spec: &str) -> Vec<bool> {
        let windows = blackout(&[spec], STOCKHOLM);
        (1..=7)
            .map(|day| windows.active_until(stockholm(day, 8, 30)).is_some())
            .collect()
    }

    #[test]
    fn day_lists_and_ranges() {
        let t = true;
        let f = false;
        // Monday 2026-06-01 first.
        assert_eq!(
            active_days("mon,wed,fri-sun 08:00-09:00"),
            [t, f, t, f, t, t, t]
        );
        assert_eq!(active_days("mon-fri 08:00-09:00"), [t, t, t, t, t, f, f]);
        assert_eq!(active_days("fri-mon 08:00-09:00"), [t, f, f, f, t, t, t]);
        assert_eq!(active_days("sat-sun 08:00-09:00"), [f, f, f, f, f, t, t]);
        assert_eq!(active_days("sun-tue 08:00-09:00"), [t, t, f, f, f, f, t]);
        assert_eq!(active_days("wed 08:00-09:00"), [f, f, t, f, f, f, f]);
        assert_eq!(active_days("thu-thu 08:00-09:00"), [f, f, f, t, f, f, f]);
        assert_eq!(active_days("weekdays 08:00-09:00"), [t, t, t, t, t, f, f]);
        assert_eq!(active_days("weekends 08:00-09:00"), [f, f, f, f, f, t, t]);
        assert_eq!(
            active_days("weekends,mon 08:00-09:00"),
            [t, f, f, f, f, t, t]
        );
        assert_eq!(active_days("daily 08:00-09:00"), [t; 7]);
        assert_eq!(active_days("08:00-09:00"), [t; 7], "days default to daily");
        assert_eq!(active_days("mon-sun 08:00-09:00"), [t; 7]);
    }

    #[test]
    fn spelling_is_forgiving() {
        let canonical = blackout(&["mon-fri 08:00-17:00"], STOCKHOLM);
        for spec in [
            "  MON-FRI   08:00-17:00  ",
            "Mon-Fri 8:00-17:00",
            "mon - fri 08:00 - 17:00",
            "\tmon-fri\t08:00-17:00",
            "MON-fri 08:00-17:00",
        ] {
            let other = blackout(&[spec], STOCKHOLM);
            for (day, hour) in [(1, 7), (1, 8), (3, 16), (5, 17), (6, 10)] {
                assert_eq!(
                    other.active_until(stockholm(day, hour, 0)),
                    canonical.active_until(stockholm(day, hour, 0)),
                    "{spec:?}"
                );
            }
        }
    }

    #[test]
    fn spring_change_makes_a_window_shorter() {
        // 2026-03-29: at 02:00 the clocks go to 03:00 (01:00 UTC) in Stockholm.
        let night = blackout(&["daily 01:00-04:00"], STOCKHOLM);
        // 01:00 CET is 00:00 UTC and 04:00 CEST is 02:00 UTC: the window lasts two hours.
        assert_eq!(
            night.active_until(utc("2026-03-29T00:30:00Z")),
            Some(utc("2026-03-29T02:00:00Z"))
        );
        assert_eq!(
            night.active_until(utc("2026-03-29T01:30:00Z")),
            Some(utc("2026-03-29T02:00:00Z"))
        );
        assert_eq!(night.active_until(utc("2026-03-29T02:00:00Z")), None);
        assert_eq!(night.active_until(utc("2026-03-28T23:59:00Z")), None);
        // The day before it has its three hours.
        assert_eq!(
            night.active_until(utc("2026-03-28T00:30:00Z")),
            Some(utc("2026-03-28T03:00:00Z"))
        );
        assert_eq!(
            night.next_start(utc("2026-03-28T12:00:00Z")),
            Some(utc("2026-03-29T00:00:00Z"))
        );
        assert_eq!(
            night.next_start(utc("2026-03-29T12:00:00Z")),
            Some(utc("2026-03-29T23:00:00Z"))
        );
    }

    #[test]
    fn spring_change_swallows_a_window_in_the_gap() {
        // 02:15 to 02:45 on 2026-03-29 does not exist in Stockholm; both ends move forward
        // by the skipped hour, to 03:15 and 03:45 CEST (01:15 and 01:45 UTC).
        let gap = blackout(&["daily 02:15-02:45"], STOCKHOLM);
        assert_eq!(
            gap.active_until(utc("2026-03-29T01:30:00Z")),
            Some(utc("2026-03-29T01:45:00Z"))
        );
        assert_eq!(gap.active_until(utc("2026-03-29T01:00:00Z")), None);
        assert_eq!(
            gap.next_start(utc("2026-03-29T00:00:00Z")),
            Some(utc("2026-03-29T01:15:00Z"))
        );
        // A window that is exactly the skipped hour has no length on that day.
        let skipped = blackout(&["daily 02:00-03:00"], STOCKHOLM);
        assert_eq!(skipped.active_until(utc("2026-03-29T01:00:00Z")), None);
        assert_eq!(
            skipped.next_start(utc("2026-03-29T00:00:00Z")),
            Some(utc("2026-03-30T00:00:00Z"))
        );
    }

    #[test]
    fn window_across_the_spring_change_is_an_hour_shorter() {
        // Saturday 22:00 CET (21:00 UTC) to Sunday 06:00 CEST (04:00 UTC): seven hours.
        let night = blackout(&["sat 22:00-06:00"], STOCKHOLM);
        assert_eq!(
            night.active_until(utc("2026-03-28T21:00:00Z")),
            Some(utc("2026-03-29T04:00:00Z"))
        );
        assert_eq!(
            night.active_until(utc("2026-03-29T03:59:00Z")),
            Some(utc("2026-03-29T04:00:00Z"))
        );
        assert_eq!(night.active_until(utc("2026-03-29T04:00:00Z")), None);
        assert_eq!(night.active_until(utc("2026-03-28T20:59:00Z")), None);
    }

    #[test]
    fn autumn_change_makes_a_window_longer() {
        // 2026-10-25: at 03:00 the clocks go back to 02:00 (01:00 UTC) in Stockholm.
        let night = blackout(&["daily 01:00-04:00"], STOCKHOLM);
        // 01:00 CEST is 23:00 UTC the day before and 04:00 CET is 03:00 UTC: four hours.
        assert_eq!(
            night.active_until(utc("2026-10-24T23:30:00Z")),
            Some(utc("2026-10-25T03:00:00Z"))
        );
        assert_eq!(
            night.active_until(utc("2026-10-25T01:30:00Z")),
            Some(utc("2026-10-25T03:00:00Z"))
        );
        assert_eq!(
            night.active_until(utc("2026-10-25T02:59:00Z")),
            Some(utc("2026-10-25T03:00:00Z"))
        );
        assert_eq!(night.active_until(utc("2026-10-25T03:00:00Z")), None);
        assert_eq!(
            night.next_start(utc("2026-10-25T03:00:00Z")),
            Some(utc("2026-10-26T00:00:00Z"))
        );
    }

    #[test]
    fn autumn_change_starts_a_repeated_time_at_its_first_occurrence() {
        // 02:30 happens twice on 2026-10-25: at 00:30 UTC (CEST) and at 01:30 UTC (CET). The
        // window starts at the first one and ends at 03:30 CET, 02:30 UTC.
        let fold = blackout(&["daily 02:30-03:30"], STOCKHOLM);
        assert_eq!(fold.active_until(utc("2026-10-25T00:15:00Z")), None);
        assert_eq!(
            fold.active_until(utc("2026-10-25T00:30:00Z")),
            Some(utc("2026-10-25T02:30:00Z"))
        );
        assert_eq!(
            fold.active_until(utc("2026-10-25T01:45:00Z")),
            Some(utc("2026-10-25T02:30:00Z"))
        );
        assert_eq!(fold.active_until(utc("2026-10-25T02:30:00Z")), None);
        assert_eq!(
            fold.next_start(utc("2026-10-24T12:00:00Z")),
            Some(utc("2026-10-25T00:30:00Z"))
        );
    }

    #[test]
    fn next_start_follows_the_clock_over_a_change() {
        // 08:00 on the Sunday of the autumn change is 07:00 UTC, one hour later than usual.
        let morning = blackout(&["daily 08:00-09:00"], STOCKHOLM);
        assert_eq!(
            morning.next_start(utc("2026-10-24T07:30:00Z")),
            Some(utc("2026-10-25T07:00:00Z"))
        );
        assert_eq!(
            morning.next_start(utc("2026-10-25T07:00:00Z")),
            Some(utc("2026-10-26T07:00:00Z"))
        );
    }

    #[test]
    fn utc_has_no_changes() {
        let night = blackout(&["daily 01:00-04:00"], "UTC");
        assert_eq!(
            night.active_until(utc("2026-03-29T01:30:00Z")),
            Some(utc("2026-03-29T04:00:00Z"))
        );
        assert_eq!(
            night.active_until(utc("2026-10-25T01:30:00Z")),
            Some(utc("2026-10-25T04:00:00Z"))
        );
    }

    #[test]
    fn bad_windows_are_refused_with_the_text_and_an_example() {
        let cases = [
            ("", "empty"),
            ("   ", "empty"),
            ("mon-fri", "no time of day"),
            ("mon-fri 08:00", "start and an end"),
            ("mon-fri 25:00-17:00", "not a time"),
            ("mon-fri 08:60-17:00", "not a time"),
            ("mon-fri 08:00-24:30", "not a time"),
            ("mon-fri 24:00-02:00", "only allowed as an end"),
            ("mon-fri 08:00-08:00", "no length"),
            ("mon-fri 00:00-00:00", "no length"),
            ("funday 08:00-17:00", "unknown day"),
            ("mon fri 08:00-17:00", "unknown day"),
            ("mon- 08:00-17:00", "unknown day"),
            ("mon,,fri 08:00-17:00", "empty entry"),
            ("mon-fri 0800-1700", "not a time"),
            ("mon-fri 8-17", "not a time"),
            ("mon-fri 08:0-17:00", "not a time"),
            ("mon-fri 008:00-17:00", "not a time"),
            ("mon-fri 08:00-17:00-18:00", "not a time"),
            ("mon-fri 08:00 17:00", "start and an end"),
        ];
        for (spec, reason) in cases {
            let error = error_of(spec);
            assert_eq!(error.code(), "scan.config", "{spec:?}");
            let detail = error.detail();
            assert!(
                detail.contains(&format!("\"{spec}\"")),
                "{spec:?}: {detail}"
            );
            assert!(detail.contains(EXAMPLE), "{spec:?}: {detail}");
            assert!(detail.contains(reason), "{spec:?}: {detail}");
        }
    }

    #[test]
    fn the_first_bad_window_is_reported() {
        let specs = [
            "mon-fri 08:00-17:00".to_owned(),
            "sat 99:00-17:00".to_owned(),
            "sun".to_owned(),
        ];
        let error = Blackout::parse(&specs, Some("UTC")).expect_err("one window is bad");
        assert!(error.detail().contains("\"sat 99:00-17:00\""), "{error}");
        assert!(!error.detail().contains("\"sun\""), "{error}");
    }

    #[test]
    fn long_and_odd_text_is_quoted_safely() {
        let error = error_of(&format!("{}\n\u{7}", "x".repeat(300)));
        let detail = error.detail();
        assert!(detail.len() < 400, "{detail}");
        assert!(
            !detail.contains('\n') && !detail.contains('\u{7}'),
            "{detail}"
        );
        assert!(detail.contains("..."), "{detail}");
    }

    #[test]
    fn unknown_zone_is_refused() {
        let error = Blackout::parse(&["mon 08:00-09:00".to_owned()], Some("Mars/Olympus_Mons"))
            .expect_err("no such zone");
        assert_eq!(error.code(), "scan.config");
        assert!(error.detail().contains("\"Mars/Olympus_Mons\""), "{error}");
        assert!(error.detail().contains("Europe/Stockholm"), "{error}");
        // The zone is checked even when there are no windows.
        assert!(Blackout::parse(&[], Some("Mars/Olympus_Mons")).is_err());
    }

    #[test]
    fn accessors_report_what_was_configured() {
        let specs = [
            " Mon-Fri  08:00-17:00 ".to_owned(),
            "sun 22:00-02:00".to_owned(),
        ];
        let configured = Blackout::parse(&specs, Some("europe/stockholm")).expect("parses");
        assert!(!configured.is_empty());
        assert_eq!(configured.zone_name(), "Europe/Stockholm");
        assert_eq!(
            configured.windows(),
            [" Mon-Fri  08:00-17:00 ", "sun 22:00-02:00"]
        );
        let in_utc = Blackout::parse(&specs, Some("UTC")).expect("parses");
        assert_eq!(in_utc.zone_name(), "UTC");
    }

    #[test]
    fn no_windows_means_no_blackout() {
        for empty in [
            Blackout::default(),
            Blackout::parse(&[], None).expect("parses"),
            Blackout::parse(&[], Some(STOCKHOLM)).expect("parses"),
        ] {
            let at = stockholm(3, 12, 0);
            assert!(empty.is_empty());
            let no_windows: &[String] = &[];
            assert_eq!(empty.windows(), no_windows);
            assert_eq!(empty.active_until(at), None);
            assert_eq!(empty.next_start(at), None);
        }
    }

    #[test]
    fn the_system_zone_is_the_default() {
        for zone in [None, Some("system"), Some("SYSTEM"), Some(""), Some("  ")] {
            let windows = Blackout::parse(&["daily 00:00-24:00".to_owned()], zone).expect("parses");
            assert_eq!(windows.zone_name(), "system");
            assert!(windows.active_until(stockholm(3, 12, 0)).is_some());
        }
    }

    proptest! {
        #[test]
        fn office_hours_agree_with_a_direct_calculation(
            secs in 1_767_225_600_i64..1_798_761_600_i64,
        ) {
            let office = blackout(&["weekdays 08:00-17:00"], STOCKHOLM);
            let zone = TimeZone::get(STOCKHOLM).expect("the zone exists");
            let at = Timestamp::from_second(secs).expect("a valid instant");
            let here = at.to_zoned(zone.clone());
            let inside =
                here.weekday().to_monday_zero_offset() < 5 && (8..17).contains(&here.hour());

            let until = office.active_until(at.into());
            prop_assert_eq!(until.is_some(), inside);
            if let Some(end) = until {
                let end = Timestamp::try_from(end).expect("a valid instant").to_zoned(zone.clone());
                prop_assert!(end.timestamp() > at);
                prop_assert_eq!((end.hour(), end.minute()), (17, 0));
                prop_assert_eq!(end.date(), here.date());
                prop_assert!(office.active_until(end.timestamp().into()).is_none());
            }

            let next = office.next_start(at.into()).expect("a window starts within a week");
            let next = Timestamp::try_from(next).expect("a valid instant").to_zoned(zone);
            prop_assert!(next.timestamp() > at);
            prop_assert_eq!((next.hour(), next.minute()), (8, 0));
            prop_assert!(next.weekday().to_monday_zero_offset() < 5);
            // From Friday 08:00 (inside the window, so the next start is the Monday) it is 72
            // hours; a change of the clocks adds an hour.
            prop_assert!(next.timestamp().as_second() - secs <= 73 * 3600);
        }
    }
}
