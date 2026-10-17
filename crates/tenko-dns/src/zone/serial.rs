//! SOA serials (DNS-07): the first serial of a new zone and the next one after a change,
//! per [`SerialPolicy`], compared in serial number arithmetic (RFC 1982).

use tenko_core::{Timestamp, dns::SerialPolicy};

/// Whether `a` is newer than `b` in serial number arithmetic (RFC 1982, section 3.2).
pub fn newer(a: u32, b: u32) -> bool {
    a != b && i32::from_ne_bytes(a.wrapping_sub(b).to_ne_bytes()) > 0
}

/// Seconds since 1970, as a serial (it wraps in 2106, as every unixtime serial does).
fn unix_seconds(now: Timestamp) -> u32 {
    let seconds = now.unix_nanos().div_euclid(1_000_000_000);
    u32::try_from(seconds.rem_euclid(1 << 32)).unwrap_or_default()
}

/// `YYYYMMDD` of a time in UTC (the civil calendar from a day count, H. Hinnant's
/// algorithm).
fn date_number(now: Timestamp) -> u32 {
    let days = now.unix_nanos().div_euclid(86_400_000_000_000);
    let days = i64::try_from(days).unwrap_or_default() + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    u32::try_from(year * 10_000 + month * 100 + day).unwrap_or_default()
}

/// The serial of a new zone: the time, 1, or today's `YYYYMMDD01`.
pub fn first(policy: SerialPolicy, now: Timestamp) -> u32 {
    match policy {
        SerialPolicy::Unixtime => unix_seconds(now).max(1),
        SerialPolicy::Counter => 1,
        SerialPolicy::DateCounter => date_number(now).saturating_mul(100).saturating_add(1),
    }
}

/// The serial after `current`: always newer than `current`. Unixtime takes the time when
/// it is newer, else plus one; the counter adds one; the date counter takes today's
/// `YYYYMMDD01` when it is newer, else plus one (so `nn` running out moves into the next
/// day's numbers).
pub fn next(policy: SerialPolicy, current: u32, now: Timestamp) -> u32 {
    let candidate = match policy {
        SerialPolicy::Unixtime => unix_seconds(now),
        SerialPolicy::Counter => current.wrapping_add(1),
        SerialPolicy::DateCounter => date_number(now).saturating_mul(100).saturating_add(1),
    };
    if newer(candidate, current) {
        candidate
    } else {
        current.wrapping_add(1)
    }
}

/// The serial an import sets: the file's serial when it is newer than the zone's, else
/// the policy's next serial.
pub fn imported(policy: SerialPolicy, current: u32, file: Option<u32>, now: Timestamp) -> u32 {
    match file {
        Some(serial) if newer(serial, current) => serial,
        _ => next(policy, current, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339_seconds: i128) -> Timestamp {
        Timestamp::from_unix_nanos(rfc3339_seconds * 1_000_000_000).expect("time")
    }

    #[test]
    fn serial_arithmetic_wraps() {
        assert!(newer(2, 1));
        assert!(!newer(1, 2));
        assert!(!newer(5, 5));
        assert!(newer(0, u32::MAX));
        assert!(newer(1 << 30, 0));
    }

    #[test]
    fn dates_are_civil_dates() {
        // 2026-10-17T12:00:00Z
        assert_eq!(date_number(at(1_792_238_400)), 20_261_017);
        // 2000-02-29T00:00:00Z
        assert_eq!(date_number(at(951_782_400)), 20_000_229);
        assert_eq!(date_number(at(0)), 19_700_101);
    }

    #[test]
    fn policies_move_forward() {
        let now = at(1_792_238_400);
        assert_eq!(first(SerialPolicy::DateCounter, now), 2_026_101_701);
        assert_eq!(
            next(SerialPolicy::DateCounter, 2_026_101_701, now),
            2_026_101_702
        );
        assert_eq!(
            next(SerialPolicy::DateCounter, 2_026_101_599, now),
            2_026_101_701
        );
        assert_eq!(
            next(SerialPolicy::DateCounter, 2_026_101_799, now),
            2_026_101_800
        );
        assert_eq!(next(SerialPolicy::Counter, 7, now), 8);
        assert_eq!(next(SerialPolicy::Counter, u32::MAX, now), 0);
        assert_eq!(first(SerialPolicy::Unixtime, now), 1_792_238_400);
        assert_eq!(
            next(SerialPolicy::Unixtime, 1_792_238_400, now),
            1_792_238_401
        );
        assert_eq!(next(SerialPolicy::Unixtime, 5, now), 1_792_238_400);
    }

    #[test]
    fn imports_keep_a_newer_file_serial() {
        let now = at(1_792_238_400);
        assert_eq!(
            imported(SerialPolicy::Counter, 4, Some(2_026_101_705), now),
            2_026_101_705
        );
        assert_eq!(imported(SerialPolicy::Counter, 4, Some(3), now), 5);
        assert_eq!(imported(SerialPolicy::Counter, 4, None, now), 5);
    }
}
