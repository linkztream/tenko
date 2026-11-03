//! The values inside tokens: decimal numbers, TTLs with units, escaped text, names and
//! RRSIG times.
//!
//! Every function here works on the bytes of one token and indexes only within bounds it
//! has checked; none of them allocates more than a small multiple of the token's length.

use std::str::FromStr;

use tenko_core::dns::{
    name::{MAX_LABEL_LEN, MAX_WIRE_LEN},
    rdata::{MAX_CHARSTRING_LEN, MAX_RDATA_LEN},
};

/// The longest token (or run of joined tokens) that can still be record data: 65,535
/// octets written as `\DDD` each.
pub(super) const MAX_TOKEN_LEN: usize = 4 * MAX_RDATA_LEN;

/// A number of decimal digits only (no sign, no space), within the range of `T`.
pub(super) fn decimal<T: FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A TTL or another duration in seconds: decimal seconds, or BIND's units `w`, `d`, `h`,
/// `m` and `s` (any case) after each number, combined (`1h30m`); a last number without a
/// unit counts seconds. The total must fit 32 bits.
pub(super) fn ttl(text: &str) -> Option<u32> {
    if let Some(value) = decimal::<u32>(text) {
        return Some(value);
    }
    if text.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    let mut number: Option<u32> = None;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            let digit = u32::from(byte - b'0');
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(digit)?);
            continue;
        }
        let unit = match byte.to_ascii_lowercase() {
            b'w' => 604_800,
            b'd' => 86_400,
            b'h' => 3_600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    if let Some(seconds) = number {
        total = total.checked_add(seconds)?;
    }
    Some(total)
}

/// The octets of a character string or another escaped token: `\DDD` is the octet of
/// three decimal digits (at most 255), `\X` is `X` itself for any other character that is
/// not a control character, everything else is taken as it is.
///
/// # Errors
///
/// A reason in English for a malformed escape, or for a token longer than the longest
/// record data could be written (four characters an octet), which is refused before it is
/// decoded.
pub(super) fn unescape(text: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_TOKEN_LEN {
        return Err("a token is longer than any record data can be written");
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'\\' {
            out.push(byte);
            index += 1;
            continue;
        }
        let (value, used) = escape(bytes, index)?;
        out.push(value);
        index += used;
    }
    Ok(out)
}

/// The escape that starts at `bytes[index]` (a backslash): its octet and its length.
fn escape(bytes: &[u8], index: usize) -> Result<(u8, usize), &'static str> {
    let Some(&next) = bytes.get(index + 1) else {
        return Err("a backslash ends the text");
    };
    if next.is_ascii_digit() {
        let digits = bytes
            .get(index + 1..index + 4)
            .filter(|digits| digits.iter().all(u8::is_ascii_digit))
            .ok_or("`\\DDD` needs three decimal digits")?;
        let value = digits
            .iter()
            .fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
        let value = u8::try_from(value).map_err(|_| "`\\DDD` is at most 255")?;
        return Ok((value, 4));
    }
    if next.is_ascii_control() {
        return Err("a backslash before a control character");
    }
    Ok((next, 2))
}

/// One character string (RFC 1035, section 3.3): at most 255 octets.
///
/// # Errors
///
/// A reason in English for a malformed escape or a string longer than 255 octets.
pub(super) fn charstring(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.len() > 4 * MAX_CHARSTRING_LEN {
        return Err("a character string is at most 255 octets");
    }
    let bytes = unescape(text)?;
    if bytes.len() > MAX_CHARSTRING_LEN {
        return Err("a character string is at most 255 octets");
    }
    Ok(bytes)
}

/// Appends the wire form of a name in presentation form: labels separated by unescaped
/// dots, with `\X` and `\DDD` escapes; `@` is the origin, `.` the root, and a name
/// without a trailing dot is relative to `origin` (a name in wire form). The case is kept.
///
/// # Errors
///
/// A reason in English for an empty or too long label, a name longer than 255 octets or a
/// malformed escape.
pub(super) fn name(text: &str, origin: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
    let start = out.len();
    let result = labels(text, origin, out);
    if result.is_err() {
        out.truncate(start);
    }
    result
}

fn labels(text: &str, origin: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
    let start = out.len();
    if text == "@" {
        out.extend_from_slice(origin);
        return Ok(());
    }
    if text == "." {
        out.push(0);
        return Ok(());
    }
    if text.is_empty() {
        return Err("an empty name");
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut absolute = false;
    while index < bytes.len() {
        let length_at = out.len();
        out.push(0);
        let mut length = 0usize;
        while let Some(&byte) = bytes.get(index) {
            let value = match byte {
                b'.' => break,
                b'\\' => {
                    let (value, used) = escape(bytes, index)?;
                    index += used;
                    value
                }
                other => {
                    index += 1;
                    other
                }
            };
            length += 1;
            if length > MAX_LABEL_LEN {
                return Err("a label is at most 63 octets");
            }
            out.push(value);
        }
        if length == 0 {
            return Err("an empty label");
        }
        out[length_at] = u8::try_from(length).unwrap_or(u8::MAX);
        if out.len() - start > MAX_WIRE_LEN {
            return Err("a name is at most 255 octets");
        }
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            if index == bytes.len() {
                absolute = true;
            }
        }
    }
    if absolute {
        out.push(0);
    } else {
        out.extend_from_slice(origin);
    }
    if out.len() - start > MAX_WIRE_LEN {
        return Err("a name is at most 255 octets");
    }
    Ok(())
}

/// An RRSIG time (RFC 4034, section 3.2): `YYYYMMDDHHmmSS` in UTC, or the seconds since
/// 1970 as a decimal number; the result is modulo 2^32 (serial number arithmetic).
pub(super) fn time(text: &str) -> Option<u32> {
    if text.len() != 14 {
        return decimal::<u32>(text);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse().ok() };
    let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
    let (hour, minute, second) = (field(8..10)?, field(10..12)?, field(12..14)?);
    if year < 1970
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u32::try_from(seconds.rem_euclid(1 << 32)).ok()
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar (the algorithm of
/// Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(text: &str) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        name(text, b"\x07example\x04test\x00", &mut out).map(|()| out)
    }

    #[test]
    fn ttls_take_numbers_and_units() {
        assert_eq!(ttl("300"), Some(300));
        assert_eq!(ttl("1h"), Some(3_600));
        assert_eq!(ttl("1H30m"), Some(5_400));
        assert_eq!(
            ttl("1w2d3h4m5s"),
            Some(604_800 + 172_800 + 10_800 + 240 + 5)
        );
        assert_eq!(ttl("1h30"), Some(3_630));
        assert_eq!(ttl("4294967295"), Some(u32::MAX));
        for bad in [
            "",
            "h",
            "1x",
            "-1",
            "+1",
            "4294967296",
            "7102w",
            "1h h",
            "1.5h",
        ] {
            assert_eq!(ttl(bad), None, "{bad}");
        }
    }

    #[test]
    fn escapes_decode_and_malformed_ones_are_refused() {
        assert_eq!(unescape(r"a\.b\\c\034\255"), Ok(b"a.b\\c\"\xff".to_vec()));
        assert_eq!(unescape("å"), Ok("å".as_bytes().to_vec()));
        for bad in ["\\", "a\\", "\\25", "\\2a5", "\\256", "\\\u{1}"] {
            assert!(unescape(bad).is_err(), "{bad:?}");
        }
        assert!(charstring(&"a".repeat(255)).is_ok());
        assert!(charstring(&"a".repeat(256)).is_err());
        assert!(charstring(&"\\097".repeat(256)).is_err());
    }

    #[test]
    fn names_are_relative_absolute_or_the_origin() {
        assert_eq!(wire("www"), Ok(b"\x03www\x07example\x04test\x00".to_vec()));
        assert_eq!(wire("WWW.other."), Ok(b"\x03WWW\x05other\x00".to_vec()));
        assert_eq!(wire("@"), Ok(b"\x07example\x04test\x00".to_vec()));
        assert_eq!(wire("."), Ok(b"\x00".to_vec()));
        assert_eq!(wire(r"a\.b.test."), Ok(b"\x03a.b\x04test\x00".to_vec()));
        assert_eq!(wire(r"\065.test."), Ok(b"\x01A\x04test\x00".to_vec()));
        for bad in ["", "a..b", ".a", "..", "a\\", &"a".repeat(64)] {
            assert!(wire(bad).is_err(), "{bad:?}");
        }
        assert!(wire(&format!("{}.", "a".repeat(63))).is_ok());
        let long = vec!["a".repeat(63); 4].join(".");
        assert!(wire(&format!("{long}.")).is_err(), "256 octets");
        let fits = format!("{}.{}.", vec!["a".repeat(63); 3].join("."), "a".repeat(61));
        assert_eq!(wire(&fits).map(|w| w.len()), Ok(255));
        // The origin is appended within the limit.
        let relative = format!("{}.{}", vec!["a".repeat(63); 3].join("."), "a".repeat(50));
        assert!(wire(&relative).is_err());
        let mut out = vec![9];
        assert!(name("a..b", b"\x00", &mut out).is_err());
        assert_eq!(out, [9], "a refused name leaves nothing behind");
    }

    #[test]
    fn rrsig_times_take_both_forms() {
        assert_eq!(time("20260101000000"), Some(1_767_225_600));
        assert_eq!(time("19700101000000"), Some(0));
        assert_eq!(time("21060207062816"), Some(0), "wraps modulo 2^32");
        assert_eq!(time("20240229235959"), Some(1_709_251_199));
        assert_eq!(time("1767225600"), Some(1_767_225_600));
        for bad in [
            "20250229000000",
            "20261301000000",
            "20260100000000",
            "20260101240000",
            "19691231235959",
            "2026010100000x",
            "",
        ] {
            assert_eq!(time(bad), None, "{bad}");
        }
    }
}
