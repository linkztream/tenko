//! The DER reader: one TLV at a time over borrowed input, every length checked against the
//! octets that are there.

use super::{DerError, DerErrorKind, tag};

/// A reader over the content of one structure or field. Errors carry the structure and the
/// field the reader was made for.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    structure: &'static str,
    field: &'static str,
}

/// One TLV as read: the tag, the value and the whole encoding (tag, length and value).
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The tag octet.
    pub tag: u8,
    /// The value octets.
    pub value: &'a [u8],
    /// The whole encoding.
    pub raw: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data` for `structure`.
    pub const fn new(data: &'a [u8], structure: &'static str) -> Self {
        Self {
            data,
            structure,
            field: "-",
        }
    }

    /// The same octets, labeled with another field for errors.
    #[must_use]
    pub const fn labeled(self, field: &'static str) -> Self {
        Self {
            data: self.data,
            structure: self.structure,
            field,
        }
    }

    /// A refusal of this reader's field.
    pub const fn error(&self, kind: DerErrorKind) -> DerError {
        DerError::new(self.structure, self.field, kind)
    }

    /// Whether every octet has been read.
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The octets not yet read.
    pub const fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// The tag of the next TLV, if there is one.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads one TLV.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::Truncated`], [`DerErrorKind::LongTag`],
    /// [`DerErrorKind::IndefiniteLength`] or [`DerErrorKind::BadLength`].
    pub fn read(&mut self) -> Result<Tlv<'a>, DerError> {
        let data = self.data;
        let Some(&tag_octet) = data.first() else {
            return Err(self.error(DerErrorKind::Missing));
        };
        if tag_octet & 0x1f == 0x1f {
            return Err(self.error(DerErrorKind::LongTag));
        }
        let Some(&first) = data.get(1) else {
            return Err(self.error(DerErrorKind::Truncated));
        };
        let (len, header) = match first {
            0..=0x7f => (usize::from(first), 2),
            0x80 => return Err(self.error(DerErrorKind::IndefiniteLength)),
            _ => {
                let count = usize::from(first & 0x7f);
                if count > 4 {
                    return Err(self.error(DerErrorKind::BadLength));
                }
                let octets = data
                    .get(2..2 + count)
                    .ok_or_else(|| self.error(DerErrorKind::Truncated))?;
                if octets[0] == 0 {
                    return Err(self.error(DerErrorKind::BadLength));
                }
                let len = octets
                    .iter()
                    .fold(0_usize, |acc, octet| (acc << 8) | usize::from(*octet));
                if len < 0x80 {
                    return Err(self.error(DerErrorKind::BadLength));
                }
                (len, 2 + count)
            }
        };
        let end = header
            .checked_add(len)
            .ok_or_else(|| self.error(DerErrorKind::Truncated))?;
        if end > data.len() {
            return Err(self.error(DerErrorKind::Truncated));
        }
        self.data = &data[end..];
        Ok(Tlv {
            tag: tag_octet,
            value: &data[header..end],
            raw: &data[..end],
        })
    }

    /// Reads one TLV that must carry `tag`, and returns its value.
    ///
    /// # Errors
    ///
    /// As [`Reader::read`], and [`DerErrorKind::UnexpectedTag`].
    pub fn expect(&mut self, expected: u8) -> Result<&'a [u8], DerError> {
        Ok(self.expect_tlv(expected)?.value)
    }

    /// Reads one TLV that must carry `tag`.
    ///
    /// # Errors
    ///
    /// As [`Reader::read`], and [`DerErrorKind::UnexpectedTag`].
    pub fn expect_tlv(&mut self, expected: u8) -> Result<Tlv<'a>, DerError> {
        match self.peek_tag() {
            None => Err(self.error(DerErrorKind::Missing)),
            Some(found) if found != expected => {
                Err(self.error(DerErrorKind::UnexpectedTag { expected, found }))
            }
            Some(_) => self.read(),
        }
    }

    /// Requires that nothing follows.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::TrailingData`].
    pub fn finish(&self) -> Result<(), DerError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(self.error(DerErrorKind::TrailingData))
        }
    }

    /// A reader over the content of a constructed TLV with `tag`.
    fn enter(&mut self, expected: u8, field: &'static str) -> Result<Reader<'a>, DerError> {
        let mut labeled = self.labeled(field);
        let value = labeled.expect(expected)?;
        self.data = labeled.data;
        Ok(Reader {
            data: value,
            structure: self.structure,
            field,
        })
    }

    /// The content of the required explicit field `[n]`.
    ///
    /// # Errors
    ///
    /// As [`Reader::expect`], naming `field`.
    pub fn field(&mut self, n: u8, field: &'static str) -> Result<Reader<'a>, DerError> {
        self.enter(tag::context(n), field)
    }

    /// The content of the optional explicit field `[n]`: `None` when the next TLV has
    /// another tag or there is none.
    ///
    /// # Errors
    ///
    /// As [`Reader::read`], naming `field`.
    pub fn opt_field(
        &mut self,
        n: u8,
        field: &'static str,
    ) -> Result<Option<Reader<'a>>, DerError> {
        if self.peek_tag() == Some(tag::context(n)) {
            self.enter(tag::context(n), field).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The content of a SEQUENCE.
    ///
    /// # Errors
    ///
    /// As [`Reader::expect`].
    pub fn sequence(&mut self) -> Result<Reader<'a>, DerError> {
        let field = self.field;
        self.enter(tag::SEQUENCE, field)
    }

    /// The content of `[APPLICATION n]`.
    ///
    /// # Errors
    ///
    /// As [`Reader::expect`].
    pub fn application(&mut self, n: u8) -> Result<Reader<'a>, DerError> {
        let field = self.field;
        self.enter(tag::application(n), field)
    }

    /// Decodes the one structure of this field with `read` and requires that nothing
    /// follows it.
    ///
    /// # Errors
    ///
    /// What `read` returns, or [`DerErrorKind::TrailingData`].
    pub fn with<T>(
        mut self,
        read: impl FnOnce(&mut Reader<'a>) -> Result<T, DerError>,
    ) -> Result<T, DerError> {
        let value = read(&mut self)?;
        self.finish()?;
        Ok(value)
    }

    /// Reads the single TLV of an explicit field with `tag` and requires that nothing
    /// follows it.
    fn only(mut self, expected: u8) -> Result<&'a [u8], DerError> {
        let value = self.expect(expected)?;
        self.finish()?;
        Ok(value)
    }

    /// An INTEGER as a signed 64-bit value.
    fn integer(self) -> Result<i64, DerError> {
        let value = self.only(tag::INTEGER)?;
        decode_integer(value).ok_or_else(|| self.error(DerErrorKind::BadInteger))
    }

    /// An `Int32`.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadInteger`], [`DerErrorKind::OutOfRange`] or a TLV error.
    pub fn int32(self) -> Result<i32, DerError> {
        let value = self.integer()?;
        i32::try_from(value).map_err(|_| self.error(DerErrorKind::OutOfRange))
    }

    /// A `UInt32`.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadInteger`], [`DerErrorKind::OutOfRange`] or a TLV error.
    pub fn uint32(self) -> Result<u32, DerError> {
        let value = self.integer()?;
        u32::try_from(value).map_err(|_| self.error(DerErrorKind::OutOfRange))
    }

    /// A sequence number or a nonce: a `UInt32` that some implementations write as a
    /// negative `Int32`. Decision (as MIT's decoder): any value from -2^31 to 2^32 - 1 is
    /// taken modulo 2^32.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadInteger`], [`DerErrorKind::OutOfRange`] or a TLV error.
    pub fn uint32_lenient(self) -> Result<u32, DerError> {
        let value = self.integer()?;
        if (-(1_i64 << 31)..(1_i64 << 32)).contains(&value) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(value as u32)
        } else {
            Err(self.error(DerErrorKind::OutOfRange))
        }
    }

    /// `Microseconds` (0 to 999,999).
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::OutOfRange`] or an INTEGER error.
    pub fn microseconds(self) -> Result<u32, DerError> {
        let value = self.uint32()?;
        if value > 999_999 {
            return Err(self.error(DerErrorKind::OutOfRange));
        }
        Ok(value)
    }

    /// An ENUMERATED.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadInteger`] or a TLV error.
    pub fn enumerated(self) -> Result<i64, DerError> {
        let value = self.only(tag::ENUMERATED)?;
        decode_integer(value).ok_or_else(|| self.error(DerErrorKind::BadInteger))
    }

    /// A BOOLEAN.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadBoolean`] or a TLV error.
    pub fn boolean(self) -> Result<bool, DerError> {
        match self.only(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(self.error(DerErrorKind::BadBoolean)),
        }
    }

    /// An OCTET STRING, borrowed.
    ///
    /// # Errors
    ///
    /// A TLV error.
    pub fn octets(self) -> Result<&'a [u8], DerError> {
        self.only(tag::OCTET_STRING)
    }

    /// A `KerberosString` (`GeneralString`) as UTF-8.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadString`] or a TLV error.
    pub fn string(self) -> Result<String, DerError> {
        let value = self.only(tag::GENERAL_STRING)?;
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| self.error(DerErrorKind::BadString))
    }

    /// A `KerberosTime` as Unix seconds.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadTime`] or a TLV error.
    pub fn time(self) -> Result<i64, DerError> {
        let value = self.only(tag::GENERALIZED_TIME)?;
        parse_time(value).ok_or_else(|| self.error(DerErrorKind::BadTime))
    }

    /// `KerberosFlags`: the first 32 bits of the BIT STRING, bit 0 as the most significant
    /// bit of the result. Fewer bits are padded with zeros, more are ignored (RFC 4120
    /// section 5.2.8 asks for at least 32 and a receiver to take what it is sent).
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadBitString`] or a TLV error.
    pub fn flags(self) -> Result<u32, DerError> {
        let value = self.only(tag::BIT_STRING)?;
        let Some((&unused, bits)) = value.split_first() else {
            return Err(self.error(DerErrorKind::BadBitString));
        };
        if unused > 7 || (bits.is_empty() && unused != 0) {
            return Err(self.error(DerErrorKind::BadBitString));
        }
        let mut word = [0_u8; 4];
        for (index, octet) in bits.iter().take(4).enumerate() {
            word[index] = *octet;
        }
        let mut flags = u32::from_be_bytes(word);
        if bits.len() <= 4 && unused > 0 {
            // The unused low bits of the last octet are not flags.
            let last_bit = u32::try_from(bits.len() * 8).unwrap_or(32) - u32::from(unused);
            flags &= if last_bit == 0 {
                0
            } else {
                u32::MAX << (32 - last_bit)
            };
        }
        Ok(flags)
    }

    /// An OBJECT IDENTIFIER's content octets, checked for the shortest form.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::BadOid`] or a TLV error.
    pub fn oid(self) -> Result<&'a [u8], DerError> {
        let value = self.only(tag::OID)?;
        if valid_oid(value) {
            Ok(value)
        } else {
            Err(self.error(DerErrorKind::BadOid))
        }
    }

    /// A `SEQUENCE OF`: `element` is called with a reader positioned at each element and
    /// must read exactly one TLV from it. At most `max` elements.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::TooMany`], or what `element` returns.
    pub fn sequence_of<T>(
        mut self,
        max: usize,
        mut element: impl FnMut(&mut Reader<'a>) -> Result<T, DerError>,
    ) -> Result<Vec<T>, DerError> {
        let mut content = self.sequence()?;
        self.finish()?;
        let mut out = Vec::new();
        while !content.is_empty() {
            if out.len() == max {
                return Err(content.error(DerErrorKind::TooMany));
            }
            out.push(element(&mut content)?);
        }
        Ok(out)
    }
}

/// Decodes a DER INTEGER of at most eight octets.
pub(crate) fn decode_integer(value: &[u8]) -> Option<i64> {
    match value {
        [] => None,
        [0x00, next, ..] if next & 0x80 == 0 => None,
        [0xff, next, ..] if next & 0x80 != 0 => None,
        _ if value.len() > 8 => None,
        _ => {
            let negative = value[0] & 0x80 != 0;
            let start = if negative { -1_i64 } else { 0 };
            Some(
                value
                    .iter()
                    .fold(start, |acc, octet| (acc << 8) | i64::from(*octet)),
            )
        }
    }
}

/// Whether OBJECT IDENTIFIER content octets are in their shortest form.
pub(crate) fn valid_oid(value: &[u8]) -> bool {
    if value.is_empty() || value.last().is_some_and(|last| last & 0x80 != 0) {
        return false;
    }
    let mut start_of_arc = true;
    for octet in value {
        if start_of_arc && *octet == 0x80 {
            return false;
        }
        start_of_arc = octet & 0x80 == 0;
    }
    true
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date of a day count from 1970-01-01.
pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
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
    (year, month, day)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Parses `YYYYMMDDHHMMSSZ` (RFC 4120 section 5.2.3: no fractions, always UTC).
pub(crate) fn parse_time(value: &[u8]) -> Option<i64> {
    if value.len() != 15 || value[14] != b'Z' || !value[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> i64 {
        value[range]
            .iter()
            .fold(0, |acc, digit| acc * 10 + i64::from(digit - b'0'))
    };
    let (year, month, day) = (number(0..4), number(4..6), number(6..8));
    let (hour, minute, second) = (number(8..10), number(10..12), number(12..14));
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Formats Unix seconds as `YYYYMMDDHHMMSSZ`; years outside 0 to 9999 are clamped to the
/// first or last second of that range.
pub(crate) fn format_time(unix: i64) -> [u8; 15] {
    let min = days_from_civil(0, 1, 1) * 86_400;
    let max = days_from_civil(9999, 12, 31) * 86_400 + 86_399;
    let unix = unix.clamp(min, max);
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let mut out = [0_u8; 15];
    let mut put = |at: usize, width: usize, value: i64| {
        let mut value = value;
        for index in (0..width).rev() {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                out[at + index] = b'0' + (value % 10) as u8;
            }
            value /= 10;
        }
    };
    put(0, 4, year);
    put(4, 2, month);
    put(6, 2, day);
    put(8, 2, seconds / 3_600);
    put(10, 2, seconds % 3_600 / 60);
    put(12, 2, seconds % 60);
    out[14] = b'Z';
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_der_and_bounded_by_the_input() {
        let mut reader = Reader::new(&[0x04, 0x02, 1, 2], "T");
        assert_eq!(
            reader.expect(tag::OCTET_STRING).expect("short form"),
            &[1, 2]
        );
        let refused = |bytes: &[u8]| Reader::new(bytes, "T").read().expect_err("refused").kind;
        assert_eq!(refused(&[0x04, 0x80, 0, 0]), DerErrorKind::IndefiniteLength);
        assert_eq!(
            refused(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]),
            DerErrorKind::BadLength
        );
        assert_eq!(refused(&[0x04, 0x82, 0x00, 0x90]), DerErrorKind::BadLength);
        assert_eq!(
            refused(&[0x04, 0x85, 1, 1, 1, 1, 1]),
            DerErrorKind::BadLength
        );
        assert_eq!(
            refused(&[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            DerErrorKind::Truncated
        );
        assert_eq!(refused(&[0x04, 0x03, 1]), DerErrorKind::Truncated);
        assert_eq!(refused(&[0x1f, 0x01, 0x00]), DerErrorKind::LongTag);
        assert_eq!(refused(&[0x04]), DerErrorKind::Truncated);
        let long = [&[0x04, 0x81, 0x80][..], &[7_u8; 0x80][..]].concat();
        assert_eq!(
            Reader::new(&long, "T")
                .read()
                .expect("long form")
                .value
                .len(),
            0x80
        );
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(decode_integer(&[0x00]), Some(0));
        assert_eq!(decode_integer(&[0x7f]), Some(127));
        assert_eq!(decode_integer(&[0x00, 0x80]), Some(128));
        assert_eq!(decode_integer(&[0xff]), Some(-1));
        assert_eq!(decode_integer(&[0x80]), Some(-128));
        assert_eq!(decode_integer(&[0x00, 0x7f]), None);
        assert_eq!(decode_integer(&[0xff, 0xff]), None);
        assert_eq!(decode_integer(&[]), None);
        assert_eq!(decode_integer(&[1; 9]), None);
        assert_eq!(
            decode_integer(&[0x00, 0xff, 0xff, 0xff, 0xff]),
            Some(0xffff_ffff)
        );
    }

    #[test]
    fn times_round_trip_and_bad_dates_are_refused() {
        assert_eq!(parse_time(b"19700101000000Z"), Some(0));
        assert_eq!(parse_time(b"20261105120000Z"), Some(1_793_880_000));
        assert_eq!(parse_time(b"20240229235959Z"), Some(1_709_251_199));
        for bad in [
            &b"20230229000000Z"[..],
            b"20261305000000Z",
            b"20261100000000Z",
            b"20261105240000Z",
            b"20261105126000Z",
            b"20261105120060Z",
            b"20261105120000",
            b"20261105120000.5Z",
            b"2026110512000AZ",
        ] {
            assert_eq!(parse_time(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        for unix in [0, 1_793_867_714, 2_147_483_647, 4_102_444_800, -86_400] {
            assert_eq!(parse_time(&format_time(unix)), Some(unix));
        }
    }

    #[test]
    fn oids_are_checked() {
        assert!(valid_oid(&[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
        ]));
        assert!(!valid_oid(&[]));
        assert!(!valid_oid(&[0x2a, 0x86]));
        assert!(!valid_oid(&[0x2a, 0x80, 0x01]));
    }

    #[test]
    fn flags_take_the_first_32_bits() {
        let flags = |value: &[u8]| {
            let mut der = vec![tag::BIT_STRING, u8::try_from(value.len()).expect("len")];
            der.extend_from_slice(value);
            Reader::new(&der, "T").flags()
        };
        assert_eq!(flags(&[0, 0x40, 0x81, 0, 0]), Ok(0x4081_0000));
        assert_eq!(flags(&[0, 0x40, 0x81, 0, 0, 0xff]), Ok(0x4081_0000));
        assert_eq!(flags(&[7, 0x80]), Ok(0x8000_0000));
        assert_eq!(flags(&[0]), Ok(0));
        assert!(flags(&[8, 0]).is_err());
        assert!(flags(&[1]).is_err());
        assert!(flags(&[]).is_err());
    }
}
