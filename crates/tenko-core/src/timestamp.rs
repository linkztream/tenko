//! Points in time: UTC, RFC 3339 on the wire.

use std::{fmt, str::FromStr, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type},
};

use crate::{
    codec::key::{KeyCodec, KeyError},
    error::InvalidValue,
};

/// A point in time with nanosecond precision.
///
/// Equality and ordering compare instants. Serialization always writes UTC in RFC 3339
/// (`2026-10-09T12:00:00.5Z`) in every format, so equal instants encode to identical bytes
/// (the audit chain hashes timestamps). Store-applied timestamps come from the proposer
/// (`WriteBatch::proposed_at`), never from the clock of the replica.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub OffsetDateTime);

impl Timestamp {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Timestamp = Timestamp(OffsetDateTime::UNIX_EPOCH);

    /// The current time in UTC.
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Creates a timestamp from nanoseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidValue`] if the value is outside the supported range (years 1 to
    /// 9999).
    pub fn from_unix_nanos(nanos: i128) -> Result<Self, InvalidValue> {
        let time = OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map_err(|_| InvalidValue::new("timestamp", &nanos.to_string(), "out of range"))?;
        if !(1..=9999).contains(&time.year()) {
            return Err(InvalidValue::new(
                "timestamp",
                &nanos.to_string(),
                "year outside 1 to 9999",
            ));
        }
        Ok(Self(time))
    }

    /// Nanoseconds since the Unix epoch.
    pub fn unix_nanos(self) -> i128 {
        self.0.unix_timestamp_nanos()
    }

    /// The same instant with a UTC offset.
    #[must_use]
    pub fn to_utc(self) -> Self {
        Self(self.0.to_offset(UtcOffset::UTC))
    }

    /// The timestamp `duration` later, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let duration = time::Duration::try_from(duration).ok()?;
        self.0.checked_add(duration).map(Self)
    }

    /// The timestamp `duration` earlier, or `None` on overflow.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let duration = time::Duration::try_from(duration).ok()?;
        self.0.checked_sub(duration).map(Self)
    }

    /// The time elapsed from `earlier` to `self`, zero if `earlier` is later.
    pub fn saturating_since(self, earlier: Timestamp) -> Duration {
        Duration::try_from(self.0 - earlier.0).unwrap_or(Duration::ZERO)
    }

    /// RFC 3339 in UTC.
    pub fn to_rfc3339(self) -> String {
        // Formatting a UTC value of years 1 to 9999 cannot fail; the fallback keeps the
        // function total for values constructed directly through the public field.
        self.to_utc()
            .0
            .format(&Rfc3339)
            .unwrap_or_else(|_| self.unix_nanos().to_string())
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.to_rfc3339())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl FromStr for Timestamp {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OffsetDateTime::parse(s.trim(), &Rfc3339)
            .map(|time| Self(time).to_utc())
            .map_err(|_| InvalidValue::new("timestamp", s, "not an RFC 3339 date and time"))
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(time: OffsetDateTime) -> Self {
        Self(time).to_utc()
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self
            .to_utc()
            .0
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 date and time")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl PartialSchema for Timestamp {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::DateTime)))
                .description(Some("RFC 3339 date and time in UTC"))
                .build(),
        ))
    }
}

impl ToSchema for Timestamp {}

/// Keys encode the nanoseconds since the epoch as a sign-flipped big-endian `i128`.
impl KeyCodec for Timestamp {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.unix_nanos().encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        let nanos = i128::decode_key(input)?;
        Timestamp::from_unix_nanos(nanos).map_err(|_| KeyError::Invalid("timestamp out of range"))
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::codec::{decode_key, encode_key, from_cbor, to_canonical_cbor, to_cbor};

    #[test]
    fn serializes_as_utc_rfc3339() {
        let ts = Timestamp(datetime!(2026-10-09 14:00:00.5 +02:00));
        assert_eq!(ts.to_string(), "2026-10-09T12:00:00.5Z");
        assert_eq!(
            serde_json::to_string(&ts).expect("json"),
            "\"2026-10-09T12:00:00.5Z\""
        );
        let back: Timestamp = from_cbor(&to_cbor(&ts).expect("cbor")).expect("cbor");
        assert_eq!(back, ts);
    }

    #[test]
    fn equal_instants_encode_identically() {
        let utc = Timestamp(datetime!(2026-10-09 12:00:00 UTC));
        let cet = Timestamp(datetime!(2026-10-09 14:00:00 +02:00));
        assert_eq!(utc, cet);
        assert_eq!(
            to_canonical_cbor(&utc).expect("cbor"),
            to_canonical_cbor(&cet).expect("cbor")
        );
    }

    #[test]
    fn keys_sort_by_instant() {
        let early = Timestamp(datetime!(1969-12-31 23:59:59 UTC));
        let late = Timestamp(datetime!(2026-10-09 12:00:00 UTC));
        assert!(encode_key(&early) < encode_key(&late));
        assert_eq!(decode_key::<Timestamp>(&encode_key(&late)), Ok(late));
    }

    #[test]
    fn arithmetic_helpers() {
        let start = Timestamp(datetime!(2026-10-09 12:00:00 UTC));
        let later = start
            .checked_add(Duration::from_secs(90))
            .expect("in range");
        assert_eq!(later.saturating_since(start), Duration::from_secs(90));
        assert_eq!(start.saturating_since(later), Duration::ZERO);
        assert!("yesterday".parse::<Timestamp>().is_err());
    }
}
