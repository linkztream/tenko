//! Serde helpers shared by the contract types.
//!
//! Binary formats (CBOR in the store) get compact encodings; human-readable formats (JSON
//! on the API) get strings. The choice follows `Serializer::is_human_readable`, which is
//! `false` for `ciborium` and `true` for `serde_json`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, Type},
};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hexadecimal without separators.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    out
}

/// Parses hexadecimal digits, ignoring `:`, `-` and `.` separators between bytes. Returns
/// `None` on an odd number of digits or a non-hexadecimal character.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b':' | b'-' | b'.'))
        .collect();
    let (pairs, rest) = digits.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

pub(crate) fn serialize_bytes_or_hex<S: Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&to_hex(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

/// The most bytes [`deserialize_bytes_or_hex`] reserves ahead for a sequence of bytes on the
/// length the input declares; longer sequences grow as their bytes are read.
const MAX_PREALLOCATED_BYTES: usize = 4096;

pub(crate) fn deserialize_bytes_or_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
    what: &'static str,
) -> Result<Vec<u8>, D::Error> {
    struct Visitor(&'static str);

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{} as bytes or a hexadecimal string", self.0)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            from_hex(v).ok_or_else(|| E::invalid_value(de::Unexpected::Str(v), &self))
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }

        /// The length of a sequence is what the input declares, not what it holds: it
        /// reserves at most [`MAX_PREALLOCATED_BYTES`], and the vector grows only by bytes
        /// that are read, so a declaration longer than the input ends in the format's
        /// decode error instead of an allocation of the declared size.
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let declared = seq.size_hint().unwrap_or(0);
            let mut out = Vec::with_capacity(declared.min(MAX_PREALLOCATED_BYTES));
            while let Some(byte) = seq.next_element::<u8>()? {
                out.push(byte);
            }
            Ok(out)
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_str(Visitor(what))
    } else {
        deserializer.deserialize_byte_buf(Visitor(what))
    }
}

/// Arbitrary bytes: a byte string in CBOR, lowercase hexadecimal in JSON.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(pub Vec<u8>);

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexBytes({})", to_hex(&self.0))
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes_or_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bytes_or_hex(deserializer, "bytes").map(Self)
    }
}

impl PartialSchema for HexBytes {
    fn schema() -> RefOr<Schema> {
        string_schema("Lowercase hexadecimal bytes")
    }
}

impl ToSchema for HexBytes {}

/// A string schema with a description, for hand-written `PartialSchema` impls.
pub fn string_schema(description: &str) -> RefOr<Schema> {
    RefOr::T(Schema::Object(
        ObjectBuilder::new()
            .schema_type(Type::String)
            .description(Some(description))
            .build(),
    ))
}

/// `#[serde(with = "tenko_core::serde_util::duration_ms")]`: a [`std::time::Duration`] as
/// whole milliseconds (`u64`).
pub mod duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the duration as milliseconds, saturating at `u64::MAX`.
    ///
    /// # Errors
    ///
    /// Propagates serializer errors.
    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
    }

    /// Deserializes milliseconds into a duration.
    ///
    /// # Errors
    ///
    /// Propagates deserializer errors.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

/// `#[serde(with = "tenko_core::serde_util::option_duration_ms")]`: an optional
/// [`std::time::Duration`] as whole milliseconds.
pub mod option_duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the duration as optional milliseconds.
    ///
    /// # Errors
    ///
    /// Propagates serializer errors.
    #[allow(clippy::ref_option)] // The signature is fixed by `#[serde(with)]`.
    pub fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(duration) => super::duration_ms::serialize(duration, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes optional milliseconds.
    ///
    /// # Errors
    ///
    /// Propagates deserializer errors.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Option::<u64>::deserialize(deserializer).map(|ms| ms.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ciborium serves byte strings longer than its 4 KiB scratch buffer only through
    /// `deserialize_byte_buf`; a `deserialize_bytes` call fails for them.
    #[test]
    fn large_byte_values_round_trip_through_cbor() {
        let value = HexBytes(vec![7; 10_000]);
        let bytes = crate::codec::to_cbor(&value).expect("encode");
        let back: HexBytes = crate::codec::from_cbor(&bytes).expect("decode");
        assert_eq!(back, value);
    }

    #[test]
    fn hex_round_trips_and_accepts_separators() {
        assert_eq!(to_hex(&[0x00, 0x5e, 0xff]), "005eff");
        assert_eq!(from_hex("00:5E-ff"), Some(vec![0x00, 0x5e, 0xff]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn hex_bytes_are_hex_in_json_and_bytes_in_cbor() {
        let value = HexBytes(vec![1, 2, 255]);
        assert_eq!(serde_json::to_string(&value).expect("json"), "\"0102ff\"");
        let cbor = crate::codec::to_cbor(&value).expect("cbor");
        assert_eq!(&cbor[..], [0x43, 1, 2, 255]);
        let back: HexBytes = crate::codec::from_cbor(&cbor).expect("decode");
        assert_eq!(back, value);
        let back: HexBytes = serde_json::from_str("\"01:02:ff\"").expect("decode");
        assert_eq!(back, value);
    }

    /// A CBOR array of bytes that declares about a terabyte and then ends is a decode
    /// error, and nothing is reserved for the declared length; a complete array decodes.
    #[test]
    fn a_byte_array_longer_than_the_input_is_a_decode_error() {
        let declared = [
            0x9b, 0x00, 0x00, 0x00, 0xf4, 0xf4, 0xf4, 0xc0, 0xc0, 0x01, 0x02,
        ];
        let error = crate::codec::from_cbor::<HexBytes>(&declared).expect_err("too short");
        assert!(
            matches!(error, crate::codec::CodecError::Decode(_)),
            "{error:?}"
        );
        let complete = [0x83, 0x01, 0x02, 0x18, 0xff];
        let back: HexBytes = crate::codec::from_cbor(&complete).expect("decode");
        assert_eq!(back, HexBytes(vec![1, 2, 255]));
    }
}
