//! CBOR values and the canonical encoding used for hashing.
//!
//! [`to_cbor`] is the everyday encoding of stored values. [`to_canonical_cbor`] produces
//! the deterministic encoding of RFC 8949 section 4.2.1 for the subset of CBOR that serde
//! produces: definite lengths, shortest-form integers and lengths, and map entries sorted by
//! the byte-wise order of their encoded keys. Two values that serialize to the same data
//! model therefore encode to identical bytes, whatever the iteration order of their maps.
//!
//! Rules for hashed types (audit records, idempotency fingerprints):
//!
//! - no floating-point fields;
//! - new fields are added with `#[serde(default, skip_serializing_if = "…")]` so that a value
//!   without the field encodes exactly as it did before the field existed.

use bytes::Bytes;
use ciborium::Value;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::error::Coded;

/// A value could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Encoding failed.
    #[error("CBOR encoding failed: {0}")]
    Encode(String),
    /// Decoding failed: malformed bytes or a shape that does not match the type.
    #[error("CBOR decoding failed: {0}")]
    Decode(String),
}

impl Coded for CodecError {
    fn code(&self) -> &'static str {
        match self {
            CodecError::Encode(_) => "sys.codec.encode",
            CodecError::Decode(_) => "sys.codec.decode",
        }
    }
    fn http_status(&self) -> u16 {
        500
    }
}

/// Encodes a value as CBOR.
///
/// # Errors
///
/// Returns [`CodecError::Encode`] if the value cannot be serialized.
pub fn to_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Bytes, CodecError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| CodecError::Encode(e.to_string()))?;
    Ok(Bytes::from(out))
}

/// Decodes a CBOR value.
///
/// # Errors
///
/// Returns [`CodecError::Decode`] if the bytes are malformed or do not match `T`.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes).map_err(|e| CodecError::Decode(e.to_string()))
}

/// Decodes a CBOR value exactly: a map key of the input that the decoded value does not
/// keep (a field `T` does not know, which serde ignores) is an error. Stored records are
/// read with [`from_cbor`], which ignores unknown fields so that an older binary reads what
/// a newer one wrote; a replicated command is read with this, because every member must
/// apply the same command or none.
///
/// The check decodes, encodes the value again and looks for every key of the input in the
/// result, at the same place: keys the result adds (defaults) are fine, keys it lost are
/// not. A key the input carries with a value the type leaves out when encoding (an empty
/// list of a field that skips empty lists) counts as lost, which only makes the check
/// stricter.
///
/// # Errors
///
/// Returns [`CodecError::Decode`] if the bytes do not decode as `T`, or naming the first
/// key `T` does not keep.
pub fn from_cbor_exact<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let input: Value = from_cbor(bytes)?;
    let value: T = input
        .deserialized()
        .map_err(|e| CodecError::Decode(e.to_string()))?;
    let kept = Value::serialized(&value).map_err(|e| CodecError::Encode(e.to_string()))?;
    match lost_key(&input, &kept) {
        Some(path) => Err(CodecError::Decode(format!("unknown field `{path}`"))),
        None => Ok(value),
    }
}

/// The path of the first map key of `input` that `kept` lacks.
fn lost_key(input: &Value, kept: &Value) -> Option<String> {
    match (input, kept) {
        (Value::Map(input), Value::Map(kept)) => input.iter().find_map(|(key, value)| {
            let name = match key {
                Value::Text(text) => text.clone(),
                other => format!("{other:?}"),
            };
            match kept.iter().find(|(kept_key, _)| kept_key == key) {
                None => Some(name),
                Some((_, kept_value)) => {
                    lost_key(value, kept_value).map(|inner| format!("{name}.{inner}"))
                }
            }
        }),
        (Value::Array(input), Value::Array(kept)) if input.len() == kept.len() => input
            .iter()
            .zip(kept)
            .enumerate()
            .find_map(|(n, (input, kept))| {
                lost_key(input, kept).map(|inner| format!("{n}.{inner}"))
            }),
        (Value::Array(_), Value::Array(_)) => Some("[]".to_owned()),
        (Value::Tag(_, input), Value::Tag(_, kept)) => lost_key(input, kept),
        _ => None,
    }
}

/// Encodes a value in canonical CBOR (RFC 8949 section 4.2.1, core deterministic
/// encoding).
///
/// # Errors
///
/// Returns [`CodecError::Encode`] if the value cannot be serialized or contains a
/// floating-point number (floats have no single canonical form here and are not allowed in
/// hashed values).
pub fn to_canonical_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CodecError> {
    let value = Value::serialized(value).map_err(|e| CodecError::Encode(e.to_string()))?;
    let value = canonicalize(value)?;
    let mut out = Vec::new();
    write_value(&value, &mut out)?;
    Ok(out)
}

/// SHA-256 over the canonical CBOR encoding of a value.
///
/// # Errors
///
/// Returns [`CodecError::Encode`] under the same conditions as [`to_canonical_cbor`].
pub fn canonical_sha256<T: Serialize + ?Sized>(value: &T) -> Result<[u8; 32], CodecError> {
    let bytes = to_canonical_cbor(value)?;
    Ok(Sha256::digest(&bytes).into())
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CodecError> {
    ciborium::into_writer(value, out).map_err(|e| CodecError::Encode(e.to_string()))
}

fn canonicalize(value: Value) -> Result<Value, CodecError> {
    Ok(match value {
        Value::Float(_) => {
            return Err(CodecError::Encode(
                "floating-point values are not allowed in canonical CBOR".to_owned(),
            ));
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize)
                .collect::<Result<_, _>>()?,
        ),
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner)?)),
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key = canonicalize(key)?;
                let value = canonicalize(value)?;
                let mut encoded = Vec::new();
                write_value(&key, &mut encoded)?;
                keyed.push((encoded, key, value));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CodecError::Encode("duplicate map key".to_owned()));
            }
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Step {
        Put { key: String },
        Stop,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Command {
        name: String,
        #[serde(default)]
        steps: Vec<Step>,
        #[serde(default)]
        context: BTreeMap<String, String>,
    }

    fn command() -> Command {
        Command {
            name: "c".to_owned(),
            steps: vec![
                Step::Stop,
                Step::Put {
                    key: "k".to_owned(),
                },
            ],
            context: [("free".to_owned(), "form".to_owned())].into(),
        }
    }

    /// `command()` as a CBOR value with an extra entry in the map at `path` (field names
    /// and list positions).
    fn with_extra(path: &[&str]) -> Vec<u8> {
        fn visit(value: &mut Value, path: &[&str]) {
            match (value, path.split_first()) {
                (Value::Map(entries), None) => {
                    entries.push((
                        Value::Text("future".to_owned()),
                        Value::Text("later".to_owned()),
                    ));
                }
                (Value::Map(entries), Some((name, rest))) => {
                    let (_, inner) = entries
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Text((*name).to_owned()))
                        .expect("the path names a field");
                    visit(inner, rest);
                }
                (Value::Array(items), Some((n, rest))) => {
                    visit(&mut items[n.parse::<usize>().expect("a position")], rest);
                }
                (other, _) => panic!("no map at the path: {other:?}"),
            }
        }
        let mut value = Value::serialized(&command()).expect("value");
        visit(&mut value, path);
        let mut out = Vec::new();
        write_value(&value, &mut out).expect("encode");
        out
    }

    // An unknown field anywhere in a command fails the exact decode and names its place,
    // while the tolerant decode of the same bytes ignores it; the command without it
    // decodes exactly, and so do keys a map of free-form entries holds.
    #[test]
    fn an_exact_decode_refuses_a_field_the_type_does_not_know() {
        let plain = to_cbor(&command()).expect("encode");
        assert_eq!(
            from_cbor_exact::<Command>(&plain).expect("exact"),
            command()
        );
        for (path, named) in [
            (&[][..], "future"),
            (&["steps", "1", "Put"][..], "steps.1.Put.future"),
        ] {
            let extra = with_extra(path);
            let Err(CodecError::Decode(error)) = from_cbor_exact::<Command>(&extra) else {
                panic!("the extra field at {path:?} must not decode exactly");
            };
            assert_eq!(error, format!("unknown field `{named}`"));
            assert_eq!(from_cbor::<Command>(&extra).expect("tolerant"), command());
        }
        let free = with_extra(&["context"]);
        let decoded = from_cbor_exact::<Command>(&free).expect("a free-form key is kept");
        assert_eq!(decoded.context["future"], "later");
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Record {
        name: String,
        #[serde(default)]
        count: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }

    #[test]
    fn round_trips_through_cbor() {
        let record = Record {
            name: "host.example.test".to_owned(),
            count: 3,
            note: None,
        };
        let bytes = to_cbor(&record).expect("encode");
        assert_eq!(from_cbor::<Record>(&bytes).expect("decode"), record);
    }

    #[test]
    fn missing_defaulted_fields_decode() {
        #[derive(Serialize)]
        struct Old {
            name: String,
        }
        let bytes = to_cbor(&Old {
            name: "a".to_owned(),
        })
        .expect("encode");
        let record: Record = from_cbor(&bytes).expect("decode");
        assert_eq!(record.count, 0);
        assert_eq!(record.note, None);
    }

    #[test]
    fn canonical_encoding_ignores_map_insertion_order() {
        let forward: HashMap<String, u32> = (0..100).map(|i| (format!("k{i}"), i)).collect();
        let mut backward = HashMap::new();
        for i in (0..100).rev() {
            backward.insert(format!("k{i}"), i);
        }
        assert_eq!(
            to_canonical_cbor(&forward).expect("encode"),
            to_canonical_cbor(&backward).expect("encode")
        );
        let sorted: BTreeMap<String, u32> = forward.into_iter().collect();
        assert_eq!(
            canonical_sha256(&sorted).expect("hash"),
            canonical_sha256(&backward).expect("hash")
        );
    }

    #[test]
    fn canonical_encoding_sorts_struct_fields_by_encoded_key() {
        #[derive(Serialize)]
        struct Fields {
            zz: u8,
            a: u8,
        }
        // Map of two entries: "a" (shorter encoding) sorts before "zz".
        let bytes = to_canonical_cbor(&Fields { zz: 1, a: 2 }).expect("encode");
        assert_eq!(bytes, [0xA2, 0x61, b'a', 0x02, 0x62, b'z', b'z', 0x01]);
    }

    #[test]
    fn canonical_encoding_rejects_floats() {
        assert!(to_canonical_cbor(&1.5_f64).is_err());
    }

    #[test]
    fn decode_errors_are_coded() {
        let error = from_cbor::<Record>(&[0xFF]).expect_err("malformed");
        assert_eq!(error.code(), "sys.codec.decode");
    }
}
