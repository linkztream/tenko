//! Encodings shared by every store user: order-preserving binary keys ([`key`]) and CBOR
//! values ([`cbor`]).
//!
//! Values are CBOR through `ciborium`. Types that are stored add new fields with
//! `#[serde(default)]`, so replicas of different versions read each other's values during a
//! rolling upgrade (OPS-08). Wherever bytes are hashed (the audit chain, idempotency
//! fingerprints) the canonical encoding of [`cbor::to_canonical_cbor`] is used.
//!
//! # Rules for stored types
//!
//! - New fields carry `#[serde(default)]`; fields are never renamed or retyped.
//! - Enums whose variants carry IP addresses or prefixes (`IpAddr`, `IpNet`), directly or
//!   nested, use the externally tagged default or the adjacently tagged form
//!   (`#[serde(tag = "type", content = "data")]`), never `#[serde(tag = "…")]` alone,
//!   `untagged` or `flatten`. Serde buffers those representations through a deserializer
//!   that reports itself as human-readable, while CBOR is not, and `std::net` and `ipnet`
//!   types encode differently in the two modes, so the value would not decode.
//!   Identifiers, timestamps, MAC addresses, names and the other `tenko-core` value types
//!   decode in both modes.
//! - Every stored type has a CBOR round-trip test.

pub mod cbor;
pub mod key;

pub use cbor::{CodecError, canonical_sha256, from_cbor, to_canonical_cbor, to_cbor};
pub use key::{KeyCodec, KeyError, decode_key, encode_key, prefix_successor};
