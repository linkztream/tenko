//! Data model shared by the generator, the Raft state machine and the serving index.
//!
//! A record set (RRset) is keyed by `(zone_id, owner_name, rtype)`. The owner name is
//! lower-case and relative to the zone apex. The key is encoded into a single byte string so
//! that the same bytes can be used as the redb table key and as the in-memory index key:
//!
//! ```text
//! zone_id (u32, big endian) | owner name bytes | 0x00 | rtype (u16, big endian)
//! ```
//!
//! The stored value is the postcard encoding of [`StoredRRset`]: TTL, RDATA list in DNS wire
//! format, plus the management metadata a DDI product keeps per record (timestamps, source,
//! IPAM reference, free-text comment). The serving index keeps only the answer-relevant part
//! (see [`serving_form`]).

#![allow(dead_code)] // Helpers kept for tests and debugging.

use serde::Deserialize;
use serde::Serialize;

/// Forward zone `example.test`.
pub const ZONE_FORWARD: u32 = 1;
/// Reverse zone `2.0.192.in-addr.arpa` (RFC 5737 TEST-NET-1).
pub const ZONE_REV_192_0_2: u32 = 2;
/// Reverse zone `100.51.198.in-addr.arpa` (RFC 5737 TEST-NET-2).
pub const ZONE_REV_198_51_100: u32 = 3;
/// Reverse zone `113.0.203.in-addr.arpa` (RFC 5737 TEST-NET-3).
pub const ZONE_REV_203_0_113: u32 = 4;

/// Human-readable apex for a zone id (used in reports and debug output only).
pub fn zone_apex(zone_id: u32) -> &'static str {
    match zone_id {
        ZONE_FORWARD => "example.test",
        ZONE_REV_192_0_2 => "2.0.192.in-addr.arpa",
        ZONE_REV_198_51_100 => "100.51.198.in-addr.arpa",
        ZONE_REV_203_0_113 => "113.0.203.in-addr.arpa",
        _ => "unknown.test",
    }
}

pub const RTYPE_A: u16 = 1;
pub const RTYPE_PTR: u16 = 12;

/// Where a record came from (management metadata).
pub const SOURCE_MANUAL: u8 = 0;
pub const SOURCE_IPAM: u8 = 1;
pub const SOURCE_DDNS: u8 = 2;

/// Management metadata kept with every RRset in the persistent store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMeta {
    pub created_unix: u64,
    pub modified_unix: u64,
    pub source: u8,
    pub ipam_ref: u64,
    pub comment: String,
}

/// The persistent value of one RRset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRRset {
    pub ttl: u32,
    /// RDATA of every RR in the set, in DNS wire format.
    pub rdata: Vec<Vec<u8>>,
    pub meta: RecordMeta,
}

/// One RRset with its key parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub zone_id: u32,
    /// Lower-case owner name relative to the zone apex, e.g. `host-42` or `45.17`.
    pub owner: String,
    pub rtype: u16,
    pub rrset: StoredRRset,
}

impl Record {
    /// Encoded `(key, value)` pair as written to redb and carried in Raft entries.
    pub fn encoded(&self) -> (Vec<u8>, Vec<u8>) {
        (
            encode_key(self.zone_id, &self.owner, self.rtype),
            encode_value(&self.rrset),
        )
    }
}

/// Encode a record key. See the module documentation for the layout.
pub fn encode_key(zone_id: u32, owner: &str, rtype: u16) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + owner.len() + 1 + 2);
    k.extend_from_slice(&zone_id.to_be_bytes());
    k.extend_from_slice(owner.as_bytes());
    k.push(0);
    k.extend_from_slice(&rtype.to_be_bytes());
    k
}

/// Decode a record key produced by [`encode_key`].
pub fn decode_key(key: &[u8]) -> Option<(u32, &str, u16)> {
    if key.len() < 7 {
        return None;
    }
    let zone_id = u32::from_be_bytes(key[0..4].try_into().ok()?);
    let n = key.len();
    if key[n - 3] != 0 {
        return None;
    }
    let rtype = u16::from_be_bytes(key[n - 2..n].try_into().ok()?);
    let owner = std::str::from_utf8(&key[4..n - 3]).ok()?;
    Some((zone_id, owner, rtype))
}

/// postcard encoding of a stored RRset.
pub fn encode_value(v: &StoredRRset) -> Vec<u8> {
    postcard::to_stdvec(v).expect("postcard encoding of StoredRRset cannot fail")
}

pub fn decode_value(bytes: &[u8]) -> anyhow::Result<StoredRRset> {
    Ok(postcard::from_bytes(bytes)?)
}

/// The compact form kept in the in-memory serving index: only what is needed to build an
/// answer.
///
/// ```text
/// ttl (u32 BE) | rr count (u16 BE) | { rdlength (u16 BE) | rdata }*
/// ```
pub fn serving_form(v: &StoredRRset) -> Vec<u8> {
    let len = 6 + v.rdata.iter().map(|r| 2 + r.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&v.ttl.to_be_bytes());
    out.extend_from_slice(&(v.rdata.len() as u16).to_be_bytes());
    for r in &v.rdata {
        out.extend_from_slice(&(r.len() as u16).to_be_bytes());
        out.extend_from_slice(r);
    }
    out
}

/// Build the serving form directly from the encoded stored value.
pub fn serving_form_from_value(value: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(serving_form(&decode_value(value)?))
}

/// Encode a domain name (absolute, dot separated, no trailing dot required) in DNS wire format.
pub fn name_to_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let k = encode_key(7, "host-12", RTYPE_A);
        assert_eq!(decode_key(&k), Some((7, "host-12", RTYPE_A)));
    }

    #[test]
    fn serving_form_layout() {
        let v = StoredRRset {
            ttl: 300,
            rdata: vec![vec![192, 0, 2, 1]],
            meta: RecordMeta {
                created_unix: 1,
                modified_unix: 2,
                source: SOURCE_IPAM,
                ipam_ref: 3,
                comment: String::new(),
            },
        };
        let s = serving_form(&v);
        assert_eq!(s, vec![0, 0, 1, 44, 0, 1, 0, 4, 192, 0, 2, 1]);
        assert_eq!(serving_form_from_value(&encode_value(&v)).unwrap(), s);
    }

    #[test]
    fn wire_name() {
        assert_eq!(name_to_wire("a.bc."), vec![1, b'a', 2, b'b', b'c', 0]);
    }
}
