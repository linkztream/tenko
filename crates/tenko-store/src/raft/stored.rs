//! The on-disk layout of `sm.redb` and the error mapping shared by the state machine.
//!
//! Every store table (`ipam.hosts`, `sys.audit`, `sys.journal`, ...) is one redb table of
//! byte keys and byte values with the same name. A stored value is the 8-byte big-endian
//! [`Revision`] that wrote it followed by the value itself, so a read returns a
//! [`Versioned`] without a second lookup. Store table names always contain a dot; the one
//! internal table, [`META`], does not, so the two can never collide. [`META`] holds the
//! [`SmMeta`] under the key [`META_STATE`], written in the same transaction as the data it
//! describes.

use std::fmt;

use bytes::Bytes;
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use tenko_core::{
    Revision, TableName,
    audit::ChainHead,
    codec::{from_cbor, to_cbor},
};

use super::types::{LogId, StorageError, StorageIOError, StoredMembership};
use crate::api::{StoreError, Versioned};

/// The internal metadata table.
pub(crate) const META: TableDefinition<&str, &[u8]> = TableDefinition::new("_meta");
/// The key of the [`SmMeta`] row.
pub(crate) const META_STATE: &str = "state";

/// The redb table that holds a store table.
pub(crate) fn data_table(name: &TableName) -> TableDefinition<'_, &'static [u8], &'static [u8]> {
    TableDefinition::new(name.as_str())
}

/// Whether a redb table name is a store table (and not internal).
pub(crate) fn is_store_table(name: &str) -> bool {
    name.contains('.')
}

/// State machine metadata, committed atomically with the data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SmMeta {
    /// The last Raft log id applied.
    pub last_applied: Option<LogId>,
    /// The last membership applied.
    pub membership: StoredMembership,
    /// The last store revision.
    pub revision: Revision,
    /// The head of the audit chain.
    pub audit_head: ChainHead,
    /// The oldest revision in the journal.
    pub journal_oldest: Option<Revision>,
    /// Change sets in the journal.
    pub journal_len: u64,
    /// Encoded bytes of the change sets in the journal (bounded by the byte limit).
    #[serde(default)]
    pub journal_bytes: u64,
    /// Bytes of live keys and values over all tables (without the revision prefix).
    pub data_bytes: u64,
}

impl SmMeta {
    pub(crate) fn encode(&self) -> Result<Bytes, StoreError> {
        Ok(to_cbor(self)?)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(from_cbor(bytes)?)
    }
}

/// Encodes a stored value: the revision, then the value.
pub(crate) fn encode_stored(revision: Revision, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + value.len());
    out.extend_from_slice(&revision.get().to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Decodes a stored value.
pub(crate) fn decode_stored(stored: &[u8]) -> Result<Versioned, StoreError> {
    let Some((revision, value)) = stored.split_first_chunk::<8>() else {
        return Err(StoreError::Storage(
            "stored value is shorter than its revision".to_owned(),
        ));
    };
    Ok(Versioned {
        value: Bytes::copy_from_slice(value),
        revision: Revision(u64::from_be_bytes(*revision)),
    })
}

/// The length of the value part of a stored value.
pub(crate) fn stored_value_len(stored: &[u8]) -> usize {
    stored.len().saturating_sub(8)
}

/// Decodes a counter value (absent counters are 0).
pub(crate) fn decode_counter(value: Option<&[u8]>) -> Result<u64, StoreError> {
    match value {
        None => Ok(0),
        Some(bytes) => <[u8; 8]>::try_from(bytes)
            .map(u64::from_be_bytes)
            .map_err(|_| StoreError::Codec("counter value is not eight bytes".to_owned())),
    }
}

/// `usize` to `u64`, saturating.
pub(crate) fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// A message as an error value for openraft's `AnyError`.
#[derive(Debug)]
pub(crate) struct Message(pub String);

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Message {}

/// A state machine write failure.
pub(crate) fn sm_write(error: impl fmt::Display) -> StorageError {
    StorageIOError::write_state_machine(&Message(error.to_string())).into()
}

/// A snapshot write failure.
pub(crate) fn snapshot_write(error: impl fmt::Display) -> StorageError {
    StorageIOError::write_snapshot(None, &Message(error.to_string())).into()
}

/// A redb or I/O failure as a store error.
pub(crate) fn storage(error: impl fmt::Display) -> StoreError {
    StoreError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_values_round_trip() {
        let stored = encode_stored(Revision(7), b"value");
        assert_eq!(stored_value_len(&stored), 5);
        assert_eq!(
            decode_stored(&stored).expect("decode"),
            Versioned {
                value: Bytes::from_static(b"value"),
                revision: Revision(7),
            }
        );
        assert!(decode_stored(&[1, 2, 3]).is_err());
    }

    #[test]
    fn meta_round_trips() {
        let meta = SmMeta {
            revision: Revision(3),
            journal_len: 2,
            ..SmMeta::default()
        };
        assert_eq!(
            SmMeta::decode(&meta.encode().expect("encode")).expect("decode"),
            meta
        );
    }

    #[test]
    fn internal_tables_are_not_store_tables() {
        assert!(!is_store_table("_meta"));
        assert!(is_store_table("ipam.hosts"));
    }
}
