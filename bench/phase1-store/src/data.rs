//! Record shapes and batch builders shared by the measurements.
//!
//! An RRset-like record has a 22 byte key (zone id, owner label `host-<10 digits>`, a zero
//! byte and the record type) and a 128 byte value, 150 bytes together, like the 150.7 byte
//! average of Spike A. The value starts with the record id and a generation so that readers
//! can check what they got; the rest is pseudo-random, so redb cannot do anything clever with
//! it.

use bytes::Bytes;
use tenko_core::{
    Principal, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::WriteBatch;

use crate::common::mix;

/// The table that holds the synthetic `RRsets`.
pub const RRSETS: TableName = TableName::from_static("ipam.bench_rrsets");
/// The audit action of benchmark writes.
pub const WRITE: AuditAction = AuditAction::from_static("ipam.bench.write");

pub const KEY_LEN: usize = 22;
pub const VALUE_LEN: usize = 128;
/// Records per batch of bulk loads and churn (ADR 0002 decision 4).
pub const BULK_BATCH: usize = 10_000;

/// The key of record `n`, in key order for increasing `n`.
pub fn key_array(n: u64) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[..4].copy_from_slice(&1_u32.to_be_bytes());
    key[4..9].copy_from_slice(b"host-");
    let mut rest = n;
    for slot in key[9..19].iter_mut().rev() {
        *slot = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        rest /= 10;
    }
    key[19] = 0;
    key[20..22].copy_from_slice(&1_u16.to_be_bytes());
    key
}

pub fn key(n: u64) -> Bytes {
    Bytes::copy_from_slice(&key_array(n))
}

/// The value of record `n` in generation `generation`.
pub fn value(n: u64, generation: u32) -> Bytes {
    let mut out = vec![0_u8; VALUE_LEN];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out[8..12].copy_from_slice(&generation.to_le_bytes());
    let mut state = mix(n ^ (u64::from(generation) << 40));
    for chunk in out[12..].chunks_mut(8) {
        state = mix(state);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Bytes::from(out)
}

/// The record id stored in a value, if it is long enough.
pub fn id_of(value: &[u8]) -> Option<u64> {
    value
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
}

/// The generation stored in a value, if it is long enough.
pub fn generation_of(value: &[u8]) -> Option<u32> {
    value
        .get(8..12)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
}

pub fn principal() -> Principal {
    Principal::system(SystemComponent::Ipam)
}

/// An empty batch stamped with the current time.
pub fn new_batch() -> WriteBatch {
    WriteBatch::new(principal(), Timestamp::now())
}

pub fn audit_draft() -> AuditDraft {
    AuditDraft::success(WRITE, Vec::new())
}

/// A batch that writes the given records in one generation, with one audit draft.
pub fn put_batch(ids: &[u64], generation: u32) -> WriteBatch {
    let mut batch = new_batch();
    for &id in ids {
        batch.put(RRSETS, key(id), value(id, generation));
    }
    batch.audit(audit_draft());
    batch
}

/// A batch that writes and deletes records, with one audit draft.
pub fn mixed_batch(puts: &[u64], generation: u32, deletes: &[u64]) -> WriteBatch {
    let mut batch = new_batch();
    for &id in puts {
        batch.put(RRSETS, key(id), value(id, generation));
    }
    for &id in deletes {
        batch.delete(RRSETS, key(id));
    }
    batch.audit(audit_draft());
    batch
}

/// A DNS-update-like batch: one record, one audit draft.
pub fn update_batch(id: u64, generation: u32) -> WriteBatch {
    put_batch(&[id], generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_150_bytes_and_ordered() {
        assert_eq!(key(0).len() + value(0, 0).len(), 150);
        assert!(key(9) < key(10));
        assert!(key(999_999) < key(1_000_000));
        assert_eq!(&key(42)[9..19], b"0000000042");
    }

    #[test]
    fn values_carry_id_and_generation() {
        let v = value(123_456, 7);
        assert_eq!(id_of(&v), Some(123_456));
        assert_eq!(generation_of(&v), Some(7));
        assert_ne!(value(5, 1), value(5, 2));
        assert_eq!(value(5, 1), value(5, 1));
    }

    #[test]
    fn batches_validate() {
        let batch = put_batch(&[1, 2, 3], 0);
        assert_eq!(batch.mutations.len(), 3);
        assert!(batch.validate(16 * 1024 * 1024).is_ok());
        let big = put_batch(&(0..10_000).collect::<Vec<_>>(), 0);
        assert!(big.validate(16 * 1024 * 1024).is_ok());
    }
}
