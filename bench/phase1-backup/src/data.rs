//! The M6 data set: 1,000,000 RRset-like records of 150 bytes (22 byte key, 128 byte value).
//!
//! Equivalent to `bench/phase1-store/src/data.rs`: the same key layout, the same value
//! generator, bulk batches of 10,000 records with one audit draft each.

use bytes::Bytes;
use tenko_core::{
    Principal, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::WriteBatch;

/// The table that holds the synthetic `RRsets`.
pub const RRSETS: TableName = TableName::from_static("ipam.bench_rrsets");
/// The audit action of benchmark writes.
pub const WRITE: AuditAction = AuditAction::from_static("ipam.bench.write");

pub const KEY_LEN: usize = 22;
pub const VALUE_LEN: usize = 128;
/// Records per batch of bulk loads.
pub const BULK_BATCH: u64 = 10_000;

/// The splitmix64 output function.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The key of record `n`, in key order for increasing `n`.
fn key(n: u64) -> Bytes {
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
    Bytes::copy_from_slice(&key)
}

/// The value of record `n` in generation `generation`.
fn value(n: u64, generation: u32) -> Bytes {
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

/// A batch that writes records `first..last` in generation 0, with one audit draft.
pub fn put_batch(first: u64, last: u64) -> WriteBatch {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), Timestamp::now());
    for id in first..last {
        batch.put(RRSETS, key(id), value(id, 0));
    }
    batch.audit(AuditDraft::success(WRITE, Vec::new()));
    batch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_150_bytes_and_ordered() {
        assert_eq!(key(0).len() + value(0, 0).len(), 150);
        assert!(key(9) < key(10));
        assert_eq!(&key(42)[9..19], b"0000000042");
    }

    #[test]
    fn batches_validate() {
        let batch = put_batch(0, BULK_BATCH);
        assert_eq!(batch.mutations.len(), 10_000);
        assert!(batch.validate(16 * 1024 * 1024).is_ok());
    }
}
