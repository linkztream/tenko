//! openraft type configuration and the application request carried in Raft entries.

use std::fmt;
use std::io::Cursor;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

pub type NodeId = u64;

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Request,
        R = Response,
        NodeId = NodeId,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = SnapshotFile,
        AsyncRuntime = openraft::TokioRuntime,
);

// Referenced by the default-type list inside `declare_raft_types!`.
#[allow(dead_code)]
type _CursorForMacro = Cursor<Vec<u8>>;

pub type Raft = openraft::Raft<TypeConfig>;
pub type Entry = openraft::Entry<TypeConfig>;
pub type LogId = openraft::LogId<NodeId>;
pub type Vote = openraft::Vote<NodeId>;
pub type StoredMembership = openraft::StoredMembership<NodeId, openraft::BasicNode>;
pub type SnapshotMeta = openraft::SnapshotMeta<NodeId, openraft::BasicNode>;
pub type Snapshot = openraft::Snapshot<TypeConfig>;
pub type StorageError = openraft::StorageError<NodeId>;
pub type StorageIOError = openraft::StorageIOError<NodeId>;

/// Snapshot payload: a file on the local disk of the node that owns it.
#[derive(Debug)]
pub struct SnapshotFile {
    pub path: PathBuf,
}

/// Application command replicated through Raft.
#[derive(Clone, Serialize, Deserialize)]
pub enum Request {
    /// Insert or replace a batch of RRsets.
    Upsert(RecordBatch),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::Upsert(b) => write!(
                f,
                "Upsert({} records, {} bytes, journal={})",
                b.count,
                b.data.len(),
                b.journal
            ),
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub applied: u32,
}

/// A batch of encoded `(key, value)` pairs packed into one buffer (one allocation per Raft
/// entry instead of two per record):
///
/// ```text
/// { key_len (u16 BE) | key | value_len (u32 BE) | value }*
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct RecordBatch {
    pub count: u32,
    /// Record the changes in the change journal (IXFR source). Bulk zone imports set this to
    /// false, incremental updates to true.
    pub journal: bool,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl RecordBatch {
    pub fn with_capacity(bytes: usize, journal: bool) -> Self {
        Self {
            count: 0,
            journal,
            data: Vec::with_capacity(bytes),
        }
    }

    pub fn push(&mut self, key: &[u8], value: &[u8]) {
        self.data
            .extend_from_slice(&(key.len() as u16).to_be_bytes());
        self.data.extend_from_slice(key);
        self.data
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.data.extend_from_slice(value);
        self.count += 1;
    }

    pub fn iter(&self) -> BatchIter<'_> {
        BatchIter { data: &self.data }
    }
}

pub struct BatchIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for BatchIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 2 {
            return None;
        }
        let kl = u16::from_be_bytes([self.data[0], self.data[1]]) as usize;
        let key = &self.data[2..2 + kl];
        let rest = &self.data[2 + kl..];
        let vl = u32::from_be_bytes(rest[0..4].try_into().ok()?) as usize;
        let value = &rest[4..4 + vl];
        self.data = &rest[4 + vl..];
        Some((key, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_roundtrip() {
        let mut b = RecordBatch::with_capacity(64, true);
        b.push(b"k1", b"v1");
        b.push(b"key2", b"");
        let v: Vec<_> = b.iter().collect();
        assert_eq!(v, vec![(&b"k1"[..], &b"v1"[..]), (&b"key2"[..], &b""[..])]);
        let enc = postcard::to_stdvec(&Request::Upsert(b)).unwrap();
        let Request::Upsert(d) = postcard::from_bytes::<Request>(&enc).unwrap();
        assert_eq!(d.count, 2);
        assert!(d.journal);
    }
}
