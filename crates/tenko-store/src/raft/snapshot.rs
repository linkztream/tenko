//! Snapshot files.
//!
//! A snapshot is the whole state machine at one log id, streamed from a redb read
//! transaction (an MVCC snapshot, so writers continue while it is written) into one file:
//!
//! ```text
//! "TNKSNAP1"
//! u32 BE header length | CBOR SnapshotHeader { format, meta, state }
//! { 0x01 | u16 BE name length | table name                     }   a table starts
//! { 0x02 | u32 BE key length | key | u32 BE value length | value }   a row (stored form)
//! 0xFF | SHA-256 of every byte before it
//! ```
//!
//! WP9.6 (ADR 0030): from format 2 on, everything after the header (the records, the end
//! tag and the hash) is one raw DEFLATE stream (`compress`), and the hash covers the bytes
//! before compression, so it checks what the install reads. Format 1 files, written before,
//! are read as they were.
//!
//! Tables appear in name order and rows in key order, so an install writes every redb
//! B-tree sequentially (Spike A: a snapshot-installed `sm.redb` is about half the size of
//! an incrementally written one, which is what re-seeding relies on, ADR 0002). The file is
//! written to a `.part` name, synced and renamed, so a complete name is a complete file;
//! the trailing hash is checked when the file is installed, before the transaction commits.
//! Transfer to another node streams the file in chunks (see `network`).

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    path::Path,
};

use flate2::{read::DeflateDecoder, write::DeflateEncoder};
use redb::{ReadTransaction, ReadableTable, TableHandle};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::codec::{from_cbor, to_cbor};

use super::{
    stored::{SmMeta, is_store_table, storage},
    types::SnapshotMeta,
};
use crate::api::StoreError;

const MAGIC: &[u8; 8] = b"TNKSNAP1";
/// The format version written into the header: 2, the records compressed.
pub(crate) const FORMAT: u32 = 2;
/// The format of the files written before WP9.6: the records as they are.
pub(crate) const FORMAT_PLAIN: u32 = 1;
const TAG_TABLE: u8 = 0x01;
const TAG_ROW: u8 = 0x02;
const TAG_END: u8 = 0xFF;
const BUFFER: usize = 1 << 20;
/// Upper bound of one length field: a corrupt length fails cleanly instead of allocating.
const MAX_FIELD: u32 = 256 * 1024 * 1024;

/// What a snapshot file describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SnapshotHeader {
    /// [`FORMAT`].
    pub(crate) format: u32,
    /// openraft's metadata: last log id, membership, snapshot id.
    pub(crate) meta: SnapshotMeta,
    /// The state machine metadata at that log id.
    pub(crate) state: SmMeta,
}

/// Totals of a written snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WrittenSnapshot {
    pub(crate) bytes: u64,
    pub(crate) tables: u64,
    pub(crate) rows: u64,
}

/// Where the bytes of a snapshot go: the file, or a DEFLATE stream into it.
enum Sink {
    Plain(BufWriter<File>),
    Deflate(DeflateEncoder<BufWriter<File>>),
    Switching,
}

impl Sink {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Sink::Plain(out) => out.write_all(data),
            Sink::Deflate(out) => out.write_all(data),
            Sink::Switching => Err(io::Error::other("the snapshot writer is switching")),
        }
    }

    /// Everything written from now on is compressed.
    fn compress(&mut self) {
        if let Sink::Plain(out) = std::mem::replace(self, Sink::Switching) {
            *self = Sink::Deflate(DeflateEncoder::new(out, super::compress::level()));
        }
    }

    /// The file, with everything written to it.
    fn finish(self) -> io::Result<File> {
        let out = match self {
            Sink::Plain(out) => out,
            Sink::Deflate(out) => out.finish()?,
            Sink::Switching => return Err(io::Error::other("the snapshot writer is switching")),
        };
        out.into_inner().map_err(io::IntoInnerError::into_error)
    }
}

struct HashingWriter {
    out: Sink,
    hasher: Sha256,
}

impl HashingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.hasher.update(data);
        self.out.write_all(data)
    }
}

fn length_u32(len: usize, what: &str) -> io::Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| io::Error::other(format!("{what} too long for a snapshot")))
}

/// Writes every store table of `txn` with `header` into `path` (synced to disk).
pub(crate) fn write_snapshot(
    txn: &ReadTransaction,
    header: &SnapshotHeader,
    path: &Path,
) -> Result<WrittenSnapshot, StoreError> {
    let file = File::create(path).map_err(storage)?;
    let mut out = HashingWriter {
        out: Sink::Plain(BufWriter::with_capacity(BUFFER, file)),
        hasher: Sha256::new(),
    };
    let encoded = to_cbor(header)?;
    out.write(MAGIC).map_err(storage)?;
    out.write(&length_u32(encoded.len(), "header").map_err(storage)?)
        .map_err(storage)?;
    out.write(&encoded).map_err(storage)?;
    if header.format != FORMAT_PLAIN {
        out.out.compress();
    }

    let mut names: Vec<String> = txn
        .list_tables()
        .map_err(storage)?
        .map(|handle| handle.name().to_owned())
        .filter(|name| is_store_table(name))
        .collect();
    names.sort();
    let (mut tables, mut rows) = (0_u64, 0_u64);
    for name in names {
        let definition = redb::TableDefinition::<&[u8], &[u8]>::new(&name);
        let table = txn.open_table(definition).map_err(storage)?;
        let name_len = u16::try_from(name.len())
            .map_err(|_| StoreError::Storage(format!("table name {name} too long")))?;
        out.write(&[TAG_TABLE]).map_err(storage)?;
        out.write(&name_len.to_be_bytes()).map_err(storage)?;
        out.write(name.as_bytes()).map_err(storage)?;
        tables += 1;
        for item in table.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let (key, value) = (key.value(), value.value());
            out.write(&[TAG_ROW]).map_err(storage)?;
            out.write(&length_u32(key.len(), "key").map_err(storage)?)
                .map_err(storage)?;
            out.write(key).map_err(storage)?;
            out.write(&length_u32(value.len(), "value").map_err(storage)?)
                .map_err(storage)?;
            out.write(value).map_err(storage)?;
            rows += 1;
        }
    }
    out.write(&[TAG_END]).map_err(storage)?;
    let digest: [u8; 32] = out.hasher.clone().finalize().into();
    out.out.write_all(&digest).map_err(storage)?;
    let file = out
        .out
        .finish()
        .map_err(|error| StoreError::Storage(error.to_string()))?;
    file.sync_all().map_err(storage)?;
    let bytes = file.metadata().map_err(storage)?.len();
    Ok(WrittenSnapshot {
        bytes,
        tables,
        rows,
    })
}

/// One record of a snapshot file.
pub(crate) enum Record<'a> {
    /// The rows that follow belong to this table.
    Table(&'a str),
    /// A row: key and stored value.
    Row(&'a [u8], &'a [u8]),
}

/// Reads a snapshot file sequentially and checks its hash at the end.
pub(crate) struct SnapshotReader {
    input: Box<dyn Read + Send>,
    hasher: Sha256,
    header: SnapshotHeader,
    name: String,
    key: Vec<u8>,
    value: Vec<u8>,
    done: bool,
}

impl SnapshotReader {
    /// Opens a file and reads its header.
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let file = File::open(path).map_err(storage)?;
        let mut input = BufReader::with_capacity(BUFFER, file);
        let mut hasher = Sha256::new();
        let mut magic = [0_u8; 8];
        read_hashed(&mut input, &mut hasher, &mut magic)?;
        if &magic != MAGIC {
            return Err(StoreError::Storage(format!(
                "{} is not a snapshot file",
                path.display()
            )));
        }
        let len = read_u32(&mut input, &mut hasher)?;
        let mut encoded = vec![0_u8; usize::try_from(len).map_err(storage)?];
        read_hashed(&mut input, &mut hasher, &mut encoded)?;
        let header: SnapshotHeader = from_cbor(&encoded)?;
        let input: Box<dyn Read + Send> = match header.format {
            FORMAT_PLAIN => Box::new(input),
            FORMAT => Box::new(BufReader::with_capacity(BUFFER, DeflateDecoder::new(input))),
            other => {
                return Err(StoreError::Storage(format!(
                    "snapshot format {other} is not supported (expected {FORMAT_PLAIN} or {FORMAT})"
                )));
            }
        };
        Ok(Self {
            input,
            hasher,
            header,
            name: String::new(),
            key: Vec::new(),
            value: Vec::new(),
            done: false,
        })
    }

    /// The header.
    pub(crate) fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    /// The next record, or `None` at the end once the hash has been verified.
    pub(crate) fn next_record(&mut self) -> Result<Option<Record<'_>>, StoreError> {
        if self.done {
            return Ok(None);
        }
        let mut tag = [0_u8; 1];
        read_hashed(&mut self.input, &mut self.hasher, &mut tag)?;
        match tag[0] {
            TAG_TABLE => {
                let mut len = [0_u8; 2];
                read_hashed(&mut self.input, &mut self.hasher, &mut len)?;
                let mut name = vec![0_u8; usize::from(u16::from_be_bytes(len))];
                read_hashed(&mut self.input, &mut self.hasher, &mut name)?;
                self.name = String::from_utf8(name).map_err(storage)?;
                Ok(Some(Record::Table(&self.name)))
            }
            TAG_ROW => {
                let len = read_u32(&mut self.input, &mut self.hasher)?;
                self.key.resize(usize::try_from(len).map_err(storage)?, 0);
                read_hashed(&mut self.input, &mut self.hasher, &mut self.key)?;
                let len = read_u32(&mut self.input, &mut self.hasher)?;
                self.value.resize(usize::try_from(len).map_err(storage)?, 0);
                read_hashed(&mut self.input, &mut self.hasher, &mut self.value)?;
                Ok(Some(Record::Row(&self.key, &self.value)))
            }
            TAG_END => {
                let expected: [u8; 32] = self.hasher.clone().finalize().into();
                let mut stored = [0_u8; 32];
                self.input.read_exact(&mut stored).map_err(storage)?;
                if stored != expected {
                    return Err(StoreError::Storage(
                        "snapshot file is corrupt: hash mismatch".to_owned(),
                    ));
                }
                let mut rest = [0_u8; 1];
                if self.input.read(&mut rest).map_err(storage)? != 0 {
                    return Err(StoreError::Storage(
                        "snapshot file has trailing bytes".to_owned(),
                    ));
                }
                self.done = true;
                Ok(None)
            }
            other => Err(StoreError::Storage(format!(
                "snapshot file is corrupt: unknown record tag {other:#04x}"
            ))),
        }
    }
}

fn read_hashed(
    input: &mut impl Read,
    hasher: &mut Sha256,
    buf: &mut [u8],
) -> Result<(), StoreError> {
    input.read_exact(buf).map_err(storage)?;
    hasher.update(&*buf);
    Ok(())
}

fn read_u32(input: &mut impl Read, hasher: &mut Sha256) -> Result<u32, StoreError> {
    let mut buf = [0_u8; 4];
    read_hashed(input, hasher, &mut buf)?;
    let len = u32::from_be_bytes(buf);
    if len > MAX_FIELD {
        return Err(StoreError::Storage(format!(
            "snapshot file is corrupt: field of {len} bytes"
        )));
    }
    Ok(len)
}

/// Reads only the header of a snapshot file.
pub(crate) fn read_header(path: &Path) -> Result<SnapshotHeader, StoreError> {
    SnapshotReader::open(path).map(|reader| reader.header)
}

#[cfg(test)]
mod tests {
    use redb::{Database, ReadableDatabase, TableDefinition};
    use tenko_core::Revision;

    use super::*;
    use crate::raft::stored::META;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tenko-snapshot-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn snapshots_round_trip_and_detect_corruption() {
        round_trip_and_corruption("round-trip", FORMAT);
    }

    // WP9.6: a file of the format before compression still reads, and the compressed one
    // is several times smaller.
    #[test]
    fn plain_snapshots_still_read_and_compressed_ones_are_smaller() {
        let plain = round_trip_and_corruption("plain", FORMAT_PLAIN);
        let compressed = round_trip_and_corruption("compressed", FORMAT);
        assert!(
            compressed * 3 < plain,
            "compressed {compressed} octets, plain {plain}"
        );
    }

    /// Writes, reads and corrupts a snapshot of `format`; returns its size.
    fn round_trip_and_corruption(name: &str, format: u32) -> u64 {
        let dir = temp_dir(name);
        let db = Database::builder()
            .set_cache_size(1 << 20)
            .create(dir.join("sm.redb"))
            .expect("create");
        let txn = db.begin_write().expect("write");
        {
            let mut rows = txn
                .open_table(TableDefinition::<&[u8], &[u8]>::new("ipam.rows"))
                .expect("table");
            for n in 0..100_u32 {
                rows.insert(&n.to_be_bytes()[..], &[7_u8; 20][..])
                    .expect("insert");
            }
            txn.open_table(TableDefinition::<&[u8], &[u8]>::new("jobs.empty"))
                .expect("table");
            txn.open_table(META).expect("meta");
        }
        txn.commit().expect("commit");

        let header = SnapshotHeader {
            format,
            meta: SnapshotMeta::default(),
            state: SmMeta {
                revision: Revision(5),
                ..SmMeta::default()
            },
        };
        let path = dir.join("snap.tnks");
        let written =
            write_snapshot(&db.begin_read().expect("read"), &header, &path).expect("write");
        assert_eq!((written.tables, written.rows), (2, 100));
        assert_eq!(
            written.bytes,
            std::fs::metadata(&path).expect("metadata").len()
        );

        let mut reader = SnapshotReader::open(&path).expect("open");
        assert_eq!(reader.header(), &header);
        let mut seen = Vec::new();
        while let Some(record) = reader.next_record().expect("record") {
            match record {
                Record::Table(name) => seen.push(name.to_owned()),
                Record::Row(_, value) => assert_eq!(value, &[7_u8; 20][..]),
            }
        }
        assert_eq!(seen, vec!["ipam.rows".to_owned(), "jobs.empty".to_owned()]);

        let mut bytes = std::fs::read(&path).expect("read");
        // Inside the value of the last row (the file ends with the end tag and the hash).
        let inside = bytes.len() - 40;
        bytes[inside] ^= 0xFF;
        std::fs::write(&path, bytes).expect("write");
        let mut reader = SnapshotReader::open(&path).expect("open");
        let error = loop {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("a corrupt file must not verify"),
                Err(error) => break error,
            }
        };
        assert!(matches!(error, StoreError::Storage(_)));
        drop(reader);
        drop(db);
        std::fs::remove_dir_all(&dir).expect("clean up");
        written.bytes
    }
}
