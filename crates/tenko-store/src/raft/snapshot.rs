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
//!
//! The reader is bounded by declared limits, so a file that was crafted or damaged fails
//! cleanly instead of making it allocate or write without bound: the header at most
//! [`MAX_HEADER`] bytes, a key at most [`MAX_KEY`], a value at most [`MAX_FIELD`], and the
//! records of a file at most [`records_bound`] bytes after decompression: [`MAX_EXPANSION`]
//! times the size of the file, at least [`EXPANSION_FLOOR`] and at most [`MAX_PLAIN`]. The
//! records are written into the new state file as they are read, before the trailing hash
//! is checked, so the bound is what keeps a small file from a peer from filling the disk.

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
/// Upper bound of a value's length field: a corrupt length fails cleanly instead of
/// allocating.
pub(crate) const MAX_FIELD: u32 = 256 * 1024 * 1024;
/// Upper bound of a key's length field (the store's keys are short identifiers).
pub(crate) const MAX_KEY: u32 = 64 * 1024;
/// Upper bound of the header's length field.
pub(crate) const MAX_HEADER: u32 = 1 << 20;
/// Upper bound of the bytes of records a reader takes from one file, after
/// decompression: the expansion of a compressed snapshot is bounded by it, not by the size
/// of the file.
pub(crate) const MAX_PLAIN: u64 = 64 << 30;
/// How many times its own size a snapshot file may expand to. The store's records compress
/// a few times (CBOR maps, identifiers, hashes); a file that expands far more is a
/// compression bomb, not a store.
pub(crate) const MAX_EXPANSION: u64 = 64;
/// The bytes of records any snapshot file may hold, whatever its size.
pub(crate) const EXPANSION_FLOOR: u64 = 1 << 30;

/// The most bytes of records a snapshot file of `file_bytes` bytes may hold.
pub(crate) fn records_bound(file_bytes: u64) -> u64 {
    file_bytes
        .saturating_mul(MAX_EXPANSION)
        .clamp(EXPANSION_FLOOR, MAX_PLAIN)
}

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
    /// Bytes of records, as a reader counts them against [`records_bound`].
    pub(crate) records: u64,
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
    /// Bytes hashed so far.
    hashed: u64,
}

impl HashingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.hasher.update(data);
        self.hashed += u64::try_from(data.len()).unwrap_or(u64::MAX);
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
        hashed: 0,
    };
    let encoded = to_cbor(header)?;
    out.write(MAGIC).map_err(storage)?;
    out.write(&length_u32(encoded.len(), "header").map_err(storage)?)
        .map_err(storage)?;
    out.write(&encoded).map_err(storage)?;
    let header_bytes = out.hashed;
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
    let records = out.hashed - header_bytes;
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
        records,
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
    /// Bytes of records read so far, after decompression.
    plain: u64,
    /// The most bytes of records this reader takes ([`records_bound`]).
    plain_limit: u64,
    /// The size of the file.
    file_bytes: u64,
    done: bool,
}

impl SnapshotReader {
    /// Opens a file and reads its header; its records may hold at most [`records_bound`]
    /// bytes.
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_limit(path, None)
    }

    /// Opens a file and reads its header; its records may hold at most `plain_limit` bytes,
    /// by default [`records_bound`] of the file's size.
    pub(crate) fn open_with_limit(
        path: &Path,
        plain_limit: Option<u64>,
    ) -> Result<Self, StoreError> {
        let file = File::open(path).map_err(storage)?;
        let file_bytes = file.metadata().map_err(storage)?.len();
        let plain_limit = plain_limit.unwrap_or_else(|| records_bound(file_bytes));
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
        let len = read_u32(&mut input, &mut hasher, MAX_HEADER, "header")?;
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
            plain: 0,
            plain_limit,
            file_bytes,
            done: false,
        })
    }

    /// Counts `len` bytes of records against the limit before they are read.
    fn take(&mut self, len: usize) -> Result<(), StoreError> {
        self.plain = self
            .plain
            .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        if self.plain > self.plain_limit {
            return Err(StoreError::Storage(format!(
                "the snapshot file of {} bytes holds more than {} bytes of records ({} reached): \
                 a file may expand to {MAX_EXPANSION} times its size, at least {EXPANSION_FLOOR} \
                 and at most {MAX_PLAIN} bytes",
                self.file_bytes, self.plain_limit, self.plain
            )));
        }
        Ok(())
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
        self.take(1)?;
        match tag[0] {
            TAG_TABLE => {
                let mut len = [0_u8; 2];
                read_hashed(&mut self.input, &mut self.hasher, &mut len)?;
                let name_len = usize::from(u16::from_be_bytes(len));
                self.take(2 + name_len)?;
                let mut name = vec![0_u8; name_len];
                read_hashed(&mut self.input, &mut self.hasher, &mut name)?;
                self.name = String::from_utf8(name).map_err(storage)?;
                Ok(Some(Record::Table(&self.name)))
            }
            TAG_ROW => {
                let len = read_u32(&mut self.input, &mut self.hasher, MAX_KEY, "key")?;
                let key_len = usize::try_from(len).map_err(storage)?;
                self.take(4 + key_len)?;
                self.key.resize(key_len, 0);
                read_hashed(&mut self.input, &mut self.hasher, &mut self.key)?;
                let len = read_u32(&mut self.input, &mut self.hasher, MAX_FIELD, "value")?;
                let value_len = usize::try_from(len).map_err(storage)?;
                self.take(4 + value_len)?;
                self.value.resize(value_len, 0);
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

/// Reads a length field of `what`, refusing one above `limit`.
fn read_u32(
    input: &mut impl Read,
    hasher: &mut Sha256,
    limit: u32,
    what: &str,
) -> Result<u32, StoreError> {
    let mut buf = [0_u8; 4];
    read_hashed(input, hasher, &mut buf)?;
    let len = u32::from_be_bytes(buf);
    if len > limit {
        return Err(StoreError::Storage(format!(
            "snapshot file is corrupt: {what} of {len} bytes, more than the limit of {limit}"
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

    /// A file of `format` with the given header length field, records and no hash: what
    /// the reader does before the hash is what these tests look at.
    fn crafted(
        dir: &Path,
        name: &str,
        format: u32,
        header_len: Option<u32>,
        records: &[u8],
    ) -> std::path::PathBuf {
        let header = SnapshotHeader {
            format,
            meta: SnapshotMeta::default(),
            state: SmMeta::default(),
        };
        let encoded = to_cbor(&header).expect("header");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        let len = header_len.unwrap_or_else(|| u32::try_from(encoded.len()).expect("length"));
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&encoded);
        if format == FORMAT_PLAIN {
            bytes.extend_from_slice(records);
        } else {
            let mut deflate = DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            deflate.write_all(records).expect("compress");
            bytes.extend_from_slice(&deflate.finish().expect("finish"));
        }
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write");
        path
    }

    fn row(key_len: u32, value_len: u32) -> Vec<u8> {
        let mut record = vec![TAG_ROW];
        record.extend_from_slice(&key_len.to_be_bytes());
        record.extend(std::iter::repeat_n(
            1_u8,
            usize::try_from(key_len).expect("key"),
        ));
        record.extend_from_slice(&value_len.to_be_bytes());
        record.extend(std::iter::repeat_n(
            2_u8,
            usize::try_from(value_len).expect("value"),
        ));
        record
    }

    fn table(name: &str) -> Vec<u8> {
        let mut record = vec![TAG_TABLE];
        record.extend_from_slice(&u16::try_from(name.len()).expect("name").to_be_bytes());
        record.extend_from_slice(name.as_bytes());
        record
    }

    /// Reads every record until the reader stops, returning its error.
    fn read_until_error(path: &Path, limit: u64) -> StoreError {
        let mut reader = SnapshotReader::open_with_limit(path, Some(limit)).expect("open");
        loop {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("the file must not read to the end"),
                Err(error) => return error,
            }
        }
    }

    // Declared limits bound a crafted file: the header's length, a key's length, and the
    // bytes of records a compressed file expands to.
    // A file may expand to 64 times its size, never less than the floor or more than the
    // cap: a file of 64 MiB that inflates to the cap of 64 GiB is refused at 4 GiB.
    #[test]
    fn records_are_bounded_by_the_size_of_the_file() {
        assert_eq!(records_bound(0), EXPANSION_FLOOR);
        assert_eq!(records_bound(1 << 20), EXPANSION_FLOOR);
        assert_eq!(records_bound(64 << 20), 4 << 30);
        assert_eq!(records_bound(2 << 30), MAX_PLAIN);
        assert_eq!(records_bound(u64::MAX), MAX_PLAIN);
    }

    #[test]
    fn crafted_lengths_and_expansions_are_refused_by_declared_limits() {
        let dir = temp_dir("limits");

        let path = crafted(&dir, "header.tnks", FORMAT, Some(MAX_HEADER + 1), &[]);
        let Err(error) = SnapshotReader::open(&path) else {
            panic!("a header beyond the limit must not open");
        };
        assert!(error.to_string().contains("header of"), "{error}");

        let mut records = table("ipam.rows");
        records.extend_from_slice(&row(MAX_KEY + 1, 0));
        let path = crafted(&dir, "key.tnks", FORMAT_PLAIN, None, &records);
        let error = read_until_error(&path, MAX_PLAIN);
        assert!(error.to_string().contains("key of"), "{error}");

        // The key length is read first: 0 bytes of key, then the value length.
        let mut with_key = table("ipam.rows");
        with_key.extend_from_slice(&[TAG_ROW]);
        with_key.extend_from_slice(&0_u32.to_be_bytes());
        with_key.extend_from_slice(&(MAX_FIELD + 1).to_be_bytes());
        let path = crafted(&dir, "value.tnks", FORMAT_PLAIN, None, &with_key);
        let error = read_until_error(&path, MAX_PLAIN);
        assert!(error.to_string().contains("value of"), "{error}");

        // Four thousand rows of 64 KiB of the same byte compress to a few hundred bytes
        // of DEFLATE and expand to 256 MiB; a limit below that stops the reader early.
        let mut records = table("ipam.rows");
        for _ in 0..4_000 {
            records.extend_from_slice(&row(8, 65_536));
        }
        let path = crafted(&dir, "bomb.tnks", FORMAT, None, &records);
        let bomb_bytes = std::fs::metadata(&path).expect("metadata").len();
        assert!(bomb_bytes < 1 << 20, "the compressed file is small");
        let error = read_until_error(&path, 1 << 20);
        assert!(error.to_string().contains("bytes of records"), "{error}");
        assert!(
            error.to_string().contains(&format!(
                "the snapshot file of {bomb_bytes} bytes holds more than 1048576 bytes of records ("
            )),
            "{error}"
        );
        // Within the bound of its size the same records read until the missing hash is
        // noticed: 256 MiB of records is under the floor.
        let reader = SnapshotReader::open(&path).expect("open");
        assert_eq!(reader.plain_limit, EXPANSION_FLOOR);
        drop(reader);
        let error = read_until_error(&path, MAX_PLAIN);
        assert!(!error.to_string().contains("bytes of records"), "{error}");

        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
