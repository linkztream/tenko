#![no_main]
//! The snapshot files of the store (`tenko_store::raft::fuzzing`): what a node installs when
//! the leader streams it a snapshot, and what it reads back from its own disk. The magic and
//! the CBOR header, then table and row records with their length fields, the end tag and the
//! SHA-256 of everything before it; from format 2 on, everything after the header is one
//! DEFLATE stream.
//!
//! The input is one control octet and the rest of a file. Bit 0 picks format 2, else format
//! 1. Unless bit 1 is set (the whole file from the input), the file starts with the magic and
//! a valid header, so inputs reach the records. With bit 2 set the target ends the records
//! itself, with the end tag and the right hash (and compresses them for format 2), so inputs
//! also reach the end of a file that checks out. The reader runs under the bound of an
//! install: an input of at most `-max_len` octets expands to some 67 MB under DEFLATE (about
//! 1032 to 1), below the 1 GiB every file may hold, so only the length fields of the records
//! bound what a run allocates (a value at most 256 MiB, under `-malloc_limit_mb`).
//!
//! It checks that a file of format 1 the reader accepts ends with the SHA-256 of every octet
//! before it, so no file is installed whose hash does not match.

use std::{io::Write as _, path::PathBuf, sync::LazyLock};

use flate2::{Compression, write::DeflateEncoder};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as _, Sha256};
use tenko_store::raft::fuzzing::{file_start, read_snapshot};

static PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    std::env::temp_dir().join(format!("tenko-fuzz-snapshot-{}", std::process::id()))
});

fuzz_target!(|data: &[u8]| {
    let Some((&control, body)) = data.split_first() else {
        return;
    };
    let format = if control & 1 == 0 { 1 } else { 2 };
    let mut file = if control & 2 == 0 {
        file_start(format).expect("a header encodes")
    } else {
        Vec::new()
    };
    if control & 4 == 0 {
        file.extend_from_slice(body);
    } else {
        // The records, the end tag and the hash over the file up to it.
        let mut hasher = Sha256::new();
        hasher.update(&file);
        hasher.update(body);
        hasher.update([0xff]);
        let mut tail = body.to_vec();
        tail.push(0xff);
        tail.extend_from_slice(&hasher.finalize());
        if format == 2 {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&tail).expect("compressing into memory");
            tail = encoder.finish().expect("compressing into memory");
        }
        file.extend_from_slice(&tail);
    }
    std::fs::write(&*PATH, &file).expect("the temporary file is written");
    if let Ok((1, _tables, _rows)) = read_snapshot(&PATH) {
        let (before, hash) = file.split_at(file.len() - 32);
        assert_eq!(&Sha256::digest(before)[..], hash);
    }
});
