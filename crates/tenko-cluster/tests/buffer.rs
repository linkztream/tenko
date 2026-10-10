//! The observation buffer against a real directory: ordering, persistence across reopen,
//! eviction by count and by size, damaged and missing files, the epoch and `next` files, the
//! `incoming/` hand-over between processes, and the wake-up of the consumer.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tenko_cluster::buffer::{
    BufferConfig, BufferError, BufferStats, DEFAULT_MAX_BATCH_BYTES, DEFAULT_MAX_BATCHES,
    DEFAULT_MAX_BYTES, ObservationBuffer, Pending,
};
use tenko_core::Coded;
use tokio::time::timeout;
use uuid::Uuid;

/// The size of the header in front of every payload in a batch file.
const HEADER: u64 = 44;

/// Long enough for a wake-up that is expected, short enough to keep a failing test quick.
const WAIT: Duration = Duration::from_secs(5);

/// Long enough to be sure that no wake-up is coming.
const SHORT: Duration = Duration::from_millis(150);

fn open(dir: &Path) -> ObservationBuffer {
    ObservationBuffer::open(BufferConfig::new(dir)).unwrap()
}

fn open_with(dir: &Path, configure: impl FnOnce(&mut BufferConfig)) -> ObservationBuffer {
    let mut config = BufferConfig::new(dir);
    configure(&mut config);
    ObservationBuffer::open(config).unwrap()
}

fn batch_path(dir: &Path, sequence: u64) -> PathBuf {
    dir.join(format!("{sequence:020}.batch"))
}

/// The names of the files (not directories) in `dir`, sorted.
fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found| found == extension)
}

/// The sum of the sizes of the `.batch` files in `dir`.
fn batch_bytes_on_disk(dir: &Path) -> u64 {
    file_names(dir)
        .iter()
        .filter(|name| has_extension(name, "batch"))
        .map(|name| fs::metadata(dir.join(name)).unwrap().len())
        .sum()
}

/// Everything the buffer returns, oldest first, acknowledging as it goes.
fn drain(buffer: &ObservationBuffer) -> Vec<Pending> {
    let mut all = Vec::new();
    while let Some(pending) = buffer.peek().unwrap() {
        buffer.ack(pending.sequence).unwrap();
        all.push(pending);
    }
    all
}

fn pending(sequence: u64, payload: &[u8]) -> Pending {
    Pending {
        sequence,
        payload: payload.to_vec(),
    }
}

#[test]
fn push_peek_and_ack_run_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert_eq!(buffer.push(b"first").unwrap(), 1);
    assert_eq!(buffer.push(b"second").unwrap(), 2);
    assert_eq!(buffer.push(b"third").unwrap(), 3);

    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"first")));
    // A peek does not consume.
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"first")));
    buffer.ack(1).unwrap();
    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"second")));
    buffer.ack(2).unwrap();
    assert_eq!(buffer.peek().unwrap(), Some(pending(3, b"third")));
    buffer.ack(3).unwrap();
    assert_eq!(buffer.peek().unwrap(), None);
}

#[test]
fn an_empty_buffer_peeks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert_eq!(buffer.peek().unwrap(), None);
    assert_eq!(buffer.stats().batches, 0);
}

#[test]
fn an_empty_payload_is_a_batch() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert_eq!(buffer.push(b"").unwrap(), 1);
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"")));
    assert_eq!(buffer.stats().bytes, HEADER);
}

#[test]
fn binary_payloads_come_back_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let payload: Vec<u8> = (0..=255).cycle().take(5000).collect();
    buffer.push(&payload).unwrap();
    assert_eq!(
        buffer.peek().unwrap(),
        Some(Pending {
            sequence: 1,
            payload
        })
    );
}

#[test]
fn a_reopened_buffer_keeps_epoch_batches_and_numbering() {
    let dir = tempfile::tempdir().unwrap();
    let (epoch, before) = {
        let buffer = open(dir.path());
        buffer.push(b"one").unwrap();
        buffer.push(b"two").unwrap();
        buffer.push(b"three").unwrap();
        // The head was peeked but never acknowledged: it must come back.
        assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"one")));
        (buffer.epoch(), buffer.stats())
    };

    let buffer = open(dir.path());
    assert_eq!(buffer.epoch(), epoch);
    let after = buffer.stats();
    assert_eq!(after.batches, 3);
    assert_eq!(after.bytes, before.bytes);
    assert_eq!((after.oldest, after.newest), (Some(1), Some(3)));
    assert_eq!((after.dropped, after.corrupt), (0, 0));

    assert_eq!(buffer.push(b"four").unwrap(), 4);
    assert_eq!(
        drain(&buffer),
        [
            pending(1, b"one"),
            pending(2, b"two"),
            pending(3, b"three"),
            pending(4, b"four"),
        ]
    );
}

#[test]
fn a_sequence_is_never_reused_after_everything_was_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    {
        let buffer = open(dir.path());
        for _ in 0..3 {
            buffer.push(b"x").unwrap();
        }
        assert_eq!(drain(&buffer).len(), 3);
        assert_eq!(buffer.stats().batches, 0);
    }
    let buffer = open(dir.path());
    assert_eq!(buffer.stats().batches, 0);
    assert_eq!(buffer.push(b"y").unwrap(), 4);
    assert_eq!(buffer.stats().oldest, Some(4));
}

#[test]
fn the_numbering_continues_when_the_next_file_is_behind_the_batches() {
    let dir = tempfile::tempdir().unwrap();
    {
        let buffer = open(dir.path());
        for _ in 0..3 {
            buffer.push(b"x").unwrap();
        }
    }
    fs::remove_file(dir.path().join("next")).unwrap();
    assert_eq!(open(dir.path()).push(b"y").unwrap(), 4);

    // A next file that is not a number is ignored; the batch names decide.
    fs::write(dir.path().join("next"), "not a number\n").unwrap();
    assert_eq!(open(dir.path()).push(b"z").unwrap(), 5);
}

#[test]
fn the_numbering_continues_from_a_next_file_ahead_of_the_batches() {
    let dir = tempfile::tempdir().unwrap();
    {
        let buffer = open(dir.path());
        buffer.push(b"x").unwrap();
    }
    fs::write(dir.path().join("next"), "50\n").unwrap();
    assert_eq!(open(dir.path()).push(b"y").unwrap(), 50);
}

#[test]
fn the_files_have_the_documented_form() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    buffer.push(b"two").unwrap();
    buffer.push(b"three").unwrap();

    assert_eq!(
        file_names(dir.path()),
        [
            "00000000000000000001.batch",
            "00000000000000000002.batch",
            "00000000000000000003.batch",
            "epoch",
            "next",
        ]
    );
    assert_eq!(fs::read_to_string(dir.path().join("next")).unwrap(), "4\n");

    let epoch = fs::read_to_string(dir.path().join("epoch")).unwrap();
    assert!(epoch.ends_with('\n'));
    assert_eq!(epoch.trim(), buffer.epoch().hyphenated().to_string());
    assert_eq!(epoch.trim().len(), 36);

    let file = fs::read(batch_path(dir.path(), 1)).unwrap();
    assert_eq!(&file[..4], b"TKB1");
    assert_eq!(&file[4..12], &3_u64.to_be_bytes());
    assert_eq!(&file[44..], b"one");
}

#[test]
fn eviction_by_count_drops_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batches = 3);
    for n in 1_u8..=5 {
        assert_eq!(buffer.push(&[n]).unwrap(), u64::from(n));
    }

    let stats = buffer.stats();
    assert_eq!(stats.batches, 3);
    assert_eq!(stats.dropped, 2);
    assert_eq!((stats.oldest, stats.newest), (Some(3), Some(5)));
    assert!(!batch_path(dir.path(), 1).exists());
    assert!(!batch_path(dir.path(), 2).exists());
    assert!(batch_path(dir.path(), 5).exists());
    assert_eq!(
        drain(&buffer),
        [pending(3, &[3]), pending(4, &[4]), pending(5, &[5])]
    );
}

#[test]
fn eviction_by_bytes_drops_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let file_size = HEADER + 100;
    let buffer = open_with(dir.path(), |config| {
        config.max_bytes = 3 * file_size + 10;
        config.max_batch_bytes = 100;
    });
    for n in 1_u8..=5 {
        buffer.push(&[n; 100]).unwrap();
    }

    let stats = buffer.stats();
    assert_eq!(stats.batches, 3);
    assert_eq!(stats.dropped, 2);
    assert_eq!(stats.bytes, 3 * file_size);
    assert_eq!(stats.bytes, batch_bytes_on_disk(dir.path()));
    assert_eq!((stats.oldest, stats.newest), (Some(3), Some(5)));
}

#[test]
fn one_large_push_can_evict_several_batches() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| {
        config.max_bytes = 560;
        config.max_batch_bytes = 500;
    });
    for n in 1_u8..=4 {
        buffer.push(&[n; 10]).unwrap();
    }
    assert_eq!(buffer.stats().dropped, 0);

    buffer.push(&[9; 500]).unwrap();
    let stats = buffer.stats();
    assert_eq!(stats.batches, 1);
    assert_eq!(stats.dropped, 4);
    assert_eq!((stats.oldest, stats.newest), (Some(5), Some(5)));
}

#[test]
fn the_batch_just_written_is_never_evicted() {
    let dir = tempfile::tempdir().unwrap();
    // A full-size payload plus its header is larger than max_bytes.
    let buffer = open_with(dir.path(), |config| {
        config.max_bytes = 100;
        config.max_batch_bytes = 100;
    });
    assert_eq!(buffer.push(&[1; 100]).unwrap(), 1);
    assert_eq!(buffer.stats().batches, 1);
    assert_eq!(buffer.stats().dropped, 0);

    assert_eq!(buffer.push(&[2; 100]).unwrap(), 2);
    let stats = buffer.stats();
    assert_eq!((stats.batches, stats.dropped), (1, 1));
    assert_eq!(stats.oldest, Some(2));
    assert_eq!(buffer.peek().unwrap(), Some(pending(2, &[2; 100])));
}

#[test]
fn a_payload_over_the_limit_is_refused_and_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batch_bytes = 10);
    let before = file_names(dir.path());

    assert_eq!(
        buffer.push(&[0; 11]).unwrap_err(),
        BufferError::TooLarge {
            size: 11,
            limit: 10
        }
    );
    assert_eq!(file_names(dir.path()), before);
    assert_eq!(file_names(dir.path()), ["epoch"]);
    let stats = buffer.stats();
    assert_eq!((stats.batches, stats.bytes, stats.dropped), (0, 0, 0));

    // The limit itself is allowed, and the refused push did not use a sequence.
    assert_eq!(buffer.push(&[0; 10]).unwrap(), 1);
}

#[test]
fn open_refuses_invalid_settings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("buffer");

    let mut no_batches = BufferConfig::new(&root);
    no_batches.max_batches = 0;
    let mut no_bytes = BufferConfig::new(&root);
    no_bytes.max_bytes = 0;
    no_bytes.max_batch_bytes = 0;
    let mut batch_over_total = BufferConfig::new(&root);
    batch_over_total.max_bytes = 1000;
    batch_over_total.max_batch_bytes = 1001;

    for config in [no_batches, no_bytes, batch_over_total] {
        let error = ObservationBuffer::open(config).unwrap_err();
        assert!(matches!(error, BufferError::Config { .. }), "{error:?}");
        assert_eq!(error.code(), "cluster.buffer.config");
    }
    assert!(!root.exists(), "an invalid configuration creates nothing");

    // The boundary is allowed.
    let mut equal = BufferConfig::new(&root);
    equal.max_bytes = 1000;
    equal.max_batch_bytes = 1000;
    assert!(ObservationBuffer::open(equal).is_ok());
}

#[test]
fn open_creates_nested_directories() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a").join("b").join("buffer");
    let buffer = open(&root);
    assert!(root.is_dir());
    assert_eq!(buffer.stats().batches, 0);
}

#[test]
fn open_fails_when_the_directory_is_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-directory");
    fs::write(&file, b"x").unwrap();

    let error = ObservationBuffer::open(BufferConfig::new(&file)).unwrap_err();
    let BufferError::Io { path, .. } = &error else {
        panic!("expected an I/O error, got {error:?}");
    };
    assert!(path.contains("not-a-directory"), "{path}");
}

#[test]
fn a_damaged_payload_is_set_aside_and_the_next_batch_is_returned() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"first batch").unwrap();
    buffer.push(b"second batch").unwrap();

    let path = batch_path(dir.path(), 1);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 0xff;
    fs::write(&path, bytes).unwrap();

    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"second batch")));
    let stats = buffer.stats();
    assert_eq!(stats.corrupt, 1);
    assert_eq!(stats.batches, 1);
    assert_eq!(stats.oldest, Some(2));
    assert!(!path.exists());
    assert!(dir.path().join("00000000000000000001.corrupt").is_file());

    // The count stays, and a second peek does not count it again.
    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"second batch")));
    assert_eq!(buffer.stats().corrupt, 1);
}

#[test]
fn a_file_with_only_a_header_is_set_aside() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"first batch").unwrap();
    buffer.push(b"second batch").unwrap();

    let path = batch_path(dir.path(), 1);
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(usize::try_from(HEADER).unwrap());
    fs::write(&path, bytes).unwrap();

    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"second batch")));
    assert_eq!(buffer.stats().corrupt, 1);
    assert!(dir.path().join("00000000000000000001.corrupt").is_file());
}

#[test]
fn every_kind_of_damage_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let good = |sequence: u64| fs::read(batch_path(dir.path(), sequence)).unwrap();

    for _ in 0..7 {
        buffer.push(b"payload of a batch").unwrap();
    }
    let template = good(7);
    let damaged: Vec<Vec<u8>> = vec![
        Vec::new(),
        template[..3].to_vec(),
        template[..43].to_vec(),
        {
            let mut bad_magic = template.clone();
            bad_magic[0] = b'X';
            bad_magic
        },
        {
            let mut longer = template.clone();
            longer.push(0);
            longer
        },
        {
            let mut shorter = template.clone();
            shorter.pop();
            shorter
        },
        {
            let mut bad_digest = template.clone();
            bad_digest[30] ^= 0x01;
            bad_digest
        },
    ];
    for (offset, bytes) in damaged.iter().enumerate() {
        let sequence = u64::try_from(offset).unwrap() + 1;
        fs::write(batch_path(dir.path(), sequence), bytes).unwrap();
    }

    // The last file was damaged too; nothing is left to return.
    assert_eq!(buffer.peek().unwrap(), None);
    let stats = buffer.stats();
    assert_eq!(stats.corrupt, 7);
    assert_eq!(stats.batches, 0);
    assert_eq!(
        file_names(dir.path())
            .iter()
            .filter(|name| has_extension(name, "corrupt"))
            .count(),
        7
    );
}

#[test]
fn a_damaged_file_is_found_after_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let buffer = open(dir.path());
        buffer.push(b"first batch").unwrap();
        buffer.push(b"second batch").unwrap();
    }
    let path = batch_path(dir.path(), 1);
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() - 3]).unwrap();

    let buffer = open(dir.path());
    // Open does not read the contents.
    assert_eq!(buffer.stats().batches, 2);
    assert_eq!(buffer.stats().corrupt, 0);
    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"second batch")));
    assert_eq!(buffer.stats().corrupt, 1);
}

#[test]
fn a_file_deleted_behind_our_back_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    buffer.push(b"two").unwrap();
    buffer.push(b"three").unwrap();
    fs::remove_file(batch_path(dir.path(), 1)).unwrap();

    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"two")));
    let stats = buffer.stats();
    assert_eq!(
        (stats.batches, stats.corrupt, stats.oldest),
        (2, 0, Some(2))
    );
    assert!(batch_path(dir.path(), 3).exists());
}

#[test]
fn stray_temporary_files_are_removed_at_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let buffer = open(dir.path());
        buffer.push(b"one").unwrap();
    }
    for name in [
        "00000000000000000002.batch.tmp",
        "next.tmp",
        "epoch.tmp",
        "x.tmp",
    ] {
        fs::write(dir.path().join(name), b"partial").unwrap();
    }
    fs::write(dir.path().join("notes.txt"), b"keep").unwrap();

    let buffer = open(dir.path());
    assert_eq!(
        file_names(dir.path()),
        ["00000000000000000001.batch", "epoch", "next", "notes.txt"]
    );
    assert_eq!(buffer.stats().batches, 1);
    // The half-written batch did not use up its sequence.
    assert_eq!(buffer.push(b"two").unwrap(), 2);
}

#[test]
fn open_ignores_files_that_are_not_batches() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "1.batch",
        "00000000000000000009.corrupt",
        "0000000000000000000x.batch",
        "readme.txt",
    ] {
        fs::write(dir.path().join(name), b"not a batch").unwrap();
    }
    let buffer = open(dir.path());
    assert_eq!(buffer.stats().batches, 0);
    assert_eq!(buffer.push(b"one").unwrap(), 1);
    assert!(dir.path().join("1.batch").is_file());
}

#[test]
fn a_missing_epoch_file_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let first = {
        let buffer = open(dir.path());
        buffer.push(b"one").unwrap();
        buffer.epoch()
    };
    fs::remove_file(dir.path().join("epoch")).unwrap();

    let buffer = open(dir.path());
    assert_ne!(buffer.epoch(), first);
    assert_eq!(buffer.stats().epoch, buffer.epoch());
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"one")));

    // The new epoch was written down.
    assert_eq!(open(dir.path()).epoch(), buffer.epoch());
}

#[test]
fn a_garbage_epoch_file_is_replaced_and_the_batches_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let first = {
        let buffer = open(dir.path());
        buffer.push(b"one").unwrap();
        buffer.push(b"two").unwrap();
        buffer.epoch()
    };
    fs::write(dir.path().join("epoch"), b"this is not a uuid\n").unwrap();

    let buffer = open(dir.path());
    assert_ne!(buffer.epoch(), first);
    assert_eq!(drain(&buffer), [pending(1, b"one"), pending(2, b"two")]);

    let text = fs::read_to_string(dir.path().join("epoch")).unwrap();
    assert_eq!(Uuid::parse_str(text.trim()).unwrap(), buffer.epoch());
    assert_eq!(open(dir.path()).epoch(), buffer.epoch());
}

#[test]
fn an_epoch_file_without_a_trailing_newline_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let epoch = Uuid::now_v7();
    fs::write(dir.path().join("epoch"), epoch.hyphenated().to_string()).unwrap();
    assert_eq!(open(dir.path()).epoch(), epoch);
}

#[test]
fn ack_of_an_unknown_sequence_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    let before = buffer.stats();

    buffer.ack(0).unwrap();
    buffer.ack(2).unwrap();
    buffer.ack(u64::MAX).unwrap();
    assert_eq!(buffer.stats(), before);

    buffer.ack(1).unwrap();
    buffer.ack(1).unwrap();
    assert_eq!(buffer.stats().batches, 0);
    assert!(!batch_path(dir.path(), 1).exists());
}

#[test]
fn ack_of_an_evicted_sequence_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batches = 1);
    buffer.push(b"one").unwrap();
    buffer.push(b"two").unwrap();
    buffer.ack(1).unwrap();
    assert_eq!(buffer.peek().unwrap(), Some(pending(2, b"two")));
}

#[test]
fn an_acknowledged_batch_is_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    buffer.push(b"two").unwrap();
    buffer.ack(2).unwrap();
    // Acknowledging out of order is allowed: only the named batch goes.
    assert!(!batch_path(dir.path(), 2).exists());
    assert!(batch_path(dir.path(), 1).exists());
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"one")));
}

#[test]
fn stats_follow_every_step() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batches = 2);
    let epoch = buffer.epoch();
    let expect =
        |batches: u64, bytes: u64, dropped: u64, oldest: Option<u64>, newest: Option<u64>| {
            BufferStats {
                epoch,
                batches,
                bytes,
                dropped,
                corrupt: 0,
                oldest,
                newest,
            }
        };

    assert_eq!(buffer.stats(), expect(0, 0, 0, None, None));
    buffer.push(&[0; 10]).unwrap();
    assert_eq!(buffer.stats(), expect(1, HEADER + 10, 0, Some(1), Some(1)));
    buffer.push(&[0; 20]).unwrap();
    assert_eq!(
        buffer.stats(),
        expect(2, 2 * HEADER + 30, 0, Some(1), Some(2))
    );
    buffer.push(&[0; 30]).unwrap();
    assert_eq!(
        buffer.stats(),
        expect(2, 2 * HEADER + 50, 1, Some(2), Some(3))
    );
    buffer.peek().unwrap();
    assert_eq!(
        buffer.stats(),
        expect(2, 2 * HEADER + 50, 1, Some(2), Some(3))
    );
    buffer.ack(2).unwrap();
    assert_eq!(buffer.stats(), expect(1, HEADER + 30, 1, Some(3), Some(3)));
    buffer.ack(3).unwrap();
    assert_eq!(buffer.stats(), expect(0, 0, 1, None, None));
}

#[test]
fn stats_serialize_to_json_and_back() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    let stats = buffer.stats();
    let json = serde_json::to_string(&stats).unwrap();
    assert_eq!(serde_json::from_str::<BufferStats>(&json).unwrap(), stats);
}

#[test]
fn a_clone_shares_the_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let other = buffer.clone();
    other.push(b"one").unwrap();
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, b"one")));
    assert_eq!(buffer.epoch(), other.epoch());
    buffer.ack(1).unwrap();
    assert_eq!(other.stats().batches, 0);
}

#[test]
fn debug_names_the_directory_and_the_stats() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    buffer.push(b"one").unwrap();
    let text = format!("{buffer:?}");
    assert!(text.starts_with("ObservationBuffer"), "{text}");
    assert!(text.contains("stats"), "{text}");
    assert!(text.contains("batches: 1"), "{text}");
}

#[test]
fn concurrent_pushes_get_distinct_consecutive_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let threads: Vec<_> = (0_u8..4)
        .map(|thread| {
            let buffer = buffer.clone();
            std::thread::spawn(move || {
                (0_u8..10)
                    .map(|n| buffer.push(&[thread, n]).unwrap())
                    .collect::<Vec<u64>>()
            })
        })
        .collect();

    let mut all = BTreeSet::new();
    for handle in threads {
        let sequences = handle.join().unwrap();
        // Within one thread the sequences rise.
        assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
        all.extend(sequences);
    }
    assert_eq!(all, (1..=40).collect::<BTreeSet<u64>>());

    let drained = drain(&buffer);
    assert_eq!(drained.len(), 40);
    assert!(
        drained
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
}

#[test]
fn the_default_limits_are_the_documented_ones() {
    let config = BufferConfig::new("buffer-dir");
    assert_eq!(config.dir, Path::new("buffer-dir"));
    assert_eq!(config.max_bytes, 64 * 1024 * 1024);
    assert_eq!(config.max_batches, 10_000);
    assert_eq!(config.max_batch_bytes, 16 * 1024 * 1024);
    assert_eq!(config.max_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(config.max_batches, DEFAULT_MAX_BATCHES);
    assert_eq!(config.max_batch_bytes, DEFAULT_MAX_BATCH_BYTES);
}

#[test]
fn dropped_files_are_adopted_in_name_order() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let payloads: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];
    let mut dropped: Vec<(PathBuf, &[u8])> = payloads
        .iter()
        .map(|payload| {
            (
                ObservationBuffer::drop_incoming(dir.path(), payload).unwrap(),
                *payload,
            )
        })
        .collect();

    for (path, payload) in &dropped {
        assert_eq!(path.parent().unwrap(), dir.path().join("incoming"));
        assert_eq!(path.extension().unwrap(), "batch");
        assert_eq!(&fs::read(path).unwrap(), payload, "dropped files are raw");
    }
    assert!(
        file_names(&dir.path().join("incoming"))
            .iter()
            .all(|name| !has_extension(name, "tmp")),
        "the temporary name is gone"
    );

    assert_eq!(buffer.adopt_incoming().unwrap(), 3);
    assert_eq!(
        file_names(&dir.path().join("incoming")),
        Vec::<String>::new()
    );

    dropped.sort();
    let adopted = drain(&buffer);
    assert_eq!(adopted.len(), 3);
    for (index, (batch, (_, payload))) in adopted.iter().zip(&dropped).enumerate() {
        assert_eq!(batch.sequence, u64::try_from(index).unwrap() + 1);
        assert_eq!(&batch.payload, payload);
    }
    // Nothing left to adopt.
    assert_eq!(buffer.adopt_incoming().unwrap(), 0);
}

#[test]
fn incoming_files_are_taken_by_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let incoming = dir.path().join("incoming");
    fs::create_dir(&incoming).unwrap();
    fs::write(incoming.join("b.batch"), b"second").unwrap();
    fs::write(incoming.join("a.batch"), b"first").unwrap();
    fs::write(incoming.join("c.batch"), b"third").unwrap();
    fs::write(incoming.join("ignored.txt"), b"left alone").unwrap();
    fs::write(incoming.join("old.rejected"), b"left alone").unwrap();

    assert_eq!(buffer.adopt_incoming().unwrap(), 3);
    assert_eq!(
        drain(&buffer),
        [
            pending(1, b"first"),
            pending(2, b"second"),
            pending(3, b"third")
        ]
    );
    assert_eq!(file_names(&incoming), ["ignored.txt", "old.rejected"]);
}

#[test]
fn adopted_batches_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    ObservationBuffer::drop_incoming(dir.path(), b"from another process").unwrap();
    {
        let buffer = open(dir.path());
        assert_eq!(buffer.adopt_incoming().unwrap(), 1);
    }
    let buffer = open(dir.path());
    assert_eq!(
        buffer.peek().unwrap(),
        Some(pending(1, b"from another process"))
    );
}

#[test]
fn an_oversized_incoming_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batch_bytes = 10);
    let incoming = dir.path().join("incoming");
    fs::create_dir(&incoming).unwrap();
    fs::write(incoming.join("big.batch"), [7_u8; 11]).unwrap();
    fs::write(incoming.join("fits.batch"), [8_u8; 10]).unwrap();

    assert_eq!(buffer.adopt_incoming().unwrap(), 1);
    assert_eq!(file_names(&incoming), ["big.rejected"]);
    assert_eq!(fs::read(incoming.join("big.rejected")).unwrap(), [7_u8; 11]);
    assert_eq!(buffer.stats().batches, 1);
    assert_eq!(buffer.peek().unwrap(), Some(pending(1, &[8; 10])));

    // The rejected file is not looked at again.
    assert_eq!(buffer.adopt_incoming().unwrap(), 0);
}

#[test]
fn adoption_without_an_incoming_directory_adopts_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert_eq!(buffer.adopt_incoming().unwrap(), 0);
    assert!(!dir.path().join("incoming").exists());
}

#[test]
fn adoption_applies_the_limits() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batches = 2);
    for n in 0_u8..4 {
        ObservationBuffer::drop_incoming(dir.path(), &[n]).unwrap();
    }
    assert_eq!(buffer.adopt_incoming().unwrap(), 4);

    let stats = buffer.stats();
    assert_eq!((stats.batches, stats.dropped), (2, 2));
    assert_eq!((stats.oldest, stats.newest), (Some(3), Some(4)));
}

#[test]
fn old_temporary_files_are_deleted_and_young_ones_are_left() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let incoming = dir.path().join("incoming");
    fs::create_dir(&incoming).unwrap();
    fs::write(incoming.join("old.tmp"), b"abandoned").unwrap();
    fs::write(incoming.join("young.tmp"), b"being written").unwrap();
    let old = fs::OpenOptions::new()
        .write(true)
        .open(incoming.join("old.tmp"))
        .unwrap();
    old.set_modified(SystemTime::now() - Duration::from_secs(2 * 60 * 60))
        .unwrap();
    drop(old);

    assert_eq!(buffer.adopt_incoming().unwrap(), 0);
    assert_eq!(file_names(&incoming), ["young.tmp"]);
}

#[tokio::test]
async fn changed_resolves_after_a_push_before_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    // The consumer found nothing, and a push lands before it starts to wait.
    assert_eq!(buffer.peek().unwrap(), None);
    buffer.push(b"one").unwrap();
    timeout(WAIT, buffer.changed()).await.unwrap();
}

#[tokio::test]
async fn changed_resolves_after_a_push_during_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let waiter = {
        let buffer = buffer.clone();
        tokio::spawn(async move { buffer.changed().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiter.is_finished(), "nothing was pushed yet");

    buffer.push(b"one").unwrap();
    timeout(WAIT, waiter).await.unwrap().unwrap();
}

#[tokio::test]
async fn changed_waits_for_a_push_that_has_not_happened() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert!(timeout(SHORT, buffer.changed()).await.is_err());

    // A push is consumed by one call; a second call waits again.
    buffer.push(b"one").unwrap();
    timeout(WAIT, buffer.changed()).await.unwrap();
    assert!(timeout(SHORT, buffer.changed()).await.is_err());
}

#[tokio::test]
async fn a_refused_push_does_not_wake_the_consumer() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open_with(dir.path(), |config| config.max_batch_bytes = 4);
    buffer.push(&[0; 5]).unwrap_err();
    assert!(timeout(SHORT, buffer.changed()).await.is_err());
}

#[tokio::test]
async fn changed_resolves_after_an_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    ObservationBuffer::drop_incoming(dir.path(), b"one").unwrap();

    assert_eq!(buffer.adopt_incoming().unwrap(), 1);
    timeout(WAIT, buffer.changed()).await.unwrap();
}

#[tokio::test]
async fn an_adoption_of_nothing_does_not_wake_the_consumer() {
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    assert_eq!(buffer.adopt_incoming().unwrap(), 0);
    assert!(timeout(SHORT, buffer.changed()).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumer_follows_a_producer_in_order() {
    const COUNT: u32 = 60;
    let dir = tempfile::tempdir().unwrap();
    let buffer = open(dir.path());
    let producer = {
        let buffer = buffer.clone();
        std::thread::spawn(move || {
            for n in 0..COUNT {
                buffer.push(&n.to_be_bytes()).unwrap();
            }
        })
    };

    let mut received = Vec::new();
    while received.len() < usize::try_from(COUNT).unwrap() {
        match buffer.peek().unwrap() {
            Some(batch) => {
                received.push((batch.sequence, batch.payload));
                buffer.ack(batch.sequence).unwrap();
            }
            None => timeout(WAIT, buffer.changed())
                .await
                .expect("the producer stalled"),
        }
    }
    producer.join().unwrap();

    let expected: Vec<(u64, Vec<u8>)> = (0..COUNT)
        .map(|n| (u64::from(n) + 1, n.to_be_bytes().to_vec()))
        .collect();
    assert_eq!(received, expected);
    assert_eq!(buffer.stats().batches, 0);
}

#[test]
fn the_errors_carry_codes_statuses_and_parameters() {
    let io = BufferError::Io {
        path: "buffer-dir".to_owned(),
        reason: "access denied".to_owned(),
    };
    assert_eq!(io.code(), "cluster.buffer.io");
    assert_eq!(io.http_status(), 500);
    assert_eq!(
        io.params(),
        [("path", "buffer-dir".to_owned())].into_iter().collect()
    );
    assert_eq!(
        io.to_string(),
        "observation buffer buffer-dir: access denied"
    );

    let too_large = BufferError::TooLarge {
        size: 11,
        limit: 10,
    };
    assert_eq!(too_large.code(), "cluster.buffer.too_large");
    assert_eq!(too_large.http_status(), 413);
    assert_eq!(
        too_large.params(),
        [("size", "11".to_owned()), ("limit", "10".to_owned())]
            .into_iter()
            .collect()
    );
    assert_eq!(
        too_large.to_string(),
        "an observation batch of 11 bytes is larger than the limit of 10 bytes"
    );

    let config = BufferError::Config {
        reason: "max_batches must be greater than zero".to_owned(),
    };
    assert_eq!(config.code(), "cluster.buffer.config");
    assert_eq!(config.http_status(), 500);
    assert!(config.params().is_empty());
    assert_eq!(
        config.to_string(),
        "invalid observation buffer settings: max_batches must be greater than zero"
    );
}

#[cfg(unix)]
#[test]
fn directories_and_files_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("buffer");
    let buffer = open(&root);
    buffer.push(b"one").unwrap();
    let dropped = ObservationBuffer::drop_incoming(&root, b"two").unwrap();

    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join("incoming")), 0o700);
    assert_eq!(mode(&root.join("epoch")), 0o600);
    assert_eq!(mode(&root.join("next")), 0o600);
    assert_eq!(mode(&batch_path(&root, 1)), 0o600);
    assert_eq!(mode(&dropped), 0o600);
}
