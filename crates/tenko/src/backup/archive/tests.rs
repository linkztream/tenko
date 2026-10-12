use std::io::Cursor;

use tenko_core::Timestamp;

use super::*;

const PASSPHRASE: &str = "correct horse battery";

fn generations() -> Vec<TransferredKek> {
    vec![
        TransferredKek {
            id: "file-00000001".to_owned(),
            material: Zeroizing::new([1; 32]),
        },
        TransferredKek {
            id: "file-00000002".to_owned(),
            material: Zeroizing::new([2; 32]),
        },
    ]
}

struct Fixture {
    manifest: Manifest,
    parts: Vec<(String, Vec<u8>)>,
}

fn fixture(snapshot_len: usize) -> Fixture {
    let snapshot: Vec<u8> = (0..snapshot_len)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect();
    let keks = encode_keks(&generations()).expect("keks").to_vec();
    let config = b"data_dir = \"/srv/tenko\"\n".to_vec();
    let parts = vec![
        (PART_SNAPSHOT.to_owned(), snapshot),
        (PART_KEKS.to_owned(), keks),
        (PART_CONFIG.to_owned(), config),
        (PART_LEASES.to_owned(), Vec::new()),
    ];
    let manifest = Manifest {
        format: FORMAT.to_owned(),
        created_at: Timestamp::now(),
        tenko_version: "0.0.1".to_owned(),
        data_format: 3,
        node: 1,
        voters: vec![1],
        revision: 42,
        audit_head: 7,
        digest: DigestRecord {
            revision: 42,
            sha256: hex_encode(&[9; 32]),
            tables: 3,
            entries: 99,
        },
        ca_fingerprint: Some(hex_encode(&[5; 32])),
        snapshot: SnapshotRecord {
            last_log_term: 1,
            last_log_node: 1,
            last_log_index: 50,
            snapshot_id: "1-1-50-1".to_owned(),
        },
        kek: KekRecord {
            generations: vec!["file-00000001".to_owned(), "file-00000002".to_owned()],
            active: "file-00000002".to_owned(),
        },
        parts: parts
            .iter()
            .map(|(name, bytes)| entry_of(name, bytes))
            .collect(),
        origin: OriginRecord {
            reason: "manual".to_owned(),
            by: "system".to_owned(),
        },
    };
    Fixture { manifest, parts }
}

fn sources(fixture: &Fixture) -> Vec<PartSource<'_>> {
    fixture
        .parts
        .iter()
        .map(|(name, bytes)| PartSource {
            entry: entry_of(name, bytes),
            reader: Box::new(Cursor::new(bytes.as_slice())),
        })
        .collect()
}

fn written(fixture: &Fixture, locks: &[Lock<'_>], chunk: u32) -> Vec<u8> {
    write_with_chunk(
        Vec::new(),
        locks,
        &fixture.manifest,
        sources(fixture),
        chunk,
    )
    .expect("write")
}

fn read_all(file: &[u8], unlock: Unlock<'_>) -> Result<(Manifest, Vec<Vec<u8>>), BackupError> {
    let mut reader = Reader::open(Cursor::new(file), unlock)?;
    let manifest = reader.manifest().clone();
    let mut parts = Vec::new();
    loop {
        let mut sink = Vec::new();
        match reader.next_part(&mut sink)? {
            Some(_) => parts.push(sink),
            None => break,
        }
    }
    Ok((manifest, parts))
}

fn passphrase_lock() -> Lock<'static> {
    Lock::Passphrase(PASSPHRASE, KdfParams::TEST)
}

#[test]
fn a_backup_round_trips_with_a_passphrase_and_a_key() {
    let key = BackupKey::generate().expect("key");
    // Several chunks, the last one short.
    let fixture = fixture(3 * 65_536 + 17);
    let file = written(
        &fixture,
        &[passphrase_lock(), Lock::Recipient(key.recipient())],
        MIN_CHUNK,
    );
    for unlock in [Unlock::Passphrase(PASSPHRASE), Unlock::Key(&key)] {
        let (manifest, parts) = read_all(&file, unlock).expect("read");
        assert_eq!(manifest, fixture.manifest);
        let expected: Vec<Vec<u8>> = fixture
            .parts
            .iter()
            .map(|(_, bytes)| bytes.clone())
            .collect();
        assert_eq!(parts, expected);
    }
    let header = Header::read(&mut Cursor::new(&file)).expect("header");
    assert_eq!(header.slot_kinds(), ["passphrase", "recipient"]);
    let keks = decode_keks(&fixture.parts[1].1).expect("keks");
    assert_eq!(keks.len(), 2);
    assert_eq!(*keks[1].material, [2; 32]);
}

#[test]
fn a_stream_of_exactly_whole_chunks_ends_with_an_empty_chunk() {
    let fixture = fixture(65_536 * 2);
    let file = written(&fixture, &[passphrase_lock()], MIN_CHUNK);
    let (_, parts) = read_all(&file, Unlock::Passphrase(PASSPHRASE)).expect("read");
    assert_eq!(parts[0], fixture.parts[0].1);
}

#[test]
fn a_wrong_passphrase_or_key_is_refused_before_any_part() {
    let key = BackupKey::generate().expect("key");
    let other = BackupKey::generate().expect("other");
    let fixture = fixture(1_000);
    let file = written(
        &fixture,
        &[passphrase_lock(), Lock::Recipient(key.recipient())],
        MIN_CHUNK,
    );
    for unlock in [
        Unlock::Passphrase("wrong horse battery"),
        Unlock::Key(&other),
    ] {
        let error = Reader::open(Cursor::new(&file), unlock).expect_err("refused");
        assert!(error.is_key_refused(), "{error}");
    }
    let only_key = written(&fixture, &[Lock::Recipient(key.recipient())], MIN_CHUNK);
    let error = Reader::open(Cursor::new(&only_key), Unlock::Passphrase(PASSPHRASE))
        .expect_err("a passphrase does not open a recipient slot");
    assert!(error.is_key_refused());
}

#[test]
fn every_changed_byte_is_refused() {
    let fixture = fixture(70_000);
    let file = written(&fixture, &[passphrase_lock()], MIN_CHUNK);
    let header_len = Header::read(&mut Cursor::new(&file))
        .map(|_| 5 + 1 + 16 + 4 + 1 + 1 + 12 + 16 + 12 + 48 + 32)
        .expect("header");
    // Positions in the header, the first chunk (the manifest and the snapshot), the second
    // chunk and the last tag.
    for position in [
        0,
        6,
        30,
        header_len - 1,
        header_len,
        header_len + 300,
        70_100,
        file.len() - 1,
    ] {
        let mut damaged = file.clone();
        damaged[position] ^= 0x01;
        let error = read_all(&damaged, Unlock::Passphrase(PASSPHRASE)).expect_err("damaged");
        assert!(
            matches!(
                error,
                BackupError::Corrupt(_) | BackupError::NotABackup(_) | BackupError::KeyRefused
            ),
            "position {position}: {error}"
        );
    }
}

#[test]
fn truncated_and_extended_files_are_refused() {
    let fixture = fixture(70_000);
    let file = written(&fixture, &[passphrase_lock()], MIN_CHUNK);
    for len in [0, 10, 80, file.len() - 70_000, file.len() - 1] {
        let error = read_all(&file[..len], Unlock::Passphrase(PASSPHRASE)).expect_err("short");
        assert!(
            matches!(error, BackupError::Corrupt(_) | BackupError::NotABackup(_)),
            "{len}: {error}"
        );
    }
    let mut longer = file.clone();
    longer.extend_from_slice(&[0; 40]);
    assert!(matches!(
        read_all(&longer, Unlock::Passphrase(PASSPHRASE)),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn other_files_and_versions_are_named() {
    assert!(matches!(
        Header::read(&mut Cursor::new(b"PK\x03\x04 not a backup")),
        Err(BackupError::NotABackup(_))
    ));
    assert!(matches!(
        Header::read(&mut Cursor::new(b"TKBK2 later format......")),
        Err(BackupError::Unsupported { .. })
    ));
}

#[test]
fn manifests_are_validated() {
    let mut fixture = fixture(10);
    fixture.manifest.format = "tenko-backup/2".to_owned();
    assert!(matches!(
        fixture.manifest.validate(),
        Err(BackupError::Unsupported { .. })
    ));
    let mut fixture = self::fixture(10);
    fixture
        .manifest
        .parts
        .retain(|part| part.name != PART_LEASES);
    assert!(fixture.manifest.validate().is_err());
    let mut fixture = self::fixture(10);
    let duplicate = fixture.manifest.parts[0].clone();
    fixture.manifest.parts.push(duplicate);
    assert!(fixture.manifest.validate().is_err());
    let mut fixture = self::fixture(10);
    fixture
        .manifest
        .parts
        .push(entry_of(PART_TLS_CERT, b"cert"));
    assert!(
        fixture.manifest.validate().is_err(),
        "a certificate without its key"
    );
    let mut fixture = self::fixture(10);
    fixture.manifest.kek.active = "file-00000001".to_owned();
    assert!(fixture.manifest.validate().is_err());
}

#[test]
fn a_part_that_changes_while_written_fails_the_write() {
    let fixture = fixture(100);
    let mut parts = sources(&fixture);
    parts[0].reader = Box::new(Cursor::new(vec![0u8; 100]));
    let error = write_with_chunk(
        Vec::new(),
        &[passphrase_lock()],
        &fixture.manifest,
        parts,
        MIN_CHUNK,
    )
    .expect_err("changed");
    assert!(matches!(error, BackupError::Corrupt(_)), "{error}");
}

#[test]
fn unknown_parts_are_verified_and_returned() {
    let mut fixture = fixture(10);
    fixture
        .parts
        .push(("later.part".to_owned(), b"later".to_vec()));
    fixture
        .manifest
        .parts
        .push(entry_of("later.part", b"later"));
    let file = written(&fixture, &[passphrase_lock()], MIN_CHUNK);
    let (_, parts) = read_all(&file, Unlock::Passphrase(PASSPHRASE)).expect("read");
    assert_eq!(parts.last().map(Vec::as_slice), Some(b"later".as_slice()));
}

#[test]
fn argon2_limits_are_enforced_before_derivation() {
    let fixture = fixture(10);
    let greedy = Lock::Passphrase(
        PASSPHRASE,
        KdfParams {
            memory_kib: 19_456,
            passes: 1,
            lanes: 9,
        },
    );
    let file = written(&fixture, &[greedy], MIN_CHUNK);
    assert!(matches!(
        Reader::open(Cursor::new(&file), Unlock::Passphrase(PASSPHRASE)),
        Err(BackupError::Corrupt(_))
    ));
}

#[test]
fn key_generation_lists_are_strict() {
    let good = encode_keks(&generations()).expect("encode");
    assert_eq!(decode_keks(&good).expect("decode").len(), 2);
    for bad in [
        &good[..good.len() - 1],
        &good[..5],
        b"TKBG\x02\x01".as_slice(),
    ] {
        assert!(decode_keks(bad).is_err());
    }
    let mut trailing = good.to_vec();
    trailing.push(0);
    assert!(decode_keks(&trailing).is_err());
    let mut twice = generations();
    twice[1].id = twice[0].id.clone();
    assert!(encode_keks(&twice).is_err());
    assert!(encode_keks(&[]).is_err());
}

#[test]
fn the_fuzz_entry_points_reach_the_parts() {
    let fixture = fixture(10);
    let parts: Vec<&[u8]> = fixture
        .parts
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect();
    let plain = plain_stream(&fixture.manifest, &parts).expect("plain");
    let sealed = fuzzing::seal_with_fixed_key(&plain).expect("seal");
    assert_eq!(fuzzing::open_with_fixed_key(&sealed).expect("open"), 4);
    fuzzing::header(&sealed).expect("header");
    assert_eq!(fuzzing::keks(&fixture.parts[1].1).expect("keks"), 2);
}
