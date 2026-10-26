//! The backup container `TKBK1` (ADR 0016): header, key slots, the chunked AEAD stream,
//! the manifest and the parts.
//!
//! ```text
//! header  = "TKBK1" | flags u8 = 0 | archive id (16) | chunk size u32 | slot count u8
//!           | slots | SHA-256 of every header byte before it (32)
//! slot    = 0x01 | memory KiB u32 | passes u32 | lanes u32 | salt (16) | nonce (12) | wrapped (48)
//!         | 0x02 | recipient tag (8) | ephemeral public key (32) | nonce (12) | wrapped (48)
//! body    = AES-256-GCM chunks; nonce = 0 (3) | index u64 | last u8; aad = header hash
//! plain   = "TKBM" | manifest length u32 | manifest (JSON) | parts back to back
//! ```
//!
//! Every chunk but the last holds exactly the chunk size of plain bytes; the last holds
//! fewer (possibly none) and is flagged in its nonce, so truncation, extension, reordering
//! and every changed byte are detected. Nothing is written by a reader before the key slot
//! opened, and the reader refuses Argon2 parameters, chunk sizes, manifest sizes and part
//! counts beyond fixed limits, so a crafted file cannot make it allocate without bound.
//!
//! The reader is fuzzed (`fuzz/fuzz_targets/backup_archive.rs`) through [`fuzzing`].

use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
};

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, X25519},
    hkdf,
    rand::{SecureRandom as _, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_auth::encoding::{hex_decode, hex_encode};
use tenko_core::Timestamp;
use tenko_vault::{kek::valid_kek_id, transfer::TransferredKek};
use zeroize::Zeroizing;

use super::{
    BackupError,
    keys::{BackupKey, KEY_LEN, Recipient},
};

/// The magic bytes of a backup file.
pub const MAGIC: &[u8; 5] = b"TKBK1";
/// The manifest format this build writes and reads.
pub const FORMAT: &str = "tenko-backup/1";
/// The plain chunk size the writer uses.
pub const DEFAULT_CHUNK: u32 = 1 << 20;
/// The smallest chunk size a reader accepts.
pub const MIN_CHUNK: u32 = 1 << 16;
/// The largest chunk size a reader accepts.
pub const MAX_CHUNK: u32 = 1 << 23;
/// The most key slots a file may have.
pub const MAX_SLOTS: usize = 8;
/// The largest manifest a reader accepts.
pub const MAX_MANIFEST: u32 = 1 << 20;
/// The most parts a manifest may list.
pub const MAX_PARTS: usize = 32;
/// The most key generations the `kek.generations` part may hold.
pub const MAX_GENERATIONS: usize = 64;

/// The Raft snapshot of the store (`TNKSNAP1`).
pub const PART_SNAPSHOT: &str = "store.snapshot";
/// The key generations.
pub const PART_KEKS: &str = "kek.generations";
/// The certificate chain of TLS mode b.
pub const PART_TLS_CERT: &str = "tls.certificate";
/// The private key of TLS mode b.
pub const PART_TLS_KEY: &str = "tls.key";
/// The configuration file.
pub const PART_CONFIG: &str = "config";
/// Leases, reserved for Phase 3 (OPS-07); empty.
pub const PART_LEASES: &str = "leases";
/// The parts every backup has.
pub const REQUIRED_PARTS: [&str; 3] = [PART_SNAPSHOT, PART_KEKS, PART_LEASES];
/// The only part encoding of format 1.
pub const ENCODING_IDENTITY: &str = "identity";

const FLAGS: u8 = 0;
const ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const HASH_LEN: usize = 32;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;
const SLOT_PASSPHRASE: u8 = 0x01;
const SLOT_RECIPIENT: u8 = 0x02;
const MANIFEST_MAGIC: &[u8; 4] = b"TKBM";
const KEKS_MAGIC: &[u8; 4] = b"TKBG";
const KEKS_VERSION: u8 = 1;
const SLOT_LABEL: &[u8] = b"tenko-backup/1 slot";
const RECIPIENT_SALT: &[u8] = b"tenko-backup/1 recipient";
const PAYLOAD_INFO: &[u8] = b"tenko-backup/1 payload";

/// Argon2id parameters of a passphrase slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes.
    pub passes: u32,
    /// Lanes.
    pub lanes: u32,
}

impl KdfParams {
    /// What the writer uses: the Hardened parameters of the password hashes.
    pub const HARDENED: Self = Self {
        memory_kib: 65_536,
        passes: 3,
        lanes: 1,
    };

    /// Cheap parameters for tests (still within the reader's limits).
    #[cfg(test)]
    pub const TEST: Self = Self {
        memory_kib: 19_456,
        passes: 1,
        lanes: 1,
    };

    fn check(self) -> Result<(), BackupError> {
        let ok = (19_456..=1_048_576).contains(&self.memory_kib)
            && (1..=16).contains(&self.passes)
            && (1..=8).contains(&self.lanes);
        if ok {
            Ok(())
        } else {
            Err(BackupError::Corrupt(
                "the key slot asks for Argon2 parameters outside the accepted limits".to_owned(),
            ))
        }
    }
}

/// A key slot of the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Wrapped under a passphrase through Argon2id.
    Passphrase {
        /// The Argon2id parameters.
        params: KdfParams,
        /// The salt.
        salt: [u8; SALT_LEN],
        /// The nonce of the wrap.
        nonce: [u8; NONCE_LEN],
        /// The wrapped file key.
        wrapped: [u8; WRAPPED_LEN],
    },
    /// Wrapped to a recipient's X25519 key.
    Recipient {
        /// [`Recipient::tag`].
        tag: [u8; 8],
        /// The ephemeral public key.
        ephemeral: [u8; KEY_LEN],
        /// The nonce of the wrap.
        nonce: [u8; NONCE_LEN],
        /// The wrapped file key.
        wrapped: [u8; WRAPPED_LEN],
    },
}

impl Slot {
    /// `passphrase` or `recipient`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Passphrase { .. } => "passphrase",
            Self::Recipient { .. } => "recipient",
        }
    }
}

/// How the writer wraps the file key: one slot each.
#[derive(Debug, Clone, Copy)]
pub enum Lock<'a> {
    /// A passphrase.
    Passphrase(&'a str, KdfParams),
    /// A recipient.
    Recipient(Recipient),
}

/// What opens a backup.
#[derive(Debug, Clone, Copy)]
pub enum Unlock<'a> {
    /// A passphrase.
    Passphrase(&'a str),
    /// A recipient key file.
    Key(&'a BackupKey),
}

/// The plain header of a backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Random, unique per file.
    pub archive_id: [u8; ID_LEN],
    /// Plain bytes per chunk.
    pub chunk_size: u32,
    /// The key slots.
    pub slots: Vec<Slot>,
    /// The SHA-256 of the header bytes before it; the additional data of every chunk.
    pub hash: [u8; HASH_LEN],
}

/// The random file key; zeroized on drop.
pub struct FileKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey")
    }
}

fn corrupt(detail: impl Into<String>) -> BackupError {
    BackupError::Corrupt(detail.into())
}

fn internal(operation: &str) -> BackupError {
    BackupError::Internal(format!("{operation} failed"))
}

fn random<const N: usize>() -> Result<[u8; N], BackupError> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| internal("random generation"))?;
    Ok(bytes)
}

fn aes_key(bytes: &[u8]) -> Result<LessSafeKey, BackupError> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| internal("key setup"))
}

/// Reads exactly `N` bytes or reports a truncated header.
fn take<const N: usize>(input: &mut impl Read) -> Result<[u8; N], BackupError> {
    let mut bytes = [0u8; N];
    input.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            BackupError::NotABackup("the file ends inside the header".to_owned())
        } else {
            BackupError::io("backup", error)
        }
    })?;
    Ok(bytes)
}

impl Header {
    /// Reads and checks a header: magic, flags, limits and the header hash.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotABackup`] for another file, [`BackupError::Corrupt`] for a damaged
    /// header, [`BackupError::Io`].
    pub fn read(input: &mut impl Read) -> Result<Self, BackupError> {
        let mut raw = Vec::with_capacity(128);
        let magic: [u8; 5] = take(input)?;
        if &magic != MAGIC {
            if magic.starts_with(b"TKBK") {
                return Err(BackupError::Unsupported {
                    found: String::from_utf8_lossy(&magic).into_owned(),
                    supported: "TKBK1",
                });
            }
            return Err(BackupError::NotABackup(
                "the file does not start with TKBK1".to_owned(),
            ));
        }
        raw.extend_from_slice(&magic);
        let [flags] = take::<1>(input)?;
        if flags != FLAGS {
            return Err(corrupt("unknown header flags"));
        }
        raw.push(flags);
        let archive_id: [u8; ID_LEN] = take(input)?;
        raw.extend_from_slice(&archive_id);
        let chunk_bytes: [u8; 4] = take(input)?;
        raw.extend_from_slice(&chunk_bytes);
        let chunk_size = u32::from_be_bytes(chunk_bytes);
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
            return Err(corrupt("the chunk size is outside the accepted limits"));
        }
        let [count] = take::<1>(input)?;
        raw.push(count);
        let count = usize::from(count);
        if count == 0 || count > MAX_SLOTS {
            return Err(corrupt("the number of key slots is outside 1 to 8"));
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let [kind] = take::<1>(input)?;
            raw.push(kind);
            let slot = match kind {
                SLOT_PASSPHRASE => {
                    let memory: [u8; 4] = take(input)?;
                    let passes: [u8; 4] = take(input)?;
                    let lanes: [u8; 4] = take(input)?;
                    let salt: [u8; SALT_LEN] = take(input)?;
                    let nonce: [u8; NONCE_LEN] = take(input)?;
                    let wrapped: [u8; WRAPPED_LEN] = take(input)?;
                    for part in [&memory[..], &passes, &lanes, &salt, &nonce, &wrapped] {
                        raw.extend_from_slice(part);
                    }
                    Slot::Passphrase {
                        params: KdfParams {
                            memory_kib: u32::from_be_bytes(memory),
                            passes: u32::from_be_bytes(passes),
                            lanes: u32::from_be_bytes(lanes),
                        },
                        salt,
                        nonce,
                        wrapped,
                    }
                }
                SLOT_RECIPIENT => {
                    let tag: [u8; 8] = take(input)?;
                    let ephemeral: [u8; KEY_LEN] = take(input)?;
                    let nonce: [u8; NONCE_LEN] = take(input)?;
                    let wrapped: [u8; WRAPPED_LEN] = take(input)?;
                    for part in [&tag[..], &ephemeral, &nonce, &wrapped] {
                        raw.extend_from_slice(part);
                    }
                    Slot::Recipient {
                        tag,
                        ephemeral,
                        nonce,
                        wrapped,
                    }
                }
                _ => return Err(corrupt("unknown key slot type")),
            };
            slots.push(slot);
        }
        let hash: [u8; HASH_LEN] = take(input)?;
        if <[u8; HASH_LEN]>::from(Sha256::digest(&raw)) != hash {
            return Err(corrupt("the header does not match its hash"));
        }
        Ok(Self {
            archive_id,
            chunk_size,
            slots,
            hash,
        })
    }

    /// Builds the header of a new file: a fresh file key wrapped once per lock.
    fn create(
        locks: &[Lock<'_>],
        chunk_size: u32,
    ) -> Result<(Self, Vec<u8>, FileKey), BackupError> {
        if locks.is_empty() {
            return Err(BackupError::NoKey(
                "a backup needs a passphrase or a recipient".to_owned(),
            ));
        }
        if locks.len() > MAX_SLOTS {
            return Err(BackupError::NoKey("at most 8 keys per backup".to_owned()));
        }
        let archive_id: [u8; ID_LEN] = random()?;
        let file_key = FileKey(Zeroizing::new(random()?));
        let mut raw = Vec::with_capacity(64 + locks.len() * 128);
        raw.extend_from_slice(MAGIC);
        raw.push(FLAGS);
        raw.extend_from_slice(&archive_id);
        raw.extend_from_slice(&chunk_size.to_be_bytes());
        raw.push(u8::try_from(locks.len()).map_err(|_| internal("slot count"))?);
        let mut slots = Vec::with_capacity(locks.len());
        for lock in locks {
            let slot = match *lock {
                Lock::Passphrase(passphrase, params) => {
                    let salt: [u8; SALT_LEN] = random()?;
                    let key = passphrase_key(passphrase, params, &salt)?;
                    let (nonce, wrapped) = wrap(&key, &archive_id, SLOT_PASSPHRASE, &file_key)?;
                    Slot::Passphrase {
                        params,
                        salt,
                        nonce,
                        wrapped,
                    }
                }
                Lock::Recipient(recipient) => {
                    let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
                        .map_err(|_| internal("ephemeral key generation"))?;
                    let ephemeral: [u8; KEY_LEN] = private
                        .compute_public_key()
                        .map_err(|_| internal("ephemeral public key"))?
                        .as_ref()
                        .try_into()
                        .map_err(|_| internal("ephemeral public key"))?;
                    let key = agreement::agree_ephemeral(
                        private,
                        UnparsedPublicKey::new(&X25519, recipient.0),
                        BackupError::InvalidKey("the recipient is not a usable key".to_owned()),
                        |dh| recipient_key(dh, &ephemeral, &recipient.0, &archive_id),
                    )?;
                    let (nonce, wrapped) = wrap(&key, &archive_id, SLOT_RECIPIENT, &file_key)?;
                    Slot::Recipient {
                        tag: recipient.tag(),
                        ephemeral,
                        nonce,
                        wrapped,
                    }
                }
            };
            encode_slot(&slot, &mut raw);
            slots.push(slot);
        }
        let hash: [u8; HASH_LEN] = Sha256::digest(&raw).into();
        raw.extend_from_slice(&hash);
        Ok((
            Self {
                archive_id,
                chunk_size,
                slots,
                hash,
            },
            raw,
            file_key,
        ))
    }

    /// Opens the file key with a passphrase or a key file. Only slots of the matching kind
    /// are tried; a recipient slot only when its tag names the key.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyRefused`] when no slot opens, [`BackupError::Corrupt`] for Argon2
    /// parameters beyond the limits.
    pub fn unlock(&self, unlock: Unlock<'_>) -> Result<FileKey, BackupError> {
        for slot in &self.slots {
            match (slot, unlock) {
                (
                    Slot::Passphrase {
                        params,
                        salt,
                        nonce,
                        wrapped,
                    },
                    Unlock::Passphrase(passphrase),
                ) => {
                    params.check()?;
                    let key = passphrase_key(passphrase, *params, salt)?;
                    if let Some(file_key) =
                        unwrap(&key, &self.archive_id, SLOT_PASSPHRASE, nonce, wrapped)
                    {
                        return Ok(file_key);
                    }
                }
                (
                    Slot::Recipient {
                        tag,
                        ephemeral,
                        nonce,
                        wrapped,
                    },
                    Unlock::Key(backup_key),
                ) if *tag == backup_key.recipient().tag() => {
                    let private = PrivateKey::from_private_key(&X25519, backup_key.private_bytes())
                        .map_err(|_| BackupError::InvalidKey("unusable key".to_owned()))?;
                    let recipient = backup_key.recipient();
                    let Ok(key) = agreement::agree(
                        &private,
                        UnparsedPublicKey::new(&X25519, ephemeral),
                        BackupError::KeyRefused,
                        |dh| recipient_key(dh, ephemeral, &recipient.0, &self.archive_id),
                    ) else {
                        continue;
                    };
                    if let Some(file_key) =
                        unwrap(&key, &self.archive_id, SLOT_RECIPIENT, nonce, wrapped)
                    {
                        return Ok(file_key);
                    }
                }
                _ => {}
            }
        }
        Err(BackupError::KeyRefused)
    }

    /// The kinds of the key slots, for reports.
    pub fn slot_kinds(&self) -> Vec<&'static str> {
        self.slots.iter().map(Slot::kind).collect()
    }
}

fn encode_slot(slot: &Slot, out: &mut Vec<u8>) {
    match slot {
        Slot::Passphrase {
            params,
            salt,
            nonce,
            wrapped,
        } => {
            out.push(SLOT_PASSPHRASE);
            out.extend_from_slice(&params.memory_kib.to_be_bytes());
            out.extend_from_slice(&params.passes.to_be_bytes());
            out.extend_from_slice(&params.lanes.to_be_bytes());
            out.extend_from_slice(salt);
            out.extend_from_slice(nonce);
            out.extend_from_slice(wrapped);
        }
        Slot::Recipient {
            tag,
            ephemeral,
            nonce,
            wrapped,
        } => {
            out.push(SLOT_RECIPIENT);
            out.extend_from_slice(tag);
            out.extend_from_slice(ephemeral);
            out.extend_from_slice(nonce);
            out.extend_from_slice(wrapped);
        }
    }
}

fn passphrase_key(
    passphrase: &str,
    params: KdfParams,
    salt: &[u8; SALT_LEN],
) -> Result<LessSafeKey, BackupError> {
    let argon = Params::new(
        params.memory_kib,
        params.passes,
        params.lanes,
        Some(KEY_LEN),
    )
    .map_err(|_| corrupt("invalid Argon2 parameters"))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| internal("passphrase key derivation"))?;
    aes_key(key.as_ref())
}

fn recipient_key(
    dh: &[u8],
    ephemeral: &[u8; KEY_LEN],
    recipient: &[u8; KEY_LEN],
    archive_id: &[u8; ID_LEN],
) -> Result<LessSafeKey, BackupError> {
    if dh.iter().all(|byte| *byte == 0) {
        return Err(BackupError::InvalidKey(
            "the recipient is not a usable key".to_owned(),
        ));
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, RECIPIENT_SALT).extract(dh);
    let info: [&[u8]; 3] = [ephemeral, recipient, archive_id];
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    prk.expand(&info, &AES_256_GCM)
        .and_then(|okm| okm.fill(key.as_mut()))
        .map_err(|_| internal("recipient key derivation"))?;
    aes_key(key.as_ref())
}

fn slot_aad(archive_id: &[u8; ID_LEN], kind: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SLOT_LABEL.len() + ID_LEN + 1);
    aad.extend_from_slice(SLOT_LABEL);
    aad.extend_from_slice(archive_id);
    aad.push(kind);
    aad
}

fn wrap(
    key: &LessSafeKey,
    archive_id: &[u8; ID_LEN],
    kind: u8,
    file_key: &FileKey,
) -> Result<([u8; NONCE_LEN], [u8; WRAPPED_LEN]), BackupError> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(WRAPPED_LEN));
    buffer.extend_from_slice(file_key.0.as_ref());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(slot_aad(archive_id, kind)),
        &mut *buffer,
    )
    .map_err(|_| internal("key wrap"))?;
    let wrapped: [u8; WRAPPED_LEN] = buffer
        .as_slice()
        .try_into()
        .map_err(|_| internal("key wrap"))?;
    Ok((nonce, wrapped))
}

fn unwrap(
    key: &LessSafeKey,
    archive_id: &[u8; ID_LEN],
    kind: u8,
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_LEN],
) -> Option<FileKey> {
    let mut buffer = Zeroizing::new(wrapped.to_vec());
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(slot_aad(archive_id, kind)),
            buffer.as_mut_slice(),
        )
        .ok()?;
    let bytes: [u8; KEY_LEN] = (&*plain).try_into().ok()?;
    Some(FileKey(Zeroizing::new(bytes)))
}

fn payload_key(file_key: &FileKey, archive_id: &[u8; ID_LEN]) -> Result<LessSafeKey, BackupError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, archive_id).extract(file_key.0.as_ref());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    prk.expand(&[PAYLOAD_INFO], &AES_256_GCM)
        .and_then(|okm| okm.fill(key.as_mut()))
        .map_err(|_| internal("payload key derivation"))?;
    aes_key(key.as_ref())
}

fn chunk_nonce(index: u64, last: bool) -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

/// Encrypts a plain stream into chunks.
struct ChunkWriter<W: Write> {
    out: W,
    key: LessSafeKey,
    aad: [u8; HASH_LEN],
    chunk: usize,
    buffer: Zeroizing<Vec<u8>>,
    index: u64,
}

impl<W: Write> ChunkWriter<W> {
    fn seal(&mut self, len: usize, last: bool) -> io::Result<()> {
        let mut sealed = Zeroizing::new(Vec::with_capacity(len + TAG_LEN));
        sealed.extend_from_slice(&self.buffer[..len]);
        self.key
            .seal_in_place_append_tag(
                chunk_nonce(self.index, last),
                Aad::from(self.aad),
                &mut *sealed,
            )
            .map_err(|_| io::Error::other("chunk encryption failed"))?;
        self.out.write_all(&sealed)?;
        self.buffer.drain(..len);
        self.index += 1;
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        let len = self.buffer.len();
        self.seal(len, true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for ChunkWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(data);
        // A full chunk goes out only when more follows: the last chunk is always short.
        while self.buffer.len() > self.chunk {
            self.seal(self.chunk, false)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Decrypts the chunks of a body into a plain stream.
struct ChunkReader<R: Read> {
    input: R,
    key: LessSafeKey,
    aad: [u8; HASH_LEN],
    chunk: usize,
    plain: Zeroizing<Vec<u8>>,
    position: usize,
    index: u64,
    done: bool,
}

fn stream_error(error: BackupError) -> io::Error {
    io::Error::other(error)
}

impl<R: Read> ChunkReader<R> {
    fn fill(&mut self) -> io::Result<()> {
        let mut sealed = vec![0u8; self.chunk + TAG_LEN];
        let mut filled = 0;
        while filled < sealed.len() {
            let read = self.input.read(&mut sealed[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        let last = filled < sealed.len();
        if filled < TAG_LEN {
            return Err(stream_error(corrupt(format!(
                "the file ends inside chunk {}",
                self.index
            ))));
        }
        sealed.truncate(filled);
        let mut sealed = Zeroizing::new(sealed);
        let plain_len = self
            .key
            .open_in_place(
                chunk_nonce(self.index, last),
                Aad::from(self.aad),
                sealed.as_mut_slice(),
            )
            .map_err(|_| {
                stream_error(corrupt(format!(
                    "chunk {} does not authenticate (changed, reordered or truncated)",
                    self.index
                )))
            })?
            .len();
        sealed.truncate(plain_len);
        self.plain = sealed;
        self.position = 0;
        self.index += 1;
        if last {
            self.done = true;
        }
        Ok(())
    }
}

impl<R: Read> Read for ChunkReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.position == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.fill()?;
        }
        let count = out.len().min(self.plain.len() - self.position);
        out[..count].copy_from_slice(&self.plain[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

/// The store digest the manifest records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRecord {
    /// The revision it covers.
    pub revision: u64,
    /// The SHA-256 as hex.
    pub sha256: String,
    /// Non-empty tables.
    pub tables: u64,
    /// Rows.
    pub entries: u64,
}

/// The Raft position of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    /// The term of the last log id.
    pub last_log_term: u64,
    /// The node that led that term.
    pub last_log_node: u64,
    /// The index of the last log id.
    pub last_log_index: u64,
    /// The snapshot id.
    pub snapshot_id: String,
}

/// The key generations in the backup (identifiers only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KekRecord {
    /// Oldest first, the active one last.
    pub generations: Vec<String>,
    /// The active generation.
    pub active: String,
}

/// One part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartEntry {
    /// The part name, such as `store.snapshot`.
    pub name: String,
    /// Its length in the plain stream.
    pub bytes: u64,
    /// Its SHA-256 as hex.
    pub sha256: String,
    /// `identity` in format 1.
    pub encoding: String,
}

/// Who made a backup and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginRecord {
    /// `manual`, `scheduled`, `before_update` or `offline`.
    pub reason: String,
    /// The principal subject, or `system`.
    pub by: String,
}

/// The manifest of a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: String,
    /// When the backup was made.
    pub created_at: Timestamp,
    /// The Tenko version that made it.
    pub tenko_version: String,
    /// The data-directory format of the store.
    pub data_format: u32,
    /// The node the state was copied on.
    pub node: u64,
    /// The voters of the Raft group then.
    pub voters: Vec<u64>,
    /// The store revision of the copy.
    pub revision: u64,
    /// The position of the audit chain head.
    pub audit_head: u64,
    /// The store digest at that revision.
    pub digest: DigestRecord,
    /// The SHA-256 of the internal CA root (DER), as hex; absent without an internal CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
    /// The snapshot's Raft position.
    pub snapshot: SnapshotRecord,
    /// The key generations.
    pub kek: KekRecord,
    /// The parts, in stream order.
    pub parts: Vec<PartEntry>,
    /// Who made it and why.
    pub origin: OriginRecord,
}

impl Manifest {
    /// The entry of a part.
    pub fn part(&self, name: &str) -> Option<&PartEntry> {
        self.parts.iter().find(|part| part.name == name)
    }

    /// Checks the format and the part list.
    ///
    /// # Errors
    ///
    /// [`BackupError::Unsupported`] or [`BackupError::Corrupt`].
    pub fn validate(&self) -> Result<(), BackupError> {
        if self.format != FORMAT {
            return Err(BackupError::Unsupported {
                found: self.format.clone(),
                supported: FORMAT,
            });
        }
        if self.parts.len() > MAX_PARTS {
            return Err(corrupt("the manifest lists too many parts"));
        }
        let mut names = BTreeSet::new();
        for part in &self.parts {
            if !names.insert(part.name.as_str()) {
                return Err(corrupt(format!("the part {} appears twice", part.name)));
            }
            if part.encoding != ENCODING_IDENTITY {
                return Err(BackupError::Unsupported {
                    found: format!("part encoding {}", part.encoding),
                    supported: FORMAT,
                });
            }
            let hash = hex_decode(&part.sha256).ok();
            if hash.as_ref().map(Vec::len) != Some(HASH_LEN) {
                return Err(corrupt(format!("the part {} has no valid hash", part.name)));
            }
        }
        for required in REQUIRED_PARTS {
            if !names.contains(required) {
                return Err(corrupt(format!("the part {required} is missing")));
            }
        }
        if names.contains(PART_TLS_CERT) != names.contains(PART_TLS_KEY) {
            return Err(corrupt(
                "a TLS certificate without its key, or the other way round",
            ));
        }
        if self.kek.generations.last() != Some(&self.kek.active) {
            return Err(corrupt("the active key generation is not listed last"));
        }
        Ok(())
    }
}

/// A part to write: its name and a reader of exactly the bytes the manifest entry promises.
pub struct PartSource<'a> {
    /// The manifest entry (name, length, hash).
    pub entry: PartEntry,
    /// The bytes.
    pub reader: Box<dyn Read + 'a>,
}

impl std::fmt::Debug for PartSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartSource")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

/// The manifest entry of in-memory bytes.
pub fn entry_of(name: &str, bytes: &[u8]) -> PartEntry {
    PartEntry {
        name: name.to_owned(),
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: hex_encode(&Sha256::digest(bytes)),
        encoding: ENCODING_IDENTITY.to_owned(),
    }
}

/// The manifest entry of a file, hashing it.
///
/// # Errors
///
/// [`BackupError::Io`].
pub fn entry_of_file(name: &str, path: &std::path::Path) -> Result<PartEntry, BackupError> {
    let mut file = std::fs::File::open(path).map_err(|error| BackupError::io(path, error))?;
    let mut hasher = Sha256::new();
    let bytes = io::copy(&mut file, &mut HashSink(&mut hasher))
        .map_err(|error| BackupError::io(path, error))?;
    Ok(PartEntry {
        name: name.to_owned(),
        bytes,
        sha256: hex_encode(&hasher.finalize()),
        encoding: ENCODING_IDENTITY.to_owned(),
    })
}

struct HashSink<'a>(&'a mut Sha256);

impl Write for HashSink<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes a complete backup into `out`: the header, then the manifest and the parts in the
/// order of `manifest.parts`, which must match `parts`. Every part is hashed again while it
/// is written; a part that changed since its entry was computed fails the write.
///
/// # Errors
///
/// [`BackupError::NoKey`] without locks, [`BackupError::Corrupt`] when a part does not
/// match its entry, [`BackupError::Io`].
pub fn write<W: Write>(
    out: W,
    locks: &[Lock<'_>],
    manifest: &Manifest,
    parts: Vec<PartSource<'_>>,
) -> Result<W, BackupError> {
    write_with_chunk(out, locks, manifest, parts, DEFAULT_CHUNK)
}

fn write_with_chunk<W: Write>(
    mut out: W,
    locks: &[Lock<'_>],
    manifest: &Manifest,
    parts: Vec<PartSource<'_>>,
    chunk_size: u32,
) -> Result<W, BackupError> {
    manifest.validate()?;
    if parts
        .iter()
        .map(|part| &part.entry)
        .ne(manifest.parts.iter())
    {
        return Err(BackupError::Internal(
            "the parts do not match the manifest".to_owned(),
        ));
    }
    let (header, raw, file_key) = Header::create(locks, chunk_size)?;
    let io = |error| BackupError::io("backup", error);
    out.write_all(&raw).map_err(io)?;
    let mut stream = ChunkWriter {
        out,
        key: payload_key(&file_key, &header.archive_id)?,
        aad: header.hash,
        chunk: usize::try_from(chunk_size).map_err(|_| internal("chunk size"))?,
        buffer: Zeroizing::new(Vec::with_capacity(
            usize::try_from(chunk_size).unwrap_or(0) + 1,
        )),
        index: 0,
    };
    drop(file_key);
    let manifest_json =
        serde_json::to_vec(manifest).map_err(|error| BackupError::Internal(error.to_string()))?;
    let manifest_len = u32::try_from(manifest_json.len())
        .ok()
        .filter(|len| *len <= MAX_MANIFEST)
        .ok_or_else(|| BackupError::Internal("the manifest is too large".to_owned()))?;
    stream.write_all(MANIFEST_MAGIC).map_err(io)?;
    stream.write_all(&manifest_len.to_be_bytes()).map_err(io)?;
    stream.write_all(&manifest_json).map_err(io)?;
    for mut part in parts {
        let mut hasher = Sha256::new();
        let mut tee = TeeWriter {
            out: &mut stream,
            hasher: &mut hasher,
        };
        let copied = io::copy(&mut part.reader, &mut tee).map_err(io)?;
        if copied != part.entry.bytes || hex_encode(&hasher.finalize()) != part.entry.sha256 {
            return Err(corrupt(format!(
                "the part {} changed while the backup was written",
                part.entry.name
            )));
        }
    }
    stream.finish().map_err(io)
}

struct TeeWriter<'a, W: Write> {
    out: &'a mut W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for TeeWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let written = self.out.write(data)?;
        self.hasher.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Reads a backup: header and key first, then the manifest, then each part in turn.
pub struct Reader<R: Read> {
    header: Header,
    stream: ChunkReader<R>,
    manifest: Manifest,
    next: usize,
}

impl<R: Read> std::fmt::Debug for Reader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("header", &self.header)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Reader<R> {
    /// Reads the header, opens the file key and reads the manifest.
    ///
    /// # Errors
    ///
    /// [`BackupError::NotABackup`], [`BackupError::Unsupported`],
    /// [`BackupError::KeyRefused`], [`BackupError::Corrupt`] or [`BackupError::Io`].
    pub fn open(mut input: R, unlock: Unlock<'_>) -> Result<Self, BackupError> {
        let header = Header::read(&mut input)?;
        let file_key = header.unlock(unlock)?;
        Self::with_key(input, header, &file_key)
    }

    fn with_key(input: R, header: Header, file_key: &FileKey) -> Result<Self, BackupError> {
        let chunk = usize::try_from(header.chunk_size).map_err(|_| internal("chunk size"))?;
        let mut stream = ChunkReader {
            input,
            key: payload_key(file_key, &header.archive_id)?,
            aad: header.hash,
            chunk,
            plain: Zeroizing::new(Vec::new()),
            position: 0,
            index: 0,
            done: false,
        };
        let mut prefix = [0u8; 8];
        read_exact_or_corrupt(&mut stream, &mut prefix, "the manifest")?;
        if &prefix[..4] != MANIFEST_MAGIC {
            return Err(corrupt("the plain stream does not start with a manifest"));
        }
        let len = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
        if len > MAX_MANIFEST {
            return Err(corrupt("the manifest is too large"));
        }
        let mut json = vec![0u8; usize::try_from(len).map_err(|_| internal("length"))?];
        read_exact_or_corrupt(&mut stream, &mut json, "the manifest")?;
        let manifest: Manifest = serde_json::from_slice(&json)
            .map_err(|error| corrupt(format!("the manifest does not parse: {error}")))?;
        manifest.validate()?;
        Ok(Self {
            header,
            stream,
            manifest,
            next: 0,
        })
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Copies the next part into `sink` and checks its length and hash; `None` after the
    /// last part, once the stream ended exactly there.
    ///
    /// # Errors
    ///
    /// [`BackupError::Corrupt`] for a short part, a hash mismatch or bytes after the last
    /// part; [`BackupError::Io`] for the sink.
    pub fn next_part(&mut self, sink: &mut dyn Write) -> Result<Option<PartEntry>, BackupError> {
        let Some(entry) = self.manifest.parts.get(self.next).cloned() else {
            let mut extra = [0u8; 1];
            let read = self
                .stream
                .read(&mut extra)
                .map_err(|error| BackupError::io("backup", error))?;
            if read != 0 {
                return Err(corrupt("bytes follow the last part"));
            }
            return Ok(None);
        };
        self.next += 1;
        let mut hasher = Sha256::new();
        let mut limited = (&mut self.stream).take(entry.bytes);
        let mut tee = TeeWriter {
            out: &mut SinkWriter(sink),
            hasher: &mut hasher,
        };
        let copied = io::copy(&mut limited, &mut tee)
            .map_err(|error| BackupError::io(format!("part {}", entry.name), error))?;
        if copied != entry.bytes {
            return Err(corrupt(format!("the part {} is short", entry.name)));
        }
        if hex_encode(&hasher.finalize()) != entry.sha256 {
            return Err(corrupt(format!(
                "the part {} does not match its hash",
                entry.name
            )));
        }
        Ok(Some(entry))
    }
}

struct SinkWriter<'a>(&'a mut dyn Write);

impl Write for SinkWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn read_exact_or_corrupt(
    stream: &mut impl Read,
    buffer: &mut [u8],
    what: &str,
) -> Result<(), BackupError> {
    stream.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            corrupt(format!("the stream ends inside {what}"))
        } else {
            BackupError::io("backup", error)
        }
    })
}

/// Encodes the `kek.generations` part: `"TKBG" | 1 | count | (id length | id | key)*`.
///
/// # Errors
///
/// [`BackupError::Internal`] for an empty list, too many generations, a duplicate or an
/// invalid identifier.
pub fn encode_keks(generations: &[TransferredKek]) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let invalid = || BackupError::Internal("the key generations cannot be encoded".to_owned());
    if generations.is_empty() || generations.len() > MAX_GENERATIONS {
        return Err(invalid());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(6 + generations.len() * 98));
    out.extend_from_slice(KEKS_MAGIC);
    out.push(KEKS_VERSION);
    out.push(u8::try_from(generations.len()).map_err(|_| invalid())?);
    for (index, kek) in generations.iter().enumerate() {
        if !valid_kek_id(&kek.id) || generations[..index].iter().any(|seen| seen.id == kek.id) {
            return Err(invalid());
        }
        out.push(u8::try_from(kek.id.len()).map_err(|_| invalid())?);
        out.extend_from_slice(kek.id.as_bytes());
        out.extend_from_slice(kek.material.as_ref());
    }
    Ok(out)
}

/// Decodes the `kek.generations` part.
///
/// # Errors
///
/// [`BackupError::Corrupt`] for anything but a well-formed list.
pub fn decode_keks(bytes: &[u8]) -> Result<Vec<TransferredKek>, BackupError> {
    let malformed = || corrupt("the key generations do not parse");
    let rest = bytes
        .strip_prefix(KEKS_MAGIC.as_slice())
        .ok_or_else(malformed)?;
    let (&version, rest) = rest.split_first().ok_or_else(malformed)?;
    if version != KEKS_VERSION {
        return Err(malformed());
    }
    let (&count, mut rest) = rest.split_first().ok_or_else(malformed)?;
    let count = usize::from(count);
    if count == 0 || count > MAX_GENERATIONS {
        return Err(malformed());
    }
    let mut generations: Vec<TransferredKek> = Vec::with_capacity(count);
    for _ in 0..count {
        let (&len, tail) = rest.split_first().ok_or_else(malformed)?;
        let (id, tail) = tail
            .split_at_checked(usize::from(len))
            .ok_or_else(malformed)?;
        let id = std::str::from_utf8(id).map_err(|_| malformed())?;
        if !valid_kek_id(id) || generations.iter().any(|seen| seen.id == id) {
            return Err(malformed());
        }
        let (key, tail) = tail.split_first_chunk::<KEY_LEN>().ok_or_else(malformed)?;
        generations.push(TransferredKek {
            id: id.to_owned(),
            material: Zeroizing::new(*key),
        });
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok(generations)
}

/// Entry points for the fuzz target `backup_archive` (not part of the API).
#[doc(hidden)]
pub mod fuzzing {
    use std::io::{self, Cursor};

    use super::{BackupError, FileKey, Header, Reader, decode_keks};
    use zeroize::Zeroizing;

    /// The file key of [`open_with_fixed_key`].
    pub const FIXED_KEY: [u8; 32] = [7; 32];

    /// Parses a header.
    ///
    /// # Errors
    ///
    /// The reader's error.
    pub fn header(data: &[u8]) -> Result<(), BackupError> {
        Header::read(&mut Cursor::new(data)).map(drop)
    }

    /// Parses a header, then reads the body with [`FIXED_KEY`] as the file key, so that
    /// inputs built from [`seal_with_fixed_key`] reach the manifest and part readers.
    ///
    /// # Errors
    ///
    /// The reader's error.
    pub fn open_with_fixed_key(data: &[u8]) -> Result<usize, BackupError> {
        let mut cursor = Cursor::new(data);
        let header = Header::read(&mut cursor)?;
        let key = FileKey(Zeroizing::new(FIXED_KEY));
        let mut reader = Reader::with_key(cursor, header, &key)?;
        let mut parts = 0;
        while reader.next_part(&mut io::sink())?.is_some() {
            parts += 1;
        }
        Ok(parts)
    }

    /// Decodes a key generation part.
    ///
    /// # Errors
    ///
    /// The decoder's error.
    pub fn keks(data: &[u8]) -> Result<usize, BackupError> {
        decode_keks(data).map(|generations| generations.len())
    }

    /// Builds a well-formed file around `plain` (the decrypted body: manifest prefix,
    /// manifest and parts) under [`FIXED_KEY`], for seeds.
    ///
    /// # Errors
    ///
    /// The writer's error.
    pub fn seal_with_fixed_key(plain: &[u8]) -> Result<Vec<u8>, BackupError> {
        super::seal_plain_with_key(plain, &FileKey(Zeroizing::new(FIXED_KEY)))
    }
}

/// A file whose body is `plain` under `file_key`, with one passphrase slot that does not
/// open it (fuzz seeds only).
fn seal_plain_with_key(plain: &[u8], file_key: &FileKey) -> Result<Vec<u8>, BackupError> {
    let (header, raw, _) = Header::create(
        &[Lock::Passphrase(
            "fuzz seed passphrase",
            KdfParams {
                memory_kib: 19_456,
                passes: 1,
                lanes: 1,
            },
        )],
        MIN_CHUNK,
    )?;
    let mut stream = ChunkWriter {
        out: raw,
        key: payload_key(file_key, &header.archive_id)?,
        aad: header.hash,
        chunk: usize::try_from(MIN_CHUNK).map_err(|_| internal("chunk size"))?,
        buffer: Zeroizing::new(Vec::new()),
        index: 0,
    };
    stream
        .write_all(plain)
        .map_err(|error| BackupError::io("seed", error))?;
    stream
        .finish()
        .map_err(|error| BackupError::io("seed", error))
}

/// The plain stream of a manifest and in-memory parts (fuzz seeds and tests).
///
/// # Errors
///
/// [`BackupError::Internal`] if the manifest does not serialize.
#[doc(hidden)]
pub fn plain_stream(manifest: &Manifest, parts: &[&[u8]]) -> Result<Vec<u8>, BackupError> {
    let json =
        serde_json::to_vec(manifest).map_err(|error| BackupError::Internal(error.to_string()))?;
    let mut plain = Vec::new();
    plain.extend_from_slice(MANIFEST_MAGIC);
    plain.extend_from_slice(
        &u32::try_from(json.len())
            .map_err(|_| internal("length"))?
            .to_be_bytes(),
    );
    plain.extend_from_slice(&json);
    for part in parts {
        plain.extend_from_slice(part);
    }
    Ok(plain)
}

#[cfg(test)]
mod tests;
