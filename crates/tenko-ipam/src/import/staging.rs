//! Staged uploads: the session record and the file bytes, both in the store, the bytes
//! encrypted.
//!
//! An upload can hold credentials in plain text (the spreadsheet's `Pass` column), and
//! secrets are never at rest in plain text (NEVER-01). Every import therefore gets a data
//! key of its own (32 random bytes), kept as a system secret in the vault (an envelope under
//! the installation's KEK) and named by its row in [`STASH_KEYS`]. The bytes of each staged
//! file, and of each named part such as the rows of the latest preview, are cut into chunks
//! of at most [`CHUNK_BYTES`], each sealed with AES-256-GCM under that key and stored as a
//! vault envelope in the secret-bearing table [`STASH_CHUNKS`], one chunk per write batch so
//! every batch stays far below the store's 16 MiB batch limit. The authenticated data of a
//! chunk binds the import, the part, the chunk's position and the number of chunks, so a
//! missing, reordered or foreign chunk does not open. Because the stash replicates with the
//! store, preview, apply and purge work on every controller (plan WP3.1b item 4).
//!
//! Without a vault (tests and embedders that pass none) the data key stays in the memory of
//! this process and the row only records that: such a staged file does not survive a
//! restart, and its session reports `import.upload.lost`.
//!
//! The session record (`import.sessions`) holds the owner, the file references, the
//! user's mapping, the apply job and what the apply froze; it expires after the staging
//! time to live (24 hours by default). The store part of the purge (expired sessions and
//! stash rows without a session) runs on the leader; the sweep of what this controller
//! keeps in memory runs on every controller.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use bytes::Bytes;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded as _, ImportId, JobId, Principal, RequestCtx, SystemComponent, Timestamp, UserId,
    audit::Digest,
    codec::encode_key,
    names::TableName,
    secret::{SecretClass, SecretRef, VaultEnvelope},
    table::TableDef,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, WriteBatch,
};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault};
use zeroize::Zeroizing;

use super::{codes, mapping::Mapping, read::SourceFormat};
use crate::error::{IpamError, IpamResult};

/// A staged file of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedFile {
    /// The name as uploaded.
    pub name: String,
    /// The detected format.
    pub format: SourceFormat,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the plain bytes.
    pub sha256: Digest,
    /// Where the bytes are staged (see [`Stash::write`]).
    pub stored_as: String,
}

/// What an apply froze, so every chunk of the job sees the same model even after earlier
/// chunks changed the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frozen {
    /// The mapping the job applies.
    pub mapping: Mapping,
    /// The accepted proposed prefixes, by VRF key.
    pub proposals: Vec<(String, IpNet)>,
    /// SHA-256 of the canonical encoding of the model.
    pub model: Digest,
    /// Addresses whose proposal was rejected (kept out of the model).
    #[serde(default)]
    pub rejected: Vec<(String, IpAddr)>,
    /// Operator secrets the job will create (new and changed credentials); a count only,
    /// for the audit record.
    #[serde(default)]
    pub secrets: u64,
}

/// The session of an upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The import.
    pub id: ImportId,
    /// The person who uploaded (sessions and personal tokens of this user see it).
    #[serde(default)]
    pub owner: Option<UserId>,
    /// The uploader's subject, for system principals.
    pub owner_subject: String,
    /// Upload time.
    pub created: Timestamp,
    /// Expiry (created plus the staging time to live).
    pub expires: Timestamp,
    /// The staged files in upload order.
    pub files: Vec<StagedFile>,
    /// The user's mapping; the suggested one applies while this is `None`.
    #[serde(default)]
    pub mapping: Option<Mapping>,
    /// The latest apply job.
    #[serde(default)]
    pub job: Option<JobId>,
    /// Counts mapping changes; a stored preview and the cursors of its rows are valid for
    /// one revision.
    #[serde(default)]
    pub mapping_revision: u64,
    /// What the latest apply froze.
    #[serde(default)]
    pub frozen: Option<Frozen>,
}

impl Session {
    /// Whether `principal` may see and change the session: its uploader (any session or
    /// personal token of the same user) or a system component.
    pub fn visible_to(&self, principal: &Principal) -> bool {
        match principal {
            Principal::System { .. } => true,
            other => match (self.owner, other.user()) {
                (Some(owner), Some(user)) => owner == user,
                _ => other.subject() == self.owner_subject,
            },
        }
    }
}

/// The session records of uploads.
pub static SESSIONS: TableDef<ImportId, Session> = TableDef::new("import.sessions");

/// Plain bytes in one stored chunk.
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// How long stash rows without a session are kept before the purge removes them: far longer
/// than an upload takes between its first chunk and its session record.
pub const ORPHAN_GRACE: Duration = Duration::from_secs(3_600);

/// The data key of every import with staged bytes.
pub static STASH_KEYS: TableDef<ImportId, StashKey> = TableDef::new("import.stash_keys");

/// The sealed chunks, keyed `(import, part, position)`; every value is a vault envelope.
pub static STASH_CHUNKS: TableName = TableName::from_static("import.stash_secrets");

/// The rows of the latest preview of every import, staged as a part of the stash.
pub static PREVIEWS: TableDef<ImportId, StoredPreview> = TableDef::new("import.previews");

/// The vault purpose of the data keys.
const PURPOSE: SecretPurpose = SecretPurpose::from_static("import.stash");
/// The format number of a chunk's envelope.
const ENVELOPE_FORMAT: u16 = 0x5331;
/// The key id a chunk's envelope names: the import's data key in [`STASH_KEYS`].
const ENVELOPE_KEY_ID: &str = "import.stash";
/// The first bytes of the authenticated data of every chunk.
const AAD_PREFIX: &[u8] = b"tenko import stash v1";
/// Data keys of imports this controller keeps open.
const KEY_CACHE: usize = 64;
/// How often the first batch of a write is tried when a concurrent write (a KEK rotation
/// starting) refuses it.
const ATTEMPTS: usize = 3;

/// The row of an import's data key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StashKey {
    /// The system secret that holds the 32 bytes; `None` when the key lives only in the
    /// memory of the process that staged the import (no vault).
    #[serde(default)]
    pub secret: Option<SecretRef>,
    /// When the first chunk was staged.
    pub created: Timestamp,
}

/// Where the rows of the latest preview of an import are staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPreview {
    /// The mapping revision the preview was computed for.
    pub mapping_revision: u64,
    /// The store revision it was computed from.
    pub base_revision: u64,
    /// Rows in it.
    pub total_rows: usize,
    /// The staged part holding them.
    pub stored_as: String,
    /// SHA-256 of the encoded rows, so a preview that yields the same rows keeps this
    /// record (and its `base_revision`) instead of staging them again.
    #[serde(default)]
    pub rows_sha256: Option<Digest>,
}

type KeyBytes = Arc<Zeroizing<[u8; 32]>>;

/// The data keys this controller holds.
#[derive(Default)]
struct Keys {
    /// Keys read from the vault, bounded by [`KEY_CACHE`].
    cached: HashMap<ImportId, KeyBytes>,
    /// Keys of imports staged without a vault: the only copy.
    local: HashMap<ImportId, KeyBytes>,
}

/// The staged bytes of imports, in the store.
pub struct Stash {
    store: Arc<dyn Store>,
    vault: Option<Arc<dyn Vault>>,
    keys: Mutex<Keys>,
}

impl std::fmt::Debug for Stash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stash")
            .field("vault", &self.vault.is_some())
            .finish_non_exhaustive()
    }
}

fn internal(detail: impl Into<String>) -> IpamError {
    IpamError::new("sys.internal", 500, detail)
}

fn crypto_error(what: &str) -> IpamError {
    internal(format!("the staged upload could not be {what}"))
}

fn lost() -> IpamError {
    IpamError::new(
        codes::UPLOAD_LOST,
        410,
        "the staged upload is no longer available (the server restarted or it expired); upload the file again",
    )
    .titled("Upload no longer available")
}

fn vault_error(error: &tenko_vault::VaultError) -> IpamError {
    IpamError::from_coded_error(error.to_coded_error())
}

fn cipher(key: &[u8; 32]) -> IpamResult<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| crypto_error("given a key"))
}

/// The authenticated data of a chunk: the import, the part, the position and the count.
fn aad(id: ImportId, name: &str, position: u32, count: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 16 + 4 + name.len() + 8);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(id.0.as_bytes());
    aad.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(&position.to_be_bytes());
    aad.extend_from_slice(&count.to_be_bytes());
    aad
}

fn chunk_key(id: ImportId, name: &str, position: u32) -> Bytes {
    encode_key(&(id, name.to_owned(), position))
}

/// Splits a stored name (`<part>:<count>`).
fn parse_stored(stored_as: &str) -> Option<(&str, u32)> {
    let (name, count) = stored_as.rsplit_once(':')?;
    let count = count.parse().ok()?;
    (count > 0 && !name.is_empty()).then_some((name, count))
}

/// A write batch of the stash: never replayed under an idempotency key (it holds random
/// nonces and keys).
fn stash_batch(cx: &RequestCtx) -> WriteBatch {
    let mut batch = WriteBatch::for_request(cx);
    batch.idempotency = None;
    batch
}

impl Stash {
    /// A stash in `store`, with the data keys in `vault` (or in this process without one).
    pub fn new(store: Arc<dyn Store>, vault: Option<Arc<dyn Vault>>) -> Self {
        Self {
            store,
            vault,
            keys: Mutex::new(Keys::default()),
        }
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, Keys> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn known_key(&self, id: ImportId) -> Option<KeyBytes> {
        let keys = self.keys();
        keys.local
            .get(&id)
            .or_else(|| keys.cached.get(&id))
            .map(Arc::clone)
    }

    fn remember(&self, id: ImportId, key: KeyBytes, local: bool) {
        let mut keys = self.keys();
        if local {
            keys.local.insert(id, key);
            return;
        }
        if keys.cached.len() >= KEY_CACHE
            && !keys.cached.contains_key(&id)
            && let Some(evict) = keys.cached.keys().next().copied()
        {
            keys.cached.remove(&evict);
        }
        keys.cached.insert(id, key);
    }

    /// Forgets what this controller holds of an import (after its rows were removed).
    pub fn forget(&self, id: ImportId) {
        let mut keys = self.keys();
        keys.cached.remove(&id);
        keys.local.remove(&id);
    }

    /// The data key of an import as `view` records it; `None` when it has none yet.
    async fn read_key(&self, view: &dyn ReadView, id: ImportId) -> IpamResult<Option<KeyBytes>> {
        if let Some(key) = self.known_key(id) {
            return Ok(Some(key));
        }
        let Some((row, _)) = view.get_typed(&STASH_KEYS, &id)? else {
            return Ok(None);
        };
        // A key held by another process (staged without a vault) is gone for good.
        let (Some(secret), Some(vault)) = (row.secret, &self.vault) else {
            return Err(lost());
        };
        let ctx = RequestCtx::system(SystemComponent::Import);
        let bytes = vault
            .get_system(&ctx, secret)
            .await
            .map_err(|error| match error {
                tenko_vault::VaultError::NotFound { .. } => lost(),
                other => vault_error(&other),
            })?;
        let key: [u8; 32] = bytes.expose().try_into().map_err(|_| lost())?;
        let key = Arc::new(Zeroizing::new(key));
        self.remember(id, Arc::clone(&key), false);
        Ok(Some(key))
    }

    /// The data key for a write: the import's key, or a new one whose row and secret are
    /// staged into `batch`. Returns the key and whether it is new (and process-local).
    async fn write_key(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        batch: &mut WriteBatch,
    ) -> IpamResult<(KeyBytes, Option<bool>)> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        if let Some(key) = self.read_key(view.as_ref(), id).await? {
            return Ok((key, None));
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        aws_lc_rs::rand::fill(&mut key[..]).map_err(|_| crypto_error("given a key"))?;
        let secret = match &self.vault {
            Some(vault) => Some(
                vault
                    .stage_put(
                        batch,
                        cx,
                        SecretClass::System,
                        SecretSpec::new(PURPOSE),
                        &SecretBytes::new(key.to_vec()),
                    )
                    .map_err(|error| vault_error(&error))?,
            ),
            None => None,
        };
        batch.expect_typed(&STASH_KEYS, &id, None);
        batch.put_typed(
            &STASH_KEYS,
            &id,
            &StashKey {
                secret,
                created: cx.now,
            },
        )?;
        Ok((Arc::new(key), Some(secret.is_none())))
    }

    fn seal(
        key: &[u8; 32],
        id: ImportId,
        name: &str,
        position: u32,
        count: u32,
        plain: &[u8],
    ) -> IpamResult<Bytes> {
        let mut nonce = [0_u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| crypto_error("encrypted"))?;
        let mut sealed = plain.to_vec();
        cipher(key)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(id, name, position, count)),
                &mut sealed,
            )
            .map_err(|_| crypto_error("encrypted"))?;
        let mut payload = Vec::with_capacity(NONCE_LEN + sealed.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&sealed);
        Ok(VaultEnvelope {
            format: ENVELOPE_FORMAT,
            key_id: ENVELOPE_KEY_ID.to_owned(),
            payload: Bytes::from(payload),
        }
        .to_bytes()?)
    }

    fn unseal(
        key: &[u8; 32],
        id: ImportId,
        name: &str,
        position: u32,
        count: u32,
        stored: &[u8],
    ) -> IpamResult<Vec<u8>> {
        let envelope = VaultEnvelope::from_bytes(stored).map_err(|_| lost())?;
        if envelope.format != ENVELOPE_FORMAT {
            return Err(lost());
        }
        let (nonce, sealed) = envelope
            .payload
            .split_at_checked(NONCE_LEN)
            .ok_or_else(lost)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| lost())?;
        let mut buffer = Vec::from(sealed);
        let plain_len = cipher(key)?
            .open_in_place(
                nonce,
                Aad::from(aad(id, name, position, count)),
                &mut buffer,
            )
            .map_err(|_| lost())?
            .len();
        buffer.truncate(plain_len);
        Ok(buffer)
    }

    /// Encrypts and stages the `index`-th file of an import; returns its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error when encryption fails, and the store's or the vault's
    /// errors.
    pub async fn write(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        index: usize,
        bytes: &[u8],
    ) -> IpamResult<String> {
        self.put(cx, id, &format!("file{index}"), bytes).await
    }

    /// Encrypts and stages a named part of an import (such as the rows of its latest
    /// preview) under a new stored name; the caller records the name and removes the
    /// part it replaces with [`remove_part`](Self::remove_part). The name must not contain
    /// `:` or `.`.
    ///
    /// # Errors
    ///
    /// As [`write`](Self::write).
    pub async fn write_part(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        part: &str,
        bytes: &[u8],
    ) -> IpamResult<String> {
        let mut generation = [0_u8; 4];
        aws_lc_rs::rand::fill(&mut generation).map_err(|_| crypto_error("named"))?;
        let name = format!("{part}.{:08x}", u32::from_be_bytes(generation));
        self.put(cx, id, &name, bytes).await
    }

    async fn put(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        name: &str,
        bytes: &[u8],
    ) -> IpamResult<String> {
        let count = u32::try_from(bytes.len().div_ceil(CHUNK_BYTES).max(1))
            .map_err(|_| internal("the staged upload is too large"))?;
        let mut chunks = bytes.chunks(CHUNK_BYTES);
        let first = chunks.next().unwrap_or_default();
        // The first chunk goes with the key when the import has none yet.
        let mut attempt = 0;
        let key = loop {
            attempt += 1;
            let mut batch = stash_batch(cx);
            let (key, new) = self.write_key(cx, id, &mut batch).await?;
            batch.put(
                STASH_CHUNKS.clone(),
                chunk_key(id, name, 0),
                Self::seal(&key, id, name, 0, count, first)?,
            );
            match self.store.propose(batch).await {
                Ok(_) => {
                    if let Some(local) = new {
                        self.remember(id, Arc::clone(&key), local);
                    }
                    break key;
                }
                Err(StoreError::PreconditionFailed(_)) if attempt < ATTEMPTS => {}
                Err(error) => return Err(error.into()),
            }
        };
        for (position, chunk) in (1..count).zip(chunks) {
            let mut batch = stash_batch(cx);
            batch.put(
                STASH_CHUNKS.clone(),
                chunk_key(id, name, position),
                Self::seal(&key, id, name, position, count, chunk)?,
            );
            self.store.propose(batch).await?;
        }
        Ok(format!("{name}:{count}"))
    }

    /// Reads and decrypts a staged file.
    ///
    /// # Errors
    ///
    /// Returns `import.upload.lost` (410) when the file is missing or does not open (it was
    /// staged by a process without a vault that has since restarted), and the store's
    /// errors.
    pub async fn read(&self, id: ImportId, index: usize, stored_as: &str) -> IpamResult<Vec<u8>> {
        let (name, count) = parse_stored(stored_as).ok_or_else(lost)?;
        if name != format!("file{index}") {
            return Err(lost());
        }
        self.get(id, name, count).await
    }

    /// Reads and decrypts a named part written by [`write_part`](Self::write_part).
    ///
    /// # Errors
    ///
    /// As [`read`](Self::read).
    pub async fn read_part(
        &self,
        id: ImportId,
        part: &str,
        stored_as: &str,
    ) -> IpamResult<Vec<u8>> {
        let (name, count) = parse_stored(stored_as).ok_or_else(lost)?;
        if name.split_once('.').map(|(prefix, _)| prefix) != Some(part) {
            return Err(lost());
        }
        self.get(id, name, count).await
    }

    /// Reads a part from this controller's view and, when it is not complete there yet
    /// (written moments ago through another controller), from a linearizable one.
    async fn get(&self, id: ImportId, name: &str, count: u32) -> IpamResult<Vec<u8>> {
        for consistency in [ReadConsistency::Local, ReadConsistency::Linearizable] {
            let view = self.store.read(consistency).await?;
            if let Some(bytes) = self.get_in(view.as_ref(), id, name, count).await? {
                return Ok(bytes);
            }
        }
        Err(lost())
    }

    async fn get_in(
        &self,
        view: &dyn ReadView,
        id: ImportId,
        name: &str,
        count: u32,
    ) -> IpamResult<Option<Vec<u8>>> {
        let Some(key) = self.read_key(view, id).await? else {
            return Ok(None);
        };
        let rows = view.scan(
            &STASH_CHUNKS,
            KeyRange::prefix(encode_key(&(id, name.to_owned()))),
            usize::try_from(count)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
            false,
        )?;
        if rows.len() != usize::try_from(count).unwrap_or(usize::MAX) {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        for (position, (stored_key, value)) in (0..count).zip(rows) {
            if stored_key != chunk_key(id, name, position) {
                return Err(lost());
            }
            bytes.extend_from_slice(&Self::unseal(
                &key,
                id,
                name,
                position,
                count,
                &value.value,
            )?);
        }
        Ok(Some(bytes))
    }

    /// Stages the removal of everything an import holds in the stash into `batch`: its
    /// chunks, its stored preview, its key row and the vault secret of its key. Call
    /// [`forget`](Self::forget) once the batch committed.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn stage_remove(
        &self,
        batch: &mut WriteBatch,
        cx: &RequestCtx,
        id: ImportId,
    ) -> IpamResult<()> {
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        self.stage_remove_in(view.as_ref(), batch, cx, id)
    }

    fn stage_remove_in(
        &self,
        view: &dyn ReadView,
        batch: &mut WriteBatch,
        cx: &RequestCtx,
        id: ImportId,
    ) -> IpamResult<()> {
        for (key, _) in view.scan(
            &STASH_CHUNKS,
            KeyRange::prefix(encode_key(&(id,))),
            usize::MAX,
            false,
        )? {
            batch.delete(STASH_CHUNKS.clone(), key);
        }
        if view.get_typed(&PREVIEWS, &id)?.is_some() {
            batch.delete_typed(&PREVIEWS, &id);
        }
        if let Some((row, revision)) = view.get_typed(&STASH_KEYS, &id)? {
            batch
                .expect_typed(&STASH_KEYS, &id, Some(revision))
                .delete_typed(&STASH_KEYS, &id);
            if let (Some(secret), Some(vault)) = (row.secret, &self.vault) {
                vault.stage_delete(batch, cx, secret);
            }
        }
        Ok(())
    }

    /// Removes the chunks of one staged part (an earlier preview), in one batch.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub async fn remove_part(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        stored_as: &str,
    ) -> IpamResult<()> {
        let Some((name, _)) = parse_stored(stored_as) else {
            return Ok(());
        };
        let view = self.store.read(ReadConsistency::Linearizable).await?;
        let rows = view.scan(
            &STASH_CHUNKS,
            KeyRange::prefix(encode_key(&(id, name.to_owned()))),
            usize::MAX,
            false,
        )?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut batch = stash_batch(cx);
        for (key, _) in rows {
            batch.delete(STASH_CHUNKS.clone(), key);
        }
        self.store.propose(batch).await?;
        Ok(())
    }

    /// The store part of the purge: removes the stash of every import that has no session
    /// (an upload that failed before its session was written, a session removed by an
    /// older release) once its key is older than [`ORPHAN_GRACE`], one fenced batch per
    /// import; returns how many. The leader runs it with the epoch of its term as `fence`.
    ///
    /// # Errors
    ///
    /// The store's errors, the precondition failure of a fenced batch among them.
    pub async fn purge_orphans(&self, now: Timestamp, fence: Option<u64>) -> IpamResult<usize> {
        let cx = RequestCtx::system(SystemComponent::Import);
        let view = self.store.read(ReadConsistency::Local).await?;
        let keys = view.scan_typed(&STASH_KEYS, KeyRange::all(), usize::MAX, false)?;
        let mut removed = 0;
        for (id, row, _) in keys {
            if view.get_typed(&SESSIONS, &id)?.is_some()
                || row.created.checked_add(ORPHAN_GRACE).unwrap_or(row.created) > now
            {
                continue;
            }
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Import), now);
            if let Some(epoch) = fence {
                batch.preconditions.push(tenko_store::fence(epoch));
            }
            batch.expect_typed(&SESSIONS, &id, None);
            self.stage_remove_in(view.as_ref(), &mut batch, &cx, id)?;
            self.store.propose(batch).await?;
            self.forget(id);
            removed += 1;
        }
        Ok(removed)
    }

    /// The local part of the purge: forgets the keys of imports for which `keep` is false;
    /// returns how many.
    pub fn sweep(&self, keep: impl Fn(ImportId) -> bool) -> usize {
        let mut keys = self.keys();
        let before = keys.cached.len() + keys.local.len();
        keys.cached.retain(|id, _| keep(*id));
        keys.local.retain(|id, _| keep(*id));
        before - keys.cached.len() - keys.local.len()
    }
}

#[cfg(test)]
mod tests {
    use tenko_store::MemStore;
    use tenko_vault::MemVault;

    use super::*;

    fn stash() -> (Arc<MemStore>, Stash) {
        let (mem, vault) = parts();
        (Arc::clone(&mem), Stash::new(mem, Some(vault)))
    }

    /// One store and one vault, as every controller of a cluster sees them.
    fn parts() -> (Arc<MemStore>, Arc<dyn Vault>) {
        let mem = Arc::new(MemStore::default());
        let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(Arc::clone(&mem)));
        (mem, vault)
    }

    fn cx() -> RequestCtx {
        RequestCtx::system(SystemComponent::Import)
    }

    async fn raw_chunks(store: &MemStore) -> Vec<Bytes> {
        store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
            .scan(&STASH_CHUNKS, KeyRange::all(), usize::MAX, false)
            .expect("scan")
            .into_iter()
            .map(|(_, value)| value.value)
            .collect()
    }

    #[tokio::test]
    async fn staged_files_are_encrypted_and_bound_to_their_import() {
        let (store, stash) = stash();
        let id = ImportId::generate();
        let plain = b"IP;Pass\n192.0.2.1;example-only\n";
        let stored = stash.write(&cx(), id, 0, plain).await.expect("write");
        for raw in raw_chunks(&store).await {
            assert!(VaultEnvelope::is_envelope(&raw));
            assert!(
                !raw.windows(12).any(|w| w == b"example-only"),
                "the password must not be in the store in plain text"
            );
        }
        assert_eq!(stash.read(id, 0, &stored).await.expect("read"), plain);
        assert!(
            stash.read(id, 1, &stored).await.is_err(),
            "bound to the file index"
        );
        assert!(
            stash.read(ImportId::generate(), 0, &stored).await.is_err(),
            "bound to the import"
        );
    }

    #[tokio::test]
    async fn another_controller_reads_what_one_staged() {
        let (store, vault) = parts();
        let stash = Stash::new(
            Arc::clone(&store) as Arc<dyn Store>,
            Some(Arc::clone(&vault)),
        );
        let elsewhere = Stash::new(store, Some(vault));
        let id = ImportId::generate();
        let stored = stash.write(&cx(), id, 0, b"a;b\n").await.expect("write");
        assert_eq!(
            elsewhere.read(id, 0, &stored).await.expect("read"),
            b"a;b\n"
        );
    }

    #[tokio::test]
    async fn large_files_are_cut_into_chunks_that_open_only_together() {
        let (store, stash) = stash();
        let id = ImportId::generate();
        let plain: Vec<u8> = (0..CHUNK_BYTES * 2 + 17)
            .map(|i| u8::try_from(i % 251).expect("small"))
            .collect();
        let stored = stash.write(&cx(), id, 0, &plain).await.expect("write");
        assert_eq!(stored, "file0:3");
        assert_eq!(raw_chunks(&store).await.len(), 3);
        assert_eq!(stash.read(id, 0, &stored).await.expect("read"), plain);
        // A wrong count does not open: the count is authenticated with every chunk.
        let error = stash.read(id, 0, "file0:2").await.expect_err("short");
        assert!(error.is(codes::UPLOAD_LOST));
        // A missing chunk does not open either.
        let mut batch = stash_batch(&cx());
        batch.delete(STASH_CHUNKS.clone(), chunk_key(id, "file0", 1));
        store.propose(batch).await.expect("delete");
        let error = stash.read(id, 0, &stored).await.expect_err("gap");
        assert!(error.is(codes::UPLOAD_LOST));
    }

    #[tokio::test]
    async fn parts_are_replaced_and_removed() {
        let (store, stash) = stash();
        let id = ImportId::generate();
        let first = stash
            .write_part(&cx(), id, "rows", b"one")
            .await
            .expect("write");
        let second = stash
            .write_part(&cx(), id, "rows", b"two")
            .await
            .expect("write");
        assert_ne!(first, second);
        stash.remove_part(&cx(), id, &first).await.expect("remove");
        assert!(stash.read_part(id, "rows", &first).await.is_err());
        assert_eq!(
            stash.read_part(id, "rows", &second).await.expect("read"),
            b"two"
        );
        assert!(stash.read_part(id, "other", &second).await.is_err());
        let mut batch = stash_batch(&cx());
        stash
            .stage_remove(&mut batch, &cx(), id)
            .await
            .expect("stage");
        store.propose(batch).await.expect("remove");
        stash.forget(id);
        assert_eq!(raw_chunks(&store).await.len(), 0);
        let view = store.read(ReadConsistency::Local).await.expect("view");
        assert!(view.get_typed(&STASH_KEYS, &id).expect("read").is_none());
    }

    #[tokio::test]
    async fn without_a_vault_the_key_stays_in_this_process() {
        let store = Arc::new(MemStore::default());
        let stash = Stash::new(Arc::clone(&store) as Arc<dyn Store>, None);
        let id = ImportId::generate();
        let stored = stash.write(&cx(), id, 0, b"x").await.expect("write");
        assert_eq!(stash.read(id, 0, &stored).await.expect("read"), b"x");
        let restarted = Stash::new(store as Arc<dyn Store>, None);
        let error = restarted.read(id, 0, &stored).await.expect_err("lost");
        assert!(error.is(codes::UPLOAD_LOST));
        assert_eq!(stash.sweep(|_| false), 1);
    }

    #[tokio::test]
    async fn the_purge_removes_the_stash_of_imports_without_a_session() {
        let (store, stash) = stash();
        let id = ImportId::generate();
        stash.write(&cx(), id, 0, b"x").await.expect("write");
        let now = Timestamp::now();
        assert_eq!(stash.purge_orphans(now, None).await.expect("purge"), 0);
        let later = now.checked_add(ORPHAN_GRACE * 2).expect("in range");
        let error = stash
            .purge_orphans(later, Some(7))
            .await
            .expect_err("a deposed leader's purge is fenced");
        assert!(error.is("sys.store.precondition_failed"), "{error}");
        assert_eq!(stash.purge_orphans(later, Some(0)).await.expect("purge"), 1);
        assert_eq!(raw_chunks(&store).await.len(), 0);
    }
}
