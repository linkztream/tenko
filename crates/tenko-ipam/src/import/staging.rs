//! Staged uploads: the session record in the store and the file bytes in a staging
//! directory, encrypted.
//!
//! An upload can hold credentials in plain text (the spreadsheet's `Pass` column), and
//! secrets are never at rest in plain text (NEVER-01). The bytes are therefore written
//! encrypted with AES-256-GCM under a key that lives only in the memory of this process
//! (drawn at start, zeroized on drop). A staged file does not survive a restart: the
//! session then reports `import.upload.lost` and a running apply job rolls back instead
//! of leaving half an import.
//!
//! The session record (`import.sessions`) holds the owner, the file references, the
//! user's mapping, the apply job and what the apply froze; it expires after the staging
//! time to live (24 hours by default).

use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{ImportId, JobId, Principal, Timestamp, UserId, audit::Digest, table::TableDef};
use zeroize::Zeroize;

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
    /// The file name inside the staging directory.
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

/// The staging directory and the in-memory key.
pub struct Stash {
    dir: PathBuf,
    key: LessSafeKey,
}

impl std::fmt::Debug for Stash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stash")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

fn io_error(what: &str, error: &std::io::Error) -> IpamError {
    IpamError::new(
        "sys.internal",
        500,
        format!("the import staging directory failed to {what}: {error}"),
    )
}

fn crypto_error(what: &str) -> IpamError {
    IpamError::new(
        "sys.internal",
        500,
        format!("the staged upload could not be {what}"),
    )
}

impl Stash {
    /// A stash in `dir` (created if missing) with a fresh random key.
    ///
    /// # Errors
    ///
    /// Returns an internal error when the directory cannot be created or no random key
    /// can be drawn.
    pub fn new(dir: &Path) -> IpamResult<Self> {
        fs::create_dir_all(dir).map_err(|e| io_error("be created", &e))?;
        let mut bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| crypto_error("given a key"))?;
        let key = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| crypto_error("given a key"));
        bytes.zeroize();
        Ok(Self {
            dir: dir.to_path_buf(),
            key: LessSafeKey::new(key?),
        })
    }

    /// The staging directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn aad(id: ImportId, index: usize) -> Vec<u8> {
        let mut aad = id.0.as_bytes().to_vec();
        aad.extend_from_slice(&(index as u64).to_be_bytes());
        aad
    }

    /// Encrypts and writes the `index`-th file of an import; returns its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error when encryption or the write fails.
    pub fn write(&self, id: ImportId, index: usize, bytes: &[u8]) -> IpamResult<String> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| crypto_error("encrypted"))?;
        let mut buffer = bytes.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(id, index)),
                &mut buffer,
            )
            .map_err(|_| crypto_error("encrypted"))?;
        let stored_as = format!("import-{}-{index}.bin", id.0);
        let path = self.dir.join(&stored_as);
        let mut file = fs::File::create(&path).map_err(|e| io_error("write a file", &e))?;
        file.write_all(&nonce)
            .and_then(|()| file.write_all(&buffer))
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("write a file", &e))?;
        Ok(stored_as)
    }

    /// Reads and decrypts a staged file.
    ///
    /// # Errors
    ///
    /// Returns `import.upload.lost` (410) when the file is missing or was written under
    /// another key (a restart).
    pub fn read(&self, id: ImportId, index: usize, stored_as: &str) -> IpamResult<Vec<u8>> {
        let lost = || {
            IpamError::new(
                codes::UPLOAD_LOST,
                410,
                "the staged upload is no longer available (the server restarted or it expired); upload the file again",
            )
            .titled("Upload no longer available")
        };
        let data = fs::read(self.dir.join(stored_as)).map_err(|_| lost())?;
        if data.len() < NONCE_LEN {
            return Err(lost());
        }
        let (nonce, sealed) = data.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| lost())?;
        let mut buffer = sealed.to_vec();
        let plain_len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(id, index)),
                &mut buffer,
            )
            .map_err(|_| lost())?
            .len();
        buffer.truncate(plain_len);
        Ok(buffer)
    }

    /// Removes a staged file; a missing file is fine.
    pub fn remove(&self, stored_as: &str) {
        let _ = fs::remove_file(self.dir.join(stored_as));
    }

    /// Removes staged files of imports for which `keep` is false (start-up and expiry
    /// clean-up). Files that do not follow the naming scheme are left alone.
    pub fn sweep(&self, keep: impl Fn(&str) -> bool) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix("import-") else {
                continue;
            };
            let Some((id, _)) = rest.rsplit_once('-') else {
                continue;
            };
            if !keep(id) && fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!("tenko-import-stash-{}", uuid::Uuid::now_v7()))
    }

    #[test]
    fn staged_files_are_encrypted_and_bound_to_their_import() {
        let dir = dir();
        let stash = Stash::new(&dir).expect("stash");
        let id = ImportId::generate();
        let plain = b"IP;Pass\n192.0.2.1;example-only\n";
        let stored = stash.write(id, 0, plain).expect("write");
        let raw = fs::read(dir.join(&stored)).expect("raw");
        assert!(
            !raw.windows(12).any(|w| w == b"example-only"),
            "the password must not be on disk in plain text"
        );
        assert_eq!(stash.read(id, 0, &stored).expect("read"), plain);
        assert!(
            stash.read(id, 1, &stored).is_err(),
            "bound to the file index"
        );
        assert!(
            stash.read(ImportId::generate(), 0, &stored).is_err(),
            "bound to the import"
        );
        let other = Stash::new(&dir).expect("second key");
        let error = other.read(id, 0, &stored).expect_err("another key");
        assert!(error.is(codes::UPLOAD_LOST));
        assert_eq!(stash.sweep(|_| true), 0);
        assert_eq!(stash.sweep(|_| false), 1);
        let _ = fs::remove_dir_all(dir);
    }
}
