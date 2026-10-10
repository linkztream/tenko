//! A directory of sealed KEK generations.
//!
//! File `kek-<generation, six digits>.<sealer name>` holds the sealed form of
//!
//! ```text
//! "TKEK" | version u8 = 1 | generation u32 BE | id length u8 | id (UTF-8) | key (32 bytes)
//! ```
//!
//! The KEK identifier is `<sealer name>-<generation>-<8 random hex digits>`, so a deleted
//! and recreated generation never matches the envelopes of its predecessor.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use zeroize::Zeroizing;

use super::{
    DataKey, KekInit, KekProtection, KekProvider, KekRing, KekSealer, LocalKek, RefusedKek,
    same_material,
};
use crate::{TransferFailure, VaultError, transfer::TransferredKek};

const MAGIC: &[u8; 4] = b"TKEK";

/// A generation found on disk: number, file and the sealer that reads it.
type Generation = (u32, PathBuf, Arc<dyn KekSealer>);
const VERSION: u8 = 1;

/// Numbered KEK generations in one directory, sealed by a [`KekSealer`].
///
/// Plain generations (a [`PlainSealer`] file) are always found, whatever the sealer; one
/// that is newer than the newest sealed generation is refused unless plain generations are
/// allowed ([`allowing_plain`](KekDir::allowing_plain)), see the module documentation of
/// [`crate::kek`] (R15).
#[derive(Debug, Clone)]
pub struct KekDir {
    dir: PathBuf,
    primary: Arc<dyn KekSealer>,
    readers: Vec<Arc<dyn KekSealer>>,
    allow_plain: bool,
}

impl KekDir {
    /// A directory whose new generations are sealed by `sealer`.
    pub fn new(dir: impl Into<PathBuf>, sealer: Arc<dyn KekSealer>) -> Self {
        let mut readers = vec![Arc::clone(&sealer)];
        if sealer.name() != PlainSealer.name() {
            readers.push(Arc::new(PlainSealer));
        }
        Self {
            dir: dir.into(),
            readers,
            primary: sealer,
            allow_plain: false,
        }
    }

    /// Also loads generations sealed by `sealer` (for example plain files written before
    /// `systemd-creds` became usable). New generations still use the primary sealer.
    #[must_use]
    pub fn also_reading(mut self, sealer: Arc<dyn KekSealer>) -> Self {
        if !self.readers.iter().any(|r| r.name() == sealer.name()) {
            self.readers.push(sealer);
        }
        self
    }

    /// Whether plain generations may be loaded, created and imported beside sealed ones
    /// (`[kek] allow_plain`, R15). Off by default.
    #[must_use]
    pub fn allowing_plain(mut self, allow: bool) -> Self {
        self.allow_plain = allow;
        self
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Whether the directory holds no generation file this directory reads.
    ///
    /// # Errors
    ///
    /// An I/O error while listing.
    pub fn is_empty(&self) -> Result<bool, VaultError> {
        Ok(self.generations()?.is_empty())
    }

    /// Loads every generation; the highest is active. A plain generation newer than the
    /// newest sealed one is refused (left out and listed in [`KekRing::refused`]) unless
    /// plain generations are allowed.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] when the directory holds no generation and `init` is
    /// [`KekInit::Require`], or when a generation cannot be read or unsealed.
    pub fn load(&self, init: KekInit) -> Result<KekRing, VaultError> {
        let mut generations = self.generations()?;
        if generations.is_empty() {
            match init {
                KekInit::Require => {
                    return Err(VaultError::kek_unavailable(format!(
                        "no key-encryption key in {}; restore the KEK directory from backup \
                         (a new KEK cannot open existing secrets)",
                        self.dir.display()
                    )));
                }
                KekInit::CreateIfMissing => {
                    let kek = self.create_generation(1)?;
                    return Ok(KekRing::new(kek));
                }
            }
        }
        generations.sort_by_key(|(generation, ..)| *generation);
        let newest_sealed = newest_sealed(&generations);
        let mut loaded = Vec::with_capacity(generations.len());
        let mut refused = Vec::new();
        for (generation, path, sealer) in &generations {
            let protection = sealer.protection();
            if let Some((sealed_generation, sealed)) = newest_sealed
                && protection.is_weak()
                && *generation > sealed_generation
            {
                if self.allow_plain {
                    tracing::warn!(
                        path = %path.display(),
                        "LOADING A PLAIN KEY GENERATION NEWER THAN THE SEALED ONE because \
                         kek.allow_plain is set: secrets written from now on are protected \
                         by a file anyone who can read {} can use",
                        self.dir.display()
                    );
                } else {
                    tracing::error!(
                        path = %path.display(),
                        "refused a plain key generation newer than the sealed generation \
                         {sealed_generation} ({}): it would downgrade the protection of every \
                         new secret; remove the file, or set kek.allow_plain = true if it is \
                         intended",
                        sealed.describe()
                    );
                    refused.push(RefusedKek {
                        generation: *generation,
                        path: path.clone(),
                        protection,
                        sealed,
                    });
                    continue;
                }
            }
            loaded.push(Self::open_generation(*generation, path, sealer.as_ref())?);
        }
        let ring = KekRing::from_generations(loaded)?.with_refused(refused);
        warn_if_weak(ring.active().as_ref(), &self.dir);
        if !ring.active().protection().is_weak() {
            for kek in ring.generations() {
                if kek.protection().is_weak() {
                    tracing::warn!(
                        kek = %kek.id(),
                        dir = %self.dir.display(),
                        "a retired key generation has no OS protection; finish the rotation \
                         and remove it with `tenko kek rotate`"
                    );
                }
            }
        }
        Ok(ring)
    }

    /// Creates the generation after the highest existing one.
    ///
    /// # Errors
    ///
    /// [`VaultError::PlainRefused`] when the new generation would be plain beside a sealed
    /// one, or an I/O or sealing error.
    pub fn create_next(&self) -> Result<Arc<dyn KekProvider>, VaultError> {
        let generations = self.generations()?;
        self.check_plain(&generations)?;
        let next = self.next_number()?;
        self.create_generation(next)
    }

    /// Writes generations received from another controller, keeping their identifiers:
    /// those this directory holds already are skipped, the others are written in the order
    /// given as the next generations. Returns the identifiers written.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transfer`] with [`TransferFailure::Conflict`] when a different key is
    /// held under one of the identifiers, [`VaultError::PlainRefused`] when the sealing is
    /// plain beside a sealed generation, or an I/O or sealing error.
    pub fn import(&self, generations: &[TransferredKek]) -> Result<Vec<String>, VaultError> {
        let mut existing = self.generations()?;
        existing.sort_by_key(|(generation, ..)| *generation);
        let mut held = Vec::with_capacity(existing.len());
        for (generation, path, sealer) in &existing {
            held.push(Self::open_generation(*generation, path, sealer.as_ref())?);
        }
        let mut fresh: Vec<&TransferredKek> = Vec::new();
        for kek in generations {
            match held.iter().find(|known| known.id() == kek.id) {
                Some(known) if same_material(known.as_ref(), kek) => {}
                Some(_) => {
                    return Err(VaultError::transfer(TransferFailure::Conflict {
                        id: kek.id.clone(),
                    }));
                }
                None if fresh.iter().any(|seen| seen.id == kek.id) => {}
                None => fresh.push(kek),
            }
        }
        if fresh.is_empty() {
            return Ok(Vec::new());
        }
        self.check_plain(&existing)?;
        let mut next = self.next_number()?;
        let mut written = Vec::with_capacity(fresh.len());
        for kek in fresh {
            self.write_generation(next, &kek.id, &kek.material)?;
            tracing::info!(
                kek = %kek.id,
                protection = self.primary.protection().describe(),
                dir = %self.dir.display(),
                "stored key generation {next} received from another controller"
            );
            written.push(kek.id.clone());
            next = next.checked_add(1).ok_or(VaultError::Malformed {
                what: "KEK generation number",
            })?;
        }
        Ok(written)
    }

    /// Deletes the file of a retired generation.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unsupported`] for the highest (active) generation,
    /// [`VaultError::UnknownKek`] when no file holds `id`, or an I/O error.
    pub fn remove(&self, id: &str) -> Result<(), VaultError> {
        let generations = self.generations()?;
        let highest = generations.iter().map(|(g, ..)| *g).max();
        for (generation, path, sealer) in &generations {
            let kek = Self::open_generation(*generation, path, sealer.as_ref())?;
            if kek.id() == id {
                if Some(*generation) == highest {
                    return Err(VaultError::Unsupported {
                        what: "removing the active KEK generation".to_owned(),
                    });
                }
                return fs::remove_file(path).map_err(|e| io_error("remove", path, &e));
            }
        }
        Err(VaultError::UnknownKek {
            key_id: id.to_owned(),
        })
    }

    /// Refuses to add a plain generation beside a sealed one unless allowed.
    fn check_plain(&self, existing: &[Generation]) -> Result<(), VaultError> {
        if !self.primary.protection().is_weak() || self.allow_plain {
            return Ok(());
        }
        match newest_sealed(existing) {
            Some((generation, sealed)) => Err(VaultError::PlainRefused {
                reason: format!(
                    "{} holds generation {generation} sealed with {}, and a new generation \
                     here would be a plain file; make the sealing work again (for example \
                     systemd-creds for this account), or set kek.allow_plain = true",
                    self.dir.display(),
                    sealed.describe(),
                ),
            }),
            None => Ok(()),
        }
    }

    /// The number after the highest generation file of any sealer, so a number is never
    /// reused, even that of a file this directory does not read.
    fn next_number(&self) -> Result<u32, VaultError> {
        self.numbers()?
            .into_iter()
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(VaultError::Malformed {
                what: "KEK generation number",
            })
    }

    /// The generation numbers of every `kek-NNNNNN.<sealer>` file.
    fn numbers(&self) -> Result<Vec<u32>, VaultError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_error("list", &self.dir, &e)),
        };
        let mut numbers = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error("list", &self.dir, &e))?;
            let name = entry.file_name();
            if let Some(generation) = name
                .to_str()
                .and_then(|name| name.split_once('.'))
                .filter(|(_, extension)| *extension != "tmp")
                .and_then(|(stem, _)| parse_stem(stem))
            {
                numbers.push(generation);
            }
        }
        Ok(numbers)
    }

    fn generations(&self) -> Result<Vec<Generation>, VaultError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_error("list", &self.dir, &e)),
        };
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error("list", &self.dir, &e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((stem, extension)) = name.split_once('.') else {
                continue;
            };
            let Some(generation) = parse_stem(stem) else {
                continue;
            };
            if let Some(sealer) = self.readers.iter().find(|s| s.name() == extension) {
                found.push((generation, entry.path(), Arc::clone(sealer)));
            }
        }
        Ok(found)
    }

    fn open_generation(
        generation: u32,
        path: &Path,
        sealer: &dyn KekSealer,
    ) -> Result<Arc<dyn KekProvider>, VaultError> {
        let blob = fs::read(path).map_err(|e| {
            VaultError::kek_unavailable(format!("cannot read {}: {e}", path.display()))
        })?;
        let plain = sealer.unseal(&stem(generation), &blob)?;
        let (file_generation, id, key) = decode(&plain)?;
        if file_generation != generation {
            return Err(VaultError::kek_unavailable(format!(
                "{} holds generation {file_generation}",
                path.display()
            )));
        }
        Ok(Arc::new(LocalKek::new(id, sealer.protection(), &key)?))
    }

    fn create_generation(&self, generation: u32) -> Result<Arc<dyn KekProvider>, VaultError> {
        let mut key = Zeroizing::new([0u8; DataKey::LEN]);
        aws_lc_rs::rand::fill(key.as_mut()).map_err(|_| VaultError::Crypto {
            operation: "random KEK",
        })?;
        let mut tag = [0u8; 4];
        aws_lc_rs::rand::fill(&mut tag).map_err(|_| VaultError::Crypto {
            operation: "random KEK identifier",
        })?;
        let id = format!("{}-{generation}-{}", self.primary.name(), super::hex(&tag));
        let kek = self.write_generation(generation, &id, &key)?;
        tracing::info!(
            kek = %id,
            protection = self.primary.protection().describe(),
            dir = %self.dir.display(),
            "created key-encryption key generation {generation}"
        );
        warn_if_weak(kek.as_ref(), &self.dir);
        Ok(kek)
    }

    /// Seals and writes one generation file; refuses to overwrite one.
    fn write_generation(
        &self,
        generation: u32,
        id: &str,
        key: &Zeroizing<[u8; DataKey::LEN]>,
    ) -> Result<Arc<dyn KekProvider>, VaultError> {
        create_private_dir(&self.dir)?;
        if self.numbers()?.contains(&generation) {
            return Err(VaultError::provider(
                "kek-dir",
                format!(
                    "generation {generation} already exists in {}",
                    self.dir.display()
                ),
            ));
        }
        let path = self
            .dir
            .join(format!("{}.{}", stem(generation), self.primary.name()));
        let plain = encode(generation, id, key)?;
        let sealed = self.primary.seal(&stem(generation), &plain)?;
        write_private(&path, &sealed)?;
        Ok(Arc::new(LocalKek::new(id, self.primary.protection(), key)?))
    }
}

/// The newest sealed (not weak) generation and its protection.
fn newest_sealed(generations: &[Generation]) -> Option<(u32, KekProtection)> {
    generations
        .iter()
        .filter(|(_, _, sealer)| !sealer.protection().is_weak())
        .max_by_key(|(generation, ..)| *generation)
        .map(|(generation, _, sealer)| (*generation, sealer.protection()))
}

/// Leaves KEK bytes unprotected: Linux without a usable `systemd-creds`. Every load logs
/// a warning.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainSealer;

impl KekSealer for PlainSealer {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn protection(&self) -> KekProtection {
        KekProtection::PlainFile
    }

    fn seal(&self, _label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(plaintext.to_vec())
    }

    fn unseal(&self, _label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(sealed.to_vec()))
    }
}

fn warn_if_weak(kek: &dyn KekProvider, dir: &Path) {
    if kek.protection().is_weak() {
        tracing::warn!(
            kek = %kek.id(),
            dir = %dir.display(),
            "THE KEY-ENCRYPTION KEY IS STORED WITHOUT OS PROTECTION ({}). Anyone who can \
             read this directory can decrypt every secret in the vault. Install \
             systemd-creds (or use DPAPI on Windows) and rotate the KEK.",
            kek.protection().describe()
        );
    }
}

fn stem(generation: u32) -> String {
    format!("kek-{generation:06}")
}

fn parse_stem(stem: &str) -> Option<u32> {
    let digits = stem.strip_prefix("kek-")?;
    if digits.len() < 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn encode(
    generation: u32,
    id: &str,
    key: &Zeroizing<[u8; DataKey::LEN]>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let id_len = u8::try_from(id.len()).map_err(|_| VaultError::Malformed {
        what: "KEK identifier",
    })?;
    let mut out = Zeroizing::new(Vec::with_capacity(10 + id.len() + DataKey::LEN));
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.push(id_len);
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(key.as_ref());
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<(u32, String, Zeroizing<[u8; DataKey::LEN]>), VaultError> {
    const MALFORMED: VaultError = VaultError::Malformed { what: "KEK file" };
    let rest = bytes.strip_prefix(MAGIC.as_slice()).ok_or(MALFORMED)?;
    let (&version, rest) = rest.split_first().ok_or(MALFORMED)?;
    if version != VERSION {
        return Err(MALFORMED);
    }
    let (generation, rest) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;
    let (&id_len, rest) = rest.split_first().ok_or(MALFORMED)?;
    let (id, key_bytes) = rest
        .split_at_checked(usize::from(id_len))
        .ok_or(MALFORMED)?;
    let id = std::str::from_utf8(id).map_err(|_| MALFORMED)?.to_owned();
    if key_bytes.len() != DataKey::LEN {
        return Err(MALFORMED);
    }
    let mut key = Zeroizing::new([0u8; DataKey::LEN]);
    key.copy_from_slice(key_bytes);
    Ok((u32::from_be_bytes(*generation), id, key))
}

pub(crate) fn io_error(action: &str, path: &Path, error: &std::io::Error) -> VaultError {
    VaultError::provider(
        "file",
        format!("cannot {action} {}: {error}", path.display()),
    )
}

/// Creates a directory (and parents) readable only by the owner on Unix.
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), VaultError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| io_error("create directory", dir, &e))
}

/// Writes a file atomically (temporary file, sync, rename) with mode 0600 on Unix.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error("write", path, &e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenko-vault-{name}-{}",
            tenko_core::SecretId::generate()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn generation_files_round_trip() {
        let key = Zeroizing::new([7u8; DataKey::LEN]);
        let bytes = encode(3, "plain-3-0011aabb", &key).expect("encode");
        let (generation, id, back) = decode(&bytes).expect("decode");
        assert_eq!((generation, id.as_str()), (3, "plain-3-0011aabb"));
        assert_eq!(back.as_ref(), key.as_ref());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode(b"nope").is_err());
    }

    /// A stand-in for a sealing mechanism (DPAPI, `systemd-creds`) on every platform:
    /// reverses the bytes and reports a sealed protection.
    #[derive(Debug)]
    struct Sealed;

    impl KekSealer for Sealed {
        fn name(&self) -> &'static str {
            "sealed"
        }

        fn protection(&self) -> KekProtection {
            KekProtection::SystemdCreds { tpm2: true }
        }

        fn seal(&self, _label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
            Ok(plaintext.iter().rev().copied().collect())
        }

        fn unseal(&self, _label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            Ok(Zeroizing::new(sealed.iter().rev().copied().collect()))
        }
    }

    fn transferred(id: &str, byte: u8) -> TransferredKek {
        TransferredKek {
            id: id.to_owned(),
            material: Zeroizing::new([byte; DataKey::LEN]),
        }
    }

    #[test]
    fn a_plain_generation_newer_than_a_sealed_one_is_refused() {
        let dir = temp_dir("dir-r15");
        let sealed = KekDir::new(&dir, Arc::new(Sealed));
        let first = sealed.load(KekInit::CreateIfMissing).expect("create");
        assert!(first.active().id().starts_with("sealed-1-"));
        // Someone who can write the directory drops a plain generation numbered above it.
        let key = Zeroizing::new([5u8; DataKey::LEN]);
        let plain = encode(2, "plain-2-0badc0de", &key).expect("encode");
        fs::write(dir.join("kek-000002.plain"), &*plain).expect("dropped");
        assert!(dir.join("kek-000002.plain").exists());
        let ring = sealed.load(KekInit::Require).expect("load");
        assert_eq!(
            ring.active().id(),
            first.active().id(),
            "still the sealed one"
        );
        assert_eq!(ring.ids().count(), 1);
        assert_eq!(ring.refused().len(), 1);
        let refused = &ring.refused()[0];
        assert_eq!(refused.generation, 2);
        assert_eq!(refused.protection, KekProtection::PlainFile);
        assert_eq!(refused.sealed, KekProtection::SystemdCreds { tpm2: true });
        // Allowed on purpose, it loads and becomes active.
        let allowed = sealed
            .clone()
            .allowing_plain(true)
            .load(KekInit::Require)
            .expect("load");
        assert!(allowed.active().id().starts_with("plain-2-"));
        assert_eq!(allowed.refused(), []);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn older_plain_generations_still_load_beside_sealed_ones() {
        let dir = temp_dir("dir-r15-older");
        // A sealing tool that did not work at first: plain files, sealed ones still read.
        let plain = KekDir::new(&dir, Arc::new(PlainSealer)).also_reading(Arc::new(Sealed));
        let first = plain.load(KekInit::CreateIfMissing).expect("create");
        let sealed = KekDir::new(&dir, Arc::new(Sealed));
        let second = sealed.create_next().expect("sealed rotation");
        let ring = sealed.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), second.id());
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            [first.active().id()]
        );
        assert_eq!(ring.refused(), []);
        // A plain directory never adds a generation beside the sealed one by itself.
        let error = plain.create_next().expect_err("plain beside sealed");
        assert!(
            matches!(error, VaultError::PlainRefused { .. }),
            "{error:?}"
        );
        assert!(plain.clone().allowing_plain(true).create_next().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn imports_keep_ids_skip_known_generations_and_refuse_conflicts() {
        let dir = temp_dir("dir-import");
        let kek_dir = KekDir::new(&dir, Arc::new(Sealed));
        let incoming = [transferred("dpapi-1-aa", 1), transferred("dpapi-2-bb", 2)];
        let written = kek_dir.import(&incoming).expect("import");
        assert_eq!(written, ["dpapi-1-aa", "dpapi-2-bb"]);
        assert!(dir.join("kek-000001.sealed").exists());
        assert!(dir.join("kek-000002.sealed").exists());
        let ring = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(ring.ids().collect::<Vec<_>>(), ["dpapi-1-aa", "dpapi-2-bb"]);
        assert_eq!(
            ring.active().protection(),
            KekProtection::SystemdCreds { tpm2: true }
        );
        assert_eq!(
            ring.get("dpapi-1-aa")
                .and_then(|kek| kek.export_material())
                .as_deref(),
            Some(&[1; DataKey::LEN])
        );
        // Again, plus a newer generation: only the new one is written, as generation 3.
        let more = [
            transferred("dpapi-1-aa", 1),
            transferred("dpapi-2-bb", 2),
            transferred("dpapi-3-cc", 3),
        ];
        assert_eq!(kek_dir.import(&more).expect("import"), ["dpapi-3-cc"]);
        assert!(dir.join("kek-000003.sealed").exists());
        // A different key under a known identifier is refused, and nothing is written.
        let conflict = [transferred("dpapi-2-bb", 9), transferred("dpapi-4-dd", 4)];
        assert_eq!(
            kek_dir.import(&conflict).expect_err("conflict"),
            VaultError::transfer(TransferFailure::Conflict {
                id: "dpapi-2-bb".to_owned()
            })
        );
        assert!(!dir.join("kek-000004.sealed").exists());
        // A plain directory does not import beside sealed generations.
        let plain = KekDir::new(&dir, Arc::new(PlainSealer)).also_reading(Arc::new(Sealed));
        assert!(matches!(
            plain.import(&[transferred("dpapi-5-ee", 5)]),
            Err(VaultError::PlainRefused { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stems_parse() {
        assert_eq!(parse_stem("kek-000001"), Some(1));
        assert_eq!(parse_stem("kek-1234567"), Some(1_234_567));
        assert_eq!(parse_stem("kek-1"), None);
        assert_eq!(parse_stem("key-000001"), None);
    }

    #[test]
    fn require_fails_on_an_empty_directory_and_create_makes_generation_one() {
        let dir = temp_dir("dir-require");
        let kek_dir = KekDir::new(&dir, Arc::new(PlainSealer));
        assert!(matches!(
            kek_dir.load(KekInit::Require),
            Err(VaultError::KekUnavailable { .. })
        ));
        let ring = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        assert!(ring.active().id().starts_with("plain-1-"));
        assert!(dir.join("kek-000001.plain").exists());
        let again = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(again.active().id(), ring.active().id());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_adds_generations_and_retires_old_ones() {
        let dir = temp_dir("dir-rotate");
        let kek_dir = KekDir::new(&dir, Arc::new(PlainSealer));
        let first = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        let second = kek_dir.create_next().expect("next");
        assert!(second.id().starts_with("plain-2-"));
        let ring = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), second.id());
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            [first.active().id()]
        );
        assert!(matches!(
            kek_dir.remove(second.id()),
            Err(VaultError::Unsupported { .. })
        ));
        kek_dir.remove(first.active().id()).expect("remove");
        let ring = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(ring.ids().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_generation_stops_the_load() {
        let dir = temp_dir("dir-corrupt");
        let kek_dir = KekDir::new(&dir, Arc::new(PlainSealer));
        kek_dir.load(KekInit::CreateIfMissing).expect("create");
        fs::write(dir.join("kek-000001.plain"), b"garbage").expect("write");
        assert!(kek_dir.load(KekInit::Require).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn generation_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dir-mode");
        let kek_dir = KekDir::new(&dir, Arc::new(PlainSealer));
        kek_dir.load(KekInit::CreateIfMissing).expect("create");
        let mode = fs::metadata(dir.join("kek-000001.plain"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
