//! Key-encryption keys (KEKs) and their providers.
//!
//! A [`KekProvider`] wraps and unwraps data keys. The built-in providers keep 256-bit KEKs
//! in memory, loaded at start from files that the platform key store protects at rest, and
//! wrap with AES-256-GCM:
//!
//! | Provider | Platform | At rest | Config |
//! |---|---|---|---|
//! | DPAPI | Windows | `CryptProtectData`, user or machine scope | [`KekConfig::Dpapi`] |
//! | `systemd-creds` | Linux | sealed with the host key and TPM2 when present; plain file with a warning when the command is unusable | [`KekConfig::SystemdCreds`] |
//! | systemd credential | Linux | a credential that the service manager decrypts (`LoadCredentialEncrypted=`), host key or TPM2 | [`KekConfig::SystemdCredential`] |
//! | File | any (containers, CI) | an explicit key file, loud warning at every start | [`KekConfig::File`] |
//! | Memory | tests | nothing | `MemKek` (feature `testing`) |
//!
//! # Generations
//!
//! The DPAPI and `systemd-creds` providers keep numbered generations in a directory
//! (`kek-000001.dpapi`, `kek-000002.dpapi`, …). The systemd credential and file providers
//! hold one root key outside the data directory and keep further generations, created by a
//! rotation or received from another controller, in a directory as well, wrapped under the
//! root key (`kek-000002.wrap`, see [`WrapSealer`]). Without a store the highest generation
//! is active; with one, the vault activates the generation the store names
//! ([`StoreVault::open`](crate::StoreVault::open)), so every controller of a cluster wraps
//! with the same KEK. The others stay loaded until every envelope is re-wrapped
//! ([`StoreVault::rotate_kek`](crate::StoreVault::rotate_kek)) and the operator retires
//! them ([`KekConfig::remove_retired`]).
//!
//! # Plain generations (R15)
//!
//! A plain generation (no OS protection) newer than the newest sealed generation of the
//! same directory would become active and silently downgrade the protection of every new
//! secret. [`KekConfig::load_with`] refuses such a generation unless
//! [`KekOptions::allow_plain`] is set: the ring carries it in [`KekRing::refused`] and the
//! vault raises the alarm `vault.kek.downgrade` when it opens. A provider never creates or
//! imports a plain generation beside a sealed one either.
//!
//! # Start
//!
//! Start fails without a usable KEK: [`KekConfig::load`] with [`KekInit::Require`]
//! returns [`VaultError::KekUnavailable`] when no generation exists or one cannot be
//! unsealed, and [`StoreVault::open`](crate::StoreVault::open) refuses a ring that cannot
//! open the envelopes in the store.

#[cfg(unix)]
mod credential;
mod dir;
mod file;
mod local;
mod wrap;

#[cfg(windows)]
mod dpapi;
#[cfg(unix)]
mod systemd;

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(unix)]
pub use credential::CREDENTIALS_DIRECTORY;
pub use dir::{KekDir, PlainSealer};
#[cfg(windows)]
pub use dpapi::DpapiSealer;
pub use file::FileKek;
pub use local::LocalKek;
#[cfg(any(test, feature = "testing"))]
pub use local::MemKek;
#[cfg(unix)]
pub use systemd::SystemdCredsSealer;
pub use wrap::WrapSealer;

use crate::{VaultError, transfer::TransferredKek};

/// Lowercase hexadecimal of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// The longest KEK identifier, in bytes.
pub const MAX_KEK_ID_LEN: usize = 64;

/// Whether `id` can name a KEK: 1 to [`MAX_KEK_ID_LEN`] ASCII letters, digits, `-`, `_`
/// and `.`. Every built-in provider makes such identifiers; a transfer or an import with
/// another one is refused.
pub fn valid_kek_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEK_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A 256-bit data-encryption key. Zeroized on drop; `Debug` is redacted.
pub struct DataKey(Zeroizing<[u8; DataKey::LEN]>);

impl DataKey {
    /// Key length in bytes (AES-256).
    pub const LEN: usize = 32;

    /// Draws a fresh key from the system random number generator.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] if the generator fails.
    pub fn generate() -> Result<Self, VaultError> {
        let mut key = Zeroizing::new([0u8; Self::LEN]);
        aws_lc_rs::rand::fill(key.as_mut()).map_err(|_| VaultError::Crypto {
            operation: "random data key",
        })?;
        Ok(Self(key))
    }

    /// Takes key bytes (for providers that unwrap into a buffer).
    pub fn from_bytes(bytes: Zeroizing<[u8; Self::LEN]>) -> Self {
        Self(bytes)
    }

    /// The key bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl ZeroizeOnDrop for DataKey {}

/// How a KEK is protected at rest; shown in the health view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum KekProtection {
    /// Windows DPAPI.
    Dpapi {
        /// User or machine scope.
        scope: DpapiScope,
    },
    /// `systemd-creds encrypt`, run by Tenko or by the service manager.
    SystemdCreds {
        /// Whether the credential is sealed to the TPM2 (otherwise the host key only).
        tpm2: bool,
    },
    /// An unprotected key file (containers, CI, or Linux without `systemd-creds`).
    PlainFile,
    /// Memory only (tests).
    Memory,
}

impl KekProtection {
    /// Whether the protection is weak enough to warn about at every start.
    pub fn is_weak(self) -> bool {
        matches!(self, KekProtection::PlainFile | KekProtection::Memory)
    }

    /// The strength of the protection, for the downgrade check (R15): 0 memory, 1 a plain
    /// file, 2 DPAPI in machine scope or `systemd-creds` with the host key, 3 DPAPI in user
    /// scope or `systemd-creds` with a TPM2.
    pub fn rank(self) -> u8 {
        match self {
            KekProtection::Memory => 0,
            KekProtection::PlainFile => 1,
            KekProtection::Dpapi {
                scope: DpapiScope::Machine,
            }
            | KekProtection::SystemdCreds { tpm2: false } => 2,
            KekProtection::Dpapi {
                scope: DpapiScope::User,
            }
            | KekProtection::SystemdCreds { tpm2: true } => 3,
        }
    }

    /// A stable code for the API and the UI: `dpapi_user`, `dpapi_machine`,
    /// `systemd_creds_host`, `systemd_creds_tpm2`, `plain_file` or `memory`.
    pub fn code(self) -> &'static str {
        match self {
            KekProtection::Dpapi {
                scope: DpapiScope::User,
            } => "dpapi_user",
            KekProtection::Dpapi {
                scope: DpapiScope::Machine,
            } => "dpapi_machine",
            KekProtection::SystemdCreds { tpm2: false } => "systemd_creds_host",
            KekProtection::SystemdCreds { tpm2: true } => "systemd_creds_tpm2",
            KekProtection::PlainFile => "plain_file",
            KekProtection::Memory => "memory",
        }
    }

    /// A short English description for logs and the health view.
    pub fn describe(self) -> &'static str {
        match self {
            KekProtection::Dpapi {
                scope: DpapiScope::User,
            } => "DPAPI (user scope)",
            KekProtection::Dpapi {
                scope: DpapiScope::Machine,
            } => "DPAPI (machine scope)",
            KekProtection::SystemdCreds { tpm2: true } => "systemd-creds (TPM2 and host key)",
            KekProtection::SystemdCreds { tpm2: false } => "systemd-creds (host key)",
            KekProtection::PlainFile => "plain key file (no OS protection)",
            KekProtection::Memory => "memory only (tests)",
        }
    }
}

/// DPAPI scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpapiScope {
    /// Bound to the service account (default): another account on the host cannot unseal.
    #[default]
    User,
    /// Bound to the machine: any process on the host can unseal; rely on file ACLs.
    Machine,
}

/// Which `systemd-creds` key to seal with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredsKey {
    /// `--with-key=auto`: TPM2 and host key when a TPM2 is present, host key otherwise.
    #[default]
    Auto,
    /// `--with-key=tpm2`: TPM2 only; fails without one.
    Tpm2,
    /// `--with-key=host`: the host key only.
    Host,
}

/// A key-encryption key: wraps and unwraps data keys.
///
/// Implementations bind `aad` into the wrap so a wrapped key only unwraps for the row and
/// class it was made for. Future providers (PKCS#11, cloud KMS, IAM-17) implement the same
/// trait.
pub trait KekProvider: Send + Sync + fmt::Debug {
    /// Stable identifier, stored in every envelope as `key_id` (for example
    /// `dpapi-1-3f9a0c2e`, `file-8c1d44b0`).
    fn id(&self) -> &str;

    /// How the KEK is protected at rest.
    fn protection(&self) -> KekProtection;

    /// Wraps a data key.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] or a provider error.
    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// Unwraps a data key.
    ///
    /// # Errors
    ///
    /// [`VaultError::Integrity`] when the wrapped key or `aad` was altered, or a provider
    /// error.
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<DataKey, VaultError>;

    /// The key itself, for the one path that moves a KEK: the sealed transfer to another
    /// controller of the installation (ADR 0014, [`crate::transfer`]). `None` for a key
    /// that cannot leave its provider (a hardware module in a later phase); such a KEK
    /// cannot serve a cluster. The copy is zeroized on drop.
    fn export_material(&self) -> Option<Zeroizing<[u8; DataKey::LEN]>> {
        None
    }
}

/// Protects the bytes of a KEK generation file at rest (DPAPI, `systemd-creds`, wrap,
/// plain).
pub trait KekSealer: Send + Sync + fmt::Debug {
    /// Short name used in KEK identifiers and as the file extension: `dpapi`, `cred`,
    /// `wrap`, `plain`.
    fn name(&self) -> &'static str;

    /// The protection this sealer gives.
    fn protection(&self) -> KekProtection;

    /// Seals `plaintext`. `label` is the file stem (`kek-000001`), bound into the seal
    /// where the mechanism supports it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Provider`] if the platform refuses.
    fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// Unseals what [`seal`](KekSealer::seal) produced.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] if the platform cannot unseal it on this host or
    /// account.
    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}

/// A generation file that a load refused (R15): a plain generation newer than the newest
/// sealed generation of its directory, while [`KekOptions::allow_plain`] is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedKek {
    /// The generation number of the file.
    pub generation: u32,
    /// The file.
    pub path: PathBuf,
    /// The protection of the file.
    pub protection: KekProtection,
    /// The protection of the newest sealed generation beside it.
    pub sealed: KekProtection,
}

/// The loaded KEKs, oldest first: one active (new wraps) and any number of others (unwrap
/// only, until every envelope is re-wrapped; a generation received during an online
/// rotation waits here until the rotation activates it).
#[derive(Debug, Clone)]
pub struct KekRing {
    entries: Vec<Arc<dyn KekProvider>>,
    active: Arc<dyn KekProvider>,
    refused: Vec<RefusedKek>,
}

impl KekRing {
    /// A ring with one active KEK.
    pub fn new(active: Arc<dyn KekProvider>) -> Self {
        Self {
            entries: vec![Arc::clone(&active)],
            active,
            refused: Vec::new(),
        }
    }

    /// A ring of generations, oldest first; the last one is active. A KEK whose identifier
    /// is already in the list is dropped.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] for an empty list.
    pub fn from_generations(
        generations: impl IntoIterator<Item = Arc<dyn KekProvider>>,
    ) -> Result<Self, VaultError> {
        let mut entries: Vec<Arc<dyn KekProvider>> = Vec::new();
        for kek in generations {
            if !entries.iter().any(|known| known.id() == kek.id()) {
                entries.push(kek);
            }
        }
        let active = entries
            .last()
            .cloned()
            .ok_or_else(|| VaultError::kek_unavailable("no key-encryption key"))?;
        Ok(Self {
            entries,
            active,
            refused: Vec::new(),
        })
    }

    /// Adds an older KEK (kept for unwrapping), just before the active one. A KEK with a
    /// loaded identifier is ignored.
    #[must_use]
    pub fn with_retired(mut self, kek: Arc<dyn KekProvider>) -> Self {
        if !self.contains(kek.id()) {
            let at = self.position(self.active.id()).unwrap_or(0);
            self.entries.insert(at, kek);
        }
        self
    }

    /// Adds a newer KEK that is not active yet (a generation received in the first phase
    /// of an online rotation). A KEK with a loaded identifier is ignored.
    #[must_use]
    pub fn with_newer(mut self, kek: Arc<dyn KekProvider>) -> Self {
        if !self.contains(kek.id()) {
            self.entries.push(kek);
        }
        self
    }

    /// The same ring with `kek` active and the previous active KEK retired.
    #[must_use]
    pub fn rotated_to(&self, kek: Arc<dyn KekProvider>) -> Self {
        let mut entries = self.entries.clone();
        match entries.iter().position(|known| known.id() == kek.id()) {
            Some(at) => entries[at] = Arc::clone(&kek),
            None => entries.push(Arc::clone(&kek)),
        }
        Self {
            entries,
            active: kek,
            refused: self.refused.clone(),
        }
    }

    /// The same ring with the loaded KEK `id` active.
    ///
    /// # Errors
    ///
    /// [`VaultError::UnknownKek`] when no loaded KEK has that identifier.
    pub fn activate(&self, id: &str) -> Result<Self, VaultError> {
        let kek = self
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError::UnknownKek {
                key_id: id.to_owned(),
            })?;
        Ok(Self {
            entries: self.entries.clone(),
            active: kek,
            refused: self.refused.clone(),
        })
    }

    /// The same ring carrying the generations a load refused.
    #[must_use]
    pub(crate) fn with_refused(mut self, refused: Vec<RefusedKek>) -> Self {
        self.refused.extend(refused);
        self
    }

    /// The KEK that wraps new data keys.
    pub fn active(&self) -> &Arc<dyn KekProvider> {
        &self.active
    }

    /// A loaded KEK by identifier.
    pub fn get(&self, id: &str) -> Option<&Arc<dyn KekProvider>> {
        self.entries.iter().find(|kek| kek.id() == id)
    }

    /// Whether a KEK with this identifier is loaded.
    pub fn contains(&self, id: &str) -> bool {
        self.get(id).is_some()
    }

    /// Every loaded KEK, oldest first.
    pub fn generations(&self) -> impl Iterator<Item = &Arc<dyn KekProvider>> {
        self.entries.iter()
    }

    /// Identifiers of every loaded KEK, active included, oldest first.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|kek| kek.id())
    }

    /// Identifiers of the loaded KEKs other than the active one, oldest first.
    pub fn retired_ids(&self) -> impl Iterator<Item = &str> {
        let active = self.active.id();
        self.ids().filter(move |id| *id != active)
    }

    /// The generations the load refused (R15); the vault raises an alarm for each.
    pub fn refused(&self) -> &[RefusedKek] {
        &self.refused
    }

    fn position(&self, id: &str) -> Option<usize> {
        self.entries.iter().position(|kek| kek.id() == id)
    }
}

/// What [`KekConfig::load`] does when no KEK exists yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekInit {
    /// Fail with [`VaultError::KekUnavailable`]: every start after the first.
    Require,
    /// Create the first KEK: first run only (empty data directory).
    CreateIfMissing,
}

/// The policy of loading, creating and importing generations: settings of `[kek]` that
/// are not part of the provider choice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KekOptions {
    /// `[kek] allow_plain`: load, create and import plain generations even beside a sealed
    /// one (R15). Off by default; every load that uses it logs a loud warning.
    pub allow_plain: bool,
    /// The generation directory of the `file` provider (`[kek] dir`, by default
    /// `<data_dir>/kek`): generations made by `tenko kek rotate`, an online rotation or a
    /// transfer, wrapped under the key file. Without it the `file` provider can neither
    /// rotate nor import.
    pub file_dir: Option<PathBuf>,
}

/// The default name of the systemd credential that holds the KEK.
pub const DEFAULT_CREDENTIAL: &str = "tenko_kek";

fn default_credential() -> String {
    DEFAULT_CREDENTIAL.to_owned()
}

/// Which KEK provider to use; part of the server configuration (WP1.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
#[non_exhaustive]
pub enum KekConfig {
    /// DPAPI-sealed generations in `dir` (Windows only).
    Dpapi {
        /// The KEK directory, normally `<data-dir>/kek`.
        dir: PathBuf,
        /// User (default) or machine scope.
        #[serde(default)]
        scope: DpapiScope,
    },
    /// `systemd-creds`-sealed generations in `dir` (Linux). When the command is missing or
    /// cannot seal for this account, new generations are plain files with mode 0600 and a
    /// loud warning at every start.
    SystemdCreds {
        /// The KEK directory, normally `<data-dir>/kek`.
        dir: PathBuf,
        /// Which key to seal with.
        #[serde(default)]
        with_key: CredsKey,
        /// The `systemd-creds` binary (default: found on `PATH`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<PathBuf>,
    },
    /// An explicit key file: 32 raw bytes, 64 hexadecimal digits or base64 (containers,
    /// CI). Warns loudly at every start. Generations made later live in
    /// [`KekOptions::file_dir`], wrapped under this key.
    File {
        /// The active key file.
        path: PathBuf,
        /// Earlier key files still needed to unwrap envelopes until rotation completes.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        retired: Vec<PathBuf>,
    },
    /// A systemd credential (Linux): the service manager decrypts the credential `name`
    /// from `LoadCredentialEncrypted=` with the host key or a TPM2 and hands it to the
    /// service in `$CREDENTIALS_DIRECTORY`, readable by the service account only. Further
    /// generations live in `dir`, wrapped under the credential.
    SystemdCredential {
        /// The credential name, as in `LoadCredentialEncrypted=<name>:…` (default
        /// `tenko_kek`).
        #[serde(default = "default_credential")]
        name: String,
        /// Earlier credentials still needed until a rotation completes.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        retired: Vec<String>,
        /// The generation directory, normally `<data-dir>/kek`.
        dir: PathBuf,
        /// The key the credential was encrypted with (`systemd-creds encrypt --with-key=`),
        /// as the operator declares it; Tenko cannot see it. The protection reads
        /// "TPM2" only for `tpm2`; `auto` and `host` read "host key".
        #[serde(default)]
        with_key: CredsKey,
        /// The credentials directory; default: `$CREDENTIALS_DIRECTORY` as the service
        /// manager sets it (a test seam).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        directory: Option<PathBuf>,
    },
}

impl KekConfig {
    /// The default provider of the platform for a data directory: DPAPI (user scope) on
    /// Windows, `systemd-creds` on Linux and other Unix systems, a key file elsewhere.
    pub fn platform_default(data_dir: &Path) -> Self {
        let dir = data_dir.join("kek");
        if cfg!(windows) {
            KekConfig::Dpapi {
                dir,
                scope: DpapiScope::User,
            }
        } else if cfg!(unix) {
            KekConfig::SystemdCreds {
                dir,
                with_key: CredsKey::Auto,
                tool: None,
            }
        } else {
            KekConfig::File {
                path: dir.join("kek.key"),
                retired: Vec::new(),
            }
        }
    }

    /// The provider name as `[kek] provider` spells it: `dpapi`, `systemd_creds`, `file`
    /// or `systemd_credential`.
    pub fn provider_name(&self) -> &'static str {
        match self {
            KekConfig::Dpapi { .. } => "dpapi",
            KekConfig::SystemdCreds { .. } => "systemd_creds",
            KekConfig::File { .. } => "file",
            KekConfig::SystemdCredential { .. } => "systemd_credential",
        }
    }

    /// A one-line English description for `tenko config check`.
    pub fn describe(&self) -> String {
        match self {
            KekConfig::Dpapi { dir, scope } => {
                let scope = match scope {
                    DpapiScope::User => "user",
                    DpapiScope::Machine => "machine",
                };
                format!("DPAPI ({scope} scope) in {}", dir.display())
            }
            KekConfig::SystemdCreds { dir, .. } => {
                format!("systemd-creds in {}", dir.display())
            }
            KekConfig::File { path, retired } => format!(
                "key file {} (no OS protection){}",
                path.display(),
                if retired.is_empty() {
                    String::new()
                } else {
                    format!(", {} retired", retired.len())
                }
            ),
            KekConfig::SystemdCredential { name, dir, .. } => format!(
                "systemd credential {name}, generations in {}",
                dir.display()
            ),
        }
    }

    /// Loads the KEKs with the default [`KekOptions`] (plain generations beside sealed ones
    /// refused, no generation directory for the `file` provider).
    ///
    /// # Errors
    ///
    /// As [`load_with`](KekConfig::load_with).
    pub fn load(&self, init: KekInit) -> Result<KekRing, VaultError> {
        self.load_with(init, &KekOptions::default())
    }

    /// Loads the KEKs. The highest generation is active; [`KekRing::refused`] lists plain
    /// generations that were not loaded (R15).
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] when no KEK exists (with [`KekInit::Require`]) or a
    /// KEK cannot be read or unsealed, [`VaultError::Unsupported`] for a provider this
    /// platform lacks.
    pub fn load_with(&self, init: KekInit, options: &KekOptions) -> Result<KekRing, VaultError> {
        match self {
            KekConfig::File { path, retired } => file::rooted(path, retired, init, options)?.load(),
            #[cfg(unix)]
            KekConfig::SystemdCredential {
                name,
                retired,
                dir,
                with_key,
                directory,
            } => credential::rooted(name, retired, dir, *with_key, directory.as_deref(), options)?
                .load(),
            #[cfg(not(unix))]
            KekConfig::SystemdCredential { .. } => Err(credential_unsupported()),
            _ => self.dir(options)?.load(init),
        }
    }

    /// Creates the next KEK generation for rotation and returns it; pass it to
    /// [`StoreVault::rotate_kek`](crate::StoreVault::rotate_kek).
    ///
    /// # Errors
    ///
    /// As [`create_next_with`](KekConfig::create_next_with).
    pub fn create_next(&self) -> Result<Arc<dyn KekProvider>, VaultError> {
        self.create_next_with(&KekOptions::default())
    }

    /// Creates the next KEK generation for rotation and returns it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unsupported`] for the `file` provider without
    /// [`KekOptions::file_dir`], [`VaultError::PlainRefused`] when the generation would be
    /// plain beside a sealed one, or a provider error.
    pub fn create_next_with(
        &self,
        options: &KekOptions,
    ) -> Result<Arc<dyn KekProvider>, VaultError> {
        match self {
            KekConfig::File { .. } if options.file_dir.is_none() => {
                Err(VaultError::Unsupported {
                    what: "rotating a file KEK without a generation directory; set kek.dir,                            or configure a new key file and list the old one under `retired`"
                        .to_owned(),
                })
            }
            KekConfig::File { path, retired } => {
                file::rooted(path, retired, KekInit::Require, options)?.create_next()
            }
            #[cfg(unix)]
            KekConfig::SystemdCredential {
                name,
                retired,
                dir,
                with_key,
                directory,
            } => credential::rooted(name, retired, dir, *with_key, directory.as_deref(), options)?
                .create_next(),
            #[cfg(not(unix))]
            KekConfig::SystemdCredential { .. } => Err(credential_unsupported()),
            _ => self.dir(options)?.create_next(),
        }
    }

    /// Seals generations received from another controller ([`crate::transfer`]) with this
    /// host's provider, keeping their identifiers, with the default [`KekOptions`].
    ///
    /// # Errors
    ///
    /// As [`import_with`](KekConfig::import_with).
    pub fn import(&self, generations: &[TransferredKek]) -> Result<KekRing, VaultError> {
        self.import_with(generations, &KekOptions::default())
    }

    /// Seals generations received from another controller ([`crate::transfer`]) with this
    /// host's provider and returns the loaded ring with the last of `generations` active
    /// (the sender's active KEK). Generations this host holds already are skipped; the
    /// others are written in the order given (oldest first), each as the next generation
    /// of the directory. Safe to run again with the same input.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transfer`] with [`TransferFailure::Conflict`] when a different key is
    /// held under one of the identifiers, or [`TransferFailure::Malformed`] for an empty
    /// list or an invalid identifier; [`VaultError::PlainRefused`] when the local sealing
    /// would be plain beside a sealed generation; [`VaultError::Unsupported`] for the
    /// `file` provider without [`KekOptions::file_dir`]; or a provider error.
    ///
    /// [`TransferFailure::Conflict`]: crate::TransferFailure::Conflict
    /// [`TransferFailure::Malformed`]: crate::TransferFailure::Malformed
    pub fn import_with(
        &self,
        generations: &[TransferredKek],
        options: &KekOptions,
    ) -> Result<KekRing, VaultError> {
        let last = generations
            .last()
            .ok_or_else(|| VaultError::transfer(crate::TransferFailure::Malformed))?;
        if generations.iter().any(|kek| !valid_kek_id(&kek.id)) {
            return Err(VaultError::transfer(crate::TransferFailure::Malformed));
        }
        let ring = match self {
            KekConfig::File { path, retired } => {
                let rooted = file::rooted(path, retired, KekInit::Require, options)?;
                rooted.import(generations)?;
                rooted.load()?
            }
            #[cfg(unix)]
            KekConfig::SystemdCredential {
                name,
                retired,
                dir,
                with_key,
                directory,
            } => {
                let rooted = credential::rooted(
                    name,
                    retired,
                    dir,
                    *with_key,
                    directory.as_deref(),
                    options,
                )?;
                rooted.import(generations)?;
                rooted.load()?
            }
            #[cfg(not(unix))]
            KekConfig::SystemdCredential { .. } => return Err(credential_unsupported()),
            _ => {
                let dir = self.dir(options)?;
                dir.import(generations)?;
                dir.load(KekInit::Require)?
            }
        };
        ring.activate(&last.id)
    }

    /// Deletes the generation file of a retired KEK after rotation completed.
    ///
    /// # Errors
    ///
    /// As [`remove_retired_with`](KekConfig::remove_retired_with).
    pub fn remove_retired(&self, id: &str) -> Result<(), VaultError> {
        self.remove_retired_with(id, &KekOptions::default())
    }

    /// Deletes the generation file of a retired KEK after rotation completed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unsupported`] for a root key of the `file` or systemd credential
    /// provider (remove it from the configuration instead) and for the highest generation,
    /// [`VaultError::UnknownKek`] when no generation holds `id`, or an I/O error.
    pub fn remove_retired_with(&self, id: &str, options: &KekOptions) -> Result<(), VaultError> {
        match self {
            KekConfig::File { path, retired } => {
                file::rooted(path, retired, KekInit::Require, options)?.remove(id)
            }
            #[cfg(unix)]
            KekConfig::SystemdCredential {
                name,
                retired,
                dir,
                with_key,
                directory,
            } => credential::rooted(name, retired, dir, *with_key, directory.as_deref(), options)?
                .remove(id),
            #[cfg(not(unix))]
            KekConfig::SystemdCredential { .. } => Err(credential_unsupported()),
            _ => self.dir(options)?.remove(id),
        }
    }

    /// The generation directory of a directory-based provider.
    fn dir(&self, options: &KekOptions) -> Result<KekDir, VaultError> {
        let dir = match self {
            #[cfg(windows)]
            KekConfig::Dpapi { dir, scope } => KekDir::new(dir, Arc::new(DpapiSealer::new(*scope))),
            #[cfg(not(windows))]
            KekConfig::Dpapi { .. } => {
                return Err(VaultError::Unsupported {
                    what: "the DPAPI KEK provider outside Windows".to_owned(),
                });
            }
            #[cfg(unix)]
            KekConfig::SystemdCreds {
                dir,
                with_key,
                tool,
            } => systemd::kek_dir(dir, *with_key, tool.as_deref()),
            #[cfg(not(unix))]
            KekConfig::SystemdCreds { .. } => {
                return Err(VaultError::Unsupported {
                    what: "the systemd-creds KEK provider outside Linux".to_owned(),
                });
            }
            KekConfig::File { .. } | KekConfig::SystemdCredential { .. } => {
                return Err(VaultError::Unsupported {
                    what: "a sealed generation directory for a root-key provider".to_owned(),
                });
            }
        };
        Ok(dir.allowing_plain(options.allow_plain))
    }
}

#[cfg(not(unix))]
fn credential_unsupported() -> VaultError {
    VaultError::Unsupported {
        what: "the systemd credential KEK provider outside Linux".to_owned(),
    }
}

/// A root key held outside the data directory (a key file or a systemd credential), its
/// retired predecessors, and the generations wrapped under them in a directory.
pub(crate) struct Rooted {
    /// Retired roots, oldest first, then the active root.
    roots: Vec<Arc<dyn KekProvider>>,
    /// The generation directory, sealed by a [`WrapSealer`] over the roots.
    dir: Option<KekDir>,
}

impl Rooted {
    pub(crate) fn new(
        roots: Vec<Arc<dyn KekProvider>>,
        dir: Option<&Path>,
        protection: KekProtection,
        options: &KekOptions,
    ) -> Result<Self, VaultError> {
        let dir = match dir {
            Some(dir) => {
                let sealer = WrapSealer::from_roots(protection, roots.iter().rev())?;
                Some(KekDir::new(dir, Arc::new(sealer)).allowing_plain(options.allow_plain))
            }
            None => None,
        };
        Ok(Self { roots, dir })
    }

    fn require_dir(&self, action: &str) -> Result<&KekDir, VaultError> {
        self.dir.as_ref().ok_or_else(|| VaultError::Unsupported {
            what: format!("{action} without a generation directory (set kek.dir)"),
        })
    }

    pub(crate) fn load(&self) -> Result<KekRing, VaultError> {
        let base = KekRing::from_generations(self.roots.iter().cloned())?;
        let Some(dir) = &self.dir else {
            return Ok(base);
        };
        if dir.is_empty()? {
            return Ok(base);
        }
        let generations = dir.load(KekInit::Require)?;
        let refused = generations.refused().to_vec();
        let mut ring = base;
        for kek in generations.generations() {
            ring = ring.with_newer(Arc::clone(kek));
        }
        Ok(ring
            .activate(generations.active().id())?
            .with_refused(refused))
    }

    pub(crate) fn create_next(&self) -> Result<Arc<dyn KekProvider>, VaultError> {
        self.require_dir("rotating a root-key KEK")?.create_next()
    }

    pub(crate) fn import(&self, generations: &[TransferredKek]) -> Result<(), VaultError> {
        let mut fresh = Vec::new();
        for kek in generations {
            match self.roots.iter().find(|root| root.id() == kek.id) {
                Some(root) if same_material(root.as_ref(), kek) => {}
                Some(_) => {
                    return Err(VaultError::transfer(crate::TransferFailure::Conflict {
                        id: kek.id.clone(),
                    }));
                }
                None => fresh.push(kek.clone()),
            }
        }
        if fresh.is_empty() {
            return Ok(());
        }
        self.require_dir("importing a key generation")?
            .import(&fresh)
            .map(drop)
    }

    pub(crate) fn remove(&self, id: &str) -> Result<(), VaultError> {
        if self.roots.iter().any(|root| root.id() == id) {
            return Err(VaultError::Unsupported {
                what: "removing a root key; delete it from the configuration".to_owned(),
            });
        }
        self.require_dir("removing a key generation")?.remove(id)
    }
}

/// Whether a provider holds exactly the key of a transferred generation.
pub(crate) fn same_material(kek: &dyn KekProvider, transferred: &TransferredKek) -> bool {
    kek.export_material().is_some_and(|material| {
        aws_lc_rs::constant_time::verify_slices_are_equal(
            material.as_ref(),
            transferred.material.as_ref(),
        )
        .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_keys_are_random_and_redacted() {
        let a = DataKey::generate().expect("key");
        let b = DataKey::generate().expect("key");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(format!("{a:?}"), "DataKey(<redacted>)");
    }

    #[test]
    fn ring_tracks_active_and_retired() {
        let first: Arc<dyn KekProvider> = Arc::new(MemKek::generate("mem-1"));
        let second: Arc<dyn KekProvider> = Arc::new(MemKek::generate("mem-2"));
        let ring = KekRing::new(Arc::clone(&first));
        assert_eq!(ring.active().id(), "mem-1");
        assert_eq!(ring.retired_ids().count(), 0);
        let rotated = ring.rotated_to(second);
        assert_eq!(rotated.active().id(), "mem-2");
        assert_eq!(rotated.retired_ids().collect::<Vec<_>>(), ["mem-1"]);
        assert!(rotated.get("mem-1").is_some());
        assert!(rotated.get("mem-3").is_none());
    }

    #[test]
    fn ring_keeps_age_order_and_activates_by_id() {
        let kek = |id: &str| -> Arc<dyn KekProvider> { Arc::new(MemKek::generate(id)) };
        let ring = KekRing::new(kek("mem-3"))
            .with_retired(kek("mem-1"))
            .with_retired(kek("mem-2"))
            .with_newer(kek("mem-4"))
            .with_retired(kek("mem-2"));
        assert_eq!(
            ring.ids().collect::<Vec<_>>(),
            ["mem-1", "mem-2", "mem-3", "mem-4"]
        );
        assert_eq!(ring.active().id(), "mem-3");
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            ["mem-1", "mem-2", "mem-4"]
        );
        let switched = ring.activate("mem-4").expect("loaded");
        assert_eq!(switched.active().id(), "mem-4");
        assert_eq!(switched.ids().count(), 4);
        assert!(matches!(
            ring.activate("mem-9"),
            Err(VaultError::UnknownKek { .. })
        ));
        let built = KekRing::from_generations([kek("a"), kek("b"), kek("a")]).expect("ring");
        assert_eq!(built.ids().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(built.active().id(), "b");
        assert!(KekRing::from_generations(Vec::new()).is_err());
    }

    #[test]
    fn config_serializes_with_a_provider_tag() {
        let config = KekConfig::File {
            path: PathBuf::from("/run/secrets/kek"),
            retired: Vec::new(),
        };
        let json = serde_json::to_value(&config).expect("json");
        assert_eq!(json["provider"], "file");
        let dpapi: KekConfig =
            serde_json::from_value(serde_json::json!({"provider": "dpapi", "dir": "C:/kek"}))
                .expect("json");
        assert_eq!(
            dpapi,
            KekConfig::Dpapi {
                dir: PathBuf::from("C:/kek"),
                scope: DpapiScope::User
            }
        );
        let credential: KekConfig = serde_json::from_value(serde_json::json!({
            "provider": "systemd_credential",
            "dir": "/var/lib/tenko/kek"
        }))
        .expect("json");
        assert_eq!(credential.provider_name(), "systemd_credential");
        assert!(credential.describe().contains("tenko_kek"));
    }

    #[test]
    fn weak_protection_is_flagged_and_ranked() {
        assert!(KekProtection::PlainFile.is_weak());
        assert!(KekProtection::Memory.is_weak());
        assert!(!KekProtection::SystemdCreds { tpm2: false }.is_weak());
        assert!(
            !KekProtection::Dpapi {
                scope: DpapiScope::Machine
            }
            .is_weak()
        );
        let user = KekProtection::Dpapi {
            scope: DpapiScope::User,
        };
        assert!(KekProtection::PlainFile.rank() < user.rank());
        assert!(KekProtection::SystemdCreds { tpm2: false }.rank() < user.rank());
        assert_eq!(
            KekProtection::SystemdCreds { tpm2: true }.rank(),
            user.rank()
        );
        assert_eq!(user.code(), "dpapi_user");
        assert_eq!(KekProtection::PlainFile.code(), "plain_file");
    }

    #[test]
    fn kek_ids_are_checked() {
        assert!(valid_kek_id("dpapi-1-3f9a0c2e"));
        assert!(valid_kek_id("file-8c1d44b0"));
        assert!(!valid_kek_id(""));
        assert!(!valid_kek_id("a/b"));
        assert!(!valid_kek_id("é"));
        assert!(!valid_kek_id(&"x".repeat(MAX_KEK_ID_LEN + 1)));
    }
}
