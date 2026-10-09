//! Key-encryption keys (KEKs) and their providers.
//!
//! A [`KekProvider`] wraps and unwraps data keys. The built-in providers keep one 256-bit
//! KEK in memory, loaded at start from a file that the platform key store protects at
//! rest, and wrap with AES-256-GCM:
//!
//! | Provider | Platform | At rest | Config |
//! |---|---|---|---|
//! | DPAPI | Windows | `CryptProtectData`, user or machine scope | [`KekConfig::Dpapi`] |
//! | `systemd-creds` | Linux | sealed with the host key and TPM2 when present; plain file with a warning when the command is unusable | [`KekConfig::SystemdCreds`] |
//! | File | any (containers, CI) | an explicit key file, loud warning at every start | [`KekConfig::File`] |
//! | Memory | tests | nothing | `MemKek` (feature `testing`) |
//!
//! The DPAPI and `systemd-creds` providers keep numbered generations in a directory
//! (`kek-000001.dpapi`, `kek-000002.dpapi`, …); the highest generation is active and the
//! others stay loaded until every envelope is re-wrapped
//! ([`StoreVault::rotate_kek`](crate::StoreVault::rotate_kek)) and the operator retires
//! them ([`KekConfig::remove_retired`]).
//!
//! Start fails without a usable KEK: [`KekConfig::load`] with [`KekInit::Require`]
//! returns [`VaultError::KekUnavailable`] when no generation exists or one cannot be
//! unsealed, and [`StoreVault::open`](crate::StoreVault::open) refuses a ring that cannot
//! open the envelopes in the store.

mod dir;
mod file;
mod local;

#[cfg(windows)]
mod dpapi;
#[cfg(unix)]
mod systemd;

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub use dir::{KekDir, PlainSealer};
#[cfg(windows)]
pub use dpapi::DpapiSealer;
pub use file::FileKek;
pub use local::LocalKek;
#[cfg(any(test, feature = "testing"))]
pub use local::MemKek;
#[cfg(unix)]
pub use systemd::SystemdCredsSealer;

use crate::VaultError;

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
    /// `systemd-creds encrypt`.
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
}

/// Protects the bytes of a KEK generation file at rest (DPAPI, `systemd-creds`, plain).
pub trait KekSealer: Send + Sync + fmt::Debug {
    /// Short name used in KEK identifiers and as the file extension: `dpapi`, `cred`,
    /// `plain`.
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

/// The loaded KEKs: one active (new wraps) and any number of retired ones (unwrap only,
/// until every envelope is re-wrapped).
#[derive(Debug, Clone)]
pub struct KekRing {
    active: Arc<dyn KekProvider>,
    all: BTreeMap<String, Arc<dyn KekProvider>>,
}

impl KekRing {
    /// A ring with one active KEK.
    pub fn new(active: Arc<dyn KekProvider>) -> Self {
        let all = BTreeMap::from([(active.id().to_owned(), Arc::clone(&active))]);
        Self { active, all }
    }

    /// Adds a retired KEK (kept for unwrapping). A KEK with the active id is ignored.
    #[must_use]
    pub fn with_retired(mut self, kek: Arc<dyn KekProvider>) -> Self {
        self.all.entry(kek.id().to_owned()).or_insert(kek);
        self
    }

    /// The same ring with `kek` active and the previous active KEK retired.
    #[must_use]
    pub fn rotated_to(&self, kek: Arc<dyn KekProvider>) -> Self {
        let mut all = self.all.clone();
        all.insert(kek.id().to_owned(), Arc::clone(&kek));
        Self { active: kek, all }
    }

    /// The KEK that wraps new data keys.
    pub fn active(&self) -> &Arc<dyn KekProvider> {
        &self.active
    }

    /// A loaded KEK by identifier.
    pub fn get(&self, id: &str) -> Option<&Arc<dyn KekProvider>> {
        self.all.get(id)
    }

    /// Identifiers of every loaded KEK, active included.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.all.keys().map(String::as_str)
    }

    /// Identifiers of the retired KEKs.
    pub fn retired_ids(&self) -> impl Iterator<Item = &str> {
        let active = self.active.id();
        self.ids().filter(move |id| *id != active)
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
    /// CI). Warns loudly at every start.
    File {
        /// The active key file.
        path: PathBuf,
        /// Earlier key files still needed to unwrap envelopes until rotation completes.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        retired: Vec<PathBuf>,
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

    /// Loads the KEKs.
    ///
    /// # Errors
    ///
    /// [`VaultError::KekUnavailable`] when no KEK exists (with [`KekInit::Require`]) or a
    /// KEK cannot be read or unsealed, [`VaultError::Unsupported`] for a provider this
    /// platform lacks.
    pub fn load(&self, init: KekInit) -> Result<KekRing, VaultError> {
        match self {
            KekConfig::File { path, retired } => {
                let active = match init {
                    KekInit::Require => FileKek::open(path)?,
                    KekInit::CreateIfMissing => FileKek::open_or_create(path)?,
                };
                let mut ring = KekRing::new(Arc::new(active));
                for path in retired {
                    ring = ring.with_retired(Arc::new(FileKek::open(path)?));
                }
                Ok(ring)
            }
            _ => self.dir()?.load(init),
        }
    }

    /// Creates the next KEK generation for rotation and returns it; pass it to
    /// [`StoreVault::rotate_kek`](crate::StoreVault::rotate_kek).
    ///
    /// # Errors
    ///
    /// [`VaultError::Unsupported`] for [`KekConfig::File`] (supply a new key file and list
    /// the old one under `retired`), or a provider error.
    pub fn create_next(&self) -> Result<Arc<dyn KekProvider>, VaultError> {
        match self {
            KekConfig::File { .. } => Err(VaultError::Unsupported {
                what: "rotating a file KEK in place; configure a new key file and list the old \
                       one under `retired`"
                    .to_owned(),
            }),
            _ => self.dir()?.create_next(),
        }
    }

    /// Deletes the generation file of a retired KEK after rotation completed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unsupported`] for [`KekConfig::File`] (remove it from `retired`), a
    /// refusal to remove the active generation, or an I/O error.
    pub fn remove_retired(&self, id: &str) -> Result<(), VaultError> {
        match self {
            KekConfig::File { .. } => Err(VaultError::Unsupported {
                what: "removing a file KEK; delete it from `retired` in the configuration"
                    .to_owned(),
            }),
            _ => self.dir()?.remove(id),
        }
    }

    /// The generation directory of a directory-based provider.
    fn dir(&self) -> Result<KekDir, VaultError> {
        match self {
            #[cfg(windows)]
            KekConfig::Dpapi { dir, scope } => {
                Ok(KekDir::new(dir, Arc::new(DpapiSealer::new(*scope))))
            }
            #[cfg(not(windows))]
            KekConfig::Dpapi { .. } => Err(VaultError::Unsupported {
                what: "the DPAPI KEK provider outside Windows".to_owned(),
            }),
            #[cfg(unix)]
            KekConfig::SystemdCreds {
                dir,
                with_key,
                tool,
            } => Ok(systemd::kek_dir(dir, *with_key, tool.as_deref())),
            #[cfg(not(unix))]
            KekConfig::SystemdCreds { .. } => Err(VaultError::Unsupported {
                what: "the systemd-creds KEK provider outside Linux".to_owned(),
            }),
            KekConfig::File { .. } => Err(VaultError::Unsupported {
                what: "generation directories for a file KEK".to_owned(),
            }),
        }
    }
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
    }

    #[test]
    fn weak_protection_is_flagged() {
        assert!(KekProtection::PlainFile.is_weak());
        assert!(KekProtection::Memory.is_weak());
        assert!(!KekProtection::SystemdCreds { tpm2: false }.is_weak());
        assert!(
            !KekProtection::Dpapi {
                scope: DpapiScope::Machine
            }
            .is_weak()
        );
    }
}
