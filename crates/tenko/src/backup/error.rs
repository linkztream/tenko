//! The errors of backups and restores, each with a stable code (`backup.*`).

use std::{collections::BTreeMap, io, path::PathBuf};

use tenko_core::Coded;
use tenko_store::StoreError;
use tenko_vault::VaultError;

/// Why a backup, a check or a restore failed.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The file is not a Tenko backup (`backup.archive.not_a_backup`).
    #[error("not a Tenko backup: {0}")]
    NotABackup(String),
    /// A backup of another major format (`backup.archive.unsupported`).
    #[error("the backup has format {found}; this build reads {supported}")]
    Unsupported {
        /// What the file says.
        found: String,
        /// What this build reads.
        supported: &'static str,
    },
    /// A changed, truncated or extended file (`backup.archive.corrupt`).
    #[error("the backup is damaged: {0}")]
    Corrupt(String),
    /// No key slot opens with the passphrase or key given (`backup.key.refused`).
    #[error("the passphrase or key does not open this backup")]
    KeyRefused,
    /// Neither a passphrase nor a recipient to encrypt to (`backup.key.missing`).
    #[error("{0}")]
    NoKey(String),
    /// A passphrase below the minimum length (`backup.passphrase.weak`).
    #[error("a backup passphrase needs at least {min} characters")]
    PassphraseWeak {
        /// The minimum length in characters.
        min: usize,
    },
    /// A recipient or key file that does not parse (`backup.key.invalid`).
    #[error("{0}")]
    InvalidKey(String),
    /// Invalid backup settings (`backup.settings.invalid`).
    #[error("{0}")]
    InvalidSettings(String),
    /// A backup runs already on this controller (`backup.running`).
    #[error("a backup is running on this controller; try again when it has finished")]
    Running,
    /// The backup holds a data format newer than this build (`backup.format_newer`).
    #[error(
        "the backup holds data format {found}; this build supports up to {supported}; restore \
         it with a newer Tenko"
    )]
    FormatNewer {
        /// The format in the backup.
        found: u32,
        /// The newest format this build knows.
        supported: u32,
    },
    /// The restored state differs from the state the backup recorded (`backup.digest_mismatch`).
    #[error("the restored store does not match the backup: {0}")]
    DigestMismatch(String),
    /// A check of the restored state failed: audit chain, envelopes, CA (`backup.check_failed`).
    #[error("{what}: {detail}")]
    CheckFailed {
        /// What was checked.
        what: &'static str,
        /// What went wrong.
        detail: String,
    },
    /// The target data directory holds a store already (`backup.restore.target_not_empty`).
    #[error("{} holds a store already; restore into an empty data directory", .0.display())]
    TargetNotEmpty(PathBuf),
    /// A server runs on the data directory (`backup.in_use`).
    #[error("{} is in use by a running server; stop it first", .0.display())]
    InUse(PathBuf),
    /// A file could not be read or written (`backup.io`).
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The vault or a key provider failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// Anything else (`backup.internal`).
    #[error("{0}")]
    Internal(String),
}

impl BackupError {
    /// An I/O error naming `path`.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        // A stream error of the archive reader travels inside an `io::Error`.
        match source
            .get_ref()
            .map(<dyn std::error::Error + Send + Sync>::is::<BackupError>)
        {
            Some(true) => source
                .into_inner()
                .and_then(|inner| inner.downcast::<BackupError>().ok())
                .map_or_else(
                    || Self::Corrupt("unreadable stream".to_owned()),
                    |error| *error,
                ),
            _ => Self::Io {
                path: path.into(),
                source,
            },
        }
    }

    /// A failed check.
    pub fn check(what: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::CheckFailed {
            what,
            detail: detail.to_string(),
        }
    }

    /// Whether the cause is the passphrase or key (a person can try again).
    pub fn is_key_refused(&self) -> bool {
        matches!(self, Self::KeyRefused)
    }
}

impl Coded for BackupError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotABackup(_) => "backup.archive.not_a_backup",
            Self::Unsupported { .. } => "backup.archive.unsupported",
            Self::Corrupt(_) => "backup.archive.corrupt",
            Self::KeyRefused => "backup.key.refused",
            Self::NoKey(_) => "backup.key.missing",
            Self::PassphraseWeak { .. } => "backup.passphrase.weak",
            Self::InvalidKey(_) => "backup.key.invalid",
            Self::InvalidSettings(_) => "backup.settings.invalid",
            Self::Running => "backup.running",
            Self::FormatNewer { .. } => "backup.format_newer",
            Self::DigestMismatch(_) => "backup.digest_mismatch",
            Self::CheckFailed { .. } => "backup.check_failed",
            Self::TargetNotEmpty(_) => "backup.restore.target_not_empty",
            Self::InUse(_) => "backup.in_use",
            Self::Io { .. } => "backup.io",
            Self::Store(error) => error.code(),
            Self::Vault(error) => error.code(),
            Self::Internal(_) => "backup.internal",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::NotABackup(_)
            | Self::Unsupported { .. }
            | Self::Corrupt(_)
            | Self::KeyRefused
            | Self::NoKey(_)
            | Self::PassphraseWeak { .. }
            | Self::InvalidKey(_)
            | Self::InvalidSettings(_)
            | Self::FormatNewer { .. }
            | Self::DigestMismatch(_)
            | Self::CheckFailed { .. } => 422,
            Self::Running | Self::TargetNotEmpty(_) | Self::InUse(_) => 409,
            Self::Store(error) => error.http_status(),
            Self::Vault(error) => error.http_status(),
            Self::Io { .. } | Self::Internal(_) => 500,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::PassphraseWeak { min } => BTreeMap::from([("min", min.to_string())]),
            Self::FormatNewer { found, supported } => BTreeMap::from([
                ("found", found.to_string()),
                ("supported", supported.to_string()),
            ]),
            Self::CheckFailed { what, .. } => BTreeMap::from([("check", (*what).to_owned())]),
            Self::Store(error) => error.params(),
            Self::Vault(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }
}
