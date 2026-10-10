//! Vault errors and their stable codes.

use std::collections::BTreeMap;

use tenko_core::{Coded, SecretId};
use tenko_store::StoreError;

/// Vault errors. Messages and parameters never contain secret values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// No usable key-encryption key: missing, unreadable, or not unsealable on this host.
    /// The server refuses to start.
    #[error("no usable key-encryption key: {reason}")]
    KekUnavailable {
        /// What went wrong, without key material.
        reason: String,
    },
    /// An envelope names a KEK that is not loaded.
    #[error("key-encryption key {key_id} is not loaded")]
    UnknownKek {
        /// The KEK identifier from the envelope.
        key_id: String,
    },
    /// The secret does not exist.
    #[error("secret {secret} not found")]
    NotFound {
        /// The secret.
        secret: SecretId,
    },
    /// A system secret cannot be revealed (Q3).
    #[error("secret {secret} is a system secret and cannot be revealed")]
    NotRevealable {
        /// The secret.
        secret: SecretId,
    },
    /// An envelope failed authentication: tampered with, moved to another row, or
    /// wrapped by a different key with the same identifier.
    #[error("envelope failed authentication")]
    Integrity,
    /// The envelope format is newer than this build understands.
    #[error("unsupported envelope format {format}")]
    UnsupportedFormat {
        /// The format number.
        format: u16,
    },
    /// The envelope or a KEK file is structurally invalid.
    #[error("malformed {what}")]
    Malformed {
        /// What was malformed.
        what: &'static str,
    },
    /// The value exceeds [`MAX_SECRET_LEN`](crate::MAX_SECRET_LEN).
    #[error("secret of {size} bytes exceeds the limit of {limit} bytes")]
    TooLarge {
        /// The value size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// A cryptographic primitive or the random number generator failed.
    #[error("cryptographic failure in {operation}")]
    Crypto {
        /// The failed operation.
        operation: &'static str,
    },
    /// A KEK provider (DPAPI, `systemd-creds`, file) failed.
    #[error("KEK provider {provider} failed: {reason}")]
    Provider {
        /// The provider.
        provider: &'static str,
        /// What went wrong, without key material.
        reason: String,
    },
    /// A KEK rotation is already running on this vault.
    #[error("a key-encryption key rotation is already running")]
    RotationInProgress,
    /// The operation is not supported by this provider or build.
    #[error("not supported: {what}")]
    Unsupported {
        /// What is not supported.
        what: String,
    },
    /// A plain KEK generation would be created or imported beside a sealed one (R15), and
    /// `[kek] allow_plain` is off.
    #[error("a plain key generation was refused: {reason}")]
    PlainRefused {
        /// Why, without key material.
        reason: String,
    },
    /// A sealed KEK transfer between controllers failed (ADR 0014).
    #[error("key transfer failed: {failure}")]
    Transfer {
        /// What failed.
        failure: TransferFailure,
    },
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Why a KEK transfer between controllers failed. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransferFailure {
    /// Another format name or version than this build reads.
    #[error("unsupported format")]
    Format,
    /// The frame or the payload does not parse.
    #[error("malformed transfer")]
    Malformed,
    /// Sealed to another key, under another context, or altered.
    #[error("the transfer does not open with this key and context")]
    Integrity,
    /// The recipient's key is not a usable X25519 public key.
    #[error("unusable recipient key")]
    PublicKey,
    /// A generation cannot leave its provider.
    #[error("a key generation cannot be exported")]
    NotExportable,
    /// This host holds a different key under a transferred identifier.
    #[error("a different key is held under {id}")]
    Conflict {
        /// The identifier.
        id: String,
    },
}

impl TransferFailure {
    /// The stable code (`vault.kek.transfer.*`).
    pub fn code(&self) -> &'static str {
        match self {
            TransferFailure::Format => "vault.kek.transfer.format",
            TransferFailure::Malformed => "vault.kek.transfer.malformed",
            TransferFailure::Integrity => "vault.kek.transfer.integrity",
            TransferFailure::PublicKey => "vault.kek.transfer.public_key",
            TransferFailure::NotExportable => "vault.kek.transfer.not_exportable",
            TransferFailure::Conflict { .. } => "vault.kek.transfer.conflict",
        }
    }
}

impl VaultError {
    pub(crate) fn transfer(failure: TransferFailure) -> Self {
        VaultError::Transfer { failure }
    }

    pub(crate) fn kek_unavailable(reason: impl Into<String>) -> Self {
        VaultError::KekUnavailable {
            reason: reason.into(),
        }
    }

    pub(crate) fn provider(provider: &'static str, reason: impl Into<String>) -> Self {
        VaultError::Provider {
            provider,
            reason: reason.into(),
        }
    }
}

impl From<tenko_core::codec::CodecError> for VaultError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        VaultError::Store(StoreError::from(error))
    }
}

impl Coded for VaultError {
    fn code(&self) -> &'static str {
        match self {
            VaultError::KekUnavailable { .. } => "vault.kek.unavailable",
            VaultError::UnknownKek { .. } => "vault.kek.unknown",
            VaultError::NotFound { .. } => "vault.secret.not_found",
            VaultError::NotRevealable { .. } => "vault.secret.not_revealable",
            VaultError::Integrity => "vault.envelope.integrity",
            VaultError::UnsupportedFormat { .. } => "vault.envelope.unsupported_format",
            VaultError::Malformed { .. } => "vault.envelope.malformed",
            VaultError::TooLarge { .. } => "vault.secret.too_large",
            VaultError::Crypto { .. } => "vault.crypto",
            VaultError::Provider { .. } => "vault.kek.provider",
            VaultError::RotationInProgress => "vault.kek.rotation_in_progress",
            VaultError::Unsupported { .. } => "vault.unsupported",
            VaultError::PlainRefused { .. } => "vault.kek.plain_refused",
            VaultError::Transfer { failure } => failure.code(),
            VaultError::Store(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            VaultError::NotFound { .. } => 404,
            VaultError::NotRevealable { .. } => 403,
            VaultError::TooLarge { .. } => 413,
            VaultError::RotationInProgress | VaultError::PlainRefused { .. } => 409,
            VaultError::Transfer { failure } => match failure {
                TransferFailure::Conflict { .. } => 409,
                TransferFailure::NotExportable => 501,
                _ => 400,
            },
            VaultError::Unsupported { .. } => 501,
            VaultError::Store(error) => error.http_status(),
            _ => 500,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            VaultError::UnknownKek { key_id } => [("key_id", key_id.clone())].into(),
            VaultError::NotFound { secret } | VaultError::NotRevealable { secret } => {
                [("secret", secret.to_string())].into()
            }
            VaultError::UnsupportedFormat { format } => [("format", format.to_string())].into(),
            VaultError::TooLarge { size, limit } => {
                [("size", size.to_string()), ("limit", limit.to_string())].into()
            }
            VaultError::Provider { provider, .. } => [("provider", (*provider).to_owned())].into(),
            VaultError::Transfer {
                failure: TransferFailure::Conflict { id },
            } => [("key_id", id.clone())].into(),
            VaultError::Store(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_namespaced_and_statuses_sane() {
        let secret = SecretId::generate();
        assert_eq!(
            VaultError::NotFound { secret }.code(),
            "vault.secret.not_found"
        );
        assert_eq!(VaultError::NotFound { secret }.http_status(), 404);
        assert_eq!(VaultError::NotRevealable { secret }.http_status(), 403);
        assert_eq!(VaultError::Integrity.http_status(), 500);
        let conflict = VaultError::transfer(TransferFailure::Conflict {
            id: "dpapi-1-00".to_owned(),
        });
        assert_eq!(conflict.code(), "vault.kek.transfer.conflict");
        assert_eq!(conflict.http_status(), 409);
        assert_eq!(conflict.params()["key_id"], "dpapi-1-00");
        assert_eq!(
            VaultError::transfer(TransferFailure::Integrity).code(),
            "vault.kek.transfer.integrity"
        );
        let store = VaultError::from(StoreError::NoQuorum);
        assert_eq!(store.code(), "sys.store.no_quorum");
        assert_eq!(store.http_status(), 503);
    }
}
