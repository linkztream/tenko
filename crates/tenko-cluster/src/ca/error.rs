//! Errors of the internal CA and the TLS material.

use std::collections::BTreeMap;

use tenko_core::Coded;
use tenko_store::StoreError;
use tenko_vault::VaultError;

/// Errors of the internal certificate authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// `init` found an existing CA.
    #[error("the internal CA already exists")]
    AlreadyInitialized,
    /// No CA has been created yet.
    #[error("the internal CA has not been created")]
    NotInitialized,
    /// A host name, address or node identifier cannot go into a certificate.
    #[error("invalid certificate name {name}: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Why.
        reason: String,
    },
    /// A certificate signing request was malformed or its signature did not verify.
    #[error("invalid certificate signing request: {reason}")]
    InvalidCsr {
        /// Why.
        reason: String,
    },
    /// Certificate generation or signing failed.
    #[error("certificate generation failed: {reason}")]
    Generation {
        /// Why.
        reason: String,
    },
    /// The stored CA record or key is inconsistent (the key does not match the root).
    #[error("the stored CA is corrupt: {reason}")]
    Corrupt {
        /// Why.
        reason: String,
    },
    /// The vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Loading TLS material failed.
    #[error(transparent)]
    Tls(#[from] TlsError),
}

impl From<tenko_core::codec::CodecError> for CaError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        CaError::Store(StoreError::from(error))
    }
}

impl From<rcgen::Error> for CaError {
    fn from(error: rcgen::Error) -> Self {
        CaError::Generation {
            reason: error.to_string(),
        }
    }
}

impl Coded for CaError {
    fn code(&self) -> &'static str {
        match self {
            CaError::AlreadyInitialized => "cluster.ca.already_initialized",
            CaError::NotInitialized => "cluster.ca.not_initialized",
            CaError::InvalidName { .. } => "cluster.ca.invalid_name",
            CaError::InvalidCsr { .. } => "cluster.ca.invalid_csr",
            CaError::Generation { .. } => "cluster.ca.generation",
            CaError::Corrupt { .. } => "cluster.ca.corrupt",
            CaError::Vault(error) => error.code(),
            CaError::Store(error) => error.code(),
            CaError::Tls(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            CaError::AlreadyInitialized => 409,
            CaError::NotInitialized => 404,
            CaError::InvalidName { .. } | CaError::InvalidCsr { .. } => 422,
            CaError::Vault(error) => error.http_status(),
            CaError::Store(error) => error.http_status(),
            CaError::Tls(error) => error.http_status(),
            CaError::Generation { .. } | CaError::Corrupt { .. } => 500,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            CaError::InvalidName { name, .. } => [("name", name.clone())].into(),
            CaError::Vault(error) => error.params(),
            CaError::Store(error) => error.params(),
            CaError::Tls(error) => error.params(),
            _ => BTreeMap::new(),
        }
    }
}

/// Errors of TLS material: reading, parsing and matching certificates and keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A file could not be read.
    #[error("cannot read {path}: {reason}")]
    Io {
        /// The file.
        path: String,
        /// Why.
        reason: String,
    },
    /// No certificate in the PEM input.
    #[error("no certificate found")]
    NoCertificate,
    /// No private key, or an unsupported key type, in the PEM input.
    #[error("no usable private key found: {reason}")]
    NoPrivateKey {
        /// Why.
        reason: String,
    },
    /// The private key does not belong to the leaf certificate.
    #[error("the private key does not match the certificate")]
    KeyMismatch,
    /// The certificate cannot be parsed.
    #[error("invalid certificate: {reason}")]
    InvalidCertificate {
        /// Why.
        reason: String,
    },
    /// rustls refused the configuration.
    #[error("TLS configuration failed: {reason}")]
    Config {
        /// Why.
        reason: String,
    },
    /// A trusted-proxy entry is neither an address nor a network.
    #[error("invalid trusted proxy {entry}")]
    InvalidProxy {
        /// The rejected entry.
        entry: String,
    },
    /// The mode has no certificate (TLS terminates in a reverse proxy).
    #[error("the TLS mode terminates TLS elsewhere; there is no local certificate")]
    NoLocalTls,
}

impl Coded for TlsError {
    fn code(&self) -> &'static str {
        match self {
            TlsError::Io { .. } => "cluster.tls.io",
            TlsError::NoCertificate => "cluster.tls.no_certificate",
            TlsError::NoPrivateKey { .. } => "cluster.tls.no_private_key",
            TlsError::KeyMismatch => "cluster.tls.key_mismatch",
            TlsError::InvalidCertificate { .. } => "cluster.tls.invalid_certificate",
            TlsError::Config { .. } => "cluster.tls.config",
            TlsError::InvalidProxy { .. } => "cluster.tls.invalid_proxy",
            TlsError::NoLocalTls => "cluster.tls.no_local_tls",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            TlsError::Io { .. } | TlsError::Config { .. } => 500,
            _ => 422,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            TlsError::Io { path, .. } => [("path", path.clone())].into(),
            TlsError::InvalidProxy { entry } => [("entry", entry.clone())].into(),
            _ => BTreeMap::new(),
        }
    }
}
