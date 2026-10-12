//! Errors of the audit export and their codes (`audit.export.*`).

use std::collections::BTreeMap;

use tenko_core::{Coded, FieldError};
use tenko_store::StoreError;

/// Code of the alarm and status warning of a sink that fails longer than its delay.
pub const FAILING: &str = "audit.export.failing";
/// Code of the status warning and of the refusal when TGL-21 requires an export and no
/// sink is enabled.
pub const REQUIRED: &str = "audit.export.required";

/// What a sink failed on, for the status and the test result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The host name did not resolve.
    Resolve,
    /// The connection was refused or timed out.
    Connect,
    /// The TLS handshake or the receiver's certificate failed.
    Tls,
    /// Writing to the connection failed.
    Send,
    /// The file could not be written or rotated.
    File,
    /// The TLS client key could not be read from the vault or does not parse.
    ClientKey,
    /// The sink's configuration cannot be used on this controller.
    Config,
}

impl FailureKind {
    /// The stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Resolve => "audit.export.resolve",
            Self::Connect => "audit.export.connect",
            Self::Tls => "audit.export.tls",
            Self::Send => "audit.export.send",
            Self::File => "audit.export.file",
            Self::ClientKey => "audit.export.client_key",
            Self::Config => "audit.export.config",
        }
    }
}

/// A failure of one sink: a kind and an English detail without secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct SinkError {
    /// What failed.
    pub kind: FailureKind,
    /// The detail.
    pub detail: String,
}

impl SinkError {
    /// A failure of `kind`.
    pub fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Errors of the settings and the test.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The settings are invalid.
    #[error("the audit export settings are invalid")]
    Invalid(Vec<FieldError>),
    /// TGL-21 requires an export (the Hardened profile) and the settings leave no sink
    /// enabled.
    #[error(
        "the security settings require an audit export (TGL-21): keep at least one sink enabled"
    )]
    Required,
    /// `If-Match` names another revision than the stored settings.
    #[error("the audit export settings changed since revision {expected}")]
    Conflict {
        /// The revision the client read.
        expected: u64,
        /// The current revision.
        current: u64,
    },
    /// No sink has this id.
    #[error("no audit export sink has the id {0}")]
    NotFound(uuid::Uuid),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Coded for ExportError {
    fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "audit.export.invalid",
            Self::Required => REQUIRED,
            Self::Conflict { .. } => "audit.export.conflict",
            Self::NotFound(_) => "audit.export.not_found",
            Self::Store(error) => error.code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Invalid(_) => 400,
            Self::Required | Self::Conflict { .. } => 409,
            Self::NotFound(_) => 404,
            Self::Store(error) => error.http_status(),
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::Conflict { expected, current } => BTreeMap::from([
                ("expected", expected.to_string()),
                ("current", current.to_string()),
            ]),
            Self::NotFound(id) => BTreeMap::from([("sink", id.to_string())]),
            Self::Store(error) => error.params(),
            Self::Invalid(_) | Self::Required => BTreeMap::new(),
        }
    }

    fn field_errors(&self) -> Vec<FieldError> {
        match self {
            Self::Invalid(problems) => problems.clone(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_coded() {
        let invalid = ExportError::Invalid(vec![FieldError::new("sinks", "audit.export.too_many")]);
        assert_eq!(invalid.code(), "audit.export.invalid");
        assert_eq!(invalid.http_status(), 400);
        assert_eq!(invalid.field_errors().len(), 1);
        assert_eq!(ExportError::Required.code(), REQUIRED);
        assert_eq!(ExportError::Required.http_status(), 409);
        let conflict = ExportError::Conflict {
            expected: 3,
            current: 5,
        };
        assert_eq!(conflict.params()["current"], "5");
        assert_eq!(ExportError::NotFound(uuid::Uuid::nil()).http_status(), 404);
        assert_eq!(FailureKind::Tls.code(), "audit.export.tls");
    }
}
