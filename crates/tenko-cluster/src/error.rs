//! The coded error of the node registry and the node transport.

use std::fmt;

use tenko_core::{Coded, CodedError};

/// An error with a stable code (`cluster.*` or the code of the component that failed), an
/// HTTP status for the API and an English detail without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterError(Box<CodedError>);

impl ClusterError {
    /// An error of this crate.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self(Box::new(CodedError::new(code, status, detail)))
    }

    /// Captures any coded error with its own code.
    pub fn coded(error: &(impl Coded + ?Sized)) -> Self {
        Self(Box::new(error.to_coded_error()))
    }

    /// `cluster.internal` (500): something that should not happen.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new("cluster.internal", 500, detail)
    }

    /// Adds a named parameter.
    #[must_use]
    pub fn with_param(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        Self(Box::new((*self.0).with_param(key, value)))
    }

    /// The stable code.
    pub fn code(&self) -> &str {
        &self.0.code
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        self.0.status
    }

    /// The English detail.
    pub fn detail(&self) -> &str {
        &self.0.detail
    }

    /// The error as problem details for the API.
    pub fn into_coded(self) -> CodedError {
        *self.0
    }

    /// The error as problem details, borrowed.
    pub fn as_coded(&self) -> &CodedError {
        &self.0
    }
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.detail)
    }
}

impl std::error::Error for ClusterError {}

macro_rules! from_coded {
    ($($error:ty),+ $(,)?) => {$(
        impl From<$error> for ClusterError {
            fn from(error: $error) -> Self {
                Self::coded(&error)
            }
        }
    )+};
}

from_coded!(
    tenko_store::StoreError,
    tenko_jobs::JobError,
    tenko_vault::VaultError,
    crate::ca::CaError,
    crate::ca::TlsError,
    crate::token::TokenError,
    crate::buffer::BufferError,
    crate::version::VersionMismatch,
);

impl From<tenko_core::codec::CodecError> for ClusterError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self::coded(&tenko_store::StoreError::from(error))
    }
}

impl From<CodedError> for ClusterError {
    fn from(error: CodedError) -> Self {
        Self(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_code_status_and_parameters() {
        let error =
            ClusterError::new("cluster.node.not_found", 404, "no node 7").with_param("node", "7");
        assert_eq!(error.code(), "cluster.node.not_found");
        assert_eq!(error.status(), 404);
        assert_eq!(error.to_string(), "no node 7");
        let coded = error.into_coded();
        assert_eq!(coded.params["node"], "7");
    }

    #[test]
    fn component_errors_keep_their_codes() {
        let error = ClusterError::from(crate::ca::CaError::NotInitialized);
        assert_eq!(error.code(), "cluster.ca.not_initialized");
        assert_eq!(error.status(), 404);
    }
}
