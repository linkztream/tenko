//! The error of the configuration service: a stable code, an HTTP status and parameters,
//! from the model (`dhcp.*`), the store or the job engine.

use std::fmt;

use tenko_core::{Coded, CodedError, dhcp::DhcpError};

/// An error of the configuration service. The API answers it as problem details.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigError(Box<CodedError>);

/// The result of a configuration service call.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// The store's code of a failed precondition.
pub(crate) const PRECONDITION_FAILED: &str = "sys.store.precondition_failed";

impl ConfigError {
    /// An error with a code, a status and an English detail.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self(Box::new(CodedError::new(code, status, detail)))
    }

    /// Adds a parameter.
    #[must_use]
    pub fn param(self, key: &str, value: impl Into<String>) -> Self {
        Self(Box::new(self.0.with_param(key, value)))
    }

    /// Wraps a captured error.
    pub fn from_coded(error: CodedError) -> Self {
        Self(Box::new(error))
    }

    /// The captured error.
    pub fn coded(&self) -> &CodedError {
        &self.0
    }

    /// Whether the error has this code.
    pub fn is(&self, code: &str) -> bool {
        self.0.code == code
    }

    /// A 404 of `code` for the object `id`.
    pub(crate) fn not_found(code: &'static str, what: &str, id: impl fmt::Display) -> Self {
        Self::new(code, 404, format!("{what} {id} does not exist")).param("id", id.to_string())
    }

    /// An invalid field (`code` is the `*.invalid` code of the object), 400.
    pub(crate) fn invalid(code: &'static str, field: &str, reason: &str) -> Self {
        DhcpError::invalid(code, field, reason).into()
    }

    /// The precondition failure of a stale plan, which the service plans again; a 412 is
    /// the caller's stale `If-Match` and is answered.
    pub(crate) fn is_stale(&self) -> bool {
        self.0.code == PRECONDITION_FAILED && self.0.status != 412
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError({}: {})", self.0.code, self.0.detail)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.detail)
    }
}

impl std::error::Error for ConfigError {}

impl From<DhcpError> for ConfigError {
    fn from(error: DhcpError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_store::StoreError> for ConfigError {
    fn from(error: tenko_store::StoreError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_jobs::JobError> for ConfigError {
    fn from(error: tenko_jobs::JobError) -> Self {
        match error {
            tenko_jobs::JobError::Store(store) => store.into(),
            other => Self(Box::new(other.to_coded_error())),
        }
    }
}

impl From<tenko_core::codec::CodecError> for ConfigError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl Coded for ConfigError {
    fn code(&self) -> &'static str {
        match &self.0.code {
            std::borrow::Cow::Borrowed(code) => code,
            std::borrow::Cow::Owned(_) => tenko_core::error::codes::INTERNAL,
        }
    }
    fn http_status(&self) -> u16 {
        self.0.status
    }
    fn field_errors(&self) -> Vec<tenko_core::FieldError> {
        self.0.errors.clone()
    }
    fn to_coded_error(&self) -> CodedError {
        (*self.0).clone()
    }
}
