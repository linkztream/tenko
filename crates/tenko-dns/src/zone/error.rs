//! The error of the zone service: a stable code, an HTTP status and parameters, from the
//! model (`dns.*`), the store, the vault or the job engine.

use std::fmt;

use tenko_core::{
    Coded, CodedError,
    dns::{DnsError, codes},
};

/// An error of the zone service. The API answers it as problem details.
#[derive(Clone, PartialEq, Eq)]
pub struct ZoneError(Box<CodedError>);

/// The result of a zone service call.
pub type ZoneResult<T> = Result<T, ZoneError>;

impl ZoneError {
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

    /// The captured error, by value.
    pub fn into_coded(self) -> CodedError {
        *self.0
    }

    /// Whether the error has this code.
    pub fn is(&self, code: &str) -> bool {
        self.0.code == code
    }

    /// `dns.zone.not_found`.
    pub fn zone_not_found(id: impl fmt::Display) -> Self {
        Self::new(
            codes::ZONE_NOT_FOUND,
            404,
            format!("zone {id} does not exist"),
        )
        .param("id", id.to_string())
    }

    /// `dns.zone.invalid` naming a field.
    pub fn zone_invalid(field: &str, reason: &str) -> Self {
        DnsError::invalid(codes::ZONE_INVALID, field, reason).into()
    }

    /// `dns.zonefile.invalid` at a line.
    pub fn zone_file(line: usize, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self::new(
            codes::ZONE_FILE_INVALID,
            422,
            format!("line {line}: {reason}"),
        )
        .param("line", line.to_string())
        .param("reason", reason)
    }

    /// The precondition failure of a stale plan, which the service plans again.
    pub(crate) fn is_stale(&self) -> bool {
        self.0.code == "sys.store.precondition_failed" && self.0.status != 412
    }
}

impl fmt::Debug for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZoneError({}: {})", self.0.code, self.0.detail)
    }
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.detail)
    }
}

impl std::error::Error for ZoneError {}

impl From<DnsError> for ZoneError {
    fn from(error: DnsError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_store::StoreError> for ZoneError {
    fn from(error: tenko_store::StoreError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_vault::VaultError> for ZoneError {
    fn from(error: tenko_vault::VaultError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_jobs::JobError> for ZoneError {
    fn from(error: tenko_jobs::JobError) -> Self {
        match error {
            tenko_jobs::JobError::Store(store) => store.into(),
            other => Self(Box::new(other.to_coded_error())),
        }
    }
}

impl From<tenko_core::codec::CodecError> for ZoneError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl Coded for ZoneError {
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
