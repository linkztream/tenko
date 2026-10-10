//! The coded error of the scanner.

use std::fmt;

/// An error with a stable code (`scan.*`) and an English detail without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    code: &'static str,
    detail: String,
}

impl ScanError {
    /// An error with `code`.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// `scan.config`: the `[scan]` section is unusable.
    pub fn config(detail: impl Into<String>) -> Self {
        Self::new("scan.config", detail)
    }

    /// `scan.io`: a socket, file or command failed.
    pub fn io(detail: impl Into<String>) -> Self {
        Self::new("scan.io", detail)
    }

    /// `scan.unavailable`: the method cannot run on this host.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new("scan.unavailable", detail)
    }

    /// `scan.cancelled`: the run was stopped (kill switch, blackout window, shutdown).
    pub fn cancelled(detail: impl Into<String>) -> Self {
        Self::new("scan.cancelled", detail)
    }

    /// `scan.out_of_scope`: a target outside the configured prefixes.
    pub fn out_of_scope(detail: impl Into<String>) -> Self {
        Self::new("scan.out_of_scope", detail)
    }

    /// The stable code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The English detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.detail)
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(error: std::io::Error) -> Self {
        Self::io(error.to_string())
    }
}
