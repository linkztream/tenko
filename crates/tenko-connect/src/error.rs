//! Connector errors.

use std::{collections::BTreeMap, time::Duration};

use tenko_core::Coded;

/// A connector call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    /// The system did not answer.
    #[error("the system is unreachable")]
    Unreachable,
    /// The credentials were rejected.
    #[error("the credentials were rejected")]
    Unauthorized,
    /// The credentials lack a permission.
    #[error("the credentials lack a required permission")]
    Forbidden,
    /// The object does not exist on the system.
    #[error("the object does not exist on the system")]
    NotFound,
    /// The read-back after a write differs from the plan (CONN-08).
    #[error("the read-back differs from the plan: {diff}")]
    VerifyMismatch {
        /// What differs.
        diff: String,
    },
    /// A guardrail refused the change (CONN-09).
    #[error("refused by guardrail {rule}")]
    GuardrailRefused {
        /// The guardrail code, for example `connect.guardrail.uplink`.
        rule: &'static str,
    },
    /// Writes to network controllers are off (TGL-20).
    #[error("writes to this system are disabled")]
    WritesDisabled,
    /// The system asked to slow down.
    #[error("rate limited; retry after {retry_after:?}")]
    RateLimited {
        /// When to retry.
        retry_after: Duration,
    },
    /// The system answered something the driver does not understand.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The driver or the system version does not support the operation.
    #[error("operation not supported")]
    Unsupported,
}

impl Coded for ConnectorError {
    fn code(&self) -> &'static str {
        match self {
            ConnectorError::Unreachable => "connect.unreachable",
            ConnectorError::Unauthorized => "connect.unauthorized",
            ConnectorError::Forbidden => "connect.forbidden",
            ConnectorError::NotFound => "connect.not_found",
            ConnectorError::VerifyMismatch { .. } => "connect.verify_mismatch",
            ConnectorError::GuardrailRefused { rule } => rule,
            ConnectorError::WritesDisabled => "connect.writes_disabled",
            ConnectorError::RateLimited { .. } => "connect.rate_limited",
            ConnectorError::Protocol(_) => "connect.protocol",
            ConnectorError::Unsupported => "connect.unsupported",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            ConnectorError::Unreachable
            | ConnectorError::Unauthorized
            | ConnectorError::Forbidden
            | ConnectorError::Protocol(_) => 502,
            ConnectorError::NotFound => 404,
            ConnectorError::VerifyMismatch { .. } | ConnectorError::GuardrailRefused { .. } => 409,
            ConnectorError::WritesDisabled => 403,
            ConnectorError::RateLimited { .. } => 429,
            ConnectorError::Unsupported => 501,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            ConnectorError::RateLimited { retry_after } => {
                BTreeMap::from([("retry_after_ms", retry_after.as_millis().to_string())])
            }
            _ => BTreeMap::new(),
        }
    }
}
