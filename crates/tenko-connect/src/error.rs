//! Connector errors: what a plugin call can fail with, on both sides of the protocol.

use std::{collections::BTreeMap, time::Duration};

use tenko_core::Coded;

/// A connector call failed.
///
/// A plugin returns these from its trait methods; the SDK turns them into a gRPC status
/// with the `tenko-error-code` metadata entry, and the host turns the status back
/// ([`crate::status`]). The host adds the variants that only it produces: [`Timeout`],
/// [`PluginUnavailable`] and the policy refusals [`GuardrailRefused`] and
/// [`WritesDisabled`].
///
/// [`Timeout`]: ConnectorError::Timeout
/// [`PluginUnavailable`]: ConnectorError::PluginUnavailable
/// [`GuardrailRefused`]: ConnectorError::GuardrailRefused
/// [`WritesDisabled`]: ConnectorError::WritesDisabled
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    /// The remote system did not answer.
    #[error("the system is unreachable")]
    Unreachable,
    /// The remote system rejected the credentials.
    #[error("the credentials were rejected")]
    Unauthorized,
    /// The credentials lack a permission.
    #[error("the credentials lack a required permission")]
    Forbidden,
    /// The object does not exist on the system.
    #[error("the object does not exist on the system")]
    NotFound,
    /// The plan is stale or the read-back after a write differs from the plan (CONN-08).
    #[error("the read-back differs from the plan: {diff}")]
    VerifyMismatch {
        /// What differs.
        diff: String,
    },
    /// A guardrail of the host refused the change (CONN-09).
    #[error("refused by guardrail {rule}")]
    GuardrailRefused {
        /// The guardrail code, for example `connect.guardrail.uplink`.
        rule: &'static str,
    },
    /// Writes through this connector are off (TGL-20).
    #[error("writes to this system are disabled")]
    WritesDisabled,
    /// The system asked to slow down.
    #[error("rate limited; retry after {retry_after:?}")]
    RateLimited {
        /// When to retry.
        retry_after: Duration,
    },
    /// The settings or the request cannot be used.
    #[error("invalid settings: {0}")]
    InvalidSettings(String),
    /// The remote system answered something the plugin does not understand, or the plugin
    /// answered something the host does not understand.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The plugin or the system version does not support the operation.
    #[error("operation not supported")]
    Unsupported,
    /// The call did not finish within its timeout (host side).
    #[error("the call timed out after {0:?}")]
    Timeout(Duration),
    /// The plugin process is not running: starting, restarting after a crash, held back by
    /// the circuit breaker, or the instance is disabled (host side).
    #[error("the plugin is not available: {0}")]
    PluginUnavailable(String),
    /// The plugin failed with an internal error.
    #[error("the plugin failed: {0}")]
    PluginFailed(String),
}

impl ConnectorError {
    /// The error for a settings document that does not deserialize or lacks a value.
    pub fn invalid_settings(detail: impl Into<String>) -> Self {
        ConnectorError::InvalidSettings(detail.into())
    }

    /// The error for a reply from the remote system that the plugin cannot read.
    pub fn protocol(detail: impl Into<String>) -> Self {
        ConnectorError::Protocol(detail.into())
    }

    /// Whether retrying the same call later may succeed: the system was unreachable, rate
    /// limited, timed out or the plugin was restarting.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ConnectorError::Unreachable
                | ConnectorError::RateLimited { .. }
                | ConnectorError::Timeout(_)
                | ConnectorError::PluginUnavailable(_)
        )
    }
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
            ConnectorError::InvalidSettings(_) => "connect.invalid_settings",
            ConnectorError::Protocol(_) => "connect.protocol",
            ConnectorError::Unsupported => "connect.unsupported",
            ConnectorError::Timeout(_) => "connect.timeout",
            ConnectorError::PluginUnavailable(_) => "connect.plugin.unavailable",
            ConnectorError::PluginFailed(_) => "connect.plugin.failed",
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            ConnectorError::Unreachable
            | ConnectorError::Unauthorized
            | ConnectorError::Forbidden
            | ConnectorError::Protocol(_)
            | ConnectorError::PluginFailed(_) => 502,
            ConnectorError::NotFound => 404,
            ConnectorError::VerifyMismatch { .. } | ConnectorError::GuardrailRefused { .. } => 409,
            ConnectorError::WritesDisabled => 403,
            ConnectorError::RateLimited { .. } => 429,
            ConnectorError::InvalidSettings(_) => 400,
            ConnectorError::Unsupported => 501,
            ConnectorError::Timeout(_) => 504,
            ConnectorError::PluginUnavailable(_) => 503,
        }
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            ConnectorError::RateLimited { retry_after } => {
                BTreeMap::from([("retry_after_ms", retry_after.as_millis().to_string())])
            }
            ConnectorError::Timeout(after) => {
                BTreeMap::from([("timeout_ms", after.as_millis().to_string())])
            }
            _ => BTreeMap::new(),
        }
    }

    fn title(&self) -> &'static str {
        match self {
            ConnectorError::Timeout(_) => "Connector call timed out",
            ConnectorError::PluginUnavailable(_) => "Connector plugin not available",
            ConnectorError::GuardrailRefused { .. } => "Refused by a guardrail",
            _ => "Connector call failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_namespaced_and_stable() {
        let cases = [
            (ConnectorError::Unreachable, "connect.unreachable", 502),
            (
                ConnectorError::invalid_settings("x"),
                "connect.invalid_settings",
                400,
            ),
            (
                ConnectorError::Timeout(Duration::from_secs(3)),
                "connect.timeout",
                504,
            ),
            (
                ConnectorError::PluginUnavailable("restarting".to_owned()),
                "connect.plugin.unavailable",
                503,
            ),
            (
                ConnectorError::GuardrailRefused {
                    rule: "connect.guardrail.uplink",
                },
                "connect.guardrail.uplink",
                409,
            ),
        ];
        for (error, code, status) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.http_status(), status);
            assert!(tenko_core::names::is_valid_name(error.code()), "{code}");
        }
        assert_eq!(
            ConnectorError::Timeout(Duration::from_millis(1500)).params()["timeout_ms"],
            "1500"
        );
        assert!(ConnectorError::Unreachable.is_transient());
        assert!(!ConnectorError::Unauthorized.is_transient());
    }
}
