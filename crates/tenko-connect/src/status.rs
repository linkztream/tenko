//! The error convention of the protocol: [`ConnectorError`] to a gRPC [`Status`] in the
//! plugin, and back in the host.
//!
//! A plugin answers a failed call with a status code and the metadata entry
//! [`ERROR_CODE`] carrying the stable code; a rate limit adds [`RETRY_AFTER`]. The host
//! prefers the code and falls back to the status code, so a plugin in another language that
//! sets only the status is understood too. The table is in `common.proto`.

use std::time::Duration;

use tenko_core::Coded;
use tonic::{Code, Status, metadata::MetadataValue};

use crate::ConnectorError;

/// Metadata entry with the stable error code of a failed call.
pub const ERROR_CODE: &str = "tenko-error-code";

/// Metadata entry with the delay before a retry, in milliseconds.
pub const RETRY_AFTER: &str = "tenko-retry-after-ms";

/// Metadata entry with the per-launch token on every call of the host.
pub const TOKEN_METADATA: &str = "x-tenko-plugin-token";

/// The error code of a call refused for a missing or wrong token.
pub const TOKEN_REFUSED: &str = "connect.plugin.token";

/// Longest status message the host keeps, in bytes.
const MAX_MESSAGE: usize = 1024;

/// The status a plugin answers for an error.
pub fn to_status(error: &ConnectorError) -> Status {
    let code = match error {
        ConnectorError::Unreachable | ConnectorError::PluginUnavailable(_) => Code::Unavailable,
        ConnectorError::Unauthorized => Code::Unauthenticated,
        ConnectorError::Forbidden
        | ConnectorError::WritesDisabled
        | ConnectorError::GuardrailRefused { .. } => Code::PermissionDenied,
        ConnectorError::NotFound => Code::NotFound,
        ConnectorError::VerifyMismatch { .. } => Code::FailedPrecondition,
        ConnectorError::RateLimited { .. } => Code::ResourceExhausted,
        ConnectorError::InvalidSettings(_) => Code::InvalidArgument,
        ConnectorError::Unsupported => Code::Unimplemented,
        ConnectorError::Timeout(_) => Code::DeadlineExceeded,
        ConnectorError::Protocol(_) | ConnectorError::PluginFailed(_) => Code::Internal,
    };
    let mut status = Status::new(code, error.to_string());
    if let Ok(value) = MetadataValue::try_from(error.code()) {
        status.metadata_mut().insert(ERROR_CODE, value);
    }
    if let ConnectorError::RateLimited { retry_after } = error
        && let Ok(value) = MetadataValue::try_from(retry_after.as_millis().to_string())
    {
        status.metadata_mut().insert(RETRY_AFTER, value);
    }
    status
}

/// The status a plugin answers for a call without the right token.
pub fn token_refused() -> Status {
    let mut status = Status::unauthenticated("the call does not carry the per-launch token");
    status
        .metadata_mut()
        .insert(ERROR_CODE, MetadataValue::from_static(TOKEN_REFUSED));
    status
}

/// The status a plugin answers for a request it cannot read (a malformed message from the
/// host): `INVALID_ARGUMENT` with the code `connect.protocol`.
pub fn malformed(detail: impl std::fmt::Display) -> Status {
    let mut status = Status::invalid_argument(format!("malformed request: {detail}"));
    status
        .metadata_mut()
        .insert(ERROR_CODE, MetadataValue::from_static("connect.protocol"));
    status
}

/// The error a host reads from a status.
pub fn from_status(status: &Status) -> ConnectorError {
    let message = clip(status.message());
    let code = status
        .metadata()
        .get(ERROR_CODE)
        .and_then(|value| value.to_str().ok());
    if let Some(code) = code
        && let Some(error) = from_code(code, &message, status)
    {
        return error;
    }
    match status.code() {
        Code::Unavailable => ConnectorError::Unreachable,
        Code::Unauthenticated => ConnectorError::Unauthorized,
        Code::PermissionDenied => ConnectorError::Forbidden,
        Code::NotFound => ConnectorError::NotFound,
        Code::FailedPrecondition => ConnectorError::VerifyMismatch { diff: message },
        Code::ResourceExhausted => ConnectorError::RateLimited {
            retry_after: retry_after(status),
        },
        Code::InvalidArgument => ConnectorError::InvalidSettings(message),
        Code::Unimplemented => ConnectorError::Unsupported,
        _ => ConnectorError::PluginFailed(format!("{:?}: {message}", status.code())),
    }
}

/// The error of a known code; `None` lets the status code decide.
fn from_code(code: &str, message: &str, status: &Status) -> Option<ConnectorError> {
    Some(match code {
        "connect.unreachable" => ConnectorError::Unreachable,
        "connect.unauthorized" => ConnectorError::Unauthorized,
        "connect.forbidden" => ConnectorError::Forbidden,
        "connect.not_found" => ConnectorError::NotFound,
        "connect.verify_mismatch" => ConnectorError::VerifyMismatch {
            diff: message.to_owned(),
        },
        "connect.rate_limited" => ConnectorError::RateLimited {
            retry_after: retry_after(status),
        },
        "connect.invalid_settings" => ConnectorError::InvalidSettings(message.to_owned()),
        "connect.protocol" => ConnectorError::Protocol(message.to_owned()),
        "connect.unsupported" => ConnectorError::Unsupported,
        TOKEN_REFUSED => ConnectorError::PluginFailed(format!(
            "the plugin refused the per-launch token: {message}"
        )),
        "connect.plugin.failed" => ConnectorError::PluginFailed(message.to_owned()),
        _ => return None,
    })
}

fn retry_after(status: &Status) -> Duration {
    status
        .metadata()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok())
        .map_or(Duration::from_secs(60), Duration::from_millis)
}

fn clip(message: &str) -> String {
    if message.len() <= MAX_MESSAGE {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_survive_the_round_trip() {
        let errors = [
            ConnectorError::Unreachable,
            ConnectorError::Unauthorized,
            ConnectorError::Forbidden,
            ConnectorError::NotFound,
            ConnectorError::VerifyMismatch {
                diff: "the read-back differs from the plan: vlan 30 != 31".to_owned(),
            },
            ConnectorError::RateLimited {
                retry_after: Duration::from_millis(2500),
            },
            ConnectorError::invalid_settings("invalid settings: url is missing"),
            ConnectorError::Unsupported,
        ];
        for error in errors {
            let back = from_status(&to_status(&error));
            assert_eq!(back.code(), error.code(), "{error:?}");
        }
        let limited = from_status(&to_status(&ConnectorError::RateLimited {
            retry_after: Duration::from_millis(2500),
        }));
        assert_eq!(
            limited,
            ConnectorError::RateLimited {
                retry_after: Duration::from_millis(2500)
            }
        );
    }

    #[test]
    fn bare_status_codes_are_understood() {
        assert_eq!(
            from_status(&Status::unavailable("down")),
            ConnectorError::Unreachable
        );
        assert_eq!(
            from_status(&Status::unimplemented("no")),
            ConnectorError::Unsupported
        );
        assert!(matches!(
            from_status(&Status::internal("boom")),
            ConnectorError::PluginFailed(_)
        ));
        assert!(matches!(
            from_status(&Status::invalid_argument("url")),
            ConnectorError::InvalidSettings(_)
        ));
        assert!(matches!(
            from_status(&token_refused()),
            ConnectorError::PluginFailed(message) if message.contains("token")
        ));
    }

    #[test]
    fn long_messages_are_clipped() {
        let long = "x".repeat(5000);
        let error = from_status(&Status::internal(long));
        assert!(error.to_string().len() < 1200);
    }
}
