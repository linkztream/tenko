//! Problem details (RFC 9457) and the error type of handlers.
//!
//! Every error response of the API is an `application/problem+json` document with the
//! standard members (`type`, `status`, `title`, `detail`, `instance`) and the Tenko members:
//! a stable `code`, named `params` and per-field `errors`. The UI translates from `code` and
//! `params`, never from the English text (API-08).
//!
//! Handlers return `Result<T, ApiError>`. Any [`Coded`] error converts into [`ApiError`] with
//! `?`, so domain errors need no mapping code in the API.

use std::{collections::BTreeMap, fmt};

#[cfg(feature = "server")]
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{Coded, CodedError, FieldError, error::codes as core_codes};
use utoipa::ToSchema;

/// Media type of problem details.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// Stable error codes of the API platform (WP1.7, namespace `sys`).
///
/// Codes are stable once merged (API-08); the UI translates them.
pub mod codes {
    /// 404: no API route matches the path.
    pub const ROUTE_NOT_FOUND: &str = "sys.route_not_found";
    /// 405: the path exists but not for this method.
    pub const METHOD_NOT_ALLOWED: &str = "sys.method_not_allowed";
    /// 400: a query parameter is missing, repeated or malformed.
    pub const INVALID_QUERY: &str = "sys.invalid_query";
    /// 400: the pagination cursor is malformed or belongs to another query.
    pub const INVALID_CURSOR: &str = "sys.invalid_cursor";
    /// 403: a state-changing request failed the `Origin` check (CSRF guard).
    pub const CSRF_REJECTED: &str = "sys.csrf_rejected";
    /// 429: a rate limit was exceeded; `Retry-After` says when to retry.
    pub const RATE_LIMITED: &str = "sys.rate_limited";
    /// 422: an `Idempotency-Key` was reused for a different request.
    pub const IDEMPOTENCY_MISMATCH: &str = "sys.idempotency_mismatch";
    /// 409: a request with the same `Idempotency-Key` is still being processed.
    pub const IDEMPOTENCY_IN_FLIGHT: &str = "sys.idempotency_in_flight";
    /// 409: a request with the same `Idempotency-Key` was already performed, and its
    /// response carried a secret (`Cache-Control: no-store` or `Set-Cookie`) that is never
    /// stored (NEVER-01), so it cannot be replayed; the handler does not run again.
    pub const IDEMPOTENCY_NOT_REPLAYABLE: &str = "sys.idempotency_not_replayable";
    /// 413: the request body exceeds the limit.
    pub const BODY_TOO_LARGE: &str = "sys.body_too_large";
    /// 403: plain HTTP from a source that is not a trusted reverse proxy (TLS mode c).
    pub const PROXY_ONLY: &str = "sys.proxy_only";
    /// 503: the node is not ready to serve (readiness probe).
    pub const NOT_READY: &str = "sys.not_ready";
    /// 503: the server is shutting down.
    pub const SHUTTING_DOWN: &str = "sys.shutting_down";
    /// 404: no audit record has the sequence number.
    pub const AUDIT_NOT_FOUND: &str = "sys.audit.not_found";
    /// 400: an unknown event topic was requested.
    pub const UNKNOWN_TOPIC: &str = "sys.events.unknown_topic";
}

/// Body sent when a problem document cannot be serialized, which should never happen.
#[cfg(feature = "server")]
const FALLBACK_BODY: &str = concat!(
    r#"{"type":"about:blank","status":500,"code":"sys.internal","#,
    r#""title":"Internal Server Error","#,
    r#""detail":"the problem document could not be serialized"}"#
);

/// The JSON body of every error response: RFC 9457 problem details plus the Tenko members
/// `code`, `params` and `errors`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    /// The problem type. Always `about:blank` for now: the stable `code` identifies the
    /// problem, and `title` is the English summary of its status.
    #[serde(rename = "type")]
    #[schema(example = "about:blank")]
    pub type_: String,
    /// The HTTP status code of the response.
    pub status: u16,
    /// The stable, namespaced error code, for example `ipam.prefix.overlap`.
    pub code: String,
    /// Short English summary of the problem.
    pub title: String,
    /// English explanation of this occurrence.
    pub detail: String,
    /// Named parameters the UI uses to render a translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// Per-field errors of the request body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
    /// A URI reference that identifies this occurrence, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl From<CodedError> for ProblemDetails {
    fn from(error: CodedError) -> Self {
        Self {
            type_: "about:blank".to_owned(),
            status: error.status,
            code: error.code.into_owned(),
            title: error.title.into_owned(),
            detail: error.detail,
            params: error.params,
            errors: error.errors,
            instance: None,
        }
    }
}

/// The error type of handlers: a [`CodedError`] that renders as problem details.
///
/// Every [`Coded`] error converts into it, so handlers use `?` on domain results. A
/// [`CodedError`] converts through [`ApiError::from_coded_error`] (a `From<CodedError>`
/// implementation would overlap the blanket implementation for [`Coded`] types).
#[derive(Debug, Clone)]
pub struct ApiError(Box<CodedError>);

impl ApiError {
    /// Wraps an already captured [`CodedError`].
    pub fn from_coded_error(error: CodedError) -> Self {
        Self(Box::new(error))
    }

    /// `sys.not_implemented` (501) for an endpoint that is in the contract but not built
    /// yet. `path` is the full path including the API base, for example `/api/v1/tags`.
    pub fn not_implemented(method: &str, path: &str) -> Self {
        Self::from_coded_error(
            CodedError::new(
                core_codes::NOT_IMPLEMENTED,
                501,
                format!("{method} {path} is not implemented yet"),
            )
            .with_param("method", method)
            .with_param("path", path),
        )
    }

    /// A 400 `sys.invalid_query` naming the offending query parameter.
    pub fn invalid_query(parameter: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self::from_coded_error(
            CodedError::new(
                codes::INVALID_QUERY,
                400,
                format!("query parameter `{parameter}`: {reason}"),
            )
            .with_param("parameter", parameter)
            .with_field_error(FieldError::new(parameter.to_owned(), codes::INVALID_QUERY)),
        )
    }

    /// An error with one of the platform's own codes, a status and an English detail.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self::from_coded_error(CodedError::new(code, status, detail))
    }

    /// Adds a named parameter for the UI's translated message.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.params.insert(key.into(), value.into());
        self
    }

    /// The captured error.
    pub fn coded_error(&self) -> &CodedError {
        &self.0
    }

    /// The HTTP status of the error.
    pub fn status(&self) -> u16 {
        self.0.status
    }
}

impl ProblemDetails {
    /// Whether the document carries the given code.
    pub fn is(&self, code: &str) -> bool {
        self.code == code
    }
}

impl fmt::Display for ProblemDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.code, self.status, self.detail)
    }
}

impl std::error::Error for ProblemDetails {}

impl<E: Coded> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self::from_coded_error(error.to_coded_error())
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0.code, self.0.detail)
    }
}

#[cfg(feature = "server")]
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut problem = ProblemDetails::from(*self.0);
        // A status outside 100..=999 is a bug of the error type; answer 500 and keep the
        // document consistent with the response line.
        let status = StatusCode::from_u16(problem.status).unwrap_or_else(|_| {
            problem.status = 500;
            StatusCode::INTERNAL_SERVER_ERROR
        });
        let (status, body) = match serde_json::to_string(&problem) {
            Ok(body) => (status, body),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, FALLBACK_BODY.to_owned()),
        };
        (
            status,
            [(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON))],
            body,
        )
            .into_response()
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use axum::body::to_bytes;
    use serde_json::{Value, json};

    use super::*;

    /// A hand-written coded error that sets every member.
    struct Overlap;

    impl fmt::Display for Overlap {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("192.0.2.0/25 overlaps 192.0.2.0/24")
        }
    }

    impl Coded for Overlap {
        fn code(&self) -> &'static str {
            "ipam.prefix.overlap"
        }
        fn http_status(&self) -> u16 {
            409
        }
        fn params(&self) -> BTreeMap<&'static str, String> {
            BTreeMap::from([("cidr", "192.0.2.0/24".to_owned())])
        }
        fn title(&self) -> &'static str {
            "Prefix overlaps an existing prefix in the VRF"
        }
        fn field_errors(&self) -> Vec<FieldError> {
            vec![FieldError::new("cidr", "ipam.prefix.overlap")]
        }
    }

    /// A coded error that sets nothing but the required members.
    struct Plain;

    impl fmt::Display for Plain {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("something went wrong")
        }
    }

    impl Coded for Plain {
        fn code(&self) -> &'static str {
            "sys.internal"
        }
        fn http_status(&self) -> u16 {
            500
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[test]
    fn maps_every_member_of_a_coded_error() {
        let problem = ProblemDetails::from(Overlap.to_coded_error());
        assert_eq!(problem.type_, "about:blank");
        assert_eq!(problem.status, 409);
        assert_eq!(problem.code, "ipam.prefix.overlap");
        assert_eq!(
            problem.title,
            "Prefix overlaps an existing prefix in the VRF"
        );
        assert_eq!(problem.detail, "192.0.2.0/25 overlaps 192.0.2.0/24");
        assert_eq!(problem.params["cidr"], "192.0.2.0/24");
        assert_eq!(
            problem.errors,
            vec![FieldError::new("cidr", "ipam.prefix.overlap")]
        );
        assert_eq!(problem.instance, None);
    }

    #[test]
    fn api_error_converts_from_any_coded_error() {
        let error = ApiError::from(Overlap);
        assert_eq!(error.coded_error().code, "ipam.prefix.overlap");
        assert_eq!(error.coded_error().status, 409);
        assert_eq!(
            error.to_string(),
            "ipam.prefix.overlap: 192.0.2.0/25 overlaps 192.0.2.0/24"
        );
        let from_coded = ApiError::from_coded_error(CodedError::internal("boom"));
        assert_eq!(from_coded.coded_error().status, 500);
    }

    #[test]
    fn json_shape_matches_the_plan() {
        let problem = ProblemDetails::from(Overlap.to_coded_error());
        assert_eq!(
            serde_json::to_value(&problem).expect("json"),
            json!({
                "type": "about:blank",
                "status": 409,
                "code": "ipam.prefix.overlap",
                "title": "Prefix overlaps an existing prefix in the VRF",
                "detail": "192.0.2.0/25 overlaps 192.0.2.0/24",
                "params": { "cidr": "192.0.2.0/24" },
                "errors": [ { "field": "cidr", "code": "ipam.prefix.overlap" } ]
            })
        );
    }

    #[test]
    fn empty_members_are_omitted() {
        let problem = ProblemDetails::from(Plain.to_coded_error());
        assert_eq!(
            serde_json::to_value(&problem).expect("json"),
            json!({
                "type": "about:blank",
                "status": 500,
                "code": "sys.internal",
                "title": "Internal Server Error",
                "detail": "something went wrong"
            })
        );
        let back: ProblemDetails =
            serde_json::from_value(serde_json::to_value(&problem).expect("json")).expect("back");
        assert_eq!(back, problem);
    }

    #[test]
    fn instance_is_serialized_when_set() {
        let mut problem = ProblemDetails::from(Plain.to_coded_error());
        problem.instance = Some("/api/v1/prefixes/1".to_owned());
        let json = serde_json::to_value(&problem).expect("json");
        assert_eq!(json["instance"], "/api/v1/prefixes/1");
    }

    #[test]
    fn not_implemented_names_the_endpoint() {
        let error = ApiError::not_implemented("GET", "/api/v1/tags");
        let coded = error.coded_error();
        assert_eq!(coded.code, core_codes::NOT_IMPLEMENTED);
        assert_eq!(coded.status, 501);
        assert_eq!(coded.title, "Not Implemented");
        assert_eq!(coded.detail, "GET /api/v1/tags is not implemented yet");
        assert_eq!(coded.params["method"], "GET");
        assert_eq!(coded.params["path"], "/api/v1/tags");
        assert_eq!(coded.params.len(), 2);
    }

    #[tokio::test]
    async fn response_has_status_content_type_and_body() {
        let response = ApiError::from(Overlap).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            PROBLEM_JSON
        );
        let body = body_json(response).await;
        assert_eq!(body["code"], "ipam.prefix.overlap");
        assert_eq!(body["status"], 409);
        assert_eq!(body["params"]["cidr"], "192.0.2.0/24");
        assert_eq!(body["errors"][0]["field"], "cidr");
    }

    #[tokio::test]
    async fn an_unusable_status_becomes_a_500() {
        let error = ApiError::from_coded_error(CodedError::new("sys.internal", 42, "odd"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            PROBLEM_JSON
        );
        let body = body_json(response).await;
        assert_eq!(body["status"], 500);
        assert_eq!(body["code"], "sys.internal");
    }

    #[test]
    fn fallback_body_is_valid_problem_details() {
        let problem: ProblemDetails = serde_json::from_str(FALLBACK_BODY).expect("fallback json");
        assert_eq!(problem.status, 500);
        assert_eq!(problem.code, core_codes::INTERNAL);
    }
}
