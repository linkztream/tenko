//! Stable error codes (plan section 2.8, API-08).
//!
//! Every error type in Tenko implements [`Coded`]: a stable, namespaced `code` such as
//! `ipam.prefix.overlap`, an HTTP status, and named parameters that the UI uses to render a
//! translated message. Codes are stable once merged; only the owning area adds codes in its
//! namespace (see [`crate::names`]).
//!
//! [`CodedError`] is the serializable snapshot of any coded error. It is what the API turns
//! into RFC 9457 problem details and what the job engine stores when a step fails.

use std::{borrow::Cow, collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Well-known codes of the `sys` namespace that several crates use.
pub mod codes {
    /// The endpoint or feature exists in the contract but is not implemented yet (501).
    pub const NOT_IMPLEMENTED: &str = "sys.not_implemented";
    /// An unexpected internal error (500). The detail never carries secrets.
    pub const INTERNAL: &str = "sys.internal";
    /// The request is malformed (400).
    pub const INVALID_REQUEST: &str = "sys.invalid_request";
    /// A value failed validation (400). Parameters: `kind`, `value`, `reason`.
    pub const INVALID_VALUE: &str = "sys.invalid_value";
    /// A namespaced name is malformed or uses an unknown namespace (400).
    pub const INVALID_NAME: &str = "sys.invalid_name";
}

/// An error with a stable code, an HTTP status and named parameters.
///
/// The [`Display`](fmt::Display) output is the English `detail` of the problem document;
/// [`Coded::title`] is the short English summary. The UI translates from `code` and
/// `params`, never from the English text.
pub trait Coded: fmt::Display {
    /// The stable, namespaced error code, for example `ipam.prefix.overlap`.
    fn code(&self) -> &'static str;

    /// The HTTP status the API answers with.
    fn http_status(&self) -> u16;

    /// Named parameters for the translated message. Never contains secrets.
    fn params(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::new()
    }

    /// Short English summary of the problem type. Defaults to the reason phrase of the
    /// status.
    fn title(&self) -> &'static str {
        status_title(self.http_status())
    }

    /// Per-field errors of a request body, for the `errors` member of problem details.
    fn field_errors(&self) -> Vec<FieldError> {
        Vec::new()
    }

    /// Captures this error as a serializable [`CodedError`].
    fn to_coded_error(&self) -> CodedError {
        CodedError {
            code: Cow::Borrowed(self.code()),
            status: self.http_status(),
            title: Cow::Borrowed(self.title()),
            detail: self.to_string(),
            params: self
                .params()
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
            errors: self.field_errors(),
        }
    }
}

impl<T: Coded + ?Sized> Coded for Box<T> {
    fn code(&self) -> &'static str {
        (**self).code()
    }
    fn http_status(&self) -> u16 {
        (**self).http_status()
    }
    fn params(&self) -> BTreeMap<&'static str, String> {
        (**self).params()
    }
    fn title(&self) -> &'static str {
        (**self).title()
    }
    fn field_errors(&self) -> Vec<FieldError> {
        (**self).field_errors()
    }
}

/// English reason phrase of an HTTP status, used as the default problem title.
pub const fn status_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        423 => "Locked",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// One invalid field of a request body (the `errors` member of problem details).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FieldError {
    /// The field path, for example `cidr` or `interfaces[0].mac`.
    pub field: String,
    /// The stable code of the problem with this field.
    #[schema(value_type = String)]
    pub code: Cow<'static, str>,
    /// Named parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

impl FieldError {
    /// Creates a field error without parameters.
    pub fn new(field: impl Into<String>, code: &'static str) -> Self {
        Self {
            field: field.into(),
            code: Cow::Borrowed(code),
            params: BTreeMap::new(),
        }
    }
}

/// A serializable snapshot of a [`Coded`] error.
///
/// This is the wire shape of every error (the API adds `type` and `instance` to make an
/// RFC 9457 problem document) and the stored shape of failed job steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, thiserror::Error)]
#[error("{detail}")]
pub struct CodedError {
    /// The stable, namespaced error code.
    #[schema(value_type = String)]
    pub code: Cow<'static, str>,
    /// The HTTP status.
    pub status: u16,
    /// Short English summary.
    #[schema(value_type = String)]
    pub title: Cow<'static, str>,
    /// English explanation of this occurrence.
    pub detail: String,
    /// Named parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// Per-field errors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
}

impl CodedError {
    /// Creates an error with the default title for `status` and no parameters.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self {
            code: Cow::Borrowed(code),
            status,
            title: Cow::Borrowed(status_title(status)),
            detail: detail.into(),
            params: BTreeMap::new(),
            errors: Vec::new(),
        }
    }

    /// Captures any coded error.
    pub fn from_coded<E: Coded + ?Sized>(error: &E) -> Self {
        error.to_coded_error()
    }

    /// `sys.not_implemented` (501) for a feature that is not built yet.
    pub fn not_implemented(what: impl Into<String>) -> Self {
        let what = what.into();
        Self::new(
            codes::NOT_IMPLEMENTED,
            501,
            format!("{what} is not implemented yet"),
        )
        .with_param("what", what)
    }

    /// `sys.internal` (500). The detail must not carry secrets.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL, 500, detail)
    }

    /// Adds a named parameter.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// Adds a field error.
    #[must_use]
    pub fn with_field_error(mut self, error: FieldError) -> Self {
        self.errors.push(error);
        self
    }

    /// Replaces the title.
    #[must_use]
    pub fn with_title(mut self, title: &'static str) -> Self {
        self.title = Cow::Borrowed(title);
        self
    }
}

/// A value failed validation: a name, an identifier, a MAC address, a DNS name and so on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} `{value}`: {reason}")]
pub struct InvalidValue {
    /// What was being parsed, for example `MAC address`.
    pub kind: &'static str,
    /// The rejected input (truncated to 128 characters).
    pub value: String,
    /// Why it was rejected.
    pub reason: &'static str,
}

impl InvalidValue {
    /// Creates the error, truncating long input so it never floods logs.
    pub fn new(kind: &'static str, value: &str, reason: &'static str) -> Self {
        Self {
            kind,
            value: value.chars().take(128).collect(),
            reason,
        }
    }
}

impl Coded for InvalidValue {
    fn code(&self) -> &'static str {
        codes::INVALID_VALUE
    }
    fn http_status(&self) -> u16 {
        400
    }
    fn params(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("kind", self.kind.to_owned()),
            ("value", self.value.clone()),
            ("reason", self.reason.to_owned()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("192.0.2.0/25 overlaps 192.0.2.0/24")]
    struct Overlap;

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
        fn field_errors(&self) -> Vec<FieldError> {
            vec![FieldError::new("cidr", "ipam.prefix.overlap")]
        }
    }

    #[test]
    fn coded_error_captures_every_member() {
        let error = Overlap.to_coded_error();
        assert_eq!(error.code, "ipam.prefix.overlap");
        assert_eq!(error.status, 409);
        assert_eq!(error.title, "Conflict");
        assert_eq!(error.detail, "192.0.2.0/25 overlaps 192.0.2.0/24");
        assert_eq!(error.params["cidr"], "192.0.2.0/24");
        assert_eq!(
            error.errors,
            vec![FieldError::new("cidr", "ipam.prefix.overlap")]
        );
        assert_eq!(error.to_string(), error.detail);
    }

    #[test]
    fn boxed_errors_stay_coded() {
        let boxed: Box<dyn Coded> = Box::new(Overlap);
        assert_eq!(boxed.code(), "ipam.prefix.overlap");
        assert_eq!(CodedError::from_coded(&boxed).status, 409);
    }

    #[test]
    fn coded_error_json_omits_empty_members() {
        let json = serde_json::to_value(CodedError::internal("boom")).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "code": "sys.internal", "status": 500,
                "title": "Internal Server Error", "detail": "boom"
            })
        );
        let back: CodedError = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, CodedError::internal("boom"));
    }

    #[test]
    fn not_implemented_names_the_feature() {
        let error = CodedError::not_implemented("GET /api/v1/tags");
        assert_eq!(error.code, codes::NOT_IMPLEMENTED);
        assert_eq!(error.status, 501);
        assert_eq!(error.params["what"], "GET /api/v1/tags");
    }

    #[test]
    fn invalid_value_truncates_input() {
        let long = "x".repeat(500);
        let error = InvalidValue::new("tag", &long, "too long");
        assert_eq!(error.value.len(), 128);
        assert_eq!(error.params()["kind"], "tag");
    }
}
