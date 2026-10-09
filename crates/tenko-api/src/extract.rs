//! Request extractors.
//!
//! [`Ctx`] builds the [`RequestCtx`] that every domain call takes: who acts, the request id,
//! the processing time, the client address and the idempotency key.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
};
use tenko_core::{
    IdempotencyKey, InvalidValue, Principal, RequestCtx, RequestId, SystemComponent, Timestamp,
};

use crate::problem::ApiError;

/// Name of the header that carries the client's idempotency key (API-04).
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// The [`RequestCtx`] of the current request.
///
/// Filled from the request:
///
/// - `request` is a new [`RequestId`] and `now` the current time.
/// - `source_ip` is the peer address from the [`ConnectInfo`] extension, when the server was
///   started with connect info. Trusted proxy headers are handled by the server layer, not
///   here.
/// - `idempotency` is the `Idempotency-Key` header. A value that is not valid UTF-8, or that
///   [`IdempotencyKey::new`] rejects, is refused with 400 `sys.invalid_value`.
/// - `principal` is a placeholder, see below.
#[derive(Debug, Clone)]
pub struct Ctx(pub RequestCtx);

impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = ApiError;

    // Nothing here awaits yet, so the future is already complete. WP1.2 turns this into an
    // `async fn` when it resolves the session or token.
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::from_parts(parts))
    }
}

impl Ctx {
    /// Builds the context from the head of a request.
    fn from_parts(parts: &Parts) -> Result<Self, ApiError> {
        let idempotency = idempotency_key(parts)?;
        let source_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| peer.ip());
        Ok(Self(RequestCtx {
            principal: placeholder_principal(),
            request: RequestId::generate(),
            now: Timestamp::now(),
            source_ip,
            idempotency,
        }))
    }
}

/// The principal of every request until authentication exists: the API acting on its own.
///
/// WP1.2 replaces this with the session or token principal, and refuses requests without
/// one.
fn placeholder_principal() -> Principal {
    Principal::System {
        component: SystemComponent::Api,
        on_behalf_of: None,
    }
}

/// Reads and validates the `Idempotency-Key` header.
fn idempotency_key(parts: &Parts) -> Result<Option<IdempotencyKey>, ApiError> {
    let Some(value) = parts.headers.get(IDEMPOTENCY_HEADER) else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value.as_bytes()).map_err(|_| {
        InvalidValue::new(
            "idempotency key",
            &String::from_utf8_lossy(value.as_bytes()),
            "must be valid UTF-8",
        )
    })?;
    Ok(Some(IdempotencyKey::new(text)?))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request, StatusCode, header},
        response::IntoResponse,
    };
    use serde_json::Value;

    use super::*;
    use crate::problem::PROBLEM_JSON;

    fn parts(key: Option<&[u8]>) -> Parts {
        let mut builder = Request::builder().method("POST").uri("/api/v1/prefixes");
        if let Some(key) = key {
            builder = builder.header(
                IDEMPOTENCY_HEADER,
                HeaderValue::from_bytes(key).expect("header value"),
            );
        }
        builder.body(Body::empty()).expect("request").into_parts().0
    }

    async fn extract(parts: &mut Parts) -> Result<Ctx, ApiError> {
        Ctx::from_request_parts(parts, &()).await
    }

    #[tokio::test]
    async fn fills_the_generated_fields() {
        let before = Timestamp::now();
        let Ctx(first) = extract(&mut parts(None)).await.expect("ctx");
        let Ctx(second) = extract(&mut parts(None)).await.expect("ctx");
        let after = Timestamp::now();

        assert_ne!(first.request, second.request);
        assert!(before <= first.now && first.now <= after);
        assert_eq!(
            first.principal,
            Principal::System {
                component: SystemComponent::Api,
                on_behalf_of: None
            }
        );
        assert_eq!(first.source_ip, None);
        assert_eq!(first.idempotency, None);
    }

    #[tokio::test]
    async fn accepts_an_idempotency_key() {
        let Ctx(ctx) = extract(&mut parts(Some(b"import-2026-10-09-a1")))
            .await
            .expect("ctx");
        assert_eq!(
            ctx.idempotency.as_ref().map(IdempotencyKey::as_str),
            Some("import-2026-10-09-a1")
        );
    }

    #[tokio::test]
    async fn rejects_an_invalid_idempotency_key_with_problem_details() {
        for key in [
            &b"has space"[..],
            &b""[..],
            &[b'k'; 256][..],
            &[0xC3, 0x28][..],
        ] {
            let error = extract(&mut parts(Some(key)))
                .await
                .expect_err("key must be rejected");
            assert_eq!(error.coded_error().code, "sys.invalid_value");
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).expect("type"),
                PROBLEM_JSON
            );
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let body: Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(body["code"], "sys.invalid_value");
            assert_eq!(body["status"], 400);
            assert_eq!(body["params"]["kind"], "idempotency key");
        }
    }

    #[tokio::test]
    async fn takes_the_source_ip_from_connect_info() {
        let mut parts = parts(None);
        let peer = SocketAddr::from(([192, 0, 2, 10], 40_000));
        parts.extensions.insert(ConnectInfo(peer));
        let Ctx(ctx) = extract(&mut parts).await.expect("ctx");
        assert_eq!(ctx.source_ip, Some(peer.ip()));
    }
}
