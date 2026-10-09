//! Security headers of every response (ADR 0008 decision 3, TGL-08).

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

/// Content Security Policy for the same-origin SPA that talks to its own API with `fetch`
/// and `EventSource`: no inline script or style, no plugins, no framing.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; \
     base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// `Strict-Transport-Security` sent on HTTPS responses: one year. Subdomains are left out
/// on purpose: the host name of a Tenko installation does not speak for its siblings.
pub const HSTS: &str = "max-age=31536000";

const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// Adds the security headers a handler did not set. `hsts` adds
/// `Strict-Transport-Security` (HTTPS responses only).
pub(crate) fn apply(headers: &mut HeaderMap, hsts: bool) {
    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (CROSS_ORIGIN_OPENER_POLICY, "same-origin"),
        (CROSS_ORIGIN_RESOURCE_POLICY, "same-origin"),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    if hsts {
        headers
            .entry(header::STRICT_TRANSPORT_SECURITY)
            .or_insert(HeaderValue::from_static(HSTS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_added_without_overriding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        );
        apply(&mut headers, false);
        assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .expect("csp")
                .starts_with("default-src 'self'")
        );
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());
        apply(&mut headers, true);
        assert_eq!(headers[header::STRICT_TRANSPORT_SECURITY], HSTS);
    }
}
