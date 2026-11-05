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

/// `Permissions-Policy`: every browser feature the web interface never uses is denied to
/// the document and to anything it could embed. The three it uses are allowed to its own
/// origin only: the clipboard (copy buttons, and the secret reveal reads the clipboard
/// back before it clears it) and the WebAuthn ceremonies of passkeys. Fullscreen is not
/// used and is denied with the rest.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), \
     attribution-reporting=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), \
     camera=(), clipboard-read=(self), clipboard-write=(self), compute-pressure=(), \
     cross-origin-isolated=(), display-capture=(), document-domain=(), \
     encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), \
     identity-credentials-get=(), idle-detection=(), keyboard-map=(), local-fonts=(), \
     magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), \
     picture-in-picture=(), publickey-credentials-create=(self), \
     publickey-credentials-get=(self), screen-wake-lock=(), serial=(), \
     speaker-selection=(), storage-access=(), sync-xhr=(), unload=(), usb=(), \
     web-share=(), window-management=(), xr-spatial-tracking=()";

const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");
const CROSS_ORIGIN_EMBEDDER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-embedder-policy");
const PERMISSIONS_POLICY_HEADER: HeaderName = HeaderName::from_static("permissions-policy");

/// Adds the security headers a handler did not set. `hsts` adds
/// `Strict-Transport-Security` (HTTPS responses only).
///
/// The three cross-origin policies isolate the interface from other origins (ZAP 90004):
/// the document gets its own browsing context group, every response is a resource of its
/// own origin only, and the document may embed nothing that does not say it may be
/// embedded. The web interface loads nothing from another origin (its fonts, images and
/// scripts are its own files or `data:` URLs, and it frames nothing), so `require-corp`
/// breaks no feature. The API answers carry the same headers: a cross-origin policy on a
/// JSON answer changes nothing for an API client, which does not embed it, and one
/// middleware for every response is simpler to prove than two.
pub(crate) fn apply(headers: &mut HeaderMap, hsts: bool) {
    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY),
        (CROSS_ORIGIN_OPENER_POLICY, "same-origin"),
        (CROSS_ORIGIN_RESOURCE_POLICY, "same-origin"),
        (CROSS_ORIGIN_EMBEDDER_POLICY, "require-corp"),
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
        assert_eq!(headers[PERMISSIONS_POLICY_HEADER], PERMISSIONS_POLICY);
        assert_eq!(headers[CROSS_ORIGIN_OPENER_POLICY], "same-origin");
        assert_eq!(headers[CROSS_ORIGIN_RESOURCE_POLICY], "same-origin");
        assert_eq!(headers[CROSS_ORIGIN_EMBEDDER_POLICY], "require-corp");
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());
        apply(&mut headers, true);
        assert_eq!(headers[header::STRICT_TRANSPORT_SECURITY], HSTS);
    }

    /// The policy denies every feature but the clipboard and the passkey ceremonies, and
    /// allows those to the interface's own origin only.
    #[test]
    fn permissions_policy_denies_everything_the_interface_does_not_use() {
        let allowed = [
            "clipboard-read",
            "clipboard-write",
            "publickey-credentials-create",
            "publickey-credentials-get",
        ];
        let mut seen = Vec::new();
        for directive in PERMISSIONS_POLICY.split(", ") {
            let (feature, allowlist) = directive.split_once('=').expect("feature=allowlist");
            assert!(!seen.contains(&feature), "{feature} listed twice");
            seen.push(feature);
            if allowed.contains(&feature) {
                assert_eq!(allowlist, "(self)", "{feature}");
            } else {
                assert_eq!(allowlist, "()", "{feature}");
            }
        }
        for feature in allowed {
            assert!(seen.contains(&feature), "{feature} missing");
        }
        for feature in [
            "camera",
            "microphone",
            "geolocation",
            "payment",
            "usb",
            "serial",
            "bluetooth",
            "display-capture",
            "midi",
            "magnetometer",
            "gyroscope",
            "accelerometer",
            "fullscreen",
        ] {
            assert!(seen.contains(&feature), "{feature} missing");
        }
    }
}
