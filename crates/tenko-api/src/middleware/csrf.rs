//! The `Origin`-based CSRF guard of state-changing requests (plan section 4: "same-origin
//! `Origin` on mutations").
//!
//! The UI authenticates with the `tenko_session` cookie (`SameSite=Strict`), which already
//! keeps cross-site requests from carrying it; this guard is the second line. Rules, for
//! every method other than `GET`, `HEAD` and `OPTIONS`:
//!
//! - An `Origin` header must equal the request's own origin (scheme and host as the trusted
//!   proxy rules see them), the configured public origin, or one of the allowed extra
//!   origins (development). `Origin: null` never matches.
//! - Without `Origin`, a request that carries the session cookie is refused, and so is one
//!   whose `Sec-Fetch-Site` is neither `same-origin` nor `none`: browsers send `Origin` on
//!   every state-changing request, so its absence next to a cookie is not a browser
//!   talking to its own origin.
//! - Requests without `Origin` and without the cookie pass: they come from non-browser
//!   clients such as the CLI, which authenticate with bearer tokens.

use axum::http::{HeaderMap, HeaderName, Method, header};

use crate::extract::{ClientInfo, normalize_origin, session_cookie};

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// Why the guard refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `Origin` names another origin.
    ForeignOrigin,
    /// No `Origin`, but a session cookie or a cross-site fetch.
    MissingOrigin,
}

/// Checks one request. `allowed` holds extra origins in normalized form
/// (`https://ddi.example.org`, `http://localhost:5173`).
pub(crate) fn check(
    method: &Method,
    headers: &HeaderMap,
    client: &ClientInfo,
    allowed: &[String],
) -> Result<(), Refusal> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    match headers.get(header::ORIGIN).map(|value| value.to_str()) {
        Some(Ok(origin)) => {
            let origin = normalize(origin).ok_or(Refusal::ForeignOrigin)?;
            let own = client.origin();
            if own.as_deref() == Some(origin.as_str()) || allowed.contains(&origin) {
                Ok(())
            } else {
                Err(Refusal::ForeignOrigin)
            }
        }
        Some(Err(_)) => Err(Refusal::ForeignOrigin),
        None => {
            let cross_site = headers
                .get(SEC_FETCH_SITE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|site| site != "same-origin" && site != "none");
            if cross_site || session_cookie(headers).is_some() {
                Err(Refusal::MissingOrigin)
            } else {
                Ok(())
            }
        }
    }
}

/// Normalizes an origin (`scheme://host[:port]`, lower case, default port dropped);
/// `None` for `null` and anything that is not an HTTP(S) origin.
pub(crate) fn normalize(origin: &str) -> Option<String> {
    let origin = origin.trim();
    let (scheme, rest) = origin.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let host = crate::extract::valid_host(rest.strip_suffix('/').unwrap_or(rest))?;
    Some(normalize_origin(&scheme, &host))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn client(https: bool, host: &str) -> ClientInfo {
        ClientInfo {
            https,
            host: Some(host.to_owned()),
            ..ClientInfo::default()
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn same_origin_mutations_pass() {
        let own = client(true, "ddi.example.org");
        for origin in ["https://ddi.example.org", "https://DDI.example.org:443"] {
            let h = headers(&[("origin", origin), ("cookie", "tenko_session=s")]);
            assert_eq!(check(&Method::POST, &h, &own, &[]), Ok(()), "{origin}");
        }
        let proxy_port = client(true, "ddi.example.org:8443");
        let h = headers(&[("origin", "https://ddi.example.org:8443")]);
        assert_eq!(check(&Method::PATCH, &h, &proxy_port, &[]), Ok(()));
    }

    #[test]
    fn foreign_origins_are_refused() {
        let own = client(true, "ddi.example.org");
        for origin in [
            "https://evil.example.com",
            "http://ddi.example.org",
            "https://ddi.example.org:8443",
            "null",
            "file://",
        ] {
            let h = headers(&[("origin", origin)]);
            assert_eq!(
                check(&Method::DELETE, &h, &own, &[]),
                Err(Refusal::ForeignOrigin),
                "{origin}"
            );
        }
    }

    #[test]
    fn allowed_extra_origins_pass() {
        let own = client(false, "127.0.0.1:8080");
        let h = headers(&[("origin", "http://localhost:5173")]);
        let allowed = vec![normalize("http://localhost:5173").expect("origin")];
        assert_eq!(check(&Method::POST, &h, &own, &allowed), Ok(()));
        assert_eq!(
            check(&Method::POST, &h, &own, &[]),
            Err(Refusal::ForeignOrigin)
        );
    }

    #[test]
    fn missing_origin_rules() {
        let own = client(true, "ddi.example.org");
        assert_eq!(
            check(&Method::POST, &HeaderMap::new(), &own, &[]),
            Ok(()),
            "CLI"
        );
        let bearer = headers(&[("authorization", "Bearer t")]);
        assert_eq!(check(&Method::POST, &bearer, &own, &[]), Ok(()));
        let cookie = headers(&[("cookie", "theme=dark; tenko_session=s")]);
        assert_eq!(
            check(&Method::POST, &cookie, &own, &[]),
            Err(Refusal::MissingOrigin)
        );
        let cross = headers(&[("sec-fetch-site", "cross-site")]);
        assert_eq!(
            check(&Method::PUT, &cross, &own, &[]),
            Err(Refusal::MissingOrigin)
        );
        let same = headers(&[("sec-fetch-site", "same-origin")]);
        assert_eq!(check(&Method::PUT, &same, &own, &[]), Ok(()));
    }

    #[test]
    fn safe_methods_are_not_checked() {
        let own = client(true, "ddi.example.org");
        let h = headers(&[
            ("origin", "https://evil.example.com"),
            ("cookie", "tenko_session=s"),
        ]);
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(check(&method, &h, &own, &[]), Ok(()));
        }
    }
}
