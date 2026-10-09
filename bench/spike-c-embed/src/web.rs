//! Static file serving (embedded or from a directory) and security headers.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, IF_NONE_MATCH, REFERRER_POLICY, VARY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::assets::{Asset, AssetTable};

/// Content Security Policy for a same-origin SPA that talks to its own API over
/// `fetch` and `EventSource`. No inline script or style, no plugins, no framing.
pub const CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; \
     connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
);
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
const REFERRER: HeaderValue = HeaderValue::from_static("no-referrer");
const SAME_ORIGIN: HeaderValue = HeaderValue::from_static("same-origin");
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// Adds the security headers to every response (UI, API and SSE alike) unless a handler
/// already set them.
pub async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    for (name, value) in [
        (X_CONTENT_TYPE_OPTIONS, NOSNIFF),
        (REFERRER_POLICY, REFERRER),
        (CONTENT_SECURITY_POLICY, CSP),
        (CROSS_ORIGIN_OPENER_POLICY, SAME_ORIGIN),
        (CROSS_ORIGIN_RESOURCE_POLICY, SAME_ORIGIN),
    ] {
        h.entry(name).or_insert(value);
    }
    res
}

/// Chosen content coding of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Brotli,
    Gzip,
}

/// Picks the best available coding from `Accept-Encoding` (RFC 9110 section 12.5.3).
/// Highest q wins; ties prefer br, then gzip, then identity. `*` covers codings not
/// listed explicitly. A missing header means identity.
pub fn negotiate(accept: Option<&HeaderValue>, has_br: bool, has_gzip: bool) -> Coding {
    let Some(accept) = accept.and_then(|v| v.to_str().ok()) else {
        return Coding::Identity;
    };
    let (mut q_br, mut q_gzip, mut q_star) = (None::<u16>, None::<u16>, None::<u16>);
    for item in accept.split(',') {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or("").trim();
        let mut q = 1000u16;
        for p in parts {
            let p = p.trim();
            if let Some(v) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                q = parse_qvalue(v.trim());
            }
        }
        if coding.eq_ignore_ascii_case("br") {
            q_br = Some(q);
        } else if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
            q_gzip = Some(q);
        } else if coding == "*" {
            q_star = Some(q);
        }
    }
    let q_br = if has_br {
        q_br.or(q_star).unwrap_or(0)
    } else {
        0
    };
    let q_gzip = if has_gzip {
        q_gzip.or(q_star).unwrap_or(0)
    } else {
        0
    };
    if q_br > 0 && q_br >= q_gzip {
        Coding::Brotli
    } else if q_gzip > 0 {
        Coding::Gzip
    } else {
        Coding::Identity
    }
}

/// Parses a qvalue (`0`, `0.5`, `1.000`) into thousandths; malformed values count as 0.
fn parse_qvalue(v: &str) -> u16 {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    let base: u16 = match int {
        "0" => 0,
        "1" => 1000,
        _ => return 0,
    };
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    let mut thousandths = 0u16;
    for (i, b) in frac.bytes().enumerate() {
        thousandths += u16::from(b - b'0') * [100, 10, 1][i];
    }
    (base + thousandths).min(1000)
}

/// Weak comparison of `If-None-Match` against the asset's content hash. The per-coding
/// suffix (`.br`, `.gz`) is ignored, so any representation the client holds validates.
pub fn etag_matches(if_none_match: &HeaderValue, base: &str) -> bool {
    let Ok(s) = if_none_match.to_str() else {
        return false;
    };
    s.split(',').any(|tag| {
        let tag = tag.trim();
        if tag == "*" {
            return true;
        }
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        let Some(opaque) = tag.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
            return false;
        };
        let opaque = opaque
            .strip_suffix(".br")
            .or_else(|| opaque.strip_suffix(".gz"))
            .unwrap_or(opaque);
        opaque == base
    })
}

fn plain(status: StatusCode, msg: &'static str) -> Response {
    let mut res = Response::new(Body::from(msg));
    *res.status_mut() = status;
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// Serves an asset from the embedded table.
///
/// - `GET`/`HEAD` only, anything else is 405.
/// - Exact path match first. A miss under `/assets/` is a 404 (a missing hashed file must
///   not turn into HTML). Any other miss is the SPA fallback to `index.html` with 200:
///   client routes in a DDI UI carry FQDNs and addresses (`/dns/zones/example.com`), so
///   "has a dot" cannot be used to tell files from routes.
/// - No directory listing exists: directories are not entries of the table.
pub async fn serve_embedded(State(table): State<Arc<AssetTable>>, req: Request) -> Response {
    let method = req.method();
    if method != Method::GET && method != Method::HEAD {
        let mut res = plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        res.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return res;
    }
    let rel = req.uri().path().trim_start_matches('/');
    let asset = match table.get(if rel.is_empty() { "index.html" } else { rel }) {
        Some(a) => a,
        None if rel == "assets" || rel.starts_with("assets/") => {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        }
        None => match table.index_html() {
            Some(a) => a,
            None => return plain(StatusCode::NOT_FOUND, "UI not embedded in this build\n"),
        },
    };
    respond(asset, req.headers(), method == Method::HEAD)
}

fn respond(asset: &Asset, req_headers: &HeaderMap, head: bool) -> Response {
    let coding = negotiate(
        req_headers.get(ACCEPT_ENCODING),
        asset.br.is_some(),
        asset.gzip.is_some(),
    );
    let (body, etag, encoding) = match coding {
        Coding::Brotli => (asset.br.as_ref(), &asset.etag_br, Some("br")),
        Coding::Gzip => (asset.gzip.as_ref(), &asset.etag_gzip, Some("gzip")),
        Coding::Identity => (Some(&asset.identity), &asset.etag_identity, None),
    };
    let body = body.unwrap_or(&asset.identity);

    let not_modified = req_headers
        .get(IF_NONE_MATCH)
        .is_some_and(|v| etag_matches(v, &asset.etag_base));
    let mut res = Response::new(if not_modified || head {
        Body::empty()
    } else {
        Body::from(Bytes::clone(body))
    });
    let h = res.headers_mut();
    h.insert(ETAG, etag.clone());
    h.insert(CACHE_CONTROL, asset.cache_control.clone());
    if asset.has_variants() {
        h.insert(VARY, HeaderValue::from_static("accept-encoding"));
    }
    if not_modified {
        *res.status_mut() = StatusCode::NOT_MODIFIED;
        return res;
    }
    h.insert(CONTENT_TYPE, asset.content_type.clone());
    if let Some(enc) = encoding {
        h.insert(CONTENT_ENCODING, HeaderValue::from_static(enc));
    }
    if head {
        h.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    res
}

/// Development mode: serve a directory from disk (`--ui-dir`) through tower-http's
/// `ServeDir`, so a rebuilt `ui/dist` is picked up without restarting the server.
/// Every response is `Cache-Control: no-cache`; `ServeDir` adds `Last-Modified` and
/// answers `If-Modified-Since`. Same fallback rules as the embedded mode: misses under
/// `/assets/` are 404, any other miss is `index.html`. `ServeDir` rejects `..` and never
/// lists directories.
pub fn dir_router(dir: &Path) -> Router {
    let assets = ServeDir::new(dir.join("assets"))
        .precompressed_br()
        .precompressed_gzip();
    let rest = ServeDir::new(dir)
        .precompressed_br()
        .precompressed_gzip()
        .fallback(ServeFile::new(dir.join("index.html")));
    Router::new()
        .nest_service("/assets", assets)
        .fallback_service(rest)
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv(s: &'static str) -> HeaderValue {
        HeaderValue::from_static(s)
    }

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(None, true, true), Coding::Identity);
        assert_eq!(
            negotiate(Some(&hv("gzip, deflate, br, zstd")), true, true),
            Coding::Brotli
        );
        assert_eq!(
            negotiate(Some(&hv("gzip, deflate")), true, true),
            Coding::Gzip
        );
        assert_eq!(
            negotiate(Some(&hv("br;q=0, gzip")), true, true),
            Coding::Gzip
        );
        assert_eq!(
            negotiate(Some(&hv("br;q=0.5, gzip;q=0.8")), true, true),
            Coding::Gzip
        );
        assert_eq!(negotiate(Some(&hv("*")), true, true), Coding::Brotli);
        assert_eq!(negotiate(Some(&hv("*;q=0")), true, true), Coding::Identity);
        assert_eq!(negotiate(Some(&hv("br")), false, true), Coding::Identity);
        assert_eq!(
            negotiate(Some(&hv("identity")), true, true),
            Coding::Identity
        );
        assert_eq!(
            negotiate(Some(&hv("gzip;q=1.000, br;q=0.999")), true, true),
            Coding::Gzip
        );
    }

    #[test]
    fn qvalues() {
        assert_eq!(parse_qvalue("1"), 1000);
        assert_eq!(parse_qvalue("0"), 0);
        assert_eq!(parse_qvalue("0.5"), 500);
        assert_eq!(parse_qvalue("0.05"), 50);
        assert_eq!(parse_qvalue("1.0"), 1000);
        assert_eq!(parse_qvalue("2"), 0);
        assert_eq!(parse_qvalue("0.1234"), 0);
    }

    #[test]
    fn etags() {
        assert!(etag_matches(&hv("\"abc\""), "abc"));
        assert!(etag_matches(&hv("\"abc.br\""), "abc"));
        assert!(etag_matches(&hv("W/\"abc.gz\""), "abc"));
        assert!(etag_matches(&hv("\"x\", \"abc\""), "abc"));
        assert!(etag_matches(&hv("*"), "abc"));
        assert!(!etag_matches(&hv("\"abd\""), "abc"));
        assert!(!etag_matches(&hv("abc"), "abc"));
    }
}
