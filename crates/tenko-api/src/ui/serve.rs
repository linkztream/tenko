//! Static file serving: the embedded table and, for development, a directory on disk.
//!
//! Neither path adds security headers; the server adds them to every response (UI, API and
//! SSE alike).

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    IF_NONE_MATCH, VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use bytes::Bytes;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use super::assets::{Asset, AssetTable};

/// Chosen content coding of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    /// The file as it is, no `Content-Encoding`.
    Identity,
    /// Brotli (`br`).
    Brotli,
    /// Gzip.
    Gzip,
}

/// Picks the best available coding from `Accept-Encoding` (RFC 9110 section 12.5.3).
///
/// The highest q-value wins; ties prefer brotli, then gzip, then identity. `*` covers the
/// codings not listed explicitly. A missing or unreadable header means identity.
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

/// Weak comparison of `If-None-Match` against the asset's content hash. The per-coding suffix
/// (`.br`, `.gz`) is ignored, so any representation the client holds validates. `*` matches.
fn etag_matches(if_none_match: &HeaderValue, base: &str) -> bool {
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

fn not_found() -> Response {
    plain(StatusCode::NOT_FOUND, "not found\n")
}

/// Whether a request path (without its leading slashes) belongs to the API namespace, which
/// never falls back to the UI.
fn is_api(rel: &str) -> bool {
    rel == "api" || rel.starts_with("api/")
}

/// Whether a request path (without its leading slashes) is the hashed-asset namespace, where
/// a miss must be a 404 and never HTML.
fn is_assets(rel: &str) -> bool {
    rel == "assets" || rel.starts_with("assets/")
}

/// A router that serves `table` for every path and method.
pub(crate) fn embedded_router(table: Arc<AssetTable>) -> Router {
    Router::new().fallback(serve_embedded).with_state(table)
}

/// Serves an asset from the embedded table.
///
/// - `GET` and `HEAD` only; anything else is 405 with `Allow: GET, HEAD`.
/// - The exact path comes first (the empty path is `index.html`). A miss under `assets/`
///   (including `/assets` and `/assets/`) is a 404, because a missing hashed file must not
///   turn into HTML. A miss at `api` or below it is a 404 as well: the API never falls back
///   to the UI. Every other miss is the single-page-app fallback to `index.html` with 200.
///   The presence of a dot never decides, because client routes carry FQDNs and addresses
///   (`/dns/zones/example.com`).
/// - No directory listing exists: directories are not entries of the table.
async fn serve_embedded(State(table): State<Arc<AssetTable>>, req: Request) -> Response {
    let method = req.method();
    if method != Method::GET && method != Method::HEAD {
        let mut res = plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        res.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return res;
    }
    let rel = req.uri().path().trim_start_matches('/');
    let asset = match table.get(if rel.is_empty() { "index.html" } else { rel }) {
        Some(asset) => asset,
        None if is_assets(rel) || is_api(rel) => return not_found(),
        None => match table.index_html() {
            Some(index) => index,
            None => return plain(StatusCode::NOT_FOUND, "UI not embedded in this build\n"),
        },
    };
    respond(asset, req.headers(), method == Method::HEAD)
}

/// Builds the response for `asset`: negotiated encoding, per-representation `ETag`,
/// `Vary` when variants exist, 304 on a matching `If-None-Match`, no body for `HEAD`.
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

/// Development mode: serves a directory from disk through tower-http's `ServeDir`, so that a
/// rebuilt UI is picked up without restarting the server.
///
/// Every response is `Cache-Control: no-cache`; `ServeDir` adds `Last-Modified` and answers
/// `If-Modified-Since`, and serves `.br` and `.gz` siblings when the client accepts them.
/// The routing rules match the embedded mode: a miss under `/assets` is a 404, `/api` and
/// everything below it is a 404, and any other miss is `index.html`. `ServeDir` rejects `..`
/// and never lists directories.
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
        .layer(middleware::from_fn(reject_api))
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
}

/// Answers 404 for `/api` and everything below it, before the directory service can turn the
/// path into the SPA fallback.
async fn reject_api(req: Request, next: Next) -> Response {
    if is_api(req.uri().path().trim_start_matches('/')) {
        return not_found();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use axum::body::to_bytes;
    use axum::http::header::HeaderName;
    use tower::ServiceExt as _;

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
        // A coding the asset lacks is never chosen, whatever the client prefers.
        assert_eq!(negotiate(Some(&hv("br, gzip")), false, true), Coding::Gzip);
        assert_eq!(
            negotiate(Some(&hv("br, gzip")), true, false),
            Coding::Brotli
        );
        assert_eq!(
            negotiate(Some(&hv("br, gzip")), false, false),
            Coding::Identity
        );
        // Case-insensitive coding names, `x-gzip` alias, malformed q-values count as 0.
        assert_eq!(negotiate(Some(&hv("BR")), true, true), Coding::Brotli);
        assert_eq!(negotiate(Some(&hv("x-gzip")), true, true), Coding::Gzip);
        assert_eq!(
            negotiate(Some(&hv("br;q=abc, gzip")), true, true),
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

    // ---- embedded router -------------------------------------------------------------------

    const INDEX_BR: &[u8] = b"index-brotli-payload";
    const INDEX_GZ: &[u8] = b"index-gzip-payload";
    const JS_BR: &[u8] = b"js-brotli-payload";
    const JS_GZ: &[u8] = b"js-gzip-payload";
    const JS: &str = "assets/app-3f2a9c.js";
    const PNG: &str = "assets/logo-3f2a9c.png";

    /// A synthetic bundle: HTML and JS of at least 2 KiB with (made-up) variants, and a PNG
    /// without any.
    fn bundle() -> (Arc<AssetTable>, String, String) {
        let mut html =
            String::from("<!doctype html><html lang=\"en\"><body><div id=\"root\"></div>\n");
        let mut js = String::new();
        for i in 0..80 {
            writeln!(
                html,
                "<p>Placeholder paragraph number {i} of the test page.</p>"
            )
            .unwrap();
            writeln!(js, "export const value{i} = {i} * 2; // filler line {i}").unwrap();
        }
        html.push_str("</body></html>\n");
        assert!(html.len() >= 2048 && js.len() >= 2048);
        let table = AssetTable::from_files(vec![
            (
                "index.html".to_owned(),
                Bytes::from(html.clone()),
                Some(Bytes::from_static(INDEX_BR)),
                Some(Bytes::from_static(INDEX_GZ)),
            ),
            (
                JS.to_owned(),
                Bytes::from(js.clone()),
                Some(Bytes::from_static(JS_BR)),
                Some(Bytes::from_static(JS_GZ)),
            ),
            (
                PNG.to_owned(),
                Bytes::from_static(b"\x89PNG\r\n\x1a\n\x00\x01\x02"),
                None,
                None,
            ),
        ]);
        (Arc::new(table), html, js)
    }

    async fn send(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> Reply {
        let mut req = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = res.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: to_bytes(body, usize::MAX).await.unwrap(),
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).map(|v| v.to_str().unwrap())
        }
    }

    #[tokio::test]
    async fn index_negotiation_and_validation() {
        let (table, html, _) = bundle();
        let app = embedded_router(table);

        let r = send(&app, "GET", "/", &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(r.header("cache-control"), Some("no-cache"));
        assert_eq!(r.header("vary"), Some("accept-encoding"));
        assert!(r.header("content-encoding").is_none());
        assert_eq!(r.body, html.as_bytes());
        let etag = r.header("etag").expect("etag").to_owned();

        let r = send(&app, "GET", "/", &[("if-none-match", &etag)]).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED);
        assert!(r.body.is_empty());
        assert_eq!(r.header("etag"), Some(etag.as_str()));
        assert!(r.header("content-type").is_none());

        let r = send(
            &app,
            "GET",
            "/",
            &[("accept-encoding", "gzip, deflate, br")],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("content-encoding"), Some("br"));
        assert_eq!(r.header("vary"), Some("accept-encoding"));
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(r.body, INDEX_BR);
        let br_etag = r.header("etag").expect("etag").to_owned();
        assert_ne!(br_etag, etag);
        let r = send(
            &app,
            "GET",
            "/",
            &[
                ("accept-encoding", "gzip, deflate, br"),
                ("if-none-match", &br_etag),
            ],
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED);
        assert!(r.body.is_empty());
        // Any representation validates any other: the suffix is ignored.
        let r = send(&app, "GET", "/", &[("if-none-match", &br_etag)]).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED);
        let r = send(&app, "GET", "/", &[("if-none-match", "*")]).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED);
        let r = send(
            &app,
            "GET",
            "/",
            &[("if-none-match", "\"0000000000000000\"")],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);

        let r = send(&app, "GET", "/", &[("accept-encoding", "gzip")]).await;
        assert_eq!(r.header("content-encoding"), Some("gzip"));
        assert_eq!(r.body, INDEX_GZ);
        assert_ne!(r.header("etag"), Some(etag.as_str()));
        assert_ne!(r.header("etag"), Some(br_etag.as_str()));

        let r = send(&app, "GET", "/", &[("accept-encoding", "br;q=0, gzip")]).await;
        assert_eq!(r.header("content-encoding"), Some("gzip"));
        assert_eq!(r.body, INDEX_GZ);

        let r = send(&app, "GET", "/", &[("accept-encoding", "identity")]).await;
        assert!(r.header("content-encoding").is_none());
        assert_eq!(r.body, html.as_bytes());

        // Explicitly requesting index.html is the same file.
        let r = send(&app, "GET", "/index.html", &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("etag"), Some(etag.as_str()));
    }

    #[tokio::test]
    async fn hashed_assets() {
        let (table, _, js) = bundle();
        let app = embedded_router(Arc::clone(&table));

        let r = send(&app, "GET", &format!("/{JS}"), &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            r.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(r.body, js.as_bytes());

        let r = send(&app, "GET", &format!("/{JS}"), &[("accept-encoding", "br")]).await;
        assert_eq!(r.header("content-encoding"), Some("br"));
        assert_eq!(r.body, JS_BR);

        let r = send(&app, "HEAD", &format!("/{JS}"), &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.body.is_empty());
        assert_eq!(
            r.header("content-length"),
            Some(js.len().to_string().as_str())
        );
        assert_eq!(
            r.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );

        // HEAD reports the length of the negotiated representation.
        let r = send(
            &app,
            "HEAD",
            &format!("/{JS}"),
            &[("accept-encoding", "gzip")],
        )
        .await;
        assert!(r.body.is_empty());
        assert_eq!(r.header("content-encoding"), Some("gzip"));
        assert_eq!(
            r.header("content-length"),
            Some(JS_GZ.len().to_string().as_str())
        );

        // A file without variants: no Vary, no encoding, whatever the client accepts.
        let r = send(
            &app,
            "GET",
            &format!("/{PNG}"),
            &[("accept-encoding", "br, gzip")],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.header("content-type"), Some("image/png"));
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        assert!(r.header("vary").is_none());
        assert!(r.header("content-encoding").is_none());
        assert_eq!(r.body, table.get(PNG).unwrap().identity);

        // The handler adds no security headers; the server does that for every response.
        for name in [
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
        ] {
            assert!(
                r.headers.get(HeaderName::from_static(name)).is_none(),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn spa_fallback_and_misses() {
        let (table, html, _) = bundle();
        let app = embedded_router(table);

        // Client routes, including ones that contain dots, addresses and trailing slashes.
        for path in [
            "/ipam",
            "/ipam/",
            "/dns/zones/example.com",
            "/ipam/192.0.2.0/24",
            "/hosts/host.example.org",
            "/hosts/2001:db8::1",
            "/apiary",
            "/api-docs",
            "/assetsx",
            "/assets-old/app.js",
        ] {
            let r = send(&app, "GET", path, &[]).await;
            assert_eq!(r.status, StatusCode::OK, "{path}");
            assert_eq!(
                r.header("content-type"),
                Some("text/html; charset=utf-8"),
                "{path}"
            );
            assert_eq!(r.header("cache-control"), Some("no-cache"), "{path}");
            assert_eq!(r.body, html.as_bytes(), "{path}");
        }
        // The fallback negotiates like the index does.
        let r = send(&app, "GET", "/ipam", &[("accept-encoding", "br")]).await;
        assert_eq!(r.header("content-encoding"), Some("br"));
        let r = send(&app, "HEAD", "/dns/zones/example.com", &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.body.is_empty());
        assert_eq!(
            r.header("content-length"),
            Some(html.len().to_string().as_str())
        );

        // No fallback under /assets and none for the API namespace.
        for path in [
            "/assets/missing-abc123.js",
            "/assets/",
            "/assets",
            "/assets/sub/dir/",
            "//assets/missing.js",
            "/api",
            "/api/",
            "/api/v2/nope",
            "//api/v1/nope",
        ] {
            for method in ["GET", "HEAD"] {
                let r = send(&app, method, path, &[]).await;
                assert_eq!(r.status, StatusCode::NOT_FOUND, "{method} {path}");
                assert_eq!(
                    r.header("content-type"),
                    Some("text/plain; charset=utf-8"),
                    "{method} {path}"
                );
            }
        }
        let r = send(&app, "GET", "/api/v2/nope", &[]).await;
        assert_eq!(r.body, "not found\n");
    }

    #[tokio::test]
    async fn only_get_and_head() {
        let (table, _, _) = bundle();
        let app = embedded_router(table);
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            for path in [
                "/",
                "/ipam",
                &format!("/{JS}"),
                "/api/v1/x",
                "/assets/nope.js",
            ] {
                let r = send(&app, method, path, &[]).await;
                assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
                assert_eq!(r.header("allow"), Some("GET, HEAD"), "{method} {path}");
                assert_eq!(
                    r.header("content-type"),
                    Some("text/plain; charset=utf-8"),
                    "{method} {path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn table_without_index() {
        let table = AssetTable::from_files(vec![(
            "assets/only-1.js".to_owned(),
            Bytes::from_static(b"1"),
            None,
            None,
        )]);
        let app = embedded_router(Arc::new(table));
        let r = send(&app, "GET", "/", &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        let r = send(&app, "GET", "/ipam", &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        let r = send(&app, "GET", "/assets/only-1.js", &[]).await;
        assert_eq!(r.status, StatusCode::OK);
    }
}
