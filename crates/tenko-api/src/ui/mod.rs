//! The web UI, embedded in the server binary (ADR 0008).
//!
//! `build.rs` copies the UI build (`ui/dist`) into the binary together with brotli and gzip
//! variants of the text files, a content type and an `ETag` per file. Nothing is compressed or
//! hashed while serving. [`router`] returns an [`axum::Router`] that serves it; the server mounts
//! that router behind its API routes and adds the security headers to every response.
//!
//! Serving rules:
//!
//! - `GET` and `HEAD` only; any other method is 405 with `Allow: GET, HEAD`.
//! - An exact path match is served (`/` is `index.html`). Files under `assets/` have content
//!   hashed names and get `Cache-Control: public, max-age=31536000, immutable`; everything
//!   else, `index.html` included, gets `no-cache` and is revalidated with its `ETag`.
//! - The encoding follows `Accept-Encoding` with q-values (brotli, then gzip, then identity).
//!   Every representation has its own `ETag`, `Vary: accept-encoding` is set when variants
//!   exist, and a matching `If-None-Match` is answered with an empty 304.
//! - A miss under `assets/` (including `/assets` and `/assets/`) is a plain-text 404: a missing
//!   hashed file must never turn into HTML.
//! - A miss at `api` or below it is a plain-text 404 too: the API never falls back to the UI.
//! - Every other miss is the single-page-app fallback: `index.html` with status 200. The
//!   presence of a dot never decides, because client routes contain FQDNs and IP addresses
//!   (`/dns/zones/example.com`, `/ipam/192.0.2.0/24`).
//!
//! # Placeholder UI
//!
//! `TENKO_UI_STUB=1` at build time embeds a small placeholder page instead of the UI so that
//! Rust-only development does not need Node.js. [`UI_STUB`] reports it, and release builds
//! refuse to compile it. A missing UI build without `TENKO_UI_STUB` is a build error.
//!
//! # Development mode
//!
//! [`UiSource::Dir`] serves a directory from disk with the same routing rules, so that a
//! rebuilt UI is picked up without recompiling. Every response is `no-cache`.

#[cfg(all(tenko_ui_stub, not(debug_assertions)))]
compile_error!(
    "TENKO_UI_STUB=1 embeds a placeholder page instead of the web UI and is refused in release builds: build the UI first (cd ui && npm ci && npm run build) and unset TENKO_UI_STUB."
);

mod assets;
mod mime;
mod serve;

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use axum::Router;

pub use assets::{Asset, AssetTable, TableStats};
pub use serve::{Coding, negotiate};

/// Whether this build embeds the placeholder page (`TENKO_UI_STUB=1`) instead of the web UI.
pub const UI_STUB: bool = cfg!(tenko_ui_stub);

/// Where the UI is served from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UiSource {
    /// The UI embedded in the binary.
    #[default]
    Embedded,
    /// A directory on disk containing a UI build (development).
    Dir(PathBuf),
}

/// Why a UI router could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiError {
    /// The directory has no `index.html`; the path is the file that was expected.
    MissingIndex(PathBuf),
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIndex(path) => write!(
                f,
                "UI directory has no index.html: {} is not a file (build the UI with `npm run \
                 build` in ui/)",
                path.display()
            ),
        }
    }
}

impl Error for UiError {}

/// Builds the router that serves the UI from `source`.
///
/// # Errors
///
/// [`UiError::MissingIndex`] when `source` is a directory without an `index.html`.
pub fn router(source: &UiSource) -> Result<Router, UiError> {
    match source {
        UiSource::Embedded => Ok(serve::embedded_router(AssetTable::embedded())),
        UiSource::Dir(dir) => {
            let index = dir.join("index.html");
            if !index.is_file() {
                return Err(UiError::MissingIndex(index));
            }
            Ok(serve::dir_router(dir))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use super::*;

    /// A unique directory below the system temp dir, removed on drop (also after a panic).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "tenko-ui-test-{label}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Reply {
        status: StatusCode,
        content_type: Option<String>,
        cache_control: Option<String>,
        body: Vec<u8>,
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        Reply {
            status: parts.status,
            content_type: header("content-type"),
            cache_control: header("cache-control"),
            body: to_bytes(body, usize::MAX).await.unwrap().to_vec(),
        }
    }

    #[tokio::test]
    async fn dir_mode() {
        const INDEX: &str = "<!doctype html><html><body><div id=\"root\"></div></body></html>\n";
        let tmp = TempDir::new("dir-mode");
        fs::create_dir_all(tmp.path().join("assets")).unwrap();
        fs::write(tmp.path().join("index.html"), INDEX).unwrap();
        fs::write(
            tmp.path().join("assets").join("app.js"),
            "export const x = 1;\n",
        )
        .unwrap();

        let app = router(&UiSource::Dir(tmp.path().to_owned())).expect("router");
        for (path, status, html) in [
            ("/", StatusCode::OK, true),
            ("/index.html", StatusCode::OK, true),
            ("/dns/zones/example.com", StatusCode::OK, true),
            ("/ipam/192.0.2.0/24", StatusCode::OK, true),
            ("/assets/app.js", StatusCode::OK, false),
            ("/assets/missing.js", StatusCode::NOT_FOUND, false),
            ("/assets/", StatusCode::NOT_FOUND, false),
            ("/assets", StatusCode::NOT_FOUND, false),
            ("/api", StatusCode::NOT_FOUND, false),
            ("/api/", StatusCode::NOT_FOUND, false),
            ("/api/v1/x", StatusCode::NOT_FOUND, false),
            ("//api/v1/x", StatusCode::NOT_FOUND, false),
            ("/apiary", StatusCode::OK, true),
            // No path traversal: the parent directory is never reachable.
            ("/../Cargo.toml", StatusCode::OK, true),
            ("/assets/../../Cargo.toml", StatusCode::NOT_FOUND, false),
        ] {
            let r = get(&app, path).await;
            assert_eq!(r.status, status, "{path}");
            assert_eq!(r.cache_control.as_deref(), Some("no-cache"), "{path}");
            if html {
                assert!(
                    r.content_type.as_deref().unwrap().starts_with("text/html"),
                    "{path}"
                );
                assert_eq!(r.body, INDEX.as_bytes(), "{path}");
            }
        }
        let r = get(&app, "/assets/app.js").await;
        assert!(
            r.content_type
                .as_deref()
                .unwrap()
                .starts_with("text/javascript")
        );
        assert_eq!(r.body, b"export const x = 1;\n");
        let r = get(&app, "/api/v1/x").await;
        assert_eq!(r.content_type.as_deref(), Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn dir_mode_picks_up_changes_without_restart() {
        let tmp = TempDir::new("dir-reload");
        fs::write(tmp.path().join("index.html"), "<p>one</p>").unwrap();
        let app = router(&UiSource::Dir(tmp.path().to_owned())).expect("router");
        assert_eq!(get(&app, "/").await.body, b"<p>one</p>");
        fs::write(tmp.path().join("index.html"), "<p>two</p>").unwrap();
        assert_eq!(get(&app, "/").await.body, b"<p>two</p>");
    }

    #[test]
    fn dir_without_index_is_an_error() {
        let tmp = TempDir::new("dir-missing");
        let missing = tmp.path().join("does-not-exist");
        let err = router(&UiSource::Dir(missing.clone())).expect_err("no such directory");
        assert_eq!(err, UiError::MissingIndex(missing.join("index.html")));

        // An existing directory without index.html, and an index.html that is a directory.
        assert!(matches!(
            router(&UiSource::Dir(tmp.path().to_owned())),
            Err(UiError::MissingIndex(_))
        ));
        fs::create_dir_all(tmp.path().join("index.html")).unwrap();
        assert!(matches!(
            router(&UiSource::Dir(tmp.path().to_owned())),
            Err(UiError::MissingIndex(_))
        ));

        let text = err.to_string();
        assert!(text.contains("index.html"), "{text}");
        let _: &dyn Error = &err;
    }

    #[test]
    fn source_defaults_to_embedded() {
        assert_eq!(UiSource::default(), UiSource::Embedded);
        assert_eq!(UI_STUB, AssetTable::is_stub());
    }

    #[tokio::test]
    async fn embedded_router_serves_the_embedded_ui() {
        let app = router(&UiSource::Embedded).expect("router");
        let r = get(&app, "/").await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.content_type.as_deref(), Some("text/html; charset=utf-8"));
        assert_eq!(r.cache_control.as_deref(), Some("no-cache"));
        let html = String::from_utf8(r.body).unwrap();
        if UI_STUB {
            assert!(html.contains("TENKO_UI_STUB"));
        } else {
            assert!(html.contains("<div id=\"root\">"));
        }
        // Client routes fall back to the same document; the API does not.
        assert_eq!(
            get(&app, "/dns/zones/example.com").await.status,
            StatusCode::OK
        );
        assert_eq!(
            get(&app, "/api/v1/health").await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&app, "/assets/missing-abc123.js").await.status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn embedded_table_has_the_ui() {
        let table = AssetTable::embedded();
        let index = table.index_html().expect("index.html is embedded");
        let html = std::str::from_utf8(&index.identity).expect("index.html is UTF-8");
        if UI_STUB {
            assert!(html.contains("TENKO_UI_STUB"));
            assert!(html.contains("/api/v1/openapi.json") && html.contains("/api/v1/health"));
            // The placeholder obeys the CSP of the server: no inline script, no inline style.
            for forbidden in ["<script", "<style", " style=", " onclick=", "javascript:"] {
                assert!(!html.contains(forbidden), "{forbidden}");
            }
            assert!(html.contains("href=\"/assets/tenko-stub.css\""));
            let css = table.get("assets/tenko-stub.css").expect("stub stylesheet");
            assert_eq!(css.content_type, "text/css; charset=utf-8");
            assert_eq!(css.cache_control, "public, max-age=31536000, immutable");
            assert_eq!(table.stats().files, 2);
        } else {
            assert!(html.contains("<div id=\"root\">"));
            assert!(table.stats().files >= 3);
            // Every asset referenced by index.html is part of the table.
            for attr in ["src=\"/", "href=\"/"] {
                for part in html.split(attr).skip(1) {
                    let path = part.split('"').next().unwrap();
                    assert!(
                        table.get(path).is_some(),
                        "index.html references missing {path}"
                    );
                }
            }
        }
    }
}
