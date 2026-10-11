//! Content types and compressibility by file extension.
//!
//! This file is shared by `build.rs` (through `#[path]`) and the server, so that the
//! build-time pre-compression and the run-time headers agree on which files are text. It
//! therefore must not depend on anything else in the crate.

/// Returns the extension of the last path segment, or `""` when there is none. A leading dot
/// alone (`.well-known`) is a name, not an extension.
fn extension(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext,
        _ => "",
    }
}

/// ASCII case-insensitive membership test.
fn ext_is(ext: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|c| ext.eq_ignore_ascii_case(c))
}

/// `Content-Type` for a file path. Text types carry `charset=utf-8`; unknown extensions are
/// `application/octet-stream`.
pub fn content_type(path: &str) -> &'static str {
    let ext = extension(path);
    if ext_is(ext, &["html", "htm"]) {
        "text/html; charset=utf-8"
    } else if ext_is(ext, &["js", "mjs"]) {
        "text/javascript; charset=utf-8"
    } else if ext_is(ext, &["css"]) {
        "text/css; charset=utf-8"
    } else if ext_is(ext, &["json", "map"]) {
        "application/json"
    } else if ext_is(ext, &["webmanifest"]) {
        "application/manifest+json"
    } else if ext_is(ext, &["svg"]) {
        "image/svg+xml"
    } else if ext_is(ext, &["png"]) {
        "image/png"
    } else if ext_is(ext, &["jpg", "jpeg"]) {
        "image/jpeg"
    } else if ext_is(ext, &["gif"]) {
        "image/gif"
    } else if ext_is(ext, &["webp"]) {
        "image/webp"
    } else if ext_is(ext, &["avif"]) {
        "image/avif"
    } else if ext_is(ext, &["ico"]) {
        "image/x-icon"
    } else if ext_is(ext, &["woff2"]) {
        "font/woff2"
    } else if ext_is(ext, &["woff"]) {
        "font/woff"
    } else if ext_is(ext, &["ttf"]) {
        "font/ttf"
    } else if ext_is(ext, &["wasm"]) {
        "application/wasm"
    } else if ext_is(ext, &["txt"]) {
        "text/plain; charset=utf-8"
    } else if ext_is(ext, &["xml"]) {
        "application/xml"
    } else if ext_is(ext, &["xlf", "xliff"]) {
        "application/xliff+xml"
    } else {
        "application/octet-stream"
    }
}

/// Whether a file is worth pre-compressing: text formats and WebAssembly. Already
/// compressed formats (images, fonts) are left alone.
#[allow(
    dead_code,
    reason = "only build.rs calls this; the server reads the generated table"
)]
pub fn is_compressible(path: &str) -> bool {
    ext_is(
        extension(path),
        &[
            "html",
            "htm",
            "js",
            "mjs",
            "css",
            "svg",
            "json",
            "map",
            "webmanifest",
            "txt",
            "xml",
            "xlf",
            "xliff",
            "wasm",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(
            content_type("assets/index-abc123.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type("assets/index-abc123.CSS"),
            "text/css; charset=utf-8"
        );
        assert_eq!(content_type("assets/logo.svg"), "image/svg+xml");
        assert_eq!(content_type("assets/logo.png"), "image/png");
        assert_eq!(content_type("assets/font.woff2"), "font/woff2");
        assert_eq!(content_type("i18n/sv.xlf"), "application/xliff+xml");
        assert_eq!(content_type("assets/blob.bin"), "application/octet-stream");
        assert_eq!(
            content_type("assets/no-extension"),
            "application/octet-stream"
        );
        assert_eq!(content_type(".well-known"), "application/octet-stream");
        assert_eq!(content_type("dir.js/readme"), "application/octet-stream");
    }

    #[test]
    fn compressibility() {
        for path in [
            "index.html",
            "assets/a.js",
            "assets/a.css",
            "a.svg",
            "a.json",
            "a.WASM",
            "i18n/en.xlf",
        ] {
            assert!(is_compressible(path), "{path}");
        }
        for path in [
            "a.png", "a.woff2", "a.jpg", "a.webp", "a.bin", "noext", ".js",
        ] {
            assert!(!is_compressible(path), "{path}");
        }
    }
}
