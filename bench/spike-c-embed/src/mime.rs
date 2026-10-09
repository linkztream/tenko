//! Content types and compressibility by file extension.
//!
//! Shared by `build.rs` (through `#[path]`) and the server, so that the build-time
//! pre-compression and the runtime agree on which files are text.

/// Returns the lower-case-insensitive extension of the last path segment, if any.
fn extension(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext,
        _ => "",
    }
}

fn ext_is(ext: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|c| ext.eq_ignore_ascii_case(c))
}

/// `Content-Type` for a file path. Text types carry `charset=utf-8`.
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
    } else {
        "application/octet-stream"
    }
}

/// Whether a file is worth pre-compressing (text formats and wasm). Used by `build.rs`.
#[allow(dead_code)]
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
            "wasm",
        ],
    )
}
