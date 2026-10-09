//! Stages the web UI for embedding into `tenko-api`.
//!
//! The source directory is the UI build output: `TENKO_UI_DIST` (relative paths resolve
//! against the crate directory) or `../../ui/dist`. It must contain `index.html`; a missing UI
//! is a build error, never a silent empty UI (ADR 0008). Setting `TENKO_UI_STUB=1` swaps in a
//! small placeholder page generated into `$OUT_DIR/ui-stub/` and sets `--cfg tenko_ui_stub`, so
//! that Rust-only development does not need Node.js. The library refuses to compile such a
//! build in release mode.
//!
//! Layout of the staging tree `$OUT_DIR/ui`:
//! - `raw/<path>`: every file of the UI build, byte for byte.
//! - `br/<path>`, `gz/<path>`: brotli (quality 11) and gzip (best) variants of compressible
//!   files (see `src/ui/mime.rs`), written only when they are at least 5 % smaller.
//!
//! The script then writes `$OUT_DIR/ui_assets.rs`: a sorted static table of `GenFile` entries
//! whose bytes come from `include_bytes!`, with the first 16 hex characters of the SHA-256 of
//! each file as `ETag` base. Without the `server` feature the table is empty and the UI is not
//! needed at all.
#![forbid(unsafe_code)]

#[allow(dead_code, reason = "the content types are only needed by the server")]
#[path = "src/ui/mime.rs"]
mod mime;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

/// Placeholder `index.html`. No inline script and no inline style: the server's Content
/// Security Policy only allows `'self'` sources.
const STUB_INDEX: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="color-scheme" content="light dark" />
    <title>Tenko DDI</title>
    <link rel="stylesheet" href="/assets/tenko-stub.css" />
  </head>
  <body>
    <main class="stub">
      <h1>Tenko DDI</h1>
      <p class="notice">
        The web UI was not embedded in this build (<code>TENKO_UI_STUB=1</code>). The API is
        available under <code>/api/v1/</code>.
      </p>
      <ul class="links">
        <li><a href="/api/v1/openapi.json">OpenAPI document</a></li>
        <li><a href="/api/v1/health">Health check</a></li>
      </ul>
      <p class="hint">
        To embed the real UI, run <code>npm ci &amp;&amp; npm run build</code> in
        <code>ui/</code>, then build again without <code>TENKO_UI_STUB</code>.
      </p>
    </main>
  </body>
</html>
"#;

/// Placeholder stylesheet, light and dark.
const STUB_CSS: &str = r"/* Placeholder styles for builds with TENKO_UI_STUB=1. */
:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --fg: #1d2330;
  --muted: #56607a;
  --panel: #ffffff;
  --border: #d3d8e2;
  --accent: #1b5fd1;
  --code-bg: #eceff5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12161d;
    --fg: #e4e8f0;
    --muted: #9aa5bd;
    --panel: #1a202a;
    --border: #2c3442;
    --accent: #7fb0ff;
    --code-bg: #232b38;
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 2rem 1rem;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
}

.stub {
  max-width: 40rem;
  margin: 0 auto;
  padding: 1.5rem 2rem;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
}

h1 {
  margin-top: 0;
  font-size: 1.75rem;
}

.notice {
  padding: 0.75rem 1rem;
  border-left: 4px solid var(--accent);
  background: var(--code-bg);
}

.hint {
  color: var(--muted);
}

.links {
  padding-left: 1.25rem;
}

a {
  color: var(--accent);
}

code {
  padding: 0.1rem 0.35rem;
  border-radius: 0.25rem;
  background: var(--code-bg);
  font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
  font-size: 0.9em;
}
";

fn main() {
    println!("cargo::rerun-if-env-changed=TENKO_UI_STUB");
    println!("cargo::rerun-if-env-changed=TENKO_UI_DIST");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/ui/mime.rs");
    println!("cargo::rustc-check-cfg=cfg(tenko_ui_stub)");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let table = out_dir.join("ui_assets.rs");

    if env::var_os("CARGO_FEATURE_SERVER").is_none() {
        // Client-only build: no UI, no UI build required.
        fs::write(&table, "pub static FILES: &[GenFile] = &[];\n").expect("write ui_assets.rs");
        return;
    }

    let stage = out_dir.join("ui");
    let stub_dir = out_dir.join("ui-stub");
    remove_dir(&stage);
    remove_dir(&stub_dir);

    let src = if env_flag("TENKO_UI_STUB") {
        println!("cargo::rustc-cfg=tenko_ui_stub");
        write_stub(&stub_dir);
        stub_dir
    } else {
        let src = ui_dist_dir();
        println!("cargo::rerun-if-changed={}", src.display());
        assert!(
            src.join("index.html").is_file(),
            "UI build not found at {}: run `npm ci && npm run build` in ui/, or set \
             TENKO_UI_STUB=1 for a Rust-only development build",
            tidy(&src).display()
        );
        src
    };

    let mut files = Vec::new();
    collect(&src, &src, &mut files);
    files.sort();

    let mut code = String::from(
        "// Generated by build.rs. Do not edit.\n\
         /// The embedded UI files, sorted by path.\n\
         pub static FILES: &[GenFile] = &[\n",
    );
    for rel in &files {
        let bytes =
            fs::read(src.join(rel)).unwrap_or_else(|e| panic!("cannot read UI file {rel}: {e}"));
        let raw = write_staged(&stage, "raw", rel, &bytes);
        let (mut br, mut gz) = (None, None);
        if mime::is_compressible(rel) {
            let packed = brotli_compress(&bytes);
            if worth_it(packed.len(), bytes.len()) {
                br = Some(write_staged(&stage, "br", rel, &packed));
            }
            let packed = gzip_compress(&bytes);
            if worth_it(packed.len(), bytes.len()) {
                gz = Some(write_staged(&stage, "gz", rel, &packed));
            }
        }
        writeln!(
            code,
            "    GenFile {{ path: {rel:?}, etag: {etag:?}, identity: include_bytes!({raw:?}), \
             br: {br}, gzip: {gz} }},",
            etag = etag_base(&bytes),
            raw = utf8(&raw),
            br = include_option(br.as_deref()),
            gz = include_option(gz.as_deref()),
        )
        .expect("write to string");
    }
    code.push_str("];\n");
    fs::write(&table, code).expect("write ui_assets.rs");
}

/// `true` for `1`, `true` and `yes` (ASCII case-insensitive); anything else, or unset, is off.
fn env_flag(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| {
        value.to_str().is_some_and(|v| {
            ["1", "true", "yes"]
                .iter()
                .any(|on| v.eq_ignore_ascii_case(on))
        })
    })
}

/// The UI build directory: `TENKO_UI_DIST` (an empty value counts as unset; relative paths
/// resolve against the crate directory) or `<crate>/../../ui/dist`.
fn ui_dist_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    match env::var_os("TENKO_UI_DIST").filter(|v| !v.is_empty()) {
        // `join` keeps an absolute path as it is.
        Some(dir) => manifest_dir.join(dir),
        None => manifest_dir.join("../../ui/dist"),
    }
}

/// Resolves `.` and `..` components lexically, for error messages only.
fn tidy(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if out.file_name().is_some() => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Writes the placeholder UI below `dir`.
fn write_stub(dir: &Path) {
    write_file(&dir.join("index.html"), STUB_INDEX.as_bytes());
    write_file(
        &dir.join("assets").join("tenko-stub.css"),
        STUB_CSS.as_bytes(),
    );
}

fn remove_dir(dir: &Path) {
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap_or_else(|e| panic!("cannot clean {}: {e}", dir.display()));
    }
}

fn write_file(path: &Path, bytes: &[u8]) {
    let parent = path.parent().expect("file has a parent directory");
    fs::create_dir_all(parent)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
    fs::write(path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Recursively collects regular files below `dir` as `/`-separated paths relative to `root`.
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        let path = entry.path();
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("cannot stat {}: {e}", path.display()));
        if kind.is_dir() {
            collect(root, &path, out);
        } else if kind.is_file() {
            let rel = path.strip_prefix(root).expect("entry is below the root");
            let parts: Vec<&str> = rel
                .iter()
                .map(|part| {
                    part.to_str().unwrap_or_else(|| {
                        panic!(
                            "UI file name is not valid UTF-8: {}: rename the file in the UI build",
                            path.display()
                        )
                    })
                })
                .collect();
            out.push(parts.join("/"));
        } else {
            panic!(
                "unsupported entry in the UI build (symbolic link?): {}",
                path.display()
            );
        }
    }
}

/// Writes `bytes` to `<stage>/<variant>/<rel>` and returns that path.
fn write_staged(stage: &Path, variant: &str, rel: &str, bytes: &[u8]) -> PathBuf {
    let path = stage.join(variant).join(rel);
    write_file(&path, bytes);
    path
}

fn utf8(path: &Path) -> &str {
    path.to_str().unwrap_or_else(|| {
        panic!(
            "build directory path is not valid UTF-8: {}",
            path.display()
        )
    })
}

/// Rust expression for an optional staged variant.
fn include_option(path: Option<&Path>) -> String {
    match path {
        Some(p) => format!("Some(include_bytes!({:?}))", utf8(p)),
        None => "None".to_owned(),
    }
}

/// The first 16 lowercase hex characters of the SHA-256 of `bytes`. `AssetTable::from_files`
/// applies the same rule at run time.
fn etag_base(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        write!(hex, "{byte:02x}").expect("write to string");
    }
    hex
}

/// A compressed variant is kept only when it is at least 5 % smaller.
fn worth_it(compressed: usize, original: usize) -> bool {
    compressed * 100 <= original * 95
}

fn brotli_compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 3 + 64);
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 64 * 1024, 11, 22);
        writer.write_all(input).expect("brotli compression");
        writer.flush().expect("brotli flush");
    }
    out
}

fn gzip_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(
        Vec::with_capacity(input.len() / 3 + 64),
        flate2::Compression::best(),
    );
    encoder.write_all(input).expect("gzip compression");
    encoder.finish().expect("gzip finish")
}
