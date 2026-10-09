//! The embedded asset table.
//!
//! `build.rs` stages the UI build into `$OUT_DIR/ui/{raw,br,gz}/`. One of three backends
//! embeds that tree into the binary; at startup it is turned into an [`AssetTable`] with
//! every header value precomputed, so serving a file is a hash lookup plus a refcount
//! increment on a `&'static [u8]`.

use std::collections::HashMap;

use axum::http::HeaderValue;
use bytes::Bytes;

use crate::mime;

/// Prefix of content-hashed build output (Vite `build.assetsDir`).
const IMMUTABLE_PREFIX: &str = "assets/";

/// `Cache-Control` for content-hashed files.
pub const CACHE_IMMUTABLE: HeaderValue =
    HeaderValue::from_static("public, max-age=31536000, immutable");
/// `Cache-Control` for everything else (`index.html`): always revalidate with the ETag.
pub const CACHE_REVALIDATE: HeaderValue = HeaderValue::from_static("no-cache");

/// One servable file with its encoded variants and precomputed headers.
pub struct Asset {
    pub identity: Bytes,
    pub br: Option<Bytes>,
    pub gzip: Option<Bytes>,
    pub content_type: HeaderValue,
    pub cache_control: HeaderValue,
    /// Hex content hash without quotes; the base of the per-encoding ETags.
    pub etag_base: Box<str>,
    pub etag_identity: HeaderValue,
    pub etag_br: HeaderValue,
    pub etag_gzip: HeaderValue,
}

impl Asset {
    fn new(
        path: &str,
        identity: Bytes,
        br: Option<Bytes>,
        gzip: Option<Bytes>,
        etag_hex: &str,
    ) -> Self {
        let etag = |suffix: &str| {
            HeaderValue::from_str(&format!("\"{etag_hex}{suffix}\""))
                .expect("hex ETag is a valid header value")
        };
        Self {
            identity,
            br,
            gzip,
            content_type: HeaderValue::from_static(mime::content_type(path)),
            cache_control: if path.starts_with(IMMUTABLE_PREFIX) {
                CACHE_IMMUTABLE
            } else {
                CACHE_REVALIDATE
            },
            etag_base: etag_hex.into(),
            etag_identity: etag(""),
            etag_br: etag(".br"),
            etag_gzip: etag(".gz"),
        }
    }

    pub fn has_variants(&self) -> bool {
        self.br.is_some() || self.gzip.is_some()
    }
}

/// All embedded files, keyed by their path relative to the UI root (`index.html`,
/// `assets/index-abc123.js`).
pub struct AssetTable {
    files: HashMap<Box<str>, Asset>,
    pub backend: &'static str,
}

/// Summary used in the startup log line.
pub struct TableStats {
    pub files: usize,
    pub identity_bytes: usize,
    pub br_files: usize,
    pub gzip_files: usize,
}

impl AssetTable {
    pub fn get(&self, path: &str) -> Option<&Asset> {
        self.files.get(path)
    }

    #[cfg(test)]
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(|k| &**k)
    }

    pub fn index_html(&self) -> Option<&Asset> {
        self.files.get("index.html")
    }

    pub fn stats(&self) -> TableStats {
        TableStats {
            files: self.files.len(),
            identity_bytes: self.files.values().map(|a| a.identity.len()).sum(),
            br_files: self.files.values().filter(|a| a.br.is_some()).count(),
            gzip_files: self.files.values().filter(|a| a.gzip.is_some()).count(),
        }
    }

    fn insert(
        &mut self,
        path: &str,
        identity: Bytes,
        br: Option<Bytes>,
        gzip: Option<Bytes>,
        etag_hex: &str,
    ) {
        let asset = Asset::new(path, identity, br, gzip, etag_hex);
        self.files.insert(path.into(), asset);
    }

    /// Builds the table from the backend selected at compile time.
    pub fn embedded() -> Self {
        backend::load()
    }
}

#[cfg(feature = "backend-codegen")]
mod backend {
    //! No embedding crate: `build.rs` generates a static table of `include_bytes!`
    //! entries, including the ETags, so startup does no hashing.
    use super::{AssetTable, Bytes, HashMap};

    pub struct GenFile {
        pub path: &'static str,
        pub etag: &'static str,
        pub identity: &'static [u8],
        pub br: Option<&'static [u8]>,
        pub gzip: Option<&'static [u8]>,
    }

    include!(concat!(env!("OUT_DIR"), "/codegen_assets.rs"));

    pub fn load() -> AssetTable {
        let mut table = AssetTable {
            files: HashMap::with_capacity(FILES.len()),
            backend: "codegen",
        };
        for f in FILES {
            table.insert(
                f.path,
                Bytes::from_static(f.identity),
                f.br.map(Bytes::from_static),
                f.gzip.map(Bytes::from_static),
                f.etag,
            );
        }
        table
    }
}

#[cfg(all(feature = "backend-rust-embed", not(feature = "backend-codegen")))]
mod backend {
    //! `rust-embed`: the derive embeds the staged tree; it also provides a SHA-256 per
    //! file, used for the ETag. With the `compression` feature the files are stored
    //! deflated and inflated here, once, into heap memory.
    use std::borrow::Cow;
    use std::fmt::Write as _;

    use rust_embed::RustEmbed;

    use super::{AssetTable, Bytes, HashMap};

    #[derive(RustEmbed)]
    #[folder = "$OUT_DIR/ui"]
    struct Ui;

    fn to_bytes(data: Cow<'static, [u8]>) -> Bytes {
        match data {
            Cow::Borrowed(b) => Bytes::from_static(b),
            Cow::Owned(v) => Bytes::from(v),
        }
    }

    pub fn load() -> AssetTable {
        let name = if cfg!(feature = "rust-embed-compression") {
            "rust-embed+deflate"
        } else {
            "rust-embed"
        };
        let mut table = AssetTable {
            files: HashMap::new(),
            backend: name,
        };
        for name in Ui::iter() {
            let Some(rel) = name.strip_prefix("raw/") else {
                continue;
            };
            let Some(file) = Ui::get(&name) else { continue };
            let mut etag = String::with_capacity(16);
            for b in &file.metadata.sha256_hash()[..8] {
                write!(etag, "{b:02x}").expect("write to string");
            }
            let br = Ui::get(&format!("br/{rel}")).map(|f| to_bytes(f.data));
            let gzip = Ui::get(&format!("gz/{rel}")).map(|f| to_bytes(f.data));
            table.insert(rel, to_bytes(file.data), br, gzip, &etag);
        }
        table
    }
}

#[cfg(all(
    feature = "backend-include-dir",
    not(feature = "backend-rust-embed"),
    not(feature = "backend-codegen")
))]
mod backend {
    //! `include_dir`: embeds the staged tree as a static `Dir`; it carries no hashes, so
    //! the ETag is an xxh3-64 computed at startup.
    use include_dir::{Dir, File, include_dir};

    use super::{AssetTable, Bytes, HashMap};

    static UI: Dir<'static> = include_dir!("$OUT_DIR/ui");

    fn walk(dir: &'static Dir<'static>, out: &mut Vec<&'static File<'static>>) {
        out.extend(dir.files());
        for d in dir.dirs() {
            walk(d, out);
        }
    }

    pub fn load() -> AssetTable {
        let mut table = AssetTable {
            files: HashMap::new(),
            backend: "include_dir",
        };
        let Some(raw) = UI.get_dir("raw") else {
            return table;
        };
        let mut files = Vec::new();
        walk(raw, &mut files);
        for file in files {
            // Paths are relative to the include root and may use `\` on Windows.
            let full = file.path().to_string_lossy().replace('\\', "/");
            let Some(rel) = full.strip_prefix("raw/") else {
                continue;
            };
            let etag = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(file.contents()));
            let variant = |v: &str| {
                UI.get_file(format!("{v}/{rel}"))
                    .map(|f| Bytes::from_static(f.contents()))
            };
            table.insert(
                rel,
                Bytes::from_static(file.contents()),
                variant("br"),
                variant("gz"),
                &etag,
            );
        }
        table
    }
}

#[cfg(not(any(
    feature = "backend-include-dir",
    feature = "backend-rust-embed",
    feature = "backend-codegen"
)))]
compile_error!(
    "enable one of the features backend-include-dir, backend-rust-embed, backend-codegen"
);
