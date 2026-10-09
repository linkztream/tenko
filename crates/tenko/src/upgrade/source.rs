//! The release source (OPS-24, R17): fetching the manifest and downloading release files.
//!
//! The manifest request carries nothing but the running version (`User-Agent:
//! tenko/<version>`): no cookie, no identifier, no query. Release files are downloaded only
//! from the scheme, host and port of the configured source (the pinned source); redirects
//! are followed, as release hosting redirects to its storage. Sizes are bounded: the
//! manifest by [`MAX_MANIFEST_BYTES`], a file by the size the manifest gives.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use tenko_api::dto::release::{
    MAX_ASSET_BYTES, MAX_MANIFEST_BYTES, ReleaseAsset, ReleaseManifest, resolve_url,
};
use tenko_core::CodedError;

/// The client of the release source.
#[derive(Debug, Clone)]
pub struct Source {
    url: String,
    client: reqwest::Client,
}

/// A downloaded or uploaded file and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// The file.
    pub path: PathBuf,
    /// Bytes written.
    pub size: u64,
    /// SHA-256 as lowercase hexadecimal.
    pub sha256: String,
}

fn fetch_failed(detail: impl Into<String>) -> CodedError {
    CodedError::new("update.fetch_failed", 502, detail)
}

impl Source {
    /// A client for the manifest at `url`.
    ///
    /// # Errors
    ///
    /// `update.fetch_failed` when the HTTP client cannot be built.
    pub fn new(url: &str) -> Result<Self, CodedError> {
        let client = reqwest::Client::builder()
            .user_agent(format!("tenko/{}", crate::version()))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30 * 60))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|error| fetch_failed(format!("cannot build the HTTP client: {error}")))?;
        Ok(Self {
            url: url.trim().to_owned(),
            client,
        })
    }

    /// The manifest URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches and validates the manifest.
    ///
    /// # Errors
    ///
    /// `update.fetch_failed` for a failed request or a body over the limit, and the
    /// `update.manifest.*` codes of an invalid manifest (status 502).
    pub async fn manifest(&self) -> Result<ReleaseManifest, CodedError> {
        let response = self
            .client
            .get(&self.url)
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| fetch_failed(format!("the release source did not answer: {error}")))?;
        if !response.status().is_success() {
            return Err(
                fetch_failed(format!("the release source answered {}", response.status()))
                    .with_param("status", response.status().as_u16().to_string()),
            );
        }
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| fetch_failed(error.to_string()))?
        {
            if body.len() + chunk.len() > MAX_MANIFEST_BYTES {
                return Err(fetch_failed("the release manifest is larger than 1 MiB"));
            }
            body.extend_from_slice(&chunk);
        }
        ReleaseManifest::parse(&body)
            .map_err(|error| CodedError::new(error.code(), 502, error.to_string()))
    }

    /// The absolute URL of an asset, refused unless it has the scheme, host and port of
    /// the source (R17).
    ///
    /// # Errors
    ///
    /// `update.source_mismatch` (400) for another origin or an unusable URL.
    pub fn asset_url(&self, asset: &ReleaseAsset) -> Result<String, CodedError> {
        let url = resolve_url(&self.url, &asset.url).ok_or_else(|| {
            CodedError::new(
                "update.source_mismatch",
                400,
                format!("the release file URL `{}` cannot be used", asset.url),
            )
        })?;
        if origin(&url) != origin(&self.url) || origin(&url).is_none() {
            return Err(CodedError::new(
                "update.source_mismatch",
                400,
                format!(
                    "the release file {} is not on the release source {} (pinned source)",
                    url, self.url
                ),
            ));
        }
        Ok(url)
    }

    /// Downloads an asset into `path` (created; any old file is replaced), hashing as it
    /// writes, and refuses more bytes than the manifest gives.
    ///
    /// # Errors
    ///
    /// `update.source_mismatch`, `update.fetch_failed`, `update.size_mismatch` (413), or
    /// `update.io` for the file.
    pub async fn download(&self, asset: &ReleaseAsset, path: &Path) -> Result<Staged, CodedError> {
        let url = self.asset_url(asset)?;
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|error| fetch_failed(format!("the download did not start: {error}")))?;
        if !response.status().is_success() {
            return Err(fetch_failed(format!(
                "the release source answered {} for {}",
                response.status(),
                asset.name
            )));
        }
        let limit = asset.size.min(MAX_ASSET_BYTES);
        let mut writer = StagedWriter::create(path, limit)?;
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| fetch_failed(error.to_string()))?
        {
            writer.write(&chunk)?;
        }
        writer.finish()
    }
}

/// The scheme, host and port of an absolute http(s) URL, lower-cased.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?.to_ascii_lowercase();
    if host_port.is_empty() {
        return None;
    }
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let normalized = if host_port.ends_with(']') || !host_port.contains(':') {
        format!("{host_port}{default_port}")
    } else {
        host_port
    };
    Some(format!("{scheme}://{normalized}"))
}

/// Writes a staged file with a size limit, hashing every byte.
#[derive(Debug)]
pub struct StagedWriter {
    path: PathBuf,
    file: std::fs::File,
    hasher: Sha256,
    size: u64,
    limit: u64,
}

fn io_error(path: &Path, error: &std::io::Error) -> CodedError {
    CodedError::new("update.io", 500, format!("{}: {error}", path.display()))
}

impl StagedWriter {
    /// Creates (or truncates) `path`; at most `limit` bytes are accepted.
    ///
    /// # Errors
    ///
    /// `update.io`.
    pub fn create(path: &Path, limit: u64) -> Result<Self, CodedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| io_error(parent, &error))?;
        }
        let file = std::fs::File::create(path).map_err(|error| io_error(path, &error))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            hasher: Sha256::new(),
            size: 0,
            limit,
        })
    }

    /// Appends a chunk.
    ///
    /// # Errors
    ///
    /// `update.size_mismatch` (413) past the limit, `update.io`.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), CodedError> {
        let size = self.size + chunk.len() as u64;
        if size > self.limit {
            let _ = std::fs::remove_file(&self.path);
            return Err(CodedError::new(
                "update.size_mismatch",
                413,
                format!(
                    "the file is larger than the {} bytes the manifest gives",
                    self.limit
                ),
            ));
        }
        self.file
            .write_all(chunk)
            .map_err(|error| io_error(&self.path, &error))?;
        self.hasher.update(chunk);
        self.size = size;
        Ok(())
    }

    /// Syncs the file and returns its size and hash.
    ///
    /// # Errors
    ///
    /// `update.io`.
    pub fn finish(self) -> Result<Staged, CodedError> {
        self.file
            .sync_all()
            .map_err(|error| io_error(&self.path, &error))?;
        Ok(Staged {
            path: self.path,
            size: self.size,
            sha256: hex(&self.hasher.finalize()),
        })
    }
}

/// Lower-case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The SHA-256 of a file, streamed.
///
/// # Errors
///
/// `update.io`.
pub fn sha256_file(path: &Path) -> Result<(u64, String), CodedError> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|error| io_error(path, &error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(path, &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, hex(&hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(url: &str) -> ReleaseAsset {
        ReleaseAsset {
            platform: "linux-x86_64".to_owned(),
            name: "tenko-0.2.0-linux-x86_64".to_owned(),
            url: url.to_owned(),
            sha256: "0".repeat(64),
            size: 10,
            signature: None,
        }
    }

    #[test]
    fn origins_compare_scheme_host_and_port() {
        assert_eq!(
            origin("https://Releases.Example.com/a/b?c"),
            Some("https://releases.example.com:443".to_owned())
        );
        assert_eq!(
            origin("https://releases.example.com:443/x"),
            origin("https://releases.example.com/y")
        );
        assert_eq!(
            origin("http://[2001:db8::1]:8080/x"),
            Some("http://[2001:db8::1]:8080".to_owned())
        );
        assert_eq!(origin("ftp://example.com/x"), None);
        assert_eq!(origin("https:///x"), None);
    }

    #[test]
    fn release_files_must_come_from_the_source() {
        let source =
            Source::new("https://releases.example.com/latest/releases.json").expect("source");
        assert_eq!(
            source
                .asset_url(&asset("tenko-0.2.0-linux-x86_64"))
                .expect("relative"),
            "https://releases.example.com/latest/tenko-0.2.0-linux-x86_64"
        );
        assert!(
            source
                .asset_url(&asset("https://releases.example.com/v0.2.0/tenko"))
                .is_ok()
        );
        let other = source
            .asset_url(&asset("https://mirror.example.net/v0.2.0/tenko"))
            .expect_err("another host");
        assert_eq!(other.code, "update.source_mismatch");
        assert!(
            source
                .asset_url(&asset("http://releases.example.com/v0.2.0/tenko"))
                .is_err(),
            "another scheme"
        );
    }

    #[test]
    fn staged_files_are_hashed_and_bounded() {
        let dir = std::env::temp_dir().join(format!("tenko-source-test-{}", std::process::id()));
        let path = dir.join("file.part");
        let mut writer = StagedWriter::create(&path, 5).expect("create");
        writer.write(b"abc").expect("write");
        let staged = writer.finish().expect("finish");
        assert_eq!(staged.size, 3);
        assert_eq!(
            staged.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_file(&path).expect("hash"),
            (3, staged.sha256.clone())
        );
        let mut writer = StagedWriter::create(&path, 2).expect("create");
        let error = writer.write(b"abc").expect_err("too large");
        assert_eq!(error.code, "update.size_mismatch");
        assert!(!path.exists(), "an oversized file is removed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
