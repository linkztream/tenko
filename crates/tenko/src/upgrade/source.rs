//! The release source (OPS-24, R17): fetching the manifest and downloading release files.
//!
//! The manifest request carries nothing but the running version (`User-Agent:
//! tenko/<version>`): no cookie, no identifier, no query. Every URL the client asks for, and
//! every redirect it follows, is checked against the pinned location ([`Pin`]): the release
//! prefix (scheme, host, port and a path prefix, `updates.release_prefix`) and the exact
//! host names a response may redirect to (`updates.redirect_hosts`, the object storage of
//! the release hosting). The check parses with the URL type of the HTTP client
//! (`reqwest::Url`, the WHATWG parser), not a parser of its own, and refuses what two
//! readers could take apart differently (credentials, backslashes, encoded separators). Redirects never go from
//! HTTPS to plain HTTP and are at most [`MAX_REDIRECTS`]. Sizes are bounded: the manifest by
//! [`MAX_MANIFEST_BYTES`], a file by the size the manifest gives.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

use std::{
    io::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use reqwest::Url;
use sha2::{Digest as _, Sha256};
use tenko_api::dto::release::{MAX_ASSET_BYTES, MAX_MANIFEST_BYTES, ReleaseAsset, ReleaseManifest};
use tenko_core::CodedError;

/// The most redirects one request follows.
pub const MAX_REDIRECTS: usize = 3;

/// The object storage that the default release hosting redirects its downloads to, observed
/// on 2026-11-10: `github.com/<owner>/<repo>/releases/download/<tag>/<file>` answers 302 with
/// a signed URL on this host.
pub const GITHUB_STORAGE_HOST: &str = "release-assets.githubusercontent.com";

/// The host of the default release hosting.
const GITHUB_HOST: &str = "github.com";

/// The most host names `updates.redirect_hosts` may list.
pub const MAX_REDIRECT_HOSTS: usize = 8;

/// The pinned location of the releases: what the client may request and where a redirect
/// may lead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The manifest URL (`updates.source_url`), inside the prefix.
    source: Url,
    /// The release prefix; its path ends with `/`.
    prefix: Url,
    /// Exact host names, lower case, reached over HTTPS on port 443 only after a redirect.
    redirect_hosts: Vec<String>,
}

/// Whether the host of `url` is the loopback host (`localhost`, `127.0.0.0/8`, `::1`).
fn is_loopback_host(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => {
            host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
                || host
                    .strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
        }
        None => false,
    }
}

/// A host name as `updates.redirect_hosts` takes it: letters, digits, hyphens and dots in
/// lower case, at least two labels, no wildcard, no port and no address.
fn valid_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').count() >= 2
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// A path that reads differently once a server decodes it: an encoded slash, backslash or
/// dot.
fn has_encoded_separator(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e")
}

/// Whether `url` uses HTTPS, or plain HTTP to the loopback host (tests).
fn usable_scheme(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => is_loopback_host(url),
        _ => false,
    }
}

impl Pin {
    /// The pin of `source_url` with the configured `prefix` and `redirect_hosts`, or their
    /// defaults: for a source of the form
    /// `https://<host>/<owner>/<repo>/releases/latest/download/<file>` the prefix is
    /// `https://<host>/<owner>/<repo>/releases/`, for any other source its directory; the
    /// redirect hosts are [`GITHUB_STORAGE_HOST`] while the source is on `github.com`, and
    /// none otherwise. A prefix without a final `/` gets one.
    ///
    /// # Errors
    ///
    /// A message that names the key: an unusable URL; a source or prefix that is not HTTPS
    /// (plain HTTP only on the loopback host, for tests); a prefix with credentials, a query,
    /// a fragment or an encoded separator; a source outside the prefix; a redirect host that
    /// is not an exact host name.
    pub fn new(
        source_url: &str,
        prefix: Option<&str>,
        redirect_hosts: Option<&[String]>,
    ) -> Result<Self, String> {
        let source = Url::parse(source_url.trim())
            .map_err(|error| format!("updates.source_url is not a URL: {error}"))?;
        if !source.username().is_empty() || source.password().is_some() {
            return Err("updates.source_url must have no user name or password".to_owned());
        }
        let prefix = match prefix {
            Some(text) => {
                let text = text.trim();
                let text = if text.ends_with('/') {
                    text.to_owned()
                } else {
                    format!("{text}/")
                };
                Url::parse(&text)
                    .map_err(|error| format!("updates.release_prefix is not a URL: {error}"))?
            }
            None => default_prefix(&source)?,
        };
        if !usable_scheme(&prefix) || !usable_scheme(&source) {
            return Err(
                "updates.source_url and updates.release_prefix must be https URLs (plain http \
                 only on the loopback host, for tests)"
                    .to_owned(),
            );
        }
        if !prefix.username().is_empty()
            || prefix.password().is_some()
            || prefix.query().is_some()
            || prefix.fragment().is_some()
            || has_encoded_separator(prefix.path())
        {
            return Err(
                "updates.release_prefix must have no user name, password, query, fragment or \
                 encoded separator"
                    .to_owned(),
            );
        }
        let hosts: Vec<String> = match redirect_hosts {
            Some(hosts) => hosts.iter().map(|host| host.trim().to_owned()).collect(),
            None if source.host_str() == Some(GITHUB_HOST) => {
                vec![GITHUB_STORAGE_HOST.to_owned()]
            }
            None => Vec::new(),
        };
        if hosts.len() > MAX_REDIRECT_HOSTS {
            return Err(format!(
                "updates.redirect_hosts lists more than {MAX_REDIRECT_HOSTS} hosts"
            ));
        }
        if let Some(own) = hosts
            .iter()
            .find(|host| prefix.host_str() == Some(host.as_str()))
        {
            return Err(format!(
                "updates.redirect_hosts: `{own}` is the host of the release prefix; a redirect \
                 there must stay inside the prefix, so it is not listed"
            ));
        }
        if let Some(bad) = hosts.iter().find(|host| !valid_host_name(host)) {
            return Err(format!(
                "updates.redirect_hosts: `{}` is not an exact host name in lower case (no \
                 wildcard, port or address)",
                bad.escape_debug()
            ));
        }
        let pin = Self {
            source,
            prefix,
            redirect_hosts: hosts,
        };
        if !pin.within_prefix(&pin.source) {
            return Err(format!(
                "updates.source_url {} is not inside updates.release_prefix {}",
                pin.source, pin.prefix
            ));
        }
        Ok(pin)
    }

    /// The manifest URL.
    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    /// The release prefix.
    pub fn prefix(&self) -> &str {
        self.prefix.as_str()
    }

    /// The hosts a redirect may lead to.
    pub fn redirect_hosts(&self) -> &[String] {
        &self.redirect_hosts
    }

    /// Whether `url` lies inside the release prefix: the same scheme, host and port, no
    /// credentials, and a path that starts with the prefix's path and has no encoded
    /// separator.
    pub fn within_prefix(&self, url: &Url) -> bool {
        url.scheme() == self.prefix.scheme()
            && url.host_str() == self.prefix.host_str()
            && url.port_or_known_default() == self.prefix.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path().starts_with(self.prefix.path())
            && !has_encoded_separator(url.path())
    }

    /// Whether `url` is on a listed redirect host, over HTTPS on port 443, without
    /// credentials. The comparison is exact: no suffix and no wildcard match.
    fn on_redirect_host(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url
                .host_str()
                .is_some_and(|name| self.redirect_hosts.iter().any(|host| host == name))
    }

    /// Whether a redirect from `from` to `to` may be followed. Both must be admitted: inside
    /// the prefix, or on a listed host. The first request of every chain is inside the
    /// prefix (the manifest URL, or an asset URL [`Pin::asset_url`] accepted), so a listed
    /// host is reached only through a response from inside the prefix, and a listed host
    /// can send the client only back into the prefix or to another listed host. An `https`
    /// URL never redirects to plain HTTP.
    pub fn admits_redirect(&self, from: &Url, to: &Url) -> bool {
        let admitted = |url: &Url| self.within_prefix(url) || self.on_redirect_host(url);
        admitted(from) && admitted(to) && !(from.scheme() == "https" && to.scheme() != "https")
    }

    /// The URL of an asset, resolved against the manifest URL by the client's parser, and
    /// refused unless it lies inside the release prefix.
    ///
    /// # Errors
    ///
    /// A message for an unusable URL or one outside the prefix.
    pub fn asset_url(&self, asset: &str) -> Result<Url, String> {
        if asset.is_empty()
            || asset
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        {
            return Err(format!(
                "the release file URL `{}` cannot be used",
                asset.escape_debug()
            ));
        }
        let url = self.source.join(asset).map_err(|error| {
            format!(
                "the release file URL `{}` cannot be used: {error}",
                asset.escape_debug()
            )
        })?;
        if self.within_prefix(&url) {
            Ok(url)
        } else {
            Err(format!(
                "the release file {url} is not under the release prefix {} (pinned source)",
                self.prefix
            ))
        }
    }
}

/// The default prefix of a source: the release path of a repository on release hosting, or
/// the source's directory.
fn default_prefix(source: &Url) -> Result<Url, String> {
    if source.cannot_be_a_base() {
        return Err("updates.source_url must be an http(s) URL with a path".to_owned());
    }
    let segments: Vec<&str> = source
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default();
    let n = segments.len();
    let release_hosting = n >= 6
        && segments[n - 4] == "releases"
        && segments[n - 3] == "latest"
        && segments[n - 2] == "download";
    let path = if release_hosting {
        format!("/{}/", segments[..n - 3].join("/"))
    } else {
        let path = source.path();
        path.rfind('/')
            .map_or_else(|| "/".to_owned(), |i| path[..=i].to_owned())
    };
    let mut prefix = source.clone();
    prefix.set_path(&path);
    prefix.set_query(None);
    prefix.set_fragment(None);
    Ok(prefix)
}

/// The client of the release source.
#[derive(Debug, Clone)]
pub struct Source {
    pin: Arc<Pin>,
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

/// A downloaded release file: the URL that was requested and the one the file finally came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    /// The file.
    pub staged: Staged,
    /// The asset URL of the manifest, resolved.
    pub requested: String,
    /// The URL of the response, after the redirects.
    pub final_url: String,
}

fn fetch_failed(detail: impl Into<String>) -> CodedError {
    CodedError::new("update.fetch_failed", 502, detail)
}

/// An error with its causes, so that a refused redirect says why.
fn chain(error: &reqwest::Error) -> String {
    let mut detail = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        detail = format!("{detail}: {inner}");
        cause = inner.source();
    }
    detail
}

impl Source {
    /// A client for the pinned location `pin`. It sends no cookie, no `Referer` and no
    /// header besides `User-Agent` and `Accept`, so nothing but the running version reaches
    /// a redirect host.
    ///
    /// # Errors
    ///
    /// `update.fetch_failed` when the HTTP client cannot be built.
    pub fn new(pin: Pin) -> Result<Self, CodedError> {
        let pin = Arc::new(pin);
        let redirects = Arc::clone(&pin);
        let client = reqwest::Client::builder()
            .user_agent(format!("tenko/{}", crate::version()))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30 * 60))
            // No `Referer` on a redirect: the storage host learns nothing of the prefix.
            .referer(false)
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > MAX_REDIRECTS {
                    return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
                }
                let admitted = attempt
                    .previous()
                    .last()
                    .is_some_and(|from| redirects.admits_redirect(from, attempt.url()));
                if admitted {
                    attempt.follow()
                } else {
                    let to = attempt.url().clone();
                    attempt.error(format!(
                        "the redirect to {to} leaves the release prefix and the redirect \
                         hosts (pinned source)"
                    ))
                }
            }))
            .build()
            .map_err(|error| fetch_failed(format!("cannot build the HTTP client: {error}")))?;
        Ok(Self { pin, client })
    }

    /// The manifest URL.
    pub fn url(&self) -> &str {
        self.pin.source()
    }

    /// The pinned location.
    pub fn pin(&self) -> &Pin {
        &self.pin
    }

    /// Fetches and validates the manifest.
    ///
    /// # Errors
    ///
    /// `update.fetch_failed` for a failed request, a refused redirect or a body over the
    /// limit, and the `update.manifest.*` codes of an invalid manifest (status 502).
    pub async fn manifest(&self) -> Result<ReleaseManifest, CodedError> {
        let response = self
            .client
            .get(self.pin.source.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| {
                fetch_failed(format!(
                    "the release source did not answer: {}",
                    chain(&error)
                ))
            })?;
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
            .map_err(|error| fetch_failed(chain(&error)))?
        {
            if body.len() + chunk.len() > MAX_MANIFEST_BYTES {
                return Err(fetch_failed("the release manifest is larger than 1 MiB"));
            }
            body.extend_from_slice(&chunk);
        }
        ReleaseManifest::parse(&body)
            .map_err(|error| CodedError::new(error.code(), 502, error.to_string()))
    }

    /// The absolute URL of an asset, refused unless it lies inside the release prefix (R17).
    ///
    /// # Errors
    ///
    /// `update.source_mismatch` (400) for a URL outside the prefix or an unusable URL.
    pub fn asset_url(&self, asset: &ReleaseAsset) -> Result<String, CodedError> {
        self.pin
            .asset_url(&asset.url)
            .map(String::from)
            .map_err(|detail| CodedError::new("update.source_mismatch", 400, detail))
    }

    /// Downloads an asset into `path` (created; any old file is replaced), hashing as it
    /// writes, and refuses more bytes than the manifest gives. The SHA-256 is of what
    /// finally arrived, after the redirects; the verify step compares it with the manifest.
    ///
    /// # Errors
    ///
    /// `update.source_mismatch`, `update.fetch_failed` (also for a refused redirect),
    /// `update.size_mismatch` (413), or `update.io` for the file.
    pub async fn download(
        &self,
        asset: &ReleaseAsset,
        path: &Path,
    ) -> Result<Downloaded, CodedError> {
        let url = self.asset_url(asset)?;
        let response = self.client.get(&url).send().await.map_err(|error| {
            fetch_failed(format!("the download did not start: {}", chain(&error)))
        })?;
        if !response.status().is_success() {
            return Err(fetch_failed(format!(
                "the release source answered {} for {}",
                response.status(),
                asset.name
            )));
        }
        let final_url = response.url().to_string();
        let limit = asset.size.min(MAX_ASSET_BYTES);
        let mut writer = StagedWriter::create(path, limit)?;
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| fetch_failed(chain(&error)))?
        {
            writer.write(&chunk)?;
        }
        Ok(Downloaded {
            staged: writer.finish()?,
            requested: url,
            final_url,
        })
    }
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

    const GITHUB_SOURCE: &str =
        "https://github.com/example-owner/tenko/releases/latest/download/releases.json";

    fn url(text: &str) -> Url {
        Url::parse(text).expect("a URL")
    }

    fn github() -> Pin {
        Pin::new(GITHUB_SOURCE, None, None).expect("the default pin")
    }

    #[test]
    fn the_default_prefix_is_the_release_path_of_the_repository() {
        let pin = github();
        assert_eq!(
            pin.prefix(),
            "https://github.com/example-owner/tenko/releases/"
        );
        assert_eq!(pin.redirect_hosts(), [GITHUB_STORAGE_HOST.to_owned()]);
        // A mirror: the directory of its manifest, and no redirect host.
        let mirror = Pin::new(
            "https://mirror.example.test/tenko/releases.json",
            None,
            None,
        )
        .expect("a mirror");
        assert_eq!(mirror.prefix(), "https://mirror.example.test/tenko/");
        assert_eq!(mirror.redirect_hosts(), &[] as &[String]);
        // An explicit prefix gets its final slash, and the source must lie inside it.
        let explicit = Pin::new(
            "https://mirror.example.test/tenko/latest/releases.json",
            Some("https://mirror.example.test/tenko"),
            Some(&[]),
        )
        .expect("an explicit prefix");
        assert_eq!(explicit.prefix(), "https://mirror.example.test/tenko/");
        let outside = Pin::new(
            "https://mirror.example.test/other/releases.json",
            Some("https://mirror.example.test/tenko/"),
            None,
        )
        .expect_err("the source outside the prefix");
        assert!(outside.contains("not inside"), "{outside}");
    }

    #[test]
    fn a_pin_refuses_plain_http_credentials_and_loose_host_names() {
        for (source, prefix, hosts, wanted) in [
            ("http://mirror.example.test/r.json", None, None, "https"),
            (
                "https://mirror.example.test/r.json",
                Some("http://mirror.example.test/"),
                None,
                "https",
            ),
            (
                "https://mirror.example.test/r.json",
                Some("https://user:secret@mirror.example.test/"),
                None,
                "user name",
            ),
            (
                "https://mirror.example.test/r.json",
                Some("https://mirror.example.test/?a=b"),
                None,
                "query",
            ),
            (
                "https://mirror.example.test/a/r.json",
                Some("https://mirror.example.test/a%2fb/"),
                None,
                "encoded",
            ),
            (
                "https://mirror.example.test/r.json",
                None,
                Some(&["*.example.test".to_owned()][..]),
                "exact host",
            ),
            (
                "https://mirror.example.test/r.json",
                None,
                Some(&["storage.example.test:8443".to_owned()][..]),
                "exact host",
            ),
            (
                "https://mirror.example.test/r.json",
                None,
                Some(&["192.0.2.10".to_owned()][..]),
                "exact host",
            ),
            (
                "https://mirror.example.test/r.json",
                None,
                Some(&["Storage.Example.Test".to_owned()][..]),
                "exact host",
            ),
            (
                "https://mirror.example.test/r.json",
                None,
                Some(&["mirror.example.test".to_owned()][..]),
                "host of the release prefix",
            ),
            (
                "https://user:secret@mirror.example.test/r.json",
                None,
                None,
                "user name or password",
            ),
        ] {
            let error = Pin::new(source, prefix, hosts).expect_err(source);
            assert!(error.contains(wanted), "{source} {prefix:?}: {error}");
        }
        // Plain HTTP on the loopback host stays possible, for tests.
        for source in [
            "http://127.0.0.1:9/releases.json",
            "http://[::1]:9/releases.json",
            "http://localhost:9/releases.json",
        ] {
            assert!(Pin::new(source, None, None).is_ok(), "{source}");
        }
    }

    #[test]
    fn release_files_must_lie_inside_the_prefix() {
        let pin = github();
        let ok = |asset: &str| pin.asset_url(asset).map(String::from);
        assert_eq!(
            ok("tenko-0.2.0-linux-x86_64").expect("relative"),
            "https://github.com/example-owner/tenko/releases/latest/download/tenko-0.2.0-linux-x86_64"
        );
        assert_eq!(
            ok("https://github.com/example-owner/tenko/releases/download/v0.2.0/tenko")
                .expect("the release download path"),
            "https://github.com/example-owner/tenko/releases/download/v0.2.0/tenko"
        );
        for refused in [
            // Another repository on the same host: the gap of an origin-only pin.
            "https://github.com/someone-else/tenko/releases/download/v0.2.0/tenko",
            "/someone-else/tenko/releases/download/v0.2.0/tenko",
            "../../../../someone-else/tenko/releases/download/v0.2.0/tenko",
            "https://github.com/example-owner/tenko/releases/../../evil/releases/x",
            // Another host, another scheme, the storage host directly.
            "https://mirror.example.net/example-owner/tenko/releases/download/v0.2.0/tenko",
            "http://github.com/example-owner/tenko/releases/download/v0.2.0/tenko",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2",
            // A URL two parsers could read differently, credentials, encoded separators.
            "https://evil.example.net\\@github.com/example-owner/tenko/releases/x",
            "https://user@github.com/example-owner/tenko/releases/download/v0.2.0/tenko",
            "https://github.com/example-owner/tenko/releases/download/v0.2.0%2f..%2f..%2fx",
            "https://github.com/example-owner/tenko/releases/%2e%2e/%2e%2e/evil/x",
            "https://github.com:8443/example-owner/tenko/releases/download/v0.2.0/tenko",
            "",
        ] {
            assert!(ok(refused).is_err(), "accepted: {refused}");
        }
        let source = Source::new(github()).expect("source");
        let error = source
            .asset_url(&asset(
                "https://github.com/someone-else/tenko/releases/download/v1/x",
            ))
            .expect_err("another repository");
        assert_eq!(error.code, "update.source_mismatch");
    }

    #[test]
    fn redirects_stay_in_the_prefix_and_on_listed_hosts() {
        let pin = github();
        let inside =
            url("https://github.com/example-owner/tenko/releases/latest/download/releases.json");
        let tagged =
            url("https://github.com/example-owner/tenko/releases/download/v0.2.0/releases.json");
        let storage = url(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sig=x",
        );
        assert!(pin.admits_redirect(&inside, &tagged), "inside the prefix");
        assert!(pin.admits_redirect(&tagged, &storage), "to the listed host");
        assert!(
            pin.admits_redirect(&storage, &tagged),
            "back into the prefix"
        );
        for refused in [
            "https://github.com/someone-else/tenko/releases/download/v0.2.0/x",
            "http://github.com/example-owner/tenko/releases/download/v0.2.0/x",
            "http://release-assets.githubusercontent.com/x",
            "https://release-assets.githubusercontent.com:8443/x",
            "https://user:pw@release-assets.githubusercontent.com/x",
            "https://evil.release-assets.githubusercontent.com/x",
            "https://release-assets.githubusercontent.com.evil.example/x",
            "https://objects.githubusercontent.com/x",
            "https://mirror.example.net/x",
        ] {
            let to = url(refused);
            assert!(
                !pin.admits_redirect(&tagged, &to),
                "from the prefix to {refused}"
            );
            assert!(
                !pin.admits_redirect(&storage, &to),
                "from the storage to {refused}"
            );
        }
        // A chain that is not admitted at its start is not continued.
        let elsewhere = url("https://mirror.example.net/x");
        assert!(!pin.admits_redirect(&elsewhere, &tagged));
        // A mirror without redirect hosts redirects only inside its prefix.
        let mirror = Pin::new(
            "https://mirror.example.test/tenko/releases.json",
            None,
            None,
        )
        .expect("a mirror");
        assert!(mirror.admits_redirect(
            &url("https://mirror.example.test/tenko/releases.json"),
            &url("https://mirror.example.test/tenko/v0.2.0/releases.json")
        ));
        assert!(!mirror.admits_redirect(
            &url("https://mirror.example.test/tenko/releases.json"),
            &storage
        ));
    }

    /// A plain HTTP server on the loopback interface that answers each path from `routes`:
    /// `Ok(body)` with 200, `Err(location)` with 302. Unknown paths get 404.
    async fn serve(
        routes: Vec<(&'static str, Result<&'static str, String>)>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = vec![0u8; 4096];
                let read = stream.read(&mut request).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&request[..read]).to_string();
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let answer = match routes.iter().find(|(route, _)| *route == path) {
                    Some((_, Ok(body))) => format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    Some((_, Err(location))) => format!(
                        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            .to_owned()
                    }
                };
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (port, task)
    }

    fn file_asset(url: &str, body: &str) -> ReleaseAsset {
        ReleaseAsset {
            platform: "linux-x86_64".to_owned(),
            name: "tenko-0.2.0-linux-x86_64".to_owned(),
            url: url.to_owned(),
            sha256: hex(&Sha256::digest(body.as_bytes())),
            size: body.len() as u64,
            signature: None,
        }
    }

    #[tokio::test]
    async fn a_download_follows_redirects_inside_the_prefix_and_reports_the_final_url() {
        let (port, task) = serve(vec![
            ("/rel/a", Err("/rel/b".to_owned())),
            ("/rel/b", Ok("the release")),
            ("/rel/out", Err("/elsewhere/c".to_owned())),
            ("/elsewhere/c", Ok("the release")),
            ("/rel/1", Err("/rel/2".to_owned())),
            ("/rel/2", Err("/rel/3".to_owned())),
            ("/rel/3", Err("/rel/4".to_owned())),
            ("/rel/4", Err("/rel/5".to_owned())),
            ("/rel/5", Ok("the release")),
            ("/rel/three", Err("/rel/3".to_owned())),
        ])
        .await;
        let pin = Pin::new(
            &format!("http://127.0.0.1:{port}/rel/releases.json"),
            None,
            None,
        )
        .expect("a loopback pin");
        let source = Source::new(pin).expect("source");
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("tenko.part");

        let downloaded = source
            .download(&file_asset("a", "the release"), &path)
            .await
            .expect("one redirect inside the prefix");
        assert_eq!(
            downloaded.requested,
            format!("http://127.0.0.1:{port}/rel/a")
        );
        assert_eq!(
            downloaded.final_url,
            format!("http://127.0.0.1:{port}/rel/b")
        );
        assert_eq!(
            downloaded.staged.sha256,
            hex(&Sha256::digest(b"the release"))
        );

        let error = source
            .download(&file_asset("out", "the release"), &path)
            .await
            .expect_err("a redirect out of the prefix");
        assert_eq!(error.code, "update.fetch_failed");
        assert!(error.detail.contains("pinned source"), "{}", error.detail);

        let error = source
            .download(&file_asset("1", "the release"), &path)
            .await
            .expect_err("four redirects");
        assert_eq!(error.code, "update.fetch_failed");
        assert!(
            error.detail.contains("more than 3 redirects"),
            "{}",
            error.detail
        );
        // Three redirects are followed.
        source
            .download(&file_asset("three", "the release"), &path)
            .await
            .expect("three redirects");
        task.abort();
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
