//! The online range source: the Pwned Passwords range API over HTTPS (IAM-04).
//!
//! Compiled only with the crate feature `online`. The request carries the 5-character hash
//! prefix in the URL path and nothing else that identifies the password; padding is requested
//! (`Add-Padding: true`) so the response size does not reveal how many hashes share the
//! prefix.

use std::time::Duration;

use async_trait::async_trait;

use super::{HibpError, HibpRangeSource};

/// The public range endpoint.
const DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com/range/";
/// User agent sent with every request.
const USER_AGENT: &str = "tenko-ddi";
/// Overall timeout of one request, connection and body included.
const TIMEOUT: Duration = Duration::from_secs(5);
/// A padded range response is about 100 KB; anything beyond this is not one.
const MAX_BODY: usize = 1 << 20;

/// A [`HibpRangeSource`] that asks the Pwned Passwords range API (or a compatible mirror) over
/// HTTP(S). It sends `GET {base_url}{prefix}` with the headers `Add-Padding: true` and
/// `User-Agent: tenko-ddi`, follows no redirect, and gives up after 5 seconds.
#[derive(Debug, Clone)]
pub struct HttpRangeSource {
    client: reqwest::Client,
    base_url: String,
}

impl HttpRangeSource {
    /// A source for the public API at `https://api.pwnedpasswords.com/range/`.
    ///
    /// # Errors
    ///
    /// [`HibpError::Unavailable`] if the HTTP client cannot be built (for example, no TLS
    /// backend).
    pub fn new() -> Result<Self, HibpError> {
        Self::with_base_url(DEFAULT_BASE_URL)
    }

    /// A source for a mirror or a proxy. `base_url` is everything before the prefix, so it
    /// normally ends in `/range/`; a missing trailing slash is added.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self, HibpError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Add-Padding",
            reqwest::header::HeaderValue::from_static("true"),
        );
        // No redirects: a redirect could send the hash prefix to another host or over
        // plain HTTP. A mirror answers at its own address; a 3xx counts as a failure.
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .build()
            .map_err(|error| HibpError::Unavailable(describe(&error)))?;
        let mut base_url = base_url.into();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }
        Ok(Self { client, base_url })
    }
}

/// A description of a transport error that cannot contain the request URL.
fn describe(error: &reqwest::Error) -> String {
    let kind = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_builder() {
        "client could not be built"
    } else if error.is_body() || error.is_decode() {
        "response body could not be read"
    } else {
        "request failed"
    };
    kind.to_owned()
}

#[async_trait]
impl HibpRangeSource for HttpRangeSource {
    async fn range(&self, prefix: &str) -> Result<String, HibpError> {
        // The prefix goes into a URL: accept exactly five hexadecimal characters.
        if prefix.len() != super::PREFIX_LEN || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HibpError::Unavailable("invalid range prefix".to_owned()));
        }
        let url = format!("{}{}", self.base_url, prefix.to_ascii_uppercase());
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| HibpError::Unavailable(describe(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(HibpError::Unavailable(format!(
                "unexpected HTTP status {}",
                status.as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| HibpError::Unavailable(describe(&error)))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(HibpError::Unavailable("response too large".to_owned()));
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| HibpError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_without_touching_the_network() {
        let source = HttpRangeSource::new().expect("client");
        assert_eq!(source.base_url, "https://api.pwnedpasswords.com/range/");
        let mirror =
            HttpRangeSource::with_base_url("https://mirror.example.test/range").expect("client");
        assert_eq!(mirror.base_url, "https://mirror.example.test/range/");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A source that answers every request with a redirect to a second listener, which
        // counts the requests it gets.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let target_port = target.local_addr().expect("address").port();
        let reached = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&reached);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = target.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buffer = [0u8; 1024];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        let source = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let port = source.local_addr().expect("address").port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = source.accept().await {
                let mut buffer = [0u8; 1024];
                let _ = socket.read(&mut buffer).await;
                let answer = format!(
                    "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{target_port}/range/5BAA6\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = socket.write_all(answer.as_bytes()).await;
            }
        });
        let client = HttpRangeSource::with_base_url(format!("http://127.0.0.1:{port}/range/"))
            .expect("client");
        let answer = client.range("5BAA6").await;
        assert!(
            matches!(&answer, Err(HibpError::Unavailable(detail)) if detail.contains("302")),
            "{answer:?}"
        );
        assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refuses_a_prefix_that_is_not_five_hex_characters() {
        let source =
            HttpRangeSource::with_base_url("https://mirror.example.test/range/").expect("client");
        for bad in ["", "5BAA", "5BAA61", "5BAA/", "5BA A", "../.."] {
            assert!(
                matches!(source.range(bad).await, Err(HibpError::Unavailable(_))),
                "{bad:?}"
            );
        }
    }
}
