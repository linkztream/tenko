//! The HTTP exchange of one call, on the SDK's [`WebClient`] (TLS by the instance's mode,
//! no redirects, no proxies from the environment, bounded answers), with the retry policy of
//! this plugin.
//!
//! Requests that may change something on the controller are retried only after a rate-limit
//! answer (429), which means the controller did not act on them; reads are also retried after
//! 502, 503, 504, timeouts and connection failures. A rate limit that persists becomes
//! [`ConnectorError::RateLimited`] with the controller's `Retry-After`.

use std::time::Duration;

use tenko_connect::{
    ConnectorError,
    sdk::http::{
        DEFAULT_BODY_LIMIT, Failure, WebClient, read_bytes,
        reqwest::{self, Method, StatusCode, header::HeaderMap},
        retry_after, sensitive_header,
    },
};

use crate::settings::Config;

/// The largest answer the plugin reads (a large site's client table is a few MiB).
pub const MAX_BODY: usize = DEFAULT_BODY_LIMIT;

/// How often a request is sent at most.
const ATTEMPTS: u32 = 3;

/// The longest wait between two attempts.
const MAX_WAIT: Duration = Duration::from_secs(10);

/// The timeout of one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// An answer of the controller.
#[derive(Debug)]
pub struct Response {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body (at most [`MAX_BODY`] bytes).
    pub body: Vec<u8>,
}

impl Response {
    /// The body as JSON, or `None` when it is not JSON.
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The values of all headers of a name.
    pub fn header_values(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect()
    }

    /// The first value of a header.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok().map(str::to_owned))
    }
}

/// Whether a request may change something on the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// A read: retried after gateway errors, timeouts and connection failures.
    Read,
    /// A login, logout or write: retried only after a rate limit.
    Write,
}

/// The HTTP client of one call.
#[derive(Debug, Clone)]
pub struct Http {
    web: WebClient,
}

impl Http {
    /// A client for the controller of `config`.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] for a URL or TLS settings that cannot be used.
    pub fn new(config: &Config) -> Result<Self, ConnectorError> {
        Ok(Self {
            web: WebClient::new(
                config.base.as_str(),
                &config.tls,
                REQUEST_TIMEOUT,
                concat!("tenko-connect-unifi/", env!("CARGO_PKG_VERSION")),
            )?,
        })
    }

    /// The SDK client (TLS notes, presented fingerprint).
    pub fn web(&self) -> &WebClient {
        &self.web
    }

    /// Sends one request and reads the answer, with retries by `effect`. Header values are
    /// marked sensitive (they carry the session cookie, the CSRF token or the API key).
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Unreachable`] when the controller does not answer,
    /// [`ConnectorError::RateLimited`] when it keeps asking to slow down,
    /// [`ConnectorError::InvalidSettings`] when its certificate is refused, and
    /// [`ConnectorError::Protocol`] for an answer that exceeds the size limit.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        effect: Effect,
    ) -> Result<Response, ConnectorError> {
        // The SDK sets the path only; a query goes on separately so that `?` is not encoded.
        let (path, query) = match path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path, None),
        };
        let mut url = self.web.url(path);
        url.set_query(query);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = self
                .web
                .client()
                .request(method.clone(), url.clone())
                .header("Accept", "application/json");
            for (name, value) in headers {
                request = request.header(*name, sensitive_header(value, name)?);
            }
            if let Some(body) = body {
                request = request
                    .header("Content-Type", "application/json")
                    .body(body.to_vec());
            }
            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let wait = retry_after(&response).unwrap_or_else(|| backoff(attempt));
                        if attempt < ATTEMPTS {
                            tokio::time::sleep(wait.min(MAX_WAIT)).await;
                            continue;
                        }
                        return Err(ConnectorError::RateLimited { retry_after: wait });
                    }
                    if effect == Effect::Read
                        && matches!(status.as_u16(), 502..=504)
                        && attempt < ATTEMPTS
                    {
                        tokio::time::sleep(backoff(attempt)).await;
                        continue;
                    }
                    let headers = response.headers().clone();
                    let body = read_bytes(response, MAX_BODY).await?;
                    return Ok(Response {
                        status,
                        headers,
                        body,
                    });
                }
                Err(error) => {
                    let failure = self.web.failure(&error);
                    if effect == Effect::Read
                        && matches!(failure, Failure::Timeout | Failure::Connect)
                        && attempt < ATTEMPTS
                    {
                        tokio::time::sleep(backoff(attempt)).await;
                        continue;
                    }
                    return Err(failure.into_error());
                }
            }
        }
    }
}

/// The wait before attempt `attempt + 1`: 250 ms doubling, with up to 100 ms of jitter.
fn backoff(attempt: u32) -> Duration {
    let base = 250u64.saturating_mul(1 << attempt.min(6));
    let jitter = u64::from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
            % 100,
    );
    Duration::from_millis(base + jitter)
}

/// Re-export for the other modules.
pub use reqwest::Url;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_double() {
        assert!(backoff(1) >= Duration::from_millis(500));
        assert!(backoff(2) >= Duration::from_secs(1));
        assert!(backoff(30) <= Duration::from_secs(17));
    }
}
