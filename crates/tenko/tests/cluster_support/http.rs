//! The lab's own HTTP client: requests to any controller with the session of the
//! administrator, the lab's CA root as the trust anchor and no panic when a controller is
//! down (a killed controller is part of the scenarios). It shares one tokio runtime with
//! the load generator and the SSE reader.

use std::{path::Path, sync::Arc, time::Duration};

use reqwest::Method;
use serde_json::Value;

use crate::serve_support::api::Reply;

/// How long one request of the lab may take, unless the call says otherwise.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A client of every controller of a lab.
#[derive(Clone)]
pub struct Http {
    runtime: Arc<tokio::runtime::Runtime>,
    client: reqwest::Client,
}

impl Http {
    /// A client that trusts the CA root in `ca_file`.
    pub fn new(ca_file: &Path) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime");
        let pem = std::fs::read(ca_file).expect("the CA root of the lab");
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("PEM"))
            .pool_max_idle_per_host(64)
            .build()
            .expect("an HTTP client");
        Self {
            runtime: Arc::new(runtime),
            client,
        }
    }

    /// The runtime the lab's background work runs on.
    pub fn runtime(&self) -> &Arc<tokio::runtime::Runtime> {
        &self.runtime
    }

    /// The underlying client.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// One request to `base` (`https://localhost:<port>`) and an API path, with the session
    /// cookie and, for a mutation, the origin of `base`. The error describes a request that
    /// got no answer.
    pub fn send(
        &self,
        method: Method,
        base: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&Value>,
        headers: &[(&str, String)],
    ) -> Result<Reply, String> {
        self.runtime.block_on(send(
            &self.client,
            method,
            base,
            path,
            cookie,
            body,
            headers,
            REQUEST_TIMEOUT,
        ))
    }

    /// `GET` of an API path.
    pub fn get(&self, base: &str, path: &str, cookie: Option<&str>) -> Result<Reply, String> {
        self.send(Method::GET, base, path, cookie, None, &[])
    }
}

/// One request, asynchronously; see [`Http::send`].
#[allow(clippy::too_many_arguments, reason = "a plain request with its parts")]
pub async fn send(
    client: &reqwest::Client,
    method: Method,
    base: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<&Value>,
    headers: &[(&str, String)],
    timeout: Duration,
) -> Result<Reply, String> {
    let mutation = method != Method::GET && method != Method::HEAD;
    let mut request = client
        .request(method, format!("{base}/api/v1{path}"))
        .timeout(timeout);
    if let Some(cookie) = cookie {
        request = request.header("Cookie", cookie);
    }
    if mutation {
        request = request.header("Origin", base);
    }
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(body).expect("JSON"));
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("{path}: {error}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response
        .text()
        .await
        .map_err(|error| format!("{path}: body: {error}"))?;
    Ok(Reply {
        status,
        headers,
        text,
    })
}
