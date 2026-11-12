//! Entry points for the fuzz target `api_request_headers` (not part of the API): the parsers
//! a request meets before any authentication, reachable from outside the crate. Each one
//! calls the function the server calls, with nothing changed.

use std::{net::SocketAddr, sync::Arc};

use axum::http::{HeaderMap, Method, Request, Uri};
use tenko_cluster::ca::TlsMode;
use tenko_core::auth::Credentials;

use crate::{
    extract::{self, ClientInfo},
    middleware::csrf,
    server::{
        forwarded::{self, ConnInfo},
        proxy_protocol::ProxyHeader,
    },
};

/// What a listener knows about a connection, as [`ConnInfo`] holds it.
#[derive(Debug, Clone)]
pub struct Connection {
    /// The TCP peer.
    pub peer: SocketAddr,
    /// Whether the listener ended TLS on the connection.
    pub tls: bool,
    /// The TLS mode, with the trusted proxies of mode c.
    pub mode: Arc<TlsMode>,
    /// Whether the peer is a trusted reverse proxy.
    pub trusted: bool,
    /// The PROXY protocol header the peer sent.
    pub proxy: Option<ProxyHeader>,
}

/// The client of a request under the trusted proxy rules, and whether its scheme was
/// stated; `connection` `None` is a router used without a listener.
pub fn client_info(
    connection: Option<&Connection>,
    headers: &HeaderMap,
    uri: &Uri,
) -> (ClientInfo, bool) {
    let conn = connection.map(|connection| ConnInfo {
        peer: connection.peer,
        tls: connection.tls,
        mode: Arc::clone(&connection.mode),
        trusted: connection.trusted,
        proxy: connection.proxy.clone(),
    });
    forwarded::resolve(conn.as_ref(), headers, uri)
}

/// The host of a request (`Host`, else the authority of the URI), validated.
pub fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    extract::request_host(headers, uri)
}

/// A `host[:port]` validated and lower-cased.
pub fn valid_host(raw: &str) -> Option<String> {
    extract::valid_host(raw)
}

/// An `Origin` header normalized as the CSRF guard reads it.
pub fn origin(origin: &str) -> Option<String> {
    csrf::normalize(origin)
}

/// Whether the CSRF guard lets a request through.
pub fn csrf_allows(
    method: &Method,
    headers: &HeaderMap,
    client: &ClientInfo,
    allowed: &[String],
) -> bool {
    csrf::check(method, headers, client, allowed).is_ok()
}

/// The credentials of a request: the session cookie of its scheme and `Authorization`.
pub fn credentials(headers: &HeaderMap, https: bool) -> Credentials {
    extract::credentials_for(headers, https)
}

/// The value of a session cookie of either name, as the CSRF guard asks for it.
pub fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    extract::session_cookie(headers)
}

/// The `Idempotency-Key` header: `Ok(None)` without one, the refusal's text when it is
/// refused.
///
/// # Errors
///
/// The text of the refusal.
pub fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, String> {
    let mut request = Request::new(());
    *request.headers_mut() = headers.clone();
    let (parts, ()) = request.into_parts();
    extract::idempotency_key(&parts)
        .map(|key| key.map(|key| key.as_str().to_owned()))
        .map_err(|error| error.to_string())
}
