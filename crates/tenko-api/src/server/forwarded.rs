//! The trusted proxy rules of OPS-22: which client address, scheme and host a request has.
//!
//! The listener records per connection whether the TCP peer is a trusted reverse proxy
//! (TLS mode c, [`TrustedProxies::is_trusted`]) and, if the PROXY protocol is on, the
//! header that proxy sent ([`ConnInfo`]). [`client_info`] then decides per request:
//!
//! - **Untrusted peer**: the peer address, `https` when the connection itself is TLS, the
//!   `Host` header (or HTTP/2 authority). `Forwarded`-style headers are never read.
//! - **Trusted peer**: the address from the PROXY header, else the nearest address of
//!   `X-Forwarded-For` that is not itself a trusted proxy (walking from the right, so a
//!   client cannot spoof its address by sending its own header through the proxy); the
//!   scheme from `X-Forwarded-Proto`, else the PROXY v2 SSL record, else HTTPS (the proxy
//!   terminates TLS in mode c); the host from `X-Forwarded-Host`, else `Host`.
//!
//! `X-Forwarded-Proto` and `X-Forwarded-Host` are read from their **last** value: the one
//! the trusted proxy itself appended or set. A proxy that appends to what the client sent
//! leaves the client's own claims to the left, where they are never read.
//!
//! **A stated scheme.** In mode c the HTTPS of a request whose proxy said nothing about
//! the scheme (no `X-Forwarded-Proto` of `https` or `http`, no PROXY v2 SSL record with the
//! client bit, no TLS of the connection itself) is assumed, not stated. The security
//! headers and the CSRF own-origin use the assumption; the enrollment of a node, which
//! hands over a secret, refuses it outside Lab ([`UnstatedScheme`]).

use std::{net::IpAddr, sync::Arc};

use axum::http::{HeaderMap, HeaderName, Uri};
use tenko_cluster::ca::{TlsMode, TrustedProxies};

use super::proxy_protocol::{ProxyCommand, ProxyHeader};
use crate::extract::{ClientInfo, request_host, valid_host};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// What the listener knows about a connection; a request extension.
#[derive(Debug, Clone)]
pub(crate) struct ConnInfo {
    /// The TCP peer.
    pub(crate) peer: std::net::SocketAddr,
    /// Whether this listener terminated TLS on the connection.
    pub(crate) tls: bool,
    /// The TLS mode when the connection was accepted (carries the trusted proxies).
    pub(crate) mode: Arc<TlsMode>,
    /// Whether the peer is a trusted reverse proxy.
    pub(crate) trusted: bool,
    /// The PROXY protocol header the trusted peer sent.
    pub(crate) proxy: Option<ProxyHeader>,
}

impl ConnInfo {
    fn trusted_proxies(&self) -> Option<&TrustedProxies> {
        self.mode.trusted_proxies()
    }
}

/// A request extension that marks a request whose HTTPS a trusted proxy did not state: the
/// proxy sent no `X-Forwarded-Proto` of `https` or `http` and no PROXY v2 SSL record with
/// the client bit, and the connection to Tenko was not TLS. [`ClientInfo::https`] is then
/// true by the assumption of mode c (the proxy terminates TLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnstatedScheme;

/// The client of a request under the trusted proxy rules.
pub(crate) fn client_info(conn: Option<&ConnInfo>, headers: &HeaderMap, uri: &Uri) -> ClientInfo {
    resolve(conn, headers, uri).0
}

/// [`client_info`] and whether the scheme was stated (`false`: assumed, see
/// [`UnstatedScheme`]).
pub(crate) fn resolve(
    conn: Option<&ConnInfo>,
    headers: &HeaderMap,
    uri: &Uri,
) -> (ClientInfo, bool) {
    let Some(conn) = conn else {
        // No listener (router used directly): nothing is trusted.
        let info = ClientInfo {
            source_ip: None,
            peer: None,
            https: uri.scheme_str() == Some("https"),
            host: request_host(headers, uri),
            via_proxy: false,
        };
        return (info, true);
    };
    let host = request_host(headers, uri);
    if !conn.trusted {
        let info = ClientInfo {
            source_ip: Some(canonical(conn.peer.ip())),
            peer: Some(conn.peer),
            https: conn.tls,
            host,
            via_proxy: false,
        };
        return (info, true);
    }

    let proxied_source = conn
        .proxy
        .as_ref()
        .filter(|header| header.command == ProxyCommand::Proxy)
        .and_then(|header| header.source);
    let mut source = proxied_source.map_or_else(|| conn.peer.ip(), |source| source.ip());
    if let Some(trusted) = conn.trusted_proxies() {
        source = walk_forwarded_for(canonical(source), headers, trusted);
    }

    let (https, stated) = match last_value(headers, &X_FORWARDED_PROTO) {
        Some(proto) if proto.eq_ignore_ascii_case("https") => (true, true),
        Some(proto) if proto.eq_ignore_ascii_case("http") => (false, true),
        _ if conn.tls || conn.proxy.as_ref().is_some_and(|header| header.tls) => (true, true),
        // Mode c: the proxy terminates TLS, so HTTPS is assumed; nobody said so.
        _ if !conn.mode.terminates_tls() => (true, false),
        _ => (false, true),
    };
    let forwarded_host = last_value(headers, &X_FORWARDED_HOST).and_then(valid_host);
    let info = ClientInfo {
        source_ip: Some(canonical(source)),
        peer: Some(conn.peer),
        https,
        host: forwarded_host.or(host),
        via_proxy: true,
    };
    (info, stated)
}

/// Walks `X-Forwarded-For` from the right while the current hop is a trusted proxy.
fn walk_forwarded_for(mut hop: IpAddr, headers: &HeaderMap, trusted: &TrustedProxies) -> IpAddr {
    if !trusted.is_trusted(hop) {
        return hop;
    }
    let entries: Vec<&str> = headers
        .get_all(&X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    for entry in entries.iter().rev() {
        let Some(address) = parse_forwarded_address(entry) else {
            // A malformed entry ends the chain: everything left of it is unverifiable.
            break;
        };
        hop = canonical(address);
        if !trusted.is_trusted(hop) {
            break;
        }
    }
    hop
}

/// An `X-Forwarded-For` entry: an address, optionally with a port, IPv6 optionally in
/// brackets.
fn parse_forwarded_address(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address);
    }
    if let Some(rest) = entry.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    let (address, port) = entry.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    address.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

/// The last comma-separated value of the last line of a header: the value the trusted
/// proxy appended or set. Values to its left may come from the client.
fn last_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get_all(name)
        .iter()
        .next_back()?
        .to_str()
        .ok()?
        .rsplit(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
}

/// IPv4-mapped IPv6 addresses as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::HeaderValue;

    use super::*;

    fn proxy_mode(proxies: &str, proxy_protocol: bool) -> Arc<TlsMode> {
        Arc::new(TlsMode::ReverseProxy {
            trusted_proxies: proxies.parse().expect("proxies"),
            proxy_protocol,
            public_host: "ddi.example.org".to_owned(),
        })
    }

    fn conn(peer: &str, mode: Arc<TlsMode>, tls: bool) -> ConnInfo {
        let peer: SocketAddr = peer.parse().expect("peer");
        let trusted = mode
            .trusted_proxies()
            .is_some_and(|trusted| trusted.is_trusted(peer.ip()));
        ConnInfo {
            peer,
            tls,
            mode,
            trusted,
            proxy: None,
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    fn uri() -> Uri {
        "/api/v1/health".parse().expect("uri")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn untrusted_peers_never_use_forwarded_headers() {
        let mode = proxy_mode("192.0.2.1", false);
        let info = client_info(
            Some(&conn("203.0.113.9:40000", Arc::clone(&mode), false)),
            &headers(&[
                ("host", "ddi.example.org"),
                ("x-forwarded-for", "198.51.100.7"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "evil.example.com"),
            ]),
            &uri(),
        );
        assert_eq!(info.source_ip, Some(ip("203.0.113.9")));
        assert!(!info.https);
        assert_eq!(info.host.as_deref(), Some("ddi.example.org"));
        assert!(!info.via_proxy);

        let internal_ca = Arc::new(TlsMode::InternalCa);
        let info = client_info(
            Some(&conn("192.0.2.1:40000", internal_ca, true)),
            &headers(&[("x-forwarded-for", "198.51.100.7")]),
            &uri(),
        );
        assert_eq!(
            info.source_ip,
            Some(ip("192.0.2.1")),
            "no proxies outside mode c"
        );
        assert!(info.https);
    }

    #[test]
    fn trusted_proxies_supply_address_scheme_and_host() {
        let mode = proxy_mode("192.0.2.0/28", false);
        let info = client_info(
            Some(&conn("192.0.2.1:40000", mode, false)),
            &headers(&[
                ("host", "backend.example.org:8080"),
                ("x-forwarded-for", "203.0.113.50, 198.51.100.7, 192.0.2.2"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "DDI.example.org"),
            ]),
            &uri(),
        );
        // 192.0.2.2 is a trusted hop; 198.51.100.7 is the nearest untrusted address. The
        // left-most entry is whatever the client claimed and is ignored.
        assert_eq!(info.source_ip, Some(ip("198.51.100.7")));
        assert!(info.https);
        assert_eq!(info.host.as_deref(), Some("ddi.example.org"));
        assert!(info.via_proxy);
        assert_eq!(info.origin().as_deref(), Some("https://ddi.example.org"));
    }

    #[test]
    fn mode_c_defaults_to_https_and_honors_an_explicit_http() {
        let mode = proxy_mode("192.0.2.1", false);
        let without = client_info(
            Some(&conn("192.0.2.1:40000", Arc::clone(&mode), false)),
            &headers(&[("host", "ddi.example.org")]),
            &uri(),
        );
        assert!(without.https);
        assert_eq!(without.source_ip, Some(ip("192.0.2.1")));
        let http = client_info(
            Some(&conn("192.0.2.1:40000", mode, false)),
            &headers(&[("x-forwarded-proto", "http")]),
            &uri(),
        );
        assert!(!http.https);
    }

    #[test]
    fn the_value_the_proxy_appended_wins_over_what_the_client_sent() {
        let mode = proxy_mode("192.0.2.1", false);
        // A proxy that appends: the client's own claims stay to the left.
        let appended = client_info(
            Some(&conn("192.0.2.1:40000", Arc::clone(&mode), false)),
            &headers(&[
                ("host", "ddi.example.org"),
                ("x-forwarded-proto", "https, http"),
                ("x-forwarded-host", "evil.example.com, ddi.example.org"),
            ]),
            &uri(),
        );
        assert!(!appended.https, "the proxy said http");
        assert_eq!(appended.host.as_deref(), Some("ddi.example.org"));
        // Two header lines: the last line is the proxy's.
        let lines = client_info(
            Some(&conn("192.0.2.1:40000", Arc::clone(&mode), false)),
            &headers(&[
                ("x-forwarded-proto", "http"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "evil.example.com"),
                ("x-forwarded-host", "ddi.example.org"),
            ]),
            &uri(),
        );
        assert!(lines.https);
        assert_eq!(lines.host.as_deref(), Some("ddi.example.org"));
        // Empty trailing entries are skipped, not read as the value.
        let trailing = client_info(
            Some(&conn("192.0.2.1:40000", mode, false)),
            &headers(&[("x-forwarded-proto", "http, ")]),
            &uri(),
        );
        assert!(!trailing.https);
    }

    #[test]
    fn a_scheme_nobody_stated_is_marked_as_assumed() {
        let mode = proxy_mode("192.0.2.1", true);
        let stated = |pairs: &[(&'static str, &'static str)], proxy: Option<ProxyHeader>| {
            let mut info = conn("192.0.2.1:40000", Arc::clone(&mode), false);
            info.proxy = proxy;
            let (client, stated) = resolve(Some(&info), &headers(pairs), &uri());
            (client.https, stated)
        };
        let v2 = |tls| ProxyHeader {
            version: 2,
            command: ProxyCommand::Proxy,
            source: Some("198.51.100.20:51000".parse().expect("addr")),
            destination: Some("192.0.2.5:443".parse().expect("addr")),
            tls,
        };
        assert_eq!(stated(&[], None), (true, false), "assumed by mode c");
        assert_eq!(
            stated(&[("x-forwarded-proto", "https")], None),
            (true, true)
        );
        assert_eq!(
            stated(&[("x-forwarded-proto", "http")], None),
            (false, true)
        );
        assert_eq!(
            stated(&[("x-forwarded-proto", "wss")], None),
            (true, false),
            "an unknown value states nothing"
        );
        assert_eq!(stated(&[], Some(v2(true))), (true, true), "the SSL record");
        assert_eq!(
            stated(&[], Some(v2(false))),
            (true, false),
            "a PROXY header without the SSL record states nothing"
        );
        // An untrusted peer and a router without a listener always state their scheme.
        let (_, untrusted) = resolve(
            Some(&conn("203.0.113.9:40000", Arc::clone(&mode), false)),
            &HeaderMap::new(),
            &uri(),
        );
        assert!(untrusted);
        assert!(resolve(None, &HeaderMap::new(), &uri()).1);
    }

    #[test]
    fn malformed_or_all_trusted_chains() {
        let mode = proxy_mode("192.0.2.0/28", false);
        let malformed = client_info(
            Some(&conn("192.0.2.1:40000", Arc::clone(&mode), false)),
            &headers(&[("x-forwarded-for", "198.51.100.7, not-an-address, 192.0.2.3")]),
            &uri(),
        );
        assert_eq!(malformed.source_ip, Some(ip("192.0.2.3")));
        let ports = client_info(
            Some(&conn("192.0.2.1:40000", Arc::clone(&mode), false)),
            &headers(&[
                ("x-forwarded-for", "[2001:db8::7]:4711"),
                ("x-forwarded-for", "198.51.100.8:80"),
            ]),
            &uri(),
        );
        assert_eq!(ports.source_ip, Some(ip("198.51.100.8")));
        let mapped = client_info(
            Some(&conn("[::ffff:192.0.2.1]:40000", mode, false)),
            &headers(&[("x-forwarded-for", "::ffff:198.51.100.9")]),
            &uri(),
        );
        assert_eq!(mapped.source_ip, Some(ip("198.51.100.9")));
    }

    #[test]
    fn proxy_protocol_addresses_win_over_the_peer() {
        let mode = proxy_mode("192.0.2.1", true);
        let mut info = conn("192.0.2.1:40000", Arc::clone(&mode), false);
        info.proxy = Some(ProxyHeader {
            version: 2,
            command: ProxyCommand::Proxy,
            source: Some("198.51.100.20:51000".parse().expect("addr")),
            destination: Some("192.0.2.5:443".parse().expect("addr")),
            tls: true,
        });
        let client = client_info(
            Some(&info),
            &headers(&[("x-forwarded-for", "203.0.113.1")]),
            &uri(),
        );
        assert_eq!(
            client.source_ip,
            Some(ip("198.51.100.20")),
            "untrusted source ends the walk"
        );
        assert!(client.https);

        info.proxy = Some(ProxyHeader {
            version: 2,
            command: ProxyCommand::Local,
            source: None,
            destination: None,
            tls: false,
        });
        let local = client_info(Some(&info), &HeaderMap::new(), &uri());
        assert_eq!(
            local.source_ip,
            Some(ip("192.0.2.1")),
            "LOCAL uses the socket address"
        );
    }

    #[test]
    fn without_a_listener_nothing_is_trusted() {
        let info = client_info(
            None,
            &headers(&[
                ("host", "ddi.example.org"),
                ("x-forwarded-for", "198.51.100.7"),
            ]),
            &uri(),
        );
        assert_eq!(info.source_ip, None);
        assert_eq!(info.host.as_deref(), Some("ddi.example.org"));
    }
}
