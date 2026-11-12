#![no_main]
//! What the API reads from a request before it authenticates anyone
//! (`tenko_api::fuzzing`): the client address, scheme and host under the trusted proxy rules
//! (`X-Forwarded-For`, `-Proto`, `-Host` and the PROXY header of a trusted peer), `Host`
//! and the URI authority, the CSRF guard with its `Origin` normalization, the session cookie
//! and the `Authorization` header, and the `Idempotency-Key` header.
//!
//! The input is two control octets and text: the first line is the URI, every further line a
//! header `name: value` (values may be any octets). The first control octet picks whether a
//! listener is in front (bit 0), whether it ended TLS (bit 1), whether it trusts the peer
//! (bit 2: only in mode c and for a peer in the trusted networks, as a listener does), the
//! TLS mode (bit 3: a reverse proxy in front, else the internal CA), a PROXY header from a
//! trusted peer (bit 4) with its TLS record (bit 5), and the method (bits 6 and 7); the
//! second picks the peer's address.
//!
//! It checks that a host and an origin that validate are lower case and validate again to
//! themselves; that an untrusted peer's forwarded headers are never read, so its own address,
//! TLS and `Host` stand; that a trusted peer's client address is the peer's or the PROXY
//! header's, or an `X-Forwarded-For` entry reached from the right through trusted hops only;
//! that the CSRF guard lets an unsafe method through only for its own origin or an allowed
//! one; and that credentials and an idempotency key are what their rules allow.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use libfuzzer_sys::fuzz_target;
use tenko_api::{
    fuzzing::{self, Connection},
    server::proxy_protocol::{ProxyCommand, ProxyHeader},
};
use tenko_cluster::ca::{TlsMode, TrustedProxies};
use tenko_core::auth::Credentials;

/// The origins allowed beside the request's own.
const ALLOWED: &[&str] = &["https://ddi.example.test", "http://localhost:5173"];

fn trusted_proxies() -> TrustedProxies {
    TrustedProxies::parse(["192.0.2.0/24", "2001:db8::/32"]).expect("networks")
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// An `X-Forwarded-For` entry as RFC 7239's predecessors write it: an address, IPv4 with a
/// port, or IPv6 in brackets with or without one.
fn entry_address(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address);
    }
    if let Some(rest) = entry.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    let (address, port) = entry.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    address.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// The client address a trusted peer may report: the start hop, then each entry of
/// `X-Forwarded-For` from the right while the hop before it is a trusted proxy.
fn reachable_sources(
    start: IpAddr,
    headers: &HeaderMap,
    trusted: Option<&TrustedProxies>,
) -> Vec<IpAddr> {
    let mut hop = canonical(start);
    let mut out = vec![hop];
    let Some(trusted) = trusted else {
        return out;
    };
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    for entry in entries.iter().rev() {
        if !trusted.is_trusted(hop) {
            break;
        }
        let Some(address) = entry_address(entry) else {
            break;
        };
        hop = canonical(address);
        out.push(hop);
    }
    out
}

fn check_host(host: &str) {
    assert_eq!(host, host.to_ascii_lowercase());
    assert!(
        !host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'/' || b == b'@')
    );
    assert_eq!(fuzzing::valid_host(host).as_deref(), Some(host));
}

fuzz_target!(|data: &[u8]| {
    let [control, peer_pick, rest @ ..] = data else {
        return;
    };
    let mut lines = rest.split(|byte| *byte == b'\n');
    let uri: Uri = lines
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| Uri::from_static("/"));
    let mut headers = HeaderMap::new();
    for line in lines {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        let value = value.strip_prefix(b" ").unwrap_or(value);
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }

    // Hosts and origins, from every header value that is text.
    for value in headers.values() {
        if let Ok(text) = value.to_str() {
            if let Some(host) = fuzzing::valid_host(text) {
                check_host(&host);
            }
            if let Some(origin) = fuzzing::origin(text) {
                assert!(origin.starts_with("https://") || origin.starts_with("http://"));
                assert_eq!(origin, origin.to_ascii_lowercase());
                assert_eq!(fuzzing::origin(&origin).as_deref(), Some(origin.as_str()));
            }
        }
    }
    let request_host = fuzzing::request_host(&headers, &uri);
    if let Some(host) = &request_host {
        check_host(host);
    }

    // The client under the trusted proxy rules.
    let peer = match peer_pick % 4 {
        0 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 40_000),
        1 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 40_001),
        2 => SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 11).to_ipv6_mapped()),
            40_002,
        ),
        _ => SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
            40_003,
        ),
    };
    let reverse_proxy = control & 8 != 0;
    let mode = if reverse_proxy {
        TlsMode::ReverseProxy {
            trusted_proxies: trusted_proxies(),
            proxy_protocol: control & 0x10 != 0,
            public_host: "ddi.example.test".to_owned(),
        }
    } else {
        TlsMode::InternalCa
    };
    // A listener trusts a peer only in mode c and only in its trusted networks, and reads a
    // PROXY header only from a trusted peer.
    let trusted = control & 4 != 0 && reverse_proxy && trusted_proxies().is_trusted(peer.ip());
    let proxy = (trusted && control & 0x10 != 0).then(|| ProxyHeader {
        version: 2,
        command: ProxyCommand::Proxy,
        source: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            50_000,
        )),
        destination: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8443,
        )),
        tls: control & 0x20 != 0,
    });
    let connection = (control & 1 != 0).then(|| Connection {
        peer,
        tls: control & 2 != 0,
        mode: Arc::new(mode),
        trusted,
        proxy: proxy.clone(),
    });
    let (client, _stated) = fuzzing::client_info(connection.as_ref(), &headers, &uri);
    if let Some(host) = &client.host {
        check_host(host);
    }
    match &connection {
        None => {
            assert_eq!(client.source_ip, None);
            assert!(!client.via_proxy);
            assert_eq!(client.host, request_host);
        }
        Some(connection) if !connection.trusted => {
            assert_eq!(client.source_ip, Some(canonical(peer.ip())));
            assert_eq!(client.peer, Some(peer));
            assert_eq!(client.https, connection.tls);
            assert_eq!(client.host, request_host);
            assert!(!client.via_proxy);
        }
        Some(connection) => {
            assert!(client.via_proxy);
            let start = connection
                .proxy
                .as_ref()
                .and_then(|header| header.source)
                .map_or(peer.ip(), |source| source.ip());
            let trusted = reverse_proxy.then(trusted_proxies);
            let reachable = reachable_sources(start, &headers, trusted.as_ref());
            let source = client
                .source_ip
                .expect("a trusted peer has a client address");
            assert!(reachable.contains(&source), "{source} not in {reachable:?}");
        }
    }

    // The CSRF guard.
    let method = match control >> 6 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::PUT,
        _ => Method::DELETE,
    };
    let allowed: Vec<String> = ALLOWED.iter().map(|origin| (*origin).to_owned()).collect();
    let passes = fuzzing::csrf_allows(&method, &headers, &client, &allowed);
    if method == Method::GET {
        assert!(passes);
    } else if passes && let Some(origin) = headers.get(http::header::ORIGIN) {
        let origin = fuzzing::origin(origin.to_str().expect("a passing Origin is text"))
            .expect("a passing Origin normalizes");
        assert!(client.origin().as_deref() == Some(origin.as_str()) || allowed.contains(&origin));
    }

    // Credentials and the idempotency key.
    for https in [false, true] {
        match fuzzing::credentials(&headers, https) {
            Credentials::Bearer(token) | Credentials::Session(token) => {
                assert!(!token.is_empty() && token.trim() == token);
            }
            Credentials::None => {}
        }
    }
    let _ = fuzzing::session_cookie(&headers);
    if let Ok(Some(key)) = fuzzing::idempotency_key(&headers) {
        assert!((1..=255).contains(&key.len()));
        assert!(key.bytes().all(|b| b.is_ascii_graphic()));
    }
});
