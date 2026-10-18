//! DNS over HTTPS (RFC 8484) on hyper: HTTP/2, and HTTP/1.1 for clients that ask for it.
//!
//! The endpoint is `/dns-query`. `GET` carries the query in the `dns` parameter as
//! base64url without padding (padding is accepted), `POST` as an `application/dns-message`
//! body of at most 65,535 octets. The answer is `200` with `application/dns-message` and
//! `Cache-Control: max-age=<the smallest TTL of the answer and authority sections>` (0
//! for an answer without records), whatever its RCODE (RFC 8484 section 4.2.1). Anything
//! else gets an empty answer: `404` for another path, `405` for another method, `415` for
//! another media type, `413` for a body over the size, `400` for a missing or undecodable
//! parameter or a message that is no query (or that the resolver drops), `504` when the
//! forwarder did not answer in time. One DNS message in, one out: no other HTTP semantics.
//!
//! A connection is closed (HTTP/2 `GOAWAY`, or the end of the HTTP/1.1 keep-alive) after
//! the idle time without a request in progress, and when the server stops. Each request
//! allocates (hyper's request and answer, the body, the answer's copy); the query itself
//! runs on the runtime thread's buffers like TCP.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use super::proxy;
use crate::{
    resolver::Resolver,
    respond::{Clock, Conn, Reply, ReplyPath, Responder, Scratch},
    transport::tcp::SCRATCH,
    wire::{self, MAX_MESSAGE_LEN},
};

/// The path of the endpoint.
pub const PATH: &str = "/dns-query";

/// The media type of a DNS message (RFC 8484 section 6).
pub const MEDIA_TYPE: &str = "application/dns-message";

/// How long a request waits for the forwarder's answer.
const FORWARD_WAIT: Duration = Duration::from_secs(15);

/// How long a closing connection may take to finish its requests.
const DRAIN: Duration = Duration::from_secs(2);

/// The settings of one connection.
#[derive(Debug, Clone, Copy)]
pub(super) struct Options {
    /// Time without a request before the connection is closed.
    pub(super) idle: Duration,
    /// Concurrent HTTP/2 streams.
    pub(super) streams: u32,
    /// Take the client from `X-Forwarded-For` (behind a proxy without the PROXY protocol).
    pub(super) forwarded_for: bool,
}

/// When the connection last saw a request start or end, and how many are running.
#[derive(Debug)]
struct Activity {
    opened: Instant,
    last_millis: AtomicU64,
    running: AtomicUsize,
}

impl Activity {
    fn new() -> Self {
        Self {
            opened: Instant::now(),
            last_millis: AtomicU64::new(0),
            running: AtomicUsize::new(0),
        }
    }

    fn touch(&self) {
        let millis = u64::try_from(self.opened.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    fn begin(self: &Arc<Self>) -> Busy {
        self.running.fetch_add(1, Ordering::Relaxed);
        self.touch();
        Busy(Arc::clone(self))
    }

    /// Time since the last request ended; zero while one runs.
    fn idle_for(&self) -> Duration {
        if self.running.load(Ordering::Relaxed) > 0 {
            return Duration::ZERO;
        }
        let last = Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
        self.opened.elapsed().saturating_sub(last)
    }
}

/// A request in progress.
struct Busy(Arc<Activity>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.touch();
        self.0.running.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serves one connection until the client closes it, it stays idle, or the server stops.
pub(super) async fn connection<R, S>(
    stream: S,
    conn: Conn,
    options: Options,
    responder: Arc<Responder<R>>,
    stop: CancellationToken,
) where
    R: Resolver + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(Activity::new());
    let requests = Arc::clone(&activity);
    let service = service_fn(move |request: Request<Incoming>| {
        let responder = Arc::clone(&responder);
        let busy = requests.begin();
        async move {
            let answer = handle(request, conn, options.forwarded_for, &responder).await;
            drop(busy);
            Ok::<_, Infallible>(answer)
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(options.idle)
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(options.streams);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let tick = (options.idle / 4).clamp(Duration::from_millis(25), Duration::from_secs(1));
    let mut ticks = tokio::time::interval(tick);
    let mut closing: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = connection.as_mut() => return,
            () = stop.cancelled(), if closing.is_none() => {
                connection.as_mut().graceful_shutdown();
                closing = Some(Instant::now());
            }
            _ = ticks.tick() => match closing {
                // Requests that do not finish in time are cut with the connection.
                Some(since) if since.elapsed() >= DRAIN => return,
                None if activity.idle_for() >= options.idle => {
                    connection.as_mut().graceful_shutdown();
                    closing = Some(Instant::now());
                }
                Some(_) | None => {}
            },
        }
    }
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}

fn dns_answer(message: Vec<u8>) -> Response<Full<Bytes>> {
    let max_age = max_age(&message);
    let mut response = Response::new(Full::new(Bytes::from(message)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    if let Ok(value) = HeaderValue::from_str(&format!("max-age={max_age}")) {
        headers.insert(CACHE_CONTROL, value);
    }
    response
}

/// Whether a request's media type is `application/dns-message` (parameters ignored).
fn is_dns_message(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(MEDIA_TYPE))
}

/// Answers one request.
async fn handle<R: Resolver>(
    request: Request<Incoming>,
    mut conn: Conn,
    forwarded_for: bool,
    responder: &Responder<R>,
) -> Response<Full<Bytes>> {
    if request.uri().path() != PATH {
        return status(StatusCode::NOT_FOUND);
    }
    if forwarded_for
        && let Some(client) = request
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .and_then(proxy::forwarded_for)
    {
        conn.client = SocketAddr::new(client, 0);
    }
    let message = match *request.method() {
        Method::GET => {
            let mut message = Vec::new();
            match request.uri().query().and_then(dns_param) {
                Some(param) if decode_base64url(param, &mut message) => message,
                _ => return status(StatusCode::BAD_REQUEST),
            }
        }
        Method::POST => {
            if !is_dns_message(request.headers().get(CONTENT_TYPE)) {
                return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            match Limited::new(request.into_body(), MAX_MESSAGE_LEN)
                .collect()
                .await
            {
                Ok(body) => body.to_bytes().to_vec(),
                Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                    return status(StatusCode::PAYLOAD_TOO_LARGE);
                }
                Err(_) => return status(StatusCode::BAD_REQUEST),
            }
        }
        _ => {
            let mut response = status(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, POST"));
            return response;
        }
    };
    if message.len() > MAX_MESSAGE_LEN
        || wire::parse_header(&message).is_none_or(|header| header.qr)
    {
        return status(StatusCode::BAD_REQUEST);
    }
    let now = Instant::now();
    let clock = Clock::now();
    let (reply, answer) = SCRATCH.with(|cell| {
        let mut slot = cell.borrow_mut();
        let scratch = slot.get_or_insert_with(Scratch::new);
        let reply = responder.respond(&message, &conn, &clock, now, scratch);
        let answer = (reply == Reply::Send).then(|| scratch.out.clone());
        (reply, answer)
    });
    match (reply, answer) {
        (Reply::Send, Some(answer)) => dns_answer(answer),
        (Reply::Forward { .. }, _) => {
            let (sender, mut receiver) = mpsc::channel(1);
            responder.forward(&message, &conn, reply, ReplyPath::Tcp(sender));
            match tokio::time::timeout(FORWARD_WAIT, receiver.recv()).await {
                Ok(Some(answer)) => dns_answer(answer),
                _ => status(StatusCode::GATEWAY_TIMEOUT),
            }
        }
        _ => status(StatusCode::BAD_REQUEST),
    }
}

/// The value of the `dns` parameter of a query string, without trailing padding.
pub fn dns_param(query: &str) -> Option<&str> {
    let value = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))?;
    let mut value = value.trim_end_matches('=');
    // Padding a client percent-encoded.
    while value.len() >= 3 && value[value.len() - 3..].eq_ignore_ascii_case("%3D") {
        value = &value[..value.len() - 3];
    }
    Some(value)
}

/// Decodes base64url (RFC 4648 section 5) into `out`; trailing `=` padding is allowed.
/// Returns `false` for any other character or an impossible length.
pub fn decode_base64url(text: &str, out: &mut Vec<u8>) -> bool {
    let text = text.trim_end_matches('=');
    out.clear();
    if text.len() % 4 == 1 || text.len() > MAX_MESSAGE_LEN.div_ceil(3) * 4 {
        return false;
    }
    out.reserve(text.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return false,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    true
}

/// The freshness of an answer for `Cache-Control` (RFC 8484 section 5.1): the smallest
/// TTL of the answer and authority sections, 0 for an answer without records or one that
/// does not parse.
pub fn max_age(answer: &[u8]) -> u32 {
    let Some(header) = wire::parse_header(answer) else {
        return 0;
    };
    let Some(mut pos) = wire::questions_end(answer, header.qdcount) else {
        return 0;
    };
    let mut smallest: Option<u32> = None;
    for _ in 0..u32::from(header.ancount) + u32::from(header.nscount) {
        let Some(record) = wire::read_record(answer, pos) else {
            return 0;
        };
        if record.rtype != wire::TYPE_OPT {
            // RFC 2181 section 8: a TTL with the top bit set counts as zero.
            let ttl = if record.ttl > 0x7fff_ffff {
                0
            } else {
                record.ttl
            };
            smallest = Some(smallest.map_or(ttl, |current| current.min(ttl)));
        }
        pos = record.end();
    }
    smallest.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let n = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            for index in 0..=chunk.len() {
                let six = (n >> (18 - 6 * index)) & 63;
                out.push(char::from(
                    ALPHABET[usize::try_from(six).expect("six bits")],
                ));
            }
        }
        out
    }

    #[test]
    fn base64url_round_trips_and_refuses_junk() {
        // The example of RFC 8484 section 4.1.1.
        let mut out = Vec::new();
        assert!(decode_base64url(
            "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
            &mut out
        ));
        assert_eq!(&out[12..17], b"\x03www\x07");
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37 % 256).expect("byte"))
                .collect();
            let text = encode(&bytes);
            assert!(decode_base64url(&text, &mut out), "{text}");
            assert_eq!(out, bytes);
            assert!(decode_base64url(&format!("{text}=="), &mut out));
        }
        assert!(!decode_base64url("AAA+", &mut out));
        assert!(!decode_base64url("AAAAA", &mut out));
        assert!(!decode_base64url("AA=A", &mut out));
    }

    #[test]
    fn the_dns_parameter_is_found() {
        assert_eq!(dns_param("ct=x&dns=AAAB"), Some("AAAB"));
        assert_eq!(dns_param("dns=AAAB%3D%3d"), Some("AAAB"));
        assert_eq!(dns_param("dnsx=AAAB"), None);
    }

    #[test]
    fn max_age_is_the_smallest_ttl() {
        let mut query = Vec::new();
        wire::write_query(&mut query, 7, "www.example.test", 1, None);
        let mut answer = query.clone();
        answer[2] |= 0x80;
        answer[7] = 2;
        for ttl in [300u32, 60] {
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            answer.extend_from_slice(&ttl.to_be_bytes());
            answer.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        }
        assert_eq!(max_age(&answer), 60);
        assert_eq!(max_age(&query), 0);
        answer.truncate(answer.len() - 3);
        assert_eq!(max_age(&answer), 0);
    }
}
