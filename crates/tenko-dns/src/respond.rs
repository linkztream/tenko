//! The query path every transport shares: parse, EDNS, cookies, the resolver, the build,
//! the metrics and the query log (plan section 2.2, ADR 0009).
//!
//! A [`Responder`] turns the octets of one query into the octets of its answer in the
//! caller's [`Scratch`], which a UDP worker owns and a TCP runtime thread keeps in a
//! thread-local, so nothing is allocated per query once the scratch exists:
//!
//! 1. A message that is no query (a runt, a response) is dropped; one that does not parse
//!    gets the header-only FORMERR of [`wire::write_formerr`].
//! 2. EDNS: a version other than 0 gets BADVERS (RFC 6891); unknown options are ignored.
//! 3. Cookies (RFC 7873, RFC 9018): with [`CookieMode::Required`], a UDP query whose client
//!    sent a cookie without a valid server cookie gets BADCOOKIE; otherwise every query with
//!    a cookie is answered with the client cookie and a fresh server cookie.
//! 4. The [`Resolver`] answers into the [`AnswerBuf`], drops the query, or hands it to the
//!    forwarder ([`Reply::Forward`]: the transport passes it to the [`ForwardSink`]; with no
//!    sink the answer is SERVFAIL).
//! 5. The codec writes the answer within the limit of the transport (the requester's EDNS
//!    size up to the server's, 1232 unless set, 512 without EDNS, 65,535 on TCP) with the
//!    truncation rules; an answer it cannot write becomes SERVFAIL.
//! 6. With metrics on, the query is counted by transport, view and RCODE and its time from
//!    arrival to answer goes into the latency histogram, both on the worker's shard; the
//!    query log sink gets one entry without blocking.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use tenko_core::dns::{ForwardRuleId, QueryTransport, ViewId};

use crate::{
    authoritative::rcode,
    codec::{AnswerBuf, Codec, CodecError, DomainCodec, Request},
    cookie::{CookieMode, CookieSecret},
    log::{NullLog, QueryLogEntry, QueryLogSink},
    metrics,
    resolver::{QueryContext, Resolution, Resolver},
    wire::{self, MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD},
};

/// Records an answer may hold (a TCP answer of the largest RRset and its additional data).
pub const ANSWER_RECORDS: usize = 8192;

/// Octets of owner names and record data an answer may hold.
pub const ANSWER_ARENA: usize = 192 * 1024;

/// The buffers of one worker: the parsed request, the answer and the output.
#[derive(Debug)]
pub struct Scratch {
    request: Request,
    answer: AnswerBuf,
    /// The answer's octets after [`Responder::respond`] returned [`Reply::Send`].
    pub out: Vec<u8>,
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Scratch {
    /// Buffers with their full capacity; nothing grows after this.
    pub fn new() -> Self {
        Self {
            request: Request::default(),
            answer: AnswerBuf::with_capacity(ANSWER_RECORDS, ANSWER_ARENA),
            out: Vec::with_capacity(MAX_MESSAGE_LEN),
        }
    }
}

/// Where a query came from.
#[derive(Debug, Clone, Copy)]
pub struct Conn {
    /// The client's address and port.
    pub client: SocketAddr,
    /// The local address the query arrived on.
    pub local: SocketAddr,
    /// The transport.
    pub transport: QueryTransport,
}

/// The wall clock as a worker reads it: once a second, not per query.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    at: Instant,
    unix_micros: u64,
    /// Seconds since 1970 (the cookie timestamps).
    pub unix_secs: u64,
    /// The minute of the day in UTC (the time test of the views).
    pub minute_of_day: u16,
}

impl Default for Clock {
    fn default() -> Self {
        Self::now()
    }
}

impl Clock {
    /// Reads the clocks.
    pub fn now() -> Self {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let unix_secs = since.as_secs();
        Self {
            at: Instant::now(),
            unix_micros: u64::try_from(since.as_micros()).unwrap_or(u64::MAX),
            unix_secs,
            minute_of_day: u16::try_from((unix_secs % 86_400) / 60).unwrap_or(0),
        }
    }

    /// Reads the clocks again when a second has passed since the last read.
    pub fn refresh(&mut self, now: Instant) {
        if now.duration_since(self.at).as_secs() >= 1 {
            *self = Self::now();
        }
    }

    /// Microseconds since 1970 at `instant` (for the query log).
    pub fn micros_at(&self, instant: Instant) -> u64 {
        let since = instant.saturating_duration_since(self.at).as_micros();
        self.unix_micros
            .saturating_add(u64::try_from(since).unwrap_or(u64::MAX))
    }
}

/// What to do with a query after [`Responder::respond`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Send [`Scratch::out`].
    Send,
    /// Send nothing.
    Drop,
    /// Hand the query to [`Responder::forward`] with the transport's reply path.
    Forward {
        /// The view that matched.
        view: Option<ViewId>,
        /// The forwarding rule; `None` for the default forwarder.
        rule: Option<ForwardRuleId>,
    },
}

/// How the answer to a forwarded query reaches its client.
#[derive(Debug, Clone)]
pub enum ReplyPath {
    /// From the worker's UDP socket to the client's address.
    Udp(Arc<std::net::UdpSocket>),
    /// Into the client's TCP connection (the octets of one message, without the length).
    Tcp(tokio::sync::mpsc::Sender<Vec<u8>>),
}

/// A query handed to the forwarder.
#[derive(Debug, Clone)]
pub struct ForwardQuery {
    /// The query's octets.
    pub message: Vec<u8>,
    /// The client.
    pub client: SocketAddr,
    /// The transport it came on.
    pub transport: QueryTransport,
    /// The view that matched.
    pub view: Option<ViewId>,
    /// The rule; `None` for the default forwarder.
    pub rule: Option<ForwardRuleId>,
    /// Where the answer goes.
    pub reply: ReplyPath,
}

/// The forwarder's intake (WP4.3, WP5.1): it runs the upstream exchange off the query path
/// and answers the client through the reply path. `submit` must not block.
pub trait ForwardSink: Send + Sync {
    /// Takes one query.
    fn submit(&self, query: ForwardQuery);
}

/// The query path of every transport.
pub struct Responder<R> {
    codec: DomainCodec,
    resolver: R,
    cookies: CookieSecret,
    cookie_mode: CookieMode,
    log: Arc<dyn QueryLogSink>,
    log_on: bool,
    forward: Option<Arc<dyn ForwardSink>>,
    metrics: bool,
    udp_size: u16,
}

impl<R> std::fmt::Debug for Responder<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("cookie_mode", &self.cookie_mode)
            .field("log", &self.log_on)
            .field("forward", &self.forward.is_some())
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl<R: Resolver> Responder<R> {
    /// A responder with cookies on, no query log, no forwarder and metrics on.
    pub fn new(resolver: R, cookies: CookieSecret) -> Self {
        Self {
            codec: DomainCodec::new(),
            resolver,
            cookies,
            cookie_mode: CookieMode::On,
            log: Arc::new(NullLog),
            log_on: false,
            forward: None,
            metrics: true,
            udp_size: SERVER_UDP_PAYLOAD,
        }
    }

    /// The same responder with another EDNS UDP size (`edns.udp_size`), clamped to 512 to
    /// 4096: the largest UDP answer and the size the OPT record advertises.
    #[must_use]
    pub fn with_udp_size(mut self, size: u16) -> Self {
        self.udp_size = size.clamp(512, 4096);
        self
    }

    /// The same responder with another cookie mode.
    #[must_use]
    pub fn with_cookie_mode(mut self, mode: CookieMode) -> Self {
        self.cookie_mode = mode;
        self
    }

    /// The same responder with a query log.
    #[must_use]
    pub fn with_log(mut self, log: Arc<dyn QueryLogSink>) -> Self {
        self.log = log;
        self.log_on = true;
        self
    }

    /// The same responder with a forwarder.
    #[must_use]
    pub fn with_forwarder(mut self, forward: Arc<dyn ForwardSink>) -> Self {
        self.forward = Some(forward);
        self
    }

    /// The same responder with the metrics on or off (M22). The families are sealed when
    /// they are on.
    #[must_use]
    pub fn with_metrics(mut self, on: bool) -> Self {
        if on {
            metrics::seal();
        }
        self.metrics = on;
        self
    }

    /// The resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// The cookie secret.
    pub fn cookies(&self) -> &CookieSecret {
        &self.cookies
    }

    /// Answers one query; see the module documentation for the steps.
    pub fn respond(
        &self,
        message: &[u8],
        conn: &Conn,
        clock: &Clock,
        now: Instant,
        scratch: &mut Scratch,
    ) -> Reply {
        let Scratch {
            request,
            answer,
            out,
        } = scratch;
        let query = match self.codec.parse(message, request) {
            Ok(query) => query,
            Err(CodecError::NotAQuery) => return Reply::Drop,
            Err(_) => {
                if !wire::write_formerr(message, out) {
                    return Reply::Drop;
                }
                self.finish(conn, None, None, rcode::FORMERR, clock, now);
                return Reply::Send;
            }
        };
        answer.clear();
        answer.udp_payload = self.udp_size;
        let max_len = match conn.transport {
            QueryTransport::Udp => request.udp_len(self.udp_size),
            _ => MAX_MESSAGE_LEN,
        };
        let client = conn.client.ip();
        let cookie = match self.cookie_mode {
            CookieMode::Off => None,
            _ => request.edns.and_then(|edns| edns.cookie),
        };
        let mut view = None;
        if request.edns.is_some_and(|edns| edns.version != 0) {
            answer.rcode = rcode::BADVERS;
        } else if let Some(cookie) = &cookie
            && self.cookie_mode == CookieMode::Required
            && conn.transport == QueryTransport::Udp
            && !self.cookies.verify(cookie, client, clock.unix_secs)
        {
            answer.rcode = rcode::BADCOOKIE;
        } else {
            let context = QueryContext {
                request,
                client: conn.client,
                local: conn.local,
                transport: conn.transport,
                minute_of_day: clock.minute_of_day,
                now,
            };
            match self.resolver.resolve(&context, answer) {
                Resolution::Answered { view: matched } => view = matched,
                Resolution::Drop => return Reply::Drop,
                Resolution::Forward { view, rule } if self.forward.is_some() => {
                    return Reply::Forward { view, rule };
                }
                Resolution::Forward { view: matched, .. } => {
                    view = matched;
                    answer.clear();
                    answer.rcode = rcode::SERVFAIL;
                }
            }
        }
        if let Some(cookie) = &cookie {
            let option = self.cookies.answer_option(cookie, client, clock.unix_secs);
            let _ = answer.set_cookie(&option);
        }
        if self
            .codec
            .build(&query, request, answer, max_len, out)
            .is_err()
        {
            answer.clear();
            answer.rcode = rcode::SERVFAIL;
            if self
                .codec
                .build(&query, request, answer, max_len, out)
                .is_err()
            {
                return Reply::Drop;
            }
        }
        self.finish(conn, Some(request), view, answer.rcode, clock, now);
        Reply::Send
    }

    /// Hands a query the resolver sent to the forwarder (after [`Reply::Forward`]).
    /// Allocates the copy of the query: the forwarder runs off the query path.
    pub fn forward(&self, message: &[u8], conn: &Conn, reply: Reply, path: ReplyPath) {
        if let (Some(sink), Reply::Forward { view, rule }) = (&self.forward, reply) {
            sink.submit(ForwardQuery {
                message: message.to_vec(),
                client: conn.client,
                transport: conn.transport,
                view,
                rule,
                reply: path,
            });
        }
    }

    fn finish(
        &self,
        conn: &Conn,
        request: Option<&Request>,
        view: Option<ViewId>,
        rcode: u16,
        clock: &Clock,
        now: Instant,
    ) {
        if !self.metrics && !self.log_on {
            return;
        }
        let micros = u64::try_from(now.elapsed().as_micros()).unwrap_or(u64::MAX);
        if self.metrics {
            metrics::QUERY_COUNTER.inc(metrics::query_index(conn.transport, view.is_some(), rcode));
            metrics::QUERY_LATENCY.observe(metrics::proto_index(conn.transport), micros);
        }
        if self.log_on {
            self.log.record(&QueryLogEntry {
                at_micros: clock.micros_at(now),
                client: conn.client.ip(),
                transport: conn.transport,
                qname: request.map_or(&[0][..], |request| request.qname.as_wire()),
                qtype: request.map_or(0, |request| request.qtype),
                rcode,
                view,
                blocked: None,
                cached: false,
                duration_micros: u32::try_from(micros).unwrap_or(u32::MAX),
            });
        }
    }
}
