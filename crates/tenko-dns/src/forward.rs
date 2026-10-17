//! The plain forwarder of Slice 4 (owner decision P2-Q16, WP4.3): queries outside the
//! authoritative zones go to configured upstream resolvers over UDP and TCP, with a timeout
//! and retries, without a cache and without policy, so that a node can stand in for a
//! home resolver from the first slice. The resolver of Slice 5 (WP5.1: cache, serve-stale,
//! DoT and DoH, 0x20) replaces it behind the same [`ForwardSink`] and [`Upstream`] traits.
//!
//! The query path hands a forwarded query to [`PlainForwarder::submit`], which only queues
//! the copy the responder made (`tests/alloc.rs` keeps the path itself allocation-free); a
//! full queue drops the query, as a busy resolver would. A dispatcher task on tokio runs
//! each query as its own task, up to a limit:
//!
//! 1. The upstreams are those of the forwarding rule the resolver chose, when it is a plain
//!    rule, else those of the configuration (`[dns] forwarders`).
//! 2. The upstream query is built anew: a random id, the client's question octets as sent
//!    (so the client's case comes back), RD and CD copied, and an OPT record with the DO bit
//!    copied when the client sent EDNS. The client's own options (its cookie among them)
//!    stay between the client and this node.
//! 3. Each attempt picks the next upstream (round-robin start per query, then the following
//!    ones), sends over UDP from a fresh socket (a random source port) or over TCP when the
//!    upstream is configured so, and repeats over TCP when the UDP answer is truncated. An
//!    answer must carry the id, QR and the same question, else it is ignored and the
//!    attempt waits on until its deadline.
//! 4. The answer is relayed with the client's id and RA set; a UDP answer longer than the
//!    client's limit is cut to the header and question with TC, so the client retries over
//!    TCP. When every attempt fails the client gets SERVFAIL.
//!
//! Forwarded answers are counted in `tenko_dns_queries_total` with the RCODE relayed and
//! observed in `tenko_dns_query_duration_seconds` from the hand-over to the answer.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::dns::{ForwardTransport, QueryTransport};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    authoritative::rcode,
    catalog::CatalogHandle,
    codec::{Codec, DomainCodec, Request},
    log::{QueryLogEntry, QueryLogSink},
    metrics,
    respond::{ForwardQuery, ForwardSink, ReplyPath},
    upstream::{Upstream, UpstreamError},
    wire::{self, HEADER_LEN, MAX_MESSAGE_LEN, SERVER_UDP_PAYLOAD, TYPE_OPT},
};

/// The default time an upstream has to answer one attempt.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2_000);

/// The default number of attempts after the first.
pub const DEFAULT_RETRIES: u8 = 2;

/// Forwarded queries waiting for the dispatcher before new ones are dropped.
pub const QUEUE: usize = 4_096;

/// Forwarded queries in flight at once.
pub const IN_FLIGHT: usize = 1_024;

/// The EDNS size this node advertises to its upstreams.
const UPSTREAM_UDP_SIZE: u16 = 1_232;

/// One upstream resolver over plain DNS: UDP with TCP on truncation, or TCP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainUpstream {
    /// The resolver's address and port.
    pub address: SocketAddr,
    /// Always TCP (`transport = "tcp"`).
    pub tcp_only: bool,
}

impl PlainUpstream {
    /// An upstream reached over UDP, TCP when an answer is truncated.
    pub const fn udp(address: SocketAddr) -> Self {
        Self {
            address,
            tcp_only: false,
        }
    }

    /// An upstream reached over TCP only.
    pub const fn tcp(address: SocketAddr) -> Self {
        Self {
            address,
            tcp_only: true,
        }
    }

    async fn over_udp(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<bool, UpstreamError> {
        let local: SocketAddr = if self.address.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|_| UpstreamError::Unreachable("no local UDP socket"))?;
        socket
            .connect(self.address)
            .await
            .map_err(|_| UpstreamError::Unreachable("the upstream address is unreachable"))?;
        socket
            .send(query)
            .await
            .map_err(|_| UpstreamError::Unreachable("the query could not be sent"))?;
        answer.clear();
        answer.resize(MAX_MESSAGE_LEN, 0);
        let deadline = tokio::time::Instant::from_std(deadline);
        loop {
            let received = tokio::time::timeout_at(deadline, socket.recv(answer)).await;
            match received {
                Err(_) => {
                    answer.clear();
                    return Err(UpstreamError::Timeout);
                }
                // A refused port (ICMP) or a receive error: this upstream does not answer.
                Ok(Err(_)) => {
                    answer.clear();
                    return Err(UpstreamError::Unreachable("the upstream refused the query"));
                }
                Ok(Ok(len)) => {
                    if matches(query, &answer[..len]) {
                        answer.truncate(len);
                        let truncated = wire::parse_header(answer).is_some_and(|h| h.tc);
                        return Ok(truncated);
                    }
                    // Not the answer to this query: keep waiting until the deadline.
                }
            }
        }
    }

    async fn over_tcp(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        let deadline = tokio::time::Instant::from_std(deadline);
        let exchange = async {
            let mut stream = TcpStream::connect(self.address)
                .await
                .map_err(|_| UpstreamError::Unreachable("no TCP connection to the upstream"))?;
            let _ = stream.set_nodelay(true);
            let len = u16::try_from(query.len())
                .map_err(|_| UpstreamError::Malformed("the query is too long"))?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(query);
            stream
                .write_all(&framed)
                .await
                .map_err(|_| UpstreamError::Unreachable("the query could not be sent"))?;
            let mut prefix = [0u8; 2];
            stream
                .read_exact(&mut prefix)
                .await
                .map_err(|_| UpstreamError::Unreachable("the connection closed"))?;
            answer.clear();
            answer.resize(usize::from(u16::from_be_bytes(prefix)), 0);
            stream
                .read_exact(answer)
                .await
                .map_err(|_| UpstreamError::Unreachable("the connection closed"))?;
            if matches(query, answer) {
                Ok(())
            } else {
                answer.clear();
                Err(UpstreamError::Malformed(
                    "the answer does not match the query",
                ))
            }
        };
        tokio::time::timeout_at(deadline, exchange)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

impl Upstream for PlainUpstream {
    fn transport(&self) -> ForwardTransport {
        ForwardTransport::Plain
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    async fn exchange(
        &self,
        query: &[u8],
        answer: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<(), UpstreamError> {
        if !self.tcp_only && !self.over_udp(query, answer, deadline).await? {
            return Ok(());
        }
        self.over_tcp(query, answer, deadline).await
    }
}

/// Whether `answer` answers `query`: the same id, QR set, one question, and the same
/// question (the name compared without regard to case).
fn matches(query: &[u8], answer: &[u8]) -> bool {
    let (Some(asked), Some(got)) = (wire::parse_header(query), wire::parse_header(answer)) else {
        return false;
    };
    if !got.qr || got.id != asked.id || got.opcode != 0 || got.qdcount != 1 {
        return false;
    }
    let (Some(query_end), Some(answer_end)) = (
        wire::questions_end(query, 1),
        wire::questions_end(answer, 1),
    ) else {
        return false;
    };
    let (asked, got) = (
        &query[HEADER_LEN..query_end],
        &answer[HEADER_LEN..answer_end],
    );
    asked.len() == got.len()
        && asked[..asked.len() - 4].eq_ignore_ascii_case(&got[..got.len() - 4])
        && asked[asked.len() - 4..] == got[got.len() - 4..]
}

/// The settings of the plain forwarder (`[dns] forwarders`, `timeout_ms`, `retries`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSettings {
    /// The default upstreams; empty forwards nothing (the resolver answers REFUSED).
    pub upstreams: Vec<PlainUpstream>,
    /// The time one attempt has.
    pub timeout: Duration,
    /// Attempts after the first.
    pub retries: u8,
    /// The server's EDNS UDP size (`edns.udp_size`), the upper bound of a UDP answer.
    pub udp_size: u16,
    /// Count forwarded answers in the engine's metrics.
    pub metrics: bool,
}

impl Default for ForwardSettings {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            udp_size: SERVER_UDP_PAYLOAD,
            metrics: true,
        }
    }
}

/// What the forwarder counted since it started.
#[derive(Debug, Default)]
pub struct ForwardCounters {
    /// Queries handed over.
    pub submitted: AtomicU64,
    /// Queries dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Answers relayed from an upstream.
    pub answered: AtomicU64,
    /// Queries answered with SERVFAIL because every attempt failed.
    pub failed: AtomicU64,
    /// Attempts that timed out.
    pub timeouts: AtomicU64,
}

/// A copy of the counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardStats {
    /// Queries handed over.
    pub submitted: u64,
    /// Queries dropped because the queue was full.
    pub dropped: u64,
    /// Answers relayed from an upstream.
    pub answered: u64,
    /// Queries answered with SERVFAIL.
    pub failed: u64,
    /// Attempts that timed out.
    pub timeouts: u64,
}

struct Submitted {
    query: ForwardQuery,
    at: Instant,
}

/// The intake of the plain forwarder; see the module documentation.
pub struct PlainForwarder {
    queue: mpsc::Sender<Submitted>,
    counters: Arc<ForwardCounters>,
    upstreams: Vec<PlainUpstream>,
}

impl std::fmt::Debug for PlainForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainForwarder")
            .field("upstreams", &self.upstreams)
            .finish_non_exhaustive()
    }
}

impl PlainForwarder {
    /// Starts the dispatcher on the current tokio runtime; it ends when `stop` is
    /// cancelled. `log` gets one entry per forwarded query.
    pub fn start(
        settings: ForwardSettings,
        catalog: CatalogHandle,
        log: Option<Arc<dyn QueryLogSink>>,
        stop: CancellationToken,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        if settings.metrics {
            metrics::seal();
        }
        let (sender, receiver) = mpsc::channel(QUEUE);
        let counters = Arc::new(ForwardCounters::default());
        let forwarder = Arc::new(Self {
            queue: sender,
            counters: Arc::clone(&counters),
            upstreams: settings.upstreams.clone(),
        });
        let shared = Arc::new(Shared {
            settings,
            catalog,
            log,
            counters,
            next: AtomicUsize::new(0),
        });
        let task = tokio::spawn(dispatch(shared, receiver, stop));
        (forwarder, task)
    }

    /// The configured upstreams.
    pub fn upstreams(&self) -> &[PlainUpstream] {
        &self.upstreams
    }

    /// The counters.
    pub fn stats(&self) -> ForwardStats {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ForwardStats {
            submitted: read(&self.counters.submitted),
            dropped: read(&self.counters.dropped),
            answered: read(&self.counters.answered),
            failed: read(&self.counters.failed),
            timeouts: read(&self.counters.timeouts),
        }
    }
}

impl ForwardSink for PlainForwarder {
    fn submit(&self, query: ForwardQuery) {
        self.counters.submitted.fetch_add(1, Ordering::Relaxed);
        if self
            .queue
            .try_send(Submitted {
                query,
                at: Instant::now(),
            })
            .is_err()
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Shared {
    settings: ForwardSettings,
    catalog: CatalogHandle,
    log: Option<Arc<dyn QueryLogSink>>,
    counters: Arc<ForwardCounters>,
    next: AtomicUsize,
}

async fn dispatch(
    shared: Arc<Shared>,
    mut receiver: mpsc::Receiver<Submitted>,
    stop: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(IN_FLIGHT));
    loop {
        let submitted = tokio::select! {
            () = stop.cancelled() => return,
            submitted = receiver.recv() => match submitted {
                Some(submitted) => submitted,
                None => return,
            },
        };
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            handle(&shared, submitted).await;
            drop(permit);
        });
    }
}

/// The upstreams for a query: those of its plain rule, else the configured ones.
fn upstreams_for(shared: &Shared, query: &ForwardQuery) -> Vec<PlainUpstream> {
    if let Some(rule) = query.rule {
        let catalog = shared.catalog.load();
        if let Some(rule) = catalog.forward_rule(rule) {
            if rule.transport != ForwardTransport::Plain {
                // DoT and DoH upstreams come with the resolver of WP5.1.
                return Vec::new();
            }
            return rule
                .upstreams
                .iter()
                .map(|upstream| {
                    PlainUpstream::udp(SocketAddr::new(
                        upstream.address,
                        upstream.port.unwrap_or(53),
                    ))
                })
                .collect();
        }
    }
    shared.settings.upstreams.clone()
}

/// The query sent upstream: a fresh id, the client's question, RD and CD, EDNS with DO.
fn upstream_query(message: &[u8], request: &Request, id: u16) -> Option<Vec<u8>> {
    let header = wire::parse_header(message)?;
    let end = wire::questions_end(message, 1)?;
    let mut out = Vec::with_capacity(end + wire::OPT_LEN);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(u8::from(header.rd));
    out.push(if header.cd { 0x10 } else { 0 });
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16::from(request.edns.is_some()).to_be_bytes());
    out.extend_from_slice(&message[HEADER_LEN..end]);
    if let Some(edns) = request.edns {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&UPSTREAM_UDP_SIZE.to_be_bytes());
        out.extend_from_slice(&[0, 0, if edns.dnssec_ok { 0x80 } else { 0 }, 0]);
        out.extend_from_slice(&[0, 0]);
    }
    Some(out)
}

/// A header-and-question answer to the client's message with `code` (SERVFAIL) or TC.
fn short_answer(message: &[u8], code: u16, truncated: bool) -> Option<Vec<u8>> {
    let header = wire::parse_header(message)?;
    let end = wire::questions_end(message, 1)?;
    let mut out = Vec::with_capacity(end);
    out.extend_from_slice(&message[..2]);
    out.push(0x80 | (header.opcode << 3) | if truncated { 0x02 } else { 0 } | u8::from(header.rd));
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the low four bits of the RCODE"
    )]
    out.push(0x80 | (code & 0x0f) as u8);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&message[HEADER_LEN..end]);
    Some(out)
}

fn random_id() -> u16 {
    let mut bytes = [0u8; 2];
    // A failing generator leaves id 0; the question check still guards the answer.
    let _ = aws_lc_rs::rand::fill(&mut bytes);
    u16::from_be_bytes(bytes)
}

async fn handle(shared: &Shared, submitted: Submitted) {
    let Submitted { query, at } = submitted;
    let codec = DomainCodec::new();
    let mut request = Request::default();
    if codec.parse(&query.message, &mut request).is_err() {
        return;
    }
    let upstreams = upstreams_for(shared, &query);
    let mut answer = Vec::new();
    let mut answered = false;
    if !upstreams.is_empty() {
        let id = random_id();
        if let Some(sent) = upstream_query(&query.message, &request, id) {
            let start = shared.next.fetch_add(1, Ordering::Relaxed);
            let attempts = usize::from(shared.settings.retries) + 1;
            for attempt in 0..attempts {
                let upstream = upstreams[(start + attempt) % upstreams.len()];
                let deadline = Instant::now() + shared.settings.timeout;
                match upstream.exchange(&sent, &mut answer, deadline).await {
                    Ok(()) => {
                        answered = true;
                        break;
                    }
                    Err(UpstreamError::Timeout) => {
                        shared.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::debug!(%error, upstream = %upstream.address, "a forwarded query failed");
                    }
                }
            }
        }
    }
    let mut code = rcode::SERVFAIL;
    if answered {
        shared.counters.answered.fetch_add(1, Ordering::Relaxed);
        answer[..2].copy_from_slice(&request.id.to_be_bytes());
        answer[3] |= 0x80;
        code = u16::from(answer[3] & 0x0f);
        if query.transport == QueryTransport::Udp
            && answer.len() > request.udp_len(shared.settings.udp_size)
        {
            match short_answer(&answer, code, true) {
                Some(cut) => answer = cut,
                None => return,
            }
        }
    } else {
        shared.counters.failed.fetch_add(1, Ordering::Relaxed);
        match short_answer(&query.message, rcode::SERVFAIL, false) {
            Some(failed) => answer = failed,
            None => return,
        }
    }
    match &query.reply {
        ReplyPath::Udp(socket) => {
            let _ = socket.send_to(&answer, query.client);
        }
        ReplyPath::Tcp(sender) => {
            let _ = sender.send(answer).await;
        }
    }
    let micros = u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX);
    if shared.settings.metrics {
        metrics::QUERY_COUNTER.inc(metrics::query_index(
            query.transport,
            query.view.is_some(),
            code,
        ));
        metrics::QUERY_LATENCY.observe(metrics::proto_index(query.transport), micros);
    }
    if let Some(log) = &shared.log {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .saturating_sub(u128::from(micros));
        log.record(&QueryLogEntry {
            at_micros: u64::try_from(since).unwrap_or(u64::MAX),
            client: query.client.ip(),
            transport: query.transport,
            qname: request.qname.as_wire(),
            qtype: request.qtype,
            rcode: code,
            view: query.view,
            blocked: None,
            cached: false,
            duration_micros: u32::try_from(micros).unwrap_or(u32::MAX),
        });
    }
}

#[cfg(test)]
mod tests;
