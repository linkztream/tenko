//! Outgoing queries (DNS-08): the query sent to an upstream, the check of its answer, and
//! the UDP sockets they leave from.
//!
//! - **The query** ([`build_query`]) is built anew for every attempt: a random id, the
//!   question with its letters in a random case (0x20, the case-randomisation draft of
//!   Dagon and others) unless the upstream breaks it, RD and CD from the client, and an
//!   OPT record of [`UPSTREAM_UDP_SIZE`] octets carrying the client's DO bit. The client's
//!   own options (its cookie among them) stay between the client and this node.
//! - **The answer** ([`check_answer`]) must carry the id, QR, opcode QUERY and the same
//!   question; with 0x20 the question must come back in exactly the case it was sent, else
//!   the answer is [`AnswerCheck::CaseBroken`] and is not used (the pool counts it per
//!   upstream and stops randomising the case of an upstream that breaks it twice).
//! - **The sockets** ([`UdpSockets`]): a query leaves from a socket bound to a random port
//!   that it holds alone for the exchange, taken from a bounded set of idle sockets per
//!   address family; a socket is retired after [`SOCKET_USES`] queries or
//!   [`SOCKET_AGE`], so ports keep changing without a new socket per query. A query to an
//!   upstream on a loopback address leaves from that address (its own set of sockets): its
//!   answer then comes back to the address it was sent from even where the host routes
//!   127.0.0.1 elsewhere (a WSL2 loopback relay).

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::wire::{self, HEADER_LEN, TYPE_OPT};

/// The EDNS size this node advertises to its upstreams (DNS flag day 2020).
pub const UPSTREAM_UDP_SIZE: u16 = 1_232;

/// Queries a UDP socket sends before it is closed.
pub const SOCKET_USES: u32 = 64;

/// The age after which an idle UDP socket is closed.
pub const SOCKET_AGE: Duration = Duration::from_secs(60);

/// Idle sockets kept per address family.
pub const IDLE_SOCKETS: usize = 64;

/// Attempts at binding a random port before the system picks one.
const BIND_ATTEMPTS: usize = 8;

/// Random octets from the system generator (aws-lc-rs). A failing generator leaves zeros:
/// the question check still guards the answer.
pub fn random_fill(out: &mut [u8]) {
    let _ = aws_lc_rs::rand::fill(out);
}

/// A random 16-bit value.
pub fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    random_fill(&mut bytes);
    u16::from_be_bytes(bytes)
}

/// A random 32-bit value.
pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    random_fill(&mut bytes);
    u32::from_be_bytes(bytes)
}

/// What an upstream query asks.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    /// The name in uncompressed wire form, in any case.
    pub qname: &'a [u8],
    /// The type.
    pub qtype: u16,
    /// The class.
    pub qclass: u16,
    /// Recursion desired.
    pub rd: bool,
    /// Checking disabled (copied from the client).
    pub cd: bool,
    /// DNSSEC OK (copied from the client).
    pub dnssec_ok: bool,
}

/// Builds the upstream query into `out` (replaced): `id`, the question with a random case
/// when `mix_case`, RD and CD, and the OPT record. Returns the end of the question.
pub fn build_query(out: &mut Vec<u8>, id: u16, question: &Question<'_>, mix_case: bool) -> usize {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.push(u8::from(question.rd));
    out.push(if question.cd { 0x10 } else { 0 });
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&1u16.to_be_bytes());
    let start = out.len();
    out.extend_from_slice(question.qname);
    if mix_case {
        mix(&mut out[start..]);
    } else {
        lower(&mut out[start..]);
    }
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
    let end = out.len();
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&UPSTREAM_UDP_SIZE.to_be_bytes());
    out.extend_from_slice(&[0, 0, if question.dnssec_ok { 0x80 } else { 0 }, 0]);
    out.extend_from_slice(&[0, 0]);
    end
}

/// Walks the labels of an uncompressed wire name and calls `f` on each letter.
fn letters(name: &mut [u8], mut f: impl FnMut(&mut u8)) {
    let mut pos = 0;
    while let Some(&len) = name.get(pos) {
        if len == 0 || len & 0xc0 != 0 {
            return;
        }
        let end = (pos + 1 + usize::from(len)).min(name.len());
        for octet in &mut name[pos + 1..end] {
            if octet.is_ascii_alphabetic() {
                f(octet);
            }
        }
        pos = end;
    }
}

fn lower(name: &mut [u8]) {
    letters(name, u8::make_ascii_lowercase);
}

/// Gives every letter of the name a random case.
fn mix(name: &mut [u8]) {
    let mut bits = [0u8; 32];
    random_fill(&mut bits);
    let mut index = 0usize;
    letters(name, |octet| {
        let bit = bits[(index / 8) % bits.len()] >> (index % 8) & 1;
        index += 1;
        if bit == 1 {
            octet.make_ascii_uppercase();
        } else {
            octet.make_ascii_lowercase();
        }
    });
}

/// What [`check_answer`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerCheck {
    /// The answer answers the query.
    Match,
    /// The answer has the id and the question, but the question's case differs (0x20).
    CaseBroken,
    /// Not an answer to this query.
    Other,
}

/// Whether `answer` answers `query`: the same id, QR set, opcode QUERY, one question and
/// the same question; with `exact_case`, the question name in exactly the case sent.
pub fn check_answer(query: &[u8], answer: &[u8], exact_case: bool) -> AnswerCheck {
    let (Some(asked), Some(got)) = (wire::parse_header(query), wire::parse_header(answer)) else {
        return AnswerCheck::Other;
    };
    if !got.qr || got.id != asked.id || got.opcode != 0 || got.qdcount != 1 {
        return AnswerCheck::Other;
    }
    let (Some(query_end), Some(answer_end)) = (
        wire::questions_end(query, 1),
        wire::questions_end(answer, 1),
    ) else {
        return AnswerCheck::Other;
    };
    let (asked, got) = (
        &query[HEADER_LEN..query_end],
        &answer[HEADER_LEN..answer_end],
    );
    if asked.len() != got.len()
        || asked[asked.len() - 4..] != got[got.len() - 4..]
        || !asked[..asked.len() - 4].eq_ignore_ascii_case(&got[..got.len() - 4])
    {
        return AnswerCheck::Other;
    }
    if exact_case && asked != got {
        return AnswerCheck::CaseBroken;
    }
    AnswerCheck::Match
}

/// One socket of the set.
#[derive(Debug)]
pub struct Pooled {
    socket: UdpSocket,
    uses: u32,
    born: Instant,
}

impl Pooled {
    /// The socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

/// The idle UDP sockets of the outgoing queries, per address family.
#[derive(Debug, Default)]
pub struct UdpSockets {
    idle: Mutex<std::collections::HashMap<std::net::IpAddr, Vec<Pooled>>>,
    stats: SocketStats,
}

/// The local address a query to `upstream` leaves from: the upstream's own address when it
/// is a loopback address, else the wildcard address of its family.
fn local_for(upstream: SocketAddr) -> std::net::IpAddr {
    match upstream.ip() {
        ip if ip.is_loopback() => ip,
        std::net::IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        std::net::IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

/// What the socket set counted.
#[derive(Debug, Default)]
struct SocketStats {
    opened: std::sync::atomic::AtomicU64,
    reused: std::sync::atomic::AtomicU64,
}

impl UdpSockets {
    /// The set every upstream of the process shares.
    pub fn global() -> &'static UdpSockets {
        static GLOBAL: OnceLock<UdpSockets> = OnceLock::new();
        GLOBAL.get_or_init(UdpSockets::default)
    }

    fn idle(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<std::net::IpAddr, Vec<Pooled>>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A socket of the family of `upstream` for one exchange: an idle one that is young
    /// enough, else a new one on a random port.
    ///
    /// # Errors
    ///
    /// The error of the last bind when no socket could be bound.
    pub async fn take(&self, upstream: SocketAddr) -> std::io::Result<Pooled> {
        let local = local_for(upstream);
        {
            let mut idle = self.idle();
            let list = idle.entry(local).or_default();
            while let Some(pooled) = list.pop() {
                if pooled.born.elapsed() < SOCKET_AGE && pooled.uses < SOCKET_USES {
                    self.stats
                        .reused
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(pooled);
                }
            }
        }
        let socket = bind_random(local).await?;
        self.stats
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Pooled {
            socket,
            uses: 0,
            born: Instant::now(),
        })
    }

    /// Gives a socket back after an exchange; it is closed when it has been used enough,
    /// is old, or the set is full.
    pub fn give(&self, mut pooled: Pooled, upstream: SocketAddr) {
        pooled.uses += 1;
        if pooled.uses >= SOCKET_USES || pooled.born.elapsed() >= SOCKET_AGE {
            return;
        }
        let mut idle = self.idle();
        let list = idle.entry(local_for(upstream)).or_default();
        if list.len() < IDLE_SOCKETS {
            list.push(pooled);
        }
    }

    /// Sockets opened and exchanges that reused an idle socket.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.stats.opened.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.reused.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// A UDP socket on `address` and a random port above 1023 (the system's choice after a few
/// ports in use). The bind runs on the blocking pool: on some hosts a bind takes
/// milliseconds (a WSL2 relay watches every new port), and the runtime's threads must not
/// wait for it.
async fn bind_random(address: std::net::IpAddr) -> std::io::Result<UdpSocket> {
    let socket = tokio::task::spawn_blocking(move || {
        for _ in 0..BIND_ATTEMPTS {
            let port = 1_024 + random_u16() % (u16::MAX - 1_024);
            if let Ok(socket) = std::net::UdpSocket::bind(SocketAddr::new(address, port)) {
                return Ok(socket);
            }
        }
        std::net::UdpSocket::bind(SocketAddr::new(address, 0))
    })
    .await
    .map_err(std::io::Error::other)??;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.split('.') {
            out.push(u8::try_from(label.len()).expect("label"));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn question(name: &[u8]) -> Question<'_> {
        Question {
            qname: name,
            qtype: 1,
            qclass: 1,
            rd: true,
            cd: false,
            dnssec_ok: true,
        }
    }

    fn answer_of(query: &[u8], end: usize) -> Vec<u8> {
        let mut answer = query[..end].to_vec();
        answer[2] |= 0x80;
        answer[10..12].copy_from_slice(&[0, 0]);
        answer
    }

    #[test]
    fn a_query_carries_the_question_rd_and_edns_with_do() {
        let name = wire_name("www.example.test");
        let mut out = Vec::new();
        let end = build_query(&mut out, 0xbeef, &question(&name), false);
        let header = wire::parse_header(&out).expect("header");
        assert_eq!(header.id, 0xbeef);
        assert!(header.rd && !header.qr);
        assert_eq!((header.qdcount, header.arcount), (1, 1));
        assert_eq!(&out[HEADER_LEN..end - 4], &name[..]);
        let opt = wire::read_record(&out, end).expect("opt");
        assert_eq!((opt.rtype, opt.class), (TYPE_OPT, UPSTREAM_UDP_SIZE));
        assert_eq!(opt.ttl & 0x8000, 0x8000, "DO copied");
    }

    #[test]
    fn mixed_case_keeps_the_name_and_changes_only_letters() {
        let name = wire_name("abcdefghijklmnop.qrstuvwxyz-0123.example.test");
        let mut seen_upper = false;
        let mut out = Vec::new();
        for _ in 0..8 {
            let end = build_query(&mut out, 1, &question(&name), true);
            let sent = &out[HEADER_LEN..end - 4];
            assert!(sent.eq_ignore_ascii_case(&name));
            assert_eq!(sent.len(), name.len());
            seen_upper |= sent.iter().any(u8::is_ascii_uppercase);
        }
        assert!(seen_upper, "64 random bits set some letter upper case");
    }

    #[test]
    fn an_answer_is_checked_by_id_question_and_case() {
        let name = wire_name("www.example.test");
        let mut query = Vec::new();
        let end = build_query(&mut query, 7, &question(&name), true);
        let answer = answer_of(&query, end);
        assert_eq!(check_answer(&query, &answer, true), AnswerCheck::Match);
        let mut lowered = answer.clone();
        lowered[HEADER_LEN..end].make_ascii_lowercase();
        let mut flipped = answer.clone();
        for octet in &mut flipped[HEADER_LEN + 1..end - 4] {
            if octet.is_ascii_alphabetic() {
                *octet ^= 0x20;
            }
        }
        assert_eq!(
            check_answer(&query, &flipped, true),
            AnswerCheck::CaseBroken
        );
        assert_eq!(check_answer(&query, &flipped, false), AnswerCheck::Match);
        let mut other_id = answer.clone();
        other_id[1] ^= 1;
        assert_eq!(check_answer(&query, &other_id, false), AnswerCheck::Other);
        let mut not_response = answer;
        not_response[2] &= 0x7f;
        assert_eq!(
            check_answer(&query, &not_response, false),
            AnswerCheck::Other
        );
    }

    #[tokio::test]
    async fn sockets_are_reused_then_retired() {
        let sockets = UdpSockets::default();
        let upstream: SocketAddr = "192.0.2.53:53".parse().expect("address");
        let first = sockets.take(upstream).await.expect("socket");
        let port = first.socket().local_addr().expect("local").port();
        assert!(port >= 1_024);
        sockets.give(first, upstream);
        let again = sockets.take(upstream).await.expect("socket");
        assert_eq!(again.socket().local_addr().expect("local").port(), port);
        let mut current = again;
        for _ in 0..SOCKET_USES {
            sockets.give(current, upstream);
            current = sockets.take(upstream).await.expect("socket");
        }
        assert_ne!(
            current.socket().local_addr().expect("local").port(),
            port,
            "a socket is retired after its uses"
        );
        assert!(sockets.counts().0 >= 2);
    }

    #[tokio::test]
    async fn a_loopback_upstream_is_asked_from_its_own_address() {
        let sockets = UdpSockets::default();
        let upstream: SocketAddr = "127.0.0.1:53".parse().expect("address");
        let socket = sockets.take(upstream).await.expect("socket");
        assert_eq!(
            socket.socket().local_addr().expect("local").ip(),
            upstream.ip()
        );
        let port = socket.socket().local_addr().expect("local").port();
        sockets.give(socket, upstream);
        let again = sockets.take(upstream).await.expect("socket");
        assert_eq!(again.socket().local_addr().expect("local").port(), port);
        let other = sockets
            .take("192.0.2.53:53".parse().expect("address"))
            .await
            .expect("socket");
        assert!(
            other
                .socket()
                .local_addr()
                .expect("local")
                .ip()
                .is_unspecified()
        );
    }
}
