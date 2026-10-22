//! The [`Authority`] on the network ([`NetAuthority`]): one exchange with one authority
//! server over the outbound layer ([`crate::outbound`]), with the defences of DNS-08 and the
//! fallback ladder of recursion plan section 2.1.
//!
//! - **The query**: a random id, no RD, the question as the engine gives it (with 0x20
//!   applied when `mix_case`), and with EDNS an OPT record of 1,232 octets with DO and the
//!   cookie option (the client cookie, and the server cookie when one is known).
//! - **UDP** from a socket of the authorities' set: one use per socket (a fresh port per
//!   exchange) unless `[dns.recursion] fresh_port_per_query` is off, then the upstreams'
//!   policy. An answer from another address, with another id or another question is
//!   unwanted: counted per server ([`ServerTable::unwanted`]) and ignored while the deadline
//!   runs. An answer whose question is in another case than sent is
//!   [`AuthorityError::Malformed`] `"0x20"`.
//! - **The ladder**: FORMERR or NOTIMP to a query with EDNS (and no OPT in the answer) is
//!   asked once more without EDNS; a truncated UDP answer is asked again over TCP (RFC 7766,
//!   RFC 9210); BADCOOKIE is asked once more with the server cookie it carried (RFC 7873
//!   section 5.3); a timeout is never a reason to drop EDNS (RFC 8906).
//! - **TCP**: a connection per exchange, length-prefixed, within the deadline.
//! - **Cookies**: an answer to a query with a client cookie whose cookie option carries
//!   another client cookie is not ours (RFC 7873 section 5.3): ignored on UDP, malformed on
//!   TCP.

use std::{sync::Arc, time::Instant};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::message;
use crate::{
    infra::ServerTable,
    outbound::{AnswerCheck, UdpSockets, check_answer, random_u16},
    recursion::{
        Authority, AuthorityError, AuthorityQuery, AuthorityTransport, Exchange, ServerCookie,
        authority::AUTHORITY_UDP_SIZE,
    },
    wire::{self, HEADER_LEN, MAX_MESSAGE_LEN, OPTION_COOKIE, TYPE_OPT},
};

/// The RCODE BADCOOKIE (RFC 7873 section 8).
pub const BADCOOKIE: u16 = 23;

const FORMERR: u16 = 1;
const NOTIMP: u16 = 4;

/// The authority on the network; see the module documentation.
#[derive(Debug)]
pub struct NetAuthority {
    fresh: UdpSockets,
    reused: &'static UdpSockets,
    servers: Arc<ServerTable>,
}

impl NetAuthority {
    /// The authority counting unwanted answers in `servers`.
    pub fn new(servers: Arc<ServerTable>) -> Self {
        Self {
            fresh: UdpSockets::with_uses(1),
            reused: UdpSockets::global(),
            servers,
        }
    }

    /// The sockets opened and reused by exchanges with a fresh port.
    pub fn socket_counts(&self) -> (u64, u64) {
        self.fresh.counts()
    }
}

/// Writes the query of one exchange into `out`: returns the end of the question.
pub fn build(
    out: &mut Vec<u8>,
    id: u16,
    query: &AuthorityQuery<'_>,
    edns: bool,
    server_cookie: Option<ServerCookie>,
) -> usize {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
    out.extend_from_slice(query.qname);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());
    let end = out.len();
    if edns {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&AUTHORITY_UDP_SIZE.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0x80, 0]);
        match query.client_cookie {
            Some(client) => {
                let server = server_cookie
                    .as_ref()
                    .map_or(&[][..], ServerCookie::as_bytes);
                let len = u16::try_from(8 + server.len()).unwrap_or(8);
                out.extend_from_slice(&(len + 4).to_be_bytes());
                out.extend_from_slice(&OPTION_COOKIE.to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&client);
                out.extend_from_slice(server);
            }
            None => out.extend_from_slice(&[0, 0]),
        }
    }
    end
}

/// The cookie option of an answer as RFC 7873 section 5.3 reads it, for a query that sent
/// `client`: the server cookie it carries, if any.
///
/// # Errors
///
/// English text when the answer carries another client cookie, a cookie to a query that
/// sent none, a server cookie of a bad length or malformed options: it is not ours.
pub fn answer_cookie(
    answer: &[u8],
    client: Option<[u8; 8]>,
) -> Result<Option<ServerCookie>, &'static str> {
    let Some(opt) = opt_of(answer) else {
        return Ok(None);
    };
    let mut cookie = None;
    let mut options = wire::options(opt);
    for (code, value) in options.by_ref() {
        if code != OPTION_COOKIE {
            continue;
        }
        let Some(sent) = client else {
            return Err("a cookie in the answer to a query without one");
        };
        if value.len() < 8 || value.get(..8) != Some(&sent[..]) {
            return Err("another client cookie");
        }
        if value.len() == 8 {
            continue;
        }
        cookie = Some(ServerCookie::new(&value[8..]).ok_or("a server cookie of a bad length")?);
    }
    if options.malformed() {
        return Err("malformed EDNS options");
    }
    Ok(cookie)
}

/// The data of the OPT record of `message`, when it has one.
fn opt_of(message: &[u8]) -> Option<&[u8]> {
    let header = wire::parse_header(message)?;
    let mut pos = wire::questions_end(message, header.qdcount)?;
    let total =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    for _ in 0..total {
        let record = wire::read_record(message, pos)?;
        if record.rtype == TYPE_OPT {
            return Some(record.data(message));
        }
        pos = record.end();
    }
    None
}

/// The full RCODE of an answer: the header's four bits and the OPT record's upper eight.
pub fn full_rcode(message: &[u8]) -> Option<u16> {
    let header = wire::parse_header(message)?;
    let mut pos = wire::questions_end(message, header.qdcount)?;
    let total =
        usize::from(header.ancount) + usize::from(header.nscount) + usize::from(header.arcount);
    let mut upper = 0u16;
    for _ in 0..total {
        let record = wire::read_record(message, pos)?;
        if record.rtype == TYPE_OPT {
            upper = u16::try_from(record.ttl >> 24).unwrap_or(0);
        }
        pos = record.end();
    }
    Some((upper << 4) | u16::from(header.rcode & 0x0f))
}

/// What one transport attempt gave.
enum Got {
    Answer,
    Truncated,
}

impl NetAuthority {
    async fn udp(
        &self,
        query: &AuthorityQuery<'_>,
        sent: &[u8],
        answer: &mut Vec<u8>,
    ) -> Result<Got, AuthorityError> {
        let server = query.server;
        let sockets = if query.fresh_port {
            &self.fresh
        } else {
            self.reused
        };
        let pooled = sockets
            .take(server)
            .await
            .map_err(|_| AuthorityError::Unreachable("no local UDP socket"))?;
        let socket = pooled.socket();
        socket
            .send_to(sent, server)
            .await
            .map_err(|_| AuthorityError::Unreachable("the query could not be sent"))?;
        answer.clear();
        answer.resize(MAX_MESSAGE_LEN, 0);
        let deadline = tokio::time::Instant::from_std(query.deadline);
        loop {
            match tokio::time::timeout_at(deadline, socket.recv_from(answer)).await {
                Err(_) => {
                    answer.clear();
                    return Err(AuthorityError::Timeout);
                }
                Ok(Err(_)) => {
                    answer.clear();
                    return Err(AuthorityError::Unreachable("the server refused the query"));
                }
                Ok(Ok((len, from))) => {
                    let from_server = from.port() == server.port()
                        && from.ip().to_canonical() == server.ip().to_canonical();
                    let check = check_answer(sent, &answer[..len], query.mix_case);
                    if from_server && check == AnswerCheck::CaseBroken {
                        answer.clear();
                        return Err(AuthorityError::Malformed("0x20"));
                    }
                    let ours = from_server
                        && check == AnswerCheck::Match
                        && answer_cookie(&answer[..len], query.client_cookie).is_ok();
                    if !ours {
                        // Unwanted: another source, another id or question, another cookie.
                        self.servers.unwanted(server.ip(), Instant::now());
                        continue;
                    }
                    answer.truncate(len);
                    sockets.give(pooled, server);
                    let truncated = wire::parse_header(answer).is_some_and(|header| header.tc);
                    return Ok(if truncated {
                        Got::Truncated
                    } else {
                        Got::Answer
                    });
                }
            }
        }
    }

    async fn tcp(
        query: &AuthorityQuery<'_>,
        sent: &[u8],
        answer: &mut Vec<u8>,
    ) -> Result<(), AuthorityError> {
        let exchange = async {
            let mut stream = TcpStream::connect(query.server)
                .await
                .map_err(|_| AuthorityError::Unreachable("no TCP connection to the server"))?;
            let _ = stream.set_nodelay(true);
            let len = u16::try_from(sent.len())
                .map_err(|_| AuthorityError::Malformed("the query is too long"))?;
            let mut framed = Vec::with_capacity(sent.len() + 2);
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(sent);
            stream
                .write_all(&framed)
                .await
                .map_err(|_| AuthorityError::Unreachable("the query could not be sent"))?;
            let mut prefix = [0u8; 2];
            stream
                .read_exact(&mut prefix)
                .await
                .map_err(|_| AuthorityError::Unreachable("the connection closed"))?;
            answer.clear();
            answer.resize(usize::from(u16::from_be_bytes(prefix)), 0);
            stream
                .read_exact(answer)
                .await
                .map_err(|_| AuthorityError::Unreachable("the connection closed"))?;
            match check_answer(sent, answer, query.mix_case) {
                AnswerCheck::Match => {}
                AnswerCheck::CaseBroken => return Err(AuthorityError::Malformed("0x20")),
                AnswerCheck::Other => {
                    return Err(AuthorityError::Malformed(
                        "the answer does not match the query",
                    ));
                }
            }
            answer_cookie(answer, query.client_cookie).map_err(AuthorityError::Malformed)?;
            Ok(())
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(query.deadline), exchange)
            .await
            .map_err(|_| AuthorityError::Timeout)?
    }
}

impl Authority for NetAuthority {
    async fn exchange(
        &self,
        query: &AuthorityQuery<'_>,
        answer: &mut Vec<u8>,
    ) -> Result<Exchange, AuthorityError> {
        let mut edns = query.edns;
        let mut tcp = query.tcp;
        let mut truncated = false;
        let mut server_cookie = query.server_cookie;
        let mut cookie_retried = false;
        let mut edns_retried = false;
        let mut sent = Vec::with_capacity(HEADER_LEN + query.qname.len() + 64);
        loop {
            build(&mut sent, random_u16(), query, edns, server_cookie);
            let started = Instant::now();
            if tcp {
                Self::tcp(query, &sent, answer).await?;
            } else if let Got::Truncated = self.udp(query, &sent, answer).await? {
                truncated = true;
                tcp = true;
                continue;
            }
            let rtt = started.elapsed();
            let rcode = full_rcode(answer).ok_or(AuthorityError::Malformed("the answer"))?;
            let has_opt = opt_of(answer).is_some();
            if edns && !has_opt && (rcode == FORMERR || rcode == NOTIMP) && !edns_retried {
                edns = false;
                edns_retried = true;
                continue;
            }
            let cookie = if edns {
                answer_cookie(answer, query.client_cookie).map_err(AuthorityError::Malformed)?
            } else {
                None
            };
            if rcode == BADCOOKIE {
                if cookie_retried || cookie.is_none() {
                    return Err(AuthorityError::BadCookie);
                }
                cookie_retried = true;
                server_cookie = cookie;
                continue;
            }
            return Ok(Exchange {
                transport: if tcp {
                    AuthorityTransport::Tcp
                } else {
                    AuthorityTransport::Udp
                },
                edns: edns && has_opt,
                truncated,
                rtt,
                server_cookie: cookie,
            });
        }
    }
}

/// Reads an answer for the fuzz target: the parse and the cookie check of an answer.
pub fn fuzz_answer(data: &[u8]) {
    let client = data
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok());
    let _ = answer_cookie(data, client);
    let _ = full_rcode(data);
    let _ = message::parse(data);
}

#[cfg(test)]
mod tests;
