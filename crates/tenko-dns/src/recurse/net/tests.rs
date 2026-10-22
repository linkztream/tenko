//! The authority on the network against a scripted UDP and TCP server on loopback: the
//! query it builds, the cookie rules of its answers, and the fallback ladder of an
//! exchange (EDNS, TCP, BADCOOKIE), with the unwanted answers it counts and the 0x20 case
//! it checks.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Mutex, PoisonError},
    time::Duration,
};

use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

use super::*;

const CLIENT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const OLD_COOKIE: [u8; 16] = [0x10; 16];
const NEW_COOKIE: [u8; 16] = [0x20; 16];
const A: u16 = 1;
const IN: u16 = 1;

// ---------------------------------------------------------------------------------------
// Helpers

fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in text.split('.') {
        out.push(u8::try_from(label.len()).expect("a short label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// An EDNS cookie option: the client cookie and the server cookie (possibly empty).
fn cookie_option(client: &[u8], server: &[u8]) -> Vec<u8> {
    let len = u16::try_from(client.len() + server.len()).expect("a short cookie");
    let mut out = OPTION_COOKIE.to_be_bytes().to_vec();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(client);
    out.extend_from_slice(server);
    out
}

fn query_to(server: SocketAddr, qname: &[u8]) -> AuthorityQuery<'_> {
    AuthorityQuery {
        server,
        qname,
        qtype: A,
        qclass: IN,
        edns: true,
        tcp: false,
        mix_case: false,
        client_cookie: Some(CLIENT),
        server_cookie: None,
        fresh_port: true,
        deadline: in_ms(3_000),
    }
}

fn in_ms(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

fn unused_server() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 53))
}

/// The cookie option value of a query's OPT record: the client cookie and any server cookie.
fn query_cookie(query: &[u8]) -> Option<Vec<u8>> {
    let opt = opt_of(query)?;
    wire::options(opt)
        .find(|(code, _)| *code == OPTION_COOKIE)
        .map(|(_, value)| value.to_vec())
}

/// An answer the scripted server writes.
#[derive(Clone, Default)]
struct Reply {
    /// The full RCODE (the upper bits go to the OPT record).
    rcode: u16,
    tc: bool,
    /// The options of an OPT record; `None` writes no OPT record.
    options: Option<Vec<u8>>,
    /// An id other than the query's.
    id: Option<u16>,
    /// The question in lower case, whatever case came.
    lower_case: bool,
    /// One A record in the answer section.
    answer: bool,
}

impl Reply {
    fn answer() -> Self {
        Self {
            answer: true,
            ..Self::default()
        }
    }

    /// The answer with the cookie option `client` + `server`.
    fn with_cookie(client: &[u8], server: &[u8]) -> Self {
        Self {
            options: Some(cookie_option(client, server)),
            ..Self::answer()
        }
    }

    /// The answer to `query`.
    fn to(&self, query: &[u8]) -> Vec<u8> {
        let header = wire::parse_header(query).expect("a query header");
        let question_end = wire::questions_end(query, 1).expect("a question");
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.unwrap_or(header.id).to_be_bytes());
        out.push(0x80 | 0x04 | if self.tc { 0x02 } else { 0 });
        out.push(u8::try_from(self.rcode & 0x0f).expect("four bits"));
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&u16::from(self.answer).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&u16::from(self.options.is_some()).to_be_bytes());
        let question = out.len();
        out.extend_from_slice(&query[HEADER_LEN..question_end]);
        if self.lower_case {
            let name_end = out.len() - 4;
            out[question..name_end].make_ascii_lowercase();
        }
        if self.answer {
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&A.to_be_bytes());
            out.extend_from_slice(&IN.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        }
        if let Some(options) = &self.options {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&AUTHORITY_UDP_SIZE.to_be_bytes());
            let upper = u32::from(self.rcode >> 4) << 24;
            out.extend_from_slice(&upper.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(options.len())
                    .expect("short options")
                    .to_be_bytes(),
            );
            out.extend_from_slice(options);
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Udp,
    Tcp,
}

/// A query the scripted server received.
#[derive(Clone)]
struct Seen {
    via: Via,
    from: SocketAddr,
    query: Vec<u8>,
}

type Handler = Arc<dyn Fn(&Seen) -> Vec<Vec<u8>> + Send + Sync>;

/// A server on 127.0.0.1 answering on one port over UDP and TCP; the handler gives the
/// messages (zero or more) to write for each query.
struct Lab {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Lab {
    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }
}

fn record(log: &Mutex<Vec<Seen>>, seen: &Seen) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(seen.clone());
}

async fn lab(handler: impl Fn(&Seen) -> Vec<Vec<u8>> + Send + Sync + 'static) -> Lab {
    let handler: Handler = Arc::new(handler);
    let log = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..20 {
        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a UDP socket on loopback");
        let addr = udp.local_addr().expect("the UDP address");
        let Ok(tcp) = TcpListener::bind(addr).await else {
            continue;
        };
        let udp_task = {
            let (handler, log) = (Arc::clone(&handler), Arc::clone(&log));
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_MESSAGE_LEN];
                loop {
                    let (len, from) = match udp.recv_from(&mut buf).await {
                        Ok(got) => got,
                        // Windows reports an ICMP error of an earlier send on the next read.
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                            continue;
                        }
                        Err(_) => return,
                    };
                    let seen = Seen {
                        via: Via::Udp,
                        from,
                        query: buf[..len].to_vec(),
                    };
                    record(&log, &seen);
                    for reply in handler(&seen) {
                        let _ = udp.send_to(&reply, from).await;
                    }
                }
            })
        };
        let tcp_task = {
            let (handler, log) = (Arc::clone(&handler), Arc::clone(&log));
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, from)) = tcp.accept().await else {
                        return;
                    };
                    let (handler, log) = (Arc::clone(&handler), Arc::clone(&log));
                    tokio::spawn(async move {
                        loop {
                            let mut prefix = [0u8; 2];
                            if stream.read_exact(&mut prefix).await.is_err() {
                                return;
                            }
                            let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                            if stream.read_exact(&mut query).await.is_err() {
                                return;
                            }
                            let seen = Seen {
                                via: Via::Tcp,
                                from,
                                query,
                            };
                            record(&log, &seen);
                            for reply in handler(&seen) {
                                let len = u16::try_from(reply.len()).expect("a short reply");
                                let mut framed = len.to_be_bytes().to_vec();
                                framed.extend_from_slice(&reply);
                                if stream.write_all(&framed).await.is_err() {
                                    return;
                                }
                            }
                        }
                    });
                }
            })
        };
        return Lab {
            addr,
            seen: log,
            tasks: vec![udp_task, tcp_task],
        };
    }
    panic!("no free port for the scripted server");
}

fn authority() -> (NetAuthority, Arc<ServerTable>) {
    let servers = Arc::new(ServerTable::new(64, Duration::from_secs(3_600)));
    (NetAuthority::new(Arc::clone(&servers)), servers)
}

/// A query built the way the exchange builds it, for the answers of the cookie tests.
fn built_query(client: Option<[u8; 8]>) -> Vec<u8> {
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        client_cookie: client,
        ..query_to(unused_server(), &qname)
    };
    let mut out = Vec::new();
    build(&mut out, 0x1234, &query, true, None);
    out
}

fn server_cookie(bytes: &[u8]) -> ServerCookie {
    ServerCookie::new(bytes).expect("a server cookie of 8 to 32 octets")
}

// ---------------------------------------------------------------------------------------
// build

#[test]
fn build_writes_a_query_without_rd_and_with_the_question_as_given() {
    let qname = wire_name("WwW.ExAmPle.TeSt");
    let query = query_to(unused_server(), &qname);
    let mut out = vec![0xee; 40];
    let end = build(&mut out, 0xabcd, &query, true, None);
    let header = wire::parse_header(&out).expect("a header");
    assert_eq!(header.id, 0xabcd);
    assert!(
        !header.qr && !header.rd,
        "a query without recursion desired"
    );
    assert_eq!(header.opcode, 0);
    assert_eq!(
        (
            header.qdcount,
            header.ancount,
            header.nscount,
            header.arcount
        ),
        (1, 0, 0, 1)
    );
    assert_eq!(
        &out[HEADER_LEN..end - 4],
        &qname[..],
        "the case is the caller's (0x20 is the engine's)"
    );
    assert_eq!(&out[end - 4..end], &[0, 1, 0, 1], "A, IN");
    let opt = wire::read_record(&out, end).expect("the OPT record");
    assert_eq!(opt.rtype, TYPE_OPT);
    assert_eq!(opt.class, 1_232, "the one EDNS size of authority queries");
    assert_eq!(opt.ttl & 0x8000, 0x8000, "DO");
    assert_eq!(opt.ttl >> 24, 0, "no extended RCODE");
    assert_eq!(opt.end(), out.len(), "nothing after the OPT record");
    let options: Vec<_> = wire::options(opt.data(&out)).collect();
    assert_eq!(options, vec![(OPTION_COOKIE, &CLIENT[..])]);
}

#[test]
fn build_without_edns_writes_no_opt_record() {
    let qname = wire_name("www.example.test");
    let query = query_to(unused_server(), &qname);
    let mut out = Vec::new();
    let end = build(&mut out, 7, &query, false, None);
    let header = wire::parse_header(&out).expect("a header");
    assert_eq!(header.arcount, 0);
    assert_eq!(end, out.len(), "the message ends with the question");
}

#[test]
fn build_carries_the_server_cookie_after_the_client_cookie() {
    let qname = wire_name("www.example.test");
    let query = query_to(unused_server(), &qname);
    let mut out = Vec::new();
    let end = build(&mut out, 7, &query, true, Some(server_cookie(&OLD_COOKIE)));
    let opt = wire::read_record(&out, end).expect("the OPT record");
    let options: Vec<_> = wire::options(opt.data(&out)).collect();
    let mut expected = CLIENT.to_vec();
    expected.extend_from_slice(&OLD_COOKIE);
    assert_eq!(options, vec![(OPTION_COOKIE, &expected[..])]);
    // The shortest and the longest server cookie.
    for len in [8usize, 32] {
        let cookie = server_cookie(&vec![0x33; len]);
        build(&mut out, 7, &query, true, Some(cookie));
        let opt = wire::read_record(&out, end).expect("the OPT record");
        assert_eq!(opt.rdlen, 4 + 8 + len);
    }
}

#[test]
fn build_without_a_client_cookie_writes_an_empty_opt_record_and_no_server_cookie() {
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        client_cookie: None,
        ..query_to(unused_server(), &qname)
    };
    let mut out = Vec::new();
    let end = build(&mut out, 7, &query, true, Some(server_cookie(&OLD_COOKIE)));
    let opt = wire::read_record(&out, end).expect("the OPT record");
    assert_eq!(opt.rdlen, 0, "a server cookie alone is not sent");
}

// ---------------------------------------------------------------------------------------
// answer_cookie and full_rcode

fn answer_with(options: Option<Vec<u8>>) -> Vec<u8> {
    Reply {
        options,
        ..Reply::answer()
    }
    .to(&built_query(Some(CLIENT)))
}

#[test]
fn an_answer_without_a_cookie_is_fine() {
    assert_eq!(answer_cookie(&answer_with(None), Some(CLIENT)), Ok(None));
    assert_eq!(
        answer_cookie(&answer_with(Some(Vec::new())), Some(CLIENT)),
        Ok(None),
        "an OPT record without options"
    );
    assert_eq!(
        answer_cookie(&answer_with(None), None),
        Ok(None),
        "no cookie asked, none given"
    );
    let other_option = [0, 15, 0, 2, 0, 22];
    assert_eq!(
        answer_cookie(&answer_with(Some(other_option.to_vec())), Some(CLIENT)),
        Ok(None),
        "an option that is not a cookie"
    );
}

#[test]
fn an_answer_with_our_client_cookie_gives_the_server_cookie() {
    let answer = answer_with(Some(cookie_option(&CLIENT, &NEW_COOKIE)));
    assert_eq!(
        answer_cookie(&answer, Some(CLIENT)),
        Ok(Some(server_cookie(&NEW_COOKIE)))
    );
    let echo = answer_with(Some(cookie_option(&CLIENT, &[])));
    assert_eq!(
        answer_cookie(&echo, Some(CLIENT)),
        Ok(None),
        "the client cookie alone carries no server cookie"
    );
    for len in [8usize, 32] {
        let answer = answer_with(Some(cookie_option(&CLIENT, &vec![5; len])));
        assert_eq!(
            answer_cookie(&answer, Some(CLIENT)),
            Ok(Some(server_cookie(&vec![5; len]))),
            "a server cookie of {len} octets"
        );
    }
}

#[test]
fn an_answer_with_another_client_cookie_is_not_ours() {
    let answer = answer_with(Some(cookie_option(&[9; 8], &NEW_COOKIE)));
    assert_eq!(
        answer_cookie(&answer, Some(CLIENT)),
        Err("another client cookie")
    );
}

#[test]
fn an_answer_with_a_cookie_to_a_query_without_one_is_not_ours() {
    let answer = answer_with(Some(cookie_option(&CLIENT, &[])));
    assert!(answer_cookie(&answer, None).is_err());
}

#[test]
fn a_cookie_option_of_a_bad_length_or_a_broken_option_is_refused() {
    // 4 octets of server cookie, 33 octets, a client cookie cut short.
    for (what, option) in [
        ("a short server cookie", cookie_option(&CLIENT, &[1; 4])),
        ("a long server cookie", cookie_option(&CLIENT, &[1; 33])),
        ("a short client cookie", cookie_option(&CLIENT[..5], &[])),
    ] {
        let answer = answer_with(Some(option));
        assert!(answer_cookie(&answer, Some(CLIENT)).is_err(), "{what}");
    }
    // An option that claims more octets than the OPT record holds.
    let broken = [0, 10, 0, 16, 1, 2, 3];
    let answer = answer_with(Some(broken.to_vec()));
    assert_eq!(
        answer_cookie(&answer, Some(CLIENT)),
        Err("malformed EDNS options")
    );
}

#[test]
fn full_rcode_joins_the_header_bits_and_the_opt_records_upper_bits() {
    let query = built_query(Some(CLIENT));
    let badcookie = Reply {
        rcode: 23,
        options: Some(Vec::new()),
        ..Reply::default()
    }
    .to(&query);
    assert_eq!(full_rcode(&badcookie), Some(23));
    let refused = Reply {
        rcode: 5,
        options: Some(Vec::new()),
        ..Reply::default()
    }
    .to(&query);
    assert_eq!(full_rcode(&refused), Some(5));
    let nxdomain = Reply {
        rcode: 3,
        ..Reply::default()
    }
    .to(&query);
    assert_eq!(full_rcode(&nxdomain), Some(3), "without an OPT record");
    assert_eq!(full_rcode(&nxdomain[..HEADER_LEN - 1]), None, "no header");
    assert_eq!(
        full_rcode(&badcookie[..badcookie.len() - 1]),
        None,
        "a cut OPT record"
    );
}

// ---------------------------------------------------------------------------------------
// exchange

/// What the plain scripted server answers: the cookie the query sent with `NEW_COOKIE`.
fn answer_with_a_cookie(seen: &Seen) -> Vec<Vec<u8>> {
    let sent = query_cookie(&seen.query).expect("a cookie in the query");
    vec![Reply::with_cookie(&sent[..8], &NEW_COOKIE).to(&seen.query)]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_exchange_answers_over_udp_with_edns_and_returns_the_server_cookie() {
    let lab = lab(answer_with_a_cookie).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        server_cookie: Some(server_cookie(&OLD_COOKIE)),
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query, &mut answer)
        .await
        .expect("the exchange succeeds");
    assert_eq!(exchange.transport, AuthorityTransport::Udp);
    assert!(exchange.edns, "the answer carries an OPT record");
    assert!(!exchange.truncated);
    assert!(
        exchange.rtt > Duration::ZERO,
        "the round-trip time is measured"
    );
    assert_eq!(exchange.server_cookie, Some(server_cookie(&NEW_COOKIE)));
    let parsed = message::parse(&answer).expect("the answer parses");
    assert_eq!((parsed.rcode, parsed.answer.len()), (0, 1));
    let seen = lab.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].via, Via::Udp);
    let sent = wire::parse_header(&seen[0].query).expect("the query");
    assert!(!sent.rd, "recursion is not desired of an authority");
    let mut cookie = CLIENT.to_vec();
    cookie.extend_from_slice(&OLD_COOKIE);
    assert_eq!(
        query_cookie(&seen[0].query),
        Some(cookie),
        "the query carried both cookies"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exchange_without_edns_or_cookies_sends_a_bare_query() {
    let lab = lab(|seen| vec![Reply::answer().to(&seen.query)]).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        edns: false,
        client_cookie: None,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query, &mut answer)
        .await
        .expect("the exchange succeeds");
    assert!(!exchange.edns);
    assert_eq!(exchange.server_cookie, None);
    assert!(opt_of(&lab.seen()[0].query).is_none(), "no OPT record sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn formerr_without_opt_to_an_edns_query_is_asked_again_without_edns() {
    let lab = lab(|seen| {
        let reply = if opt_of(&seen.query).is_some() {
            Reply {
                rcode: 1,
                ..Reply::default()
            }
        } else {
            Reply::answer()
        };
        vec![reply.to(&seen.query)]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("the retry succeeds");
    assert!(!exchange.edns, "the answer came to a query without EDNS");
    assert_eq!(exchange.server_cookie, None);
    assert_eq!(full_rcode(&answer), Some(0));
    let seen = lab.seen();
    assert_eq!(seen.len(), 2, "one retry");
    assert!(opt_of(&seen[0].query).is_some());
    assert!(opt_of(&seen[1].query).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_formerr_is_not_retried_again() {
    let lab = lab(|seen| {
        vec![
            Reply {
                rcode: 1,
                ..Reply::default()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("a FORMERR answer is an answer");
    assert!(!exchange.edns);
    assert_eq!(full_rcode(&answer), Some(1));
    assert_eq!(lab.seen().len(), 2, "one retry, no more");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_udp_answer_is_followed_over_tcp() {
    let lab = lab(|seen| {
        let reply = match seen.via {
            Via::Udp => Reply {
                tc: true,
                ..Reply::default()
            },
            Via::Tcp => Reply::with_cookie(&CLIENT, &NEW_COOKIE),
        };
        vec![reply.to(&seen.query)]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("the TCP exchange succeeds");
    assert!(exchange.truncated);
    assert_eq!(exchange.transport, AuthorityTransport::Tcp);
    assert!(exchange.edns);
    assert_eq!(exchange.server_cookie, Some(server_cookie(&NEW_COOKIE)));
    assert_eq!(
        message::parse(&answer).expect("the answer").answer.len(),
        1,
        "the TCP answer, not the truncated one"
    );
    let vias: Vec<_> = lab.seen().iter().map(|seen| seen.via).collect();
    assert_eq!(vias, vec![Via::Udp, Via::Tcp]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_query_that_asks_for_tcp_goes_straight_to_tcp() {
    let lab = lab(|seen| vec![Reply::with_cookie(&CLIENT, &NEW_COOKIE).to(&seen.query)]).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        tcp: true,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query, &mut answer)
        .await
        .expect("the TCP exchange succeeds");
    assert_eq!(exchange.transport, AuthorityTransport::Tcp);
    assert!(!exchange.truncated);
    let vias: Vec<_> = lab.seen().iter().map(|seen| seen.via).collect();
    assert_eq!(vias, vec![Via::Tcp]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn badcookie_is_asked_again_with_the_server_cookie_it_carried() {
    let lab = lab(|seen| {
        let sent = query_cookie(&seen.query).expect("a cookie in the query");
        let reply = if sent.len() == 8 {
            Reply {
                rcode: 23,
                options: Some(cookie_option(&sent[..8], &NEW_COOKIE)),
                ..Reply::default()
            }
        } else {
            Reply::with_cookie(&sent[..8], &sent[8..])
        };
        vec![reply.to(&seen.query)]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let exchange = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("the retry with the new cookie succeeds");
    assert_eq!(exchange.server_cookie, Some(server_cookie(&NEW_COOKIE)));
    assert_eq!(full_rcode(&answer), Some(0));
    let seen = lab.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(query_cookie(&seen[0].query), Some(CLIENT.to_vec()));
    let mut retried = CLIENT.to_vec();
    retried.extend_from_slice(&NEW_COOKIE);
    assert_eq!(
        query_cookie(&seen[1].query),
        Some(retried),
        "the retry carried the new server cookie"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn badcookie_twice_is_an_error() {
    let lab = lab(|seen| {
        let sent = query_cookie(&seen.query).expect("a cookie in the query");
        vec![
            Reply {
                rcode: 23,
                options: Some(cookie_option(&sent[..8], &NEW_COOKIE)),
                ..Reply::default()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let error = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect_err("BADCOOKIE after the retry");
    assert_eq!(error, AuthorityError::BadCookie);
    assert_eq!(lab.seen().len(), 2, "one retry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn badcookie_without_a_server_cookie_is_not_retried() {
    let lab = lab(|seen| {
        vec![
            Reply {
                rcode: 23,
                options: Some(Vec::new()),
                ..Reply::default()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    let error = net
        .exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect_err("BADCOOKIE with nothing to retry with");
    assert_eq!(error, AuthorityError::BadCookie);
    assert_eq!(lab.seen().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_with_another_id_is_unwanted_and_the_right_one_after_it_is_taken() {
    let lab = lab(|seen| {
        let id = wire::parse_header(&seen.query).expect("a header").id;
        vec![
            Reply {
                id: Some(id ^ 1),
                ..Reply::answer()
            }
            .to(&seen.query),
            Reply::answer().to(&seen.query),
        ]
    })
    .await;
    let (net, servers) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    net.exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("the right answer is taken");
    assert_eq!(
        servers.figures(lab.ip(), Instant::now()).unwanted,
        1,
        "the answer with the other id is counted for the server"
    );
    assert_eq!(servers.unwanted_total(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_whose_question_comes_back_in_another_case_is_a_0x20_failure() {
    let lab = lab(|seen| {
        vec![
            Reply {
                lower_case: true,
                ..Reply::answer()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    // The engine mixes the case before it calls; the query here arrives mixed.
    let qname = wire_name("WwW.ExAmPle.TeSt");
    let query = AuthorityQuery {
        mix_case: true,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("the case is broken");
    assert_eq!(error, AuthorityError::Malformed("0x20"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_case_is_only_checked_when_the_query_mixes_it() {
    let lab = lab(|seen| {
        vec![
            Reply {
                lower_case: true,
                ..Reply::answer()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("WwW.ExAmPle.TeSt");
    let mut answer = Vec::new();
    net.exchange(&query_to(lab.addr, &qname), &mut answer)
        .await
        .expect("a lower-case answer to a query that did not mix is fine");
    // A server that echoes the case exactly passes the check.
    let echo = self::lab(|seen| vec![Reply::answer().to(&seen.query)]).await;
    let query = AuthorityQuery {
        mix_case: true,
        ..query_to(echo.addr, &qname)
    };
    net.exchange(&query, &mut answer)
        .await
        .expect("an exact echo passes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_0x20_check_holds_over_tcp_as_well() {
    let lab = lab(|seen| {
        vec![
            Reply {
                lower_case: true,
                ..Reply::answer()
            }
            .to(&seen.query),
        ]
    })
    .await;
    let (net, _) = authority();
    let qname = wire_name("WwW.ExAmPle.TeSt");
    let query = AuthorityQuery {
        mix_case: true,
        tcp: true,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("the case is broken");
    assert_eq!(error, AuthorityError::Malformed("0x20"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_with_another_client_cookie_is_ignored_until_the_deadline() {
    let lab = lab(|seen| vec![Reply::with_cookie(&[9; 8], &NEW_COOKIE).to(&seen.query)]).await;
    let (net, servers) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        deadline: in_ms(300),
        ..query_to(lab.addr, &qname)
    };
    let started = Instant::now();
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("no answer of ours came");
    assert_eq!(error, AuthorityError::Timeout);
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "the exchange waited for the deadline"
    );
    assert_eq!(servers.figures(lab.ip(), Instant::now()).unwanted, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_with_another_client_cookie_over_tcp_is_malformed() {
    let lab = lab(|seen| vec![Reply::with_cookie(&[9; 8], &NEW_COOKIE).to(&seen.query)]).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        tcp: true,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("another client cookie");
    assert_eq!(error, AuthorityError::Malformed("another client cookie"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_answer_is_a_timeout_within_the_deadline() {
    let lab = lab(|_| Vec::new()).await;
    let (net, servers) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        deadline: in_ms(250),
        ..query_to(lab.addr, &qname)
    };
    let started = Instant::now();
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("the server is silent");
    let waited = started.elapsed();
    assert_eq!(error, AuthorityError::Timeout);
    assert!(waited >= Duration::from_millis(240), "waited {waited:?}");
    assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    assert_eq!(lab.seen().len(), 1, "a timeout is not retried without EDNS");
    assert_eq!(servers.figures(lab.ip(), Instant::now()).unwanted, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_answer_over_tcp_is_a_timeout_within_the_deadline() {
    let lab = lab(|_| Vec::new()).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        tcp: true,
        deadline: in_ms(250),
        ..query_to(lab.addr, &qname)
    };
    let started = Instant::now();
    let mut answer = Vec::new();
    let error = net
        .exchange(&query, &mut answer)
        .await
        .expect_err("the server is silent");
    assert_eq!(error, AuthorityError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_port_exchange_leaves_from_a_new_port_every_time() {
    let lab = lab(|seen| vec![Reply::answer().to(&seen.query)]).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let mut answer = Vec::new();
    for _ in 0..2 {
        net.exchange(&query_to(lab.addr, &qname), &mut answer)
            .await
            .expect("the exchange succeeds");
    }
    let seen = lab.seen();
    assert_eq!(seen.len(), 2);
    assert_ne!(
        seen[0].from.port(),
        seen[1].from.port(),
        "two exchanges, two source ports"
    );
    assert_eq!(
        net.socket_counts(),
        (2, 0),
        "two sockets opened, none reused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exchange_without_a_fresh_port_may_reuse_the_socket_of_the_set() {
    let lab = lab(|seen| vec![Reply::answer().to(&seen.query)]).await;
    let (net, _) = authority();
    let qname = wire_name("www.example.test");
    let query = AuthorityQuery {
        fresh_port: false,
        ..query_to(lab.addr, &qname)
    };
    let mut answer = Vec::new();
    for _ in 0..4 {
        net.exchange(&query, &mut answer)
            .await
            .expect("the exchange succeeds");
    }
    let ports: std::collections::HashSet<u16> =
        lab.seen().iter().map(|seen| seen.from.port()).collect();
    assert!(
        ports.len() < 4,
        "the shared set hands the idle socket on: {} ports for 4 exchanges",
        ports.len()
    );
    assert_eq!(
        net.socket_counts(),
        (0, 0),
        "the fresh-port set was not used"
    );
}
