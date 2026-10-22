#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use tenko_dns::{
    recurse::{
        message::parse,
        net::{answer_cookie, build, fuzz_answer},
    },
    recursion::{AuthorityQuery, ServerCookie},
};

// The input is an answer of an authority server: its cookie option as the client reads it
// (RFC 7873 section 5.3), its full RCODE and its records. The same input also supplies
// the cookies of a query, which is built, read back as a message and as the answer to
// itself: the server cookie the query carries is the one `answer_cookie` returns.
fuzz_target!(|data: &[u8]| {
    fuzz_answer(data);

    let client: Option<[u8; 8]> = data.get(..8).and_then(|bytes| bytes.try_into().ok());
    let server = data.get(8..data.len().min(40)).and_then(ServerCookie::new);
    let query = AuthorityQuery {
        server: "192.0.2.53:53".parse().expect("server"),
        qname: b"\x03www\x07example\x04test\x00",
        qtype: 1,
        qclass: 1,
        edns: true,
        tcp: false,
        mix_case: false,
        client_cookie: client,
        server_cookie: server,
        fresh_port: true,
        deadline: Instant::now(),
    };
    let mut out = Vec::new();
    build(&mut out, 0x1234, &query, true, server);

    let parsed = parse(&out).expect("a query built by the engine parses");
    assert_eq!(parsed.qname, query.qname);
    assert_eq!(parsed.qtype, 1);
    let opt = parsed.opt.expect("the query has an OPT record");
    assert!(!opt.bad_cookie_option);
    // A server cookie is only sent after a client cookie.
    assert_eq!(opt.cookie, client.map(|client| (client, server)));

    // The query as an answer to itself: the QR bit set.
    out[2] |= 0x80;
    let echoed = answer_cookie(&out, client).expect("a query's own cookie is ours");
    assert_eq!(echoed, client.and(server));
    // Another client cookie, or one where none was sent, is refused.
    if let Some(client) = client {
        let mut other = client;
        other[0] ^= 1;
        assert!(answer_cookie(&out, Some(other)).is_err());
        assert!(answer_cookie(&out, None).is_err());
    }
});
