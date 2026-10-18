#![no_main]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
    time::Instant,
};

use libfuzzer_sys::fuzz_target;
use tenko_core::{
    Revision,
    dns::{
        DnsName, Origin, QueryTransport, Rdata, RecordData, RrSet, ScopeName, SoaDefaults, Zone,
        ZoneId, ZoneKind, ZoneScope,
    },
    ipam::Stamp,
    principal::{Principal, SystemComponent},
};
use tenko_dns::{
    AnswerBuf, Codec, DnsData, DomainCodec, Request,
    authoritative::Authoritative,
    catalog::{Catalog, CatalogHandle},
    codec::{Cookie, Owner, Section},
    cookie::{CookieMode, CookieSecret},
    respond::{Clock, Conn, Reply, Responder, Scratch},
    wire::{self, MAX_MESSAGE_LEN},
};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

/// A small zone with an answer of every kind: positive, wildcard, CNAME, DNAME, a cut with
/// glue, MX with an address.
fn catalog() -> CatalogHandle {
    let stamp = Stamp::new(
        "2026-10-17T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Dns),
    );
    let zone = Zone {
        id: ZoneId::generate(),
        name: name("example.test"),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: vec![ZoneScope::default_scope()],
        serial: tenko_core::dns::SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        reverse_of: None,
        catalog: false,
        description: None,
        created: stamp.clone(),
        updated: stamp.clone(),
    };
    let mut image = DnsData::at(Revision(1));
    let rows = [
        (
            "example.test",
            RecordData::Soa {
                mname: name("ns1.example.test"),
                rname: name("hostmaster.example.test"),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 1_209_600,
                minimum: 300,
            },
        ),
        ("example.test", RecordData::Ns { host: name("ns1.example.test") }),
        ("ns1.example.test", RecordData::A { address: Ipv4Addr::new(192, 0, 2, 53) }),
        ("www.example.test", RecordData::A { address: Ipv4Addr::new(192, 0, 2, 1) }),
        ("*.wild.example.test", RecordData::A { address: Ipv4Addr::new(192, 0, 2, 9) }),
        ("alias.example.test", RecordData::Cname { target: name("www.example.test") }),
        ("old.example.test", RecordData::Dname { target: name("example.test") }),
        ("mail.example.test", RecordData::Mx { preference: 10, exchange: name("www.example.test") }),
        ("child.example.test", RecordData::Ns { host: name("ns.child.example.test") }),
        ("ns.child.example.test", RecordData::A { address: Ipv4Addr::new(192, 0, 2, 54) }),
    ];
    for (owner, data) in rows {
        let set = RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: name(owner),
            rtype: data.rtype(),
            ttl: 300,
            rdata: vec![Rdata::from_data(&data)],
            origin: Origin::Manual,
            key: None,
            updated: stamp.clone(),
        };
        image.rrsets.insert(set.key(), set);
    }
    image.zones.insert(zone.id, zone);
    CatalogHandle::new(Catalog::build(&image))
}

fn responders() -> &'static [Responder<Authoritative>; 3] {
    static RESPONDERS: OnceLock<[Responder<Authoritative>; 3]> = OnceLock::new();
    RESPONDERS.get_or_init(|| {
        let handle = catalog();
        let make = |mode| {
            Responder::new(
                Authoritative::new(handle.clone()),
                CookieSecret::with_secret([7; 16]),
            )
            .with_metrics(false)
            .with_cookie_mode(mode)
        };
        [
            make(CookieMode::Off),
            make(CookieMode::On),
            make(CookieMode::Required),
        ]
    })
}

/// Walks a built answer: the header counts must match the records that follow, and
/// nothing may follow the last one.
fn check_answer(out: &[u8], id: u16, limit: usize) {
    assert!(out.len() <= limit);
    let header = wire::parse_header(out).expect("an answer has a header");
    assert!(header.qr && header.id == id);
    let mut pos = wire::questions_end(out, header.qdcount).expect("the question");
    let records =
        u32::from(header.ancount) + u32::from(header.nscount) + u32::from(header.arcount);
    for _ in 0..records {
        pos = wire::read_record(out, pos).expect("a record").end();
    }
    assert_eq!(pos, out.len());
}

// The input starts with two control octets: the first picks the cookie mode, the transport
// and the client's address family, the second the build's size limit and the extras of the
// answer buffer; the rest is the message. The message goes through the whole responder
// (EDNS, cookies, the resolver on a small zone, the codec), then, when it parses, through
// a build of an answer with random cookie, extended error, truncation and required
// additional records, and its cookie through verification.
fuzz_target!(|data: &[u8]| {
    let [mode, extras, message @ ..] = data else {
        return;
    };
    let responder = &responders()[usize::from(*mode % 3)];
    let transport = if mode & 0x04 == 0 {
        QueryTransport::Udp
    } else {
        QueryTransport::Tcp
    };
    let client: IpAddr = if mode & 0x08 == 0 {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))
    } else {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 77))
    };
    let conn = Conn {
        client: SocketAddr::new(client, 40000),
        local: "192.0.2.53:53".parse().expect("local"),
        transport,
    };
    let mut scratch = Scratch::new();
    let clock = Clock::now();
    if responder.respond(message, &conn, &clock, Instant::now(), &mut scratch) == Reply::Send {
        let header = wire::parse_header(message).expect("a query answered has a header");
        if scratch.out.len() == 12 {
            // The header-only FORMERR.
            assert_eq!(wire::parse_header(&scratch.out).map(|h| h.id), Some(header.id));
        } else {
            check_answer(&scratch.out, header.id, MAX_MESSAGE_LEN);
        }
    }

    let codec = DomainCodec::new();
    let mut request = Request::default();
    let Ok(query) = codec.parse(message, &mut request) else {
        return;
    };
    if let Some(cookie) = request.edns.and_then(|edns| edns.cookie) {
        let secret = CookieSecret::with_secret([7; 16]);
        let _ = secret.verify(&cookie, client, 1_790_000_000);
        let option = secret.answer_option(&cookie, client, 1_790_000_000);
        let again = Cookie::from_option(&option).expect("a cookie of 24 octets");
        assert!(secret.verify(&again, client, 1_790_000_000));
    }
    let mut answer = AnswerBuf::with_capacity(64, 8192);
    answer.rcode = u16::from(extras & 0x1f);
    answer.truncated = extras & 0x20 != 0;
    for last in 0..(extras >> 6) * 8 {
        let _ = answer.push(Section::Answer, Owner::Qname, 1, 300, &[192, 0, 2, last]);
    }
    let _ = answer.push(
        Section::Authority,
        Owner::Name(b"\x07example\x04test\x00"),
        2,
        300,
        b"\x03ns1\x07example\x04test\x00",
    );
    for last in 0..u8::from(extras & 0x07) * 6 {
        let _ = answer.push(
            Section::Additional,
            Owner::Name(b"\x03ns1\x07example\x04test\x00"),
            1,
            300,
            &[198, 51, 100, last],
        );
        if last == 3 {
            answer.require_additional();
        }
    }
    if extras & 0x08 != 0 {
        let cookie: Vec<u8> = message.iter().copied().cycle().take(24).collect();
        if cookie.len() == 24 {
            let _ = answer.set_cookie(&cookie);
        }
    }
    if extras & 0x10 != 0 {
        let text = String::from_utf8_lossy(&message[..message.len().min(40)]).into_owned();
        let _ = answer.set_extended_error(u16::from(*mode), &text);
    }
    let limit = match extras & 0x03 {
        0 => 512,
        1 => request.max_udp_len(),
        2 => 100,
        _ => MAX_MESSAGE_LEN,
    };
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    if let Ok(outcome) = codec.build(&query, &request, &answer, limit, &mut out) {
        check_answer(&out, request.id, limit);
        let header = wire::parse_header(&out).expect("header");
        assert_eq!(header.tc, outcome.truncated);
        if outcome.truncated {
            assert_eq!((header.ancount, header.nscount), (0, 0));
        }
    }
});
