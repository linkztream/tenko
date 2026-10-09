//! Behavioural tests of both codecs through the shared hot path. Responses
//! are decoded with an independent decoder (hickory's full `Message`
//! decoder, or `domain` when hickory is not compiled in) and with the raw
//! header helpers.

use super::*;
use crate::wire::{
    self, QTYPE_A, QTYPE_AAAA, QTYPE_SOA, RCODE_FORMERR, RCODE_NOERROR, RCODE_NXDOMAIN,
    RCODE_REFUSED,
};
use crate::zone::Zone;

fn query(name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut q = Vec::new();
    wire::write_query(&mut q, 0x4242, name, qtype, edns);
    q
}

fn run<C: Codec>(req: &[u8]) -> Option<Vec<u8>> {
    let codec = C::new();
    let zone = Zone::new(1000);
    let mut key = NameKey::new();
    let mut out = Vec::with_capacity(1500);
    respond(&codec, &zone, req, &mut key, &mut out).then_some(out)
}

/// Checks that `resp` decodes with an independent decoder and returns
/// (answer types, authority types, OPT udp size, full 12-bit rcode).
#[cfg(feature = "backend-hickory")]
fn decode(resp: &[u8]) -> (Vec<u16>, Vec<u16>, Option<u16>, u16) {
    use hickory_proto::op::Message;
    let m = Message::from_vec(resp).expect("independent decode");
    let an = m
        .answers
        .iter()
        .map(|r| u16::from(r.record_type()))
        .collect();
    let ns = m
        .authorities
        .iter()
        .map(|r| u16::from(r.record_type()))
        .collect();
    let opt = m.edns.as_ref().map(|e| e.max_payload());
    (an, ns, opt, u16::from(m.metadata.response_code))
}

#[cfg(not(feature = "backend-hickory"))]
fn decode(resp: &[u8]) -> (Vec<u16>, Vec<u16>, Option<u16>, u16) {
    use domain::base::Message;
    let m = Message::from_octets(resp).expect("independent decode");
    let an = m
        .answer()
        .unwrap()
        .map(|r| r.unwrap().rtype().to_int())
        .collect();
    let ns = m
        .authority()
        .unwrap()
        .map(|r| r.unwrap().rtype().to_int())
        .collect();
    let opt = m.opt().map(|o| o.udp_payload_size());
    (an, ns, opt, m.opt_rcode().to_int())
}

fn check_all<C: Codec>() {
    // Positive answer with EDNS, mixed case.
    let req = query("HOST-7.Example.TEST", QTYPE_A, Some(4096));
    let resp = run::<C>(&req).unwrap();
    let h = wire::parse_header(&resp).unwrap();
    assert_eq!(
        (h.id, h.qr, h.aa, h.tc, h.ra, h.rcode),
        (0x4242, true, true, false, false, RCODE_NOERROR)
    );
    assert_eq!((h.qdcount, h.ancount, h.nscount, h.arcount), (1, 1, 0, 1));
    // Question echoed byte for byte (case preserved).
    assert_eq!(&resp[12..12 + 25], &req[12..12 + 25]);
    let (an, ns, opt, rcode) = decode(&resp);
    assert_eq!((an, ns, opt, rcode), (vec![1], vec![], Some(1232), 0));
    // The A record's address is the zone's address for host-7.
    let ip = Zone::address_for(7).octets();
    assert_eq!(&resp[resp.len() - 11 - 4..resp.len() - 11], &ip);

    // No EDNS: no OPT in the response.
    let resp = run::<C>(&query("host-7.example.test", QTYPE_A, None)).unwrap();
    let h = wire::parse_header(&resp).unwrap();
    assert_eq!((h.ancount, h.arcount), (1, 0));
    assert_eq!(&resp[resp.len() - 4..], &ip);

    // NXDOMAIN with SOA in authority.
    let resp = run::<C>(&query("nohost-1.example.test", QTYPE_A, Some(1232))).unwrap();
    let h = wire::parse_header(&resp).unwrap();
    assert_eq!(
        (h.aa, h.rcode, h.ancount, h.nscount, h.arcount),
        (true, RCODE_NXDOMAIN, 0, 1, 1)
    );
    assert_eq!(decode(&resp), (vec![], vec![6], Some(1232), 3));

    // NODATA for another type of an existing name.
    let resp = run::<C>(&query("host-1.example.test", QTYPE_AAAA, None)).unwrap();
    let h = wire::parse_header(&resp).unwrap();
    assert_eq!((h.rcode, h.ancount, h.nscount), (RCODE_NOERROR, 0, 1));

    // Apex SOA.
    let resp = run::<C>(&query("example.test", QTYPE_SOA, None)).unwrap();
    assert_eq!(decode(&resp).0, vec![6]);

    // Outside the zone: REFUSED, not authoritative.
    let resp = run::<C>(&query("www.example.org", QTYPE_A, None)).unwrap();
    let h = wire::parse_header(&resp).unwrap();
    assert_eq!((h.aa, h.rcode, h.ancount), (false, RCODE_REFUSED, 0));

    // EDNS version 1: BADVERS (extended RCODE 16).
    let mut req = query("host-1.example.test", QTYPE_A, Some(1232));
    let ver_pos = req.len() - 5; // OPT: ... ext-rcode, version, flags(2), rdlen(2)
    req[ver_pos] = 1;
    let resp = run::<C>(&req).unwrap();
    assert_eq!(decode(&resp).3, 16);
    assert_eq!(wire::parse_header(&resp).unwrap().rcode, 0);

    // Opcode STATUS (2): NOTIMP.
    let mut req = query("host-1.example.test", QTYPE_A, None);
    req[2] = 2 << 3;
    let resp = run::<C>(&req).unwrap();
    assert_eq!(wire::parse_header(&resp).unwrap().rcode, 4);

    // Garbage after a valid header: FORMERR. Responses and runts: dropped.
    let mut req = query("host-1.example.test", QTYPE_A, None);
    req.truncate(20);
    let resp = run::<C>(&req).unwrap();
    assert_eq!(wire::parse_header(&resp).unwrap().rcode, RCODE_FORMERR);
    let mut req = query("host-1.example.test", QTYPE_A, None);
    req[2] |= 0x80;
    assert!(run::<C>(&req).is_none());
    assert!(run::<C>(&[0u8; 5]).is_none());
}

fn check_truncation<C: Codec>() {
    // header 12 + question 25 + A record 16 + OPT 11 = 64 octets.
    let codec = C::new();
    let zone = Zone::new(1000);
    let req = query("host-1.example.test", QTYPE_A, Some(1232));
    let mut key = NameKey::new();
    let (q, meta) = codec.parse(&req, &mut key).unwrap();
    let outcome = decide(&zone, &key, &meta);
    let mut out = Vec::new();
    codec.build(&q, &meta, outcome, 64, &mut out).unwrap();
    let h = wire::parse_header(&out).unwrap();
    assert_eq!((out.len(), h.tc, h.ancount, h.arcount), (64, false, 1, 1));
    codec.build(&q, &meta, outcome, 63, &mut out).unwrap();
    let h = wire::parse_header(&out).unwrap();
    assert_eq!((out.len(), h.tc, h.ancount, h.arcount), (48, true, 0, 1));
}

#[cfg(feature = "backend-domain")]
#[test]
fn domain_behaviour() {
    check_all::<DomainCodec>();
    check_truncation::<DomainCodec>();
}

#[cfg(feature = "backend-hickory")]
#[test]
fn hickory_behaviour() {
    check_all::<HickoryCodec>();
    check_truncation::<HickoryCodec>();
}

/// Both crates produce the same octets for the common cases.
#[cfg(all(feature = "backend-domain", feature = "backend-hickory"))]
#[test]
fn same_bytes() {
    for (name, qtype, edns) in [
        ("host-99.example.test", QTYPE_A, Some(1232)),
        ("host-99.example.test", QTYPE_A, None),
        ("nohost-99.example.test", QTYPE_A, Some(1232)),
        ("example.test", QTYPE_SOA, None),
    ] {
        let req = query(name, qtype, edns);
        assert_eq!(
            run::<DomainCodec>(&req),
            run::<HickoryCodec>(&req),
            "{name}"
        );
    }
}
