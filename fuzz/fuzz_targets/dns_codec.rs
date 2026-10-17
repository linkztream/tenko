#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_core::dns::{DnsName, RecordData, Rtype};
use tenko_dns::{
    AnswerBuf, Codec, DomainCodec, NameBuf, Request,
    codec::{Owner, Section},
    wire::{self, MAX_MESSAGE_LEN},
};

const SOA: &[u8] = b"\x03ns1\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\
\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x03\x84\x00\x12\x75\x00\x00\x00\x01\x2c";

// The input is a query. It is parsed, answered with records at the question name and the
// apex of `example.test` (so names compress against the question), built for UDP and for
// TCP, and the answer is parsed back as a message. The same input is also read as record
// data of the type in its first two octets and as names, the stored forms the engine
// copies into answers.
fuzz_target!(|data: &[u8]| {
    let codec = DomainCodec::new();
    let mut request = Request::default();
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    match codec.parse(data, &mut request) {
        Ok(query) => {
            let mut answer = AnswerBuf::with_capacity(16, 4096);
            answer.authoritative = true;
            let _ = answer.push(Section::Answer, Owner::Qname, 1, 300, &[192, 0, 2, 1]);
            let _ = answer.push(
                Section::Answer,
                Owner::Qname,
                5,
                300,
                b"\x03www\x07example\x04test\x00",
            );
            let _ = answer.push(
                Section::Authority,
                Owner::Name(b"\x07example\x04test\x00"),
                6,
                300,
                SOA,
            );
            let _ = answer.push(
                Section::Additional,
                Owner::Name(request.qname.as_wire()),
                28,
                300,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            );
            if let Some(edns) = request.edns
                && let Some(cookie) = edns.cookie
            {
                let mut full = [0u8; 16];
                full[..8].copy_from_slice(cookie.client());
                let _ = answer.set_cookie(&full);
                let _ = answer.set_extended_error(15, "blocked");
            }
            for limit in [request.max_udp_len(), MAX_MESSAGE_LEN] {
                if codec
                    .build(&query, &request, &answer, limit, &mut out)
                    .is_ok()
                {
                    assert!(out.len() <= limit);
                    let mut back = Request::default();
                    let header = wire::parse_header(&out).expect("an answer has a header");
                    assert!(header.qr && header.id == request.id);
                    // An answer is not a query: the codec drops it.
                    assert!(codec.parse(&out, &mut back).is_err());
                }
            }
            if let Some(tsig) = &request.tsig {
                let _ = tsig.mac(data);
                let _ = tsig.other(data);
                assert!(tsig.record_start < data.len());
            }
        }
        Err(_) => {
            let _ = wire::write_formerr(data, &mut out);
        }
    }
    if let [high, low, rest @ ..] = data {
        let rtype = Rtype(u16::from_be_bytes([*high, *low]));
        if let Ok(record) = RecordData::from_wire(rtype, rest) {
            let mut again = Vec::new();
            record.write_wire(&mut again);
            assert_eq!(RecordData::from_wire(rtype, &again).as_ref(), Ok(&record));
        }
    }
    if let Ok((name, len)) = DnsName::from_wire(data) {
        assert_eq!(name.to_wire(), &data[..len].to_ascii_lowercase()[..]);
    }
    let _ = NameBuf::from_wire(data);
    let mut name = NameBuf::root();
    let _ = wire::read_name(data, 0, &mut name);
});
