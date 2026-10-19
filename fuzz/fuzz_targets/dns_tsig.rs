#![no_main]

use std::{collections::BTreeMap, sync::Arc};

use libfuzzer_sys::fuzz_target;
use tenko_core::dns::{DnsName, Rdata, Rtype, TsigAlgorithm};
use tenko_dns::{
    tsig::{self, Keyring, Signer, TsigKey, Verifier},
    update::{
        message::{self, AnswerEdns, Prerequisite, Update, ede},
        prereq::{self, Records},
    },
    wire::{self, MAX_MESSAGE_LEN},
};

const NOW: u64 = 1_790_000_000;

fn key() -> Arc<TsigKey> {
    Arc::new(TsigKey::new(
        &DnsName::new("update.example.test").expect("name"),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef",
    ))
}

/// A few RRsets for the prerequisites.
struct Fixed(BTreeMap<(String, u16), Vec<Rdata>>);

impl Records for Fixed {
    fn rrset(&self, name: &DnsName, rtype: Rtype) -> Option<&[Rdata]> {
        self.0
            .get(&(name.as_str().to_owned(), rtype.0))
            .map(Vec::as_slice)
    }

    fn name_in_use(&self, name: &DnsName) -> bool {
        self.0.keys().any(|(owner, _)| owner == name.as_str())
    }
}

fn records() -> Fixed {
    let mut map = BTreeMap::new();
    map.insert(
        ("www.example.test".to_owned(), 1),
        vec![Rdata::from_wire(Rtype::A, &[192, 0, 2, 1]).expect("a")],
    );
    map.insert(
        ("example.test".to_owned(), 2),
        vec![Rdata::from_wire(Rtype::NS, b"\x03ns1\x07example\x04test\x00").expect("ns")],
    );
    Fixed(map)
}

/// Walks a written answer: the counts match the records, nothing follows the last one.
fn check_answer(out: &[u8], id: u16) {
    let header = wire::parse_header(out).expect("an answer has a header");
    assert!(header.qr && header.id == id && header.opcode == message::OPCODE_UPDATE);
    let mut pos = wire::questions_end(out, header.qdcount).expect("the zone section");
    let records =
        u32::from(header.ancount) + u32::from(header.nscount) + u32::from(header.arcount);
    for _ in 0..records {
        pos = wire::read_record(out, pos).expect("a record").end();
    }
    assert_eq!(pos, out.len());
}

// The first octet is control: bit 0 signs the message with the fuzz key before it is read
// (so that the verified paths see arbitrary bodies), bit 1 sets the time outside the
// fudge, bit 2 corrupts the last octet of the MAC. The rest is the message. It goes
// through the TSIG reader and verifier, the UPDATE parser with the format rules of RFC
// 2136, the prerequisites against a few RRsets, and the answer writer, signed in the MAC
// chain when the request verified and checked by the verifier of the other side.
fuzz_target!(|data: &[u8]| {
    let [control, body @ ..] = data else {
        return;
    };
    let key = key();
    let keyring = Keyring::default();
    keyring.replace_shared([Arc::clone(&key)]);
    let mut message = body.to_vec();
    if control & 0x01 != 0 && message.len() >= wire::HEADER_LEN {
        let at = if control & 0x02 != 0 { NOW - 3_600 } else { NOW };
        let mut signer = Signer::request(Arc::clone(&key));
        if signer.sign(&mut message, at, 0, &[], MAX_MESSAGE_LEN) && control & 0x04 != 0 {
            // The MAC sits before the last six octets (original id, error, other length).
            if let Some(octet) = message.len().checked_sub(7).and_then(|at| message.get_mut(at)) {
                *octet ^= 0x5a;
            }
        }
    }
    let message = message.as_slice();

    // TSIG first, as the update path reads it.
    let verified = match tsig::find(message) {
        Ok(Some(view)) => match tsig::verify_request(&keyring, message, &view, NOW) {
            Ok(verified) => Some(verified),
            Err(refused) => {
                let mut out = Vec::new();
                if message::write_answer(message, None, 9, None, &mut out) {
                    let _ = tsig::refusal_tsig(&mut out, &refused, &view, NOW, MAX_MESSAGE_LEN);
                    let id = wire::parse_header(message).expect("header").id;
                    check_answer(&out, id);
                }
                None
            }
        },
        _ => None,
    };

    let (zone_end, code) = match message::parse(message) {
        Ok(parsed) => {
            assert!(parsed.zone_end <= message.len());
            for prerequisite in &parsed.prerequisites {
                assert!(prerequisite.name().is_subdomain_of(&parsed.zone));
                if let Prerequisite::Equals { rdata, .. } = prerequisite {
                    assert!(!rdata.is_empty());
                }
            }
            for update in &parsed.updates {
                assert!(update.name().is_subdomain_of(&parsed.zone));
                if let Update::Add { rtype, .. } | Update::DeleteRecord { rtype, .. } = update {
                    assert!(!rtype.is_meta());
                }
            }
            let code = match prereq::check(&parsed.prerequisites, &records()) {
                Ok(()) => message::rcode::NOERROR,
                Err(unmet) => {
                    let _ = unmet.text();
                    unmet.rcode
                }
            };
            (Some(parsed.zone_end), code)
        }
        Err(error) => match error.rcode() {
            Some(code) => (error.zone_end(), code),
            None => return,
        },
    };
    let text = String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned();
    let edns = (control & 0x08 != 0).then_some(AnswerEdns {
        udp_size: 1232,
        error: Some((ede::OTHER, text.as_str())),
    });
    let mut out = Vec::new();
    if !message::write_answer(message, zone_end, code, edns, &mut out) {
        return;
    }
    let id = wire::parse_header(message).expect("header").id;
    check_answer(&out, id);
    if let Some(verified) = verified {
        let mut signer = Signer::answer(Arc::clone(&verified.key), verified.mac);
        assert!(signer.sign(&mut out, NOW, 0, &[], MAX_MESSAGE_LEN));
        check_answer(&out, id);
        let mut verifier = Verifier::new(Arc::clone(&key), verified.mac);
        verifier
            .verify(&out, NOW)
            .expect("the other side verifies the signed answer");
    }
});
