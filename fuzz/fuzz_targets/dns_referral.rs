#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::recurse::message::{
    Composed, GlueKind, MAX_RECORDS, Rr, Step, classify, compose, parse, within,
};

/// The zones a server can be asked as: lowercase wire names, the root and two levels down.
const ZONES: [&[u8]; 3] = [b"\x00", b"\x04test\x00", b"\x07example\x04test\x00"];

fn check_within(records: &[Rr], zone: &[u8], what: &str) {
    for rr in records {
        assert!(
            within(&rr.owner, zone),
            "{what}: the owner {:?} of a record of type {} is outside the zone {zone:?}",
            rr.owner,
            rr.rtype,
        );
    }
}

// The first octet picks the zone the server was asked as, the rest is the server's answer.
// A message that parses is classified for the question it carries; the step must keep to
// the bailiwick rules (RFC 9471, RFC 2181 section 5.4.1): a referral goes strictly below
// the zone, its glue is within the zone and in-domain glue within the delegated zone, and
// the records of an answer or a negative answer are the zone's own. What the engine
// would store (an answer or a negative answer) is composed and must read back unchanged.
fuzz_target!(|data: &[u8]| {
    let [pick, message @ ..] = data else {
        return;
    };
    let zone = ZONES[usize::from(*pick) % ZONES.len()];
    let Some(parsed) = parse(message) else {
        return;
    };
    let step = classify(&parsed, zone, &parsed.qname, parsed.qtype);
    let (rcode, answer, authority): (u8, &[Rr], &[Rr]) = match &step {
        Step::Referral(referral) => {
            assert!(
                within(&referral.zone, zone) && referral.zone != zone,
                "a referral to {:?}, which is not strictly below the zone {zone:?}",
                referral.zone,
            );
            for rr in &referral.ns {
                assert_eq!(rr.owner, referral.zone, "an NS record of another zone");
            }
            for (owner, _address, _ttl, kind) in &referral.glue {
                assert!(
                    within(owner, zone),
                    "glue for {owner:?} outside the zone {zone:?}",
                );
                if *kind == GlueKind::InDomain {
                    assert!(
                        within(owner, &referral.zone),
                        "in-domain glue for {owner:?} outside the delegated zone {:?}",
                        referral.zone,
                    );
                }
            }
            return;
        }
        Step::Answer { records } => {
            check_within(records, zone, "an answer");
            (0, records, &[])
        }
        Step::Negative {
            rcode,
            records,
            authority,
        } => {
            check_within(records, zone, "a negative answer");
            check_within(authority, zone, "the authority of a negative answer");
            (*rcode, records, authority)
        }
        Step::Alias { .. } | Step::Lame(_) => return,
    };
    // The composed message carries an OPT record besides the records, and the parser
    // reads at most MAX_RECORDS in all.
    if answer.len() + authority.len() + 1 > MAX_RECORDS {
        return;
    }
    let composed = compose(&Composed {
        qname: &parsed.qname,
        qtype: parsed.qtype,
        qclass: 1,
        rcode,
        answer,
        authority,
        additional: &[],
    });
    let Some(again) = parse(&composed) else {
        panic!("a composed answer that does not parse: {composed:02x?}");
    };
    assert_eq!(
        again.answer, answer,
        "the answer section changed in compose"
    );
    assert_eq!(
        again.authority, authority,
        "the authority section changed in compose"
    );
    assert_eq!(again.qname, parsed.qname);
    assert_eq!(again.qtype, parsed.qtype);
    assert_eq!(again.rcode, u16::from(rcode));
});
