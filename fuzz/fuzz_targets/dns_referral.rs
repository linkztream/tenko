#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use tenko_dns::{
    cache::{
        Client, DenialSettings, Denials, Verdict,
        denial::store::{MAX_DELEGATION_ADDRESSES, MAX_DELEGATION_SERVERS},
    },
    recurse::message::{
        Composed, GlueKind, MAX_RECORDS, Rr, Step, classify, compose, parse, within,
    },
    recursion::denial::{DenialScope, Origin},
    wire,
};

/// The zones a server can be asked as: lowercase wire names, the root and two levels down.
const ZONES: [&[u8]; 3] = [b"\x00", b"\x04test\x00", b"\x07example\x04test\x00"];

/// The denial cache fed the server's answer as the resolver keeps it (`carried`: as composed
/// under the carry of the delegation), then asked for a name below the one it denies, with
/// and without the carry (the RPZ triggers NSDNAME and NSIP): a synthesized answer parses,
/// under the carry it holds no more name servers and addresses than the caps keep, and a
/// negative one holds no NS record of another zone than its SOA's (RFC 2308 section 2.2).
fn check_denials(message: &[u8], qname: &[u8], carried: bool) {
    let cache = Denials::new(DenialSettings::default());
    let now = Instant::now();
    // The default resolution of no view: the path the resolver's own answers take.
    let scope = DenialScope::of_view(None);
    if !cache.insert_carried(
        scope,
        message,
        &Verdict::UNVALIDATED,
        Origin::Recursion,
        now,
        carried,
    ) {
        return;
    }
    let mut below = b"x".to_vec();
    below.extend_from_slice(qname);
    if below.len() > 255 {
        return;
    }
    let mut query = Vec::new();
    let mut text = String::new();
    for label in tenko_dns::name::Labels::new(&below) {
        if !label.iter().all(u8::is_ascii_alphanumeric) {
            return;
        }
        text.push_str(std::str::from_utf8(label).unwrap_or("x"));
        text.push('.');
    }
    wire::write_query(&mut query, 1, &text, 1, None);
    let Some(question_end) = wire::questions_end(&query, 1) else {
        return;
    };
    for (carry, max_len) in [(false, 512), (true, 512), (true, 65_535)] {
        let client = Client {
            message: &query,
            question_end,
            id: 1,
            rd: true,
            cd: false,
            ad: false,
            edns: None,
            max_len,
        };
        let mut out = Vec::with_capacity(65_535);
        if cache
            .answer_carrying(scope, &below, 1, &client, now, &mut out, carry)
            .is_none()
        {
            continue;
        }
        assert!(
            out.len() <= max_len,
            "a synthesized answer over the client's length"
        );
        let Some(synthesized) = parse(&out) else {
            panic!("a synthesized answer that does not parse: {out:02x?}");
        };
        let ns = synthesized
            .authority
            .iter()
            .filter(|rr| rr.rtype == 2)
            .count();
        assert!(ns <= MAX_DELEGATION_SERVERS, "{ns} name servers written");
        assert!(
            synthesized.additional.len() <= MAX_DELEGATION_ADDRESSES,
            "{} addresses written",
            synthesized.additional.len()
        );
        if !carry {
            assert_eq!(ns, 0, "a delegation written without the carry");
        }
        if let Some(soa) = synthesized.authority.iter().find(|rr| rr.rtype == 6) {
            assert!(
                synthesized
                    .authority
                    .iter()
                    .all(|rr| rr.rtype != 2 || rr.owner == soa.owner),
                "an NS record of another zone beside the SOA"
            );
        }
    }
}

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
// The answer goes into a denial cache as well (`check_denials`), carried when the first
// octet's high bit is set.
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
    // The high bit of the first octet: the answer was composed under the carry.
    check_denials(message, &parsed.qname, *pick >= 0x80);
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
        Step::Answer { records, .. } => {
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
