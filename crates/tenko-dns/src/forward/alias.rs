//! An alias chain across routes: where an answer's CNAME chain leaves the route that
//! answered it, and the answer a client gets when the rest of the chain was resolved
//! through the route of its target.
//!
//! An upstream resolves a chain through its own servers, and the resolver did until it
//! learned to stop at a route's border; either way the records past the border were not
//! learned through the route that governs their names. [`crossing`] keeps the records up to
//! and including the link that leaves, and [`combine`] puts the target's answer, learned
//! through its own route, behind them.

use tenko_core::dns::SecurityState;

use crate::{
    name::{self, NameBuf},
    recurse::message::{self, Composed, Rr, types},
    recursion::Validation,
    wire::{self, HEADER_LEN},
};

/// Where an answer's chain leaves its route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Crossing {
    /// The answer records up to and including the link that leaves: the CNAME records of
    /// the chain's names inside the route, the DNAME records they were synthesized from,
    /// and their signatures.
    pub kept: Vec<Rr>,
    /// The name the chain leaves to, lowercase wire form.
    pub target: Vec<u8>,
    /// The CNAME links of `kept`.
    pub links: usize,
}

/// The most links of one answer's chain that are read; a longer chain does not read.
const MAX_LINKS: usize = 64;

/// Where the CNAME chain of the answer `message` to a question of `qtype` leaves the route
/// that answered it (`leaves` says of a name whether another route governs it): `None`
/// when it does not, or when the question asks for the CNAME itself; `Err` when the answer
/// section does not read or its chain is longer than [`MAX_LINKS`], so that nothing past an
/// unread border is relayed. Only the answer section is read, whatever its size.
pub(super) fn crossing(
    message: &[u8],
    qtype: u16,
    leaves: impl Fn(&[u8]) -> bool,
) -> Result<Option<Crossing>, ()> {
    if qtype == types::CNAME {
        return Ok(None);
    }
    let (qname, aliases) = aliases(message).ok_or(())?;
    let mut names = vec![qname];
    loop {
        let Some(name) = names.last() else {
            return Ok(None);
        };
        let Some(target) = aliases
            .iter()
            .find(|rr| rr.rtype == types::CNAME && rr.owner == *name)
            .and_then(Rr::target)
        else {
            return Ok(None);
        };
        if leaves(&target) {
            let kept: Vec<Rr> = aliases
                .into_iter()
                .filter(|rr| {
                    names.contains(&rr.owner)
                        || rr.of_type(types::DNAME)
                            && names
                                .iter()
                                .any(|name| *name != rr.owner && name::is_within(name, &rr.owner))
                })
                .collect();
            let links = kept.iter().filter(|rr| rr.rtype == types::CNAME).count();
            return Ok(Some(Crossing {
                kept,
                target,
                links,
            }));
        }
        if names.contains(&target) {
            // A loop inside the route: its answer is judged as it is.
            return Ok(None);
        }
        if names.len() > MAX_LINKS {
            return Err(());
        }
        names.push(target);
    }
}

/// The question name of `message` and the CNAME and DNAME records of its answer section with
/// their signatures, names decompressed and in lower case; `None` when a record does not read.
fn aliases(message: &[u8]) -> Option<(Vec<u8>, Vec<Rr>)> {
    let header = wire::parse_header(message)?;
    let mut name = NameBuf::root();
    wire::read_name(message, HEADER_LEN, &mut name)?;
    let qname = name.as_wire().to_vec();
    let mut pos = wire::questions_end(message, header.qdcount)?;
    let mut found = Vec::new();
    for _ in 0..header.ancount {
        let record = wire::read_record(message, pos)?;
        pos = record.end();
        let data = record.data(message);
        let covered = (record.rtype == types::RRSIG && data.len() >= 2)
            .then(|| u16::from_be_bytes([data[0], data[1]]));
        let data = match (record.rtype, covered) {
            (types::CNAME | types::DNAME, _) => {
                wire::read_name(message, record.rdata, &mut name)?;
                name.as_wire().to_vec()
            }
            // A signature's names are never compressed (RFC 4034 section 3.1.7).
            (_, Some(types::CNAME | types::DNAME)) => data.to_vec(),
            _ => continue,
        };
        wire::read_name(message, record.start, &mut name)?;
        found.push(Rr {
            owner: name.as_wire().to_vec(),
            rtype: record.rtype,
            class: record.class,
            ttl: record.ttl,
            data,
        });
    }
    Some((qname, found))
}

/// The CNAME links in the answer section of `message` (0 when it does not read: the
/// message was composed or accepted before).
pub(super) fn link_count(message: &[u8]) -> usize {
    aliases(message).map_or(0, |(_, aliases)| {
        aliases.iter().filter(|rr| rr.rtype == types::CNAME).count()
    })
}

/// A SERVFAIL answer to `qname`/`qtype`, without records.
pub(super) fn servfail(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    message::compose(&Composed {
        qname,
        qtype,
        qclass,
        rcode: 2,
        ..Composed::default()
    })
}

/// The links of `crossing` alone as an answer to `qname`/`qtype`: of type CNAME for the
/// validator, which then judges their signatures and wants no proof for the target that
/// another route answers; of the client's type when no route may resolve the target.
pub(super) fn links(qname: &[u8], qtype: u16, qclass: u16, crossing: &Crossing) -> Vec<u8> {
    message::compose(&Composed {
        qname,
        qtype,
        qclass,
        rcode: 0,
        answer: &crossing.kept,
        ..Composed::default()
    })
}

/// The answer to `qname`/`qtype`: the links of `crossing`, then `last`, the target's answer
/// through its own route, with its RCODE and its other sections.
pub(super) fn combine(
    qname: &[u8],
    qtype: u16,
    qclass: u16,
    crossing: &Crossing,
    last: &[u8],
) -> Option<Vec<u8>> {
    let rcode = wire::parse_header(last)?.rcode;
    let last = message::parse(last)?;
    let answer: Vec<Rr> = crossing.kept.iter().cloned().chain(last.answer).collect();
    Some(message::compose(&Composed {
        qname,
        qtype,
        qclass,
        rcode,
        answer: &answer,
        authority: &last.authority,
        additional: &last.additional,
    }))
}

/// The verdict of an answer made of two parts: the weaker state (bogus, indeterminate,
/// unvalidated, insecure, secure, in that order), its reason and extended error, the
/// earlier signature expiry. A part nobody validated (a rule with `validate = false`)
/// leaves the whole unvalidated.
pub(super) fn merge(first: Option<Validation>, second: Option<Validation>) -> Option<Validation> {
    fn rank(state: SecurityState) -> u8 {
        match state {
            SecurityState::Bogus => 0,
            SecurityState::Indeterminate => 1,
            SecurityState::Unvalidated => 2,
            SecurityState::Insecure => 3,
            SecurityState::Secure => 4,
        }
    }
    if first.is_none() && second.is_none() {
        return None;
    }
    let [first, second] = [first, second].map(|part| part.unwrap_or(Validation::UNVALIDATED));
    let weaker = if rank(second.state) < rank(first.state) {
        second
    } else {
        first
    };
    Some(Validation {
        signature_expiry: match (first.signature_expiry, second.signature_expiry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        },
        verifications: first.verifications.saturating_add(second.verifications),
        ..weaker
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenko_core::dns::DnsName;

    fn wire(text: &str) -> Vec<u8> {
        DnsName::new(text).expect("name").to_wire()
    }

    fn cname(owner: &str, target: &str) -> Rr {
        Rr {
            owner: wire(owner),
            rtype: types::CNAME,
            class: 1,
            ttl: 60,
            data: wire(target),
        }
    }

    fn a(owner: &str) -> Rr {
        Rr {
            owner: wire(owner),
            rtype: types::A,
            class: 1,
            ttl: 60,
            data: vec![192, 0, 2, 1],
        }
    }

    fn answer(qname: &str, records: &[Rr]) -> Vec<u8> {
        message::compose(&Composed {
            qname: &wire(qname),
            qtype: types::A,
            qclass: 1,
            rcode: 0,
            answer: records,
            ..Composed::default()
        })
    }

    #[test]
    fn a_chain_is_cut_at_the_first_name_another_route_governs() {
        let message = answer(
            "www.example.test",
            &[
                cname("www.example.test", "edge.example.test"),
                cname("edge.example.test", "host.corp.test"),
                cname("host.corp.test", "back.example.test"),
                a("back.example.test"),
            ],
        );
        let inside = wire("corp.test");
        let crossing = crossing(&message, types::A, |name| name::is_within(name, &inside))
            .expect("reads")
            .expect("leaves");
        assert_eq!(crossing.target, wire("host.corp.test"));
        assert_eq!(crossing.links, 2);
        assert_eq!(
            crossing.kept,
            vec![
                cname("www.example.test", "edge.example.test"),
                cname("edge.example.test", "host.corp.test"),
            ]
        );
        // A chain that stays, and a question for the CNAME itself, are answers as they are.
        assert_eq!(crossing_of(&message, |_| false), None);
        assert_eq!(super::crossing(&message, types::CNAME, |_| true), Ok(None));
    }

    #[test]
    fn a_large_answer_is_read_to_its_border_and_one_that_does_not_read_is_refused() {
        // More records than a parse of the whole message takes: the answer section still
        // reads, and the border is found.
        let mut records = vec![cname("www.example.test", "host.corp.test")];
        records.extend((0..600).map(|_| a("host.corp.test")));
        let message = answer("www.example.test", &records);
        let inside = wire("corp.test");
        let found = crossing_of(&message, |name| name::is_within(name, &inside)).expect("leaves");
        assert_eq!(found.target, wire("host.corp.test"));
        // A record cut off in the middle: nothing is relayed past an unread border.
        let end = wire::questions_end(&message, 1).expect("question");
        let short = &message[..end + 5];
        assert_eq!(crossing(short, types::A, |_| true), Err(()));
    }

    fn crossing_of(message: &[u8], leaves: impl Fn(&[u8]) -> bool) -> Option<Crossing> {
        crossing(message, types::A, leaves).expect("reads")
    }

    #[test]
    fn a_dname_is_kept_with_the_link_it_made_and_dropped_past_the_border() {
        let dname = |owner: &str, target: &str| Rr {
            rtype: types::DNAME,
            ..cname(owner, target)
        };
        let message = answer(
            "www.old.example.test",
            &[
                dname("old.example.test", "corp.test"),
                cname("www.old.example.test", "www.corp.test"),
                dname("corp.test", "elsewhere.test"),
                cname("www.corp.test", "www.elsewhere.test"),
                a("www.elsewhere.test"),
            ],
        );
        let inside = wire("corp.test");
        let crossing =
            crossing_of(&message, |name| name::is_within(name, &inside)).expect("leaves");
        assert_eq!(
            crossing.kept,
            vec![
                dname("old.example.test", "corp.test"),
                cname("www.old.example.test", "www.corp.test"),
            ]
        );
    }

    #[test]
    fn the_combined_answer_is_the_links_then_the_target_answer() {
        let crossing = Crossing {
            kept: vec![cname("www.example.test", "host.corp.test")],
            target: wire("host.corp.test"),
            links: 1,
        };
        let mut last = answer("host.corp.test", &[a("host.corp.test")]);
        last[3] = 0x83;
        let combined =
            combine(&wire("www.example.test"), types::A, 1, &crossing, &last).expect("combines");
        let parsed = message::parse(&combined).expect("parses");
        assert_eq!(parsed.qname, wire("www.example.test"));
        assert_eq!(parsed.rcode, 3, "the target's RCODE");
        assert_eq!(
            parsed.answer,
            vec![
                cname("www.example.test", "host.corp.test"),
                a("host.corp.test")
            ]
        );
    }

    #[test]
    fn the_weaker_part_decides_and_an_unvalidated_part_leaves_the_whole_unvalidated() {
        let state = |state| Validation {
            state,
            ..Validation::UNVALIDATED
        };
        let merged = |a, b| merge(a, b).map(|validation| validation.state);
        let secure = Some(state(SecurityState::Secure));
        assert_eq!(merged(None, None), None);
        assert_eq!(merged(secure, secure), Some(SecurityState::Secure));
        assert_eq!(
            merged(secure, Some(state(SecurityState::Insecure))),
            Some(SecurityState::Insecure)
        );
        assert_eq!(merged(secure, None), Some(SecurityState::Unvalidated));
        assert_eq!(
            merged(None, Some(state(SecurityState::Bogus))),
            Some(SecurityState::Bogus)
        );
    }
}
