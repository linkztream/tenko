//! The special-use and locally served names (RFC 6761, RFC 6303, RFC 8375, RFC 7686;
//! recursion plan section 2.1): a name under one of [`LOCAL_ZONES`] that no zone or rule of
//! the node answers never reaches an authority. Under the zones of RFC 6761 every name is
//! NXDOMAIN; the reverse zones of RFC 6303 are empty zones: the apex has its SOA and NS and
//! nothing else, every name below it is NXDOMAIN. Every answer carries the zone's SOA as
//! RFC 6303 section 3 writes it (the zone as the primary, `nobody.invalid.` as the mailbox)
//! so that it is cached as a negative answer. `[dns.recursion] local_zones_except` lifts
//! zones (the lab lifts `test`).

use super::message::{Rr, types};
use crate::recursion::{LOCAL_ZONES, LocalAnswer};

/// The TTL of the synthesised records (RFC 6303 section 3: the SOA's minimum).
pub const LOCAL_TTL: u32 = 10_800;

/// The locally served zones in force: [`LOCAL_ZONES`] without the exceptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalZones {
    zones: Vec<(Vec<u8>, LocalAnswer)>,
}

impl LocalZones {
    /// [`LOCAL_ZONES`] without the zones at or below an exception (lowercase wire form).
    pub fn new(except: &[Vec<u8>]) -> Self {
        let zones = LOCAL_ZONES
            .iter()
            .filter_map(|(zone, answer)| {
                let wire = tenko_core::dns::DnsName::new(zone).ok()?.to_wire();
                let lifted = except
                    .iter()
                    .any(|except| super::message::within(&wire, except));
                (!lifted).then_some((wire, *answer))
            })
            .collect();
        Self { zones }
    }

    /// The zone and its answer for `qname` (lowercase wire form), the longest first.
    pub fn find(&self, qname: &[u8]) -> Option<(&[u8], LocalAnswer)> {
        self.zones
            .iter()
            .filter(|(zone, _)| super::message::within(qname, zone))
            .max_by_key(|(zone, _)| zone.len())
            .map(|(zone, answer)| (zone.as_slice(), *answer))
    }

    /// How many zones are served locally.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

/// The SOA of a locally served zone.
pub fn soa(zone: &[u8]) -> Rr {
    let mut data = zone.to_vec();
    data.extend_from_slice(b"\x06nobody\x07invalid\x00");
    for value in [1u32, 3_600, 1_200, 604_800, LOCAL_TTL] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    Rr {
        owner: zone.to_vec(),
        rtype: types::SOA,
        class: 1,
        ttl: LOCAL_TTL,
        data,
    }
}

/// The answer of a locally served name: the RCODE, the answer section and the authority
/// section.
pub fn answer(zone: &[u8], kind: LocalAnswer, qname: &[u8], qtype: u16) -> (u8, Vec<Rr>, Vec<Rr>) {
    let soa = soa(zone);
    let apex = qname == zone;
    match kind {
        LocalAnswer::Empty if apex => {
            let mut answer = Vec::new();
            if matches!(qtype, types::SOA | types::ANY) {
                answer.push(soa.clone());
            }
            if matches!(qtype, types::NS | types::ANY) {
                answer.push(Rr {
                    owner: zone.to_vec(),
                    rtype: types::NS,
                    class: 1,
                    ttl: LOCAL_TTL,
                    data: zone.to_vec(),
                });
            }
            let authority = if answer.is_empty() {
                vec![soa]
            } else {
                Vec::new()
            };
            (0, answer, authority)
        }
        LocalAnswer::Empty | LocalAnswer::Nxdomain => (3, Vec::new(), vec![soa]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(text: &str) -> Vec<u8> {
        tenko_core::dns::DnsName::new(text).expect("name").to_wire()
    }

    #[test]
    fn local_zones_answer_and_exceptions_lift_them() {
        let zones = LocalZones::new(&[wire("test")]);
        assert!(zones.find(&wire("www.example.test")).is_none(), "lifted");
        let (zone, kind) = zones.find(&wire("printer.local")).expect("local");
        assert_eq!((zone, kind), (&wire("local")[..], LocalAnswer::Nxdomain));
        let (zone, kind) = zones
            .find(&wire("1.0.168.192.in-addr.arpa"))
            .expect("rfc 6303");
        assert_eq!(zone, &wire("168.192.in-addr.arpa")[..]);
        assert_eq!(
            answer(zone, kind, &wire("1.0.168.192.in-addr.arpa"), 12).0,
            3
        );
        let (rcode, records, authority) = answer(zone, kind, zone, 6);
        assert_eq!((rcode, records.len(), authority.len()), (0, 1, 0));
        let (rcode, records, authority) = answer(zone, kind, zone, 12);
        assert_eq!((rcode, records.len(), authority.len()), (0, 0, 1));
        assert!(zones.find(&wire("www.example.com")).is_none());
        assert!(
            LocalZones::new(&[])
                .find(&wire("ns.example.test"))
                .is_some()
        );
        assert_eq!(
            LocalZones::new(&[wire("arpa")]).len(),
            6,
            "the names of RFC 6761"
        );
    }
}
