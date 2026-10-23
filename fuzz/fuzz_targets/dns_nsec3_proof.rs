#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::{
    recurse::message::parse,
    recursion::ValidationCaps,
    validate::{
        nsec::{self, Nsec, ProofFault},
        nsec3::{Chain, Nsec3},
        rrset::{Budget, group},
    },
};

const NSEC: u16 = 47;
const NSEC3: u16 = 50;

// The first octet is the type asked, the rest a DNS message whose authority section holds
// the NSEC or NSEC3 records of the zone the question's last label names (the zone of the
// proof is the question name's parent, the apex of the records). Every proof is run for the
// question name: nothing panics, the NSEC3 hashes of one step stay within the cap, and a
// cap fault is reported as such rather than as a proof.
fuzz_target!(|data: &[u8]| {
    let [qtype, message @ ..] = data else {
        return;
    };
    let Some(parsed) = parse(message) else {
        return;
    };
    let qname = parsed.qname.clone();
    let apex: Vec<u8> = {
        let labels = tenko_dns::name::label_count(&qname);
        if labels == 0 {
            return;
        }
        tenko_dns::name::suffix(&qname, 1).to_vec()
    };
    let caps = ValidationCaps::DEFAULT;
    let sets = group(&parsed.authority);
    let nsecs: Vec<Nsec<'_>> = sets
        .iter()
        .filter(|set| set.rtype == NSEC)
        .flat_map(|set| set.records.iter().filter_map(|data| Nsec::parse(set.owner, data)))
        .collect();
    let nsec3s: Vec<Nsec3<'_>> = sets
        .iter()
        .filter(|set| set.rtype == NSEC3)
        .flat_map(|set| {
            set.records
                .iter()
                .filter_map(|data| Nsec3::parse(set.owner, data, &apex))
        })
        .collect();
    let qtype = u16::from(*qtype);
    let _ = nsec::prove_nxdomain(&nsecs, &qname, &apex);
    let _ = nsec::prove_nodata(&nsecs, &qname, qtype, &apex);
    let _ = nsec::prove_wildcard(&nsecs, &qname, &apex);
    let _ = nsec::delegation(&nsecs, &qname, &apex);
    let Some(chain) = Chain::new(&nsec3s, &apex) else {
        return;
    };
    let mut budget = Budget::default();
    for result in [
        chain.prove_nxdomain(&qname, &caps, &mut budget).map(|_| ()),
        chain
            .prove_nodata(&qname, qtype, &caps, &mut budget)
            .map(|_| ()),
        chain.prove_wildcard(&qname, 1, &caps, &mut budget).map(|_| ()),
        chain.delegation(&qname, &caps, &mut budget).map(|_| ()),
    ] {
        assert!(
            budget.hashes <= caps.nsec3_hashes_per_step,
            "the hash cap holds: {budget:?}"
        );
        if result == Err(ProofFault::Cap) {
            assert_eq!(budget.hashes, caps.nsec3_hashes_per_step);
        }
    }
});
