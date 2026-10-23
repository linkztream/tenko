#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::{
    recurse::message::parse,
    recursion::ValidationCaps,
    validate::rrset::{Budget, Fault, group, verify},
};

const DNSKEY: u16 = 48;

// The input is a DNS message. Every RRset of its answer and authority sections is checked
// against the DNSKEY sets the message holds, with every signature's signer as the zone:
// the verification never panics, never spends more than the caps allow, and a fault is
// one of the named ones. A message that does not parse is skipped.
fuzz_target!(|data: &[u8]| {
    let Some(parsed) = parse(data) else {
        return;
    };
    let caps = ValidationCaps::DEFAULT;
    let sets = group(&parsed.answer);
    let authority = group(&parsed.authority);
    let keys: Vec<&[u8]> = sets
        .iter()
        .chain(&authority)
        .filter(|set| set.rtype == DNSKEY)
        .flat_map(|set| set.records.iter().copied())
        .collect();
    let mut budget = Budget::default();
    let now = 1_750_000_000;
    for set in sets.iter().chain(&authority) {
        for sig in &set.sigs {
            let zone = sig.signer_lower();
            match verify(set, &zone, &keys, &|_| true, now, &caps, &mut budget) {
                Ok(verified) => {
                    assert!(verified.wildcard_labels.is_none_or(|labels| labels < set.owner_labels()));
                }
                Err(Fault::Cap) => assert!(
                    budget.verifications <= caps.per_query,
                    "the query cap holds: {budget:?}"
                ),
                Err(_) => {}
            }
            assert!(budget.verifications <= caps.per_query, "{budget:?}");
        }
    }
});
