use super::*;
use tenko_core::{
    Timestamp,
    dns::{JournalEntry, ScopeName, ZoneId},
};

fn entry(from: u32, to: u32) -> JournalEntry {
    JournalEntry {
        zone: ZoneId::generate(),
        scope: ScopeName::DEFAULT,
        from_serial: from,
        to_serial: to,
        revision: tenko_core::Revision(u64::from(to)),
        at: Timestamp::now(),
        removed: Vec::new(),
        added: Vec::new(),
    }
}

#[test]
fn serials_compare_in_the_arithmetic_of_rfc_1982() {
    assert!(serial_ge(5, 5));
    assert!(serial_ge(6, 5));
    assert!(!serial_ge(5, 6));
    // Across the wrap: 1 comes after 4,294,967,295.
    assert!(serial_ge(1, u32::MAX));
    assert!(!serial_ge(u32::MAX, 1));
}

#[test]
fn a_chain_follows_the_steps_and_needs_every_one() {
    let entries = vec![entry(1, 2), entry(2, 3), entry(3, 5), entry(5, 6)];
    let steps = chain(&entries, 2, 5).expect("in the journal");
    assert_eq!(
        steps
            .iter()
            .map(|step| (step.from_serial, step.to_serial))
            .collect::<Vec<_>>(),
        vec![(2, 3), (3, 5)]
    );
    assert!(chain(&entries, 4, 6).is_none(), "4 is not a step");
    assert!(
        chain(&entries, 1, 7).is_none(),
        "the journal does not reach 7"
    );
    assert!(chain(&[], 1, 2).is_none());
}
