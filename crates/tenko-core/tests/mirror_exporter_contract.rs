//! The snapshot the Windows exporter's Pester suite produces from recorded cmdlet output
//! (`deploy/windows/mirror/tests/fixtures/expected-snapshot.json`, WP14.1) is the other half
//! of the contract that `tests/mirror_model.rs` holds from this side (WP14.0): it must parse
//! into `MirrorSnapshot`, validate, and carry the fixture's shape (one active scope
//! `192.0.2.0/24`, thirty reservations, sixty leases), so that a field added or renamed on
//! either side fails here and not on the first push to a node.

use std::{fs, path::PathBuf};

use tenko_core::{
    codec::{from_cbor, to_cbor},
    ir::MirrorSnapshot,
};

fn exporter_snapshot() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/windows/mirror/tests/fixtures/expected-snapshot.json")
}

#[test]
fn the_exporters_expected_snapshot_parses_and_validates() {
    let path = exporter_snapshot();
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let parsed: MirrorSnapshot =
        serde_json::from_str(&text).expect("the exporter's snapshot parses into MirrorSnapshot");
    parsed
        .validate()
        .expect("the exporter's snapshot validates");
    assert_eq!(
        from_cbor::<MirrorSnapshot>(&to_cbor(&parsed).expect("cbor")).expect("cbor"),
        parsed,
        "the exporter's snapshot round-trips through the store's encoding"
    );
    assert_eq!(parsed.format, 1);
    assert_eq!(
        parsed.dhcp.scopes.len(),
        1,
        "one scope in the fixture domain"
    );
    assert!(
        parsed.dhcp.scopes[0].active,
        "the first push shows the scope active"
    );
    assert_eq!(parsed.reservation_count(), 30, "thirty reservations");
    assert_eq!(parsed.dhcp.leases.len(), 60, "sixty leases");
    assert!(
        !parsed.losses.entries.is_empty(),
        "the loss report names the policy, the filter and the superscope"
    );
}
