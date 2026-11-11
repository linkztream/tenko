#![no_main]

//! The tiers of the dashboard's history that a controller receives from another controller
//! (dashboard history plan, section 2): the CBOR of the answer to `Metrics.History` and of the
//! `closed` field of `Metrics.Snapshot`, decoded and checked before the combination reads them.
//! Tiers that pass the check hold no ring larger than the largest one and no number that is
//! not a number, and encode and decode to themselves.

use libfuzzer_sys::fuzz_target;
use tenko_api::dto::events::{CONTROLLER_TIERS_ENCODING, ControllerTiers};

fuzz_target!(|data: &[u8]| {
    let Ok(tiers) = ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, data) else {
        return;
    };
    for figure in &tiers.figures {
        for tier in &figure.tiers {
            assert!(tier.buckets.len() <= 71, "{} buckets", tier.buckets.len());
            for bucket in &tier.buckets {
                for value in [bucket.lowest, bucket.highest] {
                    assert!(!value.is_nan(), "{bucket:?}");
                }
                for value in [bucket.sum, bucket.second] {
                    assert!(value.is_finite(), "{bucket:?}");
                }
                let _ = bucket.mean(figure.figure.merge());
            }
        }
    }
    let encoded = tenko_core::codec::to_cbor(&tiers).expect("checked tiers encode");
    let again = ControllerTiers::decode(CONTROLLER_TIERS_ENCODING, &encoded).expect("and decode");
    assert_eq!(again, tiers);
});
