//! The health findings of signed zones (OPS-09): what `GET /system/status` and the DNSSEC
//! status of a zone warn about, computed from `dns.sign_state` at the time of the request.
//!
//! | Code | When |
//! |---|---|
//! | `dns.dnssec.clock_skew` | The controller's clock is more than 5 minutes behind the last signing of the zone: it went back, and signatures made now would start before the ones in the zone |
//! | `dns.dnssec.expiring` | An imported zone's earliest signature expires within 7 days (nothing re-signs it) |
//! | `dns.dnssec.resign_overdue` | A zone signed online has a signature with less than half of `resign_before_days` left: the signer does not keep up |
//! | `dns.dnssec.expired` | A signature of the zone has expired: validators answer SERVFAIL for it |
//!
//! One node cannot see its own clock run ahead; the cluster's skew warning
//! (`cluster.clock_skew`) compares the controllers' clocks with each other.

use std::{collections::BTreeMap, time::Duration};

use tenko_core::{
    Timestamp,
    dns::{DnssecMode, SignState, Zone, tables::SIGN_STATE},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::zone::{ZoneResult, ZoneService};

/// The controller's clock went back behind the last signing.
pub const CLOCK_SKEW: &str = "dns.dnssec.clock_skew";

/// An imported zone's signatures expire soon.
pub const EXPIRING: &str = "dns.dnssec.expiring";

/// A zone signed online is not re-signed in time.
pub const RESIGN_OVERDUE: &str = "dns.dnssec.resign_overdue";

/// A signature has expired.
pub const EXPIRED: &str = "dns.dnssec.expired";

/// The clock skew tolerated (OPS-09: Kerberos tolerates 5 minutes).
pub const SKEW_TOLERANCE: Duration = Duration::from_secs(300);

/// How soon before expiry an imported zone warns.
pub const IMPORTED_WARNING: Duration = Duration::from_secs(7 * 86_400);

/// One finding, naming the zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code.
    pub code: &'static str,
    /// What is wrong, in English.
    pub detail: String,
    /// The zone and the figures.
    pub params: BTreeMap<String, String>,
}

fn finding(code: &'static str, zone: &Zone, detail: String, extra: &[(&str, String)]) -> Finding {
    let mut params = BTreeMap::from([("zone".to_owned(), zone.name.to_string())]);
    for (key, value) in extra {
        params.insert((*key).to_owned(), value.clone());
    }
    Finding {
        code,
        detail,
        params,
    }
}

/// The findings of one zone at `now`.
pub fn findings(zone: &Zone, state: &SignState, now: Timestamp) -> Vec<Finding> {
    let mut out = Vec::new();
    if zone.dnssec.mode == DnssecMode::Off {
        return out;
    }
    if zone.dnssec.mode == DnssecMode::Online
        && let Some(signed) = state.last_signed
    {
        let behind = signed.saturating_since(now);
        if behind > SKEW_TOLERANCE {
            out.push(finding(
                CLOCK_SKEW,
                zone,
                format!(
                    "the clock of this controller is {} s behind the last signing of zone {}; \
                     check its time synchronisation",
                    behind.as_secs(),
                    zone.name
                ),
                &[("behind_secs", behind.as_secs().to_string())],
            ));
        }
    }
    let Some(expires) = state.expires else {
        return out;
    };
    let left = expires.saturating_since(now);
    if expires <= now {
        out.push(finding(
            EXPIRED,
            zone,
            format!(
                "a signature of zone {} expired at {expires}; validating resolvers fail on it",
                zone.name
            ),
            &[("expires", expires.to_string())],
        ));
        return out;
    }
    match zone.dnssec.mode {
        DnssecMode::Imported if left < IMPORTED_WARNING => out.push(finding(
            EXPIRING,
            zone,
            format!(
                "the imported signatures of zone {} expire at {expires}; import the zone \
                 signed again",
                zone.name
            ),
            &[("expires", expires.to_string())],
        )),
        DnssecMode::Online => {
            let half = Duration::from_secs(u64::from(zone.dnssec.resign_before_days) * 43_200);
            if left < half {
                out.push(finding(
                    RESIGN_OVERDUE,
                    zone,
                    format!(
                        "a signature of zone {} expires at {expires} and has not been renewed",
                        zone.name
                    ),
                    &[("expires", expires.to_string())],
                ));
            }
        }
        _ => {}
    }
    out
}

/// The findings of every zone with a signing state.
///
/// # Errors
///
/// The store's error.
pub fn all(view: &dyn ReadView, now: Timestamp) -> ZoneResult<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, state, _) in view.scan_typed(&SIGN_STATE, KeyRange::all(), usize::MAX, false)? {
        let Ok(row) = ZoneService::zone(view, id) else {
            continue;
        };
        out.extend(findings(&row.zone, &state, now));
    }
    Ok(out)
}
