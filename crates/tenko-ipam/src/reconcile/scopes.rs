//! The probe scopes as the orphan rule reads them (`scan.scopes`, written by the
//! controllers when a probe reports the configuration it applies).
//!
//! The table belongs to the cluster package (`tenko_cluster::probe::ProbeScope`); this is a
//! read-only view of the fields the rule needs, decoded from the same rows (fields it does
//! not name are ignored), so the IPAM crate does not depend on the cluster crate.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{VrfId, table::TableDef};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::{error::IpamResult, net::contains_ip};

/// The scope of each probe, keyed by node id.
pub const SCOPES: TableDef<u64, ScanScope> = TableDef::new("scan.scopes");

/// What the orphan rule reads of a probe's scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanScope {
    /// The prefixes the probe covers.
    #[serde(default)]
    pub prefixes: Vec<IpNet>,
    /// Prefixes and addresses inside them it never probes.
    #[serde(default)]
    pub exclude: Vec<IpNet>,
    /// The VRF its batches name, when its configuration names one.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// Whether its kill switch is on (it scans nothing).
    #[serde(default)]
    pub stopped: bool,
}

impl ScanScope {
    /// Whether the probe scans `ip` in `vrf`: running, of that VRF or none named, inside
    /// one of its prefixes and outside its exclusions.
    pub fn covers(&self, vrf: VrfId, ip: IpAddr) -> bool {
        !self.stopped
            && self.vrf.is_none_or(|own| own == vrf)
            && self.prefixes.iter().any(|net| contains_ip(net, ip))
            && !self.exclude.iter().any(|net| contains_ip(net, ip))
    }
}

/// Every stored scope.
pub(crate) fn load(view: &dyn ReadView) -> IpamResult<Vec<ScanScope>> {
    Ok(view
        .scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, scope, _)| scope)
        .collect())
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use tenko_core::{
        Timestamp,
        codec::{from_cbor, to_cbor},
    };

    use super::*;

    /// The fields of the cluster package's row, as it writes them.
    #[derive(Serialize)]
    struct ProbeScopeRow {
        node: u64,
        prefixes: Vec<IpNet>,
        exclude: Vec<IpNet>,
        methods: Vec<String>,
        vrf: Option<VrfId>,
        active: bool,
        stopped: bool,
        stop_reason: Option<String>,
        origin: &'static str,
        revision: u64,
        error: Option<String>,
        applied_at: Option<Timestamp>,
        reported_at: Timestamp,
    }

    #[test]
    fn a_row_of_the_cluster_package_decodes_and_covers_its_prefixes() {
        let row = ProbeScopeRow {
            node: 7,
            prefixes: vec!["192.0.2.0/24".parse().expect("net")],
            exclude: vec!["192.0.2.128/25".parse().expect("net")],
            methods: vec!["arp".to_owned()],
            vrf: None,
            active: true,
            stopped: false,
            stop_reason: None,
            origin: "synced",
            revision: 3,
            error: None,
            applied_at: None,
            reported_at: Timestamp::now(),
        };
        let scope: ScanScope = from_cbor(&to_cbor(&row).expect("cbor")).expect("decodes");
        let vrf = VrfId::generate();
        assert!(scope.covers(vrf, "192.0.2.10".parse().expect("ip")));
        assert!(!scope.covers(vrf, "192.0.2.200".parse().expect("ip")));
        assert!(!scope.covers(vrf, "198.51.100.10".parse().expect("ip")));
        let other = ScanScope {
            vrf: Some(VrfId::generate()),
            ..scope.clone()
        };
        assert!(!other.covers(vrf, "192.0.2.10".parse().expect("ip")));
        let stopped = ScanScope {
            stopped: true,
            ..scope
        };
        assert!(!stopped.covers(vrf, "192.0.2.10".parse().expect("ip")));
    }
}
