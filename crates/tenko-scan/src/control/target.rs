//! Targets of scans on demand and the probes that cover them.

use std::{collections::BTreeSet, net::IpAddr};

use ipnet::IpNet;
use tenko_cluster::{
    model::{NodeRecord, tables::NODES},
    probe::{ProbeScope, tables::SCOPES},
};
use tenko_core::{Coded, CodedError, NodeId, Role, VrfId, codec::key::encode_key};
use tenko_ipam::tables::{
    ADDRESSES, HOST_INTERFACES, HOSTS, INTERFACE_ADDRESSES, PREFIXES, TENANT_NAMES, VRF_NAMES,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{
    codes,
    model::{ProbeConfigRecord, ScanTarget, Target, tables::PROBE_CONFIG},
};

/// The default VRF of the installation, when setup created it.
///
/// # Errors
///
/// A store error.
pub fn default_vrf(view: &dyn ReadView) -> Result<Option<VrfId>, CodedError> {
    let Some((tenant, _)) = view
        .get_typed(&TENANT_NAMES, &"default".to_owned())
        .map_err(|error| error.to_coded_error())?
    else {
        return Ok(None);
    };
    Ok(view
        .get_typed(&VRF_NAMES, &(tenant, "default".to_owned()))
        .map_err(|error| error.to_coded_error())?
        .map(|(vrf, _)| vrf))
}

fn target_error(status: u16, detail: impl Into<String>) -> CodedError {
    CodedError::new(codes::JOB_TARGET, status, detail).with_param("field", "target")
}

/// The networks and the VRF a target stands for.
///
/// # Errors
///
/// `scan.job.target` (404) for a prefix or host that does not exist, (422) for a host
/// without addresses; a store error.
pub fn resolve(
    view: &dyn ReadView,
    target: &ScanTarget,
    vrf: Option<VrfId>,
) -> Result<(Vec<IpNet>, Option<VrfId>), CodedError> {
    let coded = |error: tenko_store::StoreError| error.to_coded_error();
    let target = target.parse().ok_or_else(|| {
        target_error(
            422,
            format!(
                "`{}` is not a {} target",
                target.value.chars().take(80).collect::<String>(),
                serde_json::to_value(target.kind)
                    .ok()
                    .and_then(|kind| kind.as_str().map(str::to_owned))
                    .unwrap_or_default()
            ),
        )
    })?;
    match target {
        Target::Prefix(id) => {
            let (prefix, _) = view
                .get_typed(&PREFIXES, &id)
                .map_err(coded)?
                .ok_or_else(|| target_error(404, format!("there is no prefix {id}")))?;
            Ok((vec![prefix.cidr], Some(prefix.vrf)))
        }
        Target::Host(id) => {
            if view.get_typed(&HOSTS, &id).map_err(coded)?.is_none() {
                return Err(target_error(404, format!("there is no host {id}")));
            }
            let mut networks = BTreeSet::new();
            let mut host_vrf = None;
            let interfaces = view
                .scan_typed(
                    &HOST_INTERFACES,
                    KeyRange::prefix(encode_key(&(id,))),
                    usize::MAX,
                    false,
                )
                .map_err(coded)?;
            for ((_, interface), (), _) in interfaces {
                let addresses = view
                    .scan_typed(
                        &INTERFACE_ADDRESSES,
                        KeyRange::prefix(encode_key(&(interface,))),
                        usize::MAX,
                        false,
                    )
                    .map_err(coded)?;
                for ((_, address), (), _) in addresses {
                    if let Some((address, _)) =
                        view.get_typed(&ADDRESSES, &address).map_err(coded)?
                    {
                        host_vrf.get_or_insert(address.vrf);
                        networks.insert(IpNet::from(address.ip));
                    }
                }
            }
            if networks.is_empty() {
                return Err(target_error(
                    422,
                    format!("host {id} has no addresses to scan"),
                ));
            }
            Ok((networks.into_iter().collect(), host_vrf))
        }
        Target::Address(ip) => Ok((
            vec![IpNet::from(ip)],
            match vrf {
                Some(vrf) => Some(vrf),
                None => default_vrf(view)?,
            },
        )),
        Target::Network(net) => Ok((
            vec![net.trunc()],
            match vrf {
                Some(vrf) => Some(vrf),
                None => default_vrf(view)?,
            },
        )),
    }
}

/// A probe with the scope it scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The node.
    pub node: NodeId,
    /// Its name.
    pub name: String,
    /// Whether it runs inside a controller.
    pub in_process: bool,
    /// The node record, for an enrolled node.
    pub record: Option<NodeRecord>,
    /// The configuration the controllers hold for it.
    pub stored: Option<(ProbeConfigRecord, tenko_core::Revision)>,
    /// What it last reported.
    pub applied: Option<ProbeScope>,
}

impl Candidate {
    /// The prefixes and exclusions it scans: the stored configuration's, else what it
    /// reported; `None` when its scanner is off or nothing is known.
    pub fn scope(&self) -> Option<(Vec<IpNet>, Vec<IpNet>)> {
        if let Some((stored, _)) = &self.stored {
            if !stored.config.enabled {
                return None;
            }
            let scope = stored.config.scope().ok()?;
            return Some((scope.prefixes().to_vec(), scope.exclusions().to_vec()));
        }
        self.applied
            .as_ref()
            .map(|applied| (applied.prefixes.clone(), applied.exclude.clone()))
    }

    /// The VRF its batches land in: the configured one, else the node's, else `fallback`
    /// (the default VRF).
    pub fn vrf(&self, fallback: Option<VrfId>) -> Option<VrfId> {
        self.stored
            .as_ref()
            .and_then(|(stored, _)| stored.config.vrf().ok().flatten())
            .or_else(|| self.applied.as_ref().and_then(|applied| applied.vrf))
            .or_else(|| self.record.as_ref().and_then(|record| record.vrf))
            .or(fallback)
    }
}

/// Every probe: the enrolled nodes with the role `probe`, and the probe role of this
/// controller (`local`).
///
/// # Errors
///
/// A store error.
pub fn candidates(
    view: &dyn ReadView,
    local: Option<NodeId>,
) -> Result<Vec<Candidate>, CodedError> {
    let coded = |error: tenko_store::StoreError| error.to_coded_error();
    let mut out = Vec::new();
    let mut add = |node: NodeId,
                   name: String,
                   in_process: bool,
                   record: Option<NodeRecord>|
     -> Result<(), CodedError> {
        let stored = view.get_typed(&PROBE_CONFIG, &node.0).map_err(coded)?;
        let applied = view
            .get_typed(&SCOPES, &node.0)
            .map_err(coded)?
            .map(|(scope, _)| scope);
        out.push(Candidate {
            node,
            name,
            in_process,
            record,
            stored,
            applied,
        });
        Ok(())
    };
    if let Some(local) = local {
        add(local, format!("controller-{local}"), true, None)?;
    }
    for (_, record, _) in view
        .scan_typed(&NODES, KeyRange::all(), usize::MAX, false)
        .map_err(coded)?
    {
        if record.roles.contains(&Role::Probe) && Some(record.id) != local {
            add(record.id, record.name.clone(), false, Some(record))?;
        }
    }
    Ok(out)
}

/// One probe's share of a scan: the address or network inside its scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Share {
    /// The probe.
    pub node: NodeId,
    /// The address or network.
    pub target: IpNet,
}

impl Share {
    /// The target as the probe's command names it: an address without its length.
    pub fn target_text(&self) -> String {
        if self.target.prefix_len() == self.target.max_prefix_len() {
            self.target.addr().to_string()
        } else {
            self.target.to_string()
        }
    }
}

/// The probes that cover `networks` in `vrf`, each with the parts inside its scope.
pub fn shares(
    candidates: &[Candidate],
    networks: &[IpNet],
    vrf: Option<VrfId>,
    default_vrf: Option<VrfId>,
) -> Vec<Share> {
    let mut out = BTreeSet::new();
    for candidate in candidates {
        let Some((prefixes, exclude)) = candidate.scope() else {
            continue;
        };
        if let (Some(wanted), Some(theirs)) = (vrf, candidate.vrf(default_vrf))
            && wanted != theirs
        {
            continue;
        }
        for network in networks {
            for prefix in &prefixes {
                let part = if prefix.contains(network) {
                    *network
                } else if network.contains(prefix) {
                    *prefix
                } else {
                    continue;
                };
                let excluded = exclude.iter().any(|net| net.contains(&part));
                if !excluded {
                    out.insert(Share {
                        node: candidate.node,
                        target: part,
                    });
                }
            }
        }
    }
    out.into_iter().collect()
}

/// The address of a host prefix, else `None`.
pub fn single_address(net: &IpNet) -> Option<IpAddr> {
    (net.prefix_len() == net.max_prefix_len()).then(|| net.addr())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(node: u64, prefixes: &[&str], exclude: &[&str]) -> Candidate {
        let nets = |texts: &[&str]| {
            texts
                .iter()
                .map(|text| text.parse().expect("net"))
                .collect()
        };
        Candidate {
            node: NodeId(node),
            name: format!("probe-{node}"),
            in_process: false,
            record: None,
            stored: None,
            applied: Some(ProbeScope {
                node: NodeId(node),
                prefixes: nets(prefixes),
                exclude: nets(exclude),
                methods: Vec::new(),
                vrf: None,
                active: true,
                stopped: false,
                stop_reason: None,
                origin: tenko_cluster::probe::ConfigOrigin::Local,
                revision: 0,
                error: None,
                applied_at: None,
                reported_at: tenko_core::Timestamp::now(),
            }),
        }
    }

    fn net(text: &str) -> IpNet {
        text.parse().expect("net")
    }

    #[test]
    fn a_target_goes_to_the_probes_whose_scope_overlaps_it() {
        let probes = [
            candidate(1001, &["192.0.2.0/24"], &["192.0.2.1/32"]),
            candidate(1002, &["198.51.100.0/24"], &[]),
            candidate(1003, &["192.0.2.0/25"], &[]),
        ];
        // An address inside two scopes goes to both.
        let shares_of = |networks: &[IpNet]| shares(&probes, networks, None, None);
        let found = shares_of(&[net("192.0.2.10/32")]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].target_text(), "192.0.2.10");
        // A wider network is cut to each scope.
        let found = shares_of(&[net("192.0.0.0/16")]);
        assert_eq!(
            found,
            vec![
                Share {
                    node: NodeId(1001),
                    target: net("192.0.2.0/24")
                },
                Share {
                    node: NodeId(1003),
                    target: net("192.0.2.0/25")
                },
            ]
        );
        // An excluded address is scanned by nobody that excludes it.
        let found = shares_of(&[net("192.0.2.1/32")]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].node, NodeId(1003));
        // Outside every scope: nobody.
        assert_eq!(shares_of(&[net("203.0.113.0/24")]).len(), 0);
    }

    #[test]
    fn a_probe_of_another_vrf_is_left_out() {
        let mut probe = candidate(1001, &["192.0.2.0/24"], &[]);
        let theirs = VrfId::generate();
        if let Some(applied) = probe.applied.as_mut() {
            applied.vrf = Some(theirs);
        }
        let probes = [probe];
        let networks = [net("192.0.2.10/32")];
        assert_eq!(shares(&probes, &networks, Some(theirs), None).len(), 1);
        assert_eq!(
            shares(&probes, &networks, Some(VrfId::generate()), None).len(),
            0
        );
        assert_eq!(shares(&probes, &networks, None, None).len(), 1);
    }
}
