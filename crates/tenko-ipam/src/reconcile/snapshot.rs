//! One consistent picture for a reconcile run: the live intent, the current facts with the
//! address and MAC pairs they report and the networks controllers report, and the stored
//! proposals, rejections, policies and sightings, all from one read view.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use tenko_core::{
    AddressId, HostId, InterfaceId, MacAddr, ObjectRef, PrefixId, ProposalId, Revision, SiteId,
    TenantId, Timestamp, VlanId, VrfId,
    ipam::{Address, Host, Interface, Prefix, PrefixRole, Range, RangeRole, Tenant, Vlan, Vrf},
    observe::{ObservationSource, Observed},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::scopes::ScanScope;
use crate::{
    error::IpamResult,
    net::{Family, contains_ip, contains_net, ip_to_u128},
    observe::{
        model::{IntentSighting, ObservedFact},
        tables::{FACTS, LAST_SEEN},
    },
    proposals::model::{
        ADOPTION, IntentProposal, OPEN_KEYS, PROPOSALS, REJECTIONS, Rejection, StoredPolicy,
    },
    tables::{ADDRESSES, HOSTS, INTERFACES, PREFIXES, RANGES, TENANTS, VLANS, VRFS},
};

/// Name of the default tenant and VRF.
const DEFAULT_NAME: &str = "default";

/// Where an observed address belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Placement {
    /// Inside a network prefix of a VRF (the most specific one).
    Network {
        /// The VRF.
        vrf: VrfId,
        /// The most specific network prefix.
        prefix: PrefixId,
    },
    /// Outside every network prefix of the VRF (only supernets, or nothing, contain it).
    Outside {
        /// The VRF.
        vrf: VrfId,
    },
    /// Several VRFs have a network for it and the source names none; or there is no VRF.
    Unplaced,
}

impl Placement {
    /// The VRF, if the placement has one.
    pub(crate) fn vrf(self) -> Option<VrfId> {
        match self {
            Placement::Network { vrf, .. } | Placement::Outside { vrf } => Some(vrf),
            Placement::Unplaced => None,
        }
    }

    /// The network prefix, if any.
    pub(crate) fn prefix(self) -> Option<PrefixId> {
        match self {
            Placement::Network { prefix, .. } => Some(prefix),
            _ => None,
        }
    }
}

/// The live intent.
#[derive(Debug, Default)]
pub(crate) struct Intent {
    pub default_tenant: Option<TenantId>,
    pub default_vrf: Option<VrfId>,
    pub vrfs: Vec<VrfId>,
    pub prefixes: BTreeMap<PrefixId, Prefix>,
    pub by_vrf: BTreeMap<VrfId, Vec<PrefixId>>,
    pub ranges: BTreeMap<PrefixId, Vec<Range>>,
    pub addresses: BTreeMap<AddressId, Address>,
    pub address_by_ip: BTreeMap<(VrfId, IpAddr), AddressId>,
    pub interfaces: BTreeMap<InterfaceId, Interface>,
    pub interfaces_by_mac: BTreeMap<MacAddr, Vec<InterfaceId>>,
    pub addresses_of: BTreeMap<InterfaceId, Vec<AddressId>>,
    pub hosts: BTreeMap<HostId, Host>,
    /// Live host names per tenant, lowercase.
    pub host_names: BTreeSet<(TenantId, String)>,
    /// Live VLANs.
    pub vlans: BTreeMap<VlanId, Vlan>,
    /// Live VLANs by site (`None`: global) and VLAN id.
    pub vlan_ids: BTreeMap<(Option<SiteId>, u16), VlanId>,
    /// MAC addresses whose live interfaces all belong to decommissioned hosts: the facts
    /// that name them raise nothing.
    pub decommissioned_macs: BTreeSet<MacAddr>,
}

impl Intent {
    pub(crate) fn load(view: &dyn ReadView) -> IpamResult<Self> {
        let mut intent = Intent::default();
        for (_, tenant, _) in view.scan_typed(&TENANTS, KeyRange::all(), usize::MAX, false)? {
            let tenant: Tenant = tenant;
            if !tenant.meta.is_deleted() && tenant.name.eq_ignore_ascii_case(DEFAULT_NAME) {
                intent.default_tenant = Some(tenant.id);
            }
        }
        for (_, vrf, _) in view.scan_typed(&VRFS, KeyRange::all(), usize::MAX, false)? {
            let vrf: Vrf = vrf;
            if vrf.meta.is_deleted() {
                continue;
            }
            if Some(vrf.tenant) == intent.default_tenant
                && vrf.name.eq_ignore_ascii_case(DEFAULT_NAME)
            {
                intent.default_vrf = Some(vrf.id);
            }
            intent.vrfs.push(vrf.id);
        }
        for (_, prefix, revision) in
            view.scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)?
        {
            let mut prefix: Prefix = prefix;
            if prefix.meta.is_deleted() {
                continue;
            }
            prefix.meta.revision = revision;
            intent.by_vrf.entry(prefix.vrf).or_default().push(prefix.id);
            intent.prefixes.insert(prefix.id, prefix);
        }
        for (_, vlan, _) in view.scan_typed(&VLANS, KeyRange::all(), usize::MAX, false)? {
            let vlan: Vlan = vlan;
            if !vlan.meta.is_deleted() {
                intent.vlan_ids.insert((vlan.site, vlan.vid), vlan.id);
                intent.vlans.insert(vlan.id, vlan);
            }
        }
        for (_, range, _) in view.scan_typed(&RANGES, KeyRange::all(), usize::MAX, false)? {
            let range: Range = range;
            if !range.meta.is_deleted() {
                intent.ranges.entry(range.prefix).or_default().push(range);
            }
        }
        for (_, host, revision) in view.scan_typed(&HOSTS, KeyRange::all(), usize::MAX, false)? {
            let mut host: Host = host;
            if host.meta.is_deleted() {
                continue;
            }
            host.meta.revision = revision;
            intent
                .host_names
                .insert((host.tenant, host.name.as_str().to_ascii_lowercase()));
            intent.hosts.insert(host.id, host);
        }
        for (_, interface, revision) in
            view.scan_typed(&INTERFACES, KeyRange::all(), usize::MAX, false)?
        {
            let mut interface: Interface = interface;
            if interface.meta.is_deleted() || !intent.hosts.contains_key(&interface.host) {
                continue;
            }
            interface.meta.revision = revision;
            if let Some(mac) = interface.mac {
                intent
                    .interfaces_by_mac
                    .entry(mac)
                    .or_default()
                    .push(interface.id);
            }
            intent.interfaces.insert(interface.id, interface);
        }
        for (_, address, revision) in
            view.scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)?
        {
            let mut address: Address = address;
            if address.meta.is_deleted() {
                continue;
            }
            address.meta.revision = revision;
            intent
                .address_by_ip
                .insert((address.vrf, address.ip), address.id);
            if let Some(interface) = address.interface
                && intent.interfaces.contains_key(&interface)
            {
                intent
                    .addresses_of
                    .entry(interface)
                    .or_default()
                    .push(address.id);
            }
            intent.addresses.insert(address.id, address);
        }
        if intent.default_vrf.is_none() && intent.vrfs.len() == 1 {
            intent.default_vrf = intent.vrfs.first().copied();
        }
        intent.decommissioned_macs = super::dormant::decommissioned_macs(&intent);
        Ok(intent)
    }

    /// The most specific live prefix of `vrf` that contains `ip`.
    pub(crate) fn most_specific(&self, vrf: VrfId, ip: IpAddr) -> Option<&Prefix> {
        self.by_vrf
            .get(&vrf)?
            .iter()
            .filter_map(|id| self.prefixes.get(id))
            .filter(|prefix| contains_ip(&prefix.cidr, ip))
            .max_by_key(|prefix| prefix.cidr.prefix_len())
    }

    /// The most specific network prefix of `vrf` that contains `ip`.
    pub(crate) fn network_of(&self, vrf: VrfId, ip: IpAddr) -> Option<&Prefix> {
        self.most_specific(vrf, ip)
            .filter(|prefix| prefix.role == PrefixRole::Network)
    }

    /// Where an observed address belongs; `hint` is the VRF the source names.
    pub(crate) fn place(&self, ip: IpAddr, hint: Option<VrfId>) -> Placement {
        if let Some(vrf) = hint {
            return match self.network_of(vrf, ip) {
                Some(prefix) => Placement::Network {
                    vrf,
                    prefix: prefix.id,
                },
                None => Placement::Outside { vrf },
            };
        }
        let networks: Vec<(VrfId, PrefixId)> = self
            .vrfs
            .iter()
            .filter_map(|vrf| self.network_of(*vrf, ip).map(|prefix| (*vrf, prefix.id)))
            .collect();
        match networks.as_slice() {
            [(vrf, prefix)] => Placement::Network {
                vrf: *vrf,
                prefix: *prefix,
            },
            [] => self
                .default_vrf
                .map_or(Placement::Unplaced, |vrf| Placement::Outside { vrf }),
            _ => Placement::Unplaced,
        }
    }

    /// The live VLAN with VLAN id `vid` that a network of `site` uses: the site's own, else
    /// a global one.
    pub(crate) fn vlan_at(&self, site: Option<SiteId>, vid: u16) -> Option<&Vlan> {
        self.vlan_ids
            .get(&(site, vid))
            .or_else(|| site.and_then(|_| self.vlan_ids.get(&(None, vid))))
            .and_then(|id| self.vlans.get(id))
    }

    /// Whether `ip` lies inside a live DHCP pool of `prefix`.
    pub(crate) fn in_dhcp_pool(&self, prefix: PrefixId, ip: IpAddr) -> bool {
        let value = ip_to_u128(ip);
        self.ranges.get(&prefix).is_some_and(|ranges| {
            ranges.iter().any(|range| {
                range.role == RangeRole::DhcpPool
                    && Family::of(range.first) == Family::of(ip)
                    && ip_to_u128(range.first) <= value
                    && value <= ip_to_u128(range.last)
            })
        })
    }

    /// The prefix and every live prefix of its VRF that contains it, most specific first.
    pub(crate) fn self_and_ancestors(&self, prefix: PrefixId) -> Vec<PrefixId> {
        let Some(start) = self.prefixes.get(&prefix) else {
            return Vec::new();
        };
        let mut chain: Vec<&Prefix> = self
            .by_vrf
            .get(&start.vrf)
            .into_iter()
            .flatten()
            .filter_map(|id| self.prefixes.get(id))
            .filter(|other| contains_net(&other.cidr, &start.cidr))
            .collect();
        chain.sort_by_key(|other| std::cmp::Reverse(other.cidr.prefix_len()));
        chain.into_iter().map(|other| other.id).collect()
    }

    /// The host of a live interface.
    pub(crate) fn host_of(&self, interface: InterfaceId) -> Option<&Host> {
        self.interfaces
            .get(&interface)
            .and_then(|interface| self.hosts.get(&interface.host))
    }

    /// The host an address is assigned to, through its interface.
    pub(crate) fn host_of_address(&self, address: &Address) -> Option<&Host> {
        address
            .interface
            .and_then(|interface| self.host_of(interface))
    }
}

/// One address or MAC pair a current fact reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    /// Index of the fact in [`Snapshot::facts`].
    pub fact: usize,
    /// The MAC address, when the fact pairs one with the address (or names only a MAC).
    pub mac: Option<MacAddr>,
    /// The address.
    pub ip: Option<IpAddr>,
    /// Where the address belongs.
    pub placement: Option<Placement>,
    /// The name the source gives.
    pub name: Option<String>,
    /// The fact is a host its source reports as stopped: the address is configured, not in
    /// use, and the claim is dormant ([`Snapshot::dormant`]).
    pub dormant: bool,
}

/// Whether an address is one IPAM tracks: unicast, not loopback, link-local, multicast or
/// unspecified.
pub(crate) fn trackable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || v6.is_unicast_link_local())
        }
    }
}

/// Everything a reconcile run reads.
#[derive(Debug)]
pub(crate) struct Snapshot {
    pub now: Timestamp,
    pub intent: Intent,
    /// Every fact within retention, with its revision.
    pub facts: Vec<ObservedFact>,
    /// The pairs the current facts report. Name and vendor facts are not sightings and
    /// report none.
    pub seen: Vec<Seen>,
    /// The names current name facts of probes give addresses (reverse DNS, mDNS, LLMNR,
    /// SNMP), for naming proposals only: a name is not a sighting of its address.
    pub names: BTreeMap<IpAddr, BTreeSet<String>>,
    /// Open proposals by subject key, with the revision of their key row.
    pub open: BTreeMap<String, (IntentProposal, Revision)>,
    /// Remembered rejections by subject key, with their revision.
    pub rejections: BTreeMap<String, (Rejection, Revision)>,
    /// Adoption policies by prefix.
    pub policies: BTreeMap<PrefixId, StoredPolicy>,
    /// Last sightings of intent objects, with their revision.
    pub sightings: BTreeMap<ObjectRef, (IntentSighting, Revision)>,
    /// The vendors current facts report for MAC addresses, from any source (probes,
    /// network controllers, inventories such as Home Assistant), for the `vendors`
    /// constraint of adoption policies.
    pub vendors: BTreeMap<MacAddr, BTreeSet<String>>,
    /// The scopes the probes apply (`scan.scopes`); empty when no probe reported one.
    pub scopes: Vec<ScanScope>,
    /// Indexes in [`Self::facts`] of the current networks network controllers report.
    pub networks: Vec<usize>,
    /// The dormant claims that a live claim on the same address overrides: pairs of
    /// stopped hosts at an address where a running host, a lease or a scan sees another
    /// device (or a device without a MAC address). They are not in [`Self::seen`], so no rule
    /// sees them; the views show them as configured on the stopped host.
    pub dormant: Vec<Seen>,
}

impl Snapshot {
    /// Whether the address is scanned: no probe scope is known (every address counts as
    /// scanned, as before scopes existed), or a probe covers it.
    pub(crate) fn scanned(&self, vrf: VrfId, ip: IpAddr) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.covers(vrf, ip))
    }
}

impl Snapshot {
    pub(crate) fn load(view: &dyn ReadView, now: Timestamp) -> IpamResult<Self> {
        let intent = Intent::load(view)?;
        let facts: Vec<ObservedFact> = view
            .scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, mut fact, revision)| {
                fact.revision = revision;
                fact
            })
            .collect();
        let mut seen = Vec::new();
        let mut names: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
        let mut vendors: BTreeMap<MacAddr, BTreeSet<String>> = BTreeMap::new();
        let mut networks = Vec::new();
        for (index, fact) in facts.iter().enumerate() {
            if !fact.is_current(now) {
                continue;
            }
            if let Observed::Network { .. } = &fact.observed {
                if matches!(fact.source, ObservationSource::NetworkController { .. }) {
                    networks.push(index);
                }
                continue;
            }
            if let Observed::Vendor { mac, vendor } = &fact.observed {
                let vendor = vendor.trim();
                if !vendor.is_empty() {
                    vendors.entry(*mac).or_default().insert(vendor.to_owned());
                }
                continue;
            }
            if let Observed::Name { ip, name } = &fact.observed {
                let name = name.trim();
                if !name.is_empty() && trackable(*ip) {
                    names.entry(*ip).or_default().insert(name.to_owned());
                }
                continue;
            }
            seen.extend(pairs(index, fact, &intent));
        }
        // The facts of decommissioned hosts raise nothing.
        seen.retain(|pair| {
            pair.mac
                .is_none_or(|mac| !intent.decommissioned_macs.contains(&mac))
        });
        let (seen, dormant) = super::dormant::split(seen);
        let mut open = BTreeMap::new();
        for (key, id, revision) in
            view.scan_typed(&OPEN_KEYS, KeyRange::all(), usize::MAX, false)?
        {
            let id: ProposalId = id;
            if let Some((mut proposal, proposal_revision)) = view.get_typed(&PROPOSALS, &id)? {
                proposal.revision = proposal_revision;
                if proposal.is_open() {
                    open.insert(key, (proposal, revision));
                }
            }
        }
        let rejections = view
            .scan_typed(&REJECTIONS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(key, rejection, revision)| (key, (rejection, revision)))
            .collect();
        let policies = view
            .scan_typed(&ADOPTION, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(prefix, mut policy, revision)| {
                policy.revision = revision;
                (prefix, policy)
            })
            .collect();
        let sightings = view
            .scan_typed(&LAST_SEEN, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(object, sighting, revision)| (object, (sighting, revision)))
            .collect();
        Ok(Self {
            now,
            intent,
            facts,
            seen,
            names,
            open,
            rejections,
            policies,
            sightings,
            vendors,
            scopes: super::scopes::load(view)?,
            networks,
            dormant,
        })
    }
}

/// The pairs one current fact reports. A host with exactly one MAC address pairs it with
/// each of its addresses; with several, the pairing is unknown, so each MAC address and
/// each address stands alone.
fn pairs(index: usize, fact: &ObservedFact, intent: &Intent) -> Vec<Seen> {
    let name = fact.name().map(str::to_owned);
    let macs = fact.macs();
    let ips: Vec<IpAddr> = fact.ips().into_iter().filter(|ip| trackable(*ip)).collect();
    let hint = fact.vrf();
    let dormant = matches!(&fact.observed, Observed::Host(host) if host.is_stopped());
    let seen = |mac: Option<MacAddr>, ip: Option<IpAddr>| Seen {
        fact: index,
        mac,
        ip,
        placement: ip.map(|ip| intent.place(ip, hint)),
        name: name.clone(),
        dormant,
    };
    // A link names devices, not addresses; a name, a vendor or a network is not a sighting.
    if matches!(
        fact.observed,
        Observed::Link { .. }
            | Observed::Name { .. }
            | Observed::Vendor { .. }
            | Observed::Network { .. }
    ) {
        return Vec::new();
    }
    match macs.as_slice() {
        [mac] if !ips.is_empty() => ips.iter().map(|ip| seen(Some(*mac), Some(*ip))).collect(),
        _ => {
            let mut out: Vec<Seen> = macs.iter().map(|mac| seen(Some(*mac), None)).collect();
            out.extend(ips.iter().map(|ip| seen(None, Some(*ip))));
            out
        }
    }
}
