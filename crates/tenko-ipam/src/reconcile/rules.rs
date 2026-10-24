//! The reconciler's rules: from a [`Snapshot`] to the proposals that should be open.
//!
//! Every rule is a pure function of the snapshot. Intent always wins for managed hosts:
//! no rule suggests a change to a locked host, and nothing at all concerns an
//! `unmanaged` host. Addresses that IPAM does not track (loopback, link-local, multicast,
//! unspecified) are ignored, and an address whose VRF cannot be told (several VRFs have a
//! network for it and the source names none) produces nothing.
//!
//! | Rule | Kind | Severity | Commands |
//! |---|---|---|---|
//! | `ipam.reconcile.discovered_mac` | discovered host | info | create the host (mode `dynamic`, tag `discovered`) with an interface carrying the MAC, and its addresses (or bind an unassigned address) |
//! | `ipam.reconcile.discovered_address` | discovered host | info | the same without a MAC address |
//! | `ipam.reconcile.address_unrecorded` | address mismatch | info | add the observed address to the interface |
//! | `ipam.reconcile.address_mismatch` | address mismatch | warning, info for `dynamic` hosts | renumber the intended address to the observed one |
//! | `ipam.reconcile.orphaned_address` | orphaned intent | info | deprecate the address |
//! | `ipam.reconcile.conflict_shared_address` | conflict | critical | none |
//! | `ipam.reconcile.conflict_networks` | conflict | warning | none |
//! | `ipam.reconcile.conflict_address_taken` | conflict | warning | none |
//! | `ipam.reconcile.outside_prefixes` | outside prefixes | warning | create the suggested network |
//! | `ipam.reconcile.vlan_discovered` | VLAN discovered | info | create the VLAN a controller network carries (its name, the prefix's site) |
//! | `ipam.reconcile.prefix_vlan_unset` | prefix VLAN mismatch | info | link the prefix whose range equals the network's subnet to the VLAN, creating the VLAN when missing |
//! | `ipam.reconcile.prefix_vlan_differs` | prefix VLAN mismatch | warning | the same, for a prefix linked to a VLAN with another id |
//! | `ipam.reconcile.dns_record_held` | conflict | warning | none: another origin holds an RRset IPAM wants |
//! | `ipam.reconcile.dns_no_zone` | orphaned intent | info | none: DNS names without a zone in Tenko, listed |
//! | `ipam.reconcile.dns_orphaned_record` | orphaned intent | info | none: an `ipam` RRset without intent (orphan rule `propose`) |
//! | `ipam.reconcile.dns_delegation` | orphaned intent | info | none: the RFC 2317 lines to add to a parent zone Tenko does not serve |
//! | `ipam.reconcile.dns_reverse_orphaned` | orphaned intent | info | none: a reverse zone Tenko no longer keeps |
//! | `ipam.reconcile.dns_reverse_no_servers` | orphaned intent | info | none: no zone lends a new reverse zone its SOA and name servers |
//!
//! The DNS rules come from the planner of [`crate::dns`] (the same read view); a person
//! resolves them in the zones or the intent, so they carry no commands.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    net::IpAddr,
    time::Duration,
};

use ipnet::IpNet;
use tenko_core::{
    AddressId, HostId, InterfaceId, MacAddr, ObjectRef, PrefixId, SiteId, TenantId, VlanId, VrfId,
    ipam::{Address, AssignmentMode, Host, Prefix, Status, Tag},
    net::HostName,
    observe::Observed,
};

use super::snapshot::{Placement, Seen, Snapshot};
use crate::{
    command::{
        AddressInput, AddressPatch, HostInput, InterfaceInput, IpamCommand, PrefixInput,
        PrefixPatch, UpdateAddress, UpdatePrefix, VlanInput,
    },
    dns::{DnsFinding, plan::record_text},
    net::{Family, contains_net},
    observe::model::{IntentSighting, ObservedFact},
    proposals::model::{IntentProposalKind, ProposalEvidence, ProposalSeverity, ProposalSubject},
};

/// Rule codes.
pub mod rule {
    /// An unknown MAC address.
    pub const DISCOVERED_MAC: &str = "ipam.reconcile.discovered_mac";
    /// An unknown address without a MAC address.
    pub const DISCOVERED_ADDRESS: &str = "ipam.reconcile.discovered_address";
    /// A known device on an address its intent does not list (it has none in the family).
    pub const ADDRESS_UNRECORDED: &str = "ipam.reconcile.address_unrecorded";
    /// A known device on an address other than its intent.
    pub const ADDRESS_MISMATCH: &str = "ipam.reconcile.address_mismatch";
    /// An intended address no source has seen for the orphan age.
    pub const ORPHANED_ADDRESS: &str = "ipam.reconcile.orphaned_address";
    /// Two devices on one address.
    pub const CONFLICT_SHARED_ADDRESS: &str = "ipam.reconcile.conflict_shared_address";
    /// One device in two networks of one family that its intent does not list.
    pub const CONFLICT_NETWORKS: &str = "ipam.reconcile.conflict_networks";
    /// An address intended for one device, used by another.
    pub const CONFLICT_ADDRESS_TAKEN: &str = "ipam.reconcile.conflict_address_taken";
    /// Addresses outside every known network.
    pub const OUTSIDE_PREFIXES: &str = "ipam.reconcile.outside_prefixes";
    /// A VLAN a network controller carries that IPAM does not know.
    pub const VLAN_DISCOVERED: &str = "ipam.reconcile.vlan_discovered";
    /// A prefix without a VLAN whose network a controller carries on one.
    pub const PREFIX_VLAN_UNSET: &str = "ipam.reconcile.prefix_vlan_unset";
    /// A prefix linked to another VLAN than the one a controller carries its network on.
    pub const PREFIX_VLAN_DIFFERS: &str = "ipam.reconcile.prefix_vlan_differs";
    /// An RRset IPAM wants is held by another origin with other data.
    pub const DNS_RECORD_HELD: &str = "ipam.reconcile.dns_record_held";
    /// DNS names of intent without a zone in Tenko.
    pub const DNS_NO_ZONE: &str = "ipam.reconcile.dns_no_zone";
    /// An `ipam` RRset whose address lost its name or its intent.
    pub const DNS_ORPHANED_RECORD: &str = "ipam.reconcile.dns_orphaned_record";
    /// The RFC 2317 delegation to add in a parent zone Tenko does not serve.
    pub const DNS_DELEGATION: &str = "ipam.reconcile.dns_delegation";
    /// A reverse zone whose prefix is gone or off: no longer kept.
    pub const DNS_REVERSE_ORPHANED: &str = "ipam.reconcile.dns_reverse_orphaned";
    /// A managed prefix whose reverse zone has no zone to lend it SOA values and servers.
    pub const DNS_REVERSE_NO_SERVERS: &str = "ipam.reconcile.dns_reverse_no_servers";
}

/// Names listed in full in a DNS proposal's summary; the rest are counted.
const LISTED_NAMES: usize = 20;

/// The tag of hosts created from a discovered-host proposal.
pub const DISCOVERED_TAG: &str = "discovered";

/// A proposal the snapshot calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub kind: IntentProposalKind,
    pub rule: &'static str,
    pub key: String,
    pub subject: ProposalSubject,
    pub severity: ProposalSeverity,
    pub summary: String,
    pub params: BTreeMap<String, String>,
    pub evidence: Vec<ProposalEvidence>,
    pub commands: Vec<IpamCommand>,
    /// What the suggestion does, without generated identifiers: with the evidence
    /// identities it makes the fingerprint.
    pub shape: Vec<String>,
}

/// Settings of the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleConfig {
    pub orphan_after: Duration,
}

/// Every candidate of the snapshot, ordered by key. `sightings` are the last sightings
/// after this run's updates.
pub(crate) fn candidates(
    snapshot: &Snapshot,
    sightings: &BTreeMap<ObjectRef, IntentSighting>,
    config: RuleConfig,
    dns_findings: &[DnsFinding],
) -> Vec<Candidate> {
    let mut names = NameBook::new(snapshot);
    let mut out = Vec::new();
    out.extend(dns(snapshot, dns_findings));
    out.extend(discovered(snapshot, &mut names));
    out.extend(mismatches(snapshot));
    out.extend(conflicts(snapshot));
    out.extend(outside(snapshot));
    out.extend(vlans(snapshot));
    out.extend(orphans(snapshot, sightings, config));
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out.dedup_by(|a, b| a.key == b.key);
    out
}

// ----- shared helpers ---------------------------------------------------------------

/// The evidence of a set of pairs, one entry per fact and pair.
fn evidence(snapshot: &Snapshot, pairs: &[&Seen]) -> Vec<ProposalEvidence> {
    let mut seen: BTreeSet<(usize, Option<MacAddr>, Option<IpAddr>)> = BTreeSet::new();
    let mut out = Vec::new();
    for pair in pairs {
        if !seen.insert((pair.fact, pair.mac, pair.ip)) {
            continue;
        }
        let fact = &snapshot.facts[pair.fact];
        out.push(ProposalEvidence {
            source: fact.source.clone(),
            source_key: fact.source_key.clone(),
            subject_key: fact.subject_key.clone(),
            observation: fact.observation,
            mac: pair.mac,
            ip: pair.ip,
            name: pair.name.clone(),
            first_seen: fact.first_seen,
            last_seen: fact.last_seen,
            sightings: fact.sightings,
        });
    }
    out.sort_by(|a, b| {
        (&a.source_key, &a.subject_key, a.mac, a.ip).cmp(&(
            &b.source_key,
            &b.subject_key,
            b.mac,
            b.ip,
        ))
    });
    out
}

/// The number of distinct sources among the evidence.
fn source_count(evidence: &[ProposalEvidence]) -> usize {
    evidence
        .iter()
        .map(|evidence| evidence.source_key.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn join<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// Whether nothing may concern this host: it is `unmanaged`.
fn untouchable(host: &Host) -> bool {
    host.mode == AssignmentMode::Unmanaged
}

/// Host names already used or promised: live intent names, and the names suggested by
/// open proposals (reserved for their own key).
struct NameBook {
    intent: BTreeSet<String>,
    reserved: BTreeMap<String, String>,
}

impl NameBook {
    fn new(snapshot: &Snapshot) -> Self {
        let tenant: Option<TenantId> = snapshot.intent.default_tenant;
        let intent = snapshot
            .intent
            .host_names
            .iter()
            .filter(|(owner, _)| Some(*owner) == tenant)
            .map(|(_, name)| name.clone())
            .collect();
        let mut reserved = BTreeMap::new();
        for (key, (proposal, _)) in &snapshot.open {
            for command in &proposal.commands {
                if let IpamCommand::CreateHost(input) = command {
                    reserved.insert(input.name.as_str().to_owned(), key.clone());
                }
            }
        }
        Self { intent, reserved }
    }

    /// A free name for `key`: the first usable observed name, else `fallback`, with a
    /// `-2`, `-3`, ... suffix when taken.
    fn take(&mut self, key: &str, observed: &[String], fallback: &str) -> Option<HostName> {
        let base = observed
            .iter()
            .find_map(|name| sanitize(name))
            .or_else(|| sanitize(fallback))?;
        for attempt in 1..100u32 {
            let text = if attempt == 1 {
                base.clone()
            } else {
                format!("{base}-{attempt}")
            };
            let Ok(name) = HostName::new(&text) else {
                continue;
            };
            let free = !self.intent.contains(name.as_str())
                && self
                    .reserved
                    .get(name.as_str())
                    .is_none_or(|owner| owner == key);
            if free {
                self.reserved
                    .insert(name.as_str().to_owned(), key.to_owned());
                return Some(name);
            }
        }
        None
    }
}

/// A host name from free text: lowercase, characters outside `a-z0-9-_.` become `-`, runs
/// of `-` collapse, labels are trimmed of `-` and cut to 63 characters, at most 200
/// characters in all. `None` when nothing usable remains.
fn sanitize(text: &str) -> Option<String> {
    let lower = text.trim().to_ascii_lowercase();
    let mapped: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let labels: Vec<String> = mapped
        .split('.')
        .map(|label| {
            let mut collapsed = String::new();
            for c in label.chars() {
                if c == '-' && collapsed.ends_with('-') {
                    continue;
                }
                collapsed.push(c);
            }
            let trimmed: String = collapsed.trim_matches('-').chars().take(63).collect();
            trimmed.trim_end_matches('-').to_owned()
        })
        .filter(|label| !label.is_empty())
        .collect();
    let name: String = labels.join(".").chars().take(200).collect();
    let name = name.trim_end_matches(['.', '-']).to_owned();
    HostName::new(&name)
        .ok()
        .map(|name| name.as_str().to_owned())
}

/// The fallback name of a device with a MAC address: `host-00005e005301`.
fn mac_name(mac: MacAddr) -> String {
    let hex: String = mac
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    format!("host-{hex}")
}

/// The fallback name of a device known by its address: `host-192-0-2-10`.
fn ip_name(ip: IpAddr) -> String {
    let text: String = ip
        .to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("host-{}", text.trim_matches('-'))
}

fn discovered_tag() -> std::collections::BTreeSet<Tag> {
    Tag::new(DISCOVERED_TAG)
        .map(|tag| std::collections::BTreeSet::from([tag]))
        .unwrap_or_default()
}

fn new_address(vrf: VrfId, ip: IpAddr, interface: InterfaceId) -> IpamCommand {
    IpamCommand::CreateAddress(AddressInput {
        id: Some(AddressId::generate()),
        vrf: Some(vrf),
        ip,
        status: None,
        interface: Some(interface),
        dns_name: None,
        tags: std::collections::BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    })
}

fn bind_address(address: AddressId, interface: InterfaceId) -> IpamCommand {
    IpamCommand::UpdateAddress(UpdateAddress {
        id: address,
        expected: None,
        patch: AddressPatch {
            interface: Some(Some(interface)),
            ..AddressPatch::default()
        },
    })
}

// ----- discovered hosts -------------------------------------------------------------

/// What a discovered device gets: new addresses, or an unassigned address to bind.
#[derive(Debug, Default)]
struct Placed {
    /// (VRF, prefix, address) of addresses to create.
    create: Vec<(VrfId, PrefixId, IpAddr)>,
    /// Unassigned addresses of intent to bind.
    bind: Vec<(AddressId, PrefixId, IpAddr)>,
    /// Addresses that could not be placed (outside, unplaced, taken).
    other: usize,
}

/// Places observed addresses for a discovered device. Addresses that several devices use
/// (`contested`) are left to the conflict rule.
fn place_addresses(
    snapshot: &Snapshot,
    ips: &BTreeSet<(IpAddr, Placement)>,
    contested: &BTreeSet<(VrfId, IpAddr)>,
) -> Placed {
    let mut placed = Placed::default();
    for (ip, placement) in ips {
        match placement {
            Placement::Network { vrf, .. } if contested.contains(&(*vrf, *ip)) => {
                placed.other += 1;
            }
            Placement::Network { vrf, prefix } => {
                match snapshot.intent.address_by_ip.get(&(*vrf, *ip)) {
                    None => placed.create.push((*vrf, *prefix, *ip)),
                    Some(id) => {
                        let unassigned = snapshot.intent.addresses.get(id).is_some_and(|address| {
                            address.interface.is_none()
                                || snapshot.intent.host_of_address(address).is_none()
                        });
                        if unassigned {
                            placed.bind.push((*id, *prefix, *ip));
                        } else {
                            placed.other += 1;
                        }
                    }
                }
            }
            Placement::Outside { .. } | Placement::Unplaced => placed.other += 1,
        }
    }
    placed
}

/// The proposal of one unknown device: by MAC address (`mac`) or by address.
#[allow(clippy::too_many_lines)] // One suggestion: the host, its interface and addresses.
#[allow(clippy::too_many_arguments)]
fn discovered_one(
    snapshot: &Snapshot,
    names: &mut NameBook,
    key: String,
    rule: &'static str,
    mac: Option<MacAddr>,
    pairs: &[&Seen],
    placed: &Placed,
    fallback: &str,
) -> Option<Candidate> {
    // The names the sightings carry (inventory hosts) first, then the names probes found
    // for the addresses of the device.
    let mut observed_names: Vec<String> = pairs
        .iter()
        .filter_map(|pair| pair.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let probed: BTreeSet<&String> = pairs
        .iter()
        .filter_map(|pair| pair.ip)
        .filter_map(|ip| snapshot.names.get(&ip))
        .flatten()
        .collect();
    for name in probed {
        if !observed_names.contains(name) {
            observed_names.push(name.clone());
        }
    }
    let name = names.take(&key, &observed_names, fallback)?;
    let host = HostId::generate();
    let interface = InterfaceId::generate();
    let mut commands = vec![IpamCommand::CreateHost(HostInput {
        id: Some(host),
        tenant: None,
        name: name.clone(),
        mode: Some(AssignmentMode::Dynamic),
        lock: None,
        site: None,
        interfaces: vec![InterfaceInput {
            id: Some(interface),
            host: None,
            name: "eth0".to_owned(),
            mac,
            duid: None,
            client_id: None,
            tags: std::collections::BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }],
        tags: discovered_tag(),
        custom: BTreeMap::new(),
        description: None,
    })];
    let mut shape = vec![
        format!("host:{name}"),
        format!("mac:{}", mac.map(|mac| mac.to_string()).unwrap_or_default()),
    ];
    let mut ips = Vec::new();
    for (vrf, _, ip) in &placed.create {
        commands.push(new_address(*vrf, *ip, interface));
        shape.push(format!("address:{vrf}/{ip}"));
        ips.push(*ip);
    }
    let mut objects = Vec::new();
    for (address, _, ip) in &placed.bind {
        commands.push(bind_address(*address, interface));
        shape.push(format!("bind:{address}"));
        objects.push(ObjectRef::from(*address));
        ips.push(*ip);
    }
    ips.sort();
    let first = placed
        .create
        .iter()
        .map(|(vrf, prefix, ip)| (Family::of(*ip), *ip, *vrf, *prefix))
        .chain(placed.bind.iter().filter_map(|(address, prefix, ip)| {
            let vrf = snapshot.intent.addresses.get(address)?.vrf;
            Some((Family::of(*ip), *ip, vrf, *prefix))
        }))
        .min();
    let evidence = evidence(snapshot, pairs);
    let sources = source_count(&evidence);
    let mut params = BTreeMap::from([
        ("name".to_owned(), name.to_string()),
        ("sources".to_owned(), sources.to_string()),
    ]);
    if let Some(mac) = mac {
        params.insert("mac".to_owned(), mac.to_string());
    }
    if !ips.is_empty() {
        params.insert("ips".to_owned(), join(&ips));
    }
    let who = match mac {
        Some(mac) => format!("Unknown device {mac}"),
        None => "Unknown device".to_owned(),
    };
    let summary = if ips.is_empty() {
        format!(
            "{who} ({name}) seen by {}; adopt it as host {name}",
            plural(sources, "source", "sources")
        )
    } else {
        format!(
            "{who} ({name}) seen at {} by {}; adopt it as host {name}",
            join(&ips),
            plural(sources, "source", "sources")
        )
    };
    Some(Candidate {
        kind: IntentProposalKind::DiscoveredHost,
        rule,
        key,
        subject: ProposalSubject {
            mac,
            ip: first.map(|(_, ip, _, _)| ip),
            cidr: None,
            vrf: first.map(|(_, _, vrf, _)| vrf),
            prefix: first.map(|(_, _, _, prefix)| prefix),
            name: observed_names.first().cloned(),
            objects,
        },
        severity: ProposalSeverity::Info,
        summary,
        params,
        evidence,
        commands,
        shape,
    })
}

/// Unknown MAC addresses and unknown addresses inside known networks.
fn discovered(snapshot: &Snapshot, names: &mut NameBook) -> Vec<Candidate> {
    let mut by_mac: BTreeMap<MacAddr, Vec<&Seen>> = BTreeMap::new();
    let mut paired_ips: BTreeSet<IpAddr> = BTreeSet::new();
    let mut users: BTreeMap<(VrfId, IpAddr), BTreeSet<MacAddr>> = BTreeMap::new();
    for pair in &snapshot.seen {
        if let Some(mac) = pair.mac {
            by_mac.entry(mac).or_default().push(pair);
            if let Some(ip) = pair.ip {
                paired_ips.insert(ip);
                if let Some(vrf) = pair.placement.and_then(Placement::vrf) {
                    users.entry((vrf, ip)).or_default().insert(mac);
                }
            }
        }
    }
    let contested: BTreeSet<(VrfId, IpAddr)> = users
        .into_iter()
        .filter(|(_, macs)| macs.len() > 1)
        .map(|(address, _)| address)
        .collect();
    let mut out = Vec::new();
    for (mac, pairs) in &by_mac {
        if snapshot.intent.interfaces_by_mac.contains_key(mac) {
            continue;
        }
        let ips: BTreeSet<(IpAddr, Placement)> = pairs
            .iter()
            .filter_map(|pair| Some((pair.ip?, pair.placement?)))
            .collect();
        let placed = place_addresses(snapshot, &ips, &contested);
        if !ips.is_empty() && placed.create.is_empty() && placed.bind.is_empty() {
            // Its addresses lie outside known networks or belong to other hosts: the
            // outside-prefix and conflict rules speak first.
            continue;
        }
        if let Some(candidate) = discovered_one(
            snapshot,
            names,
            format!("discovered_host/mac:{mac}"),
            rule::DISCOVERED_MAC,
            Some(*mac),
            pairs,
            &placed,
            &mac_name(*mac),
        ) {
            out.push(candidate);
        }
    }
    let mut by_ip: BTreeMap<(IpAddr, Placement), Vec<&Seen>> = BTreeMap::new();
    for pair in &snapshot.seen {
        if pair.mac.is_none()
            && let (Some(ip), Some(placement)) = (pair.ip, pair.placement)
            && !paired_ips.contains(&ip)
        {
            by_ip.entry((ip, placement)).or_default().push(pair);
        }
    }
    for ((ip, placement), pairs) in &by_ip {
        let Placement::Network { vrf, .. } = placement else {
            continue;
        };
        if snapshot.intent.address_by_ip.contains_key(&(*vrf, *ip)) {
            continue;
        }
        let placed = place_addresses(snapshot, &BTreeSet::from([(*ip, *placement)]), &contested);
        if let Some(candidate) = discovered_one(
            snapshot,
            names,
            format!("discovered_host/ip:{vrf}/{ip}"),
            rule::DISCOVERED_ADDRESS,
            None,
            pairs,
            &placed,
            &ip_name(*ip),
        ) {
            out.push(candidate);
        }
    }
    out
}

// ----- address mismatches -----------------------------------------------------------

/// Known devices on addresses their intent does not list.
#[allow(clippy::too_many_lines)] // One rule: the sightings of each interface against its intent.
fn mismatches(snapshot: &Snapshot) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    // (interface, VRF, family) -> observed pairs.
    let mut observed: BTreeMap<(InterfaceId, VrfId, Family), Vec<&Seen>> = BTreeMap::new();
    for pair in &snapshot.seen {
        let (Some(mac), Some(ip), Some(Placement::Network { vrf, .. })) =
            (pair.mac, pair.ip, pair.placement)
        else {
            continue;
        };
        for interface in intent.interfaces_by_mac.get(&mac).into_iter().flatten() {
            observed
                .entry((*interface, vrf, Family::of(ip)))
                .or_default()
                .push(pair);
        }
    }
    for ((interface, vrf, family), pairs) in observed {
        let Some(host) = intent.host_of(interface) else {
            continue;
        };
        if host.lock || untouchable(host) {
            continue;
        }
        let intended: Vec<&Address> = intent
            .addresses_of
            .get(&interface)
            .into_iter()
            .flatten()
            .filter_map(|id| intent.addresses.get(id))
            .filter(|address| address.vrf == vrf && Family::of(address.ip) == family)
            .collect();
        let seen_ips: BTreeSet<IpAddr> = pairs.iter().filter_map(|pair| pair.ip).collect();
        if intended
            .iter()
            .any(|address| seen_ips.contains(&address.ip))
        {
            continue;
        }
        // Observed addresses that belong to another live interface are conflicts, not
        // suggestions.
        let free: Vec<IpAddr> = seen_ips
            .iter()
            .copied()
            .filter(|ip| match intent.address_by_ip.get(&(vrf, *ip)) {
                None => true,
                Some(id) => intent
                    .addresses
                    .get(id)
                    .is_some_and(|address| intent.host_of_address(address).is_none()),
            })
            .collect();
        let Some(observed_ip) = free.first().copied() else {
            continue;
        };
        let family_name = match family {
            Family::V4 => "v4",
            Family::V6 => "v6",
        };
        let key = format!("address_mismatch/interface:{interface}/{vrf}/{family_name}");
        let evidence = evidence(snapshot, &pairs);
        let prefix = intent.network_of(vrf, observed_ip).map(|prefix| prefix.id);
        let mut objects = vec![ObjectRef::from(host.id), ObjectRef::from(interface)];
        let mut params = BTreeMap::from([
            ("host".to_owned(), host.name.to_string()),
            ("ip".to_owned(), observed_ip.to_string()),
        ]);
        let (rule, severity, summary, commands, shape) = match intended.as_slice() {
            [] => {
                let existing = intent.address_by_ip.get(&(vrf, observed_ip)).copied();
                let command = match existing {
                    Some(address) => {
                        objects.push(ObjectRef::from(address));
                        bind_address(address, interface)
                    }
                    None => new_address(vrf, observed_ip, interface),
                };
                (
                    rule::ADDRESS_UNRECORDED,
                    ProposalSeverity::Info,
                    format!(
                        "{} is seen at {observed_ip}, which its intent does not list; record it",
                        host.name
                    ),
                    vec![command],
                    vec![format!("record:{vrf}/{observed_ip}")],
                )
            }
            [single] => {
                objects.push(ObjectRef::from(single.id));
                params.insert("intended".to_owned(), single.ip.to_string());
                let severity = if host.mode == AssignmentMode::Dynamic {
                    ProposalSeverity::Info
                } else {
                    ProposalSeverity::Warning
                };
                let commands = if intent.address_by_ip.contains_key(&(vrf, observed_ip)) {
                    Vec::new()
                } else {
                    vec![IpamCommand::UpdateAddress(UpdateAddress {
                        id: single.id,
                        expected: None,
                        patch: AddressPatch {
                            ip: Some(observed_ip),
                            ..AddressPatch::default()
                        },
                    })]
                };
                (
                    rule::ADDRESS_MISMATCH,
                    severity,
                    format!(
                        "{} is seen at {observed_ip}, not at its intended {}",
                        host.name, single.ip
                    ),
                    commands,
                    vec![format!("renumber:{}:{observed_ip}", single.id)],
                )
            }
            several => {
                for address in several {
                    objects.push(ObjectRef::from(address.id));
                }
                params.insert(
                    "intended".to_owned(),
                    join(several.iter().map(|address| address.ip)),
                );
                (
                    rule::ADDRESS_MISMATCH,
                    ProposalSeverity::Warning,
                    format!(
                        "{} is seen at {observed_ip}, not at any of its intended {}",
                        host.name,
                        join(several.iter().map(|address| address.ip))
                    ),
                    Vec::new(),
                    vec![format!("mismatch:{observed_ip}")],
                )
            }
        };
        out.push(Candidate {
            kind: IntentProposalKind::AddressMismatch,
            rule,
            key,
            subject: ProposalSubject {
                mac: intent.interfaces.get(&interface).and_then(|i| i.mac),
                ip: Some(observed_ip),
                cidr: None,
                vrf: Some(vrf),
                prefix,
                name: Some(host.name.to_string()),
                objects,
            },
            severity,
            summary,
            params,
            evidence,
            commands,
            shape,
        });
    }
    out
}

// ----- conflicts --------------------------------------------------------------------

/// The hosts of the live interfaces carrying a MAC address.
fn hosts_of_mac(snapshot: &Snapshot, mac: MacAddr) -> Vec<&Host> {
    snapshot
        .intent
        .interfaces_by_mac
        .get(&mac)
        .into_iter()
        .flatten()
        .filter_map(|interface| snapshot.intent.host_of(*interface))
        .collect()
}

/// Two devices on one address, one device in several networks, an address used by a
/// device other than the one it is intended for.
fn conflicts(snapshot: &Snapshot) -> Vec<Candidate> {
    let mut by_address: BTreeMap<(VrfId, IpAddr), Vec<&Seen>> = BTreeMap::new();
    for pair in &snapshot.seen {
        if let (Some(_), Some(ip), Some(placement)) = (pair.mac, pair.ip, pair.placement)
            && let Some(vrf) = placement.vrf()
        {
            by_address.entry((vrf, ip)).or_default().push(pair);
        }
    }
    let mut out = shared_addresses(snapshot, &by_address);
    out.extend(networks(snapshot));
    out.extend(taken_addresses(snapshot, &by_address));
    out
}

/// Two or more MAC addresses on one address.
fn shared_addresses(
    snapshot: &Snapshot,
    by_address: &BTreeMap<(VrfId, IpAddr), Vec<&Seen>>,
) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    for ((vrf, ip), pairs) in by_address {
        let macs: BTreeSet<MacAddr> = pairs.iter().filter_map(|pair| pair.mac).collect();
        if macs.len() < 2 {
            continue;
        }
        let hosts: BTreeSet<HostId> = macs
            .iter()
            .flat_map(|mac| hosts_of_mac(snapshot, *mac))
            .map(|host| host.id)
            .collect();
        let all_one_host = hosts.len() == 1
            && macs
                .iter()
                .all(|mac| intent.interfaces_by_mac.contains_key(mac));
        let unmanaged = macs
            .iter()
            .flat_map(|mac| hosts_of_mac(snapshot, *mac))
            .any(untouchable);
        if all_one_host || unmanaged {
            continue;
        }
        let evidence = evidence(snapshot, pairs);
        let objects: Vec<ObjectRef> = hosts.iter().map(|host| ObjectRef::from(*host)).collect();
        out.push(Candidate {
            kind: IntentProposalKind::Conflict,
            rule: rule::CONFLICT_SHARED_ADDRESS,
            key: format!("conflict/shared:{vrf}/{ip}"),
            subject: ProposalSubject {
                mac: None,
                ip: Some(*ip),
                cidr: None,
                vrf: Some(*vrf),
                prefix: intent.network_of(*vrf, *ip).map(|prefix| prefix.id),
                name: None,
                objects,
            },
            severity: ProposalSeverity::Critical,
            summary: format!("{ip} is used by {} devices: {}", macs.len(), join(&macs)),
            params: BTreeMap::from([
                ("ip".to_owned(), ip.to_string()),
                ("macs".to_owned(), join(&macs)),
                ("count".to_owned(), macs.len().to_string()),
            ]),
            evidence,
            commands: Vec::new(),
            shape: macs.iter().map(|mac| format!("mac:{mac}")).collect(),
        });
    }
    out
}

/// One MAC address in several networks of one family that its intent does not list.
fn networks(snapshot: &Snapshot) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    let mut by_mac: BTreeMap<(MacAddr, Family), Vec<&Seen>> = BTreeMap::new();
    for pair in &snapshot.seen {
        if let (Some(mac), Some(ip), Some(Placement::Network { .. })) =
            (pair.mac, pair.ip, pair.placement)
        {
            by_mac.entry((mac, Family::of(ip))).or_default().push(pair);
        }
    }
    for ((mac, family), pairs) in &by_mac {
        let networks: BTreeSet<PrefixId> = pairs
            .iter()
            .filter_map(|pair| pair.placement.and_then(Placement::prefix))
            .collect();
        if networks.len() < 2 {
            continue;
        }
        let hosts = hosts_of_mac(snapshot, *mac);
        if hosts.iter().any(|host| untouchable(host)) {
            continue;
        }
        let intended: BTreeSet<PrefixId> = intent
            .interfaces_by_mac
            .get(mac)
            .into_iter()
            .flatten()
            .flat_map(|interface| intent.addresses_of.get(interface).into_iter().flatten())
            .filter_map(|id| intent.addresses.get(id))
            .map(|address| address.prefix)
            .collect();
        if networks.is_subset(&intended) {
            continue;
        }
        let cidrs: Vec<String> = networks
            .iter()
            .filter_map(|prefix| intent.prefixes.get(prefix))
            .map(|prefix| prefix.cidr.to_string())
            .collect();
        let family_name = match family {
            Family::V4 => "v4",
            Family::V6 => "v6",
        };
        let mut objects: Vec<ObjectRef> =
            hosts.iter().map(|host| ObjectRef::from(host.id)).collect();
        objects.extend(networks.iter().map(|prefix| ObjectRef::from(*prefix)));
        out.push(Candidate {
            kind: IntentProposalKind::Conflict,
            rule: rule::CONFLICT_NETWORKS,
            key: format!("conflict/networks:{mac}/{family_name}"),
            subject: ProposalSubject {
                mac: Some(*mac),
                ip: None,
                cidr: None,
                vrf: None,
                prefix: None,
                name: hosts.first().map(|host| host.name.to_string()),
                objects,
            },
            severity: ProposalSeverity::Warning,
            summary: format!(
                "{mac} is seen in {} networks: {}",
                networks.len(),
                cidrs.join(", ")
            ),
            params: BTreeMap::from([
                ("mac".to_owned(), mac.to_string()),
                ("networks".to_owned(), cidrs.join(", ")),
                ("count".to_owned(), networks.len().to_string()),
            ]),
            evidence: evidence(snapshot, pairs),
            commands: Vec::new(),
            shape: networks
                .iter()
                .map(|prefix| format!("network:{prefix}"))
                .collect(),
        });
    }
    out
}

/// An address intended for one device and used by another.
fn taken_addresses(
    snapshot: &Snapshot,
    by_address: &BTreeMap<(VrfId, IpAddr), Vec<&Seen>>,
) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    for ((vrf, ip), pairs) in by_address {
        let Some(address) = intent
            .address_by_ip
            .get(&(*vrf, *ip))
            .and_then(|id| intent.addresses.get(id))
        else {
            continue;
        };
        let Some(interface) = address.interface.and_then(|id| intent.interfaces.get(&id)) else {
            continue;
        };
        let (Some(intended_mac), Some(host)) = (interface.mac, intent.hosts.get(&interface.host))
        else {
            continue;
        };
        if untouchable(host) {
            continue;
        }
        let own: BTreeSet<MacAddr> = intent
            .interfaces
            .values()
            .filter(|other| other.host == host.id)
            .filter_map(|other| other.mac)
            .collect();
        let foreign: Vec<&Seen> = pairs
            .iter()
            .copied()
            .filter(|pair| pair.mac.is_some_and(|mac| !own.contains(&mac)))
            .collect();
        let users: BTreeSet<MacAddr> = foreign.iter().filter_map(|pair| pair.mac).collect();
        if users.is_empty() {
            continue;
        }
        out.push(Candidate {
            kind: IntentProposalKind::Conflict,
            rule: rule::CONFLICT_ADDRESS_TAKEN,
            key: format!("conflict/taken:{}", address.id),
            subject: ProposalSubject {
                mac: users.first().copied(),
                ip: Some(*ip),
                cidr: None,
                vrf: Some(*vrf),
                prefix: Some(address.prefix),
                name: Some(host.name.to_string()),
                objects: vec![ObjectRef::from(host.id), ObjectRef::from(address.id)],
            },
            severity: ProposalSeverity::Warning,
            summary: format!(
                "{ip} is intended for {} ({intended_mac}) but used by {}",
                host.name,
                join(&users)
            ),
            params: BTreeMap::from([
                ("ip".to_owned(), ip.to_string()),
                ("host".to_owned(), host.name.to_string()),
                ("intended_mac".to_owned(), intended_mac.to_string()),
                ("macs".to_owned(), join(&users)),
            ]),
            evidence: evidence(snapshot, &foreign),
            commands: Vec::new(),
            shape: users.iter().map(|mac| format!("user:{mac}")).collect(),
        });
    }
    out
}

// ----- outside known networks -------------------------------------------------------

/// The network suggested around `ip` in `vrf`: /24 or /64, narrowed until it overlaps no
/// live prefix other than supernets that contain it.
fn suggested_network(snapshot: &Snapshot, vrf: VrfId, ip: IpAddr) -> Option<IpNet> {
    let family = Family::of(ip);
    let bits = family.bits();
    let mut length: u8 = match family {
        Family::V4 => 24,
        Family::V6 => 64,
    };
    let prefixes: Vec<IpNet> = snapshot
        .intent
        .by_vrf
        .get(&vrf)
        .into_iter()
        .flatten()
        .filter_map(|id| snapshot.intent.prefixes.get(id))
        .map(|prefix| prefix.cidr)
        .collect();
    loop {
        let net = IpNet::new(ip, length).ok()?.trunc();
        let blocked = prefixes.iter().any(|other| contains_net(&net, other));
        if !blocked {
            return Some(net);
        }
        if length >= bits {
            return None;
        }
        length += 1;
    }
}

/// Addresses seen outside every known network, grouped by the suggested network.
fn outside(snapshot: &Snapshot) -> Vec<Candidate> {
    let mut groups: BTreeMap<(VrfId, IpNet), Vec<&Seen>> = BTreeMap::new();
    let mut suggestions: BTreeMap<(VrfId, IpAddr), Option<IpNet>> = BTreeMap::new();
    for pair in &snapshot.seen {
        let (Some(ip), Some(Placement::Outside { vrf })) = (pair.ip, pair.placement) else {
            continue;
        };
        // Nothing at all concerns an unmanaged host, not even its addresses.
        if pair
            .mac
            .is_some_and(|mac| hosts_of_mac(snapshot, mac).into_iter().any(untouchable))
        {
            continue;
        }
        // An address inside a network suggested for an earlier address joins it.
        let joined = groups
            .keys()
            .find(|(group_vrf, net)| *group_vrf == vrf && net.contains(&ip))
            .copied();
        let net = match joined {
            Some((_, net)) => Some(net),
            None => *suggestions
                .entry((vrf, ip))
                .or_insert_with(|| suggested_network(snapshot, vrf, ip)),
        };
        if let Some(net) = net {
            groups.entry((vrf, net)).or_default().push(pair);
        }
    }
    groups
        .into_iter()
        .map(|((vrf, net), pairs)| {
            let ips: BTreeSet<IpAddr> = pairs.iter().filter_map(|pair| pair.ip).collect();
            Candidate {
                kind: IntentProposalKind::OutsidePrefixes,
                rule: rule::OUTSIDE_PREFIXES,
                key: format!("outside_prefixes/{vrf}/{net}"),
                subject: ProposalSubject {
                    mac: None,
                    ip: ips.first().copied(),
                    cidr: Some(net),
                    vrf: Some(vrf),
                    prefix: None,
                    name: None,
                    objects: Vec::new(),
                },
                severity: ProposalSeverity::Warning,
                summary: format!(
                    "{} seen outside every known network; create the network {net}",
                    plural(ips.len(), "address", "addresses")
                ),
                params: BTreeMap::from([
                    ("cidr".to_owned(), net.to_string()),
                    ("count".to_owned(), ips.len().to_string()),
                    ("ips".to_owned(), join(&ips)),
                ]),
                evidence: evidence(snapshot, &pairs),
                commands: vec![IpamCommand::CreatePrefix(PrefixInput {
                    id: Some(PrefixId::generate()),
                    vrf: Some(vrf),
                    cidr: net,
                    role: Some(tenko_core::ipam::PrefixRole::Network),
                    status: None,
                    vlan: None,
                    site: None,
                    alarm: None,
                    alloc: None,
                    tags: discovered_tag(),
                    custom: BTreeMap::new(),
                    description: None,
                })],
                shape: vec![format!("network:{vrf}/{net}")],
            }
        })
        .collect()
}

// ----- controller networks and VLANs -------------------------------------------------

/// One network a controller reports with a VLAN id, and the prefix of intent whose range
/// equals its subnet.
struct TaggedNetwork<'a> {
    fact: &'a ObservedFact,
    name: &'a str,
    subnet: Option<IpNet>,
    vid: u16,
    prefix: Option<&'a Prefix>,
}

/// The live prefix whose range equals `subnet`: the only one, else the one of the default
/// VRF; none when that does not settle it.
fn prefix_of_subnet(snapshot: &Snapshot, subnet: IpNet) -> Option<&Prefix> {
    let intent = &snapshot.intent;
    let equal: Vec<&Prefix> = intent
        .prefixes
        .values()
        .filter(|prefix| prefix.cidr == subnet)
        .collect();
    match equal.as_slice() {
        [one] => Some(*one),
        [] => None,
        _ => {
            let default: Vec<&Prefix> = equal
                .into_iter()
                .filter(|prefix| Some(prefix.vrf) == intent.default_vrf)
                .collect();
            match default.as_slice() {
                [one] => Some(*one),
                _ => None,
            }
        }
    }
}

/// The evidence of networks, one entry per fact.
fn network_evidence(networks: &[&TaggedNetwork<'_>]) -> Vec<ProposalEvidence> {
    let mut out: Vec<ProposalEvidence> = networks
        .iter()
        .map(|network| ProposalEvidence {
            source: network.fact.source.clone(),
            source_key: network.fact.source_key.clone(),
            subject_key: network.fact.subject_key.clone(),
            observation: network.fact.observation,
            mac: None,
            ip: None,
            name: Some(network.name.to_owned()),
            first_seen: network.fact.first_seen,
            last_seen: network.fact.last_seen,
            sightings: network.fact.sightings,
        })
        .collect();
    out.sort_by(|a, b| (&a.source_key, &a.subject_key).cmp(&(&b.source_key, &b.subject_key)));
    out.dedup_by(|a, b| (&a.source_key, &a.subject_key) == (&b.source_key, &b.subject_key));
    out
}

/// The VLAN a VLAN proposal creates: the network's name, the prefix's site (global without
/// one), tagged `discovered`.
fn new_vlan(id: VlanId, site: Option<SiteId>, vid: u16, name: &str) -> IpamCommand {
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect();
    IpamCommand::CreateVlan(VlanInput {
        id: Some(id),
        vid,
        vni: None,
        name: if name.is_empty() {
            format!("VLAN {vid}")
        } else {
            name
        },
        site,
        status: None,
        tags: discovered_tag(),
        custom: BTreeMap::new(),
        description: None,
    })
}

fn site_text(site: Option<SiteId>) -> String {
    site.map_or_else(|| "global".to_owned(), |site| site.to_string())
}

/// The VLANs and prefix links the networks of the controllers call for. A tagged network
/// whose VLAN id has no VLAN at the site of its prefix (or a global one) suggests the VLAN; a
/// prefix whose range equals a tagged network's subnet and that is not linked to a VLAN with
/// that id suggests the link, creating the VLAN in the same approval when it is missing (an
/// approval checks again whether another decision created it since). The untagged default
/// network suggests nothing, and neither does a prefix whose networks disagree on the VLAN.
fn vlans(snapshot: &Snapshot) -> Vec<Candidate> {
    let networks = tagged_networks(snapshot);
    // The VLAN each missing (site, VLAN id) gets, shared by the proposals of one run.
    let mut missing: MissingVlans<'_, '_> = BTreeMap::new();
    for network in &networks {
        let site = network.prefix.and_then(|prefix| prefix.site);
        if snapshot.intent.vlan_at(site, network.vid).is_none() {
            missing
                .entry((site, network.vid))
                .or_insert_with(|| (VlanId::generate(), Vec::new()))
                .1
                .push(network);
        }
    }
    let mut out = vlan_candidates(&missing);
    out.extend(link_candidates(snapshot, &networks, &missing));
    out
}

/// The VLAN each missing (site, VLAN id) gets, with the networks that carry it.
type MissingVlans<'s, 'n> = BTreeMap<(Option<SiteId>, u16), (VlanId, Vec<&'n TaggedNetwork<'s>>)>;

/// The current networks with a VLAN id, each with the prefix that equals its subnet.
fn tagged_networks(snapshot: &Snapshot) -> Vec<TaggedNetwork<'_>> {
    snapshot
        .networks
        .iter()
        .filter_map(|index| {
            let fact = &snapshot.facts[*index];
            let Observed::Network {
                name, subnet, vlan, ..
            } = &fact.observed
            else {
                return None;
            };
            let vid = vlan.filter(|vid| (1..=4094).contains(vid))?;
            let subnet = subnet.map(|subnet| subnet.trunc());
            Some(TaggedNetwork {
                fact,
                name: name.as_str(),
                subnet,
                vid,
                prefix: subnet.and_then(|subnet| prefix_of_subnet(snapshot, subnet)),
            })
        })
        .collect()
}

/// One VLAN-discovered proposal per missing VLAN.
fn vlan_candidates(missing: &MissingVlans<'_, '_>) -> Vec<Candidate> {
    let mut out = Vec::new();
    for ((site, vid), (id, group)) in missing {
        let name = group.first().map_or("", |network| network.name);
        let prefix = group.iter().find_map(|network| network.prefix);
        let subnet = group.iter().find_map(|network| network.subnet);
        let mut params = BTreeMap::from([
            ("vid".to_owned(), vid.to_string()),
            ("name".to_owned(), name.to_owned()),
        ]);
        if let Some(subnet) = subnet {
            params.insert("cidr".to_owned(), subnet.to_string());
        }
        out.push(Candidate {
            kind: IntentProposalKind::VlanDiscovered,
            rule: rule::VLAN_DISCOVERED,
            key: format!("vlan_discovered/{}/{vid}", site_text(*site)),
            subject: ProposalSubject {
                cidr: subnet,
                vrf: prefix.map(|prefix| prefix.vrf),
                prefix: prefix.map(|prefix| prefix.id),
                name: Some(name.to_owned()),
                objects: prefix
                    .map(|prefix| vec![ObjectRef::from(prefix.id)])
                    .unwrap_or_default(),
                ..ProposalSubject::default()
            },
            severity: ProposalSeverity::Info,
            summary: format!(
                "The network controller carries VLAN {vid} ({name}), which IPAM does not know; create the VLAN"
            ),
            params,
            evidence: network_evidence(group),
            commands: vec![new_vlan(*id, *site, *vid, name)],
            shape: vec![format!("vlan:{}/{vid}/{name}", site_text(*site))],
        });
    }
    out
}

/// The tagged networks by the prefix that equals their subnet.
fn by_prefix<'n, 's>(
    networks: &'n [TaggedNetwork<'s>],
) -> BTreeMap<PrefixId, Vec<&'n TaggedNetwork<'s>>> {
    let mut out: BTreeMap<PrefixId, Vec<&TaggedNetwork<'_>>> = BTreeMap::new();
    for network in networks {
        if let Some(prefix) = network.prefix {
            out.entry(prefix.id).or_default().push(network);
        }
    }
    out
}

/// One link proposal per prefix that equals the subnet of tagged networks with one VLAN id
/// and is not linked to a VLAN with that id.
fn link_candidates(
    snapshot: &Snapshot,
    networks: &[TaggedNetwork<'_>],
    missing: &MissingVlans<'_, '_>,
) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    for (prefix_id, group) in by_prefix(networks) {
        let vids: Vec<u16> = group
            .iter()
            .map(|network| network.vid)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let (Some(prefix), [vid]) = (intent.prefixes.get(&prefix_id), vids.as_slice()) else {
            continue;
        };
        let vid = *vid;
        let current = prefix.vlan.and_then(|id| intent.vlans.get(&id));
        if current.is_some_and(|vlan| vlan.vid == vid) {
            continue;
        }
        let name = group.first().map_or("", |network| network.name);
        let site = prefix.site;
        let mut commands = Vec::new();
        let mut objects = vec![ObjectRef::from(prefix.id)];
        let target = if let Some(vlan) = intent.vlan_at(site, vid) {
            objects.push(ObjectRef::from(vlan.id));
            vlan.id
        } else {
            let id = missing
                .get(&(site, vid))
                .map_or_else(VlanId::generate, |(id, _)| *id);
            commands.push(new_vlan(id, site, vid, name));
            id
        };
        commands.push(IpamCommand::UpdatePrefix(UpdatePrefix {
            id: prefix.id,
            expected: None,
            patch: PrefixPatch {
                vlan: Some(Some(target)),
                ..PrefixPatch::default()
            },
        }));
        let mut params = BTreeMap::from([
            ("cidr".to_owned(), prefix.cidr.to_string()),
            ("vid".to_owned(), vid.to_string()),
            ("name".to_owned(), name.to_owned()),
        ]);
        let (rule, severity, summary) = match current {
            None => (
                rule::PREFIX_VLAN_UNSET,
                ProposalSeverity::Info,
                format!(
                    "The network controller carries {} on VLAN {vid} ({name}); link the prefix to that VLAN",
                    prefix.cidr
                ),
            ),
            Some(other) => {
                params.insert("current".to_owned(), other.vid.to_string());
                objects.push(ObjectRef::from(other.id));
                (
                    rule::PREFIX_VLAN_DIFFERS,
                    ProposalSeverity::Warning,
                    format!(
                        "The network controller carries {} on VLAN {vid} ({name}), but the prefix is linked to VLAN {}; link it to VLAN {vid}",
                        prefix.cidr, other.vid
                    ),
                )
            }
        };
        let creates = commands.len() > 1;
        out.push(Candidate {
            kind: IntentProposalKind::PrefixVlanMismatch,
            rule,
            key: format!("prefix_vlan_mismatch/{}", prefix.id),
            subject: ProposalSubject {
                cidr: Some(prefix.cidr),
                vrf: Some(prefix.vrf),
                prefix: Some(prefix.id),
                name: Some(name.to_owned()),
                objects,
                ..ProposalSubject::default()
            },
            severity,
            summary,
            params,
            evidence: network_evidence(&group),
            commands,
            shape: vec![if creates {
                format!(
                    "prefix_vlan:{}/new:{}/{vid}/{name}",
                    prefix.id,
                    site_text(site)
                )
            } else {
                format!("prefix_vlan:{}/{target}", prefix.id)
            }],
        });
    }
    out
}

// ----- orphaned intent --------------------------------------------------------------

/// Active addresses of intent that sources saw before but not for the orphan age. When
/// probes report scopes, only addresses a probe covers can be orphaned: one outside every
/// scope is not scanned, so not seeing it says nothing.
fn orphans(
    snapshot: &Snapshot,
    sightings: &BTreeMap<ObjectRef, IntentSighting>,
    config: RuleConfig,
) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut out = Vec::new();
    for address in intent.addresses.values() {
        if address.status != Status::Active {
            continue;
        }
        let host = intent.host_of_address(address);
        if host.is_some_and(|host| host.lock || untouchable(host)) {
            continue;
        }
        let Some(sighting) = sightings.get(&ObjectRef::from(address.id)) else {
            continue;
        };
        // Unseen outside every probe scope means "not scanned", not "gone".
        if !snapshot.scanned(address.vrf, address.ip) {
            continue;
        }
        if snapshot.now.saturating_since(sighting.at) < config.orphan_after {
            continue;
        }
        let mut objects = vec![ObjectRef::from(address.id)];
        if let Some(host) = host {
            objects.push(ObjectRef::from(host.id));
        }
        let mut params = BTreeMap::from([
            ("ip".to_owned(), address.ip.to_string()),
            ("last_seen".to_owned(), sighting.at.to_rfc3339()),
            ("source".to_owned(), sighting.source.clone()),
        ]);
        let label = match host {
            Some(host) => {
                params.insert("host".to_owned(), host.name.to_string());
                format!("{} ({})", address.ip, host.name)
            }
            None => address.ip.to_string(),
        };
        out.push(Candidate {
            kind: IntentProposalKind::OrphanedIntent,
            rule: rule::ORPHANED_ADDRESS,
            key: format!("orphaned_intent/address:{}", address.id),
            subject: ProposalSubject {
                mac: None,
                ip: Some(address.ip),
                cidr: None,
                vrf: Some(address.vrf),
                prefix: Some(address.prefix),
                name: host.map(|host| host.name.to_string()),
                objects,
            },
            severity: ProposalSeverity::Info,
            summary: format!(
                "{label} has not been seen since {}; deprecate the address",
                sighting.at.to_rfc3339()
            ),
            params,
            evidence: Vec::new(),
            commands: vec![IpamCommand::UpdateAddress(UpdateAddress {
                id: address.id,
                expected: None,
                patch: AddressPatch {
                    status: Some(Status::Deprecated),
                    ..AddressPatch::default()
                },
            })],
            shape: vec![
                format!("deprecate:{}", address.id),
                format!("sighting:{}", sighting.observation),
            ],
        });
    }
    out
}

// ----- DNS ------------------------------------------------------------------------------

fn address_objects(snapshot: &Snapshot, addresses: &[AddressId]) -> Vec<ObjectRef> {
    let mut objects: Vec<ObjectRef> = addresses.iter().map(|id| ObjectRef::from(*id)).collect();
    for id in addresses {
        if let Some(host) = snapshot
            .intent
            .addresses
            .get(id)
            .and_then(|address| snapshot.intent.host_of_address(address))
        {
            objects.push(ObjectRef::from(host.id));
        }
    }
    objects.sort();
    objects.dedup();
    objects
}

fn first_address<'a>(snapshot: &'a Snapshot, addresses: &[AddressId]) -> Option<&'a Address> {
    addresses
        .iter()
        .find_map(|id| snapshot.intent.addresses.get(id))
}

fn origin_text(origin: tenko_core::dns::Origin) -> &'static str {
    tenko_dns::zone::records::origin_name(origin)
}

/// The proposals of the DNS planner's findings (see the module documentation).
#[allow(clippy::too_many_lines, reason = "one arm per finding")]
fn dns(snapshot: &Snapshot, findings: &[DnsFinding]) -> Vec<Candidate> {
    findings
        .iter()
        .map(|finding| match finding {
            DnsFinding::Held {
                zone,
                name,
                rtype,
                held_type,
                origin,
                wanted,
                addresses,
            } => {
                let wanted: Vec<String> = wanted
                    .iter()
                    .map(|data| record_text(name, *rtype, data))
                    .collect();
                let address = first_address(snapshot, addresses);
                Candidate {
                    kind: IntentProposalKind::Conflict,
                    rule: rule::DNS_RECORD_HELD,
                    key: format!("conflict/dns:{zone}/{name}/{rtype}"),
                    subject: ProposalSubject {
                        mac: None,
                        ip: address.map(|a| a.ip),
                        cidr: None,
                        vrf: address.map(|a| a.vrf),
                        prefix: address.map(|a| a.prefix),
                        name: Some(name.to_string()),
                        objects: address_objects(snapshot, addresses),
                    },
                    severity: ProposalSeverity::Warning,
                    summary: format!(
                        "{name} {held_type} in {zone} belongs to the origin {}, so IPAM cannot write {}; delete it to give the name back to IPAM, or change the DNS name of the address",
                        origin_text(*origin),
                        join(&wanted)
                    ),
                    params: BTreeMap::from([
                        ("zone".to_owned(), zone.to_string()),
                        ("name".to_owned(), name.to_string()),
                        ("type".to_owned(), rtype.to_string()),
                        ("held_type".to_owned(), held_type.to_string()),
                        ("origin".to_owned(), origin_text(*origin).to_owned()),
                        ("wanted".to_owned(), join(&wanted)),
                    ]),
                    evidence: Vec::new(),
                    commands: Vec::new(),
                    shape: vec![
                        format!("held:{zone}:{name}:{held_type}:{}", origin_text(*origin)),
                        format!("wanted:{}", join(&wanted)),
                    ],
                }
            }
            DnsFinding::NoZone { names } => {
                let listed: Vec<String> = names
                    .keys()
                    .take(LISTED_NAMES)
                    .map(ToString::to_string)
                    .collect();
                let more = names.len().saturating_sub(LISTED_NAMES);
                let addresses: Vec<AddressId> = names.values().flatten().copied().collect();
                let mut text = join(&listed);
                if more > 0 {
                    let _ = write!(text, " and {more} more");
                }
                Candidate {
                    kind: IntentProposalKind::OrphanedIntent,
                    rule: rule::DNS_NO_ZONE,
                    key: "orphaned_intent/dns_no_zone".to_owned(),
                    subject: ProposalSubject {
                        objects: address_objects(snapshot, &addresses),
                        ..ProposalSubject::default()
                    },
                    severity: ProposalSeverity::Info,
                    summary: format!(
                        "{} have no zone in Tenko: {text}; IPAM leaves them to the DNS servers that hold them",
                        plural(names.len(), "DNS name", "DNS names")
                    ),
                    params: BTreeMap::from([
                        ("count".to_owned(), names.len().to_string()),
                        ("names".to_owned(), text),
                    ]),
                    evidence: Vec::new(),
                    commands: Vec::new(),
                    shape: names.keys().map(|name| format!("name:{name}")).collect(),
                }
            }
            DnsFinding::Orphaned {
                zone,
                name,
                rtype,
                records,
            } => {
                let texts: Vec<String> = records
                    .iter()
                    .map(|data| record_text(name, *rtype, data))
                    .collect();
                Candidate {
                    kind: IntentProposalKind::OrphanedIntent,
                    rule: rule::DNS_ORPHANED_RECORD,
                    key: format!("orphaned_intent/dns_record:{zone}/{name}/{rtype}"),
                    subject: ProposalSubject {
                        name: Some(name.to_string()),
                        ..ProposalSubject::default()
                    },
                    severity: ProposalSeverity::Info,
                    summary: format!(
                        "{} in {zone} came from IPAM and no address of intent has it any more; delete it in the zone",
                        join(&texts)
                    ),
                    params: BTreeMap::from([
                        ("zone".to_owned(), zone.to_string()),
                        ("name".to_owned(), name.to_string()),
                        ("type".to_owned(), rtype.to_string()),
                        ("records".to_owned(), join(&texts)),
                    ]),
                    evidence: Vec::new(),
                    commands: Vec::new(),
                    shape: texts,
                }
            }
            DnsFinding::Delegation {
                prefix,
                cidr,
                zone,
                parent,
                lines,
            } => Candidate {
                kind: IntentProposalKind::OrphanedIntent,
                rule: rule::DNS_DELEGATION,
                key: format!("orphaned_intent/dns_delegation:{zone}"),
                subject: ProposalSubject {
                    cidr: Some(*cidr),
                    prefix: Some(*prefix),
                    objects: vec![ObjectRef::from(*prefix)],
                    ..ProposalSubject::default()
                },
                severity: ProposalSeverity::Info,
                summary: format!(
                    "Tenko serves {zone} for {cidr} but not its parent {parent}; add these lines to {parent} where it is served: {}",
                    lines.join(" | ")
                ),
                params: BTreeMap::from([
                    ("zone".to_owned(), zone.to_string()),
                    ("parent".to_owned(), parent.to_string()),
                    ("cidr".to_owned(), cidr.to_string()),
                    ("lines".to_owned(), lines.join("\n")),
                ]),
                evidence: Vec::new(),
                commands: Vec::new(),
                shape: lines.clone(),
            },
            DnsFinding::ReverseOrphaned { zone, name, prefix } => Candidate {
                kind: IntentProposalKind::OrphanedIntent,
                rule: rule::DNS_REVERSE_ORPHANED,
                key: format!("orphaned_intent/dns_reverse_zone:{zone}"),
                subject: ProposalSubject {
                    name: Some(name.to_string()),
                    prefix: Some(*prefix),
                    objects: vec![ObjectRef::from(*zone)],
                    ..ProposalSubject::default()
                },
                severity: ProposalSeverity::Info,
                summary: format!(
                    "The reverse zone {name} belongs to a prefix that is gone or whose reverse setting is off; IPAM no longer keeps it, delete it when it is not needed"
                ),
                params: BTreeMap::from([("zone".to_owned(), name.to_string())]),
                evidence: Vec::new(),
                commands: Vec::new(),
                shape: vec![format!("zone:{zone}:{prefix}")],
            },
            DnsFinding::NoNameServers {
                prefix,
                cidr,
                zones,
            } => {
                let zones: Vec<String> = zones.iter().map(ToString::to_string).collect();
                Candidate {
                    kind: IntentProposalKind::OrphanedIntent,
                    rule: rule::DNS_REVERSE_NO_SERVERS,
                    key: format!("orphaned_intent/dns_reverse_no_servers:{prefix}"),
                    subject: ProposalSubject {
                        cidr: Some(*cidr),
                        prefix: Some(*prefix),
                        objects: vec![ObjectRef::from(*prefix)],
                        ..ProposalSubject::default()
                    },
                    severity: ProposalSeverity::Info,
                    summary: format!(
                        "The reverse zones of {cidr} ({}) cannot be created: no zone in Tenko has name servers to copy; create a forward zone first",
                        join(&zones)
                    ),
                    params: BTreeMap::from([
                        ("cidr".to_owned(), cidr.to_string()),
                        ("zones".to_owned(), join(&zones)),
                    ]),
                    evidence: Vec::new(),
                    commands: Vec::new(),
                    shape: zones,
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitized() {
        assert_eq!(
            sanitize("Living Room TV").as_deref(),
            Some("living-room-tv")
        );
        assert_eq!(
            sanitize("  web01.example.test ").as_deref(),
            Some("web01.example.test")
        );
        assert_eq!(sanitize("--").as_deref(), None);
        assert_eq!(sanitize("a--b__c").as_deref(), Some("a-b__c"));
        assert_eq!(
            mac_name("00:00:5e:00:53:01".parse().expect("mac")),
            "host-00005e005301"
        );
        assert_eq!(
            ip_name("2001:db8::10".parse().expect("ip")),
            "host-2001-db8--10"
        );
        assert!(HostName::new(&ip_name("2001:db8::10".parse().expect("ip"))).is_ok());
    }
}
