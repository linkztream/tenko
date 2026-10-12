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

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use ipnet::IpNet;
use tenko_core::{
    AddressId, HostId, InterfaceId, MacAddr, ObjectRef, PrefixId, TenantId, VrfId,
    ipam::{Address, AssignmentMode, Host, Status, Tag},
    net::HostName,
};

use super::snapshot::{Placement, Seen, Snapshot};
use crate::{
    command::{
        AddressInput, AddressPatch, HostInput, InterfaceInput, IpamCommand, PrefixInput,
        UpdateAddress,
    },
    net::{Family, contains_net},
    observe::model::IntentSighting,
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
}

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
) -> Vec<Candidate> {
    let mut names = NameBook::new(snapshot);
    let mut out = Vec::new();
    out.extend(discovered(snapshot, &mut names));
    out.extend(mismatches(snapshot));
    out.extend(conflicts(snapshot));
    out.extend(outside(snapshot));
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
