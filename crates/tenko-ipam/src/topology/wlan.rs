//! The SSID view and the two WLAN rules (IPAM-20, CONN-05; `docs/reconciliation.md`
//! section 4.12).
//!
//! The view is a tree: SSID, then VLAN, then the clients; the access point and the band
//! are attributes of a client, never levels of the tree. The clients come from the network
//! controllers only (their topology read, CONN-05), and nothing is ever written to a
//! controller (CONN-08, CONN-09).
//!
//! Two rules read the clients of every tracked SSID:
//!
//! | Rule | Raises a finding to review when |
//! |---|---|
//! | `ipam.topology.wlan_class` | a host classed as IoT (the tag `class:iot`) is on a WLAN whose VLAN has no IoT role (the tag `role:iot` on the VLAN or on one of its networks) |
//! | `ipam.topology.wlan_prefix` | a host's address is outside every network of the VLAN its SSID carries |
//!
//! The classification reads only the host's class and the network's role (UI-R8): a client
//! that is no host of intent, an `unmanaged` or decommissioned host, and a VLAN without a VLAN
//! object or networks are not judged. A per-SSID policy decides whether the rules read an
//! SSID at all (ignore by default for a guest SSID, track otherwise), and "Keep on this WLAN"
//! stores an exception per host and SSID that the rules skip from then on
//! ([`super::stored`]). Each finding offers the move of the host (the move flow of ADR 0027)
//! as its default action, and "Keep on this WLAN" beside it.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    sync::Arc,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    ConnectorId, HostId, MacAddr, ObjectRef, PrefixId, Revision, Timestamp, VlanId,
    ipam::{AssignmentMode, Host, Prefix, PrefixRole, Vlan},
    observe::RadioBand,
};
use utoipa::ToSchema;

use super::{
    build::Intent,
    model::TopologyGraph,
    stored::{Stored, WlanPolicy},
};
use crate::{
    findings::{
        Finding, FindingAction, FindingArea, FindingEvidence, FindingKind, FindingLevel,
        FindingSource, FindingSubject, SubjectKind, map::finding_id,
    },
    net::contains_ip,
    vlan::controllers::ControllerTopology,
};

/// The tag that classes a host as an IoT device.
pub const HOST_CLASS_IOT: &str = "class:iot";
/// The tag that gives a VLAN, or a network of it, the IoT role.
pub const NETWORK_ROLE_IOT: &str = "role:iot";

/// Codes of the two rules, also the codes of their findings.
pub mod rule {
    /// An IoT-classed host on a WLAN whose VLAN has no IoT role.
    pub const WLAN_CLASS: &str = "ipam.topology.wlan_class";
    /// A host's address outside the networks of its SSID's VLAN.
    pub const WLAN_PREFIX: &str = "ipam.topology.wlan_prefix";
}

/// The first 16 bytes of the SHA-256 of `text`, in hexadecimal: the stable part of the
/// identifier of a topology finding.
pub(crate) fn digest(text: &str) -> String {
    use std::fmt::Write as _;
    Sha256::digest(text.as_bytes()).iter().take(16).fold(
        String::with_capacity(32),
        |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

/// A network of a VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsidPrefix {
    /// The prefix.
    pub id: PrefixId,
    /// The network.
    #[schema(value_type = String)]
    pub cidr: IpNet,
}

/// A client of an SSID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsidClient {
    /// The client.
    pub mac: MacAddr,
    /// Its address, as the controller reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// The best name: the host of intent, else the controller's name, else the MAC address.
    pub label: String,
    /// The node of the map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The host of intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// The vendor of the MAC address, when a source names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Whether the host is classed as IoT.
    #[serde(default)]
    pub iot: bool,
    /// The access point, by its name on the controller.
    pub access_point: String,
    /// The node of the access point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_point_node: Option<String>,
    /// The radio band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<RadioBand>,
    /// The kinds of the findings about it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingKind>,
    /// Whether a person kept the host on this WLAN.
    #[serde(default)]
    pub kept: bool,
}

/// The clients of an SSID in one VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsidVlan {
    /// The VLAN id; absent for untagged clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vid: Option<u16>,
    /// The VLAN object of intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether it has the IoT role.
    #[serde(default)]
    pub iot: bool,
    /// Its networks.
    #[serde(default)]
    pub prefixes: Vec<SsidPrefix>,
    /// The clients, by label.
    pub clients: Vec<SsidClient>,
}

/// One SSID with its VLANs and clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsidEntry {
    /// The SSID.
    pub ssid: String,
    /// The controllers that report it.
    pub connectors: Vec<ConnectorId>,
    /// The VLAN the SSID carries; absent when untagged or unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vid: Option<u16>,
    /// Whether a controller marks it as a guest network.
    #[serde(default)]
    pub guest: bool,
    /// Whether it is broadcast.
    #[serde(default)]
    pub enabled: bool,
    /// The access points that broadcast it, by name.
    #[serde(default)]
    pub access_points: Vec<String>,
    /// The policy of the WLAN rules.
    pub policy: WlanPolicy,
    /// Whether a person set the policy (else it is the default).
    #[serde(default)]
    pub policy_set: bool,
    /// The clients.
    pub clients: usize,
    /// The findings about its clients.
    pub findings: usize,
    /// The clients by VLAN, the SSID's own VLAN first.
    pub vlans: Vec<SsidVlan>,
}

/// `GET /topology/ssids`: every SSID of the network controllers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SsidView {
    /// The SSIDs, by name.
    pub ssids: Vec<SsidEntry>,
    /// The store revision of the graph.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The view and the findings of the rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// The SSIDs.
    pub ssids: Vec<SsidEntry>,
    /// The findings of the two rules.
    pub findings: Vec<Finding>,
}

fn tagged(tags: &BTreeSet<tenko_core::ipam::Tag>, tag: &str) -> bool {
    tags.iter()
        .any(|t| t.as_str().trim().eq_ignore_ascii_case(tag))
}

/// What the rules read of intent, by the keys they look up.
struct Book<'a> {
    hosts: HashMap<HostId, &'a Host>,
    host_of_mac: HashMap<MacAddr, HostId>,
    vlans: Vec<&'a Vlan>,
    networks: Vec<&'a Prefix>,
}

impl<'a> Book<'a> {
    fn new(intent: &'a Intent) -> Self {
        let hosts: HashMap<HostId, &Host> = intent
            .hosts
            .iter()
            .filter(|host| !host.meta.is_deleted())
            .map(|host| (host.id, host))
            .collect();
        let host_of_mac = intent
            .interfaces
            .iter()
            .filter(|interface| !interface.meta.is_deleted() && hosts.contains_key(&interface.host))
            .filter_map(|interface| Some((interface.mac?, interface.host)))
            .collect();
        let mut networks: Vec<&Prefix> = intent
            .prefixes
            .iter()
            .filter(|prefix| !prefix.meta.is_deleted() && prefix.role == PrefixRole::Network)
            .collect();
        networks.sort_by_key(|prefix| (std::cmp::Reverse(prefix.cidr.prefix_len()), prefix.id));
        Self {
            hosts,
            host_of_mac,
            vlans: intent
                .vlans
                .iter()
                .filter(|vlan| !vlan.meta.is_deleted())
                .collect(),
            networks,
        }
    }

    /// The VLAN object of `vid` for a host at `site`: the site's, else the global one, else
    /// the only one.
    fn vlan(&self, vid: u16, site: Option<tenko_core::SiteId>) -> Option<&'a Vlan> {
        let all: Vec<&Vlan> = self
            .vlans
            .iter()
            .copied()
            .filter(|v| v.vid == vid)
            .collect();
        site.and_then(|site| all.iter().copied().find(|v| v.site == Some(site)))
            .or_else(|| all.iter().copied().find(|v| v.site.is_none()))
            .or_else(|| (all.len() == 1).then(|| all[0]))
    }

    fn prefixes_of(&self, vlan: &Vlan) -> Vec<&'a Prefix> {
        self.networks
            .iter()
            .copied()
            .filter(|prefix| prefix.vlan == Some(vlan.id))
            .collect()
    }

    fn iot(&self, vlan: &Vlan) -> bool {
        tagged(&vlan.meta.tags, NETWORK_ROLE_IOT)
            || self
                .prefixes_of(vlan)
                .iter()
                .any(|prefix| tagged(&prefix.meta.tags, NETWORK_ROLE_IOT))
    }

    /// The most specific network of intent that holds `ip`.
    fn network_of(&self, ip: IpAddr) -> Option<&'a Prefix> {
        self.networks
            .iter()
            .copied()
            .find(|prefix| contains_ip(&prefix.cidr, ip))
    }
}

/// The facts of one client the rules judge.
struct Judged<'a> {
    host: &'a Host,
    ssid: &'a str,
    vid: Option<u16>,
    vlan: Option<&'a Vlan>,
    iot_vlan: bool,
    prefixes: Vec<&'a Prefix>,
    ip: Option<IpAddr>,
    mac: MacAddr,
    access_point: &'a str,
    band: Option<RadioBand>,
}

fn rule_finding(
    book: &Book<'_>,
    judged: &Judged<'_>,
    kind: FindingKind,
    now: Timestamp,
) -> Finding {
    let host = judged.host;
    let name = host.name.as_str().to_owned();
    let code = if kind == FindingKind::WlanClass {
        rule::WLAN_CLASS
    } else {
        rule::WLAN_PREFIX
    };
    let cidrs = judged
        .prefixes
        .iter()
        .map(|prefix| prefix.cidr.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let vlan_text = judged
        .vid
        .map_or_else(|| "untagged".to_owned(), |vid| format!("VLAN {vid}"));
    let summary = match kind {
        FindingKind::WlanClass => format!(
            "{name} is classed as IoT and is on the WLAN {} ({vlan_text}), which is not an IoT network",
            judged.ssid
        ),
        _ => format!(
            "{name} has the address {} on the WLAN {}, outside {cidrs} of {vlan_text}",
            judged.ip.map(|ip| ip.to_string()).unwrap_or_default(),
            judged.ssid
        ),
    };
    let mut params = BTreeMap::from([
        ("host".to_owned(), name.clone()),
        ("ssid".to_owned(), judged.ssid.to_owned()),
        ("mac".to_owned(), judged.mac.to_string()),
        ("class".to_owned(), "iot".to_owned()),
        (
            "role".to_owned(),
            if judged.iot_vlan { "iot" } else { "other" }.to_owned(),
        ),
        ("access_point".to_owned(), judged.access_point.to_owned()),
    ]);
    if kind == FindingKind::WlanPrefix && !tagged(&host.meta.tags, HOST_CLASS_IOT) {
        params.remove("class");
    }
    if let Some(vid) = judged.vid {
        params.insert("vlan".to_owned(), vid.to_string());
    }
    if let Some(vlan) = judged.vlan {
        params.insert("vlan_name".to_owned(), vlan.name.clone());
    }
    if !cidrs.is_empty() {
        params.insert("prefix".to_owned(), cidrs);
    }
    if let Some(ip) = judged.ip {
        params.insert("ip".to_owned(), ip.to_string());
    }
    if let Some(band) = judged.band {
        params.insert("band".to_owned(), band.as_str().to_owned());
    }
    let network = judged.ip.and_then(|ip| book.network_of(ip));
    let mut subject = FindingSubject::new(SubjectKind::Host, name);
    subject.host = Some(host.id);
    subject.mac = Some(judged.mac);
    subject.ip = judged.ip;
    subject.prefix = network.map(|prefix| prefix.id);
    subject.vrf = network.map(|prefix| prefix.vrf);
    subject.objects = vec![ObjectRef::from(host.id)];
    Finding {
        id: finding_id(
            FindingSource::Topology,
            &format!(
                "wlan:{}",
                digest(&format!("{code}|{}|{}", host.id, judged.ssid))
            ),
        ),
        kind,
        severity: FindingLevel::Review,
        area: FindingArea::Topology,
        subject,
        summary,
        code: code.to_owned(),
        params,
        evidence: FindingEvidence {
            id: format!("{}/{}", host.id, judged.ssid),
            path: "/topology/ssids".to_owned(),
        },
        action: FindingAction::MoveHost,
        since: now,
        source: FindingSource::Topology,
    }
}

/// The rules for one client: the kinds of the findings it raises (none for a kept pair).
fn judge(judged: &Judged<'_>) -> Vec<FindingKind> {
    let mut kinds = Vec::new();
    if tagged(&judged.host.meta.tags, HOST_CLASS_IOT) && !judged.iot_vlan {
        kinds.push(FindingKind::WlanClass);
    }
    if let Some(ip) = judged.ip {
        let same_family: Vec<&&Prefix> = judged
            .prefixes
            .iter()
            .filter(|prefix| prefix.cidr.addr().is_ipv4() == ip.is_ipv4())
            .collect();
        if !same_family.is_empty()
            && !same_family
                .iter()
                .any(|prefix| contains_ip(&prefix.cidr, ip))
        {
            kinds.push(FindingKind::WlanPrefix);
        }
    }
    kinds
}

/// The VLAN level of the tree: the VLAN object of `vid`, its role and networks, and its
/// clients by label.
fn vlan_entry(book: &Book<'_>, vid: Option<u16>, mut clients: Vec<SsidClient>) -> SsidVlan {
    clients.sort_by(|a, b| (&a.label, a.mac).cmp(&(&b.label, b.mac)));
    let vlan = vid.and_then(|vid| book.vlan(vid, None));
    SsidVlan {
        vid,
        vlan: vlan.map(|vlan| vlan.id),
        name: vlan.map(|vlan| vlan.name.clone()),
        iot: vlan.is_some_and(|vlan| book.iot(vlan)),
        prefixes: vlan
            .map(|vlan| {
                book.prefixes_of(vlan)
                    .into_iter()
                    .map(|prefix| SsidPrefix {
                        id: prefix.id,
                        cidr: prefix.cidr,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        clients,
    }
}

/// The findings the two rules raise for one client of a tracked SSID.
fn judge_client(
    book: &Book<'_>,
    host: &Host,
    client: &crate::vlan::controllers::WirelessClient,
    vid: Option<u16>,
    access_point: &str,
    now: Timestamp,
) -> Vec<Finding> {
    let vlan = vid.and_then(|vid| book.vlan(vid, host.site));
    let judged = Judged {
        host,
        ssid: &client.ssid,
        vid,
        vlan,
        iot_vlan: vlan.is_some_and(|vlan| book.iot(vlan)),
        prefixes: vlan.map(|vlan| book.prefixes_of(vlan)).unwrap_or_default(),
        ip: client.ip,
        mac: client.mac,
        access_point,
        band: client.band,
    };
    judge(&judged)
        .into_iter()
        .map(|kind| rule_finding(book, &judged, kind, now))
        .collect()
}

#[derive(Default)]
struct SsidAcc {
    connectors: BTreeSet<ConnectorId>,
    vid: Option<u16>,
    guest: bool,
    enabled: bool,
    access_points: BTreeSet<String>,
    clients: BTreeMap<Option<u16>, Vec<SsidClient>>,
}

/// Evaluates the view and the rules over the controllers' tables, the intent and the stored
/// decisions; `graph` gives the nodes of the map.
pub fn evaluate(
    controllers: &[Arc<ControllerTopology>],
    intent: &Intent,
    stored: &Stored,
    graph: &TopologyGraph,
    now: Timestamp,
) -> Evaluation {
    let book = Book::new(intent);
    let node_of_mac: HashMap<MacAddr, &super::model::TopologyNode> = graph
        .nodes
        .iter()
        .flat_map(|node| node.macs.iter().map(move |mac| (*mac, node)))
        .collect();
    let mut ssids: BTreeMap<String, SsidAcc> = BTreeMap::new();
    let mut findings = Vec::new();
    for table in controllers {
        let devices: HashMap<&str, &crate::vlan::controllers::ControllerDevice> = table
            .devices
            .iter()
            .map(|device| (device.id.as_str(), device))
            .collect();
        let ap_name = |id: &str| {
            devices
                .get(id)
                .map_or_else(|| id.to_owned(), |device| device.name.clone())
        };
        let ap_node = |id: &str| {
            devices
                .get(id)
                .and_then(|device| device.mac)
                .and_then(|mac| node_of_mac.get(&mac))
                .map(|node| node.id.clone())
        };
        for wlan in &table.wlans {
            let acc = ssids.entry(wlan.ssid.clone()).or_default();
            acc.connectors.insert(table.connector);
            acc.vid = acc.vid.or(wlan.vlan);
            acc.guest |= wlan.guest;
            acc.enabled |= wlan.enabled;
            acc.access_points
                .extend(wlan.access_points.iter().map(|ap| ap_name(ap)));
        }
        let wlan_vid: HashMap<&str, Option<u16>> = table
            .wlans
            .iter()
            .map(|wlan| (wlan.ssid.as_str(), wlan.vlan))
            .collect();
        for client in &table.clients {
            let vid = client
                .vlan
                .or_else(|| wlan_vid.get(client.ssid.as_str()).copied().flatten());
            let host = book
                .host_of_mac
                .get(&client.mac)
                .and_then(|id| book.hosts.get(id))
                .copied();
            let node = node_of_mac.get(&client.mac);
            let acc = ssids.entry(client.ssid.clone()).or_default();
            acc.connectors.insert(table.connector);
            let (policy, _) = stored.policy(&client.ssid, acc.guest);
            let mut row = SsidClient {
                mac: client.mac,
                ip: client.ip,
                label: host
                    .map(|host| host.name.as_str().to_owned())
                    .or_else(|| client.name.clone())
                    .or_else(|| node.map(|node| node.label.clone()))
                    .unwrap_or_else(|| client.mac.to_string()),
                node: node.map(|node| node.id.clone()),
                host: host.map(|host| host.id),
                vendor: node.and_then(|node| node.vendor.clone()),
                iot: host.is_some_and(|host| tagged(&host.meta.tags, HOST_CLASS_IOT)),
                access_point: ap_name(&client.access_point),
                access_point_node: ap_node(&client.access_point),
                band: client.band,
                findings: Vec::new(),
                kept: host.is_some_and(|host| stored.kept(host.id, &client.ssid)),
            };
            let judged_host = host
                .filter(|host| host.mode != AssignmentMode::Unmanaged && !host.is_decommissioned());
            if let Some(host) = judged_host
                && policy == WlanPolicy::Track
                && !row.kept
            {
                let raised = judge_client(&book, host, client, vid, &row.access_point, now);
                row.findings = raised.iter().map(|finding| finding.kind).collect();
                findings.extend(raised);
            }
            acc.clients.entry(vid).or_default().push(row);
        }
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings.dedup_by(|a, b| a.id == b.id);
    Evaluation {
        ssids: ssids
            .into_iter()
            .map(|(ssid, acc)| entry_of(&book, stored, ssid, acc))
            .collect(),
        findings,
    }
}

/// The SSID level of the tree, from what the controllers report of it.
fn entry_of(book: &Book<'_>, stored: &Stored, ssid: String, acc: SsidAcc) -> SsidEntry {
    let (policy, policy_set) = stored.policy(&ssid, acc.guest);
    let mut vlans: Vec<SsidVlan> = acc
        .clients
        .into_iter()
        .map(|(vid, clients)| vlan_entry(book, vid, clients))
        .collect();
    // The SSID's own VLAN first, then by VLAN id.
    vlans.sort_by_key(|vlan| (vlan.vid != acc.vid, vlan.vid));
    if vlans.is_empty() {
        vlans.push(vlan_entry(book, acc.vid, Vec::new()));
    }
    let clients = vlans.iter().map(|vlan| vlan.clients.len()).sum();
    let findings = vlans
        .iter()
        .flat_map(|vlan| &vlan.clients)
        .map(|client| client.findings.len())
        .sum();
    SsidEntry {
        ssid,
        connectors: acc.connectors.into_iter().collect(),
        vid: acc.vid,
        guest: acc.guest,
        enabled: acc.enabled,
        access_points: acc.access_points.into_iter().collect(),
        policy,
        policy_set,
        clients,
        findings,
        vlans,
    }
}
