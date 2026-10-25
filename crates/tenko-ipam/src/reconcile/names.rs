//! The names of devices: placeholder names, the name authority and the operator's choice.
//!
//! Every source that names a device gives a **name candidate**: an inventory host's name, a
//! network controller's client name, a DHCP lease's name, a DNS record, a name a probe
//! found (mDNS, LLMNR, reverse DNS, SNMP). A candidate that is a **placeholder**
//! ([`tenko_core::observe::is_placeholder_name`], or marked so by its source) is no
//! candidate: it never names a host and never conflicts with a real name.
//!
//! Candidates are grouped by their first label without case (`postgresql` and
//! `postgresql.example.net` are one name). When the groups differ, the **name authority**
//! decides: an ordered list of kinds of sources ([`NameSource`]), per site or global, the
//! default being [`NameSource::DEFAULT_ORDER`]. The group whose best source ranks highest
//! wins; a tie goes to the newer sighting, then to the name. A host's **preference** (the
//! operator's "remember this for the host") puts its source first for that host.
//!
//! The rule of this module, `host_names`, proposes renaming a host of intent
//! ([`IntentProposalKind::HostName`], key `host_name/host:<id>`), never for a locked,
//! `unmanaged` or decommissioned host:
//!
//! | Rule | When |
//! |---|---|
//! | `ipam.reconcile.placeholder_name` | the host's name is a placeholder and a real name arrives |
//! | `ipam.reconcile.preferred_name` | the host prefers a source, and that source names it otherwise |
//! | `ipam.reconcile.name_conflict` | two or more real names, and the host's name is not the one the authority decides |
//!
//! After a decision on such a proposal ([`HostNameChoice`]), the same names no longer open
//! it again: only a name no source gave before does.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tenko_core::{
    ConnectorId, HostId, MacAddr, ObjectKind, ObjectRef, RequestCtx, Revision, SiteId, Timestamp,
    audit::{AuditAction, AuditDraft, FieldChange},
    ipam::{Host, Site, Stamp},
    net::HostName,
    observe::{ObservationSource, ProbeMethod},
    table::TableDef,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    rules::{Candidate, NameBook, sanitize},
    snapshot::{Seen, Snapshot},
};
use crate::{
    command::{HostPatch, IpamCommand, UpdateHost},
    error::{IpamError, IpamResult},
    observe::model::{observed_name, observed_placeholder},
    proposals::model::{
        IntentProposalKind, NameChoice, NameChoiceSource, ProposalEvidence, ProposalSeverity,
        ProposalSubject,
    },
    tables::{HOSTS, SITES},
};

/// Rule codes of the host name rule.
pub mod rule {
    /// The host's name is a placeholder and a real name arrived.
    pub const PLACEHOLDER_NAME: &str = "ipam.reconcile.placeholder_name";
    /// The host prefers a source, and that source names it otherwise.
    pub const PREFERRED_NAME: &str = "ipam.reconcile.preferred_name";
    /// Sources give two or more names and the host does not carry the one the name
    /// authority decides.
    pub const NAME_CONFLICT: &str = "ipam.reconcile.name_conflict";
}

/// Stable codes of the area.
pub mod codes {
    /// A name authority rule is invalid (422). Params: `field`.
    pub const AUTHORITY_INVALID: &str = "ipam.name_authority.invalid";
    /// The site of a name authority rule, or the host of a preference, does not exist
    /// (404). Params: `kind`, `id`.
    pub const NOT_FOUND: &str = "ipam.not_found";
}

/// Audit actions of the area.
pub mod actions {
    /// A name authority rule was set; records the old and the new order.
    pub const AUTHORITY_SET: &str = "ipam.name_authority.set";
    /// A name authority rule was removed; records the old order.
    pub const AUTHORITY_CLEAR: &str = "ipam.name_authority.clear";
    /// A host's preferred source was forgotten.
    pub const PREFERENCE_CLEAR: &str = "ipam.name_preference.clear";
}

/// A kind of source, as the name authority ranks them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// A Proxmox VE connector (the guest's name).
    Proxmox,
    /// A Home Assistant connector (the device's name).
    HomeAssistant,
    /// A Windows DNS/DHCP Server connector.
    Windows,
    /// A DNS record of a zone, or a reverse lookup of a probe.
    Dns,
    /// Multicast DNS, seen by a probe.
    Mdns,
    /// LLMNR, seen by a probe.
    Llmnr,
    /// A UniFi connector (the client's alias or the name it announced).
    Unifi,
    /// Any other probe method (SNMP `sysName` and the like).
    Scan,
    /// A DHCP lease (option 81 or 12), or DHCP snooping of a probe.
    Dhcp,
    /// Any other connector.
    Other,
}

impl NameSource {
    /// Every kind, in the order of the default rule followed by those it leaves out.
    pub const ALL: [NameSource; 10] = [
        NameSource::Proxmox,
        NameSource::HomeAssistant,
        NameSource::Windows,
        NameSource::Dns,
        NameSource::Mdns,
        NameSource::Llmnr,
        NameSource::Unifi,
        NameSource::Scan,
        NameSource::Dhcp,
        NameSource::Other,
    ];

    /// The order in force when no rule is stored. The kinds it leaves out (DHCP and other
    /// connectors) rank after it.
    pub const DEFAULT_ORDER: [NameSource; 8] = [
        NameSource::Proxmox,
        NameSource::HomeAssistant,
        NameSource::Windows,
        NameSource::Dns,
        NameSource::Mdns,
        NameSource::Llmnr,
        NameSource::Unifi,
        NameSource::Scan,
    ];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            NameSource::Proxmox => "proxmox",
            NameSource::HomeAssistant => "home_assistant",
            NameSource::Windows => "windows",
            NameSource::Dns => "dns",
            NameSource::Mdns => "mdns",
            NameSource::Llmnr => "llmnr",
            NameSource::Unifi => "unifi",
            NameSource::Scan => "scan",
            NameSource::Dhcp => "dhcp",
            NameSource::Other => "other",
        }
    }

    /// The English name in summaries.
    pub const fn label(self) -> &'static str {
        match self {
            NameSource::Proxmox => "Proxmox VE",
            NameSource::HomeAssistant => "Home Assistant",
            NameSource::Windows => "Windows",
            NameSource::Dns => "DNS",
            NameSource::Mdns => "mDNS",
            NameSource::Llmnr => "LLMNR",
            NameSource::Unifi => "UniFi",
            NameSource::Scan => "a scan",
            NameSource::Dhcp => "DHCP",
            NameSource::Other => "another connector",
        }
    }

    /// The kind of a connector by its plugin name.
    fn of_plugin(plugin: &str) -> Self {
        match plugin {
            "proxmox" => NameSource::Proxmox,
            "hass" => NameSource::HomeAssistant,
            "windows" => NameSource::Windows,
            "unifi" => NameSource::Unifi,
            _ => NameSource::Other,
        }
    }
}

/// A stored name authority rule: the global one (`site` empty) or one site's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoredAuthority {
    /// The site; `null` for the global rule.
    #[serde(default)]
    pub site: Option<SiteId>,
    /// The kinds of sources, the most trusted first. Kinds left out rank after the listed
    /// ones, in the order of [`NameSource::ALL`].
    pub order: Vec<NameSource>,
    /// Who set it and when.
    pub updated: Stamp,
    /// Store revision (filled when read).
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The operator's decision on the name of one host: the name it chose and the names on
/// offer then, so the same names do not open a proposal again, and whether the host
/// follows the chosen source from now on ("remember this for the host").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostNameChoice {
    /// The host.
    pub host: HostId,
    /// The name the host got.
    pub name: String,
    /// The names that were on offer.
    #[serde(default)]
    pub offered: Vec<String>,
    /// The kind of source of the chosen name.
    #[serde(default)]
    pub source: Option<NameSource>,
    /// Whether the host prefers that source from now on.
    #[serde(default)]
    pub prefer: bool,
    /// Who decided and when.
    pub decided: Stamp,
    /// Store revision (filled when read).
    #[serde(default)]
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The name authority rules by site (`None`: the global rule).
pub static NAME_AUTHORITY: TableDef<Option<SiteId>, StoredAuthority> =
    TableDef::new("ipam.name_authority");
/// The operator's name decisions by host.
pub static NAME_CHOICES: TableDef<HostId, HostNameChoice> = TableDef::new("ipam.name_choices");

/// What the reconciler reads of a connector instance (`connect.instances`, owned by the
/// connector host): its plugin, which tells the kind of source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ConnectorPlugin {
    #[serde(default)]
    plugin: String,
}

static CONNECTORS: TableDef<ConnectorId, ConnectorPlugin> = TableDef::new("connect.instances");

/// What decided a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecidedBy {
    /// The default order.
    Default,
    /// The global rule.
    Global,
    /// The rule of a site.
    Site(SiteId),
    /// The host's preferred source.
    Host,
}

impl DecidedBy {
    /// The text in a proposal's parameters: `default`, `global`, `site:<id>` or `host`.
    pub(crate) fn text(self) -> String {
        match self {
            DecidedBy::Default => "default".to_owned(),
            DecidedBy::Global => "global".to_owned(),
            DecidedBy::Site(site) => format!("site:{site}"),
            DecidedBy::Host => "host".to_owned(),
        }
    }

    fn english(self) -> String {
        match self {
            DecidedBy::Default => "the default name authority".to_owned(),
            DecidedBy::Global => "the global name authority".to_owned(),
            DecidedBy::Site(site) => format!("the name authority of site {site}"),
            DecidedBy::Host => "the host's preferred source".to_owned(),
        }
    }
}

/// The rules, preferences and connector kinds a run reads.
#[derive(Debug, Default)]
pub(crate) struct Authorities {
    pub global: Option<StoredAuthority>,
    pub sites: BTreeMap<SiteId, StoredAuthority>,
    pub choices: BTreeMap<HostId, HostNameChoice>,
    plugins: BTreeMap<ConnectorId, String>,
}

impl Authorities {
    pub(crate) fn load(view: &dyn ReadView) -> IpamResult<Self> {
        let mut out = Authorities::default();
        for (site, mut rule, revision) in
            view.scan_typed(&NAME_AUTHORITY, KeyRange::all(), usize::MAX, false)?
        {
            rule.revision = revision;
            match site {
                Some(site) => {
                    out.sites.insert(site, rule);
                }
                None => out.global = Some(rule),
            }
        }
        for (host, mut choice, revision) in
            view.scan_typed(&NAME_CHOICES, KeyRange::all(), usize::MAX, false)?
        {
            choice.revision = revision;
            out.choices.insert(host, choice);
        }
        for (id, connector, _) in
            view.scan_typed(&CONNECTORS, KeyRange::all(), usize::MAX, false)?
        {
            out.plugins.insert(id, connector.plugin);
        }
        Ok(out)
    }

    /// The order in force at `site` and what it comes from.
    pub(crate) fn order_at(&self, site: Option<SiteId>) -> (Vec<NameSource>, DecidedBy) {
        if let Some(site) = site
            && let Some(rule) = self.sites.get(&site)
        {
            return (full_order(&rule.order), DecidedBy::Site(site));
        }
        match &self.global {
            Some(rule) => (full_order(&rule.order), DecidedBy::Global),
            None => (full_order(&NameSource::DEFAULT_ORDER), DecidedBy::Default),
        }
    }

    /// The kind of a source.
    pub(crate) fn source_of(&self, source: &ObservationSource) -> NameSource {
        match source {
            ObservationSource::Inventory { connector }
            | ObservationSource::NetworkController { connector } => self
                .plugins
                .get(connector)
                .map_or(NameSource::Other, |plugin| NameSource::of_plugin(plugin)),
            ObservationSource::DnsRecord { .. } => NameSource::Dns,
            ObservationSource::DhcpLease { .. } => NameSource::Dhcp,
            ObservationSource::Probe { method, .. } => match method {
                ProbeMethod::ReverseDns => NameSource::Dns,
                ProbeMethod::Mdns => NameSource::Mdns,
                ProbeMethod::Llmnr => NameSource::Llmnr,
                ProbeMethod::DhcpSnoop => NameSource::Dhcp,
                _ => NameSource::Scan,
            },
        }
    }

    /// The preferred source of a host, if it has one.
    pub(crate) fn preference(&self, host: HostId) -> Option<NameSource> {
        self.choices
            .get(&host)
            .filter(|choice| choice.prefer)
            .and_then(|choice| choice.source)
    }
}

/// `order` with every kind it leaves out appended in the order of [`NameSource::ALL`].
pub fn full_order(order: &[NameSource]) -> Vec<NameSource> {
    let mut out: Vec<NameSource> = Vec::with_capacity(NameSource::ALL.len());
    for source in order.iter().chain(NameSource::ALL.iter()) {
        if !out.contains(source) {
            out.push(*source);
        }
    }
    out
}

/// The first label of a name, lowercase: what candidates are compared by.
pub(crate) fn label(name: &str) -> String {
    name.trim()
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// One source's real name for a device.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NameCandidate {
    /// The name as a host takes it.
    name: String,
    /// The name as the source gives it.
    given: String,
    source: NameSource,
    source_key: String,
    last_seen: Timestamp,
}

/// The candidates of one name, best source first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameGroup {
    pub label: String,
    /// The name of the best source.
    pub name: String,
    rank: usize,
    last_seen: Timestamp,
    sources: Vec<NameCandidate>,
}

impl NameGroup {
    /// The kind of the best source.
    pub(crate) fn source(&self) -> NameSource {
        self.sources
            .first()
            .map_or(NameSource::Other, |candidate| candidate.source)
    }
}

/// The names of a device, the decided one first, and what decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameDecision {
    pub groups: Vec<NameGroup>,
    pub decided_by: DecidedBy,
    /// The site whose rule is in force, if a site's rule is.
    pub rule_site: Option<SiteId>,
}

impl NameDecision {
    /// The decided name.
    pub(crate) fn winner(&self) -> &NameGroup {
        &self.groups[0]
    }

    /// The names of the losing groups.
    pub(crate) fn others(&self) -> Vec<&str> {
        self.groups
            .iter()
            .skip(1)
            .map(|group| group.name.as_str())
            .collect()
    }

    /// The choices of a proposal: one per name, the decided one first.
    pub(crate) fn choices(&self) -> Vec<NameChoice> {
        self.groups
            .iter()
            .enumerate()
            .map(|(index, group)| NameChoice {
                name: group.name.clone(),
                proposed: index == 0,
                sources: group
                    .sources
                    .iter()
                    .map(|candidate| NameChoiceSource {
                        source: candidate.source,
                        source_key: candidate.source_key.clone(),
                        given: candidate.given.clone(),
                        last_seen: candidate.last_seen,
                    })
                    .collect(),
                last_seen: group.last_seen,
            })
            .collect()
    }

    /// What the fingerprint covers: the names, their kinds of source and what decided.
    pub(crate) fn shape(&self) -> Vec<String> {
        let mut shape: Vec<String> = self
            .groups
            .iter()
            .map(|group| {
                let mut kinds: Vec<&str> = group
                    .sources
                    .iter()
                    .map(|candidate| candidate.source.as_str())
                    .collect();
                kinds.dedup();
                format!("choice:{}@{}", group.name, kinds.join("+"))
            })
            .collect();
        shape.push(format!("decided:{}", self.decided_by.text()));
        shape
    }

    /// The parameters it adds to a proposal.
    pub(crate) fn params(&self, params: &mut BTreeMap<String, String>) {
        params.insert(
            "name_source".to_owned(),
            self.winner().source().as_str().to_owned(),
        );
        params.insert("name_rule".to_owned(), self.decided_by.text());
        if let Some(site) = self.rule_site {
            params.insert("rule_site".to_owned(), site.to_string());
        }
        let others = self.others();
        if !others.is_empty() {
            params.insert("other_names".to_owned(), others.join(", "));
        }
    }

    /// The English sentence on the names, for a summary.
    pub(crate) fn sentence(&self) -> String {
        let winner = self.winner();
        if self.groups.len() == 1 {
            return format!("{} names it {}", winner.source().label(), winner.name);
        }
        let others: Vec<String> = self
            .groups
            .iter()
            .skip(1)
            .map(|group| format!("{} ({})", group.name, group.source().label()))
            .collect();
        format!(
            "{} names it {}, chosen by {}; also named {}",
            winner.source().label(),
            winner.name,
            self.decided_by.english(),
            others.join(", ")
        )
    }
}

/// The real names the facts `facts` give a device (placeholders left out), and the names
/// in `echoes` left out of DNS sources: the DNS names of intent that the actuator wrote.
fn gather(
    snapshot: &Snapshot,
    facts: &BTreeSet<usize>,
    echoes: &BTreeSet<String>,
) -> Vec<NameCandidate> {
    let mut out = Vec::new();
    for index in facts {
        let fact = &snapshot.facts[*index];
        if !fact.is_current(snapshot.now) || observed_placeholder(&fact.observed) {
            continue;
        }
        let Some(given) = observed_name(&fact.observed) else {
            continue;
        };
        let source = snapshot.authorities.source_of(&fact.source);
        if source == NameSource::Dns
            && echoes.contains(given.trim_end_matches('.').to_ascii_lowercase().as_str())
        {
            continue;
        }
        let Some(name) = sanitize(given) else {
            continue;
        };
        out.push(NameCandidate {
            name,
            given: given.to_owned(),
            source,
            source_key: fact.source_key.clone(),
            last_seen: fact.last_seen,
        });
    }
    out
}

/// The facts that name a device: those of `pairs` and the name facts of `ips`.
pub(crate) fn naming_facts<'a>(
    snapshot: &Snapshot,
    pairs: impl IntoIterator<Item = &'a Seen>,
    ips: impl IntoIterator<Item = std::net::IpAddr>,
) -> BTreeSet<usize> {
    let mut facts: BTreeSet<usize> = pairs.into_iter().map(|pair| pair.fact).collect();
    for ip in ips {
        if let Some(found) = snapshot.name_facts.get(&ip) {
            facts.extend(found.iter().copied());
        }
    }
    facts
}

/// The decision on the names of a device at `site`, with the preferred source of its host;
/// `None` without a real name.
pub(crate) fn decide(
    snapshot: &Snapshot,
    facts: &BTreeSet<usize>,
    echoes: &BTreeSet<String>,
    site: Option<SiteId>,
    preferred: Option<NameSource>,
) -> Option<NameDecision> {
    let candidates = gather(snapshot, facts, echoes);
    if candidates.is_empty() {
        return None;
    }
    let (order, mut decided_by) = snapshot.authorities.order_at(site);
    let rule_site = match decided_by {
        DecidedBy::Site(site) => Some(site),
        _ => None,
    };
    let rank = |source: NameSource| {
        if Some(source) == preferred {
            return 0;
        }
        1 + order
            .iter()
            .position(|other| *other == source)
            .unwrap_or(order.len())
    };
    let mut groups: BTreeMap<String, Vec<NameCandidate>> = BTreeMap::new();
    for candidate in candidates {
        groups
            .entry(label(&candidate.name))
            .or_default()
            .push(candidate);
    }
    let mut groups: Vec<NameGroup> = groups
        .into_iter()
        .map(|(label, mut sources)| {
            sources.sort_by(|a, b| {
                rank(a.source)
                    .cmp(&rank(b.source))
                    .then(b.last_seen.cmp(&a.last_seen))
                    .then(a.source_key.cmp(&b.source_key))
                    .then(a.name.cmp(&b.name))
            });
            sources.dedup_by(|a, b| a.source_key == b.source_key && a.name == b.name);
            let best = &sources[0];
            NameGroup {
                label,
                name: best.name.clone(),
                rank: rank(best.source),
                last_seen: sources
                    .iter()
                    .map(|candidate| candidate.last_seen)
                    .max()
                    .unwrap_or(best.last_seen),
                sources,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        a.rank
            .cmp(&b.rank)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.label.cmp(&b.label))
    });
    if preferred.is_some() && groups[0].rank == 0 {
        decided_by = DecidedBy::Host;
    }
    Some(NameDecision {
        groups,
        decided_by,
        rule_site,
    })
}

/// The site whose rule decides for a host: its own, else the site of the network of its
/// first address.
fn host_site(snapshot: &Snapshot, host: &Host, addresses: &[std::net::IpAddr]) -> Option<SiteId> {
    host.site.or_else(|| {
        let intent = &snapshot.intent;
        intent
            .interfaces
            .values()
            .filter(|interface| interface.host == host.id)
            .flat_map(|interface| intent.addresses_of.get(&interface.id).into_iter().flatten())
            .filter_map(|id| intent.addresses.get(id))
            .filter(|address| addresses.contains(&address.ip))
            .find_map(|address| intent.network_of(address.vrf, address.ip))
            .and_then(|prefix| prefix.site)
    })
}

/// The proposals that rename hosts of intent (see the module documentation).
#[allow(clippy::too_many_lines)] // One rule: the names of each host against its own.
pub(crate) fn host_names(snapshot: &Snapshot, book: &mut NameBook) -> Vec<Candidate> {
    let intent = &snapshot.intent;
    let mut macs_of: BTreeMap<HostId, BTreeSet<MacAddr>> = BTreeMap::new();
    let mut ips_of: BTreeMap<HostId, BTreeSet<std::net::IpAddr>> = BTreeMap::new();
    let mut echoes_of: BTreeMap<HostId, BTreeSet<String>> = BTreeMap::new();
    for interface in intent.interfaces.values() {
        if let Some(mac) = interface.mac {
            macs_of.entry(interface.host).or_default().insert(mac);
        }
        for id in intent.addresses_of.get(&interface.id).into_iter().flatten() {
            if let Some(address) = intent.addresses.get(id) {
                ips_of.entry(interface.host).or_default().insert(address.ip);
                if let Some(dns) = &address.dns_name {
                    echoes_of
                        .entry(interface.host)
                        .or_default()
                        .insert(dns.to_string().trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
    }
    let mut out = Vec::new();
    for host in intent.hosts.values() {
        if host.lock || super::rules::untouchable(host) || host.is_decommissioned() {
            continue;
        }
        let macs = macs_of.remove(&host.id).unwrap_or_default();
        let mut ips = ips_of.remove(&host.id).unwrap_or_default();
        if macs.is_empty() && ips.is_empty() {
            continue;
        }
        let pairs: Vec<&Seen> = snapshot
            .seen
            .iter()
            .filter(|pair| match pair.mac {
                Some(mac) => macs.contains(&mac),
                None => pair.ip.is_some_and(|ip| ips.contains(&ip)),
            })
            .collect();
        ips.extend(pairs.iter().filter_map(|pair| pair.ip));
        let facts = naming_facts(snapshot, pairs.iter().copied(), ips.iter().copied());
        if facts.is_empty() {
            continue;
        }
        let echoes = echoes_of.remove(&host.id).unwrap_or_default();
        let preferred = snapshot.authorities.preference(host.id);
        let site = host_site(snapshot, host, &ips.iter().copied().collect::<Vec<_>>());
        let Some(decision) = decide(snapshot, &facts, &echoes, site, preferred) else {
            continue;
        };
        let current = host.name.as_str();
        let current_label = label(current);
        if decision.winner().label == current_label {
            continue;
        }
        let placeholder = tenko_core::observe::is_placeholder_name(current);
        let rule = if placeholder {
            rule::PLACEHOLDER_NAME
        } else {
            let decided = snapshot
                .authorities
                .choices
                .get(&host.id)
                .is_some_and(|choice| {
                    label(&choice.name) == current_label
                        && decision.groups.iter().all(|group| {
                            choice
                                .offered
                                .iter()
                                .any(|offered| label(offered) == group.label)
                        })
                });
            if decided {
                continue;
            }
            if decision.decided_by == DecidedBy::Host {
                rule::PREFERRED_NAME
            } else if decision.groups.len() >= 2 {
                rule::NAME_CONFLICT
            } else {
                continue;
            }
        };
        let key = format!("host_name/host:{}", host.id);
        let Some(name) = book.take_in(&key, host.tenant, &decision.winner().name) else {
            continue;
        };
        let evidence = name_evidence(snapshot, &facts);
        let mut params = BTreeMap::from([
            ("host".to_owned(), current.to_owned()),
            ("name".to_owned(), name.to_string()),
        ]);
        decision.params(&mut params);
        let summary = match rule {
            rule::PLACEHOLDER_NAME => format!(
                "Host {current} has a placeholder name; {}; rename it to {name}",
                decision.sentence()
            ),
            rule::PREFERRED_NAME => format!(
                "Host {current} follows {}, which names it {name}; rename it to {name}",
                decision.winner().source().label()
            ),
            _ => format!(
                "The sources name host {current} differently: {}; rename it to {name}",
                decision.sentence()
            ),
        };
        let mut shape = vec![format!("rename:{}/{name}", host.id)];
        shape.extend(decision.shape());
        out.push(Candidate {
            kind: IntentProposalKind::HostName,
            rule,
            key,
            subject: ProposalSubject {
                mac: macs.iter().next().copied(),
                ip: ips.iter().next().copied(),
                cidr: None,
                vrf: None,
                prefix: None,
                name: Some(current.to_owned()),
                objects: vec![ObjectRef::from(host.id)],
            },
            severity: ProposalSeverity::Info,
            summary,
            params,
            evidence,
            commands: vec![IpamCommand::UpdateHost(UpdateHost {
                id: host.id,
                expected: None,
                patch: HostPatch {
                    name: Some(name),
                    ..HostPatch::default()
                },
            })],
            choices: decision.choices(),
            shape,
        });
    }
    out
}

/// The evidence of a name proposal: one entry per fact that names the device.
fn name_evidence(snapshot: &Snapshot, facts: &BTreeSet<usize>) -> Vec<ProposalEvidence> {
    let mut out: Vec<ProposalEvidence> = facts
        .iter()
        .map(|index| &snapshot.facts[*index])
        .filter(|fact| fact.is_current(snapshot.now))
        .map(|fact| {
            let placeholder = observed_placeholder(&fact.observed);
            ProposalEvidence {
                source: fact.source.clone(),
                source_key: fact.source_key.clone(),
                subject_key: fact.subject_key.clone(),
                observation: fact.observation,
                mac: fact.macs().first().copied(),
                ip: fact.ips().into_iter().next(),
                name: observed_name(&fact.observed)
                    .filter(|_| !placeholder)
                    .map(str::to_owned),
                first_seen: fact.first_seen,
                last_seen: fact.last_seen,
                sightings: fact.sightings,
            }
        })
        .collect();
    out.sort_by(|a, b| (&a.source_key, &a.subject_key).cmp(&(&b.source_key, &b.subject_key)));
    out
}

// ----- the rules and preferences as the API shows them --------------------------------

/// The name authority as the API shows it: the order in force without a rule, the stored
/// rules and the hosts' preferred sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NameAuthorityView {
    /// The order when no rule is stored ([`NameSource::DEFAULT_ORDER`]).
    pub default_order: Vec<NameSource>,
    /// Every kind of source, for an editor.
    pub sources: Vec<NameSource>,
    /// The global rule; `null` while the default applies.
    pub global: Option<StoredAuthority>,
    /// The rules of sites, by site name.
    pub sites: Vec<SiteAuthority>,
    /// The hosts that prefer a source.
    pub preferences: Vec<HostPreference>,
}

/// The rule of one site, with the site's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SiteAuthority {
    /// The site's name.
    pub site_name: String,
    /// The rule.
    #[serde(flatten)]
    pub rule: StoredAuthority,
}

/// A host's preferred source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostPreference {
    /// The host.
    pub host: HostId,
    /// The host's name now.
    pub host_name: String,
    /// The source it prefers.
    pub source: NameSource,
    /// The name it chose then.
    pub name: String,
    /// Who decided and when.
    pub decided: Stamp,
}

/// The body of a change of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NameAuthorityRule {
    /// The kinds of sources, the most trusted first: one to ten, each once.
    pub order: Vec<NameSource>,
}

fn not_found(kind: &str, id: &str) -> IpamError {
    IpamError::new(codes::NOT_FOUND, 404, format!("{kind} {id} does not exist"))
        .titled("Not found")
        .param("kind", kind)
        .param("id", id)
}

fn invalid(field: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::AUTHORITY_INVALID, 422, detail)
        .titled("Invalid name authority rule")
        .param("field", field)
        .field(field, codes::AUTHORITY_INVALID)
}

/// Checks a rule: at least one kind, each once.
///
/// # Errors
///
/// 422 `ipam.name_authority.invalid` with the field `order`.
pub fn validate(order: &[NameSource]) -> IpamResult<()> {
    if order.is_empty() {
        return Err(invalid("order", "name at least one kind of source"));
    }
    let unique: BTreeSet<NameSource> = order.iter().copied().collect();
    if unique.len() != order.len() {
        return Err(invalid("order", "each kind of source is listed once"));
    }
    Ok(())
}

fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

fn order_text(order: &[NameSource]) -> String {
    order
        .iter()
        .map(|source| source.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn scope_object(site: Option<SiteId>) -> ObjectRef {
    site.map_or_else(system_object, ObjectRef::from)
}

fn live_site(view: &dyn ReadView, site: SiteId) -> IpamResult<Site> {
    match view.get_typed(&SITES, &site)? {
        Some((site, _)) if !site.meta.is_deleted() => Ok(site),
        _ => Err(not_found("site", &site.to_string())),
    }
}

/// The name authority as the API shows it.
///
/// # Errors
///
/// Store errors.
pub fn view_of(view: &dyn ReadView) -> IpamResult<NameAuthorityView> {
    let authorities = Authorities::load(view)?;
    let mut sites = Vec::new();
    for (site, rule) in authorities.sites {
        let site_name = view
            .get_typed(&SITES, &site)?
            .map_or_else(|| site.to_string(), |(site, _)| site.name.clone());
        sites.push(SiteAuthority { site_name, rule });
    }
    sites.sort_by(|a, b| a.site_name.cmp(&b.site_name));
    let mut preferences = Vec::new();
    for (host, choice) in authorities.choices {
        let (true, Some(source)) = (choice.prefer, choice.source) else {
            continue;
        };
        let Some((record, _)) = view.get_typed(&HOSTS, &host)? else {
            continue;
        };
        let record: Host = record;
        if record.meta.is_deleted() {
            continue;
        }
        preferences.push(HostPreference {
            host,
            host_name: record.name.to_string(),
            source,
            name: choice.name,
            decided: choice.decided,
        });
    }
    preferences.sort_by(|a, b| a.host_name.cmp(&b.host_name));
    Ok(NameAuthorityView {
        default_order: NameSource::DEFAULT_ORDER.to_vec(),
        sources: NameSource::ALL.to_vec(),
        global: authorities.global,
        sites,
        preferences,
    })
}

/// Adds the writes that set the rule of `site` (`None`: the global one) to `order` to
/// `batch`, with its audit record, unless the rule is that already; returns the stored
/// rule.
///
/// # Errors
///
/// 422 `ipam.name_authority.invalid`, 404 for an unknown site, store errors.
pub(crate) fn stage_rule(
    view: &dyn ReadView,
    cx: &RequestCtx,
    site: Option<SiteId>,
    order: Vec<NameSource>,
    batch: &mut WriteBatch,
) -> IpamResult<StoredAuthority> {
    validate(&order)?;
    if let Some(site) = site {
        live_site(view, site)?;
    }
    let current = view.get_typed(&NAME_AUTHORITY, &site)?;
    if let Some((rule, revision)) = &current
        && rule.order == order
    {
        let mut rule = rule.clone();
        rule.revision = *revision;
        return Ok(rule);
    }
    let rule = StoredAuthority {
        site,
        order,
        updated: Stamp::new(cx.now, cx.principal.clone()),
        revision: Revision::ZERO,
    };
    batch.put_typed(&NAME_AUTHORITY, &site, &rule)?;
    batch.expect_typed(
        &NAME_AUTHORITY,
        &site,
        current.as_ref().map(|(_, revision)| *revision),
    );
    batch.audit(
        AuditDraft::success(
            AuditAction::from_static(actions::AUTHORITY_SET),
            vec![scope_object(site)],
        )
        .with_source_ip(cx.source_ip)
        .with_change(FieldChange {
            object: None,
            field: "order".to_owned(),
            old: current.map(|(rule, _)| order_text(&rule.order)),
            new: Some(order_text(&rule.order)),
        }),
    );
    Ok(rule)
}

/// Sets the rule of `site` (`None`: the global one); audited as
/// `ipam.name_authority.set` with the old and the new order. Setting the order a rule
/// has changes nothing.
///
/// # Errors
///
/// 422 `ipam.name_authority.invalid`, 404 `ipam.not_found` for an unknown site, store
/// errors.
pub async fn set_rule(
    store: &dyn Store,
    cx: &RequestCtx,
    site: Option<SiteId>,
    order: Vec<NameSource>,
) -> IpamResult<StoredAuthority> {
    let view = store.read(ReadConsistency::Linearizable).await?;
    let mut batch = WriteBatch::for_request(cx);
    let mut rule = stage_rule(view.as_ref(), cx, site, order, &mut batch)?;
    drop(view);
    if batch.mutations.is_empty() {
        return Ok(rule);
    }
    rule.revision = store.propose(batch).await?.revision;
    Ok(rule)
}

/// Removes the rule of `site` (`None`: the global one, so the default applies again);
/// audited as `ipam.name_authority.clear`. Removing a rule that does not exist changes
/// nothing.
///
/// # Errors
///
/// Store errors.
pub async fn clear_rule(
    store: &dyn Store,
    cx: &RequestCtx,
    site: Option<SiteId>,
) -> IpamResult<()> {
    let view = store.read(ReadConsistency::Linearizable).await?;
    let Some((rule, revision)) = view.get_typed(&NAME_AUTHORITY, &site)? else {
        return Ok(());
    };
    drop(view);
    let mut batch = WriteBatch::for_request(cx);
    batch.delete_typed(&NAME_AUTHORITY, &site);
    batch.expect_typed(&NAME_AUTHORITY, &site, Some(revision));
    batch.audit(
        AuditDraft::success(
            AuditAction::from_static(actions::AUTHORITY_CLEAR),
            vec![scope_object(site)],
        )
        .with_source_ip(cx.source_ip)
        .with_change(FieldChange {
            object: None,
            field: "order".to_owned(),
            old: Some(order_text(&rule.order)),
            new: None,
        }),
    );
    store.propose(batch).await?;
    Ok(())
}

/// Forgets the preferred source of `host`; the host's name decision stays, so the same
/// names do not open a proposal again. Audited as `ipam.name_preference.clear`.
///
/// # Errors
///
/// 404 `ipam.not_found` when the host prefers no source, store errors.
pub async fn clear_preference(store: &dyn Store, cx: &RequestCtx, host: HostId) -> IpamResult<()> {
    let view = store.read(ReadConsistency::Linearizable).await?;
    let Some((mut choice, revision)) = view
        .get_typed(&NAME_CHOICES, &host)?
        .filter(|(choice, _)| choice.prefer)
    else {
        return Err(not_found("name preference of host", &host.to_string()));
    };
    drop(view);
    let source = choice.source;
    choice.prefer = false;
    choice.revision = Revision::ZERO;
    let mut batch = WriteBatch::for_request(cx);
    batch.put_typed(&NAME_CHOICES, &host, &choice)?;
    batch.expect_typed(&NAME_CHOICES, &host, Some(revision));
    batch.audit(
        AuditDraft::success(
            AuditAction::from_static(actions::PREFERENCE_CLEAR),
            vec![ObjectRef::from(host)],
        )
        .with_source_ip(cx.source_ip)
        .with_context("source", source.map_or("", NameSource::as_str).to_owned()),
    );
    store.propose(batch).await?;
    Ok(())
}

/// Adds the record of a name decision on `host` to `batch`.
///
/// # Errors
///
/// Store errors.
pub(crate) fn stage_choice(
    view: &dyn ReadView,
    batch: &mut WriteBatch,
    choice: &HostNameChoice,
) -> IpamResult<()> {
    let current = view
        .get_typed(&NAME_CHOICES, &choice.host)?
        .map(|(_, revision)| revision);
    batch.put_typed(&NAME_CHOICES, &choice.host, choice)?;
    batch.expect_typed(&NAME_CHOICES, &choice.host, current);
    Ok(())
}

/// The order of the rule in force at `site` in `view`, and the site whose rule it is
/// (`None`: the global rule or the default).
///
/// # Errors
///
/// Store errors.
pub(crate) fn rule_at(
    view: &dyn ReadView,
    site: Option<SiteId>,
) -> IpamResult<(Option<SiteId>, Vec<NameSource>)> {
    if let Some(site) = site
        && let Some((rule, _)) = view.get_typed(&NAME_AUTHORITY, &Some(site))?
    {
        return Ok((Some(site), rule.order));
    }
    Ok(match view.get_typed(&NAME_AUTHORITY, &None)? {
        Some((rule, _)) => (None, rule.order),
        None => (None, NameSource::DEFAULT_ORDER.to_vec()),
    })
}

/// A host name from a chosen name.
pub(crate) fn host_name(name: &str) -> Option<HostName> {
    sanitize(name).and_then(|name| HostName::new(&name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_order_appends_what_a_rule_leaves_out() {
        assert_eq!(
            full_order(&[NameSource::Unifi]),
            [
                NameSource::Unifi,
                NameSource::Proxmox,
                NameSource::HomeAssistant,
                NameSource::Windows,
                NameSource::Dns,
                NameSource::Mdns,
                NameSource::Llmnr,
                NameSource::Scan,
                NameSource::Dhcp,
                NameSource::Other,
            ]
        );
        assert_eq!(full_order(&NameSource::DEFAULT_ORDER).len(), 10);
    }

    #[test]
    fn rules_are_validated() {
        validate(&[NameSource::Proxmox]).expect("valid");
        for order in [vec![], vec![NameSource::Dns, NameSource::Dns]] {
            let error = validate(&order).expect_err("refused").into_coded();
            assert_eq!(error.code, codes::AUTHORITY_INVALID);
            assert_eq!(error.status, 422);
        }
    }

    #[test]
    fn names_compare_by_their_first_label() {
        assert_eq!(label("PostgreSQL.example.net."), "postgresql");
        assert_eq!(label("db"), "db");
    }
}
