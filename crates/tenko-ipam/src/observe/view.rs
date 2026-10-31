//! Reads of the observation layer for the API: the fact list with filters and paging, and
//! the computed view of one subject (a MAC address, an IP address or a name) across every
//! source.
//!
//! The fact list follows the pattern of [`crate::query::list`]: it reads every fact from
//! one view, filters, builds an order-preserving sort key per fact (descending parts have
//! inverted bytes), appends the fact key and cuts a page; the cursor is the hexadecimal
//! sort key of the last item.

use std::{collections::BTreeSet, fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, ConnectorId, HostId, InterfaceId, MacAddr, ObjectRef, Revision, Timestamp, VrfId,
    codec::{KeyCodec, encode_key},
    observe::Observed,
    serde_util::{from_hex, to_hex},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use super::{
    dhcp::{LeaseFacts, Naming},
    model::{IntentSighting, ObservedFact, source_connector},
    source::Observations,
    tables::LAST_SEEN,
};
use crate::{
    error::{IpamError, IpamResult, codes},
    net::contains_ip,
    tables::{ADDRESS_IPS, ADDRESSES, HOSTS, INTERFACE_MACS, INTERFACES, VRFS},
};

/// Largest page of facts.
pub const MAX_LIMIT: usize = 1_000;
/// Page size when the caller gives none.
pub const DEFAULT_LIMIT: usize = 100;

/// Filters and paging of the fact list. Every filter is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactQuery {
    /// Facts of this source: a source key (`inventory:<id>`) or a connector id, which
    /// matches both the inventory and the network-controller source of the connector.
    pub source: Option<String>,
    /// Facts whose subject has this type (`host`, `address`, `attachment`, `services`,
    /// `os`, `link`, `name`, `vendor`).
    pub subject_type: Option<String>,
    /// Facts that name this MAC address.
    pub mac: Option<MacAddr>,
    /// Facts that name this IP address.
    pub ip: Option<IpAddr>,
    /// Facts that name an IP address inside this network.
    pub within: Option<IpNet>,
    /// Case-insensitive text over the subject key, the name, the OS, the platform, the
    /// parent, the tags and the attachment device.
    pub q: Option<String>,
    /// Only current facts (`true`) or only expired ones (`false`), at the read time.
    pub current: Option<bool>,
    /// Sort fields, `-` in front for descending: `last_seen`, `first_seen`, `source`,
    /// `subject`; `-last_seen` when empty. The fact key breaks ties.
    pub sort: Vec<String>,
    /// Page size, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// A page of facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactPage {
    /// The facts, with their revision.
    pub items: Vec<ObservedFact>,
    /// Cursor of the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    /// The revision of the view the page was read from.
    pub revision: Revision,
}

/// The sort fields of the fact list.
pub const SORTS: &[&str] = &["last_seen", "first_seen", "source", "subject"];

/// The subject types a fact can have (`FactSubject::type_name`).
const SUBJECT_TYPES: &[&str] = &[
    "host",
    "address",
    "attachment",
    "services",
    "os",
    "link",
    "name",
    "vendor",
    "network",
];

/// A sort field of the fact list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortField {
    LastSeen,
    FirstSeen,
    Source,
    Subject,
}

fn invalid_filter(name: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_FILTER, 400, detail)
        .titled("Invalid list parameter")
        .param("name", name)
        .field(name, codes::INVALID_FILTER)
}

fn limit_of(limit: Option<usize>) -> IpamResult<usize> {
    match limit {
        None => Ok(DEFAULT_LIMIT),
        Some(limit) if (1..=MAX_LIMIT).contains(&limit) => Ok(limit),
        Some(limit) => Err(invalid_filter(
            "limit",
            format!("limit {limit} is outside 1 to {MAX_LIMIT}"),
        )),
    }
}

/// The sort fields of a query: `-last_seen` when none is given.
fn parse_sorts(sort: &[String]) -> IpamResult<Vec<(SortField, bool)>> {
    let mut out = Vec::new();
    for item in sort.iter().flat_map(|s| s.split(',')) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (field, descending) = match item.strip_prefix('-') {
            Some(field) => (field, true),
            None => (item.strip_prefix('+').unwrap_or(item), false),
        };
        let field = match field {
            "last_seen" => SortField::LastSeen,
            "first_seen" => SortField::FirstSeen,
            "source" => SortField::Source,
            "subject" => SortField::Subject,
            other => {
                return Err(invalid_filter(
                    "sort",
                    format!(
                        "unknown sort field {other}; use one of {}",
                        SORTS.join(", ")
                    ),
                ));
            }
        };
        out.push((field, descending));
    }
    if out.is_empty() {
        out.push((SortField::LastSeen, true));
    }
    Ok(out)
}

fn decode_cursor(cursor: Option<&str>) -> IpamResult<Option<Vec<u8>>> {
    cursor
        .map(|text| {
            from_hex(text).ok_or_else(|| {
                IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                    .titled("Invalid cursor")
                    .field("cursor", codes::INVALID_CURSOR)
            })
        })
        .transpose()
}

/// The order-preserving key of a fact under the given sort: every sort part (inverted for
/// descending ones), then the fact key, which is unique.
fn composite_key(fact: &ObservedFact, sorts: &[(SortField, bool)]) -> Vec<u8> {
    let mut key = Vec::new();
    for (field, descending) in sorts {
        let mut part = Vec::new();
        match field {
            SortField::LastSeen => fact.last_seen.encode_key(&mut part),
            SortField::FirstSeen => fact.first_seen.encode_key(&mut part),
            SortField::Source => fact.source_key.encode_key(&mut part),
            SortField::Subject => fact.subject_key.encode_key(&mut part),
        }
        if *descending {
            // Every component encoding is self-delimiting, so inverting the bytes
            // reverses the order.
            for byte in &mut part {
                *byte = !*byte;
            }
        }
        key.extend(part);
    }
    fact.source_key.encode_key(&mut key);
    fact.subject_key.encode_key(&mut key);
    key
}

/// The lowercase text `q` searches: the subject key, the name and the descriptive
/// attributes of the observation.
fn search_text(fact: &ObservedFact) -> String {
    let mut parts: Vec<&str> = vec![fact.subject_key.as_str()];
    parts.extend(fact.name());
    match &fact.observed {
        Observed::Host(host) => {
            parts.push(host.external_id.as_str());
            parts.extend(host.os.as_deref());
            parts.extend(host.platform.as_deref());
            parts.extend(host.parent.as_deref());
            parts.extend(host.tags.iter().map(String::as_str));
        }
        Observed::Attachment {
            device, port, ssid, ..
        } => {
            parts.push(device.as_str());
            parts.extend(port.as_deref());
            parts.extend(ssid.as_deref());
        }
        Observed::Os { guess, .. } => parts.push(guess.as_str()),
        Observed::Vendor { vendor, .. } => parts.push(vendor.as_str()),
        Observed::Network { name, .. } => parts.push(name.as_str()),
        Observed::Address { .. }
        | Observed::Services { .. }
        | Observed::Link { .. }
        | Observed::Name { .. } => {}
    }
    // A newline between the parts keeps a search text from matching across two fields.
    parts.join("\n").to_lowercase()
}

/// The filters of a query, prepared once per list.
struct FactFilter<'a> {
    query: &'a FactQuery,
    source: Option<&'a str>,
    connector: Option<ConnectorId>,
    needle: Option<String>,
    now: Timestamp,
}

impl<'a> FactFilter<'a> {
    fn new(query: &'a FactQuery, now: Timestamp) -> IpamResult<Self> {
        if let Some(kind) = &query.subject_type
            && !SUBJECT_TYPES.contains(&kind.as_str())
        {
            return Err(invalid_filter(
                "type",
                format!(
                    "unknown subject type {kind}; use one of {}",
                    SUBJECT_TYPES.join(", ")
                ),
            ));
        }
        let source = query
            .source
            .as_deref()
            .map(str::trim)
            .filter(|source| !source.is_empty());
        Ok(Self {
            query,
            source,
            connector: source.and_then(|source| source.parse::<ConnectorId>().ok()),
            needle: query
                .q
                .as_ref()
                .map(|q| q.trim().to_lowercase())
                .filter(|q| !q.is_empty()),
            now,
        })
    }

    fn source_matches(&self, fact: &ObservedFact) -> bool {
        let Some(source) = self.source else {
            return true;
        };
        fact.source_key == source
            || self
                .connector
                .is_some_and(|connector| source_connector(&fact.source) == Some(connector))
    }

    fn keeps(&self, fact: &ObservedFact) -> bool {
        let query = self.query;
        self.source_matches(fact)
            && query
                .subject_type
                .as_deref()
                .is_none_or(|kind| fact.subject.type_name() == kind)
            && query
                .current
                .is_none_or(|current| fact.is_current(self.now) == current)
            && query.mac.is_none_or(|mac| fact.macs().contains(&mac))
            && query.ip.is_none_or(|ip| fact.ips().contains(&ip))
            && query
                .within
                .as_ref()
                .is_none_or(|net| fact.ips().into_iter().any(|ip| contains_ip(net, ip)))
            && self
                .needle
                .as_ref()
                .is_none_or(|needle| search_text(fact).contains(needle.as_str()))
    }
}

/// Lists facts (see [`FactQuery`]): the stored facts of `view` and the facts of the lease
/// view `leases` (ADR 0031); `now` decides which facts are current.
///
/// # Errors
///
/// `ipam.invalid_filter` for an unknown sort field or subject type, `ipam.invalid_cursor`
/// for a malformed cursor, store and decoding errors.
pub fn list_facts(
    view: &dyn ReadView,
    leases: Option<&LeaseFacts>,
    query: &FactQuery,
    now: Timestamp,
) -> IpamResult<FactPage> {
    list_facts_where(view, leases, query, now, &|_| true)
}

/// [`list_facts`] with a further condition: only facts for which `keep` answers `true` count,
/// so a scoped reader gets full pages with valid cursors (IAM-01).
///
/// # Errors
///
/// As [`list_facts`].
pub fn list_facts_where(
    view: &dyn ReadView,
    leases: Option<&LeaseFacts>,
    query: &FactQuery,
    now: Timestamp,
    keep: &dyn Fn(&ObservedFact) -> bool,
) -> IpamResult<FactPage> {
    let limit = limit_of(query.limit)?;
    let sorts = parse_sorts(&query.sort)?;
    let after = decode_cursor(query.cursor.as_deref())?;
    let filter = FactFilter::new(query, now)?;
    let mut rows: Vec<(Vec<u8>, ObservedFact)> = Observations::new(view, leases)
        .facts(now)?
        .into_iter()
        .filter_map(|fact| {
            (filter.keeps(&fact) && keep(&fact)).then(|| (composite_key(&fact, &sorts), fact))
        })
        .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if more {
        rows.last().map(|(key, _)| to_hex(key))
    } else {
        None
    };
    Ok(FactPage {
        items: rows.into_iter().map(|(_, fact)| fact).collect(),
        next_cursor,
        revision: view.revision(),
    })
}

/// What `GET /observations/{subject}` names: a MAC address, an IP address or a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectQuery {
    /// A MAC address (`00:00:5e:00:53:01` or `00-00-5E-00-53-01`).
    Mac(MacAddr),
    /// An IP address.
    Ip(IpAddr),
    /// A name, compared without case.
    Name(String),
}

impl FromStr for SubjectQuery {
    type Err = IpamError;

    /// A MAC address if the text parses as one, else an IP address, else a name of 1 to
    /// 253 characters without control characters (lowercased).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if let Ok(mac) = text.parse::<MacAddr>() {
            return Ok(SubjectQuery::Mac(mac));
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(SubjectQuery::Ip(ip));
        }
        if text.is_empty() || text.len() > 253 || text.chars().any(char::is_control) {
            return Err(IpamError::invalid(
                "subject",
                "the subject is a MAC address, an IP address or a name of 1 to 253 characters",
            ));
        }
        Ok(SubjectQuery::Name(text.to_ascii_lowercase()))
    }
}

impl SubjectQuery {
    /// What the query names, as the fact sources take it.
    pub fn naming(&self) -> Naming {
        match self {
            SubjectQuery::Mac(mac) => Naming::Mac(*mac),
            SubjectQuery::Ip(ip) => Naming::Ip(*ip),
            SubjectQuery::Name(name) => Naming::Name(name.clone()),
        }
    }
}

impl fmt::Display for SubjectQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectQuery::Mac(mac) => write!(f, "mac:{mac}"),
            SubjectQuery::Ip(ip) => write!(f, "ip:{ip}"),
            SubjectQuery::Name(name) => write!(f, "name:{name}"),
        }
    }
}

/// Where a client is attached, as one source reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AttachmentView {
    /// The source key.
    pub source: String,
    /// The client.
    pub mac: MacAddr,
    /// The switch or access point.
    pub device: String,
    /// The switch port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// The wireless network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// The VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// When the source last reported it.
    pub last_seen: Timestamp,
}

/// The picture of one subject across sources, computed from its facts. Lists are sorted
/// and without duplicates; they draw on the current facts, or on every fact when none is
/// current.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubjectSummary {
    /// Whether any fact is current.
    pub current: bool,
    /// The sources with a current fact.
    pub sources: Vec<String>,
    /// The earliest first sighting of any fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<Timestamp>,
    /// The latest sighting of any fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
    /// MAC addresses.
    pub macs: Vec<MacAddr>,
    /// IP addresses.
    #[schema(value_type = Vec<String>)]
    pub ips: Vec<IpAddr>,
    /// Names: inventory names and the names probes found (reverse DNS, mDNS, LLMNR,
    /// SNMP), as reported.
    pub names: Vec<String>,
    /// Operating systems: inventory OS and probe OS guesses.
    pub os: Vec<String>,
    /// Platforms (`qemu`, `lxc`, `esphome`).
    pub platforms: Vec<String>,
    /// Parent hosts (the hypervisor node of a VM).
    pub parents: Vec<String>,
    /// Open TCP ports (SCAN-08).
    pub open_tcp: Vec<u16>,
    /// The open TCP ports that answered a TLS handshake.
    #[serde(default)]
    pub tls_tcp: Vec<u16>,
    /// Vendors of the MAC addresses (OUI) or as devices report them.
    #[serde(default)]
    pub vendors: Vec<String>,
    /// Attachments, one per source and MAC address.
    pub attachments: Vec<AttachmentView>,
    /// Tags from the sources.
    pub tags: Vec<String>,
}

/// The intent objects that match a subject: interfaces by MAC address, addresses by IP
/// address (in any VRF), hosts by name and through their interfaces. Live objects only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntentMatch {
    /// Hosts.
    pub hosts: Vec<HostId>,
    /// Interfaces.
    pub interfaces: Vec<InterfaceId>,
    /// Addresses.
    pub addresses: Vec<AddressId>,
    /// VRFs of the matching addresses.
    pub vrfs: Vec<VrfId>,
}

/// The last sighting of an intent object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObjectSighting {
    /// The address or interface.
    pub object: ObjectRef,
    /// Its last sighting.
    pub sighting: IntentSighting,
}

/// The computed view of one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubjectView {
    /// The subject as asked: `mac:<mac>`, `ip:<ip>` or `name:<name>`.
    pub subject: String,
    /// Every fact that names the subject: current facts first, then by last sighting,
    /// newest first.
    pub facts: Vec<ObservedFact>,
    /// The picture across sources.
    pub summary: SubjectSummary,
    /// The intent objects that match.
    pub intent: IntentMatch,
    /// The last sightings of the matching addresses and interfaces.
    pub sightings: Vec<ObjectSighting>,
    /// The revision of the view.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

/// The computed view of one subject over the stored facts of `view` and the facts of the
/// lease view `leases` (ADR 0031); `now` decides which facts are current.
///
/// # Errors
///
/// `ipam.not_found` (kind `observation`) when no fact names the subject, store and
/// decoding errors.
pub fn subject_view(
    view: &dyn ReadView,
    leases: Option<&LeaseFacts>,
    subject: &SubjectQuery,
    now: Timestamp,
) -> IpamResult<SubjectView> {
    let mut facts = Observations::new(view, leases).facts_naming(&subject.naming(), now)?;
    if facts.is_empty() {
        return Err(IpamError::new(
            crate::codes::NOT_FOUND,
            404,
            format!("nothing observed for {subject}"),
        )
        .titled("Nothing observed")
        .param("kind", "observation")
        .param("subject", subject)
        .param("revision", view.revision()));
    }
    // Current facts first, then the most recently seen; the fact key breaks ties.
    facts.sort_by(|a, b| {
        b.is_current(now)
            .cmp(&a.is_current(now))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| (&a.source_key, &a.subject_key).cmp(&(&b.source_key, &b.subject_key)))
    });
    let summary = summarize(&facts, now);
    let matches = IntentMatches::find(view, subject, &summary)?;
    let sightings = matches.sightings(view)?;
    Ok(SubjectView {
        subject: subject.to_string(),
        facts,
        summary,
        intent: matches.into_intent(),
        sightings,
        revision: view.revision(),
    })
}

/// Adds `text` to `set` unless it is blank.
fn add_text(set: &mut BTreeSet<String>, text: Option<&str>) {
    if let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) {
        set.insert(text.to_owned());
    }
}

/// The picture across sources: drawn from the current facts, or from every fact when none
/// is current. `facts` are not empty.
fn summarize(facts: &[ObservedFact], now: Timestamp) -> SubjectSummary {
    let current: Vec<&ObservedFact> = facts.iter().filter(|fact| fact.is_current(now)).collect();
    let chosen: Vec<&ObservedFact> = if current.is_empty() {
        facts.iter().collect()
    } else {
        current.clone()
    };
    let mut macs = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut os = BTreeSet::new();
    let mut platforms = BTreeSet::new();
    let mut parents = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut open_tcp = BTreeSet::new();
    let mut tls_tcp = BTreeSet::new();
    let mut vendors = BTreeSet::new();
    let mut attachments = Vec::new();
    for fact in chosen {
        macs.extend(fact.macs());
        ips.extend(fact.ips());
        add_text(&mut names, fact.name());
        match &fact.observed {
            Observed::Host(host) => {
                add_text(&mut os, host.os.as_deref());
                add_text(&mut platforms, host.platform.as_deref());
                add_text(&mut parents, host.parent.as_deref());
                for tag in &host.tags {
                    add_text(&mut tags, Some(tag));
                }
            }
            Observed::Os { guess, .. } => add_text(&mut os, Some(guess)),
            Observed::Services {
                open_tcp: ports,
                tls_tcp: tls,
                ..
            } => {
                open_tcp.extend(ports.iter().copied());
                tls_tcp.extend(tls.iter().copied());
            }
            Observed::Vendor { vendor, .. } => add_text(&mut vendors, Some(vendor)),
            Observed::Attachment {
                mac,
                device,
                port,
                ssid,
                vlan,
            } => attachments.push(AttachmentView {
                source: fact.source_key.clone(),
                mac: *mac,
                device: device.clone(),
                port: port.clone(),
                ssid: ssid.clone(),
                vlan: *vlan,
                last_seen: fact.last_seen,
            }),
            Observed::Address { .. }
            | Observed::Link { .. }
            | Observed::Name { .. }
            | Observed::Network { .. } => {}
        }
    }
    attachments.sort_by(|a, b| (&a.source, a.mac).cmp(&(&b.source, b.mac)));
    SubjectSummary {
        current: !current.is_empty(),
        sources: current
            .iter()
            .map(|fact| fact.source_key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        first_seen: facts.iter().map(|fact| fact.first_seen).min(),
        last_seen: facts.iter().map(|fact| fact.last_seen).max(),
        macs: macs.into_iter().collect(),
        ips: ips.into_iter().collect(),
        names: names.into_iter().collect(),
        os: os.into_iter().collect(),
        platforms: platforms.into_iter().collect(),
        parents: parents.into_iter().collect(),
        open_tcp: open_tcp.into_iter().collect(),
        tls_tcp: tls_tcp.into_iter().collect(),
        vendors: vendors.into_iter().collect(),
        attachments,
        tags: tags.into_iter().collect(),
    }
}

/// The live intent objects that match a subject.
#[derive(Debug, Default)]
struct IntentMatches {
    hosts: BTreeSet<HostId>,
    interfaces: BTreeSet<InterfaceId>,
    addresses: BTreeSet<AddressId>,
    vrfs: BTreeSet<VrfId>,
}

impl IntentMatches {
    /// Finds the objects: interfaces by every MAC address of the summary, addresses by
    /// every IP address in every live VRF, and for a name also the hosts of that name and
    /// their interfaces.
    fn find(
        view: &dyn ReadView,
        subject: &SubjectQuery,
        summary: &SubjectSummary,
    ) -> IpamResult<Self> {
        let mut found = Self::default();
        for mac in &summary.macs {
            found.add_interfaces_of_mac(view, *mac)?;
        }
        if let SubjectQuery::Name(name) = subject {
            found.add_hosts_named(view, name)?;
        }
        found.add_addresses(view, &summary.ips)?;
        Ok(found)
    }

    fn add_interfaces_of_mac(&mut self, view: &dyn ReadView, mac: MacAddr) -> IpamResult<()> {
        let rows = view.scan_typed(
            &INTERFACE_MACS,
            KeyRange::prefix(encode_key(&(mac,))),
            usize::MAX,
            false,
        )?;
        for ((_, id), (), _) in rows {
            let Some((interface, _)) = view.get_typed(&INTERFACES, &id)? else {
                continue;
            };
            if interface.meta.is_deleted() {
                continue;
            }
            self.interfaces.insert(id);
            if view
                .get_typed(&HOSTS, &interface.host)?
                .is_some_and(|(host, _)| !host.meta.is_deleted())
            {
                self.hosts.insert(interface.host);
            }
        }
        Ok(())
    }

    fn add_hosts_named(&mut self, view: &dyn ReadView, name: &str) -> IpamResult<()> {
        let name = name.trim();
        let named: BTreeSet<HostId> = view
            .scan_typed(&HOSTS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, host, _)| {
                !host.meta.is_deleted() && host.name.as_str().eq_ignore_ascii_case(name)
            })
            .map(|(id, _, _)| id)
            .collect();
        if named.is_empty() {
            return Ok(());
        }
        let interfaces = view.scan_typed(&INTERFACES, KeyRange::all(), usize::MAX, false)?;
        for (id, interface, _) in interfaces {
            if !interface.meta.is_deleted() && named.contains(&interface.host) {
                self.interfaces.insert(id);
            }
        }
        self.hosts.extend(named);
        Ok(())
    }

    fn add_addresses(&mut self, view: &dyn ReadView, ips: &[IpAddr]) -> IpamResult<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let vrfs: Vec<VrfId> = view
            .scan_typed(&VRFS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, vrf, _)| !vrf.meta.is_deleted())
            .map(|(id, _, _)| id)
            .collect();
        for vrf in vrfs {
            for ip in ips {
                let Some((id, _)) = view.get_typed(&ADDRESS_IPS, &(vrf, *ip))? else {
                    continue;
                };
                if view
                    .get_typed(&ADDRESSES, &id)?
                    .is_some_and(|(address, _)| !address.meta.is_deleted())
                {
                    self.addresses.insert(id);
                    self.vrfs.insert(vrf);
                }
            }
        }
        Ok(())
    }

    /// The last sightings of the matching addresses and interfaces, ordered by object.
    fn sightings(&self, view: &dyn ReadView) -> IpamResult<Vec<ObjectSighting>> {
        let objects: BTreeSet<ObjectRef> = self
            .addresses
            .iter()
            .map(|id| ObjectRef::from(*id))
            .chain(self.interfaces.iter().map(|id| ObjectRef::from(*id)))
            .collect();
        let mut out = Vec::new();
        for object in objects {
            if let Some((sighting, _)) = view.get_typed(&LAST_SEEN, &object)? {
                out.push(ObjectSighting { object, sighting });
            }
        }
        Ok(out)
    }

    fn into_intent(self) -> IntentMatch {
        IntentMatch {
            hosts: self.hosts.into_iter().collect(),
            interfaces: self.interfaces.into_iter().collect(),
            addresses: self.addresses.into_iter().collect(),
            vrfs: self.vrfs.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_default_to_newest_first_and_reject_unknown_fields() {
        assert_eq!(
            parse_sorts(&[]).expect("default"),
            vec![(SortField::LastSeen, true)]
        );
        assert_eq!(
            parse_sorts(&["+source, -first_seen".to_owned(), "subject".to_owned()]).expect("sorts"),
            vec![
                (SortField::Source, false),
                (SortField::FirstSeen, true),
                (SortField::Subject, false)
            ]
        );
        let error = parse_sorts(&["name".to_owned()]).expect_err("unknown");
        assert_eq!(error.code_str(), codes::INVALID_FILTER);
    }

    #[test]
    fn limits_and_cursors_are_checked() {
        assert_eq!(limit_of(None).expect("default"), DEFAULT_LIMIT);
        assert_eq!(limit_of(Some(MAX_LIMIT)).expect("max"), MAX_LIMIT);
        for bad in [0, MAX_LIMIT + 1] {
            let error = limit_of(Some(bad)).expect_err("outside");
            assert_eq!(error.code_str(), codes::INVALID_FILTER);
        }
        assert_eq!(decode_cursor(None).expect("none"), None);
        let error = decode_cursor(Some("not hex")).expect_err("malformed");
        assert_eq!(error.code_str(), codes::INVALID_CURSOR);
    }

    #[test]
    fn subjects_parse_as_mac_ip_or_lowercase_name() {
        assert!(matches!(
            "00-00-5E-00-53-01".parse::<SubjectQuery>(),
            Ok(SubjectQuery::Mac(_))
        ));
        assert!(matches!(
            "2001:db8::1".parse::<SubjectQuery>(),
            Ok(SubjectQuery::Ip(_))
        ));
        assert_eq!(
            "Web01.Example.TEST".parse::<SubjectQuery>().expect("name"),
            SubjectQuery::Name("web01.example.test".to_owned())
        );
        assert!("  ".parse::<SubjectQuery>().is_err());
    }
}
