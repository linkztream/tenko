//! The reconciliation view (IPAM-21, IPAM-23, WP8.2): one view over the four truths of an
//! address — intent (IPAM), leases (the facts of the sources `dhcp:<node>`), DNS records
//! (the zones' facts of the sources `dns:<zone>`) and scans (the facts of the probes and
//! the connectors) — that lists where they disagree, with the rule that says which truth
//! wins. It reads intent, facts, lease rows and open proposals from one read view and
//! writes nothing.
//!
//! # The lists
//!
//! | Kind | What | Who wins |
//! |---|---|---|
//! | `ghost` | An active address of a managed or dynamic host that no current fact shows, and that nothing has shown for longer than the lease time of the DHCP scope of its network (the reconciler's orphan age where no Tenko scope serves it); only where DHCP or a probe could see it | intent for `reserved` and `static` hosts (IPAM-16); the lease for `dynamic` hosts |
//! | `rogue` | A current lease or sighting inside a network of intent, at an address without intent, of a device whose MAC address no interface carries | the newest sighting; the row links the open discovered-host proposal (IPAM-15) |
//! | `orphan` | A DNS record (A, AAAA or PTR of the origins `ipam` and `manual`) for an address that no host holds | the orphan rule for a record IPAM wrote (Phase 2's `dns_orphaned_record`, linked); the record itself for one written by hand |
//! | `ptr_mismatch` | A PTR record whose name is not the address's DNS name of intent or, without one, not a name of its forward records | intent for a managed host's DNS name; the forward record otherwise |
//! | `conflict` | Two MAC addresses on one address across the leases and the sightings, or an address the DHCP role abandoned on a conflict (WP8.5) (IPAM-23) | none: never resolved automatically |
//!
//! A conflict is not also listed as a rogue. MAC addresses that all belong to one host's
//! interfaces are no conflict. Addresses IPAM does not track (loopback, link-local,
//! multicast) and addresses whose VRF cannot be told are left out.
//!
//! # The OS field
//!
//! Every row and the host summary carry the OS guess that wins by precedence: an
//! inventory's OS (the system says what it runs), then an active scan's guess (a probe's
//! OS fingerprint), then the DHCP fingerprint's guess (DHCP-14); within one rank the
//! higher confidence, then the newer sighting. The vendors are the current vendor facts of
//! the MAC addresses (the probes' OUI names and option 60 of the leases).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, HostId, InterfaceId, MacAddr, ObjectRef, PrefixId, ProposalId, Revision, Timestamp,
    VrfId,
    dhcp::{BindingState, DhcpSettings, Lease, tables as dhcp_tables},
    ipam::{AssignmentMode, Status},
    observe::{ObservationSource, Observed},
    serde_util::{from_hex, to_hex},
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use super::{
    rules::rule,
    settings,
    snapshot::{Snapshot, trackable},
};
use crate::{
    dns::reverse,
    error::{IpamError, IpamResult, codes},
    net::{contains_ip, ip_to_u128},
    observe::model::ObservedFact,
};

/// Largest page of rows.
pub const MAX_LIMIT: usize = 1_000;
/// Page size when the caller gives none.
pub const DEFAULT_LIMIT: usize = 100;

/// The kinds of rows of the view.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileKind {
    /// Intent with no observation for longer than the scope's lease time.
    Ghost,
    /// A lease or sighting without intent.
    Rogue,
    /// A DNS record without a host.
    Orphan,
    /// A PTR record whose name disagrees with the address's DNS name.
    PtrMismatch,
    /// Two MAC addresses on one address (IPAM-23), never resolved automatically.
    Conflict,
}

impl ReconcileKind {
    /// Every kind, in the order of the view.
    pub const ALL: [ReconcileKind; 5] = [
        ReconcileKind::Conflict,
        ReconcileKind::Ghost,
        ReconcileKind::Rogue,
        ReconcileKind::Orphan,
        ReconcileKind::PtrMismatch,
    ];

    /// The name of the kind (`ghost`, `rogue`, `orphan`, `ptr_mismatch`, `conflict`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ReconcileKind::Ghost => "ghost",
            ReconcileKind::Rogue => "rogue",
            ReconcileKind::Orphan => "orphan",
            ReconcileKind::PtrMismatch => "ptr_mismatch",
            ReconcileKind::Conflict => "conflict",
        }
    }

    const fn order(self) -> u8 {
        match self {
            ReconcileKind::Conflict => 0,
            ReconcileKind::Ghost => 1,
            ReconcileKind::Rogue => 2,
            ReconcileKind::Orphan => 3,
            ReconcileKind::PtrMismatch => 4,
        }
    }
}

impl std::str::FromStr for ReconcileKind {
    type Err = IpamError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        ReconcileKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == text.trim())
            .ok_or_else(|| {
                IpamError::invalid(
                    "kind",
                    format!(
                        "unknown kind {text}; use one of ghost, rogue, orphan, ptr_mismatch, conflict"
                    ),
                )
            })
    }
}

/// The four truths (IPAM-21).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Truth {
    /// IPAM intent.
    Intent,
    /// DHCP leases.
    Lease,
    /// DNS records.
    Dns,
    /// Scans: the sightings of the probes and the connectors.
    Scan,
}

impl Truth {
    /// The truth a fact's source speaks for.
    pub const fn of(source: &ObservationSource) -> Truth {
        match source {
            ObservationSource::DhcpLease { .. } => Truth::Lease,
            ObservationSource::DnsRecord { .. } => Truth::Dns,
            ObservationSource::Probe { .. }
            | ObservationSource::Inventory { .. }
            | ObservationSource::NetworkController { .. } => Truth::Scan,
        }
    }
}

/// The rule that decides a row.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WinRule {
    /// Intent wins for a managed host (IPAM-16).
    IntentManaged,
    /// The lease wins for a `dynamic` host.
    LeaseDynamic,
    /// Without intent the newest sighting wins.
    NewestSighting,
    /// Two MAC addresses on one address are never resolved automatically (IPAM-23).
    NeverAutomatic,
    /// A record IPAM wrote without intent: the orphan rule decides.
    OrphanRule,
    /// A record written by hand stays as written.
    ManualRecord,
    /// Without a DNS name of intent the forward record wins.
    ForwardRecord,
}

impl WinRule {
    /// The truth the rule makes win, none for a conflict.
    pub const fn winner(self) -> Option<Truth> {
        match self {
            WinRule::IntentManaged | WinRule::OrphanRule => Some(Truth::Intent),
            WinRule::LeaseDynamic => Some(Truth::Lease),
            WinRule::NewestSighting | WinRule::NeverAutomatic => None,
            WinRule::ManualRecord | WinRule::ForwardRecord => Some(Truth::Dns),
        }
    }

    /// The rule in English.
    pub const fn text(self) -> &'static str {
        match self {
            WinRule::IntentManaged => {
                "intent wins for a managed host (IPAM-16): the device, its lease and its records are to follow the intent"
            }
            WinRule::LeaseDynamic => {
                "the lease wins for a dynamic host: its address follows the lease"
            }
            WinRule::NewestSighting => {
                "without intent the newest sighting wins; adopt the device with the discovered-host proposal"
            }
            WinRule::NeverAutomatic => {
                "two MAC addresses on one address are never resolved automatically (IPAM-23): find the device that should not be there"
            }
            WinRule::OrphanRule => {
                "IPAM wrote the record and no host holds the address any more: the orphan rule removes or proposes it"
            }
            WinRule::ManualRecord => {
                "a record written by hand stays as written: give the address a host or delete the record"
            }
            WinRule::ForwardRecord => {
                "without a DNS name of intent the forward record wins: correct the PTR record"
            }
        }
    }
}

/// What intent says about the address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IntentTruth {
    /// The address of intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressId>,
    /// Its status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// The host it is assigned to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// The host's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// The host's assignment mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AssignmentMode>,
    /// The MAC address of the interface the address is on.
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// The intended DNS name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
}

/// What the leases or the sightings say about the address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObservedTruth {
    /// The MAC addresses seen at the address.
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// The sources (`dhcp:1`, `probe:2:arp`, `inventory:<connector>`).
    #[serde(default)]
    pub sources: Vec<String>,
    /// The latest sighting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
    /// When the latest current fact runs out without a refresh (a lease's end).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// What the zones say about the address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsTruth {
    /// The owner names of the A and AAAA records with the address.
    #[serde(default)]
    pub forward: Vec<String>,
    /// The targets of the PTR records of the address.
    #[serde(default)]
    pub ptr: Vec<String>,
    /// The zones the records are in.
    #[serde(default)]
    pub zones: Vec<String>,
}

/// The OS guess that wins by precedence, and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OsField {
    /// The guess, such as `Windows 10 or 11`.
    pub guess: String,
    /// The confidence in percent (100 for an inventory's own statement).
    pub confidence: u8,
    /// The source key (`dhcp:1`, `probe:2:os_fingerprint`, `inventory:<connector>`).
    pub source: String,
    /// The truth the source speaks for.
    pub truth: Truth,
    /// When the source last reported it.
    pub last_seen: Timestamp,
}

/// One row of the view: what each truth says about an address, the finding and who wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReconcileRow {
    /// The row's identity and sort position.
    pub key: String,
    /// The finding.
    pub kind: ReconcileKind,
    /// The VRF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfId>,
    /// The address.
    #[schema(value_type = String)]
    pub address: IpAddr,
    /// The network prefix of intent that holds the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<PrefixId>,
    /// The host of intent, when one holds the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// What intent says, when it says anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<IntentTruth>,
    /// What the leases say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<ObservedTruth>,
    /// What the zones say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsTruth>,
    /// What the scans say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<ObservedTruth>,
    /// The MAC addresses the row is about (intent's and the observed ones).
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// The OS guess that wins by precedence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<OsField>,
    /// The vendors of the MAC addresses.
    #[serde(default)]
    pub vendors: Vec<String>,
    /// The truth that wins by the rule of the row; none for a conflict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner: Option<Truth>,
    /// The rule.
    pub rule_id: WinRule,
    /// The rule, in English.
    pub rule: String,
    /// The open proposal of the row: the discovered host of a rogue (IPAM-15), the
    /// orphaned record of an orphan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<ProposalId>,
    /// The latest sighting of the address (for a ghost the last before it went unseen;
    /// none when it was never seen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
}

/// The four truths of one host, for the host page: the OS field by precedence, every OS
/// guess, the vendors, and the MAC and IP addresses the view matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostTruths {
    /// The host.
    pub host: HostId,
    /// Its name.
    pub name: String,
    /// Its assignment mode.
    pub mode: AssignmentMode,
    /// The MAC addresses of its interfaces.
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// Its addresses.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub ips: Vec<IpAddr>,
    /// The OS guess that wins by precedence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<OsField>,
    /// Every current OS guess, in order of precedence.
    #[serde(default)]
    pub os_guesses: Vec<OsField>,
    /// The vendors of its MAC addresses.
    #[serde(default)]
    pub vendors: Vec<String>,
}

/// A page of the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilePage {
    /// The rows.
    pub items: Vec<ReconcileRow>,
    /// Cursor of the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    /// The revision of the view the page was read from.
    pub revision: Revision,
    /// With a host filter, the host's truths.
    pub host: Option<HostTruths>,
}

/// Filters and paging of the view. Every filter is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileQuery {
    /// Rows of addresses inside this prefix, in its VRF.
    pub prefix: Option<PrefixId>,
    /// Rows of this host: its addresses, its MAC addresses, and the rows it is named in.
    pub host: Option<HostId>,
    /// Rows of this kind.
    pub kind: Option<ReconcileKind>,
    /// Page size, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

fn invalid_filter(name: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_FILTER, 400, detail)
        .titled("Invalid list parameter")
        .param("name", name)
        .field(name, codes::INVALID_FILTER)
}

/// The view (see [`ReconcileQuery`]); `now` decides which facts are current.
///
/// # Errors
///
/// `ipam.not_found` for an unknown prefix or host, `ipam.invalid_filter` for a limit out of
/// range, `ipam.invalid_cursor` for a malformed cursor, store and decoding errors.
pub fn reconcile(
    view: &dyn ReadView,
    query: &ReconcileQuery,
    now: Timestamp,
) -> IpamResult<ReconcilePage> {
    reconcile_where(view, query, now, &|_| true)
}

/// [`reconcile`] with a further condition: only rows for which `keep` answers `true` count,
/// so a scoped reader gets full pages with valid cursors (IAM-01).
///
/// # Errors
///
/// As [`reconcile`].
pub fn reconcile_where(
    view: &dyn ReadView,
    query: &ReconcileQuery,
    now: Timestamp,
    keep: &dyn Fn(&ReconcileRow) -> bool,
) -> IpamResult<ReconcilePage> {
    let limit = match query.limit {
        None => DEFAULT_LIMIT,
        Some(limit) if (1..=MAX_LIMIT).contains(&limit) => limit,
        Some(limit) => {
            return Err(invalid_filter(
                "limit",
                format!("limit {limit} is outside 1 to {MAX_LIMIT}"),
            ));
        }
    };
    let after = query
        .cursor
        .as_deref()
        .map(|text| {
            from_hex(text)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| {
                    IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                        .titled("Invalid cursor")
                        .field("cursor", codes::INVALID_CURSOR)
                })
        })
        .transpose()?;
    let snapshot = Snapshot::load(view, now)?;
    let prefix = match query.prefix {
        Some(id) => Some(
            snapshot
                .intent
                .prefixes
                .get(&id)
                .cloned()
                .ok_or_else(|| IpamError::not_found(ObjectRef::from(id)))?,
        ),
        None => None,
    };
    let host = match query.host {
        Some(id) => Some(host_scope(&snapshot, id)?),
        None => None,
    };
    let all = build(view, &snapshot)?;
    let mut rows: Vec<ReconcileRow> = all
        .into_iter()
        .filter(|row| query.kind.is_none_or(|kind| row.kind == kind))
        .filter(|row| {
            prefix.as_ref().is_none_or(|prefix| {
                row.vrf.is_none_or(|vrf| vrf == prefix.vrf)
                    && contains_ip(&prefix.cidr, row.address)
            })
        })
        .filter(|row| host.as_ref().is_none_or(|host| host.admits(row)))
        .filter(|row| after.as_ref().is_none_or(|after| row.key > *after))
        .filter(|row| keep(row))
        .collect();
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = if more {
        rows.last().map(|row| to_hex(row.key.as_bytes()))
    } else {
        None
    };
    Ok(ReconcilePage {
        items: rows,
        next_cursor,
        revision: view.revision(),
        host: host.map(|host| host.truths(&snapshot)),
    })
}

/// The lease conflicts of IPAM-23 (the `conflict` rows of the view), for the health view.
///
/// # Errors
///
/// Store and decoding errors.
pub fn lease_conflicts(view: &dyn ReadView, now: Timestamp) -> IpamResult<Vec<ReconcileRow>> {
    let snapshot = Snapshot::load(view, now)?;
    let mut rows: Vec<ReconcileRow> = build(view, &snapshot)?
        .into_iter()
        .filter(|row| row.kind == ReconcileKind::Conflict)
        .collect();
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(rows)
}

/// A name as the view compares it: lowercase, without the trailing dot.
fn norm(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The sightings of one truth at one address.
#[derive(Debug, Default)]
struct Sightings {
    macs: BTreeSet<MacAddr>,
    sources: BTreeSet<String>,
    last_seen: Option<Timestamp>,
    expires_at: Option<Timestamp>,
}

impl Sightings {
    fn add(&mut self, fact: &ObservedFact, mac: Option<MacAddr>) {
        self.macs.extend(mac);
        self.sources.insert(fact.source_key.clone());
        self.last_seen = self.last_seen.max(Some(fact.last_seen));
        if let Some(expires) = fact.expires_at {
            self.expires_at = self.expires_at.max(Some(expires));
        }
    }

    fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    fn truth(&self) -> Option<ObservedTruth> {
        (!self.is_empty()).then(|| ObservedTruth {
            macs: self.macs.iter().copied().collect(),
            sources: self.sources.iter().cloned().collect(),
            last_seen: self.last_seen,
            expires_at: self.expires_at,
        })
    }
}

/// Everything the truths say about one address.
#[derive(Debug, Default)]
struct Picture {
    prefix: Option<PrefixId>,
    lease: Sightings,
    scan: Sightings,
    forward: BTreeSet<String>,
    ptr: BTreeSet<String>,
    zones: BTreeSet<String>,
    /// The address is abandoned on a conflict (WP8.5).
    abandoned: bool,
    /// The MAC address that answered the probe of an abandoned address, if ARP gave one.
    abandoned_mac: Option<MacAddr>,
}

impl Picture {
    fn macs(&self) -> BTreeSet<MacAddr> {
        let mut macs: BTreeSet<MacAddr> = self.lease.macs.union(&self.scan.macs).copied().collect();
        if let Some(mac) = self.abandoned_mac {
            macs.insert(mac);
        }
        macs
    }

    fn dns(&self) -> Option<DnsTruth> {
        (!(self.forward.is_empty() && self.ptr.is_empty())).then(|| DnsTruth {
            forward: self.forward.iter().cloned().collect(),
            ptr: self.ptr.iter().cloned().collect(),
            zones: self.zones.iter().cloned().collect(),
        })
    }

    /// The truth of the newest sighting.
    fn newest(&self) -> Option<(Truth, Timestamp)> {
        match (self.lease.last_seen, self.scan.last_seen) {
            (Some(lease), Some(scan)) if scan > lease => Some((Truth::Scan, scan)),
            (Some(lease), _) => Some((Truth::Lease, lease)),
            (None, Some(scan)) => Some((Truth::Scan, scan)),
            (None, None) => None,
        }
    }
}

/// The DHCP lease time that makes an unseen address of a network a ghost: the default
/// lease time of its enabled Tenko scope (the server's when the scope sets none).
fn scope_lease(
    view: &dyn ReadView,
    prefix: PrefixId,
    server: &DhcpSettings,
) -> IpamResult<Option<Duration>> {
    Ok(view
        .get_typed(&dhcp_tables::SCOPES, &prefix)?
        .map(|(scope, _)| scope)
        .filter(|scope| scope.enabled)
        .map(|scope| {
            Duration::from_secs(u64::from(scope.lease.unwrap_or(server.lease).default_secs))
        }))
}

/// The rows of the snapshot, unsorted.
#[allow(clippy::too_many_lines)] // One pass per list, in the order of the table above.
fn build(view: &dyn ReadView, snapshot: &Snapshot) -> IpamResult<Vec<ReconcileRow>> {
    let now = snapshot.now;
    let intent = &snapshot.intent;
    let mut pictures: BTreeMap<(VrfId, IpAddr), Picture> = BTreeMap::new();
    // MAC addresses seen anywhere by a current fact. A stopped host's configured address
    // is a dormant claim, not a sighting (`super::dormant`).
    let mut seen_macs: BTreeSet<MacAddr> = BTreeSet::new();
    for pair in snapshot.seen.iter().filter(|pair| !pair.dormant) {
        let fact = &snapshot.facts[pair.fact];
        seen_macs.extend(pair.mac);
        let (Some(ip), Some(placement)) = (pair.ip, pair.placement) else {
            continue;
        };
        let Some(vrf) = placement.vrf() else {
            continue;
        };
        let picture = pictures.entry((vrf, ip)).or_default();
        picture.prefix = picture.prefix.or(placement.prefix());
        match Truth::of(&fact.source) {
            Truth::Lease => picture.lease.add(fact, pair.mac),
            Truth::Scan => picture.scan.add(fact, pair.mac),
            Truth::Intent | Truth::Dns => {}
        }
    }
    // The zones' records: names, not sightings.
    for fact in snapshot.facts.iter().filter(|fact| fact.is_current(now)) {
        let (ObservationSource::DnsRecord { zone }, Observed::Name { ip, name, .. }) =
            (&fact.source, &fact.observed)
        else {
            continue;
        };
        if !trackable(*ip) {
            continue;
        }
        let placement = intent.place(*ip, None);
        let Some(vrf) = placement.vrf() else {
            continue;
        };
        let picture = pictures.entry((vrf, *ip)).or_default();
        picture.prefix = picture.prefix.or(placement.prefix());
        let zone = norm(zone.as_str());
        if zone.rsplit('.').next() == Some("arpa") {
            picture.ptr.insert(norm(name));
        } else {
            picture.forward.insert(norm(name));
        }
        picture.zones.insert(zone);
    }
    // The addresses the DHCP role abandoned on a conflict (WP8.5).
    for (_, lease, _) in
        view.scan_typed(&dhcp_tables::LEASES, KeyRange::all(), usize::MAX, false)?
    {
        let lease: Lease = lease;
        if lease.state != BindingState::Abandoned || lease.ends <= now {
            continue;
        }
        let ip = IpAddr::V4(lease.addr);
        let picture = pictures.entry((lease.vrf, ip)).or_default();
        picture.prefix = picture
            .prefix
            .or(intent.network_of(lease.vrf, ip).map(|prefix| prefix.id));
        picture.abandoned = true;
        picture.abandoned_mac = lease.client.mac().map(MacAddr::new);
    }

    let mut rows = Vec::new();
    let mut conflicted: BTreeSet<(VrfId, IpAddr)> = BTreeSet::new();
    for (&(vrf, ip), picture) in &pictures {
        let address = intent
            .address_by_ip
            .get(&(vrf, ip))
            .and_then(|id| intent.addresses.get(id));
        let held = address.and_then(|address| intent.host_of_address(address));
        let macs = picture.macs();

        // Conflicts: two MAC addresses, or an abandoned address.
        let owners: BTreeSet<HostId> = macs
            .iter()
            .flat_map(|mac| intent.interfaces_by_mac.get(mac).into_iter().flatten())
            .filter_map(|interface| intent.host_of(*interface).map(|host| host.id))
            .collect();
        let one_host = owners.len() == 1
            && macs
                .iter()
                .all(|mac| intent.interfaces_by_mac.contains_key(mac));
        if (macs.len() > 1 && !one_host) || picture.abandoned {
            conflicted.insert((vrf, ip));
            rows.push(row(
                snapshot,
                ReconcileKind::Conflict,
                vrf,
                ip,
                picture,
                address.map(|address| address.id),
                "",
                WinRule::NeverAutomatic,
                None,
                picture.newest().map(|(_, at)| at),
            ));
        }

        // Rogues: sightings without intent inside a network of intent.
        let known_mac = macs
            .iter()
            .any(|mac| intent.interfaces_by_mac.contains_key(mac));
        if !conflicted.contains(&(vrf, ip))
            && address.is_none()
            && !known_mac
            && picture.prefix.is_some()
            && let Some((_, newest)) = picture.newest()
        {
            let proposal = macs
                .iter()
                .find_map(|mac| snapshot.open.get(&format!("discovered_host/mac:{mac}")))
                .or_else(|| snapshot.open.get(&format!("discovered_host/ip:{vrf}/{ip}")))
                .map(|(proposal, _)| proposal.id);
            rows.push(row(
                snapshot,
                ReconcileKind::Rogue,
                vrf,
                ip,
                picture,
                None,
                "",
                WinRule::NewestSighting,
                proposal,
                Some(newest),
            ));
        }

        // Orphans: records of an address no host holds.
        if held.is_none() && !(picture.forward.is_empty() && picture.ptr.is_empty()) {
            let ptr_owner = norm(reverse::ptr_name(ip).as_str());
            let proposal = snapshot
                .open
                .values()
                .filter(|(proposal, _)| proposal.rule == rule::DNS_ORPHANED_RECORD)
                .find(|(proposal, _)| {
                    proposal
                        .subject
                        .name
                        .as_deref()
                        .map(norm)
                        .is_some_and(|name| picture.forward.contains(&name) || name == ptr_owner)
                })
                .map(|(proposal, _)| proposal.id);
            let rule_id = if proposal.is_some() {
                WinRule::OrphanRule
            } else {
                WinRule::ManualRecord
            };
            rows.push(row(
                snapshot,
                ReconcileKind::Orphan,
                vrf,
                ip,
                picture,
                address.map(|address| address.id),
                "",
                rule_id,
                proposal,
                picture.newest().map(|(_, at)| at),
            ));
        }

        // PTR mismatches: a PTR name that is not the address's name.
        if !picture.ptr.is_empty() {
            let intended = address
                .and_then(|address| address.dns_name.as_ref())
                .map(|name| norm(name.as_str()));
            let managed = held.is_some_and(|host| host.mode != AssignmentMode::Unmanaged);
            let (reference, rule_id): (BTreeSet<String>, WinRule) = match intended {
                Some(name) => (
                    BTreeSet::from([name]),
                    if managed {
                        WinRule::IntentManaged
                    } else {
                        WinRule::ForwardRecord
                    },
                ),
                None => (picture.forward.clone(), WinRule::ForwardRecord),
            };
            let wrong: Vec<&String> = picture
                .ptr
                .iter()
                .filter(|name| !reference.contains(*name))
                .collect();
            if !reference.is_empty() && !wrong.is_empty() {
                let discriminator = wrong
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                rows.push(row(
                    snapshot,
                    ReconcileKind::PtrMismatch,
                    vrf,
                    ip,
                    picture,
                    address.map(|address| address.id),
                    &discriminator,
                    rule_id,
                    None,
                    picture.newest().map(|(_, at)| at),
                ));
            }
        }
    }

    // Ghosts: intent nothing shows.
    let server: DhcpSettings = view
        .get_typed(&dhcp_tables::SETTINGS, &())?
        .map(|(settings, _)| settings)
        .unwrap_or_default();
    let orphan_after = settings::stored(view)?.map_or(Duration::from_secs(7 * 86_400), |(s, _)| {
        Duration::from_secs(s.orphan_after_secs)
    });
    for address in intent.addresses.values() {
        if address.status != Status::Active || !trackable(address.ip) {
            continue;
        }
        let Some(interface) = address.interface.and_then(|id| intent.interfaces.get(&id)) else {
            continue;
        };
        let Some(host) = intent.hosts.get(&interface.host) else {
            continue;
        };
        if host.mode == AssignmentMode::Unmanaged {
            continue;
        }
        let picture = pictures.get(&(address.vrf, address.ip));
        if picture.is_some_and(|picture| !(picture.lease.is_empty() && picture.scan.is_empty())) {
            continue;
        }
        if interface.mac.is_some_and(|mac| seen_macs.contains(&mac)) {
            continue;
        }
        let network = intent
            .network_of(address.vrf, address.ip)
            .map(|prefix| prefix.id);
        let lease = match network {
            Some(prefix) => scope_lease(view, prefix, &server)?,
            None => None,
        };
        if lease.is_none() && !snapshot.scanned(address.vrf, address.ip) {
            continue;
        }
        let threshold = lease.unwrap_or(orphan_after);
        let last = last_sighting(
            snapshot,
            address.vrf,
            address.ip,
            interface.mac,
            address.id,
            interface.id,
        );
        let since = last.unwrap_or(address.meta.created.at);
        if now.saturating_since(since) <= threshold {
            continue;
        }
        let rule_id = if host.mode == AssignmentMode::Dynamic {
            WinRule::LeaseDynamic
        } else {
            WinRule::IntentManaged
        };
        let empty = Picture {
            prefix: network,
            ..Picture::default()
        };
        rows.push(row(
            snapshot,
            ReconcileKind::Ghost,
            address.vrf,
            address.ip,
            picture.unwrap_or(&empty),
            Some(address.id),
            "",
            rule_id,
            None,
            last,
        ));
    }
    Ok(rows)
}

/// The latest sighting of an address or its interface's MAC address by any fact within
/// retention (current or not), or by the last sightings the reconciler keeps.
fn last_sighting(
    snapshot: &Snapshot,
    vrf: VrfId,
    ip: IpAddr,
    mac: Option<MacAddr>,
    address: AddressId,
    interface: InterfaceId,
) -> Option<Timestamp> {
    let facts = snapshot
        .facts
        .iter()
        .filter(|fact| {
            !matches!(
                fact.observed,
                Observed::Name { .. } | Observed::Vendor { .. } | Observed::Link { .. }
            )
        })
        .filter(|fact| {
            (fact.vrf().is_none_or(|own| own == vrf) && fact.ips().contains(&ip))
                || mac.is_some_and(|mac| fact.macs().contains(&mac))
        })
        .map(|fact| fact.last_seen);
    let kept = [ObjectRef::from(address), ObjectRef::from(interface)]
        .into_iter()
        .filter_map(|object| snapshot.sightings.get(&object))
        .map(|(sighting, _)| sighting.at);
    facts.chain(kept).max()
}

/// One row of the view.
#[allow(clippy::too_many_arguments)] // The parts of a row, each from its own list.
fn row(
    snapshot: &Snapshot,
    kind: ReconcileKind,
    vrf: VrfId,
    ip: IpAddr,
    picture: &Picture,
    address: Option<AddressId>,
    discriminator: &str,
    rule_id: WinRule,
    proposal: Option<ProposalId>,
    last_seen: Option<Timestamp>,
) -> ReconcileRow {
    let intent = &snapshot.intent;
    let address = address.and_then(|id| intent.addresses.get(&id));
    let interface = address
        .and_then(|address| address.interface)
        .and_then(|id| intent.interfaces.get(&id));
    let host = interface.and_then(|interface| intent.hosts.get(&interface.host));
    let intent_truth = address.map(|address| IntentTruth {
        address: Some(address.id),
        status: Some(address.status),
        host: host.map(|host| host.id),
        host_name: host.map(|host| host.name.to_string()),
        mode: host.map(|host| host.mode),
        macs: interface
            .and_then(|interface| interface.mac)
            .into_iter()
            .collect(),
        dns_name: address.dns_name.as_ref().map(ToString::to_string),
    });
    let mut macs = picture.macs();
    macs.extend(interface.and_then(|interface| interface.mac));
    let winner = match rule_id {
        WinRule::NewestSighting => picture.newest().map(|(truth, _)| truth),
        other => other.winner(),
    };
    let key = format!(
        "{:032x}/{vrf}/{}/{discriminator}",
        ip_to_u128(ip),
        kind.order()
    );
    ReconcileRow {
        key,
        kind,
        vrf: Some(vrf),
        address: ip,
        prefix: picture
            .prefix
            .or_else(|| intent.network_of(vrf, ip).map(|prefix| prefix.id)),
        host: host.map(|host| host.id),
        intent: intent_truth,
        lease: picture.lease.truth(),
        dns: picture.dns(),
        scan: picture.scan.truth(),
        os: os_guesses(snapshot, &BTreeSet::from([ip]), &macs)
            .into_iter()
            .next(),
        vendors: vendors(snapshot, &macs),
        macs: macs.into_iter().collect(),
        winner,
        rule_id,
        rule: rule_id.text().to_owned(),
        proposal,
        last_seen,
    }
}

/// Every current OS guess about the addresses and MAC addresses, by precedence: an
/// inventory's OS, then a probe's guess, then the DHCP fingerprint's; then by confidence,
/// the newer sighting and the source.
pub(crate) fn os_guesses(
    snapshot: &Snapshot,
    ips: &BTreeSet<IpAddr>,
    macs: &BTreeSet<MacAddr>,
) -> Vec<OsField> {
    let mut found: Vec<(u8, OsField)> = Vec::new();
    for fact in snapshot
        .facts
        .iter()
        .filter(|fact| fact.is_current(snapshot.now))
    {
        let field = |guess: &str, confidence: u8| OsField {
            guess: guess.trim().to_owned(),
            confidence: confidence.min(100),
            source: fact.source_key.clone(),
            truth: Truth::of(&fact.source),
            last_seen: fact.last_seen,
        };
        match &fact.observed {
            Observed::Host(host)
                if host.ips.iter().any(|ip| ips.contains(ip))
                    || host.macs.iter().any(|mac| macs.contains(mac)) =>
            {
                if let Some(os) = host.os.as_deref().filter(|os| !os.trim().is_empty()) {
                    found.push((0, field(os, 100)));
                }
            }
            Observed::Os {
                ip,
                guess,
                confidence,
            } if ips.contains(ip) && !guess.trim().is_empty() => {
                // A probe's active guess (`os_fingerprint`) outranks the DHCP fingerprint.
                let rank = if matches!(fact.source, ObservationSource::DhcpLease { .. }) {
                    2
                } else {
                    1
                };
                found.push((rank, field(guess, *confidence)));
            }
            _ => {}
        }
    }
    found.sort_by(|(rank_a, a), (rank_b, b)| {
        rank_a
            .cmp(rank_b)
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.source.cmp(&b.source))
    });
    found.into_iter().map(|(_, field)| field).collect()
}

/// The vendors current facts report for the MAC addresses, sorted.
fn vendors(snapshot: &Snapshot, macs: &BTreeSet<MacAddr>) -> Vec<String> {
    macs.iter()
        .filter_map(|mac| snapshot.vendors.get(mac))
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// What a host filter admits: the host's rows, addresses and MAC addresses.
struct HostScope {
    id: HostId,
    macs: BTreeSet<MacAddr>,
    addresses: BTreeSet<(VrfId, IpAddr)>,
}

fn host_scope(snapshot: &Snapshot, id: HostId) -> IpamResult<HostScope> {
    let intent = &snapshot.intent;
    if !intent.hosts.contains_key(&id) {
        return Err(IpamError::not_found(ObjectRef::from(id)));
    }
    let interfaces: Vec<_> = intent
        .interfaces
        .values()
        .filter(|interface| interface.host == id)
        .collect();
    let macs = interfaces
        .iter()
        .filter_map(|interface| interface.mac)
        .collect();
    let addresses = interfaces
        .iter()
        .flat_map(|interface| intent.addresses_of.get(&interface.id).into_iter().flatten())
        .filter_map(|address| intent.addresses.get(address))
        .map(|address| (address.vrf, address.ip))
        .collect();
    Ok(HostScope {
        id,
        macs,
        addresses,
    })
}

impl HostScope {
    fn admits(&self, row: &ReconcileRow) -> bool {
        row.host == Some(self.id)
            || row.macs.iter().any(|mac| self.macs.contains(mac))
            || row
                .vrf
                .is_some_and(|vrf| self.addresses.contains(&(vrf, row.address)))
    }

    fn truths(&self, snapshot: &Snapshot) -> HostTruths {
        let host = &snapshot.intent.hosts[&self.id];
        let ips: BTreeSet<IpAddr> = self.addresses.iter().map(|(_, ip)| *ip).collect();
        // The guesses name addresses: the host's own, and wherever a current fact sees one
        // of its MAC addresses (a pool lease of a host whose intent holds another address).
        let mut seen_at = ips.clone();
        seen_at.extend(
            snapshot
                .seen
                .iter()
                .filter(|pair| pair.mac.is_some_and(|mac| self.macs.contains(&mac)))
                .filter_map(|pair| pair.ip),
        );
        let guesses = os_guesses(snapshot, &seen_at, &self.macs);
        HostTruths {
            host: self.id,
            name: host.name.to_string(),
            mode: host.mode,
            macs: self.macs.iter().copied().collect(),
            ips: ips.iter().copied().collect(),
            os: guesses.first().cloned(),
            os_guesses: guesses,
            vendors: vendors(snapshot, &self.macs),
        }
    }
}
