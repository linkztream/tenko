//! The records of the findings model: a finding, its severity, kind, subject, action and
//! area, and the counts.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{HostId, MacAddr, ObjectRef, PrefixId, Revision, Timestamp, VrfId};
use utoipa::ToSchema;

/// How much a finding needs a person: the severity of the findings model. Only `act` colors
/// the dashboard, the rail and the status bar; `info` is listed but never counted as a
/// problem.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingLevel {
    /// Act now: something is broken or waits for a person (a conflict, a job's manual step,
    /// a full network).
    Act,
    /// Review: a decision is open (an unknown device, an orphaned record, a PTR mismatch).
    Review,
    /// Information: listed where it lives, never counted as a problem.
    Info,
}

impl FindingLevel {
    /// Every level, the most urgent first.
    pub const ALL: [FindingLevel; 3] =
        [FindingLevel::Act, FindingLevel::Review, FindingLevel::Info];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingLevel::Act => "act",
            FindingLevel::Review => "review",
            FindingLevel::Info => "info",
        }
    }

    /// Whether a finding of this level counts as a problem.
    pub const fn is_problem(self) -> bool {
        !matches!(self, FindingLevel::Info)
    }
}

/// What a finding is about.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Two devices on one address, an address used by another device, one device in two
    /// networks, a DNS record IPAM cannot write (IPAM-23).
    Conflict,
    /// A job waits for a person at a manual step (IPAM-19).
    JobWaiting,
    /// A network's utilization is over its alarm threshold (IPAM-10).
    Utilization,
    /// A device no intent knows (IPAM-15).
    UnknownDevice,
    /// A DNS record no address of intent holds.
    OrphanedRecord,
    /// An address of intent no source has seen for the orphan age.
    OrphanedAddress,
    /// A PTR record whose name is not the address's name (IPAM-21).
    PtrMismatch,
    /// A device seen on an address other than its intent.
    IntentDiffers,
    /// An address outside every known network.
    OutsidePrefixes,
    /// A VLAN a network controller carries that IPAM does not know, or a prefix linked to
    /// another VLAN.
    Vlan,
    /// A host whose name the sources disagree with.
    HostName,
    /// Another suggestion of the DNS planner (a zone, a delegation, a reverse zone).
    Dns,
    /// An address of intent nothing has shown for longer than its lease time (IPAM-21).
    Ghost,
    /// A sighting of a network's edge address (network, broadcast or subnet-router anycast):
    /// an artifact of a scan, never a conflict.
    ScanArtifact,
    /// A health condition of the installation (`GET /system/status`).
    Health,
    /// The sources of the topology root disagree (UI-Q10): the controller's gateway and the
    /// next hop of the default route are different nodes.
    TopologyRoot,
    /// An IoT-classed host on a WLAN whose VLAN has no IoT role.
    WlanClass,
    /// A host's address outside the networks of its SSID's VLAN.
    WlanPrefix,
}

impl FindingKind {
    /// Every kind.
    pub const ALL: [FindingKind; 18] = [
        FindingKind::Conflict,
        FindingKind::JobWaiting,
        FindingKind::Utilization,
        FindingKind::UnknownDevice,
        FindingKind::OrphanedRecord,
        FindingKind::OrphanedAddress,
        FindingKind::PtrMismatch,
        FindingKind::IntentDiffers,
        FindingKind::OutsidePrefixes,
        FindingKind::Vlan,
        FindingKind::HostName,
        FindingKind::Dns,
        FindingKind::Ghost,
        FindingKind::ScanArtifact,
        FindingKind::Health,
        FindingKind::TopologyRoot,
        FindingKind::WlanClass,
        FindingKind::WlanPrefix,
    ];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingKind::Conflict => "conflict",
            FindingKind::JobWaiting => "job_waiting",
            FindingKind::Utilization => "utilization",
            FindingKind::UnknownDevice => "unknown_device",
            FindingKind::OrphanedRecord => "orphaned_record",
            FindingKind::OrphanedAddress => "orphaned_address",
            FindingKind::PtrMismatch => "ptr_mismatch",
            FindingKind::IntentDiffers => "intent_differs",
            FindingKind::OutsidePrefixes => "outside_prefixes",
            FindingKind::Vlan => "vlan",
            FindingKind::HostName => "host_name",
            FindingKind::Dns => "dns",
            FindingKind::Ghost => "ghost",
            FindingKind::ScanArtifact => "scan_artifact",
            FindingKind::Health => "health",
            FindingKind::TopologyRoot => "topology_root",
            FindingKind::WlanClass => "wlan_class",
            FindingKind::WlanPrefix => "wlan_prefix",
        }
    }
}

/// Where a finding comes from. Every source keeps its own records and routes; the findings
/// index only reads them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// An open proposal of the reconciler (`ipam.proposals`).
    Proposal,
    /// The utilization alarm of a prefix (`ipam.alarms`).
    Alarm,
    /// A row of the reconciliation view, derived from intent and observation.
    Reconcile,
    /// A job waiting for a person (`jobs.jobs`).
    Job,
    /// A health condition of `GET /system/status`.
    Health,
    /// The topology: its root and the WLAN rules, derived from the graph, the controllers'
    /// SSIDs and the stored decisions.
    Topology,
}

impl FindingSource {
    /// Every source.
    pub const ALL: [FindingSource; 6] = [
        FindingSource::Proposal,
        FindingSource::Alarm,
        FindingSource::Reconcile,
        FindingSource::Job,
        FindingSource::Health,
        FindingSource::Topology,
    ];

    /// The `snake_case` name, also the prefix of the finding identifiers.
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingSource::Proposal => "proposal",
            FindingSource::Alarm => "alarm",
            FindingSource::Reconcile => "reconcile",
            FindingSource::Job => "job",
            FindingSource::Health => "health",
            FindingSource::Topology => "topology",
        }
    }
}

/// The area of the UI a finding belongs to: the rail entry whose badge counts it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingArea {
    /// Networks, addresses, utilization, the reconciliation of addresses.
    Ipam,
    /// Zones and records.
    Dns,
    /// Scopes and leases.
    Dhcp,
    /// The proposals of the reconciler (the Discovery inbox).
    Discovery,
    /// The topology.
    Topology,
    /// Jobs.
    Jobs,
    /// Connectors.
    Connectors,
    /// Nodes, the cluster and the store.
    Nodes,
    /// Settings: security, certificates, keys, backup, audit export, updates.
    Settings,
}

impl FindingArea {
    /// Every area, in the order of the rail.
    pub const ALL: [FindingArea; 9] = [
        FindingArea::Ipam,
        FindingArea::Dns,
        FindingArea::Dhcp,
        FindingArea::Discovery,
        FindingArea::Topology,
        FindingArea::Jobs,
        FindingArea::Connectors,
        FindingArea::Nodes,
        FindingArea::Settings,
    ];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingArea::Ipam => "ipam",
            FindingArea::Dns => "dns",
            FindingArea::Dhcp => "dhcp",
            FindingArea::Discovery => "discovery",
            FindingArea::Topology => "topology",
            FindingArea::Jobs => "jobs",
            FindingArea::Connectors => "connectors",
            FindingArea::Nodes => "nodes",
            FindingArea::Settings => "settings",
        }
    }

    /// The area of a health condition by its code: `dns.*` is DNS, `dhcp.*` DHCP, `ipam.*`
    /// IPAM, `connect.*` the connectors, `cluster.*`, `store.*` and the leader services the
    /// nodes, everything else (TLS, keys, backup, audit export, updates) the settings.
    pub fn of_code(code: &str) -> Self {
        let head = code.split('.').next().unwrap_or_default();
        match head {
            "dns" => FindingArea::Dns,
            "dhcp" => FindingArea::Dhcp,
            "ipam" => FindingArea::Ipam,
            "scan" => FindingArea::Discovery,
            "connect" | "connector" => FindingArea::Connectors,
            "cluster" | "store" | "node" | "leader" => FindingArea::Nodes,
            "sys" if code.starts_with("sys.leader") || code.starts_with("sys.store") => {
                FindingArea::Nodes
            }
            _ => FindingArea::Settings,
        }
    }
}

/// What kind of object the subject of a finding is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// An IP address.
    Address,
    /// A host of intent.
    Host,
    /// A prefix or a network.
    Prefix,
    /// A DNS record or name.
    Record,
    /// A job.
    Job,
    /// A node or the installation.
    Node,
    /// A device known by its MAC address only.
    Device,
}

impl SubjectKind {
    /// Every subject kind.
    pub const ALL: [SubjectKind; 7] = [
        SubjectKind::Address,
        SubjectKind::Host,
        SubjectKind::Prefix,
        SubjectKind::Record,
        SubjectKind::Job,
        SubjectKind::Node,
        SubjectKind::Device,
    ];

    /// The `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SubjectKind::Address => "address",
            SubjectKind::Host => "host",
            SubjectKind::Prefix => "prefix",
            SubjectKind::Record => "record",
            SubjectKind::Job => "job",
            SubjectKind::Node => "node",
            SubjectKind::Device => "device",
        }
    }
}

/// The default action of a finding, which the UI maps to its button.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    /// Resolve a conflict: pick the device that stays (the Discovery page's conflict
    /// dialog).
    Resolve,
    /// Open the job's manual step.
    OpenManualStep,
    /// Open the prefix.
    OpenPrefix,
    /// Adopt the device or ignore it (approve or reject the proposal).
    Adopt,
    /// Delete the orphaned record, or give its address a host.
    DeleteRecord,
    /// Correct the PTR record or the forward record.
    FixPtr,
    /// Open the host.
    OpenHost,
    /// Decide the proposal (approve or reject).
    Decide,
    /// Decommission the host of a ghost address (`POST /hosts/{id}/decommission`).
    Decommission,
    /// Open the status of the installation.
    OpenStatus,
    /// Choose the root of the topology map: "Use this" per candidate
    /// (`PUT /topology/root`), remembered.
    UseRoot,
    /// Move the host to another network (the move flow of ADR 0027); "Keep on this WLAN"
    /// (`PUT /topology/ssids/{ssid}/exceptions/{host}`) is the other action.
    MoveHost,
    /// Nothing to do: the finding is listed for information.
    None,
}

/// The subject of a finding: what it is about, with the identities the filters and the
/// scope of a reader use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingSubject {
    /// What kind of object it is.
    pub kind: SubjectKind,
    /// The subject as text: an address, a host name, a network, a record name, a job kind, a
    /// MAC address or a health code.
    pub label: String,
    /// The VRF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfId>,
    /// The IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// The network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub cidr: Option<IpNet>,
    /// The MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The prefix the subject lies in, when the source names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<PrefixId>,
    /// The host of intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// The objects involved (hosts, addresses, prefixes, a job's targets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectRef>,
}

impl FindingSubject {
    /// A subject of `kind` named `label`, with no identities.
    pub fn new(kind: SubjectKind, label: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
            vrf: None,
            ip: None,
            cidr: None,
            mac: None,
            prefix: None,
            host: None,
            objects: Vec::new(),
        }
    }
}

/// The source's own view of a finding, by reference: the record the finding stands for and
/// the API path that reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingEvidence {
    /// The identifier of the source's record: a proposal, a prefix (its alarm), a job, the
    /// key of a reconciliation row, a health code.
    pub id: String,
    /// The path under `/api/v1` that answers the source's view, such as `/proposals/<id>`.
    pub path: String,
}

/// Anything Tenko noticed that a person may need to decide on, in one shape for every
/// source (the findings model). Derived from the sources on read and never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Finding {
    /// Stable identifier derived from the source's identifier: `proposal:<id>`,
    /// `alarm:<prefix>`, `job:<id>`, `reconcile:<digest of the row key>`,
    /// `health:<digest of the code and its parameters>`.
    pub id: String,
    /// What it is about.
    pub kind: FindingKind,
    /// How much it needs a person.
    pub severity: FindingLevel,
    /// The area of the UI it belongs to.
    pub area: FindingArea,
    /// The subject.
    pub subject: FindingSubject,
    /// English one-line summary.
    pub summary: String,
    /// The source's own code: a proposal's rule (`ipam.reconcile.discovered_mac`), a
    /// reconciliation kind (`ipam.reconcile.view.ghost`), an alarm level
    /// (`ipam.prefix.alarm.critical`), a job kind, a health code.
    pub code: String,
    /// Named parameters of the summary, for translation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// The source's own view, by reference.
    pub evidence: FindingEvidence,
    /// The default action.
    pub action: FindingAction,
    /// Since when it holds: a proposal's opening, an alarm's change, the start of a job's
    /// waiting step, the last sighting of a ghost, the first sighting of an artifact, the
    /// first time this controller saw a health condition.
    pub since: Timestamp,
    /// Where it comes from.
    pub source: FindingSource,
}

/// Findings of each severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LevelCounts {
    /// Findings to act on now.
    pub act: u64,
    /// Findings to review.
    pub review: u64,
    /// Findings for information, never counted as problems.
    pub info: u64,
}

impl LevelCounts {
    /// Adds one finding of `level`.
    pub fn add(&mut self, level: FindingLevel) {
        match level {
            FindingLevel::Act => self.act += 1,
            FindingLevel::Review => self.review += 1,
            FindingLevel::Info => self.info += 1,
        }
    }

    /// The problems: act and review.
    pub const fn problems(&self) -> u64 {
        self.act + self.review
    }
}

/// Findings of each severity per area, one member per area of the rail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AreaCounts {
    /// IPAM.
    pub ipam: LevelCounts,
    /// DNS.
    pub dns: LevelCounts,
    /// DHCP.
    pub dhcp: LevelCounts,
    /// Discovery (the proposals).
    pub discovery: LevelCounts,
    /// Topology.
    pub topology: LevelCounts,
    /// Jobs.
    pub jobs: LevelCounts,
    /// Connectors.
    pub connectors: LevelCounts,
    /// Nodes.
    pub nodes: LevelCounts,
    /// Settings.
    pub settings: LevelCounts,
}

impl AreaCounts {
    /// The counts of one area.
    pub fn of_mut(&mut self, area: FindingArea) -> &mut LevelCounts {
        match area {
            FindingArea::Ipam => &mut self.ipam,
            FindingArea::Dns => &mut self.dns,
            FindingArea::Dhcp => &mut self.dhcp,
            FindingArea::Discovery => &mut self.discovery,
            FindingArea::Topology => &mut self.topology,
            FindingArea::Jobs => &mut self.jobs,
            FindingArea::Connectors => &mut self.connectors,
            FindingArea::Nodes => &mut self.nodes,
            FindingArea::Settings => &mut self.settings,
        }
    }

    /// The counts of one area.
    pub fn of(&self, area: FindingArea) -> LevelCounts {
        let mut copy = *self;
        *copy.of_mut(area)
    }
}

/// Findings of each source, every severity included.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SourceCounts {
    /// Open proposals: equal to the open proposals `GET /proposals?state=open` lists.
    pub proposal: u64,
    /// Prefixes over their alarm threshold.
    pub alarm: u64,
    /// Rows of the reconciliation view and scan artifacts not covered by a proposal.
    pub reconcile: u64,
    /// Jobs waiting for a person.
    pub job: u64,
    /// Health conditions.
    pub health: u64,
    /// The topology's root and WLAN findings.
    #[serde(default)]
    pub topology: u64,
}

impl SourceCounts {
    /// Adds one finding of `source`.
    pub fn add(&mut self, source: FindingSource) {
        match source {
            FindingSource::Proposal => self.proposal += 1,
            FindingSource::Alarm => self.alarm += 1,
            FindingSource::Reconcile => self.reconcile += 1,
            FindingSource::Job => self.job += 1,
            FindingSource::Health => self.health += 1,
            FindingSource::Topology => self.topology += 1,
        }
    }
}

/// `GET /findings/counts`: the counts every surface reads (the rail badges, the status bar,
/// the dashboard), so that a count never differs between two screens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingCounts {
    /// Every finding by severity.
    pub total: LevelCounts,
    /// The problems: act and review (info is never counted).
    pub problems: u64,
    /// By area.
    pub areas: AreaCounts,
    /// By source, every severity included.
    pub sources: SourceCounts,
    /// The store revision the index has applied.
    #[schema(value_type = u64)]
    pub revision: Revision,
}

impl FindingCounts {
    /// Adds one finding.
    pub fn add(&mut self, finding: &Finding) {
        self.total.add(finding.severity);
        self.areas.of_mut(finding.area).add(finding.severity);
        self.sources.add(finding.source);
        if finding.severity.is_problem() {
            self.problems += 1;
        }
    }
}

/// Settings of the findings index: `[ipam.findings]` of the configuration file. Keep them
/// equal on every controller, so that each counts the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FindingsConfig {
    /// How long a ghost address may stay unseen as information before it becomes a finding to
    /// review with the action "Decommission" (86,400 to 31,536,000 seconds; 30 days by
    /// default).
    pub ghost_review_after_secs: u64,
    /// The shortest interval between two refreshes of the findings derived from the
    /// reconciliation view after the intent or the observations changed (5 to 3,600
    /// seconds; 30 by default). The view is also refreshed once a minute, for the findings
    /// that age with time.
    pub reconcile_refresh_secs: u64,
}

/// The default of [`FindingsConfig::ghost_review_after_secs`]: 30 days.
pub const GHOST_REVIEW_AFTER_SECS: u64 = 30 * 86_400;

impl Default for FindingsConfig {
    fn default() -> Self {
        Self {
            ghost_review_after_secs: GHOST_REVIEW_AFTER_SECS,
            reconcile_refresh_secs: 30,
        }
    }
}

impl FindingsConfig {
    /// The ghost ageing as a duration.
    pub const fn ghost_review_after(&self) -> Duration {
        Duration::from_secs(self.ghost_review_after_secs)
    }

    /// The refresh interval as a duration.
    pub const fn reconcile_refresh(&self) -> Duration {
        Duration::from_secs(self.reconcile_refresh_secs)
    }

    /// Checks the bounds.
    ///
    /// # Errors
    ///
    /// The English message of the first value outside its bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !(86_400..=31_536_000).contains(&self.ghost_review_after_secs) {
            return Err(
                "ipam.findings.ghost_review_after_secs must be between 86400 and 31536000"
                    .to_owned(),
            );
        }
        if !(5..=3_600).contains(&self.reconcile_refresh_secs) {
            return Err(
                "ipam.findings.reconcile_refresh_secs must be between 5 and 3600".to_owned(),
            );
        }
        Ok(())
    }
}
