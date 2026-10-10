//! The records and the views of the scan control: probe configurations, scan runs and
//! their diffs.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `scan.probe_config` | node id | [`ProbeConfigRecord`] |
//! | `scan.runs` | run id | [`ScanRun`] |
//! | `scan.run_baselines` | run id | [`Baseline`]: the facts of the target before the scan |
//! | `scan.scopes` | node id | `tenko_cluster::probe::ProbeScope` (written by the cluster port) |
//! | `scan.run_results` | (command id, batch sequence) | `tenko_cluster::node_sync::commands::RunResult` |

use std::{collections::BTreeMap, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_cluster::{node_sync::secrets::SecretUse, probe::ProbeScope};
use tenko_core::{
    HostId, JobId, NodeId, PrefixId, Timestamp, UserId, VrfId, observe::Observed, table::TableDef,
};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::config::ScanConfig;

/// The store tables of the scan control.
pub mod tables {
    use super::{Baseline, ProbeConfigRecord, ScanRun, TableDef, Uuid};

    /// The configuration the controllers hold for each probe, by node id. The name is the
    /// one the node sync streams (`tenko_cluster::node_sync::tables::PROBE_CONFIG`).
    pub const PROBE_CONFIG: TableDef<u64, ProbeConfigRecord> = TableDef::new("scan.probe_config");
    /// Scan runs on demand, by run id.
    pub const RUNS: TableDef<Uuid, ScanRun> = TableDef::new("scan.runs");
    /// The facts of a run's target from before the scan, by run id.
    pub const BASELINES: TableDef<Uuid, Baseline> = TableDef::new("scan.run_baselines");
}

/// Where a stored probe configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProbeConfigOrigin {
    /// An administrator set it through the API.
    Api,
    /// The probe offered its own `[scan]` section at its first connection.
    Offer,
}

/// The configuration the controllers hold for a probe (`scan.probe_config`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeConfigRecord {
    /// The probe.
    pub node: NodeId,
    /// The configuration; SNMP passwords only as vault secrets.
    pub config: ScanConfig,
    /// The vault secrets the configuration names, for `Config.Secrets` (the field every
    /// node configuration row may carry).
    #[serde(default)]
    pub secrets: Vec<SecretUse>,
    /// Where it came from.
    pub origin: ProbeConfigOrigin,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Who changed it last, when a person did.
    #[serde(default)]
    pub updated_by: Option<UserId>,
}

/// A probe's scan configuration as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProbeConfigView {
    /// The probe.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The configuration: the stored one, or the defaults when the controllers hold none
    /// (the probe then runs on its own `[scan]` section).
    pub config: ScanConfig,
    /// Whether the controllers hold a configuration for the probe.
    pub stored: bool,
    /// Where the stored configuration came from.
    #[serde(default)]
    pub origin: Option<ProbeConfigOrigin>,
    /// The revision of the stored configuration (the `ETag`).
    #[serde(default)]
    pub revision: Option<u64>,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<Timestamp>,
    /// Who changed it last.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub updated_by: Option<UserId>,
    /// What the probe last reported it applies.
    #[serde(default)]
    pub applied: Option<ProbeScope>,
    /// Whether the probe applies the stored configuration (its reported revision is at
    /// least the stored one).
    pub in_sync: bool,
    /// SNMP devices that still need a vault secret before they are polled, by address.
    #[serde(default)]
    pub lacking_secrets: Vec<String>,
    /// The probe's kill switch.
    pub kill_switch: KillSwitchView,
}

/// The kill switch of a probe: the last switch command from the controllers, else what the
/// probe reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KillSwitchView {
    /// Whether it is on (or asked to be on).
    pub stopped: bool,
    /// Why.
    #[serde(default)]
    pub reason: Option<String>,
    /// When it was switched from the controllers.
    #[serde(default)]
    pub at: Option<Timestamp>,
    /// Who switched it.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub by: Option<UserId>,
    /// Whether the probe confirmed the last switch command (false while it is offline).
    pub confirmed: bool,
}

/// A probe as the scan pages list it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProbeSummary {
    /// The node.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// Its name; the controller's own probe is called `controller-<id>`.
    pub name: String,
    /// Whether it is the probe role running inside a controller.
    pub in_process: bool,
    /// Whether the controllers hold a configuration for it.
    pub stored: bool,
    /// The revision of that configuration.
    #[serde(default)]
    pub revision: Option<u64>,
    /// What it last reported it applies.
    #[serde(default)]
    pub applied: Option<ProbeScope>,
    /// Whether it applies the stored configuration.
    pub in_sync: bool,
    /// Its kill switch.
    pub kill_switch: KillSwitchView,
}

/// What an on-demand scan does (SCAN-09).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    /// Neighbour tables, mDNS, LLMNR and reverse DNS.
    PassiveRefresh,
    /// A TCP connect scan of the configured ports.
    PortScan,
    /// SNMP polling of the configured switches.
    SnmpPoll,
    /// OS fingerprinting (needs raw sockets; reported as unavailable until it exists).
    OsFingerprint,
}

impl ScanKind {
    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ScanKind::PassiveRefresh => "passive_refresh",
            ScanKind::PortScan => "port_scan",
            ScanKind::SnmpPoll => "snmp_poll",
            ScanKind::OsFingerprint => "os_fingerprint",
        }
    }

    /// The methods of the kind, by name, in the order they run.
    pub const fn methods(self) -> &'static [&'static str] {
        match self {
            ScanKind::PassiveRefresh => &["arp", "nd", "mdns", "llmnr", "reverse_dns"],
            ScanKind::PortScan => &["tcp_connect"],
            ScanKind::SnmpPoll => &["snmp"],
            ScanKind::OsFingerprint => &["os_fingerprint"],
        }
    }
}

/// What kind of thing a scan covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanTargetKind {
    /// A prefix of the IPAM tree; the value is its id.
    Prefix,
    /// The addresses of a host; the value is its id.
    Host,
    /// One address (`192.0.2.10`).
    Address,
    /// A network that is not (or not yet) a prefix (`192.0.2.0/28`).
    Network,
}

/// What a scan covers: `{"kind": "prefix", "value": "<prefix id>"}`, `{"kind": "host",
/// "value": "<host id>"}`, `{"kind": "address", "value": "192.0.2.10"}` or `{"kind":
/// "network", "value": "192.0.2.0/28"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanTarget {
    /// The kind.
    pub kind: ScanTargetKind,
    /// The id, address or network.
    pub value: String,
}

/// A target, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A prefix.
    Prefix(PrefixId),
    /// A host.
    Host(HostId),
    /// An address.
    Address(IpAddr),
    /// A network.
    Network(IpNet),
}

impl ScanTarget {
    /// The target of a prefix.
    pub fn prefix(id: PrefixId) -> Self {
        Self {
            kind: ScanTargetKind::Prefix,
            value: id.to_string(),
        }
    }

    /// The target of a host.
    pub fn host(id: HostId) -> Self {
        Self {
            kind: ScanTargetKind::Host,
            value: id.to_string(),
        }
    }

    /// The target of an address.
    pub fn address(ip: IpAddr) -> Self {
        Self {
            kind: ScanTargetKind::Address,
            value: ip.to_string(),
        }
    }

    /// The target parsed; `None` when the value does not fit the kind.
    pub fn parse(&self) -> Option<Target> {
        let value = self.value.trim();
        Some(match self.kind {
            ScanTargetKind::Prefix => Target::Prefix(value.parse().ok()?),
            ScanTargetKind::Host => Target::Host(value.parse().ok()?),
            ScanTargetKind::Address => Target::Address(value.parse().ok()?),
            ScanTargetKind::Network => Target::Network(value.parse().ok()?),
        })
    }
}

/// `POST /scans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    /// What to scan.
    pub target: ScanTarget,
    /// What to do; `passive_refresh` when empty.
    #[serde(default)]
    pub kinds: Vec<ScanKind>,
    /// The VRF of an `address` or `network` target; the default VRF when absent. Prefix and
    /// host targets bring their own.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub vrf: Option<VrfId>,
    /// Seconds the job waits for the probes (30 to 3600, default 600).
    #[serde(default)]
    pub deadline_secs: Option<u32>,
}

/// The state of a scan run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    /// Waiting for the job runner.
    Queued,
    /// The probes work on it.
    Running,
    /// Every probe finished and its results are in; the diff is ready.
    Done,
    /// The deadline passed or some probes failed; the diff covers what arrived.
    Partial,
    /// No probe could run it.
    Failed,
    /// Cancelled with its job.
    Cancelled,
}

/// One probe's part of a scan run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunPart {
    /// The probe.
    pub node: NodeId,
    /// Its command.
    pub command: Uuid,
    /// The address or network inside the probe's scope it scans.
    pub target: String,
}

/// A scan run on demand (`scan.runs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRun {
    /// The run id.
    pub id: Uuid,
    /// The job that runs it.
    #[serde(default)]
    pub job: Option<JobId>,
    /// What was asked for.
    pub target: ScanTarget,
    /// The networks it resolved to.
    pub networks: Vec<IpNet>,
    /// Their VRF.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// What it does.
    pub kinds: Vec<ScanKind>,
    /// Who asked.
    #[serde(default)]
    pub requested_by: Option<UserId>,
    /// When.
    pub created_at: Timestamp,
    /// When the job stops waiting.
    pub deadline: Timestamp,
    /// The state.
    pub state: ScanState,
    /// The commands to the probes, once issued.
    #[serde(default)]
    pub parts: Vec<RunPart>,
    /// The diff, once the run ended.
    #[serde(default)]
    pub diff: Option<ScanDiff>,
    /// When it ended.
    #[serde(default)]
    pub finished_at: Option<Timestamp>,
    /// Why it failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// A fact as it was before a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFact {
    /// The source key (`probe:<node>:<method>`).
    pub source: String,
    /// The subject key.
    pub subject: String,
    /// The subject type.
    pub fact_type: String,
    /// What the source reported.
    pub observed: Observed,
    /// Whether it was current.
    pub current: bool,
}

/// The facts of a run's target before the scan (`scan.run_baselines`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// The facts, at most [`MAX_BASELINE`].
    pub facts: Vec<BaselineFact>,
    /// Whether more facts existed than were kept.
    #[serde(default)]
    pub truncated: bool,
}

/// Most facts kept as the baseline of a run.
pub const MAX_BASELINE: usize = 20_000;
/// Most changed facts a diff lists one by one.
pub const MAX_DIFF_ITEMS: usize = 5_000;

/// How a fact changed in a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FactChange {
    /// Seen for the first time.
    New,
    /// Seen with other attributes.
    Changed,
    /// Known before and not seen by the scan.
    Gone,
}

/// One changed fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiffItem {
    /// How it changed.
    pub change: FactChange,
    /// The fact type (`address`, `services`, `os`, `name`, `vendor`, `attachment`,
    /// `link`).
    pub fact_type: String,
    /// The subject key.
    pub subject: String,
    /// The source key (`probe:<node>:<method>`).
    pub source: String,
    /// Before the scan.
    #[serde(default)]
    pub before: Option<Observed>,
    /// What the scan saw.
    #[serde(default)]
    pub after: Option<Observed>,
}

/// The counts of one fact type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiffCounts {
    /// Seen for the first time.
    pub new: u32,
    /// Seen with other attributes.
    pub changed: u32,
    /// Seen as before.
    pub unchanged: u32,
    /// Known before and not seen.
    pub gone: u32,
}

/// What a scan found compared with the facts before it (SCAN-09).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ScanDiff {
    /// Counts per fact type.
    pub counts: BTreeMap<String, DiffCounts>,
    /// The new, changed and gone facts, at most [`MAX_DIFF_ITEMS`].
    pub items: Vec<DiffItem>,
    /// Whether the list or the baseline was cut.
    pub truncated: bool,
}

/// One probe's part of a scan as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProbeProgress {
    /// The probe.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The command.
    pub command: Uuid,
    /// The address or network it scans.
    pub target: String,
    /// The command's state: `pending`, `accepted`, `running`, `done`, `failed`,
    /// `rejected`, `expired`, `cancelled`.
    pub state: String,
    /// Percent done.
    pub progress: u8,
    /// The probe's last detail.
    #[serde(default)]
    pub detail: Option<String>,
    /// Batches the probe queued for it.
    #[serde(default)]
    pub batches: Option<u32>,
    /// Batches that arrived.
    pub ingested: u32,
}

/// A scan run as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ScanView {
    /// The run id.
    pub id: Uuid,
    /// The job that runs it (`GET /jobs/{id}`).
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub job_id: Option<JobId>,
    /// What was asked for.
    pub target: ScanTarget,
    /// The networks it resolved to.
    #[schema(value_type = Vec<String>)]
    pub networks: Vec<IpNet>,
    /// Their VRF.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub vrf: Option<VrfId>,
    /// What it does.
    pub kinds: Vec<ScanKind>,
    /// Who asked.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub requested_by: Option<UserId>,
    /// When.
    pub created_at: Timestamp,
    /// When the job stops waiting.
    pub deadline: Timestamp,
    /// The state.
    pub state: ScanState,
    /// Percent done over every probe.
    pub progress: u8,
    /// Every probe's part.
    pub probes: Vec<ProbeProgress>,
    /// The diff, once the run ended.
    #[serde(default)]
    pub diff: Option<ScanDiff>,
    /// When it ended.
    #[serde(default)]
    pub finished_at: Option<Timestamp>,
    /// Why it failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// The answer of a kill switch request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KillSwitchResult {
    /// The commands issued, one per probe.
    pub commands: Vec<KillSwitchCommand>,
}

/// One probe's kill switch command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KillSwitchCommand {
    /// The probe.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The command (`GET /scans` does not list it; the probe's scope report shows the
    /// switch).
    pub command: Uuid,
}

/// Body of `POST /nodes/{id}/scan/stop` and `POST /scans/stop`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    /// Why, recorded with the kill switch on the probe and in the audit log (at most 200
    /// characters).
    #[serde(default)]
    pub reason: Option<String>,
}
