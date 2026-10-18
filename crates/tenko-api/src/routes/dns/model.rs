//! Request and response bodies of the DNS routes (WP4.0 contracts; WP4.2, WP5.x and WP6.x
//! implement them). The stored model is `tenko_core::dns`; these types add the revision
//! of a read, leave out what a client never sees (secret references) and shape writes.

use serde::{Deserialize, Serialize};
use tenko_core::{
    JobId, NodeId, Revision, TenantId, Timestamp,
    dns::{
        Acl, AclEntry, BlockAction, BlockList, DnsKeyId, DnsName, DnssecAlgorithm, DnssecMode,
        DnssecPolicy, ForwardRule, ForwardTransport, KeyName, KeyRole, KeyState, ListFormat,
        ListSource, MatchRule, Origin, QueryTransport, RecordData, Rtype, ScopeName, ScopeWeight,
        SecondarySource, SerialPolicy, SoaDefaults, TransferPolicy, TsigAlgorithm, UpdatePolicy,
        Upstream, View, ViewId, Zone, ZoneId, ZoneKind, ZoneScope,
    },
    ipam::Stamp,
};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// A zone as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ZoneItem {
    /// The zone.
    #[serde(flatten)]
    pub zone: Zone,
    /// The SOA serial served now.
    pub soa_serial: u32,
    /// The number of RRsets in all scopes.
    pub rrsets: u64,
    /// The RRsets per origin, one entry for each origin present, sorted by origin; empty
    /// for an empty zone.
    pub origins: Vec<OriginCount>,
    /// The store revision of the zone row (the `ETag`).
    pub revision: Revision,
}

/// How many RRsets of a zone one origin owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OriginCount {
    /// The origin.
    pub origin: Origin,
    /// Its RRsets in all scopes.
    pub rrsets: u32,
}

/// `POST /dns/zones`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ZoneCreate {
    /// The apex.
    pub name: DnsName,
    /// What the zone is.
    pub kind: ZoneKind,
    /// The owning tenant.
    #[serde(default)]
    pub tenant: Option<TenantId>,
    /// Scopes besides `default`.
    #[serde(default)]
    pub scopes: Vec<ZoneScope>,
    /// How the serial moves; `date_counter` when absent.
    #[serde(default)]
    pub serial: Option<SerialPolicy>,
    /// The SOA values.
    pub soa: SoaDefaults,
    /// The name servers of the apex NS set; at least one for a primary zone.
    #[serde(default)]
    pub name_servers: Vec<DnsName>,
    /// Zone transfers and NOTIFY.
    #[serde(default)]
    pub transfer: Option<TransferPolicy>,
    /// Dynamic updates.
    #[serde(default)]
    pub update: Option<UpdatePolicy>,
    /// Signing.
    #[serde(default)]
    pub dnssec: Option<DnssecPolicy>,
    /// The servers of a secondary, stub or forward zone.
    #[serde(default)]
    pub source: Option<SecondarySource>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dns/zones/{id}`: the fields to change; the name and the kind do not change.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ZonePatch {
    /// The scopes, `default` included.
    #[serde(default)]
    pub scopes: Option<Vec<ZoneScope>>,
    /// How the serial moves.
    #[serde(default)]
    pub serial: Option<SerialPolicy>,
    /// The SOA values.
    #[serde(default)]
    pub soa: Option<SoaDefaults>,
    /// Zone transfers and NOTIFY.
    #[serde(default)]
    pub transfer: Option<TransferPolicy>,
    /// Dynamic updates.
    #[serde(default)]
    pub update: Option<UpdatePolicy>,
    /// Signing.
    #[serde(default)]
    pub dnssec: Option<DnssecPolicy>,
    /// The servers of a secondary, stub or forward zone.
    #[serde(default)]
    pub source: Option<SecondarySource>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

/// An RRset as the API reads and writes it: the records typed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RrSetItem {
    /// The zone scope.
    pub scope: ScopeName,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The TTL in seconds.
    pub ttl: u32,
    /// The records.
    pub records: Vec<RecordData>,
    /// Who owns the RRset.
    pub origin: Origin,
    /// The TSIG key of a dynamic update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyName>,
    /// The last change.
    pub updated: Stamp,
}

/// The filters of `GET /dns/zones/{id}/records`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecordFilters {
    /// The scope; `default` when absent.
    pub scope: Option<ScopeName>,
    /// Owner names starting with this prefix (`www`, `_ldap._tcp`).
    pub name: Option<String>,
    /// One type.
    #[serde(rename = "type")]
    #[param(rename = "type", value_type = Option<String>)]
    pub rtype: Option<Rtype>,
    /// One origin.
    pub origin: Option<Origin>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
    /// Items per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
}

/// What one change of a batch does to an RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordOp {
    /// Replace the RRset with these records (create it when absent).
    Set,
    /// Add these records to the RRset.
    Add,
    /// Remove these records from the RRset; an empty RRset is deleted.
    Remove,
    /// Delete the RRset.
    Delete,
}

/// One change of `POST /dns/zones/{id}/records/batch`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecordChange {
    /// What to do.
    pub op: RecordOp,
    /// The scope; `default` when absent.
    #[serde(default)]
    pub scope: Option<ScopeName>,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The TTL; the zone's default TTL when absent.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// The records of `set`, `add` and `remove`.
    #[serde(default)]
    pub records: Vec<RecordData>,
    /// The change may replace an RRset of another origin (`ipam`, `dynamic`, `dhcp`,
    /// `ad`); the result is then `manual`. Without it such a change is refused with 409
    /// `dns.record.origin`.
    #[serde(default)]
    pub take_over: Option<bool>,
}

/// `POST /dns/zones/{id}/records/batch`: changes applied together or not at all.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecordBatch {
    /// The changes, in order.
    pub changes: Vec<RecordChange>,
}

/// The query of the batch and import routes.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DryRunParams {
    /// Compute the diff without writing (API-09).
    #[serde(default)]
    pub dry_run: Option<bool>,
}

/// The diff of one RRset.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecordDiff {
    /// The scope.
    pub scope: ScopeName,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The RRset before; absent when it is new.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<RrSetItem>,
    /// The RRset after; absent when it is deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<RrSetItem>,
}

/// The answer of a batch: the diff, and after a write the new serial and revision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecordBatchResult {
    /// Nothing was written.
    pub dry_run: bool,
    /// The changed RRsets.
    pub changes: Vec<RecordDiff>,
    /// The serial after the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// The store revision of the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

/// `POST /dns/zones/{id}/records/import`: a zone file (RFC 1035 master format).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ZoneFileImport {
    /// The zone file text; `$ORIGIN` and `$TTL` are honoured, `$INCLUDE` is refused.
    pub zone_file: String,
    /// The scope to import into; `default` when absent.
    #[serde(default)]
    pub scope: Option<ScopeName>,
    /// Replace the scope's records (`true`) or merge into them (`false`).
    #[serde(default)]
    pub replace: bool,
}

/// One line of a zone file that the import could not take as it is.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportLoss {
    /// The line number, from 1.
    pub line: u32,
    /// The stable code of the problem.
    pub code: String,
    /// What was lost, in English.
    pub detail: String,
}

/// How many records of one type a zone file brings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportTypeCount {
    /// The record type.
    pub rtype: Rtype,
    /// The records of the type.
    pub records: u32,
}

/// The answer of an import: counts, losses, and after a write the serial and revision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ZoneFileImportReport {
    /// Nothing was written.
    pub dry_run: bool,
    /// RRsets added.
    pub added: u64,
    /// RRsets replaced.
    pub replaced: u64,
    /// RRsets removed (with `replace`).
    pub removed: u64,
    /// The records the file brings per type, sorted by type.
    pub types: Vec<ImportTypeCount>,
    /// What the import could not take.
    pub losses: Vec<ImportLoss>,
    /// The serial after the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// The store revision of the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

/// The query of `GET /dns/zones/{id}/records/export`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportParams {
    /// The scope; `default` when absent.
    pub scope: Option<ScopeName>,
}

/// A DNSSEC key without its private part.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnssecKeyItem {
    /// Identifier.
    pub id: DnsKeyId,
    /// KSK, ZSK or CSK.
    pub role: KeyRole,
    /// The algorithm.
    pub algorithm: DnssecAlgorithm,
    /// The key tag.
    pub key_tag: u16,
    /// The state.
    pub state: KeyState,
    /// The DNSKEY record.
    pub dnskey: RecordData,
    /// When the DNSKEY was published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<Timestamp>,
    /// When it started to sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<Timestamp>,
    /// When it stopped signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<Timestamp>,
}

/// `GET /dns/zones/{id}/dnssec`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnssecStatus {
    /// The zone.
    pub zone: ZoneId,
    /// Off, online or imported.
    pub mode: DnssecMode,
    /// The keys.
    pub keys: Vec<DnssecKeyItem>,
    /// The DS records for the parent (and the CDS published during a rollover).
    pub ds: Vec<RecordData>,
    /// The serial last signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_serial: Option<u32>,
    /// When the zone was last signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_signed: Option<Timestamp>,
    /// When the earliest signature expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
}

/// `POST /dns/zones/{id}/dnssec/rollover`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RolloverRequest {
    /// The role of the key to roll.
    pub role: KeyRole,
}

/// A request that started a job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsJobStarted {
    /// The job; follow it with `GET /jobs/{id}`.
    pub job_id: JobId,
}

/// The transfer state of one source server.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PrimaryState {
    /// The server.
    pub address: String,
    /// The last successful transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success: Option<Timestamp>,
    /// The stable code of the last failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// `GET /dns/zones/{id}/transfer`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransferStatus {
    /// The zone.
    pub zone: ZoneId,
    /// The serial held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// The sources of a secondary zone.
    pub primaries: Vec<PrimaryState>,
    /// The next refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_refresh: Option<Timestamp>,
    /// When the data expires without a successful refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    /// A transfer is running.
    pub running: bool,
}

/// A view as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ViewItem {
    /// The view.
    #[serde(flatten)]
    pub view: View,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/views`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ViewCreate {
    /// A unique name.
    pub name: String,
    /// The tests.
    #[serde(default)]
    pub rules: Vec<MatchRule>,
    /// The scopes per zone.
    #[serde(default)]
    pub scope_map: Vec<ScopeWeight>,
    /// The position, lower first.
    pub order: u32,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dns/views/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ViewPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The tests.
    #[serde(default)]
    pub rules: Option<Vec<MatchRule>>,
    /// The scopes per zone.
    #[serde(default)]
    pub scope_map: Option<Vec<ScopeWeight>>,
    /// The position.
    #[serde(default)]
    pub order: Option<u32>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// A forwarding rule as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ForwarderItem {
    /// The rule.
    #[serde(flatten)]
    pub rule: ForwardRule,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/forwarders`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ForwarderCreate {
    /// The names the rule covers; `.` for the default forwarder.
    pub suffix: DnsName,
    /// The upstreams.
    pub upstreams: Vec<Upstream>,
    /// How they are reached.
    #[serde(default)]
    pub transport: ForwardTransport,
    /// The certificate name of DoT and DoH upstreams.
    #[serde(default)]
    pub tls_name: Option<String>,
    /// The view the rule applies in.
    #[serde(default)]
    pub view: Option<ViewId>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dns/forwarders/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ForwarderPatch {
    /// The names the rule covers.
    #[serde(default)]
    pub suffix: Option<DnsName>,
    /// The upstreams.
    #[serde(default)]
    pub upstreams: Option<Vec<Upstream>>,
    /// How they are reached.
    #[serde(default)]
    pub transport: Option<ForwardTransport>,
    /// The certificate name; an empty string clears it.
    #[serde(default)]
    pub tls_name: Option<String>,
    /// The view the rule applies in.
    #[serde(default)]
    pub view: Option<ViewId>,
    /// Apply the rule in every view (clears `view`).
    #[serde(default)]
    pub all_views: bool,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

/// An access list as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AclItem {
    /// The list.
    #[serde(flatten)]
    pub acl: Acl,
    /// The zones and views that name it.
    pub used_by: Vec<String>,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/acls`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AclCreate {
    /// A unique name.
    pub name: String,
    /// The entries, in order.
    pub entries: Vec<AclEntry>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dns/acls/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct AclPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The entries.
    #[serde(default)]
    pub entries: Option<Vec<AclEntry>>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// A TSIG key without its secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyItem {
    /// Identifier.
    pub id: DnsKeyId,
    /// The key name.
    pub name: KeyName,
    /// The algorithm.
    pub algorithm: TsigAlgorithm,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation.
    pub created: Stamp,
}

/// `POST /dns/keys`: generate a TSIG key, or import one with its secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyCreate {
    /// The key name, as the peers know it.
    pub name: KeyName,
    /// The algorithm; `hmac-sha256` when absent.
    #[serde(default)]
    pub algorithm: Option<TsigAlgorithm>,
    /// The secret in base64 to import; generated when absent.
    #[serde(default)]
    pub secret: Option<String>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// The answer of `POST /dns/keys`: the secret is shown this once.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyCreated {
    /// The key.
    pub key: KeyItem,
    /// The secret in base64.
    pub secret: String,
}

/// The newest compiled version of a block list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListVersionItem {
    /// The version.
    pub revision: u64,
    /// How many names it blocks.
    pub entries: u64,
    /// When the source was read.
    pub fetched: Timestamp,
}

/// A block list as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListItem {
    /// The list.
    #[serde(flatten)]
    pub list: BlockList,
    /// The newest compiled version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<ListVersionItem>,
    /// The stable code of the last failed fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/lists`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListCreate {
    /// A unique name.
    pub name: String,
    /// Where it comes from.
    pub source: ListSource,
    /// The file format.
    pub format: ListFormat,
    /// How often a URL list is fetched, in hours.
    #[serde(default)]
    pub interval_hours: Option<u16>,
    /// What a blocked name answers.
    pub action: BlockAction,
    /// Whether it is applied; `true` when absent.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dns/lists/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ListPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// Where it comes from.
    #[serde(default)]
    pub source: Option<ListSource>,
    /// The file format.
    #[serde(default)]
    pub format: Option<ListFormat>,
    /// How often a URL list is fetched, in hours.
    #[serde(default)]
    pub interval_hours: Option<u16>,
    /// What a blocked name answers.
    #[serde(default)]
    pub action: Option<BlockAction>,
    /// Whether it is applied.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// A listener of a node's DNS role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListenerItem {
    /// The local address and port.
    pub address: String,
    /// The transport.
    pub transport: QueryTransport,
    /// Workers on it (UDP).
    pub workers: u16,
}

/// `GET /nodes/{id}/dns`: the DNS role of one node (the report `dns.status`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsNodeStatus {
    /// The node.
    pub node: NodeId,
    /// The role answers queries.
    pub serving: bool,
    /// The store revision the index holds.
    pub revision: Revision,
    /// How far the index is behind the store, in revisions.
    pub lag: u64,
    /// Zones served.
    pub zones: u32,
    /// RRsets served.
    pub rrsets: u64,
    /// Octets the bases of the index hold, a lower bound of its memory (the arrays and the
    /// record data, without allocator overhead and changes not yet folded into a base).
    #[serde(default)]
    pub index_bytes: u64,
    /// The listeners.
    pub listeners: Vec<ListenerItem>,
    /// Entries in the cache.
    pub cache_entries: u64,
    /// Octets the cache accounts for (keys, answers, bookkeeping), a lower bound of its
    /// memory.
    #[serde(default)]
    pub cache_bytes: u64,
    /// Answers from the cache since the role started.
    #[serde(default)]
    pub cache_hits: u64,
    /// Forwarded queries the cache could not answer since the role started.
    #[serde(default)]
    pub cache_misses: u64,
    /// The share of forwarded queries the cache answered, 0 to 1; absent before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_hit_ratio: Option<f64>,
    /// Stale answers (RFC 8767) since the role started.
    #[serde(default)]
    pub cache_stale: u64,
    /// What keeps the resolver side from working as configured: stub zones whose name
    /// servers could not be learnt, views whose recursion access list does not exist.
    #[serde(default)]
    pub problems: Vec<String>,
    /// When the role started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<Timestamp>,
    /// How the UDP workers use sockets: `reuseport` (a socket per worker) or `shared`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_mode: Option<String>,
    /// The UDP workers with their counters since the start (ADR 0009): uneven `received`
    /// counts across `reuseport` workers are the flow-hash effect.
    #[serde(default)]
    pub udp_workers: Vec<UdpWorkerItem>,
    /// Open TCP connections.
    #[serde(default)]
    pub tcp_open: u64,
    /// TCP connections refused by the per-node or per-client cap since the start.
    #[serde(default)]
    pub tcp_refused: u64,
    /// The node's query log; absent while it is off (`[dns.log]`, TGL-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_log: Option<QueryLogStatus>,
}

/// The query log of a node's DNS role: its settings and its counters since the start.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueryLogStatus {
    /// `on`, or `stopped` by the node command `dns.log.stop` (the kill switch).
    pub state: QueryLogState,
    /// `jsonl` or `dnstap`.
    pub format: String,
    /// What the log keeps of the client: `pseudonym`, `address` or `hidden`.
    pub client: String,
    /// One query in `sample` is logged.
    pub sample: u32,
    /// Days a file is kept.
    pub days: u32,
    /// MiB the files may take.
    pub size_mb: u64,
    /// Entries written since the role started.
    pub written: u64,
    /// Entries dropped since the role started: a full buffer or a failed write
    /// (`tenko_dns_log_dropped_total`).
    pub dropped: u64,
    /// Batches that could not be written since the role started.
    pub write_errors: u64,
}

/// The state of a node's query log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryLogState {
    /// Queries are logged.
    On,
    /// The kill switch is set: nothing is logged until `dns.log.start`.
    Stopped,
}

/// One UDP worker of a node's DNS role and its counters.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UdpWorkerItem {
    /// The worker's number, from 0.
    pub index: u32,
    /// The address its socket is bound to.
    pub listen: String,
    /// The socket of the address it reads (0 for the shared socket).
    pub socket: u32,
    /// Datagrams received.
    pub received: u64,
    /// Answers sent.
    pub sent: u64,
    /// Queries dropped.
    pub dropped: u64,
    /// Queries handed to the forwarder.
    pub forwarded: u64,
    /// Receive errors.
    pub recv_errors: u64,
    /// Send errors.
    pub send_errors: u64,
}

/// A node command that was recorded.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsCommandAccepted {
    /// The command.
    pub command_id: Uuid,
}

/// One line of a node's query log.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueryLogLine {
    /// When the query arrived.
    pub at: Timestamp,
    /// The client: its pseudonym (`p:` and hexadecimal digits), or its address when the log
    /// keeps addresses and the principal may update the node. Absent when the log keeps no
    /// client (`client = "hidden"`) or the address is withheld from the principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The transport.
    pub transport: QueryTransport,
    /// The query name.
    pub qname: String,
    /// The query type.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The RCODE answered.
    pub rcode: u16,
    /// The view that matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
    /// The list that blocked the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<tenko_core::dns::BlockListId>,
    /// Answered from the cache.
    pub cached: bool,
    /// Microseconds from arrival to answer.
    pub duration_micros: u32,
}

/// The query of `POST /nodes/{id}/dns/cache/flush`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CacheFlushParams {
    /// Flush only the names at or below this suffix (`example.test`); everything when
    /// absent.
    pub suffix: Option<String>,
}

/// The query of `GET /nodes/{id}/dns/log`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct QueryLogParams {
    /// The cursor of the next page (newest first).
    pub cursor: Option<String>,
    /// Lines per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
    /// Query names equal to this name or under it (`example.test` finds
    /// `www.example.test`, not `badexample.test`).
    pub qname: Option<String>,
    /// A client: its pseudonym, or its address (which needs the right to update the node).
    pub client: Option<String>,
    /// The RCODE answered (0 to 4095).
    pub rcode: Option<u16>,
    /// Queries that arrived at or after this time (RFC 3339).
    pub from: Option<Timestamp>,
    /// Queries that arrived at or before this time (RFC 3339).
    pub until: Option<Timestamp>,
}
