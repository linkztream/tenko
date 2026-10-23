//! Request and response bodies of the DNS routes (WP4.0 contracts; WP4.2, WP5.x and WP6.x
//! implement them). The stored model is `tenko_core::dns`; these types add the revision
//! of a read, leave out what a client never sees (secret references) and shape writes.

use serde::{Deserialize, Serialize};
use tenko_core::{
    JobId, NodeId, Revision, TenantId, Timestamp,
    dns::{
        Acl,
        AclEntry,
        AclId,
        // WP10.0
        AnchorState,
        BlockAction,
        BlockList,
        DnsKeyId,
        DnsName,
        DnssecAlgorithm,
        DnssecMode,
        DnssecPolicy,
        ForwardRule,
        ForwardTransport,
        KeyName,
        KeyRole,
        KeyState,
        ListFormat,
        ListKind,
        ListSource,
        MatchRule,
        NegativeTrustAnchor,
        Origin,
        QueryTransport,
        RecordData,
        ResolutionMode,
        Rtype,
        RuleMode,
        ScopeName,
        ScopeWeight,
        SecondarySource,
        SecurityState,
        SerialPolicy,
        SoaDefaults,
        TransferPolicy,
        TrustAnchor,
        TsigAlgorithm,
        UpdatePolicy,
        Upstream,
        View,
        ViewId,
        Zone,
        ZoneId,
        ZoneKind,
        ZoneScope,
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
    /// A catalog zone (RFC 9432): on a secondary zone its members become secondary zones;
    /// on a primary zone Tenko writes the members. False when absent.
    #[serde(default)]
    pub catalog: bool,
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
    /// Whether the zone is a catalog zone (RFC 9432).
    #[serde(default)]
    pub catalog: Option<bool>,
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
    // WP6.3: the timer, the rollover and the findings.
    /// When the signer renews signatures next (for an imported zone, when it reads their
    /// expiry again).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_resign: Option<Timestamp>,
    /// The key rollover that runs; follow it with `GET /jobs/{id}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_job: Option<JobId>,
    /// The health findings of the zone (OPS-09): `dns.dnssec.clock_skew`,
    /// `dns.dnssec.expiring`, `dns.dnssec.resign_overdue`, `dns.dnssec.expired`.
    pub findings: Vec<DnssecFinding>,
}

/// A health finding of a signed zone.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnssecFinding {
    /// The code.
    pub code: String,
    /// What is wrong, in English.
    pub detail: String,
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
    // WP10.4: the profile's resolution beside the view's own.
    /// The resolution the view follows when `resolution` is absent: the profile's default
    /// (`recurse` under every profile; a node whose resolver is off forwards instead).
    pub profile_resolution: ResolutionMode,
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
    /// The position, from 1; the views from there move one down, and a position past the
    /// end is the end.
    pub order: u32,
    /// The access list of the clients that may recurse (WP6.4); the profile's default when
    /// absent.
    #[serde(default)]
    pub recursion: Option<AclId>,
    // WP10.0: how the view resolves names outside the zones and the rules.
    /// How the view's clients get names outside the zones and the forwarding rules; the
    /// profile's default when absent.
    #[serde(default)]
    pub resolution: Option<ResolutionMode>,
    // WP10.0: end.
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
    /// The position, from 1; the other views move to make room.
    #[serde(default)]
    pub order: Option<u32>,
    /// The access list of the clients that may recurse (WP6.4).
    #[serde(default)]
    pub recursion: Option<AclId>,
    /// Follow the profile's default for recursion (clears `recursion`, WP6.4).
    #[serde(default)]
    pub default_recursion: bool,
    // WP10.0: how the view resolves names outside the zones and the rules.
    /// How the view's clients get names outside the zones and the forwarding rules.
    #[serde(default)]
    pub resolution: Option<ResolutionMode>,
    /// Follow the profile's default for the resolution (clears `resolution`).
    #[serde(default)]
    pub default_resolution: bool,
    // WP10.0: end.
    /// Free text; an empty string clears it.
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
    // dns-visibility: the upstreams' figures.
    /// The rule's upstreams with their round-trip times and state on the node that
    /// answers (in the list and on a read), when it runs the DNS role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<Vec<UpstreamFigures>>,
}

/// `POST /dns/forwarders`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ForwarderCreate {
    /// The names the rule covers; `.` for the default forwarder.
    pub suffix: DnsName,
    // WP10.0: a recurse rule names no upstream.
    /// The upstreams, 1 to 16; none for a rule of mode `recurse`.
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    /// Forward to the upstreams (the default) or resolve the names under the suffix
    /// iteratively from the root servers (`recurse`: no upstreams, no transport, no
    /// `tls_name`, validation on).
    #[serde(default)]
    pub mode: Option<RuleMode>,
    /// Validate the upstreams' answers with DNSSEC (the default); `false` relays them
    /// unvalidated (TGL-12).
    #[serde(default)]
    pub validate: Option<bool>,
    // WP10.0: end.
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
    // WP10.0: the rule's mode and validation.
    /// Forward to the upstreams or resolve the names under the suffix iteratively. A rule
    /// turned to `recurse` must drop its upstreams in the same change (`upstreams: []`).
    #[serde(default)]
    pub mode: Option<RuleMode>,
    /// Validate the upstreams' answers with DNSSEC; `false` relays them unvalidated.
    #[serde(default)]
    pub validate: Option<bool>,
    // WP10.0: end.
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
    /// How many names it holds (after duplicates and names under a listed name).
    pub entries: u64,
    /// When the source was read.
    pub fetched: Timestamp,
    /// The HTTP entity tag of the fetched source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Octets of the compiled form.
    #[serde(default)]
    pub bytes: u64,
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
    /// The stable code of the last failed fetch or compile (`dns.list.fetch_failed`,
    /// `dns.list.invalid`, `dns.list.upload_missing`); the list keeps its version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// English detail of the last failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_detail: Option<String>,
    /// When the last fetch or compile ran on this controller (a fetch that found the source
    /// unchanged included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked: Option<Timestamp>,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/lists`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListCreate {
    /// A unique name.
    pub name: String,
    /// `block` (the default) or `allow`.
    #[serde(default)]
    pub kind: Option<ListKind>,
    /// Where it comes from.
    pub source: ListSource,
    /// The file format.
    pub format: ListFormat,
    /// How often a URL list is fetched, in hours.
    #[serde(default)]
    pub interval_hours: Option<u16>,
    /// What a blocked name answers; NXDOMAIN when absent (an allow list blocks nothing).
    #[serde(default)]
    pub action: Option<BlockAction>,
    /// Whether it is applied; `true` when absent.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Clients exempt from the list (at most 1,000 prefixes); an allow list exempts them
    /// from every list and RPZ zone.
    #[schema(value_type = Vec<String>, example = json!(["192.0.2.10/32"]))]
    #[serde(default)]
    pub exempt: Vec<String>,
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
    /// `block` or `allow`.
    #[serde(default)]
    pub kind: Option<ListKind>,
    /// Where it comes from; a new source or format drops the list's versions.
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
    /// The exempt client prefixes, replaced whole.
    #[schema(value_type = Option<Vec<String>>)]
    #[serde(default)]
    pub exempt: Option<Vec<String>>,
    /// Free text; an empty string clears it.
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
    /// Queries blocked since the role started, per enabled block list and RPZ zone, by
    /// name.
    #[serde(default)]
    pub blocked: Vec<BlockedCountItem>,
    // dns-visibility: the upstreams' figures and the pause of the block lists.
    /// The upstreams of the default forwarder, of every forwarding rule and of the stub
    /// zones, with their round-trip times and states.
    #[serde(default)]
    pub upstreams: Vec<UpstreamGroupItem>,
    /// The pause of the block lists in force, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_paused: Option<BlockingPause>,
}

/// The queries one block list or RPZ zone blocked since the node's role started.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockedCountItem {
    /// The list's name, or the RPZ zone's name.
    pub list: String,
    /// Queries blocked.
    pub count: u64,
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
    // WP10.1: how the answer was found and what the recursive resolver asked for it.
    /// How the answer was found: `zone`, `cache`, `denial`, `stale`, `forward`, `recurse`,
    /// `local`, `policy` or `refused`; absent in lines written before it was logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    /// Queries the recursive resolver sent to authorities for the answer; 0 (and left out)
    /// when it sent none.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub subqueries: u16,
    // WP10.1: end.
    // WP10.2: the validation state and the extended error.
    /// The DNSSEC state of the answer: `secure`, `insecure`, `bogus`, `indeterminate` or
    /// `unvalidated`; absent when nothing validated it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<SecurityState>,
    /// The extended DNS error code the answer carried (RFC 8914); absent for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ede: Option<u16>,
    // WP10.2: end.
}

// WP10.1: the default of `subqueries` is left out of a line.
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde's signature")]
fn is_zero(value: &u16) -> bool {
    *value == 0
}
// WP10.1: end.

/// The query of `POST /nodes/{id}/dns/cache/flush`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CacheFlushParams {
    /// Flush only the names at or below this suffix (`example.test`); everything when
    /// absent.
    pub suffix: Option<String>,
}

// cache-browse: the listing of a node's cache.
/// The query of `GET /nodes/{id}/dns/cache`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DnsCacheParams {
    /// Only the names equal to this name or under it (`example.test` finds
    /// `www.example.test`, not `badexample.test`).
    pub suffix: Option<String>,
    /// Only one view: its identifier, or `default` for the entries asked outside any view.
    pub view: Option<String>,
    /// Entries per page, 1 to 1000; 200 by default.
    pub limit: Option<u32>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
}

/// One entry of a node's DNS cache: the answer to one question in one view.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsCacheEntry {
    /// The name asked.
    pub name: String,
    /// The type asked.
    #[serde(rename = "type")]
    pub rtype: Rtype,
    /// The view the entry belongs to; absent for the entries asked outside any view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
    /// The RCODE of the cached answer: 0 (NOERROR, with records or NODATA) or 3 (NXDOMAIN).
    pub rcode: u16,
    /// Seconds the entry stays fresh; 0 once it is stale.
    pub ttl: u32,
    /// Expired but within the stale window: it answers only when the upstreams fail
    /// (RFC 8767).
    pub stale: bool,
    /// Answers from the entry since it was stored.
    pub hits: u32,
    // WP10.0: the validation state (recursion plan section 2.2); the DO and CD bits are no
    // longer part of the cache key.
    /// The validation state: `secure`, `insecure`, `bogus`, `indeterminate`, or
    /// `unvalidated` when nothing validated the answer.
    pub state: SecurityState,
    /// The extended DNS error (RFC 8914) a bogus entry is answered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ede: Option<u16>,
    /// The earliest expiry of the signatures that made the entry secure; the entry lives
    /// no longer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_expiry: Option<Timestamp>,
    // WP10.0: end.
    /// The records of the answer section, in the order received; empty for a negative
    /// answer.
    pub records: Vec<RecordData>,
}
// cache-browse: end.

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

// dns-visibility: the upstreams' figures and the blocking view.
/// The state of an upstream on the node that answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStateItem {
    /// Not asked yet.
    Unknown,
    /// The last exchange was answered.
    Up,
    /// Failing, not yet in back-off.
    Degraded,
    /// In back-off after three failures in a row: asked only when every other upstream is.
    Down,
}

/// One upstream with its round-trip times and state on the node that answers (since its
/// DNS role started).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamFigures {
    /// `address:port`.
    pub upstream: String,
    /// The transport.
    pub transport: ForwardTransport,
    /// The state.
    pub state: UpstreamStateItem,
    /// The upstream the next query of the rule goes to (one query in 16 probes another).
    pub chosen: bool,
    /// The round-trip time of the last answer, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rtt_ms: Option<f64>,
    /// The smoothed round-trip time (an EWMA with weight 1/8, the one the choice uses), in
    /// milliseconds; it doubles with each failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ewma_ms: Option<f64>,
    /// The median round-trip time of the answers of the last minute, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<f64>,
    /// The 99th percentile of the round-trip times of the answers of the last minute, in
    /// milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    /// The answers the quantiles look at (at most the last 512 of the minute).
    pub window_answers: u32,
    /// Failures in a row.
    pub failures: u32,
    /// Answered exchanges since the role started.
    pub answered: u64,
    /// Exchanges that timed out, could not reach the upstream or got a malformed answer.
    pub failed: u64,
    /// The last failure, in English.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the last failure happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<Timestamp>,
}

/// The upstreams of one forwarding rule, of the default forwarder of the configuration or of
/// a stub zone.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamGroupItem {
    /// The forwarding rule; absent for the default forwarder (`[dns] forwarders`) and stub
    /// zones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<tenko_core::dns::ForwardRuleId>,
    /// The stub zone whose name servers these are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stub: Option<ZoneId>,
    /// The `rule` label of the metrics: the rule's suffix, `default`, or `stub:` and the
    /// zone.
    pub label: String,
    /// The upstreams in the rule's order.
    pub upstreams: Vec<UpstreamFigures>,
}

/// A pause of the block lists in force.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingPause {
    /// When it started.
    pub since: Timestamp,
    /// When it ends; absent while it lasts until resumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
}

/// The window of `GET /dns/blocking/stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum BlockingWindow {
    /// The last 24 hours.
    #[default]
    #[serde(rename = "24h")]
    Day,
    /// The last 7 days (as far as the query log keeps them).
    #[serde(rename = "7d")]
    Week,
}

/// The query of `GET /dns/blocking/stats`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BlockingStatsParams {
    /// `24h` (the default) or `7d`.
    #[param(value_type = Option<String>)]
    pub window: Option<BlockingWindow>,
    /// The length of each top list, 1 to 100; 10 by default.
    pub top: Option<u32>,
}

/// The queries of one hour.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingHour {
    /// The start of the hour.
    pub start: Timestamp,
    /// Queries.
    pub queries: u64,
    /// Of them blocked by a block list.
    pub blocked: u64,
}

/// The queries one block list blocked in the window.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingListCount {
    /// The list.
    pub list: tenko_core::dns::BlockListId,
    /// Its name; absent for a list deleted since.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Queries blocked.
    pub blocked: u64,
}

/// A query name with its counts in the window.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingNameCount {
    /// The query name.
    pub name: String,
    /// Queries.
    pub queries: u64,
    /// Of them blocked.
    pub blocked: u64,
}

/// A client with its counts in the window.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingClientCount {
    /// The client as the log keeps it: a pseudonym (`p:` and hexadecimal digits, one per
    /// client and day), or its address when the log keeps addresses and the principal may
    /// update the node; absent when withheld.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The DNS name IPAM records for the address, when the address is shown and known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Queries.
    pub queries: u64,
    /// Of them blocked.
    pub blocked: u64,
}

/// `GET /dns/blocking/stats`: the queries of a window of the node's query log, blocked and
/// answered.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingStats {
    /// The node whose log was read.
    pub node: NodeId,
    /// The window.
    pub window: BlockingWindow,
    /// Its start.
    pub from: Timestamp,
    /// Its end (now).
    pub until: Timestamp,
    /// Days the log keeps (`[dns.log] days`): a 7-day window of a log that keeps fewer
    /// covers that many.
    pub log_days: u32,
    /// What the log keeps of the client: `pseudonym`, `address` or `hidden`.
    pub log_client: String,
    /// One query in `log_sample` is logged; the counts are of the logged queries.
    pub log_sample: u32,
    /// Queries logged in the window.
    pub queries: u64,
    /// Of them blocked by a block list.
    pub blocked: u64,
    /// Of them answered from the cache.
    pub cached: u64,
    /// The share blocked, 0 to 1; absent without a query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_share: Option<f64>,
    /// Distinct clients (a pseudonym counts once per day).
    pub clients: u64,
    /// The queries per hour, oldest first.
    pub hours: Vec<BlockingHour>,
    /// The blocked queries per block list, the busiest first.
    pub lists: Vec<BlockingListCount>,
    /// The names blocked most often.
    pub top_blocked: Vec<BlockingNameCount>,
    /// The names asked most often.
    pub top_names: Vec<BlockingNameCount>,
    /// The clients that asked most often.
    pub top_clients: Vec<BlockingClientCount>,
    /// The newest blocked queries, newest first (at most 50), for allow from the log.
    pub recent_blocked: Vec<QueryLogLine>,
    /// The pause of the block lists in force, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<BlockingPause>,
    /// The log held more in the window than one read looks at (512 MiB): the figures
    /// cover the newest part.
    pub truncated: bool,
}

/// `POST /dns/blocking/pause`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct BlockingPauseRequest {
    /// Minutes the pause lasts, 1 to 1440 (the UI offers 5, 15 and 60); absent until
    /// resumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minutes: Option<u32>,
}

/// The answer of `POST /dns/blocking/pause` and `DELETE /dns/blocking/pause`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingPauseState {
    /// The node whose block lists were paused or resumed.
    pub node: NodeId,
    /// The pause in force; absent after a resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<BlockingPause>,
    /// The node command that did it.
    pub command_id: Uuid,
}

/// `POST /dns/blocking/allow`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingAllowRequest {
    /// The name to allow (and the names under it).
    pub name: DnsName,
    /// The allow list to add it to: an uploaded allow list. Absent: the list `allowed`,
    /// created the first time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<tenko_core::dns::BlockListId>,
}

/// The answer of `POST /dns/blocking/allow`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockingAllowed {
    /// The allow list.
    pub list: tenko_core::dns::BlockListId,
    /// Its name.
    pub list_name: String,
    /// The list was created for this name.
    pub created: bool,
    /// The list covered the name already: nothing changed.
    pub already: bool,
    /// The compile job that writes the list's next version; absent when nothing changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobId>,
}
// dns-visibility: end.

// WP10.0: the recursive resolver (recursion plan section 3.4): trust anchors, negative trust
// anchors and the node's recursion status and infrastructure cache.
/// A trust anchor as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TrustAnchorItem {
    /// The trust anchor of the zone with its keys and their RFC 5011 state.
    #[serde(flatten)]
    pub anchor: TrustAnchor,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/trust-anchors`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TrustAnchorAdd {
    /// The zone; `.` for the root.
    pub zone: DnsName,
    /// A DS record's data in presentation form (`20326 8 2 E06D44B8...`): key tag,
    /// algorithm, digest type and the digest in hexadecimal. Exactly one of `ds` and
    /// `dnskey` is given.
    #[serde(default)]
    pub ds: Option<String>,
    /// A DNSKEY record's data in presentation form (`257 3 8 AwEAAa...`): flags, protocol,
    /// algorithm and the key in base64. Exactly one of `ds` and `dnskey` is given.
    #[serde(default)]
    pub dnskey: Option<String>,
    /// Replace the root's trust anchor with this key instead of adding to it. Allowed only
    /// under the Lab profile (`dns.trust_anchor.root_protected` otherwise).
    #[serde(default)]
    pub replace_root: bool,
}

/// A negative trust anchor as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NtaItem {
    /// The negative trust anchor.
    #[serde(flatten)]
    pub nta: NegativeTrustAnchor,
    /// The store revision of the row.
    pub revision: Revision,
}

/// `POST /dns/ntas`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NtaCreate {
    /// The zone; never the root. Names at or below it are `insecure` instead of `bogus`
    /// while the anchor lives.
    pub zone: DnsName,
    /// When it stops applying, at most seven days ahead. Absent: seven days from now,
    /// which the Hardened profile refuses (`dns.nta.invalid`).
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
    /// Why it exists, 1 to 500 characters.
    pub reason: String,
}

/// The last priming of a node's resolver.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PrimingItem {
    /// When the priming ended.
    pub at: Timestamp,
    /// `ok`, or `failed` when no server of the root hints answered.
    pub outcome: String,
    /// How long the priming took, in milliseconds.
    pub duration_ms: f64,
}

/// One root server of a node's resolver with its smoothed round-trip time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RootServerItem {
    /// The server's name (`a.root-servers.net.`).
    pub name: String,
    /// The address in use.
    pub address: String,
    /// The smoothed round-trip time in milliseconds; absent before the first answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srtt_ms: Option<f64>,
}

/// The sizes of a node's infrastructure cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct InfraSizes {
    /// Zone cuts held.
    pub zones: u64,
    /// The most zone cuts the cache holds; the least recently used go first.
    pub max_zones: u64,
    /// Authority server addresses held.
    pub servers: u64,
    /// The most server addresses the cache holds.
    pub max_servers: u64,
    /// Server names held.
    pub names: u64,
    // WP10.2: the validator's key sets.
    /// Zones whose validated key sets the validator holds beside the cuts; 0 with
    /// validation off.
    #[serde(default)]
    pub validated_zones: u64,
    /// The most such zones.
    #[serde(default)]
    pub max_validated_zones: u64,
}

/// What a node's resolver did since the role started.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct RecursionCounters {
    /// Client queries answered by recursion.
    pub answered: u64,
    /// Client queries answered SERVFAIL.
    pub servfail: u64,
    /// Client queries that ran out of budget.
    pub budget: u64,
    /// Client queries that timed out.
    pub timeout: u64,
    /// Client queries answered from local data.
    pub local: u64,
    /// Client queries answered SERVFAIL from the failure cache without asking an authority.
    pub failure_cache_hits: u64,
    /// Client queries joined to a resolution of the same question already in flight.
    pub joined: u64,
    /// Queries sent to authorities, sub-queries for name server addresses included.
    pub subqueries: u64,
    /// Resolutions that hit the bound on queries sent.
    pub budget_queries: u64,
    /// Resolutions that hit the bound on CNAME and DNAME restarts.
    pub budget_restarts: u64,
    /// Resolutions that hit the bound on the depth of name server address lookups.
    pub budget_depth: u64,
    /// Resolutions that hit the wall clock bound.
    pub budget_time: u64,
    /// Primings that succeeded.
    pub primings_ok: u64,
    /// Primings that failed.
    pub primings_failed: u64,
    /// Answers dropped as unwanted (wrong source, port, identifier or question) across the
    /// authority servers.
    pub unwanted: u64,
    /// Flushes of the answer cache that an excess of unwanted answers caused.
    pub unwanted_flushes: u64,
    /// Answers validated `secure`.
    pub secure: u64,
    /// Answers validated `insecure`.
    pub insecure: u64,
    /// Answers validated `bogus`.
    pub bogus: u64,
    /// Answers for which no trust anchor applied (`indeterminate`).
    pub indeterminate: u64,
}

/// The work budget one resolution runs under.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct RecursionBudget {
    /// The most queries sent to authorities for one client query, sub-queries included.
    pub queries: u32,
    /// The most CNAME and DNAME restarts.
    pub restarts: u32,
    /// The deepest level of name server address lookups.
    pub depth: u32,
    /// Attempts per server before the next one.
    pub attempts: u32,
    /// The wall clock bound of one resolution, in milliseconds.
    pub wall_ms: u64,
}

/// One key of a trust anchor in the node's status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AnchorKeyState {
    /// The zone.
    pub zone: DnsName,
    /// The key tag.
    pub key_tag: u16,
    /// The key's RFC 5011 state.
    pub state: AnchorState,
}

/// `GET /nodes/{id}/dns/recursion`: the recursive resolver of a node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecursionStatus {
    /// The resolver runs on the node.
    pub enabled: bool,
    /// Where the root hints come from: `shipped` or the path of the file.
    pub hints_source: String,
    /// The date of the hints (`2026-01-31`).
    pub hints_date: String,
    /// The last priming; absent before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_priming: Option<PrimingItem>,
    /// Seconds until the root's NS set expires and the next priming is due; absent before the
    /// first priming.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_expires_secs: Option<u64>,
    /// The root servers in use with their smoothed round-trip times.
    pub root_servers: Vec<RootServerItem>,
    /// The sizes of the infrastructure cache against their bounds.
    pub infra: InfraSizes,
    /// The work budget in force.
    pub budget: RecursionBudget,
    /// The counters since the role started.
    pub counters: RecursionCounters,
    /// The keys of the trust anchors with their RFC 5011 state and source.
    pub trust_anchors: Vec<AnchorKeyState>,
    /// What is wrong now: `priming_failed`, `clock` (the root's DNSKEY signatures fail
    /// on time) and `trust_anchor_stale` (a zone without a trusted key left).
    pub problems: Vec<String>,
}

/// The query of `GET /nodes/{id}/dns/infra`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InfraParams {
    /// Only the zone cuts equal to this name or under it (`example.test` finds
    /// `www.example.test`, not `badexample.test`).
    pub suffix: Option<String>,
    /// Zone cuts per page, 1 to 1000; 200 by default.
    pub limit: Option<u32>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
}

/// The query of `POST /nodes/{id}/dns/infra/flush`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InfraFlushParams {
    /// Flush only the zone cuts at or below this suffix (`example.test`); everything when
    /// absent.
    pub suffix: Option<String>,
}

/// The answer of `POST /nodes/{id}/dns/infra/flush`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InfraFlushed {
    /// The zone cuts dropped.
    pub entries: u64,
}

/// One address of an authority server in the infrastructure cache.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the flags of one server address"
)]
pub struct InfraAddressItem {
    /// The address.
    pub address: String,
    /// Where the address was learned: `glue`, `sibling_glue` or `authoritative`.
    pub origin: String,
    /// Seconds the address stays valid.
    pub ttl: u32,
    /// The smoothed round-trip time in milliseconds; absent before the first answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srtt_ms: Option<f64>,
    /// The median round-trip time of the last minute in milliseconds; absent without
    /// answers in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<f64>,
    /// The 99th percentile of the round-trip time of the last minute in milliseconds;
    /// absent without answers in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    /// Failures in a row.
    pub failures: u32,
    /// The server is in back-off after failures and is not asked now.
    pub down: bool,
    /// Whether the server speaks EDNS; absent while unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns: Option<bool>,
    /// The server answers only over TCP.
    pub tcp_only: bool,
    /// The server is lame for the zone.
    pub lame: bool,
    /// The server is asked in lower case because it broke the 0x20 case randomisation.
    pub lower_case: bool,
    /// Unwanted answers from the server in the current hour.
    pub unwanted: u32,
}

/// One authority server of a zone cut with its addresses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InfraServerItem {
    /// The server's name.
    pub name: DnsName,
    /// Its addresses.
    pub addresses: Vec<InfraAddressItem>,
}

/// One zone cut of a node's infrastructure cache.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InfraCutItem {
    /// The zone the cut starts.
    pub zone: DnsName,
    /// Its authority servers.
    pub servers: Vec<InfraServerItem>,
    /// Whether the zone is signed: `unknown`, `secure`, `insecure` or `bogus`.
    pub ds: String,
    /// Seconds the cut stays valid.
    pub ttl: u32,
}
// WP10.0: end.
