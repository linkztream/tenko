//! CSV export in the import vocabulary (MIG-14, IPAM-11).
//!
//! Three files, one per entity, with the canonical target names of
//! [`Target`](crate::import::vocab::Target) as headers, so an export maps onto itself
//! when it is imported again:
//!
//! | File | Columns |
//! |---|---|
//! | `prefixes.csv` | `prefix`, `vrf`, `role`, `status`, `vlan`, `vlan_name`, `site`, `alarm_warn`, `alarm_crit`, `alloc`, `description`, `tags`, `custom.<key>`... |
//! | `hosts.csv` | `host`, `tenant`, `mode`, `lock`, `site`, `description`, `interfaces`, `tags`, `custom.<key>`... |
//! | `addresses.csv` | `address`, `vrf`, `status`, `dns_name`, `host`, `interface`, `mac`, `duid`, `description`, `tags`, `custom.<key>`... |
//!
//! The files are UTF-8 with a byte order mark (so Excel opens them as UTF-8), comma
//! separated, CRLF line ends. Credentials are never exported: the vault is not read.
//! Soft-deleted objects are left out. Rows come in the order of the uniqueness indexes
//! (VRF then network, VRF then address, tenant then host name), from one read view, in
//! chunks, so a large export streams without holding the whole file in memory.
//!
//! # Cells
//!
//! - Roles, statuses, modes and allocation policies are written in `snake_case`
//!   (`supernet`, `deprecated`, `reserved`, `highest`), `lock` as `true` or `false`.
//! - References are written as names: the VRF, tenant and site name, the VLAN id and name,
//!   and for an address assigned to an interface the host and interface name with the
//!   MAC address (lowercase, colon separated) and DUID of the interface.
//! - `tags` are joined with `; ` in tag order. A prefix without alarm leaves
//!   `alarm_warn` and `alarm_crit` empty.
//! - `interfaces` of a host lists its live interfaces sorted by name, joined with `; `:
//!   `name`, `name=mac`, `name=mac=duid` or, without a MAC address, `name==duid`.
//! - A `custom.<key>` column exists for every custom field whose definition applies to
//!   the entity of the file, sorted by key, after the fixed columns. Text, URLs and
//!   select options are written as they are, integers in decimal, booleans as `true` or
//!   `false` and dates as `YYYY-MM-DD`.
//!
//! # Spreadsheet formulas
//!
//! A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return would be read as
//! a formula by a spreadsheet. The export puts a single quote in front of such a cell
//! (`'=SUM(1)`), and the importer removes one leading quote that stands before one of
//! those characters. A value that already starts with quotes before one of those
//! characters gets one more, so the importer returns exactly what was exported. A negative
//! integer (`-5`) is a number and stays as it is.

use std::{collections::HashMap, fmt, hash::Hash, sync::Arc};

use bytes::Bytes;
use csv::{QuoteStyle, Terminator, WriterBuilder};
use tenko_core::{
    HostId, InterfaceId, ObjectKind, ObjectRef, SiteId, TableName, TenantId, VlanId, VrfId,
    codec::encode_key,
    ipam::{
        Address, AllocPolicy, AssignmentMode, FieldKey, Host, Interface, Meta, Prefix, PrefixRole,
        Site, Status, Tag, Tenant, Vlan, Vrf,
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use crate::{
    IpamError, IpamResult,
    custom::value_to_text,
    error::codes,
    import::vocab::Target,
    query,
    tables::{ADDRESS_IPS, CUSTOM_FIELDS, HOST_INTERFACES, HOST_NAMES, PREFIX_CIDRS},
};

/// The UTF-8 byte order mark at the start of every file.
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Separator of the items inside a tags or interfaces cell.
const ITEM_SEPARATOR: &str = "; ";

/// Which file to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportKind {
    /// `prefixes.csv`.
    Prefixes,
    /// `addresses.csv`.
    Addresses,
    /// `hosts.csv`.
    Hosts,
}

impl ExportKind {
    /// Every file of the export.
    pub const ALL: [ExportKind; 3] = [
        ExportKind::Prefixes,
        ExportKind::Addresses,
        ExportKind::Hosts,
    ];

    /// The file name: `prefixes.csv`, `addresses.csv` or `hosts.csv`.
    pub fn file_name(self) -> &'static str {
        match self {
            ExportKind::Prefixes => "prefixes.csv",
            ExportKind::Addresses => "addresses.csv",
            ExportKind::Hosts => "hosts.csv",
        }
    }

    /// The kind of object a row of the file describes (it selects the custom fields).
    fn object_kind(self) -> ObjectKind {
        match self {
            ExportKind::Prefixes => ObjectKind::Prefix,
            ExportKind::Addresses => ObjectKind::Address,
            ExportKind::Hosts => ObjectKind::Host,
        }
    }

    /// The uniqueness index the rows are read from, in file order.
    fn index(self) -> &'static TableName {
        match self {
            ExportKind::Prefixes => PREFIX_CIDRS.name(),
            ExportKind::Addresses => ADDRESS_IPS.name(),
            ExportKind::Hosts => HOST_NAMES.name(),
        }
    }

    /// The fixed columns, before the custom fields.
    fn fixed_columns(self) -> Vec<Target> {
        match self {
            ExportKind::Prefixes => vec![
                Target::Prefix,
                Target::Vrf,
                Target::Role,
                Target::Status,
                Target::Vlan,
                Target::VlanName,
                Target::Site,
                Target::AlarmWarn,
                Target::AlarmCrit,
                Target::Alloc,
                Target::Description,
                Target::Tags,
            ],
            ExportKind::Hosts => vec![
                Target::Name,
                Target::Tenant,
                Target::Mode,
                Target::Lock,
                Target::Site,
                Target::Description,
                Target::Interfaces,
                Target::Tags,
            ],
            ExportKind::Addresses => vec![
                Target::Address,
                Target::Vrf,
                Target::Status,
                Target::DnsName,
                Target::Name,
                Target::Interface,
                Target::Mac,
                Target::Duid,
                Target::Description,
                Target::Tags,
            ],
        }
    }
}

/// Streams one export file in chunks from one read view.
///
/// The first chunk starts with the UTF-8 byte order mark and the header line. Every call of
/// [`next_chunk`](CsvExport::next_chunk) reads at most [`CsvExport::CHUNK_ROWS`] objects
/// from the view, so the memory use does not depend on the size of the data.
pub struct CsvExport {
    view: Arc<dyn ReadView>,
    kind: ExportKind,
    chunk_rows: usize,
    /// The header line, written with the first chunk.
    header: Vec<String>,
    /// The custom fields with a column, sorted by key.
    custom: Vec<FieldKey>,
    /// Objects for which this answers `false` are left out (scoped readers, IAM-01).
    keep: Arc<dyn Fn(ObjectRef) -> bool + Send + Sync>,
    /// The last raw key of the uniqueness index that was exported.
    after: Option<Bytes>,
    /// Whether the first chunk (BOM and header) has been produced.
    started: bool,
    /// Whether the last chunk has been produced.
    finished: bool,
}

impl fmt::Debug for CsvExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsvExport")
            .field("file", &self.kind.file_name())
            .field("revision", &self.view.revision())
            .field("started", &self.started)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl CsvExport {
    /// Rows per chunk.
    pub const CHUNK_ROWS: usize = 1_000;

    /// Starts an export over `view` (one consistent snapshot).
    ///
    /// # Errors
    ///
    /// Returns the store error if the custom field definitions cannot be read.
    pub fn new(view: Arc<dyn ReadView>, kind: ExportKind) -> IpamResult<Self> {
        Self::with_chunk_rows(view, kind, Self::CHUNK_ROWS)
    }

    /// Starts an export that leaves out every object for which `keep` answers `false`, so a
    /// scoped reader exports only what it may read (IAM-01); the chunks stay bounded.
    ///
    /// # Errors
    ///
    /// As [`CsvExport::new`].
    pub fn with_filter(
        view: Arc<dyn ReadView>,
        kind: ExportKind,
        keep: Arc<dyn Fn(ObjectRef) -> bool + Send + Sync>,
    ) -> IpamResult<Self> {
        Self::build(view, kind, Self::CHUNK_ROWS, keep)
    }

    /// Starts an export with `chunk_rows` rows per chunk (at least one).
    fn with_chunk_rows(
        view: Arc<dyn ReadView>,
        kind: ExportKind,
        chunk_rows: usize,
    ) -> IpamResult<Self> {
        Self::build(view, kind, chunk_rows, Arc::new(|_| true))
    }

    fn build(
        view: Arc<dyn ReadView>,
        kind: ExportKind,
        chunk_rows: usize,
        keep: Arc<dyn Fn(ObjectRef) -> bool + Send + Sync>,
    ) -> IpamResult<Self> {
        let applies = kind.object_kind();
        let mut custom: Vec<FieldKey> = view
            .scan_typed(&CUSTOM_FIELDS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, definition, _)| definition)
            .filter(|definition| definition.applies_to.contains(&applies))
            .map(|definition| definition.key)
            .collect();
        custom.sort();
        custom.dedup();
        let header = kind
            .fixed_columns()
            .into_iter()
            .chain(custom.iter().cloned().map(Target::Custom))
            .map(|target| target.name())
            .collect();
        Ok(Self {
            view,
            kind,
            chunk_rows: chunk_rows.max(1),
            header,
            custom,
            keep,
            after: None,
            started: false,
            finished: false,
        })
    }

    /// The file name (`prefixes.csv`, `addresses.csv`, `hosts.csv`).
    pub fn file_name(&self) -> &'static str {
        self.kind.file_name()
    }

    /// The next chunk of bytes: the first chunk starts with the UTF-8 BOM and the header
    /// line; `None` after the last row. Each call reads at most [`CsvExport::CHUNK_ROWS`]
    /// objects.
    ///
    /// # Errors
    ///
    /// Returns the store or decoding error, or `ipam.not_found` if an object refers to one
    /// that does not exist. After an error the call can be repeated: it reads the same rows
    /// again.
    pub fn next_chunk(&mut self) -> IpamResult<Option<Vec<u8>>> {
        if self.finished {
            return Ok(None);
        }
        let range = match &self.after {
            Some(key) => KeyRange::all().after(key.clone()),
            None => KeyRange::all(),
        };
        let entries = self
            .view
            .scan(self.kind.index(), range, self.chunk_rows, false)?;
        if entries.is_empty() && self.started {
            self.finished = true;
            return Ok(None);
        }

        let mut out = Vec::new();
        if !self.started {
            out.extend_from_slice(&BOM);
        }
        let mut writer = WriterBuilder::new()
            .terminator(Terminator::CRLF)
            .quote_style(QuoteStyle::Necessary)
            .from_writer(out);
        if !self.started {
            writer
                .write_record(&self.header)
                .map_err(|error| encoding_failed(&error))?;
        }
        let mut lookups = Lookups::new(self.view.as_ref());
        for (_, indexed) in &entries {
            if let Some(row) = self.row(&mut lookups, indexed.value.as_ref())? {
                writer
                    .write_record(row.into_iter().map(escape_cell))
                    .map_err(|error| encoding_failed(&error))?;
            }
        }
        let chunk = writer
            .into_inner()
            .map_err(|error| encoding_failed(&error))?;

        self.started = true;
        self.finished = entries.len() < self.chunk_rows;
        self.after = entries.last().map(|(key, _)| key.clone());
        Ok(Some(chunk))
    }

    /// The cells of the object an index entry points at; `None` for a deleted object.
    fn row(&self, lookups: &mut Lookups<'_>, indexed: &[u8]) -> IpamResult<Option<Vec<String>>> {
        match self.kind {
            ExportKind::Prefixes => {
                let id = PREFIX_CIDRS.decode(indexed)?;
                if !(self.keep)(ObjectRef::from(id)) {
                    return Ok(None);
                }
                let prefix = query::get::<Prefix>(self.view.as_ref(), id)?;
                self.prefix_row(lookups, &prefix)
            }
            ExportKind::Addresses => {
                let id = ADDRESS_IPS.decode(indexed)?;
                if !(self.keep)(ObjectRef::from(id)) {
                    return Ok(None);
                }
                let address = query::get::<Address>(self.view.as_ref(), id)?;
                self.address_row(lookups, &address)
            }
            ExportKind::Hosts => {
                let id = HOST_NAMES.decode(indexed)?;
                if !(self.keep)(ObjectRef::from(id)) {
                    return Ok(None);
                }
                let host = query::get::<Host>(self.view.as_ref(), id)?;
                self.host_row(lookups, &host)
            }
        }
    }

    fn prefix_row(
        &self,
        lookups: &mut Lookups<'_>,
        prefix: &Prefix,
    ) -> IpamResult<Option<Vec<String>>> {
        if prefix.meta.is_deleted() {
            return Ok(None);
        }
        let (vlan_id, vlan_name) = match prefix.vlan {
            Some(vlan) => {
                let (vid, name) = lookups.vlan(vlan)?;
                (vid.to_string(), name.to_string())
            }
            None => (String::new(), String::new()),
        };
        let (warn, crit) = prefix.alarm.map_or_else(
            || (String::new(), String::new()),
            |alarm| (alarm.warn_pct.to_string(), alarm.crit_pct.to_string()),
        );
        let mut row = vec![
            prefix.cidr.to_string(),
            lookups.vrf(prefix.vrf)?.to_string(),
            role_name(prefix.role).to_owned(),
            status_name(prefix.status).to_owned(),
            vlan_id,
            vlan_name,
            lookups.optional_site(prefix.site)?,
            warn,
            crit,
            alloc_name(prefix.alloc).to_owned(),
            description_cell(&prefix.meta),
            tags_cell(&prefix.meta),
        ];
        self.push_custom(&mut row, &prefix.meta);
        Ok(Some(row))
    }

    fn host_row(&self, lookups: &mut Lookups<'_>, host: &Host) -> IpamResult<Option<Vec<String>>> {
        if host.meta.is_deleted() {
            return Ok(None);
        }
        let mut interfaces = lookups.interfaces_of(host.id)?;
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        let interfaces: Vec<String> = interfaces.iter().map(interface_cell).collect();
        let mut row = vec![
            host.name.to_string(),
            lookups.tenant(host.tenant)?.to_string(),
            mode_name(host.mode).to_owned(),
            host.lock.to_string(),
            lookups.optional_site(host.site)?,
            description_cell(&host.meta),
            interfaces.join(ITEM_SEPARATOR),
            tags_cell(&host.meta),
        ];
        self.push_custom(&mut row, &host.meta);
        Ok(Some(row))
    }

    fn address_row(
        &self,
        lookups: &mut Lookups<'_>,
        address: &Address,
    ) -> IpamResult<Option<Vec<String>>> {
        if address.meta.is_deleted() {
            return Ok(None);
        }
        let (host, interface, mac, duid) = match address.interface {
            Some(id) => {
                let interface = lookups.interface(id)?;
                (
                    lookups.host_name(interface.host)?.to_string(),
                    interface.name.clone(),
                    interface.mac.map(|mac| mac.to_string()).unwrap_or_default(),
                    interface
                        .duid
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                )
            }
            None => Default::default(),
        };
        let mut row = vec![
            address.ip.to_string(),
            lookups.vrf(address.vrf)?.to_string(),
            status_name(address.status).to_owned(),
            address
                .dns_name
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            host,
            interface,
            mac,
            duid,
            description_cell(&address.meta),
            tags_cell(&address.meta),
        ];
        self.push_custom(&mut row, &address.meta);
        Ok(Some(row))
    }

    /// Appends one cell per custom field column.
    fn push_custom(&self, row: &mut Vec<String>, meta: &Meta) {
        row.extend(
            self.custom
                .iter()
                .map(|key| meta.custom.get(key).map(value_to_text).unwrap_or_default()),
        );
    }
}

/// The whole file at once (tests, CLI).
///
/// # Errors
///
/// Returns the first error of [`CsvExport::next_chunk`].
pub fn export_csv(view: Arc<dyn ReadView>, kind: ExportKind) -> IpamResult<Vec<u8>> {
    let mut export = CsvExport::new(view, kind)?;
    let mut file = Vec::new();
    while let Some(chunk) = export.next_chunk()? {
        file.extend_from_slice(&chunk);
    }
    Ok(file)
}

/// A failure of the CSV encoder. Records of equal length written into memory cannot fail,
/// so this reports a broken invariant rather than bad data.
fn encoding_failed(error: &dyn fmt::Display) -> IpamError {
    IpamError::new(
        codes::JOB_FAILED,
        500,
        format!("the CSV export failed: {error}"),
    )
}

/// Protects a cell against being read as a formula by a spreadsheet.
///
/// A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading
/// quote. The importer removes one leading quote that stands before one of those
/// characters, so a cell that has quotes before such a character gets one more. A
/// negative integer is a number and stays as it is.
fn escape_cell(cell: String) -> String {
    let risky = cell
        .trim_start_matches('\'')
        .starts_with(['=', '+', '-', '@', '\t', '\r']);
    if !risky || (cell.starts_with('-') && cell.parse::<i64>().is_ok()) {
        return cell;
    }
    let mut escaped = String::with_capacity(cell.len() + 1);
    escaped.push('\'');
    escaped.push_str(&cell);
    escaped
}

fn description_cell(meta: &Meta) -> String {
    meta.description.clone().unwrap_or_default()
}

/// The tags in tag order, joined with `; `.
fn tags_cell(meta: &Meta) -> String {
    meta.tags
        .iter()
        .map(Tag::as_str)
        .collect::<Vec<_>>()
        .join(ITEM_SEPARATOR)
}

/// `name`, `name=mac`, `name=mac=duid` or `name==duid`.
fn interface_cell(interface: &Interface) -> String {
    match (interface.mac, &interface.duid) {
        (None, None) => interface.name.clone(),
        (Some(mac), None) => format!("{}={mac}", interface.name),
        (mac, Some(duid)) => format!(
            "{}={}={duid}",
            interface.name,
            mac.map(|mac| mac.to_string()).unwrap_or_default()
        ),
    }
}

fn role_name(role: PrefixRole) -> &'static str {
    match role {
        PrefixRole::Supernet => "supernet",
        PrefixRole::Network => "network",
    }
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Planned => "planned",
        Status::Active => "active",
        Status::Reserved => "reserved",
        Status::Deprecated => "deprecated",
    }
}

fn mode_name(mode: AssignmentMode) -> &'static str {
    match mode {
        AssignmentMode::Static => "static",
        AssignmentMode::Reserved => "reserved",
        AssignmentMode::Dynamic => "dynamic",
        AssignmentMode::Unmanaged => "unmanaged",
    }
}

fn alloc_name(policy: AllocPolicy) -> &'static str {
    match policy {
        AllocPolicy::Lowest => "lowest",
        AllocPolicy::Highest => "highest",
    }
}

/// Looks up the objects a row refers to, once per chunk and object.
struct Lookups<'v> {
    view: &'v dyn ReadView,
    vrfs: HashMap<VrfId, Arc<str>>,
    tenants: HashMap<TenantId, Arc<str>>,
    sites: HashMap<SiteId, Arc<str>>,
    vlans: HashMap<VlanId, (u16, Arc<str>)>,
    hosts: HashMap<HostId, Arc<str>>,
    interfaces: HashMap<InterfaceId, Arc<Interface>>,
}

/// The cached value of `key`, loaded with `load` on the first use.
fn cached<K: Copy + Eq + Hash, V: Clone>(
    cache: &mut HashMap<K, V>,
    key: K,
    load: impl FnOnce() -> IpamResult<V>,
) -> IpamResult<V> {
    if let Some(value) = cache.get(&key) {
        return Ok(value.clone());
    }
    let value = load()?;
    cache.insert(key, value.clone());
    Ok(value)
}

impl<'v> Lookups<'v> {
    fn new(view: &'v dyn ReadView) -> Self {
        Self {
            view,
            vrfs: HashMap::new(),
            tenants: HashMap::new(),
            sites: HashMap::new(),
            vlans: HashMap::new(),
            hosts: HashMap::new(),
            interfaces: HashMap::new(),
        }
    }

    fn vrf(&mut self, id: VrfId) -> IpamResult<Arc<str>> {
        let view = self.view;
        cached(&mut self.vrfs, id, || {
            Ok(Arc::from(query::get::<Vrf>(view, id)?.name))
        })
    }

    fn tenant(&mut self, id: TenantId) -> IpamResult<Arc<str>> {
        let view = self.view;
        cached(&mut self.tenants, id, || {
            Ok(Arc::from(query::get::<Tenant>(view, id)?.name))
        })
    }

    fn site(&mut self, id: SiteId) -> IpamResult<Arc<str>> {
        let view = self.view;
        cached(&mut self.sites, id, || {
            Ok(Arc::from(query::get::<Site>(view, id)?.name))
        })
    }

    /// The site name, or an empty cell without a site.
    fn optional_site(&mut self, id: Option<SiteId>) -> IpamResult<String> {
        id.map_or_else(
            || Ok(String::new()),
            |id| self.site(id).map(|name| name.to_string()),
        )
    }

    /// The VLAN id and name.
    fn vlan(&mut self, id: VlanId) -> IpamResult<(u16, Arc<str>)> {
        let view = self.view;
        cached(&mut self.vlans, id, || {
            let vlan = query::get::<Vlan>(view, id)?;
            Ok((vlan.vid, Arc::from(vlan.name)))
        })
    }

    fn host_name(&mut self, id: HostId) -> IpamResult<Arc<str>> {
        let view = self.view;
        cached(&mut self.hosts, id, || {
            Ok(Arc::from(query::get::<Host>(view, id)?.name.as_str()))
        })
    }

    fn interface(&mut self, id: InterfaceId) -> IpamResult<Arc<Interface>> {
        let view = self.view;
        cached(&mut self.interfaces, id, || {
            Ok(Arc::new(query::get::<Interface>(view, id)?))
        })
    }

    /// The live interfaces of a host, in index order.
    fn interfaces_of(&self, host: HostId) -> IpamResult<Vec<Interface>> {
        let mut live = Vec::new();
        for ((_, id), (), _) in self.view.scan_typed(
            &HOST_INTERFACES,
            KeyRange::prefix(encode_key(&host)),
            usize::MAX,
            false,
        )? {
            let interface = query::get::<Interface>(self.view, id)?;
            if !interface.meta.is_deleted() {
                live.push(interface);
            }
        }
        Ok(live)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use tenko_core::{
        AddressId, AuthStrength, HostId, InterfaceId, ObjectRef, PrefixId, Principal, RequestCtx,
        SessionId, SiteId, UserId, VlanId, VrfId,
        ipam::{CustomKind, CustomValue, UtilizationAlarm},
    };
    use tenko_store::{MemStore, Store};

    use super::*;
    use crate::{
        IpamCommand, IpamService, PlanOptions,
        command::{
            AddressInput, CustomFieldInput, HostInput, InterfaceInput, PrefixInput, SiteInput,
            VlanInput, VrfInput,
        },
        tables::VRFS,
    };

    const PREFIX_HEADER: &str = "prefix,vrf,role,status,vlan,vlan_name,site,alarm_warn,alarm_crit,\
         alloc,description,tags,custom.delta,custom.owner,custom.reviewed,custom.wiki";
    const HOST_HEADER: &str = "host,tenant,mode,lock,site,description,interfaces,tags,\
         custom.critical,custom.rack_unit,custom.tier";
    const ADDRESS_HEADER: &str = "address,vrf,status,dns_name,host,interface,mac,duid,\
         description,tags,custom.critical,custom.owner";

    const DUID_NTP_ETH0: &str = "00:01:00:01:2b:6d:8e:4a:00:00:5e:00:53:02";
    const DUID_NTP_ETH1: &str = "00:03:00:01:00:00:5e:00:53:03";

    // ----- data builders -----------------------------------------------------------------

    fn person() -> RequestCtx {
        RequestCtx::new(Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        })
    }

    fn service() -> Arc<IpamService> {
        IpamService::with_direct_jobs(Arc::new(MemStore::default()) as Arc<dyn Store>)
            .expect("service")
    }

    async fn run(service: &IpamService, commands: Vec<IpamCommand>) {
        service
            .execute(&commands, &person(), &PlanOptions::default())
            .await
            .expect("execute");
    }

    async fn snapshot(service: &IpamService) -> Arc<dyn ReadView> {
        service.view(None).await.expect("view")
    }

    fn tags(items: &[&str]) -> BTreeSet<Tag> {
        items
            .iter()
            .map(|tag| Tag::new(tag).expect("tag"))
            .collect()
    }

    fn custom(items: Vec<(&str, CustomValue)>) -> BTreeMap<FieldKey, CustomValue> {
        items
            .into_iter()
            .map(|(key, value)| (FieldKey::new(key).expect("key"), value))
            .collect()
    }

    fn text(value: &str) -> CustomValue {
        CustomValue::Text(value.to_owned())
    }

    fn field(key: &str, kind: CustomKind, applies_to: &[ObjectKind]) -> IpamCommand {
        IpamCommand::CreateCustomField(CustomFieldInput {
            id: None,
            key: FieldKey::new(key).expect("key"),
            kind,
            applies_to: applies_to.to_vec(),
            required: false,
        })
    }

    fn prefix(cidr: &str) -> PrefixInput {
        PrefixInput {
            id: Some(PrefixId::generate()),
            vrf: None,
            cidr: cidr.parse().expect("cidr"),
            role: None,
            status: None,
            vlan: None,
            site: None,
            alarm: None,
            alloc: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn address(ip: &str) -> AddressInput {
        AddressInput {
            id: Some(AddressId::generate()),
            vrf: None,
            ip: ip.parse().expect("ip"),
            status: None,
            interface: None,
            dns_name: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn interface(name: &str, mac: Option<&str>, duid: Option<&str>) -> InterfaceInput {
        InterfaceInput {
            id: Some(InterfaceId::generate()),
            host: None,
            name: name.to_owned(),
            mac: mac.map(|mac| mac.parse().expect("mac")),
            duid: duid.map(|duid| duid.parse().expect("duid")),
            client_id: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn host(name: &str, mode: AssignmentMode, interfaces: Vec<InterfaceInput>) -> HostInput {
        HostInput {
            id: Some(HostId::generate()),
            tenant: None,
            name: name.parse().expect("host name"),
            mode: Some(mode),
            lock: None,
            site: None,
            interfaces,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    /// The identifier of the interface of a host input.
    fn interface_of(host: &HostInput, name: &str) -> InterfaceId {
        host.interfaces
            .iter()
            .find(|interface| interface.name == name)
            .and_then(|interface| interface.id)
            .expect("interface")
    }

    /// What the fixture deleted.
    struct Fixture {
        service: Arc<IpamService>,
        old_host: HostId,
        old_address: AddressId,
        old_free_address: AddressId,
        old_prefix: PrefixId,
    }

    /// A small network with every kind of cell once, and deleted objects that must not
    /// show up.
    #[allow(clippy::too_many_lines)] // One command list; splitting it would hide the data.
    async fn fixture() -> Fixture {
        let service = service();
        let site = SiteId::generate();
        let vlan = VlanId::generate();

        let mut nas = host(
            "nas01",
            AssignmentMode::Static,
            vec![
                interface("eth1", None, None),
                interface("eth0", Some("00:00:5e:00:53:01"), None),
            ],
        );
        nas.lock = Some(true);
        nas.site = Some(site);
        nas.tags = tags(&["core"]);
        nas.description = Some("Main NAS".to_owned());
        nas.custom = custom(vec![
            ("rack_unit", CustomValue::Integer(42)),
            ("critical", CustomValue::Boolean(true)),
            ("tier", CustomValue::Select("gold".to_owned())),
        ]);
        let ntp = host(
            "ntp01",
            AssignmentMode::Reserved,
            vec![
                interface("eth0", Some("00:00:5e:00:53:02"), Some(DUID_NTP_ETH0)),
                interface("eth1", None, Some(DUID_NTP_ETH1)),
            ],
        );
        let old = host(
            "old01",
            AssignmentMode::Static,
            vec![interface("eth0", Some("00:00:5e:00:53:09"), None)],
        );

        let mut main = prefix("192.0.2.0/24");
        main.vlan = Some(vlan);
        main.site = Some(site);
        main.alarm = Some(UtilizationAlarm::new(80, 95).expect("alarm"));
        main.alloc = Some(AllocPolicy::Highest);
        main.tags = tags(&["lab", "iot"]);
        main.description = Some("Lab, \"main\" network".to_owned());
        main.custom = custom(vec![
            ("owner", text("Network Team")),
            ("reviewed", CustomValue::Date("2026-10-01".to_owned())),
            (
                "wiki",
                CustomValue::Url("https://example.test/net".to_owned()),
            ),
            ("delta", CustomValue::Integer(-5)),
        ]);
        let mut supernet = prefix("198.51.100.0/24");
        supernet.role = Some(PrefixRole::Supernet);
        supernet.description = Some("=SUM(1)".to_owned());
        let mut child = prefix("198.51.100.0/26");
        child.role = Some(PrefixRole::Network);
        child.status = Some(Status::Reserved);
        let gone = prefix("203.0.113.0/24");

        let mut primary = address("192.0.2.10");
        primary.interface = Some(interface_of(&nas, "eth0"));
        primary.dns_name = Some("nas01.example.test".parse().expect("dns name"));
        primary.description = Some("Primary".to_owned());
        primary.tags = tags(&["mgmt"]);
        primary.custom = custom(vec![
            ("owner", text("ops")),
            ("critical", CustomValue::Boolean(true)),
        ]);
        let mut secondary = address("192.0.2.11");
        secondary.interface = Some(interface_of(&nas, "eth1"));
        let mut reserved = address("192.0.2.20");
        reserved.status = Some(Status::Reserved);
        let mut v6 = address("2001:db8::10");
        v6.interface = Some(interface_of(&ntp, "eth0"));
        v6.dns_name = Some("ntp01.example.test".parse().expect("dns name"));
        let mut old_address = address("192.0.2.99");
        old_address.interface = Some(interface_of(&old, "eth0"));
        let old_free = address("192.0.2.98");

        let old_host = old.id.expect("host id");
        let old_address_id = old_address.id.expect("address id");
        let old_free_id = old_free.id.expect("address id");
        let old_prefix = gone.id.expect("prefix id");
        run(
            &service,
            vec![
                field("rack_unit", CustomKind::Integer, &[ObjectKind::Host]),
                field(
                    "critical",
                    CustomKind::Boolean,
                    &[ObjectKind::Host, ObjectKind::Address],
                ),
                field(
                    "tier",
                    CustomKind::Select {
                        options: vec!["gold".to_owned(), "silver".to_owned()],
                    },
                    &[ObjectKind::Host],
                ),
                field(
                    "owner",
                    CustomKind::Text,
                    &[ObjectKind::Prefix, ObjectKind::Address],
                ),
                field("reviewed", CustomKind::Date, &[ObjectKind::Prefix]),
                field("wiki", CustomKind::Url, &[ObjectKind::Prefix]),
                field("delta", CustomKind::Integer, &[ObjectKind::Prefix]),
                // Applies to no exported entity: no column.
                field("unused", CustomKind::Text, &[ObjectKind::Vrf]),
                IpamCommand::CreateSite(SiteInput {
                    id: Some(site),
                    name: "home".to_owned(),
                    parent: None,
                    ad_site: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreateVlan(VlanInput {
                    id: Some(vlan),
                    vid: 10,
                    vni: None,
                    name: "lab".to_owned(),
                    site: Some(site),
                    status: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                IpamCommand::CreatePrefix(main),
                IpamCommand::CreatePrefix(supernet),
                IpamCommand::CreatePrefix(child),
                IpamCommand::CreatePrefix(prefix("2001:db8::/64")),
                IpamCommand::CreatePrefix(gone),
                IpamCommand::CreateHost(nas),
                IpamCommand::CreateHost(ntp),
                IpamCommand::CreateHost(old),
                IpamCommand::CreateAddress(primary),
                IpamCommand::CreateAddress(secondary),
                IpamCommand::CreateAddress(reserved),
                IpamCommand::CreateAddress(v6),
                IpamCommand::CreateAddress(old_address),
                IpamCommand::CreateAddress(old_free),
            ],
        )
        .await;
        run(
            &service,
            vec![
                IpamCommand::Delete {
                    object: ObjectRef::from(old_host),
                    expected: None,
                    cascade: true,
                },
                IpamCommand::Delete {
                    object: ObjectRef::from(old_free_id),
                    expected: None,
                    cascade: false,
                },
                IpamCommand::Delete {
                    object: ObjectRef::from(old_prefix),
                    expected: None,
                    cascade: false,
                },
            ],
        )
        .await;
        Fixture {
            service,
            old_host,
            old_address: old_address_id,
            old_free_address: old_free_id,
            old_prefix,
        }
    }

    // ----- reading the output ------------------------------------------------------------

    async fn export(service: &IpamService, kind: ExportKind) -> Vec<u8> {
        export_csv(snapshot(service).await, kind).expect("export")
    }

    /// The cells of every record, header first; the file must start with the BOM.
    fn parse(file: &[u8]) -> Vec<Vec<String>> {
        assert!(file.starts_with(&BOM), "the file starts with the BOM");
        parse_records(&file[BOM.len()..])
    }

    fn parse_records(bytes: &[u8]) -> Vec<Vec<String>> {
        csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(bytes)
            .records()
            .map(|record| record.expect("record").iter().map(str::to_owned).collect())
            .collect()
    }

    fn row(line: &str) -> Vec<String> {
        line.split('|').map(str::to_owned).collect()
    }

    fn header(line: &str) -> Vec<String> {
        line.split(',').map(str::to_owned).collect()
    }

    /// One BOM at the start, and every line break is a CRLF.
    fn assert_wire_format(file: &[u8]) {
        assert!(file.starts_with(&BOM));
        let body = &file[BOM.len()..];
        assert!(
            !body.windows(BOM.len()).any(|window| window == BOM),
            "the BOM appears once"
        );
        assert!(body.ends_with(b"\r\n"));
        for (index, byte) in body.iter().enumerate() {
            if *byte == b'\n' {
                assert!(index > 0 && body[index - 1] == b'\r', "bare LF at {index}");
            }
        }
    }

    fn as_text(file: &[u8]) -> String {
        String::from_utf8(file.to_vec()).expect("UTF-8")
    }

    // ----- tests -------------------------------------------------------------------------

    #[test]
    fn files_are_named_and_listed() {
        assert_eq!(ExportKind::Prefixes.file_name(), "prefixes.csv");
        assert_eq!(ExportKind::Addresses.file_name(), "addresses.csv");
        assert_eq!(ExportKind::Hosts.file_name(), "hosts.csv");
        let names: BTreeSet<&str> = ExportKind::ALL
            .iter()
            .map(|kind| kind.file_name())
            .collect();
        assert_eq!(names.len(), 3);
        assert_eq!(CsvExport::CHUNK_ROWS, 1_000);
    }

    #[test]
    fn the_stream_can_move_between_threads() {
        fn assert_send<T: Send>() {}
        assert_send::<CsvExport>();
    }

    #[test]
    fn enums_are_written_in_snake_case() {
        assert_eq!(role_name(PrefixRole::Supernet), "supernet");
        assert_eq!(role_name(PrefixRole::Network), "network");
        assert_eq!(status_name(Status::Planned), "planned");
        assert_eq!(status_name(Status::Active), "active");
        assert_eq!(status_name(Status::Reserved), "reserved");
        assert_eq!(status_name(Status::Deprecated), "deprecated");
        assert_eq!(mode_name(AssignmentMode::Static), "static");
        assert_eq!(mode_name(AssignmentMode::Reserved), "reserved");
        assert_eq!(mode_name(AssignmentMode::Dynamic), "dynamic");
        assert_eq!(mode_name(AssignmentMode::Unmanaged), "unmanaged");
        assert_eq!(alloc_name(AllocPolicy::Lowest), "lowest");
        assert_eq!(alloc_name(AllocPolicy::Highest), "highest");
    }

    #[test]
    fn formula_characters_are_escaped_with_a_quote() {
        let escaped = |cell: &str| escape_cell(cell.to_owned());
        assert_eq!(escaped("=SUM(1)"), "'=SUM(1)");
        assert_eq!(escaped("+1+1"), "'+1+1");
        assert_eq!(escaped("-x"), "'-x");
        assert_eq!(escaped("@user"), "'@user");
        assert_eq!(escaped("\tcell"), "'\tcell");
        assert_eq!(escaped("\rcell"), "'\rcell");
        assert_eq!(escaped("-"), "'-");
        assert_eq!(escaped("-5.5"), "'-5.5");
        // Everything else is left alone.
        assert_eq!(escaped(""), "");
        assert_eq!(escaped("plain"), "plain");
        assert_eq!(escaped("a=b"), "a=b");
        assert_eq!(escaped("'plain"), "'plain");
        assert_eq!(escaped("2001:db8::/64"), "2001:db8::/64");
        // A negative integer is a number, not a formula.
        assert_eq!(escaped("-5"), "-5");
        assert_eq!(escaped("-9223372036854775808"), "-9223372036854775808");
        // The importer removes one quote before a formula character, so a cell that
        // has quotes there gets one more and comes back as it was.
        assert_eq!(escaped("'=1"), "''=1");
        assert_eq!(escaped("''@x"), "'''@x");
        assert_eq!(escaped("'-5"), "''-5");
    }

    #[tokio::test]
    async fn an_empty_store_exports_the_header_only() {
        let service = service();
        let view = snapshot(&service).await;
        for kind in ExportKind::ALL {
            let file = export_csv(Arc::clone(&view), kind).expect("export");
            let mut expected = BOM.to_vec();
            expected.extend_from_slice(
                match kind {
                    ExportKind::Prefixes => {
                        "prefix,vrf,role,status,vlan,vlan_name,site,alarm_warn,alarm_crit,alloc,\
                         description,tags\r\n"
                    }
                    ExportKind::Hosts => {
                        "host,tenant,mode,lock,site,description,interfaces,tags\r\n"
                    }
                    ExportKind::Addresses => {
                        "address,vrf,status,dns_name,host,interface,mac,duid,description,tags\r\n"
                    }
                }
                .as_bytes(),
            );
            assert_eq!(file, expected, "{}", kind.file_name());

            let mut stream = CsvExport::new(Arc::clone(&view), kind).expect("export");
            assert_eq!(stream.file_name(), kind.file_name());
            assert_eq!(stream.next_chunk().expect("chunk"), Some(expected));
            assert_eq!(stream.next_chunk().expect("chunk"), None);
            assert_eq!(stream.next_chunk().expect("chunk"), None);
        }
    }

    #[tokio::test]
    async fn prefixes_come_out_with_names_and_custom_fields() {
        let fixture = fixture().await;
        let file = export(&fixture.service, ExportKind::Prefixes).await;
        assert_wire_format(&file);
        let raw = as_text(&file);
        assert!(raw.starts_with(&format!("\u{feff}{PREFIX_HEADER}\r\n")));
        // A comma and quotes in a description are quoted; a formula is made inert.
        assert!(raw.contains(",\"Lab, \"\"main\"\" network\","), "{raw}");
        assert!(raw.contains(",'=SUM(1),"), "{raw}");

        assert_eq!(
            parse(&file),
            vec![
                header(PREFIX_HEADER),
                row(
                    "192.0.2.0/24|default|network|active|10|lab|home|80|95|highest\
                     |Lab, \"main\" network|iot; lab|-5|Network Team|2026-10-01\
                     |https://example.test/net"
                ),
                row("198.51.100.0/24|default|supernet|active||||||lowest|'=SUM(1)|||||"),
                row("198.51.100.0/26|default|network|reserved||||||lowest||||||"),
                row("2001:db8::/64|default|network|active||||||lowest||||||"),
            ]
        );
    }

    #[tokio::test]
    async fn hosts_come_out_with_their_interfaces() {
        let fixture = fixture().await;
        let file = export(&fixture.service, ExportKind::Hosts).await;
        assert_wire_format(&file);
        assert!(as_text(&file).starts_with(&format!("\u{feff}{HOST_HEADER}\r\n")));
        assert_eq!(
            parse(&file),
            vec![
                header(HOST_HEADER),
                row(
                    "nas01|default|static|true|home|Main NAS|eth0=00:00:5e:00:53:01; eth1|core|true|42|gold"
                ),
                row(&format!(
                    "ntp01|default|reserved|false|||eth0=00:00:5e:00:53:02={DUID_NTP_ETH0}; \
                     eth1=={DUID_NTP_ETH1}||||"
                )),
            ]
        );
    }

    #[tokio::test]
    async fn addresses_come_out_with_host_interface_and_identifiers() {
        let fixture = fixture().await;
        let file = export(&fixture.service, ExportKind::Addresses).await;
        assert_wire_format(&file);
        assert!(as_text(&file).starts_with(&format!("\u{feff}{ADDRESS_HEADER}\r\n")));
        assert_eq!(
            parse(&file),
            vec![
                header(ADDRESS_HEADER),
                row(
                    "192.0.2.10|default|active|nas01.example.test|nas01|eth0|00:00:5e:00:53:01||\
                     Primary|mgmt|true|ops"
                ),
                row("192.0.2.11|default|active||nas01|eth1||||||"),
                row("192.0.2.20|default|reserved|||||||||"),
                row(&format!(
                    "2001:db8::10|default|active|ntp01.example.test|ntp01|eth0|00:00:5e:00:53:02\
                     |{DUID_NTP_ETH0}||||"
                )),
            ]
        );
    }

    #[tokio::test]
    async fn deleted_objects_are_left_out() {
        let fixture = fixture().await;
        // They exist, soft-deleted.
        let view = snapshot(&fixture.service).await;
        assert!(
            query::get::<Host>(view.as_ref(), fixture.old_host)
                .expect("host")
                .meta
                .is_deleted()
        );
        assert!(
            query::get::<Address>(view.as_ref(), fixture.old_address)
                .expect("address")
                .meta
                .is_deleted()
        );
        assert!(
            query::get::<Address>(view.as_ref(), fixture.old_free_address)
                .expect("address")
                .meta
                .is_deleted()
        );
        assert!(
            query::get::<Prefix>(view.as_ref(), fixture.old_prefix)
                .expect("prefix")
                .meta
                .is_deleted()
        );

        let prefixes = as_text(&export(&fixture.service, ExportKind::Prefixes).await);
        let hosts = as_text(&export(&fixture.service, ExportKind::Hosts).await);
        let addresses = as_text(&export(&fixture.service, ExportKind::Addresses).await);
        assert!(!prefixes.contains("203.0.113.0"));
        assert!(!hosts.contains("old01"));
        assert!(!hosts.contains("00:00:5e:00:53:09"));
        assert!(!addresses.contains("192.0.2.99"));
        assert!(!addresses.contains("192.0.2.98"));
        assert!(!addresses.contains("old01"));
        assert_eq!(parse(prefixes.as_bytes()).len(), 5);
        assert_eq!(parse(hosts.as_bytes()).len(), 3);
        assert_eq!(parse(addresses.as_bytes()).len(), 5);
    }

    #[tokio::test]
    async fn no_credential_is_exported() {
        let fixture = fixture().await;
        let credential_words = ["login", "password", "secret", "credential", "token"];
        for kind in ExportKind::ALL {
            let file = export(&fixture.service, kind).await;
            let records = parse(&file);
            for column in &records[0] {
                assert_ne!(*column, Target::Login.name());
                assert_ne!(*column, Target::Password.name());
                assert!(
                    !credential_words.iter().any(|word| column.contains(word)),
                    "column {column} of {}",
                    kind.file_name()
                );
            }
            let lowered = as_text(&file).to_lowercase();
            assert!(!credential_words.iter().any(|word| lowered.contains(word)));
        }
    }

    #[tokio::test]
    async fn headers_use_the_import_vocabulary() {
        let fixture = fixture().await;
        for kind in ExportKind::ALL {
            let file = export(&fixture.service, kind).await;
            for column in &parse(&file)[0] {
                let target: Target = column.parse().expect("an import target");
                assert_eq!(&target.name(), column);
            }
        }
    }

    #[tokio::test]
    async fn chunks_cover_the_file_exactly_once() {
        let fixture = fixture().await;
        let view = snapshot(&fixture.service).await;
        // Rows per file: 4 prefixes, 4 addresses, 2 hosts.
        for (kind, rows) in [
            (ExportKind::Prefixes, 4_usize),
            (ExportKind::Addresses, 4),
            (ExportKind::Hosts, 2),
        ] {
            let whole = export_csv(Arc::clone(&view), kind).expect("export");
            for chunk_rows in [1, 2, 3, 4, 5, 1_000] {
                let mut stream =
                    CsvExport::with_chunk_rows(Arc::clone(&view), kind, chunk_rows).expect("start");
                let mut chunks = Vec::new();
                while let Some(chunk) = stream.next_chunk().expect("chunk") {
                    chunks.push(chunk);
                }
                // Nothing more comes after the end.
                assert_eq!(stream.next_chunk().expect("chunk"), None);

                assert_eq!(
                    chunks.len(),
                    rows.div_ceil(chunk_rows),
                    "{kind:?} {chunk_rows}"
                );
                assert_eq!(chunks.concat(), whole, "{kind:?} {chunk_rows}");
                for (index, chunk) in chunks.iter().enumerate() {
                    let data_rows = if index == 0 {
                        // The BOM and the header belong to the first chunk only.
                        assert!(chunk.starts_with(&BOM));
                        parse(chunk).len() - 1
                    } else {
                        assert!(!chunk.starts_with(&BOM));
                        parse_records(chunk).len()
                    };
                    assert!(data_rows >= 1 && data_rows <= chunk_rows);
                }
            }
        }
    }

    #[tokio::test]
    async fn many_rows_stream_in_pages_in_index_order() {
        let service = service();
        let mut commands = vec![IpamCommand::CreatePrefix(prefix("192.0.2.0/24"))];
        commands
            .extend((1..=25).map(|n| IpamCommand::CreateAddress(address(&format!("192.0.2.{n}")))));
        run(&service, commands).await;
        let view = snapshot(&service).await;

        let mut stream = CsvExport::with_chunk_rows(Arc::clone(&view), ExportKind::Addresses, 10)
            .expect("start");
        let mut sizes = Vec::new();
        let mut addresses = Vec::new();
        while let Some(chunk) = stream.next_chunk().expect("chunk") {
            let mut records = if sizes.is_empty() {
                parse(&chunk)
            } else {
                parse_records(&chunk)
            };
            if sizes.is_empty() {
                assert_eq!(records.remove(0)[0], "address");
            }
            sizes.push(records.len());
            addresses.extend(records.into_iter().map(|record| record[0].clone()));
        }
        assert_eq!(sizes, vec![10, 10, 5]);
        let expected: Vec<String> = (1..=25).map(|n| format!("192.0.2.{n}")).collect();
        assert_eq!(addresses, expected);
    }

    #[tokio::test]
    async fn an_export_reads_one_snapshot() {
        let service = service();
        run(
            &service,
            vec![
                IpamCommand::CreatePrefix(prefix("192.0.2.0/24")),
                IpamCommand::CreatePrefix(prefix("198.51.100.0/24")),
            ],
        )
        .await;
        let mut stream =
            CsvExport::with_chunk_rows(snapshot(&service).await, ExportKind::Prefixes, 1)
                .expect("start");
        let first = stream.next_chunk().expect("chunk").expect("first chunk");
        assert!(as_text(&first).contains("192.0.2.0/24"));

        // Changes made while the export runs are not part of it.
        run(
            &service,
            vec![
                IpamCommand::CreatePrefix(prefix("203.0.113.0/24")),
                IpamCommand::Delete {
                    object: ObjectRef::from(
                        query::list::<Prefix>(
                            snapshot(&service).await.as_ref(),
                            &query::ListQuery::default(),
                        )
                        .expect("list")
                        .items
                        .iter()
                        .find(|prefix| prefix.cidr.to_string() == "198.51.100.0/24")
                        .map(|prefix| prefix.id)
                        .expect("prefix"),
                    ),
                    expected: None,
                    cascade: false,
                },
            ],
        )
        .await;
        let mut rest = String::new();
        while let Some(chunk) = stream.next_chunk().expect("chunk") {
            rest.push_str(&as_text(&chunk));
        }
        assert!(rest.contains("198.51.100.0/24"), "{rest}");
        assert!(!rest.contains("203.0.113.0/24"), "{rest}");
        // A new export sees the new state.
        let now = as_text(&export(&service, ExportKind::Prefixes).await);
        assert!(now.contains("203.0.113.0/24"));
        assert!(!now.contains("198.51.100.0/24"));
    }

    #[tokio::test]
    async fn rows_follow_the_vrf_index_and_name_their_vrf() {
        let service = service();
        let blue = VrfId::generate();
        let mut in_blue = prefix("192.0.2.0/24");
        in_blue.vrf = Some(blue);
        let mut address_in_blue = address("192.0.2.10");
        address_in_blue.vrf = Some(blue);
        run(
            &service,
            vec![
                IpamCommand::CreateVrf(VrfInput {
                    id: Some(blue),
                    tenant: None,
                    name: "blue".to_owned(),
                    rd: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }),
                // The same network and address in the default VRF (IPAM-23).
                IpamCommand::CreatePrefix(prefix("192.0.2.0/24")),
                IpamCommand::CreatePrefix(in_blue),
                IpamCommand::CreateAddress(address("192.0.2.10")),
                IpamCommand::CreateAddress(address_in_blue),
            ],
        )
        .await;
        let view = snapshot(&service).await;
        let default = view
            .scan_typed(&VRFS, KeyRange::all(), usize::MAX, false)
            .expect("vrfs")
            .into_iter()
            .find(|(_, vrf, _)| vrf.name == "default")
            .map(|(id, _, _)| id)
            .expect("default VRF");
        let mut by_id = [(default, "default"), (blue, "blue")];
        by_id.sort();
        let expected: Vec<&str> = by_id.iter().map(|(_, name)| *name).collect();

        for (kind, column) in [(ExportKind::Prefixes, 1), (ExportKind::Addresses, 1)] {
            let records = parse(&export_csv(Arc::clone(&view), kind).expect("export"));
            let names: Vec<&str> = records[1..]
                .iter()
                .map(|record| record[column].as_str())
                .collect();
            assert_eq!(names, expected, "{}", kind.file_name());
        }
    }

    #[tokio::test]
    async fn a_multi_line_description_is_quoted() {
        let service = service();
        let mut network = prefix("192.0.2.0/24");
        network.description = Some("first line\nsecond line".to_owned());
        run(&service, vec![IpamCommand::CreatePrefix(network)]).await;
        let file = export(&service, ExportKind::Prefixes).await;
        let records = parse(&file);
        assert_eq!(records[1][10], "first line\nsecond line");
        assert!(as_text(&file).contains("\"first line\nsecond line\""));
    }
}
