//! Translation: sheets and their mapping into the [`ImportModel`] and the loss report
//! (MIG-01), following rules 1 to 6 of the import specification
//! (`docs/plans/import-fixtures.md`).
//!
//! # Layouts
//!
//! The mapped targets of a sheet decide how its rows are read:
//!
//! | Columns | Layout | A row is |
//! |---|---|---|
//! | a `prefix` column | network list | one prefix |
//! | two or more `address` columns | device-centric | one host with one interface and address per address column |
//! | one `address` column | address list | one address, with a host when the row has a name |
//! | `host` or `interfaces`, no address | host list | one host |
//!
//! # Rules
//!
//! - A row of an address list with an address and nothing else creates nothing: it is a
//!   free address of a pre-filled list (rule 5).
//! - A range cell (`192.0.2.10-20`) is split into its addresses (at most
//!   [`MAX_RANGE`]); the row's label becomes their description and their status is
//!   `reserved`, because one label cannot name many hosts.
//! - An address with a length (`192.0.2.5/24`) or a mask column adds its network.
//! - Hosts merge by name across rows and sheets; an address seen twice merges when it
//!   names the same host and is reported when it names another.
//! - Interfaces come from numbered address columns (`Nic1` → `nic1`), an `interface` or
//!   `interfaces` column, or are named `nic1`, `nic2`... in source order otherwise.
//! - Addresses outside every network of the import and the store get a proposed prefix:
//!   the sheet's prefix length (or /24, /64) around them, narrowed until it overlaps
//!   nothing (rule 4). A rejected proposal drops its addresses.
//! - A prefix that contains another becomes a supernet. A host address equal to the
//!   network or broadcast address of an IPv4 network of /30 or wider is left out with a
//!   warning; the host stays (rule 6).
//! - Credential columns become [`ModelCredential`]s with their values kept apart
//!   ([`CredentialValues`]), with warnings for a login with spaces and a numeric password.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    ipam::{FieldKey, PrefixRole},
    ir::{LossReport, SourceLocation},
    net::{Fqdn, HostName},
};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::{
    codes,
    mapping::{
        CredentialPolicy, IndexEntries, Mapping, SheetKind, SheetMapping, column_letter,
        index_entries, sheet_address, sheet_names, sheets,
    },
    model::{
        CredentialValue, CredentialValues, ImportModel, ModelAddress, ModelCredential, ModelHost,
        ModelInterface, ModelPrefix, ModelVlan, PrefixSource,
    },
    read::{Cell, CellKind, Sheet, SourceFile},
    shape, transform,
    vocab::{self, Target},
};

/// Most addresses one range cell is split into.
pub const MAX_RANGE: u128 = 1024;
/// Most addresses the range cells of one import are split into together. Without it, a
/// file of many distinct ranges below [`MAX_RANGE`] builds a thousand addresses per row.
pub const MAX_RANGE_ADDRESSES: usize = 65_536;
/// The name of the default VRF and tenant.
pub const DEFAULT_NAME: &str = "default";

/// Prefixes that exist in the store, by VRF name (lowercase).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownPrefixes(pub BTreeMap<String, Vec<(IpNet, PrefixRole)>>);

/// Networks by VRF key and network (host bits cleared). Ordered by address, then length, so
/// a lookup by prefix length or a range of addresses costs the same whatever the number of
/// networks a file holds.
type Nets<V> = BTreeMap<(String, IpNet), V>;

#[cfg(test)]
thread_local! {
    /// The lookup steps of this thread's translations, for the tests that state how the
    /// work grows with the file.
    static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Counts one lookup step (in tests only).
fn step() {
    #[cfg(test)]
    STEPS.with(|steps| steps.set(steps.get() + 1));
}

/// The most specific network of `vrf` that contains `net` or equals it: one lookup per
/// prefix length.
fn enclosing<'a, V>(nets: &'a Nets<V>, vrf: &str, net: IpNet) -> Option<(IpNet, &'a V)> {
    let mut key = (vrf.to_owned(), net);
    for length in (0..=net.prefix_len()).rev() {
        step();
        key.1 = IpNet::new(net.addr(), length).ok()?.trunc();
        if let Some(((_, found), value)) = nets.get_key_value(&key) {
            return Some((*found, value));
        }
    }
    None
}

/// The networks of `vrf` inside `net`, `net` itself included: one range of the ordered
/// keys. Keys before the first hit can only be shorter networks at the same address, at
/// most one per prefix length.
fn inside<'a, V>(nets: &'a Nets<V>, vrf: &str, net: IpNet) -> impl Iterator<Item = IpNet> + 'a {
    let low = IpNet::new(net.network(), 0).unwrap_or(net);
    let high = IpNet::new(net.broadcast(), net.max_prefix_len()).unwrap_or(net);
    nets.range((vrf.to_owned(), low)..=(vrf.to_owned(), high))
        .inspect(|_| step())
        .map(|((_, other), _)| *other)
        .filter(move |other| other.prefix_len() >= net.prefix_len())
}

/// The number of leading bits two addresses of one family share.
fn common_length(a: IpAddr, b: IpAddr) -> u8 {
    let bits: u8 = if a.is_ipv4() { 32 } else { 128 };
    let unused = 128 - u32::from(bits);
    let same = (ip_to_u128(a) ^ ip_to_u128(b))
        .leading_zeros()
        .saturating_sub(unused);
    u8::try_from(same).unwrap_or(bits)
}

/// Keeps the first of every repeated tag.
fn dedupe(tags: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    tags.retain(|tag| {
        step();
        seen.insert(tag.clone())
    });
}

/// A proposed prefix for addresses outside every known network (rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Proposal {
    /// The proposed network.
    #[schema(value_type = String, example = "198.51.100.64/26")]
    pub cidr: IpNet,
    /// The VRF name; the import's target VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// The addresses it would hold.
    #[schema(value_type = Vec<String>)]
    pub addresses: Vec<IpAddr>,
    /// Whether it is created (the mapping options decide; accepted by default).
    pub accepted: bool,
    /// Where the first of its addresses comes from.
    pub origin: SourceLocation,
}

/// What became of a sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SheetOutcome {
    /// The sheet.
    pub sheet: String,
    /// What it was read as.
    pub kind: SheetKind,
    /// Its network, for network sheets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub cidr: Option<IpNet>,
    /// Rows with data after the header.
    pub rows: usize,
    /// Address-only rows of a pre-filled list (free addresses).
    pub free: usize,
    /// Rows that produced something.
    pub imported: usize,
    /// Rows left out (see the loss report).
    pub skipped: usize,
}

/// What became of a source row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RowStatus {
    /// An address-only row of a pre-filled list.
    Free,
    /// Imported (some values may be listed in the loss report).
    Imported,
    /// Not imported (see the loss report).
    Skipped,
}

/// A model item, by natural key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ItemKey {
    /// A VLAN.
    Vlan {
        /// Site name, `None` for global.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
        /// VLAN id.
        vid: u16,
    },
    /// A prefix.
    Prefix {
        /// VRF name (lowercase).
        vrf: String,
        /// The network.
        cidr: String,
    },
    /// A host.
    Host {
        /// Host name.
        name: String,
    },
    /// An interface.
    Interface {
        /// Host name.
        host: String,
        /// Interface name.
        name: String,
    },
    /// An address.
    Address {
        /// VRF name (lowercase).
        vrf: String,
        /// The address.
        ip: String,
    },
    /// The credential of a host.
    Credential {
        /// Host name.
        host: String,
    },
}

impl ItemKey {
    /// A short label: `prefix 192.0.2.0/24`, `host nas01`.
    pub fn label(&self) -> String {
        match self {
            ItemKey::Vlan { vid, .. } => format!("VLAN {vid}"),
            ItemKey::Prefix { cidr, .. } => format!("prefix {cidr}"),
            ItemKey::Host { name } => format!("host {name}"),
            ItemKey::Interface { host, name } => format!("interface {name} of {host}"),
            ItemKey::Address { ip, .. } => format!("address {ip}"),
            ItemKey::Credential { host } => format!("credential of {host}"),
        }
    }
}

/// What a source row produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RowOutcome {
    /// The row (sheet and row number).
    pub location: SourceLocation,
    /// What became of it.
    pub status: RowStatus,
    /// The model items it produced or contributed to.
    pub items: Vec<ItemKey>,
}

/// The result of translation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Translation {
    /// Per sheet.
    pub sheets: Vec<SheetOutcome>,
    /// The model.
    pub model: ImportModel,
    /// What could not be mapped or was transformed.
    pub loss: LossReport,
    /// Per data row, in source order.
    pub rows: Vec<RowOutcome>,
    /// Proposed prefixes (accepted ones are in the model).
    pub proposals: Vec<Proposal>,
    /// Credential values, by host. Never serialized.
    pub credentials: CredentialValues,
}

/// The VRF key of an item: its own VRF, else the import's, else `default`, lowercase.
pub fn vrf_key(own: Option<&str>, import: Option<&str>) -> String {
    own.or(import).unwrap_or(DEFAULT_NAME).to_lowercase()
}

/// Translates the files of an import with its mapping. `known` are the prefixes of the
/// store, so addresses inside them need no proposal and supernets are recognized.
/// `frozen` replaces the proposal step with the proposals an apply froze (by VRF key),
/// so every chunk of the job sees the same model while the store fills.
pub fn translate(
    files: &[SourceFile],
    mapping: &Mapping,
    known: &KnownPrefixes,
    frozen: Option<&[(String, IpNet)]>,
) -> Translation {
    let names = sheet_names(files);
    let refs = sheets(files, &names);
    let mut builder = Builder::new(mapping, known);
    builder.frozen = frozen;
    // The first mapping of each sheet, found once rather than by a scan per sheet.
    let mut by_name: BTreeMap<&str, &SheetMapping> = BTreeMap::new();
    for sheet in &mapping.sheets {
        by_name.entry(sheet.sheet.as_str()).or_insert(sheet);
    }
    let sheet_mapping = |name: &str| by_name.get(name).copied();

    let index = refs.iter().find_map(|r| {
        sheet_mapping(r.name)
            .filter(|m| m.kind == SheetKind::Index)
            .map(|m| (r.name, r.sheet, m))
    });
    let entries = index.map(|(name, sheet, sheet_mapping)| {
        builder.index(name, sheet, sheet_mapping);
        index_entries(sheet, sheet_mapping)
    });

    for sheet in &refs {
        let Some(sheet_mapping) = sheet_mapping(sheet.name) else {
            builder.skip(sheet.name, sheet.sheet, None);
            continue;
        };
        match sheet_mapping.kind {
            SheetKind::Index => {}
            SheetKind::Skip => builder.skip(sheet.name, sheet.sheet, Some(sheet_mapping)),
            SheetKind::Network | SheetKind::Host | SheetKind::List => {
                builder.sheet(sheet.name, sheet.sheet, sheet_mapping, entries.as_ref());
            }
        }
    }
    builder.finish()
}

/// One row being read: its cells, mapping and location.
struct Row<'a> {
    sheet: &'a str,
    cells: &'a Sheet,
    mapping: &'a SheetMapping,
    line: usize,
}

impl<'a> Row<'a> {
    fn cell(&self, column: usize) -> &'a Cell {
        self.cells.cell(self.line, column)
    }

    /// The value of the first column mapped to `target`, unescaped.
    fn get(&self, target: &Target) -> Option<(&'a str, usize)> {
        let column = *self.mapping.columns_of(target).first()?;
        self.cell(column)
            .value()
            .map(|value| (transform::unescape(value), column))
    }

    fn location(&self, column: Option<usize>) -> SourceLocation {
        SourceLocation {
            sheet: Some(self.sheet.to_owned()),
            row: Some(u32::try_from(self.line + 1).unwrap_or(u32::MAX)),
            column: column.map(column_letter),
        }
    }

    /// Whether a column other than addresses, masks and ignored ones holds a value.
    fn has_data(&self) -> bool {
        self.mapping.columns.iter().any(|c| {
            !matches!(c.target, Target::Address | Target::Mask | Target::Ignore)
                && super::mapping::column_index(&c.column)
                    .is_some_and(|index| !self.cell(index).is_empty())
        })
    }

    fn is_blank(&self) -> bool {
        self.cells
            .rows
            .get(self.line)
            .is_none_or(|cells| cells.iter().all(Cell::is_empty))
    }
}

/// An address waiting for a default interface name.
struct PendingInterface {
    key: (String, IpAddr),
    host: HostName,
    mac: Option<tenko_core::MacAddr>,
}

/// The state of a translation.
struct Builder<'m> {
    mapping: &'m Mapping,
    /// The store's prefixes, keyed like the model's.
    known: Nets<PrefixRole>,
    frozen: Option<&'m [(String, IpNet)]>,
    import_vrf: Option<&'m str>,
    loss: LossReport,
    prefixes: Nets<ModelPrefix>,
    vlans: BTreeMap<(Option<String>, u16), ModelVlan>,
    hosts: BTreeMap<HostName, ModelHost>,
    /// Where each interface sits in its host's list while rows are read.
    interface_slots: BTreeMap<(HostName, String), usize>,
    /// Addresses the range cells were split into so far ([`MAX_RANGE_ADDRESSES`]).
    range_addresses: usize,
    addresses: BTreeMap<(String, IpAddr), ModelAddress>,
    /// The prefix length of the network sheet an address came from, for proposals.
    address_lengths: BTreeMap<(String, IpAddr), u8>,
    /// VLAN ids given on address rows, for the network that ends up holding the address.
    address_vlans: Vec<((String, IpAddr), u16, SourceLocation)>,
    credentials: BTreeMap<HostName, (ModelCredential, CredentialValue)>,
    pending: Vec<PendingInterface>,
    sheets: Vec<SheetOutcome>,
    rows: Vec<RowOutcome>,
    has_index: bool,
    index_hosts: Vec<(IpAddr, Option<String>, SourceLocation)>,
    host_sheets: BTreeSet<IpAddr>,
}

impl<'m> Builder<'m> {
    fn new(mapping: &'m Mapping, known: &KnownPrefixes) -> Self {
        let mut index = Nets::new();
        for (vrf, nets) in &known.0 {
            for (net, role) in nets {
                index.entry((vrf.clone(), net.trunc())).or_insert(*role);
            }
        }
        Self {
            mapping,
            known: index,
            frozen: None,
            import_vrf: mapping.options.vrf.as_deref(),
            loss: LossReport::default(),
            prefixes: BTreeMap::new(),
            vlans: BTreeMap::new(),
            hosts: BTreeMap::new(),
            interface_slots: BTreeMap::new(),
            range_addresses: 0,
            addresses: BTreeMap::new(),
            address_lengths: BTreeMap::new(),
            address_vlans: Vec::new(),
            credentials: BTreeMap::new(),
            pending: Vec::new(),
            sheets: Vec::new(),
            rows: Vec::new(),
            has_index: false,
            index_hosts: Vec::new(),
            host_sheets: BTreeSet::new(),
        }
    }

    fn vrf(&self, own: Option<&str>) -> String {
        vrf_key(own, self.import_vrf)
    }

    fn push(&mut self, location: SourceLocation, code: &'static str, detail: impl Into<String>) {
        self.loss.push(location, code, detail);
    }

    fn sheet_location(sheet: &str) -> SourceLocation {
        SourceLocation {
            sheet: Some(sheet.to_owned()),
            row: None,
            column: None,
        }
    }

    // ----- sheets ----------------------------------------------------------------------

    fn skip(&mut self, name: &str, sheet: &Sheet, mapping: Option<&SheetMapping>) {
        if sheet.is_empty() {
            self.push(
                Self::sheet_location(name),
                codes::SHEET_EMPTY,
                format!("sheet `{name}` is empty"),
            );
        } else {
            let why = if mapping.is_some() {
                "has no address, network or host column"
            } else {
                "has no mapping"
            };
            self.push(
                Self::sheet_location(name),
                codes::SHEET_SKIPPED,
                format!("sheet `{name}` {why}; nothing of it is imported"),
            );
        }
        self.sheets.push(SheetOutcome {
            sheet: name.to_owned(),
            kind: SheetKind::Skip,
            cidr: None,
            rows: 0,
            free: 0,
            imported: 0,
            skipped: 0,
        });
    }

    /// The `Index` sheet: its networks become prefixes with their descriptions; its single
    /// addresses mark host sheets (rule 1).
    fn index(&mut self, name: &str, sheet: &Sheet, mapping: &SheetMapping) {
        self.has_index = true;
        let mut outcome = SheetOutcome {
            sheet: name.to_owned(),
            kind: SheetKind::Index,
            cidr: None,
            rows: 0,
            free: 0,
            imported: 0,
            skipped: 0,
        };
        if sheet.is_empty() {
            self.push(
                Self::sheet_location(name),
                codes::SHEET_EMPTY,
                format!("sheet `{name}` is empty"),
            );
        }
        let network_column = mapping.columns_of(&Target::Prefix).first().copied();
        let description_column = mapping.columns_of(&Target::Description).first().copied();
        for row in mapping.first_data_row()..sheet.rows.len() {
            let row_ref = Row {
                sheet: name,
                cells: sheet,
                mapping,
                line: row,
            };
            if row_ref.is_blank() {
                continue;
            }
            outcome.rows += 1;
            let Some(column) = network_column else {
                outcome.skipped += 1;
                continue;
            };
            let Some(value) = row_ref.cell(column).value() else {
                outcome.skipped += 1;
                continue;
            };
            let description = description_column
                .and_then(|c| row_ref.cell(c).value())
                .map(str::to_owned);
            let location = row_ref.location(Some(column));
            if let Some(ip) = shape::parse_address(value) {
                self.index_hosts.push((ip, description, location.clone()));
                outcome.imported += 1;
                self.rows.push(RowOutcome {
                    location: row_ref.location(None),
                    status: RowStatus::Imported,
                    items: Vec::new(),
                });
            } else if let Some(net) = shape::parse_cidr(value) {
                let cidr = net.trunc();
                if cidr != net {
                    self.push(
                        location.clone(),
                        codes::PREFIX_HOST_BITS,
                        format!("`{value}` has host bits; the network {cidr} is used"),
                    );
                }
                let key = (self.vrf(None), cidr);
                let mut prefix = ModelPrefix::new(cidr, PrefixSource::Index, location);
                prefix.description = description;
                self.prefixes.entry(key.clone()).or_insert(prefix);
                outcome.imported += 1;
                self.rows.push(RowOutcome {
                    location: row_ref.location(None),
                    status: RowStatus::Imported,
                    items: vec![prefix_key(&key)],
                });
            } else {
                self.push(
                    location,
                    codes::PREFIX_UNPARSABLE,
                    format!("`{value}` is not a network or an address; the row is not imported"),
                );
                outcome.skipped += 1;
                self.rows.push(RowOutcome {
                    location: row_ref.location(None),
                    status: RowStatus::Skipped,
                    items: Vec::new(),
                });
            }
        }
        self.sheets.push(outcome);
    }

    fn sheet(
        &mut self,
        name: &str,
        sheet: &Sheet,
        mapping: &SheetMapping,
        index: Option<&IndexEntries>,
    ) {
        let mut outcome = SheetOutcome {
            sheet: name.to_owned(),
            kind: mapping.kind,
            cidr: mapping.cidr,
            rows: 0,
            free: 0,
            imported: 0,
            skipped: 0,
        };
        let mut length = None;
        let mut host_description = None;
        match mapping.kind {
            SheetKind::Network => {
                if let Some(cidr) = mapping.cidr {
                    length = Some(cidr);
                    let key = (self.vrf(None), cidr);
                    let listed = index.and_then(|e| e.network(&cidr));
                    let location = Self::sheet_location(name);
                    let prefix = self.prefixes.entry(key).or_insert_with(|| {
                        ModelPrefix::new(cidr, PrefixSource::Sheet, location.clone())
                    });
                    prefix.source = PrefixSource::Sheet;
                    prefix.origin = location.clone();
                    if prefix.description.is_none() {
                        prefix.description = listed.and_then(|(_, d, _)| d.clone());
                    }
                    if self.has_index && listed.is_none() {
                        self.push(
                            location,
                            codes::PREFIX_UNLISTED,
                            format!(
                                "sheet `{name}` is the network {cidr}, which the Index sheet does not list; {}",
                                mask_note(name, cidr)
                            ),
                        );
                    }
                }
            }
            SheetKind::Host => {
                if let Some((ip, _)) = sheet_address(name) {
                    self.host_sheets.insert(ip);
                    host_description = index
                        .and_then(|e| e.host(ip))
                        .and_then(|(_, d, _)| d.clone());
                }
            }
            _ => {}
        }
        if sheet.is_empty() {
            self.push(
                Self::sheet_location(name),
                codes::SHEET_EMPTY,
                format!("sheet `{name}` is empty"),
            );
            self.sheets.push(outcome);
            return;
        }

        self.unmapped_columns(name, sheet, mapping);

        let addresses = mapping.columns_of(&Target::Address);
        let has_prefix = !mapping.columns_of(&Target::Prefix).is_empty();
        let has_host = !mapping.columns_of(&Target::Name).is_empty()
            || !mapping.columns_of(&Target::Interfaces).is_empty();
        if !has_prefix && addresses.is_empty() && !has_host {
            self.push(
                Self::sheet_location(name),
                codes::SHEET_SKIPPED,
                format!("sheet `{name}` has no address, network or host column; nothing of it is imported"),
            );
            outcome.kind = SheetKind::Skip;
            self.sheets.push(outcome);
            return;
        }
        for row in mapping.first_data_row()..sheet.rows.len() {
            let row = Row {
                sheet: name,
                cells: sheet,
                mapping,
                line: row,
            };
            if row.is_blank() {
                continue;
            }
            outcome.rows += 1;
            let result = if has_prefix {
                self.network_row(&row)
            } else if addresses.len() >= 2 {
                self.device_row(&row, &addresses, length, host_description.as_deref())
            } else if let Some(&column) = addresses.first() {
                self.address_row(&row, column, length, host_description.as_deref())
            } else {
                self.host_row(&row)
            };
            match result.status {
                RowStatus::Free => outcome.free += 1,
                RowStatus::Imported => outcome.imported += 1,
                RowStatus::Skipped => outcome.skipped += 1,
            }
            self.rows.push(result);
        }
        self.sheets.push(outcome);
    }

    /// Lists columns whose values are not imported (rule 6: `import.column.unmapped`).
    fn unmapped_columns(&mut self, name: &str, sheet: &Sheet, mapping: &SheetMapping) {
        let first = mapping.first_data_row();
        let skip_credentials = self.mapping.options.credentials == CredentialPolicy::Skip;
        for column in 0..sheet.width() {
            let target = mapping.target(column);
            let credential = target.is_credential();
            if target != Target::Ignore && !(credential && skip_credentials) {
                continue;
            }
            let values: Vec<(usize, &str)> = (first..sheet.rows.len())
                .filter_map(|row| sheet.cell(row, column).value().map(|v| (row, v)))
                .collect();
            let Some(&(row, _)) = values.first() else {
                continue;
            };
            let header = mapping
                .header_row
                .and_then(|h| usize::try_from(h).ok()?.checked_sub(1))
                .and_then(|h| sheet.cell(h, column).value());
            let letter = column_letter(column);
            let location = SourceLocation {
                sheet: Some(name.to_owned()),
                row: Some(u32::try_from(row + 1).unwrap_or(u32::MAX)),
                column: Some(letter.clone()),
            };
            if credential {
                self.push(
                    location,
                    codes::CREDENTIAL_SKIPPED,
                    format!(
                        "column {letter} holds {} credential value{}; credentials are left out of this import",
                        values.len(),
                        plural(values.len())
                    ),
                );
                continue;
            }
            let shown: Vec<String> = values
                .iter()
                .take(3)
                .map(|(_, v)| format!("`{v}`"))
                .collect();
            let what = match header {
                Some(header) => format!("column {letter} (`{header}`) is not mapped"),
                None => format!("column {letter} has no header"),
            };
            self.push(
                location,
                codes::COLUMN_UNMAPPED,
                format!(
                    "{what}; {} value{} {} not imported: {}",
                    values.len(),
                    plural(values.len()),
                    if values.len() == 1 { "is" } else { "are" },
                    shown.join(", ")
                ),
            );
        }
    }

    // ----- rows ------------------------------------------------------------------------

    fn skipped(row: &Row<'_>) -> RowOutcome {
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Skipped,
            items: Vec::new(),
        }
    }

    /// A row of a network list.
    fn network_row(&mut self, row: &Row<'_>) -> RowOutcome {
        let Some((value, column)) = row.get(&Target::Prefix) else {
            if row.has_data() {
                self.push(
                    row.location(None),
                    codes::PREFIX_UNPARSABLE,
                    "the row has no network; it is not imported",
                );
            }
            return Self::skipped(row);
        };
        let mask = row.get(&Target::Mask);
        let parsed = shape::parse_cidr(value).or_else(|| {
            let ip = shape::parse_address(value)?;
            let length = match mask {
                Some((mask, _)) => shape::parse_mask(mask, ip.is_ipv6())?,
                None => {
                    if ip.is_ipv4() {
                        32
                    } else {
                        128
                    }
                }
            };
            IpNet::new(ip, length).ok()
        });
        let Some(net) = parsed else {
            self.push(
                row.location(Some(column)),
                codes::PREFIX_UNPARSABLE,
                format!("`{value}` is not a network; the row is not imported"),
            );
            return Self::skipped(row);
        };
        let cidr = net.trunc();
        if cidr != net {
            self.push(
                row.location(Some(column)),
                codes::PREFIX_HOST_BITS,
                format!("`{value}` has host bits; the network {cidr} is used"),
            );
        }
        let vrf_name = row.get(&Target::Vrf).map(|(v, _)| v.to_owned());
        let key = (self.vrf(vrf_name.as_deref()), cidr);
        let mut prefix = ModelPrefix::new(cidr, PrefixSource::Row, row.location(None));
        prefix.vrf = vrf_name;
        prefix.role = self.parse(row, &Target::Role, "a prefix role", transform::role);
        prefix.status = self.parse(row, &Target::Status, "a status", transform::status);
        prefix.vlan = self.vlan_of(row);
        prefix.site = row.get(&Target::Site).map(|(v, _)| v.to_owned());
        prefix.alarm_warn = self.parse(row, &Target::AlarmWarn, "a percentage", transform::percent);
        prefix.alarm_crit = self.parse(row, &Target::AlarmCrit, "a percentage", transform::percent);
        prefix.alloc = self.parse(row, &Target::Alloc, "a next-free policy", transform::alloc);
        prefix.description = row.get(&Target::Description).map(|(v, _)| v.to_owned());
        prefix.tags = row_tags(row);
        prefix.custom = custom_values(row);
        self.credentials_without_host(row);
        match self.prefixes.get_mut(&key) {
            Some(existing) => {
                let location = row.location(None);
                merge_prefix(existing, prefix, &location, &mut self.loss);
            }
            None => {
                self.prefixes.insert(key.clone(), prefix);
            }
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items: vec![prefix_key(&key)],
        }
    }

    /// The VLAN of a row, registered as a model VLAN.
    fn vlan_of(&mut self, row: &Row<'_>) -> Option<u16> {
        let vid = self.parse(row, &Target::Vlan, "a VLAN id (1 to 4094)", transform::vlan)?;
        let site = row.get(&Target::Site).map(|(v, _)| v.to_owned());
        let name = row.get(&Target::VlanName).map(|(v, _)| v.to_owned());
        let location = row.location(None);
        let vlan = self
            .vlans
            .entry((site.clone(), vid))
            .or_insert_with(|| ModelVlan {
                vid,
                name: None,
                site,
                origin: location,
            });
        if vlan.name.is_none() {
            vlan.name = name;
        }
        Some(vid)
    }

    /// Parses an optional column value; an invalid value is reported and left out.
    fn parse<T>(
        &mut self,
        row: &Row<'_>,
        target: &Target,
        what: &str,
        parse: impl Fn(&str) -> Option<T>,
    ) -> Option<T> {
        let (value, column) = row.get(target)?;
        let parsed = parse(value);
        if parsed.is_none() {
            self.push(
                row.location(Some(column)),
                codes::VALUE_INVALID,
                format!("`{value}` is not {what}; the value is left out"),
            );
        }
        parsed
    }

    /// The host of a row from its name column, normalized (rule 3).
    fn host_of(
        &mut self,
        row: &Row<'_>,
        default_description: Option<&str>,
    ) -> Option<Result<HostName, String>> {
        let (label, column) = row.get(&Target::Name)?;
        let Some((name, changed)) = transform::host_name(label) else {
            return Some(Err(label.to_owned()));
        };
        if changed {
            self.push(
                row.location(Some(column)),
                codes::NAME_NORMALIZED,
                format!(
                    "`{label}` is not a valid host name; the host is named `{name}` and keeps the label as its description"
                ),
            );
        }
        let mut host = ModelHost::new(name.clone(), row.location(None));
        host.tenant = row.get(&Target::Tenant).map(|(v, _)| v.to_owned());
        host.mode = self.parse(row, &Target::Mode, "an assignment mode", transform::mode);
        host.lock = self.parse(row, &Target::Lock, "a yes or no", transform::boolean);
        host.site = row.get(&Target::Site).map(|(v, _)| v.to_owned());
        if changed {
            host.description = Some(label.to_owned());
        } else if let Some(description) = default_description {
            host.description = Some(description.to_owned());
        }
        self.merge_host(host, &row.location(None));
        Some(Ok(name))
    }

    fn merge_host(&mut self, host: ModelHost, location: &SourceLocation) {
        let Some(existing) = self.hosts.get_mut(&host.name) else {
            for (slot, interface) in host.interfaces.iter().enumerate() {
                self.interface_slots
                    .entry((host.name.clone(), interface.name.clone()))
                    .or_insert(slot);
            }
            self.hosts.insert(host.name.clone(), host);
            return;
        };
        let name = existing.name.clone();
        let loss = &mut self.loss;
        let text = |v: &String| v.clone();
        merge_field(
            &mut existing.tenant,
            host.tenant,
            text,
            "tenant",
            &name,
            location,
            loss,
        );
        merge_field(
            &mut existing.mode,
            host.mode,
            snake,
            "mode",
            &name,
            location,
            loss,
        );
        merge_field(
            &mut existing.lock,
            host.lock,
            bool::to_string,
            "lock",
            &name,
            location,
            loss,
        );
        merge_field(
            &mut existing.site,
            host.site,
            text,
            "site",
            &name,
            location,
            loss,
        );
        merge_field(
            &mut existing.description,
            host.description,
            text,
            "description",
            &name,
            location,
            loss,
        );
        // Repeated tags are dropped once, when the model is finished.
        existing.tags.extend(host.tags);
        for (key, value) in host.custom {
            existing.custom.entry(key).or_insert(value);
        }
        for interface in host.interfaces {
            merge_interface(
                existing,
                &mut self.interface_slots,
                interface,
                location,
                loss,
            );
        }
    }

    /// Credentials of a row for `host` (rule 3).
    fn credentials(&mut self, row: &Row<'_>, host: Option<&HostName>) -> Option<ItemKey> {
        if self.mapping.options.credentials == CredentialPolicy::Skip {
            return None;
        }
        let login = row.get(&Target::Login);
        let password = row.get(&Target::Password);
        if login.is_none() && password.is_none() {
            return None;
        }
        let Some(host) = host else {
            let column = login.or(password).map(|(_, c)| c);
            self.push(
                row.location(column),
                codes::CREDENTIAL_NO_HOST,
                "the row has credentials but no host to attach them to; they are not imported",
            );
            return None;
        };
        if let Some((value, column)) = login
            && value.chars().any(char::is_whitespace)
        {
            self.push(
                row.location(Some(column)),
                codes::CREDENTIAL_SUSPICIOUS,
                format!(
                    "the login `{value}` of {host} contains spaces and may be a description; it is stored as the login"
                ),
            );
        }
        if let Some((value, column)) = password {
            let numeric = row.cell(column).kind == CellKind::Number
                || (!value.is_empty() && value.chars().all(|c| c.is_ascii_digit()));
            if numeric {
                self.push(
                    row.location(Some(column)),
                    codes::CREDENTIAL_NUMERIC,
                    format!(
                        "the password of {host} is a number; a spreadsheet may have dropped leading zeros, so check it before relying on it"
                    ),
                );
            }
        }
        let value = CredentialValue {
            login: login.map(|(v, _)| Zeroizing::new(v.to_owned())),
            password: password.map(|(v, _)| Zeroizing::new(v.to_owned())),
        };
        let reference = ModelCredential {
            host: host.clone(),
            login: value.login.is_some(),
            password: value.password.is_some(),
            origin: row.location(None),
        };
        if let Some((existing, _)) = self.credentials.get(host) {
            let first = existing.origin.clone();
            self.push(
                row.location(None),
                codes::CREDENTIAL_DUPLICATE,
                format!("{host} already has credentials from {first}; these are not imported"),
            );
        } else {
            self.credentials.insert(host.clone(), (reference, value));
        }
        Some(ItemKey::Credential {
            host: host.to_string(),
        })
    }

    fn credentials_without_host(&mut self, row: &Row<'_>) {
        let _ = self.credentials(row, None);
    }

    /// A row of an address list: one address, a host when the row has a name.
    #[allow(clippy::too_many_lines)] // One row, in the order of the specification's rules.
    fn address_row(
        &mut self,
        row: &Row<'_>,
        column: usize,
        length: Option<IpNet>,
        host_description: Option<&str>,
    ) -> RowOutcome {
        let Some(text) = row.cell(column).value().map(transform::unescape) else {
            if row.has_data() {
                self.push(
                    row.location(Some(column)),
                    codes::ADDRESS_MISSING,
                    "the row has values but no address; it is not imported",
                );
                return Self::skipped(row);
            }
            return Self::skipped(row);
        };
        let label = row.get(&Target::Name).map(|(v, _)| v);
        let mut range = None;
        let ip = if let Some(ip) = shape::parse_address(text) {
            ip
        } else if let Some(net) = shape::parse_cidr(text) {
            let cidr = net.trunc();
            if cidr != IpNet::from(net.addr()) {
                self.add_row_prefix(row, cidr);
            }
            net.addr()
        } else if let Some((first, last)) = shape::parse_range(text) {
            range = Some((first, last));
            first
        } else {
            let suffix = label.map(|l| format!(" ({l})")).unwrap_or_default();
            self.push(
                row.location(Some(column)),
                codes::ADDRESS_UNPARSABLE,
                format!(
                    "`{text}` is not an address, a network or a range; the row{suffix} is not imported"
                ),
            );
            return Self::skipped(row);
        };
        if let Some((mask, mask_column)) = row.get(&Target::Mask) {
            match shape::parse_mask(mask, ip.is_ipv6()).and_then(|len| IpNet::new(ip, len).ok()) {
                Some(net) => self.add_row_prefix(row, net.trunc()),
                None => self.push(
                    row.location(Some(mask_column)),
                    codes::VALUE_INVALID,
                    format!(
                        "`{mask}` is not a subnet mask or prefix length; the value is left out"
                    ),
                ),
            }
        }
        if !row.has_data() {
            return RowOutcome {
                location: row.location(None),
                status: RowStatus::Free,
                items: Vec::new(),
            };
        }
        if let Some((first, last)) = range {
            return self.range_row(row, column, first, last, length);
        }

        let vrf_name = row.get(&Target::Vrf).map(|(v, _)| v.to_owned());
        let vrf = self.vrf(vrf_name.as_deref());
        let mut items = Vec::new();
        let host = match self.host_of(row, host_description) {
            Some(Ok(name)) => {
                items.push(ItemKey::Host {
                    name: name.to_string(),
                });
                Some(name)
            }
            Some(Err(label)) => {
                self.push(
                    row.location(row.get(&Target::Name).map(|(_, c)| c)),
                    codes::NAME_INVALID,
                    format!(
                        "`{label}` cannot be a host name; the address is imported without a host, with the label as its description"
                    ),
                );
                None
            }
            None => None,
        };
        let mut address = ModelAddress::new(ip, row.location(Some(column)));
        address.vrf = vrf_name;
        address.status = self.parse(row, &Target::Status, "a status", transform::status);
        address.dns_name = self.parse(row, &Target::DnsName, "a DNS name", |v| Fqdn::new(v).ok());
        address.description = row.get(&Target::Description).map(|(v, _)| v.to_owned());
        if host.is_none() && address.description.is_none() {
            address.description = label.map(str::to_owned);
        }
        address.tags = row_tags(row);
        address.custom = custom_values(row);
        if let Some(vid) = self.vlan_of(row) {
            let location = row.location(row.get(&Target::Vlan).map(|(_, c)| c));
            self.address_vlans.push(((vrf.clone(), ip), vid, location));
        }
        let mac = self.parse(row, &Target::Mac, "a MAC address", shape::parse_mac);
        let duid = self.parse(row, &Target::Duid, "a DUID", shape::parse_duid);
        let client_id = self.parse(
            row,
            &Target::ClientId,
            "a client identifier",
            transform::client_id,
        );
        if let Some(host) = &host {
            address.host = Some(host.clone());
            match row.get(&Target::Interface) {
                Some((interface, _)) => {
                    address.interface = Some(interface.to_owned());
                    let mut host_update = ModelHost::new(host.clone(), row.location(None));
                    host_update.interfaces.push(ModelInterface {
                        name: interface.to_owned(),
                        mac,
                        duid,
                        client_id,
                        origin: row.location(None),
                    });
                    self.merge_host(host_update, &row.location(None));
                    items.push(ItemKey::Interface {
                        host: host.to_string(),
                        name: interface.to_owned(),
                    });
                }
                None => self.pending.push(PendingInterface {
                    key: (vrf.clone(), ip),
                    host: host.clone(),
                    mac,
                }),
            }
        }
        let key = (vrf, ip);
        self.record_length(&key, length);
        if self.merge_address(address, &row.location(Some(column))) {
            items.push(address_key(&key));
        }
        if let Some(item) = self.credentials(row, host.as_ref()) {
            items.push(item);
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items,
        }
    }

    /// A range cell: its addresses, reserved, labeled with the row's name.
    fn range_row(
        &mut self,
        row: &Row<'_>,
        column: usize,
        first: IpAddr,
        last: IpAddr,
        length: Option<IpNet>,
    ) -> RowOutcome {
        let start = ip_to_u128(first);
        let end = ip_to_u128(last);
        // Both bounds are checked before anything is built: the whole IPv6 space holds one
        // address more than a u128 counts.
        let size = end.checked_sub(start).and_then(|span| span.checked_add(1));
        let count = size
            .filter(|size| *size <= MAX_RANGE)
            .and_then(|size| usize::try_from(size).ok());
        let Some(count) = count else {
            let size = size.map_or_else(|| "2^128".to_owned(), |size| size.to_string());
            self.push(
                row.location(Some(column)),
                codes::RANGE_TOO_LARGE,
                format!("the range {first}-{last} holds {size} addresses, more than {MAX_RANGE}; the row is not imported"),
            );
            return Self::skipped(row);
        };
        if count > MAX_RANGE_ADDRESSES.saturating_sub(self.range_addresses) {
            self.push(
                row.location(Some(column)),
                codes::RANGE_TOO_LARGE,
                format!("the range {first}-{last} holds {count} addresses, and the ranges of one import hold at most {MAX_RANGE_ADDRESSES} together; the row is not imported"),
            );
            return Self::skipped(row);
        }
        self.range_addresses += count;
        let label = row
            .get(&Target::Description)
            .or(row.get(&Target::Name))
            .map(|(v, _)| v.to_owned());
        let status = self
            .parse(row, &Target::Status, "a status", transform::status)
            .or(Some(tenko_core::ipam::Status::Reserved));
        let vrf_name = row.get(&Target::Vrf).map(|(v, _)| v.to_owned());
        let vrf = self.vrf(vrf_name.as_deref());
        self.credentials_without_host(row);
        let mut items = Vec::new();
        for value in start..=end {
            let ip = u128_to_ip(first, value);
            let mut address = ModelAddress::new(ip, row.location(Some(column)));
            address.vrf.clone_from(&vrf_name);
            address.status = status;
            address.description.clone_from(&label);
            let key = (vrf.clone(), ip);
            self.record_length(&key, length);
            if self.merge_address(address, &row.location(Some(column))) {
                items.push(address_key(&key));
            }
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items,
        }
    }

    /// A row of a device-centric sheet: one host, one interface and address per address
    /// column (rule 4).
    fn device_row(
        &mut self,
        row: &Row<'_>,
        columns: &[usize],
        length: Option<IpNet>,
        host_description: Option<&str>,
    ) -> RowOutcome {
        let has_address = columns.iter().any(|&c| !row.cell(c).is_empty());
        let host = match self.host_of(row, host_description) {
            Some(Ok(name)) => name,
            Some(Err(label)) => {
                self.push(
                    row.location(row.get(&Target::Name).map(|(_, c)| c)),
                    codes::NAME_INVALID,
                    format!("`{label}` cannot be a host name; the device row is not imported"),
                );
                return Self::skipped(row);
            }
            None => {
                if has_address || row.has_data() {
                    self.push(
                        row.location(None),
                        codes::NAME_MISSING,
                        "the device row has no name; it is not imported",
                    );
                }
                return Self::skipped(row);
            }
        };
        let mut items = vec![ItemKey::Host {
            name: host.to_string(),
        }];
        let vrf_name = row.get(&Target::Vrf).map(|(v, _)| v.to_owned());
        let vrf = self.vrf(vrf_name.as_deref());
        let status = self.parse(row, &Target::Status, "a status", transform::status);
        let (mac, dns_name) = self.single_address_values(row, columns);
        for (n, &column) in columns.iter().enumerate() {
            let Some(text) = row.cell(column).value().map(transform::unescape) else {
                continue;
            };
            let ip = if let Some(ip) = shape::parse_address(text) {
                ip
            } else if let Some(net) = shape::parse_cidr(text) {
                let cidr = net.trunc();
                if cidr != IpNet::from(net.addr()) {
                    self.add_row_prefix(row, cidr);
                }
                net.addr()
            } else {
                self.push(
                    row.location(Some(column)),
                    codes::ADDRESS_UNPARSABLE,
                    format!("`{text}` is not an address; the value is not imported"),
                );
                continue;
            };
            let interface = row
                .mapping
                .interface_of(column)
                .map_or_else(|| vocab::default_interface(n + 1), str::to_owned);
            let mut update = ModelHost::new(host.clone(), row.location(None));
            update.interfaces.push(ModelInterface {
                name: interface.clone(),
                mac,
                duid: None,
                client_id: None,
                origin: row.location(Some(column)),
            });
            self.merge_host(update, &row.location(Some(column)));
            items.push(ItemKey::Interface {
                host: host.to_string(),
                name: interface.clone(),
            });
            let mut address = ModelAddress::new(ip, row.location(Some(column)));
            address.vrf.clone_from(&vrf_name);
            address.host = Some(host.clone());
            address.interface = Some(interface);
            address.status = status;
            address.dns_name.clone_from(&dns_name);
            let key = (vrf.clone(), ip);
            self.record_length(&key, length);
            if self.merge_address(address, &row.location(Some(column))) {
                items.push(address_key(&key));
            }
        }
        let mut update = ModelHost::new(host.clone(), row.location(None));
        update.description = row.get(&Target::Description).map(|(v, _)| v.to_owned());
        update.tags = row_tags(row);
        update.custom = custom_values(row);
        self.merge_host(update, &row.location(None));
        if let Some(item) = self.credentials(row, Some(&host)) {
            items.push(item);
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items,
        }
    }

    /// The MAC address and DNS name of a device row: they belong to one address, so they
    /// apply when the row has one, and are reported as left out when it has none or
    /// several.
    fn single_address_values(
        &mut self,
        row: &Row<'_>,
        columns: &[usize],
    ) -> (Option<tenko_core::MacAddr>, Option<Fqdn>) {
        let addresses = columns
            .iter()
            .filter_map(|&c| row.cell(c).value().map(transform::unescape))
            .filter(|text| {
                shape::parse_address(text).is_some() || shape::parse_cidr(text).is_some()
            })
            .count();
        if addresses == 1 {
            return (
                self.parse(row, &Target::Mac, "a MAC address", shape::parse_mac),
                self.parse(row, &Target::DnsName, "a DNS name", |v| Fqdn::new(v).ok()),
            );
        }
        let has = if addresses == 0 { "none" } else { "several" };
        for target in [Target::Mac, Target::DnsName] {
            if let Some((value, column)) = row.get(&target) {
                self.push(
                    row.location(Some(column)),
                    codes::VALUE_INVALID,
                    format!("`{value}` belongs to one address, and the device row has {has}; the value is left out"),
                );
            }
        }
        (None, None)
    }

    /// A row of a host list.
    fn host_row(&mut self, row: &Row<'_>) -> RowOutcome {
        let host = match self.host_of(row, None) {
            Some(Ok(name)) => name,
            Some(Err(label)) => {
                self.push(
                    row.location(row.get(&Target::Name).map(|(_, c)| c)),
                    codes::NAME_INVALID,
                    format!("`{label}` cannot be a host name; the row is not imported"),
                );
                return Self::skipped(row);
            }
            None => {
                if row.has_data() {
                    self.push(
                        row.location(None),
                        codes::NAME_MISSING,
                        "the row has no host name; it is not imported",
                    );
                }
                return Self::skipped(row);
            }
        };
        let mut items = vec![ItemKey::Host {
            name: host.to_string(),
        }];
        let mut update = ModelHost::new(host.clone(), row.location(None));
        update.description = row.get(&Target::Description).map(|(v, _)| v.to_owned());
        update.tags = row_tags(row);
        update.custom = custom_values(row);
        if let Some((value, column)) = row.get(&Target::Interfaces) {
            let (entries, bad) = transform::interfaces(value);
            for entry in entries {
                items.push(ItemKey::Interface {
                    host: host.to_string(),
                    name: entry.name.clone(),
                });
                update.interfaces.push(ModelInterface {
                    name: entry.name,
                    mac: entry.mac,
                    duid: entry.duid,
                    client_id: None,
                    origin: row.location(Some(column)),
                });
            }
            for part in bad {
                self.push(
                    row.location(Some(column)),
                    codes::VALUE_INVALID,
                    format!("`{part}` is not `name`, `name=mac` or `name=mac=duid`; the interface is left out"),
                );
            }
        }
        let mac = self.parse(row, &Target::Mac, "a MAC address", shape::parse_mac);
        let duid = self.parse(row, &Target::Duid, "a DUID", shape::parse_duid);
        if (mac.is_some() || duid.is_some()) && update.interfaces.is_empty() {
            let name = row
                .get(&Target::Interface)
                .map_or_else(|| vocab::default_interface(1), |(v, _)| v.to_owned());
            update.interfaces.push(ModelInterface {
                name,
                mac,
                duid,
                client_id: None,
                origin: row.location(None),
            });
        }
        self.merge_host(update, &row.location(None));
        if let Some(item) = self.credentials(row, Some(&host)) {
            items.push(item);
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items,
        }
    }

    /// Remembers the prefix length of the network sheet an address came from, when the
    /// families match, for a proposal.
    fn record_length(&mut self, key: &(String, IpAddr), sheet: Option<IpNet>) {
        if let Some(net) = sheet
            && net.addr().is_ipv4() == key.1.is_ipv4()
        {
            self.address_lengths
                .entry(key.clone())
                .or_insert(net.prefix_len());
        }
    }

    /// Adds the network of an address with a length or mask.
    fn add_row_prefix(&mut self, row: &Row<'_>, cidr: IpNet) {
        let vrf_name = row.get(&Target::Vrf).map(|(v, _)| v.to_owned());
        let key = (self.vrf(vrf_name.as_deref()), cidr);
        let location = row.location(None);
        self.prefixes.entry(key).or_insert_with(|| {
            let mut prefix = ModelPrefix::new(cidr, PrefixSource::Row, location);
            prefix.vrf = vrf_name;
            prefix
        });
    }

    /// Merges an address into the model; returns whether it is (now) in the model.
    fn merge_address(&mut self, address: ModelAddress, location: &SourceLocation) -> bool {
        let key = (self.vrf(address.vrf.as_deref()), address.ip);
        let Some(existing) = self.addresses.get_mut(&key) else {
            self.addresses.insert(key, address);
            return true;
        };
        if address.host.is_some() && existing.host.is_some() && address.host != existing.host {
            let first = existing.origin.clone();
            let (ip, theirs, ours) = (
                address.ip,
                existing
                    .host
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                address
                    .host
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            );
            self.loss.push(
                location.clone(),
                codes::ADDRESS_DUPLICATE,
                format!("{ip} belongs to {theirs} at {first}; this row names {ours} and is not imported for it"),
            );
            return false;
        }
        if existing.host.is_none() {
            existing.host = address.host;
        }
        if existing.interface.is_none() {
            existing.interface = address.interface;
        }
        fill(&mut existing.status, address.status);
        fill(&mut existing.dns_name, address.dns_name);
        fill(&mut existing.description, address.description);
        existing.tags.extend(address.tags);
        for (k, v) in address.custom {
            existing.custom.entry(k).or_insert(v);
        }
        true
    }

    // ----- the whole import --------------------------------------------------------------

    fn finish(mut self) -> Translation {
        self.index_addresses();
        let proposals = self.propose();
        self.supernets();
        self.network_and_broadcast();
        self.address_vlans();
        self.default_interfaces();
        let tags = self.prefixes.values_mut().map(|p| &mut p.tags);
        let tags = tags.chain(self.hosts.values_mut().map(|h| &mut h.tags));
        tags.chain(self.addresses.values_mut().map(|a| &mut a.tags))
            .for_each(dedupe);

        let mut credentials = CredentialValues::default();
        let mut references = Vec::new();
        for (host, (reference, value)) in std::mem::take(&mut self.credentials) {
            if self.hosts.contains_key(&host) {
                references.push(reference);
                credentials.0.insert(host, value);
            }
        }
        let mut model = ImportModel {
            prefixes: self.prefixes.into_values().collect(),
            vlans: self.vlans.into_values().collect(),
            hosts: self.hosts.into_values().collect(),
            addresses: self.addresses.into_values().collect(),
            credentials: references,
        };
        model.sort();
        Translation {
            sheets: self.sheets,
            model,
            loss: self.loss,
            rows: self.rows,
            proposals,
            credentials,
        }
    }

    /// Single addresses of `Index` without a host sheet become addresses with the Index
    /// description.
    fn index_addresses(&mut self) {
        for (ip, description, location) in std::mem::take(&mut self.index_hosts) {
            if self.host_sheets.contains(&ip) {
                continue;
            }
            let key = (self.vrf(None), ip);
            if self.addresses.contains_key(&key) {
                continue;
            }
            let mut address = ModelAddress::new(ip, location);
            address.description = description;
            self.addresses.insert(key, address);
        }
    }

    /// The most specific prefix of the model or the store containing an address.
    fn containing(&self, vrf: &str, ip: IpAddr) -> Option<(IpNet, PrefixRole)> {
        let host = IpNet::from(ip);
        let model = enclosing(&self.prefixes, vrf, host)
            .map(|(net, p)| (net, p.role.unwrap_or(PrefixRole::Network)));
        let known = enclosing(&self.known, vrf, host).map(|(net, role)| (net, *role));
        match (model, known) {
            (Some(m), Some(k)) => Some(if m.0.prefix_len() >= k.0.prefix_len() {
                m
            } else {
                k
            }),
            (m, k) => m.or(k),
        }
    }

    /// Proposes prefixes for addresses outside every network (rule 4).
    fn propose(&mut self) -> Vec<Proposal> {
        if let Some(frozen) = self.frozen {
            return self.frozen_proposals(frozen);
        }
        let mut proposals: Nets<Proposal> = BTreeMap::new();
        let decisions = self.mapping.options.decisions();
        let keys: Vec<(String, IpAddr)> = self.addresses.keys().cloned().collect();
        for key in keys {
            let (vrf, ip) = &key;
            if let Some((net, _)) = enclosing(&proposals, vrf, IpNet::from(*ip)) {
                if let Some(proposal) = proposals.get_mut(&(vrf.clone(), net)) {
                    proposal.addresses.push(*ip);
                }
                continue;
            }
            if self.containing(vrf, *ip).is_some() {
                continue;
            }
            let bits: u8 = if ip.is_ipv4() { 32 } else { 128 };
            let mut length = self
                .address_lengths
                .get(&key)
                .copied()
                .unwrap_or(if ip.is_ipv4() { 24 } else { 64 });
            let mut net = IpNet::new(*ip, length).map_or(IpNet::from(*ip), |n| n.trunc());
            // No network contains the address, so none contains a block around it either:
            // the block only has to shrink until no network lies inside it. Each network
            // found inside moves the length past the bits it shares with the address.
            while length < bits {
                let Some(other) = inside(&self.prefixes, vrf, net)
                    .next()
                    .or_else(|| inside(&self.known, vrf, net).next())
                else {
                    break;
                };
                length = common_length(*ip, other.addr())
                    .saturating_add(1)
                    .clamp(length + 1, bits);
                net = IpNet::new(*ip, length).map_or(IpNet::from(*ip), |n| n.trunc());
            }
            let origin = self.addresses[&key].origin.clone();
            let vrf_name = self.addresses[&key].vrf.clone();
            let accepted = decisions.get(&net).copied().unwrap_or(true);
            proposals.insert(
                (vrf.clone(), net),
                Proposal {
                    cidr: net,
                    vrf: vrf_name,
                    addresses: vec![*ip],
                    accepted,
                    origin,
                },
            );
        }
        for ((vrf, net), proposal) in &proposals {
            let addresses: Vec<String> =
                proposal.addresses.iter().map(ToString::to_string).collect();
            if proposal.accepted {
                self.loss.push(
                    proposal.origin.clone(),
                    codes::PREFIX_PROPOSED,
                    format!(
                        "{} lie{} outside every known network; the import proposes the prefix {net}",
                        addresses.join(", "),
                        if addresses.len() == 1 { "s" } else { "" }
                    ),
                );
                let mut prefix =
                    ModelPrefix::new(*net, PrefixSource::Proposal, proposal.origin.clone());
                prefix.vrf.clone_from(&proposal.vrf);
                self.prefixes.insert((vrf.clone(), *net), prefix);
            } else {
                for ip in &proposal.addresses {
                    let key = (vrf.clone(), *ip);
                    if let Some(address) = self.addresses.remove(&key) {
                        self.loss.push(
                            address.origin,
                            codes::ADDRESS_NO_PREFIX,
                            format!("{ip} lies outside every known network and the proposed prefix {net} was rejected; it is not imported"),
                        );
                    }
                }
            }
        }
        proposals.into_values().collect()
    }

    /// The proposals an apply froze: their prefixes join the model, and addresses outside
    /// every network are left out as rejected.
    fn frozen_proposals(&mut self, frozen: &[(String, IpNet)]) -> Vec<Proposal> {
        let mut proposals = Vec::new();
        for (vrf, net) in frozen {
            let addresses: Vec<IpAddr> = self
                .addresses
                .range((vrf.clone(), net.network())..=(vrf.clone(), net.broadcast()))
                .map(|((_, ip), _)| *ip)
                .collect();
            let Some(first) = addresses.first() else {
                continue;
            };
            let address = &self.addresses[&(vrf.clone(), *first)];
            let mut prefix = ModelPrefix::new(*net, PrefixSource::Proposal, address.origin.clone());
            prefix.vrf.clone_from(&address.vrf);
            proposals.push(Proposal {
                cidr: *net,
                vrf: address.vrf.clone(),
                addresses,
                accepted: true,
                origin: address.origin.clone(),
            });
            self.prefixes.entry((vrf.clone(), *net)).or_insert(prefix);
        }
        let keys: Vec<(String, IpAddr)> = self.addresses.keys().cloned().collect();
        for key in keys {
            if self.containing(&key.0, key.1).is_none()
                && let Some(address) = self.addresses.remove(&key)
            {
                self.loss.push(
                    address.origin,
                    codes::ADDRESS_NO_PREFIX,
                    format!(
                        "{} lies outside every known network; it is not imported",
                        key.1
                    ),
                );
            }
        }
        proposals
    }

    /// A prefix that contains another one of the import or the store is a supernet.
    fn supernets(&mut self) {
        let supernets: Vec<(String, IpNet)> = self
            .prefixes
            .iter()
            .filter(|(_, prefix)| prefix.role.is_none())
            .map(|(key, _)| key)
            .filter(|(vrf, net)| {
                inside(&self.prefixes, vrf, *net).any(|other| other != *net)
                    || inside(&self.known, vrf, *net).any(|other| other != *net)
            })
            .cloned()
            .collect();
        for key in supernets {
            if let Some(prefix) = self.prefixes.get_mut(&key) {
                prefix.role = Some(PrefixRole::Supernet);
            }
        }
    }

    /// Gives the network holding an address the VLAN its row names; a second, different
    /// VLAN for the same network is reported and left out.
    fn address_vlans(&mut self) {
        for ((vrf, ip), vid, location) in std::mem::take(&mut self.address_vlans) {
            let key = enclosing(&self.prefixes, &vrf, IpNet::from(ip)).map(|(net, _)| (vrf, net));
            let Some(key) = key else {
                self.loss.push(
                    location,
                    codes::VALUE_INVALID,
                    format!(
                        "VLAN {vid} of {ip} is not set: the network holding the address is not part of this import"
                    ),
                );
                continue;
            };
            let Some(prefix) = self.prefixes.get_mut(&key) else {
                continue;
            };
            match prefix.vlan {
                None => prefix.vlan = Some(vid),
                Some(existing) if existing == vid => {}
                Some(existing) => {
                    let cidr = prefix.cidr;
                    self.loss.push(
                        location,
                        codes::VALUE_INVALID,
                        format!(
                            "{ip} names VLAN {vid}, but {cidr} already has VLAN {existing}; {vid} is left out"
                        ),
                    );
                }
            }
        }
    }

    /// Leaves out host addresses equal to the network or broadcast address of an IPv4
    /// network of /30 or wider (rule 6: `import.address.is_network`).
    fn network_and_broadcast(&mut self) {
        let mut left: BTreeMap<HostName, BTreeSet<String>> = BTreeMap::new();
        let keys: Vec<(String, IpAddr)> = self.addresses.keys().cloned().collect();
        for key in keys {
            let (vrf, ip) = &key;
            let Some((IpNet::V4(net), PrefixRole::Network)) = self.containing(vrf, *ip) else {
                continue;
            };
            if net.prefix_len() > 30 {
                continue;
            }
            let (code, what) = if *ip == IpAddr::V4(net.network()) {
                (codes::ADDRESS_IS_NETWORK, "network")
            } else if *ip == IpAddr::V4(net.broadcast()) {
                (codes::ADDRESS_IS_BROADCAST, "broadcast")
            } else {
                continue;
            };
            let Some(address) = self.addresses.remove(&key) else {
                continue;
            };
            let detail = match &address.host {
                Some(host) => format!(
                    "{ip} is the {what} address of {net} and cannot be a host address; the host {host} is imported without it (choose a wider network for the sheet to keep it)"
                ),
                None => {
                    format!("{ip} is the {what} address of {net}; it is not imported as an address")
                }
            };
            self.loss.push(address.origin, code, detail);
            if let (Some(host), Some(interface)) = (address.host, address.interface) {
                left.entry(host).or_default().insert(interface);
            }
        }
        self.drop_unused_interfaces(left);
    }

    /// Drops the interfaces in `left` (by host) that no remaining address uses and that
    /// carry no MAC address or DUID: one pass over the addresses for all of them.
    fn drop_unused_interfaces(&mut self, mut left: BTreeMap<HostName, BTreeSet<String>>) {
        if left.is_empty() {
            return;
        }
        for address in self.addresses.values() {
            step();
            if let (Some(host), Some(interface)) = (&address.host, &address.interface)
                && let Some(names) = left.get_mut(host)
            {
                names.remove(interface);
            }
        }
        for (host, names) in left {
            if let Some(model) = self.hosts.get_mut(&host) {
                model
                    .interfaces
                    .retain(|i| !names.contains(&i.name) || i.mac.is_some() || i.duid.is_some());
            }
        }
    }

    /// Names the interfaces of addresses whose source names none: `nic1`, `nic2`... per
    /// host, skipping names in use, in source order. The names of each host and the next
    /// number to try are kept, so naming does not grow with the square of the interfaces.
    fn default_interfaces(&mut self) {
        let mut taken: BTreeMap<HostName, (BTreeSet<String>, usize)> = BTreeMap::new();
        for pending in std::mem::take(&mut self.pending) {
            let Some(address) = self.addresses.get_mut(&pending.key) else {
                continue;
            };
            if address.interface.is_some() || address.host.as_ref() != Some(&pending.host) {
                continue;
            }
            let Some(host) = self.hosts.get_mut(&pending.host) else {
                continue;
            };
            let (names, next) = taken.entry(pending.host.clone()).or_insert_with(|| {
                let names = host.interfaces.iter().map(|i| i.name.clone()).collect();
                (names, 1)
            });
            let name = loop {
                step();
                let name = vocab::default_interface(*next);
                *next += 1;
                if names.insert(name.clone()) {
                    break name;
                }
            };
            host.interfaces.push(ModelInterface {
                name: name.clone(),
                mac: pending.mac,
                duid: None,
                client_id: None,
                origin: address.origin.clone(),
            });
            address.interface = Some(name);
        }
    }
}

/// How a sheet's network was found, for the unlisted note.
fn mask_note(name: &str, cidr: IpNet) -> String {
    if name.contains(['_', ' ']) {
        format!(
            "the length /{} comes from the sheet name",
            cidr.prefix_len()
        )
    } else {
        format!(
            "the length /{} was inferred from the rows (choose another in the mapping if it is wrong)",
            cidr.prefix_len()
        )
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn prefix_key(key: &(String, IpNet)) -> ItemKey {
    ItemKey::Prefix {
        vrf: key.0.clone(),
        cidr: key.1.to_string(),
    }
}

fn address_key(key: &(String, IpAddr)) -> ItemKey {
    ItemKey::Address {
        vrf: key.0.clone(),
        ip: key.1.to_string(),
    }
}

/// The tags of a row, each once. Rows that repeat tags of an earlier row are merged by
/// appending, and the model drops those repeats once when it is finished.
fn row_tags(row: &Row<'_>) -> Vec<String> {
    let mut tags = row
        .get(&Target::Tags)
        .map(|(v, _)| transform::tags(v))
        .unwrap_or_default();
    dedupe(&mut tags);
    tags
}

/// Custom field values of a row, by key.
fn custom_values(row: &Row<'_>) -> BTreeMap<String, String> {
    row.mapping
        .columns
        .iter()
        .filter_map(|c| match &c.target {
            Target::Custom(key) => Some((key, c)),
            _ => None,
        })
        .filter_map(|(key, c)| {
            let column = super::mapping::column_index(&c.column)?;
            row.cell(column)
                .value()
                .map(|v| (FieldKey::to_string(key), transform::unescape(v).to_owned()))
        })
        .collect()
}

fn fill<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

/// The `snake_case` name of an enumeration value.
fn snake<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        _ => String::new(),
    }
}

/// Sets a host field, reporting a different second value.
fn merge_field<T: PartialEq>(
    slot: &mut Option<T>,
    value: Option<T>,
    show: impl Fn(&T) -> String,
    field: &str,
    host: &HostName,
    location: &SourceLocation,
    loss: &mut LossReport,
) {
    let Some(value) = value else {
        return;
    };
    match slot {
        None => *slot = Some(value),
        Some(existing) if *existing == value => {}
        Some(existing) => loss.push(
            location.clone(),
            codes::HOST_CONFLICT,
            format!(
                "{host} has the {field} `{}` from an earlier row; `{}` is not imported",
                show(existing),
                show(&value)
            ),
        ),
    }
}

/// Merges an interface into its host, found by name through `slots` (the position of each
/// interface in its host's list).
fn merge_interface(
    host: &mut ModelHost,
    slots: &mut BTreeMap<(HostName, String), usize>,
    interface: ModelInterface,
    location: &SourceLocation,
    loss: &mut LossReport,
) {
    let name = host.name.clone();
    let key = (name.clone(), interface.name.clone());
    match slots
        .get(&key)
        .and_then(|&slot| host.interfaces.get_mut(slot))
    {
        None => {
            slots.insert(key, host.interfaces.len());
            host.interfaces.push(interface);
        }
        Some(existing) => {
            for (field, ours, theirs) in [
                (
                    "MAC",
                    existing.mac.map(|m| m.to_string()),
                    interface.mac.map(|m| m.to_string()),
                ),
                (
                    "DUID",
                    existing.duid.as_ref().map(ToString::to_string),
                    interface.duid.as_ref().map(ToString::to_string),
                ),
            ] {
                if let (Some(ours), Some(theirs)) = (ours, theirs)
                    && ours != theirs
                {
                    loss.push(
                        location.clone(),
                        codes::HOST_CONFLICT,
                        format!("interface {} of {name} has the {field} {ours} from an earlier row; {theirs} is not imported", existing.name),
                    );
                }
            }
            fill(&mut existing.mac, interface.mac);
            fill(&mut existing.duid, interface.duid);
            fill(&mut existing.client_id, interface.client_id);
        }
    }
}

/// Merges a second row of the same prefix into the first.
fn merge_prefix(
    existing: &mut ModelPrefix,
    prefix: ModelPrefix,
    _location: &SourceLocation,
    _loss: &mut LossReport,
) {
    fill(&mut existing.vrf, prefix.vrf);
    fill(&mut existing.role, prefix.role);
    fill(&mut existing.status, prefix.status);
    fill(&mut existing.vlan, prefix.vlan);
    fill(&mut existing.site, prefix.site);
    fill(&mut existing.alarm_warn, prefix.alarm_warn);
    fill(&mut existing.alarm_crit, prefix.alarm_crit);
    fill(&mut existing.alloc, prefix.alloc);
    fill(&mut existing.description, prefix.description);
    existing.tags.extend(prefix.tags);
    for (k, v) in prefix.custom {
        existing.custom.entry(k).or_insert(v);
    }
    if existing.source == PrefixSource::Index {
        existing.source = PrefixSource::Row;
        existing.origin = prefix.origin;
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn u128_to_ip(family: IpAddr, value: u128) -> IpAddr {
    match family {
        IpAddr::V4(_) => IpAddr::V4(u32::try_from(value).unwrap_or(u32::MAX).into()),
        IpAddr::V6(_) => IpAddr::V6(value.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use tenko_core::ipam::Status;

    use super::*;
    use crate::import::{
        mapping,
        read::{self, ReadLimits},
    };

    /// Translates CSV files with their suggested mapping.
    fn translate_csv(files: &[(&str, &str)]) -> Translation {
        let files: Vec<SourceFile> = files
            .iter()
            .map(|(name, text)| {
                read::read_file(name, text.as_bytes(), &ReadLimits::default()).expect("read")
            })
            .collect();
        let (_, suggested) = mapping::analyze(&files);
        translate(&files, &suggested, &KnownPrefixes::default(), None)
    }

    /// The lookup steps of one translation.
    fn steps_of(files: &[(&str, &str)]) -> u64 {
        STEPS.with(|steps| steps.set(0));
        translate_csv(files);
        STEPS.with(std::cell::Cell::get)
    }

    /// The rows and details of the loss entries with `code`.
    fn entries(translation: &Translation, code: &str) -> Vec<(Option<u32>, String)> {
        translation
            .loss
            .entries
            .iter()
            .filter(|entry| entry.code == code)
            .map(|entry| (entry.location.row, entry.detail.clone()))
            .collect()
    }

    fn has_address(translation: &Translation, ip: &str) -> bool {
        let ip: IpAddr = ip.parse().expect("ip");
        translation.model.addresses.iter().any(|a| a.ip == ip)
    }

    /// A range of the whole IPv6 space counts one address more than a u128 holds: it is
    /// refused with its row and size before any address is built, like a range of 2^127.
    #[test]
    fn a_range_of_the_whole_ipv6_space_is_refused_before_anything_is_built() {
        let translation = translate_csv(&[(
            "list.csv",
            "IP,Name\n\
             ::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,all\n\
             ::-7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,half\n",
        )]);
        assert_eq!(translation.model.addresses.len(), 0);
        let refused = entries(&translation, codes::RANGE_TOO_LARGE);
        let rows: Vec<Option<u32>> = refused.iter().map(|(row, _)| *row).collect();
        assert_eq!(rows, [Some(2), Some(3)]);
        assert!(
            refused[0].1.contains("holds 2^128 addresses"),
            "{refused:?}"
        );
        assert!(
            refused[1]
                .1
                .contains("holds 170141183460469231731687303715884105728 addresses"),
            "{refused:?}"
        );
    }

    /// A range of exactly the limit is split, one address more is refused, and ranges at
    /// both ends of the address space (the largest value of the type included) are split
    /// without wrapping. A prefix length of 0 adds its network and nothing else.
    #[test]
    fn ranges_at_the_limits_of_the_count_and_the_type_are_split_exactly() {
        let translation = translate_csv(&[(
            "list.csv",
            "IP,Name\n\
             2001:db8::-2001:db8::3ff,full\n\
             2001:db8:1::-2001:db8:1::400,over\n\
             ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,top\n\
             ::-::1,bottom\n\
             2001:db8:2::5/0,everything\n",
        )]);
        let refused = entries(&translation, codes::RANGE_TOO_LARGE);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].0, Some(3));
        assert!(refused[0].1.contains("holds 1025 addresses"), "{refused:?}");
        for ip in [
            "2001:db8::",
            "2001:db8::3ff",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::",
            "::1",
            "2001:db8:2::5",
        ] {
            assert!(has_address(&translation, ip), "{ip}");
        }
        assert!(!has_address(&translation, "2001:db8:1::"));
        assert_eq!(translation.model.addresses.len(), 1024 + 2 + 2 + 1);
        let everything: IpNet = "::/0".parse().expect("net");
        assert!(
            translation
                .model
                .prefixes
                .iter()
                .any(|p| p.cidr == everything)
        );
    }

    /// The ranges of one import are split into at most [`MAX_RANGE_ADDRESSES`] together:
    /// the range that would pass it is refused with its row and size, however many rows
    /// of allowed size the file holds.
    #[test]
    fn the_ranges_of_one_import_share_one_address_budget() {
        let mut text = "IP,Name\n".to_owned();
        for n in 0..65 {
            writeln!(text, "2001:db8:0:{n:x}::-2001:db8:0:{n:x}::3ff,range{n}").expect("text");
        }
        let translation = translate_csv(&[("list.csv", &text)]);
        assert_eq!(translation.model.addresses.len(), MAX_RANGE_ADDRESSES);
        let refused = entries(&translation, codes::RANGE_TOO_LARGE);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].0, Some(66));
        assert!(
            refused[0].1.contains("at most 65536 together"),
            "{refused:?}"
        );
    }

    /// The largest allowed range repeated row after row is charged every time: the budget
    /// bounds the work of splitting, not only the addresses kept.
    #[test]
    fn a_repeated_largest_range_is_charged_on_every_row() {
        let mut text = "IP,Name\n".to_owned();
        for n in 0..100 {
            writeln!(text, "2001:db8::-2001:db8::3ff,again{n}").expect("text");
        }
        let translation = translate_csv(&[("list.csv", &text)]);
        assert_eq!(translation.model.addresses.len(), 1024);
        let refused = entries(&translation, codes::RANGE_TOO_LARGE);
        let rows: Vec<Option<u32>> = refused.iter().map(|(row, _)| *row).collect();
        let expected: Vec<Option<u32>> = (66..=101).map(Some).collect();
        assert_eq!(rows, expected);
    }

    /// A device row keeps its tags and status, and the MAC address of its only address; a
    /// MAC address of a row with several addresses is reported as left out.
    #[test]
    fn a_device_row_keeps_its_tags_status_and_single_mac() {
        let translation = translate_csv(&[(
            "devices.csv",
            "Name,Nic1,Nic2,Tags,Status,MAC\n\
             web01,192.0.2.10,192.0.2.11,prod,planned,00:00:5e:00:53:01\n\
             web02,192.0.2.12,,lab,planned,00:00:5e:00:53:02\n\
             web03,n/a,,,,00:00:5e:00:53:03\n",
        )]);
        let host = |name: &str| {
            translation
                .model
                .hosts
                .iter()
                .find(|h| h.name.as_str() == name)
                .expect("host")
        };
        assert_eq!(host("web01").tags, ["prod"]);
        assert_eq!(host("web02").tags, ["lab"]);
        for address in &translation.model.addresses {
            assert_eq!(address.status, Some(Status::Planned), "{}", address.ip);
        }
        let mac = host("web02").interface("nic1").and_then(|i| i.mac);
        assert_eq!(
            mac.map(|m| m.to_string()),
            Some("00:00:5e:00:53:02".to_owned())
        );
        assert!(host("web01").interfaces.iter().all(|i| i.mac.is_none()));
        // A cell that is not an address does not count: web03 has none for its MAC.
        let left_out = entries(&translation, codes::VALUE_INVALID);
        let rows: Vec<Option<u32>> = left_out.iter().map(|(row, _)| *row).collect();
        assert_eq!(rows, [Some(2), Some(4)], "{left_out:?}");
        assert!(left_out[0].1.contains("00:00:5e:00:53:01"), "{left_out:?}");
        assert!(left_out[0].1.contains("has several"), "{left_out:?}");
        assert!(left_out[1].1.contains("has none"), "{left_out:?}");
    }

    /// Networks, addresses inside them and addresses that need a proposal: a file ten
    /// times larger takes at most about ten times the lookup steps.
    #[test]
    fn the_network_passes_grow_with_the_file_not_its_square() {
        let files = |n: usize| {
            let mut nets = "Network\n".to_owned();
            let mut addresses = "IP,Name\n".to_owned();
            for i in 0..n {
                let (a, b) = (i / 256, i % 256);
                writeln!(nets, "10.{a}.{b}.0/24").expect("text");
                writeln!(addresses, "10.{a}.{b}.5,inside{i}").expect("text");
                writeln!(addresses, "172.{}.{b}.9,outside{i}", 16 + a).expect("text");
            }
            (nets, addresses)
        };
        let (small_nets, small_addresses) = files(300);
        let (large_nets, large_addresses) = files(3000);
        let small = steps_of(&[
            ("nets.csv", &small_nets),
            ("addresses.csv", &small_addresses),
        ]);
        let large = steps_of(&[
            ("nets.csv", &large_nets),
            ("addresses.csv", &large_addresses),
        ]);
        assert!(small > 0);
        assert!(large <= small * 12, "{small} steps, then {large}");
    }

    /// One host with many unnamed interfaces and tags: naming the interfaces and dropping
    /// repeated tags grow with the rows, not with their square.
    #[test]
    fn interface_names_and_tags_of_one_host_grow_with_the_rows() {
        let files = |n: usize| {
            let mut addresses = "IP,Name\n".to_owned();
            let mut hosts = "Name,Tags\n".to_owned();
            for i in 0..n {
                writeln!(addresses, "192.0.{}.{},web01", i / 200, 1 + i % 200).expect("text");
                writeln!(hosts, "web01,t{i};shared").expect("text");
            }
            (addresses, hosts)
        };
        let (small_addresses, small_hosts) = files(300);
        let (large_addresses, large_hosts) = files(3000);
        let small = steps_of(&[("list.csv", &small_addresses), ("hosts.csv", &small_hosts)]);
        let large = steps_of(&[("list.csv", &large_addresses), ("hosts.csv", &large_hosts)]);
        assert!(large <= small * 12, "{small} steps, then {large}");

        let translation =
            translate_csv(&[("list.csv", &small_addresses), ("hosts.csv", &small_hosts)]);
        let host = &translation.model.hosts[0];
        assert_eq!(host.interfaces.len(), 300);
        assert_eq!(
            host.interface("nic300").map(|i| i.name.as_str()),
            Some("nic300")
        );
        assert_eq!(host.tags.len(), 301);
        let shared = host.tags.iter().filter(|t| *t == "shared").count();
        assert_eq!(shared, 1);
    }
}
