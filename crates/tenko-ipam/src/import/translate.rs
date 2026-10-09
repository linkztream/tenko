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
/// The name of the default VRF and tenant.
pub const DEFAULT_NAME: &str = "default";

/// Prefixes that exist in the store, by VRF name (lowercase).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownPrefixes(pub BTreeMap<String, Vec<(IpNet, PrefixRole)>>);

impl KnownPrefixes {
    /// The most specific known prefix of `vrf` containing `ip`.
    pub fn containing(&self, vrf: &str, ip: IpAddr) -> Option<(IpNet, PrefixRole)> {
        self.0
            .get(vrf)?
            .iter()
            .filter(|(net, _)| net.contains(&ip))
            .max_by_key(|(net, _)| net.prefix_len())
            .copied()
    }

    /// Whether a known prefix of `vrf` overlaps `net`.
    pub fn overlaps(&self, vrf: &str, net: &IpNet) -> bool {
        self.0.get(vrf).is_some_and(|nets| {
            nets.iter()
                .any(|(known, _)| known.contains(net) || net.contains(known))
        })
    }

    /// Whether a known prefix of `vrf` lies strictly inside `net`.
    pub fn inside(&self, vrf: &str, net: &IpNet) -> bool {
        self.0.get(vrf).is_some_and(|nets| {
            nets.iter()
                .any(|(known, _)| known != net && net.contains(known))
        })
    }
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

    let index = refs.iter().find_map(|r| {
        mapping
            .sheet(r.name)
            .filter(|m| m.kind == SheetKind::Index)
            .map(|m| (r.name, r.sheet, m))
    });
    let entries = index.map(|(name, sheet, sheet_mapping)| {
        builder.index(name, sheet, sheet_mapping);
        index_entries(sheet, sheet_mapping)
    });

    for sheet in &refs {
        let Some(sheet_mapping) = mapping.sheet(sheet.name) else {
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
    known: &'m KnownPrefixes,
    frozen: Option<&'m [(String, IpNet)]>,
    import_vrf: Option<&'m str>,
    loss: LossReport,
    prefixes: BTreeMap<(String, IpNet), ModelPrefix>,
    vlans: BTreeMap<(Option<String>, u16), ModelVlan>,
    hosts: BTreeMap<HostName, ModelHost>,
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
    fn new(mapping: &'m Mapping, known: &'m KnownPrefixes) -> Self {
        Self {
            mapping,
            known,
            frozen: None,
            import_vrf: mapping.options.vrf.as_deref(),
            loss: LossReport::default(),
            prefixes: BTreeMap::new(),
            vlans: BTreeMap::new(),
            hosts: BTreeMap::new(),
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
                .and_then(|h| sheet.cell(h as usize - 1, column).value());
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
        prefix.tags = row
            .get(&Target::Tags)
            .map(|(v, _)| transform::tags(v))
            .unwrap_or_default();
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
        match self.hosts.get_mut(&host.name) {
            Some(existing) => {
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
                for tag in host.tags {
                    if !existing.tags.contains(&tag) {
                        existing.tags.push(tag);
                    }
                }
                for (key, value) in host.custom {
                    existing.custom.entry(key).or_insert(value);
                }
                for interface in host.interfaces {
                    merge_interface(existing, interface, location, loss);
                }
            }
            None => {
                self.hosts.insert(host.name.clone(), host);
            }
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
        address.tags = row
            .get(&Target::Tags)
            .map(|(v, _)| transform::tags(v))
            .unwrap_or_default();
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

    /// A range cell: its addresses, reserved, labelled with the row's name.
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
        let count = end - start + 1;
        if count > MAX_RANGE {
            self.push(
                row.location(Some(column)),
                codes::RANGE_TOO_LARGE,
                format!("the range {first}-{last} holds {count} addresses, more than {MAX_RANGE}; the row is not imported"),
            );
            return Self::skipped(row);
        }
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
                mac: None,
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
            let key = (vrf.clone(), ip);
            self.record_length(&key, length);
            if self.merge_address(address, &row.location(Some(column))) {
                items.push(address_key(&key));
            }
        }
        if let Some((description, _)) = row.get(&Target::Description) {
            let mut update = ModelHost::new(host.clone(), row.location(None));
            update.description = Some(description.to_owned());
            self.merge_host(update, &row.location(None));
        }
        if let Some(item) = self.credentials(row, Some(&host)) {
            items.push(item);
        }
        RowOutcome {
            location: row.location(None),
            status: RowStatus::Imported,
            items,
        }
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
        update.tags = row
            .get(&Target::Tags)
            .map(|(v, _)| transform::tags(v))
            .unwrap_or_default();
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
        for tag in address.tags {
            if !existing.tags.contains(&tag) {
                existing.tags.push(tag);
            }
        }
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
        let model = self
            .prefixes
            .iter()
            .filter(|((v, net), _)| v == vrf && net.contains(&ip))
            .max_by_key(|((_, net), _)| net.prefix_len())
            .map(|((_, net), p)| (*net, p.role.unwrap_or(PrefixRole::Network)));
        let known = self.known.containing(vrf, ip);
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
        let mut proposals: BTreeMap<(String, IpNet), Proposal> = BTreeMap::new();
        let keys: Vec<(String, IpAddr)> = self.addresses.keys().cloned().collect();
        for key in keys {
            let (vrf, ip) = &key;
            if self.containing(vrf, *ip).is_some()
                || proposals
                    .keys()
                    .any(|(v, net)| v == vrf && net.contains(ip))
            {
                if let Some(proposal) = proposals
                    .iter_mut()
                    .find(|((v, net), _)| v == vrf && net.contains(ip))
                    .map(|(_, p)| p)
                {
                    proposal.addresses.push(*ip);
                }
                continue;
            }
            let bits: u8 = if ip.is_ipv4() { 32 } else { 128 };
            let mut length = self
                .address_lengths
                .get(&key)
                .copied()
                .unwrap_or(if ip.is_ipv4() { 24 } else { 64 });
            let overlapping = |builder: &Self, net: &IpNet| {
                builder
                    .prefixes
                    .keys()
                    .any(|(v, other)| v == vrf && (other.contains(net) || net.contains(other)))
                    || builder.known.overlaps(vrf, net)
            };
            let mut net = IpNet::new(*ip, length).map_or(IpNet::from(*ip), |n| n.trunc());
            while length < bits && overlapping(self, &net) {
                length += 1;
                net = IpNet::new(*ip, length).map_or(IpNet::from(*ip), |n| n.trunc());
            }
            let origin = self.addresses[&key].origin.clone();
            let vrf_name = self.addresses[&key].vrf.clone();
            let accepted = self.mapping.options.accepts(&net);
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
                .keys()
                .filter(|(v, ip)| v == vrf && net.contains(ip))
                .map(|(_, ip)| *ip)
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
        let nets: Vec<(String, IpNet)> = self.prefixes.keys().cloned().collect();
        for ((vrf, net), prefix) in &mut self.prefixes {
            if prefix.role.is_some() {
                continue;
            }
            let contains = nets
                .iter()
                .any(|(v, other)| v == vrf && other != net && net.contains(other))
                || self.known.inside(vrf, net);
            if contains {
                prefix.role = Some(PrefixRole::Supernet);
            }
        }
    }

    /// Gives the network holding an address the VLAN its row names; a second, different
    /// VLAN for the same network is reported and left out.
    fn address_vlans(&mut self) {
        for ((vrf, ip), vid, location) in std::mem::take(&mut self.address_vlans) {
            let key = self
                .prefixes
                .keys()
                .filter(|(v, net)| *v == vrf && net.contains(&ip))
                .max_by_key(|(_, net)| net.prefix_len())
                .cloned();
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
            if let (Some(host), Some(interface)) = (&address.host, &address.interface) {
                self.drop_interface_if_unused(host, interface);
            }
        }
    }

    fn drop_interface_if_unused(&mut self, host: &HostName, interface: &str) {
        let used = self
            .addresses
            .values()
            .any(|a| a.host.as_ref() == Some(host) && a.interface.as_deref() == Some(interface));
        if !used && let Some(model) = self.hosts.get_mut(host) {
            model
                .interfaces
                .retain(|i| i.name != interface || i.mac.is_some() || i.duid.is_some());
        }
    }

    /// Names the interfaces of addresses whose source names none: `nic1`, `nic2`... per
    /// host, skipping names in use, in source order.
    fn default_interfaces(&mut self) {
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
            let name = (1..=host.interfaces.len() + 1)
                .map(vocab::default_interface)
                .find(|name| host.interface(name).is_none())
                .unwrap_or_default();
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

fn merge_interface(
    host: &mut ModelHost,
    interface: ModelInterface,
    location: &SourceLocation,
    loss: &mut LossReport,
) {
    let name = host.name.clone();
    match host
        .interfaces
        .iter_mut()
        .find(|i| i.name == interface.name)
    {
        None => host.interfaces.push(interface),
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
    for tag in prefix.tags {
        if !existing.tags.contains(&tag) {
            existing.tags.push(tag);
        }
    }
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
