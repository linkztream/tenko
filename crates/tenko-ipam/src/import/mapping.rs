//! The mapping step: what each sheet is, where its header is, and what each column is
//! imported as; the analysis that suggests it (rules 1 to 3 of the import specification,
//! `docs/plans/import-fixtures.md`).
//!
//! # Rules
//!
//! - **Sheet kinds.** A sheet named `Index` is the network list: column `A` holds networks
//!   in CIDR notation or single addresses, column `B` their description. A sheet named
//!   like an address is a network ([`SheetKind::Network`]); its mask comes from `Index`
//!   when the network is listed there, else from a length in the name (`192.0.2.0_24`),
//!   else from the row count (255 rows mean a /24), widened until it holds the sheet's
//!   own addresses ([`MaskSource`]); the user can choose another in the mapping. A sheet
//!   named after an address that `Index` lists as a single address is one host
//!   ([`SheetKind::Host`]). Other sheets are lists whose rows stand on their own
//!   ([`SheetKind::List`]): a CSV export, a network list, a host list.
//! - **Header row by shape.** No header when the first row holds an address, a network or
//!   a range; otherwise the first of the first ten rows with a known header word.
//! - **Columns by synonym, then by shape.** Header words in English and Swedish suggest a
//!   [`Target`] ([`vocab`](super::vocab)). A sheet without a header borrows the column
//!   roles of the most common header layout of its workbook whose shapes fit (the
//!   positions are implied); failing that, roles come from value shapes. Unlabeled and
//!   unknown columns are ignored, and their values are listed in the loss report.
//! - **Credentials.** `Login`, `Användare`, `User`, `Pass`, `Lösen`, `Password` columns
//!   are credential targets: never IPAM fields, but operator secrets of the host. Their
//!   samples are never shown.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{
    read::{Sheet, SourceFile},
    shape::{self, Shape, ShapeCounts},
    vocab::{self, Target},
};

/// Values shown per column in the mapping step.
pub const SAMPLE_VALUES: usize = 5;
/// What a credential sample shows instead of its value.
pub const HIDDEN_SAMPLE: &str = "(hidden)";
/// Rows looked at for a header.
const HEADER_SCAN_ROWS: usize = 10;
/// Share of non-empty values a shape needs to suggest a target, in percent.
const DOMINANT_PERCENT: usize = 60;

/// What a sheet is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SheetKind {
    /// The network list named `Index`.
    Index,
    /// A sheet about one network: its rows are addresses or devices in it.
    Network,
    /// A sheet about one host, named after its address.
    Host,
    /// A list whose rows stand on their own (networks, hosts or addresses).
    List,
    /// Not imported.
    Skip,
}

/// Where the network of a sheet comes from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MaskSource {
    /// The `Index` sheet lists the network.
    Index,
    /// The sheet name carries the length (`192.0.2.0_24`).
    Name,
    /// The number of rows, widened to hold the sheet's addresses.
    RowCount,
    /// The addresses of a device-centric sheet.
    Addresses,
    /// The user chose it in the mapping.
    User,
}

/// What to do when the store already holds an object with different values.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Overwrite the fields the source sets (default).
    #[default]
    Update,
    /// Keep the store's values; the difference is listed.
    Skip,
    /// Refuse to apply while differences exist.
    Fail,
}

/// What to do with credential columns.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPolicy {
    /// Store them as operator secrets of their hosts (default; needs the vault and an
    /// account strong enough for IAM-07).
    #[default]
    Import,
    /// Leave them out.
    Skip,
}

/// The user's decision on a proposed prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProposalDecision {
    /// The proposed network, as the preview listed it.
    #[schema(value_type = String, example = "198.51.100.64/26")]
    pub cidr: IpNet,
    /// Whether to create it (the default when no decision is given).
    pub accept: bool,
}

/// Options of the whole import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportOptions {
    /// VRF of items that name none; the default VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// Tenant of hosts that name none; the default tenant when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// What to do with existing objects that differ.
    #[serde(default)]
    pub conflict: ConflictPolicy,
    /// What to do with credential columns.
    #[serde(default)]
    pub credentials: CredentialPolicy,
    /// Decisions on proposed prefixes; a proposal without a decision is accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposals: Vec<ProposalDecision>,
    /// Warning codes of the plan the user acknowledges (IPAM-06).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub acknowledge: BTreeSet<String>,
}

impl ImportOptions {
    /// Whether a proposed prefix is accepted.
    pub fn accepts(&self, cidr: &IpNet) -> bool {
        self.proposals
            .iter()
            .find(|d| &d.cidr == cidr)
            .is_none_or(|d| d.accept)
    }
}

/// The target of one column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ColumnMapping {
    /// The column letter (`A`).
    pub column: String,
    /// What the column is imported as.
    pub target: Target,
    /// For one of several address columns: the interface the addresses go on (`nic1`,
    /// from a `Nic1` header by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

/// The mapping of one sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SheetMapping {
    /// The sheet name (unique within the import).
    pub sheet: String,
    /// What the sheet is.
    pub kind: SheetKind,
    /// The network of a [`SheetKind::Network`] sheet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "192.0.2.0/24")]
    pub cidr: Option<IpNet>,
    /// The header row, 1-based; `None` when the data starts in row 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_row: Option<u32>,
    /// Column targets; columns not listed are ignored.
    #[serde(default)]
    pub columns: Vec<ColumnMapping>,
}

impl SheetMapping {
    /// The target of a column (0-based), `Ignore` when not mapped.
    pub fn target(&self, column: usize) -> Target {
        let letter = column_letter(column);
        self.columns
            .iter()
            .find(|c| c.column == letter)
            .map_or(Target::Ignore, |c| c.target.clone())
    }

    /// The columns (0-based) mapped to `target`, in order.
    pub fn columns_of(&self, target: &Target) -> Vec<usize> {
        let mut columns: Vec<usize> = self
            .columns
            .iter()
            .filter(|c| &c.target == target)
            .filter_map(|c| column_index(&c.column))
            .collect();
        columns.sort_unstable();
        columns
    }

    /// The interface name set for an address column.
    pub fn interface_of(&self, column: usize) -> Option<&str> {
        let letter = column_letter(column);
        self.columns
            .iter()
            .find(|c| c.column == letter)
            .and_then(|c| c.interface.as_deref())
    }

    /// The first row of data, 0-based.
    pub fn first_data_row(&self) -> usize {
        self.header_row.map_or(0, |row| row as usize)
    }
}

/// The mapping of an import: one entry per sheet, and the options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Mapping {
    /// Sheet mappings, in upload order.
    pub sheets: Vec<SheetMapping>,
    /// Options.
    #[serde(default)]
    pub options: ImportOptions,
}

impl Mapping {
    /// The mapping of a sheet.
    pub fn sheet(&self, name: &str) -> Option<&SheetMapping> {
        self.sheets.iter().find(|s| s.sheet == name)
    }
}

/// What the analysis found in one column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ColumnAnalysis {
    /// The column letter.
    pub column: String,
    /// The header text, if the sheet has a header row and the cell is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Shapes of the data values.
    pub shapes: ShapeCounts,
    /// Up to five distinct values (credential columns show [`HIDDEN_SAMPLE`]).
    pub samples: Vec<String>,
    /// The suggested target.
    pub suggested: Target,
}

/// What the analysis found in one sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SheetAnalysis {
    /// The sheet name (unique within the import).
    pub sheet: String,
    /// The file the sheet comes from.
    pub file: String,
    /// Rows up to the last non-empty one.
    pub rows: usize,
    /// Rows after the header with at least one value.
    pub data_rows: usize,
    /// Columns up to the widest row.
    pub width: usize,
    /// Where the suggested network of a network sheet comes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_source: Option<MaskSource>,
    /// Whether the `Index` sheet lists the sheet's network or address.
    pub listed_in_index: bool,
    /// Where the column roles of a sheet without header come from: the sheet whose header
    /// layout was borrowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_from: Option<String>,
    /// Columns.
    pub columns: Vec<ColumnAnalysis>,
    /// The suggested mapping of the sheet.
    pub suggested: SheetMapping,
}

/// One sheet of an import with its unique name.
#[derive(Debug, Clone, Copy)]
pub struct SheetRef<'a> {
    /// The unique name.
    pub name: &'a str,
    /// The file.
    pub file: &'a SourceFile,
    /// The sheet.
    pub sheet: &'a Sheet,
}

/// Unique sheet names across the files of an import: a name that repeats gets ` (2)`,
/// ` (3)` and so on, in upload order.
pub fn sheet_names(files: &[SourceFile]) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut names = Vec::new();
    for file in files {
        for sheet in &file.sheets {
            let count = seen.entry(sheet.name.clone()).or_default();
            *count += 1;
            names.push(if *count == 1 {
                sheet.name.clone()
            } else {
                format!("{} ({count})", sheet.name)
            });
        }
    }
    names
}

/// The sheets of an import with their unique names.
pub fn sheets<'a>(files: &'a [SourceFile], names: &'a [String]) -> Vec<SheetRef<'a>> {
    let mut refs = Vec::new();
    let mut index = 0;
    for file in files {
        for sheet in &file.sheets {
            refs.push(SheetRef {
                name: &names[index],
                file,
                sheet,
            });
            index += 1;
        }
    }
    refs
}

/// The letter of a 0-based column (`0` → `A`, `26` → `AA`).
pub fn column_letter(column: usize) -> String {
    let mut n = column + 1;
    let mut letters = Vec::new();
    while n > 0 {
        let rem = (n - 1) % 26;
        letters.push(char::from(b'A' + u8::try_from(rem).unwrap_or(0)));
        n = (n - 1) / 26;
    }
    letters.iter().rev().collect()
}

/// The 0-based index of a column letter.
pub fn column_index(letter: &str) -> Option<usize> {
    if letter.is_empty() || letter.len() > 3 {
        return None;
    }
    let mut n = 0usize;
    for c in letter.chars() {
        let c = c.to_ascii_uppercase();
        if !c.is_ascii_uppercase() {
            return None;
        }
        n = n * 26 + usize::from(u8::try_from(c).ok()? - b'A' + 1);
    }
    Some(n - 1)
}

/// Whether a sheet is the network list.
pub fn is_index_name(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case("index")
}

/// The address (and length, when the name carries one) of a sheet named like an
/// address: `192.0.2.0`, `192.0.2.0_24`, `192.0.2.0 24`.
pub fn sheet_address(name: &str) -> Option<(IpAddr, Option<u8>)> {
    let name = name.trim();
    if let Some(ip) = shape::parse_address(name) {
        return Some((ip, None));
    }
    let (head, tail) = name.rsplit_once(['_', ' '])?;
    let ip = shape::parse_address(head)?;
    let len: u8 = tail.trim().parse().ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    (len <= bits).then_some((ip, Some(len)))
}

/// The entries of the `Index` sheet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexEntries {
    /// Listed networks with description and 0-based row.
    pub networks: Vec<(IpNet, Option<String>, usize)>,
    /// Listed single addresses with description and 0-based row.
    pub hosts: Vec<(IpAddr, Option<String>, usize)>,
}

impl IndexEntries {
    /// The listed network whose network address is `ip`.
    pub fn network_at(&self, ip: IpAddr) -> Option<&(IpNet, Option<String>, usize)> {
        self.networks.iter().find(|(net, _, _)| net.network() == ip)
    }

    /// The listed network equal to `cidr`.
    pub fn network(&self, cidr: &IpNet) -> Option<&(IpNet, Option<String>, usize)> {
        self.networks.iter().find(|(net, _, _)| net == cidr)
    }

    /// The listed single address `ip`.
    pub fn host(&self, ip: IpAddr) -> Option<&(IpAddr, Option<String>, usize)> {
        self.hosts.iter().find(|(addr, _, _)| *addr == ip)
    }
}

/// Reads the `Index` entries of a sheet with its mapping: the [`Target::Prefix`] column
/// holds networks or single addresses, the [`Target::Description`] column their
/// description. Values that are neither are skipped here (translation reports them).
pub fn index_entries(sheet: &Sheet, mapping: &SheetMapping) -> IndexEntries {
    let mut entries = IndexEntries::default();
    let Some(&network_column) = mapping
        .columns_of(&Target::Prefix)
        .first()
        .or(mapping.columns_of(&Target::Address).first())
    else {
        return entries;
    };
    let description_column = mapping.columns_of(&Target::Description).first().copied();
    for row in mapping.first_data_row()..sheet.rows.len() {
        let Some(value) = sheet.cell(row, network_column).value() else {
            continue;
        };
        let description = description_column
            .and_then(|c| sheet.cell(row, c).value())
            .map(str::to_owned);
        if let Some(ip) = shape::parse_address(value) {
            entries.hosts.push((ip, description, row));
        } else if let Some(net) = shape::parse_cidr(value) {
            entries.networks.push((net.trunc(), description, row));
        }
    }
    entries
}

/// Finds the header row (0-based) of a sheet by shape: none when the first row holds an
/// address, a network or a range, else the first of the first ten rows with a known
/// header word, else the first row when it is all text and the second holds an address.
pub fn detect_header(sheet: &Sheet) -> Option<usize> {
    let addressy = |row: usize| {
        sheet.rows.get(row).is_some_and(|cells| {
            cells.iter().any(|cell| {
                matches!(
                    shape::shape_of(&cell.text),
                    Shape::Address | Shape::Cidr | Shape::Range
                )
            })
        })
    };
    if addressy(0) {
        return None;
    }
    for row in 0..sheet.rows.len().min(HEADER_SCAN_ROWS) {
        if addressy(row) {
            break;
        }
        let known = sheet.rows[row]
            .iter()
            .filter_map(|cell| cell.value())
            .any(|text| vocab::target_for_header(text).is_some());
        if known {
            return Some(row);
        }
    }
    let first_is_text = sheet.rows.first().is_some_and(|cells| {
        let values: Vec<&str> = cells.iter().filter_map(|c| c.value()).collect();
        !values.is_empty()
            && values
                .iter()
                .all(|text| shape::shape_of(text) == Shape::Text)
    });
    (first_is_text && addressy(1)).then_some(0)
}

/// Shapes and samples of one column from `first_row` on.
fn profile(sheet: &Sheet, column: usize, first_row: usize) -> (ShapeCounts, Vec<String>) {
    let mut counts = ShapeCounts::default();
    let mut samples: Vec<String> = Vec::new();
    for row in first_row..sheet.rows.len() {
        let cell = sheet.cell(row, column);
        counts.add(shape::shape_of(&cell.text));
        if let Some(value) = cell.value()
            && samples.len() < SAMPLE_VALUES
            && !samples.iter().any(|s| s == value)
        {
            samples.push(value.to_owned());
        }
    }
    (counts, samples)
}

/// The target a column's shapes suggest when the header says nothing.
fn target_for_shapes(counts: &ShapeCounts) -> Option<Target> {
    match counts.dominant(DOMINANT_PERCENT)? {
        Shape::Address | Shape::Range => Some(Target::Address),
        Shape::Cidr => Some(Target::Prefix),
        Shape::Mac => Some(Target::Mac),
        Shape::Duid => Some(Target::Duid),
        _ => None,
    }
}

/// Whether a target can hold values of the given dominant shape (for borrowing a header
/// layout by position).
fn fits(target: &Target, counts: &ShapeCounts) -> bool {
    if counts.filled() == 0 {
        return true;
    }
    let dominant = counts.dominant(DOMINANT_PERCENT);
    match target {
        Target::Address => matches!(dominant, Some(Shape::Address)),
        Target::Prefix => matches!(dominant, Some(Shape::Cidr)),
        Target::Mac => matches!(dominant, Some(Shape::Mac)),
        Target::Duid => matches!(dominant, Some(Shape::Duid)),
        _ => !matches!(dominant, Some(Shape::Address | Shape::Cidr)),
    }
}

/// A header layout of an analyzed sheet, for sheets without a header.
#[derive(Debug, Clone)]
struct Layout {
    sheet: String,
    targets: Vec<Target>,
    interfaces: Vec<Option<String>>,
}

/// Analyzes the sheets of an import and suggests a mapping.
pub fn analyze(files: &[SourceFile]) -> (Vec<SheetAnalysis>, Mapping) {
    let names = sheet_names(files);
    let refs = sheets(files, &names);

    // First pass: headers and header-based targets, so sheets without a header can borrow.
    let mut drafts: Vec<Draft> = refs.iter().map(|r| Draft::new(r)).collect();
    let layouts: Vec<Layout> = drafts
        .iter()
        .filter(|d| d.header.is_some() && !is_index_name(&d.name))
        .map(|d| Layout {
            sheet: d.name.clone(),
            targets: d.targets.clone(),
            interfaces: d.interfaces.clone(),
        })
        .collect();
    for (draft, sheet) in drafts.iter_mut().zip(&refs) {
        if draft.header.is_none() && !is_index_name(&draft.name) {
            draft.borrow_or_infer(sheet.sheet, &layouts);
        }
        if is_index_name(&draft.name) {
            draft.index_columns(sheet.sheet);
        }
    }

    // The Index sheet, then sheet kinds and networks.
    let index = drafts
        .iter()
        .zip(&refs)
        .find(|(d, _)| is_index_name(&d.name))
        .map(|(d, r)| index_entries(r.sheet, &d.mapping(SheetKind::Index, None)));
    let mut results = Vec::with_capacity(drafts.len());
    let mut mapping = Mapping::default();
    for (draft, sheet) in drafts.into_iter().zip(&refs) {
        let finished = draft.finish(sheet, index.as_ref());
        mapping.sheets.push(finished.suggested.clone());
        results.push(finished);
    }
    (results, mapping)
}

/// The analysis of one sheet while it is built.
struct Draft {
    name: String,
    header: Option<usize>,
    width: usize,
    headers: Vec<Option<String>>,
    targets: Vec<Target>,
    interfaces: Vec<Option<String>>,
    roles_from: Option<String>,
}

impl Draft {
    fn new(sheet: &SheetRef<'_>) -> Self {
        let header = detect_header(sheet.sheet);
        let width = sheet.sheet.width();
        let first = header.map_or(0, |h| h + 1);
        let mut headers = Vec::with_capacity(width);
        let mut targets = Vec::with_capacity(width);
        for column in 0..width {
            let text = header
                .and_then(|h| sheet.sheet.cell(h, column).value())
                .map(str::to_owned);
            let (counts, _) = profile(sheet.sheet, column, first);
            let target = match (&header, &text) {
                (Some(_), Some(text)) => vocab::target_for_header(text)
                    .or_else(|| target_for_shapes(&counts))
                    .unwrap_or(Target::Ignore),
                // An unlabeled column under a header row is never imported; without a
                // header the roles are borrowed or inferred later.
                (Some(_), None) | (None, _) => Target::Ignore,
            };
            headers.push(text);
            targets.push(target);
        }
        let mut draft = Self {
            name: sheet.name.to_owned(),
            header,
            width,
            headers,
            targets,
            interfaces: vec![None; width],
            roles_from: None,
        };
        draft.name_interfaces();
        draft
    }

    /// Gives each of several address columns its interface name (`Nic1` → `nic1`).
    fn name_interfaces(&mut self) {
        let addresses: Vec<usize> = (0..self.width)
            .filter(|&c| self.targets[c] == Target::Address)
            .collect();
        if addresses.len() < 2 {
            self.interfaces = vec![None; self.width];
            return;
        }
        for (n, &column) in addresses.iter().enumerate() {
            let named = self.headers[column]
                .as_deref()
                .and_then(vocab::numbered_interface);
            self.interfaces[column] =
                Some(named.unwrap_or_else(|| vocab::default_interface(n + 1)));
        }
    }

    /// Roles for a sheet without a header: the most common fitting header layout of the
    /// upload, else value shapes.
    fn borrow_or_infer(&mut self, sheet: &Sheet, layouts: &[Layout]) {
        let profiles: Vec<ShapeCounts> = (0..self.width).map(|c| profile(sheet, c, 0).0).collect();
        let mut candidates: BTreeMap<Vec<Target>, (usize, &Layout)> = BTreeMap::new();
        for layout in layouts {
            if layout.targets.len() < self.width {
                continue;
            }
            let targets = &layout.targets[..self.width];
            let anchored = targets
                .first()
                .is_some_and(|t| matches!(t, Target::Address | Target::Prefix));
            let all_fit = targets.iter().zip(&profiles).all(|(t, c)| fits(t, c));
            if anchored && all_fit {
                candidates
                    .entry(targets.to_vec())
                    .and_modify(|(count, _)| *count += 1)
                    .or_insert((1, layout));
            }
        }
        if let Some((targets, (_, layout))) = candidates
            .into_iter()
            .max_by_key(|(_, (count, layout))| (*count, std::cmp::Reverse(layout.sheet.clone())))
        {
            self.targets = targets;
            self.interfaces = layout.interfaces[..self.width].to_vec();
            self.roles_from = Some(layout.sheet.clone());
            return;
        }
        let mut named = false;
        for (column, counts) in profiles.iter().enumerate() {
            self.targets[column] = match target_for_shapes(counts) {
                Some(target) => target,
                None if !named && counts.dominant(DOMINANT_PERCENT) == Some(Shape::Text) => {
                    named = true;
                    Target::Name
                }
                None => Target::Ignore,
            };
        }
        self.name_interfaces();
    }

    /// The `Index` sheet: networks or single addresses in the first column that holds
    /// them, descriptions in the first text column after it.
    fn index_columns(&mut self, sheet: &Sheet) {
        let first = self.header.map_or(0, |h| h + 1);
        let profiles: Vec<ShapeCounts> = (0..self.width)
            .map(|c| profile(sheet, c, first).0)
            .collect();
        let network = (0..self.width).find(|&c| {
            matches!(self.targets[c], Target::Prefix | Target::Address)
                || matches!(
                    profiles[c].dominant(DOMINANT_PERCENT),
                    Some(Shape::Cidr | Shape::Address)
                )
        });
        let description = network.and_then(|n| {
            (n + 1..self.width).find(|&c| {
                self.targets[c] == Target::Description
                    || profiles[c].dominant(DOMINANT_PERCENT) == Some(Shape::Text)
            })
        });
        self.targets = vec![Target::Ignore; self.width];
        if let Some(column) = network {
            self.targets[column] = Target::Prefix;
        }
        if let Some(column) = description {
            self.targets[column] = Target::Description;
        }
        self.interfaces = vec![None; self.width];
    }

    fn mapping(&self, kind: SheetKind, cidr: Option<IpNet>) -> SheetMapping {
        SheetMapping {
            sheet: self.name.clone(),
            kind,
            cidr,
            header_row: self
                .header
                .map(|h| u32::try_from(h + 1).unwrap_or(u32::MAX)),
            columns: self
                .targets
                .iter()
                .enumerate()
                .filter(|(_, t)| **t != Target::Ignore)
                .map(|(column, target)| ColumnMapping {
                    column: column_letter(column),
                    target: target.clone(),
                    interface: self.interfaces[column].clone(),
                })
                .collect(),
        }
    }

    fn finish(self, sheet: &SheetRef<'_>, index: Option<&IndexEntries>) -> SheetAnalysis {
        let first = self.header.map_or(0, |h| h + 1);
        let data_rows = (first..sheet.sheet.rows.len())
            .filter(|&r| sheet.sheet.rows[r].iter().any(|c| !c.is_empty()))
            .count();
        let recognized = self.targets.iter().any(|t| {
            matches!(
                t,
                Target::Address | Target::Prefix | Target::Name | Target::Interfaces
            )
        });
        let mut mask_source = None;
        let mut listed = false;
        let (kind, cidr) = if is_index_name(&self.name) {
            (SheetKind::Index, None)
        } else if let Some((ip, length)) = sheet_address(&self.name) {
            if let Some(entries) = index
                && entries.host(ip).is_some()
                && length.is_none()
            {
                listed = true;
                (SheetKind::Host, None)
            } else if let Some((net, _, _)) = index.and_then(|e| e.network_at(ip)) {
                listed = true;
                mask_source = Some(MaskSource::Index);
                (SheetKind::Network, Some(*net))
            } else if let Some(length) = length {
                mask_source = Some(MaskSource::Name);
                listed = index.is_some_and(|e| {
                    IpNet::new(ip, length).is_ok_and(|n| e.network(&n.trunc()).is_some())
                });
                (
                    SheetKind::Network,
                    IpNet::new(ip, length).ok().map(|n| n.trunc()),
                )
            } else if sheet.sheet.is_empty() {
                (SheetKind::Skip, None)
            } else {
                let addresses: Vec<usize> = (0..self.width)
                    .filter(|&c| self.targets[c] == Target::Address)
                    .collect();
                let (net, source) = infer_network(sheet.sheet, ip, &addresses, first, data_rows);
                mask_source = Some(source);
                (SheetKind::Network, Some(net))
            }
        } else if sheet.sheet.is_empty() || !recognized {
            (SheetKind::Skip, None)
        } else {
            (SheetKind::List, None)
        };
        let suggested = self.mapping(kind, cidr);
        let columns = (0..self.width)
            .map(|column| {
                let (shapes, samples) = profile(sheet.sheet, column, first);
                let target = self.targets[column].clone();
                let samples = if target.is_credential()
                    || self.headers[column]
                        .as_deref()
                        .and_then(vocab::target_for_header)
                        .is_some_and(|t| t.is_credential())
                {
                    vec![HIDDEN_SAMPLE.to_owned(); samples.len().min(1)]
                } else {
                    samples
                };
                ColumnAnalysis {
                    column: column_letter(column),
                    header: self.headers[column].clone(),
                    shapes,
                    samples,
                    suggested: target,
                }
            })
            .collect();
        SheetAnalysis {
            sheet: self.name,
            file: sheet.file.name.clone(),
            rows: sheet.sheet.rows.len(),
            data_rows,
            width: self.width,
            mask_source,
            listed_in_index: listed,
            roles_from: self.roles_from,
            columns,
            suggested,
        }
    }
}

/// The network of a sheet named after `ip` that `Index` does not list: from the row count
/// (a pre-filled list of a /24 has about 255 rows), widened while the name stays the
/// network address until the block holds the sheet's own addresses near `ip` (the same
/// /24 or /64). A device-centric sheet (several address columns) uses its addresses
/// only, and a /24 or /64 when they say nothing.
pub fn infer_network(
    sheet: &Sheet,
    ip: IpAddr,
    address_columns: &[usize],
    first_row: usize,
    data_rows: usize,
) -> (IpNet, MaskSource) {
    let bits: u8 = if ip.is_ipv4() { 32 } else { 128 };
    let neighbourhood: u8 = if ip.is_ipv4() { 24 } else { 64 };
    let near = IpNet::new(ip, neighbourhood).map(|n| n.trunc()).ok();
    let mut own: Vec<IpAddr> = Vec::new();
    for row in first_row..sheet.rows.len() {
        for &column in address_columns {
            let text = &sheet.cell(row, column).text;
            let found = shape::parse_address(text)
                .map(|a| vec![a])
                .or_else(|| shape::parse_range(text).map(|(a, b)| vec![a, b]))
                .or_else(|| shape::parse_cidr(text).map(|n| vec![n.addr()]))
                .unwrap_or_default();
            for address in found {
                if near.is_some_and(|n| n.contains(&address)) && address >= ip {
                    own.push(address);
                }
            }
        }
    }
    let device_centric = address_columns.len() >= 2;
    let mut length = if device_centric {
        bits
    } else {
        let rows = u32::try_from(data_rows.max(1)).unwrap_or(u32::MAX);
        let block_bits = u8::try_from(32 - (rows - 1).leading_zeros()).unwrap_or(bits);
        bits.saturating_sub(block_bits)
    };
    let aligned = |len: u8| IpNet::new(ip, len).is_ok_and(|n| n.network() == ip);
    while length > 0
        && own
            .iter()
            .any(|a| !IpNet::new(ip, length).is_ok_and(|n| n.contains(a)))
        && aligned(length - 1)
    {
        length -= 1;
    }
    let source = if device_centric {
        if length == bits && aligned(neighbourhood) {
            length = neighbourhood;
        }
        MaskSource::Addresses
    } else {
        MaskSource::RowCount
    };
    let net = IpNet::new(ip, length).map_or_else(|_| IpNet::from(ip), |n| n.trunc());
    (net, source)
}

/// Why a mapping does not fit its upload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MappingError(pub String);

/// Checks a mapping against the sheets of its upload: every sheet mapped once, columns
/// inside the sheet and mapped once, network sheets with a network, header rows inside
/// the sheet, one name column at most.
///
/// # Errors
///
/// Returns [`MappingError`] naming the first problem.
pub fn validate(mapping: &Mapping, analyses: &[SheetAnalysis]) -> Result<(), MappingError> {
    let mut seen = BTreeSet::new();
    for sheet in &mapping.sheets {
        let Some(found) = analyses.iter().find(|a| a.sheet == sheet.sheet) else {
            return Err(MappingError(format!(
                "the upload has no sheet `{}`",
                sheet.sheet
            )));
        };
        if !seen.insert(sheet.sheet.as_str()) {
            return Err(MappingError(format!(
                "sheet `{}` is mapped twice",
                sheet.sheet
            )));
        }
        if let Some(row) = sheet.header_row
            && (row == 0 || row as usize > found.rows.max(1))
        {
            return Err(MappingError(format!(
                "sheet `{}` has no row {row} for a header",
                sheet.sheet
            )));
        }
        if sheet.kind == SheetKind::Network && sheet.cidr.is_none() {
            return Err(MappingError(format!(
                "sheet `{}` is a network sheet without a network",
                sheet.sheet
            )));
        }
        if let Some(cidr) = sheet.cidr
            && cidr != cidr.trunc()
        {
            return Err(MappingError(format!(
                "the network {cidr} of sheet `{}` has host bits",
                sheet.sheet
            )));
        }
        let mut columns = BTreeSet::new();
        let mut singles = BTreeSet::new();
        for column in &sheet.columns {
            let Some(index) = column_index(&column.column) else {
                return Err(MappingError(format!(
                    "`{}` is not a column letter (sheet `{}`)",
                    column.column, sheet.sheet
                )));
            };
            if index >= found.width.max(1) {
                return Err(MappingError(format!(
                    "sheet `{}` has no column {}",
                    sheet.sheet, column.column
                )));
            }
            if !columns.insert(index) {
                return Err(MappingError(format!(
                    "column {} of sheet `{}` is mapped twice",
                    column.column, sheet.sheet
                )));
            }
            if !matches!(column.target, Target::Address | Target::Ignore)
                && !singles.insert(column.target.clone())
            {
                return Err(MappingError(format!(
                    "sheet `{}` maps two columns to `{}`",
                    sheet.sheet, column.target
                )));
            }
        }
    }
    for analysis in analyses {
        if !seen.contains(analysis.sheet.as_str()) {
            return Err(MappingError(format!(
                "sheet `{}` has no mapping (map it with kind `skip` to leave it out)",
                analysis.sheet
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_letters_round_trip() {
        for (index, letter) in [
            (0, "A"),
            (4, "E"),
            (25, "Z"),
            (26, "AA"),
            (27, "AB"),
            (701, "ZZ"),
            (702, "AAA"),
        ] {
            assert_eq!(column_letter(index), letter);
            assert_eq!(column_index(letter), Some(index));
        }
        assert_eq!(column_index(""), None);
        assert_eq!(column_index("A1"), None);
    }

    #[test]
    fn sheet_names_are_addresses_with_optional_lengths() {
        assert_eq!(
            sheet_address("192.0.2.0"),
            Some(("192.0.2.0".parse().expect("ip"), None))
        );
        assert_eq!(
            sheet_address("192.0.2.0_24"),
            Some(("192.0.2.0".parse().expect("ip"), Some(24)))
        );
        assert_eq!(sheet_address("Index"), None);
        assert_eq!(sheet_address("192.0.2.0_33"), None);
        assert!(is_index_name(" index "));
    }

    #[test]
    fn repeated_sheet_names_are_made_unique() {
        let file = |name: &str| SourceFile {
            name: name.to_owned(),
            format: super::super::read::SourceFormat::Csv,
            sheets: vec![Sheet {
                name: "Sheet1".to_owned(),
                rows: Vec::new(),
            }],
            text: None,
        };
        assert_eq!(
            sheet_names(&[file("a.csv"), file("b.csv")]),
            ["Sheet1", "Sheet1 (2)"]
        );
    }
}
