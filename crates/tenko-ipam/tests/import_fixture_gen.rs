//! Committed generator of the import fixtures described in `docs/plans/import-fixtures.md`.
//!
//! The reference spreadsheet never enters the repository (API-13). This file holds an
//! anonymized stand-in as plain data (documentation ranges only, fake credentials) and writes
//! it in the three shapes the importer has to read:
//!
//! - `tests/fixtures/ip-plan.xlsx`, written with `rust_xlsxwriter`;
//! - `tests/fixtures/ip-plan.ods`, written by hand as an `OpenDocument` zip package;
//! - `tests/fixtures/ip-plan-csv/<sheet name>.csv`, one UTF-8 file with a byte order mark per
//!   sheet, comma delimited, LF line ends, ragged rows (each row ends at its last non-empty
//!   cell, header rows are written in full).
//!
//! To regenerate the files after changing the data or a writer:
//!
//! ```text
//! TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko-ipam --test import_fixture_gen
//! ```
//!
//! Without the variable the tests only verify that the committed files still equal what the
//! generator produces and that the files read back, through `calamine`, to exactly the data.
//! The writers are byte deterministic across time and platforms: fixed document dates, no
//! author or generator metadata, and every zip entry written with a fixed time, a fixed
//! deflate level, fixed permissions and the Unix host (the workbook from `rust_xlsxwriter` is
//! rewritten that way, because the `zip` crate otherwise records DOS on Windows and Unix
//! elsewhere). So the committed bytes are compared as well. The CSV files
//! use LF line ends, which the repository's line ending normalization keeps as they are (the
//! CSV reader takes CRLF as well; its own tests cover that).
//!
//! Fixture additions that the real workbook does not have, so that the importer transforms
//! are exercised, are marked `FIXTURE ADDITION` in the source below:
//!
//! - the range cell `192.0.2.10-20` (row 257 of sheet `192.0.2.0`);
//! - the IPv6 cell `2001:db8::10` (sheet `198.51.100.0`, row of `Wifi Controller Hall`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use calamine::{Data, Range, Reader, Sheets, open_workbook_auto_from_rs};
use ipnet::IpNet;
use rust_xlsxwriter::{DocProperties, ExcelDateTime, Workbook};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, System, ZipArchive, ZipWriter};

/// Result type of the helpers and tests of this file.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Environment variable that switches `regenerate_fixtures` from a no-op to writing files.
const REGENERATE_VARIABLE: &str = "TENKO_REGENERATE_FIXTURES";

/// Media type (and content of the `mimetype` entry) of an `OpenDocument` spreadsheet.
const ODS_MEDIA_TYPE: &str = "application/vnd.oasis.opendocument.spreadsheet";

/// Namespace declarations of the `OpenDocument` content part.
const ODS_CONTENT_NAMESPACES: &str = concat!(
    r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" "#,
    r#"xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" "#,
    r#"xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0""#,
);

/// The `OpenDocument` package manifest.
const ODS_MANIFEST: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
    "\n",
    r#"<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" "#,
    r#"manifest:version="1.2">"#,
    r#"<manifest:file-entry manifest:full-path="/" manifest:version="1.2" "#,
    r#"manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"/>"#,
    r#"<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>"#,
    r#"<manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>"#,
    r"</manifest:manifest>",
    "\n",
);

/// The `OpenDocument` metadata part: a fixed creation date and nothing else.
const ODS_META: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
    "\n",
    r#"<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" "#,
    r#"xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" office:version="1.2">"#,
    r"<office:meta><meta:creation-date>2026-10-09T00:00:00</meta:creation-date></office:meta>",
    r"</office:document-meta>",
    "\n",
);

/// One cell of the fixture workbook.
#[derive(Clone, Debug, PartialEq)]
enum FixtureCell {
    /// No cell is written at all.
    Empty,
    /// A text cell.
    Text(String),
    /// A numeric cell (CSV carries it as text).
    Number(f64),
}

impl FixtureCell {
    /// True when no cell is written for this position.
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// The cell as it appears in a CSV file.
    fn csv_text(&self) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Text(text) => text.clone(),
            Self::Number(number) => number.to_string(),
        }
    }
}

/// One sheet of the fixture workbook: a name and rows of cells starting in `A1`.
#[derive(Clone, Debug)]
struct FixtureSheet {
    /// Sheet name, also the stem of the CSV file name.
    name: &'static str,
    /// Whether row 1 is a header row (it is then written in full to CSV).
    header: bool,
    /// The rows; short rows are shorter than the widest row of the sheet.
    rows: Vec<Vec<FixtureCell>>,
}

/// Builds a row of text cells; an empty string means no cell.
fn row(cells: &[&str]) -> Vec<FixtureCell> {
    cells
        .iter()
        .map(|cell| {
            if cell.is_empty() {
                FixtureCell::Empty
            } else {
                FixtureCell::Text((*cell).to_owned())
            }
        })
        .collect()
}

/// The shared header of the address-list sheets.
fn address_list_header() -> Vec<FixtureCell> {
    row(&["IP", "Beteckning", "Login", "Pass"])
}

/// Number of cells of a row up to and including its last non-empty cell.
fn used_width(cells: &[FixtureCell]) -> usize {
    cells
        .iter()
        .rposition(|cell| !cell.is_empty())
        .map_or(0, |index| index + 1)
}

/// Named rows of sheet `192.0.2.0`: last octet, name, login and password (empty when absent).
const NAMED_192_0_2_0: &[(u8, &str, &str, &str)] = &[
    (1, "gateway", "admin", "example-gw-pass"),
    // A model string in the login column: a misplaced description, not a login.
    (2, "SW_Attic", "Acme SG-2448", ""),
    (3, "hyper3", "", ""),
    (4, "pve02", "root", "example-pve-pass"),
    (5, "pve03", "", ""),
    (6, "ups41", "", ""),
    (7, "ap-hall", "", ""),
    (8, "ap-office", "", ""),
    (22, "printer01", "", ""),
    (23, "printer02", "", ""),
    (24, "files-old", "", ""),
    (25, "backup01", "", ""),
    (30, "kvm-switch", "", ""),
    (31, "pdu01", "", ""),
    (40, "camera01", "", ""),
    (41, "camera02", "", ""),
    (50, "tv-livingroom", "", ""),
    (51, "sonos-kitchen", "", ""),
    (60, "hass", "", ""),
    (61, "zigbee-bridge", "", ""),
    (100, "laptop01", "", ""),
];

/// Named rows of sheet `203.0.113.0`: last octet and name.
const NAMED_203_0_113_0: &[(u8, &str)] = &[(10, "dc-a1"), (11, "dc-a2"), (20, "store7")];

/// Sheet `Index`: the network list, no header row.
fn index_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "Index",
        header: false,
        rows: vec![
            row(&["192.0.2.0/24", "Network gear, hypervisors"]),
            row(&["192.0.2.9", "NAS"]),
            row(&["203.0.113.0/25", "Servers"]),
            row(&["198.51.100.0/26", "Appliances"]),
            row(&["192.0.2.128/26", "Alarm"]),
            row(&["192.0.2.192/26", "DHCP"]),
            row(&["198.51.100.128/26", "Printers"]),
        ],
    }
}

/// Sheet `192.0.2.0`: the pre-filled address list of a whole /24 (255 rows).
fn prefilled_192_0_2_0_sheet() -> FixtureSheet {
    let mut rows = vec![address_list_header()];
    for host in 1..=255_u8 {
        let address = format!("192.0.2.{host}");
        let named = NAMED_192_0_2_0.iter().find(|entry| entry.0 == host);
        rows.push(match named {
            Some(&(_, name, login, password)) => row(&[&address, name, login, password]),
            None => row(&[&address]),
        });
    }
    // FIXTURE ADDITION: the real workbook has no range cell. This row exists so that the range
    // transform of the importer is tested.
    rows.push(row(&["192.0.2.10-20", "DHCP pool"]));
    FixtureSheet {
        name: "192.0.2.0",
        header: true,
        rows,
    }
}

/// Sheet `203.0.113.0`: sparse names, a text value in the address column and a stray value in
/// the unlabeled column `E`.
fn prefilled_203_0_113_0_sheet() -> FixtureSheet {
    let mut rows = vec![address_list_header()];
    for host in 1..=125_u8 {
        let address = format!("203.0.113.{host}");
        let named = NAMED_203_0_113_0.iter().find(|entry| entry.0 == host);
        rows.push(match (host, named) {
            // Text in the address column (row 51 would hold 203.0.113.50).
            (50, _) => row(&["TBD", "old-scanner"]),
            // A stray value in the unlabeled column E, on an address without a name.
            (30, _) => row(&[&address, "", "", "", "rack 2"]),
            (_, Some(&(_, name))) => row(&[&address, name]),
            (_, None) => row(&[&address]),
        });
    }
    FixtureSheet {
        name: "203.0.113.0",
        header: true,
        rows,
    }
}

/// Sheet `192.0.2.64`: five named rows; the first uses the network address as a host address.
fn lab_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "192.0.2.64",
        header: true,
        rows: vec![
            address_list_header(),
            row(&["192.0.2.64", "lab-gw"]),
            row(&["192.0.2.65", "lab-sw"]),
            row(&["192.0.2.66", "lab-ap", "admin", "example-lab-pass"]),
            row(&["192.0.2.67", "lab-nvr"]),
            row(&["192.0.2.68", "lab-cam"]),
        ],
    }
}

/// Sheet `198.51.100.0`: the device-centric layout with lowercase credential headers.
fn device_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "198.51.100.0",
        header: true,
        rows: vec![
            row(&["Enhet", "Nic1", "Nic2", "Nic3", "Nic4", "login", "pass"]),
            // One device whose four NICs sit in four different networks.
            row(&[
                "hyper3",
                "198.51.100.3",
                "198.51.100.67",
                "203.0.113.3",
                "192.0.2.3",
                "root",
                "example-pve1-pass",
            ]),
            row(&[
                "fw01",
                "198.51.100.1",
                "203.0.113.1",
                "",
                "",
                "admin",
                "example-fw-pass",
            ]),
            // FIXTURE ADDITION: the real workbook has no IPv6 address. The second NIC cell of
            // this row exists so that the IPv6 transform of the importer is tested.
            row(&[
                "Wifi Controller Hall",
                "198.51.100.5",
                "2001:db8::10",
                "",
                "",
                "",
                "",
            ]),
            row(&["nvr01", "198.51.100.6", "", "", "", "", ""]),
        ],
    }
}

/// Sheet `192.0.2.128`: no header row, data starts in row 1.
fn headerless_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "192.0.2.128",
        header: false,
        rows: vec![
            row(&["192.0.2.130", "idrac - host1", "root", "example-idrac-1"]),
            row(&["192.0.2.131", "idrac - host2", "root", "example-idrac-2"]),
        ],
    }
}

/// Sheet `192.0.2.9`: a single host whose password is a numeric cell.
fn single_host_sheet() -> FixtureSheet {
    let mut data = row(&["192.0.2.9", "MX-9200", "admin"]);
    // The only numeric cell of the workbook: a four-digit password read as an integer.
    data.push(FixtureCell::Number(1234.0));
    FixtureSheet {
        name: "192.0.2.9",
        header: true,
        rows: vec![address_list_header(), data],
    }
}

/// Sheet `203.0.113.128`: four names, for a network that `Index` does not list.
fn workstation_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "203.0.113.128",
        header: true,
        rows: vec![
            address_list_header(),
            row(&["203.0.113.129", "ws01"]),
            row(&["203.0.113.130", "ws02"]),
            row(&["203.0.113.131", "ws03"]),
            row(&["203.0.113.132", "ws04"]),
        ],
    }
}

/// Sheet `192.0.2.192`: one row.
fn dhcp_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "192.0.2.192",
        header: true,
        rows: vec![address_list_header(), row(&["192.0.2.193", "dhcp01"])],
    }
}

/// Sheet `198.51.100.128`: an empty sheet, no cells at all.
fn empty_sheet() -> FixtureSheet {
    FixtureSheet {
        name: "198.51.100.128",
        header: false,
        rows: Vec::new(),
    }
}

/// The whole fixture workbook, sheets in workbook order.
fn workbook() -> Vec<FixtureSheet> {
    vec![
        index_sheet(),
        prefilled_192_0_2_0_sheet(),
        prefilled_203_0_113_0_sheet(),
        lab_sheet(),
        device_sheet(),
        headerless_sheet(),
        single_host_sheet(),
        workstation_sheet(),
        dhcp_sheet(),
        empty_sheet(),
    ]
}

/// Writes the workbook as an `.xlsx` file image. Text cells are written as strings, the
/// numeric cell as a number, and empty cells are not written.
fn write_xlsx(sheets: &[FixtureSheet]) -> TestResult<Vec<u8>> {
    let mut book = Workbook::new();
    // A fixed creation date and no author or company keep the file reproducible and anonymous.
    let created = ExcelDateTime::from_ymd(2026, 10, 9)?.and_hms(0, 0, 0)?;
    book.set_properties(&DocProperties::new().set_creation_datetime(&created));
    for sheet in sheets {
        let worksheet = book.add_worksheet();
        worksheet.set_name(sheet.name)?;
        for (row_index, cells) in sheet.rows.iter().enumerate() {
            let row_number = u32::try_from(row_index)?;
            for (column_index, cell) in cells.iter().enumerate() {
                let column_number = u16::try_from(column_index)?;
                match cell {
                    FixtureCell::Empty => {}
                    FixtureCell::Text(text) => {
                        worksheet.write_string(row_number, column_number, text.as_str())?;
                    }
                    FixtureCell::Number(number) => {
                        worksheet.write_number(row_number, column_number, *number)?;
                    }
                }
            }
        }
    }
    canonical_zip(&book.save_to_buffer()?)
}

/// The fixed modification time of every zip entry.
fn entry_time() -> TestResult<DateTime> {
    Ok(DateTime::from_date_and_time(2026, 10, 9, 0, 0, 0)?)
}

/// The options of every zip entry: a fixed time, a fixed deflate level, and the Unix host
/// with fixed permissions. Without an explicit host the `zip` crate records DOS on Windows
/// and Unix elsewhere, so the same package would differ by platform.
fn entry_options(method: CompressionMethod) -> TestResult<SimpleFileOptions> {
    let level = (method == CompressionMethod::Deflated).then_some(6);
    Ok(SimpleFileOptions::default()
        .compression_method(method)
        .compression_level(level)
        .last_modified_time(entry_time()?)
        .system(System::Unix)
        .unix_permissions(0o644))
}

/// Rewrites a zip package with [`entry_options`], keeping the entries, their order, their
/// content and their compression method, so the bytes depend neither on the clock nor on the
/// platform (the workbook writer leaves the host system to the `zip` crate's default).
fn canonical_zip(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    let mut package = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = file.name()?.into_owned();
        let options = entry_options(file.compression())?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        drop(file);
        package.start_file(name, options)?;
        package.write_all(&content)?;
    }
    Ok(package.finish()?.into_inner())
}

/// Escapes text for use in XML character data and attribute values.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Appends a run of `count` empty cells (nothing for zero).
fn push_empty_cells(out: &mut String, count: usize) -> std::fmt::Result {
    match count {
        0 => {}
        1 => out.push_str("<table:table-cell/>"),
        many => write!(
            out,
            r#"<table:table-cell table:number-columns-repeated="{many}"/>"#
        )?,
    }
    Ok(())
}

/// Renders one row as `table:table-row`; repeated attributes are used only for empty cells.
fn ods_row(cells: &[FixtureCell]) -> TestResult<String> {
    let used = used_width(cells);
    let mut out = String::from("<table:table-row>");
    let mut gap = 0_usize;
    for cell in &cells[..used] {
        match cell {
            FixtureCell::Empty => gap += 1,
            FixtureCell::Text(text) => {
                push_empty_cells(&mut out, std::mem::take(&mut gap))?;
                write!(
                    out,
                    r#"<table:table-cell office:value-type="string"><text:p>{}</text:p></table:table-cell>"#,
                    xml_escape(text),
                )?;
            }
            FixtureCell::Number(number) => {
                push_empty_cells(&mut out, std::mem::take(&mut gap))?;
                write!(
                    out,
                    r#"<table:table-cell office:value-type="float" office:value="{number}"><text:p>{number}</text:p></table:table-cell>"#,
                )?;
            }
        }
    }
    if used == 0 {
        out.push_str("<table:table-cell/>");
    }
    out.push_str("</table:table-row>");
    Ok(out)
}

/// Renders one sheet as `table:table`.
fn ods_table(sheet: &FixtureSheet) -> TestResult<String> {
    let columns = sheet
        .rows
        .iter()
        .map(|cells| used_width(cells))
        .max()
        .unwrap_or(0)
        .max(1);
    let mut out = String::new();
    write!(
        out,
        r#"<table:table table:name="{}"><table:table-column table:number-columns-repeated="{columns}"/>"#,
        xml_escape(sheet.name),
    )?;
    if sheet.rows.is_empty() {
        // An empty sheet still needs one row with one empty cell to be a valid table.
        out.push_str("<table:table-row><table:table-cell/></table:table-row>");
    }
    for cells in &sheet.rows {
        out.push_str(&ods_row(cells)?);
    }
    out.push_str("</table:table>");
    Ok(out)
}

/// Renders the `content.xml` part of the `OpenDocument` package.
fn ods_content(sheets: &[FixtureSheet]) -> TestResult<String> {
    let mut out = String::new();
    write!(
        out,
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            "\n",
            r#"<office:document-content {} office:version="1.2">"#,
            "<office:body><office:spreadsheet>",
        ),
        ODS_CONTENT_NAMESPACES,
    )?;
    for sheet in sheets {
        out.push_str(&ods_table(sheet)?);
    }
    out.push_str("</office:spreadsheet></office:body></office:document-content>\n");
    Ok(out)
}

/// Writes the workbook as an `.ods` file image: a zip package whose first entry is the
/// stored `mimetype`, followed by the manifest, the metadata and the content.
fn write_ods(sheets: &[FixtureSheet]) -> TestResult<Vec<u8>> {
    let stored = entry_options(CompressionMethod::Stored)?;
    let deflated = entry_options(CompressionMethod::Deflated)?;

    let mut package = ZipWriter::new(Cursor::new(Vec::new()));
    package.start_file("mimetype", stored)?;
    package.write_all(ODS_MEDIA_TYPE.as_bytes())?;
    package.start_file("META-INF/manifest.xml", deflated)?;
    package.write_all(ODS_MANIFEST.as_bytes())?;
    package.start_file("meta.xml", deflated)?;
    package.write_all(ODS_META.as_bytes())?;
    package.start_file("content.xml", deflated)?;
    package.write_all(ods_content(sheets)?.as_bytes())?;
    Ok(package.finish()?.into_inner())
}

/// Renders one sheet as a CSV file: a UTF-8 byte order mark, comma delimiter, LF line ends,
/// quoting only where needed, ragged rows. An empty sheet gives an empty file.
fn write_csv(sheet: &FixtureSheet) -> TestResult<Vec<u8>> {
    if sheet.rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut writer = csv::WriterBuilder::new()
        .delimiter(b',')
        .terminator(csv::Terminator::Any(b'\n'))
        .flexible(true)
        .from_writer(Vec::new());
    for (index, cells) in sheet.rows.iter().enumerate() {
        let width = if sheet.header && index == 0 {
            cells.len()
        } else {
            used_width(cells)
        };
        writer.write_record(cells[..width].iter().map(FixtureCell::csv_text))?;
    }
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend(writer.into_inner()?);
    Ok(bytes)
}

/// Directory of the committed fixtures.
fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Directory of the committed per-sheet CSV files.
fn csv_dir() -> PathBuf {
    fixtures_dir().join("ip-plan-csv")
}

/// File name of the CSV file of a sheet.
fn csv_file_name(sheet: &FixtureSheet) -> String {
    format!("{}.csv", sheet.name)
}

/// Writes all fixture files, replacing the previous ones.
fn write_fixture_files(sheets: &[FixtureSheet]) -> TestResult {
    fs::create_dir_all(csv_dir())?;
    fs::write(fixtures_dir().join("ip-plan.xlsx"), write_xlsx(sheets)?)?;
    fs::write(fixtures_dir().join("ip-plan.ods"), write_ods(sheets)?)?;
    let mut wanted = BTreeSet::new();
    for sheet in sheets {
        let name = csv_file_name(sheet);
        fs::write(csv_dir().join(&name), write_csv(sheet)?)?;
        wanted.insert(name);
    }
    // Drop CSV files of sheets that no longer exist.
    for entry in fs::read_dir(csv_dir())? {
        let path = entry?.path();
        let stale = path.extension().is_some_and(|extension| extension == "csv")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|n| !wanted.contains(n));
        if stale {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Description of a cell for comparisons: its kind and value, or nothing for an empty cell.
fn describe_cell(cell: &FixtureCell) -> Option<String> {
    match cell {
        FixtureCell::Empty => None,
        FixtureCell::Text(text) => Some(format!("text:{text}")),
        FixtureCell::Number(number) => Some(format!("number:{number}")),
    }
}

/// Description of a cell as read by `calamine`, in the same form as [`describe_cell`].
fn describe_data(data: &Data) -> Option<String> {
    match data {
        Data::Empty => None,
        Data::String(text) => Some(format!("text:{text}")),
        Data::Int(number) => Some(format!("number:{number}")),
        Data::Float(number) => Some(format!("number:{number}")),
        other => Some(format!("unexpected:{other:?}")),
    }
}

/// The non-empty cells of a sheet by zero-based position.
fn expected_cells(sheet: &FixtureSheet) -> BTreeMap<(usize, usize), String> {
    let mut cells = BTreeMap::new();
    for (row_index, row_cells) in sheet.rows.iter().enumerate() {
        for (column_index, cell) in row_cells.iter().enumerate() {
            if let Some(description) = describe_cell(cell) {
                cells.insert((row_index, column_index), description);
            }
        }
    }
    cells
}

/// The non-empty cells of a `calamine` range by absolute zero-based position.
fn actual_cells(range: &Range<Data>) -> TestResult<BTreeMap<(usize, usize), String>> {
    let (row_offset, column_offset) = match range.start() {
        Some((row_start, column_start)) => {
            (usize::try_from(row_start)?, usize::try_from(column_start)?)
        }
        None => (0, 0),
    };
    let mut cells = BTreeMap::new();
    for (row_index, column_index, data) in range.used_cells() {
        if let Some(description) = describe_data(data) {
            cells.insert(
                (row_offset + row_index, column_offset + column_index),
                description,
            );
        }
    }
    Ok(cells)
}

/// Up to five positions where the expected and the actual cells differ.
fn first_differences(
    expected: &BTreeMap<(usize, usize), String>,
    actual: &BTreeMap<(usize, usize), String>,
) -> Vec<String> {
    let positions: BTreeSet<_> = expected.keys().chain(actual.keys()).collect();
    positions
        .into_iter()
        .filter(|position| expected.get(position) != actual.get(position))
        .take(5)
        .map(|position| {
            format!(
                "row {} column {}: expected {:?}, read {:?}",
                position.0 + 1,
                position.1 + 1,
                expected.get(position),
                actual.get(position),
            )
        })
        .collect()
}

/// The container format a fixture file must be detected as.
#[derive(Clone, Copy, Debug)]
enum Container {
    /// An Office Open XML workbook.
    Xlsx,
    /// An `OpenDocument` spreadsheet.
    Ods,
}

impl Container {
    /// Whether `calamine` detected this container format.
    fn detected_as<RS>(self, sheets: &Sheets<RS>) -> bool {
        match self {
            Self::Xlsx => matches!(sheets, Sheets::Xlsx(_)),
            Self::Ods => matches!(sheets, Sheets::Ods(_)),
        }
    }
}

/// Opens a workbook image with `calamine` and compares sheet names, and every cell (kind,
/// position and value) with the data.
fn verify_with_calamine(
    label: &str,
    bytes: &[u8],
    container: Container,
    sheets: &[FixtureSheet],
) -> TestResult {
    let mut opened = open_workbook_auto_from_rs(Cursor::new(bytes))?;
    assert!(
        container.detected_as(&opened),
        "{label}: not detected as {container:?}"
    );
    let names: Vec<&str> = sheets.iter().map(|sheet| sheet.name).collect();
    assert_eq!(
        opened.sheet_names(),
        names,
        "{label}: sheet names or order differ"
    );
    for sheet in sheets {
        let range = opened.worksheet_range(sheet.name)?;
        let differences = first_differences(&expected_cells(sheet), &actual_cells(&range)?);
        assert!(
            differences.is_empty(),
            "{label}: sheet {}: {}",
            sheet.name,
            differences.join("; "),
        );
    }
    Ok(())
}

/// Reads every entry of a zip package: name, compression method and content.
fn zip_entries(bytes: &[u8]) -> TestResult<Vec<(String, CompressionMethod, Vec<u8>)>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        entries.push((file.name()?.into_owned(), file.compression(), content));
    }
    Ok(entries)
}

/// Text of the entry `name` of a package.
fn entry_text(entries: &[(String, CompressionMethod, Vec<u8>)], name: &str) -> TestResult<String> {
    let entry = entries
        .iter()
        .find(|entry| entry.0 == name)
        .ok_or_else(|| format!("missing package entry {name}"))?;
    Ok(String::from_utf8(entry.2.clone())?)
}

/// Text of the first `tag` element (attributes allowed); empty for `<tag/>` and
/// `<tag></tag>`; `None` when the element is absent.
fn element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let mut search_from = 0;
    while let Some(found) = xml[search_from..].find(&open) {
        let after_name = search_from + found + open.len();
        search_from = after_name;
        // Skip elements whose name merely starts with `tag`.
        if !xml[after_name..].starts_with(['>', ' ', '/']) {
            continue;
        }
        let tag_end = after_name + xml[after_name..].find('>')?;
        if xml[..tag_end].ends_with('/') {
            return Some(String::new());
        }
        let content_end = tag_end + 1 + xml[tag_end + 1..].find(&format!("</{tag}>"))?;
        return Some(xml[tag_end + 1..content_end].to_owned());
    }
    None
}

/// The documentation ranges that fixture data may use (RFC 5737 and RFC 3849).
fn documentation_ranges() -> Vec<IpNet> {
    [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    ]
    .iter()
    .map(|range| range.parse().expect("a literal documentation range parses"))
    .collect()
}

/// The addresses a cell value stands for when it looks like an address, a CIDR block or an
/// `a.b.c.d-e` range, else `None`. A CIDR block stands for its first and last address.
fn address_like(text: &str) -> Option<Vec<IpAddr>> {
    if let Ok(address) = text.parse::<IpAddr>() {
        return Some(vec![address]);
    }
    if let Ok(network) = text.parse::<IpNet>() {
        return Some(vec![network.network(), network.broadcast()]);
    }
    let (first, last_octet) = text.split_once('-')?;
    let first: Ipv4Addr = first.parse().ok()?;
    let last_octet: u8 = last_octet.parse().ok()?;
    let [a, b, c, _] = first.octets();
    Some(vec![
        IpAddr::V4(first),
        IpAddr::V4(Ipv4Addr::new(a, b, c, last_octet)),
    ])
}

/// Whether every address lies in one of the documentation ranges.
fn in_documentation_ranges(addresses: &[IpAddr]) -> bool {
    let ranges = documentation_ranges();
    addresses
        .iter()
        .all(|address| ranges.iter().any(|range| range.contains(address)))
}

/// Writes the committed fixture files when `TENKO_REGENERATE_FIXTURES=1`, else does nothing.
#[test]
fn regenerate_fixtures() -> TestResult {
    if !std::env::var(REGENERATE_VARIABLE).is_ok_and(|value| value == "1") {
        return Ok(());
    }
    write_fixture_files(&workbook())
}

/// The sheets, their order and their sizes are the ones the plan describes.
#[test]
fn workbook_shape_matches_the_plan() {
    let shape: Vec<(&str, usize)> = workbook()
        .iter()
        .map(|sheet| (sheet.name, sheet.rows.len()))
        .collect();
    assert_eq!(
        shape,
        [
            ("Index", 7),
            ("192.0.2.0", 257),
            ("203.0.113.0", 126),
            ("192.0.2.64", 6),
            ("198.51.100.0", 5),
            ("192.0.2.128", 2),
            ("192.0.2.9", 2),
            ("203.0.113.128", 5),
            ("192.0.2.192", 2),
            ("198.51.100.128", 0),
        ]
    );
    let numbers = workbook()
        .iter()
        .flat_map(|sheet| sheet.rows.iter().flatten())
        .filter(|cell| matches!(cell, FixtureCell::Number(_)))
        .count();
    assert_eq!(numbers, 1, "exactly one numeric cell");
}

/// Sheet names are valid in every format, and text survives all three writers unchanged.
#[test]
fn texts_are_plain_enough_for_every_format() {
    let names: BTreeSet<&str> = workbook().iter().map(|sheet| sheet.name).collect();
    assert_eq!(names.len(), workbook().len(), "sheet names are unique");
    for sheet in workbook() {
        assert!(
            !sheet.name.is_empty() && sheet.name.len() <= 31,
            "sheet name {}",
            sheet.name
        );
        assert!(
            !sheet
                .name
                .contains(['/', '\\', '?', '*', '[', ']', ':', '\''])
        );
        for cell in sheet.rows.iter().flatten() {
            if let FixtureCell::Text(text) = cell {
                // Leading, trailing and repeated spaces would not survive an OpenDocument
                // paragraph without markup, and control characters would not survive CSV.
                assert_eq!(text.trim(), text, "{text:?}");
                assert!(!text.contains("  "), "{text:?}");
                assert!(
                    !text.is_empty() && !text.chars().any(char::is_control),
                    "{text:?}"
                );
                assert!(text.is_ascii(), "{text:?}");
            }
        }
    }
}

/// Generating twice gives identical bytes in every format.
#[test]
fn writers_are_byte_deterministic() -> TestResult {
    let sheets = workbook();
    let xlsx = write_xlsx(&sheets)?;
    let ods = write_ods(&sheets)?;
    let csv: Vec<Vec<u8>> = sheets.iter().map(write_csv).collect::<TestResult<_>>()?;
    // Across a change of the wall-clock second: nothing in the output may follow the clock.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert!(write_xlsx(&sheets)? == xlsx, "xlsx differs between runs");
    assert!(write_ods(&sheets)? == ods, "ods differs between runs");
    for (sheet, first) in sheets.iter().zip(&csv) {
        assert_eq!(&write_csv(sheet)?, first);
    }
    // Nothing that depends on the platform: every entry records the Unix host, the fixed
    // time and fixed permissions, and no XML part carries a carriage return.
    for (label, package) in [("xlsx", &xlsx), ("ods", &ods)] {
        assert_platform_neutral(label, package)?;
    }
    Ok(())
}

/// Checks the platform-dependent fields of a zip package: the host system byte of "version
/// made by" in every central directory header, entry times, permissions, and line ends.
fn assert_platform_neutral(label: &str, package: &[u8]) -> TestResult {
    const CENTRAL_HEADER: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
    let hosts: Vec<u8> = package
        .windows(6)
        .filter(|window| window[..4] == CENTRAL_HEADER)
        .map(|window| window[5])
        .collect();
    assert!(!hosts.is_empty(), "{label}: no central directory headers");
    assert!(
        hosts.iter().all(|host| *host == u8::from(System::Unix)),
        "{label}: an entry records a host other than Unix: {hosts:?}"
    );
    let mut archive = ZipArchive::new(Cursor::new(package))?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = file.name()?.into_owned();
        assert_eq!(file.last_modified(), Some(entry_time()?), "{label}: {name}");
        assert_eq!(
            file.unix_mode().map(|mode| mode & 0o777),
            Some(0o644),
            "{label}: {name}"
        );
        assert!(!name.contains('\\'), "{label}: {name} has a backslash");
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        // Every part is XML or the plain `mimetype`: none may carry a carriage return.
        assert!(
            !content.contains(&b'\r'),
            "{label}: {name} has a carriage return"
        );
    }
    Ok(())
}

/// The committed CSV files equal the generated bytes, and no other CSV file is committed.
#[test]
fn csv_fixtures_match_the_generator() -> TestResult {
    let sheets = workbook();
    for sheet in &sheets {
        let path = csv_dir().join(csv_file_name(sheet));
        let committed = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        assert!(
            committed == write_csv(sheet)?,
            "{} differs from the generator; regenerate with {REGENERATE_VARIABLE}=1",
            path.display(),
        );
    }
    let committed: BTreeSet<String> = fs::read_dir(csv_dir())?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<TestResult<_>>()?;
    let generated: BTreeSet<String> = sheets.iter().map(csv_file_name).collect();
    assert_eq!(committed, generated);
    Ok(())
}

/// The CSV bytes have the shape the importer has to cope with.
#[test]
fn csv_fixtures_have_the_expected_shape() -> TestResult {
    let sheets = workbook();
    let by_name = |name: &str| sheets.iter().find(|sheet| sheet.name == name);
    let text = |name: &str| -> TestResult<String> {
        let sheet = by_name(name).ok_or("unknown sheet")?;
        let bytes = write_csv(sheet)?;
        let body = bytes
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .ok_or("missing byte order mark")?;
        Ok(String::from_utf8(body.to_vec())?)
    };
    assert_eq!(
        write_csv(by_name("198.51.100.128").ok_or("unknown sheet")?)?,
        Vec::<u8>::new()
    );
    let index = text("Index")?;
    assert!(index.starts_with("192.0.2.0/24,\"Network gear, hypervisors\"\n192.0.2.9,NAS\n"));
    let pool = text("192.0.2.0")?;
    assert!(
        pool.starts_with("IP,Beteckning,Login,Pass\n192.0.2.1,gateway,admin,example-gw-pass\n")
    );
    assert!(pool.contains("\n192.0.2.2,SW_Attic,Acme SG-2448\n192.0.2.3,hyper3\n"));
    assert!(pool.contains("\n192.0.2.5,pve03\n192.0.2.6,ups41\n"));
    assert!(pool.ends_with("\n192.0.2.255\n192.0.2.10-20,DHCP pool\n"));
    assert!(text("203.0.113.0")?.contains("\n203.0.113.30,,,,rack 2\n"));
    assert!(text("203.0.113.0")?.contains("\nTBD,old-scanner\n"));
    assert!(text("192.0.2.9")?.ends_with("192.0.2.9,MX-9200,admin,1234\n"));
    let devices = text("198.51.100.0")?;
    assert!(devices.starts_with("Enhet,Nic1,Nic2,Nic3,Nic4,login,pass\n"));
    assert!(devices.contains("\nfw01,198.51.100.1,203.0.113.1,,,admin,example-fw-pass\n"));
    assert!(devices.contains("\nWifi Controller Hall,198.51.100.5,2001:db8::10\n"));
    assert!(text("192.0.2.128")?.starts_with("192.0.2.130,idrac - host1,root,example-idrac-1\n"));
    Ok(())
}

/// The committed workbooks read back, through `calamine`, to exactly the data, and equal the
/// freshly generated bytes.
#[test]
fn workbook_fixtures_match_the_generator() -> TestResult {
    let sheets = workbook();
    let xlsx = fs::read(fixtures_dir().join("ip-plan.xlsx"))?;
    verify_with_calamine("ip-plan.xlsx", &xlsx, Container::Xlsx, &sheets)?;
    let ods = fs::read(fixtures_dir().join("ip-plan.ods"))?;
    verify_with_calamine("ip-plan.ods", &ods, Container::Ods, &sheets)?;
    // The writers are byte deterministic (see `writers_are_byte_deterministic`), so the
    // committed bytes must equal the generated ones.
    assert!(
        xlsx == write_xlsx(&sheets)?,
        "ip-plan.xlsx differs from the generator; regenerate with {REGENERATE_VARIABLE}=1",
    );
    assert!(
        ods == write_ods(&sheets)?,
        "ip-plan.ods differs from the generator; regenerate with {REGENERATE_VARIABLE}=1",
    );
    Ok(())
}

/// The `OpenDocument` package starts with a stored `mimetype` and has no author or generator
/// metadata; the workbook carries a fixed creation date and no author or company.
#[test]
fn packages_are_well_formed_and_anonymous() -> TestResult {
    let sheets = workbook();

    let ods = zip_entries(&write_ods(&sheets)?)?;
    let (first_name, first_method, first_content) = &ods[0];
    assert_eq!(first_name, "mimetype");
    assert_eq!(*first_method, CompressionMethod::Stored);
    assert_eq!(first_content.as_slice(), ODS_MEDIA_TYPE.as_bytes());
    let names: Vec<&str> = ods.iter().map(|entry| entry.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "mimetype",
            "META-INF/manifest.xml",
            "meta.xml",
            "content.xml"
        ]
    );
    let meta = entry_text(&ods, "meta.xml")?;
    for tag in [
        "meta:generator",
        "meta:initial-creator",
        "dc:creator",
        "meta:user-defined",
    ] {
        assert!(!meta.contains(tag), "unexpected {tag} in meta.xml");
    }
    assert_eq!(
        element_text(&meta, "meta:creation-date").as_deref(),
        Some("2026-10-09T00:00:00")
    );

    let xlsx = zip_entries(&write_xlsx(&sheets)?)?;
    let core = entry_text(&xlsx, "docProps/core.xml")?;
    assert_eq!(element_text(&core, "dc:creator").as_deref(), Some(""));
    assert_eq!(
        element_text(&core, "cp:lastModifiedBy").as_deref(),
        Some("")
    );
    assert_eq!(
        element_text(&core, "dcterms:created").as_deref(),
        Some("2026-10-09T00:00:00Z")
    );
    assert_eq!(
        element_text(&core, "dcterms:modified").as_deref(),
        Some("2026-10-09T00:00:00Z")
    );
    let app = entry_text(&xlsx, "docProps/app.xml")?;
    assert_eq!(element_text(&app, "Company").as_deref(), Some(""));
    Ok(())
}

/// Every address-like string of the data (sheet names included) lies in a documentation range.
#[test]
fn all_addresses_are_in_documentation_ranges() {
    let mut texts: Vec<String> = Vec::new();
    for sheet in workbook() {
        texts.push(sheet.name.to_owned());
        for cell in sheet.rows.iter().flatten() {
            if let FixtureCell::Text(text) = cell {
                texts.push(text.clone());
            }
        }
    }
    let mut found = 0_usize;
    for text in &texts {
        if let Some(addresses) = address_like(text) {
            found += 1;
            assert!(
                in_documentation_ranges(&addresses),
                "{text} is outside the documentation ranges"
            );
        }
    }
    // The check must not pass because nothing was parsed.
    assert!(found > 400, "only {found} address-like strings found");

    // The checker itself rejects addresses outside the documentation ranges.
    for outside in [
        "10.0.0.1",
        "192.0.3.1",
        "192.0.2.0/23",
        "198.51.101.1-9",
        "2001:db9::1",
    ] {
        let addresses = address_like(outside).expect("the sample parses as address-like");
        assert!(
            !in_documentation_ranges(&addresses),
            "{outside} must be rejected"
        );
    }
    for inside in [
        "192.0.2.255",
        "203.0.113.0/25",
        "192.0.2.10-20",
        "2001:db8:ffff::1",
    ] {
        let addresses = address_like(inside).expect("the sample parses as address-like");
        assert!(
            in_documentation_ranges(&addresses),
            "{inside} must be accepted"
        );
    }
}
