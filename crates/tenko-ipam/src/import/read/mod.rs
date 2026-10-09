//! Readers: CSV files and workbooks (xlsx, xls, ods) into [`Sheet`]s of [`Cell`]s.
//!
//! A reader keeps the geometry of the source: `rows[0]` is the first row of the sheet as a
//! spreadsheet program numbers it (row 1), and `rows[r][0]` is column `A`, so every
//! [`SourceLocation`](tenko_core::ir::SourceLocation) of the loss report points at the
//! cell the user sees. Trailing empty rows are dropped; rows may be ragged.
//!
//! - CSV ([`csv`]): UTF-8 with or without a byte order mark, Windows-1252 when the bytes
//!   are not UTF-8 (detected with `encoding_rs`), the delimiter sniffed among `,`, `;`
//!   and tab, quoted fields per RFC 4180. One file is one sheet, named after the file
//!   without its extension (`192.0.2.0.csv` is the sheet `192.0.2.0`).
//! - Workbooks ([`workbook`]): `calamine` for xlsx, xls and ods. Numbers keep their kind
//!   ([`CellKind::Number`]), so the importer can tell a password that a spreadsheet stored
//!   as a number (leading zeros lost) from text.

pub mod csv;
pub mod workbook;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What kind of value a cell held in the source.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CellKind {
    /// Nothing, or only whitespace.
    #[default]
    Empty,
    /// Text (every CSV value that is not empty).
    Text,
    /// A number stored as a number by a spreadsheet program.
    Number,
    /// A boolean.
    Bool,
    /// A date or time, rendered as ISO 8601 text.
    Date,
    /// A formula error such as `#N/A`, rendered as its text.
    Error,
}

/// One cell: its kind and its text.
///
/// Numbers are rendered without a fractional part when they are integral (`1234`, not
/// `1234.0`), otherwise in the shortest form that reads back as the same number.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    /// The kind of value.
    pub kind: CellKind,
    /// The value as text, surrounding whitespace removed; empty for [`CellKind::Empty`].
    pub text: String,
}

impl Cell {
    /// An empty cell.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A text cell; empty when `text` is only whitespace.
    pub fn text(text: impl AsRef<str>) -> Self {
        Self::of_kind(CellKind::Text, text)
    }

    /// A number cell with the given rendering.
    pub fn number(text: impl AsRef<str>) -> Self {
        Self::of_kind(CellKind::Number, text)
    }

    /// A cell of `kind`; empty when `text` is only whitespace.
    pub fn of_kind(kind: CellKind, text: impl AsRef<str>) -> Self {
        let trimmed = text.as_ref().trim();
        if trimmed.is_empty() {
            Self::empty()
        } else {
            Self {
                kind,
                text: trimmed.to_owned(),
            }
        }
    }

    /// Whether the cell holds nothing.
    pub fn is_empty(&self) -> bool {
        self.kind == CellKind::Empty || self.text.is_empty()
    }

    /// The text, `None` when empty.
    pub fn value(&self) -> Option<&str> {
        (!self.is_empty()).then_some(self.text.as_str())
    }
}

/// One sheet (a worksheet, or a whole CSV file).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sheet {
    /// The sheet name (CSV: the file name without extension).
    pub name: String,
    /// The rows from row 1, each from column `A`; trailing empty rows removed.
    pub rows: Vec<Vec<Cell>>,
}

impl Sheet {
    /// The number of columns of the widest row.
    pub fn width(&self) -> usize {
        self.rows.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// The cell at `row` and `column` (0-based), empty outside the data.
    pub fn cell(&self, row: usize, column: usize) -> &Cell {
        static EMPTY: Cell = Cell {
            kind: CellKind::Empty,
            text: String::new(),
        };
        self.rows
            .get(row)
            .and_then(|cells| cells.get(column))
            .unwrap_or(&EMPTY)
    }

    /// Whether the sheet holds no value at all.
    pub fn is_empty(&self) -> bool {
        self.rows.iter().all(|row| row.iter().all(Cell::is_empty))
    }
}

/// The format of an uploaded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    /// Comma, semicolon or tab separated text.
    Csv,
    /// Office Open XML workbook.
    Xlsx,
    /// Legacy Excel workbook.
    Xls,
    /// `OpenDocument` spreadsheet.
    Ods,
}

/// How a text file was decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TextInfo {
    /// The encoding: `UTF-8`, `windows-1252`, `UTF-16LE` or `UTF-16BE`.
    pub encoding: String,
    /// Whether the file started with a byte order mark (always the case for UTF-16).
    pub bom: bool,
    /// The field delimiter: `,`, `;` or a tab.
    pub delimiter: char,
}

/// A read file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// The file name as uploaded.
    pub name: String,
    /// The format.
    pub format: SourceFormat,
    /// The sheets in workbook order (one for CSV).
    pub sheets: Vec<Sheet>,
    /// How a CSV file was decoded; `None` for workbooks.
    pub text: Option<TextInfo>,
}

/// Limits of the readers, against oversized or hostile files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLimits {
    /// Sheets per workbook.
    pub max_sheets: usize,
    /// Rows per sheet.
    pub max_rows: usize,
    /// Columns per row.
    pub max_columns: usize,
    /// Total uncompressed size of the parts of a zip-based workbook (xlsx, ods), checked
    /// before parsing so a compressed bomb is refused cheaply.
    pub max_uncompressed: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_sheets: 256,
            max_rows: 200_000,
            max_columns: 256,
            max_uncompressed: 256 * 1024 * 1024,
        }
    }
}

/// Why a file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// Not a CSV file or a workbook this importer reads.
    #[error("the file is not a CSV file or an xlsx, xls or ods workbook")]
    Unsupported,
    /// The file is damaged, encrypted or not what its name says.
    #[error("the file cannot be read: {0}")]
    Malformed(String),
    /// A limit of [`ReadLimits`] was exceeded.
    #[error("the file exceeds a limit: {0}")]
    TooLarge(String),
}

/// The magic number of a zip archive (a local file header).
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
/// The magic number of an OLE compound file (legacy xls).
const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// How much of the start of a text file is checked for binary content.
const TEXT_SNIFF_BYTES: usize = 8 * 1024;
/// Starts of well known binary formats that contain no NUL byte early on.
const BINARY_MAGICS: [&[u8]; 5] = [
    b"%PDF-",
    b"\x89PNG",
    b"\xFF\xD8\xFF",
    b"\x1F\x8B",
    b"7z\xBC\xAF\x27\x1C",
];

/// Reads one uploaded file: detects the format from its content (zip, OLE or text) and
/// its name, then reads it with the matching reader.
///
/// The content decides: a zip archive is an xlsx or an ods workbook (by its parts), an OLE
/// compound file is an xls workbook, and anything else must be text and is read as CSV,
/// whatever the file name says. The extension only breaks a tie, for a zip that fits both
/// workbook formats or an `OpenDocument` package that does not state its type. The sizes of a
/// zip archive are checked against [`ReadLimits::max_uncompressed`] before any workbook
/// parser sees the bytes.
///
/// # Errors
///
/// Returns [`ReadError`] when the format is unknown, the file is damaged or a limit is
/// exceeded.
pub fn read_file(name: &str, bytes: &[u8], limits: &ReadLimits) -> Result<SourceFile, ReadError> {
    let file = if bytes.starts_with(ZIP_MAGIC) {
        let format = workbook::detect_zip(bytes, limits, format_from_name(name))?;
        workbook::read_workbook(name, bytes, format, limits)?
    } else if bytes.starts_with(OLE_MAGIC) {
        workbook::read_workbook(name, bytes, SourceFormat::Xls, limits)?
    } else {
        check_text(bytes)?;
        csv::read_csv(name, bytes, limits)?
    };
    if file.sheets.len() > limits.max_sheets {
        return Err(ReadError::TooLarge(format!(
            "more than {} sheets (max_sheets)",
            limits.max_sheets
        )));
    }
    Ok(file)
}

/// The format a file name suggests, `None` for an unknown or missing extension.
fn format_from_name(name: &str) -> Option<SourceFormat> {
    let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (_, extension) = file.rsplit_once('.')?;
    match extension.to_ascii_lowercase().as_str() {
        "xlsx" | "xlsm" | "xltx" | "xltm" => Some(SourceFormat::Xlsx),
        "xls" => Some(SourceFormat::Xls),
        "ods" => Some(SourceFormat::Ods),
        "csv" | "tsv" | "txt" => Some(SourceFormat::Csv),
        _ => None,
    }
}

/// Refuses content that is not text: NUL bytes early on (UTF-16 text announces itself with
/// a byte order mark and is exempt), the start of well known binary formats, and markup
/// (an HTML or XML document saved under a spreadsheet name).
fn check_text(bytes: &[u8]) -> Result<(), ReadError> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Ok(());
    }
    let head = &bytes[..bytes.len().min(TEXT_SNIFF_BYTES)];
    if head.contains(&0) || BINARY_MAGICS.iter().any(|magic| head.starts_with(magic)) {
        return Err(ReadError::Unsupported);
    }
    let text = head.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(head);
    let text = text.trim_ascii_start();
    let is_markup = [&b"<?xml"[..], b"<html", b"<!doctype", b"<table"]
        .iter()
        .any(|start| {
            text.get(..start.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(start))
        });
    if is_markup {
        return Err(ReadError::Unsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rust_xlsxwriter::Workbook;

    use super::workbook::test_support::{ods, zip, zip_declaring};
    use super::*;

    fn read(name: &str, bytes: &[u8]) -> Result<SourceFile, ReadError> {
        read_file(name, bytes, &ReadLimits::default())
    }

    fn xlsx_bytes() -> Vec<u8> {
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        sheet.write_string(0, 0, "host").unwrap();
        sheet.write_string(0, 1, "ip").unwrap();
        sheet.write_string(1, 0, "web01").unwrap();
        sheet.write_string(1, 1, "192.0.2.10").unwrap();
        workbook.save_to_buffer().unwrap()
    }

    #[test]
    fn cell_constructors_trim_and_empty() {
        assert_eq!(Cell::text("  x \n").text, "x");
        assert_eq!(Cell::text("  x \n").kind, CellKind::Text);
        assert!(Cell::text(" \t ").is_empty());
        assert_eq!(Cell::text(" \t ").kind, CellKind::Empty);
        assert_eq!(Cell::number(" 12 ").kind, CellKind::Number);
        assert_eq!(Cell::of_kind(CellKind::Bool, "").kind, CellKind::Empty);
        assert_eq!(Cell::text("x").value(), Some("x"));
        assert_eq!(Cell::empty().value(), None);
    }

    #[test]
    fn sheet_geometry_helpers() {
        let sheet = Sheet {
            name: "s".to_owned(),
            rows: vec![
                vec![Cell::text("a"), Cell::text("b")],
                vec![],
                vec![Cell::empty()],
            ],
        };
        assert_eq!(sheet.width(), 2);
        assert_eq!(sheet.cell(0, 1).text, "b");
        assert!(sheet.cell(1, 0).is_empty());
        assert!(sheet.cell(9, 9).is_empty());
        assert!(!sheet.is_empty());
        assert!(Sheet::default().is_empty());
        assert_eq!(Sheet::default().width(), 0);
    }

    #[test]
    fn default_limits() {
        let limits = ReadLimits::default();
        assert_eq!(limits.max_sheets, 256);
        assert_eq!(limits.max_rows, 200_000);
        assert_eq!(limits.max_columns, 256);
        assert_eq!(limits.max_uncompressed, 256 * 1024 * 1024);
    }

    #[test]
    fn text_is_read_as_csv_whatever_the_name() {
        for name in [
            "plan.csv",
            "plan.txt",
            "plan",
            "plan.xlsx",
            "plan.ods",
            "plan.xls",
        ] {
            let file = read(name, b"host;ip\nweb01;192.0.2.10\n").unwrap();
            assert_eq!(file.format, SourceFormat::Csv, "{name}");
            assert_eq!(file.sheets.len(), 1);
            assert_eq!(file.text.as_ref().unwrap().delimiter, ';');
        }
        let file = read("192.0.2.0.csv", b"a,b\n").unwrap();
        assert_eq!(file.sheets[0].name, "192.0.2.0");
        assert_eq!(file.name, "192.0.2.0.csv");
    }

    #[test]
    fn utf16_text_is_not_binary_garbage() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "a;b\n1;2\n".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        let file = read("plan.csv", &bytes).unwrap();
        assert_eq!(file.text.as_ref().unwrap().encoding, "UTF-16LE");
        assert_eq!(file.sheets[0].cell(1, 1).text, "2");
    }

    #[test]
    fn empty_file_is_an_empty_csv_sheet() {
        let file = read("empty.csv", b"").unwrap();
        assert_eq!(file.format, SourceFormat::Csv);
        assert_eq!(file.sheets[0].rows.len(), 0);
    }

    #[test]
    fn binary_garbage_is_unsupported() {
        let mut nul = b"host,ip\n".to_vec();
        nul.extend_from_slice(&[0, 1, 2, 3, 0, 0, 0xFF]);
        let mut late_nul = vec![b'a'; 100];
        late_nul.push(0);
        let png = b"\x89PNG\r\n\x1a\n rest of an image".to_vec();
        for (name, bytes) in [
            ("plan.csv", nul.as_slice()),
            ("plan.xlsx", late_nul.as_slice()),
            ("logo.csv", png.as_slice()),
            ("doc.csv", b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".as_slice()),
            ("photo.csv", b"\xFF\xD8\xFF\xE0 photo".as_slice()),
            ("pack.csv", b"\x1F\x8B\x08 archive".as_slice()),
        ] {
            assert_eq!(read(name, bytes), Err(ReadError::Unsupported), "{name}");
        }
    }

    #[test]
    fn nul_after_the_sniffed_head_is_not_checked() {
        let mut bytes = b"a,b\n".repeat(3000);
        bytes.push(0);
        assert!(bytes.len() > TEXT_SNIFF_BYTES);
        assert!(read("big.csv", &bytes).is_ok());
    }

    #[test]
    fn markup_is_unsupported() {
        for text in [
            "<?xml version=\"1.0\"?><Workbook/>",
            "  \n<html><body><table></table></body></html>",
            "<!DOCTYPE html><html></html>",
            "<TABLE><tr><td>x</td></tr></TABLE>",
            "\u{FEFF}<html>",
        ] {
            assert_eq!(
                read("export.xls", text.as_bytes()),
                Err(ReadError::Unsupported),
                "{text}"
            );
        }
        // A value that merely starts with an angle bracket is still text.
        assert!(read("a.csv", b"<name>,ip\nx,1\n").is_ok());
    }

    #[test]
    fn xlsx_is_detected_from_the_content() {
        let bytes = xlsx_bytes();
        for name in ["plan.xlsx", "plan.csv", "plan", "upload.bin"] {
            let file = read(name, &bytes).unwrap();
            assert_eq!(file.format, SourceFormat::Xlsx, "{name}");
            assert!(file.text.is_none());
            assert_eq!(file.sheets[0].name, "Sheet1");
            assert_eq!(file.sheets[0].cell(1, 1).text, "192.0.2.10");
        }
    }

    #[test]
    fn ods_is_detected_from_the_content() {
        let bytes = ods("Plan", &[&["host", "ip"], &["web01", "192.0.2.10"]]);
        for name in ["plan.ods", "plan.xlsx", "plan.csv", "plan"] {
            let file = read(name, &bytes).unwrap();
            assert_eq!(file.format, SourceFormat::Ods, "{name}");
            assert_eq!(file.sheets[0].name, "Plan");
            assert_eq!(file.sheets[0].cell(1, 0).text, "web01");
        }
    }

    #[test]
    fn other_zip_files_are_unsupported() {
        let plain = zip(&[("notes.txt", b"hello")]);
        assert_eq!(read("plan.xlsx", &plain), Err(ReadError::Unsupported));
        let docx = zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<document/>"),
        ]);
        assert_eq!(read("plan.xlsx", &docx), Err(ReadError::Unsupported));
    }

    #[test]
    fn damaged_zip_is_malformed() {
        let mut bytes = ZIP_MAGIC.to_vec();
        bytes.extend_from_slice(&[0x13; 200]);
        assert!(matches!(
            read("plan.xlsx", &bytes),
            Err(ReadError::Malformed(_))
        ));
        let xlsx = xlsx_bytes();
        assert!(matches!(
            read("plan.xlsx", &xlsx[..xlsx.len() - 40]),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn ole_files_are_read_as_xls() {
        let mut bytes = OLE_MAGIC.to_vec();
        bytes.extend_from_slice(&[0x42; 700]);
        for name in ["plan.xls", "plan.csv", "plan"] {
            assert!(
                matches!(read(name, &bytes), Err(ReadError::Malformed(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn encrypted_ooxml_reports_the_password() {
        let mut bytes = OLE_MAGIC.to_vec();
        bytes.extend_from_slice(&[0; 64]);
        for unit in "EncryptedPackage".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 64]);
        let error = read("secret.xlsx", &bytes).unwrap_err();
        assert!(
            matches!(&error, ReadError::Malformed(m) if m.contains("password")),
            "{error:?}"
        );
    }

    #[test]
    fn zip_bomb_is_refused_before_parsing() {
        // Stored entries that declare far more than the limit allows.
        let bytes = zip_declaring(&[
            ("[Content_Types].xml", b"<Types/>", 50_000),
            ("xl/workbook.xml", b"<workbook/>", 60_000),
        ]);
        let limits = ReadLimits {
            max_uncompressed: 100_000,
            ..ReadLimits::default()
        };
        let error = read_file("bomb.xlsx", &bytes, &limits).unwrap_err();
        assert!(
            matches!(&error, ReadError::TooLarge(m) if m.contains("max_uncompressed")),
            "{error:?}"
        );
        // Within the limit the same archive reaches the parser, which finds no workbook.
        let roomy = ReadLimits {
            max_uncompressed: 120_000,
            ..ReadLimits::default()
        };
        assert!(matches!(
            read_file("bomb.xlsx", &bytes, &roomy),
            Err(ReadError::Malformed(_))
        ));
        // zip64 sentinels are refused too.
        let zip64 = zip_declaring(&[("xl/workbook.xml", b"x", 0xFFFF_FFFF)]);
        assert!(matches!(
            read("big.xlsx", &zip64),
            Err(ReadError::TooLarge(_))
        ));
    }

    #[test]
    fn limits_apply_to_every_format() {
        let sheets = ReadLimits {
            max_sheets: 0,
            ..ReadLimits::default()
        };
        let error = read_file("a.csv", b"a,b\n", &sheets).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_sheets")));

        let rows = ReadLimits {
            max_rows: 1,
            ..ReadLimits::default()
        };
        let error = read_file("a.csv", b"a\nb\n", &rows).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_rows")));
        let error = read_file("a.xlsx", &xlsx_bytes(), &rows).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_rows")));

        let columns = ReadLimits {
            max_columns: 1,
            ..ReadLimits::default()
        };
        let error = read_file("a.csv", b"a,b\n", &columns).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_columns")));
        let error = read_file("a.ods", &ods("S", &[&["a", "b"]]), &columns).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_columns")));
    }

    #[test]
    fn name_hints() {
        assert_eq!(format_from_name("a.XLSX"), Some(SourceFormat::Xlsx));
        assert_eq!(format_from_name("dir.d/a.ods"), Some(SourceFormat::Ods));
        assert_eq!(format_from_name("a.xls"), Some(SourceFormat::Xls));
        assert_eq!(format_from_name("a.tsv"), Some(SourceFormat::Csv));
        assert_eq!(format_from_name("a"), None);
        assert_eq!(format_from_name("a.dat"), None);
        assert_eq!(format_from_name("192.0.2.0"), None);
    }
}
