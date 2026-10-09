//! The workbook reader (see the [module documentation](super)).
//!
//! xlsx, xls and ods are read with `calamine`. For the zip-based formats the zip central
//! directory is read by hand before `calamine` sees the bytes, so a workbook that expands
//! beyond [`ReadLimits::max_uncompressed`] is refused without being inflated.

use std::io::{Cursor, Read, Seek};
use std::panic::{AssertUnwindSafe, catch_unwind};

use calamine::{Data, ExcelDateTime, Ods, Range, Reader, Xls, Xlsx};

use super::{Cell, CellKind, ReadError, ReadLimits, Sheet, SourceFile, SourceFormat};

/// Reads an xlsx, xls or ods workbook into [`Sheet`]s in workbook order.
///
/// The geometry of the source is kept: `rows[0]` is spreadsheet row 1 and index 0 of a row
/// is column `A`, however far from the corner the first stored cell is. An empty worksheet
/// is a sheet without rows. Rows of a sheet are as wide as its last non-empty column, and a
/// row without a value is an empty vector. Cell kinds follow the source: text, numbers
/// (integral values without a fraction), booleans, dates and times as ISO 8601 text, and
/// formula errors as their text.
///
/// # Errors
///
/// Returns [`ReadError::Malformed`] for a damaged, encrypted or mislabeled file,
/// [`ReadError::TooLarge`] when a limit of `limits` is exceeded (including a zip whose
/// parts expand beyond [`ReadLimits::max_uncompressed`] or that uses zip64), and
/// [`ReadError::Unsupported`] for [`SourceFormat::Csv`], which is not a workbook.
pub fn read_workbook(
    name: &str,
    bytes: &[u8],
    format: SourceFormat,
    limits: &ReadLimits,
) -> Result<SourceFile, ReadError> {
    match format {
        SourceFormat::Csv => return Err(ReadError::Unsupported),
        SourceFormat::Xlsx | SourceFormat::Ods => {
            read_directory(bytes, limits)?;
        }
        SourceFormat::Xls => {
            if is_encrypted_package(bytes) {
                return Err(ReadError::Malformed(
                    "the workbook is password protected".to_owned(),
                ));
            }
        }
    }
    // A parser panic on hostile bytes is a damaged file, not a crashed import.
    let sheets = catch_unwind(AssertUnwindSafe(|| read_sheets(bytes, format, limits)))
        .map_err(|_| ReadError::Malformed("the workbook structure is damaged".to_owned()))??;
    Ok(SourceFile {
        name: name.to_owned(),
        format,
        sheets,
        text: None,
    })
}

/// Opens the workbook with the reader of its format and converts every sheet.
fn read_sheets(
    bytes: &[u8],
    format: SourceFormat,
    limits: &ReadLimits,
) -> Result<Vec<Sheet>, ReadError> {
    let cursor = Cursor::new(bytes);
    match format {
        SourceFormat::Xlsx => convert_workbook(
            Xlsx::new(cursor).map_err(|error| damaged_workbook("xlsx", &error))?,
            "xlsx",
            limits,
        ),
        SourceFormat::Xls => convert_workbook(
            Xls::new(cursor).map_err(|error| damaged_workbook("xls", &error))?,
            "xls",
            limits,
        ),
        SourceFormat::Ods => convert_workbook(
            Ods::new(cursor).map_err(|error| damaged_workbook("ods", &error))?,
            "ods",
            limits,
        ),
        SourceFormat::Csv => Err(ReadError::Unsupported),
    }
}

/// The error for a workbook `calamine` could not open or read.
fn damaged_workbook(label: &str, error: &dyn std::fmt::Display) -> ReadError {
    ReadError::Malformed(format!("the {label} workbook cannot be read ({error})"))
}

/// Converts every sheet of an opened workbook.
fn convert_workbook<RS, R>(
    mut workbook: R,
    label: &str,
    limits: &ReadLimits,
) -> Result<Vec<Sheet>, ReadError>
where
    RS: Read + Seek,
    R: Reader<RS>,
    <R as Reader<RS>>::Error: std::fmt::Display,
{
    let names = workbook.sheet_names();
    if names.len() > limits.max_sheets {
        return Err(ReadError::TooLarge(format!(
            "more than {} sheets (max_sheets)",
            limits.max_sheets
        )));
    }
    let mut sheets = Vec::with_capacity(names.len());
    for name in names {
        let range = workbook
            .worksheet_range(&name)
            .map_err(|error| damaged_workbook(label, &error))?;
        let rows = convert_range(&range, limits)?;
        sheets.push(Sheet { name, rows });
    }
    Ok(sheets)
}

/// Converts one sheet, offsetting the range so that row 0 is spreadsheet row 1 and column
/// 0 is column `A`.
fn convert_range(range: &Range<Data>, limits: &ReadLimits) -> Result<Vec<Vec<Cell>>, ReadError> {
    let Some((start_row, start_column)) = range.start() else {
        return Ok(Vec::new());
    };
    let start_row = to_usize(start_row);
    let start_column = to_usize(start_column);

    // The extent of the values, relative to the range: trailing empty rows and columns
    // are dropped (and do not count against the limits).
    let mut last_row = None;
    let mut last_column = 0;
    for (row_index, row) in range.rows().enumerate() {
        for (column_index, data) in row.iter().enumerate() {
            if !is_blank(data) {
                last_row = Some(row_index);
                last_column = last_column.max(column_index);
            }
        }
    }
    let Some(last_row) = last_row else {
        return Ok(Vec::new());
    };
    if start_row.saturating_add(last_row) >= limits.max_rows {
        return Err(ReadError::TooLarge(format!(
            "more than {} rows (max_rows)",
            limits.max_rows
        )));
    }
    if start_column.saturating_add(last_column) >= limits.max_columns {
        return Err(ReadError::TooLarge(format!(
            "more than {} columns (max_columns)",
            limits.max_columns
        )));
    }

    let mut rows = Vec::with_capacity(start_row + last_row + 1);
    rows.extend(std::iter::repeat_n(Vec::new(), start_row));
    for row in range.rows().take(last_row + 1) {
        if row.iter().all(is_blank) {
            rows.push(Vec::new());
            continue;
        }
        let mut cells = Vec::with_capacity(start_column + last_column + 1);
        cells.extend(std::iter::repeat_n(Cell::empty(), start_column));
        cells.extend(row.iter().take(last_column + 1).map(convert_cell));
        rows.push(cells);
    }
    Ok(rows)
}

/// A `u32` position as an index.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Whether a cell holds nothing (an empty cell, or text of only whitespace).
fn is_blank(data: &Data) -> bool {
    match data {
        Data::Empty => true,
        Data::String(text) => text.trim().is_empty(),
        _ => false,
    }
}

/// Converts one cell.
fn convert_cell(data: &Data) -> Cell {
    match data {
        Data::Empty => Cell::empty(),
        Data::String(text) => Cell::text(text),
        Data::Int(value) => Cell::number(value.to_string()),
        Data::Float(value) => float_cell(*value),
        Data::Bool(value) => Cell::of_kind(CellKind::Bool, if *value { "true" } else { "false" }),
        Data::DateTime(value) => Cell::of_kind(CellKind::Date, format_excel_datetime(value)),
        Data::DateTimeIso(text) | Data::DurationIso(text) => Cell::of_kind(CellKind::Date, text),
        Data::Error(error) => Cell::of_kind(CellKind::Error, error.to_string()),
    }
}

/// A number cell: integral values without a fraction, others in the shortest form that
/// reads back as the same number, exponent notation only for extreme magnitudes.
fn float_cell(value: f64) -> Cell {
    if !value.is_finite() {
        return Cell::of_kind(CellKind::Error, "#NUM!");
    }
    let magnitude = value.abs();
    let text = if value == 0.0 {
        "0".to_owned()
    } else if (1e-7..1e21).contains(&magnitude) {
        format!("{value}")
    } else {
        format!("{value:e}")
    };
    Cell::number(text)
}

/// ISO 8601 text of a date and time stored as an Excel serial number: `2026-10-09`, or
/// `2026-10-09T12:30:00` with a time of day, or `12:30:00` for a time alone (a serial
/// below one). A duration is rendered as `PT36H30M0S`. Fractions of a second are dropped.
fn format_excel_datetime(value: &ExcelDateTime) -> String {
    let serial = value.as_f64();
    if !serial.is_finite() || serial < 0.0 {
        return format!("{serial}");
    }
    if value.is_duration() {
        return format_duration(serial);
    }
    let (year, month, day, hour, minute, second, _milli) = value.to_ymd_hms_milli();
    let time = format!("{hour:02}:{minute:02}:{second:02}");
    if serial < 1.0 {
        time
    } else if hour == 0 && minute == 0 && second == 0 {
        format!("{year:04}-{month:02}-{day:02}")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{time}")
    }
}

/// An ISO 8601 duration for a span of `days` (hours may exceed 24).
fn format_duration(days: f64) -> String {
    // The cast is exact: the value is finite, not negative and rounded; the saturating
    // conversion keeps absurd magnitudes finite.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let seconds = (days * 86_400.0).round() as u64;
    format!(
        "PT{}H{}M{}S",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

// ---------------------------------------------------------------------------------------
// Zip central directory
// ---------------------------------------------------------------------------------------

/// Signature of the end of central directory record.
const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
/// Size of the end of central directory record without its comment.
const EOCD_SIZE: usize = 22;
/// Signature of the zip64 end of central directory locator.
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = *b"PK\x06\x07";
/// Size of the zip64 end of central directory locator.
const ZIP64_LOCATOR_SIZE: usize = 20;
/// Signature of a central directory entry.
const CENTRAL_SIGNATURE: [u8; 4] = *b"PK\x01\x02";
/// Size of a central directory entry without name, extra field and comment.
const CENTRAL_SIZE: usize = 46;
/// Signature of a local file header.
const LOCAL_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
/// Size of a local file header without name and extra field.
const LOCAL_SIZE: usize = 30;
/// The value a 32-bit zip field holds when the real value is in the zip64 extra field.
const ZIP64_SENTINEL: u32 = 0xFFFF_FFFF;
/// The value the 16-bit entry count holds when the real count is in the zip64 record.
const ZIP64_COUNT_SENTINEL: u16 = 0xFFFF;
/// The media type an `OpenDocument` spreadsheet declares in its `mimetype` part.
const ODS_MEDIA_TYPE: &[u8] = b"application/vnd.oasis.opendocument.spreadsheet";

/// One entry of the zip central directory.
struct ZipEntry {
    /// The part name.
    name: String,
    /// The compression method (0 is stored).
    method: u16,
    /// The declared uncompressed size.
    uncompressed: u32,
    /// The offset of the local header, relative to the start of the archive.
    local_offset: u32,
}

/// The parsed central directory of a zip archive.
struct ZipDirectory {
    /// The entries in directory order.
    entries: Vec<ZipEntry>,
    /// Bytes before the archive proper (a prefix such as an executable stub).
    archive_offset: usize,
}

impl ZipDirectory {
    /// Whether a part of this exact name exists.
    fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|entry| entry.name == name)
    }

    /// The first bytes of a stored (uncompressed) part, `None` when it is missing,
    /// compressed or its local header is damaged.
    fn stored_head<'a>(&self, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
        let entry = self.entries.iter().find(|entry| entry.name == name)?;
        if entry.method != 0 {
            return None;
        }
        let header = self
            .archive_offset
            .checked_add(usize::try_from(entry.local_offset).ok()?)?;
        if bytes.get(header..header.checked_add(4)?)? != LOCAL_SIGNATURE {
            return None;
        }
        let name_length = usize::from(read_u16(bytes, header + 26).ok()?);
        let extra_length = usize::from(read_u16(bytes, header + 28).ok()?);
        let start = header + LOCAL_SIZE + name_length + extra_length;
        let length = usize::try_from(entry.uncompressed).ok()?.min(256);
        bytes.get(start..start.checked_add(length)?)
    }
}

/// Decides between xlsx and ods from the part names of a zip archive (and the media type
/// of its `mimetype` part), after the size guard of [`read_directory`] passed.
///
/// The file extension (`hint`) only decides when the content fits both formats or an
/// `OpenDocument` file does not state its type.
///
/// # Errors
///
/// [`ReadError::Malformed`] for a damaged directory, [`ReadError::TooLarge`] for a zip
/// that exceeds the uncompressed size limit or uses zip64, [`ReadError::Unsupported`] for
/// a zip that is neither an xlsx nor an ods workbook.
pub(super) fn detect_zip(
    bytes: &[u8],
    limits: &ReadLimits,
    hint: Option<SourceFormat>,
) -> Result<SourceFormat, ReadError> {
    let directory = read_directory(bytes, limits)?;
    let is_xlsx =
        directory.contains("[Content_Types].xml") && directory.contains("xl/workbook.xml");
    let media_type = directory.stored_head(bytes, "mimetype");
    let is_ods = match media_type {
        Some(media_type) => media_type.trim_ascii().starts_with(ODS_MEDIA_TYPE),
        // Compressed or missing: an OpenDocument package by its parts, the extension decides.
        None => {
            directory.contains("content.xml")
                && directory.contains("META-INF/manifest.xml")
                && hint == Some(SourceFormat::Ods)
        }
    };
    match (is_xlsx, is_ods) {
        (false, false) => Err(ReadError::Unsupported),
        (false, true) => Ok(SourceFormat::Ods),
        (true, true) if hint == Some(SourceFormat::Ods) => Ok(SourceFormat::Ods),
        (true, _) => Ok(SourceFormat::Xlsx),
    }
}

/// Reads the central directory of a zip archive and applies the size guard: the declared
/// uncompressed sizes are summed and must stay within
/// [`ReadLimits::max_uncompressed`]; zip64 is refused because its sizes are not read.
fn read_directory(bytes: &[u8], limits: &ReadLimits) -> Result<ZipDirectory, ReadError> {
    let eocd = find_end_record(bytes).ok_or_else(damaged_zip)?;
    let has_zip64_locator = eocd
        .checked_sub(ZIP64_LOCATOR_SIZE)
        .and_then(|at| bytes.get(at..at + 4))
        .is_some_and(|signature| signature == ZIP64_LOCATOR_SIGNATURE);
    let disk = read_u16(bytes, eocd + 4)?;
    let directory_disk = read_u16(bytes, eocd + 6)?;
    let disk_entries = read_u16(bytes, eocd + 8)?;
    let entry_count = read_u16(bytes, eocd + 10)?;
    let directory_size = read_u32(bytes, eocd + 12)?;
    let directory_offset = read_u32(bytes, eocd + 16)?;
    if has_zip64_locator
        || entry_count == ZIP64_COUNT_SENTINEL
        || directory_size == ZIP64_SENTINEL
        || directory_offset == ZIP64_SENTINEL
    {
        return Err(zip64_refused());
    }
    if disk != 0 || directory_disk != 0 || disk_entries != entry_count {
        return Err(ReadError::Malformed(
            "the zip archive spans several disks".to_owned(),
        ));
    }

    // The directory ends where the end record starts; anything before it is a prefix.
    let directory_start = eocd
        .checked_sub(to_usize(directory_size))
        .ok_or_else(damaged_zip)?;
    let archive_offset = directory_start
        .checked_sub(to_usize(directory_offset))
        .ok_or_else(damaged_zip)?;

    let mut entries = Vec::with_capacity(usize::from(entry_count));
    let mut total: u64 = 0;
    let mut at = directory_start;
    for _ in 0..entry_count {
        if bytes.get(at..at + 4) != Some(&CENTRAL_SIGNATURE[..]) {
            return Err(damaged_zip());
        }
        let method = read_u16(bytes, at + 10)?;
        let compressed = read_u32(bytes, at + 20)?;
        let uncompressed = read_u32(bytes, at + 24)?;
        let name_length = usize::from(read_u16(bytes, at + 28)?);
        let extra_length = usize::from(read_u16(bytes, at + 30)?);
        let comment_length = usize::from(read_u16(bytes, at + 32)?);
        let local_offset = read_u32(bytes, at + 42)?;
        if compressed == ZIP64_SENTINEL
            || uncompressed == ZIP64_SENTINEL
            || local_offset == ZIP64_SENTINEL
        {
            return Err(zip64_refused());
        }
        let name_start = at + CENTRAL_SIZE;
        let next = name_start + name_length + extra_length + comment_length;
        if next > eocd {
            return Err(damaged_zip());
        }
        total = total.saturating_add(u64::from(uncompressed));
        if total > limits.max_uncompressed {
            return Err(ReadError::TooLarge(format!(
                "the workbook parts expand to more than {} bytes (max_uncompressed)",
                limits.max_uncompressed
            )));
        }
        entries.push(ZipEntry {
            name: String::from_utf8_lossy(&bytes[name_start..name_start + name_length])
                .into_owned(),
            method,
            uncompressed,
            local_offset,
        });
        at = next;
    }
    Ok(ZipDirectory {
        entries,
        archive_offset,
    })
}

/// The offset of the end of central directory record: the last signature whose comment
/// fits in the file, searched within the longest comment a record can carry.
fn find_end_record(bytes: &[u8]) -> Option<usize> {
    let last = bytes.len().checked_sub(EOCD_SIZE)?;
    let first = last.saturating_sub(usize::from(u16::MAX));
    (first..=last).rev().find(|&at| {
        bytes[at..at + 4] == EOCD_SIGNATURE
            && read_u16(bytes, at + 20)
                .is_ok_and(|comment| at + EOCD_SIZE + usize::from(comment) <= bytes.len())
    })
}

/// A little endian `u16` at `at`.
fn read_u16(bytes: &[u8], at: usize) -> Result<u16, ReadError> {
    let field = bytes.get(at..at + 2).ok_or_else(damaged_zip)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

/// A little endian `u32` at `at`.
fn read_u32(bytes: &[u8], at: usize) -> Result<u32, ReadError> {
    let field = bytes.get(at..at + 4).ok_or_else(damaged_zip)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// The error for a zip archive whose directory cannot be read.
fn damaged_zip() -> ReadError {
    ReadError::Malformed("the file is not a valid zip archive".to_owned())
}

/// The error for a zip64 archive.
fn zip64_refused() -> ReadError {
    ReadError::TooLarge(
        "zip64 archives are not read, their size cannot be checked (max_uncompressed)".to_owned(),
    )
}

/// Whether an OLE compound file holds an encrypted OOXML package (a password protected
/// xlsx): the stream name is stored in UTF-16 in the directory.
fn is_encrypted_package(bytes: &[u8]) -> bool {
    let needle: Vec<u8> = "EncryptedPackage"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Helpers that build small zip archives by hand, for the tests of the readers.
#[cfg(test)]
pub(crate) mod test_support {
    /// The CRC-32 of `data`.
    pub(crate) fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn u32_of(length: usize) -> u32 {
        u32::try_from(length).expect("small test archive")
    }

    fn u16_of(length: usize) -> u16 {
        u16::try_from(length).expect("small test archive")
    }

    /// A zip archive of stored entries.
    pub(crate) fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let declared: Vec<(&str, &[u8], u32)> = entries
            .iter()
            .map(|&(name, data)| (name, data, u32_of(data.len())))
            .collect();
        zip_declaring(&declared)
    }

    /// A zip archive of stored entries whose directory declares the given uncompressed
    /// sizes (the third item of each entry), whatever the data holds.
    pub(crate) fn zip_declaring(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut archive = Vec::new();
        let mut directory = Vec::new();
        for &(name, data, declared) in entries {
            let offset = u32_of(archive.len());
            let crc = crc32(data);
            let size = u32_of(data.len());
            archive.extend_from_slice(b"PK\x03\x04");
            archive.extend_from_slice(&20u16.to_le_bytes());
            archive.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x21, 0]);
            archive.extend_from_slice(&crc.to_le_bytes());
            archive.extend_from_slice(&size.to_le_bytes());
            archive.extend_from_slice(&declared.to_le_bytes());
            archive.extend_from_slice(&u16_of(name.len()).to_le_bytes());
            archive.extend_from_slice(&0u16.to_le_bytes());
            archive.extend_from_slice(name.as_bytes());
            archive.extend_from_slice(data);

            directory.extend_from_slice(b"PK\x01\x02");
            directory.extend_from_slice(&20u16.to_le_bytes());
            directory.extend_from_slice(&20u16.to_le_bytes());
            directory.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x21, 0]);
            directory.extend_from_slice(&crc.to_le_bytes());
            directory.extend_from_slice(&size.to_le_bytes());
            directory.extend_from_slice(&declared.to_le_bytes());
            directory.extend_from_slice(&u16_of(name.len()).to_le_bytes());
            directory.extend_from_slice(&[0; 8]);
            directory.extend_from_slice(&0u32.to_le_bytes());
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let directory_offset = u32_of(archive.len());
        archive.extend_from_slice(&directory);
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0; 4]);
        archive.extend_from_slice(&u16_of(entries.len()).to_le_bytes());
        archive.extend_from_slice(&u16_of(entries.len()).to_le_bytes());
        archive.extend_from_slice(&u32_of(directory.len()).to_le_bytes());
        archive.extend_from_slice(&directory_offset.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive
    }

    /// A minimal `OpenDocument` spreadsheet with one sheet of the given rows (all text
    /// except cells that parse as numbers, which are floats).
    pub(crate) fn ods(sheet: &str, rows: &[&[&str]]) -> Vec<u8> {
        let mut body = String::new();
        for row in rows {
            body.push_str("<table:table-row>");
            for cell in *row {
                let xml = if cell.parse::<f64>().is_ok() {
                    format!(
                        "<table:table-cell office:value-type=\"float\" office:value=\"{cell}\"><text:p>{cell}</text:p></table:table-cell>"
                    )
                } else if cell.is_empty() {
                    "<table:table-cell/>".to_owned()
                } else {
                    format!(
                        "<table:table-cell office:value-type=\"string\"><text:p>{cell}</text:p></table:table-cell>"
                    )
                };
                body.push_str(&xml);
            }
            body.push_str("</table:table-row>");
        }
        let content = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <office:document-content \
             xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
             xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\" \
             xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" \
             office:version=\"1.2\"><office:body><office:spreadsheet>\
             <table:table table:name=\"{sheet}\">{body}</table:table>\
             </office:spreadsheet></office:body></office:document-content>"
        );
        let manifest = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <manifest:manifest \
             xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\" \
             manifest:version=\"1.2\"/>";
        zip(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet",
            ),
            ("content.xml", content.as_bytes()),
            ("META-INF/manifest.xml", manifest.as_bytes()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use rust_xlsxwriter::{ExcelDateTime as WriterDate, Format, Workbook};

    use super::test_support::{ods, zip, zip_declaring};
    use super::*;

    fn limits() -> ReadLimits {
        ReadLimits::default()
    }

    fn texts(sheet: &Sheet) -> Vec<Vec<String>> {
        sheet
            .rows
            .iter()
            .map(|row| row.iter().map(|cell| cell.text.clone()).collect())
            .collect()
    }

    fn xlsx_with_all_kinds() -> Vec<u8> {
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        sheet.set_name("Plan").unwrap();
        sheet.write_string(0, 0, "host").unwrap();
        sheet.write_string(0, 1, "  192.0.2.10  ").unwrap();
        sheet.write_number(1, 0, 1234).unwrap();
        sheet.write_number(1, 1, -5).unwrap();
        sheet.write_number(1, 2, 1.5).unwrap();
        sheet.write_number(1, 3, 0.1).unwrap();
        sheet.write_number(1, 4, 12_345_678_901.0).unwrap();
        sheet.write_boolean(2, 0, true).unwrap();
        sheet.write_boolean(2, 1, false).unwrap();
        let date = Format::new().set_num_format("yyyy-mm-dd");
        let stamp = Format::new().set_num_format("yyyy-mm-dd hh:mm:ss");
        sheet
            .write_datetime_with_format(3, 0, WriterDate::from_ymd(2026, 10, 9).unwrap(), &date)
            .unwrap();
        sheet
            .write_datetime_with_format(
                3,
                1,
                WriterDate::from_ymd(2026, 10, 9)
                    .unwrap()
                    .and_hms(12, 30, 0)
                    .unwrap(),
                &stamp,
            )
            .unwrap();
        sheet.write_string(4, 0, "   ").unwrap();
        sheet.write_string(5, 2, "late").unwrap();
        workbook.save_to_buffer().unwrap()
    }

    #[test]
    fn xlsx_cells_keep_their_kind() {
        let file = read_workbook(
            "plan.xlsx",
            &xlsx_with_all_kinds(),
            SourceFormat::Xlsx,
            &limits(),
        )
        .unwrap();
        assert_eq!(file.format, SourceFormat::Xlsx);
        assert_eq!(file.name, "plan.xlsx");
        assert!(file.text.is_none());
        assert_eq!(file.sheets.len(), 1);
        let sheet = &file.sheets[0];
        assert_eq!(sheet.name, "Plan");
        assert_eq!(sheet.cell(0, 0), &Cell::text("host"));
        assert_eq!(sheet.cell(0, 1), &Cell::text("192.0.2.10"));
        assert_eq!(sheet.cell(1, 0), &Cell::number("1234"));
        assert_eq!(sheet.cell(1, 1), &Cell::number("-5"));
        assert_eq!(sheet.cell(1, 2), &Cell::number("1.5"));
        assert_eq!(sheet.cell(1, 3), &Cell::number("0.1"));
        assert_eq!(sheet.cell(1, 4), &Cell::number("12345678901"));
        assert_eq!(sheet.cell(2, 0), &Cell::of_kind(CellKind::Bool, "true"));
        assert_eq!(sheet.cell(2, 1), &Cell::of_kind(CellKind::Bool, "false"));
        assert_eq!(
            sheet.cell(3, 0),
            &Cell::of_kind(CellKind::Date, "2026-10-09")
        );
        assert_eq!(
            sheet.cell(3, 1),
            &Cell::of_kind(CellKind::Date, "2026-10-09T12:30:00")
        );
        // Whitespace-only text is an empty cell and its row is empty.
        assert_eq!(sheet.rows[4].len(), 0);
        assert_eq!(sheet.cell(5, 2), &Cell::text("late"));
        // Rows are as wide as the last column with a value in the sheet (column E).
        assert_eq!(sheet.rows.len(), 6);
        assert_eq!(sheet.rows[5].len(), 5);
    }

    #[test]
    fn xlsx_geometry_is_absolute() {
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        sheet.write_string(2, 1, "B3").unwrap();
        sheet.write_string(3, 2, "C4").unwrap();
        let bytes = workbook.save_to_buffer().unwrap();
        let file = read_workbook("g.xlsx", &bytes, SourceFormat::Xlsx, &limits()).unwrap();
        let sheet = &file.sheets[0];
        assert_eq!(sheet.rows.len(), 4);
        assert_eq!(sheet.rows[0].len(), 0);
        assert_eq!(sheet.rows[1].len(), 0);
        assert!(sheet.cell(0, 0).is_empty());
        assert_eq!(sheet.cell(2, 0), &Cell::empty());
        assert_eq!(sheet.rows[2][1], Cell::text("B3"));
        assert_eq!(sheet.rows[3][2], Cell::text("C4"));
        assert!(sheet.rows[2][0].is_empty());
    }

    #[test]
    fn xlsx_sheets_keep_workbook_order_and_empty_sheets_have_no_rows() {
        let mut workbook = Workbook::new();
        workbook.add_worksheet().set_name("Zeta").unwrap();
        workbook
            .add_worksheet()
            .set_name("Alpha")
            .unwrap()
            .write_string(0, 0, "x")
            .unwrap();
        let bytes = workbook.save_to_buffer().unwrap();
        let file = read_workbook("o.xlsx", &bytes, SourceFormat::Xlsx, &limits()).unwrap();
        let names: Vec<&str> = file
            .sheets
            .iter()
            .map(|sheet| sheet.name.as_str())
            .collect();
        assert_eq!(names, ["Zeta", "Alpha"]);
        assert_eq!(file.sheets[0].rows.len(), 0);
        assert_eq!(texts(&file.sheets[1]), vec![vec!["x".to_owned()]]);
    }

    #[test]
    fn xlsx_formula_errors_become_error_cells() {
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        sheet.write_string(0, 0, "ok").unwrap();
        sheet
            .write_formula(
                0,
                1,
                rust_xlsxwriter::Formula::new("=NA()").set_result("#N/A"),
            )
            .unwrap();
        let bytes = workbook.save_to_buffer().unwrap();
        let file = read_workbook("e.xlsx", &bytes, SourceFormat::Xlsx, &limits()).unwrap();
        assert_eq!(
            file.sheets[0].cell(0, 1),
            &Cell::of_kind(CellKind::Error, "#N/A")
        );
    }

    #[test]
    fn xlsx_limits() {
        let mut workbook = Workbook::new();
        for index in 0..3 {
            let sheet = workbook.add_worksheet();
            sheet.write_string(0, 0, "a").unwrap();
            if index == 0 {
                sheet.write_string(9, 4, "z").unwrap();
            }
        }
        let bytes = workbook.save_to_buffer().unwrap();
        assert!(read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &limits()).is_ok());

        let sheets = ReadLimits {
            max_sheets: 2,
            ..limits()
        };
        let error = read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &sheets).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_sheets")));

        let rows = ReadLimits {
            max_rows: 10,
            ..limits()
        };
        assert!(read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &rows).is_ok());
        let rows = ReadLimits {
            max_rows: 9,
            ..limits()
        };
        let error = read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &rows).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_rows")));

        let columns = ReadLimits {
            max_columns: 5,
            ..limits()
        };
        assert!(read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &columns).is_ok());
        let columns = ReadLimits {
            max_columns: 4,
            ..limits()
        };
        let error = read_workbook("l.xlsx", &bytes, SourceFormat::Xlsx, &columns).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_columns")));
    }

    #[test]
    fn xlsx_bomb_guard_uses_the_real_archive_sizes() {
        let bytes = xlsx_with_all_kinds();
        let tiny = ReadLimits {
            max_uncompressed: 1024,
            ..limits()
        };
        let error = read_workbook("b.xlsx", &bytes, SourceFormat::Xlsx, &tiny).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_uncompressed")));
    }

    #[test]
    fn ods_round_trip() {
        let bytes = ods(
            "Plan",
            &[&["host", "ip", "vlan"], &["web01", "192.0.2.10", "100"]],
        );
        let file = read_workbook("plan.ods", &bytes, SourceFormat::Ods, &limits()).unwrap();
        assert_eq!(file.format, SourceFormat::Ods);
        let sheet = &file.sheets[0];
        assert_eq!(sheet.name, "Plan");
        assert_eq!(sheet.cell(0, 1), &Cell::text("ip"));
        assert_eq!(sheet.cell(1, 1), &Cell::text("192.0.2.10"));
        assert_eq!(sheet.cell(1, 2), &Cell::number("100"));
    }

    #[test]
    fn csv_is_not_a_workbook() {
        assert_eq!(
            read_workbook("a.csv", b"a,b\n", SourceFormat::Csv, &limits()),
            Err(ReadError::Unsupported)
        );
    }

    #[test]
    fn damaged_workbooks_are_malformed() {
        for format in [SourceFormat::Xlsx, SourceFormat::Ods, SourceFormat::Xls] {
            // Not a zip, not an OLE file.
            assert!(matches!(
                read_workbook("x", b"definitely not a workbook", format, &limits()),
                Err(ReadError::Malformed(_))
            ));
            assert!(matches!(
                read_workbook("x", b"", format, &limits()),
                Err(ReadError::Malformed(_))
            ));
        }
        // A zip prefix with its directory cut off.
        let whole = zip(&[("a.txt", b"hello")]);
        let cut = &whole[..whole.len() - 30];
        assert!(matches!(
            read_workbook("x.xlsx", cut, SourceFormat::Xlsx, &limits()),
            Err(ReadError::Malformed(_))
        ));
        // A valid zip that holds no workbook.
        assert!(matches!(
            read_workbook("x.xlsx", &whole, SourceFormat::Xlsx, &limits()),
            Err(ReadError::Malformed(_))
        ));
        // An OLE signature followed by garbage.
        let mut ole = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        ole.extend_from_slice(&[0x55; 600]);
        assert!(matches!(
            read_workbook("x.xls", &ole, SourceFormat::Xls, &limits()),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn truncated_xlsx_is_malformed() {
        let bytes = xlsx_with_all_kinds();
        let half = &bytes[..bytes.len() / 2];
        assert!(matches!(
            read_workbook("x.xlsx", half, SourceFormat::Xlsx, &limits()),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn corrupted_directory_entries_are_malformed() {
        let mut bytes = zip(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        // Break the signature of the second central directory entry.
        let position = bytes
            .windows(4)
            .enumerate()
            .filter(|(_, window)| *window == b"PK\x01\x02")
            .map(|(at, _)| at)
            .nth(1)
            .unwrap();
        bytes[position + 2] = 0x7F;
        assert!(matches!(
            read_directory(&bytes, &limits()),
            Err(ReadError::Malformed(_))
        ));
        // A directory size larger than the file.
        let mut bytes = zip(&[("a.txt", b"hello")]);
        let eocd = bytes.len() - 22;
        bytes[eocd + 12..eocd + 16].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        assert!(matches!(
            read_directory(&bytes, &limits()),
            Err(ReadError::Malformed(_))
        ));
        // A name that runs past the directory.
        let mut bytes = zip(&[("a.txt", b"hello")]);
        let entry = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bytes[entry + 28..entry + 30].copy_from_slice(&0x4000u16.to_le_bytes());
        assert!(matches!(
            read_directory(&bytes, &limits()),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn zip_bomb_guard_sums_declared_sizes() {
        let bytes = zip_declaring(&[
            ("a.xml", b"x", 600),
            ("b.xml", b"y", 600),
            ("c.xml", b"z", 600),
        ]);
        let tiny = ReadLimits {
            max_uncompressed: 1500,
            ..limits()
        };
        let error = read_directory(&bytes, &tiny).err().unwrap();
        assert!(matches!(&error, ReadError::TooLarge(m) if m.contains("max_uncompressed")));
        let fits = ReadLimits {
            max_uncompressed: 1800,
            ..limits()
        };
        assert_eq!(read_directory(&bytes, &fits).unwrap().entries.len(), 3);
        // The guard runs before the bytes reach the workbook parser.
        let error = read_workbook("bomb.xlsx", &bytes, SourceFormat::Xlsx, &tiny).unwrap_err();
        assert!(matches!(error, ReadError::TooLarge(_)));
        let error = read_workbook("bomb.ods", &bytes, SourceFormat::Ods, &tiny).unwrap_err();
        assert!(matches!(error, ReadError::TooLarge(_)));
    }

    #[test]
    fn zip64_sentinels_are_refused() {
        // A declared uncompressed size of 0xFFFFFFFF.
        let bytes = zip_declaring(&[("a.xml", b"x", 0xFFFF_FFFF)]);
        let error = read_directory(&bytes, &limits()).err().unwrap();
        assert!(matches!(error, ReadError::TooLarge(_)), "{error:?}");
        // Sentinel in the end record.
        let mut bytes = zip(&[("a.xml", b"x")]);
        let eocd = bytes.len() - 22;
        bytes[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(
            read_directory(&bytes, &limits()),
            Err(ReadError::TooLarge(_))
        ));
        // A zip64 locator before the end record.
        let mut bytes = zip(&[("a.xml", b"x")]);
        let eocd = bytes.len() - 22;
        let mut with_locator = bytes[..eocd].to_vec();
        with_locator.extend_from_slice(b"PK\x06\x07");
        with_locator.extend_from_slice(&[0; 16]);
        with_locator.extend_from_slice(&bytes.split_off(eocd));
        assert!(matches!(
            read_directory(&with_locator, &limits()),
            Err(ReadError::TooLarge(_))
        ));
    }

    #[test]
    fn zip_with_a_prefix_and_a_comment_is_read() {
        let inner = zip(&[(
            "mimetype",
            b"application/vnd.oasis.opendocument.spreadsheet",
        )]);
        let mut bytes = b"stub".to_vec();
        bytes.extend_from_slice(&inner);
        // A comment after the end record.
        let eocd = bytes.len() - 22;
        bytes[eocd + 20..eocd + 22].copy_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(b"hello");
        let directory = read_directory(&bytes, &limits()).unwrap();
        assert_eq!(directory.entries.len(), 1);
        assert_eq!(directory.archive_offset, 4);
        assert_eq!(
            directory.stored_head(&bytes, "mimetype"),
            Some(b"application/vnd.oasis.opendocument.spreadsheet".as_slice())
        );
    }

    #[test]
    fn detects_zip_kinds() {
        let xlsx = zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("xl/workbook.xml", b"<workbook/>"),
        ]);
        assert_eq!(detect_zip(&xlsx, &limits(), None), Ok(SourceFormat::Xlsx));
        let ods = zip(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet",
            ),
            ("content.xml", b"<doc/>"),
        ]);
        assert_eq!(detect_zip(&ods, &limits(), None), Ok(SourceFormat::Ods));
        // Both markers: the extension decides.
        let both = zip(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet",
            ),
            ("[Content_Types].xml", b"<Types/>"),
            ("xl/workbook.xml", b"<workbook/>"),
        ]);
        assert_eq!(detect_zip(&both, &limits(), None), Ok(SourceFormat::Xlsx));
        assert_eq!(
            detect_zip(&both, &limits(), Some(SourceFormat::Ods)),
            Ok(SourceFormat::Ods)
        );
        // Other OpenDocument types and other zip files are not workbooks.
        let odt = zip(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text"),
            ("content.xml", b"<doc/>"),
            ("META-INF/manifest.xml", b"<m/>"),
        ]);
        assert_eq!(
            detect_zip(&odt, &limits(), Some(SourceFormat::Ods)),
            Err(ReadError::Unsupported)
        );
        let docx = zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<d/>"),
        ]);
        assert_eq!(
            detect_zip(&docx, &limits(), Some(SourceFormat::Xlsx)),
            Err(ReadError::Unsupported)
        );
        let plain = zip(&[("notes.txt", b"hello")]);
        assert_eq!(
            detect_zip(&plain, &limits(), None),
            Err(ReadError::Unsupported)
        );
    }

    #[test]
    fn number_rendering() {
        assert_eq!(float_cell(1234.0), Cell::number("1234"));
        assert_eq!(float_cell(-5.0), Cell::number("-5"));
        assert_eq!(float_cell(1.5), Cell::number("1.5"));
        assert_eq!(float_cell(-0.25), Cell::number("-0.25"));
        assert_eq!(float_cell(0.0), Cell::number("0"));
        assert_eq!(float_cell(-0.0), Cell::number("0"));
        assert_eq!(float_cell(0.1 + 0.2), Cell::number("0.30000000000000004"));
        assert_eq!(float_cell(123_456_789_012.0), Cell::number("123456789012"));
        assert_eq!(float_cell(1e21), Cell::number("1e21"));
        assert_eq!(float_cell(1.5e-10), Cell::number("1.5e-10"));
        assert_eq!(float_cell(f64::NAN).kind, CellKind::Error);
        assert_eq!(float_cell(f64::INFINITY).kind, CellKind::Error);
        assert_eq!(convert_cell(&Data::Int(-5)), Cell::number("-5"));
        assert_eq!(convert_cell(&Data::Float(7.0)), Cell::number("7"));
    }

    #[test]
    fn cell_conversion() {
        assert_eq!(convert_cell(&Data::Empty), Cell::empty());
        assert_eq!(
            convert_cell(&Data::String("  x ".to_owned())),
            Cell::text("x")
        );
        assert_eq!(convert_cell(&Data::String("  ".to_owned())), Cell::empty());
        assert_eq!(
            convert_cell(&Data::Bool(true)),
            Cell::of_kind(CellKind::Bool, "true")
        );
        assert_eq!(
            convert_cell(&Data::DateTimeIso("2026-10-09T12:30:00".to_owned())),
            Cell::of_kind(CellKind::Date, "2026-10-09T12:30:00")
        );
        assert_eq!(
            convert_cell(&Data::DurationIso("PT1H".to_owned())),
            Cell::of_kind(CellKind::Date, "PT1H")
        );
        for (error, text) in [
            (calamine::CellErrorType::NA, "#N/A"),
            (calamine::CellErrorType::Div0, "#DIV/0!"),
            (calamine::CellErrorType::Ref, "#REF!"),
        ] {
            assert_eq!(
                convert_cell(&Data::Error(error)),
                Cell::of_kind(CellKind::Error, text)
            );
        }
    }

    #[test]
    fn excel_serials_render_as_iso_8601() {
        use calamine::ExcelDateTimeType::{DateTime, TimeDelta};
        let render = |serial: f64, kind, is_1904| {
            format_excel_datetime(&ExcelDateTime::new(serial, kind, is_1904))
        };
        // 2026-10-09 is serial 46304.
        assert_eq!(render(46_304.0, DateTime, false), "2026-10-09");
        assert_eq!(render(46_304.5, DateTime, false), "2026-10-09T12:00:00");
        assert_eq!(
            render(46_304.521_180_555_6, DateTime, false),
            "2026-10-09T12:30:30"
        );
        assert_eq!(render(0.5, DateTime, false), "12:00:00");
        assert_eq!(render(0.75, DateTime, true), "18:00:00");
        // The 1904 system counts from 1904-01-01.
        assert_eq!(render(1_462.0, DateTime, true), "1908-01-02");
        assert_eq!(render(1.5, TimeDelta, false), "PT36H0M0S");
        assert_eq!(render(0.020_833_333_3, TimeDelta, false), "PT0H30M0S");
    }
}
