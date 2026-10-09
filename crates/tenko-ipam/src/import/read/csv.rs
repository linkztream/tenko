//! The CSV reader (see the [module documentation](super)).

use std::borrow::Cow;

use encoding_rs::{UTF_16BE, UTF_16LE, WINDOWS_1252};

use super::{Cell, ReadError, ReadLimits, Sheet, SourceFile, SourceFormat, TextInfo};

/// The delimiters the sniffer chooses among; on a tie the earlier one wins.
const DELIMITERS: [u8; 3] = *b",;\t";
/// How many non-empty lines the delimiter sniffer looks at.
const SNIFF_LINES: usize = 20;
/// The UTF-8 byte order mark.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
/// The UTF-16 little endian byte order mark.
const UTF16LE_BOM: [u8; 2] = [0xFF, 0xFE];
/// The UTF-16 big endian byte order mark.
const UTF16BE_BOM: [u8; 2] = [0xFE, 0xFF];

/// Reads one CSV file into a single [`Sheet`] named after the file.
///
/// The text is decoded (UTF-8 with or without a byte order mark, UTF-16 with one,
/// Windows-1252 otherwise), the delimiter is sniffed among `,`, `;` and tab, and the
/// fields are parsed per RFC 4180. Every value is a [`CellKind::Text`](super::CellKind::Text)
/// cell; rows stay ragged and trailing empty rows are removed. A blank line inside the
/// file is an empty row, so row numbers match what a spreadsheet program shows.
///
/// # Errors
///
/// Returns [`ReadError::Malformed`] when UTF-16 text is damaged and
/// [`ReadError::TooLarge`] when the file has more rows or columns than `limits` allow.
pub fn read_csv(name: &str, bytes: &[u8], limits: &ReadLimits) -> Result<SourceFile, ReadError> {
    let decoded = decode(bytes)?;
    let delimiter = sniff_delimiter(&decoded.text);
    let rows = parse_rows(&decoded.text, delimiter, limits)?;
    Ok(SourceFile {
        name: name.to_owned(),
        format: SourceFormat::Csv,
        sheets: vec![Sheet {
            name: sheet_name(name),
            rows,
        }],
        text: Some(TextInfo {
            encoding: decoded.encoding.to_owned(),
            bom: decoded.bom,
            delimiter: char::from(delimiter),
        }),
    })
}

/// A decoded text file.
struct Decoded<'a> {
    /// The text without its byte order mark.
    text: Cow<'a, str>,
    /// The name of the encoding it was decoded from.
    encoding: &'static str,
    /// Whether the file started with a byte order mark.
    bom: bool,
}

/// Decodes the bytes: a UTF-16 byte order mark selects UTF-16, otherwise valid UTF-8 (a
/// UTF-8 byte order mark is stripped) is UTF-8 and anything else is Windows-1252, which
/// maps every byte to a character.
fn decode(bytes: &[u8]) -> Result<Decoded<'_>, ReadError> {
    if let Some(rest) = bytes.strip_prefix(&UTF16LE_BOM) {
        return decode_utf16(rest, UTF_16LE, "UTF-16LE");
    }
    if let Some(rest) = bytes.strip_prefix(&UTF16BE_BOM) {
        return decode_utf16(rest, UTF_16BE, "UTF-16BE");
    }
    let (body, bom) = match bytes.strip_prefix(&UTF8_BOM) {
        Some(rest) => (rest, true),
        None => (bytes, false),
    };
    Ok(match std::str::from_utf8(body) {
        Ok(text) => Decoded {
            text: Cow::Borrowed(text),
            encoding: "UTF-8",
            bom,
        },
        Err(_) => Decoded {
            text: WINDOWS_1252.decode_without_bom_handling(body).0,
            encoding: "windows-1252",
            bom,
        },
    })
}

/// Decodes UTF-16 text whose byte order mark is already removed.
fn decode_utf16<'a>(
    bytes: &'a [u8],
    encoding: &'static encoding_rs::Encoding,
    label: &'static str,
) -> Result<Decoded<'a>, ReadError> {
    let (text, had_errors) = encoding.decode_without_bom_handling(bytes);
    if had_errors {
        return Err(ReadError::Malformed(format!("the {label} text is damaged")));
    }
    Ok(Decoded {
        text,
        encoding: label,
        bom: true,
    })
}

/// Picks the delimiter from the first lines of the text.
///
/// Each candidate is counted per line outside quoted sections. A candidate qualifies when
/// one non-zero count repeats on at least half of the sampled lines; the candidate with
/// the most such lines wins, and on a tie the one with the higher count (so a decimal
/// comma in a semicolon file does not win over the semicolons). Without a qualifying
/// candidate (a single column) the delimiter is a comma.
fn sniff_delimiter(text: &str) -> u8 {
    let samples = sample_counts(text);
    let mut best: Option<(usize, usize, u8)> = None;
    for (slot, delimiter) in DELIMITERS.into_iter().enumerate() {
        // The most frequent non-zero count of this candidate, as (lines, count).
        let mut mode = (0, 0);
        for count in samples.iter().map(|line| line[slot]).filter(|&n| n > 0) {
            let lines = samples.iter().filter(|line| line[slot] == count).count();
            mode = mode.max((lines, count));
        }
        if mode.0 == 0 || mode.0 * 2 < samples.len() {
            continue;
        }
        if best.is_none_or(|(lines, count, _)| (mode.0, mode.1) > (lines, count)) {
            best = Some((mode.0, mode.1, delimiter));
        }
    }
    best.map_or(b',', |(_, _, delimiter)| delimiter)
}

/// Counts every candidate delimiter outside quoted sections on the first non-empty
/// lines. A quote opens a quoted section only at the start of a field, as in RFC 4180.
fn sample_counts(text: &str) -> Vec<[usize; DELIMITERS.len()]> {
    let mut samples = Vec::new();
    let mut counts = [0; DELIMITERS.len()];
    let mut in_quotes = false;
    let mut field_start = true;
    let mut blank = true;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            continue;
        }
        if c == '\n' || c == '\r' {
            if !blank {
                samples.push(counts);
                if samples.len() == SNIFF_LINES {
                    return samples;
                }
            }
            counts = [0; DELIMITERS.len()];
            field_start = true;
            blank = true;
            continue;
        }
        let slot = u8::try_from(c)
            .ok()
            .and_then(|byte| DELIMITERS.iter().position(|&d| d == byte));
        if let Some(slot) = slot {
            counts[slot] += 1;
            field_start = true;
            blank = false;
        } else if c == '"' && field_start {
            in_quotes = true;
            field_start = false;
            blank = false;
        } else {
            field_start = false;
            blank &= c.is_whitespace();
        }
    }
    if !blank {
        samples.push(counts);
    }
    samples
}

/// Parses the text into rows of cells, keeping blank lines as empty rows and dropping
/// the trailing ones.
fn parse_rows(text: &str, delimiter: u8, limits: &ReadLimits) -> Result<Vec<Vec<Cell>>, ReadError> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    // Empty rows seen since the last row with a value; they are kept only when a later
    // row has a value, so a file of blank lines costs no memory.
    let mut pending_empty = 0usize;
    let bytes = text.as_bytes();
    let mut record = csv::StringRecord::new();
    loop {
        match reader.read_record(&mut record) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                return Err(ReadError::Malformed(format!(
                    "the CSV text cannot be parsed: {error}"
                )));
            }
        }
        // The csv crate skips blank lines. A record's position is where the previous one
        // ended, so the blank lines it skipped are the line breaks that follow that point.
        let from = record.position().map_or(0, |position| {
            usize::try_from(position.byte()).unwrap_or(usize::MAX)
        });
        pending_empty = pending_empty.saturating_add(blank_lines_from(bytes, from));

        let cells = record_cells(&record, limits)?;
        if cells.iter().all(Cell::is_empty) {
            pending_empty = pending_empty.saturating_add(1);
            continue;
        }
        if rows.len().saturating_add(pending_empty) >= limits.max_rows {
            return Err(ReadError::TooLarge(format!(
                "more than {} rows (max_rows)",
                limits.max_rows
            )));
        }
        rows.extend(std::iter::repeat_n(Vec::new(), pending_empty));
        pending_empty = 0;
        rows.push(cells);
    }
    Ok(rows)
}

/// The number of blank lines (line breaks with nothing before them) at `bytes[from..]`.
///
/// The csv crate ends a record after the `\r` of a `\r\n` break, so when `from` is in the
/// middle of one the `\n` belongs to the previous record.
fn blank_lines_from(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    if at > 0 && bytes.get(at - 1) == Some(&b'\r') && bytes.get(at) == Some(&b'\n') {
        at += 1;
    }
    let mut count = 0usize;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\n' => at += 1,
            b'\r' => {
                at += if bytes.get(at + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                }
            }
            _ => break,
        }
        count += 1;
    }
    count
}

/// The cells of one record. Empty fields beyond `max_columns` are dropped, a value
/// beyond it is an error.
fn record_cells(record: &csv::StringRecord, limits: &ReadLimits) -> Result<Vec<Cell>, ReadError> {
    let width = record.len().min(limits.max_columns);
    if record
        .iter()
        .skip(width)
        .any(|field| !field.trim().is_empty())
    {
        return Err(ReadError::TooLarge(format!(
            "more than {} columns (max_columns)",
            limits.max_columns
        )));
    }
    Ok(record.iter().take(width).map(Cell::text).collect())
}

/// The sheet name of a CSV file: the file name without its directory and without a
/// `.csv`, `.tsv` or `.txt` extension (any case). Other names stay whole, so
/// `192.0.2.0.csv` is `192.0.2.0` and `192.0.2.0` is `192.0.2.0`.
fn sheet_name(name: &str) -> String {
    let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
    for extension in [".csv", ".tsv", ".txt"] {
        let Some(split) = file.len().checked_sub(extension.len()).filter(|&at| at > 0) else {
            continue;
        };
        if file
            .get(split..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(extension))
        {
            return file[..split].to_owned();
        }
    }
    file.to_owned()
}

#[cfg(test)]
mod tests {
    use super::super::CellKind;
    use super::*;

    fn read(bytes: &[u8]) -> SourceFile {
        read_csv("plan.csv", bytes, &ReadLimits::default()).expect("readable")
    }

    fn texts(file: &SourceFile) -> Vec<Vec<&str>> {
        file.sheets[0]
            .rows
            .iter()
            .map(|row| row.iter().map(|cell| cell.text.as_str()).collect())
            .collect()
    }

    fn info(file: &SourceFile) -> &TextInfo {
        file.text.as_ref().expect("text info")
    }

    fn utf16(text: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            UTF16LE_BOM.to_vec()
        } else {
            UTF16BE_BOM.to_vec()
        };
        for unit in text.encode_utf16() {
            bytes.extend(if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        bytes
    }

    #[test]
    fn utf8_without_bom() {
        let file = read("name,ip\nweb01,192.0.2.10\n".as_bytes());
        assert_eq!(file.format, SourceFormat::Csv);
        assert_eq!(file.name, "plan.csv");
        assert_eq!(file.sheets.len(), 1);
        assert_eq!(
            info(&file),
            &TextInfo {
                encoding: "UTF-8".to_owned(),
                bom: false,
                delimiter: ',',
            }
        );
        assert_eq!(
            texts(&file),
            vec![vec!["name", "ip"], vec!["web01", "192.0.2.10"]]
        );
    }

    #[test]
    fn utf8_with_bom_is_stripped() {
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice("namn,värde\n".as_bytes());
        let file = read(&bytes);
        assert_eq!(info(&file).encoding, "UTF-8");
        assert!(info(&file).bom);
        assert_eq!(texts(&file), vec![vec!["namn", "värde"]]);
    }

    #[test]
    fn windows_1252_when_not_utf8() {
        let file = read(b"namn;v\xE4rde\n\xE5\xE4\xF6;\xC5\xC4\xD6\n");
        assert_eq!(info(&file).encoding, "windows-1252");
        assert!(!info(&file).bom);
        assert_eq!(info(&file).delimiter, ';');
        assert_eq!(
            texts(&file),
            vec![vec!["namn", "värde"], vec!["åäö", "ÅÄÖ"]]
        );
    }

    #[test]
    fn windows_1252_specials() {
        // 0x80 is the euro sign, 0x93 and 0x94 are curly quotes.
        let file = read(b"price;note\n5 \x80;\x93x\x94\n");
        assert_eq!(texts(&file)[1], vec!["5 €", "\u{201C}x\u{201D}"]);
    }

    #[test]
    fn utf16_little_endian_with_bom() {
        let file = read(&utf16("namn;värde\nweb01;192.0.2.10\n", true));
        assert_eq!(info(&file).encoding, "UTF-16LE");
        assert!(info(&file).bom);
        assert_eq!(info(&file).delimiter, ';');
        assert_eq!(
            texts(&file),
            vec![vec!["namn", "värde"], vec!["web01", "192.0.2.10"]]
        );
    }

    #[test]
    fn utf16_big_endian_with_bom() {
        let file = read(&utf16("a\tb\nåäö\t2\n", false));
        assert_eq!(info(&file).encoding, "UTF-16BE");
        assert_eq!(info(&file).delimiter, '\t');
        assert_eq!(texts(&file), vec![vec!["a", "b"], vec!["åäö", "2"]]);
    }

    #[test]
    fn damaged_utf16_is_malformed() {
        // An odd number of bytes after the mark.
        let mut odd = utf16("a,b\n", true);
        odd.push(0x41);
        assert!(matches!(
            read_csv("x.csv", &odd, &ReadLimits::default()),
            Err(ReadError::Malformed(_))
        ));
        // A lone high surrogate.
        let lone = [0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00];
        assert!(matches!(
            read_csv("x.csv", &lone, &ReadLimits::default()),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn sniffs_comma_semicolon_and_tab() {
        let comma = read(b"a,b,c\n1,2,3\n");
        assert_eq!(info(&comma).delimiter, ',');
        assert_eq!(texts(&comma)[1], vec!["1", "2", "3"]);

        let semicolon = read(b"a;b;c\n1;2;3\n");
        assert_eq!(info(&semicolon).delimiter, ';');
        assert_eq!(texts(&semicolon)[1], vec!["1", "2", "3"]);

        let tab = read(b"a\tb\tc\n1\t2\t3\n");
        assert_eq!(info(&tab).delimiter, '\t');
        assert_eq!(texts(&tab)[1], vec!["1", "2", "3"]);
    }

    #[test]
    fn single_column_defaults_to_comma() {
        let file = read(b"host\nweb01\nweb02\n");
        assert_eq!(info(&file).delimiter, ',');
        assert_eq!(
            texts(&file),
            vec![vec!["host"], vec!["web01"], vec!["web02"]]
        );
        let empty = read(b"");
        assert_eq!(info(&empty).delimiter, ',');
    }

    #[test]
    fn swedish_file_with_decimal_commas_stays_semicolon() {
        let file = read(
            "Namn;IP;Pris\nweb01;192.0.2.10;12,5\nweb02;192.0.2.11;7,25\nweb03;192.0.2.12;3,0\n"
                .as_bytes(),
        );
        assert_eq!(info(&file).delimiter, ';');
        let sheet = &file.sheets[0];
        assert_eq!(sheet.cell(1, 2).text, "12,5");
        assert_eq!(sheet.cell(2, 2).text, "7,25");
        assert_eq!(sheet.width(), 3);
    }

    #[test]
    fn delimiters_inside_quotes_are_not_counted() {
        let file =
            read(b"name,note\nweb01,\"a;b;c;d\"\nweb02,\"x;y;z;w\"\nweb03,\"one;two;three\"\n");
        assert_eq!(info(&file).delimiter, ',');
        assert_eq!(file.sheets[0].cell(1, 1).text, "a;b;c;d");

        let tabs = read(b"name\tnote\nweb01\ta, b, c\nweb02\td, e\n");
        assert_eq!(info(&tabs).delimiter, '\t');
        assert_eq!(tabs.sheets[0].cell(1, 1).text, "a, b, c");
    }

    #[test]
    fn sniffs_only_the_first_lines() {
        let mut text = String::from("a;b\n");
        text.push_str(&"1;2\n".repeat(30));
        text.push_str(&"x,y,z,w\n".repeat(50));
        let file = read(text.as_bytes());
        assert_eq!(info(&file).delimiter, ';');
    }

    #[test]
    fn quoted_fields_follow_rfc_4180() {
        let file = read(
            b"name,note,value\n\"web, one\",\"say \"\"hi\"\"\",1\n\"web two\",\"line1\nline2\",2\nplain,\"\",3\n",
        );
        assert_eq!(
            texts(&file),
            vec![
                vec!["name", "note", "value"],
                vec!["web, one", "say \"hi\"", "1"],
                vec!["web two", "line1\nline2", "2"],
                vec!["plain", "", "3"],
            ]
        );
    }

    #[test]
    fn quoted_newline_with_crlf_line_ends() {
        let file = read(b"a,b\r\n\"x\r\ny\",2\r\nz,3\r\n");
        assert_eq!(
            texts(&file),
            vec![vec!["a", "b"], vec!["x\r\ny", "2"], vec!["z", "3"]]
        );
    }

    #[test]
    fn rows_stay_ragged() {
        let file = read(b"a,b,c\n1\n1,2,3,4\n,\n\n5,6\n");
        let rows = texts(&file);
        assert_eq!(rows[0], vec!["a", "b", "c"]);
        assert_eq!(rows[1], vec!["1"]);
        assert_eq!(rows[2], vec!["1", "2", "3", "4"]);
        // A row of empty fields is an empty row, the blank line after it too.
        assert_eq!(rows[3].len(), 0);
        assert_eq!(rows[4].len(), 0);
        assert_eq!(rows[5], vec!["5", "6"]);
        assert_eq!(file.sheets[0].width(), 4);
    }

    #[test]
    fn trailing_empty_rows_are_removed() {
        let file = read(b"a,b\n1,2\n\n\n,,\n   \n\n");
        assert_eq!(texts(&file), vec![vec!["a", "b"], vec!["1", "2"]]);
        let only_blank = read(b"\n\n,\n");
        assert_eq!(only_blank.sheets[0].rows.len(), 0);
        assert!(only_blank.sheets[0].is_empty());
    }

    #[test]
    fn blank_lines_keep_the_row_numbers() {
        let file = read(b"\n\nhead,x\n\nweb01,1\r\n\r\nweb02,2");
        let sheet = &file.sheets[0];
        assert_eq!(sheet.rows.len(), 7);
        assert_eq!(sheet.rows[0].len(), 0);
        assert_eq!(sheet.rows[1].len(), 0);
        assert_eq!(sheet.cell(2, 0).text, "head");
        assert_eq!(sheet.rows[3].len(), 0);
        assert_eq!(sheet.cell(4, 0).text, "web01");
        assert_eq!(sheet.rows[5].len(), 0);
        assert_eq!(sheet.cell(6, 0).text, "web02");
    }

    #[test]
    fn carriage_return_line_ends() {
        let file = read(b"a,b\r1,2\r\r3,4\r");
        assert_eq!(
            texts(&file),
            vec![vec!["a", "b"], vec!["1", "2"], vec![], vec!["3", "4"]]
        );
    }

    #[test]
    fn blank_lines_after_a_multiline_field_keep_the_row_numbers() {
        let file = read(b"a,b\n\"x\ny\",2\n\nz,3\n");
        let sheet = &file.sheets[0];
        assert_eq!(sheet.rows.len(), 4);
        assert_eq!(sheet.cell(1, 0).text, "x\ny");
        assert_eq!(sheet.rows[2].len(), 0);
        assert_eq!(sheet.cell(3, 0).text, "z");
    }

    #[test]
    fn values_are_trimmed_text() {
        let file = read(b"a , b\n  x  ,   \n\"  y \", \xC2\xA0 \n");
        let sheet = &file.sheets[0];
        assert_eq!(sheet.cell(0, 0).text, "a");
        assert_eq!(sheet.cell(0, 1).text, "b");
        assert_eq!(sheet.cell(1, 0), &Cell::text("x"));
        assert!(sheet.cell(1, 1).is_empty());
        assert_eq!(sheet.cell(1, 1).kind, CellKind::Empty);
        assert_eq!(sheet.cell(2, 0).text, "y");
        assert!(sheet.cell(2, 1).is_empty());
        for row in &sheet.rows {
            for cell in row.iter().filter(|cell| !cell.is_empty()) {
                assert_eq!(cell.kind, CellKind::Text);
            }
        }
    }

    #[test]
    fn empty_input_is_an_empty_sheet() {
        let file = read(b"");
        assert_eq!(file.sheets.len(), 1);
        assert_eq!(file.sheets[0].rows.len(), 0);
        let bom_only = read(&UTF8_BOM);
        assert_eq!(bom_only.sheets[0].rows.len(), 0);
        assert!(info(&bom_only).bom);
    }

    #[test]
    fn sheet_names() {
        assert_eq!(sheet_name("192.0.2.0.csv"), "192.0.2.0");
        assert_eq!(sheet_name("192.0.2.0"), "192.0.2.0");
        assert_eq!(sheet_name("ip-plan.CSV"), "ip-plan");
        assert_eq!(sheet_name("ip-plan.Tsv"), "ip-plan");
        assert_eq!(sheet_name("notes.txt"), "notes");
        assert_eq!(sheet_name("C:\\data\\site a.csv"), "site a");
        assert_eq!(sheet_name("/srv/uploads/203.0.113.0.csv"), "203.0.113.0");
        assert_eq!(sheet_name("plan.xlsx"), "plan.xlsx");
        assert_eq!(sheet_name("plan.csv.bak"), "plan.csv.bak");
        assert_eq!(sheet_name("a.csv.csv"), "a.csv");
        assert_eq!(sheet_name(".csv"), ".csv");
        assert_eq!(sheet_name(""), "");
        let file = read_csv("dir/192.0.2.0.csv", b"a\n", &ReadLimits::default()).unwrap();
        assert_eq!(file.sheets[0].name, "192.0.2.0");
        assert_eq!(file.name, "dir/192.0.2.0.csv");
    }

    #[test]
    fn row_limit_is_enforced() {
        let limits = ReadLimits {
            max_rows: 3,
            ..ReadLimits::default()
        };
        assert!(read_csv("x.csv", b"a\nb\nc\n", &limits).is_ok());
        // Trailing empty rows do not count.
        assert!(read_csv("x.csv", b"a\nb\nc\n\n\n\n\n", &limits).is_ok());
        let error = read_csv("x.csv", b"a\nb\nc\nd\n", &limits).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(message) if message.contains("max_rows")));
        // Blank lines before a row with a value count.
        assert!(matches!(
            read_csv("x.csv", b"a\n\n\n\nd\n", &limits),
            Err(ReadError::TooLarge(_))
        ));
    }

    #[test]
    fn column_limit_is_enforced() {
        let limits = ReadLimits {
            max_columns: 3,
            ..ReadLimits::default()
        };
        assert!(read_csv("x.csv", b"a,b,c\n", &limits).is_ok());
        // Empty fields beyond the limit are dropped.
        let file = read_csv("x.csv", b"a,b,c,,,\n", &limits).unwrap();
        assert_eq!(file.sheets[0].rows[0].len(), 3);
        let error = read_csv("x.csv", b"a,b,c,d\n", &limits).unwrap_err();
        assert!(matches!(&error, ReadError::TooLarge(message) if message.contains("max_columns")));
    }
}
