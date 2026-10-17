//! Zone files (RFC 1035, section 5): the reader of the import and the writer of the export
//! (MIG-15).
//!
//! # Reading
//!
//! [`Reader`] scans a file with `domain`'s zone file scanner and yields one record at a
//! time with its line, or a [`Loss`] for a record the import cannot take. `$ORIGIN` and
//! `$TTL` are honoured (the zone apex is the first origin); `$INCLUDE` is refused, since
//! the import reads one uploaded file; `$GENERATE` (the BIND extension) is expanded before
//! scanning, at most [`ZoneConfig::max_generate`](super::ZoneConfig::max_generate) records
//! per line, with `$`, `${offset,width,base}` (bases `d`, `o`, `x`, `X`, `n`, `N`), `\$`
//! and `$$`. A syntax error stops the read with `dns.zonefile.invalid` and its line; the
//! scanner cannot continue after one.
//!
//! The losses: a record of a class other than IN, an owner outside the zone, a name or
//! data the model refuses (outside the name character set of the model, an invalid
//! length), and a record that breaks a rule of its type.
//!
//! # Writing
//!
//! [`header`] writes `$ORIGIN` and `$TTL`; [`write_rrset`] writes one RRset, one line per
//! record: the owner relative to the apex (`@` for the apex), the TTL, `IN`, the type and
//! the data in presentation format, its records in canonical order (by wire form). The
//! export writes the apex SOA first, then every RRset in key order, which is the canonical
//! name order of RFC 4034, types ascending, so the same data always gives the same bytes.

use std::fmt::Write as _;

use bytes::Bytes;
use domain::{base::name::ParsedName, dep::octseq::Parser};
use domain::{
    base::{
        iana::{Class, Rtype as WireRtype},
        name::{Name, ToName},
        rdata::{ComposeRecordData, ParseRecordData},
        zonefile_fmt::{DisplayKind, ZonefileFmt},
    },
    rdata::ZoneRecordData,
    zonefile::inplace::{Entry, Zonefile},
};
use tenko_core::dns::{DnsName, Rdata, RrSet, Rtype};

use super::{ZoneError, ZoneResult, relative_name};

/// The code of a loss: a record of another class than IN.
pub const LOSS_CLASS: &str = "dns.zonefile.class";
/// The code of a loss: a record whose owner is outside the zone.
pub const LOSS_OUTSIDE: &str = "dns.zonefile.outside_zone";
/// The code of a loss: a name or data the model refuses.
pub const LOSS_DATA: &str = "dns.zonefile.data";
/// The code of a loss: an RRset that breaks a rule of its type or conflicts with others.
pub const LOSS_RULE: &str = "dns.zonefile.rule";
/// The code of a loss: an RRset of another origin that the import does not replace.
pub const LOSS_ORIGIN: &str = "dns.zonefile.origin";
/// The code of a loss: a record the file repeats.
pub const LOSS_DUPLICATE: &str = "dns.zonefile.duplicate";
/// The code of a loss: an SOA record that is not the apex SOA, or a second one.
pub const LOSS_SOA: &str = "dns.zonefile.soa";

/// One record of a zone file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// The line it starts on, from 1.
    pub line: usize,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The data, canonical.
    pub rdata: Rdata,
}

/// A record the import does not take, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    /// The line, from 1.
    pub line: usize,
    /// The stable code.
    pub code: &'static str,
    /// What was lost, in English.
    pub detail: String,
}

/// What the reader yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A record.
    Record(FileRecord),
    /// A record the import does not take.
    Loss(Loss),
}

/// Where the lines of the scanned text come from.
#[derive(Debug, Default)]
struct LineMap {
    /// Byte offset of the start of each scanned line.
    starts: Vec<usize>,
    /// The original line of each scanned line (a `$GENERATE` line gives many).
    origin: Vec<u32>,
    /// Whether a scanned line is blank or a comment.
    blank: Vec<bool>,
}

impl LineMap {
    fn push(&mut self, start: usize, origin: usize, text: &str) {
        self.starts.push(start);
        self.origin.push(u32::try_from(origin).unwrap_or(u32::MAX));
        let content = text.trim_start();
        self.blank
            .push(content.is_empty() || content.starts_with(';'));
    }

    /// The original line of the first non-blank scanned line at or after `offset`.
    fn line_at(&self, offset: usize) -> usize {
        let mut index = self
            .starts
            .partition_point(|start| *start <= offset)
            .saturating_sub(1);
        while index + 1 < self.blank.len() && self.blank[index] {
            index += 1;
        }
        self.original(index + 1)
    }

    /// The original line of a scanned line number (from 1).
    fn original(&self, scanned: usize) -> usize {
        self.origin
            .get(scanned.saturating_sub(1))
            .map_or(scanned, |line| *line as usize)
    }
}

/// Reads the records of a zone file one by one.
pub struct Reader {
    zonefile: Zonefile,
    lines: LineMap,
    apex: DnsName,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("apex", &self.apex)
            .finish_non_exhaustive()
    }
}

impl Reader {
    /// A reader over `text` for the zone `apex`.
    ///
    /// # Errors
    ///
    /// `dns.zonefile.invalid` for `$INCLUDE`, a malformed `$GENERATE` or one that makes too
    /// many records.
    pub fn new(text: &str, apex: &DnsName, max_generate: u32) -> ZoneResult<Self> {
        let (scanned, lines) = preprocess(text, max_generate)?;
        // Records of another class are read and reported as losses, not refused.
        let mut zonefile = Zonefile::with_capacity(scanned.len()).allow_invalid();
        zonefile.extend_from_slice(scanned.as_bytes());
        drop(scanned);
        let origin = Name::<Bytes>::from_octets(Bytes::from(apex.to_wire()))
            .map_err(|_| ZoneError::zone_file(1, "the zone apex is not a valid name"))?;
        zonefile.set_origin(origin);
        zonefile.set_default_class(Class::IN);
        Ok(Self {
            zonefile,
            lines,
            apex: apex.clone(),
        })
    }

    /// The next record or loss; `None` at the end.
    ///
    /// # Errors
    ///
    /// `dns.zonefile.invalid` with the line of a syntax error or of `$INCLUDE`.
    pub fn next_item(&mut self) -> ZoneResult<Option<Item>> {
        let offset = self.zonefile.current_offset();
        let entry = match self.zonefile.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => return Ok(None),
            Err(error) => {
                // The scanner's own line can be the next one when the error shows at the
                // end of a line; the entry started where the previous one ended.
                let text = error.to_string();
                let reason = text
                    .splitn(3, ':')
                    .nth(2)
                    .unwrap_or(&text)
                    .trim()
                    .to_owned();
                return Err(ZoneError::zone_file(self.lines.line_at(offset), reason));
            }
        };
        let line = self.lines.line_at(offset);
        let record = match entry {
            Entry::Record(record) => record,
            Entry::Include { .. } => {
                return Err(ZoneError::zone_file(
                    line,
                    "$INCLUDE is refused: the import reads one file",
                ));
            }
        };
        let loss =
            |code: &'static str, detail: String| Ok(Some(Item::Loss(Loss { line, code, detail })));
        let rtype = Rtype(record.rtype().to_int());
        if record.class() != Class::IN {
            return loss(
                LOSS_CLASS,
                format!("a record of class {} is not served", record.class()),
            );
        }
        let mut owner_wire = Vec::new();
        if record.owner().compose(&mut owner_wire).is_err() {
            return loss(LOSS_DATA, "the owner name does not encode".to_owned());
        }
        let name = match DnsName::from_wire(&owner_wire) {
            Ok((name, _)) => name,
            Err(error) => {
                return loss(LOSS_DATA, format!("owner name refused: {}", error.reason));
            }
        };
        if !name.is_subdomain_of(&self.apex) {
            return loss(
                LOSS_OUTSIDE,
                format!("{name} is outside the zone {}", self.apex),
            );
        }
        let mut data = Vec::new();
        if record.data().compose_rdata(&mut data).is_err() {
            return loss(
                LOSS_DATA,
                format!("{name} {rtype}: the data does not encode"),
            );
        }
        let rdata = match Rdata::from_wire(rtype, &data) {
            Ok(rdata) => rdata,
            Err(error) => {
                return loss(LOSS_DATA, format!("{name} {rtype}: {}", error.reason));
            }
        };
        Ok(Some(Item::Record(FileRecord {
            line,
            name,
            rtype,
            ttl: record.ttl().as_secs(),
            rdata,
        })))
    }
}

// ----- preprocessing --------------------------------------------------------------------

/// Expands `$GENERATE`, refuses `$INCLUDE`, and maps the scanned lines to the original
/// ones. A directive counts only at the start of a line outside parentheses and quotes.
fn preprocess(text: &str, max_generate: u32) -> ZoneResult<(String, LineMap)> {
    let mut out = String::with_capacity(text.len() + 1);
    let mut lines = LineMap::default();
    let mut depth = 0usize;
    let mut quoted = false;
    for (index, raw) in text.split('\n').enumerate() {
        let number = index + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if depth == 0 && !quoted && line.starts_with('$') {
            let directive: String = line
                .split(|c: char| c.is_ascii_whitespace())
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            match directive.as_str() {
                "$INCLUDE" => {
                    return Err(ZoneError::zone_file(
                        number,
                        "$INCLUDE is refused: the import reads one file",
                    ));
                }
                "$GENERATE" => {
                    for generated in generate(line, number, max_generate)? {
                        lines.push(out.len(), number, &generated);
                        out.push_str(&generated);
                        out.push('\n');
                    }
                    continue;
                }
                _ => {}
            }
        }
        scan_state(line, &mut depth, &mut quoted);
        lines.push(out.len(), number, line);
        out.push_str(line);
        out.push('\n');
    }
    Ok((out, lines))
}

/// Follows parentheses and quotes over one line.
fn scan_state(line: &str, depth: &mut usize, quoted: &mut bool) {
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => *quoted = !*quoted,
            ';' if !*quoted => break,
            '(' if !*quoted => *depth += 1,
            ')' if !*quoted => *depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

/// The lines of one `$GENERATE range lhs [ttl] [class] type rhs`.
fn generate(line: &str, number: usize, max: u32) -> ZoneResult<Vec<String>> {
    let content = line.split(';').next().unwrap_or_default();
    let mut fields = content.split_ascii_whitespace();
    let _ = fields.next();
    let bad = |reason: &str| ZoneError::zone_file(number, format!("$GENERATE: {reason}"));
    let range = fields.next().ok_or_else(|| bad("the range is missing"))?;
    let lhs = fields.next().ok_or_else(|| bad("the owner is missing"))?;
    let rest: Vec<&str> = fields.collect();
    if rest.len() < 2 {
        return Err(bad("the type and the data are missing"));
    }
    let (bounds, step) = match range.split_once('/') {
        Some((bounds, step)) => (
            bounds,
            step.parse::<u64>()
                .map_err(|_| bad("the step is not a number"))?,
        ),
        None => (range, 1),
    };
    let (low, high) = bounds
        .split_once('-')
        .ok_or_else(|| bad("the range is start-stop"))?;
    let first: u64 = low
        .parse()
        .map_err(|_| bad("the range start is not a number"))?;
    let last: u64 = high
        .parse()
        .map_err(|_| bad("the range stop is not a number"))?;
    if step == 0 || last < first {
        return Err(bad(
            "the range runs from start up to stop by a step above zero",
        ));
    }
    let count = (last - first) / step + 1;
    if count > u64::from(max) {
        return Err(bad(&format!(
            "the range makes {count} records, more than {max}"
        )));
    }
    let rest = rest.join(" ");
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
    let mut value = first;
    while value <= last {
        let owner = substitute(lhs, value).map_err(|reason| bad(&reason))?;
        let data = substitute(&rest, value).map_err(|reason| bad(&reason))?;
        out.push(format!("{owner} {data}"));
        value += step;
    }
    Ok(out)
}

/// Replaces `$` and `${offset,width,base}` with the iterator; `\$` and `$$` are a `$`.
fn substitute(template: &str, value: u64) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + 8);
    let bytes: Vec<char> = template.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        let c = bytes[index];
        match c {
            '\\' | '$' if bytes.get(index + 1) == Some(&'$') => {
                out.push('$');
                index += 2;
            }
            '$' if bytes.get(index + 1) == Some(&'{') => {
                let close = bytes[index..]
                    .iter()
                    .position(|c| *c == '}')
                    .ok_or("an unclosed ${")?;
                let spec: String = bytes[index + 2..index + close].iter().collect();
                out.push_str(&modifier(&spec, value)?);
                index += close + 1;
            }
            '$' => {
                out.push_str(&value.to_string());
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    Ok(out)
}

/// One `${offset,width,base}`.
fn modifier(spec: &str, value: u64) -> Result<String, String> {
    let mut parts = spec.split(',');
    let offset: i64 = parts
        .next()
        .filter(|part| !part.is_empty())
        .map_or(Ok(0), str::parse)
        .map_err(|_| "the offset is not a number".to_owned())?;
    let width: usize = parts
        .next()
        .filter(|part| !part.is_empty())
        .map_or(Ok(0), str::parse)
        .map_err(|_| "the width is not a number".to_owned())?;
    let base = parts.next().unwrap_or("d");
    let shifted = i64::try_from(value)
        .ok()
        .and_then(|value| value.checked_add(offset))
        .filter(|value| *value >= 0)
        .ok_or("the offset moves the value below zero")?;
    let shifted = u64::try_from(shifted).unwrap_or_default();
    Ok(match base {
        "d" => format!("{shifted:0width$}"),
        "o" => format!("{shifted:0width$o}"),
        "x" => format!("{shifted:0width$x}"),
        "X" => format!("{shifted:0width$X}"),
        "n" | "N" => {
            let hex = if base == "n" {
                format!("{shifted:0width$x}")
            } else {
                format!("{shifted:0width$X}")
            };
            let mut nibbles: Vec<String> = hex.chars().rev().map(String::from).collect();
            if width > 0 {
                nibbles.truncate(width);
            }
            nibbles.join(".")
        }
        _ => return Err(format!("the base {base} is not d, o, x, X, n or N")),
    })
}

// ----- writing --------------------------------------------------------------------------

/// The `$ORIGIN` and `$TTL` lines.
pub fn header(apex: &DnsName, ttl: u32) -> String {
    format!("$ORIGIN {}\n$TTL {ttl}\n", absolute(apex))
}

/// A name with its trailing dot.
pub fn absolute(name: &DnsName) -> String {
    if name.is_root() {
        ".".to_owned()
    } else {
        format!("{name}.")
    }
}

/// The record data in presentation format.
///
/// # Errors
///
/// `dns.record.invalid` when stored data does not parse.
pub fn presentation(rtype: Rtype, rdata: &Rdata) -> ZoneResult<String> {
    let mut parser = Parser::from_ref(rdata.as_bytes());
    let parsed = ZoneRecordData::<&[u8], ParsedName<&[u8]>>::parse_rdata(
        WireRtype::from_int(rtype.0),
        &mut parser,
    )
    .ok()
    .flatten()
    .ok_or_else(|| {
        ZoneError::new(
            tenko_core::dns::codes::RECORD_INVALID,
            400,
            format!("stored {rtype} data does not parse"),
        )
    })?;
    Ok(parsed.display_zonefile(DisplayKind::Simple).to_string())
}

/// The type as the zone file names it.
pub fn type_name(rtype: Rtype) -> String {
    WireRtype::from_int(rtype.0).to_string()
}

/// Writes the lines of one RRset.
///
/// # Errors
///
/// `dns.record.invalid` when stored data does not parse.
pub fn write_rrset(out: &mut String, apex: &DnsName, rrset: &RrSet) -> ZoneResult<()> {
    let owner = relative_name(&rrset.name, apex);
    let type_name = type_name(rrset.rtype);
    let mut records: Vec<&Rdata> = rrset.rdata.iter().collect();
    records.sort();
    for rdata in records {
        let data = presentation(rrset.rtype, rdata)?;
        let _ = writeln!(out, "{owner} {} IN {type_name} {data}", rrset.ttl);
    }
    Ok(())
}
