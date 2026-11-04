//! The zone file reader and writer of Tenko 0.0.10, on `domain`'s zone file scanner (the
//! dev-dependency feature `zonefile`): the reference of the differential test and of the
//! timing comparison. It is the code the import used until Tenko read zone files with its
//! own code, kept here unchanged in behavior: `$GENERATE` expanded and `$INCLUDE` refused
//! before the scan, the lines mapped back to the file's lines, the records checked by the
//! model.

#![allow(dead_code, reason = "each test binary uses a part")]

use bytes::Bytes;
use domain::{
    base::{
        iana::{Class, Rtype as WireRtype},
        name::{Name, ParsedName, ToName},
        rdata::{ComposeRecordData, ParseRecordData},
        zonefile_fmt::{DisplayKind, ZonefileFmt},
    },
    dep::octseq::Parser,
    rdata::ZoneRecordData,
    zonefile::inplace::{Entry, Zonefile},
};
use tenko_core::dns::{DnsName, Rdata, Rtype};
use tenko_dns::zone::{
    ZoneError, ZoneResult,
    zonefile::{FileRecord, Item, LOSS_CLASS, LOSS_DATA, LOSS_OUTSIDE, Loss},
};

/// Where the lines of the scanned text come from.
#[derive(Debug, Default)]
struct LineMap {
    starts: Vec<usize>,
    origin: Vec<u32>,
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

    fn original(&self, scanned: usize) -> usize {
        self.origin
            .get(scanned.saturating_sub(1))
            .map_or(scanned, |line| *line as usize)
    }
}

/// The reader of 0.0.10.
pub struct OldReader {
    zonefile: Zonefile,
    lines: LineMap,
    apex: DnsName,
}

impl OldReader {
    /// A reader over `text` for the zone `apex`.
    ///
    /// # Errors
    ///
    /// `dns.zonefile.invalid` for `$INCLUDE`, a malformed `$GENERATE` or an unclosed
    /// parenthesis.
    pub fn new(text: &str, apex: &DnsName, max_generate: u32) -> ZoneResult<Self> {
        let (scanned, lines) = preprocess(text, max_generate)?;
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

    /// The next record or loss.
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

fn preprocess(text: &str, max_generate: u32) -> ZoneResult<(String, LineMap)> {
    let mut out = String::with_capacity(text.len() + 1);
    let mut lines = LineMap::default();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut opened = 0usize;
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
                        follow(&generated, number, &mut depth, &mut quoted, &mut opened);
                        lines.push(out.len(), number, &generated);
                        out.push_str(&generated);
                        out.push('\n');
                    }
                    continue;
                }
                _ => {}
            }
        }
        follow(line, number, &mut depth, &mut quoted, &mut opened);
        lines.push(out.len(), number, line);
        out.push_str(line);
        out.push('\n');
    }
    if depth > 0 {
        return Err(ZoneError::zone_file(
            opened,
            "the parenthesis opened on this line is not closed by the end of the file",
        ));
    }
    Ok((out, lines))
}

fn follow(line: &str, number: usize, depth: &mut usize, quoted: &mut bool, opened: &mut usize) {
    let closed = *depth == 0;
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
    if closed && *depth > 0 {
        *opened = number;
    }
}

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
    let mut out = Vec::new();
    let mut value = first;
    while value <= last {
        let owner = substitute(lhs, value).map_err(|reason| bad(&reason))?;
        let data = substitute(&rest, value).map_err(|reason| bad(&reason))?;
        out.push(format!("{owner} {data}"));
        value += step;
    }
    Ok(out)
}

fn substitute(template: &str, value: u64) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + 8);
    let chars: Vec<char> = template.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        match c {
            '\\' | '$' if chars.get(index + 1) == Some(&'$') => {
                out.push('$');
                index += 2;
            }
            '$' if chars.get(index + 1) == Some(&'{') => {
                let close = chars[index..]
                    .iter()
                    .position(|c| *c == '}')
                    .ok_or("an unclosed ${")?;
                let spec: String = chars[index + 2..index + close].iter().collect();
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

/// The record data in presentation format as 0.0.10 wrote it (`domain`'s `ZonefileFmt`);
/// `None` when `domain` cannot parse the data.
pub fn old_presentation(rtype: Rtype, rdata: &Rdata) -> Option<String> {
    let mut parser = Parser::from_ref(rdata.as_bytes());
    let parsed = ZoneRecordData::<&[u8], ParsedName<&[u8]>>::parse_rdata(
        WireRtype::from_int(rtype.0),
        &mut parser,
    )
    .ok()
    .flatten()?;
    Some(parsed.display_zonefile(DisplayKind::Simple).to_string())
}

/// The type as 0.0.10 named it.
pub fn old_type_name(rtype: Rtype) -> String {
    WireRtype::from_int(rtype.0).to_string()
}

/// What a reader made of a text: the items before the first error, and the error's line
/// and reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The records and losses, in order.
    pub items: Vec<Item>,
    /// The first error: its line and reason.
    pub error: Option<(usize, String)>,
}

fn error_of(error: &ZoneError) -> (usize, String) {
    let coded = error.coded();
    (
        coded
            .params
            .get("line")
            .and_then(|line| line.parse().ok())
            .unwrap_or_default(),
        coded.params.get("reason").cloned().unwrap_or_default(),
    )
}

/// Reads `text` with the reader of 0.0.10; `None` when `domain`'s scanner panics.
pub fn read_old(text: &str, apex: &DnsName, max_generate: u32) -> Option<Outcome> {
    let text = text.to_owned();
    let apex = apex.clone();
    std::panic::catch_unwind(move || {
        let mut items = Vec::new();
        let mut reader = match OldReader::new(&text, &apex, max_generate) {
            Ok(reader) => reader,
            Err(error) => {
                return Outcome {
                    items,
                    error: Some(error_of(&error)),
                };
            }
        };
        loop {
            match reader.next_item() {
                Ok(Some(item)) => items.push(item),
                Ok(None) => return Outcome { items, error: None },
                Err(error) => {
                    return Outcome {
                        items,
                        error: Some(error_of(&error)),
                    };
                }
            }
        }
    })
    .ok()
}

/// Reads `text` with Tenko's reader.
pub fn read_new(text: &str, apex: &DnsName, max_generate: u32) -> Outcome {
    let mut items = Vec::new();
    let mut reader = match tenko_dns::zone::zonefile::Reader::new(text, apex, max_generate) {
        Ok(reader) => reader,
        Err(error) => {
            return Outcome {
                items,
                error: Some(error_of(&error)),
            };
        }
    };
    loop {
        match reader.next_item() {
            Ok(Some(item)) => items.push(item),
            Ok(None) => return Outcome { items, error: None },
            Err(error) => {
                return Outcome {
                    items,
                    error: Some(error_of(&error)),
                };
            }
        }
    }
}
