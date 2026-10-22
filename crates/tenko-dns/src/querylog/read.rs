//! The reader of the query log: pages newest first, with a cursor and filters.
//!
//! A cursor is `<segment>:<offset>`: the page holds the entries of that segment that start
//! before the offset, then those of the older segments. A read looks at no more than
//! [`MAX_SCAN_BYTES`] of segments; a filter that matches little may therefore answer a
//! short page with a cursor, and the next read goes on from there.

use std::{fs, io, net::IpAddr, path::Path};

use tenko_core::Timestamp;

use super::{
    LogFormat, LogLine, day_of, dnstap,
    keys::{self, Keys},
    segment_micros, segments,
};

/// The segment octets one read looks at, at most.
pub const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

/// How long before its segment's name an entry may have arrived.
const LATE_MICROS: u64 = 60_000_000;

/// What a page keeps; every field that is set must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFilter {
    /// The query name is this name or under it (labels compared without case): `example.test`
    /// matches `example.test` and `www.example.test`, not `badexample.test`.
    pub qname: Option<String>,
    /// A pseudonym (`p:` and hexadecimal digits) or an address. An address also finds the
    /// entries where it was written as a pseudonym, through the key of each entry's day.
    pub client: Option<String>,
    /// The RCODE answered.
    pub rcode: Option<u16>,
    /// The query arrived at or after this time.
    pub from: Option<Timestamp>,
    /// The query arrived at or before this time.
    pub until: Option<Timestamp>,
}

enum Client {
    Pseudonym(String),
    Address(IpAddr),
}

impl LogFilter {
    /// Whether the filter can be applied.
    ///
    /// # Errors
    ///
    /// [`ReadError::Filter`] for a client that is neither an address nor a pseudonym, or a
    /// time window that ends before it starts.
    pub fn validate(&self) -> Result<(), ReadError> {
        self.client()?;
        if let (Some(from), Some(until)) = (self.from, self.until)
            && until < from
        {
            return Err(ReadError::Filter("until is before from".to_owned()));
        }
        Ok(())
    }

    fn client(&self) -> Result<Option<Client>, ReadError> {
        let Some(text) = self.client.as_deref().map(str::trim) else {
            return Ok(None);
        };
        if keys::is_pseudonym(&text.to_ascii_lowercase()) {
            return Ok(Some(Client::Pseudonym(text.to_ascii_lowercase())));
        }
        text.parse::<IpAddr>()
            .map(|address| Some(Client::Address(address.to_canonical())))
            .map_err(|_| {
                ReadError::Filter(format!(
                    "client `{text}` is neither an address nor a pseudonym (p: and hexadecimal digits)"
                ))
            })
    }

    /// Whether the filter asks for a client by its address.
    pub fn names_an_address(&self) -> bool {
        matches!(self.client(), Ok(Some(Client::Address(_))))
    }
}

/// One page of the log, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogPage {
    /// The lines.
    pub lines: Vec<LogLine>,
    /// The cursor of the next (older) page, if there may be one.
    pub next: Option<String>,
}

/// Why the log could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The cursor is not one this log handed out.
    #[error("the cursor is not valid")]
    Cursor,
    /// A filter cannot be applied.
    #[error("the filter is not valid: {0}")]
    Filter(String),
    /// The directory or a segment could not be read.
    #[error("the query log could not be read: {0}")]
    Io(String),
}

fn parse_cursor(cursor: &str) -> Option<(String, u64)> {
    let (name, offset) = cursor.rsplit_once(':')?;
    LogFormat::of_segment(name)?;
    Some((name.to_owned(), offset.parse().ok()?))
}

pub(super) fn micros_of(time: Timestamp) -> u64 {
    u64::try_from(time.unix_nanos() / 1_000).unwrap_or(0)
}

/// Matches lines against a filter, with the key of the last day it needed.
struct Matcher<'a> {
    filter: &'a LogFilter,
    client: Option<Client>,
    qname: Option<String>,
    keys: Option<Keys>,
    dir: &'a Path,
    tag: Option<(u64, [u8; 32])>,
}

impl<'a> Matcher<'a> {
    fn new(dir: &'a Path, filter: &'a LogFilter) -> Result<Self, ReadError> {
        let qname = filter
            .qname
            .as_deref()
            .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase());
        Ok(Self {
            client: filter.client()?,
            qname,
            filter,
            keys: None,
            dir,
            tag: None,
        })
    }

    fn matches(&mut self, line: &LogLine) -> bool {
        if self.filter.rcode.is_some_and(|rcode| rcode != line.rcode)
            || self.filter.from.is_some_and(|from| line.at < from)
            || self.filter.until.is_some_and(|until| line.at > until)
        {
            return false;
        }
        if let Some(suffix) = &self.qname
            && !suffix.is_empty()
        {
            let name = line.qname.trim_end_matches('.').to_ascii_lowercase();
            let under = name.len() > suffix.len()
                && name.ends_with(suffix.as_str())
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
            if name != *suffix && !under {
                return false;
            }
        }
        match &self.client {
            None => true,
            Some(Client::Pseudonym(pseudonym)) => line
                .client
                .as_deref()
                .is_some_and(|client| client.eq_ignore_ascii_case(pseudonym)),
            Some(Client::Address(address)) => {
                let address = *address;
                let Some(client) = line.client.as_deref() else {
                    return false;
                };
                if let Ok(written) = client.parse::<IpAddr>() {
                    return written.to_canonical() == address;
                }
                let Some(hex) = client.strip_prefix("p:") else {
                    return false;
                };
                let day = day_of(micros_of(line.at));
                let Some(tag) = self.tag_of(day, address) else {
                    return false;
                };
                let octets = (hex.len() / 2).min(tag.len());
                keys::pseudonym_text(&tag[..octets]).eq_ignore_ascii_case(client)
            }
        }
    }

    fn tag_of(&mut self, day: u64, address: IpAddr) -> Option<[u8; 32]> {
        if let Some((known, tag)) = self.tag
            && known == day
        {
            return Some(tag);
        }
        let keys = self.keys.get_or_insert_with(|| Keys::load(self.dir));
        let tag = keys::tag(keys.get(day)?, address);
        self.tag = Some((day, tag));
        Some(tag)
    }
}

/// The records of a segment with their offsets, oldest first: whole JSON lines, or the
/// data frames of a dnstap segment that starts with the dnstap content type.
pub(super) fn records(format: LogFormat, bytes: &[u8]) -> Vec<(usize, &[u8])> {
    match format {
        LogFormat::Jsonl => {
            let mut out = Vec::new();
            let mut start = 0;
            for (at, byte) in bytes.iter().enumerate() {
                if *byte == b'\n' {
                    out.push((start, &bytes[start..at]));
                    start = at + 1;
                }
            }
            out
        }
        LogFormat::Dnstap => {
            let (frames, _) = dnstap::frames(bytes);
            let dnstap = matches!(
                frames.first(),
                Some((_, dnstap::Frame::Control { kind, content_types }))
                    if *kind == dnstap::control::START
                        && (content_types.is_empty() || content_types.contains(&dnstap::CONTENT_TYPE))
            );
            if !dnstap {
                return Vec::new();
            }
            frames
                .into_iter()
                .filter_map(|(at, frame)| match frame {
                    dnstap::Frame::Data(payload) => Some((at, payload)),
                    dnstap::Frame::Control { .. } => None,
                })
                .collect()
        }
    }
}

pub(super) fn decode(format: LogFormat, record: &[u8]) -> Option<LogLine> {
    match format {
        LogFormat::Jsonl => serde_json::from_slice(record).ok(),
        LogFormat::Dnstap => dnstap::line_of(&dnstap::Dnstap::decode(record).ok()?),
    }
}

/// Reads up to `limit` lines that match `filter`, newest first, from `cursor` (or the
/// newest line).
///
/// # Errors
///
/// [`ReadError::Cursor`] for a malformed cursor, [`ReadError::Filter`] for a filter that
/// cannot be applied, [`ReadError::Io`] when the directory cannot be read.
pub fn read(
    dir: &Path,
    cursor: Option<&str>,
    limit: usize,
    filter: &LogFilter,
) -> Result<LogPage, ReadError> {
    let start = match cursor {
        Some(cursor) => Some(parse_cursor(cursor).ok_or(ReadError::Cursor)?),
        None => None,
    };
    let mut matcher = Matcher::new(dir, filter)?;
    let mut names = match segments(dir) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(ReadError::Io(error.to_string())),
    };
    names.sort();
    names.reverse();
    // The start of the next newer segment bounds the entries of a segment from above.
    let mut newer_start: Option<u64> = None;
    if let Some((cursor_name, _)) = &start {
        newer_start = names
            .iter()
            .filter(|name| *name > cursor_name)
            .filter_map(|name| segment_micros(name))
            .min();
        names.retain(|name| name <= cursor_name);
    }
    let from = filter.from.map(micros_of);
    let until = filter.until.map(micros_of);
    let limit = limit.max(1);
    let mut page = LogPage::default();
    let mut scanned = 0u64;
    for (position, name) in names.iter().enumerate() {
        let opened = segment_micros(name).unwrap_or(0);
        let bound = newer_start.replace(opened);
        if let (Some(from), Some(bound)) = (from, bound)
            && bound.saturating_add(LATE_MICROS) < from
        {
            // This segment and every older one end before the window.
            return Ok(page);
        }
        if until.is_some_and(|until| opened > until.saturating_add(LATE_MICROS)) {
            continue;
        }
        if scanned >= MAX_SCAN_BYTES {
            page.next = Some(format!("{name}:{}", u64::MAX));
            return Ok(page);
        }
        let Some(format) = LogFormat::of_segment(name) else {
            continue;
        };
        let bytes = match fs::read(dir.join(name)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ReadError::Io(error.to_string())),
        };
        scanned += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let end = match &start {
            Some((cursor_name, offset)) if cursor_name == name => *offset,
            _ => u64::MAX,
        };
        let records = records(format, &bytes);
        let mut older = records
            .iter()
            .rev()
            .filter(|(at, _)| u64::try_from(*at).unwrap_or(u64::MAX) < end)
            .peekable();
        while let Some((at, record)) = older.next() {
            let Some(line) = decode(format, record) else {
                continue;
            };
            if !matcher.matches(&line) {
                continue;
            }
            page.lines.push(line);
            if page.lines.len() >= limit {
                let more = older.peek().is_some() || position + 1 < names.len();
                page.next = more.then(|| format!("{name}:{at}"));
                return Ok(page);
            }
        }
    }
    Ok(page)
}
