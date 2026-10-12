//! RFC 5424 messages, a strict RFC 5424 parser and RFC 6587 octet counting.
//!
//! [`message`] renders the header, the structured data and the body of one message;
//! [`frame`] and [`FrameDecoder`] add and remove the octet-counting frame of TCP and TLS;
//! [`parse`] reads a message back (a test receiver, `tenko audit verify` and the fuzz
//! target `audit_export_syslog` use it).

use tenko_core::Timestamp;
use thiserror::Error;

use crate::audit_export::model::Facility;

/// The byte order mark that starts a UTF-8 MSG (RFC 5424 section 6.4).
const BOM: &str = "\u{feff}";
const BOM_BYTES: [u8; 3] = [0xEF, 0xBB, 0xBF];

const MAX_HOSTNAME: usize = 255;
const MAX_APP_NAME: usize = 48;
const MAX_PROCID: usize = 128;
const MAX_MSGID: usize = 32;
const MAX_SD_NAME: usize = 32;
/// The longest MSG-LEN: nine digits.
const MAX_LEN_DIGITS: usize = 9;
/// The longest frame prefix: nine digits and the space.
const MAX_PREFIX: usize = MAX_LEN_DIGITS + 1;

/// The header fields of a message.
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    /// The facility.
    pub facility: Facility,
    /// The severity, 0 to 7.
    pub severity: u8,
    /// The TIMESTAMP.
    pub at: Timestamp,
    /// The HOSTNAME; `-` when empty.
    pub hostname: &'a str,
    /// The MSGID.
    pub msgid: &'a str,
}

/// One structured data element.
#[derive(Debug, Clone)]
pub struct SdElement<'a> {
    /// The SD-ID.
    pub id: &'a str,
    /// The parameters, unescaped.
    pub params: Vec<(&'a str, &'a str)>,
}

/// A header field of 1 to `max` printable US-ASCII characters, else the NILVALUE.
fn header_field(value: &str, max: usize) -> &str {
    if (1..=max).contains(&value.len()) && value.bytes().all(|b| (33..=126).contains(&b)) {
        value
    } else {
        "-"
    }
}

/// RFC 3339 in UTC with `Z`, the fraction truncated to microseconds.
fn timestamp(at: Timestamp) -> String {
    let utc = at.0.to_offset(time::UtcOffset::UTC);
    if !(0..=9999).contains(&utc.year()) {
        return "-".to_owned();
    }
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    );
    let micros = utc.nanosecond() / 1000;
    if micros != 0 {
        let fraction = format!("{micros:06}");
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

/// An SD-ID or PARAM-NAME: printable ASCII without `=`, SP, `]` and `"`, at most 32.
fn sd_name(name: &str) -> String {
    let mut out: String = name
        .bytes()
        .take(MAX_SD_NAME)
        .map(|b| {
            if (33..=126).contains(&b) && !matches!(b, b'=' | b']' | b'"') {
                char::from(b)
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Renders a message: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA
/// [MSG]`. The body is appended as is (preceded by a byte order mark when `bom` is set);
/// callers pass a single line.
pub fn message(header: &Header<'_>, sd: &[SdElement<'_>], body: &str, bom: bool) -> String {
    let severity = header.severity.min(7);
    let pri = u16::from(header.facility.code()) * 8 + u16::from(severity);
    let mut out = format!(
        "<{pri}>1 {} {} {} - {} ",
        timestamp(header.at),
        header_field(header.hostname, MAX_HOSTNAME),
        super::APP_NAME,
        header_field(header.msgid, MAX_MSGID),
    );
    if sd.is_empty() {
        out.push('-');
    }
    for element in sd {
        out.push('[');
        out.push_str(&sd_name(element.id));
        for (name, value) in &element.params {
            out.push(' ');
            out.push_str(&sd_name(name));
            out.push_str("=\"");
            for c in value.chars() {
                match c {
                    '"' | '\\' | ']' => {
                        out.push('\\');
                        out.push(c);
                    }
                    '\r' | '\n' => out.push(' '),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        out.push(']');
    }
    if !body.is_empty() {
        out.push(' ');
        if bom {
            out.push_str(BOM);
        }
        out.push_str(body);
    }
    out
}

/// Frames a message with octet counting: `<length> <message>` (RFC 6587 section 3.4.1,
/// RFC 5425 section 4.3).
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message);
    out
}

/// Why [`FrameDecoder`] refused its input. The decoder stays failed afterwards: the
/// stream has lost its framing and the connection must be dropped.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The length is not `NONZERO-DIGIT *DIGIT SP` of at most nine digits.
    #[error("malformed octet-counting length")]
    BadLength,
    /// The frame is longer than the decoder accepts.
    #[error("frame of {len} octets exceeds the limit of {max}")]
    TooLong {
        /// The announced length.
        len: usize,
        /// The limit.
        max: usize,
    },
}

/// A decoder of octet-counted frames (RFC 6587 section 3.4.1).
///
/// Feed it what the transport read with [`push`](Self::push) and drain
/// [`next_frame`](Self::next_frame) until it returns `Ok(None)` before the next push: the
/// buffer then holds at most one incomplete frame, which is at most `max_frame + 10`
/// octets (the length prefix is checked as soon as it is complete, so a frame that is too
/// long is refused before its body is buffered further).
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    max_frame: usize,
    buf: Vec<u8>,
    pos: usize,
    failed: Option<FrameError>,
}

impl FrameDecoder {
    /// A decoder that accepts frames of up to `max_frame` octets.
    pub fn new(max_frame: usize) -> Self {
        Self {
            max_frame,
            buf: Vec::new(),
            pos: 0,
            failed: None,
        }
    }

    /// Appends what the transport read. Once the decoder has failed, input is dropped.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The octets buffered and not yet returned.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The next complete frame, `Ok(None)` when more input is needed.
    ///
    /// # Errors
    ///
    /// [`FrameError`] for a malformed or too long length; the same error again afterwards.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        match self.try_next() {
            Err(error) => {
                self.failed = Some(error.clone());
                self.buf = Vec::new();
                self.pos = 0;
                Err(error)
            }
            ok => ok,
        }
    }

    fn try_next(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let pending = &self.buf[self.pos..];
        let Some(&first) = pending.first() else {
            return Ok(None);
        };
        if !(b'1'..=b'9').contains(&first) {
            return Err(FrameError::BadLength);
        }
        let mut len: usize = 0;
        let mut digits = 0;
        let mut prefix = None;
        for (index, &byte) in pending.iter().take(MAX_PREFIX).enumerate() {
            if byte.is_ascii_digit() {
                digits += 1;
                if digits > MAX_LEN_DIGITS {
                    return Err(FrameError::BadLength);
                }
                len = len * 10 + usize::from(byte - b'0');
            } else if byte == b' ' {
                prefix = Some(index + 1);
                break;
            } else {
                return Err(FrameError::BadLength);
            }
        }
        let Some(prefix) = prefix else {
            if pending.len() >= MAX_PREFIX {
                return Err(FrameError::BadLength);
            }
            return Ok(None);
        };
        if len > self.max_frame {
            return Err(FrameError::TooLong {
                len,
                max: self.max_frame,
            });
        }
        let end = prefix + len;
        if pending.len() < end {
            return Ok(None);
        }
        let frame = pending[prefix..end].to_vec();
        self.pos += end;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        Ok(Some(frame))
    }
}

/// One structured data element read by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdElementOwned {
    /// The SD-ID.
    pub id: String,
    /// The parameters in order, unescaped.
    pub params: Vec<(String, String)>,
}

/// A message read by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogMessage {
    /// PRI: facility times 8 plus severity.
    pub pri: u8,
    /// The facility, 0 to 23.
    pub facility: u8,
    /// The severity, 0 to 7.
    pub severity: u8,
    /// VERSION, always 1.
    pub version: u8,
    /// The TIMESTAMP; `None` for the NILVALUE.
    pub timestamp: Option<String>,
    /// The HOSTNAME.
    pub hostname: Option<String>,
    /// The APP-NAME.
    pub app_name: Option<String>,
    /// The PROCID.
    pub procid: Option<String>,
    /// The MSGID.
    pub msgid: Option<String>,
    /// The structured data elements; empty for the NILVALUE.
    pub structured_data: Vec<SdElementOwned>,
    /// Whether the MSG started with a UTF-8 byte order mark (stripped from `msg`).
    pub bom: bool,
    /// The MSG, without the leading space and the byte order mark.
    pub msg: Vec<u8>,
}

/// Why [`parse`] refused a message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// The PRI is missing, malformed or above 191.
    #[error("invalid PRI")]
    Pri,
    /// The VERSION is not 1.
    #[error("unsupported VERSION")]
    Version,
    /// A header field is missing, empty, too long or not printable US-ASCII.
    #[error("invalid {0}")]
    Field(&'static str),
    /// The structured data is malformed.
    #[error("invalid STRUCTURED-DATA")]
    StructuredData,
    /// Something other than a space follows the structured data.
    #[error("unexpected input after STRUCTURED-DATA")]
    Trailing,
}

/// A cursor over the input; every step checks the bounds.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// The bytes up to the next SP (or the end), consuming the SP when it follows.
    fn token(&mut self) -> &'a [u8] {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        self.pos += end;
        &rest[..end]
    }
}

fn nil_or(token: &[u8], max: usize, name: &'static str) -> Result<Option<String>, ParseError> {
    if token == b"-" {
        return Ok(None);
    }
    if token.is_empty() || token.len() > max || !token.iter().all(|b| (33..=126).contains(b)) {
        return Err(ParseError::Field(name));
    }
    String::from_utf8(token.to_vec())
        .map(Some)
        .map_err(|_| ParseError::Field(name))
}

/// A structural check of a date-time of RFC 3339 section 5.6.
fn valid_timestamp(token: &[u8]) -> bool {
    fn digits(token: &[u8], range: std::ops::Range<usize>) -> Option<u32> {
        let part = token.get(range)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(part.iter().fold(0, |n, b| n * 10 + u32::from(b - b'0')))
    }
    if token.len() > 32 || token.len() < 20 {
        return false;
    }
    let fixed = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if fixed.iter().any(|&(i, c)| token.get(i) != Some(&c)) {
        return false;
    }
    let (Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(token, 5..7),
        digits(token, 8..10),
        digits(token, 11..13),
        digits(token, 14..16),
        digits(token, 17..19),
    ) else {
        return false;
    };
    if digits(token, 0..4).is_none()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }
    let mut at = 19;
    if token.get(at) == Some(&b'.') {
        let start = at + 1;
        at = start;
        while token.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start || at - start > 6 {
            return false;
        }
    }
    match token.get(at..) {
        Some(b"Z") => true,
        Some([sign, rest @ ..]) if matches!(sign, b'+' | b'-') && rest.len() == 5 => {
            rest.get(2) == Some(&b':')
                && digits(rest, 0..2).is_some_and(|h| h <= 23)
                && digits(rest, 3..5).is_some_and(|m| m <= 59)
        }
        _ => false,
    }
}

fn sd_name_bytes(cursor: &mut Cursor<'_>) -> Result<String, ParseError> {
    let rest = cursor.bytes.get(cursor.pos..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|&b| !(33..=126).contains(&b) || matches!(b, b'=' | b']' | b'"'))
        .unwrap_or(rest.len());
    if end == 0 || end > MAX_SD_NAME {
        return Err(ParseError::StructuredData);
    }
    cursor.pos += end;
    String::from_utf8(rest[..end].to_vec()).map_err(|_| ParseError::StructuredData)
}

fn sd_value(cursor: &mut Cursor<'_>) -> Result<String, ParseError> {
    let mut raw = Vec::new();
    loop {
        let byte = cursor.peek().ok_or(ParseError::StructuredData)?;
        cursor.pos += 1;
        match byte {
            b'"' => break,
            b'\\' => match cursor.peek() {
                Some(escaped @ (b'"' | b'\\' | b']')) => {
                    cursor.pos += 1;
                    raw.push(escaped);
                }
                // A backslash before any other character stays (RFC 5424 section 6.3.3).
                _ => raw.push(b'\\'),
            },
            other => raw.push(other),
        }
    }
    String::from_utf8(raw).map_err(|_| ParseError::StructuredData)
}

fn sd_elements(cursor: &mut Cursor<'_>) -> Result<Vec<SdElementOwned>, ParseError> {
    if cursor.eat(b'-') {
        return Ok(Vec::new());
    }
    let mut elements = Vec::new();
    while cursor.eat(b'[') {
        let id = sd_name_bytes(cursor)?;
        let mut params = Vec::new();
        while cursor.eat(b' ') {
            let name = sd_name_bytes(cursor)?;
            if !cursor.eat(b'=') || !cursor.eat(b'"') {
                return Err(ParseError::StructuredData);
            }
            params.push((name, sd_value(cursor)?));
        }
        if !cursor.eat(b']') {
            return Err(ParseError::StructuredData);
        }
        elements.push(SdElementOwned { id, params });
    }
    if elements.is_empty() {
        return Err(ParseError::StructuredData);
    }
    Ok(elements)
}

/// Reads one RFC 5424 message (without transport framing).
///
/// # Errors
///
/// [`ParseError`] for the first violation of the grammar.
pub fn parse(bytes: &[u8]) -> Result<SyslogMessage, ParseError> {
    let mut cursor = Cursor { bytes, pos: 0 };
    if !cursor.eat(b'<') {
        return Err(ParseError::Pri);
    }
    let digits_start = cursor.pos;
    while cursor.peek().is_some_and(|b| b.is_ascii_digit()) {
        cursor.pos += 1;
    }
    let digits = &bytes[digits_start..cursor.pos];
    if digits.is_empty() || digits.len() > 3 || (digits.len() > 1 && digits[0] == b'0') {
        return Err(ParseError::Pri);
    }
    let pri = digits
        .iter()
        .fold(0u16, |n, b| n * 10 + u16::from(b - b'0'));
    if pri > 191 || !cursor.eat(b'>') {
        return Err(ParseError::Pri);
    }
    let pri = u8::try_from(pri).map_err(|_| ParseError::Pri)?;
    if !cursor.eat(b'1') || !cursor.eat(b' ') {
        return Err(ParseError::Version);
    }
    let token = cursor.token();
    let timestamp = if token == b"-" {
        None
    } else if valid_timestamp(token) {
        Some(String::from_utf8_lossy(token).into_owned())
    } else {
        return Err(ParseError::Field("TIMESTAMP"));
    };
    let mut field = |max: usize, name: &'static str| -> Result<Option<String>, ParseError> {
        if !cursor.eat(b' ') {
            return Err(ParseError::Field(name));
        }
        nil_or(cursor.token(), max, name)
    };
    let hostname = field(MAX_HOSTNAME, "HOSTNAME")?;
    let app_name = field(MAX_APP_NAME, "APP-NAME")?;
    let procid = field(MAX_PROCID, "PROCID")?;
    let msgid = field(MAX_MSGID, "MSGID")?;
    if !cursor.eat(b' ') {
        return Err(ParseError::StructuredData);
    }
    let structured_data = sd_elements(&mut cursor)?;
    let mut msg = Vec::new();
    let mut bom = false;
    if cursor.peek().is_some() {
        if !cursor.eat(b' ') {
            return Err(ParseError::Trailing);
        }
        let rest = bytes.get(cursor.pos..).unwrap_or_default();
        bom = rest.starts_with(&BOM_BYTES);
        msg = rest
            .get(if bom { BOM_BYTES.len() } else { 0 }..)
            .unwrap_or_default()
            .to_vec();
    }
    Ok(SyslogMessage {
        pri,
        facility: pri / 8,
        severity: pri % 8,
        version: 1,
        timestamp,
        hostname,
        app_name,
        procid,
        msgid,
        structured_data,
        bom,
        msg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(hostname: &'a str, msgid: &'a str, at: &str, severity: u8) -> Header<'a> {
        Header {
            facility: Facility::LogAudit,
            severity,
            at: at.parse().expect("time"),
            hostname,
            msgid,
        }
    }

    #[test]
    fn header_layout_and_pri() {
        let h = header(
            "ctl1.example.test",
            "audit",
            "2026-10-11T12:00:00.123456789Z",
            5,
        );
        let text = message(&h, &[], "", false);
        assert_eq!(
            text,
            "<109>1 2026-10-11T12:00:00.123456Z ctl1.example.test tenko - audit -"
        );
        let text = message(&h, &[], "{}", false);
        assert!(text.ends_with(" - {}"), "{text}");
        let h = Header {
            facility: Facility::Local7,
            severity: 99,
            ..h
        };
        assert!(message(&h, &[], "", false).starts_with("<191>1 "));
    }

    #[test]
    fn timestamp_truncates_and_trims() {
        for (input, want) in [
            ("2026-10-11T12:00:00Z", "2026-10-11T12:00:00Z"),
            (
                "2026-10-11T12:00:00.9999999Z",
                "2026-10-11T12:00:00.999999Z",
            ),
            ("2026-10-11T12:00:00.5Z", "2026-10-11T12:00:00.5Z"),
            ("2026-10-11T12:00:00.000001Z", "2026-10-11T12:00:00.000001Z"),
            ("2026-10-11T12:00:00.0000009Z", "2026-10-11T12:00:00Z"),
            ("2026-10-11T14:00:00.25+02:00", "2026-10-11T12:00:00.25Z"),
        ] {
            let h = header("h", "m", input, 0);
            let text = message(&h, &[], "", false);
            assert_eq!(text.split(' ').nth(1), Some(want), "{input}");
        }
    }

    #[test]
    fn hostname_and_msgid_fall_back() {
        let long = "a".repeat(256);
        let msgid_long = "m".repeat(33);
        for (hostname, msgid, host_want, id_want) in [
            ("", "", "-", "-"),
            ("has space", "has space", "-", "-"),
            ("h\u{e9}", "m\u{e9}", "-", "-"),
            (long.as_str(), msgid_long.as_str(), "-", "-"),
            ("a", "m", "a", "m"),
        ] {
            let h = header(hostname, msgid, "2026-10-11T12:00:00Z", 6);
            let text = message(&h, &[], "", false);
            let parts: Vec<&str> = text.split(' ').collect();
            assert_eq!(parts[2], host_want);
            assert_eq!(parts[5], id_want);
        }
        let (host, id) = ("a".repeat(255), "m".repeat(32));
        let h = header(&host, &id, "2026-10-11T12:00:00Z", 6);
        let text = message(&h, &[], "", false);
        assert!(!text.contains(" - audit"));
        assert!(text.contains(&"a".repeat(255)));
    }

    #[test]
    fn structured_data_is_escaped() {
        let h = header("h", "m", "2026-10-11T12:00:00Z", 6);
        let sd = [
            SdElement {
                id: "tenko@32473",
                params: vec![("a", "q\"b\\c]d"), ("b", "")],
            },
            SdElement {
                id: "x",
                params: vec![],
            },
        ];
        let text = message(&h, &sd, "", false);
        assert!(
            text.ends_with(r#" [tenko@32473 a="q\"b\\c\]d" b=""][x]"#),
            "{text}"
        );
        let text = message(&h, &sd, "line\u{fc}", true);
        assert!(text.ends_with(" \u{feff}line\u{fc}"), "{text}");
        assert!(!text.contains('\n'));
    }

    #[test]
    fn header_never_carries_line_breaks() {
        let h = header("h\r\n", "m\n", "2026-10-11T12:00:00Z", 6);
        let sd = [SdElement {
            id: "i\nd",
            params: vec![("n\r", "v\r\nw")],
        }];
        let text = message(&h, &sd, "", false);
        assert!(!text.contains('\r') && !text.contains('\n'), "{text:?}");
        parse(text.as_bytes()).expect("still parses");
    }

    #[test]
    fn round_trip() {
        let values = [
            "",
            "plain",
            "q\"uote",
            "back\\slash",
            "br]acket",
            "\\\"]\\\\]]\"",
            "caf\u{e9} \u{1f980} \u{65e5}\u{672c}",
            "trailing\\",
            "a b  c",
        ];
        for (index, value) in values.iter().enumerate() {
            for body in ["", "{\"k\":\"v\"}", "caf\u{e9}"] {
                for bom in [false, true] {
                    let h = header("ctl1.example.test", "audit", "2026-10-11T12:00:00.5Z", 4);
                    let sd = [SdElement {
                        id: "tenko@32473",
                        params: vec![("seq", "7"), ("value", value)],
                    }];
                    let text = message(&h, &sd, body, bom);
                    let parsed = parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}: {text}"));
                    assert_eq!(parsed.pri, 13 * 8 + 4, "{index}");
                    assert_eq!((parsed.facility, parsed.severity), (13, 4));
                    assert_eq!(parsed.version, 1);
                    assert_eq!(parsed.timestamp.as_deref(), Some("2026-10-11T12:00:00.5Z"));
                    assert_eq!(parsed.hostname.as_deref(), Some("ctl1.example.test"));
                    assert_eq!(parsed.app_name.as_deref(), Some("tenko"));
                    assert_eq!(parsed.procid, None);
                    assert_eq!(parsed.msgid.as_deref(), Some("audit"));
                    assert_eq!(parsed.structured_data.len(), 1);
                    assert_eq!(parsed.structured_data[0].id, "tenko@32473");
                    assert_eq!(
                        parsed.structured_data[0].params,
                        vec![
                            ("seq".to_owned(), "7".to_owned()),
                            ("value".to_owned(), (*value).to_owned())
                        ]
                    );
                    assert_eq!(parsed.msg, body.as_bytes());
                    assert_eq!(parsed.bom, bom && !body.is_empty());
                }
            }
        }
    }

    #[test]
    fn parse_nil_fields_and_errors() {
        let parsed = parse(b"<0>1 - - - - - -").expect("parses");
        assert_eq!(
            (parsed.pri, parsed.timestamp, parsed.hostname),
            (0, None, None)
        );
        assert!(parsed.structured_data.is_empty() && parsed.msg.is_empty() && !parsed.bom);
        let parsed = parse(b"<13>1 - - - - - - ").expect("empty msg");
        assert_eq!(parsed.msg, b"");
        let parsed = parse(b"<13>1 - - - - - - \xff\xfe").expect("binary msg");
        assert_eq!(parsed.msg, b"\xff\xfe");
        for bad in [
            &b""[..],
            b"<",
            b"<>1 - - - - - -",
            b"<192>1 - - - - - -",
            b"<013>1 - - - - - -",
            b"<1234>1 - - - - - -",
            b"<13>2 - - - - - -",
            b"<13>1- - - - - -",
            b"<13>1 2026-10-11 - - - - -",
            b"<13>1 - - - - -",
            b"<13>1 - - - - - x",
            b"<13>1 - - - - - [",
            b"<13>1 - - - - - []",
            b"<13>1 - - - - - [a b]",
            b"<13>1 - - - - - [a b=c]",
            b"<13>1 - - - - - [a b=\"c]",
            b"<13>1 - - - - - [a b=\"\xff\"]",
            b"<13>1 - - - - - [a]x",
            b"<13>1 - - - - - -x",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let long_host = format!("<13>1 - {} - - - -", "h".repeat(256));
        assert_eq!(
            parse(long_host.as_bytes()),
            Err(ParseError::Field("HOSTNAME"))
        );
        let long_app = format!("<13>1 - h {} - - -", "a".repeat(49));
        assert_eq!(
            parse(long_app.as_bytes()),
            Err(ParseError::Field("APP-NAME"))
        );
        let long_id = format!("<13>1 - h a - {} -", "m".repeat(33));
        assert_eq!(parse(long_id.as_bytes()), Err(ParseError::Field("MSGID")));
        let long_proc = format!("<13>1 - h a {} m -", "p".repeat(129));
        assert_eq!(
            parse(long_proc.as_bytes()),
            Err(ParseError::Field("PROCID"))
        );
        assert!(parse(format!("<13>1 - h a {} m -", "p".repeat(128)).as_bytes()).is_ok());
    }

    #[test]
    fn parse_keeps_unknown_escapes() {
        let parsed = parse(br#"<13>1 - - - - - [a b="x\y\""]"#).expect("parses");
        assert_eq!(parsed.structured_data[0].params[0].1, "x\\y\"");
    }

    fn drain(decoder: &mut FrameDecoder) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut out = Vec::new();
        while let Some(frame) = decoder.next_frame()? {
            out.push(frame);
        }
        Ok(out)
    }

    #[test]
    fn frame_round_trip_at_every_split() {
        let messages: Vec<Vec<u8>> = vec![
            b"<13>1 - - - - - -".to_vec(),
            vec![b'x'; 1234],
            b"a".to_vec(),
        ];
        let stream: Vec<u8> = messages.iter().flat_map(|m| frame(m)).collect();
        for split in 0..=stream.len() {
            let mut decoder = FrameDecoder::new(4096);
            let mut got = Vec::new();
            decoder.push(&stream[..split]);
            got.extend(drain(&mut decoder).expect("first"));
            decoder.push(&stream[split..]);
            got.extend(drain(&mut decoder).expect("second"));
            assert_eq!(got, messages, "split {split}");
            assert_eq!(decoder.buffered(), 0);
        }
        let mut decoder = FrameDecoder::new(4096);
        for byte in &stream {
            decoder.push(std::slice::from_ref(byte));
        }
        assert_eq!(drain(&mut decoder).expect("bytes"), messages);
    }

    #[test]
    fn decoder_errors() {
        for (input, want) in [
            (&b"0 x"[..], FrameError::BadLength),
            (b"01 x", FrameError::BadLength),
            (b"x", FrameError::BadLength),
            (b"-1 x", FrameError::BadLength),
            (b"1x", FrameError::BadLength),
            (b"1234567890 ", FrameError::BadLength),
            (b"1234567890", FrameError::BadLength),
            (b"101 x", FrameError::TooLong { len: 101, max: 100 }),
            (
                b"999999999 ",
                FrameError::TooLong {
                    len: 999_999_999,
                    max: 100,
                },
            ),
        ] {
            let mut decoder = FrameDecoder::new(100);
            decoder.push(input);
            assert_eq!(decoder.next_frame(), Err(want.clone()), "{input:?}");
            // The failure sticks and nothing more is buffered.
            decoder.push(b"3 abc");
            assert_eq!(decoder.next_frame(), Err(want));
            assert_eq!(decoder.buffered(), 0);
        }
        let mut decoder = FrameDecoder::new(100);
        decoder.push(b"3 ab");
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.push(b"c4 wxyz");
        assert_eq!(
            drain(&mut decoder),
            Ok(vec![b"abc".to_vec(), b"wxyz".to_vec()])
        );
        let mut decoder = FrameDecoder::new(100);
        decoder.push(b"99");
        assert_eq!(decoder.next_frame(), Ok(None));
        // A frame at the limit is fine, and its buffer stays within limit plus prefix.
        let mut decoder = FrameDecoder::new(100);
        decoder.push(&frame(&[b'z'; 100]));
        assert!(decoder.buffered() <= 100 + MAX_PREFIX);
        assert_eq!(
            decoder.next_frame().expect("frame").map(|f| f.len()),
            Some(100)
        );
    }

    #[test]
    fn frame_prefix() {
        assert_eq!(frame(b"abc"), b"3 abc");
        assert_eq!(frame(b""), b"0 ");
    }
}
