//! `ArcSight` Common Event Format (CEF version 0): one line per event.
//!
//! `CEF:0|Tenko|Tenko DDI|<version>|<signature>|<name>|<severity>|<extension>`. Header
//! fields escape `\` and `|`; extension values escape `\`, `=` and line breaks, so a value
//! round trips through [`render`] and [`parse`] exactly.

use tenko_core::audit::{AuditOutcome, AuditRecord};
use thiserror::Error;

use super::{Checkpoint, Event, Origin, TestMessage};

/// The vendor field of the header.
const VENDOR: &str = "Tenko";
/// The product field of the header.
const PRODUCT: &str = "Tenko DDI";
/// The longest line [`parse`] accepts, in bytes.
pub const MAX_LINE: usize = 4 * 1024 * 1024;

fn header_field(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
}

fn extension_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// The extension: `key=value` pairs separated by single spaces.
#[derive(Default)]
struct Extension(String);

impl Extension {
    fn pair(&mut self, key: &str, value: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(key);
        self.0.push('=');
        self.0.push_str(&extension_value(value));
    }

    fn labelled(&mut self, key: &str, label: &str, value: &str) {
        self.pair(key, value);
        self.pair(&format!("{key}Label"), label);
    }
}

fn millis(at: tenko_core::Timestamp) -> String {
    at.unix_nanos().div_euclid(1_000_000).to_string()
}

fn record_extension(record: &AuditRecord) -> Extension {
    let draft = &record.draft;
    let mut ext = Extension::default();
    ext.pair("rt", &millis(record.at));
    ext.pair("suser", &record.principal.subject());
    match draft.source_ip {
        Some(ip @ std::net::IpAddr::V4(_)) => ext.pair("src", &ip.to_string()),
        Some(ip @ std::net::IpAddr::V6(_)) => ext.labelled("c6a2", "source", &ip.to_string()),
        None => {}
    }
    match &draft.outcome {
        AuditOutcome::Success => ext.pair("outcome", "success"),
        AuditOutcome::Denied => ext.pair("outcome", "denied"),
        AuditOutcome::Failed { code } => {
            ext.pair("outcome", "failed");
            ext.pair("reason", code);
        }
    }
    ext.labelled("cn1", "seq", &record.seq.to_string());
    ext.labelled("cs1", "hash", &record.hash.to_string());
    ext.labelled("cs2", "prev", &record.prev.to_string());
    ext.labelled("cn2", "revision", &record.revision.to_string());
    if !draft.objects.is_empty() {
        let objects: Vec<String> = draft.objects.iter().map(ToString::to_string).collect();
        ext.labelled("cs3", "objects", &objects.join(","));
    }
    if let Some(request) = record.request {
        ext.labelled("cs4", "request", &request.to_string());
    }
    if (!draft.details.changes.is_empty() || !draft.details.context.is_empty())
        && let Ok(details) = serde_json::to_string(&draft.details)
    {
        ext.pair("msg", &details);
    }
    ext
}

fn checkpoint_extension(origin: &Origin, checkpoint: &Checkpoint) -> Extension {
    let mut ext = Extension::default();
    ext.pair("rt", &millis(checkpoint.at));
    ext.labelled("cn1", "seq", &checkpoint.head.seq.to_string());
    ext.labelled("cs1", "hash", &checkpoint.head.hash.to_string());
    ext.labelled("cn3", "store_head", &checkpoint.store_head.to_string());
    ext.labelled("cs5", "sink", &origin.sink);
    ext
}

fn test_extension(origin: &Origin, test: &TestMessage) -> Extension {
    let mut ext = Extension::default();
    ext.pair("rt", &millis(test.at));
    ext.pair("suser", &test.by);
    ext.pair("cs5", &origin.sink);
    ext.pair("cs5Label", "sink");
    ext
}

/// Renders an event as one CEF line.
pub fn render(origin: &Origin, event: &Event<'_>) -> String {
    let (signature, name, extension) = match event {
        Event::Record(record) => (
            record.draft.action.to_string(),
            record.draft.action.to_string(),
            record_extension(record),
        ),
        Event::Checkpoint(checkpoint) => (
            "audit.export.checkpoint".to_owned(),
            "Audit export checkpoint".to_owned(),
            checkpoint_extension(origin, checkpoint),
        ),
        Event::Test(test) => (
            "audit.export.test".to_owned(),
            "Audit export test".to_owned(),
            test_extension(origin, test),
        ),
    };
    let mut out = String::from("CEF:0|");
    for field in [VENDOR, PRODUCT, &origin.version, &signature, &name] {
        header_field(&mut out, field);
        out.push('|');
    }
    out.push_str(&event.cef_severity().to_string());
    out.push('|');
    out.push_str(&extension.0);
    out
}

/// A CEF event read by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CefEvent {
    /// The CEF version, such as `0`.
    pub version: String,
    /// The device vendor.
    pub vendor: String,
    /// The device product.
    pub product: String,
    /// The device version.
    pub device_version: String,
    /// The device event class id.
    pub signature: String,
    /// The event name.
    pub name: String,
    /// The severity, as written.
    pub severity: String,
    /// The extension pairs in order, values unescaped.
    pub extensions: Vec<(String, String)>,
}

impl CefEvent {
    /// The first value of an extension key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.extensions
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Why [`parse`] refused a line.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CefError {
    /// The line is longer than [`MAX_LINE`].
    #[error("line too long")]
    TooLong,
    /// The line does not start with `CEF:`.
    #[error("missing CEF: prefix")]
    Prefix,
    /// The header has fewer than seven unescaped pipes.
    #[error("incomplete header")]
    Header,
    /// The extension is not a sequence of `key=value` pairs.
    #[error("malformed extension")]
    Extension,
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Splits the header at its first seven unescaped pipes; returns the fields and the rest.
fn split_header(text: &str) -> Result<(Vec<String>, &str), CefError> {
    let bytes = text.as_bytes();
    let mut fields = Vec::with_capacity(7);
    let mut current = Vec::new();
    let mut i = 0;
    while i < bytes.len() && fields.len() < 7 {
        match bytes[i] {
            b'\\' => {
                if let Some(&next @ (b'\\' | b'|')) = bytes.get(i + 1) {
                    current.push(next);
                    i += 2;
                } else {
                    current.push(b'\\');
                    i += 1;
                }
            }
            b'|' => {
                fields.push(String::from_utf8_lossy(&current).into_owned());
                current.clear();
                i += 1;
            }
            other => {
                current.push(other);
                i += 1;
            }
        }
    }
    if fields.len() < 7 {
        return Err(CefError::Header);
    }
    Ok((fields, text.get(i..).ok_or(CefError::Header)?))
}

fn unescape_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('\\') => out.push('\\'),
            Some('=') => out.push('='),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            _ => {
                out.push('\\');
                continue;
            }
        }
        chars.next();
    }
    out
}

/// The length of `key=` at the start of `bytes`, if there is one.
fn key_len(bytes: &[u8]) -> Option<usize> {
    let key = bytes.iter().take_while(|&&b| is_key_byte(b)).count();
    (key > 0 && bytes.get(key) == Some(&b'=')).then_some(key)
}

fn parse_extension(text: &str) -> Result<Vec<(String, String)>, CefError> {
    let bytes = text.as_bytes();
    let mut pairs = Vec::new();
    if bytes.is_empty() {
        return Ok(pairs);
    }
    let mut key_start = 0;
    loop {
        let key = key_len(&bytes[key_start..]).ok_or(CefError::Extension)?;
        let value_start = key_start + key + 1;
        // The value runs to the next space that is followed by `key=`.
        let mut next = None;
        let mut at = value_start;
        while let Some(offset) = bytes[at..].iter().position(|&b| b == b' ') {
            let space = at + offset;
            if key_len(&bytes[space + 1..]).is_some() {
                next = Some(space);
                break;
            }
            at = space + 1;
        }
        let end = next.unwrap_or(bytes.len());
        let name = text
            .get(key_start..key_start + key)
            .ok_or(CefError::Extension)?;
        let raw = text.get(value_start..end).ok_or(CefError::Extension)?;
        pairs.push((name.to_owned(), unescape_value(raw)));
        match next {
            Some(space) => key_start = space + 1,
            None => return Ok(pairs),
        }
    }
}

/// Reads one CEF line.
///
/// # Errors
///
/// [`CefError`] when the line has no `CEF:` prefix, fewer than seven header pipes or a
/// malformed extension.
pub fn parse(line: &str) -> Result<CefEvent, CefError> {
    if line.len() > MAX_LINE {
        return Err(CefError::TooLong);
    }
    let rest = line.strip_prefix("CEF:").ok_or(CefError::Prefix)?;
    let (fields, extension) = split_header(rest)?;
    let mut fields = fields.into_iter();
    let mut next = || fields.next().unwrap_or_default();
    Ok(CefEvent {
        version: next(),
        vendor: next(),
        product: next(),
        device_version: next(),
        signature: next(),
        name: next(),
        severity: next(),
        extensions: parse_extension(extension)?,
    })
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        AuditSeq, Timestamp,
        audit::{AuditOutcome, ChainHead},
    };

    use super::{
        super::tests::{chain, origin},
        *,
    };

    fn ext(event: &CefEvent) -> Vec<&str> {
        event.extensions.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn record_line_is_exact() {
        let records = chain(1);
        let record = &records[0];
        let line = render(&origin(), &Event::Record(record));
        let objects = record.draft.objects[0].to_string();
        let request = record.request.expect("request");
        let expected = format!(
            "CEF:0|Tenko|Tenko DDI|0.0.1|ipam.host.create|ipam.host.create|3|\
             rt=1791720000123 suser=system:ipam src=203.0.113.5 outcome=success \
             cn1=1 cn1Label=seq cs1={} cs1Label=hash cs2={} cs2Label=prev \
             cn2=2 cn2Label=revision cs3={objects} cs3Label=objects \
             cs4={request} cs4Label=request msg={}",
            record.hash,
            record.prev,
            extension_value(&serde_json::to_string(&record.draft.details).expect("json")),
        );
        assert_eq!(line, expected);
        assert!(!line.contains('\n') && !line.contains('\r'));
        let parsed = parse(&line).expect("parses");
        assert_eq!(
            parsed.get("msg").map(str::len),
            Some(
                serde_json::to_string(&record.draft.details)
                    .expect("json")
                    .len()
            )
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(parsed.get("msg").expect("msg"))
                .expect("json"),
            serde_json::to_value(&record.draft.details).expect("value")
        );
    }

    #[test]
    fn ipv6_and_failed_outcome() {
        let mut records = chain(1);
        records[0].draft.source_ip = Some("2001:db8::7".parse().expect("ip"));
        records[0].draft.outcome = AuditOutcome::Failed {
            code: "ipam.conflict".into(),
        };
        records[0].draft.objects.clear();
        records[0].request = None;
        records[0].draft.details = tenko_core::audit::AuditDetails::default();
        let line = render(&origin(), &Event::Record(&records[0]));
        assert!(
            line.starts_with("CEF:0|Tenko|Tenko DDI|0.0.1|ipam.host.create|ipam.host.create|6|")
        );
        assert!(
            line.contains(
                " c6a2=2001:db8::7 c6a2Label=source outcome=failed reason=ipam.conflict cn1=1 "
            ),
            "{line}"
        );
        assert!(!line.contains(" src="));
        assert!(!line.contains("cs3=") && !line.contains("cs4=") && !line.contains(" msg="));
        let parsed = parse(&line).expect("parses");
        assert_eq!(
            ext(&parsed),
            [
                "rt",
                "suser",
                "c6a2",
                "c6a2Label",
                "outcome",
                "reason",
                "cn1",
                "cn1Label",
                "cs1",
                "cs1Label",
                "cs2",
                "cs2Label",
                "cn2",
                "cn2Label"
            ]
        );
        records[0].draft.source_ip = None;
        records[0].draft.outcome = AuditOutcome::Denied;
        let line = render(&origin(), &Event::Record(&records[0]));
        assert!(line.contains("|7|rt="));
        assert!(
            line.contains(" suser=system:ipam outcome=denied cn1="),
            "{line}"
        );
    }

    #[test]
    fn checkpoint_and_test_lines() {
        let records = chain(1);
        let at: Timestamp = "2026-10-11T12:00:01.9999Z".parse().expect("time");
        let checkpoint = Checkpoint {
            head: ChainHead {
                seq: AuditSeq(1),
                hash: records[0].hash,
            },
            store_head: AuditSeq(9),
            at,
        };
        let line = render(&origin(), &Event::Checkpoint(&checkpoint));
        assert_eq!(
            line,
            format!(
                "CEF:0|Tenko|Tenko DDI|0.0.1|audit.export.checkpoint|Audit export checkpoint|1|\
                 rt=1791720001999 cn1=1 cn1Label=seq cs1={} cs1Label=hash cn3=9 \
                 cn3Label=store_head cs5=siem cs5Label=sink",
                records[0].hash
            )
        );
        let test = TestMessage {
            at: Timestamp::UNIX_EPOCH,
            by: "user:00000000-0000-0000-0000-000000000001".to_owned(),
        };
        let line = render(&origin(), &Event::Test(&test));
        assert_eq!(
            line,
            "CEF:0|Tenko|Tenko DDI|0.0.1|audit.export.test|Audit export test|1|\
             rt=0 suser=user:00000000-0000-0000-0000-000000000001 cs5=siem cs5Label=sink"
        );
    }

    #[test]
    fn header_escaping() {
        let mut origin = origin();
        origin.version = "1.0|b\\c\r\nd".to_owned();
        let test = TestMessage {
            at: Timestamp::UNIX_EPOCH,
            by: "u".to_owned(),
        };
        let line = render(&origin, &Event::Test(&test));
        assert!(
            line.starts_with("CEF:0|Tenko|Tenko DDI|1.0\\|b\\\\c  d|audit.export.test|"),
            "{line}"
        );
        let parsed = parse(&line).expect("parses");
        assert_eq!(parsed.device_version, "1.0|b\\c  d");
        assert_eq!(parsed.signature, "audit.export.test");
        assert_eq!(parsed.severity, "1");
    }

    #[test]
    fn extension_values_round_trip() {
        let values = [
            "plain",
            "",
            "a=b",
            "k=v k2=v2",
            "back\\slash\\",
            "\\=\\n",
            "line\nbreak\r\nend",
            "pipe|and|more",
            "  spaces  inside  ",
            "caf\u{e9} \u{1f980}",
            " x=",
        ];
        for value in values {
            let mut origin = origin();
            origin.sink = value.to_owned();
            let test = TestMessage {
                at: Timestamp::UNIX_EPOCH,
                by: value.to_owned(),
            };
            let line = render(&origin, &Event::Test(&test));
            assert!(!line.contains('\n') && !line.contains('\r'), "{line:?}");
            let parsed = parse(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
            assert_eq!(parsed.get("suser"), Some(value), "{line:?}");
            assert_eq!(parsed.get("cs5"), Some(value), "{line:?}");
            assert_eq!(parsed.get("cs5Label"), Some("sink"), "{line:?}");
            assert_eq!(parsed.get("rt"), Some("0"));
        }
    }

    #[test]
    fn record_context_round_trips() {
        let records = chain(1);
        let line = render(&origin(), &Event::Record(&records[0]));
        let parsed = parse(&line).expect("parses");
        let details: tenko_core::audit::AuditDetails =
            serde_json::from_str(parsed.get("msg").expect("msg")).expect("details");
        assert_eq!(details, records[0].draft.details);
        assert_eq!(
            parsed.get("cs1"),
            Some(records[0].hash.to_string().as_str())
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse(""), Err(CefError::Prefix));
        assert_eq!(parse("cef:0|a|b|c|d|e|1|"), Err(CefError::Prefix));
        assert_eq!(parse("CEF:0|a|b|c|d|e|1"), Err(CefError::Header));
        assert_eq!(parse("CEF:0|a|b|c|d|e\\|1|"), Err(CefError::Header));
        assert_eq!(parse("CEF:0|a|b|c|d|e|1|novalue"), Err(CefError::Extension));
        assert_eq!(parse("CEF:0|a|b|c|d|e|1| k=v"), Err(CefError::Extension));
        assert_eq!(
            parse("CEF:0|a|b|c|d|e|1|k=v bad"),
            Ok(CefEvent {
                version: "0".into(),
                vendor: "a".into(),
                product: "b".into(),
                device_version: "c".into(),
                signature: "d".into(),
                name: "e".into(),
                severity: "1".into(),
                extensions: vec![("k".into(), "v bad".into())],
            })
        );
        let empty = parse("CEF:0|a|b|c|d|e|1|").expect("empty extension");
        assert_eq!(empty.extensions, []);
        let pipes = parse("CEF:0|a|b|c|d|e|1|k=x|y").expect("pipe in extension");
        assert_eq!(pipes.get("k"), Some("x|y"));
        assert_eq!(parse(&"x".repeat(MAX_LINE + 1)), Err(CefError::TooLong));
    }
}
