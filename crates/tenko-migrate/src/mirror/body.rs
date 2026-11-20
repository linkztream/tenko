//! A push body to a checked snapshot (plan section 2.1, rule 6; ADR 0033 decisions 2 and 5).
//!
//! The order is the defense: the route reads at most [`MAX_BODY_BYTES`] of the body, a gzip
//! body inflates into at most [`MAX_INFLATED_BYTES`] and stops there, one pass over the JSON
//! counts its array elements and refuses more than [`MAX_ELEMENTS`] before anything is
//! parsed, the JSON parses into the strict types of `tenko-core` (`deny_unknown_fields` on the
//! envelope), and the parsed snapshot is checked whole ([`MirrorSnapshot::validate`]). A body
//! that fails any step is refused whole, with the JSON path of the first error, and nothing
//! of it is kept.
//!
//! What decoding may allocate: the inflated text (at most [`MAX_INFLATED_BYTES`], twice that
//! while its buffer grows), the strings of the snapshot (no more octets than the text holds),
//! and at most [`MAX_ELEMENTS`] list items of at most a few hundred octets each, which their
//! vectors may hold twice while they grow. [`DECODE_ALLOCATION_BOUND`] is the sum, and
//! `tests/decode_alloc.rs` holds the most element-dense body the bounds let through to it.

use std::{fmt::Write as _, io::Read};

use tenko_core::ir::{
    MirrorSnapshot,
    mirror::{MAX_ELEMENTS, MAX_INFLATED_BYTES},
};

use super::MirrorError;

pub use tenko_core::ir::mirror::MAX_BODY_BYTES;

/// The octets decoding one push may allocate in all, counted over every allocation it
/// makes (so also over every growth of a vector): the inflated text and its growth, the
/// text's strings, and [`MAX_ELEMENTS`] items of up to 512 octets, twice. 224 MiB.
pub const DECODE_ALLOCATION_BOUND: usize = 3 * MAX_INFLATED_BYTES + 2 * 512 * MAX_ELEMENTS;

/// The deepest nesting of a push body; the envelope needs six levels.
const MAX_DEPTH: usize = 32;

/// Decodes a push body that the caller read within [`MAX_BODY_BYTES`]: `gzip` when the
/// request says `Content-Encoding: gzip`.
///
/// # Errors
///
/// [`MirrorError::TooLarge`] above a bound, [`MirrorError::Invalid`] for anything that does
/// not inflate, parse or validate.
pub fn decode(body: &[u8], gzip: bool) -> Result<MirrorSnapshot, MirrorError> {
    let inflated;
    let json = if gzip {
        inflated = inflate(body)?;
        inflated.as_slice()
    } else {
        body
    };
    count_elements(json)?;
    let snapshot: MirrorSnapshot = serde_json::from_slice(json).map_err(|error| {
        MirrorError::invalid(
            json_path(json, error.line(), error.column()),
            error.to_string(),
        )
    })?;
    snapshot.validate().map_err(MirrorError::Invalid)?;
    Ok(snapshot)
}

/// Inflates a gzip body into at most [`MAX_INFLATED_BYTES`].
fn inflate(body: &[u8]) -> Result<Vec<u8>, MirrorError> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take(MAX_INFLATED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| MirrorError::invalid("", "the gzip body does not inflate"))?;
    if out.len() > MAX_INFLATED_BYTES {
        return Err(MirrorError::TooLarge {
            limit: MAX_INFLATED_BYTES,
        });
    }
    Ok(out)
}

/// Counts the array elements of a JSON text without parsing it, and refuses more than
/// [`MAX_ELEMENTS`] or a nesting deeper than [`MAX_DEPTH`]. Text that is not JSON passes:
/// the parser refuses it with its path.
fn count_elements(json: &[u8]) -> Result<(), MirrorError> {
    // Per open container: whether it is an array, and whether an element has started in it.
    let mut stack: Vec<(bool, bool)> = Vec::new();
    let mut elements = 0usize;
    let mut at = 0;
    while at < json.len() {
        let byte = json[at];
        if !byte.is_ascii_whitespace()
            && !matches!(byte, b']' | b'}' | b',' | b':')
            && let Some((true, started)) = stack.last_mut()
        {
            *started = true;
        }
        match byte {
            b'[' | b'{' => {
                if stack.len() == MAX_DEPTH {
                    return Err(MirrorError::invalid("", "the body is nested too deeply"));
                }
                stack.push((byte == b'[', false));
            }
            b']' | b'}' => {
                if let Some((true, true)) = stack.pop() {
                    elements += 1;
                }
            }
            b',' if matches!(stack.last(), Some((true, _))) => elements += 1,
            b'"' => {
                at += 1;
                while at < json.len() && json[at] != b'"' {
                    at += if json[at] == b'\\' { 2 } else { 1 };
                }
            }
            _ => {}
        }
        if elements > MAX_ELEMENTS {
            return Err(MirrorError::invalid(
                "",
                format!("more than {MAX_ELEMENTS} list items in the body"),
            ));
        }
        at += 1;
    }
    Ok(())
}

/// One open container of [`json_path`].
enum Frame {
    /// An object, with the key of the member being read and whether a key comes next.
    Object(Option<String>, bool),
    /// An array, with the index of the element being read.
    Array(usize),
}

/// The JSON path (`dhcp.scopes[0].cidr`) of the member that holds the position `line` and
/// `column` (1-based, as `serde_json` reports them) of `text`; empty at the top. The scan
/// reads only up to the position, so its stack is no deeper than the parser went.
pub fn json_path(text: &[u8], line: usize, column: usize) -> String {
    let start: usize = text
        .split(|byte| *byte == b'\n')
        .take(line.saturating_sub(1))
        .map(|line| line.len() + 1)
        .sum();
    let end = start.saturating_add(column).min(text.len());
    let mut stack: Vec<Frame> = Vec::new();
    let mut at = 0;
    while at < end {
        match text[at] {
            b'{' => stack.push(Frame::Object(None, true)),
            b'[' => stack.push(Frame::Array(0)),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => match stack.last_mut() {
                Some(Frame::Array(index)) => *index += 1,
                Some(Frame::Object(key, next)) => (*key, *next) = (None, true),
                None => {}
            },
            b':' => {
                if let Some(Frame::Object(_, next)) = stack.last_mut() {
                    *next = false;
                }
            }
            b'"' => {
                let from = at + 1;
                at = from;
                while at < end && text[at] != b'"' {
                    at += if text[at] == b'\\' { 2 } else { 1 };
                }
                if let Some(Frame::Object(key, true)) = stack.last_mut() {
                    *key = Some(String::from_utf8_lossy(&text[from..at.min(end)]).into_owned());
                }
            }
            _ => {}
        }
        at += 1;
    }
    let mut path = String::new();
    for frame in &stack {
        match frame {
            Frame::Object(Some(key), _) => {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
            }
            Frame::Object(None, _) => {}
            Frame::Array(index) => {
                let _ = write!(path, "[{index}]");
            }
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use proptest::prelude::*;
    use tenko_core::Coded;

    use super::*;

    const FIXTURE: &str = include_str!("../../../tenko-core/tests/fixtures/mirror/snapshot.json");

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("gzip");
        encoder.finish().expect("gzip")
    }

    fn refused(body: &[u8], gzip: bool) -> MirrorError {
        decode(body, gzip).expect_err("refused")
    }

    #[test]
    fn the_fixture_decodes_plain_and_gzipped() {
        let plain = decode(FIXTURE.as_bytes(), false).expect("the fixture");
        assert_eq!(plain.sequence, 1);
        assert_eq!(
            decode(&gzip(FIXTURE.as_bytes()), true).expect("gzip"),
            plain
        );
        // The invariant of the fuzz target: a decoded snapshot reads back from its own JSON.
        let json = serde_json::to_vec(&plain).expect("json");
        assert_eq!(decode(&json, false).expect("again"), plain);
    }

    #[test]
    fn a_refusal_names_the_path_of_the_first_error() {
        let cases = [
            (
                FIXTURE.replacen("\"format\": 1", "\"format\": 1, \"extra\": 2", 1),
                "extra",
            ),
            (
                FIXTURE.replacen(
                    "\"cidr\": \"192.0.2.0/24\"",
                    "\"cidr\": \"192.0.2.0/33\"",
                    1,
                ),
                "dhcp.scopes[0].cidr",
            ),
            (
                FIXTURE.replacen("\"192.0.2.110\"", "\"192.0.2.300\"", 1),
                "dhcp.leases[0].ip",
            ),
            (
                FIXTURE.replacen("\"server\": \"dc1", "\"server\": \"\\u0007dc1", 1),
                "source.server",
            ),
        ];
        for (body, path) in cases {
            assert_ne!(body, FIXTURE, "{path}: the case changes the fixture");
            let error = refused(body.as_bytes(), false);
            assert_eq!(error.code(), "migrate.mirror.invalid", "{path}");
            assert_eq!(error.params()["path"], path, "{error}");
        }
    }

    #[test]
    fn the_bounds_hold_before_and_after_inflating() {
        let bomb = gzip(&vec![b' '; MAX_INFLATED_BYTES + 1]);
        assert!(bomb.len() < MAX_BODY_BYTES, "a small body on the wire");
        let error = refused(&bomb, true);
        assert_eq!(error.code(), "migrate.mirror.too_large");
        assert_eq!(error.params()["limit"], MAX_INFLATED_BYTES.to_string());
        assert_eq!(refused(b"not gzip", true).code(), "migrate.mirror.invalid");
    }

    #[test]
    fn list_items_and_nesting_are_counted_before_the_parse() {
        let many = format!("[{}0]", "0,".repeat(MAX_ELEMENTS));
        let error = refused(many.as_bytes(), false);
        assert_eq!(
            error.params()["reason"],
            format!("more than {MAX_ELEMENTS} list items in the body")
        );
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(
            refused(deep.as_bytes(), false).params()["reason"],
            "the body is nested too deeply"
        );
        // Commas inside strings and objects are no list items.
        count_elements(br#"[{"a": "x,y,z", "b": 1}, [1, 2], []]"#).expect("five items");
        // Exactly the bound passes.
        let mut text = String::from("[");
        text.push_str(&"1,".repeat(MAX_ELEMENTS - 1));
        text.push_str("1]");
        count_elements(text.as_bytes()).expect("exactly the bound");
    }

    #[test]
    fn every_free_text_is_one_bounded_line() {
        let long = "x".repeat(tenko_core::ir::mirror::MAX_LOCATION_LEN + 1);
        for (from, to, path) in [
            (
                "\"column\": \"Name=Printers\"",
                format!("\"column\": \"{long}\""),
                "losses.entries[0].location.column",
            ),
            (
                "is not carried; policies",
                "is not carried;\\npolicies".to_owned(),
                "losses.entries[0].detail",
            ),
            (
                "\"192.0.2.254\"",
                "\"\\u001b]52;c;Y2FsYw==\\u0007\"".to_owned(),
                "dhcp.scopes[0].reservations[0].options[0].values[0]",
            ),
            (
                "\"vendor_class\": \"Microsoft Windows 2000 Options\"",
                "\"vendor_class\": \"Microsoft\\u001b[2K\"".to_owned(),
                "dhcp.scopes[0].options[4].vendor_class",
            ),
            (
                "\"name\": \"Office\"",
                "\"name\": \"Off\\rice\"".to_owned(),
                "dhcp.scopes[0].name",
            ),
        ] {
            let body = FIXTURE.replacen(from, &to, 1);
            assert_ne!(body, FIXTURE, "{path}");
            assert_eq!(refused(body.as_bytes(), false).params()["path"], path);
        }
    }

    #[test]
    fn json_paths_follow_objects_and_arrays() {
        let text = br#"{"a": {"b": [1, {"c": "x,]"}]}}"#;
        let at = |needle: &str| {
            let offset = text
                .windows(needle.len())
                .position(|window| window == needle.as_bytes())
                .expect("needle");
            json_path(text, 1, offset + needle.len())
        };
        assert_eq!(at("\"c\""), "a.b[1].c");
        assert_eq!(at("[1"), "a.b[0]");
        assert_eq!(at("{\"b\""), "a.b");
        assert_eq!(json_path(b"", 1, 1), "");
    }

    proptest! {
        #[test]
        fn any_body_is_decoded_or_refused_with_a_code(body in proptest::collection::vec(any::<u8>(), 0..512), gzip in any::<bool>()) {
            if let Err(error) = decode(&body, gzip) {
                prop_assert!(matches!(error.http_status(), 413 | 422));
            }
        }

        #[test]
        fn json_path_reads_any_text_at_any_position(text in ".{0,200}", line in 0usize..4, column in 0usize..300) {
            let _ = json_path(text.as_bytes(), line, column);
        }
    }
}
