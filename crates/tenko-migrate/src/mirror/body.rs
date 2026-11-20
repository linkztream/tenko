//! A push body to a checked snapshot (plan section 2.1, rule 6; ADR 0033 decisions 2 and 5).
//!
//! The order is the defense: the route reads at most [`MAX_BODY_BYTES`] of the body, a gzip
//! body inflates into at most [`MAX_INFLATED_BYTES`] and stops there, one pass over the JSON
//! refuses more than [`MAX_ELEMENTS`] array elements, a nesting deeper than [`MAX_DEPTH`] and
//! a string longer than [`MAX_STRING_OCTETS`] before anything is parsed, the JSON parses into
//! the strict types of `tenko-core` (`deny_unknown_fields` on the envelope), and the parsed
//! snapshot is checked whole ([`MirrorSnapshot::validate`]). A body that fails any step is
//! refused whole, with the JSON path of the first error, and nothing of it is kept.
//!
//! What decoding allocates, [`DECODE_ALLOCATION_BOUND`] at most, counted over every
//! allocation and every growth of one: the inflated text (its buffer doubles up to
//! [`MAX_INFLATED_BYTES`] and no further); the snapshot's strings (no more octets than the
//! text holds); the parser's scratch for a string with escapes (twice the longest string);
//! and the list items. A vector of `n` items holds at most `2n + 2` slots, so an item costs
//! at most two slots in a list of the envelope's top level and four in a list inside an item
//! (where a list may hold one); [`ELEMENT_BYTES`] is the most that comes to for any item
//! type, which the assertions below hold at compile time. `tests/decode_alloc.rs` measures
//! the most element-dense bodies of each kind against the bound.

use std::{fmt::Write as _, io::Read, mem::size_of};

use ipnet::IpNet;
use tenko_core::ir::{
    LossEntry, MirrorSnapshot,
    dhcp::{
        IrClass, IrCondition, IrFailover, IrFilter, IrLease, IrOption, IrOptionDef, IrPolicy,
        IrRange, IrReservation, IrScope, IrSuperscope,
    },
    mirror::{MAX_ELEMENTS, MAX_INFLATED_BYTES, MAX_LOSS_DETAIL_LEN, MAX_OPTION_VALUE_LEN},
};

use super::MirrorError;

pub use tenko_core::ir::mirror::MAX_BODY_BYTES;

/// The deepest nesting of a push body; the envelope needs six levels.
pub const MAX_DEPTH: usize = 32;

/// The longest string of a push body as it stands in the JSON: twelve octets (a surrogate
/// pair as `\uXXXX\uXXXX`) for each character of the longest text the snapshot may hold,
/// so that nothing longer can pass [`MirrorSnapshot::validate`]. 48 KiB.
pub const MAX_STRING_OCTETS: usize = 12
    * if MAX_OPTION_VALUE_LEN > MAX_LOSS_DETAIL_LEN {
        MAX_OPTION_VALUE_LEN
    } else {
        MAX_LOSS_DETAIL_LEN
    };

/// The most one list item may cost with the slots its vector holds for it: two slots of the
/// largest item of a top-level list ([`IrScope`]), four of the largest item that sits in a
/// list inside another item ([`IrReservation`]).
pub const ELEMENT_BYTES: usize = 832;

// Every list item type of the envelope, with the slots its list may hold for it.
const _: () = {
    let top = [
        size_of::<IrOption>(),
        size_of::<IrOptionDef>(),
        size_of::<IrClass>(),
        size_of::<IrScope>(),
        size_of::<IrSuperscope>(),
        size_of::<IrPolicy>(),
        size_of::<IrFilter>(),
        size_of::<IrFailover>(),
        size_of::<IrLease>(),
        size_of::<LossEntry>(),
    ];
    let nested = [
        size_of::<IrReservation>(),
        size_of::<IrOption>(),
        size_of::<IrRange>(),
        size_of::<IrCondition>(),
        size_of::<IpNet>(),
        size_of::<String>(),
    ];
    let mut at = 0;
    while at < top.len() {
        assert!(2 * top[at] <= ELEMENT_BYTES);
        at += 1;
    }
    at = 0;
    while at < nested.len() {
        assert!(4 * nested[at] <= ELEMENT_BYTES);
        at += 1;
    }
};

/// What the bound adds besides the text and the items: the scratch of a string with escapes
/// (twice [`MAX_STRING_OCTETS`]), the first slots of the ten top-level lists, and the path and
/// reason of a refusal.
const SLACK_BYTES: usize = 1 << 20;

/// The octets decoding one push may allocate in all, counted over every allocation and every
/// growth of one: the inflated text and the strings parsed from it, each at most
/// [`MAX_INFLATED_BYTES`], [`MAX_ELEMENTS`] items of [`ELEMENT_BYTES`], and [`SLACK_BYTES`].
/// 286,141,440 octets (273 MiB). One push decodes at a time on a node
/// (`MirrorService::decoding`).
pub const DECODE_ALLOCATION_BOUND: usize =
    2 * MAX_INFLATED_BYTES + ELEMENT_BYTES * MAX_ELEMENTS + SLACK_BYTES;

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

/// Inflates a gzip body into at most [`MAX_INFLATED_BYTES`]. The buffer doubles, but never
/// past the bound (`read_to_end` would double it once more to find the end).
fn inflate(body: &[u8]) -> Result<Vec<u8>, MirrorError> {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8 << 10];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|_| MirrorError::invalid("", "the gzip body does not inflate"))?;
        if read == 0 {
            return Ok(out);
        }
        if out.len() + read > MAX_INFLATED_BYTES {
            return Err(MirrorError::TooLarge {
                limit: MAX_INFLATED_BYTES,
            });
        }
        if out.capacity() - out.len() < read {
            let capacity = (2 * out.capacity())
                .max(out.len() + read)
                .min(MAX_INFLATED_BYTES);
            out.reserve_exact(capacity - out.len());
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

/// Counts the array elements of a JSON text without parsing it, and refuses more than
/// [`MAX_ELEMENTS`], a nesting deeper than [`MAX_DEPTH`] or a string longer than
/// [`MAX_STRING_OCTETS`]. Text that is not JSON passes: the parser refuses it with its path.
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
                let from = at;
                at += 1;
                while at < json.len() && json[at] != b'"' {
                    at += if json[at] == b'\\' { 2 } else { 1 };
                }
                if at - from - 1 > MAX_STRING_OCTETS {
                    return Err(MirrorError::invalid(
                        "",
                        format!("a string of the body is longer than {MAX_STRING_OCTETS} octets"),
                    ));
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
        // A string longer than any text the snapshot may hold, escapes counted as written.
        let long = format!("[\"{}\"]", "\\n".repeat(MAX_STRING_OCTETS / 2 + 1));
        assert_eq!(
            refused(long.as_bytes(), false).params()["reason"],
            format!("a string of the body is longer than {MAX_STRING_OCTETS} octets")
        );
        count_elements(format!("[\"{}\"]", "x".repeat(MAX_STRING_OCTETS)).as_bytes())
            .expect("the longest string");
    }

    #[test]
    fn the_bound_is_the_one_the_documentation_states() {
        assert_eq!(MAX_ELEMENTS, 262_000);
        assert_eq!(DECODE_ALLOCATION_BOUND, 286_141_440);
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
            (
                "\"192.0.2.254\"",
                "\"192.0.2.\\u202e452\"".to_owned(),
                "dhcp.scopes[0].reservations[0].options[0].values[0]",
            ),
            (
                "\"name\": \"Office\"",
                "\"name\": \"Off\\u200bice\"".to_owned(),
                "dhcp.scopes[0].name",
            ),
        ] {
            let body = FIXTURE.replacen(from, &to, 1);
            assert_ne!(body, FIXTURE, "{path}");
            assert_eq!(refused(body.as_bytes(), false).params()["path"], path);
        }
        // The refusal names the character, so that an operator can find it in the source.
        let body = FIXTURE.replacen("\"name\": \"Office\"", "\"name\": \"\\u2066Office\"", 1);
        assert!(
            refused(body.as_bytes(), false).params()["reason"].contains("U+2066"),
            "the character is named"
        );
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
