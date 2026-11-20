//! A push body to a checked snapshot (plan section 2.1, rule 6; ADR 0033 decisions 2 and 5).
//!
//! The order is the defense: the size on the wire is bounded before the body is read (the
//! route reads at most [`MAX_BODY_BYTES`]), a gzip body inflates into at most
//! [`MAX_INFLATED_BYTES`] and stops there, the JSON parses into the strict types of
//! `tenko-core` (`deny_unknown_fields` on the envelope), and the parsed snapshot is checked
//! whole ([`MirrorSnapshot::validate`] and [`check_texts`]). A body that fails any step is
//! refused whole, with the JSON path of the first error, and nothing of it is kept.

use std::{fmt::Write as _, io::Read};

use tenko_core::ir::{
    MirrorSnapshot,
    mirror::{MAX_BODY_BYTES, MAX_INFLATED_BYTES},
};

use super::MirrorError;

/// The longest sheet or column of a loss entry's location: the location is the entry's key,
/// which the acknowledgment stores and the audit names.
pub const MAX_LOCATION_LEN: usize = 256;

/// Decodes a push body: `gzip` when the request says `Content-Encoding: gzip`.
///
/// # Errors
///
/// [`MirrorError::TooLarge`] above a bound, [`MirrorError::Invalid`] for anything that does
/// not inflate, parse or validate.
pub fn decode(body: &[u8], gzip: bool) -> Result<MirrorSnapshot, MirrorError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(MirrorError::TooLarge {
            limit: MAX_BODY_BYTES,
        });
    }
    let inflated;
    let json = if gzip {
        inflated = inflate(body)?;
        inflated.as_slice()
    } else {
        body
    };
    let snapshot: MirrorSnapshot = serde_json::from_slice(json).map_err(|error| {
        MirrorError::invalid(
            json_path(json, error.line(), error.column()),
            error.to_string(),
        )
    })?;
    snapshot.validate().map_err(MirrorError::Invalid)?;
    check_texts(&snapshot)?;
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

/// The checks of what the core leaves free and this crate stores or shows: a loss entry's
/// location is its key, and its detail reaches the audit and the card, so each is one line
/// and the location is bounded.
///
/// # Errors
///
/// [`MirrorError::Invalid`] with the path of the first error.
pub fn check_texts(snapshot: &MirrorSnapshot) -> Result<(), MirrorError> {
    for (index, entry) in snapshot.losses.entries.iter().enumerate() {
        let path = format!("losses.entries[{index}]");
        let parts = [
            ("location.sheet", entry.location.sheet.as_deref()),
            ("location.column", entry.location.column.as_deref()),
        ];
        for (field, text) in parts {
            if text.is_some_and(|text| {
                text.chars().count() > MAX_LOCATION_LEN || text.chars().any(char::is_control)
            }) {
                return Err(MirrorError::invalid(
                    format!("{path}.{field}"),
                    "a location is one line of at most 256 characters",
                ));
            }
        }
        if entry.detail.chars().any(char::is_control) {
            return Err(MirrorError::invalid(
                format!("{path}.detail"),
                "the detail holds a control character",
            ));
        }
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
        let large = vec![b' '; MAX_BODY_BYTES + 1];
        assert_eq!(refused(&large, false).code(), "migrate.mirror.too_large");
        let bomb = gzip(&vec![b' '; MAX_INFLATED_BYTES + 1]);
        assert!(bomb.len() < MAX_BODY_BYTES, "a small body on the wire");
        let error = refused(&bomb, true);
        assert_eq!(error.code(), "migrate.mirror.too_large");
        assert_eq!(error.params()["limit"], MAX_INFLATED_BYTES.to_string());
        assert_eq!(refused(b"not gzip", true).code(), "migrate.mirror.invalid");
    }

    #[test]
    fn a_loss_location_is_one_bounded_line() {
        let long = "x".repeat(MAX_LOCATION_LEN + 1);
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
