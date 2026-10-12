//! The JSON form of an event: one object per line, discriminated by `type`.
//!
//! - `{"type":"record", <every field of the audit record>, "cbor":"<base64>"}`: `cbor` is
//!   the canonical CBOR of the hashed part of the record (every field except `hash`), so
//!   `SHA-256(cbor)` equals `hash`.
//! - `{"type":"checkpoint","sink":…,"seq":…,"hash":…,"store_head":…,"at":…}`: the last
//!   record sent before the checkpoint and the newest record of the log at that time.
//! - `{"type":"test","sink":…,"at":…,"by":…}`: a test message, not part of the chain.
//!
//! [`parse_line`] reads a line back; `tenko audit verify --file` and the fuzz target
//! `audit_export_jsonl` use it.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    AuditSeq, Principal, RequestId, Revision, Timestamp,
    audit::{AuditDraft, AuditRecord, Digest},
    codec::{CodecError, to_canonical_cbor},
};

use super::{Checkpoint, Event, Origin, TestMessage};

/// The longest line [`parse_line`] accepts, in bytes.
pub const MAX_LINE: usize = 4 * 1024 * 1024;

/// The hashed part of a record, field for field as `tenko_core::audit` hashes it.
#[derive(Serialize)]
struct Unsealed<'a> {
    seq: AuditSeq,
    revision: Revision,
    at: Timestamp,
    principal: &'a Principal,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<RequestId>,
    draft: &'a AuditDraft,
    prev: Digest,
}

/// The canonical CBOR that the record's hash covers.
///
/// # Errors
///
/// [`CodecError`] when the record cannot be encoded.
pub fn hashed_bytes(record: &AuditRecord) -> Result<Vec<u8>, CodecError> {
    to_canonical_cbor(&Unsealed {
        seq: record.seq,
        revision: record.revision,
        at: record.at,
        principal: &record.principal,
        request: record.request,
        draft: &record.draft,
        prev: record.prev,
    })
}

/// A record line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordLine {
    /// The record.
    #[serde(flatten)]
    pub record: AuditRecord,
    /// The canonical CBOR of the hashed part, in standard base64 with padding.
    pub cbor: String,
}

/// A checkpoint line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointLine {
    /// The sink that sent it.
    pub sink: String,
    /// The last record sent before the checkpoint (0 before any).
    pub seq: AuditSeq,
    /// Its hash.
    pub hash: Digest,
    /// The newest record of the log when the checkpoint was sent.
    pub store_head: AuditSeq,
    /// When it was sent.
    pub at: Timestamp,
}

/// A test line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLine {
    /// The sink that sent it.
    pub sink: String,
    /// When it was sent.
    pub at: Timestamp,
    /// Who asked for it.
    pub by: String,
}

/// One line of a JSON export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Line {
    /// An audit record.
    Record(Box<RecordLine>),
    /// A chain checkpoint.
    Checkpoint(CheckpointLine),
    /// A test message.
    Test(TestLine),
}

/// The line of an event.
///
/// # Errors
///
/// [`CodecError`] when the record cannot be encoded.
pub fn line(origin: &Origin, event: &Event<'_>) -> Result<Line, CodecError> {
    Ok(match event {
        Event::Record(record) => Line::Record(Box::new(RecordLine {
            record: (*record).clone(),
            cbor: base64_encode(&hashed_bytes(record)?),
        })),
        Event::Checkpoint(Checkpoint {
            head,
            store_head,
            at,
        }) => Line::Checkpoint(CheckpointLine {
            sink: origin.sink.clone(),
            seq: head.seq,
            hash: head.hash,
            store_head: *store_head,
            at: *at,
        }),
        Event::Test(TestMessage { at, by }) => Line::Test(TestLine {
            sink: origin.sink.clone(),
            at: *at,
            by: by.clone(),
        }),
    })
}

/// The JSON text of an event, on one line.
///
/// # Errors
///
/// [`CodecError`] when the record cannot be encoded.
pub fn render(origin: &Origin, event: &Event<'_>) -> Result<String, CodecError> {
    serde_json::to_string(&line(origin, event)?)
        .map_err(|error| CodecError::Encode(error.to_string()))
}

/// Why a line does not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    /// The line is longer than [`MAX_LINE`].
    #[error("the line is longer than {MAX_LINE} bytes")]
    TooLong,
    /// The line is not a JSON export line.
    #[error("the line is not an export line: {0}")]
    Malformed(String),
    /// `cbor` is not valid base64.
    #[error("record {0}: cbor is not valid base64")]
    Base64(AuditSeq),
    /// `SHA-256(cbor)` is not the record's hash.
    #[error("record {0}: the canonical bytes do not match the hash")]
    CborHash(AuditSeq),
    /// `cbor` does not encode the fields of the line.
    #[error("record {0}: the canonical bytes do not match the fields")]
    CborFields(AuditSeq),
}

/// Reads one line. A record line is checked for itself: `cbor` must be valid base64,
/// hash to `hash`, and encode exactly the fields of the line. The chain (sequence, link and
/// hash of the fields) is the caller's to check with `ChainVerifier`.
///
/// # Errors
///
/// [`LineError`] for the first problem.
pub fn parse_line(text: &str) -> Result<Line, LineError> {
    if text.len() > MAX_LINE {
        return Err(LineError::TooLong);
    }
    let line: Line =
        serde_json::from_str(text).map_err(|error| LineError::Malformed(error.to_string()))?;
    if let Line::Record(record_line) = &line {
        let seq = record_line.record.seq;
        let cbor = base64_decode(&record_line.cbor).ok_or(LineError::Base64(seq))?;
        let digest: [u8; 32] = Sha256::digest(&cbor).into();
        if Digest(digest) != record_line.record.hash {
            return Err(LineError::CborHash(seq));
        }
        let fields = hashed_bytes(&record_line.record).map_err(|_| LineError::CborFields(seq))?;
        if fields != cbor {
            return Err(LineError::CborFields(seq));
        }
    }
    Ok(line)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |word, (i, &b)| word | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (word >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64 with padding; `None` for anything else.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (index, quad) in bytes.chunks(4).enumerate() {
        let padding = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && index + 1 != quads) {
            return None;
        }
        let mut word = 0u32;
        for &c in &quad[..4 - padding] {
            word = word << 6 | value(c)?;
        }
        word <<= 6 * padding;
        let [_, a, b, c] = word.to_be_bytes();
        // Non-canonical padding bits would let two texts decode to the same bytes.
        if (padding == 1 && c != 0) || (padding == 2 && (b != 0 || c != 0)) {
            return None;
        }
        out.push(a);
        if padding < 2 {
            out.push(b);
        }
        if padding < 1 {
            out.push(c);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use tenko_core::audit::{ChainHead, verify_chain};

    use super::super::tests::{chain, origin};
    use super::*;

    #[test]
    fn the_canonical_bytes_hash_to_the_record_hash() {
        for record in chain(3) {
            let digest: [u8; 32] = Sha256::digest(hashed_bytes(&record).expect("cbor")).into();
            assert_eq!(Digest(digest), record.hash);
        }
    }

    #[test]
    fn record_lines_read_back_and_verify() {
        let records = chain(3);
        let mut read = Vec::new();
        for record in &records {
            let text = render(&origin(), &Event::Record(record)).expect("renders");
            assert!(text.starts_with(r#"{"type":"record","#), "{text}");
            let Line::Record(line) = parse_line(&text).expect("parses") else {
                panic!("record line");
            };
            read.push(line.record);
        }
        assert_eq!(read, records);
        verify_chain(&read).expect("verifies");
    }

    #[test]
    fn checkpoint_and_test_lines_read_back() {
        let checkpoint = Checkpoint {
            head: ChainHead::default(),
            store_head: AuditSeq(9),
            at: "2026-10-11T12:00:00Z".parse().expect("time"),
        };
        let text = render(&origin(), &Event::Checkpoint(&checkpoint)).expect("renders");
        assert_eq!(
            parse_line(&text).expect("parses"),
            Line::Checkpoint(CheckpointLine {
                sink: "siem".to_owned(),
                seq: AuditSeq(0),
                hash: Digest::ZERO,
                store_head: AuditSeq(9),
                at: checkpoint.at,
            })
        );
        let message = TestMessage {
            at: checkpoint.at,
            by: "system:api".to_owned(),
        };
        let text = render(&origin(), &Event::Test(&message)).expect("renders");
        assert!(matches!(parse_line(&text), Ok(Line::Test(_))));
    }

    #[test]
    fn tampering_with_fields_or_bytes_is_found() {
        let record = &chain(1)[0];
        let text = render(&origin(), &Event::Record(record)).expect("renders");
        let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
        value["revision"] = serde_json::json!(99);
        assert_eq!(
            parse_line(&value.to_string()),
            Err(LineError::CborFields(AuditSeq(1)))
        );
        let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
        let mut cbor = base64_decode(value["cbor"].as_str().expect("cbor")).expect("base64");
        cbor[3] ^= 1;
        value["cbor"] = serde_json::json!(base64_encode(&cbor));
        assert_eq!(
            parse_line(&value.to_string()),
            Err(LineError::CborHash(AuditSeq(1)))
        );
        value["cbor"] = serde_json::json!("not base64!");
        assert_eq!(
            parse_line(&value.to_string()),
            Err(LineError::Base64(AuditSeq(1)))
        );
        assert!(matches!(parse_line("{}"), Err(LineError::Malformed(_))));
        assert!(matches!(parse_line("[1]"), Err(LineError::Malformed(_))));
    }

    #[test]
    fn base64_round_trips_and_refuses_garbage() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37 % 256).expect("byte"))
                .collect();
            let text = base64_encode(&bytes);
            assert_eq!(base64_decode(&text), Some(bytes));
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
        for bad in ["T", "TQ=", "TQ==TQ==", "TR==", "TWF=", "TW!u", "===="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }
}
