//! The three export formats (S3-Q6) and what a sink writes for each event.
//!
//! An [`Event`] is an audit record, a chain checkpoint or a test message. [`render`] turns
//! it into the bytes of one message, without the transport's framing (octet counting on
//! TCP and TLS, a newline in a file):
//!
//! | Format | Syslog sink | File sink |
//! |---|---|---|
//! | `rfc5424` | RFC 5424 header, structured data `[tenko@32473 …]`, BOM, the JSON form | the same line without the BOM |
//! | `cef` | RFC 5424 header without structured data, the CEF line | the CEF line |
//! | `json` | RFC 5424 header without structured data, the JSON form | the JSON form (JSON lines) |
//!
//! The JSON form ([`json`]) carries every field of the record plus `cbor`, the canonical
//! bytes the hash covers, so a receiver can check `SHA-256(cbor) = hash` and the link
//! `prev` without Tenko. 32473 is the documentation enterprise number of RFC 5612, used
//! until a number is registered.

pub mod cef;
pub mod json;
pub mod syslog;

use tenko_core::{
    AuditSeq, Timestamp,
    audit::{AuditOutcome, AuditRecord, ChainHead},
    codec::CodecError,
};

use super::model::{ExportFormat, Facility};

/// The SD-ID of Tenko's structured data element (RFC 5424 section 6.3.2; RFC 5612).
pub const SD_ID: &str = "tenko@32473";
/// The APP-NAME of the syslog header.
pub const APP_NAME: &str = "tenko";
/// The MSGID of an audit record.
pub const MSGID_RECORD: &str = "audit";
/// The MSGID of a chain checkpoint.
pub const MSGID_CHECKPOINT: &str = "checkpoint";
/// The MSGID of a test message.
pub const MSGID_TEST: &str = "test";

/// Who writes: the header fields that do not come from the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The HOSTNAME of the syslog header; `-` when unknown.
    pub hostname: String,
    /// The product version for the CEF header.
    pub version: String,
    /// The sink's name, carried by checkpoints and test messages.
    pub sink: String,
}

/// A chain checkpoint: the last record a sink was sent, so a receiver sees truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// The last record sent before the checkpoint ([`super::model::START`] before any).
    pub head: ChainHead,
    /// The newest record of the log when the checkpoint was sent.
    pub store_head: AuditSeq,
    /// When it was sent.
    pub at: Timestamp,
}

/// A test message (`POST /settings/audit-export/test`); not part of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestMessage {
    /// When it was sent.
    pub at: Timestamp,
    /// The subject of the principal that asked for it, such as `user:<uuid>`.
    pub by: String,
}

/// What a sink sends.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// An audit record.
    Record(&'a AuditRecord),
    /// A chain checkpoint.
    Checkpoint(&'a Checkpoint),
    /// A test message.
    Test(&'a TestMessage),
}

impl Event<'_> {
    /// The MSGID of the syslog header.
    pub fn msgid(&self) -> &'static str {
        match self {
            Event::Record(_) => MSGID_RECORD,
            Event::Checkpoint(_) => MSGID_CHECKPOINT,
            Event::Test(_) => MSGID_TEST,
        }
    }

    /// The time of the event: the record's time, so that a duplicate after a failover
    /// carries the same header.
    pub fn at(&self) -> Timestamp {
        match self {
            Event::Record(record) => record.at,
            Event::Checkpoint(checkpoint) => checkpoint.at,
            Event::Test(test) => test.at,
        }
    }

    /// The syslog severity (RFC 5424 section 6.2.1): 5 (notice) for a success, 4
    /// (warning) for a denied or failed action, 6 (informational) for a checkpoint or a
    /// test.
    pub fn syslog_severity(&self) -> u8 {
        match self {
            Event::Record(record) => match record.draft.outcome {
                AuditOutcome::Success => 5,
                AuditOutcome::Denied | AuditOutcome::Failed { .. } => 4,
            },
            Event::Checkpoint(_) | Event::Test(_) => 6,
        }
    }

    /// The CEF severity (0 to 10): 3 for a success, 6 for a failure, 7 for a denial, 1
    /// for a checkpoint or a test.
    pub fn cef_severity(&self) -> u8 {
        match self {
            Event::Record(record) => match record.draft.outcome {
                AuditOutcome::Success => 3,
                AuditOutcome::Failed { .. } => 6,
                AuditOutcome::Denied => 7,
            },
            Event::Checkpoint(_) | Event::Test(_) => 1,
        }
    }

    /// The parameters of Tenko's structured data element.
    pub fn sd_params(&self) -> Vec<(&'static str, String)> {
        match self {
            Event::Record(record) => vec![
                ("seq", record.seq.to_string()),
                ("hash", record.hash.to_string()),
                ("prev", record.prev.to_string()),
            ],
            Event::Checkpoint(checkpoint) => vec![
                ("checkpoint", "1".to_owned()),
                ("seq", checkpoint.head.seq.to_string()),
                ("hash", checkpoint.head.hash.to_string()),
                ("store_head", checkpoint.store_head.to_string()),
            ],
            Event::Test(_) => vec![("test", "1".to_owned())],
        }
    }
}

/// Where the message goes: a syslog transport (with a header) or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// UDP, TCP or TLS: every format gets the RFC 5424 header.
    Syslog(Facility),
    /// A file: one line per message; only `rfc5424` has a header.
    File,
}

/// Renders one event as the bytes of one message, without transport framing. The result
/// never contains a line break, so a file sink writes it as one line.
///
/// # Errors
///
/// [`CodecError`] when the record cannot be encoded.
pub fn render(
    format: ExportFormat,
    framing: Framing,
    origin: &Origin,
    event: &Event<'_>,
) -> Result<Vec<u8>, CodecError> {
    let facility = match framing {
        Framing::Syslog(facility) => facility,
        Framing::File => Facility::default(),
    };
    let header = syslog::Header {
        facility,
        severity: event.syslog_severity(),
        at: event.at(),
        hostname: &origin.hostname,
        msgid: event.msgid(),
    };
    let text = match (format, framing) {
        (ExportFormat::Json, Framing::File) => json::render(origin, event)?,
        (ExportFormat::Cef, Framing::File) => cef::render(origin, event),
        (ExportFormat::Rfc5424, framing) => {
            let params = event.sd_params();
            let element = syslog::SdElement {
                id: SD_ID,
                params: params
                    .iter()
                    .map(|(name, value)| (*name, value.as_str()))
                    .collect(),
            };
            syslog::message(
                &header,
                &[element],
                &json::render(origin, event)?,
                framing != Framing::File,
            )
        }
        (ExportFormat::Json, Framing::Syslog(_)) => {
            syslog::message(&header, &[], &json::render(origin, event)?, false)
        }
        (ExportFormat::Cef, Framing::Syslog(_)) => {
            syslog::message(&header, &[], &cef::render(origin, event), false)
        }
    };
    Ok(text.into_bytes())
}

#[cfg(test)]
pub(crate) mod tests {
    use tenko_core::{
        Principal, RequestId, Revision, SystemComponent,
        audit::{AuditAction, AuditDraft, Digest, FieldChange},
        id::HostId,
    };

    use super::*;

    /// A sealed chain of `len` records with documentation values.
    pub(crate) fn chain(len: u64) -> Vec<AuditRecord> {
        let mut prev = Digest::ZERO;
        (1..=len)
            .map(|seq| {
                let draft = AuditDraft::success(
                    AuditAction::from_static("ipam.host.create"),
                    vec![HostId::generate().into()],
                )
                .with_source_ip(Some("203.0.113.5".parse().expect("ip")))
                .with_context("note", "line one\nline \"two\" ] | = \\")
                .with_change(FieldChange {
                    object: None,
                    field: "name".to_owned(),
                    old: None,
                    new: Some(format!("host{seq}.example.test")),
                });
                let record = AuditRecord::seal(
                    AuditSeq(seq),
                    Revision(seq * 2),
                    "2026-10-11T12:00:00.123456789Z".parse().expect("time"),
                    Principal::system(SystemComponent::Ipam),
                    Some(RequestId::generate()),
                    draft,
                    prev,
                )
                .expect("seal");
                prev = record.hash;
                record
            })
            .collect()
    }

    pub(crate) fn origin() -> Origin {
        Origin {
            hostname: "ctl1.example.test".to_owned(),
            version: "0.0.1".to_owned(),
            sink: "siem".to_owned(),
        }
    }

    #[test]
    fn every_format_renders_one_line() {
        let records = chain(1);
        let checkpoint = Checkpoint {
            head: ChainHead {
                seq: records[0].seq,
                hash: records[0].hash,
            },
            store_head: AuditSeq(1),
            at: records[0].at,
        };
        let test = TestMessage {
            at: records[0].at,
            by: "user:00000000-0000-0000-0000-000000000001".to_owned(),
        };
        let events = [
            Event::Record(&records[0]),
            Event::Checkpoint(&checkpoint),
            Event::Test(&test),
        ];
        for format in [ExportFormat::Rfc5424, ExportFormat::Cef, ExportFormat::Json] {
            for framing in [Framing::File, Framing::Syslog(Facility::LogAudit)] {
                for event in &events {
                    let bytes = render(format, framing, &origin(), event).expect("renders");
                    assert!(!bytes.contains(&b'\n'), "{format:?} {framing:?}");
                    assert!(!bytes.contains(&b'\r'), "{format:?} {framing:?}");
                    let line = String::from_utf8(bytes).expect("UTF-8");
                    let syslog_header =
                        matches!(framing, Framing::Syslog(_)) || format == ExportFormat::Rfc5424;
                    assert_eq!(line.starts_with('<'), syslog_header, "{line}");
                    if format == ExportFormat::Rfc5424 {
                        assert!(line.contains("[tenko@32473 "), "{line}");
                    }
                }
            }
        }
    }

    #[test]
    fn severities_follow_the_outcome() {
        let mut records = chain(1);
        assert_eq!(Event::Record(&records[0]).syslog_severity(), 5);
        assert_eq!(Event::Record(&records[0]).cef_severity(), 3);
        records[0].draft.outcome = AuditOutcome::Denied;
        assert_eq!(Event::Record(&records[0]).syslog_severity(), 4);
        assert_eq!(Event::Record(&records[0]).cef_severity(), 7);
    }
}
