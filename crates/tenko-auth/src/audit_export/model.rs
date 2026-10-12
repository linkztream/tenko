//! The stored model of the audit export: the settings with their sinks and the cursor of
//! every sink, with validation.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `sys.audit_export_settings` | `()` | [`AuditExportSettings`]: the sinks and the alarm delay |
//! | `sys.audit_export_cursors` | sink id | [`ExportCursor`]: delivery position, last checkpoint, failure state |
//!
//! Both tables live in the store (plan section 2.6): every controller sees the same sinks,
//! and the controller that takes over the export after a leader change resumes from the
//! cursors of the previous one. The last checkpoint of a sink is part of its cursor row, so
//! a checkpoint costs no write of its own.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tenko_core::{
    AuditSeq, SecretId, Timestamp,
    audit::{ChainHead, Digest},
    table::TableDef,
};
use utoipa::ToSchema;
use uuid::Uuid;

use super::error::ExportError;

/// The settings: one row under the unit key.
pub const SETTINGS: TableDef<(), AuditExportSettings> = TableDef::new("sys.audit_export_settings");
/// The cursor of every sink, by sink id.
pub const CURSORS: TableDef<Uuid, ExportCursor> = TableDef::new("sys.audit_export_cursors");

/// The most sinks the settings hold.
pub const MAX_SINKS: usize = 8;
/// The longest sink name, in characters.
pub const MAX_NAME: usize = 64;
/// The longest PEM text (a CA bundle or a client certificate chain), in bytes.
pub const MAX_PEM: usize = 64 * 1024;
/// The default delay before a failing sink raises the alarm `audit.export.failing`.
pub const DEFAULT_ALERT_AFTER_SECS: u32 = 300;
/// The shortest and longest alarm delay.
pub const ALERT_AFTER_RANGE: std::ops::RangeInclusive<u32> = 10..=86_400;
/// The default size at which a file sink rotates.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The smallest and largest rotation size of a file sink.
pub const MAX_BYTES_RANGE: std::ops::RangeInclusive<u64> = 64 * 1024..=(1 << 40);
/// The default number of rotated files a file sink keeps.
pub const DEFAULT_KEEP: u32 = 10;
/// The most rotated files a file sink keeps.
pub const MAX_KEEP: u32 = 1000;

/// How an exported record is written (S3-Q6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// RFC 5424 with the structured data `[tenko@32473 seq= hash= prev=]` and the record as
    /// JSON in the message.
    #[default]
    Rfc5424,
    /// `ArcSight` Common Event Format.
    Cef,
    /// One JSON object per record with every field of the record and its canonical CBOR.
    Json,
}

impl ExportFormat {
    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfc5424 => "rfc5424",
            Self::Cef => "cef",
            Self::Json => "json",
        }
    }
}

/// The transport of a syslog sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    /// RFC 5426: one message per datagram, no delivery guarantee.
    Udp,
    /// RFC 6587 octet counting over plain TCP.
    Tcp,
    /// RFC 5425: octet counting over TLS (the default, S3-Q6).
    #[default]
    Tls,
}

impl SyslogTransport {
    /// The port of the transport when the sink names none.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 514,
            Self::Tls => 6514,
        }
    }

    /// The stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

/// The syslog facility of the messages (RFC 5424 section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Facility {
    /// 1: user-level messages.
    User,
    /// 3: system daemons.
    Daemon,
    /// 4: security and authorization messages.
    Auth,
    /// 10: security and authorization messages (private).
    #[default]
    Authpriv,
    /// 13: log audit.
    LogAudit,
    /// 16: local use 0.
    Local0,
    /// 17: local use 1.
    Local1,
    /// 18: local use 2.
    Local2,
    /// 19: local use 3.
    Local3,
    /// 20: local use 4.
    Local4,
    /// 21: local use 5.
    Local5,
    /// 22: local use 6.
    Local6,
    /// 23: local use 7.
    Local7,
}

impl Facility {
    /// The numeric facility code.
    pub const fn code(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Authpriv => 10,
            Self::LogAudit => 13,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

/// TLS options of a syslog sink over TLS (RFC 5425).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct TlsOptions {
    /// The certificate authorities that sign the receiver's certificate, in PEM. Empty: the
    /// operating system's roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// The name the receiver's certificate must carry. Empty: the sink's host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// The client certificate chain in PEM, leaf first, when the receiver asks for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_pem: Option<String>,
    /// The operator secret that holds the client certificate's private key in PEM
    /// (PKCS #8, SEC1 or PKCS #1). Required with `client_cert_pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub client_key: Option<SecretId>,
}

/// A syslog receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SyslogTarget {
    /// UDP, TCP or TLS.
    #[serde(default)]
    pub transport: SyslogTransport,
    /// The receiver's host name or address.
    pub host: String,
    /// The receiver's port; empty: 514 for UDP and TCP, 6514 for TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The facility of the messages.
    #[serde(default)]
    pub facility: Facility,
    /// TLS options; used with the TLS transport only.
    #[serde(default)]
    pub tls: TlsOptions,
}

impl SyslogTarget {
    /// The port the sink connects to.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(self.transport.default_port())
    }
}

/// A JSON lines (or other format) file on the controller that exports, rotated by size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FileTarget {
    /// The file name inside the export directory of the controller (`[audit_export]
    /// file_dir`, by default `<data_dir>/audit-export`); no directories.
    pub file: String,
    /// The size in bytes at which the file rotates.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// How many rotated files (`<file>.1` to `<file>.<keep>`) are kept.
    #[serde(default = "default_keep")]
    pub keep: u32,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

fn default_keep() -> u32 {
    DEFAULT_KEEP
}

/// Where a sink sends the records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SinkTarget {
    /// A syslog receiver over UDP, TCP or TLS.
    Syslog(SyslogTarget),
    /// A file on the exporting controller.
    File(FileTarget),
}

/// A sink as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Sink {
    /// The stable id; the cursor of the sink is kept under it.
    pub id: Uuid,
    /// A name for people.
    pub name: String,
    /// Whether the sink exports; a disabled sink keeps its cursor.
    pub enabled: bool,
    /// How records are written.
    pub format: ExportFormat,
    /// Where they go.
    pub target: SinkTarget,
}

/// A sink as a client writes it: the id is optional for a new sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SinkSpec {
    /// The id of an existing sink; empty for a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// A name for people.
    pub name: String,
    /// Whether the sink exports (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How records are written (default `rfc5424`).
    #[serde(default)]
    pub format: ExportFormat,
    /// Where they go.
    pub target: SinkTarget,
}

fn default_true() -> bool {
    true
}

/// The stored settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportSettings {
    /// The sinks.
    #[serde(default)]
    pub sinks: Vec<Sink>,
    /// Seconds a sink may fail before the alarm `audit.export.failing` (default 300).
    #[serde(default = "default_alert_after")]
    pub alert_after_secs: u32,
}

impl Default for AuditExportSettings {
    fn default() -> Self {
        Self {
            sinks: Vec::new(),
            alert_after_secs: DEFAULT_ALERT_AFTER_SECS,
        }
    }
}

fn default_alert_after() -> u32 {
    DEFAULT_ALERT_AFTER_SECS
}

impl AuditExportSettings {
    /// Whether at least one sink is enabled (what TGL-21 `required` asks for).
    pub fn has_enabled_sink(&self) -> bool {
        self.sinks.iter().any(|sink| sink.enabled)
    }

    /// The sink with this id.
    pub fn sink(&self, id: Uuid) -> Option<&Sink> {
        self.sinks.iter().find(|sink| sink.id == id)
    }
}

/// The settings as a client writes them (`PUT /settings/audit-export`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportUpdate {
    /// The complete list of sinks: sinks left out are removed with their cursors.
    #[serde(default)]
    pub sinks: Vec<SinkSpec>,
    /// Seconds a sink may fail before the alarm (default 300, from 10 to 86,400).
    #[serde(default = "default_alert_after")]
    pub alert_after_secs: u32,
}

impl AuditExportUpdate {
    /// Validates the update and turns it into settings: names are trimmed, new sinks get
    /// an id, and every value is checked. `known` lists the ids of the stored sinks: an id
    /// that is neither known nor new is refused, so a client cannot pick ids.
    ///
    /// # Errors
    ///
    /// [`ExportError::Invalid`] with one field error per problem.
    pub fn validate(self, known: &BTreeSet<Uuid>) -> Result<AuditExportSettings, ExportError> {
        let mut problems = Vec::new();
        if !ALERT_AFTER_RANGE.contains(&self.alert_after_secs) {
            problems.push(invalid("alert_after_secs", "audit.export.range"));
        }
        if self.sinks.len() > MAX_SINKS {
            problems.push(invalid("sinks", "audit.export.too_many"));
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut sinks = Vec::with_capacity(self.sinks.len());
        for (index, spec) in self.sinks.into_iter().enumerate() {
            let at = |field: &str| format!("sinks[{index}].{field}");
            let id = match spec.id {
                Some(id) if !known.contains(&id) => {
                    problems.push(invalid(at("id"), "audit.export.unknown_sink"));
                    id
                }
                Some(id) => id,
                None => Uuid::now_v7(),
            };
            if !ids.insert(id) {
                problems.push(invalid(at("id"), "audit.export.duplicate"));
            }
            let name = spec.name.trim().to_owned();
            if name.is_empty()
                || name.chars().count() > MAX_NAME
                || name.chars().any(char::is_control)
            {
                problems.push(invalid(at("name"), "audit.export.name"));
            } else if !names.insert(name.to_lowercase()) {
                problems.push(invalid(at("name"), "audit.export.duplicate"));
            }
            let target = match spec.target {
                SinkTarget::Syslog(target) => {
                    SinkTarget::Syslog(validate_syslog(target, &at, &mut problems))
                }
                SinkTarget::File(target) => {
                    validate_file(&target, &at, &mut problems);
                    SinkTarget::File(target)
                }
            };
            sinks.push(Sink {
                id,
                name,
                enabled: spec.enabled,
                format: spec.format,
                target,
            });
        }
        if problems.is_empty() {
            Ok(AuditExportSettings {
                sinks,
                alert_after_secs: self.alert_after_secs,
            })
        } else {
            Err(ExportError::Invalid(problems))
        }
    }
}

fn invalid(field: impl Into<String>, code: &'static str) -> tenko_core::FieldError {
    tenko_core::FieldError::new(field, code)
}

/// Trims empty optional texts to `None`.
fn non_empty(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn validate_syslog(
    target: SyslogTarget,
    at: &dyn Fn(&str) -> String,
    problems: &mut Vec<tenko_core::FieldError>,
) -> SyslogTarget {
    let host = target.host.trim().to_owned();
    if !valid_host(&host) {
        problems.push(invalid(at("target.host"), "audit.export.host"));
    }
    if target.port == Some(0) {
        problems.push(invalid(at("target.port"), "audit.export.port"));
    }
    let tls = TlsOptions {
        ca_pem: non_empty(target.tls.ca_pem),
        server_name: non_empty(target.tls.server_name),
        client_cert_pem: non_empty(target.tls.client_cert_pem),
        client_key: target.tls.client_key,
    };
    if target.transport == SyslogTransport::Tls {
        for (field, pem) in [
            ("target.tls.ca_pem", &tls.ca_pem),
            ("target.tls.client_cert_pem", &tls.client_cert_pem),
        ] {
            if let Some(pem) = pem
                && (pem.len() > MAX_PEM || !pem.contains("-----BEGIN CERTIFICATE-----"))
            {
                problems.push(invalid(at(field), "audit.export.pem"));
            }
        }
        if let Some(name) = &tls.server_name
            && !valid_host(name)
        {
            problems.push(invalid(at("target.tls.server_name"), "audit.export.host"));
        }
        if tls.client_cert_pem.is_some() != tls.client_key.is_some() {
            problems.push(invalid(
                at("target.tls.client_key"),
                "audit.export.client_key",
            ));
        }
    } else if tls != TlsOptions::default() {
        problems.push(invalid(at("target.tls"), "audit.export.tls_unused"));
    }
    SyslogTarget {
        transport: target.transport,
        host,
        port: target.port,
        facility: target.facility,
        tls,
    }
}

fn validate_file(
    target: &FileTarget,
    at: &dyn Fn(&str) -> String,
    problems: &mut Vec<tenko_core::FieldError>,
) {
    if !valid_file_name(&target.file) {
        problems.push(invalid(at("target.file"), "audit.export.file"));
    }
    if !MAX_BYTES_RANGE.contains(&target.max_bytes) {
        problems.push(invalid(at("target.max_bytes"), "audit.export.range"));
    }
    if target.keep > MAX_KEEP {
        problems.push(invalid(at("target.keep"), "audit.export.range"));
    }
}

/// A host name (letters, digits, `-`, `_` and dots), an IPv4 or an IPv6 address.
pub fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A plain file name: 1 to 128 characters of letters, digits, `-`, `_` and `.`, not
/// starting with a dot, so it cannot leave the export directory or hide.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A failure of a sink, as the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SinkFailure {
    /// The stable code, such as `audit.export.connect`.
    pub code: String,
    /// An English description (never a secret).
    pub detail: String,
    /// When it happened.
    pub at: Timestamp,
}

/// A checkpoint a sink has sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CheckpointMark {
    /// The chain position the checkpoint names: the last record sent before it.
    pub head: ChainHead,
    /// When it was sent.
    pub at: Timestamp,
}

/// The progress and failure state of a sink, written by the exporting controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExportCursor {
    /// The last record handed to the sink; the export resumes after it. A controller that
    /// takes over may send records after this position again (at least once).
    pub delivered: ChainHead,
    /// When the row was written.
    pub updated_at: Timestamp,
    /// The last checkpoint sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointMark>,
    /// When the last successful delivery happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<Timestamp>,
    /// Since when the sink fails without a success in between.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<Timestamp>,
    /// The last failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<SinkFailure>,
    /// Whether the alarm of the current failure was recorded (an audit record
    /// `audit.export.failing`); cleared with the recovery.
    #[serde(default)]
    pub alarmed: bool,
}

impl ExportCursor {
    /// The cursor of a sink that has exported nothing.
    pub fn start(now: Timestamp) -> Self {
        Self {
            delivered: ChainHead::default(),
            updated_at: now,
            checkpoint: None,
            last_success_at: None,
            failing_since: None,
            last_error: None,
            alarmed: false,
        }
    }

    /// Whether the alarm is due: the sink fails for at least `alert_after`.
    pub fn alarm_due(&self, now: Timestamp, alert_after: std::time::Duration) -> bool {
        self.failing_since
            .is_some_and(|since| now.saturating_since(since) >= alert_after)
    }
}

/// The chain head before the first record.
pub const START: ChainHead = ChainHead {
    seq: AuditSeq::NONE,
    hash: Digest::ZERO,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn syslog(transport: SyslogTransport) -> SinkTarget {
        SinkTarget::Syslog(SyslogTarget {
            transport,
            host: "siem.example.test".to_owned(),
            port: None,
            facility: Facility::default(),
            tls: TlsOptions::default(),
        })
    }

    fn spec(name: &str, target: SinkTarget) -> SinkSpec {
        SinkSpec {
            id: None,
            name: name.to_owned(),
            enabled: true,
            format: ExportFormat::default(),
            target,
        }
    }

    fn update(sinks: Vec<SinkSpec>) -> AuditExportUpdate {
        AuditExportUpdate {
            sinks,
            alert_after_secs: DEFAULT_ALERT_AFTER_SECS,
        }
    }

    fn codes(error: &ExportError) -> Vec<(String, String)> {
        match error {
            ExportError::Invalid(problems) => problems
                .iter()
                .map(|p| (p.field.clone(), p.code.to_string()))
                .collect(),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn defaults_follow_the_decision() {
        let target: SyslogTarget =
            serde_json::from_str(r#"{"host":"192.0.2.10"}"#).expect("decodes");
        assert_eq!(target.transport, SyslogTransport::Tls);
        assert_eq!(target.port(), 6514);
        assert_eq!(target.facility.code(), 10);
        let spec: SinkSpec = serde_json::from_str(
            r#"{"name":"siem","target":{"kind":"file","file":"audit.jsonl"}}"#,
        )
        .expect("decodes");
        assert!(spec.enabled);
        assert_eq!(spec.format, ExportFormat::Rfc5424);
        let SinkTarget::File(file) = spec.target else {
            panic!("file target");
        };
        assert_eq!(
            (file.max_bytes, file.keep),
            (DEFAULT_MAX_BYTES, DEFAULT_KEEP)
        );
        let settings: AuditExportSettings = serde_json::from_str("{}").expect("decodes");
        assert_eq!(settings, AuditExportSettings::default());
        assert!(!settings.has_enabled_sink());
    }

    #[test]
    fn a_valid_update_gets_ids_and_trimmed_names() {
        let settings = update(vec![
            spec(" siem ", syslog(SyslogTransport::Udp)),
            spec(
                "file",
                SinkTarget::File(FileTarget {
                    file: "audit.jsonl".to_owned(),
                    max_bytes: DEFAULT_MAX_BYTES,
                    keep: 3,
                }),
            ),
        ])
        .validate(&BTreeSet::new())
        .expect("valid");
        assert_eq!(settings.sinks.len(), 2);
        assert_eq!(settings.sinks[0].name, "siem");
        assert_ne!(settings.sinks[0].id, settings.sinks[1].id);
        assert!(settings.has_enabled_sink());
    }

    #[test]
    fn known_ids_are_kept_and_unknown_ids_refused() {
        let known = Uuid::now_v7();
        let mut kept = spec("a", syslog(SyslogTransport::Tcp));
        kept.id = Some(known);
        let settings = update(vec![kept.clone()])
            .validate(&BTreeSet::from([known]))
            .expect("valid");
        assert_eq!(settings.sinks[0].id, known);
        let error = update(vec![kept.clone(), kept])
            .validate(&BTreeSet::new())
            .expect_err("unknown");
        let found = codes(&error);
        assert!(found.contains(&(
            "sinks[0].id".to_owned(),
            "audit.export.unknown_sink".to_owned()
        )));
        assert!(found.contains(&(
            "sinks[1].id".to_owned(),
            "audit.export.duplicate".to_owned()
        )));
        assert!(found.contains(&(
            "sinks[1].name".to_owned(),
            "audit.export.duplicate".to_owned()
        )));
    }

    #[test]
    fn invalid_values_are_named() {
        let mut bad_tls = SyslogTarget {
            transport: SyslogTransport::Tls,
            host: "bad host".to_owned(),
            port: Some(0),
            facility: Facility::Local3,
            tls: TlsOptions {
                ca_pem: Some("not a pem".to_owned()),
                server_name: Some("..".to_owned()),
                client_cert_pem: Some("-----BEGIN CERTIFICATE-----x".to_owned()),
                client_key: None,
            },
        };
        let mut sinks = vec![
            spec("", SinkTarget::Syslog(bad_tls.clone())),
            spec(
                "f",
                SinkTarget::File(FileTarget {
                    file: "../etc/passwd".to_owned(),
                    max_bytes: 10,
                    keep: MAX_KEEP + 1,
                }),
            ),
        ];
        bad_tls.transport = SyslogTransport::Udp;
        bad_tls.host = "198.51.100.7".to_owned();
        bad_tls.port = None;
        sinks.push(spec("udp", SinkTarget::Syslog(bad_tls)));
        let mut update = update(sinks);
        update.alert_after_secs = 1;
        let found: Vec<String> = codes(&update.validate(&BTreeSet::new()).expect_err("invalid"))
            .into_iter()
            .map(|(field, code)| format!("{field}={code}"))
            .collect();
        assert_eq!(
            found,
            [
                "alert_after_secs=audit.export.range",
                "sinks[0].name=audit.export.name",
                "sinks[0].target.host=audit.export.host",
                "sinks[0].target.port=audit.export.port",
                "sinks[0].target.tls.ca_pem=audit.export.pem",
                "sinks[0].target.tls.server_name=audit.export.host",
                "sinks[0].target.tls.client_key=audit.export.client_key",
                "sinks[1].target.file=audit.export.file",
                "sinks[1].target.max_bytes=audit.export.range",
                "sinks[1].target.keep=audit.export.range",
                "sinks[2].target.tls=audit.export.tls_unused",
            ]
        );
    }

    #[test]
    fn too_many_sinks_are_refused() {
        let sinks = (0..=MAX_SINKS)
            .map(|i| spec(&format!("s{i}"), syslog(SyslogTransport::Udp)))
            .collect();
        let found = codes(
            &update(sinks)
                .validate(&BTreeSet::new())
                .expect_err("too many"),
        );
        assert_eq!(
            found,
            [("sinks".to_owned(), "audit.export.too_many".to_owned())]
        );
    }

    #[test]
    fn hosts_and_file_names() {
        for host in ["siem.example.test", "192.0.2.1", "2001:db8::1", "log_host"] {
            assert!(valid_host(host), "{host}");
        }
        for host in ["", "a..b", "a b", "a/b", &"x".repeat(64)] {
            assert!(!valid_host(host), "{host}");
        }
        for name in ["audit.jsonl", "a-b_c.log"] {
            assert!(valid_file_name(name), "{name}");
        }
        for name in ["", ".hidden", "a/b", "..", "a\\b", "c:x", &"x".repeat(129)] {
            assert!(!valid_file_name(name), "{name}");
        }
    }

    #[test]
    fn the_alarm_is_due_after_the_delay() {
        let since: Timestamp = "2026-10-11T12:00:00Z".parse().expect("time");
        let mut cursor = ExportCursor::start(since);
        let delay = std::time::Duration::from_secs(300);
        let later = since.checked_add(delay).expect("time");
        assert!(!cursor.alarm_due(later, delay));
        cursor.failing_since = Some(since);
        assert!(!cursor.alarm_due(since, delay));
        assert!(cursor.alarm_due(later, delay));
    }

    #[test]
    fn tables_are_in_the_system_namespace() {
        assert_eq!(SETTINGS.name().as_str(), "sys.audit_export_settings");
        assert_eq!(CURSORS.name().as_str(), "sys.audit_export_cursors");
    }
}
