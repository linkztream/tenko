//! The audit export (IAM-18, TGL-21, S3-Q6): the audit log leaves the installation as
//! syslog (RFC 5424 over UDP, TCP or TLS), CEF or JSON lines, with chain checkpoints, so a
//! receiver sees gaps by sequence number, truncation by checkpoint and tampering by hash.
//!
//! # Map
//!
//! | Module | Contents |
//! |---|---|
//! | [`model`] | the settings with their sinks, the cursors, validation, the tables |
//! | [`format`] | RFC 5424, CEF and the JSON form with the canonical bytes |
//! | [`sink`] | the transports: UDP, TCP, TLS and a file rotated by size |
//! | [`exporter`] | the leader service that delivers the log to every sink |
//! | [`status`] | the state of every sink, the TGL-21 policy and the status warnings |
//! | [`admin`] | the settings service of the API: read, replace with audit, test |
//! | [`verify`] | offline verification of a JSON export (`tenko audit verify --file`) |
//! | [`error`] | the `audit.export.*` codes |
//!
//! Docs: `docs/audit-export.md`.

pub mod admin;
pub mod error;
pub mod exporter;
pub mod format;
pub mod model;
pub mod sink;
pub mod status;
pub mod verify;

pub use error::{ExportError, FailureKind, SinkError};
#[cfg(test)]
mod tests;
