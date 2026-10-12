//! The replicated state of backups: the settings, the record of every backup a controller
//! wrote, and the record of a restore. The tables live in the namespace `backup`, which
//! the event stream maps to the topic `system`.

use serde::{Deserialize, Serialize};
use tenko_core::{JobId, ObjectKind, ObjectRef, Timestamp};
use uuid::Uuid;

/// The store tables.
pub mod tables {
    use tenko_core::table::TableDef;
    use uuid::Uuid;

    use super::{BackupRun, BackupSettings, RestoreRecord};

    /// The settings (singleton).
    pub const SETTINGS: TableDef<(), BackupSettings> = TableDef::new("backup.settings");
    /// The backups written, by run id (UUID v7, so in time order).
    pub const RUNS: TableDef<Uuid, BackupRun> = TableDef::new("backup.runs");
    /// The last restore (singleton).
    pub const RESTORE: TableDef<(), RestoreRecord> = TableDef::new("backup.restore");
}

/// Audit actions.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A backup was written, or failed.
    pub const CREATE: AuditAction = AuditAction::from_static("sys.backup.create");
    /// The backup settings changed.
    pub const SETTINGS: AuditAction = AuditAction::from_static("sys.backup.settings");
    /// The installation started for the first time after a restore.
    pub const RESTORE: AuditAction = AuditAction::from_static("sys.backup.restore");
}

/// How many backup records the store keeps; older ones are removed when a new one is
/// written.
pub const KEEP_RUNS: usize = 100;

/// The default interval of scheduled backups, in hours.
pub const DEFAULT_INTERVAL_HOURS: u32 = 24;
/// The longest interval, in hours (one week).
pub const MAX_INTERVAL_HOURS: u32 = 168;
/// The default number of backup files the schedule keeps.
pub const DEFAULT_KEEP: u32 = 7;
/// The largest keep count.
pub const MAX_KEEP: u32 = 365;

/// The backup settings of the installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSettings {
    /// Scheduled backups run (off by default, S3-Q11).
    pub enabled: bool,
    /// Hours between scheduled backups.
    pub interval_hours: u32,
    /// Backup files the schedule keeps in the target directory.
    pub keep: u32,
    /// The target directory on every controller; `None`: `[backup] target_dir` of the host,
    /// else `<data_dir>/backups`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_dir: Option<String>,
    /// The recipient (`tkbr1:…`) that backups are wrapped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Whether backups include the configuration file of the controller.
    pub include_config: bool,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_hours: DEFAULT_INTERVAL_HOURS,
            keep: DEFAULT_KEEP,
            target_dir: None,
            recipient: None,
            include_config: true,
        }
    }
}

/// Why a backup was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunReason {
    /// Through the API.
    Manual,
    /// By the schedule.
    Scheduled,
}

impl RunReason {
    /// `manual` or `scheduled`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
        }
    }
}

/// A failure, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunError {
    /// The error code.
    pub code: String,
    /// The English detail.
    pub detail: String,
}

/// One backup a controller wrote, or tried to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRun {
    /// Why it was made.
    pub reason: RunReason,
    /// The controller that wrote it.
    pub node: u64,
    /// The directory it went to, on that controller.
    pub target_dir: String,
    /// The file name, once written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The size of the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// The store revision it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// The kinds of its key slots (`passphrase`, `recipient`).
    #[serde(default)]
    pub slots: Vec<String>,
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
    /// Who asked: a principal subject, or `system`.
    pub by: String,
    /// The inline job that recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobId>,
    /// Why it failed; absent for a good backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RunError>,
}

impl BackupRun {
    /// Whether the backup was written completely.
    pub fn is_good(&self) -> bool {
        self.error.is_none() && self.file.is_some()
    }
}

/// The record of a restore, written at the first start after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRecord {
    /// When the restore ran.
    pub restored_at: Timestamp,
    /// When the server first started from it.
    pub started_at: Timestamp,
    /// When the backup was made.
    pub backup_created_at: Timestamp,
    /// The backup file name.
    pub file: String,
    /// The node the backup was made on.
    pub source_node: u64,
    /// The voters of the source.
    pub source_voters: Vec<u64>,
    /// The revision of the backup.
    pub revision: u64,
    /// The node it was restored as.
    pub node: u64,
}

/// The object audit records of backups name: the system.
pub fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

#[cfg(test)]
mod tests {
    use tenko_core::{audit::AuditAction, table::TableDef};

    use super::*;

    #[test]
    fn the_defaults_keep_the_schedule_off() {
        let settings = BackupSettings::default();
        assert!(!settings.enabled);
        assert_eq!(settings.interval_hours, 24);
        assert_eq!(settings.keep, 7);
        assert!(settings.include_config);
        let _: (TableDef<(), BackupSettings>, AuditAction) = (tables::SETTINGS, actions::CREATE);
    }
}
