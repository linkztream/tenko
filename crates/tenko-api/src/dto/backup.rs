//! The bodies of the backup endpoints (OPS-07, ADR 0016) and the backup fragment of
//! `GET /system/status`.

use serde::{Deserialize, Serialize};
use tenko_core::{JobId, Revision, Timestamp};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{release::ReleaseVersion, system::StatusWarning};

/// The backup settings of the installation, the same on every controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupSettingsView {
    /// Whether scheduled backups run (off until an administrator turns them on).
    pub enabled: bool,
    /// Hours between scheduled backups, 1 to 168.
    pub interval_hours: u32,
    /// Backup files the schedule keeps in the target directory, 1 to 365; older ones are
    /// deleted after each scheduled backup.
    pub keep: u32,
    /// An absolute directory for backup files on every controller; absent: each
    /// controller's `[backup] target_dir`, else `backups/` in its data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_dir: Option<String>,
    /// The recipient key (`tkbr1:` and 43 base64url characters) that every backup is
    /// encrypted to; `tenko backup keygen` creates the key file that opens them. Scheduled
    /// backups need one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Whether backups include the configuration file of the controller that writes them.
    pub include_config: bool,
    /// The directory the controller that answers writes to.
    pub effective_target_dir: String,
    /// The store revision of the settings, for `If-Match`; absent while they were never
    /// saved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

/// New backup settings (all fields; the stored settings are replaced).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupSettingsUpdate {
    /// Whether scheduled backups run; turning them on needs a recipient.
    pub enabled: bool,
    /// Hours between scheduled backups, 1 to 168.
    pub interval_hours: u32,
    /// Backup files the schedule keeps, 1 to 365.
    pub keep: u32,
    /// An absolute directory, or absent for each controller's default.
    #[serde(default)]
    pub target_dir: Option<String>,
    /// The recipient key, or absent.
    #[serde(default)]
    pub recipient: Option<String>,
    /// Whether backups include the configuration file.
    pub include_config: bool,
}

/// A request to write a backup now.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupCreateRequest {
    /// A passphrase of at least 12 characters that opens this backup, in addition to the
    /// configured recipient. It is used once and never stored.
    #[serde(default)]
    #[schema(format = Password)]
    pub passphrase: Option<String>,
    /// The version an update is about to install: the backup is recorded with the reason
    /// `before_update` and this version, as the restore point before that update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_update: Option<ReleaseVersion>,
}

impl std::fmt::Debug for BackupCreateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupCreateRequest")
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("before_update", &self.before_update)
            .finish()
    }
}

/// Why a backup was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupReason {
    /// Through the API or the UI.
    Manual,
    /// By the schedule.
    Scheduled,
    /// Before an update, as its restore point; `before_update` names the version.
    BeforeUpdate,
}

/// Whether a backup was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupOutcome {
    /// The file is complete.
    Succeeded,
    /// It failed; `error` says why.
    Failed,
}

/// Why a backup failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupFailure {
    /// The error code, such as `backup.io`.
    pub code: String,
    /// What went wrong, in English.
    pub detail: String,
}

/// One backup a controller wrote, or tried to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupRunView {
    /// The record.
    pub id: Uuid,
    /// The outcome.
    pub outcome: BackupOutcome,
    /// Why it was made.
    pub reason: BackupReason,
    /// For the reason `before_update`: the version the update was about to install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_update: Option<ReleaseVersion>,
    /// The controller that wrote it.
    pub node: u64,
    /// The directory on that controller.
    pub target_dir: String,
    /// The file name, for a good backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The size of the file in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// The store revision the backup holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
    /// What opens it: `passphrase`, `recipient`.
    pub slots: Vec<String>,
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
    /// Who asked: a principal subject such as `user:<id>`, or `system`.
    pub by: String,
    /// The inline job `backup.create` that recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobId>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<BackupFailure>,
}

/// The restore this installation was started from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RestoreNoticeView {
    /// When the restore ran.
    pub restored_at: Timestamp,
    /// When the server first started from it.
    pub started_at: Timestamp,
    /// When the backup was made.
    pub backup_created_at: Timestamp,
    /// The backup file name.
    pub file: String,
    /// The controller the backup was made on.
    pub source_node: u64,
    /// The store revision of the backup.
    pub revision: Revision,
    /// The controller it was restored as.
    pub node: u64,
}

/// Backups: the settings, the last backups and the conditions to look at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupStatusView {
    /// The settings.
    pub settings: BackupSettingsView,
    /// The newest good backup of any controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_good: Option<BackupRunView>,
    /// The newest failed backup, when it is newer than the last good one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed: Option<BackupRunView>,
    /// Seconds since the last good backup was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
    /// When the next scheduled backup is due; absent while the schedule is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_due_at: Option<Timestamp>,
    /// Whether a backup runs on the controller that answers.
    pub running: bool,
    /// The newest backups, newest first (at most 20).
    pub recent: Vec<BackupRunView>,
    /// The restore this installation started from; shown until the next good backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<RestoreNoticeView>,
    /// Conditions to look at: `backup.stale`, `backup.failed`, `backup.restored`.
    pub warnings: Vec<StatusWarning>,
}

/// The backup fragment of `GET /system/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupSummaryView {
    /// Whether scheduled backups run.
    pub schedule_enabled: bool,
    /// When the last good backup was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_good_at: Option<Timestamp>,
    /// Seconds since then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
    /// When the last backup failed, if that is newer than the last good one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_at: Option<Timestamp>,
    /// When the restore this installation started from ran, until the next good backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_at: Option<Timestamp>,
}
