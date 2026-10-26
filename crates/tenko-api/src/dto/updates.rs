//! Bodies of the update endpoints under `/system/updates` (OPS-24, TGL-23, R17).
//!
//! The server checks a release source on a schedule (nothing but the running version is
//! sent), keeps the last release manifest, and reports here what is newer, whether this
//! installation can install it from the UI, and how the last attempt went. The notes of
//! every newer release travel with the status ([`Release::notes`], Markdown), with security
//! fixes and required actions marked.

use serde::{Deserialize, Serialize};
use tenko_core::{JobId, Timestamp};
use utoipa::{IntoParams, ToSchema};

use super::release::{Release, ReleaseVersion};

/// How an administrator may install a new version (TGL-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstallPolicy {
    /// Download from the release source and install from the UI (Home, Lab).
    Ui,
    /// As `ui`, with a fresh authentication (step-up) for every install (Standard).
    UiStepUp,
    /// Only an uploaded release file, with step-up (Hardened).
    UploadOnly,
}

/// Why the scheduled check does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckOff {
    /// `updates.air_gapped` in `tenko.toml`: the server never contacts the release source.
    AirGapped,
    /// The check is switched off in the security settings (TGL-23).
    Setting,
}

/// The scheduled check of the release source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateCheck {
    /// Whether the check runs.
    pub enabled: bool,
    /// Why it does not.
    pub off_reason: Option<CheckOff>,
    /// The URL of the release manifest.
    pub source: String,
    /// Hours between two checks.
    pub interval_hours: u32,
    /// When the source was last asked.
    pub last_checked: Option<Timestamp>,
    /// The code of the last failed check, for example `update.fetch_failed`.
    pub last_error: Option<String>,
}

/// Where the stored release manifest came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestOrigin {
    /// Fetched from the release source.
    Fetched,
    /// Uploaded by an administrator (air-gapped installations).
    Uploaded,
}

/// The stored release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ManifestInfo {
    /// Where it came from.
    pub origin: ManifestOrigin,
    /// When it was fetched or uploaded.
    pub at: Timestamp,
    /// Releases it lists.
    pub releases: usize,
}

/// Why an installation path is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstallBlock {
    /// The server runs in a container: pull the new image instead.
    Container,
    /// The store has more than one voter; the rolling order arrives with OPS-08.
    Cluster,
    /// The binary does not run from the `current` link layout (`docs/upgrades.md`).
    LayoutMissing,
    /// No service manager restarts the server after the switch (systemd, the Windows
    /// service, or `TENKO_SUPERVISED=1` for another supervisor).
    Unsupervised,
    /// No release is published for this platform.
    UnsupportedPlatform,
    /// TGL-23 allows only uploaded release files (Hardened).
    UploadOnly,
    /// `updates.air_gapped`: nothing is downloaded; upload the release file.
    AirGapped,
    /// The newest release has no file for this platform.
    NoAsset,
    /// The running version is the newest one.
    UpToDate,
    /// An install is running or waits for its restart.
    InProgress,
}

/// How this installation can install a new version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InstallAbility {
    /// The policy of TGL-23.
    pub policy: InstallPolicy,
    /// Installing needs a fresh authentication (step-up).
    pub step_up: bool,
    /// `POST /system/updates/install` would start now.
    pub from_source: bool,
    /// Why it would not.
    pub from_source_blocked: Option<InstallBlock>,
    /// `POST /system/updates/upload` is possible.
    pub upload: bool,
    /// Why it is not.
    pub upload_blocked: Option<InstallBlock>,
    /// Containers: the command that pulls the newest image.
    pub pull_command: Option<String>,
    /// Seconds a new version has to become ready before it is switched back.
    pub ready_timeout_secs: u64,
    /// The backup before an install: how old the newest good backup is and what an install
    /// request must say about a backup.
    pub backup: PreUpdateBackupStatus,
}

/// The answer of an install or upload request to "take a backup first?" (ADR 0023).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreUpdateBackup {
    /// The install job takes a backup as its first step, wrapped to the configured
    /// recipient, and fails before anything changed when the backup fails.
    Run,
    /// No backup; the install's audit record says so and who decided it. Refused under the
    /// Hardened profile (TGL-37).
    Skip,
}

/// The backup before an install, as `GET /system/updates` reports it.
///
/// A request without `backup` installs only while a good backup is younger than
/// `max_age_seconds`; otherwise it is refused with 409 `update.backup_required`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreUpdateBackupStatus {
    /// Seconds since the newest good backup of any controller; absent when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
    /// The age up to which a good backup counts as recent (one hour).
    pub max_age_seconds: u64,
    /// Whether `backup: "skip"` is accepted; not under the Hardened profile (TGL-37).
    pub skip_allowed: bool,
    /// Whether a backup recipient is configured. Without one a backup needs a passphrase:
    /// `backup: "run"` is refused with 422 `backup.key.missing`, and the UI asks for a
    /// passphrase for `POST /system/backups`.
    pub recipient: bool,
}

impl PreUpdateBackupStatus {
    /// Whether a good backup is younger than the limit.
    pub fn recent(&self) -> bool {
        self.age_seconds
            .is_some_and(|age| age < self.max_age_seconds)
    }
}

/// The state of an install attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// The install job runs: download, verification, dry run.
    Installing,
    /// The new version is in place; the server restarts into it.
    Restarting,
    /// The new version became ready.
    Confirmed,
    /// The new version did not become ready in time and the previous one runs again.
    RolledBack,
    /// The install job failed before the switch; nothing changed.
    Failed,
}

/// The last install attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateAttempt {
    /// The version before.
    pub from: ReleaseVersion,
    /// The version installed.
    pub to: ReleaseVersion,
    /// Where it stands.
    pub state: AttemptState,
    /// When it reached this state.
    pub at: Timestamp,
    /// The install job.
    pub job_id: Option<JobId>,
    /// The code of a failure or of the reason for a switch back.
    pub reason: Option<String>,
}

/// `GET /system/updates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateStatus {
    /// The running version.
    pub running: ReleaseVersion,
    /// The data-directory format of the running binary.
    pub format: u32,
    /// The platform of this server, `<os>-<arch>`.
    pub platform: String,
    /// The newest release in the manifest.
    pub latest: Option<ReleaseVersion>,
    /// A release newer than the running one exists.
    pub update_available: bool,
    /// A newer release fixes security issues.
    pub security: bool,
    /// A newer release needs an action when upgrading.
    pub requires_action: bool,
    /// The releases newer than the running one, newest first, with their notes.
    pub releases: Vec<Release>,
    /// The stored manifest.
    pub manifest: Option<ManifestInfo>,
    /// The scheduled check.
    pub check: UpdateCheck,
    /// How a new version can be installed.
    pub install: InstallAbility,
    /// The last install attempt.
    pub attempt: Option<UpdateAttempt>,
}

/// `POST /system/updates/install`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InstallRequest {
    /// The version to install; it must be in the manifest and newer than the running one.
    pub version: ReleaseVersion,
    /// Take a backup first (`run`) or not (`skip`). Without it the install starts only
    /// while a good backup is younger than `install.backup.max_age_seconds` of the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<PreUpdateBackup>,
}

/// The answer of `POST /system/updates/install` and `POST /system/updates/upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InstallStarted {
    /// The install job: download (or the uploaded file), verification, dry run and switch.
    /// The server restarts into the new version when it succeeds.
    pub job_id: JobId,
    /// The version being installed.
    pub version: ReleaseVersion,
}

/// Query of `POST /system/updates/upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct UploadQuery {
    /// The version of the uploaded file; the manifest must list it with a file for this
    /// platform, whose SHA-256 the upload must match.
    pub version: ReleaseVersion,
    /// Take a backup first (`run`) or not (`skip`), as in `POST /system/updates/install`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<PreUpdateBackup>,
}

/// `GET /system/updates/whats-new`: the notes to show a user once after an upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WhatsNew {
    /// The running version.
    pub running: ReleaseVersion,
    /// The version whose notes the user saw last; `null` for a user who never saw any.
    pub last_seen: Option<ReleaseVersion>,
    /// Whether to show the notes now: the user saw an older version's notes.
    pub show: bool,
    /// The releases after `last_seen` up to the running one, newest first.
    pub releases: Vec<Release>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_use_snake_case_names() {
        assert_eq!(
            serde_json::to_value(InstallPolicy::UiStepUp).expect("json"),
            "ui_step_up"
        );
        assert_eq!(
            serde_json::to_value(InstallBlock::LayoutMissing).expect("json"),
            "layout_missing"
        );
        assert_eq!(
            serde_json::to_value(AttemptState::RolledBack).expect("json"),
            "rolled_back"
        );
        assert_eq!(
            serde_json::to_value(CheckOff::AirGapped).expect("json"),
            "air_gapped"
        );
        assert_eq!(
            serde_json::to_value(PreUpdateBackup::Skip).expect("json"),
            "skip"
        );
    }

    #[test]
    fn the_backup_field_is_optional_and_a_backup_is_recent_below_the_limit() {
        let request: InstallRequest =
            serde_json::from_str(r#"{"version":"0.2.0"}"#).expect("without backup");
        assert_eq!(request.backup, None);
        let request: InstallRequest =
            serde_json::from_str(r#"{"version":"0.2.0","backup":"run"}"#).expect("run");
        assert_eq!(request.backup, Some(PreUpdateBackup::Run));
        let status = |age_seconds| PreUpdateBackupStatus {
            age_seconds,
            max_age_seconds: 3_600,
            skip_allowed: true,
            recipient: true,
        };
        assert!(status(Some(3_599)).recent());
        assert!(!status(Some(3_600)).recent());
        assert!(!status(None).recent());
    }
}
