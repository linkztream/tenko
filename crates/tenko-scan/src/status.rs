//! The files of the scanner in `<data_dir>/scan/`: the status the running scanner writes
//! for `tenko node scan status`, the known addresses, and the kill switch.
//!
//! The kill switch is the file `stop`: while it exists, every running scan stops and no
//! method starts, on schedule or on demand. `tenko node scan stop` creates it and `tenko
//! node scan resume` removes it, so it works across processes and survives a restart.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;

use crate::{
    capability::Capabilities,
    error::ScanError,
    method::{Availability, MethodKind},
};

/// The directory below the data directory.
pub const SCAN_DIR: &str = "scan";

/// Where the scanner keeps its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPaths {
    dir: PathBuf,
}

impl ScanPaths {
    /// The files below `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(SCAN_DIR),
        }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The status of the running scanner.
    pub fn status(&self) -> PathBuf {
        self.dir.join("status.json")
    }

    /// The known addresses.
    pub fn known(&self) -> PathBuf {
        self.dir.join("known.json")
    }

    /// The kill switch.
    pub fn kill_switch(&self) -> PathBuf {
        self.dir.join("stop")
    }

    /// Whether the kill switch is on.
    pub fn killed(&self) -> bool {
        self.kill_switch().exists()
    }

    /// Turns the kill switch on, recording who and when in the file.
    ///
    /// # Errors
    ///
    /// `scan.io` when the file cannot be written.
    pub fn kill(&self, reason: &str) -> Result<(), ScanError> {
        let text = format!("{} {}\n", Timestamp::now(), reason.trim());
        write_atomically(&self.kill_switch(), text.as_bytes())
    }

    /// Turns the kill switch off; whether it was on.
    ///
    /// # Errors
    ///
    /// `scan.io` when the file exists and cannot be removed.
    pub fn resume(&self) -> Result<bool, ScanError> {
        match std::fs::remove_file(self.kill_switch()) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(ScanError::io(format!(
                "cannot remove {}: {error}",
                self.kill_switch().display()
            ))),
        }
    }

    /// Reads the status the scanner wrote; `None` when there is none.
    pub fn read_status(&self) -> Option<ScanStatus> {
        std::fs::read(self.status())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }
}

/// Writes `bytes` to `path` through a temporary file and a rename, creating the directory.
///
/// # Errors
///
/// `scan.io` when a step fails.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), ScanError> {
    let fail = |error: std::io::Error| ScanError::io(format!("{}: {error}", path.display()));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let temporary = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&temporary).map_err(fail)?;
        file.write_all(bytes).map_err(fail)?;
        file.sync_all().map_err(fail)?;
    }
    std::fs::rename(&temporary, path).map_err(fail)
}

/// What a method is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodState {
    /// Waiting for its next run.
    Idle,
    /// Waiting for the other methods to report once (it works on their addresses).
    WaitingForAddresses,
    /// Running.
    Running,
    /// Held by a blackout window.
    Blackout,
    /// Held by the kill switch.
    Stopped,
    /// Switched off in the configuration, or by `active = false`.
    Disabled,
    /// It cannot run on this host or with this configuration.
    Unavailable,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// It covered everything; the batch is complete.
    Complete,
    /// It covered part (a narrower target, a device that did not answer); the batch is
    /// not complete.
    Partial,
    /// The kill switch, a blackout window, the deadline or the shutdown stopped it; what
    /// it saw so far went out as a batch that is not complete.
    Cancelled,
    /// It could not run; no batch.
    Failed,
}

/// The last run of a method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// When it started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
    /// How it ended.
    pub outcome: RunOutcome,
    /// Sightings in the batch.
    pub sightings: usize,
    /// Probes sent.
    pub probes: u64,
    /// Whether a batch was handed on (a run with nothing to report and nothing to expire
    /// hands on none).
    #[serde(default)]
    pub queued: bool,
    /// Whether it was started on demand.
    #[serde(default)]
    pub on_demand: bool,
    /// The target of an on-demand run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The error of a failed run, or what stopped it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why the batch of the run could not be handed on (a full buffer, a disk error); the
    /// sightings of the run are lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_error: Option<String>,
    /// Notes of the method (devices that did not answer and so on).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// One method in the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodStatus {
    /// The method.
    pub method: MethodKind,
    /// Whether it is switched on in the configuration.
    pub enabled: bool,
    /// Whether it can run here.
    pub availability: Availability,
    /// What it is doing.
    pub state: MethodState,
    /// Seconds between two runs.
    pub interval_secs: u64,
    /// Seconds a sighting stays current.
    pub ttl_secs: u64,
    /// When it runs next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<Timestamp>,
    /// Its last run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<RunRecord>,
}

/// The status of the running scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStatus {
    /// When it was written.
    pub updated_at: Timestamp,
    /// The process that writes it.
    pub pid: u32,
    /// Whether the kill switch is on.
    pub kill_switch: bool,
    /// The prefixes.
    pub prefixes: Vec<String>,
    /// The exclusions.
    pub exclude: Vec<String>,
    /// Whether active probing is on (TGL-18).
    pub active: bool,
    /// Probes per second; `None` is unlimited (TGL-19).
    pub per_second: Option<u32>,
    /// The blackout windows.
    pub blackout: Vec<String>,
    /// Their time zone.
    pub timezone: String,
    /// The end of the blackout in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackout_until: Option<Timestamp>,
    /// What the host allows.
    pub capabilities: Capabilities,
    /// Addresses known from recent sightings.
    pub known_addresses: usize,
    /// The methods, in scheduling order.
    pub methods: Vec<MethodStatus>,
}

impl ScanStatus {
    /// The status of one method.
    pub fn method(&self, kind: MethodKind) -> Option<&MethodStatus> {
        self.methods.iter().find(|status| status.method == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kill_switch_is_a_file() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = ScanPaths::new(dir.path());
        assert!(!paths.killed());
        assert!(!paths.resume().expect("resume"));
        paths.kill("operator request").expect("kill");
        assert!(paths.killed());
        let text = std::fs::read_to_string(paths.kill_switch()).expect("read");
        assert!(text.contains("operator request"));
        assert!(paths.resume().expect("resume"));
        assert!(!paths.killed());
        assert!(paths.read_status().is_none());
    }
}
