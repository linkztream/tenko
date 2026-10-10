//! What the scanner asks of the operating system: commands (`ip`, PowerShell, `ping`) and
//! files (`/proc/net/arp`, `/etc/resolv.conf`). Behind a trait, so tests replay recorded
//! outputs instead of reading the tables of the machine they run on.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;

use crate::error::ScanError;

/// Longest output of a command that is kept.
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// The result of a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// The exit status; `None` when the process was killed.
    pub status: Option<i32>,
    /// Standard output, lossy UTF-8.
    pub stdout: String,
    /// Standard error, lossy UTF-8.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the command exited with status 0.
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

/// The operating system as the scanner sees it.
#[async_trait]
pub trait System: Send + Sync + std::fmt::Debug {
    /// Runs `program` with `args`, without a shell, and waits at most `timeout`.
    ///
    /// # Errors
    ///
    /// `scan.io` when the program cannot start or does not finish in time.
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, ScanError>;

    /// Reads a text file.
    ///
    /// # Errors
    ///
    /// `scan.io` when it cannot be read.
    fn read(&self, path: &Path) -> Result<String, ScanError>;

    /// Whether a file exists.
    fn exists(&self, path: &Path) -> bool;
}

/// The real operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostSystem;

#[async_trait]
impl System for HostSystem {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, ScanError> {
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW: a service or a console session gets no flashing window.
            command.creation_flags(0x0800_0000);
        }
        let child = command
            .spawn()
            .map_err(|error| ScanError::io(format!("cannot run {program}: {error}")))?;
        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                ScanError::io(format!(
                    "{program} did not finish within {} s",
                    timeout.as_secs()
                ))
            })?
            .map_err(|error| ScanError::io(format!("{program} failed: {error}")))?;
        let text = |bytes: &[u8]| {
            String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned()
        };
        Ok(CommandOutput {
            status: output.status.code(),
            stdout: text(&output.stdout),
            stderr: text(&output.stderr),
        })
    }

    fn read(&self, path: &Path) -> Result<String, ScanError> {
        std::fs::read(path)
            .map(|bytes| {
                String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned()
            })
            .map_err(|error| ScanError::io(format!("cannot read {}: {error}", path.display())))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// A system that answers from recorded outputs: commands by their program and arguments
/// joined with spaces, files by path. Anything not recorded fails like a missing program.
#[derive(Debug, Clone, Default)]
pub struct RecordedSystem {
    commands: Arc<Mutex<BTreeMap<String, CommandOutput>>>,
    files: Arc<Mutex<BTreeMap<PathBuf, String>>>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordedSystem {
    /// An empty recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the output of a command line (`program arg arg`).
    #[must_use]
    pub fn command(self, line: &str, status: i32, stdout: &str) -> Self {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                line.to_owned(),
                CommandOutput {
                    status: Some(status),
                    stdout: stdout.to_owned(),
                    stderr: String::new(),
                },
            );
        self
    }

    /// Records a file.
    #[must_use]
    pub fn file(self, path: impl Into<PathBuf>, text: &str) -> Self {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.into(), text.to_owned());
        self
    }

    /// The command lines run so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl System for RecordedSystem {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _timeout: Duration,
    ) -> Result<CommandOutput, ScanError> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.clone());
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&line)
            .cloned()
            .ok_or_else(|| ScanError::io(format!("cannot run {program}: not recorded")))
    }

    fn read(&self, path: &Path) -> Result<String, ScanError> {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(path)
            .cloned()
            .ok_or_else(|| ScanError::io(format!("cannot read {}: not recorded", path.display())))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recorded_commands_and_files_replay() {
        let system = RecordedSystem::new()
            .command("ip -6 neigh show", 0, "2001:db8::1 dev eth0 FAILED\n")
            .file("/proc/net/arp", "IP address\n");
        let output = system
            .run("ip", &["-6", "neigh", "show"], Duration::from_secs(1))
            .await
            .expect("recorded");
        assert!(output.success());
        assert!(output.stdout.contains("2001:db8::1"));
        assert!(
            system
                .run("ping", &[], Duration::from_secs(1))
                .await
                .is_err()
        );
        assert_eq!(system.calls(), ["ip -6 neigh show", "ping"]);
        assert!(system.exists(Path::new("/proc/net/arp")));
        assert!(system.read(Path::new("/etc/resolv.conf")).is_err());
    }
}
