//! Backups and restores (OPS-07, owner decision S3-Q11, WP3.4b): the command
//! `tenko backup`.
//!
//! WP3.0 created this module with the command line in its final place; the backup package
//! (WP3.4b) fills it: an encrypted `TKBK1` container with the store snapshot, the key
//! generations wrapped under the backup key, the imported TLS files and optionally the
//! configuration; `create` online through the API or offline with `--data-dir`, `verify`
//! and `restore` onto a new data directory.

use std::io::Write;

use clap::Subcommand;

use crate::Pending;

/// Subcommands of `tenko backup`. Each one is a stub until WP3.4b implements it: it prints
/// that it is not available in this build and exits with status 2.
#[derive(Debug, Clone, Subcommand)]
pub enum BackupCommand {
    /// Write an encrypted backup of the installation.
    Create(Pending),
    /// Check a backup file: decrypt, verify every part and the audit chain.
    Verify(Pending),
    /// Restore a backup into a new data directory.
    Restore(Pending),
}

impl BackupCommand {
    /// The command as typed, such as `backup create`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create(_) => "backup create",
            Self::Verify(_) => "backup verify",
            Self::Restore(_) => "backup restore",
        }
    }
}

/// Runs `tenko backup …`.
pub fn command(action: &BackupCommand, err: &mut impl Write) -> u8 {
    crate::not_available(action.name(), err)
}
