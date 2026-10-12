//! Backups and restores (OPS-07, owner decision S3-Q11, WP3.4b): the command
//! `tenko backup`.
//!
//! A backup is one encrypted `TKBK1` file (ADR 0016) with the store snapshot, the key
//! generations wrapped under the backup key, the imported TLS files and optionally the
//! configuration.
//!
//! | Module | What |
//! |---|---|
//! | [`archive`] | the container: header, key slots, chunk stream, manifest, parts |
//! | [`keys`] | recipient key files and the passphrase rule |
//! | [`create`] | writing a backup from a running or a stopped store |
//! | [`restore`] | checking a backup and restoring it as a single controller |
//! | [`model`] | the replicated settings, backup records and restore record |
//! | [`service`] | the backups of `tenko serve`: API, schedule, status, the restore record |
//! | [`cli`] | `tenko backup keygen`, `create`, `verify` and `restore` |

pub mod archive;
pub mod cli;
pub mod create;
mod error;
pub mod keys;
pub mod model;
pub mod restore;
pub mod service;
#[cfg(test)]
mod tests;

use std::io::Write;

use clap::Subcommand;

pub use self::error::BackupError;

/// Subcommands of `tenko backup`.
#[derive(Debug, Clone, Subcommand)]
pub enum BackupCommand {
    /// Create a recipient key file; the recipient it prints goes into the backup settings.
    Keygen(cli::KeygenArgs),
    /// Write an encrypted backup: online through the controller at `--url`, or of a
    /// stopped node with `--config` or `--data-dir`.
    Create(Box<cli::CreateArgs>),
    /// Check a backup file: decrypt it, verify every part, the store digest, the audit
    /// chain and every secret.
    Verify(cli::VerifyArgs),
    /// Restore a backup into a data directory without a store (`--dry-run` checks only).
    Restore(cli::RestoreArgs),
}

impl BackupCommand {
    /// The command as typed, such as `backup create`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Keygen(_) => "backup keygen",
            Self::Create(_) => "backup create",
            Self::Verify(_) => "backup verify",
            Self::Restore(_) => "backup restore",
        }
    }
}

/// Runs `tenko backup …`.
pub fn command(action: &BackupCommand, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let name = action.name();
    match action {
        BackupCommand::Keygen(args) => cli::finish(name, false, cli::keygen(args), out, err),
        BackupCommand::Create(args) => {
            cli::finish(name, args.client.json, cli::create(args), out, err)
        }
        BackupCommand::Verify(args) => cli::finish(name, args.json, cli::verify(args), out, err),
        BackupCommand::Restore(args) => cli::finish(name, args.json, cli::restore(args), out, err),
    }
}
