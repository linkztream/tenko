//! `tenko system diagnostics`: the diagnostics of a bug report (`GET /system/diagnostics`),
//! printed as the same text the UI's "Report a bug" dialog shows, redacted by the node
//! before it answers (addresses, host names, zone names and account names are numbered
//! placeholders). With `--json` the whole document, the text included.

use clap::{Args, Subcommand};
use tenko_api::dto::system::SystemDiagnostics;

use super::{ClientOpts, Failure, Output, Target};

/// Subcommands of `tenko system`.
#[derive(Debug, Clone, Subcommand)]
pub enum SystemCommand {
    /// Print the diagnostics of a bug report, redacted: version, platform, security
    /// profile, roles, modules, uptime, the active health findings and the last log lines
    /// at warn level or above.
    Diagnostics(DiagnosticsArgs),
}

impl SystemCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            SystemCommand::Diagnostics(args) => &args.client,
        }
    }

    /// The command name for messages: `system diagnostics`.
    pub fn name(&self) -> &'static str {
        match self {
            SystemCommand::Diagnostics(_) => "system diagnostics",
        }
    }
}

/// Arguments of `tenko system diagnostics`.
#[derive(Debug, Clone, Args)]
pub struct DiagnosticsArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Runs `tenko system <command>`.
///
/// # Errors
///
/// The [`Failure`] of the command.
pub async fn run(command: &SystemCommand) -> Result<Output, Failure> {
    match command {
        SystemCommand::Diagnostics(args) => diagnostics(args).await,
    }
}

async fn diagnostics(args: &DiagnosticsArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let client = target.connect().await?;
    let document: SystemDiagnostics = client.get("/system/diagnostics").await?;
    if target.json {
        return Ok(Output::json(&document));
    }
    Ok(Output::text(document.text))
}
