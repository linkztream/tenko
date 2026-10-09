//! `tenko export prefixes|addresses|hosts`: CSV in the import vocabulary (MIG-14), to
//! standard output or a file.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::{ClientOpts, Failure, Output, Target};

/// What to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportKind {
    /// `GET /exports/prefixes.csv`.
    Prefixes,
    /// `GET /exports/addresses.csv`.
    Addresses,
    /// `GET /exports/hosts.csv`.
    Hosts,
}

impl ExportKind {
    /// The API path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Prefixes => "/exports/prefixes.csv",
            Self::Addresses => "/exports/addresses.csv",
            Self::Hosts => "/exports/hosts.csv",
        }
    }
}

/// Arguments of `tenko export`.
#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// What to export.
    #[arg(value_enum, value_name = "WHAT")]
    pub kind: ExportKind,

    /// Write the CSV to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Runs `tenko export`.
///
/// # Errors
///
/// The [`Failure`] of the request or of writing the file.
pub async fn run(args: &ExportArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let csv = target.client()?.get_text(args.kind.path()).await?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, csv.as_bytes()).map_err(|error| {
                Failure::other(format!("cannot write {}: {error}", path.display()))
            })?;
            let rows = csv.lines().count().saturating_sub(1);
            Ok(Output::default().note(format!("{rows} row(s) written to {}", path.display())))
        }
        None => Ok(Output::text(csv)),
    }
}
