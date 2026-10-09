//! Entry point of the `tenko` binary.

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<ExitCode> {
    // Logs go to standard error; `RUST_LOG` overrides the default `info` level.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = tenko::Cli::parse();
    let status = tenko::execute(
        &cli,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )?;
    Ok(ExitCode::from(status))
}
