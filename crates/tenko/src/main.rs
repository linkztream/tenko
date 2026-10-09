//! Entry point of the `tenko` binary. The exit statuses are documented in [`tenko::exit`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = tenko::Cli::parse();
    // Unlocked handles: the server writes to both from other threads while this one waits.
    let status = tenko::execute(&cli, &mut std::io::stdout(), &mut std::io::stderr());
    ExitCode::from(status)
}
