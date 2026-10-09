//! Entry point of the `tenko-server` binary.

use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    // Logs go to standard error; `RUST_LOG` overrides the default `info` level.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let args = tenko_server::Args::parse();
    tenko_server::run(&args, &mut std::io::stdout().lock())
}
