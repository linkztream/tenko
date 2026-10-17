#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

use phase2_dns::{load, report, zonegen};

/// Phase 2 DNS bench harness: load generator, zone generator, report renderer.
#[derive(Parser)]
#[command(name = "phase2-dns", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate query load against a DNS server and report QPS and latency.
    Load(load::LoadArgs),
    /// Render Markdown tables from JSONL result files.
    Report(report::ReportArgs),
    /// Write the Phase 2 zone files and a query file for a data set size.
    Zonegen(zonegen::ZonegenArgs),
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Load(args) => load::run(&args),
        Command::Report(args) => report::run(&args),
        Command::Zonegen(args) => zonegen::run(&args),
    }
}
