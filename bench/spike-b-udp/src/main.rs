#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

use spike_b_udp::{load, matrix, report, server};

/// Spike B: raw UDP DNS throughput and DNS wire-format crate comparison.
#[derive(Parser)]
#[command(name = "spike-b-udp", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the minimal authoritative UDP responder for `example.test`.
    Serve(server::ServeArgs),
    /// Generate closed-loop query load against a server and report QPS and latency.
    Load(load::LoadArgs),
    /// Run the backend x mode x workers matrix: spawn `serve`, run `load`, record JSONL.
    Matrix(matrix::MatrixArgs),
    /// Render Markdown tables from JSONL result files.
    Report(report::ReportArgs),
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
        Command::Serve(args) => server::run(&args),
        Command::Load(args) => load::run(&args),
        Command::Matrix(args) => matrix::run(&args),
        Command::Report(args) => report::run(&args),
    }
}
