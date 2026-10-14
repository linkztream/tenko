#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

use phase1_metrics::{pairs, responder};

/// M8: the cost of the tenko-core metrics on the hot path of a UDP DNS responder.
#[derive(Parser)]
#[command(name = "phase1-metrics", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the responder, with the metrics on or off, until standard input closes.
    Serve(responder::ServeArgs),
    /// Run paired loads (metrics off and on, alternating first) and print the table.
    Pairs(pairs::PairsArgs),
    /// Print the tables of JSONL files written by `pairs`.
    Report(pairs::ReportArgs),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => responder::run(&args),
        Command::Pairs(args) => pairs::run(&args),
        Command::Report(args) => pairs::report(&args),
    }
}
