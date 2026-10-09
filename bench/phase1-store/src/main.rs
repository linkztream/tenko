//! Phase 1 store benchmarks (M1, M2, M5, M6, M10) for the openraft-over-redb store.
//!
//! `phase1-store <m1|m2|m5|m6|m10|all|report>`: every measurement prints a summary and writes
//! a JSON file into `results/raw/`; `report` turns the JSON files into the results document.
#![forbid(unsafe_code)]

mod common;
mod data;
mod index;
mod m1;
mod m10;
mod m2;
mod m5;
mod m6;
mod readers;
mod report;

use std::{path::PathBuf, process::Command as Process};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use crate::common::Output;

/// Settings every measurement shares.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub data_root: PathBuf,
    pub out: Output,
}

#[derive(Debug, Parser)]
#[command(name = "phase1-store", version, about)]
struct Cli {
    /// Directory for the data directories of the stores (default: a directory under the
    /// system temporary directory).
    #[arg(long, global = true)]
    data_root: Option<PathBuf>,
    /// Directory that holds `raw/` and the results document.
    #[arg(long, global = true, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/results"))]
    results_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// M1: index swap on snapshot install.
    M1(m1::Args),
    /// M2: crash and restart (100 kills plus 20 with immediate durability).
    M2(m2::Args),
    /// M5: coalescer ceiling.
    M5(m5::Args),
    /// M6: disk growth after re-seed.
    M6(m6::Args),
    /// M10: fsync probe on both drives.
    M10(m10::Args),
    /// Every measurement in turn, each in its own process, then the report.
    All(AllArgs),
    /// Writes the results document from `results/raw/*.json`.
    Report,
    /// The child process of M2.
    #[command(name = "m2-child", hide = true)]
    M2Child(m2::ChildArgs),
}

#[derive(Debug, clap::Args)]
struct AllArgs {
    /// Record counts for M1, comma separated.
    #[arg(long, default_value = "1000000")]
    m1_records: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,openraft=off")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let ctx = Ctx {
        data_root: cli
            .data_root
            .clone()
            .unwrap_or_else(common::default_data_root),
        out: Output {
            dir: cli.results_dir.clone(),
        },
    };
    match &cli.command {
        Command::M1(args) => m1::run(args.clone(), &ctx).await,
        Command::M2(args) => m2::run(args.clone(), &ctx).await,
        Command::M5(args) => m5::run(args.clone(), &ctx).await,
        Command::M6(args) => m6::run(args.clone(), &ctx).await,
        Command::M10(args) => m10::run(args, &ctx),
        Command::M2Child(args) => m2::child(args.clone()).await,
        Command::Report => report::run(&ctx),
        Command::All(args) => run_all(args, &cli),
    }
}

/// Runs every measurement as its own process so that none inherits another's heap.
fn run_all(args: &AllArgs, cli: &Cli) -> Result<()> {
    let exe = std::env::current_exe()?;
    let steps: [(&str, Vec<String>); 5] = [
        ("m10", vec![]),
        ("m1", vec!["--records".to_owned(), args.m1_records.clone()]),
        ("m5", vec![]),
        ("m6", vec![]),
        ("m2", vec![]),
    ];
    for (name, extra) in steps {
        let mut command = Process::new(&exe);
        command.arg("--results-dir").arg(&cli.results_dir);
        if let Some(root) = &cli.data_root {
            command.arg("--data-root").arg(root);
        }
        let status = command.arg(name).args(&extra).status()?;
        if !status.success() {
            bail!("{name} failed: {status}");
        }
    }
    let status = Process::new(&exe)
        .arg("--results-dir")
        .arg(&cli.results_dir)
        .arg("report")
        .status()?;
    if !status.success() {
        bail!("report failed: {status}");
    }
    Ok(())
}
