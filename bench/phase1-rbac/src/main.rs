//! M13: the cost of scope filtering (`docs/plans/slice-3-plan.md` section 5).
//!
//! `list` times a full listing of 10,000 hosts through the HTTP router for an unscoped
//! administrator and for scoped principals; `sse` measures the CPU the scoped event filter
//! costs for 1,000 subscribers at 100 events per second. See the README.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

mod common;
mod data;
mod env;
mod list;
mod sse;
mod world;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::env::StoreKind;

#[derive(Debug, Parser)]
#[command(name = "phase1-rbac", about = "M13: scope filtering cost")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Listing 10,000 hosts as an administrator and as scoped principals.
    List(ListArgs),
    /// The scoped event filter at 100 events per second for 1,000 subscribers.
    Sse(SseArgs),
}

/// The synthetic tree: `mids` /56 prefixes, `leaves_per_mid` /64 prefixes under each,
/// `hosts_per_leaf` hosts (each with an interface and an address) in each /64.
#[derive(Debug, Clone, Args)]
pub struct TreeArgs {
    /// Number of /56 prefixes (at most 256).
    #[arg(long, default_value_t = 100)]
    pub mids: usize,
    /// Number of /64 leaf prefixes under each /56.
    #[arg(long, default_value_t = 5)]
    pub leaves_per_mid: usize,
    /// Hosts in each leaf prefix.
    #[arg(long, default_value_t = 20)]
    pub hosts_per_leaf: usize,
    /// Number of scoped grants of each scoped principal.
    #[arg(long, default_value_t = 50)]
    pub grants: usize,
    /// Which store to run on.
    #[arg(long, value_enum, default_value_t = StoreKind::Mem)]
    pub store: StoreKind,
    /// Parent directory of the scratch directory of the raft store.
    #[arg(long, default_value_os_t = std::env::temp_dir())]
    pub data_dir: PathBuf,
    /// Write the raw numbers as JSON to this file.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub tree: TreeArgs,
    /// Timed full listings per case (after the warm-up).
    #[arg(long, default_value_t = 30)]
    pub iterations: usize,
    /// Untimed full listings per case before the timed ones.
    #[arg(long, default_value_t = 3)]
    pub warmup: usize,
    /// Page size.
    #[arg(long, default_value_t = 1000)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct SseArgs {
    #[command(flatten)]
    pub tree: TreeArgs,
    /// Length of each run in seconds.
    #[arg(long, default_value_t = 30)]
    pub seconds: u64,
    /// Events per second.
    #[arg(long, default_value_t = 100)]
    pub rate: u64,
    /// Subscribers (streams, or filter calls per event).
    #[arg(long, default_value_t = 1000)]
    pub subscribers: usize,
    /// Distinct scoped principals; subscribers share them round robin.
    #[arg(long, default_value_t = 50)]
    pub principals: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::List(args) => list::run(args).await,
        Command::Sse(args) => sse::run(args).await,
    }
}
