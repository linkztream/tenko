//! `tenko node inject`: queues a batch of observations from a JSON file for the
//! controller, through the `incoming/` directory of the node's buffer. The running node
//! process adopts it within a second and sends it like a batch of its own probes. A
//! diagnostic: it proves the path from a probe to the reconciler before the scanner runs,
//! and it is how tests feed a probe node.
//!
//! The file is a [`ProbeBatch`] as JSON, for example:
//!
//! ```json
//! {
//!   "method": "arp",
//!   "complete": false,
//!   "collected_at": "2026-10-10T08:00:05Z",
//!   "sightings": [
//!     {"observed_at": "2026-10-10T08:00:01Z",
//!      "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}}
//!   ]
//! }
//! ```

use std::path::PathBuf;

use clap::Args;
use serde_json::json;
use tenko_cluster::{
    buffer::ObservationBuffer,
    identity::{NodePaths, create_private_dir},
    probe::ProbeBatch,
};

use super::NodeDirArgs;
use crate::{
    client::{Failure, Output},
    exit,
};

/// Arguments of `tenko node inject`.
#[derive(Debug, Clone, Args)]
pub struct InjectArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// The batch, as JSON.
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
}

/// Runs `tenko node inject`.
///
/// # Errors
///
/// The node is not enrolled, or the file is not a batch.
pub fn run(args: &InjectArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = NodePaths::new(&resolved.data_dir);
    if !paths.is_enrolled() {
        return Err(Failure::new(
            exit::USAGE,
            "this node is not enrolled; run `tenko node enrol` first",
        ));
    }
    let text = std::fs::read(&args.file).map_err(|error| {
        Failure::new(
            exit::USAGE,
            format!("cannot read {}: {error}", args.file.display()),
        )
    })?;
    let batch: ProbeBatch = serde_json::from_slice(&text).map_err(|error| {
        Failure::new(
            exit::USAGE,
            format!(
                "{} is not an observation batch: {error}",
                args.file.display()
            ),
        )
    })?;
    create_private_dir(&paths.buffer())
        .map_err(|error| Failure::other(error.detail().to_owned()))?;
    let path = ObservationBuffer::drop_incoming(&paths.buffer(), &batch.encode())
        .map_err(|error| Failure::other(error.to_string()))?;
    let sightings = batch.sightings.len();
    if args.node.json {
        return Ok(Output::json(&json!({
            "queued": path,
            "sightings": sightings,
        })));
    }
    Ok(Output::text(format!(
        "queued a batch of {sightings} sighting(s) as {}; the node process sends it\n",
        path.display()
    )))
}
