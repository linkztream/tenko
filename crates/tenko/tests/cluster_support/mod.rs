//! The cluster lab (WP3.1c): several controllers of Tenko DDI as separate `tenko serve`
//! processes on one machine, for the `cluster_*.rs` scenarios and measurements.
//!
//! - [`ClusterLab::start`] brings up one to five controllers with the internal CA on
//!   `localhost`, each with its own data directory under the operating system's temporary
//!   directory and its own loopback ports for the API and the cluster port, the lab
//!   timings (`heartbeat_secs = 1`, `isolation_after_ms = 1000`,
//!   `catch_up_timeout_secs = 30`) and logging at `info`. The first controller runs
//!   first-run setup and signs the administrator in; every further one joins through the
//!   real `tenko cluster join` with a controller token from the API and starts with
//!   `tenko serve --config`. The start returns once the membership is complete with an odd
//!   number of voters and every controller knows the leader.
//! - Every directed link between two controllers runs through a [`relay::Relay`]: each
//!   controller's `[cluster] peer_address_map` sends the cluster port of every peer to the
//!   relay of that link, so [`ClusterLab::partition`], [`ClusterLab::delay`] and
//!   [`ClusterLab::drop_links`] act on single links. Probes are not relayed.
//! - Faults of processes: [`ClusterLab::kill`], [`ClusterLab::stop`],
//!   [`ClusterLab::restart`], [`ClusterLab::wipe_and_restart`], [`ClusterLab::remove`],
//!   [`ClusterLab::add_controller`].
//! - Observing: [`ClusterLab::leader`], [`ClusterLab::followers`],
//!   [`ClusterLab::members`], [`ClusterLab::digests_agree`] (the digest of every member
//!   through its own API at one revision), [`ClusterLab::sse_client`] (an event-stream
//!   reader that resumes from `Last-Event-ID` on another controller, as the web UI does),
//!   [`ClusterLab::probe`] (an enrolled probe process), [`ClusterLab::write_load`] and
//!   [`ClusterLab::start_load`] (a steady write load with a report).
//! - Every wait has a limit and fails with the last log lines of every process
//!   ([`ClusterLab::wait_until`]), so a hang never reaches the CI timeout. Dropping the lab
//!   kills every process and removes every directory, also when a test panics.
//!
//! This directory is not a test of its own: a file named `cluster_*.rs` would be run as one.

#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    reason = "each scenario file uses a different part of the harness"
)]

pub mod digest;
pub mod http;
pub mod lab;
pub mod load;
pub mod probe;
pub mod relay;
pub mod sse;

pub use lab::{ClusterLab, LabOptions, State, StoreSize, learners, odd_voters, voters};
pub use load::{LoadHandle, LoadReport, Outcome as WriteOutcome, WriteRecord};
pub use probe::LabProbe;
pub use relay::{Echo, Fault, Relay};
pub use sse::SseClient;

/// Whether the slow lab scenarios and the measurements should print their numbers: always;
/// the measurements also write JSON when `TENKO_LAB_RESULTS` names a directory.
pub const RESULTS_ENV: &str = "TENKO_LAB_RESULTS";

/// Writes the raw result of a measurement as `<name>.json` into the directory of
/// `TENKO_LAB_RESULTS`, when it is set; returns the path.
pub fn write_result(name: &str, value: &serde_json::Value) -> Option<std::path::PathBuf> {
    let dir = std::env::var_os(RESULTS_ENV)?;
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("the results directory");
    let path = dir.join(format!("{name}.json"));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(value).expect("JSON of a result"),
    )
    .expect("write a result");
    println!("{name}: {}", path.display());
    Some(path)
}
