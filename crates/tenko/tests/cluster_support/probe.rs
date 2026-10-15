//! A probe node of the lab, enrolled as in `node_cluster.rs`: `tenko node enrol` against a
//! controller of the lab with a probe token and the CA fingerprint, then
//! `tenko serve --roles probe` in a data directory of its own. It connects to the
//! controllers' cluster ports directly (probes are not relayed) and learns every
//! controller's port from the `Hello` answer.

use std::{path::PathBuf, process::Command, time::Duration};

use serde_json::Value;
use tempfile::TempDir;

use super::lab::{ClusterLab, START_LIMIT};
use crate::serve_support::{Outcome, Proc, run, tenko};

/// A batch of two documentation addresses seen by ARP.
pub const BATCH: &str = r#"{
  "method": "arp",
  "complete": false,
  "collected_at": "2026-10-10T08:00:05Z",
  "sightings": [
    {"observed_at": "2026-10-10T08:00:01Z",
     "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}},
    {"observed_at": "2026-10-10T08:00:02Z",
     "subject": {"type": "address", "data": {"ip": "192.0.2.31"}}}
  ]
}"#;

/// An enrolled, running probe; stopped and removed when dropped.
pub struct LabProbe {
    proc: Option<Proc>,
    /// Its node id.
    pub id: u64,
    dir: TempDir,
}

impl ClusterLab {
    /// Enrols a probe through controller `via` and starts its node process; returns once
    /// the process says it runs.
    #[track_caller]
    pub fn probe(&mut self, via: u64) -> LabProbe {
        let token = self.probe_token();
        let number = self.next_probe();
        let dir = tempfile::Builder::new()
            .prefix("tenko-lab-probe-")
            .tempdir()
            .expect("a temporary directory");
        let data_dir = dir.path().join("data");
        let mut enrol = tenko();
        enrol
            .args(["node", "enrol", "--controller", &self.url(via)])
            .args(["--token", &token, "--ca-fingerprint", self.fingerprint()])
            .args([
                "--name",
                &format!("lab-probe-{number}"),
                "--address",
                "192.0.2.20",
            ])
            .arg("--data-dir")
            .arg(&data_dir);
        let enrolled = run(enrol, None);
        assert_eq!(
            enrolled.code,
            Some(0),
            "enrol a probe\n{}",
            enrolled.diagnostics()
        );
        let identity: Value = serde_json::from_slice(
            &std::fs::read(data_dir.join("node").join("identity.json")).expect("identity.json"),
        )
        .expect("JSON");
        let id = identity["node"]
            .as_u64()
            .or_else(|| identity["id"].as_u64())
            .unwrap_or_else(|| panic!("no node id in {identity}"));
        let mut probe = LabProbe {
            proc: None,
            id,
            dir,
        };
        probe.start();
        let proc = probe.proc.as_ref().expect("the probe process");
        assert!(
            proc.wait_stdout_line(START_LIMIT, |line| line.contains(" running"))
                .is_some(),
            "the probe did not start\n{}",
            proc.diagnostics()
        );
        probe
    }

    /// The controller's view of a node (`GET /nodes/{id}`) on controller `on`.
    pub fn node_view(&self, on: u64, node: u64) -> Option<Value> {
        let reply = self.get(on, &format!("/nodes/{node}"))?;
        (reply.status == 200).then(|| reply.json())
    }

    /// The observed facts of a probe's ARP source on controller `on`.
    pub fn probe_facts(&self, on: u64, node: u64) -> Option<usize> {
        let reply = self.get(on, &format!("/observations?source=probe:{node}:arp"))?;
        (reply.status == 200).then(|| reply.json()["items"].as_array().map_or(0, Vec::len))
    }
}

impl LabProbe {
    /// The data directory.
    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = tenko();
        command.args(args).arg("--data-dir").arg(self.data_dir());
        command
    }

    /// Starts the node process (`tenko serve --roles probe`).
    pub fn start(&mut self) {
        assert!(self.proc.is_none(), "the probe runs");
        let mut command = self.command(&["serve", "--roles", "probe", "--stop-on-eof"]);
        command.env("TENKO_LOG__LEVEL", "info");
        self.proc = Some(Proc::spawn(command));
    }

    /// Stops the node process gracefully.
    #[track_caller]
    pub fn stop(&mut self) -> Outcome {
        self.proc.take().expect("a running probe").stop()
    }

    /// The node process's output so far.
    pub fn diagnostics(&self) -> String {
        self.proc
            .as_ref()
            .map_or_else(String::new, Proc::diagnostics)
    }

    /// `tenko node status --json`.
    #[track_caller]
    pub fn status(&self) -> Value {
        let status = run(self.command(&["node", "status", "--json"]), None);
        status.assert_code(0);
        status.json()
    }

    /// The state of the node process (`connected`, `connecting`, ...).
    pub fn process_state(&self) -> String {
        self.status()["process"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// The batches waiting in the buffer.
    pub fn buffered(&self) -> u64 {
        self.status()["process"]["buffer"]["batches"]
            .as_u64()
            .unwrap_or(u64::MAX)
    }

    /// Injects a batch (`tenko node inject`); [`BATCH`] when `batch` is `None`.
    #[track_caller]
    pub fn inject(&self, batch: Option<&str>) {
        let file = self.dir.path().join("batch.json");
        std::fs::write(&file, batch.unwrap_or(BATCH)).expect("write the batch");
        let injected = run(
            self.command(&["node", "inject", "--file", file.to_str().expect("UTF-8")]),
            None,
        );
        injected.assert_code(0);
    }

    /// Waits for a line of the node process's standard error.
    pub fn wait_log(&self, limit: Duration, needle: &str) -> bool {
        self.proc.as_ref().is_some_and(|proc| {
            proc.wait_stderr_line(limit, |line| line.contains(needle))
                .is_some()
        })
    }
}
