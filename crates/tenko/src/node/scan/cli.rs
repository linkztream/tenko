//! `tenko node scan`: the status of the scanner, a run on demand, and the kill switch.
//!
//! | Command | Effect |
//! |---|---|
//! | `status` | The methods with their schedule, state, last run and capability, from the status file the running scanner writes; without a running scanner, what the configuration and the host allow |
//! | `run <method>` | Runs one method now in this process and queues its batch for the running node process (`--dry-run` prints it instead); `--target` narrows it to an address or a prefix inside the scope |
//! | `stop` | The kill switch: every running scan stops and nothing starts until `resume` |
//! | `resume` | Switches the kill switch off |

use std::{fmt::Write as _, sync::Arc, time::Duration};

use clap::{Args, Subcommand};
use serde_json::json;
use tenko_cluster::{
    identity::NodePaths,
    probe::{ProbeBatch, SightingSubject},
};
use tenko_core::Timestamp;
use tenko_scan::{
    ScanError,
    method::{Availability, MethodKind},
    scanner::{BatchSink, Environment, MemorySink, Mode, RunRequest, Scanner},
    status::{MethodState, MethodStatus, RunRecord, ScanPaths, ScanStatus},
};

use super::IncomingSink;
use crate::{
    client::{Failure, Output},
    exit,
    node::NodeDirArgs,
};

/// A status file older than this is not from a running scanner.
const STALE_AFTER: Duration = Duration::from_secs(180);

/// Arguments of `tenko node scan`.
#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// What to do.
    #[command(subcommand)]
    pub action: ScanCommand,
}

/// Subcommands of `tenko node scan`.
#[derive(Debug, Clone, Subcommand)]
pub enum ScanCommand {
    /// Show the methods, their schedules, last runs and what this host allows.
    Status(StatusArgs),
    /// Run one method now (diagnostics); its batch goes to the controller like a scheduled one.
    Run(RunArgs),
    /// Kill switch: stop every running scan and start none until `resume`.
    Stop(StopArgs),
    /// Switch the kill switch off.
    Resume(StatusArgs),
}

/// Arguments of `status` and `resume`.
#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,
}

/// Arguments of `run`.
#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// The method to run, such as arp, icmp or snmp; `tenko node scan status` lists them.
    #[arg(value_name = "METHOD")]
    pub method: String,

    /// An address or prefix inside the configured prefixes; the batch is then not complete.
    #[arg(long, value_name = "ADDRESS|PREFIX")]
    pub target: Option<String>,

    /// Run inside a blackout window too.
    #[arg(long)]
    pub ignore_blackout: bool,

    /// Print what the method saw and queue nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments of `stop`.
#[derive(Debug, Clone, Args)]
pub struct StopArgs {
    /// Where this node keeps its files.
    #[command(flatten)]
    pub node: NodeDirArgs,

    /// Why, recorded in the kill switch file.
    #[arg(
        long,
        value_name = "TEXT",
        default_value = "stopped with tenko node scan stop"
    )]
    pub reason: String,
}

impl ScanCommand {
    /// The command as typed, such as `node scan status`.
    pub fn name(&self) -> &'static str {
        match self {
            ScanCommand::Status(_) => "node scan status",
            ScanCommand::Run(_) => "node scan run",
            ScanCommand::Stop(_) => "node scan stop",
            ScanCommand::Resume(_) => "node scan resume",
        }
    }

    /// Whether `--json` was given.
    pub fn json(&self) -> bool {
        match self {
            ScanCommand::Status(args) | ScanCommand::Resume(args) => args.node.json,
            ScanCommand::Run(args) => args.node.json,
            ScanCommand::Stop(args) => args.node.json,
        }
    }
}

/// The exit status of a scanner error.
fn failure(error: &ScanError) -> Failure {
    let status = match error.code() {
        "scan.config" => exit::CONFIG,
        "scan.out_of_scope" | "scan.disabled" | "scan.unavailable" | "scan.stopped"
        | "scan.blackout" => exit::USAGE,
        _ => exit::FAILURE,
    };
    Failure::new(status, error.to_string())
}

/// Runs a `tenko node scan` subcommand.
///
/// # Errors
///
/// A configuration that does not load, an unknown method, a refused or failed run.
pub async fn run(args: &ScanArgs) -> Result<Output, Failure> {
    match &args.action {
        ScanCommand::Status(args) => status(args),
        ScanCommand::Run(args) => run_method(args).await,
        ScanCommand::Stop(args) => stop(args),
        ScanCommand::Resume(args) => resume(args),
    }
}

fn status(args: &StatusArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = ScanPaths::new(&resolved.data_dir);
    let written = paths.read_status();
    let live = written
        .as_ref()
        .is_some_and(|status| Timestamp::now().saturating_since(status.updated_at) < STALE_AFTER);
    let status = match written {
        Some(status) if live => status,
        stale => {
            // What the configuration and this host allow, without runs.
            let scanner = Scanner::new(
                resolved.config.scan.clone(),
                paths.clone(),
                Arc::new(MemorySink::default()),
                &Environment::host(),
                Mode::OneShot,
            )
            .map_err(|error| failure(&error))?;
            let mut status = scanner.status();
            if let Some(stale) = stale {
                // Keep the last runs the scanner recorded before it stopped.
                for method in &mut status.methods {
                    method.last_run = stale.method(method.method).and_then(|m| m.last_run.clone());
                }
            }
            status
        }
    };
    if args.node.json {
        return Ok(Output::json(&json!({
            "running": live,
            "enabled": resolved.config.scan.enabled,
            "status": status,
        })));
    }
    Ok(Output::text(render_status(
        &status,
        live,
        resolved.config.scan.enabled,
    )))
}

fn duration(secs: u64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn state_text(state: MethodState) -> &'static str {
    match state {
        MethodState::Idle => "idle",
        MethodState::WaitingForAddresses => "waiting",
        MethodState::Running => "running",
        MethodState::Blackout => "blackout",
        MethodState::Stopped => "stopped",
        MethodState::Disabled => "disabled",
        MethodState::Unavailable => "unavailable",
    }
}

fn outcome_text(record: &RunRecord) -> &'static str {
    match record.outcome {
        tenko_scan::status::RunOutcome::Complete => "complete",
        tenko_scan::status::RunOutcome::Partial => "partial",
        tenko_scan::status::RunOutcome::Cancelled => "cancelled",
        tenko_scan::status::RunOutcome::Failed => "failed",
    }
}

fn method_line(out: &mut String, method: &MethodStatus) {
    let (last, outcome, sightings) = match &method.last_run {
        Some(run) => (
            run.finished_at.to_string(),
            outcome_text(run),
            run.sightings.to_string(),
        ),
        None => ("-".to_owned(), "-", "-".to_owned()),
    };
    let next = method
        .next_run
        .map_or_else(|| "-".to_owned(), |at| at.to_string());
    let _ = writeln!(
        out,
        "{:<15} {:<12} {:<6} {:<31} {:<10} {:<10} {}",
        method.method.name(),
        state_text(method.state),
        duration(method.interval_secs),
        last,
        outcome,
        sightings,
        next
    );
    if let Availability::Unavailable(reason) = &method.availability {
        let _ = writeln!(out, "{:<15} {reason}", "");
    } else if !method.enabled {
        let _ = writeln!(out, "{:<15} switched off in [scan]", "");
    }
    if let Some(error) = method.last_run.as_ref().and_then(|run| run.error.as_ref()) {
        let _ = writeln!(out, "{:<15} last run: {error}", "");
    }
    if let Some(error) = method
        .last_run
        .as_ref()
        .and_then(|run| run.delivery_error.as_ref())
    {
        let _ = writeln!(out, "{:<15} the batch could not be queued: {error}", "");
    }
}

/// The status as text.
pub fn render_status(status: &ScanStatus, live: bool, enabled: bool) -> String {
    let mut out = String::new();
    let state = match (enabled, live) {
        (false, _) => "switched off ([scan] enabled = false)".to_owned(),
        (true, true) => format!(
            "running (pid {}, status of {})",
            status.pid, status.updated_at
        ),
        (true, false) => "not running on this node (no current status file)".to_owned(),
    };
    let _ = writeln!(out, "scanner:        {state}");
    let _ = writeln!(
        out,
        "kill switch:    {}",
        if status.kill_switch {
            "ON: no scan runs (tenko node scan resume)"
        } else {
            "off"
        }
    );
    let prefixes = if status.prefixes.is_empty() {
        "none: nothing is scanned".to_owned()
    } else {
        status.prefixes.join(", ")
    };
    let _ = writeln!(out, "prefixes:       {prefixes}");
    if !status.exclude.is_empty() {
        let _ = writeln!(out, "excluded:       {}", status.exclude.join(", "));
    }
    let rate = status
        .per_second
        .map_or_else(|| "unlimited".to_owned(), |rate| format!("{rate} probes/s"));
    let _ = writeln!(
        out,
        "active probing: {}; rate {rate}",
        if status.active {
            "on"
        } else {
            "off (passive only)"
        }
    );
    if status.blackout.is_empty() {
        let _ = writeln!(out, "blackout:       none");
    } else {
        let until = status
            .blackout_until
            .map_or_else(String::new, |until| format!("; in force until {until}"));
        let _ = writeln!(
            out,
            "blackout:       {} ({}){until}",
            status.blackout.join(", "),
            status.timezone
        );
    }
    let raw = if status.capabilities.raw_sockets {
        "yes"
    } else {
        "no"
    };
    let _ = writeln!(
        out,
        "raw sockets:    {raw} ({}); ICMP: {}",
        status.capabilities.raw_detail,
        serde_json::to_value(status.capabilities.icmp)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default()
            .replace('_', " ")
    );
    let _ = writeln!(out, "known addresses: {}", status.known_addresses);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<15} {:<12} {:<6} {:<31} {:<10} {:<10} NEXT RUN",
        "METHOD", "STATE", "EVERY", "LAST RUN", "OUTCOME", "SIGHTINGS"
    );
    for method in &status.methods {
        method_line(&mut out, method);
    }
    out
}

fn subject_line(subject: &SightingSubject) -> String {
    match subject {
        SightingSubject::Address { ip, mac } => match mac {
            Some(mac) => format!("address  {ip} {mac}"),
            None => format!("address  {ip}"),
        },
        SightingSubject::Services {
            ip,
            open_tcp,
            tls_tcp,
        } => {
            let ports: Vec<String> = open_tcp
                .iter()
                .map(|port| {
                    if tls_tcp.contains(port) {
                        format!("{port}/tls")
                    } else {
                        port.to_string()
                    }
                })
                .collect();
            format!("services {ip} {}", ports.join(" "))
        }
        SightingSubject::Os {
            ip,
            guess,
            confidence,
        } => format!("os       {ip} {guess} ({confidence}%)"),
        SightingSubject::Name { ip, name } => format!("name     {ip} {name}"),
        SightingSubject::Vendor { mac, vendor } => format!("vendor   {mac} {vendor}"),
        SightingSubject::Attachment {
            mac,
            device,
            port,
            vlan,
        } => format!(
            "attached {mac} {device} port {} vlan {}",
            port.as_deref().unwrap_or("-"),
            vlan.map_or_else(|| "-".to_owned(), |vlan| vlan.to_string())
        ),
        SightingSubject::Link { a, b, kind } => format!(
            "link     {} {} <-> {} {} ({kind:?})",
            a.device,
            a.port.as_deref().unwrap_or("-"),
            b.device,
            b.port.as_deref().unwrap_or("-")
        ),
    }
}

async fn run_method(args: &RunArgs) -> Result<Output, Failure> {
    let kind = MethodKind::parse(&args.method).ok_or_else(|| {
        Failure::new(
            exit::USAGE,
            format!(
                "`{}` is not a method; one of {}",
                args.method,
                MethodKind::ALL
                    .iter()
                    .map(|kind| kind.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;
    let resolved = args.node.resolve()?;
    let paths = ScanPaths::new(&resolved.data_dir);
    let node = NodePaths::new(&resolved.data_dir);
    let memory = Arc::new(MemorySink::default());
    let sink: Arc<dyn BatchSink> = if args.dry_run {
        Arc::clone(&memory) as Arc<dyn BatchSink>
    } else {
        if !node.is_enrolled() {
            return Err(Failure::new(
                exit::USAGE,
                "this node is not enrolled, so nothing would reach a controller; enrol it with \
                 `tenko node enrol`, or look with --dry-run",
            ));
        }
        Arc::new(IncomingSink::new(node.buffer()))
    };
    let scanner = Scanner::new(
        resolved.config.scan.clone(),
        paths,
        sink,
        &Environment::host(),
        Mode::OneShot,
    )
    .map_err(|error| failure(&error))?;
    let request = RunRequest {
        target: args.target.clone(),
        ignore_blackout: args.ignore_blackout,
        run: None,
    };
    let record = scanner
        .run_now(kind, &request)
        .await
        .map_err(|error| failure(&error))?;
    let batches = memory.batches();
    let mut output = if args.node.json {
        Output::json(&json!({
            "method": kind,
            "run": record,
            "queued": !args.dry_run && record.queued,
            "batch": batches.first(),
        }))
    } else {
        Output::text(run_text(kind, &record, &batches, args.dry_run))
    };
    if matches!(record.outcome, tenko_scan::status::RunOutcome::Failed) {
        output.status = exit::FAILURE;
    }
    if let Some(error) = &record.delivery_error {
        output = output.note(format!(
            "tenko node scan run: error: the batch could not be queued: {error}"
        ));
        output.status = exit::FAILURE;
    }
    Ok(output)
}

/// What `tenko node scan run` prints for a finished run.
fn run_text(kind: MethodKind, record: &RunRecord, batches: &[ProbeBatch], dry_run: bool) -> String {
    let mut text = String::new();
    let seconds = record
        .finished_at
        .saturating_since(record.started_at)
        .as_secs_f64();
    let _ = writeln!(
        text,
        "{kind}: {}, {} sighting(s), {} probe(s) in {seconds:.1} s",
        outcome_text(record),
        record.sightings,
        record.probes
    );
    if let Some(error) = &record.error {
        let _ = writeln!(text, "  {error}");
    }
    for note in &record.notes {
        let _ = writeln!(text, "  {note}");
    }
    if dry_run {
        for batch in batches {
            for sighting in &batch.sightings {
                let _ = writeln!(text, "  {}", subject_line(&sighting.subject));
            }
        }
        let _ = writeln!(text, "dry run: nothing was queued");
    } else if record.queued {
        let _ = writeln!(
            text,
            "queued for the controller; the running node process sends it within a second"
        );
    } else if record.delivery_error.is_none() {
        let _ = writeln!(text, "nothing to queue");
    }
    text
}

fn stop(args: &StopArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = ScanPaths::new(&resolved.data_dir);
    paths.kill(&args.reason).map_err(|error| failure(&error))?;
    if args.node.json {
        return Ok(Output::json(&json!({ "kill_switch": true })));
    }
    Ok(Output::text(format!(
        "kill switch on ({}): the running scanner stops every scan within a second and starts \
         none until `tenko node scan resume`\n",
        paths.kill_switch().display()
    )))
}

fn resume(args: &StatusArgs) -> Result<Output, Failure> {
    let resolved = args.node.resolve()?;
    let paths = ScanPaths::new(&resolved.data_dir);
    let was_on = paths.resume().map_err(|error| failure(&error))?;
    if args.node.json {
        return Ok(Output::json(
            &json!({ "kill_switch": false, "was_on": was_on }),
        ));
    }
    Ok(Output::text(if was_on {
        "kill switch off: scans run again on their schedules\n"
    } else {
        "the kill switch was not on\n"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_like_people_write_them() {
        assert_eq!(duration(300), "5m");
        assert_eq!(duration(21_600), "6h");
        assert_eq!(duration(86_400), "1d");
        assert_eq!(duration(45), "45s");
    }

    #[test]
    fn sightings_print_on_one_line() {
        let line = subject_line(&SightingSubject::Services {
            ip: "192.0.2.10".parse().expect("ip"),
            open_tcp: vec![22, 443],
            tls_tcp: vec![443],
        });
        assert_eq!(line, "services 192.0.2.10 22 443/tls");
    }
}
