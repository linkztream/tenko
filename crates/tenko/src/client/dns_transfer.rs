//! `tenko dns transfer status|now`: the transfer state of a zone and a refresh now
//! (`GET` and `POST /api/v1/dns/zones/{id}/transfer`, WP6.1).
//!
//! The answer is a `TransferStatus`: `serial`, `primaries[].{address, last_success,
//! last_error}`, `next_refresh`, `expires`, `running`.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::{key, resolve_zone, text, zone_path};
use crate::client::{ClientOpts, Failure, Output, Target, table};

/// Subcommands of `tenko dns transfer`.
#[derive(Debug, Clone, Subcommand)]
pub enum TransferCommand {
    /// Show the transfer state of a zone: the serial, each primary, the timers.
    Status(TransferArgs),
    /// Refresh a secondary zone now (IXFR with the AXFR fallback).
    Now(TransferArgs),
}

/// Arguments of `tenko dns transfer status|now`.
#[derive(Debug, Clone, Args)]
pub struct TransferArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
}

impl TransferCommand {
    /// The connection options of the command.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Status(args) | Self::Now(args) => &args.client,
        }
    }
}

/// Runs a `tenko dns transfer` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &TransferCommand) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let (args, now) = match command {
        TransferCommand::Status(args) => (args, false),
        TransferCommand::Now(args) => (args, true),
    };
    let zone = resolve_zone(&client, &args.zone).await?;
    let path = format!("{}/transfer", zone_path(&zone));
    let answer: Value = if now {
        client.post(&path, &json!({}), Some(&key())).await?
    } else {
        client.get(&path).await?
    };
    if target.json {
        return Ok(Output::json(&answer));
    }
    let mut out = String::new();
    if now {
        let _ = writeln!(out, "refresh of {} queued", text(&zone, &["name"]));
    }
    out.push_str(&describe(text(&zone, &["name"]), &answer));
    Ok(Output::text(out))
}

fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => "-".to_owned(),
    }
}

fn describe(name: &str, status: &Value) -> String {
    let lines = [
        ("zone", name.to_owned()),
        ("serial", field(status, "serial")),
        ("next refresh", field(status, "next_refresh")),
        ("expires", field(status, "expires")),
        ("running", field(status, "running")),
    ];
    let width = lines.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    let rows: Vec<Vec<String>> = status
        .get("primaries")
        .and_then(Value::as_array)
        .map(|primaries| {
            primaries
                .iter()
                .map(|primary| {
                    vec![
                        field(primary, "address"),
                        field(primary, "last_success"),
                        field(primary, "last_error"),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    if !rows.is_empty() {
        out.push('\n');
        out.push_str(&table(&["PRIMARY", "LAST SUCCESS", "LAST ERROR"], &rows));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_reads_as_lines_and_a_table() {
        let status = json!({
            "zone": "00000000-0000-0000-0000-000000000000",
            "serial": 7,
            "primaries": [
                {"address": "192.0.2.53:53", "last_success": "2026-10-18T10:00:00Z"},
                {"address": "192.0.2.54:853", "last_error": "dns.transfer.tsig"},
            ],
            "next_refresh": "2026-10-18T11:00:00Z",
            "running": false,
        });
        let text = describe("example.test", &status);
        assert!(text.contains("serial        7"), "{text}");
        assert!(text.contains("expires       -"), "{text}");
        assert!(text.contains("192.0.2.54:853"), "{text}");
        assert!(text.contains("dns.transfer.tsig"), "{text}");
    }
}
