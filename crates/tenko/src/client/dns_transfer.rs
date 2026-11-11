//! `tenko dns transfer status|now|site`: the transfer state of a zone and a refresh now
//! (`GET` and `POST /api/v1/dns/zones/{id}/transfer`, WP6.1).
//!
//! The answer is a `TransferStatus`: `serial`, `primaries[].{address, last_success,
//! last_error}`, `next_refresh`, `expires`, `running`.
//!
//! `site` shows the networks of the Hardened rule of zone transfers (TGL-10,
//! `GET /api/v1/settings/security`). The CLI holds a token, and changing the list needs an
//! administrator session with a fresh sign-in (a token is refused), so `--set` and
//! `--default` only point to the web UI and the API.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::{key, resolve_zone, text, zone_path};
use tenko_core::dns::{TRANSFER_SITE_DEFAULT, parse_transfer_site};

use crate::client::{ClientOpts, Failure, Output, Target, table};
use crate::exit;

/// Subcommands of `tenko dns transfer`.
#[derive(Debug, Clone, Subcommand)]
pub enum TransferCommand {
    /// Show the transfer state of a zone: the serial, each primary, the timers.
    Status(TransferArgs),
    /// Refresh a secondary zone now (IXFR with the AXFR fallback).
    Now(TransferArgs),
    /// Show the networks the Hardened profile lets zones transfer to without TLS (XoT).
    ///
    /// Under the Hardened profile, a zone transfer to an address outside these networks
    /// needs TLS (XoT, zone transfer over TLS). An empty list means every transfer needs it.
    /// Changing the list needs an administrator session with a fresh sign-in, which a token
    /// does not give: use the security settings of the web UI or `PATCH
    /// /api/v1/settings/security`.
    Site(SiteArgs),
}

/// Arguments of `tenko dns transfer site`.
#[derive(Debug, Clone, Args)]
pub struct SiteArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Set the list: comma-separated networks such as `10.0.0.0/8,fd00::/8`; an empty
    /// value means no network, so every transfer under Hardened needs XoT.
    #[arg(long, value_name = "NETWORKS", conflicts_with = "default")]
    pub set: Option<String>,
    /// Go back to the default list (private, shared, unique-local, loopback and link-local
    /// networks).
    #[arg(long)]
    pub default: bool,
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
            Self::Site(args) => &args.client,
        }
    }
}

/// Runs a `tenko dns transfer` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &TransferCommand) -> Result<Output, Failure> {
    if let TransferCommand::Site(args) = command {
        return site(target, args).await;
    }
    let client = target.connect().await?;
    let (args, now) = match command {
        TransferCommand::Status(args) => (args, false),
        TransferCommand::Now(args) => (args, true),
        TransferCommand::Site(_) => unreachable!("handled above"),
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

/// `tenko dns transfer site`: shows the list; changing it needs a session, not a token.
async fn site(target: &Target, args: &SiteArgs) -> Result<Output, Failure> {
    if args.default || args.set.is_some() {
        if let Some(set) = &args.set {
            parse_site(set)?;
        }
        return Err(Failure::new(
            exit::USAGE,
            "the transfer site list is changed in the security settings of the web UI, or with \
             PATCH /api/v1/settings/security by an administrator session with a fresh \
             sign-in; a token is refused",
        ));
    }
    let client = target.connect().await?;
    let answer: Value = client.get("/settings/security").await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(describe_site(&answer)))
}

/// The networks of a `--set` value, checked as the server checks them.
fn parse_site(value: &str) -> Result<Vec<String>, Failure> {
    let entries: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    parse_transfer_site(&entries).map_err(|message| Failure::new(exit::USAGE, message))?;
    Ok(entries)
}

/// The effective list, one network per line, and whether it is the default.
fn describe_site(answer: &Value) -> String {
    let custom = answer
        .pointer("/settings/transfer_site")
        .and_then(Value::as_array);
    let mut out = String::new();
    if let Some(list) = custom {
        for network in list.iter().filter_map(Value::as_str) {
            let _ = writeln!(out, "{network}");
        }
        if list.is_empty() {
            let _ = writeln!(out, "(no network)");
            let _ = writeln!(out, "custom list: under Hardened every transfer needs XoT");
        } else {
            let _ = writeln!(out, "custom list");
        }
    } else {
        for network in TRANSFER_SITE_DEFAULT {
            let _ = writeln!(out, "{network}");
        }
        let _ = writeln!(out, "default list");
    }
    out
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

    #[test]
    fn the_site_list_reads_as_lines_and_says_whether_it_is_the_default() {
        let default = describe_site(&json!({"settings": {}}));
        assert!(default.starts_with("10.0.0.0/8\n"), "{default}");
        assert!(default.ends_with("default list\n"), "{default}");
        let custom = describe_site(&json!({"settings": {"transfer_site": ["192.0.2.0/24"]}}));
        assert_eq!(custom, "192.0.2.0/24\ncustom list\n");
        let empty = describe_site(&json!({"settings": {"transfer_site": []}}));
        assert!(empty.contains("no network"), "{empty}");
    }

    #[test]
    fn a_set_value_is_checked_before_anything_is_sent() {
        assert_eq!(
            parse_site("10.0.0.0/8, 192.0.2.0/24").expect("ok"),
            ["10.0.0.0/8", "192.0.2.0/24"]
        );
        assert_eq!(
            parse_site("").expect("empty is allowed"),
            Vec::<String>::new()
        );
        assert!(parse_site("not-a-network").is_err());
    }
}
