//! `tenko ipam host decommission|reinstate`: the lifecycle of a host
//! (`POST /hosts/{id}/decommission`, `POST /hosts/{id}/reinstate`).
//!
//! A decommissioned host releases its addresses (their DNS names go too, unless
//! `--keep-dns`), its facts raise no proposals and the default lists leave it out; a
//! reinstatement binds back the released addresses that are still free.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::{ClientOpts, Failure, Output, Target, ipam::host_id};

/// Subcommands of `tenko ipam host`.
#[derive(Debug, Clone, Subcommand)]
pub enum HostCommand {
    /// Decommission a host: release its addresses and keep it out of the default lists.
    Decommission(DecommissionArgs),
    /// Reinstate a decommissioned host: bind back the addresses it released.
    Reinstate(ReinstateArgs),
}

impl HostCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Decommission(args) => &args.client,
            Self::Reinstate(args) => &args.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Decommission(_) => "ipam host decommission",
            Self::Reinstate(_) => "ipam host reinstate",
        }
    }
}

/// Arguments of `tenko ipam host decommission`.
#[derive(Debug, Clone, Args)]
pub struct DecommissionArgs {
    /// The host: its identifier or name.
    #[arg(value_name = "ID_OR_NAME")]
    pub host: String,
    /// Why, for the list of decommissioned hosts.
    #[arg(long)]
    pub reason: Option<String>,
    /// Keep the DNS names of the released addresses, so their records stay.
    #[arg(long)]
    pub keep_dns: bool,
    /// Show what would change without changing it.
    #[arg(long)]
    pub dry_run: bool,
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of `tenko ipam host reinstate`.
#[derive(Debug, Clone, Args)]
pub struct ReinstateArgs {
    /// The host: its identifier or name.
    #[arg(value_name = "ID_OR_NAME")]
    pub host: String,
    /// Show what would change without changing it.
    #[arg(long)]
    pub dry_run: bool,
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// The path of a lifecycle request.
fn path(host: &str, action: &str, dry_run: bool) -> String {
    let mut path = format!("/hosts/{host}/{action}");
    if dry_run {
        path.push_str("?dry_run=true");
    }
    path
}

/// The body of a decommission.
fn decommission_body(args: &DecommissionArgs) -> Value {
    let reason = args
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    json!({ "reason": reason, "keep_dns": args.keep_dns })
}

/// Runs a `tenko ipam host` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &HostCommand) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let (answer, action): (Value, &str) = match command {
        HostCommand::Decommission(args) => {
            let id = host_id(&client, &args.host).await?;
            let body = decommission_body(args);
            let answer = client
                .post(&path(&id, "decommission", args.dry_run), &body, None)
                .await?;
            (answer, "decommission")
        }
        HostCommand::Reinstate(args) => {
            let id = host_id(&client, &args.host).await?;
            let answer = client
                .post(&path(&id, "reinstate", args.dry_run), &json!({}), None)
                .await?;
            (answer, "reinstate")
        }
    };
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(answer_text(&answer, action)))
}

/// The answer of a lifecycle change in words.
fn answer_text(answer: &Value, action: &str) -> String {
    let item = &answer["item"];
    let name = item["name"].as_str().unwrap_or("-");
    let dry_run = answer["dry_run"] == true;
    let mut out = String::new();
    if action == "decommission" {
        let released = item["decommissioned"]["released"]
            .as_array()
            .map_or(0, Vec::len);
        let verb = if dry_run {
            "would be decommissioned"
        } else {
            "is decommissioned"
        };
        let dns = if item["decommissioned"]["kept_dns"] == true {
            "DNS names kept"
        } else {
            "DNS names removed"
        };
        let _ = writeln!(
            out,
            "host {name} {verb}; {released} address{} released, {dns}",
            if released == 1 { "" } else { "es" }
        );
    } else {
        let verb = if dry_run {
            "would be reinstated"
        } else {
            "is reinstated"
        };
        let _ = writeln!(out, "host {name} {verb}");
    }
    for warning in answer["warnings"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "warning: {}",
            warning["message"].as_str().unwrap_or_default()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(reason: Option<&str>, keep_dns: bool) -> DecommissionArgs {
        DecommissionArgs {
            host: "old-controller".to_owned(),
            reason: reason.map(str::to_owned),
            keep_dns,
            dry_run: false,
            client: ClientOpts::default(),
        }
    }

    #[test]
    fn the_request_names_the_host_and_the_options() {
        assert_eq!(path("h1", "decommission", false), "/hosts/h1/decommission");
        assert_eq!(
            path("h1", "reinstate", true),
            "/hosts/h1/reinstate?dry_run=true"
        );
        assert_eq!(
            decommission_body(&args(Some("  replaced  "), true)),
            json!({ "reason": "replaced", "keep_dns": true })
        );
        assert_eq!(
            decommission_body(&args(Some(" "), false)),
            json!({ "reason": null, "keep_dns": false })
        );
    }

    #[test]
    fn the_answer_reads_as_a_sentence() {
        let answer = json!({
            "item": {
                "name": "old-controller",
                "decommissioned": { "released": [{}, {}], "kept_dns": false }
            },
            "dry_run": false,
            "warnings": []
        });
        assert_eq!(
            answer_text(&answer, "decommission"),
            "host old-controller is decommissioned; 2 addresses released, DNS names removed\n"
        );
        let answer = json!({
            "item": { "name": "old-controller" },
            "dry_run": true,
            "warnings": [{ "message": "address 192.0.2.10 was not bound again: assigned" }]
        });
        assert_eq!(
            answer_text(&answer, "reinstate"),
            "host old-controller would be reinstated\nwarning: address 192.0.2.10 was not bound again: assigned\n"
        );
    }
}
