//! `tenko dns blocking ...`: the blocking view of the node that answers
//! (`GET /dns/blocking/stats`) and the pause of its block lists (`POST` and
//! `DELETE /dns/blocking/pause`).
//!
//! The figures are counted from the node's query log, so they need the log on; every read
//! is audited on the server as `dns.blocking.stats`, since it names the clients and what
//! they asked.

use std::fmt::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};

use super::{ClientOpts, Failure, Output, Target, key, number, table, text};

/// Subcommands of `tenko dns blocking`.
#[derive(Debug, Clone, Subcommand)]
pub enum BlockingCommand {
    /// The queries of the last 24 hours or 7 days: blocked, per list, the top names and
    /// clients.
    Stats(BlockingStatsArgs),
    /// Pause the block lists for some minutes, or until resumed.
    Pause(BlockingPauseArgs),
    /// End the pause: the block lists block again.
    Resume(BlockingResumeArgs),
}

impl BlockingCommand {
    /// The connection options.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Stats(args) => &args.client,
            Self::Pause(args) => &args.client,
            Self::Resume(args) => &args.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Stats(_) => "dns blocking stats",
            Self::Pause(_) => "dns blocking pause",
            Self::Resume(_) => "dns blocking resume",
        }
    }
}

/// The window of the figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WindowArg {
    /// The last 24 hours.
    #[value(name = "24h")]
    Day,
    /// The last 7 days.
    #[value(name = "7d")]
    Week,
}

/// Arguments of `tenko dns blocking stats`.
#[derive(Debug, Clone, Args)]
pub struct BlockingStatsArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The window.
    #[arg(long, value_enum, default_value = "24h")]
    pub window: WindowArg,
    /// The length of each top list, 1 to 100.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub top: u32,
}

/// Arguments of `tenko dns blocking pause`.
#[derive(Debug, Clone, Args)]
pub struct BlockingPauseArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Minutes the pause lasts, 1 to 1440; until resumed when absent.
    #[arg(long, value_name = "MINUTES", value_parser = clap::value_parser!(u32).range(1..=1440))]
    pub minutes: Option<u32>,
}

/// Arguments of `tenko dns blocking resume`.
#[derive(Debug, Clone, Args)]
pub struct BlockingResumeArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Runs a `tenko dns blocking` subcommand.
///
/// # Errors
///
/// The connection's or the server's failure.
pub async fn run(target: &Target, command: &BlockingCommand) -> Result<Output, Failure> {
    match command {
        BlockingCommand::Stats(args) => stats(target, args).await,
        BlockingCommand::Pause(args) => pause(target, args).await,
        BlockingCommand::Resume(_) => resume(target).await,
    }
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The pause as one line: until when, or until resumed.
fn pause_line(paused: Option<&Value>) -> String {
    match paused {
        None | Some(Value::Null) => "blocking is on".to_owned(),
        Some(paused) => match text(paused, &["until"]) {
            "" => "blocking is paused until resumed".to_owned(),
            until => format!("blocking is paused until {until}"),
        },
    }
}

async fn stats(target: &Target, args: &BlockingStatsArgs) -> Result<Output, Failure> {
    let window = match args.window {
        WindowArg::Day => "24h",
        WindowArg::Week => "7d",
    };
    let client = target.connect().await?;
    let answer: Value = client
        .get_query(
            "/dns/blocking/stats",
            &[("window", window.to_owned()), ("top", args.top.to_string())],
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let mut out = String::new();
    let share = answer
        .get("blocked_share")
        .and_then(Value::as_f64)
        .map(|share| format!(" ({:.1} %)", share * 100.0))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "node {}, {window} from {} to {}",
        number(&answer, &["node"]),
        text(&answer, &["from"]),
        text(&answer, &["until"])
    );
    let _ = writeln!(
        out,
        "queries {}, blocked {}{share}, from the cache {}, clients {}",
        number(&answer, &["queries"]),
        number(&answer, &["blocked"]),
        number(&answer, &["cached"]),
        number(&answer, &["clients"])
    );
    let _ = writeln!(out, "{}", pause_line(answer.get("paused")));
    let lists: Vec<Vec<String>> = items(&answer, "lists")
        .iter()
        .map(|list| {
            vec![
                match text(list, &["name"]) {
                    "" => text(list, &["list"]).to_owned(),
                    name => name.to_owned(),
                },
                number(list, &["blocked"]),
            ]
        })
        .collect();
    if !lists.is_empty() {
        out.push('\n');
        out.push_str(&table(&["LIST", "BLOCKED"], &lists));
    }
    let names = |key: &str| -> Vec<Vec<String>> {
        items(&answer, key)
            .iter()
            .map(|name| {
                vec![
                    text(name, &["name"]).to_owned(),
                    number(name, &["queries"]),
                    number(name, &["blocked"]),
                ]
            })
            .collect()
    };
    let blocked = names("top_blocked");
    if !blocked.is_empty() {
        out.push('\n');
        out.push_str(&table(&["TOP BLOCKED", "QUERIES", "BLOCKED"], &blocked));
    }
    let clients: Vec<Vec<String>> = items(&answer, "top_clients")
        .iter()
        .map(|client| {
            vec![
                match text(client, &["client"]) {
                    "" => "(withheld)".to_owned(),
                    shown => shown.to_owned(),
                },
                text(client, &["name"]).to_owned(),
                number(client, &["queries"]),
                number(client, &["blocked"]),
            ]
        })
        .collect();
    if !clients.is_empty() {
        out.push('\n');
        out.push_str(&table(&["CLIENT", "NAME", "QUERIES", "BLOCKED"], &clients));
    }
    let mut output = Output::text(out);
    if answer.get("truncated").and_then(Value::as_bool) == Some(true) {
        output = output.note("the log holds more in the window than one read looks at: the figures cover the newest part");
    }
    Ok(output)
}

async fn pause(target: &Target, args: &BlockingPauseArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let body = args
        .minutes
        .map_or_else(|| json!({}), |minutes| json!({ "minutes": minutes }));
    let answer: Value = client
        .post("/dns/blocking/pause", &body, Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "{} on node {} (command {})\n",
        pause_line(answer.get("paused")),
        number(&answer, &["node"]),
        text(&answer, &["command_id"])
    )))
}

async fn resume(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    client.delete("/dns/blocking/pause", None).await?;
    if target.json {
        return Ok(Output::json(&json!({ "paused": null })));
    }
    Ok(Output::text("blocking is on\n".to_owned()))
}
