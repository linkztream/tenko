//! `tenko dns trust-anchor ...`, `tenko dns nta ...` and `tenko dns recursion ...`: the
//! recursive resolver's trust anchors, negative trust anchors, status, priming and
//! infrastructure cache (recursion plan section 3.4; WP10.0 declares the commands).
//!
//! The routes behind the trust anchor, negative trust anchor, status, priming and
//! infrastructure cache commands are built (WP10.1, WP10.2); a command whose route is
//! still to come answers the 501 `sys.not_implemented` problem details, printed as any
//! other API error.
//!
//! # Routes
//!
//! | Command | Request |
//! |---|---|
//! | `trust-anchor list` | `GET /dns/trust-anchors` |
//! | `trust-anchor add <zone> --ds D\|--dnskey K [--replace-root]` | `POST /dns/trust-anchors` |
//! | `trust-anchor remove <zone>` | `DELETE /dns/trust-anchors/{zone}` |
//! | `trust-anchor refresh <zone>` | `POST /dns/trust-anchors/{zone}/refresh` |
//! | `nta list` | `GET /dns/ntas` |
//! | `nta add <zone> --expires D --reason T` | `POST /dns/ntas` |
//! | `nta remove <id>` | `DELETE /dns/ntas/{id}` |
//! | `recursion status <node>` | `GET /nodes/{id}/dns/recursion` |
//! | `recursion prime <node>` | `POST /nodes/{id}/dns/recursion/prime` |
//! | `recursion infra <node> [--suffix S]` | `GET /nodes/{id}/dns/infra` |
//! | `recursion flush-infra <node> [--suffix S]` | `POST /nodes/{id}/dns/infra/flush` |
//!
//! The root zone is written `.`; `remove` and `refresh` put the zone in the URL path, where
//! `.` is a dot segment, so they send it as `root`, the routes' spelling of the root. A
//! negative trust anchor's `--expires` is a duration (`30m`, `12h`, `2d`, `1d12h`) of at
//! most seven days, added to the local clock.

use std::{fmt::Write as _, time::Duration};

use clap::{ArgGroup, Args, Subcommand};
use serde_json::{Value, json};
use tenko_api::dto::Page;
use tenko_core::Timestamp;
use uuid::Uuid;

use super::{
    ClientOpts, Failure, ListArgs, Output, Target, cache::encode, canonical, key, list_all, number,
    table, text, usage,
};

/// The longest a negative trust anchor may live (RFC 7646 section 3: seven days).
const NTA_MAX: Duration = Duration::from_secs(7 * 24 * 3600);

/// Subcommands of `tenko dns trust-anchor`.
#[derive(Debug, Clone, Subcommand)]
pub enum TrustAnchorCommand {
    /// List the trust anchors with the state of each key.
    List(ListArgs),
    /// Add a key to the trust anchor of a zone, creating it.
    Add(TrustAnchorAddArgs),
    /// Remove the trust anchor of a zone (an interactive session only).
    Remove(ZoneArgs),
    /// Run the RFC 5011 refresh of a zone's trust anchor now.
    Refresh(ZoneArgs),
}

impl TrustAnchorCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::List(a) => &a.client,
            Self::Add(a) => &a.client,
            Self::Remove(a) | Self::Refresh(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "dns trust-anchor list",
            Self::Add(_) => "dns trust-anchor add",
            Self::Remove(_) => "dns trust-anchor remove",
            Self::Refresh(_) => "dns trust-anchor refresh",
        }
    }
}

/// Subcommands of `tenko dns nta`.
#[derive(Debug, Clone, Subcommand)]
pub enum NtaCommand {
    /// List the negative trust anchors.
    List(ListArgs),
    /// Create a negative trust anchor: a zone whose failing validation is treated as
    /// insecure for a while.
    Add(NtaAddArgs),
    /// Delete a negative trust anchor (its identifier).
    Remove(NtaRemoveArgs),
}

impl NtaCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::List(a) => &a.client,
            Self::Add(a) => &a.client,
            Self::Remove(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "dns nta list",
            Self::Add(_) => "dns nta add",
            Self::Remove(_) => "dns nta remove",
        }
    }
}

/// Subcommands of `tenko dns recursion`.
#[derive(Debug, Clone, Subcommand)]
pub enum RecursionCommand {
    /// The state of a node's recursive resolver.
    Status(NodeArgs),
    /// Prime a node's resolver now (ask the root servers again).
    Prime(NodeArgs),
    /// List what a node's infrastructure cache holds, one page of zone cuts.
    Infra(InfraArgs),
    /// Empty a node's infrastructure cache, or the zone cuts at or below a suffix.
    FlushInfra(InfraFlushArgs),
}

impl RecursionCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::Status(a) | Self::Prime(a) => &a.client,
            Self::Infra(a) => &a.client,
            Self::FlushInfra(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "dns recursion status",
            Self::Prime(_) => "dns recursion prime",
            Self::Infra(_) => "dns recursion infra",
            Self::FlushInfra(_) => "dns recursion flush-infra",
        }
    }
}

/// Arguments of the commands that take a zone.
#[derive(Debug, Clone, Args)]
pub struct ZoneArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone (`example.test`), or `.` for the root.
    #[arg(value_name = "ZONE")]
    pub zone: String,
}

/// Arguments of `tenko dns trust-anchor add`.
#[derive(Debug, Clone, Args)]
#[command(group(ArgGroup::new("key").required(true).args(["ds", "dnskey"])))]
pub struct TrustAnchorAddArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone (`example.test`), or `.` for the root.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// A DS record's data: key tag, algorithm, digest type and the digest in hexadecimal
    /// (`"20326 8 2 E06D44B8..."`).
    #[arg(long, value_name = "DS")]
    pub ds: Option<String>,
    /// A DNSKEY record's data: flags, protocol, algorithm and the key in base64
    /// (`"257 3 8 AwEAAa..."`).
    #[arg(long, value_name = "DNSKEY")]
    pub dnskey: Option<String>,
    /// Replace the root's trust anchor with this key instead of adding to it (the Lab
    /// profile only).
    #[arg(long)]
    pub replace_root: bool,
}

/// Arguments of `tenko dns nta add`.
#[derive(Debug, Clone, Args)]
pub struct NtaAddArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone (`example.test`); never the root.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// How long it applies, at most seven days: `30m`, `12h`, `2d`, `1d12h`.
    #[arg(long, value_name = "DURATION", value_parser = parse_expiry)]
    pub expires: Duration,
    /// Why it exists, 1 to 500 characters.
    #[arg(long, value_name = "TEXT")]
    pub reason: String,
}

/// Arguments of `tenko dns nta remove`.
#[derive(Debug, Clone, Args)]
pub struct NtaRemoveArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The negative trust anchor's identifier.
    #[arg(value_name = "ID")]
    pub id: Uuid,
}

/// Arguments of the commands that take a node.
#[derive(Debug, Clone, Args)]
pub struct NodeArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node's id.
    #[arg(value_name = "NODE")]
    pub node: u64,
}

/// Arguments of `tenko dns recursion infra`.
#[derive(Debug, Clone, Args)]
pub struct InfraArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node's id.
    #[arg(value_name = "NODE")]
    pub node: u64,
    /// Only the zone cuts equal to this name or under it.
    #[arg(long, value_name = "NAME")]
    pub suffix: Option<String>,
    /// Zone cuts in the page, 1 to 1000.
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: u32,
    /// The cursor of the page, as the previous page printed it.
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
}

/// Arguments of `tenko dns recursion flush-infra`.
#[derive(Debug, Clone, Args)]
pub struct InfraFlushArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node's id.
    #[arg(value_name = "NODE")]
    pub node: u64,
    /// Only the zone cuts at or below this suffix; everything when absent.
    #[arg(long, value_name = "NAME")]
    pub suffix: Option<String>,
}

/// A duration such as `30m`, `12h`, `2d` or `1d12h`: whole numbers each followed by `s`, `m`,
/// `h` or `d`. Zero and more than seven days are refused.
///
/// # Errors
///
/// A message naming the mistake.
pub fn parse_expiry(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let bad = || {
        format!(
            "`{text}` is not a duration: numbers followed by s, m, h or d, such as 30m, 12h, 2d \
             or 1d12h"
        )
    };
    if text.is_empty() {
        return Err(bad());
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        let unit: u64 = match ch.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return Err(bad()),
        };
        let count: u64 = digits.parse().map_err(|_| bad())?;
        digits.clear();
        total = count
            .checked_mul(unit)
            .and_then(|secs| total.checked_add(secs))
            .ok_or_else(bad)?;
    }
    if !digits.is_empty() {
        return Err(bad());
    }
    if total == 0 {
        return Err(format!(
            "`{text}` is no time at all: an expiry is at least a second"
        ));
    }
    let duration = Duration::from_secs(total);
    if duration > NTA_MAX {
        return Err(format!(
            "`{text}` is too long: a negative trust anchor lives at most 7 days (7d)"
        ));
    }
    Ok(duration)
}

/// Runs a `tenko dns trust-anchor` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run_trust_anchor(
    target: &Target,
    command: &TrustAnchorCommand,
) -> Result<Output, Failure> {
    match command {
        TrustAnchorCommand::List(_) => anchor_list(target).await,
        TrustAnchorCommand::Add(args) => anchor_add(target, args).await,
        TrustAnchorCommand::Remove(args) => anchor_remove(target, args).await,
        TrustAnchorCommand::Refresh(args) => anchor_refresh(target, args).await,
    }
}

/// Runs a `tenko dns nta` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run_nta(target: &Target, command: &NtaCommand) -> Result<Output, Failure> {
    match command {
        NtaCommand::List(_) => nta_list(target).await,
        NtaCommand::Add(args) => nta_add(target, args).await,
        NtaCommand::Remove(args) => nta_remove(target, args).await,
    }
}

/// Runs a `tenko dns recursion` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run_recursion(target: &Target, command: &RecursionCommand) -> Result<Output, Failure> {
    match command {
        RecursionCommand::Status(args) => status(target, args).await,
        RecursionCommand::Prime(args) => prime(target, args).await,
        RecursionCommand::Infra(args) => infra(target, args).await,
        RecursionCommand::FlushInfra(args) => flush_infra(target, args).await,
    }
}

/// The zone as it goes into a path: canonical, the root as `.`.
fn zone_segment(zone: &str) -> Result<String, Failure> {
    let zone = canonical(zone);
    if zone.is_empty() {
        return Err(usage("the zone is empty: give a name, or `.` for the root"));
    }
    Ok(zone)
}

/// The zone as it goes into a path segment. The root is `.`, which a URL turns into a dot
/// segment that never reaches the server (`/dns/trust-anchors/./refresh` becomes
/// `/dns/trust-anchors/refresh`), so the routes spell it `root` in a path (a zone named
/// `root` is written `root.`).
fn path_zone(zone: &str) -> Result<String, Failure> {
    let zone = zone_segment(zone)?;
    Ok(if zone == "." { "root".to_owned() } else { zone })
}

/// The rows of the trust anchors: one per key.
fn anchor_rows(anchors: &[Value]) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for anchor in anchors {
        let keys = anchor
            .get("keys")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for key in keys {
            let kind = if key.get("digest_type").is_some_and(|d| !d.is_null()) {
                "DS"
            } else {
                "DNSKEY"
            };
            rows.push(vec![
                text(anchor, &["zone"]).to_owned(),
                number(key, &["key_tag"]),
                number(key, &["algorithm"]),
                kind.to_owned(),
                text(key, &["state"]).to_owned(),
                text(key, &["source"]).to_owned(),
                text(key, &["state_since"]).to_owned(),
            ]);
        }
    }
    rows
}

async fn anchor_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/trust-anchors", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    Ok(Output::text(table(
        &["ZONE", "TAG", "ALG", "TYPE", "STATE", "SOURCE", "SINCE"],
        &anchor_rows(&items),
    )))
}

async fn anchor_add(target: &Target, args: &TrustAnchorAddArgs) -> Result<Output, Failure> {
    let zone = zone_segment(&args.zone)?;
    let mut body = json!({ "zone": zone });
    for (field, value) in [("ds", &args.ds), ("dnskey", &args.dnskey)] {
        if let Some(value) = value {
            body[field] = json!(value.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    if args.replace_root {
        body["replace_root"] = json!(true);
    }
    let client = target.connect().await?;
    let answer: Value = client
        .post("/dns/trust-anchors", &body, Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let keys = answer
        .get("keys")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(Output::text(format!(
        "trust anchor of {zone} now holds {keys} key(s)\n"
    )))
}

async fn anchor_remove(target: &Target, args: &ZoneArgs) -> Result<Output, Failure> {
    let zone = path_zone(&args.zone)?;
    let client = target.connect().await?;
    client
        .delete(&format!("/dns/trust-anchors/{}", encode(&zone)), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": zone })));
    }
    Ok(Output::text(format!(
        "removed the trust anchor of {zone}\n"
    )))
}

async fn anchor_refresh(target: &Target, args: &ZoneArgs) -> Result<Output, Failure> {
    let zone = path_zone(&args.zone)?;
    let client = target.connect().await?;
    let path = format!("/dns/trust-anchors/{}/refresh", encode(&zone));
    let answer: Value = client.post(&path, &json!({}), Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "refresh of the trust anchor of {zone} recorded as command {}\n",
        text(&answer, &["command_id"])
    )))
}

async fn nta_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/ntas", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|nta| {
            vec![
                text(nta, &["id"]).to_owned(),
                text(nta, &["zone"]).to_owned(),
                text(nta, &["expires_at"]).to_owned(),
                text(nta, &["reason"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(
        &["ID", "ZONE", "EXPIRES", "REASON"],
        &rows,
    )))
}

async fn nta_add(target: &Target, args: &NtaAddArgs) -> Result<Output, Failure> {
    let zone = zone_segment(&args.zone)?;
    let expires_at = Timestamp::now()
        .checked_add(args.expires)
        .ok_or_else(|| usage("the expiry is out of range"))?
        .to_rfc3339();
    let body = json!({ "zone": zone, "expires_at": expires_at, "reason": args.reason });
    let client = target.connect().await?;
    let answer: Value = client.post("/dns/ntas", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created negative trust anchor {} for {} until {}\n",
        text(&answer, &["id"]),
        text(&answer, &["zone"]),
        text(&answer, &["expires_at"]),
    )))
}

async fn nta_remove(target: &Target, args: &NtaRemoveArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    client
        .delete(&format!("/dns/ntas/{}", args.id), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": args.id.to_string() })));
    }
    Ok(Output::text(format!(
        "deleted negative trust anchor {}\n",
        args.id
    )))
}

/// The status of a node's resolver as lines.
fn describe_status(status: &Value) -> String {
    let mut out = String::new();
    let enabled = status.get("enabled").and_then(Value::as_bool) == Some(true);
    let _ = writeln!(out, "recursion      {}", if enabled { "on" } else { "off" });
    let _ = writeln!(
        out,
        "hints          {} ({})",
        text(status, &["hints_source"]),
        text(status, &["hints_date"])
    );
    match status.get("last_priming").filter(|p| !p.is_null()) {
        Some(priming) => {
            let _ = writeln!(
                out,
                "last priming   {} {}",
                text(priming, &["outcome"]),
                text(priming, &["at"])
            );
        }
        None => {
            let _ = writeln!(out, "last priming   never");
        }
    }
    let _ = writeln!(
        out,
        "infra cache    {} zone cuts, {} servers, {} names",
        number(status, &["infra", "zones"]),
        number(status, &["infra", "servers"]),
        number(status, &["infra", "names"]),
    );
    if let Some(counters) = status.get("counters").and_then(Value::as_object) {
        for (name, value) in counters {
            let _ = writeln!(out, "{name:<14} {}", value.as_u64().unwrap_or_default());
        }
    }
    let problems: Vec<&str> = status
        .get("problems")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "problems       {}",
        if problems.is_empty() {
            "none".to_owned()
        } else {
            problems.join(", ")
        }
    );
    let roots: Vec<Vec<String>> = status
        .get("root_servers")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|root| {
                    vec![
                        text(root, &["name"]).to_owned(),
                        text(root, &["address"]).to_owned(),
                        root.get("srtt_ms")
                            .and_then(Value::as_f64)
                            .map(|ms| format!("{ms:.1}"))
                            .unwrap_or_default(),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    if !roots.is_empty() {
        out.push('\n');
        out.push_str(&table(&["ROOT SERVER", "ADDRESS", "SRTT MS"], &roots));
    }
    let anchors: Vec<Vec<String>> = status
        .get("trust_anchors")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|anchor| {
                    vec![
                        text(anchor, &["zone"]).to_owned(),
                        number(anchor, &["key_tag"]),
                        text(anchor, &["state"]).to_owned(),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    if !anchors.is_empty() {
        out.push('\n');
        out.push_str(&table(&["ANCHOR", "TAG", "STATE"], &anchors));
    }
    out
}

async fn status(target: &Target, args: &NodeArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client
        .get(&format!("/nodes/{}/dns/recursion", args.node))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(describe_status(&answer)))
}

async fn prime(target: &Target, args: &NodeArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let path = format!("/nodes/{}/dns/recursion/prime", args.node);
    let answer: Value = client.post(&path, &json!({}), Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "priming recorded as command {} on node {}\n",
        text(&answer, &["command_id"]),
        args.node
    )))
}

/// The row of a zone cut: the servers by name, how many addresses, the fastest round-trip
/// time, and whether any server is lame.
fn infra_row(cut: &Value) -> Vec<String> {
    let servers = cut
        .get("servers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let names: Vec<&str> = servers.iter().map(|s| text(s, &["name"])).collect();
    let addresses: Vec<&Value> = servers
        .iter()
        .filter_map(|s| s.get("addresses").and_then(Value::as_array))
        .flatten()
        .collect();
    let best = addresses
        .iter()
        .filter_map(|a| a.get("srtt_ms").and_then(Value::as_f64))
        .fold(None, |best: Option<f64>, ms| {
            Some(best.map_or(ms, |b| b.min(ms)))
        });
    let lame = addresses
        .iter()
        .filter(|a| a.get("lame").and_then(Value::as_bool) == Some(true))
        .count();
    vec![
        text(cut, &["zone"]).to_owned(),
        text(cut, &["ds"]).to_owned(),
        number(cut, &["ttl"]),
        addresses.len().to_string(),
        best.map(|ms| format!("{ms:.1}")).unwrap_or_default(),
        if lame == 0 {
            String::new()
        } else {
            lame.to_string()
        },
        names.join(", "),
    ]
}

async fn infra(target: &Target, args: &InfraArgs) -> Result<Output, Failure> {
    let mut query: Vec<(&str, String)> = vec![("limit", args.limit.to_string())];
    for (name, value) in [("suffix", &args.suffix), ("cursor", &args.cursor)] {
        if let Some(value) = value {
            query.push((name, value.clone()));
        }
    }
    let client = target.connect().await?;
    let path = format!("/nodes/{}/dns/infra", args.node);
    let page: Page<Value> = client.get_query(&path, &query).await?;
    if target.json {
        return Ok(Output::json(&page));
    }
    let rows: Vec<Vec<String>> = page.items.iter().map(infra_row).collect();
    let mut output = Output::text(table(
        &["ZONE", "DS", "TTL", "ADDRS", "SRTT MS", "LAME", "SERVERS"],
        &rows,
    ));
    if let Some(cursor) = &page.next_cursor {
        output = output.note(format!("more zone cuts follow: --cursor {cursor}"));
    }
    Ok(output)
}

async fn flush_infra(target: &Target, args: &InfraFlushArgs) -> Result<Output, Failure> {
    let mut path = format!("/nodes/{}/dns/infra/flush", args.node);
    if let Some(suffix) = &args.suffix {
        let _ = write!(path, "?suffix={}", encode(suffix));
    }
    let client = target.connect().await?;
    let answer: Value = client.post(&path, &json!({}), Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "dropped {} zone cut(s) from the infrastructure cache of node {}{}\n",
        number(&answer, &["entries"]),
        args.node,
        args.suffix
            .as_deref()
            .map(|suffix| format!(", at or below {suffix}"))
            .unwrap_or_default()
    )))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{anchor_rows, describe_status, infra_row, parse_expiry};

    #[test]
    fn durations_read_like_people_write_them() {
        assert_eq!(parse_expiry("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_expiry("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_expiry("2d"), Ok(Duration::from_secs(172_800)));
        assert_eq!(parse_expiry("1d12h"), Ok(Duration::from_secs(129_600)));
        assert_eq!(parse_expiry("7d"), Ok(Duration::from_secs(604_800)));
        assert_eq!(parse_expiry("90S"), Ok(Duration::from_secs(90)));
    }

    #[test]
    fn durations_that_are_not_refused_with_a_reason() {
        for text in ["", "d", "5", "5x", "1.5h", "-1h", "h5", "1d 2h"] {
            let error = parse_expiry(text).expect_err(text);
            assert!(error.contains("is not a duration"), "{text}: {error}");
        }
        assert!(parse_expiry("0s").expect_err("zero").contains("no time"));
        let error = parse_expiry("8d").expect_err("too long");
        assert!(error.contains("at most 7 days"), "{error}");
        assert!(parse_expiry("169h").is_err());
        assert!(parse_expiry("99999999999999999999d").is_err());
    }

    #[test]
    fn anchor_keys_make_one_row_each() {
        let anchors = [json!({
            "zone": ".",
            "keys": [
                { "key_tag": 20326, "algorithm": 8, "digest_type": 2, "state": "valid",
                  "source": "shipped", "state_since": "2026-01-01T00:00:00Z" },
                { "key_tag": 38696, "algorithm": 8, "state": "add_pend",
                  "source": "rfc5011", "state_since": "2026-02-01T00:00:00Z" }
            ]
        })];
        let rows = anchor_rows(&anchors);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][..5], [".", "20326", "8", "DS", "valid"]);
        assert_eq!(rows[1][3], "DNSKEY");
    }

    #[test]
    fn a_status_shows_the_figures_and_the_problems() {
        let status = json!({
            "enabled": true, "hints_source": "shipped", "hints_date": "2026-01-31",
            "root_servers": [{ "name": "a.root-servers.net.", "address": "198.51.100.1",
                               "srtt_ms": 12.34 }],
            "infra": { "zones": 3, "servers": 7, "names": 9 },
            "counters": { "answered": 5 },
            "trust_anchors": [{ "zone": ".", "key_tag": 20326, "state": "valid" }],
            "problems": ["clock"]
        });
        let text = describe_status(&status);
        assert!(text.contains("recursion      on"), "{text}");
        assert!(text.contains("last priming   never"), "{text}");
        assert!(text.contains("3 zone cuts, 7 servers, 9 names"), "{text}");
        assert!(text.contains("problems       clock"), "{text}");
        assert!(text.contains("a.root-servers.net."), "{text}");
        assert!(text.contains("12.3"), "{text}");
    }

    #[test]
    fn a_zone_cut_row_counts_addresses_and_lame_servers() {
        let cut = json!({
            "zone": "example.test", "ds": "secure", "ttl": 300,
            "servers": [
                { "name": "ns1.example.test", "addresses": [
                    { "address": "192.0.2.1", "srtt_ms": 20.0, "lame": false },
                    { "address": "2001:db8::1", "srtt_ms": 8.0, "lame": true }] },
                { "name": "ns2.example.test", "addresses": [] }
            ]
        });
        assert_eq!(
            infra_row(&cut),
            [
                "example.test",
                "secure",
                "300",
                "2",
                "8.0",
                "1",
                "ns1.example.test, ns2.example.test"
            ]
        );
    }
}
