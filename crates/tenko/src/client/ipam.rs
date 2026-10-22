//! `tenko ipam reconcile`: the reconciliation view of the public API (`GET /ipam/reconcile`,
//! IPAM-21, WP8.2): ghosts, rogues, orphans, PTR mismatches and conflicts, with the truth
//! that wins per row.

use std::fmt::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};
use tenko_api::client::Client;

use super::{ClientOpts, Failure, Output, Target, table};

/// Subcommands of `tenko ipam`.
#[derive(Debug, Clone, Subcommand)]
pub enum IpamCommand {
    /// Show where intent, the DHCP leases, the DNS records and the scans disagree.
    Reconcile(ReconcileArgs),
}

impl IpamCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Reconcile(args) => &args.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Reconcile(_) => "ipam reconcile",
        }
    }
}

/// The kinds of rows of the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KindArg {
    /// Intent that nothing has shown for longer than the scope's lease time.
    Ghost,
    /// A lease or sighting without intent.
    Rogue,
    /// A DNS record of an address no host holds.
    Orphan,
    /// A PTR record whose name disagrees with the address's DNS name.
    #[value(name = "ptr_mismatch", alias = "ptr-mismatch")]
    PtrMismatch,
    /// Two MAC addresses on one address (IPAM-23).
    Conflict,
}

impl KindArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Ghost => "ghost",
            Self::Rogue => "rogue",
            Self::Orphan => "orphan",
            Self::PtrMismatch => "ptr_mismatch",
            Self::Conflict => "conflict",
        }
    }
}

/// Arguments of `tenko ipam reconcile`.
#[derive(Debug, Clone, Args)]
pub struct ReconcileArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only rows inside this prefix: its identifier, or its network (`192.0.2.0/24`) in the
    /// default VRF.
    #[arg(long, value_name = "ID_OR_CIDR")]
    pub prefix: Option<String>,
    /// Only rows of this host: its identifier or its name; also prints its OS field.
    #[arg(long, value_name = "ID_OR_NAME")]
    pub host: Option<String>,
    /// Only rows of this kind.
    #[arg(long, value_enum, value_name = "KIND")]
    pub kind: Option<KindArg>,
    /// Most rows per request, 1 to 1,000.
    #[arg(long, value_name = "N", default_value_t = 1000)]
    pub limit: u32,
    /// Follow the cursor and list every page.
    #[arg(long)]
    pub all: bool,
}

/// Runs a `tenko ipam` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &IpamCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        IpamCommand::Reconcile(args) => reconcile(&target, args).await,
    }
}

#[derive(Serialize)]
struct Query<'a> {
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
}

/// Whether the text is a UUID (an identifier rather than a network or a name).
fn is_id(text: &str) -> bool {
    uuid::Uuid::parse_str(text.trim()).is_ok()
}

fn not_found(what: &str, text: &str) -> Failure {
    Failure::new(crate::exit::API, format!("no {what} {text}"))
}

/// The identifier of a prefix given by identifier or network.
async fn prefix_id(client: &Client, text: &str) -> Result<String, Failure> {
    if is_id(text) {
        return Ok(text.trim().to_owned());
    }
    if !text.contains('/') {
        return Err(Failure::new(
            crate::exit::USAGE,
            format!("--prefix {text}: give an identifier or a network such as 192.0.2.0/24"),
        ));
    }
    let page: Value = client
        .get_query(
            "/prefixes",
            &json!({ "within": text.trim(), "limit": 1000 }),
        )
        .await?;
    let wanted = text.trim().to_ascii_lowercase();
    page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|item| {
            item["cidr"]
                .as_str()
                .is_some_and(|cidr| cidr.eq_ignore_ascii_case(&wanted))
        })
        .and_then(|item| item["id"].as_str().map(str::to_owned))
        .ok_or_else(|| not_found("prefix", text))
}

/// The identifier of a host given by identifier or name.
async fn host_id(client: &Client, text: &str) -> Result<String, Failure> {
    if is_id(text) {
        return Ok(text.trim().to_owned());
    }
    let page: Value = client
        .get_query("/hosts", &json!({ "q": text.trim(), "limit": 1000 }))
        .await?;
    page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|item| {
            item["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(text.trim()))
        })
        .and_then(|item| item["id"].as_str().map(str::to_owned))
        .ok_or_else(|| not_found("host", text))
}

async fn reconcile(target: &Target, args: &ReconcileArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let prefix = match &args.prefix {
        Some(text) => Some(prefix_id(&client, text).await?),
        None => None,
    };
    let host = match &args.host {
        Some(text) => Some(host_id(&client, text).await?),
        None => None,
    };
    let mut items: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let (revision, truths) = loop {
        let query = Query {
            limit: args.limit.clamp(1, 1000),
            cursor: cursor.as_deref(),
            prefix: prefix.as_deref(),
            host: host.as_deref(),
            kind: args.kind.map(KindArg::api),
        };
        let page: Value = client.get_query("/ipam/reconcile", &query).await?;
        if let Some(rows) = page["items"].as_array() {
            items.extend(rows.iter().cloned());
        }
        cursor = page["next_cursor"].as_str().map(str::to_owned);
        if !args.all || cursor.is_none() {
            break (page["revision"].clone(), page["host"].clone());
        }
    };
    if target.json {
        let mut answer = json!({
            "items": items,
            "next_cursor": cursor,
            "revision": revision,
        });
        if !truths.is_null() {
            answer["host"] = truths;
        }
        return Ok(Output::json(&answer));
    }
    let rows: Vec<Vec<String>> = items.iter().map(row).collect();
    let mut text = String::new();
    if !truths.is_null() {
        text.push_str(&host_text(&truths));
    }
    if rows.is_empty() {
        text.push_str("no differences between the truths\n");
    } else {
        text.push_str(&table(
            &[
                "ADDRESS", "KIND", "INTENT", "LEASE", "DNS", "SCAN", "WINNER", "RULE",
            ],
            &rows,
        ));
    }
    let mut output = Output::text(text);
    if cursor.is_some() {
        output = output.note("more rows follow: use --all or a narrower filter");
    }
    Ok(output)
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn dash(text: String) -> String {
    if text.is_empty() {
        "-".to_owned()
    } else {
        text
    }
}

/// What intent says, in a cell: the host and its mode, else the address alone.
fn intent_cell(intent: &Value) -> String {
    if intent.is_null() {
        return "-".to_owned();
    }
    match (intent["host_name"].as_str(), intent["mode"].as_str()) {
        (Some(name), Some(mode)) => format!("{name} ({mode})"),
        (Some(name), None) => name.to_owned(),
        _ => "address, no host".to_owned(),
    }
}

/// What a lease or the scans say: the MAC addresses, else the sources.
fn observed_cell(observed: &Value) -> String {
    if observed.is_null() {
        return "-".to_owned();
    }
    let macs = strings(&observed["macs"]);
    if macs.is_empty() {
        dash(strings(&observed["sources"]).join(" "))
    } else {
        macs.join(" ")
    }
}

/// What the zones say: the forward names, then `PTR` and the PTR names.
fn dns_cell(dns: &Value) -> String {
    if dns.is_null() {
        return "-".to_owned();
    }
    let mut parts = strings(&dns["forward"]);
    let ptr = strings(&dns["ptr"]);
    if !ptr.is_empty() {
        parts.push(format!("PTR {}", ptr.join(" ")));
    }
    dash(parts.join(" "))
}

fn row(item: &Value) -> Vec<String> {
    let text = |key: &str| item[key].as_str().unwrap_or("-").to_owned();
    let mut rule = text("rule_id");
    if let Some(proposal) = item["proposal"].as_str() {
        let _ = write!(rule, " (proposal {proposal})");
    }
    vec![
        text("address"),
        text("kind"),
        intent_cell(&item["intent"]),
        observed_cell(&item["lease"]),
        dns_cell(&item["dns"]),
        observed_cell(&item["scan"]),
        item["winner"].as_str().unwrap_or("none").to_owned(),
        rule,
    ]
}

/// The host's truths: the OS field by precedence and the vendors.
fn host_text(truths: &Value) -> String {
    let name = truths["name"].as_str().unwrap_or("-");
    let os = &truths["os"];
    let os = if os.is_null() {
        "-".to_owned()
    } else {
        format!(
            "{} ({} %, {})",
            os["guess"].as_str().unwrap_or("-"),
            os["confidence"].as_u64().unwrap_or(0),
            os["source"].as_str().unwrap_or("-")
        )
    };
    format!(
        "host {name}\nos: {os}\nvendors: {}\n\n",
        dash(strings(&truths["vendors"]).join(", "))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_shows_the_four_truths_and_the_rule() {
        let item = json!({
            "address": "192.0.2.50",
            "kind": "rogue",
            "lease": { "macs": ["00:00:5e:00:53:50"], "sources": ["dhcp:1"] },
            "dns": { "forward": ["laptop.example.test"], "ptr": ["other.example.test"] },
            "winner": "lease",
            "rule_id": "newest_sighting",
            "proposal": "0190d1c2-0000-7000-8000-000000000001",
        });
        assert_eq!(
            row(&item),
            [
                "192.0.2.50",
                "rogue",
                "-",
                "00:00:5e:00:53:50",
                "laptop.example.test PTR other.example.test",
                "-",
                "lease",
                "newest_sighting (proposal 0190d1c2-0000-7000-8000-000000000001)"
            ]
        );
        let conflict = json!({
            "address": "192.0.2.60",
            "kind": "conflict",
            "intent": { "host_name": "printer", "mode": "reserved" },
            "scan": { "macs": [], "sources": ["probe:7:arp"] },
            "rule_id": "never_automatic",
        });
        let cells = row(&conflict);
        assert_eq!(cells[2], "printer (reserved)");
        assert_eq!(cells[5], "probe:7:arp");
        assert_eq!(cells[6], "none");
    }

    #[test]
    fn the_host_block_names_the_os_field() {
        let truths = json!({
            "name": "tv",
            "os": { "guess": "Android 13", "confidence": 90, "source": "dhcp:1" },
            "vendors": ["android-dhcp-13"],
        });
        assert_eq!(
            host_text(&truths),
            "host tv\nos: Android 13 (90 %, dhcp:1)\nvendors: android-dhcp-13\n\n"
        );
        assert!(is_id("0190d1c2-0000-7000-8000-000000000001"));
        assert!(!is_id("printer"));
    }
}
