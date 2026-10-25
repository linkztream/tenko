//! `tenko ipam reconcile`: the reconciliation view of the public API (`GET /ipam/reconcile`,
//! IPAM-21, WP8.2): ghosts, rogues, orphans, PTR mismatches and conflicts, with the truth
//! that wins per row. `tenko ipam address reserve`: reserving an address in DHCP
//! (`POST /addresses/{id}/reserve`, or `POST /addresses/reserve` for an address given by
//! value), the IPAM rows of the reservation in one batch. `tenko ipam host
//! decommission|reinstate`: the lifecycle of a host ([`super::ipam_host`]).

use std::{fmt::Write as _, net::IpAddr, str::FromStr};

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};
use tenko_api::client::Client;

use super::{ClientOpts, Failure, Output, Target, ipam_host::HostCommand, table};

/// Subcommands of `tenko ipam`.
#[derive(Debug, Clone, Subcommand)]
pub enum IpamCommand {
    /// Show where intent, the DHCP leases, the DNS records and the scans disagree.
    Reconcile(ReconcileArgs),
    /// Act on one address.
    Address {
        /// The `ipam address` subcommand to run.
        #[command(subcommand)]
        action: AddressCommand,
    },
    /// Act on one host.
    Host {
        /// The `ipam host` subcommand to run.
        #[command(subcommand)]
        action: HostCommand,
    },
}

/// Subcommands of `tenko ipam address`.
#[derive(Debug, Clone, Subcommand)]
pub enum AddressCommand {
    /// Reserve an address in DHCP: the host becomes reserved, its interface gets the MAC
    /// address and client identifier, the address is bound to it.
    Reserve(ReserveArgs),
}

impl IpamCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Reconcile(args) => &args.client,
            Self::Address {
                action: AddressCommand::Reserve(args),
            } => &args.client,
            Self::Host { action } => action.client(),
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Reconcile(_) => "ipam reconcile",
            Self::Address {
                action: AddressCommand::Reserve(_),
            } => "ipam address reserve",
            Self::Host { action } => action.name(),
        }
    }
}

/// The status of a reserved address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReserveStatus {
    /// Served now.
    Active,
    /// Planned; served as well (a move or a device not yet installed).
    Planned,
}

/// Arguments of `tenko ipam address reserve`.
#[derive(Debug, Clone, Args)]
pub struct ReserveArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The address: its identifier, or the address itself (`192.0.2.20`), which is created
    /// when IPAM does not hold it.
    #[arg(value_name = "ID_OR_ADDRESS")]
    pub address: String,
    /// The VRF of an address given by value; the default VRF when absent.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
    /// The host: its identifier or name. Without it and without --new-host, the host of the
    /// address's interface.
    #[arg(long, value_name = "ID_OR_NAME", conflicts_with = "new_host")]
    pub host: Option<String>,
    /// Create a new host of mode reserved with this name.
    #[arg(long, value_name = "NAME")]
    pub new_host: Option<String>,
    /// The interface of the host (identifier). Without it and without --new-interface, the
    /// address's interface, else the host's only one, else a new eth0.
    #[arg(long, value_name = "ID", conflicts_with = "new_interface")]
    pub interface: Option<String>,
    /// Create a new interface of the host with this name.
    #[arg(long, value_name = "NAME")]
    pub new_interface: Option<String>,
    /// The MAC address the interface gets.
    #[arg(long, value_name = "MAC")]
    pub mac: Option<String>,
    /// The DHCPv4 client identifier (option 61) in hexadecimal; the reservation is then
    /// keyed by it.
    #[arg(long, value_name = "HEX", conflicts_with = "clear_client_id")]
    pub client_id: Option<String>,
    /// Remove the interface's client identifier, so the reservation is keyed by the MAC.
    #[arg(long)]
    pub clear_client_id: bool,
    /// The status of the address afterwards; an active or planned address keeps its own.
    #[arg(long, value_enum, value_name = "STATUS")]
    pub status: Option<ReserveStatus>,
    /// Show the plan without writing.
    #[arg(long)]
    pub dry_run: bool,
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
        IpamCommand::Address {
            action: AddressCommand::Reserve(args),
        } => reserve(&target, args).await,
        IpamCommand::Host { action } => super::ipam_host::run(&target, action).await,
    }
}

fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(crate::exit::USAGE, message.to_string())
}

/// The path and the body of a reservation request, checked without the server.
fn reserve_request(args: &ReserveArgs, host: Option<String>) -> Result<(String, Value), Failure> {
    let mut body = serde_json::Map::new();
    let path = if is_id(&args.address) {
        if args.vrf.is_some() {
            return Err(usage(
                "--vrf names the VRF of an address given by value, not by identifier",
            ));
        }
        format!("/addresses/{}/reserve", args.address.trim())
    } else {
        let ip = IpAddr::from_str(args.address.trim()).map_err(|_| {
            usage(format!(
                "`{}` is neither an address identifier nor an IP address",
                args.address
            ))
        })?;
        body.insert("ip".into(), json!(ip.to_string()));
        if let Some(vrf) = &args.vrf {
            body.insert("vrf".into(), json!(vrf.trim()));
        }
        "/addresses/reserve".to_owned()
    };
    if let Some(host) = host {
        body.insert("host".into(), json!(host));
    }
    if let Some(name) = &args.new_host {
        tenko_core::net::HostName::new(name.trim())
            .map_err(|error| usage(format!("--new-host {name}: {error}")))?;
        body.insert("new_host".into(), json!(name.trim()));
    }
    if let Some(interface) = &args.interface {
        if !is_id(interface) {
            return Err(usage(format!(
                "--interface {interface}: give the interface's identifier"
            )));
        }
        body.insert("interface".into(), json!(interface.trim()));
    }
    if let Some(name) = &args.new_interface {
        body.insert("new_interface".into(), json!(name.trim()));
    }
    if let Some(mac) = &args.mac {
        let mac = tenko_core::MacAddr::from_str(mac.trim())
            .map_err(|error| usage(format!("--mac {mac}: {error}")))?;
        body.insert("mac".into(), json!(mac.to_string()));
    }
    if let Some(client_id) = &args.client_id {
        let octets = tenko_core::serde_util::from_hex(client_id.trim()).ok_or_else(|| {
            usage(format!(
                "--client-id {client_id}: not hexadecimal octets such as 01:02:00:5e:10:00:01"
            ))
        })?;
        body.insert(
            "client_id".into(),
            json!(tenko_core::serde_util::to_hex(&octets)),
        );
    } else if args.clear_client_id {
        body.insert("client_id".into(), Value::Null);
    }
    if let Some(status) = args.status {
        let status = match status {
            ReserveStatus::Active => "active",
            ReserveStatus::Planned => "planned",
        };
        body.insert("status".into(), json!(status));
    }
    let path = if args.dry_run {
        format!("{path}?dry_run=true")
    } else {
        path
    };
    Ok((path, Value::Object(body)))
}

async fn reserve(target: &Target, args: &ReserveArgs) -> Result<Output, Failure> {
    // Check what can be checked before connecting.
    reserve_request(args, None)?;
    let client = target.connect().await?;
    let host = match &args.host {
        Some(text) => Some(host_id(&client, text).await?),
        None => None,
    };
    let (path, body) = reserve_request(args, host)?;
    let answer: Value = client.post(&path, &body, None).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(reserve_text(&answer)))
}

/// The answer of a reservation in words.
fn reserve_text(answer: &Value) -> String {
    let text = |value: &Value| value.as_str().unwrap_or("-").to_owned();
    let address = &answer["address"];
    let interface = &answer["interface"];
    let identity = match interface["client_id"].as_str() {
        Some(client_id) => format!("client identifier {client_id}"),
        None => format!("MAC address {}", text(&interface["mac"])),
    };
    let mut out = String::new();
    let verb = if answer["dry_run"] == true {
        "would be reserved"
    } else if answer["unchanged"] == true {
        "is reserved already"
    } else {
        "is reserved"
    };
    let _ = writeln!(
        out,
        "{} {verb} for host {} on interface {}, keyed by its {identity}; status {}",
        text(&address["ip"]),
        text(&answer["host"]["name"]),
        text(&interface["name"]),
        text(&address["status"]),
    );
    for warning in answer["warnings"].as_array().into_iter().flatten() {
        let _ = writeln!(out, "warning: {}", text(&warning["message"]));
    }
    out
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

/// The identifier of a host given by identifier or name; a decommissioned host is found
/// too.
pub(super) async fn host_id(client: &Client, text: &str) -> Result<String, Failure> {
    if is_id(text) {
        return Ok(text.trim().to_owned());
    }
    let page: Value = client
        .get_query(
            "/hosts",
            &json!({ "q": text.trim(), "limit": 1000, "lifecycle": "all" }),
        )
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
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: IpamCommand,
    }

    fn parse(words: &[&str]) -> ReserveArgs {
        let cli = Cli::try_parse_from(["ipam", "address", "reserve"].iter().chain(words).copied())
            .expect("arguments");
        match cli.command {
            IpamCommand::Address {
                action: AddressCommand::Reserve(args),
            } => args,
            IpamCommand::Reconcile(_) | IpamCommand::Host { .. } => {
                unreachable!("parsed as reserve")
            }
        }
    }

    #[test]
    fn an_address_by_value_goes_to_the_value_route_with_its_identity() {
        let args = parse(&[
            "192.0.2.20",
            "--new-host",
            "printer01",
            "--mac",
            "02-00-5E-10-00-01",
            "--client-id",
            "01:02:00:5e:10:00:01",
            "--status",
            "planned",
            "--dry-run",
        ]);
        let (path, body) = reserve_request(&args, None).expect("request");
        assert_eq!(path, "/addresses/reserve?dry_run=true");
        assert_eq!(
            body,
            json!({
                "ip": "192.0.2.20",
                "new_host": "printer01",
                "mac": "02:00:5e:10:00:01",
                "client_id": "0102005e100001",
                "status": "planned"
            })
        );
    }

    #[test]
    fn an_address_by_identifier_goes_to_its_route_and_may_clear_the_client_id() {
        let id = "01890a5d-ac96-774b-bcce-b302099a8057";
        let args = parse(&[id, "--clear-client-id"]);
        let (path, body) = reserve_request(&args, Some("host-id".into())).expect("request");
        assert_eq!(path, format!("/addresses/{id}/reserve"));
        assert_eq!(body, json!({ "host": "host-id", "client_id": null }));
    }

    #[test]
    fn mistakes_are_usage_errors_before_the_server_is_asked() {
        for words in [
            &["not-an-address"][..],
            &["192.0.2.20", "--mac", "02:00"][..],
            &["192.0.2.20", "--client-id", "xyz"][..],
            &["192.0.2.20", "--interface", "eth0"][..],
            &["192.0.2.20", "--new-host", "living room tv"][..],
            &["01890a5d-ac96-774b-bcce-b302099a8057", "--vrf", "x"][..],
        ] {
            let error = reserve_request(&parse(words), None).expect_err("refused");
            assert_eq!(error.status, crate::exit::USAGE, "{words:?}");
        }
    }

    #[test]
    fn the_answer_says_what_was_reserved() {
        let answer = json!({
            "address": { "ip": "192.0.2.20", "status": "active" },
            "host": { "name": "printer01" },
            "interface": { "name": "eth0", "mac": "02:00:5e:10:00:01" },
            "dry_run": false,
            "unchanged": false,
            "warnings": []
        });
        assert_eq!(
            reserve_text(&answer),
            "192.0.2.20 is reserved for host printer01 on interface eth0, keyed by its MAC address 02:00:5e:10:00:01; status active\n"
        );
    }

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
