//! `tenko dns view ...`: views (DNS-20, `/api/v1/dns/views`). A view is tried in its
//! `order`; the first view whose rules all hold for a query wins, and its scope map picks the
//! zone scopes the query sees. A query no view matches is in the implicit default view: the
//! default scope of every zone and the profile's recursion default.
//!
//! # Rules
//!
//! One flag per test, repeatable; the values of one test form one rule (any of them
//! matches), and every rule must hold:
//!
//! - `--client-subnet 192.0.2.0/24` (the client address is in a prefix),
//! - `--transport udp|tcp|dot|doh`,
//! - `--interface 192.0.2.53` (the server address the query arrived on),
//! - `--qtype AAAA`,
//! - `--qname example.test` (the query name is at or below the suffix),
//! - `--time 22:00-06:00` (UTC, both minutes included; a window across midnight wraps).
//!
//! # Scopes
//!
//! `--scope <zone>:<scope>[:<weight>]`, repeatable: the zone by name or identifier, a scope
//! the zone has, and a weight from 1 to 1000 (1 when absent). Among the scopes of one zone
//! a client gets one in proportion to the weights, the same one every time.

use std::fmt::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Map, Value, json};
use tenko_api::client::Client;
use uuid::Uuid;

use super::{
    ClientOpts, Failure, ListArgs, NamedArgs, Output, Target, key, list_all, not_found, number,
    resolve_acl, resolve_zone, table, text, usage,
};

/// Subcommands of `tenko dns view`.
#[derive(Debug, Clone, Subcommand)]
pub enum ViewCommand {
    /// List the views in the order they are tried.
    List(ListArgs),
    /// Create a view.
    Create(ViewCreateArgs),
    /// Show one view (its identifier or its name).
    Get(NamedArgs),
    /// Change a view.
    Update(ViewUpdateArgs),
    /// Delete a view (its identifier or its name).
    Delete(NamedArgs),
}

impl ViewCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::List(a) => &a.client,
            Self::Create(a) => &a.client,
            Self::Get(a) | Self::Delete(a) => &a.client,
            Self::Update(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "dns view list",
            Self::Create(_) => "dns view create",
            Self::Get(_) => "dns view get",
            Self::Update(_) => "dns view update",
            Self::Delete(_) => "dns view delete",
        }
    }
}

/// A transport a query arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum QueryTransportArg {
    /// UDP on port 53.
    Udp,
    /// TCP on port 53.
    Tcp,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS.
    Doh,
}

impl QueryTransportArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }
}

// WP10.0: how a view resolves names outside its zones and the rules.
/// How a view's clients get names outside the zones and the forwarding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResolutionArg {
    /// Resolve iteratively from the root servers.
    Recurse,
    /// Forward to the default forwarder.
    Forward,
    /// Answer REFUSED.
    Refuse,
}

impl ResolutionArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Recurse => "recurse",
            Self::Forward => "forward",
            Self::Refuse => "refuse",
        }
    }
}

/// The values of `tenko dns view update --resolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResolutionUpdateArg {
    /// Resolve iteratively from the root servers.
    Recurse,
    /// Forward to the default forwarder.
    Forward,
    /// Answer REFUSED.
    Refuse,
    /// Follow the profile's default.
    Default,
}

impl ResolutionUpdateArg {
    /// The body fields: `resolution`, or `default_resolution` for `default`.
    fn field(self) -> (&'static str, Value) {
        match self {
            Self::Recurse => ("resolution", json!("recurse")),
            Self::Forward => ("resolution", json!("forward")),
            Self::Refuse => ("resolution", json!("refuse")),
            Self::Default => ("default_resolution", json!(true)),
        }
    }
}
// WP10.0: end.

/// The rule flags of `create` and `update`.
#[derive(Debug, Clone, Default, Args)]
pub struct RuleArgs {
    /// The client address is in this prefix (`192.0.2.0/24`, `2001:db8::/32`). Repeat for
    /// more.
    #[arg(long = "client-subnet", value_name = "PREFIX")]
    pub client_subnets: Vec<String>,
    /// The query arrived on this transport. Repeat for more.
    #[arg(long = "transport", value_enum, value_name = "TRANSPORT")]
    pub transports: Vec<QueryTransportArg>,
    /// The query arrived on this server address. Repeat for more.
    #[arg(long = "interface", value_name = "ADDRESS")]
    pub interfaces: Vec<String>,
    /// The query type is this one (`A`, `AAAA`, `MX`). Repeat for more.
    #[arg(long = "qtype", value_name = "TYPE")]
    pub qtypes: Vec<String>,
    /// The query name is at or below this name. Repeat for more.
    #[arg(long = "qname", value_name = "SUFFIX")]
    pub qnames: Vec<String>,
    /// The time of day in UTC is in this window (`08:00-17:00`, `22:00-06:00`).
    #[arg(long = "time", value_name = "FROM-TO")]
    pub time: Option<String>,
}

impl RuleArgs {
    fn given(&self) -> bool {
        !(self.client_subnets.is_empty()
            && self.transports.is_empty()
            && self.interfaces.is_empty()
            && self.qtypes.is_empty()
            && self.qnames.is_empty()
            && self.time.is_none())
    }
}

/// Arguments of `tenko dns view create`.
#[derive(Debug, Clone, Args)]
pub struct ViewCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The rules.
    #[command(flatten)]
    pub rules: RuleArgs,
    /// A zone scope the view sees: `<zone>:<scope>[:<weight>]`. Repeat for more.
    #[arg(long = "scope", value_name = "ZONE:SCOPE[:WEIGHT]")]
    pub scopes: Vec<String>,
    /// The access list of the clients that may recurse (its name or identifier); the
    /// profile's default when absent.
    #[arg(long, value_name = "ACL")]
    pub recursion: Option<String>,
    // WP10.0
    /// How the view's clients get names outside the zones and the forwarding rules; the
    /// profile's default when absent.
    #[arg(long, value_enum, value_name = "MODE")]
    pub resolution: Option<ResolutionArg>,
    // WP10.0: end.
    /// The position, from 1; the views from there move one down. Last when absent.
    #[arg(long, value_name = "N")]
    pub order: Option<u32>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dns view update`.
#[derive(Debug, Clone, Args)]
pub struct ViewUpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The view: its identifier or its name.
    #[arg(value_name = "VIEW")]
    pub view: String,
    /// A new name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// New rules, replacing all of them.
    #[command(flatten)]
    pub rules: RuleArgs,
    /// Remove every rule: the view matches every query.
    #[arg(long, conflicts_with_all = ["client_subnets", "transports", "interfaces", "qtypes", "qnames", "time"])]
    pub no_rules: bool,
    /// New zone scopes, replacing all of them; as for `create`.
    #[arg(long = "scope", value_name = "ZONE:SCOPE[:WEIGHT]")]
    pub scopes: Vec<String>,
    /// Remove every zone scope: the view sees the default scope of every zone.
    #[arg(long, conflicts_with = "scopes")]
    pub no_scopes: bool,
    /// The recursion access list.
    #[arg(long, value_name = "ACL", conflicts_with = "default_recursion")]
    pub recursion: Option<String>,
    /// Follow the profile's default for recursion.
    #[arg(long)]
    pub default_recursion: bool,
    // WP10.0
    /// How the view's clients get names outside the zones and the forwarding rules: resolve
    /// them iteratively, forward them to the default forwarder, refuse them, or `default`
    /// to follow the profile.
    #[arg(long, value_enum, value_name = "MODE")]
    pub resolution: Option<ResolutionUpdateArg>,
    // WP10.0: end.
    /// A new position, from 1.
    #[arg(long, value_name = "N")]
    pub order: Option<u32>,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Runs `tenko dns view`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &ViewCommand) -> Result<Output, Failure> {
    match command {
        ViewCommand::List(_) => list(target).await,
        ViewCommand::Create(args) => create(target, args).await,
        ViewCommand::Get(args) => get(target, args).await,
        ViewCommand::Update(args) => update(target, args).await,
        ViewCommand::Delete(args) => delete(target, args).await,
    }
}

/// A minute of the day from `HH:MM`.
fn minute(text: &str) -> Option<u16> {
    let (hours, minutes) = text.trim().split_once(':')?;
    let (hours, minutes): (u16, u16) = (hours.parse().ok()?, minutes.parse().ok()?);
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

/// The rules as the API takes them.
fn parse_rules(args: &RuleArgs) -> Result<Vec<Value>, Failure> {
    let mut rules = Vec::new();
    if !args.client_subnets.is_empty() {
        for prefix in &args.client_subnets {
            prefix.trim().parse::<ipnet::IpNet>().map_err(|_| {
                usage(format!(
                    "`{prefix}` is not a prefix such as 192.0.2.0/24 or 2001:db8::/32"
                ))
            })?;
        }
        rules.push(json!({"test": "client_subnet", "prefixes": args.client_subnets.iter().map(|p| p.trim()).collect::<Vec<_>>()}));
    }
    if !args.transports.is_empty() {
        let transports: Vec<&str> = args.transports.iter().map(|t| t.api()).collect();
        rules.push(json!({"test": "transport", "transports": transports}));
    }
    if !args.interfaces.is_empty() {
        for address in &args.interfaces {
            address
                .trim()
                .parse::<std::net::IpAddr>()
                .map_err(|_| usage(format!("`{address}` is not an address")))?;
        }
        rules.push(json!({"test": "interface", "addresses": args.interfaces.iter().map(|a| a.trim()).collect::<Vec<_>>()}));
    }
    if !args.qtypes.is_empty() {
        let types: Vec<String> = args
            .qtypes
            .iter()
            .map(|t| t.trim().to_ascii_uppercase())
            .collect();
        rules.push(json!({"test": "qtype", "types": types}));
    }
    if !args.qnames.is_empty() {
        let suffixes: Vec<String> = args.qnames.iter().map(|n| super::canonical(n)).collect();
        rules.push(json!({"test": "qname", "suffixes": suffixes}));
    }
    if let Some(window) = &args.time {
        let bad = || {
            usage(format!(
                "`{window}` is not a time window such as 08:00-17:00"
            ))
        };
        let (from, to) = window.split_once('-').ok_or_else(bad)?;
        let (from, to) = (minute(from).ok_or_else(bad)?, minute(to).ok_or_else(bad)?);
        rules.push(json!({"test": "time_of_day", "from_minute": from, "to_minute": to}));
    }
    Ok(rules)
}

/// The scope map as the API takes it, the zones looked up by name.
async fn parse_scopes(client: &Client, scopes: &[String]) -> Result<Vec<Value>, Failure> {
    let mut map = Vec::new();
    for entry in scopes {
        let bad = || {
            usage(format!(
                "`{entry}` is not a zone scope: <zone>:<scope>[:<weight>], such as \
                 example.test:inside:700"
            ))
        };
        let mut parts = entry.split(':');
        let (Some(zone), Some(scope)) = (parts.next(), parts.next()) else {
            return Err(bad());
        };
        let weight: u16 = match parts.next() {
            Some(weight) => weight.trim().parse().map_err(|_| bad())?,
            None => 1,
        };
        if parts.next().is_some() || zone.trim().is_empty() || scope.trim().is_empty() {
            return Err(bad());
        }
        let zone = resolve_zone(client, zone.trim()).await?;
        map.push(json!({"zone": text(&zone, &["id"]), "scope": scope.trim(), "weight": weight}));
    }
    Ok(map)
}

/// The view `reference` names: its identifier, or its name.
async fn resolve_view(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/dns/views/{reference}")).await?);
    }
    let wanted = reference.to_lowercase();
    list_all(client, "/dns/views", &[])
        .await?
        .into_iter()
        .find(|view| text(view, &["name"]).to_lowercase() == wanted)
        .ok_or_else(|| not_found("dns.view.not_found", "view", reference))
}

fn values(rule: &Value, key: &str) -> String {
    rule.get(key)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|value| value.as_str().unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn clock(minute: u64) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// One rule in words.
fn present_rule(rule: &Value) -> String {
    match text(rule, &["test"]) {
        "client_subnet" => format!("client in {}", values(rule, "prefixes")),
        "transport" => format!("transport {}", values(rule, "transports")),
        "interface" => format!("arrives on {}", values(rule, "addresses")),
        "qtype" => format!("type {}", values(rule, "types")),
        "qname" => format!("name in {}", values(rule, "suffixes")),
        "time_of_day" => format!(
            "time {}-{} UTC",
            clock(rule["from_minute"].as_u64().unwrap_or_default()),
            clock(rule["to_minute"].as_u64().unwrap_or_default())
        ),
        other => other.to_owned(),
    }
}

fn rules_of(view: &Value) -> Vec<String> {
    view.get("rules")
        .and_then(Value::as_array)
        .map(|rules| rules.iter().map(present_rule).collect())
        .unwrap_or_default()
}

/// The scopes of a view as `<zone>:<scope>:<weight>`, the zones by name where known.
fn scopes_of(view: &Value, zones: &[Value]) -> Vec<String> {
    view.get("scope_map")
        .and_then(Value::as_array)
        .map(|map| {
            map.iter()
                .map(|entry| {
                    let id = text(entry, &["zone"]);
                    let zone = zones
                        .iter()
                        .find(|zone| text(zone, &["id"]) == id)
                        .map_or(id, |zone| text(zone, &["name"]));
                    format!(
                        "{zone}:{}:{}",
                        text(entry, &["scope"]),
                        number(entry, &["weight"])
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn recursion_of(view: &Value, acls: &[Value]) -> String {
    let id = text(view, &["recursion"]);
    if id.is_empty() {
        return "profile default".to_owned();
    }
    acls.iter()
        .find(|acl| text(acl, &["id"]) == id)
        .map_or(id, |acl| text(acl, &["name"]))
        .to_owned()
}

// WP10.4: the view's resolution, or the profile's it follows.
/// The view's `resolution`, else `default (<the profile's>)`.
fn resolution_of(view: &Value) -> String {
    match text(view, &["resolution"]) {
        "" => match text(view, &["profile_resolution"]) {
            "" => "profile default".to_owned(),
            profile => format!("profile default ({profile})"),
        },
        mode => mode.to_owned(),
    }
}
// WP10.4: end.

fn describe(view: &Value, zones: &[Value], acls: &[Value]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "name         {}", text(view, &["name"]));
    let _ = writeln!(out, "id           {}", text(view, &["id"]));
    let _ = writeln!(out, "order        {}", number(view, &["order"]));
    let _ = writeln!(out, "recursion    {}", recursion_of(view, acls));
    // WP10.0
    let _ = writeln!(out, "resolution   {}", resolution_of(view));
    // WP10.0: end.
    let description = text(view, &["description"]);
    if !description.is_empty() {
        let _ = writeln!(out, "description  {description}");
    }
    let _ = writeln!(out, "revision     {}", number(view, &["revision"]));
    let rules = rules_of(view);
    if rules.is_empty() {
        let _ = writeln!(out, "rules        none: every query");
    }
    for rule in rules {
        let _ = writeln!(out, "rule         {rule}");
    }
    for scope in scopes_of(view, zones) {
        let _ = writeln!(out, "scope        {scope}");
    }
    out
}

async fn list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/views", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let zones = list_all(&client, "/dns/zones", &[]).await?;
    let acls = list_all(&client, "/dns/acls", &[]).await?;
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|view| {
            let rules = rules_of(view);
            vec![
                number(view, &["order"]),
                text(view, &["name"]).to_owned(),
                if rules.is_empty() {
                    "every query".to_owned()
                } else {
                    rules.join("; ")
                },
                scopes_of(view, &zones).join(" "),
                recursion_of(view, &acls),
                // WP10.4: the view's resolution.
                resolution_of(view),
                text(view, &["id"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(
        &[
            "ORDER",
            "NAME",
            "RULES",
            "SCOPES",
            "RECURSION",
            "RESOLUTION",
            "ID",
        ],
        &rows,
    )))
}

async fn create(target: &Target, args: &ViewCreateArgs) -> Result<Output, Failure> {
    let rules = parse_rules(&args.rules)?;
    let client = target.connect().await?;
    let scope_map = parse_scopes(&client, &args.scopes).await?;
    let mut body = json!({
        "name": args.name,
        "rules": rules,
        "scope_map": scope_map,
        "order": args.order.unwrap_or(u32::MAX),
    });
    if let Some(acl) = &args.recursion {
        body["recursion"] = json!(text(&resolve_acl(&client, acl).await?, &["id"]));
    }
    // WP10.0
    if let Some(resolution) = args.resolution {
        body["resolution"] = json!(resolution.api());
    }
    // WP10.0: end.
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    let answer: Value = client.post("/dns/views", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created view {} at order {} ({})\n",
        text(&answer, &["name"]),
        number(&answer, &["order"]),
        text(&answer, &["id"]),
    )))
}

async fn get(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let view = resolve_view(&client, &args.name).await?;
    if target.json {
        return Ok(Output::json(&view));
    }
    let zones = list_all(&client, "/dns/zones", &[]).await?;
    let acls = list_all(&client, "/dns/acls", &[]).await?;
    Ok(Output::text(describe(&view, &zones, &acls)))
}

async fn update(target: &Target, args: &ViewUpdateArgs) -> Result<Output, Failure> {
    let mut body = Map::new();
    if let Some(name) = &args.name {
        body.insert("name".to_owned(), json!(name));
    }
    if args.rules.given() {
        body.insert("rules".to_owned(), json!(parse_rules(&args.rules)?));
    } else if args.no_rules {
        body.insert("rules".to_owned(), json!([]));
    }
    if args.no_scopes {
        body.insert("scope_map".to_owned(), json!([]));
    }
    if args.default_recursion {
        body.insert("default_recursion".to_owned(), json!(true));
    }
    // WP10.0
    if let Some(resolution) = args.resolution {
        let (field, value) = resolution.field();
        body.insert(field.to_owned(), value);
    }
    // WP10.0: end.
    if let Some(order) = args.order {
        body.insert("order".to_owned(), json!(order));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    if body.is_empty() && args.scopes.is_empty() && args.recursion.is_none() {
        return Err(usage(
            "nothing to change: give --name, a rule flag, --no-rules, --scope, --no-scopes, \
             --recursion, --default-recursion, --resolution, --order or --description",
        ));
    }
    let client = target.connect().await?;
    if !args.scopes.is_empty() {
        body.insert(
            "scope_map".to_owned(),
            json!(parse_scopes(&client, &args.scopes).await?),
        );
    }
    if let Some(acl) = &args.recursion {
        body.insert(
            "recursion".to_owned(),
            json!(text(&resolve_acl(&client, acl).await?, &["id"])),
        );
    }
    let view = resolve_view(&client, &args.view).await?;
    let path = format!("/dns/views/{}", text(&view, &["id"]));
    let answer: Value = client.patch(&path, &Value::Object(body), None).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated view {} at order {}, revision {}\n",
        text(&answer, &["name"]),
        number(&answer, &["order"]),
        number(&answer, &["revision"]),
    )))
}

async fn delete(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let view = resolve_view(&client, &args.name).await?;
    client
        .delete(&format!("/dns/views/{}", text(&view, &["id"])), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": text(&view, &["id"]) })));
    }
    Ok(Output::text(format!(
        "deleted view {} ({})\n",
        text(&view, &["name"]),
        text(&view, &["id"]),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_read_from_their_flags() {
        let args = RuleArgs {
            client_subnets: vec!["192.0.2.0/24".to_owned(), " 2001:db8::/32".to_owned()],
            transports: vec![QueryTransportArg::Dot],
            interfaces: vec!["192.0.2.53".to_owned()],
            qtypes: vec!["aaaa".to_owned()],
            qnames: vec!["Example.Test.".to_owned()],
            time: Some("22:00-06:30".to_owned()),
        };
        let rules = parse_rules(&args).expect("rules");
        assert_eq!(
            Value::Array(rules.clone()),
            json!([
                {"test": "client_subnet", "prefixes": ["192.0.2.0/24", "2001:db8::/32"]},
                {"test": "transport", "transports": ["dot"]},
                {"test": "interface", "addresses": ["192.0.2.53"]},
                {"test": "qtype", "types": ["AAAA"]},
                {"test": "qname", "suffixes": ["example.test"]},
                {"test": "time_of_day", "from_minute": 1320, "to_minute": 390}
            ])
        );
        let words: Vec<String> = rules.iter().map(present_rule).collect();
        assert_eq!(
            words,
            [
                "client in 192.0.2.0/24, 2001:db8::/32",
                "transport dot",
                "arrives on 192.0.2.53",
                "type AAAA",
                "name in example.test",
                "time 22:00-06:30 UTC"
            ]
        );
        for bad in [
            RuleArgs {
                client_subnets: vec!["192.0.2.0/33".to_owned()],
                ..RuleArgs::default()
            },
            RuleArgs {
                interfaces: vec!["host".to_owned()],
                ..RuleArgs::default()
            },
            RuleArgs {
                time: Some("24:00-01:00".to_owned()),
                ..RuleArgs::default()
            },
            RuleArgs {
                time: Some("08:00".to_owned()),
                ..RuleArgs::default()
            },
        ] {
            assert!(parse_rules(&bad).is_err(), "{bad:?}");
        }
        assert!(!RuleArgs::default().given());
    }

    // WP10.0
    #[test]
    fn a_resolution_is_a_mode_or_the_profile_default() {
        assert_eq!(
            ResolutionUpdateArg::Recurse.field(),
            ("resolution", json!("recurse"))
        );
        assert_eq!(
            ResolutionUpdateArg::Refuse.field(),
            ("resolution", json!("refuse"))
        );
        assert_eq!(
            ResolutionUpdateArg::Default.field(),
            ("default_resolution", json!(true))
        );
        assert_eq!(ResolutionArg::Forward.api(), "forward");
        let text = describe(&json!({ "name": "a", "resolution": "forward" }), &[], &[]);
        assert!(text.contains("resolution   forward"), "{text}");
        let text = describe(&json!({ "name": "a" }), &[], &[]);
        assert!(text.contains("resolution   profile default"), "{text}");
        // WP10.4: the profile's value is named when the answer carries it.
        let text = describe(
            &json!({ "name": "a", "profile_resolution": "recurse" }),
            &[],
            &[],
        );
        assert!(
            text.contains("resolution   profile default (recurse)"),
            "{text}"
        );
    }
    // WP10.0: end.

    #[test]
    fn scopes_and_recursion_are_shown_by_name() {
        let zones = [json!({"id": "z1", "name": "example.test"})];
        let acls = [json!({"id": "a1", "name": "office"})];
        let view = json!({
            "name": "inside", "id": "v1", "order": 2, "revision": 9, "recursion": "a1",
            "rules": [],
            "scope_map": [
                {"zone": "z1", "scope": "inside", "weight": 700},
                {"zone": "z2", "scope": "default", "weight": 300}
            ]
        });
        assert_eq!(
            scopes_of(&view, &zones),
            ["example.test:inside:700", "z2:default:300"]
        );
        assert_eq!(recursion_of(&view, &acls), "office");
        assert_eq!(recursion_of(&json!({}), &acls), "profile default");
        let text = describe(&view, &zones, &acls);
        assert!(text.contains("rules        none: every query"), "{text}");
        assert!(
            text.contains("scope        example.test:inside:700"),
            "{text}"
        );
    }
}
