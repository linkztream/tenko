//! `tenko prefix list|get|create`: the prefix endpoints of the public API.

use std::{collections::BTreeMap, fmt::Write as _};

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tenko_api::{dto::Page, problem::ProblemDetails};
use tenko_core::ipam::Prefix;

use super::{ClientOpts, Failure, Output, Target, table};

/// Subcommands of `tenko prefix`.
#[derive(Debug, Clone, Subcommand)]
pub enum PrefixCommand {
    /// List prefixes, optionally filtered.
    List(ListArgs),
    /// Show one prefix by identifier or by network.
    Get(GetArgs),
    /// Create a prefix.
    Create(CreateArgs),
}

impl PrefixCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::List(args) => &args.client,
            Self::Get(args) => &args.client,
            Self::Create(args) => &args.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "prefix list",
            Self::Get(_) => "prefix get",
            Self::Create(_) => "prefix create",
        }
    }
}

/// Arguments of `tenko prefix list`.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only prefixes of this VRF (identifier).
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
    /// Only prefixes inside this network, for example 192.0.2.0/24.
    #[arg(long, value_name = "CIDR")]
    pub within: Option<String>,
    /// Only prefixes in these statuses (comma-separated).
    #[arg(long, value_name = "STATUS")]
    pub status: Option<String>,
    /// Text search over the network, tags and description.
    #[arg(long, short = 'q', value_name = "TEXT")]
    pub query: Option<String>,
    /// Most prefixes per request, 1 to 1,000.
    #[arg(long, value_name = "N", default_value_t = 1000)]
    pub limit: u32,
    /// Follow the cursor and list every page.
    #[arg(long)]
    pub all: bool,
}

/// Arguments of `tenko prefix get`.
#[derive(Debug, Clone, Args)]
pub struct GetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The prefix identifier, or its network (`192.0.2.0/24`) in the default VRF or the one
    /// given with `--vrf`.
    #[arg(value_name = "ID_OR_CIDR")]
    pub prefix: String,
    /// The VRF to look a network up in.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
}

/// Arguments of `tenko prefix create`.
#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The network, without host bits, for example 192.0.2.0/24.
    #[arg(value_name = "CIDR")]
    pub cidr: String,
    /// The VRF (identifier); the default VRF when absent.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
    /// `supernet` or `network`; chosen from the tree when absent.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<String>,
    /// Lifecycle status; `active` when absent.
    #[arg(long, value_name = "STATUS")]
    pub status: Option<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// A tag; repeat for more.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Acknowledge a warning code (for example `ipam.prefix.nibble_boundary`); repeat for
    /// more.
    #[arg(long, value_name = "CODE")]
    pub acknowledge: Vec<String>,
    /// Show the plan without writing (API-09).
    #[arg(long)]
    pub dry_run: bool,
}

/// Runs a `tenko prefix` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &PrefixCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        PrefixCommand::List(args) => list(&target, args).await,
        PrefixCommand::Get(args) => get(&target, args).await,
        PrefixCommand::Create(args) => create(&target, args).await,
    }
}

#[derive(Serialize)]
struct ListQuery<'a> {
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    within: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<&'a str>,
}

async fn list(target: &Target, args: &ListArgs) -> Result<Output, Failure> {
    let client = target.client()?;
    let mut items: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let revision = loop {
        let query = ListQuery {
            limit: args.limit.clamp(1, 1000),
            cursor: cursor.as_deref(),
            vrf: args.vrf.as_deref(),
            within: args.within.as_deref(),
            status: args.status.as_deref(),
            q: args.query.as_deref(),
        };
        let page: Page<Value> = client.get_query("/prefixes", &query).await?;
        items.extend(page.items);
        cursor = page.next_cursor;
        if !args.all || cursor.is_none() {
            break page.revision;
        }
    };
    if target.json {
        return Ok(Output::json(&json!({
            "items": items,
            "next_cursor": cursor,
            "revision": revision,
        })));
    }
    let prefixes = decode_all(&items)?;
    let rows: Vec<Vec<String>> = prefixes.iter().map(row).collect();
    let mut output = Output::text(table(
        &["CIDR", "STATUS", "ROLE", "DESCRIPTION", "ID"],
        &rows,
    ));
    if cursor.is_some() {
        output = output.note("more prefixes follow: use --all or a narrower filter");
    }
    Ok(output)
}

async fn get(target: &Target, args: &GetArgs) -> Result<Output, Failure> {
    let client = target.client()?;
    let value: Value = if args.prefix.contains('/') {
        let query = ListQuery {
            limit: 1000,
            cursor: None,
            vrf: args.vrf.as_deref(),
            within: Some(&args.prefix),
            status: None,
            q: None,
        };
        let page: Page<Value> = client.get_query("/prefixes", &query).await?;
        let wanted = args.prefix.trim().to_ascii_lowercase();
        page.items
            .into_iter()
            .find(|item| {
                item.get("cidr")
                    .and_then(Value::as_str)
                    .is_some_and(|cidr| cidr.eq_ignore_ascii_case(&wanted))
            })
            .ok_or_else(|| {
                // The same problem the server gives for an unknown identifier, so that
                // `--json` prints problem details here too.
                Failure::problem(ProblemDetails {
                    type_: "about:blank".to_owned(),
                    status: 404,
                    code: "ipam.not_found".to_owned(),
                    title: "Not Found".to_owned(),
                    detail: format!("no prefix {} in the VRF", args.prefix),
                    params: BTreeMap::from([("cidr".to_owned(), args.prefix.clone())]),
                    errors: Vec::new(),
                    instance: None,
                })
            })?
    } else {
        client.get(&format!("/prefixes/{}", args.prefix)).await?
    };
    if target.json {
        return Ok(Output::json(&value));
    }
    let prefix = decode(&value)?;
    Ok(Output::text(describe(&prefix)))
}

async fn create(target: &Target, args: &CreateArgs) -> Result<Output, Failure> {
    let client = target.client()?;
    let mut body = Map::new();
    body.insert("cidr".to_owned(), json!(args.cidr));
    let optional = [
        ("vrf", &args.vrf),
        ("role", &args.role),
        ("status", &args.status),
        ("description", &args.description),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            body.insert(key.to_owned(), json!(value));
        }
    }
    if !args.tags.is_empty() {
        body.insert("tags".to_owned(), json!(args.tags));
    }
    let mut path = String::from("/prefixes");
    let mut params = Vec::new();
    if args.dry_run {
        params.push("dry_run=true".to_owned());
    }
    if !args.acknowledge.is_empty() {
        params.push(format!("acknowledge={}", args.acknowledge.join(",")));
    }
    if !params.is_empty() {
        path.push('?');
        path.push_str(&params.join("&"));
    }
    let key = uuid::Uuid::now_v7().to_string();
    let answer: Value = client.post(&path, &Value::Object(body), Some(&key)).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let mut output = match answer.get("item").filter(|item| !item.is_null()) {
        Some(item) => {
            let prefix = decode(item)?;
            let verb = if args.dry_run {
                "would create"
            } else {
                "created"
            };
            let mut text = format!("{verb} prefix {} ({})", prefix.cidr, prefix.id);
            if let Some(revision) = answer.get("revision").and_then(Value::as_u64) {
                let _ = write!(text, " at revision {revision}");
            }
            if let Some(job) = answer.get("job_id").and_then(Value::as_str) {
                let _ = write!(text, ", job {job}");
            }
            text.push('\n');
            Output::text(text)
        }
        None => Output::text("no change\n"),
    };
    for warning in answer
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let code = warning
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("warning");
        let detail = warning
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default();
        output = output.note(format!("warning[{code}]: {detail}"));
    }
    Ok(output)
}

fn decode(value: &Value) -> Result<Prefix, Failure> {
    serde_json::from_value(value.clone())
        .map_err(|error| Failure::other(format!("unexpected prefix in the answer: {error}")))
}

fn decode_all(values: &[Value]) -> Result<Vec<Prefix>, Failure> {
    values.iter().map(decode).collect()
}

fn word(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

fn row(prefix: &Prefix) -> Vec<String> {
    vec![
        prefix.cidr.to_string(),
        word(&prefix.status),
        word(&prefix.role),
        prefix.meta.description.clone().unwrap_or_default(),
        prefix.id.to_string(),
    ]
}

fn describe(prefix: &Prefix) -> String {
    let tags: Vec<String> = prefix.meta.tags.iter().map(word).collect();
    let mut lines = vec![
        ("cidr", prefix.cidr.to_string()),
        ("id", prefix.id.to_string()),
        ("vrf", prefix.vrf.to_string()),
        ("status", word(&prefix.status)),
        ("role", word(&prefix.role)),
        ("revision", prefix.meta.revision.to_string()),
    ];
    if let Some(description) = &prefix.meta.description {
        lines.push(("description", description.clone()));
    }
    if !tags.is_empty() {
        lines.push(("tags", tags.join(", ")));
    }
    if let Some(vlan) = &prefix.vlan {
        lines.push(("vlan", vlan.to_string()));
    }
    if let Some(site) = &prefix.site {
        lines.push(("site", site.to_string()));
    }
    let width = lines
        .iter()
        .map(|(key, _)| key.len())
        .max()
        .unwrap_or_default();
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    out
}
