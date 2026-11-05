//! `tenko migrate ...`: mirrored sources and the takeover of their scopes (Windows takeover
//! plan section 3.2, WP14.0). The commands are wired to the routes of `/api/v1/migrate`,
//! which answer `501 sys.not_implemented` until WP14.1 and WP14.2 build them; the commands
//! print the problem and exit with the server's status like every other client command.
//!
//! - `tenko migrate mirror list|create|show|token|delete|losses|ack`
//! - `tenko migrate diff <mirror> <cidr>`
//! - `tenko migrate prepare|takeover|revert <mirror> <cidr>`
//!
//! A mirror is named by its identifier or its name; a scope by its network with its length
//! (`192.0.2.0/24`), which the path carries with the slash percent-encoded.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde_json::{Map, Value, json};
use tenko_api::{client::Client, dto::Page, problem::ProblemDetails};
use uuid::Uuid;

use super::{ClientOpts, Failure, Output, Target, table};
use crate::exit;

/// Subcommands of `tenko migrate`.
#[derive(Debug, Clone, Subcommand)]
pub enum MigrateCommand {
    /// Mirrored sources: list, create, show, token, delete, losses, ack.
    Mirror {
        /// The `mirror` subcommand to run.
        #[command(subcommand)]
        action: MirrorCommand,
    },
    /// The diff of a mirrored scope against Tenko's scope of the same network.
    Diff(ScopeArgs),
    /// Prepare Tenko's scope from a mirrored scope (a job).
    Prepare(ScopeArgs),
    /// Take over a mirrored scope: its leases and names become Tenko's, the scope is enabled
    /// (a job; an interactive session only).
    Takeover(ScopeArgs),
    /// Revert a takeover: Tenko's scope is disabled, its leases and records kept (a job).
    Revert(ScopeArgs),
}

/// Subcommands of `tenko migrate mirror`.
#[derive(Debug, Clone, Subcommand)]
pub enum MirrorCommand {
    /// List the mirrored sources with their freshness.
    List(ListArgs),
    /// Create a mirrored source; prints the token once (an interactive session only).
    Create(MirrorCreateArgs),
    /// Show one mirrored source.
    Show(MirrorRefArgs),
    /// Replace the token of a mirrored source; prints the new token once (an administrator's
    /// interactive session only).
    Token(MirrorTokenArgs),
    /// Delete a mirrored source with its service account and token.
    Delete(MirrorRefArgs),
    /// The loss report of the latest snapshot, with the acknowledgments.
    Losses(MirrorRefArgs),
    /// Acknowledge loss entries by their keys.
    Ack(AckArgs),
}

/// Arguments of `tenko migrate mirror list`.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of the commands that take one mirror.
#[derive(Debug, Clone, Args)]
pub struct MirrorRefArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The mirror: its identifier or its name.
    #[arg(value_name = "MIRROR")]
    pub mirror: String,
}

/// Arguments of `tenko migrate mirror create`.
#[derive(Debug, Clone, Args)]
pub struct MirrorCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The name; the service account is `mirror-<name>`.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The kind of source (`windows-dhcp`).
    #[arg(long, value_name = "KIND", default_value = "windows-dhcp")]
    pub kind: String,
    /// The expected interval between pushes, in seconds; 60 when absent.
    #[arg(long, value_name = "SECS")]
    pub interval: Option<u32>,
    /// The token's lifetime in days; the profile's maximum when absent.
    #[arg(long, value_name = "DAYS")]
    pub token_days: Option<u32>,
}

/// Arguments of `tenko migrate mirror token`.
#[derive(Debug, Clone, Args)]
pub struct MirrorTokenArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The mirror: its identifier or its name.
    #[arg(value_name = "MIRROR")]
    pub mirror: String,
    /// The token's lifetime in days; the profile's maximum when absent.
    #[arg(long, value_name = "DAYS")]
    pub token_days: Option<u32>,
}

/// Arguments of `tenko migrate mirror ack`.
#[derive(Debug, Clone, Args)]
pub struct AckArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The mirror: its identifier or its name.
    #[arg(value_name = "MIRROR")]
    pub mirror: String,
    /// The keys of the entries to acknowledge, as `losses` lists them; at least one.
    #[arg(value_name = "KEY", required = true)]
    pub keys: Vec<String>,
}

/// Arguments of the scope commands: a mirror and a scope.
#[derive(Debug, Clone, Args)]
pub struct ScopeArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The mirror: its identifier or its name.
    #[arg(value_name = "MIRROR")]
    pub mirror: String,
    /// The scope's network with its length, for example 192.0.2.0/24.
    #[arg(value_name = "CIDR")]
    pub cidr: String,
}

impl MigrateCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Mirror { action } => match action {
                MirrorCommand::List(args) => &args.client,
                MirrorCommand::Create(args) => &args.client,
                MirrorCommand::Show(args)
                | MirrorCommand::Delete(args)
                | MirrorCommand::Losses(args) => &args.client,
                MirrorCommand::Token(args) => &args.client,
                MirrorCommand::Ack(args) => &args.client,
            },
            Self::Diff(args) | Self::Prepare(args) | Self::Takeover(args) | Self::Revert(args) => {
                &args.client
            }
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Mirror { action } => match action {
                MirrorCommand::List(_) => "migrate mirror list",
                MirrorCommand::Create(_) => "migrate mirror create",
                MirrorCommand::Show(_) => "migrate mirror show",
                MirrorCommand::Token(_) => "migrate mirror token",
                MirrorCommand::Delete(_) => "migrate mirror delete",
                MirrorCommand::Losses(_) => "migrate mirror losses",
                MirrorCommand::Ack(_) => "migrate mirror ack",
            },
            Self::Diff(_) => "migrate diff",
            Self::Prepare(_) => "migrate prepare",
            Self::Takeover(_) => "migrate takeover",
            Self::Revert(_) => "migrate revert",
        }
    }
}

/// Runs a `tenko migrate` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &MigrateCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        MigrateCommand::Mirror { action } => match action {
            MirrorCommand::List(_) => mirror_list(&target).await,
            MirrorCommand::Create(args) => mirror_create(&target, args).await,
            MirrorCommand::Show(args) => mirror_show(&target, args).await,
            MirrorCommand::Token(args) => mirror_token(&target, args).await,
            MirrorCommand::Delete(args) => mirror_delete(&target, args).await,
            MirrorCommand::Losses(args) => mirror_losses(&target, args).await,
            MirrorCommand::Ack(args) => mirror_ack(&target, args).await,
        },
        MigrateCommand::Diff(args) => scope_diff(&target, args).await,
        MigrateCommand::Prepare(args) => scope_job(&target, args, "prepare").await,
        MigrateCommand::Takeover(args) => scope_job(&target, args, "takeover").await,
        MigrateCommand::Revert(args) => scope_job(&target, args, "revert").await,
    }
}

// ---------------------------------------------------------------------------------------
// Helpers

/// A usage error (exit status 2).
fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(exit::USAGE, message.to_string())
}

/// A text field of a JSON object, `-` when absent.
fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => "-".to_owned(),
    }
}

/// Reads every page of a list endpoint.
async fn list_all(client: &Client, path: &str) -> Result<Vec<Value>, Failure> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query: Vec<(&str, String)> = vec![("limit", "1000".to_owned())];
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Page<Value> = client.get_query(path, &query).await?;
        items.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(items);
        }
    }
}

/// The mirror `reference` names (an identifier or a name), read from the server.
async fn resolve_mirror(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/migrate/mirrors/{reference}")).await?);
    }
    let wanted = reference.trim();
    let mirrors = list_all(client, "/migrate/mirrors").await?;
    mirrors
        .into_iter()
        .find(|mirror| field(mirror, "name") == wanted)
        .ok_or_else(|| {
            Failure::problem(ProblemDetails {
                type_: "about:blank".to_owned(),
                status: 404,
                code: "migrate.mirror.not_found".to_owned(),
                title: "Not Found".to_owned(),
                detail: format!("no mirror {reference}"),
                params: std::collections::BTreeMap::from([(
                    "name".to_owned(),
                    reference.to_owned(),
                )]),
                errors: Vec::new(),
                instance: None,
            })
        })
}

fn mirror_path(mirror: &Value) -> String {
    format!("/migrate/mirrors/{}", field(mirror, "id"))
}

/// The path of a scope under a mirror: the network with its length, the slash
/// percent-encoded.
fn scope_path(mirror: &Value, cidr: &str) -> Result<String, Failure> {
    let cidr: ipnet::IpNet = cidr
        .trim()
        .parse()
        .map_err(|_| usage(format!("`{cidr}` is not a network with its length")))?;
    if cidr.trunc() != cidr {
        return Err(usage(format!(
            "`{cidr}` is not a network address; did you mean {}?",
            cidr.trunc()
        )));
    }
    Ok(format!(
        "{}/scopes/{}",
        mirror_path(mirror),
        cidr.to_string().replace('/', "%2F")
    ))
}

fn describe_mirror(mirror: &Value) -> String {
    let lines = [
        ("name", field(mirror, "name")),
        ("id", field(mirror, "id")),
        ("kind", field(mirror, "kind")),
        ("enabled", field(mirror, "enabled")),
        ("interval", format!("{} s", field(mirror, "interval_secs"))),
        ("last push", field(mirror, "last_push")),
        ("last change", field(mirror, "last_change")),
        ("sequence", field(mirror, "last_sequence")),
        ("age", field(mirror, "age_secs")),
        ("stale", field(mirror, "stale")),
        ("token expires", field(mirror, "token_expires_at")),
        ("open losses", field(mirror, "losses_open")),
    ];
    let width = lines.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    if let Some(counts) = mirror.get("counts") {
        let _ = writeln!(
            out,
            "snapshot       {} scopes, {} reservations, {} leases, {} losses",
            field(counts, "scopes"),
            field(counts, "reservations"),
            field(counts, "leases"),
            field(counts, "losses")
        );
    }
    if let Some(source) = mirror.get("source") {
        let _ = writeln!(
            out,
            "source         {} ({} {})",
            field(source, "server"),
            field(source, "adapter"),
            field(source, "adapter_version")
        );
    }
    out
}

fn describe_created(created: &Value) -> String {
    let mut out = String::new();
    if let Some(mirror) = created.get("mirror") {
        out.push_str(&describe_mirror(mirror));
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The token is shown once; store it with Install-TenkoDhcpMirror.ps1 on the controller."
    );
    let _ = writeln!(out, "token           {}", field(created, "token"));
    let _ = writeln!(
        out,
        "token expires   {}",
        field(created, "token_expires_at")
    );
    let _ = writeln!(out, "CA fingerprint  {}", field(created, "ca_fingerprint"));
    out
}

// ---------------------------------------------------------------------------------------
// Mirrors

async fn mirror_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/migrate/mirrors").await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|mirror| {
            vec![
                field(mirror, "name"),
                field(mirror, "kind"),
                field(mirror, "enabled"),
                field(mirror, "last_sequence"),
                field(mirror, "age_secs"),
                field(mirror, "stale"),
                field(mirror, "losses_open"),
                field(mirror, "id"),
            ]
        })
        .collect();
    Ok(Output::text(table(
        &[
            "NAME", "KIND", "ENABLED", "SEQUENCE", "AGE", "STALE", "LOSSES", "ID",
        ],
        &rows,
    )))
}

async fn mirror_create(target: &Target, args: &MirrorCreateArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mut body = Map::new();
    body.insert("name".to_owned(), json!(args.name.trim()));
    body.insert("kind".to_owned(), json!(args.kind.trim()));
    if let Some(interval) = args.interval {
        body.insert("interval_secs".to_owned(), json!(interval));
    }
    if let Some(days) = args.token_days {
        body.insert("token_expires_in_days".to_owned(), json!(days));
    }
    let answer: Value = client
        .post("/migrate/mirrors", &Value::Object(body), Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(describe_created(&answer)))
}

async fn mirror_show(target: &Target, args: &MirrorRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    if target.json {
        return Ok(Output::json(&mirror));
    }
    Ok(Output::text(describe_mirror(&mirror)))
}

async fn mirror_token(target: &Target, args: &MirrorTokenArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    let mut body = Map::new();
    if let Some(days) = args.token_days {
        body.insert("expires_in_days".to_owned(), json!(days));
    }
    let answer: Value = client
        .post(
            &format!("{}/token", mirror_path(&mirror)),
            &Value::Object(body),
            Some(&key()),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(describe_created(&answer)))
}

async fn mirror_delete(target: &Target, args: &MirrorRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    client.delete(&mirror_path(&mirror), None).await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": field(&mirror, "id") })));
    }
    Ok(Output::text(format!(
        "mirror {} deleted\n",
        field(&mirror, "name")
    )))
}

async fn mirror_losses(target: &Target, args: &MirrorRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    let answer: Value = client
        .get(&format!("{}/losses", mirror_path(&mirror)))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let rows: Vec<Vec<String>> = answer
        .get("entries")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|item| {
                    let entry = item.get("entry").cloned().unwrap_or(Value::Null);
                    vec![
                        field(item, "key"),
                        field(item, "scope"),
                        field(&entry, "code"),
                        field(&entry, "detail"),
                        item.get("ack")
                            .filter(|ack| !ack.is_null())
                            .map_or_else(|| "-".to_owned(), |ack| field(ack, "at")),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = format!(
        "losses of {} at sequence {}\n",
        field(&mirror, "name"),
        field(&answer, "sequence")
    );
    out.push_str(&table(
        &["KEY", "SCOPE", "CODE", "DETAIL", "ACKNOWLEDGED"],
        &rows,
    ));
    Ok(Output::text(out))
}

async fn mirror_ack(target: &Target, args: &AckArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    let answer: Value = client
        .post(
            &format!("{}/losses/ack", mirror_path(&mirror)),
            &json!({ "keys": args.keys }),
            Some(&key()),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let count = answer
        .get("acks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(Output::text(format!(
        "{count} loss entries of {} acknowledged\n",
        field(&mirror, "name")
    )))
}

// ---------------------------------------------------------------------------------------
// Scopes

async fn scope_diff(target: &Target, args: &ScopeArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    let answer: Value = client
        .get(&format!("{}/diff", scope_path(&mirror, &args.cidr)?))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let rows: Vec<Vec<String>> = answer
        .get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    vec![
                        field(row, "kind"),
                        field(row, "item"),
                        field(row, "mirror"),
                        field(row, "tenko"),
                        field(row, "action"),
                        field(row, "reason"),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = format!(
        "scope {} of {} at sequence {}: source {}, Tenko scope {}\n",
        field(&answer, "scope"),
        field(&mirror, "name"),
        field(&answer, "sequence"),
        if answer.get("source_active") == Some(&Value::Bool(true)) {
            "active"
        } else {
            "inactive"
        },
        if answer.get("tenko_enabled") == Some(&Value::Bool(true)) {
            "enabled"
        } else {
            "disabled"
        }
    );
    if rows.is_empty() {
        out.push_str("no differences\n");
    } else {
        out.push_str(&table(
            &["KIND", "ITEM", "MIRROR", "TENKO", "ACTION", "REASON"],
            &rows,
        ));
    }
    Ok(Output::text(out))
}

async fn scope_job(target: &Target, args: &ScopeArgs, action: &str) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mirror = resolve_mirror(&client, &args.mirror).await?;
    let answer: Value = client
        .post(
            &format!("{}/{action}", scope_path(&mirror, &args.cidr)?),
            &json!({}),
            Some(&key()),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "{action} of {} from {} started: job {}\n",
        field(&answer, "scope"),
        field(&mirror, "name"),
        field(&answer, "job")
    )))
}

/// A fresh idempotency key.
fn key() -> String {
    Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_path_carries_the_network_with_its_slash_encoded() {
        let mirror = json!({ "id": "0190d1c2-0000-7000-8000-000000000001" });
        assert_eq!(
            scope_path(&mirror, "192.0.2.0/24").expect("a path"),
            "/migrate/mirrors/0190d1c2-0000-7000-8000-000000000001/scopes/192.0.2.0%2F24"
        );
        let error = scope_path(&mirror, "192.0.2.1/24").expect_err("not a network");
        assert!(error.message.contains("192.0.2.0/24"), "{}", error.message);
        assert!(scope_path(&mirror, "office").is_err());
    }

    #[test]
    fn a_mirror_reads_as_lines() {
        let mirror = json!({
            "id": "0190d1c2-0000-7000-8000-000000000001",
            "name": "dc1",
            "kind": "windows-dhcp",
            "enabled": true,
            "interval_secs": 60,
            "last_sequence": 42,
            "stale": false,
            "losses_open": 3,
            "counts": { "scopes": 1, "reservations": 30, "leases": 60, "losses": 4 },
        });
        let text = describe_mirror(&mirror);
        assert!(text.contains("name           dc1"), "{text}");
        assert!(text.contains("interval       60 s"), "{text}");
        assert!(text.contains("last push      -"), "{text}");
        assert!(
            text.contains("1 scopes, 30 reservations, 60 leases, 4 losses"),
            "{text}"
        );
    }
}
