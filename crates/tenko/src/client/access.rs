//! `tenko access mapping ...`: the directory mappings of groups onto roles and scopes
//! (identity plan sections 3.16 and 4.3; WP13.0 declares the commands, WP13.5 builds the
//! routes).
//!
//! Every route answers the 501 `sys.not_implemented` problem details until WP13.5 builds
//! it, printed as any other API error.
//!
//! # Routes
//!
//! | Command | Request |
//! |---|---|
//! | `mapping list [--provider ID]` | `GET /access/directory-mappings` |
//! | `mapping create <provider> <role> --sid S\|--dn D\|--claim C [--scope KIND=VALUE[,subtree]]` | `POST /access/directory-mappings` |
//! | `mapping delete <id>` | `DELETE /access/directory-mappings/{id}` |

use clap::{ArgGroup, Args, Subcommand};
use serde_json::{Value, json};
use tenko_api::dto::Page;
use uuid::Uuid;

use super::{ClientOpts, Failure, Output, Target, table};
use crate::exit;

/// Subcommands of `tenko access`.
#[derive(Debug, Clone, Subcommand)]
pub enum AccessCommand {
    /// Directory mappings: list, create, delete.
    Mapping {
        /// The `mapping` subcommand to run.
        #[command(subcommand)]
        action: MappingCommand,
    },
}

impl AccessCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::Mapping { action } => action.client(),
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Mapping { action } => action.name(),
        }
    }
}

/// Subcommands of `tenko access mapping`.
#[derive(Debug, Clone, Subcommand)]
pub enum MappingCommand {
    /// List the mappings, with the users each applied to last.
    List(ListArgs),
    /// Create a mapping of a group onto a role (an interactive session only).
    Create(CreateArgs),
    /// Delete a mapping (an interactive session only).
    Delete(DeleteArgs),
}

impl MappingCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::List(a) => &a.client,
            Self::Create(a) => &a.client,
            Self::Delete(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "access mapping list",
            Self::Create(_) => "access mapping create",
            Self::Delete(_) => "access mapping delete",
        }
    }
}

/// Arguments of `tenko access mapping list`.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only the mappings of this provider.
    #[arg(long, value_name = "ID")]
    pub provider: Option<Uuid>,
}

/// Arguments of `tenko access mapping create`.
#[derive(Debug, Clone, Args)]
#[command(group(ArgGroup::new("group").required(true).args(["sid", "dn", "claim"])))]
pub struct CreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The provider's identifier.
    #[arg(value_name = "PROVIDER")]
    pub provider: Uuid,
    /// The role: `admin`, `operator`, `viewer` or `auditor`.
    #[arg(value_name = "ROLE", value_parser = ["admin", "operator", "viewer", "auditor"])]
    pub role: String,
    /// The group by SID (`S-1-5-21-...-1105`).
    #[arg(long, value_name = "SID")]
    pub sid: Option<String>,
    /// The group by distinguished name.
    #[arg(long, value_name = "DN")]
    pub dn: Option<String>,
    /// The group by the value of the OIDC groups claim (a group id or an app role).
    #[arg(long, value_name = "VALUE")]
    pub claim: Option<String>,
    /// The scope of an operator or viewer: `tenant=<id>`, `vrf=<id>`, `site=<id>` or
    /// `prefix=<id>`, with `,subtree` for a site's child sites or everything inside a
    /// prefix. Absent: the whole installation.
    #[arg(long, value_name = "KIND=VALUE[,subtree]")]
    pub scope: Option<String>,
}

/// Arguments of `tenko access mapping delete`.
#[derive(Debug, Clone, Args)]
pub struct DeleteArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The mapping's identifier.
    #[arg(value_name = "ID")]
    pub id: Uuid,
}

/// A usage error (exit status 2).
fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(exit::USAGE, message.to_string())
}

/// A text field of an answer, or the empty string.
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}

/// The scope flag as the API's scope rule (`{kind, value}` with `subtree` where it
/// applies).
///
/// # Errors
///
/// A usage message for a flag that is not `kind=value[,subtree]`.
pub fn parse_scope(text: &str) -> Result<Value, Failure> {
    let bad = || {
        usage(format!(
            "`{text}` is not a scope: tenant=<id>, vrf=<id>, site=<id> or prefix=<id>, with \
             ,subtree for a site or a prefix"
        ))
    };
    let (kind, rest) = text.split_once('=').ok_or_else(bad)?;
    let (value, subtree) = match rest.split_once(',') {
        Some((value, "subtree")) => (value, true),
        Some(_) => return Err(bad()),
        None => (rest, false),
    };
    if value.trim().is_empty() {
        return Err(bad());
    }
    match kind.trim().to_ascii_lowercase().as_str() {
        kind @ ("tenant" | "vrf") if !subtree => Ok(json!({ "kind": kind, "value": value.trim() })),
        kind @ ("site" | "prefix") => {
            Ok(json!({ "kind": kind, "value": value.trim(), "subtree": subtree }))
        }
        _ => Err(bad()),
    }
}

/// The group of a mapping as the API's `GroupMatch`.
fn group_of(args: &CreateArgs) -> Value {
    if let Some(sid) = &args.sid {
        json!({ "kind": "sid", "sid": sid.trim() })
    } else if let Some(dn) = &args.dn {
        json!({ "kind": "dn", "dn": dn.trim() })
    } else {
        json!({ "kind": "claim", "value": args.claim.as_deref().unwrap_or_default().trim() })
    }
}

/// The group of a mapping item as one word for a table.
fn group_text(mapping: &Value) -> String {
    let group = mapping.get("group").cloned().unwrap_or(Value::Null);
    match text(&group, "kind") {
        "sid" => format!("sid {}", text(&group, "sid")),
        "dn" => format!("dn {}", text(&group, "dn")),
        "claim" => format!("claim {}", text(&group, "value")),
        _ => String::new(),
    }
}

/// The scope of a mapping item as one word for a table.
fn scope_text(mapping: &Value) -> String {
    match mapping.get("scope") {
        Some(scope) if !scope.is_null() => {
            let subtree = scope
                .get("subtree")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            format!(
                "{}={}{}",
                text(scope, "kind"),
                text(scope, "value"),
                if subtree { ",subtree" } else { "" }
            )
        }
        _ => "everywhere".to_owned(),
    }
}

fn rows(items: &[Value]) -> Vec<Vec<String>> {
    items
        .iter()
        .map(|item| {
            let users = item
                .get("users")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            vec![
                text(item, "id").to_owned(),
                text(item, "provider").to_owned(),
                group_text(item),
                text(item, "role").to_owned(),
                scope_text(item),
                users.to_string(),
            ]
        })
        .collect()
}

/// Runs a `tenko access` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &AccessCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        AccessCommand::Mapping { action } => match action {
            MappingCommand::List(args) => list(&target, args).await,
            MappingCommand::Create(args) => create(&target, args).await,
            MappingCommand::Delete(args) => delete(&target, args).await,
        },
    }
}

async fn list(target: &Target, args: &ListArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query: Vec<(&str, String)> = vec![("limit", "500".to_owned())];
        if let Some(provider) = args.provider {
            query.push(("provider", provider.to_string()));
        }
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Page<Value> = client
            .get_query("/access/directory-mappings", &query)
            .await?;
        items.extend(page.items);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    Ok(Output::text(table(
        &["ID", "PROVIDER", "GROUP", "ROLE", "SCOPE", "USERS"],
        &rows(&items),
    )))
}

async fn create(target: &Target, args: &CreateArgs) -> Result<Output, Failure> {
    let mut body = json!({
        "provider": args.provider,
        "group": group_of(args),
        "role": args.role,
    });
    if let Some(scope) = &args.scope {
        if matches!(args.role.as_str(), "admin" | "auditor") {
            return Err(usage("a global role (admin, auditor) takes no scope"));
        }
        body["scope"] = parse_scope(scope)?;
    }
    let client = target.connect().await?;
    let answer: Value = client
        .post(
            "/access/directory-mappings",
            &body,
            Some(&Uuid::now_v7().to_string()),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created mapping {}: {} to {} {}\n",
        text(&answer, "id"),
        group_text(&answer),
        text(&answer, "role"),
        scope_text(&answer)
    )))
}

async fn delete(target: &Target, args: &DeleteArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    client
        .delete(&format!("/access/directory-mappings/{}", args.id), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": args.id })));
    }
    Ok(Output::text(format!("deleted mapping {}\n", args.id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_their_kind_value_and_subtree() {
        assert_eq!(
            parse_scope("site=0190d1c2-0000-7000-8000-000000000001,subtree").expect("scope"),
            json!({ "kind": "site", "value": "0190d1c2-0000-7000-8000-000000000001", "subtree": true })
        );
        assert_eq!(
            parse_scope("prefix=0190d1c2-0000-7000-8000-000000000002").expect("scope"),
            json!({ "kind": "prefix", "value": "0190d1c2-0000-7000-8000-000000000002", "subtree": false })
        );
        assert_eq!(
            parse_scope("VRF=0190d1c2-0000-7000-8000-000000000003").expect("scope"),
            json!({ "kind": "vrf", "value": "0190d1c2-0000-7000-8000-000000000003" })
        );
        for bad in [
            "",
            "site",
            "site=",
            "tenant=x,subtree",
            "host=x",
            "site=x,everything",
        ] {
            assert!(parse_scope(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mappings_render_as_rows() {
        let rows = rows(&[
            json!({
                "id": "0190d1c2-0000-7000-8000-000000000001",
                "provider": "0190d1c2-0000-7000-8000-000000000002",
                "group": { "kind": "sid", "sid": "S-1-5-21-1004336348-1177238915-682003330-1105" },
                "role": "operator",
                "scope": { "kind": "site", "value": "0190d1c2-0000-7000-8000-000000000003", "subtree": true },
                "users": [{ "user": "0190d1c2-0000-7000-8000-000000000004", "display_name": "Alex", "at": "2026-10-25T12:00:00Z" }]
            }),
            json!({ "id": "x", "provider": "y", "group": { "kind": "claim", "value": "tenko-admins" }, "role": "admin" }),
        ]);
        assert_eq!(
            rows[0][2],
            "sid S-1-5-21-1004336348-1177238915-682003330-1105"
        );
        assert_eq!(
            rows[0][4],
            "site=0190d1c2-0000-7000-8000-000000000003,subtree"
        );
        assert_eq!(rows[0][5], "1");
        assert_eq!(rows[1][2], "claim tenko-admins");
        assert_eq!(rows[1][4], "everywhere");
        assert_eq!(rows[1][5], "0");
    }
}
