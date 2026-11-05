//! `tenko auth provider ...`: the sign-in providers (identity plan sections 3.12 to 3.14
//! and 4.3; WP13.0 declares the commands, WP13.5 and WP13.6 build the routes).
//!
//! Every route answers the 501 `sys.not_implemented` problem details until its package
//! builds it, printed as any other API error.
//!
//! # Routes
//!
//! | Command | Request |
//! |---|---|
//! | `provider list` | `GET /auth/providers` |
//! | `provider create <name> --file settings.json [--secret-stdin]` | `POST /auth/providers` |
//! | `provider show <id>` | `GET /auth/providers/{id}` |
//! | `provider update <id> [--name N] [--file settings.json] [--state S] [--secret-stdin]` | `PATCH /auth/providers/{id}` |
//! | `provider delete <id>` | `DELETE /auth/providers/{id}` |
//! | `provider test <id> <user name> [--password-stdin]` | `POST /auth/providers/{id}/test` |
//! | `provider ldap-chain <url> [--starttls]` | `POST /auth/providers/ldap/chain` |
//!
//! The settings of a provider are a JSON document of the `DirectoryProvider` schema of the
//! OpenAPI document (`kind`: `oidc`, `ldap` or `negotiate`), read from a file. A client
//! secret or a service account password is asked for on the terminal or read from the
//! first line of standard input with `--secret-stdin`; it is never a flag. `ldap-chain`
//! prints each certificate of the chain with its fingerprint, for the comparison the
//! administrator makes before confirming the pin.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{ClientOpts, Failure, Output, Target, read_secret, table};
use crate::exit;

/// Subcommands of `tenko auth`.
#[derive(Debug, Clone, Subcommand)]
pub enum AuthCommand {
    /// Sign-in providers: list, create, show, update, delete, test, ldap-chain.
    Provider {
        /// The `provider` subcommand to run.
        #[command(subcommand)]
        action: ProviderCommand,
    },
}

impl AuthCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::Provider { action } => action.client(),
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Provider { action } => action.name(),
        }
    }
}

/// Subcommands of `tenko auth provider`.
#[derive(Debug, Clone, Subcommand)]
pub enum ProviderCommand {
    /// List the providers with their state.
    List(ListArgs),
    /// Create a provider from a settings file (a draft until a test sign-in completes).
    Create(CreateArgs),
    /// Show a provider.
    Show(IdArgs),
    /// Change a provider's name, settings, secret or state.
    Update(UpdateArgs),
    /// Delete a provider and its mappings.
    Delete(IdArgs),
    /// Test an LDAP provider with a user name and password.
    Test(TestArgs),
    /// Fetch the certificate chain of an LDAP server and print its fingerprints.
    LdapChain(ChainArgs),
}

impl ProviderCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::List(a) => &a.client,
            Self::Create(a) => &a.client,
            Self::Show(a) | Self::Delete(a) => &a.client,
            Self::Update(a) => &a.client,
            Self::Test(a) => &a.client,
            Self::LdapChain(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "auth provider list",
            Self::Create(_) => "auth provider create",
            Self::Show(_) => "auth provider show",
            Self::Update(_) => "auth provider update",
            Self::Delete(_) => "auth provider delete",
            Self::Test(_) => "auth provider test",
            Self::LdapChain(_) => "auth provider ldap-chain",
        }
    }
}

/// Arguments of `tenko auth provider list`.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of the commands that take a provider id.
#[derive(Debug, Clone, Args)]
pub struct IdArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The provider's identifier.
    #[arg(value_name = "ID")]
    pub id: Uuid,
}

/// Arguments of `tenko auth provider create`.
#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name, 1 to 64 characters.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The settings file: a JSON document with `kind` (`oidc`, `ldap`, `negotiate`) and
    /// the fields of that kind.
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
    /// Read the client secret or the service account password from the first line of
    /// standard input instead of asking for it; without `--secret` nothing is asked.
    #[arg(long, requires = "secret")]
    pub secret_stdin: bool,
    /// Ask for the client secret (OIDC) or the service account password (LDAP).
    #[arg(long)]
    pub secret: bool,
}

/// Arguments of `tenko auth provider update`.
#[derive(Debug, Clone, Args)]
pub struct UpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The provider's identifier.
    #[arg(value_name = "ID")]
    pub id: Uuid,
    /// A new name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// New settings, a JSON document of the same kind.
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// A new state: `disabled` or `draft`.
    #[arg(long, value_name = "STATE", value_parser = ["disabled", "draft"])]
    pub state: Option<String>,
    /// Ask for a new client secret or service account password.
    #[arg(long)]
    pub secret: bool,
    /// Read the new secret from the first line of standard input.
    #[arg(long, requires = "secret")]
    pub secret_stdin: bool,
}

/// Arguments of `tenko auth provider test`.
#[derive(Debug, Clone, Args)]
pub struct TestArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The provider's identifier.
    #[arg(value_name = "ID")]
    pub id: Uuid,
    /// The user name to sign in with.
    #[arg(value_name = "USER")]
    pub user_name: String,
    /// Read the password from the first line of standard input instead of asking for it.
    #[arg(long)]
    pub password_stdin: bool,
}

/// Arguments of `tenko auth provider ldap-chain`.
#[derive(Debug, Clone, Args)]
pub struct ChainArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The server, an `ldaps://` URL (or `ldap://` with `--starttls`).
    #[arg(value_name = "URL")]
    pub server: String,
    /// `StartTLS` on an `ldap://` URL instead of LDAPS.
    #[arg(long)]
    pub starttls: bool,
}

/// A usage error (exit status 2).
fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(exit::USAGE, message.to_string())
}

/// An idempotency key for a write.
fn key() -> String {
    Uuid::now_v7().to_string()
}

/// A text field of an answer, or the empty string.
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}

/// The settings file as JSON, with a `kind`.
fn settings_from(path: &PathBuf) -> Result<Value, Failure> {
    let bytes = std::fs::read(path)
        .map_err(|error| usage(format!("cannot read {}: {error}", path.display())))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| usage(format!("{} is not JSON: {error}", path.display())))?;
    match value.get("kind").and_then(Value::as_str) {
        Some("oidc" | "ldap" | "negotiate") => Ok(value),
        _ => Err(usage(format!(
            "{} names no kind: `oidc`, `ldap` or `negotiate`",
            path.display()
        ))),
    }
}

/// Runs a `tenko auth` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &AuthCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        AuthCommand::Provider { action } => match action {
            ProviderCommand::List(_) => list(&target).await,
            ProviderCommand::Create(args) => create(&target, args).await,
            ProviderCommand::Show(args) => show(&target, args).await,
            ProviderCommand::Update(args) => update(&target, args).await,
            ProviderCommand::Delete(args) => delete(&target, args).await,
            ProviderCommand::Test(args) => test(&target, args).await,
            ProviderCommand::LdapChain(args) => ldap_chain(&target, args).await,
        },
    }
}

fn provider_rows(items: &[Value]) -> Vec<Vec<String>> {
    items
        .iter()
        .map(|item| {
            vec![
                text(item, "id").to_owned(),
                text(item, "name").to_owned(),
                item.get("provider")
                    .map(|provider| text(provider, "kind").to_owned())
                    .unwrap_or_default(),
                text(item, "state").to_owned(),
                text(item, "last_success").to_owned(),
                text(item, "last_error").to_owned(),
            ]
        })
        .collect()
}

async fn list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items: Vec<Value> = client.get("/auth/providers").await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    Ok(Output::text(table(
        &["ID", "NAME", "KIND", "STATE", "LAST SUCCESS", "LAST ERROR"],
        &provider_rows(&items),
    )))
}

async fn create(target: &Target, args: &CreateArgs) -> Result<Output, Failure> {
    let settings = settings_from(&args.file)?;
    let mut body = json!({ "name": args.name.trim(), "provider": settings });
    if args.secret {
        let secret = read_secret("Secret of the provider: ", args.secret_stdin)?;
        body["secret"] = json!(secret.to_dto());
    }
    let client = target.connect().await?;
    let answer: Value = client.post("/auth/providers", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created provider {} ({}) as {}\n",
        text(&answer, "name"),
        text(&answer, "id"),
        text(&answer, "state")
    )))
}

async fn show(target: &Target, args: &IdArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client.get(&format!("/auth/providers/{}", args.id)).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(table(
        &["ID", "NAME", "KIND", "STATE", "LAST SUCCESS", "LAST ERROR"],
        &provider_rows(std::slice::from_ref(&answer)),
    )))
}

async fn update(target: &Target, args: &UpdateArgs) -> Result<Output, Failure> {
    let mut body = json!({});
    if let Some(name) = &args.name {
        body["name"] = json!(name.trim());
    }
    if let Some(file) = &args.file {
        body["provider"] = settings_from(file)?;
    }
    if let Some(state) = &args.state {
        body["state"] = json!(state);
    }
    if args.secret {
        let secret = read_secret("New secret of the provider: ", args.secret_stdin)?;
        body["secret"] = json!(secret.to_dto());
    }
    if body.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(usage(
            "nothing to change: give --name, --file, --state or --secret",
        ));
    }
    let client = target.connect().await?;
    let answer: Value = client
        .patch(&format!("/auth/providers/{}", args.id), &body, None)
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated provider {} ({}), now {}\n",
        text(&answer, "name"),
        text(&answer, "id"),
        text(&answer, "state")
    )))
}

async fn delete(target: &Target, args: &IdArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    client
        .delete(&format!("/auth/providers/{}", args.id), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": args.id })));
    }
    Ok(Output::text(format!("deleted provider {}\n", args.id)))
}

async fn test(target: &Target, args: &TestArgs) -> Result<Output, Failure> {
    let password = read_secret(
        &format!("Password of {}: ", args.user_name),
        args.password_stdin,
    )?;
    let body = json!({ "user_name": args.user_name, "password": password.to_dto() });
    let client = target.connect().await?;
    let answer: Value = client
        .post(
            &format!("/auth/providers/{}/test", args.id),
            &body,
            Some(&key()),
        )
        .await?;
    drop(password);
    if target.json {
        return Ok(Output::json(&answer));
    }
    let groups: Vec<&str> = answer
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let roles: Vec<&str> = answer
        .get("roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    Ok(Output::text(format!(
        "{} ({}): groups {}; roles {}; provider {}\n",
        text(&answer, "display_name"),
        text(&answer, "subject"),
        if groups.is_empty() {
            "none".to_owned()
        } else {
            groups.join(", ")
        },
        if roles.is_empty() {
            "none".to_owned()
        } else {
            roles.join(", ")
        },
        if answer
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "verified"
        } else {
            "not verified"
        }
    )))
}

async fn ldap_chain(target: &Target, args: &ChainArgs) -> Result<Output, Failure> {
    let url = args.server.trim();
    let scheme_ok = if args.starttls {
        url.starts_with("ldap://")
    } else {
        url.starts_with("ldaps://")
    };
    if !scheme_ok {
        return Err(usage(
            "the URL is ldaps://host[:port], or ldap://host[:port] with --starttls",
        ));
    }
    let body = json!({
        "url": url,
        "transport": if args.starttls { "start_tls" } else { "ldaps" },
    });
    let client = target.connect().await?;
    let answer: Value = client
        .post("/auth/providers/ldap/chain", &body, Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let rows: Vec<Vec<String>> = answer
        .get("certificates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|cert| {
            vec![
                text(cert, "subject").to_owned(),
                text(cert, "issuer").to_owned(),
                text(cert, "not_after").to_owned(),
                if cert.get("ca").and_then(Value::as_bool).unwrap_or(false) {
                    "CA".to_owned()
                } else {
                    "server".to_owned()
                },
                text(cert, "fingerprint").to_owned(),
            ]
        })
        .collect();
    let verifies = answer
        .get("verifies")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut out = table(
        &["SUBJECT", "ISSUER", "NOT AFTER", "ROLE", "SHA-256"],
        &rows,
    );
    out.push_str(if verifies {
        "the chain verifies against the system trust store\n"
    } else {
        "the chain does not verify against the system trust store: compare the fingerprints \
         on a domain controller before confirming it\n"
    });
    Ok(Output::text(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_settings_file_names_its_kind() {
        let dir = tempfile::tempdir().expect("dir");
        let good = dir.path().join("ldap.json");
        std::fs::write(
            &good,
            br#"{"kind":"ldap","urls":["ldaps://dc01.corp.example.test"]}"#,
        )
        .expect("write");
        assert_eq!(settings_from(&good).expect("json")["kind"], "ldap");
        let bad = dir.path().join("saml.json");
        std::fs::write(&bad, br#"{"kind":"saml"}"#).expect("write");
        assert!(settings_from(&bad).is_err());
        assert!(settings_from(&dir.path().join("missing.json")).is_err());
    }

    #[test]
    fn providers_render_as_rows() {
        let rows = provider_rows(&[json!({
            "id": "0190d1c2-0000-7000-8000-000000000001", "name": "Corp AD",
            "provider": { "kind": "ldap" }, "state": "draft"
        })]);
        assert_eq!(rows[0][1], "Corp AD");
        assert_eq!(rows[0][2], "ldap");
        assert_eq!(rows[0][3], "draft");
        assert_eq!(rows[0][4], "");
    }
}
