//! `tenko dns kerberos ...`: the Kerberos account of secure dynamic updates (identity plan
//! sections 3.1 and 4.3; WP13.0 declares the commands, WP13.3 builds the routes).
//!
//! Every route answers the 501 `sys.not_implemented` problem details until WP13.3 builds
//! it, printed as any other API error.
//!
//! # Routes
//!
//! | Command | Request |
//! |---|---|
//! | `kerberos status` | `GET /dns/kerberos` |
//! | `kerberos adopt <realm> <name> --spn S... [--kdc K...] [--rotation-days D]` | `POST /dns/kerberos/adopt` |
//! | `kerberos import <realm> <keytab file> --spn S... [--kdc K...]` | `POST /dns/kerberos/import` |
//! | `kerberos check` | `POST /dns/kerberos/check` |
//! | `kerberos rotate` | `POST /dns/kerberos/rotate` |
//! | `kerberos delete` | `DELETE /dns/kerberos` |
//!
//! The one-time password of `adopt` is asked for on the terminal, or read from the first
//! line of standard input with `--password-stdin`; it is never a flag. The keytab of
//! `import` is read from the file and sent in base64url without padding (RFC 4648 section
//! 5, as the route's schema says); the file stays where it is.

use std::{fmt::Write as _, path::PathBuf};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use tenko_auth::encoding::base64url_encode;

use super::{ClientOpts, Failure, Output, Target, key, number, text, usage};
use crate::client::read_secret;

/// Subcommands of `tenko dns kerberos`.
#[derive(Debug, Clone, Subcommand)]
pub enum KerberosCommand {
    /// The account's status: key versions, SPNs, the last rotation and self-test, the
    /// findings, the contexts of the node.
    Status(StatusArgs),
    /// Take over a pre-staged computer account with its one-time password.
    Adopt(AdoptArgs),
    /// Import a keytab made with ktpass or msktutil.
    Import(ImportArgs),
    /// Run the self-test now.
    Check(StatusArgs),
    /// Rotate the account's password now (an interactive session only).
    Rotate(StatusArgs),
    /// Delete the account and its keys from Tenko (an interactive session only).
    Delete(StatusArgs),
}

impl KerberosCommand {
    /// The connection options.
    pub const fn client(&self) -> &ClientOpts {
        match self {
            Self::Status(a) | Self::Check(a) | Self::Rotate(a) | Self::Delete(a) => &a.client,
            Self::Adopt(a) => &a.client,
            Self::Import(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "dns kerberos status",
            Self::Adopt(_) => "dns kerberos adopt",
            Self::Import(_) => "dns kerberos import",
            Self::Check(_) => "dns kerberos check",
            Self::Rotate(_) => "dns kerberos rotate",
            Self::Delete(_) => "dns kerberos delete",
        }
    }
}

/// Arguments of the commands that take nothing but the connection.
#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of `tenko dns kerberos adopt`.
#[derive(Debug, Clone, Args)]
pub struct AdoptArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The realm (`CORP.EXAMPLE.TEST`).
    #[arg(value_name = "REALM")]
    pub realm: String,
    /// The account name as the administrator created it (`TENKO-DNS$`).
    #[arg(value_name = "NAME")]
    pub name: String,
    /// A service principal name the account holds (`DNS/ns1.corp.example.test`); repeat
    /// for each.
    #[arg(long = "spn", value_name = "SPN", required = true)]
    pub spns: Vec<String>,
    /// A KDC, `host` or `host:port`; repeat for each. None: found through
    /// `_kerberos._tcp.<realm>`.
    #[arg(long = "kdc", value_name = "KDC")]
    pub kdcs: Vec<String>,
    /// Days between password rotations, 0 to 365 (30 when absent; 0 is off, Lab only).
    #[arg(long, value_name = "DAYS", value_parser = clap::value_parser!(u16).range(0..=365))]
    pub rotation_days: Option<u16>,
    /// Read the one-time password from the first line of standard input instead of asking
    /// for it.
    #[arg(long)]
    pub password_stdin: bool,
}

/// Arguments of `tenko dns kerberos import`.
#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The realm (`CORP.EXAMPLE.TEST`).
    #[arg(value_name = "REALM")]
    pub realm: String,
    /// The keytab file (MIT format version 2).
    #[arg(value_name = "FILE")]
    pub keytab: PathBuf,
    /// A service principal name the account holds; repeat for each.
    #[arg(long = "spn", value_name = "SPN", required = true)]
    pub spns: Vec<String>,
    /// A KDC, `host` or `host:port`; repeat for each.
    #[arg(long = "kdc", value_name = "KDC")]
    pub kdcs: Vec<String>,
}

/// Runs a `tenko dns kerberos` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &KerberosCommand) -> Result<Output, Failure> {
    match command {
        KerberosCommand::Status(_) => status(target).await,
        KerberosCommand::Adopt(args) => adopt(target, args).await,
        KerberosCommand::Import(args) => import(target, args).await,
        KerberosCommand::Check(_) => check(target).await,
        KerberosCommand::Rotate(_) => rotate(target).await,
        KerberosCommand::Delete(_) => delete(target).await,
    }
}

/// The realm as it goes into a body: trimmed and in upper case, never empty.
fn realm_text(realm: &str) -> Result<String, Failure> {
    let realm = realm.trim().to_ascii_uppercase();
    if realm.is_empty() || realm.contains(['@', '/', '\\']) || realm.contains(char::is_whitespace) {
        return Err(usage(
            "the realm is a name such as CORP.EXAMPLE.TEST, without `@`, `/` or spaces",
        ));
    }
    Ok(realm)
}

/// The status as lines: the account, its versions, the findings and the contexts.
fn render_status(answer: &Value) -> String {
    let mut out = String::new();
    match answer.get("account").filter(|account| !account.is_null()) {
        None => out.push_str("no Kerberos account is set up\n"),
        Some(account) => {
            let _ = writeln!(
                out,
                "account {} of {} ({})",
                text(account, &["name"]),
                text(account, &["realm"]),
                if account
                    .get("owned")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "the password is Tenko's"
                } else {
                    "imported from a keytab"
                }
            );
            for spn in account
                .get("spns")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let _ = writeln!(out, "  spn {}", spn.as_str().unwrap_or_default());
            }
            for version in account
                .get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let _ = writeln!(
                    out,
                    "  kvno {} {} since {}",
                    number(version, &["kvno"]),
                    text(version, &["state"]),
                    text(version, &["created"])
                );
            }
            for (label, field) in [
                ("last rotation", "last_rotation"),
                ("last check", "last_check"),
            ] {
                let value = text(account, &[field]);
                if !value.is_empty() {
                    let _ = writeln!(out, "  {label} {value}");
                }
            }
        }
    }
    for finding in answer
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let _ = writeln!(
            out,
            "finding {}: {}",
            text(finding, &["code"]),
            text(finding, &["detail"])
        );
    }
    if let Some(contexts) = answer.get("contexts") {
        let _ = writeln!(
            out,
            "contexts: {} negotiating, {} established, {} refused in the last hour",
            number(contexts, &["negotiating"]),
            number(contexts, &["established"]),
            number(contexts, &["refused_last_hour"])
        );
    }
    out
}

async fn status(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client.get("/dns/kerberos").await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(render_status(&answer)))
}

async fn adopt(target: &Target, args: &AdoptArgs) -> Result<Output, Failure> {
    let realm = realm_text(&args.realm)?;
    let name = args.name.trim();
    if name.is_empty() {
        return Err(usage("the account name is empty"));
    }
    let password = read_secret(
        &format!("One-time password of {name}@{realm}: "),
        args.password_stdin,
    )?;
    let mut body = json!({
        "realm": realm,
        "name": name,
        "password": password.to_dto(),
        "spns": args.spns,
        "kdcs": args.kdcs,
    });
    if let Some(days) = args.rotation_days {
        body["rotation_days"] = json!(days);
    }
    let client = target.connect().await?;
    let answer: Value = client
        .post("/dns/kerberos/adopt", &body, Some(&key()))
        .await?;
    drop(password);
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "adopted {name}@{realm}\n{}",
        render_status(&answer)
    )))
}

async fn import(target: &Target, args: &ImportArgs) -> Result<Output, Failure> {
    let realm = realm_text(&args.realm)?;
    let bytes = std::fs::read(&args.keytab).map_err(|error| {
        usage(format!(
            "cannot read the keytab {}: {error}",
            args.keytab.display()
        ))
    })?;
    if bytes.len() > 1 << 20 {
        return Err(usage("a keytab is at most 1 MiB"));
    }
    let body = json!({
        "realm": realm,
        "keytab": base64url_encode(&bytes),
        "spns": args.spns,
        "kdcs": args.kdcs,
    });
    let client = target.connect().await?;
    let answer: Value = client
        .post("/dns/kerberos/import", &body, Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "imported the keys of {realm}\n{}",
        render_status(&answer)
    )))
}

async fn check(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client
        .post("/dns/kerberos/check", &json!({}), Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(render_status(&answer)))
}

async fn rotate(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client
        .post("/dns/kerberos/rotate", &json!({}), Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "rotation started as job {}\n",
        text(&answer, &["job_id"])
    )))
}

async fn delete(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    client.delete("/dns/kerberos", None).await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": true })));
    }
    Ok(Output::text("deleted the Kerberos account from Tenko\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_realm_is_checked_and_folded() {
        assert_eq!(
            realm_text(" corp.example.test ").expect("realm"),
            "CORP.EXAMPLE.TEST"
        );
        for bad in ["", "a@b", "a/b", "a b"] {
            assert!(realm_text(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_status_renders_the_account_and_without_one_says_so() {
        assert_eq!(render_status(&json!({})), "no Kerberos account is set up\n");
        let rendered = render_status(&json!({
            "account": {
                "realm": "CORP.EXAMPLE.TEST", "name": "TENKO-DNS$", "owned": true,
                "spns": ["DNS/ns1.corp.example.test"],
                "versions": [{ "kvno": 3, "state": "current", "created": "2026-10-25T12:00:00Z" }],
                "last_check": "2026-10-26T12:00:00Z"
            },
            "findings": [{ "code": "dns.gss.clock_skew", "detail": "61 s" }],
            "contexts": { "negotiating": 1, "established": 2, "refused_last_hour": 0 }
        }));
        for line in [
            "account TENKO-DNS$ of CORP.EXAMPLE.TEST (the password is Tenko's)",
            "  spn DNS/ns1.corp.example.test",
            "  kvno 3 current since 2026-10-25T12:00:00Z",
            "  last check 2026-10-26T12:00:00Z",
            "finding dns.gss.clock_skew: 61 s",
            "contexts: 1 negotiating, 2 established, 0 refused in the last hour",
        ] {
            assert!(rendered.contains(line), "{line}\n{rendered}");
        }
        assert!(!rendered.contains("last rotation"));
    }
}
