//! `tenko dns dnssec status|enable|disable|rollover` (WP6.3): the signing state of a zone,
//! signing switched on and off through the zone's `dnssec` policy, and key rollovers.
//!
//! - `status` reads `GET /dns/zones/{id}/dnssec`: the mode, the keys with their tags and
//!   states, the DS records for the parent, the serial last signed, the earliest expiry,
//!   the rollover that runs and the health findings.
//! - `enable` patches the zone with `dnssec.mode = online` (or `imported` with
//!   `--imported`) and the algorithm, denial and timing options given; the signer signs the
//!   zone right after, and `status` shows the DS to put at the parent.
//! - `disable` patches `dnssec.mode = off`: the signer removes the rows it wrote and keeps
//!   the keys retired, so enabling again takes them up and the DS stays valid.
//! - `rollover` posts `POST /dns/zones/{id}/dnssec/rollover` with the role (`zsk` by
//!   default) and prints the job.

use std::fmt::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Map, Value, json};

use super::{ZoneRefArgs, key, resolve_zone, revision, text, usage, zone_path};
use crate::client::{ClientOpts, Failure, Output, Target, table};

/// Subcommands of `tenko dns dnssec`.
#[derive(Debug, Clone, Subcommand)]
pub enum DnssecCommand {
    /// Show the signing state, the keys and the DS records of a zone.
    Status(ZoneRefArgs),
    /// Sign a zone online (or serve it as imported, already signed).
    Enable(EnableArgs),
    /// Stop signing a zone: the signer removes its rows and retires the keys.
    Disable(ZoneRefArgs),
    /// Start a key rollover.
    Rollover(RolloverArgs),
}

impl DnssecCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Status(args) | Self::Disable(args) => &args.client,
            Self::Enable(args) => &args.zone.client,
            Self::Rollover(args) => &args.zone.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "dns dnssec status",
            Self::Enable(_) => "dns dnssec enable",
            Self::Disable(_) => "dns dnssec disable",
            Self::Rollover(_) => "dns dnssec rollover",
        }
    }
}

/// A signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgorithmArg {
    /// ECDSA P-256 with SHA-256, algorithm 13 (the default).
    Ecdsap256sha256,
    /// Ed25519, algorithm 15.
    Ed25519,
}

impl AlgorithmArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Ecdsap256sha256 => "ecdsa_p256_sha256",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// A key role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    /// The zone-signing key.
    Zsk,
    /// The key-signing key (its DS is at the parent).
    Ksk,
    /// The combined key.
    Csk,
}

impl RoleArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Zsk => "zsk",
            Self::Ksk => "ksk",
            Self::Csk => "csk",
        }
    }
}

/// Arguments of `tenko dns dnssec enable`.
#[derive(Debug, Clone, Args)]
pub struct EnableArgs {
    /// The zone and the connection.
    #[command(flatten)]
    pub zone: ZoneRefArgs,
    /// The algorithm of new keys.
    #[arg(long, value_enum)]
    pub algorithm: Option<AlgorithmArg>,
    /// Deny with NSEC3 (zero iterations, no salt, RFC 9276) instead of NSEC.
    #[arg(long)]
    pub nsec3: bool,
    /// Sign with one combined key (CSK) instead of a KSK and a ZSK.
    #[arg(long)]
    pub csk: bool,
    /// How long a signature is valid, in days (14 by default).
    #[arg(long, value_name = "DAYS")]
    pub validity_days: Option<u16>,
    /// How long before the expiry a signature is renewed, in days (7 by default).
    #[arg(long, value_name = "DAYS")]
    pub resign_days: Option<u16>,
    /// Roll the ZSK every this many days.
    #[arg(long, value_name = "DAYS")]
    pub zsk_rollover_days: Option<u16>,
    /// Serve the zone's own signatures (an imported signed zone) instead of signing it.
    #[arg(long, conflicts_with_all = ["algorithm", "nsec3", "csk", "zsk_rollover_days"])]
    pub imported: bool,
}

/// Arguments of `tenko dns dnssec rollover`.
#[derive(Debug, Clone, Args)]
pub struct RolloverArgs {
    /// The zone and the connection.
    #[command(flatten)]
    pub zone: ZoneRefArgs,
    /// The role of the key to roll.
    #[arg(long, value_enum, default_value = "zsk")]
    pub role: RoleArg,
}

/// Runs `tenko dns dnssec ...`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(target: &Target, command: &DnssecCommand) -> Result<Output, Failure> {
    match command {
        DnssecCommand::Status(args) => status(target, args).await,
        DnssecCommand::Enable(args) => enable(target, args).await,
        DnssecCommand::Disable(args) => disable(target, args).await,
        DnssecCommand::Rollover(args) => rollover(target, args).await,
    }
}

fn date(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_owned()
}

fn ds_line(zone: &str, ds: &Value) -> String {
    let field = |key: &str| ds.get(key).map(ToString::to_string).unwrap_or_default();
    format!(
        "{zone}. IN DS {} {} {} {}",
        field("key_tag"),
        field("algorithm"),
        field("digest_type"),
        ds.get("digest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_uppercase()
    )
}

async fn status(target: &Target, args: &ZoneRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let state: Value = client.get(&format!("{}/dnssec", zone_path(&zone))).await?;
    if target.json {
        return Ok(Output::json(&state));
    }
    let name = text(&zone, &["name"]).to_owned();
    let mut out = format!("zone {name}: {}\n", text(&state, &["mode"]));
    for (label, key) in [
        ("signed serial", "signed_serial"),
        ("last signed", "last_signed"),
        ("earliest expiry", "expires"),
        ("next re-sign", "next_resign"),
        ("rollover job", "rollover_job"),
    ] {
        if let Some(value) = state.get(key).filter(|value| !value.is_null()) {
            let shown = value
                .as_str()
                .map_or_else(|| value.to_string(), ToOwned::to_owned);
            let _ = writeln!(out, "{label}: {shown}");
        }
    }
    let keys = state
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !keys.is_empty() {
        let rows: Vec<Vec<String>> = keys
            .iter()
            .map(|key| {
                vec![
                    text(key, &["role"]).to_ascii_uppercase(),
                    key.get("key_tag")
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    text(key, &["algorithm"]).to_owned(),
                    text(key, &["state"]).to_owned(),
                    date(key, "published"),
                    date(key, "activated"),
                    date(key, "retired"),
                ]
            })
            .collect();
        out.push('\n');
        out.push_str(&table(
            &[
                "ROLE",
                "TAG",
                "ALGORITHM",
                "STATE",
                "PUBLISHED",
                "ACTIVE",
                "RETIRED",
            ],
            &rows,
        ));
    }
    let ds = state
        .get("ds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !ds.is_empty() {
        out.push_str("\nDS records for the parent zone:\n");
        for record in &ds {
            out.push_str(&ds_line(&name, record));
            out.push('\n');
        }
    }
    for finding in state
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let _ = writeln!(
            out,
            "warning {}: {}",
            text(finding, &["code"]),
            text(finding, &["detail"])
        );
    }
    Ok(Output::text(out))
}

async fn patch_policy(
    target: &Target,
    args: &ZoneRefArgs,
    change: impl FnOnce(&mut Map<String, Value>),
) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let mut policy = zone
        .get("dnssec")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    change(&mut policy);
    let answer: Value = client
        .patch(
            &zone_path(&zone),
            &json!({ "dnssec": Value::Object(policy) }),
            revision(args.if_match),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "zone {}: dnssec {}\n",
        text(&answer, &["name"]),
        text(&answer, &["dnssec", "mode"])
    )))
}

async fn enable(target: &Target, args: &EnableArgs) -> Result<Output, Failure> {
    if args
        .resign_days
        .zip(args.validity_days)
        .is_some_and(|(resign, validity)| resign >= validity)
    {
        return Err(usage("--resign-days must be less than --validity-days"));
    }
    patch_policy(target, &args.zone, |policy| {
        let mode = if args.imported { "imported" } else { "online" };
        policy.insert("mode".to_owned(), json!(mode));
        if let Some(algorithm) = args.algorithm {
            policy.insert("algorithm".to_owned(), json!(algorithm.api()));
        }
        if args.nsec3 {
            policy.insert(
                "denial".to_owned(),
                json!({ "kind": "nsec3", "iterations": 0, "salt": "" }),
            );
        }
        if args.csk {
            policy.insert("csk".to_owned(), json!(true));
        }
        if let Some(days) = args.validity_days {
            policy.insert("signature_validity_days".to_owned(), json!(days));
        }
        if let Some(days) = args.resign_days {
            policy.insert("resign_before_days".to_owned(), json!(days));
        }
        if let Some(days) = args.zsk_rollover_days {
            policy.insert("zsk_rollover_days".to_owned(), json!(days));
        }
    })
    .await
}

async fn disable(target: &Target, args: &ZoneRefArgs) -> Result<Output, Failure> {
    patch_policy(target, args, |policy| {
        policy.insert("mode".to_owned(), json!("off"));
    })
    .await
}

async fn rollover(target: &Target, args: &RolloverArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone.zone).await?;
    let answer: Value = client
        .post(
            &format!("{}/dnssec/rollover", zone_path(&zone)),
            &json!({ "role": args.role.api() }),
            Some(&key()),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let job = text(&answer, &["job_id"]);
    Ok(Output::text(format!(
        "started the {} rollover of zone {} as job {job}\n\
         follow it with GET /api/v1/jobs/{job} and `tenko dns dnssec status {}`\n",
        args.role.api(),
        text(&zone, &["name"]),
        text(&zone, &["name"]),
    )))
}
