//! The command line: `tenko backup keygen`, `create`, `verify` and `restore`.
//!
//! Secrets are never flags: a passphrase comes from a prompt without echo, from the first
//! line of standard input (`--passphrase-stdin`) or of a file (`--passphrase-file`); a
//! recipient key from its key file (`--key-file`).

use std::{
    fmt::Write as _,
    io::{IsTerminal as _, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Args;
use serde::Serialize;
use tenko_auth::service::{CodeLogin, LoginResponse, PasswordLogin, SecondFactorMethod};
use tenko_core::Coded as _;
use tenko_vault::KekInit;
use zeroize::Zeroizing;

use super::{
    BackupError,
    archive::{KdfParams, OriginRecord, Unlock},
    create::{self, Extras, KeyLock, Target},
    keys::{BackupKey, Recipient, check_passphrase},
    restore,
};
use crate::{
    client::{
        ClientOpts, Failure, Output, Raw, Secret, Target as ApiTarget, read_line, read_secret,
    },
    config::{self, Resolved, TlsSpec},
    exit,
};

/// Where a passphrase comes from.
#[derive(Debug, Clone, Default, Args)]
pub struct PassphraseArgs {
    /// Read the passphrase from the first line of standard input.
    #[arg(long, conflicts_with = "passphrase_file")]
    pub passphrase_stdin: bool,

    /// Read the passphrase from the first line of this file.
    #[arg(long, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,
}

/// Arguments of `tenko backup keygen`.
#[derive(Debug, Clone, Args)]
pub struct KeygenArgs {
    /// The key file to create (never replaced); keep it offline.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Arguments of `tenko backup create`.
#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// The configuration file of the stopped node (offline backup).
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory of the stopped node (offline backup); overrides `data_dir` of the
    /// file. Without `--config` and `--data-dir` the backup is written online by the
    /// controller at `--url`.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Offline: the file or directory to write; default the `[backup] target_dir` of the
    /// node, else `backups/` in its data directory.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Offline: a recipient (`tkbr1:…`) to encrypt to; repeatable.
    #[arg(long, value_name = "RECIPIENT")]
    pub recipient: Vec<String>,

    /// Offline: leave the configuration file out of the backup.
    #[arg(long)]
    pub no_config: bool,

    /// The passphrase (offline: asked for unless a recipient is given; online: optional,
    /// besides the configured recipient).
    #[command(flatten)]
    pub passphrase: PassphraseArgs,

    /// Online: the account to sign in with; asked for when not given.
    #[arg(long, short = 'u', value_name = "NAME")]
    pub user: Option<String>,

    /// Online: read the account's password from the first line of standard input.
    #[arg(long, conflicts_with = "passphrase_stdin")]
    pub password_stdin: bool,

    /// Online: the TOTP code, when the account has a second factor.
    #[arg(long, value_name = "CODE")]
    pub totp_code: Option<String>,

    /// Online: connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// What opens a backup.
#[derive(Debug, Clone, Default, Args)]
pub struct UnlockArgs {
    /// A recipient key file (`tenko backup keygen`) instead of a passphrase.
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,

    /// The passphrase.
    #[command(flatten)]
    pub passphrase: PassphraseArgs,
}

/// Arguments of `tenko backup verify`.
#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    /// The backup file.
    pub file: PathBuf,

    /// What opens it.
    #[command(flatten)]
    pub unlock: UnlockArgs,

    /// The directory for the temporary store of the check (default: the system temporary
    /// directory); it needs about twice the size of the backup.
    #[arg(long, value_name = "PATH")]
    pub work_dir: Option<PathBuf>,

    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments of `tenko backup restore`.
#[derive(Debug, Clone, Args)]
pub struct RestoreArgs {
    /// The backup file.
    pub file: PathBuf,

    /// The configuration of this node: the KEK provider and `[node] id`.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// The data directory to restore into (without a store); overrides `data_dir` of the
    /// file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Check everything and write nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// What opens the backup.
    #[command(flatten)]
    pub unlock: UnlockArgs,

    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

fn failed(error: &BackupError) -> Failure {
    let status = match error {
        BackupError::KeyRefused => exit::AUTH,
        BackupError::Corrupt(_)
        | BackupError::DigestMismatch(_)
        | BackupError::CheckFailed { .. } => exit::INTEGRITY,
        BackupError::NotABackup(_)
        | BackupError::Unsupported { .. }
        | BackupError::NoKey(_)
        | BackupError::PassphraseWeak { .. }
        | BackupError::InvalidKey(_)
        | BackupError::TargetNotEmpty(_)
        | BackupError::InUse(_) => exit::USAGE,
        BackupError::FormatNewer { .. } => exit::UPGRADE_REFUSED,
        _ => exit::FAILURE,
    };
    Failure::new(status, format!("[{}] {error}", error.code()))
}

fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| Failure::other(format!("runtime: {error}")))
}

fn resolve(file: Option<&PathBuf>, data_dir: Option<&PathBuf>) -> Result<Resolved, Failure> {
    let sources = config::Sources {
        file: file.cloned(),
        data_dir: data_dir.cloned(),
        roles: None,
    };
    config::load(&sources, std::env::vars())
        .and_then(|loaded| loaded.config.resolve())
        .map_err(|error| Failure::new(exit::CONFIG, error.to_string()))
}

fn first_line(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.lines().next().unwrap_or_default().to_owned())
}

/// The passphrase of `args`, or `None` when neither source is given and `prompt` is off.
fn passphrase(
    args: &PassphraseArgs,
    prompt: Option<&str>,
    confirm: bool,
) -> Result<Option<Zeroizing<String>>, Failure> {
    if let Some(path) = &args.passphrase_file {
        let text = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|error| failed(&BackupError::io(path, error)))?,
        );
        return Ok(Some(first_line(&text)));
    }
    if args.passphrase_stdin {
        let secret = read_secret("", true)?;
        return Ok(Some(Zeroizing::new(secret.expose().to_owned())));
    }
    let Some(prompt) = prompt else {
        return Ok(None);
    };
    if !std::io::stdin().is_terminal() {
        return Err(Failure::new(
            exit::USAGE,
            "no terminal to ask for the passphrase: use --passphrase-stdin or --passphrase-file",
        ));
    }
    let first = read_secret(prompt, false)?;
    if confirm {
        let second = read_secret("Repeat the passphrase: ", false)?;
        if first.expose() != second.expose() {
            return Err(Failure::new(exit::USAGE, "the passphrases differ"));
        }
    }
    Ok(Some(Zeroizing::new(first.expose().to_owned())))
}

/// The key or passphrase that opens a backup.
enum Opener {
    Key(BackupKey),
    Passphrase(Zeroizing<String>),
}

impl Opener {
    fn read(args: &UnlockArgs) -> Result<Self, Failure> {
        if let Some(path) = &args.key_file {
            return BackupKey::read(path)
                .map(Self::Key)
                .map_err(|error| failed(&error));
        }
        passphrase(&args.passphrase, Some("Backup passphrase: "), false)?
            .map(Self::Passphrase)
            .ok_or_else(|| Failure::new(exit::USAGE, "no passphrase"))
    }

    fn unlock(&self) -> Unlock<'_> {
        match self {
            Self::Key(key) => Unlock::Key(key),
            Self::Passphrase(passphrase) => Unlock::Passphrase(passphrase),
        }
    }
}

/// Runs `tenko backup keygen`.
///
/// # Errors
///
/// A [`Failure`] naming the cause.
pub fn keygen(args: &KeygenArgs) -> Result<Output, Failure> {
    let key = BackupKey::generate().map_err(|error| failed(&error))?;
    key.write_new(&args.out).map_err(|error| failed(&error))?;
    Ok(Output::text(format!("{}\n", key.recipient())).note(format!(
        "NOTE: {} opens every backup encrypted to this recipient. Keep it offline, away from \
         the controllers; set the recipient above in the backup settings.",
        args.out.display()
    )))
}

#[derive(Serialize)]
struct CreatedView<'a> {
    file: &'a Path,
    bytes: u64,
    revision: u64,
    slots: usize,
    duration_ms: u64,
}

/// Runs `tenko backup create`.
///
/// # Errors
///
/// A [`Failure`] naming the cause.
pub fn create(args: &CreateArgs) -> Result<Output, Failure> {
    if args.config.is_none() && args.data_dir.is_none() {
        let runtime = runtime()?;
        let result = runtime.block_on(online(args));
        runtime.shutdown_timeout(Duration::from_secs(5));
        return result;
    }
    let resolved = resolve(args.config.as_ref(), args.data_dir.as_ref())?;
    if resolved.layout().is_fresh() {
        return Err(Failure::new(
            exit::USAGE,
            format!("{} holds no store", resolved.data_dir.display()),
        ));
    }
    let mut locks = Vec::new();
    for text in &args.recipient {
        locks.push(KeyLock::Recipient(
            Recipient::parse(text).map_err(|error| failed(&error))?,
        ));
    }
    let prompt = locks.is_empty().then_some("New backup passphrase: ");
    if let Some(passphrase) = passphrase(&args.passphrase, prompt, true)? {
        check_passphrase(&passphrase).map_err(|error| failed(&error))?;
        locks.push(KeyLock::Passphrase(passphrase));
    }
    let tls = match &resolved.tls {
        TlsSpec::Imported {
            cert_path,
            key_path,
        } => Some((cert_path.clone(), key_path.clone())),
        _ => None,
    };
    let target = match &args.out {
        Some(path) if path.is_dir() => Target::Dir(path.clone()),
        Some(path) => Target::File(path.clone()),
        None => Target::Dir(resolved.backup_dir()),
    };
    let request = create::Request {
        locks,
        kdf: KdfParams::HARDENED,
        origin: OriginRecord {
            reason: "offline".to_owned(),
            by: "system".to_owned(),
        },
        extras: Extras {
            tls,
            config: if args.no_config {
                None
            } else {
                args.config.clone()
            },
        },
        target,
    };
    let ring = resolved
        .kek
        .load_with(KekInit::Require, &resolved.kek_options)
        .map_err(|error| Failure::new(exit::START, format!("[{}] {error}", error.code())))?;
    let runtime = runtime()?;
    let result = runtime.block_on(create::from_closed(
        &resolved.layout().store(),
        resolved.node_id,
        &ring,
        request,
    ));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let created = result.map_err(|error| failed(&error))?;
    let view = CreatedView {
        file: &created.path,
        bytes: created.bytes,
        revision: created.manifest.revision,
        slots: created.manifest.parts.len(),
        duration_ms: u64::try_from(created.duration.as_millis()).unwrap_or(u64::MAX),
    };
    if args.client.json {
        return Ok(Output::json(&view));
    }
    Ok(Output::text(format!(
        "wrote {} ({} bytes, revision {}) in {} ms\n",
        created.path.display(),
        created.bytes,
        created.manifest.revision,
        view.duration_ms
    )))
}

/// The online backup: a fresh session (the step-up), `POST /system/backups`, sign-out.
async fn online(args: &CreateArgs) -> Result<Output, Failure> {
    let target = ApiTarget::resolve(&args.client, false)?;
    let raw = target.raw()?;
    let passphrase = passphrase(&args.passphrase, None, false)?;
    if let Some(passphrase) = &passphrase {
        check_passphrase(passphrase).map_err(|error| failed(&error))?;
    }
    let user = match &args.user {
        Some(user) => user.clone(),
        None => read_line("User: ")?,
    };
    if user.is_empty() {
        return Err(Failure::new(exit::USAGE, "no user name"));
    }
    let password = read_secret(&format!("Password for {user}: "), args.password_stdin)?;
    let cookie = sign_in(&raw, &user, &password, args.totp_code.as_ref()).await?;
    drop(password);
    let body = tenko_api::dto::backup::BackupCreateRequest {
        passphrase: passphrase.as_ref().map(|passphrase| passphrase.to_string()),
        before_update: None,
    };
    let answer = raw.post_json("/system/backups", &body, Some(&cookie)).await;
    let _ = raw
        .post_json("/auth/logout", &serde_json::json!({}), Some(&cookie))
        .await;
    let run: tenko_api::dto::backup::BackupRunView = answer?.json()?;
    if target.json {
        return Ok(Output::json(&run));
    }
    Ok(Output::text(format!(
        "controller {} wrote {} in {} ({} bytes)\n",
        run.node,
        run.file.as_deref().unwrap_or("?"),
        run.target_dir,
        run.bytes.unwrap_or_default()
    )))
}

async fn sign_in(
    raw: &Raw,
    user: &str,
    password: &Secret,
    totp_code: Option<&String>,
) -> Result<String, Failure> {
    let first = raw
        .post_json(
            "/auth/login/password",
            &PasswordLogin {
                user_name: user.to_owned(),
                password: password.to_dto(),
            },
            None,
        )
        .await?;
    let (response, cookie) = match first.json::<LoginResponse>()? {
        authenticated @ LoginResponse::Authenticated { .. } => {
            (authenticated, first.session_cookie())
        }
        LoginResponse::SecondFactor {
            challenge_id,
            methods,
            ..
        } => {
            if !methods.contains(&SecondFactorMethod::Totp) {
                return Err(Failure::new(
                    exit::AUTH,
                    "this account signs in with a passkey or a recovery code only: write the \
                     backup from the web UI",
                ));
            }
            let code = match totp_code {
                Some(code) => code.clone(),
                None => read_line("TOTP code: ")?,
            };
            let body = CodeLogin {
                challenge_id,
                code: Secret::new(code).to_dto(),
            };
            let second = raw.post_json("/auth/login/totp", &body, None).await?;
            (second.json::<LoginResponse>()?, second.session_cookie())
        }
    };
    if !matches!(response, LoginResponse::Authenticated { .. }) {
        return Err(Failure::new(
            exit::AUTH,
            "the second factor was not accepted",
        ));
    }
    cookie.ok_or_else(|| Failure::other("the server signed in but set no session cookie"))
}

fn render(report: &restore::Report) -> String {
    let manifest = &report.manifest;
    let mut text = String::new();
    let _ = writeln!(text, "backup      {}", report.file.display());
    let _ = writeln!(
        text,
        "made        {} by Tenko {} on node {} (voters {:?})",
        manifest.created_at, manifest.tenko_version, manifest.node, manifest.voters
    );
    let _ = writeln!(
        text,
        "store       revision {}, data format {}, {} rows in {} tables, audit head {}",
        manifest.revision,
        manifest.data_format,
        manifest.digest.entries,
        manifest.digest.tables,
        manifest.audit_head
    );
    let _ = writeln!(text, "opens with  {}", report.slots.join(", "));
    for part in &report.parts {
        let _ = writeln!(text, "part        {} ({} bytes) ok", part.name, part.bytes);
    }
    let _ = writeln!(
        text,
        "checks      digest {}, audit chain verified, {} secrets opened, key generations {}",
        if report.digest_matches {
            "matches"
        } else {
            "DIFFERS"
        },
        report.envelopes,
        manifest.kek.generations.join(", ")
    );
    if let Some(fingerprint) = &report.ca_fingerprint {
        let _ = writeln!(text, "CA          SHA-256 {fingerprint}");
    }
    for path in &report.written {
        let _ = writeln!(text, "wrote       {}", path.display());
    }
    for note in &report.notes {
        let _ = writeln!(text, "note        {note}");
    }
    text
}

/// Runs `tenko backup verify`.
///
/// # Errors
///
/// A [`Failure`] naming the first check that failed.
pub fn verify(args: &VerifyArgs) -> Result<Output, Failure> {
    let opener = Opener::read(&args.unlock)?;
    let work = args.work_dir.clone().unwrap_or_else(std::env::temp_dir);
    let runtime = runtime()?;
    let result = runtime.block_on(restore::check(
        &args.file,
        opener.unlock(),
        &work,
        tenko_core::NodeId(1),
    ));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let report = result.map_err(|error| failed(&error))?;
    if args.json {
        return Ok(Output::json(&report));
    }
    Ok(Output::text(render(&report)).note("the backup is complete and restores"))
}

/// Runs `tenko backup restore`.
///
/// # Errors
///
/// A [`Failure`] naming the first check that failed; nothing restored stays behind.
pub fn restore(args: &RestoreArgs) -> Result<Output, Failure> {
    let resolved = resolve(args.config.as_ref(), args.data_dir.as_ref())?;
    let opener = Opener::read(&args.unlock)?;
    let target = restore::Target {
        data_dir: resolved.data_dir.clone(),
        store_dir: resolved.layout().store(),
        node: resolved.node_id,
        address: resolved.config.node.address.clone(),
        kek: resolved.kek.clone(),
        kek_options: resolved.kek_options.clone(),
    };
    let runtime = runtime()?;
    let result = runtime.block_on(restore::restore(
        &args.file,
        opener.unlock(),
        &target,
        args.dry_run,
    ));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let report = result.map_err(|error| failed(&error))?;
    if args.json {
        return Ok(Output::json(&report));
    }
    let note = if args.dry_run {
        "dry run: the backup restores here; nothing was written".to_owned()
    } else {
        format!(
            "restored into {}; start the server with the configuration of this host. Copy \
             files from {} into place as needed.",
            resolved.data_dir.display(),
            resolved.data_dir.join(restore::EXTRAS_DIR).display()
        )
    };
    Ok(Output::text(render(&report)).note(note))
}

/// Writes the outcome of a command and returns its exit status.
pub(crate) fn finish(
    name: &str,
    json: bool,
    result: Result<Output, Failure>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    match result {
        Ok(output) => {
            let _ = out.write_all(output.stdout.as_bytes());
            let _ = err.write_all(output.stderr.as_bytes());
            output.status
        }
        Err(failure) => failure.report(name, json, out, err),
    }
}
