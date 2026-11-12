//! The steps of the install job (kind `sys.update`, OPS-24): backup, fetch, verify, check,
//! switch.
//!
//! | Step | What it does | Undo |
//! |---|---|---|
//! | `sys.update.backup` | writes and records a backup before the update (ADR 0023), wrapped to the configured recipient, when the request answered `backup: "run"`; a failed backup fails the job before anything changed | nothing: the backup stays |
//! | `sys.update.fetch` | downloads the release file for this platform from the pinned source into `<data_dir>/updates/<version>/tenko.part` (not for uploads), following redirects only inside the release prefix and to the listed redirect hosts, and audits `sys.update.download` with the requested URL, the final URL, the size and the SHA-256 of what arrived | removes the file |
//! | `sys.update.verify` | compares size and SHA-256 with the manifest (and the signature with the feature `release-signatures`, off until API-19), then puts the file in place with its manifest entry | removes the version directory |
//! | `sys.update.check` | asks the new binary for its version, copies the running state, and lets the new binary dry-run its migrations on the copy (`tenko upgrade check --disposable`) | nothing to undo |
//! | `sys.update.switch` | records the attempt and points `current` at the new version (`previous` at the running one) | points `current` back |
//!
//! When the job succeeds, the service restarts the server into the new version. Every step
//! is audited with the job's transitions.

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Weak},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_api::dto::release::{ReleaseAsset, ReleaseVersion};
use tenko_core::{
    CodedError, MessageKey, ObjectKind, ObjectRef,
    audit::{AuditAction, AuditDetails, AuditDraft},
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_jobs::{
    GroupKey, JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepSpec,
};
use tenko_store::{ReadView, WriteBatch, format};

use super::{
    layout::{CURRENT, PREVIOUS},
    probation::{self, Attempt},
    source::{Staged, sha256_file},
    updates::Inner,
};

/// The job kind.
pub const JOB_KIND: &str = "sys.update";
/// The job title (a message key of the UI).
pub const JOB_TITLE: &str = "jobs.title.update_install";
/// The backup step, first when the request asked for a backup.
pub const BACKUP: &str = "sys.update.backup";
/// The fetch step.
pub const FETCH: &str = "sys.update.fetch";
/// The verify step.
pub const VERIFY: &str = "sys.update.verify";
/// The check step.
pub const CHECK: &str = "sys.update.check";
/// The switch step.
pub const SWITCH: &str = "sys.update.switch";

/// How long the new binary may take to print its version: it starts and exits.
const VERSION_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the new binary may take for its dry run on the copy of the running state.
const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(600);
/// The limit of the whole check step: the version, the copy of the running state (two
/// minutes), the dry run. The Windows service smoke waits this long for the step.
const CHECK_TIMEOUT: Duration =
    Duration::from_secs(VERSION_TIMEOUT.as_secs() + 120 + DRY_RUN_TIMEOUT.as_secs());

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssetParams {
    version: ReleaseVersion,
    asset: ReleaseAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwitchParams {
    version: ReleaseVersion,
    deadline_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupParams {
    version: ReleaseVersion,
}

/// How long the backup before an update may take.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn failed(code: &'static str, status: u16, detail: impl Into<String>) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, detail)))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "taken by value to serve as the argument of `map_err`"
)]
fn io_failed(error: std::io::Error) -> StepError {
    failed("update.io", 500, error.to_string())
}

fn coded(error: CodedError) -> StepError {
    StepError::Coded(Box::new(error))
}

fn params<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StepError> {
    from_cbor(bytes).map_err(|error| StepError::InvalidParams(error.to_string()))
}

fn encode(value: &impl Serialize) -> Result<HexBytes, CodedError> {
    to_cbor(value)
        .map(|bytes| HexBytes(bytes.to_vec()))
        .map_err(|error| CodedError::new("update.job", 500, error.to_string()))
}

/// Checks a staged file against the manifest entry.
///
/// # Errors
///
/// `update.size_mismatch` or `update.checksum_mismatch` (400).
pub fn matches(staged: &Staged, asset: &ReleaseAsset) -> Result<(), CodedError> {
    if staged.size != asset.size {
        return Err(CodedError::new(
            "update.size_mismatch",
            400,
            format!(
                "the file has {} bytes, the manifest says {}",
                staged.size, asset.size
            ),
        ));
    }
    if !staged.sha256.eq_ignore_ascii_case(&asset.sha256) {
        return Err(CodedError::new(
            "update.checksum_mismatch",
            400,
            format!(
                "the SHA-256 of the file is {}, the manifest says {}",
                staged.sha256, asset.sha256
            ),
        ));
    }
    Ok(())
}

/// The signature check of API-19: off by default; with the feature `release-signatures` an
/// install refuses every release until signing exists.
#[cfg(feature = "release-signatures")]
fn verify_signature(asset: &ReleaseAsset) -> Result<(), StepError> {
    Err(failed(
        "update.signature_unverified",
        400,
        match &asset.signature {
            Some(_) => "release signatures cannot be verified yet (API-19)",
            None => "the release has no signature",
        },
    ))
}

#[cfg(not(feature = "release-signatures"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the same signature as the check of the feature `release-signatures`"
)]
fn verify_signature(_asset: &ReleaseAsset) -> Result<(), StepError> {
    Ok(())
}

/// The install job of `version`: the backup (when asked for), fetch (unless the file was
/// uploaded), verify, check, switch.
///
/// # Errors
///
/// `update.job` when the parameters cannot be encoded.
pub fn job_spec(
    version: &ReleaseVersion,
    asset: &ReleaseAsset,
    fetch: bool,
    backup: bool,
    deadline_secs: u64,
) -> Result<JobSpec, CodedError> {
    let asset_params = encode(&AssetParams {
        version: version.clone(),
        asset: asset.clone(),
    })?;
    let mut steps = Vec::new();
    if backup {
        steps.push(StepSpec {
            kind: StepKind::from_static(BACKUP),
            params: encode(&BackupParams {
                version: version.clone(),
            })?,
            timeout: Some(BACKUP_TIMEOUT),
        });
    }
    if fetch {
        steps.push(StepSpec {
            kind: StepKind::from_static(FETCH),
            params: asset_params.clone(),
            timeout: Some(Duration::from_secs(30 * 60)),
        });
    }
    steps.push(StepSpec {
        kind: StepKind::from_static(VERIFY),
        params: asset_params,
        timeout: Some(Duration::from_secs(300)),
    });
    steps.push(StepSpec {
        kind: StepKind::from_static(CHECK),
        params: encode(&SwitchParams {
            version: version.clone(),
            deadline_secs,
        })?,
        timeout: Some(CHECK_TIMEOUT),
    });
    steps.push(StepSpec {
        kind: StepKind::from_static(SWITCH),
        params: encode(&SwitchParams {
            version: version.clone(),
            deadline_secs,
        })?,
        timeout: Some(Duration::from_secs(60)),
    });
    Ok(JobSpec {
        kind: JobKind::from_static(JOB_KIND),
        title: MessageKey::from_static(JOB_TITLE),
        targets: vec![ObjectRef::singleton(ObjectKind::System)],
        steps,
        timeout: Duration::from_secs(60 * 60)
            + if backup {
                BACKUP_TIMEOUT
            } else {
                Duration::ZERO
            },
        group: GroupKey::new(JOB_KIND).ok(),
        group_limit: Some(1),
        idempotency: None,
        node: None,
    })
}

/// Registers the five handlers.
pub(crate) fn register(engine: &mut JobEngine, inner: &Arc<Inner>) {
    for kind in [BACKUP, FETCH, VERIFY, CHECK, SWITCH] {
        engine.register(Arc::new(UpdateStep {
            kind,
            inner: Arc::downgrade(inner),
        }));
    }
}

/// The handler of one step kind, for the tests of the service.
#[cfg(test)]
pub(crate) fn handler(kind: &'static str, inner: &Arc<Inner>) -> Arc<dyn StepHandler> {
    Arc::new(UpdateStep {
        kind,
        inner: Arc::downgrade(inner),
    })
}

struct UpdateStep {
    kind: &'static str,
    inner: Weak<Inner>,
}

impl UpdateStep {
    fn inner(&self) -> Result<Arc<Inner>, StepError> {
        self.inner
            .upgrade()
            .ok_or_else(|| failed("update.unavailable", 503, "the update service has stopped"))
    }
}

fn args(version: &ReleaseVersion) -> BTreeMap<String, String> {
    BTreeMap::from([("version".to_owned(), version.to_string())])
}

#[async_trait::async_trait]
impl StepHandler for UpdateStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(self.kind)
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let version = if self.kind == BACKUP {
            self::params::<BackupParams>(params)?.version
        } else if self.kind == FETCH || self.kind == VERIFY {
            self::params::<AssetParams>(params)?.version
        } else {
            self::params::<SwitchParams>(params)?.version
        };
        let summary = match self.kind {
            BACKUP => "jobs.step.sys_update_backup",
            FETCH => "jobs.step.sys_update_fetch",
            VERIFY => "jobs.step.sys_update_verify",
            CHECK => "jobs.step.sys_update_check",
            _ => "jobs.step.sys_update_switch",
        };
        Ok(StepPreview {
            summary: MessageKey::from_static(summary),
            args: args(&version),
            changes: vec![ObjectRef::singleton(ObjectKind::System)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let inner = self.inner()?;
        match self.kind {
            BACKUP => backup(&inner, &self::params(params)?, cx).await,
            FETCH => fetch(&inner, self::params(params)?, cx).await,
            VERIFY => verify(&inner, &self::params(params)?),
            CHECK => check(&inner, &self::params(params)?).await,
            _ => switch(&inner, &self::params(params)?, cx.job),
        }?;
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        let inner = self.inner()?;
        let layout = &inner.layout;
        match self.kind {
            FETCH => {
                let params: AssetParams = self::params(params)?;
                if let Ok(part) = layout.staged(&params.version) {
                    let _ = std::fs::remove_file(part);
                }
            }
            VERIFY => {
                let params: AssetParams = self::params(params)?;
                if params.version != inner.env.running
                    && layout.current() != Some(params.version.clone())
                    && let Ok(dir) = layout.version_dir(&params.version)
                {
                    let _ = std::fs::remove_dir_all(dir);
                }
            }
            SWITCH => {
                let params: SwitchParams = self::params(params)?;
                if layout.current() == Some(params.version) {
                    layout
                        .point(CURRENT, &inner.env.running)
                        .map_err(|error| failed("update.io", 500, error.to_string()))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The backup before the update: written and recorded good by the backup service, or the
/// step fails with the backup's error and the job ends before anything changed.
async fn backup(inner: &Inner, params: &BackupParams, cx: &StepContext) -> Result<(), StepError> {
    let backups = inner.backups.get().cloned().ok_or_else(|| {
        failed(
            "update.backup_unavailable",
            503,
            "this server has no backup service",
        )
    })?;
    // The backup records itself with an inline job of its own, which must not be taken for
    // a replay of the install request's idempotency key.
    let mut ctx = cx.request.clone();
    ctx.idempotency = None;
    let run = backups
        .run_before_update(&ctx, &params.version)
        .await
        .map_err(coded)?;
    tracing::info!(version = %params.version, file = ?run.file, "the backup before the update is written");
    Ok(())
}

/// Downloads the release file and records where it came from: `sys.update.download` with
/// the URL the manifest named, the URL after the redirects, and the size and SHA-256 of what
/// arrived, which the verify step then compares with the manifest. A download whose record
/// cannot be written fails, and its file is removed.
async fn fetch(inner: &Inner, params: AssetParams, cx: &StepContext) -> Result<(), StepError> {
    let path = inner
        .layout
        .prepare_staged(&params.version)
        .map_err(io_failed)?;
    let downloaded = inner
        .source
        .download(&params.asset, &path)
        .await
        .map_err(coded)?;
    let mut details = AuditDetails::default();
    let context = &mut details.context;
    context.insert("version".to_owned(), params.version.to_string());
    context.insert("url".to_owned(), downloaded.requested.clone());
    context.insert("final_url".to_owned(), downloaded.final_url.clone());
    context.insert("size".to_owned(), downloaded.staged.size.to_string());
    context.insert("sha256".to_owned(), downloaded.staged.sha256.clone());
    context.insert("job".to_owned(), cx.job.to_string());
    // Not a replay of the install request's idempotency key: a record of its own.
    let mut request = cx.request.clone();
    request.idempotency = None;
    let mut batch = WriteBatch::for_request(&request);
    batch.audit(AuditDraft {
        details,
        source_ip: cx.request.source_ip,
        ..AuditDraft::success(
            AuditAction::from_static(super::updates::DOWNLOAD_AUDIT),
            Vec::new(),
        )
    });
    if let Err(error) = inner.store.propose(batch).await {
        let _ = std::fs::remove_file(&path);
        return Err(failed(
            "update.store",
            503,
            format!("the download could not be audited: {error}"),
        ));
    }
    tracing::info!(
        version = %params.version,
        bytes = downloaded.staged.size,
        url = %downloaded.requested,
        final_url = %downloaded.final_url,
        "downloaded the release file"
    );
    Ok(())
}

fn verify(inner: &Inner, params: &AssetParams) -> Result<(), StepError> {
    let layout = &inner.layout;
    let part = layout.staged(&params.version).map_err(io_failed)?;
    let target = layout.binary_path(&params.version).map_err(io_failed)?;
    if !part.is_file() && target.is_file() {
        // A repeated run after the rename: check the file in place.
        let (size, sha256) = sha256_file(&target).map_err(coded)?;
        return matches(
            &Staged {
                path: target,
                size,
                sha256,
            },
            &params.asset,
        )
        .map_err(coded);
    }
    let (size, sha256) = sha256_file(&part).map_err(coded)?;
    let staged = Staged {
        path: part.clone(),
        size,
        sha256,
    };
    if let Err(error) = matches(&staged, &params.asset) {
        let _ = std::fs::remove_file(&part);
        return Err(coded(error));
    }
    verify_signature(&params.asset)?;
    make_executable(&part)?;
    std::fs::rename(&part, &target).map_err(|error| failed("update.io", 500, error.to_string()))?;
    let entry = serde_json::to_vec_pretty(&params.asset)
        .map_err(|error| failed("update.io", 500, error.to_string()))?;
    let dir = layout.version_dir(&params.version).map_err(io_failed)?;
    std::fs::write(dir.join("release.json"), entry).map_err(io_failed)?;
    tracing::info!(version = %params.version, "verified the release file");
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), StepError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| failed("update.io", 500, error.to_string()))
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version, which sets the mode"
)]
fn make_executable(_path: &Path) -> Result<(), StepError> {
    Ok(())
}

/// The command that runs the new binary with `args`. The new binary is not the unit's main
/// process, so it does not get the service manager's notify socket either.
fn new_binary_command(binary: &Path, args: &[&std::ffi::OsStr]) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .env_remove("TENKO_CONFIG")
        .env_remove("NOTIFY_SOCKET")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    command
}

/// The most of the new binary's standard error that goes into a log line or an error.
const STDERR_TAIL: usize = 2048;

/// What the new binary printed and how it ended.
struct NewOutput {
    status: Option<i32>,
    stdout: String,
    /// The end of its standard error, trimmed.
    stderr: String,
}

impl NewOutput {
    /// `; standard error: …`, or nothing when it printed none.
    fn stderr_note(&self) -> String {
        if self.stderr.is_empty() {
            String::new()
        } else {
            format!("; standard error: {}", self.stderr)
        }
    }
}

/// The last `max` bytes of `bytes` as text, trimmed, cut at a character boundary.
fn tail(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    let mut start = text.len().saturating_sub(max);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

/// Runs the new binary with `args` for at most `limit` and returns what it printed. `what`
/// names the run in the two log lines, one when the child starts and one when it ends.
async fn run_new(
    what: &'static str,
    binary: &Path,
    args: &[&std::ffi::OsStr],
    limit: Duration,
) -> Result<NewOutput, StepError> {
    let mut command = new_binary_command(binary, args);
    let started = std::time::Instant::now();
    tracing::info!(what, binary = %binary.display(), limit_secs = limit.as_secs(), "started the new binary");
    // `output` reads standard output and standard error while it waits for the exit, so a
    // child that prints more than a pipe holds cannot block on a full pipe.
    let output = match tokio::time::timeout(limit, command.output()).await {
        Err(_) => {
            tracing::warn!(
                what,
                duration_ms = started.elapsed().as_millis(),
                limit_secs = limit.as_secs(),
                "the new binary did not end within its limit and was stopped"
            );
            return Err(failed(
                "update.check_timeout",
                504,
                format!(
                    "the new binary did not finish `{what}` within {} s",
                    limit.as_secs()
                ),
            ));
        }
        Ok(Err(error)) => {
            tracing::warn!(what, %error, "the new binary could not be started");
            return Err(failed(
                "update.not_executable",
                400,
                format!("the new binary does not run on this host: {error}"),
            ));
        }
        Ok(Ok(output)) => output,
    };
    let result = NewOutput {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: tail(&output.stderr, STDERR_TAIL),
    };
    let duration_ms = started.elapsed().as_millis();
    if output.status.success() || result.status == Some(i32::from(crate::exit::MIGRATION_NEEDED)) {
        tracing::info!(what, duration_ms, status = %output.status, stdout_bytes = output.stdout.len(), "the new binary ended");
    } else {
        tracing::warn!(what, duration_ms, status = %output.status, stdout_bytes = output.stdout.len(), stderr = %result.stderr, "the new binary ended");
    }
    Ok(result)
}

async fn check(inner: &Inner, params: &SwitchParams) -> Result<(), StepError> {
    let binary = inner.layout.binary(&params.version);
    tracing::info!(binary = %binary.display(), "asking the new binary for its version");
    let version = run_new(
        "upgrade version",
        &binary,
        &["upgrade".as_ref(), "version".as_ref()],
        VERSION_TIMEOUT,
    )
    .await?;
    let reported = super::parse_version_output(&version.stdout);
    if version.status != Some(0) || reported.as_ref() != Ok(&params.version) {
        return Err(failed(
            "update.version_mismatch",
            400,
            format!(
                "the new binary reports version `{}` (exit status {:?}), the manifest says {}{}",
                version.stdout.trim(),
                version.status,
                params.version,
                version.stderr_note()
            ),
        ));
    }
    let raft = inner
        .raft
        .as_ref()
        .ok_or_else(|| failed("update.check_unavailable", 503, "no store to copy"))?;
    let work = inner
        .layout
        .root()
        .join(format!("check-{}", params.version));
    let _ = std::fs::remove_dir_all(&work);
    let store_copy = work.join("store");
    let revision = raft
        .copy_state_to(&store_copy)
        .await
        .map_err(|error| failed("update.io", 500, format!("cannot copy the state: {error}")))?;
    tracing::info!(
        copy = %store_copy.display(),
        revision = %revision,
        "copied the running state for the dry run of the new binary"
    );
    if let Ok(Some(marker)) = format::read_marker(&inner.env.data_dir.join("store")) {
        format::write_marker(&store_copy, &marker)
            .map_err(|error| failed("update.io", 500, error.to_string()))?;
    }
    let node = inner.env.node.0.to_string();
    let config = inner.env.config_file.as_deref();
    let arguments = check_arguments(&work, &node, config);
    let arguments: Vec<&std::ffi::OsStr> = arguments.iter().map(AsRef::as_ref).collect();
    let result = run_new("upgrade check", &binary, &arguments, DRY_RUN_TIMEOUT).await;
    let _ = std::fs::remove_dir_all(&work);
    let output = result?;
    if let (Some(config), Some(status)) = (config, output.status)
        && status == i32::from(crate::exit::CONFIG)
    {
        return Err(config_refused(&params.version, config, &output.stderr));
    }
    let report = super::parse_check_output(output.stdout.as_bytes()).map_err(|error| {
        failed(
            "update.check_failed",
            400,
            format!(
                "the new binary's check printed no report (exit status {:?}): {error}{}",
                output.status,
                output.stderr_note()
            ),
        )
    })?;
    if report.verdict.lets_install_switch() {
        tracing::info!(version = %params.version, verdict = ?report.verdict, "the new binary accepts the data directory");
        return Ok(());
    }
    Err(failed(
        "update.check_refused",
        409,
        super::problem_text(&report),
    ))
}

/// The command line of the new binary's dry run: the arguments every released install job
/// passes, and the configuration file of the running server, which every released
/// `upgrade check` accepts, so that a version that does not read it is refused here.
fn check_arguments(work: &Path, node: &str, config: Option<&Path>) -> Vec<std::ffi::OsString> {
    let mut arguments: Vec<std::ffi::OsString> = Vec::new();
    arguments.extend(["upgrade", "check"].map(Into::into));
    if let Some(config) = config {
        arguments.extend(["--config".into(), config.into()]);
    }
    arguments.extend([
        "--data-dir".into(),
        work.into(),
        "--disposable".into(),
        "--node-id".into(),
        node.into(),
        "--json".into(),
    ]);
    arguments
}

/// The refusal when the new binary does not accept the configuration file (its exit status
/// 3): it says what to do, before anything was switched.
fn config_refused(version: &ReleaseVersion, config: &Path, stderr: &str) -> StepError {
    failed(
        "update.config_refused",
        409,
        format!(
            "version {version} does not accept the configuration file {}: {}; change the \
             file so that both versions read it (the release notes name renamed or removed \
             settings), then install again",
            config.display(),
            if stderr.is_empty() {
                "no message"
            } else {
                stderr
            }
        ),
    )
}

fn switch(inner: &Inner, params: &SwitchParams, job: tenko_core::JobId) -> Result<(), StepError> {
    let layout = &inner.layout;
    let running = &inner.env.running;
    if !layout.binary(&params.version).is_file() {
        return Err(failed(
            "update.io",
            500,
            format!("version {} is not installed", params.version),
        ));
    }
    let attempt = Attempt::restarting(
        running.clone(),
        params.version.clone(),
        Some(job),
        params.deadline_secs,
    );
    probation::write(layout, &attempt)
        .map_err(|error| failed("update.io", 500, error.to_string()))?;
    layout
        .point(PREVIOUS, running)
        .and_then(|()| layout.point(CURRENT, &params.version))
        .map_err(|error| {
            failed(
                "update.io",
                500,
                format!("cannot switch the version: {error}"),
            )
        })?;
    tracing::info!(from = %running, to = %params.version, "switched the current version");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_binary_does_not_get_the_notify_socket() {
        let command = new_binary_command(Path::new("tenko"), &["upgrade".as_ref()]);
        let removed = |wanted: &str| {
            command
                .as_std()
                .get_envs()
                .any(|(name, value)| name == wanted && value.is_none())
        };
        assert!(removed("NOTIFY_SOCKET"));
        assert!(removed("TENKO_CONFIG"));
    }

    #[test]
    fn the_dry_run_gets_the_configuration_file_and_the_released_arguments() {
        let work = Path::new("/var/lib/tenko/updates/check-0.0.12");
        let config = Path::new("/etc/tenko/tenko.toml");
        let with = check_arguments(work, "1", Some(config));
        assert_eq!(
            with,
            [
                "upgrade",
                "check",
                "--config",
                "/etc/tenko/tenko.toml",
                "--data-dir",
                "/var/lib/tenko/updates/check-0.0.12",
                "--disposable",
                "--node-id",
                "1",
                "--json"
            ]
            .map(std::ffi::OsString::from)
        );
        let without = check_arguments(work, "1", None);
        assert_eq!(&with[..2], &without[..2]);
        assert_eq!(&with[4..], &without[2..]);
    }

    #[test]
    fn a_refused_configuration_says_what_to_do() {
        let StepError::Coded(error) = config_refused(
            &"0.0.14".parse().expect("version"),
            Path::new("/etc/tenko/tenko.toml"),
            "tenko upgrade check: /etc/tenko/tenko.toml: unknown field `renamed_ttl_secs`",
        ) else {
            panic!("a coded error");
        };
        assert_eq!(error.code, "update.config_refused");
        assert_eq!(error.status, 409);
        assert!(
            error.detail.contains("renamed_ttl_secs"),
            "{}",
            error.detail
        );
        assert!(
            error.detail.contains("then install again"),
            "{}",
            error.detail
        );
    }

    #[test]
    fn the_tail_of_standard_error_is_bounded_and_whole_characters() {
        assert_eq!(tail(b"  short\n", 2048), "short");
        let long = format!("{}{}", "x".repeat(3000), "end");
        let cut = tail(long.as_bytes(), 2048);
        assert_eq!(cut.len(), 2048);
        assert!(cut.ends_with("end"));
        // "å" is two bytes; a cut inside it moves to the next character.
        let text = "åååå";
        assert_eq!(tail(text.as_bytes(), 3), "å");
    }

    /// A child that fills both pipes far beyond their buffer (4 KiB on Windows, 64 KiB on
    /// Linux) before it exits: `run_new` drains both while it waits, so it ends at once.
    #[tokio::test]
    async fn a_child_that_prints_more_than_a_pipe_holds_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big.txt");
        std::fs::write(&file, "0123456789abcdef\n".repeat(64 * 1024)).unwrap();
        // cmd.exe takes the words one by one: Rust's quoting of one argument is not cmd's.
        #[cfg(windows)]
        let (shell, arguments): (std::path::PathBuf, Vec<&std::ffi::OsStr>) = (
            Path::new(&std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe"),
            vec![
                "/c".as_ref(),
                "type".as_ref(),
                file.as_os_str(),
                "1>&2".as_ref(),
                "&".as_ref(),
                "type".as_ref(),
                file.as_os_str(),
            ],
        );
        #[cfg(not(windows))]
        let script = format!("cat '{0}' >&2; cat '{0}'", file.display());
        #[cfg(not(windows))]
        let (shell, arguments): (std::path::PathBuf, Vec<&std::ffi::OsStr>) = (
            std::path::PathBuf::from("/bin/sh"),
            vec!["-c".as_ref(), script.as_ref()],
        );
        let output = run_new("pipe test", &shell, &arguments, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(output.status, Some(0));
        assert_eq!(output.stdout.len(), 17 * 64 * 1024);
        assert_eq!(output.stderr.len(), STDERR_TAIL);
    }

    #[tokio::test]
    async fn a_child_over_its_limit_is_stopped_and_named() {
        #[cfg(windows)]
        let (shell, arguments): (std::path::PathBuf, Vec<&std::ffi::OsStr>) = (
            Path::new(&std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("ping.exe"),
            vec!["-n".as_ref(), "30".as_ref(), "127.0.0.1".as_ref()],
        );
        #[cfg(not(windows))]
        let (shell, arguments): (std::path::PathBuf, Vec<&std::ffi::OsStr>) =
            (std::path::PathBuf::from("/bin/sleep"), vec!["30".as_ref()]);
        let started = std::time::Instant::now();
        let Err(StepError::Coded(error)) =
            run_new("slow test", &shell, &arguments, Duration::from_secs(1)).await
        else {
            panic!("the slow child was not stopped");
        };
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(error.code, "update.check_timeout");
        assert!(
            error.detail.contains("`slow test` within 1 s"),
            "{}",
            error.detail
        );
    }
}
