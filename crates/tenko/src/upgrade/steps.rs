//! The steps of the install job (kind `sys.update`, OPS-24): fetch, verify, check, switch.
//!
//! | Step | What it does | Undo |
//! |---|---|---|
//! | `sys.update.fetch` | downloads the release file for this platform from the pinned source into `<data_dir>/updates/<version>/tenko.part` (not for uploads) | removes the file |
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
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_api::dto::release::{ReleaseAsset, ReleaseVersion};
use tenko_core::{
    CodedError, MessageKey, ObjectKind, ObjectRef,
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_jobs::{
    GroupKey, JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepSpec,
};
use tenko_store::{ReadView, format};

use super::{
    layout::{CURRENT, Layout, PREVIOUS, binary_name},
    probation::{self, Attempt},
    source::{Staged, sha256_file},
    updates::Inner,
};

/// The job kind.
pub const JOB_KIND: &str = "sys.update";
/// The job title (a message key of the UI).
pub const JOB_TITLE: &str = "jobs.title.update_install";
/// The fetch step.
pub const FETCH: &str = "sys.update.fetch";
/// The verify step.
pub const VERIFY: &str = "sys.update.verify";
/// The check step.
pub const CHECK: &str = "sys.update.check";
/// The switch step.
pub const SWITCH: &str = "sys.update.switch";

/// How long the new binary may take for its dry run.
const CHECK_TIMEOUT: Duration = Duration::from_secs(600);

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

fn failed(code: &'static str, status: u16, detail: impl Into<String>) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, detail)))
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

/// The file a download or an upload is staged in.
pub fn staged_path(layout: &Layout, version: &ReleaseVersion) -> PathBuf {
    layout
        .version_dir(version)
        .join(format!("{}.part", binary_name()))
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

/// The install job of `version`: fetch (unless the file was uploaded), verify, check,
/// switch.
///
/// # Errors
///
/// `update.job` when the parameters cannot be encoded.
pub fn job_spec(
    version: &ReleaseVersion,
    asset: &ReleaseAsset,
    fetch: bool,
    deadline_secs: u64,
) -> Result<JobSpec, CodedError> {
    let asset_params = encode(&AssetParams {
        version: version.clone(),
        asset: asset.clone(),
    })?;
    let mut steps = Vec::new();
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
        timeout: Some(CHECK_TIMEOUT + Duration::from_secs(120)),
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
        timeout: Duration::from_secs(60 * 60),
        group: GroupKey::new(JOB_KIND).ok(),
        group_limit: Some(1),
        idempotency: None,
    })
}

/// Registers the four handlers.
pub(crate) fn register(engine: &mut JobEngine, inner: &Arc<Inner>) {
    for kind in [FETCH, VERIFY, CHECK, SWITCH] {
        engine.register(Arc::new(UpdateStep {
            kind,
            inner: Arc::downgrade(inner),
        }));
    }
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
        let version = if self.kind == FETCH || self.kind == VERIFY {
            self::params::<AssetParams>(params)?.version
        } else {
            self::params::<SwitchParams>(params)?.version
        };
        let summary = match self.kind {
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
            FETCH => fetch(&inner, self::params(params)?).await,
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
                let _ = std::fs::remove_file(staged_path(layout, &params.version));
            }
            VERIFY => {
                let params: AssetParams = self::params(params)?;
                if params.version != inner.env.running
                    && layout.current() != Some(params.version.clone())
                {
                    let _ = std::fs::remove_dir_all(layout.version_dir(&params.version));
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

async fn fetch(inner: &Inner, params: AssetParams) -> Result<(), StepError> {
    let path = staged_path(&inner.layout, &params.version);
    let staged = inner
        .source
        .download(&params.asset, &path)
        .await
        .map_err(coded)?;
    tracing::info!(version = %params.version, bytes = staged.size, "downloaded the release file");
    Ok(())
}

fn verify(inner: &Inner, params: &AssetParams) -> Result<(), StepError> {
    let layout = &inner.layout;
    let part = staged_path(layout, &params.version);
    let target = layout.binary(&params.version);
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
    std::fs::write(
        layout.version_dir(&params.version).join("release.json"),
        entry,
    )
    .map_err(|error| failed("update.io", 500, error.to_string()))?;
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

/// Runs the new binary with `args` and returns its standard output.
async fn run_new(
    binary: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<(Option<i32>, String), StepError> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .env_remove("TENKO_CONFIG")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(CHECK_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            failed(
                "update.check_timeout",
                504,
                "the new binary did not finish its check",
            )
        })?
        .map_err(|error| {
            failed(
                "update.not_executable",
                400,
                format!("the new binary does not run on this host: {error}"),
            )
        })?;
    Ok((
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

async fn check(inner: &Inner, params: &SwitchParams) -> Result<(), StepError> {
    let binary = inner.layout.binary(&params.version);
    tracing::info!(binary = %binary.display(), "asking the new binary for its version");
    let (status, stdout) = run_new(&binary, &["upgrade".as_ref(), "version".as_ref()]).await?;
    let reported = stdout.trim();
    if status != Some(0) || reported != params.version.to_string() {
        return Err(failed(
            "update.version_mismatch",
            400,
            format!(
                "the new binary reports version `{reported}`, the manifest says {}",
                params.version
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
    let result = run_new(
        &binary,
        &[
            "upgrade".as_ref(),
            "check".as_ref(),
            "--data-dir".as_ref(),
            work.as_os_str(),
            "--disposable".as_ref(),
            "--node-id".as_ref(),
            node.as_ref(),
            "--json".as_ref(),
        ],
    )
    .await;
    let _ = std::fs::remove_dir_all(&work);
    let (status, stdout) = result?;
    let report: serde_json::Value = serde_json::from_str(&stdout).map_err(|error| {
        failed(
            "update.check_failed",
            400,
            format!("the new binary's check printed no report (status {status:?}): {error}"),
        )
    })?;
    let verdict = report["verdict"].as_str().unwrap_or_default();
    if verdict == "current" || verdict == "migration_needed" {
        tracing::info!(version = %params.version, verdict, "the new binary accepts the data directory");
        return Ok(());
    }
    let code = report["problem"]["code"]
        .as_str()
        .unwrap_or("upgrade.refused");
    let message = report["problem"]["message"]
        .as_str()
        .unwrap_or("the new binary refuses the data directory");
    Err(failed(
        "update.check_refused",
        409,
        format!("{code}: {message}"),
    ))
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
