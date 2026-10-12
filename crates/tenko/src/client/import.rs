//! `tenko import <file>`: upload, mapping, preview, apply, and the wait for the job.
//!
//! # Flow
//!
//! 1. The file is read (20 MB at most) and, with `--mapping`, the mapping file is parsed;
//!    both are checked before anything is sent.
//! 2. `POST /imports` stages the upload. What the server detected (file kind, sheets, columns
//!    with their suggested targets) is printed as a note on standard error.
//! 3. The mapping is the one from `--mapping` (sent as it is) or the suggested one. The
//!    choices of `--sheet`, `--header-row`, `--vrf` and `--acknowledge` are applied to it, and
//!    `PUT /imports/{id}/mapping` stores it.
//! 4. `GET /imports/{id}/preview` is rendered on standard output: changes per kind and
//!    action, row counts, warnings and the totals of the loss report. With `--json` the
//!    preview body is printed instead.
//! 5. `--dry-run` stops here, and so does a preview without changes. The staged upload is
//!    deleted (`DELETE /imports/{id}`) unless `--keep` is given.
//! 6. Otherwise `--yes`, or an answer on the terminal, confirms. Without a terminal and
//!    without `--yes` the command refuses (status 2).
//! 7. `POST /imports/{id}/apply` (with an `Idempotency-Key`) answers `202` with a job. The
//!    job is polled every 500 ms for `--wait-secs` seconds. A job that does not end in
//!    `succeeded`, or does not end in time, gives status 8.
//!
//! With `--json` standard output holds one JSON document: the preview body when nothing was
//! applied, else `{"preview": ..., "job": ...}` with the last job body.
//!
//! # Shapes of the API
//!
//! The import routes (WP1.5) were still stubs when this was written, so the answers are read
//! as [`serde_json::Value`] and looked up defensively; each lookup lists the keys it accepts.
//! These are the assumptions; the final data types of the routes may need small changes here.
//!
//! - **Upload answer.** The identifier is `id` (also `import_id`, `upload_id`, `import.id`,
//!   `upload.id`). `sheets` is a list of `SheetAnalysis`
//!   (`tenko-ipam/src/import/mapping.rs`, `SheetAnalysis`, `ColumnAnalysis`): `sheet`,
//!   `data_rows`, `columns[].{column, header, suggested}` and the `suggested` `SheetMapping`
//!   with `kind`, `cidr` and `header_row`. The file kind is `format` (`SourceFormat` in
//!   `tenko-ipam/src/import/read/mod.rs`; also `kind`), else the file extension. The mapping
//!   is `suggested_mapping` (also `mapping`, `suggested`) holding a `Mapping`, else the
//!   `suggested` mappings of the sheets are put together.
//! - **Mapping body.** A `Mapping` (`mapping.rs`, `Mapping`, `SheetMapping`,
//!   `ImportOptions`): `sheets[].{sheet, kind, header_row, ...}` and `options.{vrf, acknowledge,
//!   ...}`. `--sheet` sets `kind` to `skip` on the other sheets, `--header-row N` sets
//!   `header_row` (0 removes it: the data starts in row 1), `--vrf` sets `options.vrf`,
//!   `--acknowledge` adds to `options.acknowledge`.
//! - **Preview answer.** `summary` (also `plan.summary`) is a `PlanSummary`
//!   (`tenko-ipam/src/plan/mod.rs`, `PlanSummary`, `SummaryCount`): `counts[].{kind, action,
//!   count}`, `warnings` (code to count), `unacknowledged`, `lines`, `mutations`. Without
//!   `counts` the zero-change test falls back to `changes` (a list), `mutations`, then
//!   `lines`; when none is there the preview counts as "has changes" and the server decides.
//!   `warnings` may also be a list of `PlanWarning`. `rows` is a list of `RowOutcome`
//!   (`tenko-ipam/src/import/translate.rs`, `RowOutcome`, `RowStatus`) and `proposals` of
//!   `Proposal`. The loss report is `loss_report` (also `loss`) with `entries[].{code, ...}`
//!   (`tenko-core/src/ir.rs`, `LossReport`), or a bare list of entries.
//! - **Apply answer.** `job_id` (also `job.id`, `id`).
//! - **Job.** `GET /jobs/{id}` is a `JobDetail` (`tenko-jobs/src/query.rs`, `JobDetail`):
//!   `job.state` (`JobState` in `tenko-jobs/src/model.rs`: `queued`, `running`, `waiting`,
//!   `rolling_back` are active, `succeeded` is success, `failed`, `rolled_back` and
//!   `cancelled` end without success), `job.error` (`CodedError` in
//!   `tenko-core/src/error.rs`: `code`, `detail`), else the error of the first failed step,
//!   and `job.steps[].state.state` for progress. A `JobSummary` (`state`, `error`,
//!   `steps_done`, `step_count`) is read as well.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Write as _},
    io::{IsTerminal as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Args;
use serde_json::{Value, json};
use tenko_api::client::{Client, ClientError};
use tokio::time::Instant;

use super::{ClientOpts, Failure, Output, Target, read_line, table};
use crate::exit;

/// Largest file `tenko import` uploads (the limit of the API).
const MAX_UPLOAD_BYTES: u64 = 20 * 1024 * 1024;

/// Time between two reads of the job.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Default of `--wait-secs`.
const DEFAULT_WAIT_SECS: u64 = 600;

/// The question before an apply.
const PROMPT: &str = "Apply these changes? [y/N] ";

/// Arguments of `tenko import`.
#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The spreadsheet (xlsx, xls, ods) or CSV file, 20 MB at most.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Import only this sheet of a workbook; the other sheets are skipped.
    #[arg(long, value_name = "NAME")]
    pub sheet: Option<String>,

    /// The row with the column headers, counted from 1, for every sheet that is imported;
    /// 0 means there is no header and the data starts in row 1.
    #[arg(long, value_name = "N")]
    pub header_row: Option<u32>,

    /// A mapping (JSON) to use instead of the suggested one; it is sent as it is, apart from
    /// what the other flags set.
    #[arg(long, value_name = "FILE")]
    pub mapping: Option<PathBuf>,

    /// The VRF (name or identifier) of items that name none; the default VRF when absent.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,

    /// Acknowledge a warning code of the preview (for example
    /// `ipam.prefix.nibble_boundary`); repeat for more.
    #[arg(long, value_name = "CODE")]
    pub acknowledge: Vec<String>,

    /// Show the preview and stop; nothing is imported.
    #[arg(long)]
    pub dry_run: bool,

    /// Apply without asking.
    #[arg(long)]
    pub yes: bool,

    /// Keep the staged upload when nothing is applied (it expires after 24 hours).
    #[arg(long)]
    pub keep: bool,

    /// Seconds to wait for the import job; 0 starts the job and returns at once.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_WAIT_SECS)]
    pub wait_secs: u64,
}

/// Runs `tenko import`.
///
/// # Errors
///
/// The [`Failure`] of the first step that failed.
pub async fn run(args: &ImportArgs) -> Result<Output, Failure> {
    let input = Input::load(args).await?;
    let target = Target::resolve(&args.client, true)?;
    let client = target.connect().await?;
    let upload: Value = target
        .raw()?
        .upload("/imports", "file", &input.name, input.bytes)
        .await?
        .json()?;
    let id = find_id(&upload, UPLOAD_ID)
        .ok_or_else(|| Failure::other("unexpected answer: the upload has no usable identifier"))?;
    let mut import = Import {
        args,
        client,
        id,
        console: Console::default(),
        submitted: false,
    };
    import.console.note(describe_upload(
        &upload,
        &input.name,
        args.mapping.as_deref(),
    ));
    // Said now, so that it comes before the preview on the screen.
    import.console.flush();
    let result = import.proceed(&upload, input.mapping).await;
    import.cleanup(result.is_ok()).await;
    match result {
        Ok(status) => Ok(import.console.finish(status)),
        Err(failure) => {
            import.console.flush();
            Err(failure)
        }
    }
}

/// What is read from disk before anything is sent.
#[derive(Debug)]
struct Input {
    /// The file name for the upload.
    name: String,
    /// The file.
    bytes: Vec<u8>,
    /// The mapping file, parsed.
    mapping: Option<Value>,
}

impl Input {
    async fn load(args: &ImportArgs) -> Result<Self, Failure> {
        let name = upload_name(&args.file);
        let metadata = tokio::fs::metadata(&args.file)
            .await
            .map_err(|error| usage(format!("cannot read {}: {error}", args.file.display())))?;
        if !metadata.is_file() {
            return Err(usage(format!("{} is not a file", args.file.display())));
        }
        check_size(metadata.len(), &name)?;
        let bytes = tokio::fs::read(&args.file)
            .await
            .map_err(|error| usage(format!("cannot read {}: {error}", args.file.display())))?;
        check_size(bytes.len() as u64, &name)?;
        let mapping = match &args.mapping {
            Some(path) => Some(read_mapping(path).await?),
            None => None,
        };
        Ok(Self {
            name,
            bytes,
            mapping,
        })
    }
}

/// The import in progress: the staged upload, and what has been said so far.
struct Import<'a> {
    args: &'a ImportArgs,
    client: Client,
    id: String,
    console: Console,
    /// Whether the apply request may have started the job; the staged upload then belongs to
    /// the server.
    submitted: bool,
}

impl Import<'_> {
    fn path(&self, tail: &str) -> String {
        format!("/imports/{}{tail}", self.id)
    }

    fn json(&self) -> bool {
        self.args.client.json
    }

    /// Mapping, preview, confirmation, apply and wait; the exit status.
    async fn proceed(
        &mut self,
        upload: &Value,
        mapping_file: Option<Value>,
    ) -> Result<u8, Failure> {
        let mapping = build_mapping(upload, mapping_file, self.args)?;
        let _: Value = self
            .client
            .put(&self.path("/mapping"), &mapping, None)
            .await?;
        let preview: Value = self.client.get(&self.path("/preview")).await?;
        let summary = render_preview(&preview);
        if !self.json() {
            self.console.out(&summary);
        }
        if self.args.dry_run {
            self.preview_document(&preview);
            self.console.note("dry run: nothing was imported");
            return Ok(exit::OK);
        }
        if total_changes(&preview) == Some(0) {
            self.preview_document(&preview);
            let message = "nothing to import: the file matches the current data";
            if self.json() {
                self.console.note(message);
            } else {
                self.console.out(format!("{message}\n"));
            }
            return Ok(exit::OK);
        }
        let pending = unacknowledged(&preview);
        if !pending.is_empty() {
            return Err(usage(format!(
                "the preview has warnings that need an acknowledgement: {}; run again with \
                 --acknowledge CODE for each",
                pending.join(", ")
            )));
        }
        let blockers = blockers(&preview);
        if !blockers.is_empty() {
            return Err(Failure::new(
                exit::API,
                format!(
                    "the server would refuse to apply this import: {}",
                    blockers.join(", ")
                ),
            ));
        }
        match confirmation(self.args.yes, std::io::stdin().is_terminal()) {
            Confirmation::Go => {}
            Confirmation::Ask => {
                if self.json() {
                    self.console.note(summary.trim_end());
                }
                self.console.flush();
                if !is_yes(&read_line(PROMPT)?) {
                    self.console.note("aborted: nothing was imported");
                    return Ok(exit::FAILURE);
                }
            }
            Confirmation::Refuse => {
                return Err(usage(
                    "not applying without a confirmation: pass --yes to apply without asking, \
                     or --dry-run to only look at the preview",
                ));
            }
        }
        let job_id = self.apply().await?;
        if self.args.wait_secs == 0 {
            self.console.note(format!(
                "import job {job_id} started; not waiting for it (--wait-secs 0)"
            ));
            if self.json() {
                self.console
                    .out(pretty(&json!({ "preview": preview, "job_id": job_id })));
            }
            return Ok(exit::OK);
        }
        let end = self.wait(&job_id).await?;
        Ok(self.report(&preview, &job_id, &end))
    }

    /// The preview body, for `--json`, when nothing is applied.
    fn preview_document(&mut self, preview: &Value) {
        if self.json() {
            self.console.out(pretty(preview));
        }
    }

    /// Starts the job; its identifier.
    async fn apply(&mut self) -> Result<String, Failure> {
        let key = uuid::Uuid::now_v7().to_string();
        let answer: Value = match self
            .client
            .post(&self.path("/apply"), &json!({}), Some(&key))
            .await
        {
            Ok(answer) => answer,
            Err(error) => {
                // An answer with problem details means the job did not start; anything else
                // (a lost connection) leaves it open, and then the upload is not touched.
                self.submitted = !matches!(error, ClientError::Problem(_));
                return Err(error.into());
            }
        };
        self.submitted = true;
        find_id(&answer, JOB_ID)
            .ok_or_else(|| Failure::other("unexpected answer: the apply has no usable job_id"))
    }

    /// Reads the job until it ends or the time is up.
    async fn wait(&mut self, job_id: &str) -> Result<JobEnd, Failure> {
        let deadline = Instant::now() + Duration::from_secs(self.args.wait_secs);
        let path = format!("/jobs/{job_id}");
        let mut seen: Option<(String, Option<(u64, u64)>)> = None;
        loop {
            let body: Value = self.client.get(&path).await.map_err(|error| {
                let failure = Failure::from_client(&error);
                Failure {
                    message: format!("lost track of import job {job_id}: {}", failure.message),
                    ..failure
                }
            })?;
            let state = job_state(&body).unwrap_or("unknown").to_owned();
            let progress = step_progress(&body).filter(|(_, total)| *total > 0);
            if seen
                .as_ref()
                .is_none_or(|(s, p)| *s != state || *p != progress)
            {
                let steps = progress
                    .map(|(done, total)| format!(" ({done}/{total} steps)"))
                    .unwrap_or_default();
                self.console
                    .note(format!("job {job_id}: {}{steps}", words(&state)));
                self.console.flush();
                seen = Some((state.clone(), progress));
            }
            if job_phase(&state) != JobPhase::Active {
                return Ok(JobEnd::Ended(body));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(JobEnd::TimedOut(body));
            }
            tokio::time::sleep(POLL_INTERVAL.min(remaining)).await;
        }
    }

    /// Says how the job ended; the exit status.
    fn report(&mut self, preview: &Value, job_id: &str, end: &JobEnd) -> u8 {
        let (JobEnd::Ended(body) | JobEnd::TimedOut(body)) = end;
        if self.json() {
            self.console
                .out(pretty(&json!({ "preview": preview, "job": body })));
        }
        let state = job_state(body).unwrap_or("unknown");
        let line = match end {
            JobEnd::Ended(_) if job_phase(state) == JobPhase::Succeeded => {
                if !self.json() {
                    let changes = match total_changes(preview) {
                        Some(1) => "1 change".to_owned(),
                        Some(count) => format!("{count} changes"),
                        None => "the changes".to_owned(),
                    };
                    self.console
                        .out(format!("import applied: {changes} (job {job_id})\n"));
                }
                return exit::OK;
            }
            JobEnd::Ended(_) => unsuccessful_line(job_id, state, job_error(body).as_deref()),
            JobEnd::TimedOut(_) => format!(
                "timed out after {} s waiting for import job {job_id} (last state: {}); it \
                 keeps running on the controller, read it with GET /api/v1/jobs/{job_id}",
                self.args.wait_secs,
                words(state)
            ),
        };
        self.console.note(format!("tenko import: error: {line}"));
        exit::JOB
    }

    /// Deletes the staged upload unless it was kept on request or belongs to the job.
    async fn cleanup(&mut self, report: bool) {
        if self.submitted {
            return;
        }
        if self.args.keep {
            if report {
                self.console.note(format!(
                    "the staged upload {} was kept; it expires after 24 hours",
                    self.id
                ));
            }
            return;
        }
        if let Err(error) = self.client.delete(&self.path(""), None).await
            && report
        {
            self.console.note(format!(
                "warning: could not delete the staged upload {}: {}",
                self.id,
                Failure::from_client(&error).message
            ));
        }
    }
}

/// How the wait for the job ended; the last body of the job.
#[derive(Debug)]
enum JobEnd {
    /// The job is in a final state.
    Ended(Value),
    /// The time ran out.
    TimedOut(Value),
}

/// Output that can be written before the command ends: the preview and a progress line must
/// be on the screen before the question, and before an error line.
#[derive(Default)]
struct Console {
    chunks: Vec<(Stream, String)>,
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

impl Console {
    /// Text for standard output.
    fn out(&mut self, text: impl Into<String>) {
        self.chunks.push((Stream::Out, text.into()));
    }

    /// A line for standard error.
    fn note(&mut self, text: impl Display) {
        self.chunks.push((Stream::Err, format!("{text}\n")));
    }

    /// Writes what is pending now, in order.
    fn flush(&mut self) {
        for (stream, text) in self.chunks.drain(..) {
            match stream {
                Stream::Out => {
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(text.as_bytes());
                    let _ = out.flush();
                }
                Stream::Err => {
                    let _ = std::io::stderr().lock().write_all(text.as_bytes());
                }
            }
        }
    }

    /// What is left, for the framework to write.
    fn finish(self, status: u8) -> Output {
        let mut output = Output {
            status,
            ..Output::default()
        };
        for (stream, text) in self.chunks {
            match stream {
                Stream::Out => output.stdout.push_str(&text),
                Stream::Err => output.stderr.push_str(&text),
            }
        }
        output
    }
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::new(exit::USAGE, message)
}

/// The file name sent with the upload.
fn upload_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || "upload".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Refuses files over [`MAX_UPLOAD_BYTES`].
fn check_size(len: u64, name: &str) -> Result<(), Failure> {
    if len <= MAX_UPLOAD_BYTES {
        return Ok(());
    }
    Err(usage(format!(
        "{name} is {} MB, over the {} MB limit for imports",
        len.div_ceil(1024 * 1024),
        MAX_UPLOAD_BYTES / (1024 * 1024)
    )))
}

/// Reads and parses the mapping file: a JSON object, with or without a byte order mark.
async fn read_mapping(path: &Path) -> Result<Value, Failure> {
    let bytes = tokio::fs::read(path).await.map_err(|error| {
        usage(format!(
            "cannot read the mapping {}: {error}",
            path.display()
        ))
    })?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        usage(format!(
            "the mapping {} is not valid JSON: {error}",
            path.display()
        ))
    })?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(usage(format!(
            "the mapping {} must be a JSON object",
            path.display()
        )))
    }
}

/// Pointers to the identifier of an upload.
const UPLOAD_ID: &[&str] = &[
    "/id",
    "/import_id",
    "/upload_id",
    "/import/id",
    "/upload/id",
];

/// Pointers to the identifier of the job an apply started.
const JOB_ID: &[&str] = &["/job_id", "/job/id", "/id"];

/// The first identifier found under one of the pointers, if it is safe to put in a path.
fn find_id(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| match value.pointer(pointer)? {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A string of the server's answer made safe for a terminal.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `rolled_back` as `rolled back`.
fn words(state: &str) -> String {
    clean(&state.replace('_', " "))
}

// ---- the mapping --------------------------------------------------------------------

/// The suggested mapping of an upload answer.
fn suggested_mapping(upload: &Value) -> Option<Value> {
    let named = ["/suggested_mapping", "/mapping", "/suggested"]
        .iter()
        .filter_map(|pointer| upload.pointer(pointer))
        .find(|mapping| mapping.get("sheets").is_some_and(Value::is_array));
    if let Some(mapping) = named {
        return Some(mapping.clone());
    }
    let sheets: Vec<Value> = upload
        .get("sheets")?
        .as_array()?
        .iter()
        .filter_map(|sheet| sheet.get("suggested"))
        .filter(|suggested| suggested.is_object())
        .cloned()
        .collect();
    (!sheets.is_empty()).then(|| json!({ "sheets": sheets, "options": {} }))
}

/// The mapping to store: the one from the file or the suggested one, with the choices of
/// the flags applied.
fn build_mapping(
    upload: &Value,
    from_file: Option<Value>,
    args: &ImportArgs,
) -> Result<Value, Failure> {
    let mut mapping = match from_file {
        Some(mapping) => mapping,
        None => suggested_mapping(upload).ok_or_else(|| {
            Failure::other(
                "unexpected answer: the upload has no suggested mapping; pass one with --mapping",
            )
        })?,
    };
    if let Some(sheet) = &args.sheet {
        restrict_to_sheet(&mut mapping, sheet).map_err(usage)?;
    }
    if let Some(row) = args.header_row {
        set_header_row(&mut mapping, row).map_err(usage)?;
    }
    if let Some(vrf) = &args.vrf {
        let options = options_mut(&mut mapping).map_err(usage)?;
        options.insert("vrf".to_owned(), json!(vrf));
    }
    if !args.acknowledge.is_empty() {
        add_acknowledge(&mut mapping, &args.acknowledge).map_err(usage)?;
    }
    Ok(mapping)
}

fn sheets_mut(mapping: &mut Value) -> Result<&mut Vec<Value>, String> {
    mapping
        .get_mut("sheets")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "the mapping has no list of sheets".to_owned())
}

fn is_skipped(sheet: &Value) -> bool {
    str_at(sheet, "kind") == Some("skip")
}

/// Marks every sheet but `wanted` (exact name, else the one that differs only in case) as
/// `skip`.
fn restrict_to_sheet(mapping: &mut Value, wanted: &str) -> Result<(), String> {
    let sheets = sheets_mut(mapping)?;
    let names: Vec<String> = sheets
        .iter()
        .filter_map(|sheet| str_at(sheet, "sheet"))
        .map(str::to_owned)
        .collect();
    let mut insensitive = names
        .iter()
        .filter(|name| name.eq_ignore_ascii_case(wanted));
    let chosen = names
        .iter()
        .find(|name| *name == wanted)
        .or_else(|| insensitive.next().filter(|_| insensitive.next().is_none()))
        .cloned()
        .ok_or_else(|| {
            let list: Vec<String> = names.iter().map(|name| clean(name)).collect();
            format!(
                "the file has no sheet named \"{}\"; its sheets are: {}",
                clean(wanted),
                list.join(", ")
            )
        })?;
    for sheet in sheets {
        if str_at(sheet, "sheet") != Some(chosen.as_str())
            && let Some(object) = sheet.as_object_mut()
        {
            object.insert("kind".to_owned(), json!("skip"));
        }
    }
    Ok(())
}

/// Sets the header row of every sheet that is imported; 0 removes it.
fn set_header_row(mapping: &mut Value, row: u32) -> Result<(), String> {
    for sheet in sheets_mut(mapping)? {
        if is_skipped(sheet) {
            continue;
        }
        if let Some(object) = sheet.as_object_mut() {
            if row == 0 {
                object.remove("header_row");
            } else {
                object.insert("header_row".to_owned(), json!(row));
            }
        }
    }
    Ok(())
}

fn options_mut(mapping: &mut Value) -> Result<&mut serde_json::Map<String, Value>, String> {
    mapping
        .as_object_mut()
        .ok_or_else(|| "the mapping must be a JSON object".to_owned())?
        .entry("options")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| "`options` of the mapping must be an object".to_owned())
}

/// Adds warning codes to `options.acknowledge`.
fn add_acknowledge(mapping: &mut Value, codes: &[String]) -> Result<(), String> {
    let options = options_mut(mapping)?;
    let mut all: BTreeSet<String> = options
        .get("acknowledge")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    all.extend(codes.iter().cloned());
    options.insert("acknowledge".to_owned(), json!(all));
    Ok(())
}

// ---- what the upload found ----------------------------------------------------------

/// The note on standard error after the upload: file kind, sheets, columns and their
/// suggested targets.
fn describe_upload(upload: &Value, file_name: &str, mapping_file: Option<&Path>) -> String {
    let kind = ["/format", "/kind", "/file_kind"]
        .iter()
        .find_map(|pointer| upload.pointer(pointer)?.as_str())
        .map(str::to_owned)
        .or_else(|| {
            Path::new(file_name)
                .extension()
                .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let sheets = upload
        .get("sheets")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut out = format!(
        "uploaded {}: {} file with {} sheet{}\n",
        clean(file_name),
        clean(&kind),
        sheets.len(),
        if sheets.len() == 1 { "" } else { "s" }
    );
    for sheet in sheets {
        out.push_str(&describe_sheet(sheet));
    }
    match mapping_file {
        Some(path) => {
            let _ = writeln!(out, "mapping: from {}", path.display());
        }
        None => out.push_str("mapping: suggested by the server"),
    }
    out.trim_end().to_owned()
}

/// One sheet: what it is, and its columns with their suggested targets.
fn describe_sheet(sheet: &Value) -> String {
    if let Some(name) = sheet.as_str() {
        return format!("  sheet \"{}\"\n", clean(name));
    }
    let name = str_at(sheet, "sheet")
        .or_else(|| str_at(sheet, "name"))
        .unwrap_or("?");
    let mut facts: Vec<String> = Vec::new();
    if let Some(suggested) = sheet.get("suggested").filter(|s| s.is_object()) {
        let kind = str_at(suggested, "kind").unwrap_or("sheet");
        facts.push(match str_at(suggested, "cidr") {
            Some(cidr) => format!("{} {}", clean(kind), clean(cidr)),
            None => clean(kind),
        });
        facts.push(match suggested.get("header_row").and_then(Value::as_u64) {
            Some(row) => format!("header row {row}"),
            None => "no header row".to_owned(),
        });
    }
    if let Some(rows) = sheet
        .get("data_rows")
        .or_else(|| sheet.get("rows"))
        .and_then(Value::as_u64)
    {
        facts.push(format!(
            "{rows} data row{}",
            if rows == 1 { "" } else { "s" }
        ));
    }
    let mut out = format!("  sheet \"{}\"", clean(name));
    if !facts.is_empty() {
        let _ = write!(out, ": {}", facts.join(", "));
    }
    out.push('\n');
    let columns: Vec<String> = sheet
        .get("columns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|column| {
            let letter = clean(str_at(column, "column").unwrap_or("?"));
            let header = str_at(column, "header")
                .map(|header| format!(" {}", clean(header)))
                .unwrap_or_default();
            let target = clean(str_at(column, "suggested").unwrap_or("ignore"));
            format!("{letter}{header}={target}")
        })
        .collect();
    if !columns.is_empty() {
        let _ = writeln!(out, "    columns: {}", columns.join(", "));
    }
    out
}

// ---- the preview --------------------------------------------------------------------

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

/// The plan summary of a preview.
fn plan_summary(preview: &Value) -> Option<&Value> {
    ["/summary", "/plan/summary"]
        .iter()
        .filter_map(|pointer| preview.pointer(pointer))
        .find(|summary| summary.is_object())
}

/// The warnings of a preview as a list, if it has one.
fn warning_list(preview: &Value) -> Option<&Vec<Value>> {
    ["/warnings", "/plan/warnings"]
        .iter()
        .find_map(|pointer| preview.pointer(pointer)?.as_array())
}

/// Counts per kind and action.
fn change_counts(preview: &Value) -> Option<Vec<(String, String, u64)>> {
    let counts = plan_summary(preview)?.get("counts")?.as_array()?;
    Some(
        counts
            .iter()
            .filter_map(|item| {
                Some((
                    str_at(item, "kind")?.to_owned(),
                    str_at(item, "action")?.to_owned(),
                    item.get("count")?.as_u64()?,
                ))
            })
            .collect(),
    )
}

/// How many changes the preview holds, `None` when its shape does not say. Items that stay
/// as they are (`unchanged`, and `kept` by the conflict policy) are not changes.
fn total_changes(preview: &Value) -> Option<u64> {
    if let Some(counts) = change_counts(preview) {
        return Some(
            counts
                .iter()
                .filter(|(_, action, _)| !matches!(action.as_str(), "unchanged" | "kept"))
                .map(|(_, _, count)| count)
                .sum(),
        );
    }
    let summary = plan_summary(preview);
    if let Some(changes) = ["/changes", "/plan/changes"]
        .iter()
        .find_map(|pointer| preview.pointer(pointer)?.as_array())
    {
        return u64::try_from(changes.len()).ok();
    }
    if let Some(mutations) = summary.and_then(|s| s.get("mutations")?.as_u64()) {
        return Some(mutations);
    }
    let lines = summary?.get("lines")?.as_array()?;
    let none = lines.is_empty()
        || (lines.len() == 1
            && lines[0]
                .as_str()
                .is_some_and(|l| l.eq_ignore_ascii_case("no changes")));
    none.then_some(0)
}

/// Warnings by code.
fn warning_counts(preview: &Value) -> BTreeMap<String, u64> {
    if let Some(map) = plan_summary(preview)
        .and_then(|summary| summary.get("warnings"))
        .and_then(Value::as_object)
    {
        return map
            .iter()
            .filter_map(|(code, count)| Some((code.clone(), count.as_u64()?)))
            .collect();
    }
    let mut counts = BTreeMap::new();
    for warning in warning_list(preview).into_iter().flatten() {
        if let Some(code) = str_at(warning, "code") {
            *counts.entry(code.to_owned()).or_default() += 1;
        }
    }
    counts
}

/// Warning codes the plan applies only after they are acknowledged.
fn unacknowledged(preview: &Value) -> Vec<String> {
    if let Some(list) = plan_summary(preview)
        .and_then(|summary| summary.get("unacknowledged"))
        .and_then(Value::as_array)
    {
        return list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    let codes: BTreeSet<String> = warning_list(preview)
        .into_iter()
        .flatten()
        .filter(|warning| {
            warning.get("requires_ack").and_then(Value::as_bool) == Some(true)
                && warning.get("acknowledged").and_then(Value::as_bool) != Some(true)
        })
        .filter_map(|warning| str_at(warning, "code"))
        .map(str::to_owned)
        .collect();
    codes.into_iter().collect()
}

/// What stops the apply, from `can_apply` and `blockers` of the preview (`ImportPreview`
/// in `tenko-ipam/src/import/dto.rs`); empty when the preview allows it or does not say.
fn blockers(preview: &Value) -> Vec<String> {
    if preview.get("can_apply").and_then(Value::as_bool) != Some(false) {
        return Vec::new();
    }
    let listed: Vec<String> = preview
        .get("blockers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(clean)
        .collect();
    if listed.is_empty() {
        vec!["import.plan.blocked".to_owned()]
    } else {
        listed
    }
}

/// Source rows by what became of them (`imported`, `free`, `skipped`).
fn row_counts(preview: &Value) -> Option<BTreeMap<String, u64>> {
    let rows = preview.get("rows")?.as_array()?;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for row in rows {
        *counts
            .entry(str_at(row, "status").unwrap_or("other").to_owned())
            .or_default() += 1;
    }
    Some(counts)
}

/// Loss report entries by code, `None` when the preview has no loss report.
fn loss_counts(preview: &Value) -> Option<BTreeMap<String, u64>> {
    let entries = [
        "/loss_report/entries",
        "/loss/entries",
        "/loss_report",
        "/loss",
    ]
    .iter()
    .find_map(|pointer| preview.pointer(pointer)?.as_array())?;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for entry in entries {
        *counts
            .entry(str_at(entry, "code").unwrap_or("unknown").to_owned())
            .or_default() += 1;
    }
    Some(counts)
}

/// The summary of a preview for people.
fn render_preview(preview: &Value) -> String {
    let mut out = String::new();
    match change_counts(preview) {
        Some(counts) if counts.is_empty() => out.push_str("changes: none\n"),
        Some(counts) => {
            let rows: Vec<Vec<String>> = counts
                .iter()
                .map(|(kind, action, count)| vec![clean(kind), clean(action), count.to_string()])
                .collect();
            out.push_str("changes:\n");
            for line in table(&["KIND", "ACTION", "COUNT"], &rows).lines() {
                let _ = writeln!(out, "  {line}");
            }
        }
        None => match plan_summary(preview).and_then(|summary| summary.get("lines")?.as_array()) {
            Some(lines) if !lines.is_empty() => {
                out.push_str("changes:\n");
                for line in lines.iter().filter_map(Value::as_str) {
                    let _ = writeln!(out, "  {}", clean(line));
                }
            }
            _ => out.push_str("changes: the preview has no summary (see --json)\n"),
        },
    }
    if let Some(rows) = row_counts(preview).filter(|rows| !rows.is_empty()) {
        let total: u64 = rows.values().sum();
        let parts: Vec<String> = rows
            .iter()
            .map(|(status, count)| format!("{count} {}", clean(status)))
            .collect();
        let _ = writeln!(out, "rows: {total} read ({})", parts.join(", "));
    }
    let proposals: Vec<String> = preview
        .get("proposals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|proposal| {
            let cidr = clean(str_at(proposal, "cidr")?);
            let accepted = proposal.get("accepted").and_then(Value::as_bool) == Some(true);
            Some(format!(
                "{cidr} ({})",
                if accepted { "accepted" } else { "declined" }
            ))
        })
        .collect();
    if !proposals.is_empty() {
        let _ = writeln!(out, "proposed prefixes: {}", proposals.join(", "));
    }
    let warnings = warning_counts(preview);
    if !warnings.is_empty() {
        let total: u64 = warnings.values().sum();
        let _ = writeln!(out, "warnings: {total}");
        for (code, count) in &warnings {
            let _ = writeln!(out, "  {}  {count}", clean(code));
        }
    }
    let pending = unacknowledged(preview);
    if !pending.is_empty() {
        let list: Vec<String> = pending.iter().map(|code| clean(code)).collect();
        let _ = writeln!(
            out,
            "needs acknowledgement: {} (run with --acknowledge CODE)",
            list.join(", ")
        );
    }
    match loss_counts(preview) {
        Some(losses) if losses.is_empty() => out.push_str("loss report: empty\n"),
        Some(losses) => {
            let total: u64 = losses.values().sum();
            let _ = writeln!(
                out,
                "loss report: {total} entr{}",
                if total == 1 { "y" } else { "ies" }
            );
            for (code, count) in &losses {
                let _ = writeln!(out, "  {}  {count}", clean(code));
            }
        }
        None => {}
    }
    out
}

// ---- confirmation -------------------------------------------------------------------

/// What to do before applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirmation {
    /// `--yes`.
    Go,
    /// Ask on the terminal.
    Ask,
    /// No terminal and no `--yes`.
    Refuse,
}

fn confirmation(yes: bool, terminal: bool) -> Confirmation {
    if yes {
        Confirmation::Go
    } else if terminal {
        Confirmation::Ask
    } else {
        Confirmation::Refuse
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ---- the job ------------------------------------------------------------------------

/// Where a job is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobPhase {
    /// Queued, running, waiting or rolling back; unknown states count as active.
    Active,
    /// `succeeded`.
    Succeeded,
    /// `failed`, `rolled_back` or `cancelled`.
    Unsuccessful,
}

fn job_phase(state: &str) -> JobPhase {
    match state {
        "succeeded" => JobPhase::Succeeded,
        "failed" | "rolled_back" | "cancelled" => JobPhase::Unsuccessful,
        _ => JobPhase::Active,
    }
}

/// The job of a `JobDetail` (`job`) or a `JobSummary` (the body itself).
fn job_of(body: &Value) -> &Value {
    body.get("job")
        .filter(|job| job.is_object())
        .unwrap_or(body)
}

fn job_state(body: &Value) -> Option<&str> {
    str_at(job_of(body), "state")
}

/// Steps done or skipped, and all steps.
fn step_progress(body: &Value) -> Option<(u64, u64)> {
    let job = job_of(body);
    if let (Some(done), Some(total)) = (
        job.get("steps_done").and_then(Value::as_u64),
        job.get("step_count").and_then(Value::as_u64),
    ) {
        return Some((done, total));
    }
    let steps = job.get("steps")?.as_array()?;
    let done = steps
        .iter()
        .filter(|step| {
            matches!(
                step.pointer("/state/state").and_then(Value::as_str),
                Some("done" | "skipped")
            )
        })
        .count();
    Some((u64::try_from(done).ok()?, u64::try_from(steps.len()).ok()?))
}

/// `[code] detail` of the error of the job, else of its first failed step.
fn job_error(body: &Value) -> Option<String> {
    let job = job_of(body);
    let error = job
        .get("error")
        .filter(|error| error.is_object())
        .or_else(|| {
            job.get("steps")?
                .as_array()?
                .iter()
                .find_map(|step| step.pointer("/state/data/error"))
        })?;
    let code = str_at(error, "code").map(clean);
    let detail = str_at(error, "detail").map(clean);
    match (code, detail) {
        (Some(code), Some(detail)) => Some(format!("[{code}] {detail}")),
        (Some(code), None) => Some(format!("[{code}]")),
        (None, Some(detail)) => Some(detail),
        (None, None) => None,
    }
}

/// The error line for a job that ended without success.
fn unsuccessful_line(job_id: &str, state: &str, error: Option<&str>) -> String {
    let what = match state {
        "rolled_back" => "was rolled back, no changes were kept".to_owned(),
        "cancelled" => "was cancelled, no changes were kept".to_owned(),
        "failed" => "failed and could not be rolled back; some changes may remain, so an \
                     operator must review them"
            .to_owned(),
        other => format!("ended in state {}", words(other)),
    };
    match error {
        Some(error) => format!("import job {job_id} {what}: {error}"),
        None => format!("import job {job_id} {what}"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
    };

    use clap::Parser;
    use tenko_api::client::ClientConfig;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    #[derive(Parser)]
    struct Line {
        #[command(flatten)]
        args: ImportArgs,
    }

    fn parse(args: &[&str]) -> Result<ImportArgs, clap::Error> {
        let mut line = vec!["import"];
        line.extend_from_slice(args);
        Line::try_parse_from(line).map(|line| line.args)
    }

    fn args(extra: &[&str]) -> ImportArgs {
        let mut line = vec!["plan.xlsx"];
        line.extend_from_slice(extra);
        parse(&line).expect("valid arguments")
    }

    fn upload() -> Value {
        json!({
            "id": "0190a5b2-7c3e-7d11-9f1a-000000000001",
            "format": "xlsx",
            "sheets": [
                {
                    "sheet": "Index",
                    "data_rows": 7,
                    "columns": [
                        {"column": "A", "samples": ["192.0.2.0/24"], "suggested": "prefix"},
                        {"column": "B", "samples": ["NAS"], "suggested": "description"}
                    ],
                    "suggested": {"sheet": "Index", "kind": "index", "columns": []}
                },
                {
                    "sheet": "192.0.2.0",
                    "data_rows": 255,
                    "columns": [
                        {"column": "A", "header": "IP", "suggested": "address"},
                        {"column": "C", "header": "Login", "suggested": "login", "samples": ["(hidden)"]}
                    ],
                    "suggested": {
                        "sheet": "192.0.2.0", "kind": "network", "cidr": "192.0.2.0/24",
                        "header_row": 1, "columns": []
                    }
                }
            ],
            "suggested_mapping": {
                "sheets": [
                    {"sheet": "Index", "kind": "index", "columns": []},
                    {"sheet": "192.0.2.0", "kind": "network", "header_row": 1, "columns": []}
                ],
                "options": {"conflict": "update"}
            }
        })
    }

    fn preview() -> Value {
        json!({
            "summary": {
                "counts": [
                    {"kind": "address", "action": "create", "count": 12},
                    {"kind": "prefix", "action": "create", "count": 3},
                    {"kind": "host", "action": "update", "count": 1}
                ],
                "warnings": {"ipam.address.is_network": 2},
                "unacknowledged": [],
                "lines": ["12 addresses created"],
                "mutations": 40
            },
            "rows": [
                {"status": "imported"}, {"status": "imported"}, {"status": "free"},
                {"status": "skipped"}
            ],
            "proposals": [{"cidr": "198.51.100.64/26", "accepted": true}],
            "loss_report": {"entries": [
                {"code": "import.address.unparsable", "detail": "x"},
                {"code": "import.column.unmapped", "detail": "y"},
                {"code": "import.column.unmapped", "detail": "z"}
            ]}
        })
    }

    #[test]
    fn flags_parse_with_their_defaults() {
        let plain = args(&[]);
        assert_eq!(plain.file, PathBuf::from("plan.xlsx"));
        assert_eq!(plain.wait_secs, 600);
        assert!(!plain.dry_run && !plain.yes && !plain.keep);
        assert!(plain.sheet.is_none() && plain.header_row.is_none() && plain.vrf.is_none());

        let full = args(&[
            "--sheet",
            "LAN",
            "--header-row",
            "3",
            "--mapping",
            "m.json",
            "--vrf",
            "lab",
            "--acknowledge",
            "a.b",
            "--acknowledge",
            "c.d",
            "--dry-run",
            "--yes",
            "--keep",
            "--wait-secs",
            "30",
            "--json",
        ]);
        assert_eq!(full.sheet.as_deref(), Some("LAN"));
        assert_eq!(full.header_row, Some(3));
        assert_eq!(full.mapping, Some(PathBuf::from("m.json")));
        assert_eq!(full.vrf.as_deref(), Some("lab"));
        assert_eq!(full.acknowledge, ["a.b", "c.d"]);
        assert!(full.dry_run && full.yes && full.keep && full.client.json);
        assert_eq!(full.wait_secs, 30);
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn the_upload_id_is_found_and_must_be_safe() {
        assert_eq!(
            find_id(&upload(), UPLOAD_ID).as_deref(),
            Some("0190a5b2-7c3e-7d11-9f1a-000000000001")
        );
        assert_eq!(
            find_id(&json!({"import_id": "abc_1"}), UPLOAD_ID).as_deref(),
            Some("abc_1")
        );
        assert_eq!(
            find_id(&json!({"import": {"id": 42}}), UPLOAD_ID).as_deref(),
            Some("42")
        );
        assert_eq!(find_id(&json!({}), UPLOAD_ID), None);
        for hostile in ["", "../x", "a/b", "a?b", "a b", "{e4}"] {
            assert_eq!(
                find_id(&json!({ "id": hostile }), UPLOAD_ID),
                None,
                "{hostile:?}"
            );
        }
        assert_eq!(find_id(&json!({"id": "x".repeat(65)}), UPLOAD_ID), None);
    }

    #[test]
    fn the_job_id_is_found_in_the_apply_answer() {
        assert_eq!(
            find_id(&json!({"job_id": "j1"}), JOB_ID).as_deref(),
            Some("j1")
        );
        assert_eq!(
            find_id(&json!({"job": {"id": "j2"}}), JOB_ID).as_deref(),
            Some("j2")
        );
        assert_eq!(find_id(&json!({"state": "queued"}), JOB_ID), None);
    }

    #[test]
    fn the_suggested_mapping_comes_from_the_answer_or_the_sheets() {
        let mapping = suggested_mapping(&upload()).expect("mapping");
        assert_eq!(mapping["options"]["conflict"], "update");
        assert_eq!(mapping["sheets"].as_array().map(Vec::len), Some(2));

        let mut without = upload();
        without
            .as_object_mut()
            .expect("object")
            .remove("suggested_mapping");
        let built = suggested_mapping(&without).expect("built from the sheets");
        assert_eq!(built["sheets"][1]["cidr"], "192.0.2.0/24");
        assert_eq!(built["options"], json!({}));

        let alias = json!({"mapping": {"sheets": []}});
        assert_eq!(suggested_mapping(&alias), Some(json!({"sheets": []})));
        assert_eq!(suggested_mapping(&json!({"mapping": "x"})), None);
        assert_eq!(suggested_mapping(&json!({})), None);
    }

    #[test]
    fn flags_shape_the_suggested_mapping() {
        let mapping = build_mapping(
            &upload(),
            None,
            &args(&[
                "--sheet",
                "192.0.2.0",
                "--header-row",
                "2",
                "--vrf",
                "lab",
                "--acknowledge",
                "b.b",
                "--acknowledge",
                "a.a",
            ]),
        )
        .expect("mapping");
        assert_eq!(mapping["sheets"][0]["kind"], "skip");
        assert_eq!(mapping["sheets"][1]["kind"], "network");
        assert_eq!(mapping["sheets"][1]["header_row"], 2);
        assert!(mapping["sheets"][0].get("header_row").is_none());
        assert_eq!(mapping["options"]["vrf"], "lab");
        assert_eq!(mapping["options"]["acknowledge"], json!(["a.a", "b.b"]));
        assert_eq!(mapping["options"]["conflict"], "update");
    }

    #[test]
    fn a_mapping_file_is_kept_apart_from_the_flags() {
        let file =
            json!({"sheets": [{"sheet": "LAN", "kind": "list", "header_row": 4}], "extra": 1});
        let same = build_mapping(&upload(), Some(file.clone()), &args(&[])).expect("mapping");
        assert_eq!(same, file);

        let changed = build_mapping(
            &upload(),
            Some(
                json!({"sheets": [{"sheet": "LAN", "kind": "list", "header_row": 4}],
                        "options": {"acknowledge": ["x.y"]}}),
            ),
            &args(&["--header-row", "0", "--vrf", "lab", "--acknowledge", "a.a"]),
        )
        .expect("mapping");
        assert!(changed["sheets"][0].get("header_row").is_none());
        assert_eq!(changed["options"]["vrf"], "lab");
        assert_eq!(changed["options"]["acknowledge"], json!(["a.a", "x.y"]));
    }

    #[test]
    fn the_sheet_choice_is_checked_against_the_mapping() {
        let mut mapping = suggested_mapping(&upload()).expect("mapping");
        let error = restrict_to_sheet(&mut mapping, "nope").expect_err("unknown sheet");
        assert!(error.contains("\"nope\""));
        assert!(error.contains("Index, 192.0.2.0"));

        let mut mapping = suggested_mapping(&upload()).expect("mapping");
        restrict_to_sheet(&mut mapping, "INDEX").expect("case-insensitive match");
        assert_eq!(mapping["sheets"][0]["kind"], "index");
        assert_eq!(mapping["sheets"][1]["kind"], "skip");

        let mut twins = json!({"sheets": [{"sheet": "A"}, {"sheet": "a"}]});
        assert!(
            restrict_to_sheet(&mut twins, "A").is_ok(),
            "exact match wins"
        );
        assert!(
            restrict_to_sheet(
                &mut json!({"sheets": [{"sheet": "A"}, {"sheet": "a"}]}),
                "a"
            )
            .is_ok()
        );
        assert!(
            restrict_to_sheet(
                &mut json!({"sheets": [{"sheet": "Ab"}, {"sheet": "aB"}]}),
                "AB"
            )
            .is_err()
        );
        assert!(restrict_to_sheet(&mut json!({"options": {}}), "A").is_err());
    }

    #[test]
    fn a_build_without_any_mapping_is_an_error() {
        let failure = build_mapping(&json!({"id": "x"}), None, &args(&[])).expect_err("no mapping");
        assert!(failure.message.contains("--mapping"));
        let failure = build_mapping(
            &upload(),
            Some(json!({"sheets": [], "options": 3})),
            &args(&["--vrf", "lab"]),
        )
        .expect_err("options is not an object");
        assert_eq!(failure.status, exit::USAGE);
    }

    #[test]
    fn the_upload_note_names_kind_sheets_columns_and_targets() {
        let note = describe_upload(&upload(), "plan.xlsx", None);
        assert_eq!(
            note,
            "uploaded plan.xlsx: xlsx file with 2 sheets\n\
             \x20 sheet \"Index\": index, no header row, 7 data rows\n\
             \x20   columns: A=prefix, B=description\n\
             \x20 sheet \"192.0.2.0\": network 192.0.2.0/24, header row 1, 255 data rows\n\
             \x20   columns: A IP=address, C Login=login\n\
             mapping: suggested by the server"
        );
        let csv = describe_upload(
            &json!({"sheets": ["plan"]}),
            "plan.CSV",
            Some(Path::new("m.json")),
        );
        assert_eq!(
            csv,
            "uploaded plan.CSV: csv file with 1 sheet\n  sheet \"plan\"\nmapping: from m.json"
        );
    }

    #[test]
    fn control_characters_of_the_file_never_reach_the_terminal() {
        let hostile = json!({"sheets": [{"sheet": "a\u{1b}[31mred", "columns": [{"column": "A", "header": "x\ny", "suggested": "name"}]}]});
        let note = describe_upload(&hostile, "f.csv", None);
        assert!(!note.contains('\u{1b}'));
        assert!(note.contains("a?[31mred"));
        assert!(note.contains("A x?y=name"));
    }

    #[test]
    fn the_preview_summary_shows_changes_rows_warnings_and_losses() {
        assert_eq!(
            render_preview(&preview()),
            "changes:\n\
             \x20 KIND     ACTION  COUNT\n\
             \x20 address  create  12\n\
             \x20 prefix   create  3\n\
             \x20 host     update  1\n\
             rows: 4 read (1 free, 2 imported, 1 skipped)\n\
             proposed prefixes: 198.51.100.64/26 (accepted)\n\
             warnings: 2\n\
             \x20 ipam.address.is_network  2\n\
             loss report: 3 entries\n\
             \x20 import.address.unparsable  1\n\
             \x20 import.column.unmapped  2\n"
        );
    }

    #[test]
    fn the_preview_summary_copes_with_other_shapes() {
        let empty = json!({"summary": {"counts": []}, "rows": [], "loss": []});
        assert_eq!(
            render_preview(&empty),
            "changes: none\nloss report: empty\n"
        );

        let lines = json!({"plan": {"summary": {"lines": ["3 prefixes created"]}}});
        assert_eq!(render_preview(&lines), "changes:\n  3 prefixes created\n");

        assert_eq!(
            render_preview(&json!({})),
            "changes: the preview has no summary (see --json)\n"
        );

        let acknowledge = json!({"summary": {
            "counts": [{"kind": "prefix", "action": "create", "count": 1}],
            "unacknowledged": ["ipam.prefix.nibble_boundary"]
        }});
        let text = render_preview(&acknowledge);
        assert!(text.contains(
            "needs acknowledgement: ipam.prefix.nibble_boundary (run with --acknowledge CODE)"
        ));
        assert_eq!(
            unacknowledged(&acknowledge),
            ["ipam.prefix.nibble_boundary"]
        );
    }

    #[test]
    fn warnings_come_from_the_summary_or_the_list() {
        let list = json!({"warnings": [
            {"code": "a.one", "requires_ack": true, "acknowledged": false},
            {"code": "a.one", "requires_ack": true},
            {"code": "b.two", "requires_ack": true, "acknowledged": true},
            {"code": "c.three"}
        ]});
        let counts = warning_counts(&list);
        assert_eq!(counts.get("a.one"), Some(&2));
        assert_eq!(counts.len(), 3);
        assert_eq!(unacknowledged(&list), ["a.one"]);
        assert_eq!(unacknowledged(&preview()), Vec::<String>::new());
    }

    #[test]
    fn unchanged_and_kept_items_are_not_changes() {
        let preview = json!({"summary": {"counts": [
            {"kind": "prefix", "action": "unchanged", "count": 3},
            {"kind": "host", "action": "kept", "count": 1},
            {"kind": "address", "action": "update", "count": 2}
        ]}});
        assert_eq!(total_changes(&preview), Some(2));
        let same = json!({"summary": {"counts": [
            {"kind": "prefix", "action": "unchanged", "count": 3}
        ]}});
        assert_eq!(total_changes(&same), Some(0));
    }

    #[test]
    fn blockers_come_from_the_preview() {
        assert_eq!(
            blockers(&json!({"can_apply": true, "blockers": []})),
            Vec::<String>::new()
        );
        assert_eq!(blockers(&json!({})), Vec::<String>::new());
        assert_eq!(
            blockers(
                &json!({"can_apply": false, "blockers": ["import.credentials.vault_required"]})
            ),
            ["import.credentials.vault_required"]
        );
        assert_eq!(
            blockers(&json!({"can_apply": false})),
            ["import.plan.blocked"]
        );
    }

    #[test]
    fn zero_changes_are_recognized() {
        assert_eq!(total_changes(&preview()), Some(16));
        assert_eq!(total_changes(&json!({"summary": {"counts": []}})), Some(0));
        assert_eq!(
            total_changes(&json!({"summary": {"counts": [
                {"kind": "prefix", "action": "create", "count": 0}
            ]}})),
            Some(0)
        );
        assert_eq!(total_changes(&json!({"changes": []})), Some(0));
        assert_eq!(
            total_changes(&json!({"plan": {"changes": [{}, {}]}})),
            Some(2)
        );
        assert_eq!(
            total_changes(&json!({"summary": {"mutations": 0}})),
            Some(0)
        );
        assert_eq!(
            total_changes(&json!({"summary": {"mutations": 6}})),
            Some(6)
        );
        assert_eq!(
            total_changes(&json!({"summary": {"lines": ["no changes"]}})),
            Some(0)
        );
        assert_eq!(total_changes(&json!({"summary": {"lines": []}})), Some(0));
        assert_eq!(
            total_changes(&json!({"summary": {"lines": ["3 prefixes created"]}})),
            None
        );
        assert_eq!(total_changes(&json!({})), None);
        assert_eq!(total_changes(&json!({"summary": "x"})), None);
    }

    #[test]
    fn the_confirmation_follows_yes_and_the_terminal() {
        assert_eq!(confirmation(true, true), Confirmation::Go);
        assert_eq!(confirmation(true, false), Confirmation::Go);
        assert_eq!(confirmation(false, true), Confirmation::Ask);
        assert_eq!(confirmation(false, false), Confirmation::Refuse);
        for yes in ["y", "Y", " yes ", "YES"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "yeah", "ja"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn job_states_are_classified() {
        for state in [
            "queued",
            "running",
            "waiting",
            "rolling_back",
            "something_new",
        ] {
            assert_eq!(job_phase(state), JobPhase::Active, "{state}");
        }
        assert_eq!(job_phase("succeeded"), JobPhase::Succeeded);
        for state in ["failed", "rolled_back", "cancelled"] {
            assert_eq!(job_phase(state), JobPhase::Unsuccessful, "{state}");
        }
    }

    #[test]
    fn job_bodies_are_read_as_detail_or_summary() {
        let detail = json!({"job": {
            "id": "j1", "state": "rolled_back",
            "error": {"code": "ipam.conflict", "status": 409, "detail": "192.0.2.5 is taken"},
            "steps": [
                {"state": {"state": "compensated"}},
                {"state": {"state": "done"}},
                {"state": {"state": "skipped"}}
            ]
        }, "revision": 9});
        assert_eq!(job_state(&detail), Some("rolled_back"));
        assert_eq!(step_progress(&detail), Some((2, 3)));
        assert_eq!(
            job_error(&detail).as_deref(),
            Some("[ipam.conflict] 192.0.2.5 is taken")
        );

        let summary = json!({"id": "j1", "state": "running", "steps_done": 1, "step_count": 4});
        assert_eq!(job_state(&summary), Some("running"));
        assert_eq!(step_progress(&summary), Some((1, 4)));
        assert_eq!(job_error(&summary), None);

        let step_error = json!({"job": {"state": "failed", "steps": [
            {"state": {"state": "done"}},
            {"state": {"state": "compensation_failed",
                       "data": {"error": {"code": "jobs.step.failed", "detail": "disk full"}}}}
        ]}});
        assert_eq!(
            job_error(&step_error).as_deref(),
            Some("[jobs.step.failed] disk full")
        );
        assert_eq!(job_state(&json!({})), None);
        assert_eq!(step_progress(&json!({"job": {"state": "queued"}})), None);
    }

    #[test]
    fn unsuccessful_jobs_say_what_became_of_the_changes() {
        let line = unsuccessful_line("j1", "rolled_back", Some("[ipam.conflict] taken"));
        assert_eq!(
            line,
            "import job j1 was rolled back, no changes were kept: [ipam.conflict] taken"
        );
        assert!(unsuccessful_line("j1", "cancelled", None).ends_with("no changes were kept"));
        assert!(unsuccessful_line("j1", "failed", None).contains("operator must review"));
        assert_eq!(
            unsuccessful_line("j1", "weird_state", None),
            "import job j1 ended in state weird state"
        );
    }

    #[test]
    fn large_files_are_refused_with_their_size() {
        assert!(check_size(0, "a.csv").is_ok());
        assert!(check_size(MAX_UPLOAD_BYTES, "a.csv").is_ok());
        let failure = check_size(MAX_UPLOAD_BYTES + 1, "plan.xlsx").expect_err("too large");
        assert_eq!(failure.status, exit::USAGE);
        assert_eq!(
            failure.message,
            "plan.xlsx is 21 MB, over the 20 MB limit for imports"
        );
        assert_eq!(upload_name(Path::new("dir/plan.xlsx")), "plan.xlsx");
    }

    #[test]
    fn the_console_keeps_order_and_streams() {
        let mut console = Console::default();
        console.note("first");
        console.out("second\n");
        console.note("third");
        let output = console.finish(8);
        assert_eq!(output.stdout, "second\n");
        assert_eq!(output.stderr, "first\nthird\n");
        assert_eq!(output.status, 8);
    }

    #[tokio::test]
    async fn mapping_files_are_parsed_before_anything_is_sent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).expect("write");
            path
        };
        let good = write("good.json", b"\xEF\xBB\xBF{\"sheets\": []}");
        assert_eq!(
            read_mapping(&good).await.expect("mapping"),
            json!({"sheets": []})
        );
        let array = write("array.json", b"[1]");
        assert!(
            read_mapping(&array)
                .await
                .expect_err("array")
                .message
                .contains("JSON object")
        );
        let broken = write("broken.json", b"{");
        assert!(
            read_mapping(&broken)
                .await
                .expect_err("broken")
                .message
                .contains("not valid JSON")
        );
        let missing = dir.path().join("missing.json");
        let failure = read_mapping(&missing).await.expect_err("missing");
        assert_eq!(failure.status, exit::USAGE);

        let mut line = args(&[]);
        line.file = dir.path().join("absent.csv");
        let failure = Input::load(&line).await.expect_err("no such file");
        assert_eq!(failure.status, exit::USAGE);
        line.file = dir.path().to_path_buf();
        assert!(
            Input::load(&line)
                .await
                .expect_err("a directory")
                .message
                .contains("not a file")
        );
    }

    // ---- the whole flow against a scripted server ---------------------------------------

    /// A one-purpose HTTP server: answers by `METHOD /path` from a script (the last answer
    /// of a route repeats) and records what it saw.
    struct Fake {
        url: String,
        seen: Arc<Mutex<Vec<String>>>,
    }

    type Script = HashMap<String, VecDeque<(u16, String)>>;

    impl Fake {
        async fn start(routes: &[(&str, Vec<(u16, String)>)]) -> Self {
            let script: Script = routes
                .iter()
                .map(|(route, answers)| ((*route).to_owned(), answers.iter().cloned().collect()))
                .collect();
            let script = Arc::new(Mutex::new(script));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("address"));
            let (script_for_task, seen_for_task) = (script.clone(), seen.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(answer(
                        stream,
                        script_for_task.clone(),
                        seen_for_task.clone(),
                    ));
                }
            });
            Self { url, seen }
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().expect("log").clone()
        }
    }

    async fn answer(
        mut stream: TcpStream,
        script: Arc<Mutex<Script>>,
        seen: Arc<Mutex<Vec<String>>>,
    ) {
        let mut data = Vec::new();
        let mut chunk = [0_u8; 4096];
        let head_end = loop {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            if read == 0 {
                return;
            }
            data.extend_from_slice(&chunk[..read]);
            if let Some(at) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
        let mut lines = head.lines();
        let mut request = lines.next().unwrap_or_default().split_whitespace();
        let method = request.next().unwrap_or_default().to_owned();
        let path = request
            .next()
            .unwrap_or_default()
            .trim_start_matches("/api/v1")
            .to_owned();
        let headers: Vec<String> = lines.map(str::to_ascii_lowercase).collect();
        let length: usize = headers
            .iter()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        while data.len() < head_end + length {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..read]);
        }
        let route = format!("{method} {path}");
        let idempotent = headers
            .iter()
            .any(|line| line.starts_with("idempotency-key:"));
        seen.lock().expect("log").push(if idempotent {
            format!("{route} [idempotency-key]")
        } else {
            route.clone()
        });
        let (status, body) = {
            let mut script = script.lock().expect("script");
            match script.get_mut(&route) {
                Some(answers) if answers.len() > 1 => answers.pop_front().expect("answer"),
                Some(answers) => answers.front().cloned().expect("answer"),
                None => (404, "{}".to_owned()),
            }
        };
        let kind = if status >= 400 {
            "application/problem+json"
        } else {
            "application/json"
        };
        let reply = format!(
            "HTTP/1.1 {status} Scripted\r\ncontent-type: {kind}\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(reply.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    fn job(state: &str, done: u64) -> (u16, String) {
        (
            200,
            json!({"id": "j1", "state": state, "steps_done": done, "step_count": 2}).to_string(),
        )
    }

    fn failed_job(state: &str) -> (u16, String) {
        (
            200,
            json!({"job": {
                "id": "j1", "state": state,
                "error": {"code": "ipam.conflict", "status": 409, "detail": "192.0.2.5 is taken"},
                "steps": []
            }})
            .to_string(),
        )
    }

    fn routes(
        preview: &Value,
        jobs: Vec<(u16, String)>,
    ) -> Vec<(&'static str, Vec<(u16, String)>)> {
        vec![
            ("PUT /imports/imp1/mapping", vec![(200, "{}".to_owned())]),
            (
                "GET /imports/imp1/preview",
                vec![(200, preview.to_string())],
            ),
            (
                "POST /imports/imp1/apply",
                vec![(202, json!({"job_id": "j1"}).to_string())],
            ),
            ("GET /jobs/j1", jobs),
            ("DELETE /imports/imp1", vec![(204, String::new())]),
        ]
    }

    /// Runs the flow after the upload against the server.
    async fn flow(fake: &Fake, extra: &[&str]) -> Output {
        let args = args(extra);
        let client = Client::new(ClientConfig::new(fake.url.clone())).expect("client");
        let mut import = Import {
            args: &args,
            client,
            id: "imp1".to_owned(),
            console: Console::default(),
            submitted: false,
        };
        let result = import.proceed(&upload(), None).await;
        import.cleanup(result.is_ok()).await;
        import
            .console
            .finish(result.expect("the flow ends with a status"))
    }

    #[tokio::test]
    async fn an_import_is_applied_and_followed_to_its_end() {
        let fake = Fake::start(&routes(
            &preview(),
            vec![job("queued", 0), job("running", 1), job("succeeded", 2)],
        ))
        .await;
        let output = flow(&fake, &["--yes", "--wait-secs", "30"]).await;
        assert_eq!(output.status, exit::OK);
        assert!(
            output
                .stdout
                .ends_with("import applied: 16 changes (job j1)\n"),
            "{}",
            output.stdout
        );
        assert_eq!(
            fake.seen(),
            [
                "PUT /imports/imp1/mapping",
                "GET /imports/imp1/preview",
                "POST /imports/imp1/apply [idempotency-key]",
                "GET /jobs/j1",
                "GET /jobs/j1",
                "GET /jobs/j1",
            ],
            "the job owns the upload, so nothing is deleted"
        );
    }

    #[tokio::test]
    async fn a_rolled_back_job_gives_status_8_with_its_error() {
        let fake = Fake::start(&routes(&preview(), vec![failed_job("rolled_back")])).await;
        let output = flow(&fake, &["--yes", "--json"]).await;
        assert_eq!(output.status, exit::JOB);
        assert_eq!(
            output.stderr.lines().last(),
            Some(
                "tenko import: error: import job j1 was rolled back, no changes were kept: \
                 [ipam.conflict] 192.0.2.5 is taken"
            )
        );
        let document: Value = serde_json::from_str(&output.stdout).expect("one JSON document");
        assert_eq!(document["job"]["job"]["state"], "rolled_back");
        assert_eq!(document["preview"], preview());
    }

    #[tokio::test]
    async fn a_job_that_does_not_end_in_time_gives_status_8() {
        let fake = Fake::start(&routes(&preview(), vec![job("running", 1)])).await;
        let output = flow(&fake, &["--yes", "--wait-secs", "1"]).await;
        assert_eq!(output.status, exit::JOB);
        let last = output.stderr.lines().last().expect("an error line");
        assert!(
            last.starts_with("tenko import: error: timed out after 1 s waiting for import job j1"),
            "{last}"
        );
        assert!(last.contains("GET /api/v1/jobs/j1"));
        let polls = fake
            .seen()
            .iter()
            .filter(|line| *line == "GET /jobs/j1")
            .count();
        assert!((2..=4).contains(&polls), "{polls} polls");
    }

    #[tokio::test]
    async fn a_zero_wait_starts_the_job_and_returns() {
        let fake = Fake::start(&routes(&preview(), vec![job("queued", 0)])).await;
        let output = flow(&fake, &["--yes", "--wait-secs", "0"]).await;
        assert_eq!(output.status, exit::OK);
        assert!(output.stderr.contains("import job j1 started"));
        assert!(!fake.seen().iter().any(|line| line.contains("/jobs/")));
    }

    #[tokio::test]
    async fn a_dry_run_shows_the_preview_and_deletes_the_upload() {
        let fake = Fake::start(&routes(&preview(), vec![job("queued", 0)])).await;
        let output = flow(&fake, &["--dry-run"]).await;
        assert_eq!(output.status, exit::OK);
        assert_eq!(output.stdout, render_preview(&preview()));
        assert!(output.stderr.contains("dry run: nothing was imported"));
        assert_eq!(
            fake.seen(),
            [
                "PUT /imports/imp1/mapping",
                "GET /imports/imp1/preview",
                "DELETE /imports/imp1"
            ]
        );

        let json = Fake::start(&routes(&preview(), vec![job("queued", 0)])).await;
        let output = flow(&json, &["--dry-run", "--json"]).await;
        let body: Value = serde_json::from_str(&output.stdout).expect("the preview body");
        assert_eq!(body, preview());
    }

    #[tokio::test]
    async fn keep_leaves_the_upload_staged() {
        let fake = Fake::start(&routes(&preview(), vec![job("queued", 0)])).await;
        let output = flow(&fake, &["--dry-run", "--keep"]).await;
        assert!(!fake.seen().iter().any(|line| line.starts_with("DELETE")));
        assert!(output.stderr.contains("the staged upload imp1 was kept"));
    }

    #[tokio::test]
    async fn a_preview_without_changes_applies_nothing() {
        let empty = json!({"summary": {"counts": [], "warnings": {}, "unacknowledged": []}});
        let fake = Fake::start(&routes(&empty, vec![job("queued", 0)])).await;
        let output = flow(&fake, &["--yes"]).await;
        assert_eq!(output.status, exit::OK);
        assert!(
            output
                .stdout
                .ends_with("nothing to import: the file matches the current data\n")
        );
        let seen = fake.seen();
        assert!(
            !seen.iter().any(|line| line.starts_with("POST")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|line| line == "DELETE /imports/imp1"));
    }

    #[tokio::test]
    async fn an_apply_the_server_refuses_leaves_no_staged_upload() {
        let problem = json!({
            "type": "about:blank", "status": 409, "code": "import.stale",
            "title": "Conflict", "detail": "the data changed since the preview"
        });
        let mut script = routes(&preview(), vec![job("queued", 0)]);
        script[2] = ("POST /imports/imp1/apply", vec![(409, problem.to_string())]);
        let fake = Fake::start(&script).await;
        let args = args(&["--yes"]);
        let client = Client::new(ClientConfig::new(fake.url.clone())).expect("client");
        let mut import = Import {
            args: &args,
            client,
            id: "imp1".to_owned(),
            console: Console::default(),
            submitted: false,
        };
        let failure = import.proceed(&upload(), None).await.expect_err("refused");
        import.cleanup(false).await;
        assert_eq!(failure.status, exit::API);
        assert!(
            failure.message.starts_with("[import.stale]"),
            "{}",
            failure.message
        );
        assert!(
            fake.seen()
                .iter()
                .any(|line| line == "DELETE /imports/imp1")
        );
    }

    #[tokio::test]
    async fn unacknowledged_warnings_stop_the_apply_before_it_starts() {
        let mut pending = preview();
        pending["summary"]["unacknowledged"] = json!(["ipam.prefix.nibble_boundary"]);
        let fake = Fake::start(&routes(&pending, vec![job("queued", 0)])).await;
        let args = args(&["--yes"]);
        let client = Client::new(ClientConfig::new(fake.url.clone())).expect("client");
        let mut import = Import {
            args: &args,
            client,
            id: "imp1".to_owned(),
            console: Console::default(),
            submitted: false,
        };
        let failure = import
            .proceed(&upload(), None)
            .await
            .expect_err("needs an acknowledgement");
        assert_eq!(failure.status, exit::USAGE);
        assert!(failure.message.contains("--acknowledge"));
        assert!(!fake.seen().iter().any(|line| line.starts_with("POST")));
    }
}
