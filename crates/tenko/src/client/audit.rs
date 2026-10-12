//! `tenko audit verify` and `tenko audit export`.
//!
//! - `verify` without `--file` asks the controller to check the hash chain of the audit log
//!   (IAM-18) and reports the first break.
//! - `verify --file <path> [--from <seq>:<hash>]` checks a JSON lines export on this
//!   machine with the library of the audit export (WP3.3): no server and no login, so the
//!   connection options are accepted but unused. `--from` names a trusted head that the file
//!   continues; a file that starts with a checkpoint needs none. Exit status 9 when the
//!   file is broken, 1 when it cannot be read.
//! - `export` pages through `GET /api/v1/audit/export` and writes the records in the chosen
//!   format (`json`, `rfc5424`, `cef`) with a chain checkpoint at the start, after every
//!   [`CHECKPOINT_EVERY`] records and at the end, to a file or standard output. The JSON
//!   form verifies with `verify --file`. Standard output is collected in memory; use
//!   `--output` for a large log.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use tenko_api::{
    client::Client,
    routes::audit_export::{AuditExportPage, AuditExportQuery},
};
use tenko_auth::audit_export::{
    format::{Checkpoint, Event, Framing, Origin, render},
    model::ExportFormat,
    verify::{Anchor, VerifyReport, verify_lines},
};
use tenko_core::{
    AuditSeq, Timestamp,
    audit::{ChainHead, Digest},
};

use super::{ClientOpts, Failure, Output, Target};
use crate::exit;

/// Records per request to `GET /audit/export` (the largest page the API serves).
const PAGE: u32 = 5000;

/// Records between two checkpoints of an export.
pub const CHECKPOINT_EVERY: u64 = 100;

/// Subcommands of `tenko audit`.
#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// Verify the hash chain of the audit log, or of an exported file; exits with status 9
    /// when it is broken.
    Verify(VerifyArgs),
    /// Write the audit log from a sequence number, in a log format, with chain checkpoints.
    Export(ExportArgs),
}

/// Arguments of `tenko audit verify`.
#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    /// Connection options (unused with `--file`).
    #[command(flatten)]
    pub client: ClientOpts,

    /// Verify this JSON lines export on this machine instead of asking the controller.
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// A trusted head that the file continues, as `<seq>:<64 hex digits>`; only with
    /// `--file`.
    #[arg(long, value_name = "SEQ:HASH", requires = "file", value_parser = parse_head)]
    pub from: Option<ChainHead>,
}

/// The log format of an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum FormatArg {
    /// One JSON object per line; verifies with `tenko audit verify --file`.
    #[default]
    Json,
    /// RFC 5424 syslog lines.
    Rfc5424,
    /// `ArcSight` Common Event Format.
    Cef,
}

impl FormatArg {
    const fn format(self) -> ExportFormat {
        match self {
            Self::Json => ExportFormat::Json,
            Self::Rfc5424 => ExportFormat::Rfc5424,
            Self::Cef => ExportFormat::Cef,
        }
    }
}

/// Arguments of `tenko audit export`.
#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,

    /// The first sequence number to export.
    #[arg(
        long,
        value_name = "SEQ",
        default_value_t = 1,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub from: u64,

    /// The log format.
    #[arg(long, value_enum, default_value_t = FormatArg::Json)]
    pub format: FormatArg,

    /// Write to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Replace `--output` when it exists.
    #[arg(long, requires = "output")]
    pub force: bool,
}

/// Parses `<seq>:<hash>` with a hash of 64 hexadecimal digits in either case.
fn parse_head(text: &str) -> Result<ChainHead, String> {
    let (seq, hash) = text
        .split_once(':')
        .ok_or_else(|| "expected <seq>:<64 hex digits>".to_owned())?;
    let seq = u64::from_str(seq).map_err(|_| format!("`{seq}` is not a sequence number"))?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the hash must have 64 hexadecimal digits".to_owned());
    }
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(hash.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).map_err(|_| "the hash is not ASCII".to_owned())?;
        *byte = u8::from_str_radix(digits, 16).map_err(|error| error.to_string())?;
    }
    Ok(ChainHead {
        seq: AuditSeq(seq),
        hash: Digest(bytes),
    })
}

/// Runs `tenko audit verify` against the controller.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn verify(args: &VerifyArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let report = target.connect().await?.audit_verify().await?;
    let mut output = if target.json {
        Output::json(&report)
    } else if report.intact {
        Output::text(format!(
            "audit chain intact: {} record(s) verified, head {} ({}) at revision {}\n",
            report.checked, report.head.seq, report.head.hash, report.revision
        ))
    } else {
        let text = match &report.first_break {
            Some(broken) => format!(
                "audit chain BROKEN at record {} [{}]: {}; {} record(s) verified before it\n",
                broken.seq, broken.code, broken.detail, report.checked
            ),
            None => format!(
                "audit chain BROKEN: {} record(s) verified, the store reports head {}\n",
                report.checked, report.store_head
            ),
        };
        Output::text(text)
    };
    if !report.intact {
        output.status = exit::INTEGRITY;
    }
    Ok(output)
}

/// Runs `tenko audit verify --file`: no server and no login.
///
/// # Errors
///
/// The file cannot be read (exit status 1).
pub fn verify_file(path: &Path, from: Option<ChainHead>, json: bool) -> Result<Output, Failure> {
    let file = File::open(path)
        .map_err(|error| Failure::other(format!("cannot read {}: {error}", path.display())))?;
    let report = verify_lines(BufReader::new(file), from)
        .map_err(|error| Failure::other(format!("cannot read {}: {error}", path.display())))?;
    let mut output = if json {
        Output::json(&report)
    } else {
        Output::text(describe(&report))
    };
    if !report.intact {
        output.status = exit::INTEGRITY;
    }
    Ok(output)
}

fn anchor_text(anchor: Anchor) -> &'static str {
    match anchor {
        Anchor::None => "the file holds no record",
        Anchor::Start => "anchored at the start of the log",
        Anchor::Given => "anchored at the head given with --from",
        Anchor::Checkpoint => "anchored at the first checkpoint",
        Anchor::Unanchored => "start not anchored",
    }
}

fn describe(report: &VerifyReport) -> String {
    if let Some(problem) = &report.problem {
        return format!(
            "export BROKEN at line {} [{}]: {}; {} record(s) verified before it\n",
            problem.line, problem.code, problem.detail, report.records
        );
    }
    let first = report
        .first
        .map_or_else(|| "-".to_owned(), |first| first.to_string());
    let mut text = format!(
        "export intact: {} record(s) verified from {first} to {} ({}), {} duplicate(s), {} checkpoint(s)\n",
        report.records,
        report.head.seq,
        anchor_text(report.anchor),
        report.duplicates,
        report.checkpoints
    );
    if report.anchor == Anchor::Unanchored {
        text.push_str(
            "warning: the start is not anchored: nothing confirms the hash before the first \
             record; pass --from <seq>:<hash> or export from a checkpoint\n",
        );
    }
    text
}

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSummary {
    /// Records written.
    pub records: u64,
    /// The first record written.
    pub first: Option<AuditSeq>,
    /// The last record written.
    pub last: Option<AuditSeq>,
}

/// Runs `tenko audit export`.
///
/// # Errors
///
/// The [`Failure`] of a request, of the file, or of a log that does not continue.
pub async fn export(args: &ExportArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let client = target.client()?;
    let format = args.format.format();
    let Some(path) = &args.output else {
        let mut buffer = Vec::new();
        let summary = export_pages(&client, format, args.from, PAGE, &mut buffer).await?;
        let text = String::from_utf8(buffer).map_err(Failure::other)?;
        return Ok(Output::text(text).note(summary_line(&summary, None)));
    };
    if !args.force && path.exists() {
        return Err(Failure::new(
            exit::USAGE,
            format!(
                "{} exists: choose another --output or pass --force",
                path.display()
            ),
        ));
    }
    let temporary = temporary_path(path);
    let result = write_file(&client, format, args.from, &temporary, path).await;
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    let summary = result?;
    if target.json {
        #[derive(Serialize)]
        struct Written<'a> {
            #[serde(flatten)]
            summary: &'a ExportSummary,
            path: String,
        }
        return Ok(Output::json(&Written {
            summary: &summary,
            path: path.display().to_string(),
        }));
    }
    Ok(Output::text(format!(
        "{}\n",
        summary_line(&summary, Some(path))
    )))
}

async fn write_file(
    client: &Client,
    format: ExportFormat,
    from: u64,
    temporary: &Path,
    path: &Path,
) -> Result<ExportSummary, Failure> {
    let io_error =
        |error: std::io::Error| Failure::other(format!("cannot write {}: {error}", path.display()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(io_error)?;
    let mut writer = std::io::BufWriter::new(file);
    let summary = export_pages(client, format, from, PAGE, &mut writer).await?;
    writer.flush().map_err(io_error)?;
    drop(writer);
    fs::rename(temporary, path).map_err(io_error)?;
    Ok(summary)
}

/// A name for the temporary file next to `path`.
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

fn summary_line(summary: &ExportSummary, path: Option<&Path>) -> String {
    let range = match (summary.first, summary.last) {
        (Some(first), Some(last)) => format!(", sequence {first} to {last}"),
        _ => String::new(),
    };
    let to = path.map_or_else(String::new, |path| format!(" to {}", path.display()));
    format!("exported {} record(s){range}{to}", summary.records)
}

/// Writes one rendered event as a line.
fn put(
    out: &mut impl Write,
    format: ExportFormat,
    origin: &Origin,
    event: &Event<'_>,
) -> Result<(), Failure> {
    let mut line = render(format, Framing::File, origin, event).map_err(Failure::other)?;
    line.push(b'\n');
    out.write_all(&line)
        .map_err(|error| Failure::other(format!("cannot write the export: {error}")))
}

/// Pages through the export endpoint from `from` to the end of the log as of the first page
/// and writes the lines to `out`.
async fn export_pages(
    client: &Client,
    format: ExportFormat,
    from: u64,
    page_size: u32,
    out: &mut impl Write,
) -> Result<ExportSummary, Failure> {
    let origin = Origin {
        hostname: "-".to_owned(),
        version: crate::version().to_owned(),
        sink: "cli".to_owned(),
    };
    let mut summary = ExportSummary {
        records: 0,
        first: None,
        last: None,
    };
    let mut next = Some(from);
    let mut end = None;
    let mut tail: Option<ChainHead> = None;
    let mut since_checkpoint = 0u64;
    let mut store_head = AuditSeq::NONE;
    while let Some(from) = next.take() {
        let query = AuditExportQuery {
            from: Some(from),
            limit: Some(page_size),
        };
        let page: AuditExportPage = client.get_query("/audit/export", &query).await?;
        let end = *end.get_or_insert(page.store_head);
        if tail.is_none() {
            store_head = page.store_head;
            let checkpoint = Checkpoint {
                head: page.anchor,
                store_head,
                at: Timestamp::now(),
            };
            put(out, format, &origin, &Event::Checkpoint(&checkpoint))?;
            tail = Some(page.anchor);
        }
        for record in page.records.iter().take_while(|record| record.seq <= end) {
            let expected = tail.map_or(AuditSeq(from), |head| head.seq.next());
            let linked = tail.is_none_or(|head| head.hash == record.prev);
            if record.seq != expected || !linked {
                return Err(Failure::other(format!(
                    "the server's audit log does not continue at record {}",
                    record.seq
                )));
            }
            put(out, format, &origin, &Event::Record(record))?;
            tail = Some(ChainHead {
                seq: record.seq,
                hash: record.hash,
            });
            summary.first.get_or_insert(record.seq);
            summary.last = Some(record.seq);
            summary.records += 1;
            since_checkpoint += 1;
            if since_checkpoint == CHECKPOINT_EVERY {
                since_checkpoint = 0;
                checkpoint_at(out, format, &origin, tail, store_head)?;
            }
        }
        if let Some(after) = page.next {
            if after.0 <= from {
                return Err(Failure::other(format!(
                    "GET /audit/export: the next page starts at {after}, not after {from}"
                )));
            }
            if after.0 <= end.0 {
                next = Some(after.0);
            }
        }
    }
    if since_checkpoint > 0 {
        checkpoint_at(out, format, &origin, tail, store_head)?;
    }
    Ok(summary)
}

fn checkpoint_at(
    out: &mut impl Write,
    format: ExportFormat,
    origin: &Origin,
    head: Option<ChainHead>,
    store_head: AuditSeq,
) -> Result<(), Failure> {
    let checkpoint = Checkpoint {
        head: head.unwrap_or_default(),
        store_head,
        at: Timestamp::now(),
    };
    put(out, format, origin, &Event::Checkpoint(&checkpoint))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_api::client::ClientConfig;
    use tenko_core::{
        Principal, Revision, SystemComponent,
        audit::{AuditAction, AuditDraft, AuditRecord},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::*;
    use crate::{Cli, execute};

    const HASH: &str = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef";

    fn chain(count: u64) -> Vec<AuditRecord> {
        let mut records: Vec<AuditRecord> = Vec::new();
        for seq in 1..=count {
            let prev = records.last().map_or(Digest::ZERO, |record| record.hash);
            let draft =
                AuditDraft::success(AuditAction::from_static("ipam.host.create"), Vec::new())
                    .with_context("name", format!("host{seq}.example.test"));
            records.push(
                AuditRecord::seal(
                    AuditSeq(seq),
                    Revision(seq),
                    Timestamp::now(),
                    Principal::system(SystemComponent::Ipam),
                    None,
                    draft,
                    prev,
                )
                .expect("seals"),
            );
        }
        records
    }

    fn origin() -> Origin {
        Origin {
            hostname: "-".to_owned(),
            version: "0".to_owned(),
            sink: "cli".to_owned(),
        }
    }

    /// A JSON lines export of `records` with a leading checkpoint at `anchor`.
    fn json_export(records: &[AuditRecord], anchor: Option<ChainHead>) -> String {
        let mut text = String::new();
        let mut line = |event: &Event<'_>| {
            let bytes =
                render(ExportFormat::Json, Framing::File, &origin(), event).expect("renders");
            text.push_str(&String::from_utf8(bytes).expect("UTF-8"));
            text.push('\n');
        };
        if let Some(head) = anchor {
            line(&Event::Checkpoint(&Checkpoint {
                head,
                store_head: AuditSeq(records.len() as u64),
                at: Timestamp::now(),
            }));
        }
        for record in records {
            line(&Event::Record(record));
        }
        text
    }

    fn run(args: &[&str]) -> (u8, String, String) {
        let mut line = vec!["tenko"];
        line.extend_from_slice(args);
        let cli = <Cli as clap::Parser>::try_parse_from(line).expect("valid arguments");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = execute(&cli, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).expect("UTF-8"),
            String::from_utf8(err).expect("UTF-8"),
        )
    }

    fn parses(args: &[&str]) -> bool {
        let mut line = vec!["tenko"];
        line.extend_from_slice(args);
        <Cli as clap::Parser>::try_parse_from(line).is_ok()
    }

    #[test]
    fn heads_parse_in_either_case() {
        let head = parse_head(&format!("42:{HASH}")).expect("valid");
        assert_eq!(head.seq, AuditSeq(42));
        assert_eq!(head.hash.to_string(), HASH.to_ascii_lowercase());
        assert_eq!(
            parse_head(&format!("0:{}", "0".repeat(64))),
            Ok(ChainHead::default())
        );
    }

    #[test]
    fn bad_heads_are_refused() {
        for bad in [
            "",
            "42",
            ":abcd",
            &format!("x:{HASH}"),
            &format!("-1:{HASH}"),
            "1:abcd",
            &format!("1:{}g", &HASH[..63]),
            &format!("1:{HASH}00"),
        ] {
            assert!(parse_head(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_flags_parse() {
        assert!(parses(&["audit", "verify"]));
        assert!(parses(&["audit", "verify", "--file", "a.jsonl"]));
        assert!(parses(&[
            "audit",
            "verify",
            "--file",
            "a.jsonl",
            "--from",
            &format!("5:{HASH}")
        ]));
        assert!(!parses(&[
            "audit",
            "verify",
            "--from",
            &format!("5:{HASH}")
        ]));
        assert!(!parses(&["audit", "verify", "--file", "a", "--from", "5"]));
        assert!(parses(&["audit", "export"]));
        assert!(parses(&[
            "audit", "export", "--from", "7", "--format", "cef", "--output", "x", "--force"
        ]));
        assert!(parses(&["audit", "export", "--format", "rfc5424"]));
        assert!(!parses(&["audit", "export", "--format", "xml"]));
        assert!(!parses(&["audit", "export", "--from", "0"]));
        assert!(!parses(&["audit", "export", "--force"]));
    }

    #[test]
    fn an_intact_file_verifies_without_a_server() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        let records = chain(5);
        fs::write(&path, json_export(&records, Some(ChainHead::default()))).expect("write");
        let file = path.to_str().expect("UTF-8");
        let (status, out, err) = run(&["audit", "verify", "--file", file]);
        assert_eq!((status, err.as_str()), (exit::OK, ""));
        assert_eq!(
            out,
            "export intact: 5 record(s) verified from 1 to 5 (anchored at the first checkpoint), \
             0 duplicate(s), 1 checkpoint(s)\n"
        );
        let (status, out, _) = run(&["audit", "verify", "--file", file, "--json"]);
        assert_eq!(status, exit::OK);
        let report: serde_json::Value = serde_json::from_str(&out).expect("JSON");
        assert_eq!(report["intact"], true);
        assert_eq!(report["records"], 5);
    }

    #[test]
    fn a_file_without_anchor_warns_and_from_anchors_it() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        let records = chain(5);
        fs::write(&path, json_export(&records[2..], None)).expect("write");
        let file = path.to_str().expect("UTF-8");
        let (status, out, _) = run(&["audit", "verify", "--file", file]);
        assert_eq!(status, exit::OK);
        assert!(out.contains("start not anchored"), "{out}");
        assert!(
            out.contains("\nwarning: the start is not anchored"),
            "{out}"
        );
        let from = format!("2:{}", records[1].hash);
        let (status, out, _) = run(&["audit", "verify", "--file", file, "--from", &from]);
        assert_eq!(status, exit::OK);
        assert!(
            out.contains("anchored at the head given with --from"),
            "{out}"
        );
        assert!(!out.contains("warning"), "{out}");
        let wrong = format!("2:{}", records[0].hash);
        let (status, out, _) = run(&["audit", "verify", "--file", file, "--from", &wrong]);
        assert_eq!(status, exit::INTEGRITY, "{out}");
    }

    #[test]
    fn a_tampered_file_exits_with_the_integrity_status() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        let text = json_export(&chain(5), Some(ChainHead::default()));
        let changed = text.replacen("host3.example.test", "host9.example.test", 1);
        assert_ne!(changed, text);
        fs::write(&path, changed).expect("write");
        let (status, out, err) = run(&["audit", "verify", "--file", path.to_str().expect("UTF-8")]);
        assert_eq!(status, exit::INTEGRITY, "{err}");
        assert!(out.starts_with("export BROKEN at line "), "{out}");
        assert!(out.contains("record(s) verified before it"), "{out}");
    }

    #[test]
    fn an_unreadable_file_is_an_io_failure() {
        let dir = tempfile::tempdir().expect("dir");
        let missing = dir.path().join("missing.jsonl");
        let (status, out, err) = run(&[
            "audit",
            "verify",
            "--file",
            missing.to_str().expect("UTF-8"),
        ]);
        assert_eq!(status, exit::FAILURE);
        assert_eq!(out, "");
        assert!(err.contains("cannot read"), "{err}");
    }

    /// Serves `GET /api/v1/audit/export` over loopback from `records`.
    async fn serve(records: Vec<AuditRecord>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let records = Arc::new(records);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let records = Arc::clone(&records);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 8192];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
                    let target = request.split_whitespace().nth(1).unwrap_or("");
                    let query = target.split_once('?').map_or("", |(_, query)| query);
                    let value = |name: &str| -> usize {
                        query
                            .split('&')
                            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
                            .and_then(|value| value.parse().ok())
                            .unwrap_or(1)
                    };
                    let (from, limit) = (value("from"), value("limit"));
                    let start = from.saturating_sub(1).min(records.len());
                    let end = (start + limit).min(records.len());
                    let anchor = if start == 0 {
                        ChainHead::default()
                    } else {
                        ChainHead {
                            seq: records[start - 1].seq,
                            hash: records[start - 1].hash,
                        }
                    };
                    let page = AuditExportPage {
                        anchor,
                        records: records[start..end].to_vec(),
                        next: (end < records.len()).then(|| AuditSeq(end as u64 + 1)),
                        store_head: AuditSeq(records.len() as u64),
                    };
                    let body = serde_json::to_string(&page).expect("JSON");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        url
    }

    #[tokio::test]
    async fn an_export_pages_checkpoints_and_verifies() {
        let url = serve(chain(250)).await;
        let client = Client::new(ClientConfig::new(url)).expect("client");
        for from in [1, 60] {
            let mut buffer = Vec::new();
            let summary = export_pages(&client, ExportFormat::Json, from, 120, &mut buffer)
                .await
                .expect("exports");
            assert_eq!(summary.first, Some(AuditSeq(from)));
            assert_eq!(summary.last, Some(AuditSeq(250)));
            assert_eq!(summary.records, 251 - from);
            let report = verify_lines(buffer.as_slice(), None).expect("reads");
            assert!(report.intact, "{report:?}");
            assert_eq!(report.anchor, Anchor::Checkpoint);
            assert_eq!(report.records, 251 - from);
            assert_eq!(report.head.seq, AuditSeq(250));
            // The leading, every 100 records and the final checkpoint.
            let expected = 1 + (251 - from) / CHECKPOINT_EVERY + u64::from((251 - from) % 100 != 0);
            assert_eq!(report.checkpoints, expected);
            assert_eq!(report.after_last_checkpoint, 0);
        }
        let mut buffer = Vec::new();
        export_pages(&client, ExportFormat::Cef, 1, 5000, &mut buffer)
            .await
            .expect("exports");
        assert_eq!(
            String::from_utf8(buffer).expect("UTF-8").lines().count(),
            250 + 4
        );
    }

    #[tokio::test]
    async fn an_export_past_the_end_holds_only_the_checkpoint() {
        let url = serve(chain(3)).await;
        let client = Client::new(ClientConfig::new(url)).expect("client");
        let mut buffer = Vec::new();
        let summary = export_pages(&client, ExportFormat::Json, 4, 100, &mut buffer)
            .await
            .expect("exports");
        assert_eq!(summary.records, 0);
        assert_eq!(String::from_utf8(buffer).expect("UTF-8").lines().count(), 1);
    }

    #[test]
    fn the_temporary_file_sits_next_to_the_target() {
        let temporary = temporary_path(Path::new("/var/x/audit.jsonl"));
        assert_eq!(temporary.parent(), Some(Path::new("/var/x")));
        assert!(temporary.to_string_lossy().ends_with(".tmp"));
    }
}
