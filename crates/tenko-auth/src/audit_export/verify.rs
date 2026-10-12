//! Offline verification of a JSON export (`tenko audit verify --file`, IAM-18).
//!
//! The lines are read in order. Every record line must carry canonical bytes that hash to
//! its `hash` and encode its fields ([`parse_line`]), and the records must form the
//! chain: consecutive sequence numbers, each linked to its predecessor. The chain starts
//! at the first of:
//!
//! - the head given with `--from <seq>:<hash>`, which the file must continue;
//! - the first checkpoint line, which a sink writes when it connects and at the top of
//!   every rotated file;
//! - record 1;
//! - otherwise the first record's own `prev`; the report then says the start is not
//!   anchored.
//!
//! Records at or below the verified head are duplicates (a sink resends after a
//! reconnect or a leader change): each must equal the record verified before under that
//! number, within the last [`DUPLICATE_WINDOW`] records. A checkpoint must name a
//! position of the verified chain. The first problem ends the verification.

use std::{
    collections::VecDeque,
    io::{self, BufRead},
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    AuditSeq, Coded,
    audit::{ChainHead, ChainVerifier, Digest},
};

use super::format::json::{Line, LineError, MAX_LINE, parse_line};

/// How many recent records a duplicate may repeat.
pub const DUPLICATE_WINDOW: usize = 100_000;

/// Where the verified chain starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchor {
    /// The file holds no record and no checkpoint.
    None,
    /// At record 1.
    Start,
    /// At the head given on the command line.
    Given,
    /// At the first checkpoint of the file.
    Checkpoint,
    /// At the first record's `prev`, which nothing confirms.
    Unanchored,
}

/// The first problem found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyProblem {
    /// The line, from 1.
    pub line: u64,
    /// A stable code: `sys.audit.gap`, `sys.audit.broken_link`, `sys.audit.bad_hash`, or
    /// one of `audit.export.verify.*`.
    pub code: String,
    /// An English description.
    pub detail: String,
}

/// The result of a verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Whether every line verified.
    pub intact: bool,
    /// Where the chain starts.
    pub anchor: Anchor,
    /// The first verified record.
    pub first: Option<AuditSeq>,
    /// The last verified position.
    pub head: ChainHead,
    /// Distinct records verified.
    pub records: u64,
    /// Repeated records that matched.
    pub duplicates: u64,
    /// Records before the given head that were skipped.
    pub skipped: u64,
    /// Checkpoint lines.
    pub checkpoints: u64,
    /// Test lines.
    pub tests: u64,
    /// The last checkpoint: the position it names and the newest record of the log then.
    pub last_checkpoint: Option<(ChainHead, AuditSeq)>,
    /// Records verified after the last checkpoint; a truncated tail is only visible
    /// against a later checkpoint or the live log.
    pub after_last_checkpoint: u64,
    /// The problem, when not intact.
    pub problem: Option<VerifyProblem>,
}

/// Verifies the lines of `reader`. `from` is a trusted head the file continues.
///
/// # Errors
///
/// The reader's I/O error.
pub fn verify_lines<R: BufRead>(reader: R, from: Option<ChainHead>) -> io::Result<VerifyReport> {
    let mut state = State::new(from);
    let mut number = 0u64;
    let mut reader = reader;
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = read_line(&mut reader, &mut buffer)?;
        if read == 0 {
            break;
        }
        number += 1;
        if let Err(problem) = state.line(number, &buffer) {
            state.report.problem = Some(problem);
            break;
        }
    }
    let mut report = state.report;
    report.intact = report.problem.is_none();
    Ok(report)
}

/// Reads one line of at most [`MAX_LINE`] bytes (plus its end); longer lines are cut, so
/// that they fail as malformed without exhausting memory.
fn read_line<R: BufRead>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }
        let (take, done) = match available.iter().position(|&b| b == b'\n') {
            Some(end) => (end + 1, true),
            None => (available.len(), false),
        };
        let room = (MAX_LINE + 2).saturating_sub(out.len());
        out.extend_from_slice(&available[..take.min(room)]);
        reader.consume(take);
        total += take;
        if done {
            return Ok(total);
        }
    }
}

struct State {
    verifier: Option<ChainVerifier>,
    recent: VecDeque<(AuditSeq, Digest)>,
    given: Option<ChainHead>,
    report: VerifyReport,
}

fn problem(line: u64, code: &str, detail: impl Into<String>) -> VerifyProblem {
    VerifyProblem {
        line,
        code: code.to_owned(),
        detail: detail.into(),
    }
}

impl State {
    fn new(from: Option<ChainHead>) -> Self {
        let mut state = Self {
            verifier: None,
            recent: VecDeque::new(),
            given: from,
            report: VerifyReport {
                intact: true,
                anchor: Anchor::None,
                first: None,
                head: ChainHead::default(),
                records: 0,
                duplicates: 0,
                skipped: 0,
                checkpoints: 0,
                tests: 0,
                last_checkpoint: None,
                after_last_checkpoint: 0,
                problem: None,
            },
        };
        if let Some(head) = from {
            state.anchor(head, Anchor::Given);
        }
        state
    }

    fn anchor(&mut self, head: ChainHead, anchor: Anchor) {
        self.verifier = Some(ChainVerifier::resume(head));
        self.report.anchor = anchor;
        self.report.head = head;
        self.remember(head);
    }

    fn remember(&mut self, head: ChainHead) {
        if self.recent.len() == DUPLICATE_WINDOW {
            self.recent.pop_front();
        }
        self.recent.push_back((head.seq, head.hash));
    }

    /// The hash remembered for `seq`, if it is still in the window.
    fn known(&self, seq: AuditSeq) -> Option<Digest> {
        let (first, _) = self.recent.front()?;
        let index = usize::try_from(seq.0.checked_sub(first.0)?).ok()?;
        self.recent
            .get(index)
            .filter(|(at, _)| *at == seq)
            .map(|(_, hash)| *hash)
    }

    fn line(&mut self, number: u64, bytes: &[u8]) -> Result<(), VerifyProblem> {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| {
            problem(
                number,
                "audit.export.verify.malformed",
                "the line is not UTF-8",
            )
        })?;
        let line = parse_line(text).map_err(|error| {
            let code = match error {
                LineError::TooLong | LineError::Malformed(_) => "audit.export.verify.malformed",
                LineError::Base64(_) | LineError::CborHash(_) | LineError::CborFields(_) => {
                    "audit.export.verify.cbor"
                }
            };
            problem(number, code, error.to_string())
        })?;
        match line {
            Line::Test(_) => self.report.tests += 1,
            Line::Checkpoint(checkpoint) => {
                let head = ChainHead {
                    seq: checkpoint.seq,
                    hash: checkpoint.hash,
                };
                self.checkpoint(number, head)?;
                self.report.checkpoints += 1;
                self.report.last_checkpoint = Some((head, checkpoint.store_head));
                self.report.after_last_checkpoint = 0;
            }
            Line::Record(line) => {
                let record = line.record;
                let head = ChainHead {
                    seq: record.seq,
                    hash: record.hash,
                };
                if self.verifier.is_none() {
                    let start = ChainHead {
                        seq: AuditSeq(record.seq.0.saturating_sub(1)),
                        hash: record.prev,
                    };
                    let anchor = if record.seq == AuditSeq(1) {
                        Anchor::Start
                    } else {
                        Anchor::Unanchored
                    };
                    self.anchor(start, anchor);
                }
                let current = self.report.head;
                if record.seq <= current.seq {
                    return self.repeated(number, head);
                }
                let verifier = self.verifier.as_mut().expect("anchored above");
                verifier
                    .push(&record)
                    .map_err(|error| problem(number, error.code(), error.to_string()))?;
                self.report.head = head;
                self.report.first.get_or_insert(record.seq);
                self.report.records += 1;
                self.report.after_last_checkpoint += 1;
                self.remember(head);
            }
        }
        Ok(())
    }

    fn checkpoint(&mut self, number: u64, head: ChainHead) -> Result<(), VerifyProblem> {
        if self.verifier.is_none() {
            self.anchor(head, Anchor::Checkpoint);
            return Ok(());
        }
        let current = self.report.head;
        let matches = match head.seq.cmp(&current.seq) {
            std::cmp::Ordering::Equal => head.hash == current.hash,
            std::cmp::Ordering::Less => {
                self.known(head.seq) == Some(head.hash)
                    || (head.seq == AuditSeq::NONE && head.hash == Digest::ZERO)
            }
            std::cmp::Ordering::Greater => false,
        };
        if matches {
            Ok(())
        } else {
            Err(problem(
                number,
                "audit.export.verify.checkpoint",
                format!(
                    "the checkpoint names record {} ({}), which is not part of the verified chain ending at {}",
                    head.seq, head.hash, current.seq
                ),
            ))
        }
    }

    fn repeated(&mut self, number: u64, head: ChainHead) -> Result<(), VerifyProblem> {
        if self.report.anchor == Anchor::Given && self.report.records == 0 {
            let given = self.given.unwrap_or_default();
            if head.seq < given.seq {
                self.report.skipped += 1;
                return Ok(());
            }
        }
        match self.known(head.seq) {
            Some(hash) if hash == head.hash => {
                self.report.duplicates += 1;
                Ok(())
            }
            Some(_) => Err(problem(
                number,
                "audit.export.verify.duplicate",
                format!(
                    "record {} repeats with another hash than the record verified before",
                    head.seq
                ),
            )),
            None => Err(problem(
                number,
                "audit.export.verify.duplicate",
                format!(
                    "record {} repeats a record that is not among the last {DUPLICATE_WINDOW} verified",
                    head.seq
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tenko_core::audit::AuditRecord;

    use super::super::format::{
        Checkpoint, Event, json,
        tests::{chain, origin},
    };
    use super::*;

    fn record_line(record: &AuditRecord) -> String {
        json::render(&origin(), &Event::Record(record)).expect("renders")
    }

    fn checkpoint_line(head: ChainHead, store_head: u64) -> String {
        let checkpoint = Checkpoint {
            head,
            store_head: AuditSeq(store_head),
            at: "2026-10-11T12:00:00Z".parse().expect("time"),
        };
        json::render(&origin(), &Event::Checkpoint(&checkpoint)).expect("renders")
    }

    fn head_of(record: &AuditRecord) -> ChainHead {
        ChainHead {
            seq: record.seq,
            hash: record.hash,
        }
    }

    fn verify(lines: &[String], from: Option<ChainHead>) -> VerifyReport {
        verify_lines(Cursor::new(lines.join("\n")), from).expect("reads")
    }

    #[test]
    fn a_whole_export_verifies() {
        let records = chain(5);
        let mut lines = vec![checkpoint_line(ChainHead::default(), 5)];
        lines.extend(records.iter().map(record_line));
        lines.push(checkpoint_line(head_of(&records[4]), 5));
        lines.push(String::new());
        let report = verify(&lines, None);
        assert!(report.intact, "{report:?}");
        assert_eq!(report.anchor, Anchor::Checkpoint);
        assert_eq!(report.records, 5);
        assert_eq!(report.checkpoints, 2);
        assert_eq!(report.head, head_of(&records[4]));
        assert_eq!(report.first, Some(AuditSeq(1)));
        assert_eq!(report.after_last_checkpoint, 0);
    }

    #[test]
    fn a_changed_record_is_found() {
        let records = chain(3);
        let mut lines: Vec<String> = records.iter().map(record_line).collect();
        let mut value: serde_json::Value = serde_json::from_str(&lines[1]).expect("json");
        value["draft"]["details"]["context"]["note"] = serde_json::json!("changed");
        lines[1] = value.to_string();
        let report = verify(&lines, None);
        assert!(!report.intact);
        let problem = report.problem.expect("problem");
        assert_eq!(problem.line, 2);
        assert_eq!(problem.code, "audit.export.verify.cbor");
        assert_eq!(report.records, 1);
    }

    #[test]
    fn a_resealed_record_breaks_the_chain() {
        let records = chain(3);
        let forged = AuditRecord::seal(
            records[1].seq,
            records[1].revision,
            records[1].at,
            records[1].principal.clone(),
            records[1].request,
            records[1].draft.clone(),
            Digest([9; 32]),
        )
        .expect("seal");
        let lines = vec![
            record_line(&records[0]),
            record_line(&forged),
            record_line(&records[2]),
        ];
        let report = verify(&lines, None);
        assert_eq!(
            report.problem.expect("problem").code,
            "sys.audit.broken_link"
        );
    }

    #[test]
    fn gaps_and_wrong_checkpoints_are_found() {
        let records = chain(4);
        let lines = vec![record_line(&records[0]), record_line(&records[2])];
        assert_eq!(
            verify(&lines, None).problem.expect("gap").code,
            "sys.audit.gap"
        );
        let lines = vec![
            record_line(&records[0]),
            checkpoint_line(head_of(&records[2]), 4),
        ];
        assert_eq!(
            verify(&lines, None).problem.expect("checkpoint").code,
            "audit.export.verify.checkpoint"
        );
        let lines = vec![
            checkpoint_line(head_of(&records[0]), 4),
            record_line(&records[2]),
        ];
        assert_eq!(
            verify(&lines, None).problem.expect("gap").code,
            "sys.audit.gap"
        );
    }

    #[test]
    fn duplicates_after_a_reconnect_are_accepted() {
        let records = chain(5);
        let mut lines: Vec<String> = records[..4].iter().map(record_line).collect();
        lines.push(checkpoint_line(head_of(&records[1]), 5));
        lines.extend(records[2..].iter().map(record_line));
        let report = verify(&lines, None);
        assert!(report.intact, "{report:?}");
        assert_eq!(report.records, 5);
        assert_eq!(report.duplicates, 2);

        let other = chain(3);
        let mut lines: Vec<String> = records[..3].iter().map(record_line).collect();
        lines.push(record_line(&other[1]));
        assert_eq!(
            verify(&lines, None).problem.expect("mismatch").code,
            "audit.export.verify.duplicate"
        );
    }

    #[test]
    fn a_given_head_anchors_the_file() {
        let records = chain(4);
        let lines: Vec<String> = records.iter().map(record_line).collect();
        let report = verify(&lines, Some(head_of(&records[1])));
        assert!(report.intact, "{report:?}");
        assert_eq!(report.anchor, Anchor::Given);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.records, 2);
        let wrong = ChainHead {
            seq: AuditSeq(2),
            hash: Digest([3; 32]),
        };
        let report = verify(&lines[2..], Some(wrong));
        assert_eq!(report.problem.expect("link").code, "sys.audit.broken_link");
    }

    #[test]
    fn a_rotated_file_without_checkpoint_is_unanchored() {
        let records = chain(4);
        let lines: Vec<String> = records[2..].iter().map(record_line).collect();
        let report = verify(&lines, None);
        assert!(report.intact);
        assert_eq!(report.anchor, Anchor::Unanchored);
        assert_eq!(report.first, Some(AuditSeq(3)));
    }

    #[test]
    fn garbage_and_empty_input() {
        let report = verify(&[], None);
        assert!(report.intact);
        assert_eq!(report.anchor, Anchor::None);
        let report = verify(&["{\"type\":\"record\"}".to_owned()], None);
        assert_eq!(
            report.problem.expect("malformed").code,
            "audit.export.verify.malformed"
        );
        let long = "x".repeat(MAX_LINE + 10);
        let report = verify(&[long], None);
        assert_eq!(
            report.problem.expect("long").code,
            "audit.export.verify.malformed"
        );
        let report = verify_lines(Cursor::new(vec![0xff, 0xfe, b'\n']), None).expect("reads");
        assert_eq!(
            report.problem.expect("utf8").code,
            "audit.export.verify.malformed"
        );
    }
}
