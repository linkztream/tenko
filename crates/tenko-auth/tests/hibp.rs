//! Tests of the breached-password check (IAM-04, TGL-06): range parsing, the modes of the
//! checker with fake range sources, and the offline binary fuse filter.
//!
//! The fixtures under `tests/fixtures/hibp/` were written for these tests and nothing was
//! downloaded. The range files follow the response format of the published Pwned Passwords
//! range API with padding enabled: one `SUFFIX:COUNT` entry per line, a 35-character
//! uppercase hexadecimal suffix, a colon, a decimal count, CRLF line endings, sorted, with
//! padding entries that have count 0. The suffixes of the filler entries come from the SHA-1
//! of made-up strings and the counts are illustrative; only the suffix of the SHA-1 of the
//! well-known test value `password` (`5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`) is a real
//! digest suffix, with an illustrative count. `downloader-sample.txt` has the format of the
//! corpus downloader (`SHA1HEX:COUNT`) with a handful of common test values plus four
//! entries with count 1.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tenko_auth::hibp::{
    BreachChecker, BreachMode, BreachOutcome, BuildOptions, BuildSummary, FilterError, HibpError,
    HibpFilter, HibpRangeSource, build_filter, parse_range, sha1, sha1_hex_upper,
};

const RANGE_PASSWORD: &str = include_str!("fixtures/hibp/range-5BAA6.txt");
const RANGE_CLEAN: &str = include_str!("fixtures/hibp/range-8CD81.txt");
const DOWNLOADER_SAMPLE: &str = include_str!("fixtures/hibp/downloader-sample.txt");

/// SHA-1 of `password` is `5BAA61E4...`; the fixture has its suffix with this count.
const PASSWORD: &str = "password";
const PASSWORD_COUNT: u64 = 9_545_824;
/// SHA-1 of this value is `8CD814CA...`; the fixture lists its suffix as padding (count 0).
const CLEAN_PASSWORD: &str = "tenko-fixture-clean-password";

const HEADER_LEN: usize = 88;

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

/// A deterministic 64-bit generator (`SplitMix64`) so every run sees the same keys.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn random_keys(count: usize, seed: u64) -> Vec<u64> {
    let mut stream = Stream(seed);
    (0..count).map(|_| stream.next()).collect()
}

/// A SHA-1 value whose first 8 bytes are `key`; the rest is not used by the filter.
fn digest_of_key(key: u64) -> [u8; 20] {
    let mut digest = [0_u8; 20];
    digest[..8].copy_from_slice(&key.to_be_bytes());
    digest
}

fn downloader_text(keys: &[u64], count: u64) -> String {
    let mut text = String::with_capacity(keys.len() * 50);
    for key in keys {
        writeln!(text, "{key:016X}{:024X}:{count}", key >> 40).expect("write to string");
    }
    text
}

fn try_build(text: &[u8], min_count: u64) -> Result<(Vec<u8>, BuildSummary), FilterError> {
    let mut out = Vec::new();
    let summary = build_filter(text, &mut out, &BuildOptions { min_count })?;
    Ok((out, summary))
}

fn build(text: &str, min_count: u64) -> (Vec<u8>, BuildSummary) {
    try_build(text.as_bytes(), min_count).expect("build")
}

fn build_keys(keys: &[u64]) -> (Vec<u8>, BuildSummary) {
    build(&downloader_text(keys, 5), 1)
}

fn sample_filter() -> Arc<HibpFilter> {
    let (bytes, _) = build(DOWNLOADER_SAMPLE, 1);
    Arc::new(HibpFilter::from_bytes(bytes).expect("filter"))
}

/// A path in the temporary directory that is removed when the guard drops.
struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "tenko-hibp-test-{}-{unique}-{label}.bin",
            std::process::id()
        )))
    }

    fn write(label: &str, bytes: &[u8]) -> Self {
        let file = Self::new(label);
        fs::write(&file.0, bytes).expect("write temp file");
        file
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// A fake range source serving the fixture files. It checks that it only ever receives a
/// 5-character uppercase hexadecimal prefix and records every request.
struct FakeSource {
    bodies: HashMap<&'static str, &'static str>,
    seen: Mutex<Vec<String>>,
}

impl FakeSource {
    fn new() -> Arc<Self> {
        let mut bodies = HashMap::new();
        bodies.insert("5BAA6", RANGE_PASSWORD);
        bodies.insert("8CD81", RANGE_CLEAN);
        Arc::new(Self {
            bodies,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }
}

#[async_trait]
impl HibpRangeSource for FakeSource {
    async fn range(&self, prefix: &str) -> Result<String, HibpError> {
        assert_eq!(
            prefix.len(),
            5,
            "only a 5-character prefix may reach the source"
        );
        assert!(
            prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
            "prefix must be uppercase hexadecimal: {prefix}"
        );
        self.seen.lock().expect("lock").push(prefix.to_owned());
        Ok(self.bodies.get(prefix).map_or_else(
            || "0000000000000000000000000000000000A:0\r\n".to_owned(),
            |b| (*b).to_owned(),
        ))
    }
}

/// A range source that always fails; it records its requests like [`FakeSource`].
struct FailingSource {
    seen: Mutex<Vec<String>>,
    error: HibpError,
}

impl FailingSource {
    fn new(error: HibpError) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            error,
        })
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }
}

#[async_trait]
impl HibpRangeSource for FailingSource {
    async fn range(&self, prefix: &str) -> Result<String, HibpError> {
        assert_eq!(
            prefix.len(),
            5,
            "only a 5-character prefix may reach the source"
        );
        self.seen.lock().expect("lock").push(prefix.to_owned());
        Err(self.error.clone())
    }
}

fn dynamic<T: HibpRangeSource + 'static>(source: &Arc<T>) -> Arc<dyn HibpRangeSource> {
    Arc::<T>::clone(source)
}

fn no_requests() -> Vec<String> {
    Vec::new()
}

fn unavailable() -> HibpError {
    HibpError::Unavailable("simulated outage".to_owned())
}

// ---------------------------------------------------------------------------------------
// parse_range with the fixtures
// ---------------------------------------------------------------------------------------

#[test]
fn fixtures_have_the_documented_shape() {
    for body in [RANGE_PASSWORD, RANGE_CLEAN] {
        let lines: Vec<&str> = body.split('\n').filter(|l| !l.trim().is_empty()).collect();
        assert!(lines.len() > 40);
        let mut previous = "";
        let mut padding = 0;
        for raw in &lines {
            let line = raw.trim_end_matches('\r');
            let (suffix, count) = line.split_once(':').expect("colon");
            assert_eq!(suffix.len(), 35);
            assert!(
                suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            );
            assert!(count.bytes().all(|b| b.is_ascii_digit()));
            assert!(suffix > previous, "sorted and unique");
            previous = suffix;
            padding += usize::from(count == "0");
        }
        assert!(padding >= 10, "padding entries present");
    }
}

#[test]
fn parse_range_reads_the_fixtures() {
    let hex = sha1_hex_upper(PASSWORD);
    assert_eq!(hex, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    let (prefix, suffix) = hex.split_at(5);
    assert_eq!(prefix, "5BAA6");
    assert_eq!(
        parse_range(RANGE_PASSWORD, suffix),
        Ok(Some(PASSWORD_COUNT))
    );

    // The same body with LF and with CRLF line endings, whatever the checkout produced.
    let lf = RANGE_PASSWORD.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(parse_range(&lf, suffix), Ok(Some(PASSWORD_COUNT)));
    assert_eq!(parse_range(&crlf, suffix), Ok(Some(PASSWORD_COUNT)));
    assert_eq!(
        parse_range(&crlf, &suffix.to_ascii_lowercase()),
        Ok(Some(PASSWORD_COUNT))
    );

    // Another password's suffix is a miss in this range.
    let other = sha1_hex_upper("another fake value");
    assert_eq!(parse_range(RANGE_PASSWORD, &other[5..]), Ok(None));

    // A suffix that the file lists only as padding is not found.
    let clean = sha1_hex_upper(CLEAN_PASSWORD);
    assert_eq!(&clean[..5], "8CD81");
    assert!(RANGE_CLEAN.contains(&format!("{}:0", &clean[5..])));
    assert_eq!(parse_range(RANGE_CLEAN, &clean[5..]), Ok(None));

    // A damaged body is refused even though the entry is there.
    let damaged = format!("{RANGE_PASSWORD}half a lin");
    assert_eq!(parse_range(&damaged, suffix), Err(HibpError::Malformed));
}

// ---------------------------------------------------------------------------------------
// BreachChecker
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn off_checks_nothing() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(
        BreachMode::Off,
        Some(dynamic(&source)),
        Some(sample_filter()),
    );
    assert_eq!(checker.mode(), BreachMode::Off);
    assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Clean);
    assert_eq!(source.seen(), no_requests());
}

#[tokio::test]
async fn online_asks_the_source_with_the_prefix_only() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(BreachMode::Online, Some(dynamic(&source)), None);
    assert_eq!(checker.mode(), BreachMode::Online);
    assert_eq!(
        checker.check(PASSWORD).await,
        BreachOutcome::Breached {
            count: Some(PASSWORD_COUNT)
        }
    );
    // Padding entry for the suffix, so it does not count as found.
    assert_eq!(checker.check(CLEAN_PASSWORD).await, BreachOutcome::Clean);
    // A value whose range has no entry for it.
    assert_eq!(
        checker.check("a value no fixture knows").await,
        BreachOutcome::Clean
    );

    let seen = source.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0], "5BAA6");
    assert_eq!(seen[1], "8CD81");
    for prefix in &seen {
        assert_eq!(prefix.len(), 5);
    }
    // Neither the password nor more than the prefix of any digest was handed over.
    let full = sha1_hex_upper(PASSWORD);
    assert!(
        seen.iter()
            .all(|p| p != PASSWORD && !full.eq_ignore_ascii_case(p))
    );
}

#[tokio::test]
async fn online_without_a_source_or_filter_is_unavailable() {
    let checker = BreachChecker::new(BreachMode::Online, None, None);
    assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Unavailable);
}

#[tokio::test]
async fn online_failure_without_a_filter_is_unavailable() {
    for error in [unavailable(), HibpError::Malformed] {
        let source = FailingSource::new(error);
        let checker = BreachChecker::new(BreachMode::Online, Some(dynamic(&source)), None);
        assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Unavailable);
        assert_eq!(source.seen(), ["5BAA6"]);
    }
}

#[tokio::test]
async fn online_failure_falls_back_to_the_filter() {
    let source = FailingSource::new(unavailable());
    let checker = BreachChecker::new(
        BreachMode::Online,
        Some(dynamic(&source)),
        Some(sample_filter()),
    );
    assert_eq!(
        checker.check(PASSWORD).await,
        BreachOutcome::Breached { count: None }
    );
    assert_eq!(checker.check(CLEAN_PASSWORD).await, BreachOutcome::Clean);
    assert_eq!(source.seen(), ["5BAA6", "8CD81"]);
}

#[tokio::test]
async fn online_without_a_source_uses_the_filter() {
    let checker = BreachChecker::new(BreachMode::Online, None, Some(sample_filter()));
    assert_eq!(
        checker.check("letmein").await,
        BreachOutcome::Breached { count: None }
    );
    assert_eq!(checker.check(CLEAN_PASSWORD).await, BreachOutcome::Clean);
}

#[tokio::test]
async fn online_success_does_not_consult_the_filter() {
    // The source says clean for this value while the filter would say breached.
    let source = FakeSource::new();
    let checker = BreachChecker::new(
        BreachMode::Online,
        Some(dynamic(&source)),
        Some(sample_filter()),
    );
    let outcome = checker.check("letmein").await;
    assert_eq!(outcome, BreachOutcome::Clean);
    assert_eq!(source.seen().len(), 1);
}

#[tokio::test]
async fn offline_uses_only_the_filter() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(
        BreachMode::Offline,
        Some(dynamic(&source)),
        Some(sample_filter()),
    );
    assert_eq!(checker.mode(), BreachMode::Offline);
    assert_eq!(
        checker.check(PASSWORD).await,
        BreachOutcome::Breached { count: None }
    );
    assert_eq!(
        checker.check("qwerty").await,
        BreachOutcome::Breached { count: None }
    );
    assert_eq!(checker.check(CLEAN_PASSWORD).await, BreachOutcome::Clean);
    assert_eq!(
        source.seen(),
        no_requests(),
        "offline never contacts the source"
    );
}

#[tokio::test]
async fn offline_without_a_filter_is_unavailable_even_with_a_source() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(BreachMode::Offline, Some(dynamic(&source)), None);
    assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Unavailable);
    assert_eq!(source.seen(), no_requests());
}

#[tokio::test]
async fn offline_preferred_uses_the_filter_when_present() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(
        BreachMode::OfflinePreferred,
        Some(dynamic(&source)),
        Some(sample_filter()),
    );
    assert_eq!(checker.mode(), BreachMode::OfflinePreferred);
    assert_eq!(
        checker.check(PASSWORD).await,
        BreachOutcome::Breached { count: None }
    );
    assert_eq!(checker.check(CLEAN_PASSWORD).await, BreachOutcome::Clean);
    assert_eq!(source.seen(), no_requests());
}

#[tokio::test]
async fn offline_preferred_falls_back_to_the_source_when_there_is_no_filter() {
    let source = FakeSource::new();
    let checker = BreachChecker::new(BreachMode::OfflinePreferred, Some(dynamic(&source)), None);
    assert_eq!(
        checker.check(PASSWORD).await,
        BreachOutcome::Breached {
            count: Some(PASSWORD_COUNT)
        }
    );
    assert_eq!(source.seen(), ["5BAA6"]);

    let failing = FailingSource::new(unavailable());
    let checker = BreachChecker::new(BreachMode::OfflinePreferred, Some(dynamic(&failing)), None);
    assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Unavailable);
    assert_eq!(failing.seen(), ["5BAA6"]);

    let nothing = BreachChecker::new(BreachMode::OfflinePreferred, None, None);
    assert_eq!(nothing.check(PASSWORD).await, BreachOutcome::Unavailable);
}

#[tokio::test]
async fn a_filter_read_error_is_unavailable() {
    // Build a file, open it, then cut the fingerprint array off: every lookup fails to read.
    let (bytes, _) = build(DOWNLOADER_SAMPLE, 1);
    let file = TempFile::write("truncated-after-open", &bytes);
    let filter = Arc::new(HibpFilter::open(&file.0).expect("open"));
    assert_eq!(filter.contains_password(PASSWORD), Ok(true));
    OpenOptions::new()
        .write(true)
        .open(&file.0)
        .expect("reopen")
        .set_len(HEADER_LEN as u64)
        .expect("truncate");
    assert!(matches!(
        filter.contains_password(PASSWORD),
        Err(FilterError::Io(_))
    ));

    for mode in [BreachMode::Offline, BreachMode::OfflinePreferred] {
        let source = FakeSource::new();
        let checker = BreachChecker::new(mode, Some(dynamic(&source)), Some(Arc::clone(&filter)));
        assert_eq!(
            checker.check(PASSWORD).await,
            BreachOutcome::Unavailable,
            "{mode:?}"
        );
        assert_eq!(source.seen(), no_requests(), "{mode:?}");
    }
    // Online mode: the failing source falls back to the filter, whose error ends in Unavailable.
    let failing = FailingSource::new(unavailable());
    let checker = BreachChecker::new(BreachMode::Online, Some(dynamic(&failing)), Some(filter));
    assert_eq!(checker.check(PASSWORD).await, BreachOutcome::Unavailable);
    assert_eq!(failing.seen(), ["5BAA6"]);
}

#[tokio::test]
async fn the_checker_is_shareable_across_tasks() {
    let source = FakeSource::new();
    let checker = Arc::new(BreachChecker::new(
        BreachMode::OfflinePreferred,
        Some(dynamic(&source)),
        Some(sample_filter()),
    ));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let checker = Arc::clone(&checker);
        tasks.push(tokio::spawn(async move { checker.check(PASSWORD).await }));
    }
    for task in tasks {
        assert_eq!(
            task.await.expect("task"),
            BreachOutcome::Breached { count: None }
        );
    }
}

#[cfg(feature = "online")]
#[test]
fn the_http_source_is_a_range_source() {
    let source = tenko_auth::hibp::HttpRangeSource::new().expect("client");
    let _checker = BreachChecker::new(BreachMode::Online, Some(Arc::new(source)), None);
}

// ---------------------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------------------

#[test]
fn no_false_negatives_and_a_low_false_positive_rate() {
    const MEMBERS: usize = 100_000;
    const PROBES: usize = 1_000_000;
    let keys = random_keys(MEMBERS, 0x5eed_0001);
    let (bytes, summary) = build_keys(&keys);
    assert_eq!(summary.keys, MEMBERS as u64);
    assert_eq!(summary.skipped, 0);
    assert_eq!(summary.bytes, bytes.len() as u64);
    let filter = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(filter.key_count(), MEMBERS as u64);

    for &key in &keys {
        assert!(
            filter.contains_sha1(&digest_of_key(key)).expect("lookup"),
            "member {key:016x}"
        );
    }

    let members: HashSet<u64> = keys.iter().copied().collect();
    let mut stream = Stream(0x5eed_0002);
    let mut false_positives = 0_usize;
    let mut probed = 0_usize;
    while probed < PROBES {
        let key = stream.next();
        if members.contains(&key) {
            continue;
        }
        probed += 1;
        if filter.contains_sha1(&digest_of_key(key)).expect("lookup") {
            false_positives += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let rate = false_positives as f64 / PROBES as f64;
    // About 1/65,536 = 0.0000153 is expected.
    assert!(
        rate < 0.0003,
        "false positive rate {rate} ({false_positives} of {PROBES})"
    );

    // The file is about 1.13 slots of 16 bits per key.
    #[allow(clippy::cast_precision_loss)]
    let bits_per_key = (summary.bytes - HEADER_LEN as u64) as f64 * 8.0 / MEMBERS as f64;
    assert!(
        (17.5..20.5).contains(&bits_per_key),
        "bits per key {bits_per_key}"
    );
}

#[test]
fn small_and_empty_key_sets_work() {
    for size in [0_usize, 1, 2, 3, 4, 5, 7, 10, 100, 1000] {
        let keys = random_keys(size, 77 + size as u64);
        let (bytes, summary) = build_keys(&keys);
        assert_eq!(summary.keys, size as u64, "size {size}");
        assert_eq!(summary.bytes, bytes.len() as u64, "size {size}");
        let filter = HibpFilter::from_bytes(bytes).expect("filter");
        assert_eq!(filter.key_count(), size as u64);
        assert!(filter.verify_checksum().expect("checksum"), "size {size}");
        for &key in &keys {
            assert!(
                filter.contains_sha1(&digest_of_key(key)).expect("lookup"),
                "size {size}"
            );
        }
        if size == 0 {
            // An empty set answers "not present" for everything, not for 1 in 65,536 values.
            for key in random_keys(200_000, 5) {
                assert!(!filter.contains_sha1(&digest_of_key(key)).expect("lookup"));
            }
        }
    }
}

#[test]
fn an_empty_input_is_a_valid_empty_filter() {
    let (bytes, summary) = build("", 1);
    assert_eq!(
        summary,
        BuildSummary {
            keys: 0,
            skipped: 0,
            bytes: bytes.len() as u64
        }
    );
    let filter = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(filter.key_count(), 0);
    assert_eq!(filter.contains_password(PASSWORD), Ok(false));
    assert!(filter.verify_checksum().expect("checksum"));
}

#[test]
fn duplicates_and_shared_prefixes_collapse_into_one_key() {
    let text = "\
5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:10\n\
5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:10\n\
5baa61e4c9b93f3f0000000000000000deadbeef:3\n\
B1B3773A05C0ED0176787A4F1574FF0075F7521E:2\n";
    let (bytes, summary) = build(text, 1);
    assert_eq!(summary.keys, 2, "three lines share one 8-byte prefix");
    assert_eq!(summary.skipped, 0);
    let filter = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(filter.key_count(), 2);
    assert_eq!(filter.contains_password("password"), Ok(true));
    assert_eq!(filter.contains_password("qwerty"), Ok(true));
}

#[test]
fn lines_below_min_count_are_skipped() {
    // downloader-sample.txt: ten common values (counts above 300,000) and four with count 1.
    let (bytes, summary) = build(DOWNLOADER_SAMPLE, 1);
    assert_eq!((summary.keys, summary.skipped), (14, 0));
    let everything = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(everything.min_count(), 1);
    for i in 0..4 {
        assert_eq!(
            everything.contains_password(&format!("fixture-rare-{i}")),
            Ok(true)
        );
    }

    let (bytes, summary) = build(DOWNLOADER_SAMPLE, 2);
    assert_eq!((summary.keys, summary.skipped), (10, 4));
    let common = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(common.key_count(), 10);
    assert_eq!(common.min_count(), 2);
    for word in [
        "password", "123456", "qwerty", "letmein", "dragon", "monkey", "iloveyou", "sunshine",
        "master", "welcome",
    ] {
        assert_eq!(common.contains_password(word), Ok(true), "{word}");
    }
    // These four are absent; the rate of false positives makes a hit here a 1 in 16,000
    // event, and the fixture is fixed, so the outcome does not change between runs.
    for i in 0..4 {
        assert_eq!(
            common.contains_password(&format!("fixture-rare-{i}")),
            Ok(false)
        );
    }

    let (bytes, summary) = build(DOWNLOADER_SAMPLE, 100_000_000);
    assert_eq!((summary.keys, summary.skipped), (0, 14));
    let none = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(none.key_count(), 0);
    assert_eq!(none.contains_password(PASSWORD), Ok(false));
}

#[test]
fn the_default_min_count_is_one() {
    assert_eq!(BuildOptions::default().min_count, 1);
    let text =
        "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:0\nB1B3773A05C0ED0176787A4F1574FF0075F7521E:1\n";
    let mut out = Vec::new();
    let summary = build_filter(text.as_bytes(), &mut out, &BuildOptions::default()).expect("build");
    assert_eq!(
        (summary.keys, summary.skipped),
        (1, 1),
        "count 0 is below the default"
    );
}

#[test]
fn malformed_lines_report_their_line_number() {
    let good1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:10";
    let good2 = "B1B3773A05C0ED0176787A4F1574FF0075F7521E:2";
    let cases: Vec<(String, u64)> = vec![
        (format!("{good1}\n{good2}\nnot a line\n"), 3),
        (format!("{good1}\r\n{good2}\r\nnot a line\r\n"), 3),
        ("garbage\n".to_owned(), 1),
        (format!("{good1}\n{good2}\ngarbage"), 3), // no final newline
        (format!("{good1}\n\n\n{good2}\nxx\n"), 5), // blank lines count
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD:10\n"),
            2,
        ), // 39 hex digits
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FDG:10\n"),
            2,
        ), // not hex
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8\n"),
            2,
        ), // no colon
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:\n"),
            2,
        ), // no count
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:12a\n"),
            2,
        ),
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:-3\n"),
            2,
        ),
        (
            format!("{good1}\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999999\n"),
            2,
        ),
        (
            format!("{good1}\n 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3\n"),
            2,
        ),
        (format!("{good1}\n{}\n", "A".repeat(500)), 2), // far longer than any line
    ];
    for (text, line) in cases {
        for min_count in [1, 1000] {
            // A malformed line is an error even when its count would be skipped anyway.
            assert_eq!(
                try_build(text.as_bytes(), min_count).map(|_| ()),
                Err(FilterError::Input { line }),
                "{text:?} with min_count {min_count}"
            );
        }
    }
    // Bytes that are not text are malformed input, not an I/O error.
    let mut bytes = format!("{good1}\n").into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe, 0x00, b'\n']);
    assert_eq!(
        try_build(&bytes, 1).map(|_| ()),
        Err(FilterError::Input { line: 2 })
    );
}

#[test]
fn input_order_case_and_line_endings_do_not_matter() {
    let keys = random_keys(2000, 31);
    let text = downloader_text(&keys, 3);
    let (reference, _) = build(&text, 1);

    let mut lines: Vec<&str> = text.lines().collect();
    lines.reverse();
    let reversed = lines.join("\n");
    assert_eq!(build(&reversed, 1).0, reference, "order");

    let crlf = text.replace('\n', "\r\n");
    assert_eq!(build(&crlf, 1).0, reference, "CRLF");

    let lower = text.to_ascii_lowercase();
    assert_eq!(build(&lower, 1).0, reference, "case");

    // Same input, same bytes.
    assert_eq!(build(&text, 1).0, reference, "repeatable");
}

#[test]
fn the_sample_file_and_the_hash_helpers_agree() {
    let (bytes, summary) = build(DOWNLOADER_SAMPLE, 1);
    assert_eq!(summary.keys, 14);
    let filter = HibpFilter::from_bytes(bytes).expect("filter");
    assert_eq!(filter.contains_password(PASSWORD), Ok(true));
    assert_eq!(filter.contains_sha1(&sha1(PASSWORD)), Ok(true));
    assert_eq!(filter.contains_password(CLEAN_PASSWORD), Ok(false));
    // The CRLF form of the sample builds the same filter.
    let crlf = DOWNLOADER_SAMPLE
        .replace("\r\n", "\n")
        .replace('\n', "\r\n");
    assert_eq!(build(&crlf, 1).0, build(DOWNLOADER_SAMPLE, 1).0);
}

fn valid_bytes() -> Vec<u8> {
    build(DOWNLOADER_SAMPLE, 1).0
}

#[test]
fn corrupt_files_are_refused() {
    let good = valid_bytes();
    assert!(HibpFilter::from_bytes(good.clone()).is_ok());

    let patched = |at: usize, value: u8| {
        let mut bytes = good.clone();
        bytes[at] = value;
        bytes
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("magic", patched(0, b'X')),
        ("magic last byte", patched(7, b'2')),
        ("version", patched(8, 2)),
        ("version high byte", patched(9, 1)),
        ("fingerprint bits", patched(10, 8)),
        ("key kind", patched(11, 2)),
        ("reserved", patched(12, 1)),
        ("segment length not a power of two", patched(24, 5)),
        ("segment length mask", patched(28, 0xff)),
        ("segment count length", patched(32, 1)),
        ("array length", patched(36, 0xfe)),
        ("key count beyond the table", patched(47, 0x7f)),
        ("empty", Vec::new()),
        ("shorter than the header", good[..HEADER_LEN - 1].to_vec()),
        ("header only", good[..HEADER_LEN].to_vec()),
        ("one byte short", good[..good.len() - 1].to_vec()),
    ];
    let mut longer = good.clone();
    longer.push(0);
    cases.push(("one byte too long", longer));
    let mut doubled = good.clone();
    doubled.extend_from_slice(&good[HEADER_LEN..]);
    cases.push(("array twice", doubled));

    for (label, bytes) in cases {
        let from_memory = HibpFilter::from_bytes(bytes.clone());
        assert!(
            matches!(from_memory, Err(FilterError::Format(_))),
            "from_bytes: {label}"
        );
        let file = TempFile::write("corrupt", &bytes);
        let from_file = HibpFilter::open(&file.0);
        assert!(
            matches!(from_file, Err(FilterError::Format(_))),
            "open: {label}"
        );
    }
}

#[test]
fn opening_a_missing_file_is_an_io_error() {
    let missing = TempFile::new("never-created");
    assert!(matches!(
        HibpFilter::open(&missing.0),
        Err(FilterError::Io(_))
    ));
}

#[test]
fn a_file_round_trip_answers_like_memory() {
    let keys = random_keys(1500, 0xf11e);
    let text = downloader_text(&keys, 9);

    let file = TempFile::new("round-trip");
    let summary = {
        let output = BufWriter::new(File::create(&file.0).expect("create"));
        build_filter(text.as_bytes(), output, &BuildOptions { min_count: 2 }).expect("build")
    };
    assert_eq!(summary.keys, 1500);
    assert_eq!(
        fs::metadata(&file.0).expect("metadata").len(),
        summary.bytes
    );

    let on_disk = HibpFilter::open(&file.0).expect("open");
    let in_memory = HibpFilter::from_bytes(fs::read(&file.0).expect("read")).expect("from_bytes");
    assert_eq!(on_disk.key_count(), 1500);
    assert_eq!(on_disk.key_count(), in_memory.key_count());
    assert_eq!(on_disk.min_count(), 2);

    let members: HashSet<u64> = keys.iter().copied().collect();
    for &key in &keys {
        let digest = digest_of_key(key);
        assert_eq!(on_disk.contains_sha1(&digest), Ok(true));
        assert_eq!(in_memory.contains_sha1(&digest), Ok(true));
    }
    let mut disagreements = 0;
    for key in random_keys(20_000, 0xf11f) {
        if members.contains(&key) {
            continue;
        }
        let digest = digest_of_key(key);
        let a = on_disk.contains_sha1(&digest).expect("file lookup");
        let b = in_memory.contains_sha1(&digest).expect("memory lookup");
        disagreements += usize::from(a != b);
    }
    assert_eq!(disagreements, 0, "file and memory give the same answers");
    assert_eq!(
        on_disk.contains_password(PASSWORD),
        in_memory.contains_password(PASSWORD)
    );
    assert!(on_disk.verify_checksum().expect("checksum"));
    assert!(in_memory.verify_checksum().expect("checksum"));
}

#[test]
fn a_filter_can_be_shared_between_threads() {
    let keys = random_keys(500, 3);
    let (bytes, _) = build_keys(&keys);
    let file = TempFile::write("threads", &bytes);
    let filter = Arc::new(HibpFilter::open(&file.0).expect("open"));
    let keys = Arc::new(keys);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let filter = Arc::clone(&filter);
            let keys = Arc::clone(&keys);
            std::thread::spawn(move || {
                keys.iter()
                    .all(|&key| filter.contains_sha1(&digest_of_key(key)) == Ok(true))
            })
        })
        .collect();
    for thread in threads {
        assert!(thread.join().expect("thread"));
    }
}

#[test]
fn the_checksum_detects_a_flipped_fingerprint_byte() {
    let keys = random_keys(800, 0xc5c5);
    let (bytes, _) = build_keys(&keys);

    // In memory.
    let mut flipped = bytes.clone();
    let middle = HEADER_LEN + (flipped.len() - HEADER_LEN) / 2;
    flipped[middle] ^= 0x01;
    let damaged = HibpFilter::from_bytes(flipped).expect("structure is still valid");
    assert!(!damaged.verify_checksum().expect("checksum"));

    // On disk: true, then false after the flip.
    let file = TempFile::write("checksum", &bytes);
    let filter = HibpFilter::open(&file.0).expect("open");
    assert!(filter.verify_checksum().expect("checksum"));
    {
        let mut handle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file.0)
            .expect("reopen");
        let at = (HEADER_LEN + (bytes.len() - HEADER_LEN) / 2) as u64;
        handle.seek(SeekFrom::Start(at)).expect("seek");
        handle
            .write_all(&[bytes[usize::try_from(at).expect("fits")] ^ 0x01])
            .expect("write");
        handle.flush().expect("flush");
    }
    assert!(
        !filter.verify_checksum().expect("checksum"),
        "same handle sees the change"
    );
    // The damage does not stop lookups; only the checksum tells.
    assert!(filter.contains_sha1(&digest_of_key(keys[0])).is_ok());
    let reopened = HibpFilter::open(&file.0).expect("open still validates the header only");
    assert!(!reopened.verify_checksum().expect("checksum"));
}

#[test]
fn a_changed_checksum_field_in_the_header_is_detected() {
    let mut bytes = valid_bytes();
    bytes[60] ^= 0xff;
    let filter = HibpFilter::from_bytes(bytes).expect("header fields are consistent");
    assert!(!filter.verify_checksum().expect("checksum"));
}

#[test]
fn open_reads_the_header_only() {
    // Overwrite the whole fingerprint array with garbage: open still succeeds and only the
    // checksum notices, which shows that opening does not touch the array.
    let mut bytes = valid_bytes();
    for byte in &mut bytes[HEADER_LEN..] {
        *byte = 0xa5;
    }
    let file = TempFile::write("garbage-array", &bytes);
    let filter = HibpFilter::open(&file.0).expect("open");
    assert_eq!(filter.key_count(), 14);
    assert!(!filter.verify_checksum().expect("checksum"));
}

/// A larger build to watch the construction at scale: `cargo test -p tenko-auth --release
/// --test hibp -- --ignored --nocapture`. The size can be changed with `TENKO_HIBP_KEYS`.
#[test]
#[ignore = "slow: builds a filter over millions of keys"]
fn a_large_set_builds_and_has_no_false_negatives() {
    let count: usize = std::env::var("TENKO_HIBP_KEYS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_000_000);
    let keys = random_keys(count, 0xb16);
    let started = std::time::Instant::now();
    let (bytes, summary) = build_keys(&keys);
    let built = started.elapsed();
    assert_eq!(summary.keys, count as u64);
    let filter = HibpFilter::from_bytes(bytes).expect("filter");
    assert!(
        keys.iter()
            .all(|&key| filter.contains_sha1(&digest_of_key(key)) == Ok(true))
    );
    let probes = 2_000_000_usize;
    let members: HashSet<u64> = keys.iter().copied().collect();
    let mut stream = Stream(0xb17);
    let mut hits = 0_usize;
    for _ in 0..probes {
        let key = stream.next();
        if !members.contains(&key) && filter.contains_sha1(&digest_of_key(key)) == Ok(true) {
            hits += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let rate = hits as f64 / probes as f64;
    println!(
        "{count} keys: {} bytes, built in {built:?}, false positive rate {rate}",
        summary.bytes
    );
    assert!(rate < 0.0003);
}
