//! The writer thread of the query log: drains the ring, writes segments, rotates them,
//! applies the retention and keeps the pseudonymisation keys.

use std::{
    fs, io,
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tenko_core::{
    Timestamp,
    dns::{DnsName, Rtype},
};

use super::{
    ClientField, FileLog, LogFormat, LogLine, LogSettings, MIB, RING_SLOTS, SEGMENT_PREFIX, day_of,
    dnstap,
    keys::{self, Keys, PSEUDONYM_OCTETS},
    ring::{Ring, Slot},
    segment_micros, segments,
};

/// How often the writer empties the ring.
const DRAIN_EVERY: Duration = Duration::from_millis(100);

/// How often the writer applies the retention without a new segment.
const RETENTION_EVERY: Duration = Duration::from_secs(60);

/// The shortest interval between two log lines about failed writes.
pub const ERROR_EVERY: Duration = Duration::from_secs(60);

/// How long before its segment's name an entry may have arrived (a forwarded query is
/// logged when its answer leaves): the keys of that margin are kept with the segment.
const LATE_ENTRY_MICROS: u64 = 60_000_000;

/// The running writer of a [`FileLog`].
#[derive(Debug)]
pub struct LogWriter {
    log: Arc<FileLog>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LogWriter {
    /// Creates the directory and starts the writer thread with a ring of [`RING_SLOTS`].
    ///
    /// # Errors
    ///
    /// The directory cannot be created, or the thread cannot be started.
    pub fn start(settings: LogSettings) -> io::Result<Self> {
        fs::create_dir_all(&settings.dir)?;
        Self::attach(Arc::new(FileLog::new(settings, RING_SLOTS)))
    }

    /// Starts the writer thread for a sink made with [`super::detached`] (tests choose the
    /// ring's size that way). The directory must exist.
    ///
    /// # Errors
    ///
    /// The thread cannot be started.
    #[doc(hidden)]
    pub fn attach(log: Arc<FileLog>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("dns-query-log".to_owned())
                .spawn(move || Writer::new(log.settings().clone()).run(&log, &stop))?
        };
        Ok(Self {
            log,
            stop,
            thread: Some(thread),
        })
    }

    /// The sink for the query path.
    pub fn sink(&self) -> Arc<FileLog> {
        Arc::clone(&self.log)
    }

    /// The directory of the segments.
    pub fn dir(&self) -> &Path {
        self.log.dir()
    }

    /// Writes what the ring holds, closes the segment and stops the thread.
    pub fn stop(mut self) {
        self.finish();
    }

    fn finish(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Logs a failing operation at most once per [`ERROR_EVERY`], with the count of the
/// failures it kept quiet about.
#[derive(Debug, Default)]
struct Throttle {
    last: Option<Instant>,
    quiet: u64,
}

impl Throttle {
    fn report(&mut self, what: &str, error: &io::Error, dir: &Path) {
        if self.last.is_some_and(|last| last.elapsed() < ERROR_EVERY) {
            self.quiet += 1;
            return;
        }
        tracing::warn!(
            %error,
            dir = %dir.display(),
            failures_since_last_report = self.quiet,
            "the DNS query log {what}; entries are dropped and counted until it can write again"
        );
        self.last = Some(Instant::now());
        self.quiet = 0;
    }
}

struct Segment {
    file: fs::File,
    path: PathBuf,
    name: String,
    /// Octets written to the file.
    bytes: u64,
    /// The UTC day of its first entry.
    day: u64,
}

pub(crate) struct Writer {
    settings: LogSettings,
    segment: Option<Segment>,
    keys: Keys,
    /// The bytes of the batch not yet written to the segment.
    pending: Vec<u8>,
    /// Entries in `pending`.
    pending_entries: usize,
    entry: Vec<u8>,
    message: Vec<u8>,
    scratch: Vec<u8>,
    last_retention: Option<Instant>,
    last_name: u64,
    errors: Throttle,
}

fn unix_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(u64::MAX)
}

/// The client text of a JSON line.
fn client_text(
    settings: &LogSettings,
    keys: &mut Keys,
    errors: &mut Throttle,
    client: IpAddr,
    day: u64,
) -> Option<String> {
    match settings.client {
        ClientField::Hidden => None,
        ClientField::Address => Some(client.to_canonical().to_string()),
        ClientField::Pseudonym => {
            let key = keys.key_for(day, &mut |error| {
                errors.report(
                    "cannot store its pseudonymisation key",
                    &error,
                    &settings.dir,
                );
            })?;
            Some(keys::pseudonym_text(
                &keys::tag(&key, client)[..PSEUDONYM_OCTETS],
            ))
        }
    }
}

/// The address octets of a dnstap message.
fn client_octets(
    settings: &LogSettings,
    keys: &mut Keys,
    errors: &mut Throttle,
    client: IpAddr,
    day: u64,
) -> Option<Vec<u8>> {
    let octets = dnstap::address_octets(client);
    match settings.client {
        ClientField::Hidden => None,
        ClientField::Address => Some(octets),
        ClientField::Pseudonym => {
            let key = keys.key_for(day, &mut |error| {
                errors.report(
                    "cannot store its pseudonymisation key",
                    &error,
                    &settings.dir,
                );
            })?;
            Some(keys::tag(&key, client)[..octets.len()].to_vec())
        }
    }
}

impl Writer {
    pub(crate) fn new(settings: LogSettings) -> Self {
        let keys = Keys::load(&settings.dir);
        Self {
            settings,
            segment: None,
            keys,
            pending: Vec::with_capacity(256 * 1024),
            pending_entries: 0,
            entry: Vec::with_capacity(1024),
            message: Vec::with_capacity(512),
            scratch: Vec::with_capacity(512),
            last_retention: None,
            last_name: 0,
            errors: Throttle::default(),
        }
    }

    fn run(mut self, log: &FileLog, stop: &AtomicBool) {
        if let Err(error) = recover(&self.settings.dir) {
            tracing::warn!(%error, dir = %self.settings.dir.display(), "the newest DNS query log segment could not be checked");
        }
        self.retention();
        let capacity = log
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .capacity();
        let mut spare = Ring::new(capacity);
        loop {
            let stopping = stop.load(Ordering::Relaxed);
            std::mem::swap(
                &mut *log.ring.lock().unwrap_or_else(PoisonError::into_inner),
                &mut spare,
            );
            if !spare.is_empty() {
                let batch = spare.filled();
                match self.write(batch) {
                    Ok(()) => log.wrote(batch.len()),
                    Err((error, written)) => {
                        log.wrote(written);
                        log.lost(batch.len() - written);
                        self.errors
                            .report("cannot be written", &error, &self.settings.dir);
                    }
                }
                spare.clear();
            }
            if self
                .last_retention
                .is_none_or(|last| last.elapsed() >= RETENTION_EVERY)
            {
                self.retention();
            }
            if stopping {
                self.close();
                return;
            }
            std::thread::sleep(DRAIN_EVERY);
        }
    }

    fn line_of(&mut self, slot: &Slot) -> LogLine {
        let qname = DnsName::from_wire(slot.qname())
            .map_or_else(|_| "?".to_owned(), |(name, _)| name.to_string());
        let client = client_text(
            &self.settings,
            &mut self.keys,
            &mut self.errors,
            slot.client,
            day_of(slot.at_micros),
        );
        LogLine {
            at: Timestamp::from_unix_nanos(i128::from(slot.at_micros) * 1_000)
                .unwrap_or(Timestamp::UNIX_EPOCH),
            client,
            transport: slot.transport,
            qname,
            rtype: Rtype(slot.qtype),
            rcode: slot.rcode,
            view: slot.view,
            blocked: slot.blocked,
            cached: slot.cached,
            duration_micros: slot.duration_micros,
            // WP10.1: the resolution and the engine's queries.
            resolution: slot.resolution,
            subqueries: slot.subqueries,
            // WP10.2: the validation state and the extended error.
            validation: slot.validation,
            ede: slot.ede,
        }
    }

    /// Encodes one entry into `self.entry`.
    fn encode(&mut self, slot: &Slot) {
        self.entry.clear();
        match self.settings.format {
            LogFormat::Jsonl => {
                let line = self.line_of(slot);
                // Serialising these fields cannot fail.
                let _ = serde_json::to_writer(&mut self.entry, &line);
                self.entry.push(b'\n');
            }
            LogFormat::Dnstap => self.encode_dnstap(slot),
        }
    }

    fn encode_dnstap(&mut self, slot: &Slot) {
        let address = client_octets(
            &self.settings,
            &mut self.keys,
            &mut self.errors,
            slot.client,
            day_of(slot.at_micros),
        );
        let family = match slot.client.to_canonical() {
            IpAddr::V4(_) => dnstap::family::INET,
            IpAddr::V6(_) => dnstap::family::INET6,
        };
        let answered = slot
            .at_micros
            .saturating_add(u64::from(slot.duration_micros));
        let seconds = |micros: u64| micros / 1_000_000;
        let nanos = |micros: u64| u32::try_from((micros % 1_000_000) * 1_000).unwrap_or(0);
        let identity = (!self.settings.identity.is_empty())
            .then(|| self.settings.identity.as_bytes().to_vec());
        let version =
            (!self.settings.version.is_empty()).then(|| self.settings.version.as_bytes().to_vec());
        let extra = Some(dnstap::extra(
            self.settings.client,
            slot.cached,
            slot.resolution,
            slot.subqueries,
            slot.validation,
            slot.ede,
        ));
        self.message.clear();
        dnstap::build_message(&mut self.message, slot.qname(), slot.qtype, None);
        let query = dnstap::Dnstap {
            identity: identity.clone(),
            version: version.clone(),
            extra: extra.clone(),
            kind: dnstap::DNSTAP_MESSAGE,
            message: Some(dnstap::Message {
                kind: dnstap::message_type::CLIENT_QUERY,
                socket_family: Some(family),
                socket_protocol: Some(dnstap::protocol_of(slot.transport)),
                query_address: address.clone(),
                query_time_sec: Some(seconds(slot.at_micros)),
                query_time_nsec: Some(nanos(slot.at_micros)),
                query_message: Some(self.message.clone()),
                ..dnstap::Message::default()
            }),
        };
        self.message.clear();
        dnstap::build_message(
            &mut self.message,
            slot.qname(),
            slot.qtype,
            Some(slot.rcode),
        );
        let response = dnstap::Dnstap {
            identity,
            version,
            extra,
            kind: dnstap::DNSTAP_MESSAGE,
            message: Some(dnstap::Message {
                kind: dnstap::message_type::CLIENT_RESPONSE,
                socket_family: Some(family),
                socket_protocol: Some(dnstap::protocol_of(slot.transport)),
                query_address: address,
                query_time_sec: Some(seconds(slot.at_micros)),
                query_time_nsec: Some(nanos(slot.at_micros)),
                response_time_sec: Some(seconds(answered)),
                response_time_nsec: Some(nanos(answered)),
                response_message: Some(self.message.clone()),
                ..dnstap::Message::default()
            }),
        };
        let scratch = &mut self.scratch;
        dnstap::data_frame(&mut self.entry, |out| query.encode(out, scratch));
        dnstap::data_frame(&mut self.entry, |out| response.encode(out, scratch));
    }

    /// Writes a batch; on an error, how many of its entries reached a segment.
    fn write(&mut self, batch: &[Slot]) -> Result<(), (io::Error, usize)> {
        let limit = self.settings.segment_bytes();
        let mut written = 0;
        for slot in batch {
            self.encode(slot);
            let size = u64::try_from(self.pending.len() + self.entry.len()).unwrap_or(u64::MAX);
            let day = day_of(slot.at_micros);
            let rotate = self.segment.as_ref().is_none_or(|segment| {
                day > segment.day || (segment.bytes > 0 && segment.bytes + size > limit)
            });
            if rotate {
                written += self.flush().map_err(|error| (error, written))?;
                self.close();
                self.open_segment(slot.at_micros, day)
                    .map_err(|error| (error, written))?;
            }
            self.pending.extend_from_slice(&self.entry);
            self.pending_entries += 1;
        }
        self.flush().map_err(|error| (error, written))?;
        Ok(())
    }

    /// Writes `pending` to the segment; the entries written.
    fn flush(&mut self) -> io::Result<usize> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        let Some(segment) = &mut self.segment else {
            return Err(io::Error::other("no segment is open"));
        };
        let result = segment.file.write_all(&self.pending);
        let entries = std::mem::take(&mut self.pending_entries);
        let octets = u64::try_from(self.pending.len()).unwrap_or(u64::MAX);
        self.pending.clear();
        match result {
            Ok(()) => {
                segment.bytes += octets;
                Ok(entries)
            }
            Err(error) => {
                // Cut off what part of the batch reached the file, so the segment ends
                // with whole lines or frames, and open a new one for the next batch.
                if let Some(segment) = self.segment.take() {
                    let _ = segment.file.set_len(segment.bytes);
                    drop(segment.file);
                    if self.settings.format == LogFormat::Dnstap {
                        let _ = append_stop(&segment.path);
                    }
                }
                Err(error)
            }
        }
    }

    /// Closes the open segment: a dnstap segment gets its STOP frame.
    fn close(&mut self) {
        let _ = self.flush();
        let Some(mut segment) = self.segment.take() else {
            return;
        };
        if self.settings.format == LogFormat::Dnstap {
            let mut stop = Vec::with_capacity(12);
            dnstap::stop_frame(&mut stop);
            if let Err(error) = segment.file.write_all(&stop) {
                self.errors
                    .report("cannot close a segment", &error, &self.settings.dir);
            }
        }
    }

    fn open_segment(&mut self, first_micros: u64, day: u64) -> io::Result<()> {
        let mut micros = first_micros.max(self.last_name + 1);
        let suffix = self.settings.format.suffix();
        let (file, name) = loop {
            let name = format!("{SEGMENT_PREFIX}{micros:020}{suffix}");
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.settings.dir.join(&name))
            {
                Ok(file) => break (file, name),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => micros += 1,
                Err(error) => return Err(error),
            }
        };
        self.last_name = micros;
        let mut segment = Segment {
            path: self.settings.dir.join(&name),
            file,
            name,
            bytes: 0,
            day,
        };
        if self.settings.format == LogFormat::Dnstap {
            let mut start = Vec::with_capacity(48);
            dnstap::start_frame(&mut start);
            segment.file.write_all(&start)?;
            segment.bytes = u64::try_from(start.len()).unwrap_or(u64::MAX);
        }
        self.segment = Some(segment);
        self.retention();
        Ok(())
    }

    /// Removes segments older than `days`, then the oldest beyond `size_mb`; the open
    /// segment stays. Then the keys of the days no segment holds any more.
    pub(crate) fn retention(&mut self) {
        self.last_retention = Some(Instant::now());
        let dir = &self.settings.dir;
        let Ok(mut names) = segments(dir) else {
            return;
        };
        names.sort();
        let open = self.segment.as_ref().map(|segment| segment.name.as_str());
        let max_age = Duration::from_secs(u64::from(self.settings.days) * 86_400);
        let size_of = |name: &str| fs::metadata(dir.join(name)).map_or(0, |meta| meta.len());
        let mut kept = Vec::with_capacity(names.len());
        for name in names {
            let old = Some(name.as_str()) != open
                && fs::metadata(dir.join(&name))
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age > max_age);
            if old {
                let _ = fs::remove_file(dir.join(&name));
            } else {
                kept.push(name);
            }
        }
        let mut total: u64 = kept.iter().map(|name| size_of(name)).sum();
        let limit = self.settings.size_mb.saturating_mul(MIB);
        let mut left = Vec::with_capacity(kept.len());
        for name in kept {
            if total > limit && Some(name.as_str()) != open {
                total = total.saturating_sub(size_of(&name));
                let _ = fs::remove_file(dir.join(&name));
            } else {
                left.push(name);
            }
        }
        let today = day_of(unix_micros());
        let oldest = left
            .iter()
            .filter_map(|name| segment_micros(name))
            .min()
            .map_or(today, |micros| {
                day_of(micros.saturating_sub(LATE_ENTRY_MICROS)).min(today)
            });
        if let Err(error) = self.keys.retain_from(oldest) {
            self.errors
                .report("cannot store its pseudonymisation keys", &error, dir);
        }
    }
}

/// Appends a STOP frame to a dnstap segment.
fn append_stop(path: &Path) -> io::Result<()> {
    let mut stop = Vec::with_capacity(12);
    dnstap::stop_frame(&mut stop);
    fs::OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(&stop)
}

/// Cuts an unfinished tail off the newest segment (the process stopped in the middle of
/// a write): a JSON-lines segment ends after its last newline, a dnstap segment after its
/// last whole frame, with a STOP frame. A segment left with nothing whole is removed.
pub(crate) fn recover(dir: &Path) -> io::Result<()> {
    let names = match segments(dir) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(newest) = names.into_iter().max() else {
        return Ok(());
    };
    let path = dir.join(&newest);
    let bytes = fs::read(&path)?;
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    match LogFormat::of_segment(&newest) {
        Some(LogFormat::Jsonl) => {
            let whole = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |at| at + 1);
            if whole == 0 && !bytes.is_empty() {
                fs::remove_file(&path)?;
            } else if whole < bytes.len() {
                tracing::warn!(segment = %path.display(), cut = bytes.len() - whole, "the newest DNS query log segment ended in an unfinished line, which was cut off");
                fs::OpenOptions::new()
                    .write(true)
                    .open(&path)?
                    .set_len(u64::try_from(whole).unwrap_or(length))?;
            }
        }
        Some(LogFormat::Dnstap) => {
            let (frames, whole) = dnstap::frames(&bytes);
            let started = matches!(
                frames.first(),
                Some((_, dnstap::Frame::Control { kind, .. })) if *kind == dnstap::control::START
            );
            if !started {
                tracing::warn!(segment = %path.display(), "the newest DNS query log segment has no START frame and was removed");
                fs::remove_file(&path)?;
                return Ok(());
            }
            let stopped = matches!(
                frames.last(),
                Some((_, dnstap::Frame::Control { kind, .. })) if *kind == dnstap::control::STOP
            );
            if whole < bytes.len() {
                tracing::warn!(segment = %path.display(), cut = bytes.len() - whole, "the newest DNS query log segment ended in an unfinished frame, which was cut off");
                fs::OpenOptions::new()
                    .write(true)
                    .open(&path)?
                    .set_len(u64::try_from(whole).unwrap_or(length))?;
            }
            if !stopped {
                append_stop(&path)?;
            }
        }
        None => {}
    }
    Ok(())
}
