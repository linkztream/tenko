//! The figures of the blocking view (`docs/dns.md`, "Blocking view"): the queries of a time
//! window counted from the node's query log, in total and blocked, per block list, per
//! client, per bucket of time (an hour), the busiest blocked and asked names, and the
//! newest blocked queries.
//!
//! The window is read newest first and at most [`MAX_STATS_BYTES`] of segments are looked
//! at; a log that holds more in the window answers the newest part with `truncated` set. A
//! client is counted as the log keeps it: its address, its pseudonym of the day (so one
//! client counts once per day), or not at all.

use std::{collections::HashMap, fs, io, path::Path};

use serde::{Deserialize, Serialize};
use tenko_core::{Timestamp, dns::BlockListId};

use super::{
    LogFormat, LogLine,
    read::{ReadError, decode, micros_of, records},
    segment_micros, segments,
};

/// The segment octets one computation looks at, at most.
pub const MAX_STATS_BYTES: u64 = 512 * 1024 * 1024;

/// The most buckets a window is cut into.
pub const MAX_BUCKETS: usize = 400;

/// The most names and clients in each top list.
pub const MAX_TOP: u32 = 100;

/// The newest blocked queries kept.
pub const RECENT_BLOCKED: usize = 50;

/// How long before its segment's name an entry may have arrived (as the reader).
const LATE_MICROS: u64 = 60_000_000;

/// The arguments of `dns.blocking.stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsArgs {
    /// The start of the window.
    pub from: Timestamp,
    /// The end of the window.
    pub until: Timestamp,
    /// The length of a bucket in seconds (3,600: an hour).
    pub bucket_secs: u32,
    /// The length of each top list (1 to [`MAX_TOP`]).
    pub top: u32,
}

/// The queries of one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    /// The start of the bucket.
    pub start: Timestamp,
    /// Queries.
    pub queries: u64,
    /// Queries a block list blocked.
    pub blocked: u64,
}

/// A name or a client with its count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Count {
    /// The query name, or the client (an address or a pseudonym).
    pub key: String,
    /// Queries.
    pub queries: u64,
    /// Of them blocked.
    pub blocked: u64,
}

/// The figures of a window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockingStats {
    /// Queries logged in the window.
    pub queries: u64,
    /// Of them blocked by a block list.
    pub blocked: u64,
    /// Of them answered from the cache.
    pub cached: u64,
    /// Distinct clients (as the log keeps them).
    pub clients: u64,
    /// The buckets, oldest first.
    pub buckets: Vec<Bucket>,
    /// The blocked queries per list, the busiest first.
    pub lists: Vec<(BlockListId, u64)>,
    /// The names blocked most often.
    pub top_blocked: Vec<Count>,
    /// The names asked most often.
    pub top_names: Vec<Count>,
    /// The clients that asked most often (absent from the lines of a log that keeps no
    /// client).
    pub top_clients: Vec<Count>,
    /// The newest blocked queries, newest first.
    pub recent_blocked: Vec<LogLine>,
    /// Octets of segments looked at.
    pub scanned_bytes: u64,
    /// The log held more in the window than one computation looks at: the figures cover
    /// the newest part.
    pub truncated: bool,
}

#[derive(Default)]
struct Tally {
    queries: u64,
    blocked: u64,
}

fn top(map: HashMap<String, Tally>, length: usize, blocked_first: bool) -> Vec<Count> {
    let mut counts: Vec<Count> = map
        .into_iter()
        .map(|(key, tally)| Count {
            key,
            queries: tally.queries,
            blocked: tally.blocked,
        })
        .collect();
    counts.sort_by(|left, right| {
        let order = if blocked_first {
            right.blocked.cmp(&left.blocked)
        } else {
            right.queries.cmp(&left.queries)
        };
        order.then_with(|| left.key.cmp(&right.key))
    });
    counts.truncate(length);
    counts
}

/// The counts of one computation while the lines come in.
struct Counting {
    stats: BlockingStats,
    /// The start of the first bucket, in microseconds since 1970.
    first: u64,
    /// The length of a bucket in microseconds.
    bucket: u64,
    lists: HashMap<BlockListId, u64>,
    blocked_names: HashMap<String, Tally>,
    asked: HashMap<String, Tally>,
    clients: HashMap<String, Tally>,
}

impl Counting {
    fn new(args: &StatsArgs, from: u64, until: u64) -> Self {
        let bucket = u64::from(args.bucket_secs) * 1_000_000;
        let first = from - from % bucket;
        let count = usize::try_from((until - first) / bucket + 1)
            .unwrap_or(MAX_BUCKETS)
            .min(MAX_BUCKETS);
        let stats = BlockingStats {
            buckets: (0..count)
                .map(|index| Bucket {
                    start: Timestamp::from_unix_nanos(
                        i128::from(first + bucket * u64::try_from(index).unwrap_or(0)) * 1_000,
                    )
                    .unwrap_or(args.from),
                    queries: 0,
                    blocked: 0,
                })
                .collect(),
            ..BlockingStats::default()
        };
        Self {
            stats,
            first,
            bucket,
            lists: HashMap::new(),
            blocked_names: HashMap::new(),
            asked: HashMap::new(),
            clients: HashMap::new(),
        }
    }

    /// Counts one line that arrived at `at` (newest lines first).
    fn add(&mut self, line: LogLine, at: u64) {
        let stats = &mut self.stats;
        stats.queries += 1;
        stats.cached += u64::from(line.cached);
        let blocked = u64::from(line.blocked.is_some());
        stats.blocked += blocked;
        if let Some(slot) = usize::try_from((at - self.first) / self.bucket)
            .ok()
            .and_then(|index| stats.buckets.get_mut(index))
        {
            slot.queries += 1;
            slot.blocked += blocked;
        }
        let name = self.asked.entry(line.qname.clone()).or_default();
        name.queries += 1;
        name.blocked += blocked;
        if let Some(client) = &line.client {
            let tally = self.clients.entry(client.clone()).or_default();
            tally.queries += 1;
            tally.blocked += blocked;
        }
        if let Some(list) = line.blocked {
            *self.lists.entry(list).or_default() += 1;
            let name = self.blocked_names.entry(line.qname.clone()).or_default();
            name.queries += 1;
            name.blocked += 1;
            if stats.recent_blocked.len() < RECENT_BLOCKED {
                stats.recent_blocked.push(line);
            }
        }
    }

    /// The figures with top lists of `length`.
    fn finish(self, length: usize) -> BlockingStats {
        let mut stats = self.stats;
        stats.clients = u64::try_from(self.clients.len()).unwrap_or(u64::MAX);
        stats.top_blocked = top(self.blocked_names, length, true);
        stats.top_names = top(self.asked, length, false);
        stats.top_clients = top(self.clients, length, false);
        let mut lists: Vec<(BlockListId, u64)> = self.lists.into_iter().collect();
        lists.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        stats.lists = lists;
        stats
            .recent_blocked
            .sort_by_key(|line| std::cmp::Reverse(line.at));
        stats
    }
}

/// Counts the queries of the log in `dir` from `args.from` to `args.until`.
///
/// # Errors
///
/// [`ReadError::Filter`] for a window that ends before it starts or a bucket of no length,
/// [`ReadError::Io`] when the directory cannot be read.
pub fn compute(dir: &Path, args: &StatsArgs) -> Result<BlockingStats, ReadError> {
    let from = micros_of(args.from);
    let until = micros_of(args.until);
    if until < from {
        return Err(ReadError::Filter("the window ends before it starts".into()));
    }
    if args.bucket_secs == 0 {
        return Err(ReadError::Filter(
            "a bucket must last at least a second".into(),
        ));
    }
    let mut counting = Counting::new(args, from, until);
    let mut names = match segments(dir) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(ReadError::Io(error.to_string())),
    };
    names.sort();
    names.reverse();
    // The start of the next newer segment bounds the entries of a segment from above.
    let mut newer_start: Option<u64> = None;
    for name in &names {
        let opened = segment_micros(name).unwrap_or(0);
        let bound = newer_start.replace(opened);
        if bound.is_some_and(|bound| bound.saturating_add(LATE_MICROS) < from) {
            break;
        }
        if opened > until.saturating_add(LATE_MICROS) {
            continue;
        }
        if counting.stats.scanned_bytes >= MAX_STATS_BYTES {
            counting.stats.truncated = true;
            break;
        }
        let Some(format) = LogFormat::of_segment(name) else {
            continue;
        };
        let bytes = match fs::read(dir.join(name)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ReadError::Io(error.to_string())),
        };
        counting.stats.scanned_bytes += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        for (_, record) in records(format, &bytes).into_iter().rev() {
            let Some(line) = decode(format, record) else {
                continue;
            };
            let at = micros_of(line.at);
            if (from..=until).contains(&at) {
                counting.add(line, at);
            }
        }
    }
    Ok(counting.finish(usize::try_from(args.top.clamp(1, MAX_TOP)).unwrap_or(10)))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tenko_core::dns::{DnsName, QueryTransport};

    use super::*;
    use crate::{
        log::{QueryLogEntry, QueryLogSink as _},
        querylog::{ClientField, LogSettings, LogWriter},
    };

    /// 2026-10-15 in microseconds, a few hours into the UTC day.
    const NOW: u64 = 1_792_000_000_000_000;
    const HOUR: u64 = 3_600_000_000;

    fn at(micros: u64) -> Timestamp {
        Timestamp::from_unix_nanos(i128::from(micros) * 1_000).expect("time")
    }

    fn list(n: u8) -> BlockListId {
        format!("0190d1c2-0000-7000-8000-0000000000{n:02x}")
            .parse()
            .expect("id")
    }

    /// Writes `(hour, name, client, list)` entries into a log in `dir`.
    fn write(dir: &Path, entries: &[(u64, &str, u8, Option<u8>)]) {
        let writer = LogWriter::start(LogSettings {
            client: ClientField::Address,
            ..LogSettings::new(dir)
        })
        .expect("log");
        let sink = writer.sink();
        for (n, (hour, name, client, blocked)) in entries.iter().enumerate() {
            let qname = DnsName::new(name).expect("name").to_wire();
            sink.record(&QueryLogEntry {
                at_micros: NOW + hour * HOUR + n as u64,
                client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, *client)),
                transport: QueryTransport::Udp,
                qname: &qname,
                qtype: 1,
                rcode: 0,
                view: None,
                blocked: blocked.map(list),
                cached: false,
                duration_micros: 10,
                // WP10.1: the resolution of the log line.
                resolution: None,
                subqueries: 0,
                // WP10.2: the validation state and the extended error.
                validation: None,
                ede: None,
            });
        }
        writer.stop();
    }

    fn args(from: u64, until: u64, top: u32) -> StatsArgs {
        StatsArgs {
            from: at(from),
            until: at(until),
            bucket_secs: 3_600,
            top,
        }
    }

    #[test]
    fn the_window_is_counted_per_hour_list_name_and_client() {
        let dir = std::env::temp_dir().join(format!("tenko-stats-{}", uuid::Uuid::now_v7()));
        write(
            &dir,
            &[
                (0, "www.example.test", 10, None),
                (0, "ads.example.test", 10, Some(1)),
                (1, "ads.example.test", 11, Some(1)),
                (1, "tracker.example.test", 10, Some(2)),
                (2, "www.example.test", 11, None),
                (5, "late.example.test", 12, None),
            ],
        );
        // The window ends before the last entry.
        let stats = compute(&dir, &args(NOW, NOW + 3 * HOUR, 2)).expect("stats");
        assert_eq!(stats.queries, 5);
        assert_eq!(stats.blocked, 3);
        assert_eq!(stats.clients, 2);
        let per_hour: Vec<(u64, u64)> = stats
            .buckets
            .iter()
            .map(|bucket| (bucket.queries, bucket.blocked))
            .collect();
        assert_eq!(&per_hour[..3], [(2, 1), (2, 2), (1, 0)]);
        let hours = stats.buckets.len();
        assert!((4..=5).contains(&hours), "{hours} buckets");
        assert_eq!(stats.lists, [(list(1), 2), (list(2), 1)]);
        assert_eq!(stats.top_blocked[0].key, "ads.example.test");
        assert_eq!(stats.top_blocked[0].blocked, 2);
        assert_eq!(stats.top_blocked.len(), 2);
        assert_eq!(stats.top_names[0].key, "ads.example.test");
        assert_eq!(stats.top_clients[0].key, "192.0.2.10");
        assert_eq!(stats.top_clients[0].queries, 3);
        assert_eq!(stats.top_clients[0].blocked, 2);
        let recent: Vec<&str> = stats
            .recent_blocked
            .iter()
            .map(|line| line.qname.as_str())
            .collect();
        assert_eq!(
            recent,
            [
                "tracker.example.test",
                "ads.example.test",
                "ads.example.test"
            ]
        );
        assert!(!stats.truncated);
        assert!(stats.scanned_bytes > 0);

        let empty = compute(&dir, &args(NOW + 10 * HOUR, NOW + 11 * HOUR, 5)).expect("stats");
        assert_eq!(empty.queries, 0);
        assert_eq!(empty.top_names, []);
        assert!(matches!(
            compute(&dir, &args(NOW + HOUR, NOW, 5)),
            Err(ReadError::Filter(_))
        ));
        let missing = dir.join("nothing-here");
        assert_eq!(
            compute(&missing, &args(NOW, NOW + HOUR, 5))
                .expect("stats")
                .queries,
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
