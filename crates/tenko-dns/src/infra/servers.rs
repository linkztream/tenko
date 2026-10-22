//! The figures of the authority servers ([`ServerTable`]): the bookkeeping the upstream
//! pool keeps per upstream ([`crate::pool`]), kept here per server address because a
//! delegation's servers are shared by many zones (the root's by all of them).
//!
//! - **Round-trip times.** The smoothed round-trip time is an EWMA with weight 1/8 (a
//!   server never measured counts as the fastest, so it is measured first); a failure
//!   doubles it, up to the longest attempt. The p50 and p99 come from the answers of the
//!   last minute (at most the last [`WINDOW`]).
//! - **The timeout of an attempt** ([`ServerTable::timeout`]): four times the smoothed time,
//!   at least [`MIN_TIMEOUT`], at most `[dns.recursion] timeout_ms`; half of that most for a
//!   server never measured.
//! - **Back-off.** Three failures in a row put the address in back-off for one second,
//!   doubling with each further failure up to a minute; an answer ends it.
//! - **0x20.** Two answers in another case than asked and the address is asked in lower case
//!   until the infrastructure TTL passes.
//! - **Unwanted answers** (recursion plan section 2.1): answers on a query's socket that
//!   match no outstanding query (another id, another question, another source address). Over
//!   [`UNWANTED_PER_SERVER`] in an hour the address is asked over TCP for the rest of the
//!   hour; over [`UNWANTED_PER_NODE`] across the node in an hour the owner of the answer
//!   cache flushes it ([`ServerTable::take_flush`]).
//!
//! Bounded like the infrastructure cache's server addresses, least recently used out.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Answers kept for the quantiles.
pub const WINDOW: usize = 32;

/// The time the quantiles look back.
pub const WINDOW_SPAN: Duration = Duration::from_secs(60);

/// The shortest attempt.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(300);

/// Failures in a row before the back-off.
pub const FAILURES_BEFORE_BACKOFF: u32 = 3;

/// The longest back-off.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Answers in another case before the address is asked in lower case.
pub const CASE_STRIKES: u8 = 2;

/// Truncated answers in a row before the address is asked over TCP from the start.
pub const TRUNCATIONS: u8 = 3;

/// Unwanted answers from one address in an hour before it is asked over TCP.
pub const UNWANTED_PER_SERVER: u32 = 1_000;

/// Unwanted answers across the node in an hour before the answer cache is flushed.
pub const UNWANTED_PER_NODE: u64 = 100_000;

const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
struct Figures {
    /// Microseconds; 0 when never measured.
    srtt: u64,
    last_rtt: u64,
    failures: u32,
    down_until: Option<Instant>,
    case_strikes: u8,
    lower_case_until: Option<Instant>,
    truncations: u8,
    window: [(u32, Instant); WINDOW],
    next: usize,
    len: usize,
    unwanted_since: Instant,
    unwanted: u32,
    tcp_until: Option<Instant>,
    answers: u64,
    used: u64,
}

impl Figures {
    fn new(now: Instant) -> Self {
        Self {
            srtt: 0,
            last_rtt: 0,
            failures: 0,
            down_until: None,
            case_strikes: 0,
            lower_case_until: None,
            truncations: 0,
            window: [(0, now); WINDOW],
            next: 0,
            len: 0,
            unwanted_since: now,
            unwanted: 0,
            tcp_until: None,
            answers: 0,
            used: 0,
        }
    }

    fn quantiles(&self, now: Instant) -> (Option<Duration>, Option<Duration>) {
        let mut recent: Vec<u32> = self.window[..self.len]
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(*at) <= WINDOW_SPAN)
            .map(|(rtt, _)| *rtt)
            .collect();
        if recent.is_empty() {
            return (None, None);
        }
        recent.sort_unstable();
        let at = |percent: usize| {
            let rank = (recent.len() * percent).div_ceil(100).max(1);
            Duration::from_micros(u64::from(recent[rank - 1]))
        };
        (Some(at(50)), Some(at(99)))
    }
}

/// What the table knows about one address, for the status and the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerFigures {
    /// The smoothed round-trip time; `None` before the first answer.
    pub srtt: Option<Duration>,
    /// The last round-trip time.
    pub last_rtt: Option<Duration>,
    /// The median of the last minute.
    pub p50: Option<Duration>,
    /// The 99th percentile of the last minute.
    pub p99: Option<Duration>,
    /// Failures in a row.
    pub failures: u32,
    /// In back-off now.
    pub down: bool,
    /// Asked in lower case (it broke 0x20).
    pub lower_case: bool,
    /// Asked over TCP for the hour (unwanted answers).
    pub tcp_hour: bool,
    /// Unwanted answers in the current hour.
    pub unwanted: u32,
    /// Answers since the address was first asked.
    pub answers: u64,
}

/// The figures of every authority server address; see the module documentation.
#[derive(Debug)]
pub struct ServerTable {
    bound: usize,
    ttl: Duration,
    inner: Mutex<HashMap<IpAddr, Figures>>,
    tick: AtomicU64,
    node: Mutex<(Instant, u64)>,
    unwanted_total: AtomicU64,
    flush_due: AtomicBool,
}

impl ServerTable {
    /// A table of at most `bound` addresses whose learnt behaviour (0x20) holds for `ttl`.
    pub fn new(bound: usize, ttl: Duration) -> Self {
        Self {
            bound: bound.max(1),
            ttl,
            inner: Mutex::new(HashMap::new()),
            tick: AtomicU64::new(0),
            node: Mutex::new((Instant::now(), 0)),
            unwanted_total: AtomicU64::new(0),
            flush_due: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, Figures>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<T>(&self, address: IpAddr, now: Instant, f: impl FnOnce(&mut Figures) -> T) -> T {
        let tick = self.tick.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.lock();
        let figures = inner.entry(address).or_insert_with(|| Figures::new(now));
        figures.used = tick;
        let out = f(figures);
        super::trim(&mut inner, self.bound, |figures| figures.used);
        out
    }

    fn read<T>(&self, address: IpAddr, f: impl FnOnce(Option<&Figures>) -> T) -> T {
        f(self.lock().get(&address))
    }

    /// The smoothed round-trip time in microseconds, 0 for an address never measured.
    pub fn srtt_micros(&self, address: IpAddr) -> u64 {
        self.read(address, |figures| figures.map_or(0, |figures| figures.srtt))
    }

    /// The time one attempt to `address` has, at most `longest`.
    pub fn timeout(&self, address: IpAddr, longest: Duration) -> Duration {
        let srtt = self.srtt_micros(address);
        let longest = longest.max(MIN_TIMEOUT);
        if srtt == 0 {
            return (longest / 2).max(MIN_TIMEOUT);
        }
        Duration::from_micros(srtt.saturating_mul(4)).clamp(MIN_TIMEOUT, longest)
    }

    /// Whether `address` is in back-off at `now`.
    pub fn down(&self, address: IpAddr, now: Instant) -> bool {
        self.read(address, |figures| {
            figures.is_some_and(|figures| figures.down_until.is_some_and(|until| until > now))
        })
    }

    /// When the back-off of `address` ends.
    pub fn down_until(&self, address: IpAddr) -> Option<Instant> {
        self.read(address, |figures| {
            figures.and_then(|figures| figures.down_until)
        })
    }

    /// An answer came from `address` after `rtt`.
    pub fn answered(&self, address: IpAddr, rtt: Duration, now: Instant) {
        let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX).max(1);
        self.with(address, now, |figures| {
            figures.failures = 0;
            figures.down_until = None;
            figures.last_rtt = micros;
            figures.srtt = if figures.srtt == 0 {
                micros
            } else {
                (figures.srtt * 7 + micros) / 8
            };
            figures.window[figures.next] = (u32::try_from(micros).unwrap_or(u32::MAX), now);
            figures.next = (figures.next + 1) % WINDOW;
            figures.len = (figures.len + 1).min(WINDOW);
            figures.answers = figures.answers.saturating_add(1);
        });
    }

    /// An attempt to `address` of `timeout` failed.
    pub fn failed(&self, address: IpAddr, timeout: Duration, now: Instant) {
        let ceiling = u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX);
        self.with(address, now, |figures| {
            figures.failures = figures.failures.saturating_add(1);
            figures.srtt = figures
                .srtt
                .saturating_mul(2)
                .max(ceiling / 2)
                .clamp(1_000, ceiling.max(1_000));
            if figures.failures >= FAILURES_BEFORE_BACKOFF {
                let steps = (figures.failures - FAILURES_BEFORE_BACKOFF).min(6);
                let backoff = Duration::from_secs(1u64 << steps).min(MAX_BACKOFF);
                figures.down_until = Some(now + backoff);
            }
        });
    }

    /// `address` answered in another case than asked; returns whether it is asked in lower
    /// case from now on.
    pub fn broke_case(&self, address: IpAddr, now: Instant) -> bool {
        let ttl = self.ttl;
        self.with(address, now, |figures| {
            figures.case_strikes = figures.case_strikes.saturating_add(1);
            if figures.case_strikes >= CASE_STRIKES {
                figures.lower_case_until = Some(now + ttl);
                figures.case_strikes = 0;
                true
            } else {
                false
            }
        })
    }

    /// Whether `address` is asked with 0x20 at `now`.
    pub fn mixes_case(&self, address: IpAddr, now: Instant) -> bool {
        self.read(address, |figures| {
            figures.is_none_or(|figures| figures.lower_case_until.is_none_or(|until| until <= now))
        })
    }

    /// `address` truncated a UDP answer (`truncated`) or answered in full; returns whether it
    /// truncated [`TRUNCATIONS`] in a row (ask it over TCP from the start).
    pub fn truncation(&self, address: IpAddr, truncated: bool, now: Instant) -> bool {
        self.with(address, now, |figures| {
            if truncated {
                figures.truncations = figures.truncations.saturating_add(1);
            } else {
                figures.truncations = 0;
            }
            figures.truncations >= TRUNCATIONS
        })
    }

    /// An answer that matched no outstanding query came on a socket of a query to
    /// `address`: counted per address and for the node.
    pub fn unwanted(&self, address: IpAddr, now: Instant) {
        self.unwanted_total.fetch_add(1, Ordering::Relaxed);
        self.with(address, now, |figures| {
            if now.saturating_duration_since(figures.unwanted_since) >= HOUR {
                figures.unwanted_since = now;
                figures.unwanted = 0;
            }
            figures.unwanted = figures.unwanted.saturating_add(1);
            if figures.unwanted > UNWANTED_PER_SERVER && figures.tcp_until.is_none() {
                figures.tcp_until = Some(figures.unwanted_since + HOUR);
                tracing::warn!(
                    server = %address,
                    "an authority server drew over {UNWANTED_PER_SERVER} unwanted answers in \
                     an hour: it is asked over TCP for the rest of the hour"
                );
            }
        });
        let mut node = self.node.lock().unwrap_or_else(PoisonError::into_inner);
        if now.saturating_duration_since(node.0) >= HOUR {
            *node = (now, 0);
        }
        node.1 += 1;
        if node.1 == UNWANTED_PER_NODE + 1 {
            self.flush_due.store(true, Ordering::Relaxed);
        }
    }

    /// Whether `address` is asked over TCP for the hour of its unwanted answers.
    pub fn tcp_forced(&self, address: IpAddr, now: Instant) -> bool {
        self.read(address, |figures| {
            figures.is_some_and(|figures| figures.tcp_until.is_some_and(|until| until > now))
        })
    }

    /// Whether the node crossed [`UNWANTED_PER_NODE`] since the last call (the owner of the
    /// answer cache flushes it and audits `dns.recursion.unwanted_flush`).
    pub fn take_flush(&self) -> bool {
        self.flush_due.swap(false, Ordering::Relaxed)
    }

    /// Unwanted answers across the node since the start.
    pub fn unwanted_total(&self) -> u64 {
        self.unwanted_total.load(Ordering::Relaxed)
    }

    /// The figures of `address`.
    pub fn figures(&self, address: IpAddr, now: Instant) -> ServerFigures {
        self.read(address, |figures| {
            let Some(figures) = figures else {
                return ServerFigures::default();
            };
            let (p50, p99) = figures.quantiles(now);
            ServerFigures {
                srtt: (figures.srtt > 0).then(|| Duration::from_micros(figures.srtt)),
                last_rtt: (figures.last_rtt > 0).then(|| Duration::from_micros(figures.last_rtt)),
                p50,
                p99,
                failures: figures.failures,
                down: figures.down_until.is_some_and(|until| until > now),
                lower_case: figures.lower_case_until.is_some_and(|until| until > now),
                tcp_hour: figures.tcp_until.is_some_and(|until| until > now),
                unwanted: figures.unwanted,
                answers: figures.answers,
            }
        })
    }

    /// Addresses held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every address.
    pub fn clear(&self) {
        self.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn times_back_off_and_case_follow_the_pool() {
        let table = ServerTable::new(4, Duration::from_secs(900));
        let now = Instant::now();
        let server = address(1);
        let longest = Duration::from_secs(2);
        assert_eq!(table.timeout(server, longest), Duration::from_secs(1));
        table.answered(server, Duration::from_millis(10), now);
        assert_eq!(table.timeout(server, longest), MIN_TIMEOUT);
        table.answered(server, Duration::from_millis(200), now);
        // (10 * 7 + 200) / 8 = 33.75 ms; four times is 135 ms, below the floor.
        assert_eq!(
            table.figures(server, now).srtt,
            Some(Duration::from_micros(33_750))
        );
        for _ in 0..3 {
            table.failed(server, longest, now);
        }
        assert!(table.down(server, now));
        assert!(!table.down(server, now + Duration::from_secs(2)));
        assert!(table.mixes_case(server, now));
        assert!(!table.broke_case(server, now));
        assert!(table.broke_case(server, now));
        assert!(!table.mixes_case(server, now));
        assert!(table.mixes_case(server, now + Duration::from_secs(901)));
        assert!(!table.truncation(server, true, now));
        assert!(!table.truncation(server, true, now));
        assert!(table.truncation(server, true, now));
        assert!(!table.truncation(server, false, now));
        let figures = table.figures(server, now);
        assert_eq!(figures.answers, 2);
        assert!(figures.p50.is_some() && figures.p99.is_some());
    }

    #[test]
    fn unwanted_answers_force_tcp_and_flag_a_flush() {
        let table = ServerTable::new(4, Duration::from_secs(900));
        let now = Instant::now();
        let server = address(2);
        for _ in 0..=UNWANTED_PER_SERVER {
            table.unwanted(server, now);
        }
        assert!(table.tcp_forced(server, now));
        assert!(!table.tcp_forced(server, now + HOUR));
        assert!(!table.take_flush());
        assert_eq!(table.unwanted_total(), u64::from(UNWANTED_PER_SERVER) + 1);
    }

    #[test]
    fn the_table_is_bounded() {
        let table = ServerTable::new(16, Duration::from_secs(900));
        let now = Instant::now();
        for last in 0..40 {
            table.answered(address(last), Duration::from_millis(1), now);
        }
        assert!(table.len() <= 16);
        assert_eq!(
            table.figures(address(39), now).answers,
            1,
            "the most recent stays"
        );
    }
}
