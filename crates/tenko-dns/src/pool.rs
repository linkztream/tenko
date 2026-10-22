//! The upstream pool (DNS-02, DNS-08, TGL-14): the upstreams of one forwarding rule, their
//! health and round-trip times, and the attempts of one query.
//!
//! - **Choice.** Each attempt goes to an upstream not yet tried for the query: the healthy
//!   one with the lowest smoothed round-trip time (an upstream never measured counts as the
//!   fastest, so it is measured first), except one attempt in [`PROBE_ONE_IN`] that goes to
//!   another healthy upstream at random, so the times of the others stay current. When
//!   every upstream left is in back-off, the one whose back-off ends first is asked.
//! - **Health.** [`FAILURES_BEFORE_BACKOFF`] failures in a row (timeouts, refused
//!   connections, malformed answers) put an upstream in back-off for one second, doubling
//!   with each further failure up to [`MAX_BACKOFF`]; an answer ends it.
//! - **Budget.** A query has `retries + 1` attempts of `timeout` each (`[dns]
//!   forward_timeout_ms` and `forward_retries`). An answer with SERVFAIL or REFUSED moves on
//!   to the next upstream while attempts remain, and is relayed when none answers better.
//! - **0x20.** Plain upstreams get the question in a random case; an answer whose question
//!   comes back in another case is not used. After [`CASE_STRIKES`] such answers the
//!   upstream is asked in lower case from then on (logged once). DoT and DoH upstreams are
//!   asked in lower case: their transport already defeats spoofing.
//! - **Figures.** Per upstream the last round-trip time, the smoothed one (an EWMA with
//!   weight 1/8, the one the choice uses), the p50 and p99 of the answers of the last
//!   minute (at most the last [`RTT_WINDOW`] answers), the state ([`UpstreamState`]) and the
//!   last error with its time; [`UpstreamSet::health`] reports them with the upstream the
//!   next query goes to (`chosen`). They are kept on the reply path, under the member's
//!   locks, and computed when they are read.
//! - **Metrics.** `tenko_dns_upstream_queries_total{rule,upstream,transport,outcome}`,
//!   `tenko_dns_upstream_rtt_seconds{rule,upstream}` and
//!   `tenko_dns_upstream_health{rule,upstream}` (1 answering, 0.5 failing, 0 in back-off;
//!   computed at the scrape), kept per rule and upstream for the life of the process
//!   ([`UpstreamQueries`], [`UpstreamRtt`], [`UpstreamHealthGauge`]).

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    Timestamp,
    dns::{ForwardRule, ForwardRuleId, ForwardTransport, ZoneId},
    metrics::{Collect, Desc, HistogramValue, Labels, Series, Value},
};

use crate::{
    authoritative::rcode,
    metrics::{LATENCY_BUCKETS_US, UPSTREAM_HEALTH, UPSTREAM_QUERIES, UPSTREAM_RTT},
    outbound::{AnswerCheck, Question, build_query, check_answer, random_u16, random_u32},
    upstream::{
        AnyUpstream, DohUpstream, DotUpstream, PlainUpstream, TlsClient, Upstream, UpstreamError,
        server_name,
    },
};

/// One attempt in this many goes to a healthy upstream at random (about 6 percent).
pub const PROBE_ONE_IN: u32 = 16;

/// Failures in a row before an upstream goes into back-off.
pub const FAILURES_BEFORE_BACKOFF: u32 = 3;

/// The longest back-off.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Answers in a broken case before an upstream is asked without 0x20.
pub const CASE_STRIKES: u8 = 2;

/// The most upstreams a set holds (a rule has at most 16; a stub zone's name servers are
/// cut to this many addresses).
pub const MAX_MEMBERS: usize = 32;

/// The attempts of one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The time one attempt has.
    pub timeout: Duration,
    /// Attempts after the first.
    pub retries: u8,
}

/// The outcome label values of `tenko_dns_upstream_queries_total`.
pub const OUTCOMES: [&str; 5] = ["ok", "servfail", "timeout", "unreachable", "malformed"];

/// The answers the quantiles of the last minute look at, at most.
pub const RTT_WINDOW: usize = 512;

/// The span of the quantiles.
pub const RTT_WINDOW_SPAN: Duration = Duration::from_secs(60);

/// The instant the pool's clocks count from.
fn base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

/// Milliseconds from [`base`] to `at` (0 before it).
fn millis_of(at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(base()).as_millis()).unwrap_or(u64::MAX)
}

/// The state of an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamState {
    /// Not asked yet.
    #[default]
    Unknown,
    /// The last exchange was answered.
    Up,
    /// Failing, fewer than [`FAILURES_BEFORE_BACKOFF`] times in a row.
    Degraded,
    /// In back-off: asked only when every other upstream is in back-off as well.
    Down,
}

impl UpstreamState {
    /// The word of the API and the CLI: `unknown`, `up`, `degraded`, `down`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Up => "up",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }
}

const STATE_UNKNOWN: u8 = 0;
const STATE_UP: u8 = 1;
const STATE_FAILING: u8 = 2;

/// The counters of one upstream under one rule.
#[derive(Debug, Default)]
pub struct UpstreamStats {
    outcomes: [AtomicU64; 5],
    rtt_buckets: [AtomicU64; 16],
    rtt_sum: AtomicU64,
    /// [`STATE_UNKNOWN`], [`STATE_UP`] or [`STATE_FAILING`], for the health gauge.
    state: AtomicU8,
    /// The end of the back-off in milliseconds from [`base`]; 0 when none.
    down_until: AtomicU64,
    /// The members of held sets that count into these counters: the health gauge leaves
    /// out an upstream no set holds any more.
    live: AtomicU32,
}

impl UpstreamStats {
    fn count(&self, outcome: usize) {
        self.outcomes[outcome].fetch_add(1, Ordering::Relaxed);
    }

    fn rtt(&self, micros: u64) {
        let bucket = LATENCY_BUCKETS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(LATENCY_BUCKETS_US.len());
        self.rtt_buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.rtt_sum.fetch_add(micros, Ordering::Relaxed);
    }

    /// Exchanges by outcome, in the order of [`OUTCOMES`].
    pub fn outcomes(&self) -> [u64; 5] {
        std::array::from_fn(|index| self.outcomes[index].load(Ordering::Relaxed))
    }
}

type StatsKey = (String, String, &'static str);

fn stats_table() -> &'static Mutex<BTreeMap<StatsKey, Arc<UpstreamStats>>> {
    static TABLE: OnceLock<Mutex<BTreeMap<StatsKey, Arc<UpstreamStats>>>> = OnceLock::new();
    TABLE.get_or_init(Mutex::default)
}

/// The counters of `upstream` under `rule`, created the first time.
pub fn upstream_stats(
    rule: &str,
    upstream: &str,
    transport: ForwardTransport,
) -> Arc<UpstreamStats> {
    let mut table = stats_table().lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(
        table
            .entry((
                rule.to_owned(),
                upstream.to_owned(),
                transport_label(transport),
            ))
            .or_default(),
    )
}

/// The `transport` label of a forward transport.
pub const fn transport_label(transport: ForwardTransport) -> &'static str {
    match transport {
        ForwardTransport::Plain => "plain",
        ForwardTransport::Dot => "dot",
        ForwardTransport::Doh => "doh",
    }
}

/// `tenko_dns_upstream_queries_total{rule,upstream,transport,outcome}`, read from the
/// counters of every upstream the process has asked.
#[derive(Debug)]
pub struct UpstreamQueries;

/// The family registered with the process registry.
pub static UPSTREAM_QUERY_FAMILY: UpstreamQueries = UpstreamQueries;

impl Collect for UpstreamQueries {
    fn desc(&self) -> &Desc {
        &UPSTREAM_QUERIES
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let table = stats_table().lock().unwrap_or_else(PoisonError::into_inner);
        for ((rule, upstream, transport), stats) in table.iter() {
            for (outcome, value) in OUTCOMES.iter().zip(stats.outcomes()) {
                out.push(Series {
                    labels: Labels::owned(&[rule, upstream, transport, outcome]),
                    value: Value::Counter(value),
                });
            }
        }
    }
}

/// `tenko_dns_upstream_rtt_seconds{rule,upstream}`: the round-trip times of the answered
/// exchanges per rule and upstream.
#[derive(Debug)]
pub struct UpstreamRtt;

/// The family registered with the process registry.
pub static UPSTREAM_RTT_FAMILY: UpstreamRtt = UpstreamRtt;

impl Collect for UpstreamRtt {
    fn desc(&self) -> &Desc {
        &UPSTREAM_RTT
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let table = stats_table().lock().unwrap_or_else(PoisonError::into_inner);
        let mut per_upstream: BTreeMap<(&str, &str), ([u64; 16], u64)> = BTreeMap::new();
        for ((rule, upstream, _), stats) in table.iter() {
            let (buckets, sum) = per_upstream
                .entry((rule.as_str(), upstream.as_str()))
                .or_default();
            for (total, bucket) in buckets.iter_mut().zip(&stats.rtt_buckets) {
                *total += bucket.load(Ordering::Relaxed);
            }
            *sum += stats.rtt_sum.load(Ordering::Relaxed);
        }
        for ((rule, upstream), (buckets, sum)) in per_upstream {
            let mut cumulative = Vec::with_capacity(LATENCY_BUCKETS_US.len() + 1);
            let mut running = 0;
            for count in &buckets[..=LATENCY_BUCKETS_US.len()] {
                running += count;
                cumulative.push(running);
            }
            out.push(Series {
                labels: Labels::owned(&[rule, upstream]),
                value: Value::Histogram(HistogramValue {
                    buckets: cumulative,
                    sum,
                }),
            });
        }
    }
}

/// `tenko_dns_upstream_health{rule,upstream}`: 1 while an upstream answers, 0.5 while it
/// fails without being in back-off, 0 in back-off; computed at the scrape from the state
/// the members leave. An upstream not asked yet, and one no set holds any more, has no
/// series.
#[derive(Debug)]
pub struct UpstreamHealthGauge;

/// The family registered with the process registry.
pub static UPSTREAM_HEALTH_FAMILY: UpstreamHealthGauge = UpstreamHealthGauge;

impl Collect for UpstreamHealthGauge {
    fn desc(&self) -> &Desc {
        &UPSTREAM_HEALTH
    }

    fn collect(&self, out: &mut Vec<Series>) {
        let now = millis_of(Instant::now());
        let table = stats_table().lock().unwrap_or_else(PoisonError::into_inner);
        let mut per_upstream: BTreeMap<(&str, &str), f64> = BTreeMap::new();
        for ((rule, upstream, _), stats) in table.iter() {
            if stats.live.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let value = match stats.state.load(Ordering::Relaxed) {
                STATE_UNKNOWN => continue,
                _ if stats.down_until.load(Ordering::Relaxed) > now => 0.0,
                STATE_UP => 1.0,
                _ => 0.5,
            };
            per_upstream
                .entry((rule.as_str(), upstream.as_str()))
                .and_modify(|held| *held = held.min(value))
                .or_insert(value);
        }
        for ((rule, upstream), value) in per_upstream {
            out.push(Series {
                labels: Labels::owned(&[rule, upstream]),
                value: Value::Gauge(value),
            });
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Health {
    /// Smoothed round-trip time in microseconds; 0 when never measured.
    srtt: u64,
    /// The last round-trip time in microseconds; 0 when never measured.
    last_rtt: u64,
    failures: u32,
    down_until: Option<Instant>,
    case_strikes: u8,
    lower_case: bool,
    /// The last exchange was answered.
    answered: bool,
    /// The last failure and when it happened.
    last_error: Option<(UpstreamError, Timestamp)>,
}

/// The round-trip times of the last answers, in a ring.
#[derive(Debug)]
struct RttWindow {
    /// Microseconds, saturated at `u32::MAX`.
    rtt: [u32; RTT_WINDOW],
    /// When each answer came, in seconds from [`base`].
    at: [u32; RTT_WINDOW],
    next: usize,
    len: usize,
}

impl Default for RttWindow {
    fn default() -> Self {
        Self {
            rtt: [0; RTT_WINDOW],
            at: [0; RTT_WINDOW],
            next: 0,
            len: 0,
        }
    }
}

impl RttWindow {
    fn push(&mut self, micros: u64, now: Instant) {
        self.rtt[self.next] = u32::try_from(micros).unwrap_or(u32::MAX);
        self.at[self.next] = u32::try_from(millis_of(now) / 1_000).unwrap_or(u32::MAX);
        self.next = (self.next + 1) % RTT_WINDOW;
        self.len = (self.len + 1).min(RTT_WINDOW);
    }

    /// The p50 and p99 of the answers of the last [`RTT_WINDOW_SPAN`], and how many there
    /// were.
    fn quantiles(&self, now: Instant) -> (Option<Duration>, Option<Duration>, u32) {
        let since = (millis_of(now) / 1_000).saturating_sub(RTT_WINDOW_SPAN.as_secs());
        let mut recent: Vec<u32> = (0..self.len)
            .filter(|index| u64::from(self.at[*index]) >= since)
            .map(|index| self.rtt[index])
            .collect();
        if recent.is_empty() {
            return (None, None, 0);
        }
        recent.sort_unstable();
        // The nearest rank: the smallest time at or above the share.
        let at = |percent: usize| {
            let rank = (recent.len() * percent).div_ceil(100).max(1);
            Duration::from_micros(u64::from(recent[rank - 1]))
        };
        let count = u32::try_from(recent.len()).unwrap_or(u32::MAX);
        (Some(at(50)), Some(at(99)), count)
    }
}

/// One upstream of a set.
#[derive(Debug)]
pub struct Member {
    upstream: AnyUpstream,
    label: String,
    health: Mutex<Health>,
    window: Mutex<RttWindow>,
    stats: Arc<UpstreamStats>,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.stats.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The state of one upstream, for the status and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberHealth {
    /// `address:port`.
    pub upstream: String,
    /// The transport.
    pub transport: ForwardTransport,
    /// The smoothed round-trip time (the EWMA the choice uses); `None` when never measured.
    pub srtt: Option<Duration>,
    /// The round-trip time of the last answer; `None` when never answered.
    pub last_rtt: Option<Duration>,
    /// The median round-trip time of the answers of the last minute.
    pub p50: Option<Duration>,
    /// The 99th percentile of the round-trip times of the answers of the last minute.
    pub p99: Option<Duration>,
    /// The answers the quantiles look at.
    pub window_answers: u32,
    /// The state.
    pub state: UpstreamState,
    /// Failures in a row.
    pub failures: u32,
    /// In back-off now.
    pub down: bool,
    /// Asked without 0x20 since it broke the case.
    pub lower_case: bool,
    /// The last failure, in English.
    pub last_error: Option<String>,
    /// When the last failure happened.
    pub last_error_at: Option<Timestamp>,
    /// The upstream the next query goes to (outside the probes).
    pub chosen: bool,
    /// Exchanges by outcome since the process started, in the order of [`OUTCOMES`].
    pub outcomes: [u64; 5],
}

impl MemberHealth {
    /// The state of an upstream no set holds yet: never asked.
    pub fn unmeasured(spec: &UpstreamSpec) -> Self {
        Self {
            upstream: spec.address.to_string(),
            transport: spec.transport,
            srtt: None,
            last_rtt: None,
            p50: None,
            p99: None,
            window_answers: 0,
            state: UpstreamState::Unknown,
            failures: 0,
            down: false,
            lower_case: false,
            last_error: None,
            last_error_at: None,
            chosen: false,
            outcomes: [0; 5],
        }
    }
}

impl Member {
    fn health(&self) -> std::sync::MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn succeeded(&self, rtt: Duration) {
        let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX).max(1);
        let mut health = self.health();
        health.failures = 0;
        health.down_until = None;
        health.answered = true;
        health.last_rtt = micros;
        health.srtt = if health.srtt == 0 {
            micros
        } else {
            (health.srtt * 7 + micros) / 8
        };
        drop(health);
        self.window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(micros, Instant::now());
        self.stats.rtt(micros);
        self.stats.state.store(STATE_UP, Ordering::Relaxed);
        self.stats.down_until.store(0, Ordering::Relaxed);
    }

    fn failed(&self, now: Instant, timeout: Duration, error: UpstreamError) {
        let mut health = self.health();
        health.failures = health.failures.saturating_add(1);
        health.answered = false;
        health.last_error = Some((error, Timestamp::now()));
        let ceiling = u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX);
        health.srtt = health
            .srtt
            .saturating_mul(2)
            .clamp(1_000, ceiling.max(1_000));
        if health.failures >= FAILURES_BEFORE_BACKOFF {
            let steps = (health.failures - FAILURES_BEFORE_BACKOFF).min(6);
            let backoff = Duration::from_secs(1u64 << steps).min(MAX_BACKOFF);
            health.down_until = Some(now + backoff);
            self.stats
                .down_until
                .store(millis_of(now + backoff), Ordering::Relaxed);
        }
        drop(health);
        self.stats.state.store(STATE_FAILING, Ordering::Relaxed);
    }

    fn broke_case(&self) {
        let mut health = self.health();
        health.last_error = Some((
            UpstreamError::Malformed("the answer broke the 0x20 case"),
            Timestamp::now(),
        ));
        health.case_strikes = health.case_strikes.saturating_add(1);
        if health.case_strikes >= CASE_STRIKES && !health.lower_case {
            health.lower_case = true;
            drop(health);
            tracing::info!(
                upstream = %self.label,
                "the upstream answers in another case than it was asked (0x20): it is asked in \
                 lower case from now on"
            );
        }
    }

    fn mixes_case(&self) -> bool {
        self.upstream.transport() == ForwardTransport::Plain && !self.health().lower_case
    }

    /// The upstream's state.
    pub fn state(&self) -> MemberHealth {
        let health = *self.health();
        let now = Instant::now();
        let (p50, p99, window_answers) = self
            .window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .quantiles(now);
        let down = health.down_until.is_some_and(|until| until > now);
        let state = if down {
            UpstreamState::Down
        } else if health.failures > 0 {
            UpstreamState::Degraded
        } else if health.answered {
            UpstreamState::Up
        } else {
            UpstreamState::Unknown
        };
        MemberHealth {
            upstream: self.label.clone(),
            transport: self.upstream.transport(),
            srtt: (health.srtt > 0).then(|| Duration::from_micros(health.srtt)),
            last_rtt: (health.last_rtt > 0).then(|| Duration::from_micros(health.last_rtt)),
            p50,
            p99,
            window_answers,
            state,
            failures: health.failures,
            down,
            lower_case: health.lower_case,
            last_error: health.last_error.map(|(error, _)| error.to_string()),
            last_error_at: health.last_error.map(|(_, at)| at),
            chosen: false,
            outcomes: self.stats.outcomes(),
        }
    }

    /// The counters of the upstream under its rule.
    pub fn stats(&self) -> &UpstreamStats {
        &self.stats
    }
}

/// The upstreams of one rule.
#[derive(Debug)]
pub struct UpstreamSet {
    rule: String,
    members: Vec<Member>,
}

impl UpstreamSet {
    /// A set named `rule` (the `rule` label) over `upstreams`, cut to [`MAX_MEMBERS`].
    pub fn new(rule: &str, upstreams: Vec<AnyUpstream>) -> Self {
        let members = upstreams
            .into_iter()
            .take(MAX_MEMBERS)
            .map(|upstream| {
                let label = upstream.address().to_string();
                let stats = upstream_stats(rule, &label, upstream.transport());
                stats.live.fetch_add(1, Ordering::Relaxed);
                Member {
                    stats,
                    label,
                    upstream,
                    health: Mutex::new(Health::default()),
                    window: Mutex::new(RttWindow::default()),
                }
            })
            .collect();
        Self {
            rule: rule.to_owned(),
            members,
        }
    }

    /// The `rule` label.
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// The upstreams.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// Whether the set has no upstream.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Whether every upstream is in back-off now (serve-stale answers at once then).
    pub fn all_down(&self, now: Instant) -> bool {
        !self.members.is_empty()
            && self
                .members
                .iter()
                .all(|member| member.health().down_until.is_some_and(|until| until > now))
    }

    /// The upstream for the next attempt; `tried` marks the ones asked already.
    fn choose(&self, tried: u64, now: Instant) -> usize {
        let fresh = |index: &usize| tried & (1 << index) == 0;
        let mut candidates: Vec<usize> = (0..self.members.len()).filter(fresh).collect();
        if candidates.is_empty() {
            candidates = (0..self.members.len()).collect();
        }
        let states: Vec<(usize, Health)> = candidates
            .iter()
            .map(|index| (*index, *self.members[*index].health()))
            .collect();
        let healthy: Vec<(usize, u64)> = states
            .iter()
            .filter(|(_, health)| health.down_until.is_none_or(|until| until <= now))
            .map(|(index, health)| (*index, health.srtt))
            .collect();
        if healthy.is_empty() {
            return states
                .iter()
                .min_by_key(|(_, health)| health.down_until)
                .map_or(0, |(index, _)| *index);
        }
        if healthy.len() > 1 && random_u32().is_multiple_of(PROBE_ONE_IN) {
            let pick = usize::try_from(random_u32()).unwrap_or(0) % healthy.len();
            return healthy[pick].0;
        }
        healthy
            .iter()
            .min_by_key(|(_, srtt)| *srtt)
            .map_or(0, |(index, _)| *index)
    }

    /// Asks the upstreams `question` within `budget` and writes the answer into `answer`.
    ///
    /// # Errors
    ///
    /// The error of the last attempt when no upstream answered.
    pub async fn query(
        &self,
        question: &Question<'_>,
        budget: Budget,
        answer: &mut Vec<u8>,
    ) -> Result<(), UpstreamError> {
        if self.members.is_empty() {
            return Err(UpstreamError::Unreachable("the rule has no upstream"));
        }
        let attempts = usize::from(budget.retries) + 1;
        let mut tried = 0u64;
        let mut last = UpstreamError::Timeout;
        let mut fallback: Option<Vec<u8>> = None;
        let mut query = Vec::with_capacity(512);
        for attempt in 0..attempts {
            let now = Instant::now();
            let index = self.choose(tried, now);
            tried |= 1 << index;
            let member = &self.members[index];
            let mixed = member.mixes_case();
            // DoH asks with id 0 (RFC 8484 section 4.1); the stream carries the match.
            let id = if member.upstream.transport() == ForwardTransport::Doh {
                0
            } else {
                random_u16()
            };
            build_query(&mut query, id, question, mixed);
            let started = Instant::now();
            match member
                .upstream
                .exchange(&query, answer, started + budget.timeout)
                .await
            {
                Ok(()) => {
                    if mixed && check_answer(&query, answer, true) == AnswerCheck::CaseBroken {
                        member.broke_case();
                        member.stats.count(4);
                        last = UpstreamError::Malformed("the answer broke the 0x20 case");
                        continue;
                    }
                    member.succeeded(started.elapsed());
                    let code = u16::from(answer.get(3).copied().unwrap_or(0) & 0x0f);
                    if (code == rcode::SERVFAIL || code == rcode::REFUSED)
                        && attempt + 1 < attempts
                        && self.members.len() > 1
                    {
                        member.stats.count(1);
                        fallback = Some(answer.clone());
                        continue;
                    }
                    member.stats.count(0);
                    return Ok(());
                }
                Err(error) => {
                    member.failed(Instant::now(), budget.timeout, error);
                    member.stats.count(match error {
                        UpstreamError::Timeout => 2,
                        UpstreamError::Unreachable(_) => 3,
                        UpstreamError::Malformed(_) => 4,
                    });
                    tracing::debug!(%error, upstream = %member.label, rule = %self.rule, "an upstream attempt failed");
                    last = error;
                }
            }
        }
        if let Some(kept) = fallback {
            *answer = kept;
            return Ok(());
        }
        Err(last)
    }

    /// The upstream the next query goes to outside the probes: the healthy one with the
    /// lowest smoothed round-trip time (one never measured first), else the one whose
    /// back-off ends first.
    pub fn chosen(&self, now: Instant) -> Option<usize> {
        let states: Vec<Health> = self.members.iter().map(|member| *member.health()).collect();
        states
            .iter()
            .enumerate()
            .filter(|(_, health)| health.down_until.is_none_or(|until| until <= now))
            .min_by_key(|(_, health)| health.srtt)
            .or_else(|| {
                states
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, health)| health.down_until)
            })
            .map(|(index, _)| index)
    }

    /// The state of each upstream, with the one the next query goes to marked.
    pub fn health(&self) -> Vec<MemberHealth> {
        let chosen = self.chosen(Instant::now());
        let mut members: Vec<MemberHealth> = self.members.iter().map(Member::state).collect();
        if let Some(member) = chosen.and_then(|index| members.get_mut(index)) {
            member.chosen = true;
        }
        members
    }
}

/// One upstream as a rule or the configuration names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamSpec {
    /// The address and port.
    pub address: std::net::SocketAddr,
    /// The transport.
    pub transport: ForwardTransport,
    /// TCP only, for a plain upstream.
    pub tcp_only: bool,
    /// The certificate name, for DoT and DoH.
    pub tls_name: Option<String>,
    /// The URL path, for DoH.
    pub path: Option<String>,
}

impl UpstreamSpec {
    /// The upstreams of a forwarding rule.
    pub fn of_rule(rule: &ForwardRule) -> Vec<Self> {
        rule.upstreams
            .iter()
            .map(|upstream| Self {
                address: std::net::SocketAddr::new(
                    upstream.address,
                    upstream.port.unwrap_or(rule.transport.default_port()),
                ),
                transport: rule.transport,
                tcp_only: false,
                tls_name: rule.tls_name.clone(),
                path: upstream.path.clone(),
            })
            .collect()
    }
}

/// Which set a query uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolKey {
    /// The default forwarder of the configuration (`[dns] forwarders`).
    Default,
    /// A forwarding rule of the store.
    Rule(ForwardRuleId),
    /// The name servers of a stub zone.
    Stub(ZoneId),
    /// The servers a stub zone's NS set is asked from (its `source`).
    StubSource(ZoneId),
}

/// The sets held: each with the specs it was built from.
type Sets = HashMap<PoolKey, (Vec<UpstreamSpec>, Arc<UpstreamSet>)>;

/// The sets of the forwarder, built on first use and rebuilt when their upstreams change.
#[derive(Debug)]
pub struct Pools {
    sets: Mutex<Sets>,
    ca: Option<Vec<u8>>,
    tls: OnceLock<Result<TlsClient, String>>,
}

impl Pools {
    /// Sets that check DoT and DoH certificates against `ca` (PEM) alone, or against the
    /// system's roots when it is `None`.
    pub fn new(ca: Option<Vec<u8>>) -> Self {
        Self {
            sets: Mutex::new(HashMap::new()),
            ca,
            tls: OnceLock::new(),
        }
    }

    /// The TLS client, built the first time a DoT or DoH upstream needs it.
    ///
    /// # Errors
    ///
    /// The reason it could not be built (no roots, a CA file without certificates).
    pub fn tls(&self) -> Result<&TlsClient, String> {
        self.tls
            .get_or_init(|| TlsClient::new(self.ca.as_deref()))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// One upstream of a spec.
    ///
    /// # Errors
    ///
    /// English text when the TLS name is missing or invalid or TLS cannot be set up.
    pub fn upstream(&self, spec: &UpstreamSpec) -> Result<AnyUpstream, String> {
        Ok(match spec.transport {
            ForwardTransport::Plain if spec.tcp_only => {
                AnyUpstream::Plain(PlainUpstream::tcp(spec.address))
            }
            ForwardTransport::Plain => AnyUpstream::Plain(PlainUpstream::udp(spec.address)),
            ForwardTransport::Dot => {
                let name = server_name(
                    spec.tls_name
                        .as_deref()
                        .ok_or("a DoT upstream needs a tls_name")?,
                )?;
                AnyUpstream::Dot(DotUpstream::new(spec.address, name, self.tls()?))
            }
            ForwardTransport::Doh => {
                let name = server_name(
                    spec.tls_name
                        .as_deref()
                        .ok_or("a DoH upstream needs a tls_name")?,
                )?;
                AnyUpstream::Doh(DohUpstream::new(
                    spec.address,
                    name,
                    spec.path.as_deref(),
                    self.tls()?,
                ))
            }
        })
    }

    /// The set of `key` over `specs`: the one held while the specs are unchanged (so the
    /// health and the times carry over), else a new one named `label`.
    ///
    /// # Errors
    ///
    /// English text when an upstream cannot be built (see [`Pools::upstream`]).
    pub fn get(
        &self,
        key: PoolKey,
        label: &str,
        specs: &[UpstreamSpec],
    ) -> Result<Arc<UpstreamSet>, String> {
        let mut sets = self.sets.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((held, set)) = sets.get(&key)
            && held.as_slice() == specs
        {
            return Ok(Arc::clone(set));
        }
        let upstreams = specs
            .iter()
            .map(|spec| self.upstream(spec))
            .collect::<Result<Vec<_>, _>>()?;
        let set = Arc::new(UpstreamSet::new(label, upstreams));
        sets.insert(key, (specs.to_vec(), Arc::clone(&set)));
        Ok(set)
    }

    /// The set of `key` if it was built.
    pub fn held(&self, key: PoolKey) -> Option<Arc<UpstreamSet>> {
        self.sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .map(|(_, set)| Arc::clone(set))
    }

    /// Drops the sets whose key `keep` refuses (rules and stub zones that are gone).
    pub fn retain(&self, mut keep: impl FnMut(&PoolKey) -> bool) {
        self.sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|key, _| keep(key));
    }
}

// The pool's tests run against in-test upstreams: `tests/upstreams.rs`.
