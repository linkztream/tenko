//! The two times of a move (`docs/moves.md` section 5): when the client's next DHCP
//! message is expected, and the migration deadline, when the job gives up and rolls back.
//!
//! # What a moved client does (RFC 2131 section 4.4.5)
//!
//! A bound client sends nothing until T1 (half the lease unless the server sets option
//! 58). At T1 it unicasts a REQUEST to its server, RENEWING; without an answer it sends
//! again after half the time left to T2, at least 60 seconds. At T2 (seven eighths unless
//! option 59) it broadcasts the REQUEST, REBINDING, again after half the time left to the
//! lease's end, at least 60 seconds; at the end it starts over with a DISCOVER.
//!
//! A client whose network the move changed keeps its old address. Its unicast REQUEST at
//! T1 never leaves it (it cannot reach its old gateway), and a NAK the server could send
//! goes to the old network (`tests/engine.rs` documents it), so T1 is no deadline. Its
//! broadcast at T2 reaches the relay of the new network, the relay's `giaddr` selects the
//! target scope, the engine NAKs the old address and the client DISCOVERs and gets its new
//! address. The real deadline of a client that does not react to the link change is
//! therefore T2 or the end of its lease. What makes it short is the short lease the job
//! asks for before it changes the network ([`super::lease`]).
//!
//! # The times
//!
//! Both come from the client's own lease when Tenko serves the old network (the row of
//! `dhcp.leases`: its `cltt` is the start, `ends` the end; the row keeps no T1 or T2, so
//! they are the RFC defaults), and from the target pools' default lease time otherwise.
//!
//! - **Next expected DHCP activity** ([`LeaseClock::next_activity`]): before T1, T1; then
//!   the next retransmission of the RENEWING or REBINDING schedule above; at the end, the
//!   end.
//! - **Migration deadline** ([`migration_deadline`]): the request's timeout when it names
//!   one; else, after a successful preparation, the short lease's end plus the margin; else
//!   the end of the client's lease plus the margin, at most the configured limit; else the
//!   target pools' lease plus the margin, at most the limit; else 3,600 seconds. Never
//!   below 300 seconds from the start of the observation.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tenko_core::{Timestamp, dhcp::Lease};
use utoipa::ToSchema;

use super::{DEFAULT_TIMEOUT_SECS, MIN_TIMEOUT_SECS, MoveTimeoutSource, settings::MoveSettings};

/// The shortest wait between two retransmissions of a REQUEST (RFC 2131 section 4.4.5).
pub const MIN_RETRANSMIT_SECS: u64 = 60;

/// `at` plus `secs`.
pub fn plus(at: Timestamp, secs: u64) -> Timestamp {
    at.checked_add(Duration::from_secs(secs)).unwrap_or(at)
}

/// `at` less `secs`.
pub fn minus(at: Timestamp, secs: u64) -> Timestamp {
    Timestamp::from_unix_nanos(at.unix_nanos() - i128::from(secs) * 1_000_000_000).unwrap_or(at)
}

/// Seconds from `earlier` to `later`, 0 when `later` is not after it.
pub fn secs_between(earlier: Timestamp, later: Timestamp) -> u64 {
    later.saturating_since(earlier).as_secs()
}

/// A client's lease as the timing reads it: its start and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseClock {
    /// When the client last got it (the row's `cltt`).
    pub start: Timestamp,
    /// Its length in seconds.
    pub secs: u64,
}

impl LeaseClock {
    /// The clock of a lease row.
    pub fn of(lease: &Lease) -> Self {
        Self {
            start: lease.cltt,
            secs: secs_between(lease.cltt, lease.ends),
        }
    }

    /// A lease of `secs` that started at `start`.
    pub fn new(start: Timestamp, secs: u64) -> Self {
        Self { start, secs }
    }

    /// T1 in seconds from the start (half the lease).
    pub fn t1_secs(&self) -> u64 {
        self.secs / 2
    }

    /// T2 in seconds from the start (seven eighths of the lease).
    pub fn t2_secs(&self) -> u64 {
        self.secs / 8 * 7 + self.secs % 8 * 7 / 8
    }

    /// The lease's end.
    pub fn end(&self) -> Timestamp {
        plus(self.start, self.secs)
    }

    /// When the client is expected to send its next DHCP message after `now`: T1 before
    /// T1, then the RENEWING and REBINDING retransmissions (half the time left to T2, then
    /// to the end, at least 60 seconds), then the end of the lease, when it starts over
    /// with a DISCOVER; none once the lease has ended.
    pub fn next_activity(&self, now: Timestamp) -> Option<Timestamp> {
        let elapsed = secs_between(self.start, now);
        let (t1, t2, end) = (self.t1_secs(), self.t2_secs(), self.secs);
        if elapsed >= end {
            return None;
        }
        let next = if elapsed <= t1 {
            t1
        } else if elapsed < t2 {
            retransmission(t1, t2, elapsed)
        } else {
            retransmission(t2, end, elapsed)
        };
        Some(plus(self.start, next))
    }
}

/// The first retransmission after `elapsed` of a schedule that starts at `from` and waits
/// half the time left to `to`, at least 60 seconds, with `to` itself as the last point.
fn retransmission(from: u64, to: u64, elapsed: u64) -> u64 {
    let mut at = from;
    // At most a few dozen steps: the waits halve until they reach 60 seconds.
    for _ in 0..4_096 {
        let next = at + ((to - at) / 2).max(MIN_RETRANSMIT_SECS);
        if next >= to {
            return to;
        }
        if next > elapsed {
            return next;
        }
        at = next;
    }
    to
}

/// What the migration deadline is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineInputs {
    /// The request's own timeout.
    pub request_secs: Option<u32>,
    /// The client's lease on its old network, when Tenko serves it.
    pub lease: Option<LeaseClock>,
    /// Whether that lease is the short lease of the preparation.
    pub prepared: bool,
    /// The longest default lease of the target's pools.
    pub pool_secs: Option<u32>,
}

/// The migration deadline of an observation that starts at `start`, and how it was
/// chosen (see the module documentation).
pub fn migration_deadline(
    start: Timestamp,
    inputs: &DeadlineInputs,
    settings: &MoveSettings,
) -> (Timestamp, MoveTimeoutSource) {
    if let Some(secs) = inputs.request_secs {
        return (plus(start, u64::from(secs)), MoveTimeoutSource::Request);
    }
    let floor = plus(start, u64::from(MIN_TIMEOUT_SECS));
    let limit = plus(start, u64::from(settings.deadline_limit_secs));
    let margin = u64::from(settings.margin_secs);
    if let Some(lease) = inputs.lease {
        let end = plus(lease.end(), margin);
        if inputs.prepared {
            return (end.max(floor), MoveTimeoutSource::ShortLease);
        }
        return (end.min(limit).max(floor), MoveTimeoutSource::Lease);
    }
    if let Some(pool) = inputs.pool_secs {
        let end = plus(start, u64::from(pool) + margin);
        return (end.min(limit).max(floor), MoveTimeoutSource::Pool);
    }
    (
        plus(start, u64::from(DEFAULT_TIMEOUT_SECS)),
        MoveTimeoutSource::Default,
    )
}

/// How the next expected DHCP activity of a client was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MoveActivitySource {
    /// From the client's lease in Tenko's lease table.
    Lease,
    /// Half the target pools' default lease time: Tenko does not serve the old network.
    Pool,
    /// Unknown: no lease and no lease time.
    #[default]
    Unknown,
}

/// What the job does before it changes the client's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MovePrepare {
    /// It waits for the client's next renewal, which gets the short lease.
    ShortLease,
    /// The next renewal is expected after the preparation limit: the job moves at once.
    Limit,
    /// The operator chose to move at once (`move_now`).
    MoveNow,
    /// Tenko holds no lease of the client on its old network.
    #[default]
    NotServed,
    /// The interface has no MAC address to find the client's lease by.
    NoMac,
}

/// The two times of one moved address, as the preview estimates them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct MoveTiming {
    /// When the client's next DHCP message is expected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_activity: Option<Timestamp>,
    /// How that was found.
    pub next_activity_source: MoveActivitySource,
    /// The start of the client's lease on its old network, when Tenko serves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_start: Option<Timestamp>,
    /// Its end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_end: Option<Timestamp>,
    /// What the job does before the network change.
    pub prepare: MovePrepare,
    /// The short lease the job asks for, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_lease_secs: Option<u32>,
    /// The migration deadline in seconds from the start of the observation, as if it
    /// started now; the job computes it again from the lease when the observation starts.
    pub deadline_secs: u32,
    /// How the deadline was chosen.
    pub deadline_source: MoveTimeoutSource,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> Timestamp {
        plus("2026-10-26T12:00:00Z".parse().expect("time"), secs)
    }

    /// A lease of one hour from `t(0)`: T1 at 1,800 s, T2 at 3,150 s.
    fn hour() -> LeaseClock {
        LeaseClock::new(t(0), 3_600)
    }

    #[test]
    fn before_t1_the_next_activity_is_t1() {
        assert_eq!(hour().t1_secs(), 1_800);
        assert_eq!(hour().t2_secs(), 3_150);
        assert_eq!(hour().next_activity(t(0)), Some(t(1_800)));
        assert_eq!(hour().next_activity(t(1_799)), Some(t(1_800)));
        assert_eq!(hour().next_activity(t(1_800)), Some(t(1_800)));
    }

    #[test]
    fn between_t1_and_t2_the_client_retransmits_at_half_the_time_left() {
        // 1,800 + 675 = 2,475; + 337 = 2,812; + 169 = 2,981; + 84 = 3,065; + 60 = 3,125;
        // the next 60 s would pass T2, so T2.
        assert_eq!(hour().next_activity(t(1_801)), Some(t(2_475)));
        assert_eq!(hour().next_activity(t(2_475)), Some(t(2_812)));
        assert_eq!(hour().next_activity(t(2_900)), Some(t(2_981)));
        assert_eq!(hour().next_activity(t(3_000)), Some(t(3_065)));
        assert_eq!(hour().next_activity(t(3_100)), Some(t(3_125)));
        assert_eq!(hour().next_activity(t(3_130)), Some(t(3_150)));
    }

    #[test]
    fn after_t2_the_client_rebinds_towards_the_end_then_starts_over() {
        // 3,150 + 225 = 3,375; + 112 = 3,487; + 60 = 3,547; then the end.
        assert_eq!(hour().next_activity(t(3_150)), Some(t(3_375)));
        assert_eq!(hour().next_activity(t(3_400)), Some(t(3_487)));
        assert_eq!(hour().next_activity(t(3_500)), Some(t(3_547)));
        assert_eq!(hour().next_activity(t(3_560)), Some(t(3_600)));
        assert_eq!(hour().next_activity(t(3_600)), None);
    }

    #[test]
    fn a_short_lease_retransmits_at_least_sixty_seconds_apart() {
        let short = LeaseClock::new(t(0), 120);
        assert_eq!(short.next_activity(t(0)), Some(t(60)));
        // T2 at 105 s comes before the first 60-second retransmission.
        assert_eq!(short.next_activity(t(61)), Some(t(105)));
        assert_eq!(short.next_activity(t(106)), Some(t(120)));
    }

    #[test]
    fn the_deadline_follows_the_lease_and_the_preparation() {
        let settings = MoveSettings::default();
        let start = t(100);
        let lease = Some(LeaseClock::new(t(0), 3_600));
        // The request's timeout wins.
        let asked = DeadlineInputs {
            request_secs: Some(900),
            lease,
            prepared: false,
            pool_secs: Some(86_400),
        };
        assert_eq!(
            migration_deadline(start, &asked, &settings),
            (t(1_000), MoveTimeoutSource::Request)
        );
        // The client's lease: its end plus the margin.
        let leased = DeadlineInputs {
            request_secs: None,
            ..asked
        };
        assert_eq!(
            migration_deadline(start, &leased, &settings),
            (t(3_660), MoveTimeoutSource::Lease)
        );
        // The short lease of a preparation ends soon; the floor of 300 s holds.
        let prepared = DeadlineInputs {
            lease: Some(LeaseClock::new(t(90), 120)),
            prepared: true,
            ..leased
        };
        assert_eq!(
            migration_deadline(start, &prepared, &settings),
            (t(400), MoveTimeoutSource::ShortLease)
        );
        // A long lease is bounded by the limit.
        let long = DeadlineInputs {
            lease: Some(LeaseClock::new(t(0), 8 * 86_400)),
            ..leased
        };
        assert_eq!(
            migration_deadline(start, &long, &settings),
            (t(100 + 172_800), MoveTimeoutSource::Lease)
        );
        // Without the client's lease, the target pools' lease from the start.
        let pool = DeadlineInputs {
            lease: None,
            ..leased
        };
        assert_eq!(
            migration_deadline(start, &pool, &settings),
            (t(100 + 86_460), MoveTimeoutSource::Pool)
        );
        let nothing = DeadlineInputs {
            pool_secs: None,
            ..pool
        };
        assert_eq!(
            migration_deadline(start, &nothing, &settings),
            (t(3_700), MoveTimeoutSource::Default)
        );
        // An ended lease gives the floor.
        let ended = DeadlineInputs {
            lease: Some(LeaseClock::new(t(0), 60)),
            ..leased
        };
        assert_eq!(migration_deadline(start, &ended, &settings).0, t(400));
    }
}
