//! Time source of the authentication service.
//!
//! Every expiry, lockout and TOTP decision takes the time from a [`Clock`], so tests drive
//! time explicitly with `MockClock` (feature `testing`) instead of sleeping.

use std::fmt;
#[cfg(any(test, feature = "testing"))]
use std::{sync::Mutex, time::Duration};

use tenko_core::Timestamp;

/// A source of the current time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// The system clock (UTC).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A clock that only moves when told to. Test helper.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct MockClock {
    now: Mutex<Timestamp>,
}

#[cfg(any(test, feature = "testing"))]
impl MockClock {
    /// A clock standing at `start`.
    pub fn new(start: Timestamp) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// A clock standing at 2026-10-09T12:00:00Z.
    pub fn fixed() -> Self {
        // 1_791_547_200 s after the epoch is 2026-10-09T12:00:00Z.
        Self::new(
            Timestamp::from_unix_nanos(1_791_547_200_000_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        )
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now = now.checked_add(by).unwrap_or(*now);
    }

    /// Sets the clock.
    pub fn set(&self, to: Timestamp) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = to;
    }
}

#[cfg(any(test, feature = "testing"))]
impl Clock for MockClock {
    fn now(&self) -> Timestamp {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_moves_only_when_told() {
        let clock = MockClock::fixed();
        let start = clock.now();
        assert_eq!(start.to_rfc3339(), "2026-10-09T12:00:00Z");
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.now().saturating_since(start), Duration::from_secs(90));
        clock.set(start);
        assert_eq!(clock.now(), start);
    }

    #[test]
    fn system_clock_is_close_to_now() {
        let before = Timestamp::now();
        let now = SystemClock.now();
        assert!(now >= before);
    }
}
