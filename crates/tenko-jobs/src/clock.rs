//! Time for the engine: [`SystemClock`] in production, [`MockClock`] in tests.
//!
//! The engine reads the time only through a [`Clock`] and waits only through
//! [`Clock::sleep_until`], so job and step timeouts, waiting deadlines and runner leases
//! all follow a mock clock that a test advances by hand.

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use tenko_core::Timestamp;
use tokio::sync::watch;

/// A source of time and timers.
pub trait Clock: Send + Sync + 'static {
    /// The current time.
    fn now(&self) -> Timestamp;

    /// A future that completes once [`now`](Clock::now) has reached `deadline`.
    fn sleep_until(&self, deadline: Timestamp) -> BoxFuture<'static, ()>;
}

/// The system clock with tokio timers.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }

    fn sleep_until(&self, deadline: Timestamp) -> BoxFuture<'static, ()> {
        let wait = deadline.saturating_since(Timestamp::now());
        Box::pin(tokio::time::sleep(wait))
    }
}

/// A clock that only moves when told to. Cloning shares the clock.
///
/// Sleepers wake as soon as [`advance`](MockClock::advance) or [`set`](MockClock::set)
/// moves the time to or past their deadline.
#[derive(Debug, Clone)]
pub struct MockClock {
    time: Arc<watch::Sender<Timestamp>>,
}

impl MockClock {
    /// A clock standing at `start`.
    pub fn new(start: Timestamp) -> Self {
        let (time, _) = watch::channel(start);
        Self {
            time: Arc::new(time),
        }
    }

    /// Moves the clock forward.
    ///
    /// # Panics
    ///
    /// Panics if the result is outside the range of [`Timestamp`].
    pub fn advance(&self, by: Duration) {
        self.time.send_modify(|now| {
            *now = now.checked_add(by).expect("mock time stays in range");
        });
    }

    /// Sets the time; moving it backwards is allowed but wakes no sleeper.
    pub fn set(&self, to: Timestamp) {
        self.time.send_replace(to);
    }
}

impl Default for MockClock {
    /// A clock standing at 2026-10-09T12:00:00Z.
    fn default() -> Self {
        Self::new(
            Timestamp::from_unix_nanos(1_791_547_200_000_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        )
    }
}

impl Clock for MockClock {
    fn now(&self) -> Timestamp {
        *self.time.borrow()
    }

    fn sleep_until(&self, deadline: Timestamp) -> BoxFuture<'static, ()> {
        let mut time = self.time.subscribe();
        Box::pin(async move {
            loop {
                if *time.borrow_and_update() >= deadline {
                    return;
                }
                if time.changed().await.is_err() {
                    // The clock is gone: time never moves again.
                    futures::future::pending::<()>().await;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_sleepers_wake_when_the_clock_reaches_their_deadline() {
        let clock = MockClock::default();
        assert_eq!(clock.now().to_rfc3339(), "2026-10-09T12:00:00Z");
        let deadline = clock
            .now()
            .checked_add(Duration::from_secs(60))
            .expect("time");
        let sleeper = tokio::spawn(clock.sleep_until(deadline));
        clock.advance(Duration::from_secs(59));
        tokio::task::yield_now().await;
        assert!(!sleeper.is_finished());
        clock.advance(Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(5), sleeper)
            .await
            .expect("woken")
            .expect("joined");
        // A deadline in the past completes at once.
        clock.sleep_until(deadline).await;
    }

    #[tokio::test]
    async fn the_system_clock_sleeps_in_real_time() {
        let clock = SystemClock;
        let before = clock.now();
        clock
            .sleep_until(before.checked_add(Duration::from_millis(5)).expect("time"))
            .await;
        assert!(clock.now() >= before);
    }
}
