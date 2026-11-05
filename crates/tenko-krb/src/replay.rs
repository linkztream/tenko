//! The acceptor's replay cache (RFC 4120 section 3.2.3; identity plan section 3.3).
//!
//! One cache serves every negotiation of an acceptor (the spike's observation S6 against
//! `sspi`, whose cache was per context). An entry is the client principal, the
//! authenticator's `ctime` and `cusec` (decision 6 of the spike) and lives until
//! `ctime` plus the skew window: after that the skew check refuses the authenticator
//! anyway. Anything whose `ctime` is not later than the acceptor's start is refused, so
//! that a restart, which empties the cache, does not open a window for replays of what was
//! sent before it (without the five minutes of refusals the RFC otherwise asks for).
//!
//! The cache is bounded: when it is full and pruning the expired entries frees nothing,
//! a new authenticator is refused rather than an entry dropped.

use std::collections::HashMap;

/// The most entries held by default: a busy node sees a few TKEY negotiations a second.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Why an authenticator was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// The authenticator was seen before.
    #[error("the authenticator was seen before")]
    Replay,
    /// Its time is not later than the acceptor's start.
    #[error("the authenticator is from before the acceptor started")]
    BeforeStart,
    /// The cache is full of live entries.
    #[error("the replay cache is full")]
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Entry {
    client: String,
    ctime: i64,
    cusec: u32,
}

/// The replay cache.
#[derive(Debug)]
pub struct ReplayCache {
    started: i64,
    skew: i64,
    max: usize,
    entries: HashMap<Entry, i64>,
}

impl ReplayCache {
    /// A cache for an acceptor that started at `started` (Unix seconds) with a skew window
    /// of `skew` seconds.
    pub fn new(started: i64, skew: i64, max: usize) -> Self {
        Self {
            started,
            skew,
            max,
            entries: HashMap::new(),
        }
    }

    /// The number of entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entry is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drops the entries whose window has passed at `now`.
    pub fn prune(&mut self, now: i64) {
        self.entries.retain(|_, expires| *expires >= now);
    }

    /// Records an authenticator of `client` with `ctime` and `cusec`, seen at `now`.
    ///
    /// # Errors
    ///
    /// A [`ReplayError`].
    pub fn check(
        &mut self,
        client: &str,
        ctime: i64,
        cusec: u32,
        now: i64,
    ) -> Result<(), ReplayError> {
        if ctime <= self.started {
            return Err(ReplayError::BeforeStart);
        }
        let entry = Entry {
            client: client.to_owned(),
            ctime,
            cusec,
        };
        if self.entries.contains_key(&entry) {
            return Err(ReplayError::Replay);
        }
        if self.entries.len() >= self.max {
            self.prune(now);
            if self.entries.len() >= self.max {
                return Err(ReplayError::Full);
            }
        }
        self.entries.insert(entry, ctime.saturating_add(self.skew));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS-28: a replay is refused, as is anything from before the start; entries expire
    /// after the skew window and the cache stays bounded.
    #[test]
    fn dns_28_replays_are_refused_and_entries_expire() {
        let mut cache = ReplayCache::new(1_000, 300, 3);
        assert_eq!(
            cache.check("alice@CORP.EXAMPLE.TEST", 1_000, 5, 1_001),
            Err(ReplayError::BeforeStart)
        );
        assert_eq!(
            cache.check("alice@CORP.EXAMPLE.TEST", 999, 5, 1_001),
            Err(ReplayError::BeforeStart)
        );
        cache
            .check("alice@CORP.EXAMPLE.TEST", 1_001, 5, 1_001)
            .expect("first");
        assert_eq!(
            cache.check("alice@CORP.EXAMPLE.TEST", 1_001, 5, 1_002),
            Err(ReplayError::Replay)
        );
        cache
            .check("alice@CORP.EXAMPLE.TEST", 1_001, 6, 1_002)
            .expect("another usec");
        cache
            .check("bob@CORP.EXAMPLE.TEST", 1_001, 5, 1_002)
            .expect("another client");
        assert_eq!(cache.len(), 3);
        // Full of live entries: refused, nothing dropped.
        assert_eq!(
            cache.check("carol@CORP.EXAMPLE.TEST", 1_010, 0, 1_010),
            Err(ReplayError::Full)
        );
        assert_eq!(cache.len(), 3);
        // After the window the old entries go and the new one fits.
        cache
            .check("carol@CORP.EXAMPLE.TEST", 1_400, 0, 1_400)
            .expect("after the window");
        assert_eq!(cache.len(), 1);
        cache.prune(1_701);
        assert!(cache.is_empty());
    }
}
