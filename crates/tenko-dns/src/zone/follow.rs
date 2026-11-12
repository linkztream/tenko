//! Following the store's change stream: the one loop with which the leader services and
//! watchers of this crate stay current with a set of tables.
//!
//! The contract of [`Follow::next`]:
//!
//! - The first call opens the stream at the current revision and answers
//!   [`Followed::Reset`]: the caller reads its whole state then. The stream is open before
//!   the answer, so no change after that read is missed.
//! - Every change set after that comes in revision order as [`Followed::Changes`], and its
//!   revision becomes the last one seen.
//! - A stream that ends because its reader lagged is opened again from the last revision
//!   seen: the change sets in between come as usual, nothing is lost and nothing is reset.
//!   Before the first change set there is no revision to resume from: the stream is opened
//!   at the current revision again and the answer is [`Followed::Reset`].
//! - When the store no longer holds the revisions after the last one seen (`Compacted`,
//!   whether the stream ends with it or opening answers it), the gap cannot be replayed:
//!   the stream is opened at the current revision and the answer is [`Followed::Reset`].
//! - A stream that cannot be opened, or that ends without an error (the store stops), is
//!   tried again after a pause that doubles from [`BACKOFF_MIN`] to [`BACKOFF_MAX`] and
//!   returns to the minimum with the next change set; the first failure of a run is logged
//!   at warn, the later ones at debug. It never spins and never gives up.
//! - Shutdown is the caller's: `next` is cancel-safe (the stream and the time of the next
//!   attempt live in the [`Follow`]), so the caller selects it against its stop token and
//!   drops it.

use std::{sync::Arc, time::Duration};

use futures::StreamExt as _;
use tenko_core::Revision;
use tenko_store::{ChangeSet, ChangeStream, Store, StoreError, WatchError, WatchFilter};
use tokio::time::Instant;

/// The first pause before a stream is opened again after a failure.
pub const BACKOFF_MIN: Duration = Duration::from_millis(100);

/// The longest pause between two attempts to open a stream.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// What [`Follow::next`] brings.
#[derive(Debug)]
pub enum Followed {
    /// Read the whole state again: the first call, or a gap the store cannot replay.
    Reset,
    /// The next change set.
    Changes(ChangeSet),
}

/// A follower of the tables of a [`WatchFilter`].
pub struct Follow {
    store: Arc<dyn Store>,
    filter: WatchFilter,
    what: &'static str,
    stream: Option<ChangeStream>,
    /// The revision of the last change set handed out.
    last: Option<Revision>,
    /// The caller has not been told to read its whole state since the last gap.
    reset: bool,
    retry_at: Option<Instant>,
    backoff: Duration,
}

impl std::fmt::Debug for Follow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follow")
            .field("what", &self.what)
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

impl Follow {
    /// A follower of `filter` in `store`; `what` names the follower in the log.
    pub fn new(store: Arc<dyn Store>, filter: WatchFilter, what: &'static str) -> Self {
        Self {
            store,
            filter,
            what,
            stream: None,
            last: None,
            reset: true,
            retry_at: None,
            backoff: BACKOFF_MIN,
        }
    }

    /// The next thing to do, by the contract of the module.
    pub async fn next(&mut self) -> Followed {
        loop {
            let Some(stream) = &mut self.stream else {
                if let Some(at) = self.retry_at {
                    tokio::time::sleep_until(at).await;
                    self.retry_at = None;
                }
                self.open();
                continue;
            };
            if self.reset {
                self.reset = false;
                return Followed::Reset;
            }
            match stream.next().await {
                Some(Ok(set)) => {
                    self.last = Some(set.revision);
                    self.backoff = BACKOFF_MIN;
                    return Followed::Changes(set);
                }
                Some(Err(WatchError::Lagged { .. })) => self.reopen(),
                Some(Err(WatchError::Compacted { .. })) => self.gap(),
                None => {
                    self.reopen();
                    self.failed(&"the change stream ended");
                }
            }
        }
    }

    /// The stream ends; the next one starts after the last revision seen. Before any
    /// change set was seen there is no such revision: the next one starts at the current
    /// revision, and what came in between is read whole (a reset).
    fn reopen(&mut self) {
        self.stream = None;
        if self.last.is_none() {
            self.reset = true;
        }
    }

    fn open(&mut self) {
        match self.store.watch(self.last, self.filter.clone()) {
            Ok(stream) => self.stream = Some(stream),
            Err(StoreError::Compacted { .. }) if self.last.is_some() => self.gap(),
            Err(error) => self.failed(&error),
        }
    }

    /// The revisions after the last one seen are gone: start over at the current one.
    fn gap(&mut self) {
        tracing::info!(
            follower = self.what,
            "the store no longer holds the changes after the last one seen; reading everything again"
        );
        self.stream = None;
        self.last = None;
        self.reset = true;
    }

    fn failed(&mut self, error: &dyn std::fmt::Display) {
        if self.backoff == BACKOFF_MIN {
            tracing::warn!(follower = self.what, %error, "the store's change stream cannot be followed; trying again");
        } else {
            tracing::debug!(follower = self.what, %error, "the store's change stream cannot be followed yet");
        }
        self.retry_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests;
