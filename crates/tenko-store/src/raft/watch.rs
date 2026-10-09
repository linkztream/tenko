//! Watch streams over the journal (`sys.journal`), with the semantics of `MemStore`.
//!
//! A watcher replays journal entries after its cursor from a read view, then waits for the
//! applied revision to move. It ends with `Compacted` when the journal no longer holds the
//! revision after its cursor, and with `Lagged` when, once caught up, it falls further
//! behind the applied revision than the configured limit.

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tenko_core::Revision;
use tokio::sync::watch;

use super::sm::StateMachine;
use crate::api::{
    ChangeSet, ChangeStream, KeyRange, ReadView, StoreError, WatchError, WatchFilter, tables,
};

const JOURNAL_CHUNK: usize = 256;

/// State of one watch stream.
struct Watcher {
    sm: StateMachine,
    shutdown: Arc<AtomicBool>,
    max_lag: u64,
    /// The last revision handed to the consumer (or skipped by the filter).
    cursor: Revision,
    filter: WatchFilter,
    notified: watch::Receiver<Revision>,
    pending: VecDeque<ChangeSet>,
    /// Whether the stream has reached the live revision once; only then does lag count.
    caught_up: bool,
    done: bool,
}

enum Step {
    Wait,
    Loaded(Vec<ChangeSet>, Revision),
    Fail(WatchError),
}

/// Opens a watch stream after `from` (`None`: the current revision).
pub(crate) fn watch(
    sm: &StateMachine,
    shutdown: Arc<AtomicBool>,
    max_lag: u64,
    from: Option<Revision>,
    filter: WatchFilter,
) -> Result<ChangeStream, StoreError> {
    let notified = sm.subscribe();
    let view = sm.view()?;
    let current = view.revision();
    let cursor = from.unwrap_or(current);
    if cursor < current {
        match view.meta().journal_oldest {
            Some(oldest) if oldest <= cursor.next() => {}
            oldest => {
                return Err(StoreError::Compacted {
                    oldest: oldest.unwrap_or(current),
                });
            }
        }
    }
    drop(view);
    let watcher = Watcher {
        sm: sm.clone(),
        shutdown,
        max_lag,
        cursor,
        filter,
        notified,
        pending: VecDeque::new(),
        caught_up: cursor >= current,
        done: false,
    };
    Ok(Box::pin(futures::stream::unfold(
        watcher,
        |mut watcher| async move { watcher.next().await.map(|item| (item, watcher)) },
    )))
}

impl Watcher {
    async fn next(&mut self) -> Option<Result<ChangeSet, WatchError>> {
        loop {
            if self.done {
                return None;
            }
            if let Some(change_set) = self.pending.pop_front() {
                return Some(Ok(change_set));
            }
            if self.shutdown.load(Ordering::SeqCst) {
                self.done = true;
                return None;
            }
            // Mark the notification as seen before reading, so a commit after the read
            // always wakes the wait below.
            self.notified.borrow_and_update();
            match self.load() {
                Step::Fail(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
                Step::Loaded(change_sets, current) => {
                    for change_set in change_sets {
                        self.cursor = change_set.revision;
                        if let Some(filtered) = self.filter.apply(&change_set) {
                            self.pending.push_back(filtered);
                        }
                    }
                    if self.cursor >= current {
                        self.caught_up = true;
                    }
                }
                Step::Wait => {
                    self.caught_up = true;
                    if self.notified.changed().await.is_err() {
                        self.done = true;
                        return None;
                    }
                }
            }
        }
    }

    fn load(&self) -> Step {
        let Ok(view) = self.sm.view() else {
            // An unreadable store: the consumer must reload, like after a lag.
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        };
        let current = view.revision();
        if current <= self.cursor {
            return Step::Wait;
        }
        if self.caught_up && current.get() - self.cursor.get() > self.max_lag {
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        }
        match view.meta().journal_oldest {
            Some(oldest) if oldest <= self.cursor.next() => {}
            oldest => {
                return Step::Fail(WatchError::Compacted {
                    oldest: oldest.unwrap_or(current),
                });
            }
        }
        let range = KeyRange::all().after(tables::JOURNAL.key(&self.cursor));
        let Ok(rows) = view.scan(tables::JOURNAL.name(), range, JOURNAL_CHUNK, false) else {
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        };
        let mut change_sets = Vec::with_capacity(rows.len());
        for (_, versioned) in rows {
            match tables::JOURNAL.decode(&versioned.value) {
                Ok(change_set) => change_sets.push(change_set),
                // An unreadable journal entry: the consumer must reload, like after a lag.
                Err(_) => return Step::Fail(WatchError::Lagged { last: self.cursor }),
            }
        }
        if change_sets.is_empty() {
            // The journal must hold every revision after the oldest retained one; a hole
            // would make the stream spin, so the consumer reloads instead.
            return Step::Fail(WatchError::Lagged { last: self.cursor });
        }
        Step::Loaded(change_sets, current)
    }
}
