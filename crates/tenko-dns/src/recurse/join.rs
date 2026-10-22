//! The join table (recursion plan section 2.1): identical client queries in flight (the
//! same name, type, class and view: the answer cache's key) share one resolution, so that a
//! burst of one name costs one resolution and an attacker cannot have many identical
//! queries outstanding at once (the birthday attack on outstanding queries). It lives on
//! the runtime: the worker hands queries over as before and never sees it.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
};

use tokio::sync::oneshot;

/// The resolutions in flight by key, each with the queries waiting for it.
type Waiting<T> = HashMap<Box<[u8]>, Vec<oneshot::Sender<Arc<T>>>>;

/// The table; `T` is the shared outcome.
#[derive(Debug)]
pub struct Joins<T> {
    waiting: Mutex<Waiting<T>>,
}

impl<T> Default for Joins<T> {
    fn default() -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
        }
    }
}

/// Removes the key when the leading resolution ends, also when its task is dropped: the
/// waiters then see a closed channel and resolve on their own.
struct Leader<'a, T> {
    joins: &'a Joins<T>,
    key: &'a [u8],
    done: bool,
}

impl<T> Drop for Leader<'_, T> {
    fn drop(&mut self) {
        if !self.done {
            self.joins.lock().remove(self.key);
        }
    }
}

impl<T> Joins<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Waiting<T>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queries in flight.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Runs `resolve` for `key`, or waits for the resolution of `key` in flight. Returns the
    /// outcome and whether it was joined.
    pub async fn run<F>(&self, key: &[u8], resolve: impl FnOnce() -> F) -> (Arc<T>, bool)
    where
        F: Future<Output = T>,
    {
        let receiver = {
            let mut waiting = self.lock();
            if let Some(waiters) = waiting.get_mut(key) {
                let (sender, receiver) = oneshot::channel();
                waiters.push(sender);
                Some(receiver)
            } else {
                waiting.insert(key.into(), Vec::new());
                None
            }
        };
        if let Some(receiver) = receiver {
            if let Ok(outcome) = receiver.await {
                return (outcome, true);
            }
            // The leader was dropped: resolve without the table.
            return (Arc::new(resolve().await), false);
        }
        let mut leader = Leader {
            joins: self,
            key,
            done: false,
        };
        let outcome = Arc::new(resolve().await);
        let waiters = self.lock().remove(key).unwrap_or_default();
        leader.done = true;
        for waiter in waiters {
            let _ = waiter.send(Arc::clone(&outcome));
        }
        (outcome, false)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test]
    async fn identical_queries_share_one_resolution() {
        let joins: Arc<Joins<u32>> = Arc::new(Joins::default());
        let runs = Arc::new(AtomicU32::new(0));
        let (release, released) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let joins = Arc::clone(&joins);
            let runs = Arc::clone(&runs);
            let mut released = released.clone();
            tasks.push(tokio::spawn(async move {
                joins
                    .run(b"key", || async move {
                        runs.fetch_add(1, Ordering::Relaxed);
                        let _ = released.wait_for(|go| *go).await;
                        42
                    })
                    .await
            }));
        }
        while joins.lock().get(&b"key"[..]).map_or(0, Vec::len) < 7 {
            tokio::task::yield_now().await;
        }
        let _ = release.send(true);
        let mut joined = 0;
        for task in tasks {
            let (outcome, was_joined) = task.await.expect("task");
            assert_eq!(*outcome, 42);
            joined += usize::from(was_joined);
        }
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert_eq!(joined, 7);
        assert!(joins.is_empty());
    }

    #[tokio::test]
    async fn a_dropped_leader_lets_the_waiters_resolve() {
        let joins: Arc<Joins<u32>> = Arc::new(Joins::default());
        let leader = {
            let joins = Arc::clone(&joins);
            tokio::spawn(async move { joins.run(b"key", std::future::pending::<u32>).await })
        };
        while joins.is_empty() {
            tokio::task::yield_now().await;
        }
        let waiter = {
            let joins = Arc::clone(&joins);
            tokio::spawn(async move { joins.run(b"key", || async { 7 }).await })
        };
        while joins.lock().get(&b"key"[..]).map_or(0, Vec::len) < 1 {
            tokio::task::yield_now().await;
        }
        leader.abort();
        let (outcome, joined) = waiter.await.expect("waiter");
        assert_eq!((*outcome, joined), (7, false));
        assert!(joins.is_empty());
    }
}
