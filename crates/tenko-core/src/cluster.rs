//! Leader-only work in a cluster of controllers (Slice 3, plan section 2.3).
//!
//! Every controller serves the API, the event streams and its node sessions, but some work
//! must run on exactly one controller at a time: the job runner, the reconciler loop, the
//! connector polling schedule, the update check, purges, audit export, scheduled backups
//! and command dispatch to nodes. Each owning package exposes such a loop as a
//! [`LeaderService`] instead of spawning it; the supervisor of `tenko serve` starts every
//! registered service when this controller takes office and cancels them when it loses
//! leadership or shuts down.
//!
//! # Epoch fencing
//!
//! Taking office bumps the store counter [`LEADER_EPOCH`] in a batch that expects its
//! previous value, and hands the new value to [`LeaderService::run`]. Every write a
//! leader-only service makes carries the counter precondition built by
//! `tenko_store::fence(epoch)`, so once another controller has taken office (and bumped
//! the counter again), every write of the deposed one fails at apply instead of racing
//! the new leader. A service that performs an external side effect (a network write, a
//! plugin call) confirms leadership with a linearizable read right before it, because a
//! precondition cannot fence what happens outside the store.
//!
//! A single controller is always the leader: the supervisor runs its services exactly as
//! today's start code does, with an epoch of its own.

use crate::names::CounterKey;

/// The store counter that numbers the terms of office of leader-only work. The supervisor
/// bumps it when this controller takes office; leader-only writes expect its value.
pub const LEADER_EPOCH: CounterKey = CounterKey::new("sys.leader_epoch");

/// A loop that runs on the leader only.
///
/// `run` is started by the supervisor after this controller has taken office, with the
/// epoch of that term, and runs until `stop` is cancelled (leadership lost or shutdown). It
/// returns `Ok(())` after a stop and an error text when it gave up on its own; the
/// supervisor logs the error and restarts the service with a backoff while this controller
/// stays the leader. A service keeps no state across terms that the store does not hold:
/// the next term may start on another controller.
#[async_trait::async_trait]
pub trait LeaderService: Send + Sync + 'static {
    /// A stable name for the log and `/system/status`, such as `jobs.runner`.
    fn name(&self) -> &'static str;

    /// Runs until `stop` fires. `epoch` is the value of the counter [`LEADER_EPOCH`]
    /// after this node bumped it on taking office; leader-only writes carry it as a counter
    /// precondition (`tenko_store::fence(epoch)`), so a deposed leader's writes fail.
    ///
    /// # Errors
    ///
    /// A description of why the service stopped on its own.
    async fn run(
        &self,
        epoch: u64,
        stop: tokio_util::sync::CancellationToken,
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct Idle;

    #[async_trait::async_trait]
    impl LeaderService for Idle {
        fn name(&self) -> &'static str {
            "test.idle"
        }

        async fn run(
            &self,
            _epoch: u64,
            stop: tokio_util::sync::CancellationToken,
        ) -> Result<(), String> {
            stop.cancelled().await;
            Ok(())
        }
    }

    #[test]
    fn services_are_object_safe_and_named() {
        let services: Vec<Arc<dyn LeaderService>> = vec![Arc::new(Idle)];
        assert_eq!(services[0].name(), "test.idle");
        assert_eq!(LEADER_EPOCH.name().as_str(), "sys.leader_epoch");
    }
}
