//! Test doubles (feature `testing`).

use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{Mutex, PoisonError},
};

use tenko_core::Timestamp;

use crate::{
    Capability, Connector, ConnectorError, Cursor, DriverInfo, Health, HealthReport,
    InventoryBatch, InventorySource,
};

/// An inventory source that returns scripted poll results in order and records the
/// cursors it was polled with. After the script runs out it returns an empty, incomplete
/// batch with the last cursor.
#[derive(Debug, Default)]
pub struct MockInventorySource {
    script: Mutex<VecDeque<Result<InventoryBatch, ConnectorError>>>,
    polls: Mutex<Vec<Option<Cursor>>>,
}

impl MockInventorySource {
    /// A source that answers with `script`, one entry per poll.
    pub fn new(script: impl IntoIterator<Item = Result<InventoryBatch, ConnectorError>>) -> Self {
        Self {
            script: Mutex::new(script.into_iter().collect()),
            polls: Mutex::new(Vec::new()),
        }
    }

    /// The cursors of every poll so far.
    pub fn polls(&self) -> Vec<Option<Cursor>> {
        self.polls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl Connector for MockInventorySource {
    fn info(&self) -> DriverInfo {
        DriverInfo {
            driver: Cow::Borrowed("mock"),
            version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
            capabilities: vec![Capability::Inventory],
        }
    }

    async fn check(&self) -> Result<HealthReport, ConnectorError> {
        Ok(HealthReport {
            health: Health::Healthy,
            checked_at: Timestamp::now(),
            latency_ms: Some(0),
            remote_version: None,
            detail: None,
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for MockInventorySource {
    async fn poll(&self, cursor: Option<Cursor>) -> Result<InventoryBatch, ConnectorError> {
        self.polls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cursor.clone());
        let next = self
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        next.unwrap_or_else(|| {
            Ok(InventoryBatch {
                observed_at: Timestamp::now(),
                hosts: Vec::new(),
                complete: false,
                cursor,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{MacAddr, observe::ObservedHost};

    use super::*;

    #[tokio::test]
    async fn mock_source_follows_its_script() {
        let host = ObservedHost {
            external_id: "qemu/100".to_owned(),
            name: Some("web01".to_owned()),
            macs: vec!["00:00:5e:00:53:10".parse::<MacAddr>().expect("mac")],
            ips: vec!["192.0.2.10".parse().expect("ip")],
            ..ObservedHost::default()
        };
        let source = MockInventorySource::new([
            Ok(InventoryBatch {
                observed_at: "2026-10-09T12:00:00Z".parse().expect("time"),
                hosts: vec![host.clone()],
                complete: true,
                cursor: Some(Cursor("1".to_owned())),
            }),
            Err(ConnectorError::Unreachable),
        ]);
        let first = source.poll(None).await.expect("first poll");
        assert_eq!(first.hosts, vec![host]);
        assert!(first.complete);
        assert_eq!(
            source.poll(first.cursor.clone()).await,
            Err(ConnectorError::Unreachable)
        );
        let idle = source.poll(first.cursor.clone()).await.expect("idle poll");
        assert_eq!(idle.hosts.len(), 0);
        assert_eq!(
            source.polls(),
            vec![None, first.cursor.clone(), first.cursor]
        );
        assert_eq!(
            source.check().await.expect("health").health,
            Health::Healthy
        );
        assert!(source.webhook().is_none());
    }
}
