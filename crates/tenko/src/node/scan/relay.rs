//! The relay of the probe role in process on a controller (OPS-26, WP3.9): the scanner's
//! batches go into a local buffer under `<data_dir>/scan/relay/`, and a task hands them to
//! the controller's own ingest in order, oldest first. While the controller cannot write
//! (isolated, electing) or the ingest fails, the batches wait in the buffer and the task
//! tries again with a growing pause, so nothing the scanner saw is lost and the facts merge
//! once the controller can write again.
//!
//! Each batch is ingested under the controller's node id with the same resend recognition
//! as a probe node's (`cluster.ingest_cursors`): a batch that was ingested but not removed
//! from the buffer before a crash is recognised and not ingested twice. A batch that
//! answers a scan on demand is recorded as that command's result in the same write as the
//! cursor.

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use tenko_cluster::{
    buffer::{BufferConfig, ObservationBuffer},
    error::ClusterError,
    node_sync::cursors,
    probe::{ProbeBatch, ProbeSink},
};
use tenko_core::NodeId;
use tenko_scan::{ScanError, scanner::BatchSink};
use tenko_store::Store;
use tokio::sync::watch;
use uuid::Uuid;

/// The directory of the relay buffer under the data directory.
pub const RELAY_DIR: &str = "scan/relay";
/// The shortest and the longest pause after a failed ingest.
const RETRY: (Duration, Duration) = (Duration::from_millis(500), Duration::from_secs(30));
/// How often the relay looks at the buffer without a wake-up.
const POLL: Duration = Duration::from_secs(1);

/// The local buffer of a controller's probe role.
#[derive(Clone)]
pub struct Relay {
    buffer: ObservationBuffer,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("stats", &self.buffer.stats())
            .finish()
    }
}

impl Relay {
    /// Opens the relay buffer under `data_dir`, holding at most `max_bytes`.
    ///
    /// # Errors
    ///
    /// The buffer error of a directory that cannot be created or read.
    pub fn open(data_dir: &Path, max_bytes: u64) -> Result<Self, ClusterError> {
        let mut config = BufferConfig::new(data_dir.join(RELAY_DIR));
        if max_bytes > 0 {
            config.max_bytes = max_bytes;
            config.max_batch_bytes = config
                .max_batch_bytes
                .min(usize::try_from(max_bytes).unwrap_or(usize::MAX));
        }
        let buffer = ObservationBuffer::open(config).map_err(|error| {
            ClusterError::new(
                "cluster.buffer.open",
                500,
                format!("the scan relay: {error}"),
            )
        })?;
        Ok(Self { buffer })
    }

    /// The buffer.
    pub fn buffer(&self) -> &ObservationBuffer {
        &self.buffer
    }

    /// The scanner's sink into the buffer.
    pub fn sink(&self) -> Arc<dyn BatchSink> {
        Arc::new(RelaySink(self.buffer.clone()))
    }

    /// Hands the buffered batches to `sink` under `node`, oldest first, until `stop`
    /// turns true.
    pub async fn run(
        self,
        store: Arc<dyn Store>,
        sink: Arc<dyn ProbeSink>,
        node: NodeId,
        mut stop: watch::Receiver<bool>,
    ) {
        let epoch = self.buffer.epoch().to_string();
        let mut pause = RETRY.0;
        loop {
            if *stop.borrow() {
                return;
            }
            let buffer = self.buffer.clone();
            let pending = match tokio::task::spawn_blocking(move || buffer.peek()).await {
                Ok(Ok(pending)) => pending,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "the scan relay could not be read");
                    None
                }
                Err(error) => {
                    tracing::error!(%error, "the scan relay task failed");
                    None
                }
            };
            let Some(pending) = pending else {
                tokio::select! {
                    _ = stop.wait_for(|stopped| *stopped) => return,
                    () = self.buffer.changed() => {}
                    () = tokio::time::sleep(POLL) => {}
                }
                continue;
            };
            match self
                .deliver(
                    store.as_ref(),
                    sink.as_ref(),
                    node,
                    &epoch,
                    &pending.payload,
                    pending.sequence,
                )
                .await
            {
                Ok(()) => {
                    pause = RETRY.0;
                    self.ack(pending.sequence).await;
                }
                Err(error) if error.status() == 400 => {
                    tracing::warn!(sequence = pending.sequence, code = %error.code(), "a relayed batch is dropped: {}", error.detail());
                    self.ack(pending.sequence).await;
                }
                Err(error) => {
                    tracing::debug!(sequence = pending.sequence, code = %error.code(), "the relayed batch waits: {}", error.detail());
                    tokio::select! {
                        _ = stop.wait_for(|stopped| *stopped) => return,
                        () = tokio::time::sleep(pause) => {}
                    }
                    pause = (pause * 2).min(RETRY.1);
                }
            }
        }
    }

    async fn deliver(
        &self,
        store: &dyn Store,
        sink: &dyn ProbeSink,
        node: NodeId,
        epoch: &str,
        payload: &[u8],
        sequence: u64,
    ) -> Result<(), ClusterError> {
        if !store.status().quorum.accepts_writes() {
            return Err(ClusterError::new(
                tenko_cluster::node_sync::codes::NO_QUORUM,
                503,
                "this controller cannot write; the batch waits",
            ));
        }
        if cursors::seen_anywhere(store, node, epoch, sequence).await? {
            return Ok(());
        }
        let (batch, _skipped, run) = ProbeBatch::decode_with_run(payload)?;
        let tagged: Option<(Uuid, ProbeBatch)> = run.map(|command| (command, batch.clone()));
        let vrf = batch.vrf;
        sink.ingest(node, vrf, batch).await?;
        let run = tagged.as_ref().map(|(command, batch)| (*command, batch));
        if let Err(error) = cursors::record(store, node, epoch, sequence, run).await {
            tracing::warn!(sequence, code = %error.code(), "the ingest cursor of the probe role could not be written: {}", error.detail());
        }
        Ok(())
    }

    async fn ack(&self, sequence: u64) {
        let buffer = self.buffer.clone();
        match tokio::task::spawn_blocking(move || buffer.ack(sequence)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "a relayed batch could not be removed"),
            Err(error) => tracing::error!(%error, "the scan relay task failed"),
        }
    }
}

/// The scanner's batches into the relay buffer, split to fit an entry.
struct RelaySink(ObservationBuffer);

impl std::fmt::Debug for RelaySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySink").finish_non_exhaustive()
    }
}

#[async_trait]
impl BatchSink for RelaySink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        let buffer = self.0.clone();
        let limit = tenko_cluster::buffer::DEFAULT_MAX_BATCH_BYTES.saturating_sub(128);
        tokio::task::spawn_blocking(move || {
            let mut count = 0u32;
            for part in batch.split_to_fit(limit) {
                buffer
                    .push(&part.encode_with_run(run))
                    .map_err(|error| ScanError::io(error.to_string()))?;
                count = count.saturating_add(1);
            }
            Ok(count)
        })
        .await
        .map_err(|error| ScanError::io(error.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tenko_cluster::probe::IngestCounts;
    use tenko_core::{VrfId, observe::ProbeMethod};
    use tenko_store::{MemStore, ReadConsistency, ReadViewExt};

    use super::*;

    /// A sink that refuses until it is opened, then records what it took.
    #[derive(Default)]
    struct Gate {
        open: std::sync::atomic::AtomicBool,
        taken: Mutex<Vec<ProbeBatch>>,
    }

    #[async_trait]
    impl ProbeSink for Gate {
        async fn ingest(
            &self,
            _node: NodeId,
            _vrf: Option<VrfId>,
            batch: ProbeBatch,
        ) -> Result<IngestCounts, ClusterError> {
            if !self.open.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ClusterError::new(
                    "sys.store.no_quorum",
                    503,
                    "the store cannot write",
                ));
            }
            self.taken.lock().expect("lock").push(batch);
            Ok(IngestCounts::default())
        }
    }

    fn batch(host: u8) -> ProbeBatch {
        ProbeBatch {
            method: ProbeMethod::Arp,
            vrf: None,
            complete: false,
            collected_at: tenko_core::Timestamp::now(),
            sightings: vec![tenko_cluster::probe::Sighting {
                observed_at: tenko_core::Timestamp::now(),
                ttl_secs: None,
                subject: tenko_cluster::probe::SightingSubject::Address {
                    ip: std::net::IpAddr::from([192, 0, 2, host]),
                    mac: None,
                },
            }],
        }
    }

    #[tokio::test]
    async fn batches_wait_while_the_ingest_fails_and_go_in_order_afterwards() {
        let dir = tempfile::tempdir().expect("dir");
        let relay = Relay::open(dir.path(), 0).expect("relay");
        let sink = relay.sink();
        for host in 1..=3 {
            assert_eq!(sink.deliver(batch(host), None).await.expect("queued"), 1);
        }
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let gate = Arc::new(Gate::default());
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(relay.clone().run(
            Arc::clone(&store),
            Arc::clone(&gate) as Arc<dyn ProbeSink>,
            NodeId(1),
            stopped,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            relay.buffer().stats().batches,
            3,
            "nothing leaves while refused"
        );
        gate.open.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(10), async {
            while relay.buffer().stats().batches > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the relay drains");
        let taken: Vec<String> = gate
            .taken
            .lock()
            .expect("lock")
            .iter()
            .map(|batch| format!("{:?}", batch.sightings[0].subject))
            .collect();
        assert_eq!(taken.len(), 3);
        assert!(
            taken[0].contains("192.0.2.1") && taken[2].contains("192.0.2.3"),
            "{taken:?}"
        );
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let cursor = view
            .get_typed(&tenko_cluster::node_sync::tables::INGEST_CURSORS, &1)
            .expect("read")
            .expect("a cursor");
        assert_eq!(cursor.0.sequence, 3);
        stop.send(true).expect("receiver");
        task.await.expect("the relay stops");
    }
}
