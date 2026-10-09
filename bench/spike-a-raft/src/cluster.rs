//! Starting and driving an in-process openraft cluster.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use openraft::BasicNode;
use openraft::Config;
use openraft::SnapshotPolicy;
use redb::Durability;

use crate::index::ServingIndex;
use crate::log_store::LogStore;
use crate::network::NetworkFactory;
use crate::network::Router;
use crate::raft_types::NodeId;
use crate::raft_types::Raft;
use crate::state_machine::NodeStats;
use crate::state_machine::SmOptions;
use crate::state_machine::StateMachineStore;

#[derive(Clone, Copy, Debug)]
pub struct ClusterOptions {
    pub log_cache_bytes: usize,
    pub sm_cache_bytes: usize,
    pub sm_durability: Durability,
    pub journal_retain: u64,
    pub max_payload_entries: u64,
    pub heartbeat_ms: u64,
    pub election_min_ms: u64,
    pub election_max_ms: u64,
}

pub struct Node {
    pub id: NodeId,
    pub raft: Raft,
    pub sm: StateMachineStore,
    pub log: LogStore,
    pub index: Arc<ServingIndex>,
    pub stats: Arc<NodeStats>,
    pub dir: PathBuf,
}

impl Node {
    pub fn log_file(&self) -> PathBuf {
        self.dir.join("log.redb")
    }

    pub fn sm_file(&self) -> PathBuf {
        self.dir.join("sm.redb")
    }

    pub fn metrics(&self) -> openraft::RaftMetrics<NodeId, BasicNode> {
        self.raft.metrics().borrow().clone()
    }
}

pub struct Cluster {
    pub router: Router,
    pub nodes: BTreeMap<NodeId, Node>,
    pub base_dir: PathBuf,
    pub opts: ClusterOptions,
}

fn raft_config(opts: &ClusterOptions) -> anyhow::Result<Config> {
    let cfg = Config {
        cluster_name: "spike-a".to_string(),
        heartbeat_interval: opts.heartbeat_ms,
        election_timeout_min: opts.election_min_ms,
        election_timeout_max: opts.election_max_ms,
        max_payload_entries: opts.max_payload_entries,
        // Snapshots are triggered explicitly by the benchmark.
        snapshot_policy: SnapshotPolicy::Never,
        // After a snapshot every log entry it covers may be purged, so a new learner has to be
        // brought up by a snapshot rather than by log replay.
        max_in_snapshot_log_to_keep: 0,
        install_snapshot_timeout: 30 * 60 * 1000,
        ..Default::default()
    };
    Ok(cfg.validate()?)
}

pub async fn start_node(
    id: NodeId,
    base_dir: &Path,
    router: &Router,
    opts: &ClusterOptions,
) -> anyhow::Result<Node> {
    let dir = base_dir.join(format!("node-{id}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)?;
    let log = LogStore::open(&dir.join("log.redb"), opts.log_cache_bytes)?;
    let index = Arc::new(ServingIndex::new());
    let stats = Arc::new(NodeStats::default());
    let sm = StateMachineStore::open(
        &dir.join("sm.redb"),
        &dir.join("snapshots"),
        index.clone(),
        stats.clone(),
        SmOptions {
            cache_bytes: opts.sm_cache_bytes,
            durability: opts.sm_durability,
            journal_retain: opts.journal_retain,
        },
    )?;
    let config = Arc::new(raft_config(opts)?);
    let raft = Raft::new(
        id,
        config,
        NetworkFactory {
            router: router.clone(),
        },
        log.clone(),
        sm.clone(),
    )
    .await?;
    router.register(id, raft.clone(), sm.clone());
    Ok(Node {
        id,
        raft,
        sm,
        log,
        index,
        stats,
        dir,
    })
}

pub fn basic_node(id: NodeId) -> BasicNode {
    BasicNode::new(format!("in-process-node-{id}"))
}

impl Cluster {
    /// Start `voters` nodes (ids 1..=voters), initialize node 1 with all of them as voters and
    /// wait until a leader is elected.
    pub async fn start(
        base_dir: &Path,
        voters: u32,
        opts: ClusterOptions,
    ) -> anyhow::Result<Cluster> {
        std::fs::create_dir_all(base_dir)?;
        let router = Router::default();
        let mut nodes = BTreeMap::new();
        for id in 1..=voters as NodeId {
            nodes.insert(id, start_node(id, base_dir, &router, &opts).await?);
        }
        let members: BTreeMap<NodeId, BasicNode> =
            nodes.keys().map(|id| (*id, basic_node(*id))).collect();
        nodes[&1].raft.initialize(members).await?;
        let cluster = Cluster {
            router,
            nodes,
            base_dir: base_dir.to_path_buf(),
            opts,
        };
        for n in cluster.nodes.values() {
            n.raft
                .wait(Some(Duration::from_secs(30)))
                .metrics(|m| m.current_leader.is_some(), "leader elected")
                .await?;
        }
        Ok(cluster)
    }

    pub fn leader_id(&self) -> anyhow::Result<NodeId> {
        for n in self.nodes.values() {
            if let Some(l) = n.metrics().current_leader {
                return Ok(l);
            }
        }
        anyhow::bail!("no leader known")
    }

    pub fn leader(&self) -> anyhow::Result<&Node> {
        let id = self.leader_id()?;
        self.nodes.get(&id).context("leader node not found")
    }

    /// A voter that is not the leader (falls back to the leader in a one-node cluster).
    pub fn follower(&self) -> anyhow::Result<&Node> {
        let lid = self.leader_id()?;
        Ok(self
            .nodes
            .values()
            .find(|n| n.id != lid)
            .unwrap_or(&self.nodes[&lid]))
    }

    /// Wait until every node has applied at least `index`.
    pub async fn wait_all_applied(&self, index: u64, timeout: Duration) -> anyhow::Result<()> {
        for n in self.nodes.values() {
            n.raft
                .wait(Some(timeout))
                .applied_index_at_least(Some(index), "all applied")
                .await?;
        }
        Ok(())
    }

    pub async fn add_node(&mut self, id: NodeId) -> anyhow::Result<()> {
        let node = start_node(id, &self.base_dir, &self.router, &self.opts).await?;
        self.nodes.insert(id, node);
        Ok(())
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        for (id, n) in self.nodes {
            self.router.unregister(id);
            n.raft
                .shutdown()
                .await
                .map_err(|e| anyhow::anyhow!("shutdown node {id}: {e}"))?;
        }
        Ok(())
    }
}
