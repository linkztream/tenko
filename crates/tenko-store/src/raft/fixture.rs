//! A cluster of Raft stores in one process over [`InProcessNetwork`] (feature `testing`):
//! the fixture of the follower conformance cases (`tests/conformance_raft.rs`) and of the
//! in-process cluster tests of other packages (the job runner as a leader service, the
//! partition layer).
//!
//! [`InProcessCluster::start`] opens `size` temporary stores, makes member 1 the bootstrap
//! voter, adds the others as learners, waits until they caught up and makes all of them
//! voters. Writes on any member are forwarded to the leader through the network's leader
//! link; [`ClusterFixture::change_leader`] hands leadership over with
//! [`RaftStore::step_down`].
//!
//! ```ignore
//! use tenko_store::{raft::fixture::InProcessCluster, testing::ConformanceConfig};
//!
//! let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
//! let follower = cluster.a_follower().await;
//! follower.propose(batch).await?; // forwarded to the leader, readable here at once
//! ```

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::NodeId;

use super::{RaftStore, RaftStoreConfig, network::InProcessNetwork};
use crate::{
    api::{Store, StoreRole},
    testing::{ClusterFixture, ConformanceConfig},
};

/// How long the fixture waits for a leader, a catch-up or a hand-over.
const WAIT: Duration = Duration::from_secs(30);

/// Raft stores in one process that form one cluster.
pub struct InProcessCluster {
    network: InProcessNetwork,
    members: Vec<RaftStore>,
}

impl std::fmt::Debug for InProcessCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessCluster")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

impl InProcessCluster {
    /// `size` voters (nodes 1 to `size`) in temporary directories, configured for the
    /// conformance suite.
    ///
    /// # Panics
    ///
    /// Panics when a store does not open or the cluster does not form in time.
    pub async fn start(size: usize, config: &ConformanceConfig) -> Self {
        Self::start_with(size, config, |_| {}).await
    }

    /// As [`InProcessCluster::start`], with `configure` applied to each member's
    /// configuration (timings, snapshot policy) before it opens.
    ///
    /// # Panics
    ///
    /// Panics when a store does not open or the cluster does not form in time.
    pub async fn start_with(
        size: usize,
        config: &ConformanceConfig,
        configure: impl Fn(&mut RaftStoreConfig),
    ) -> Self {
        assert!(size >= 1, "a cluster has at least one member");
        let network = InProcessNetwork::new();
        let mut members = Vec::with_capacity(size);
        for node in 1..=u64::try_from(size).unwrap_or(u64::MAX) {
            let mut store_config = RaftStoreConfig::for_conformance(config);
            store_config.node_id = NodeId(node);
            store_config.address = format!("in-process-{node}");
            store_config.bootstrap = node == 1;
            store_config.timings.heartbeat_ms = 50;
            configure(&mut store_config);
            let store = RaftStore::open_temp(store_config)
                .await
                .expect("open a member store");
            // Opened on no transport, as `tenko serve` opens its store before the cluster
            // step; the network replaces it.
            store.set_transport(Arc::new(network.clone()));
            network.register(&store);
            members.push(store);
        }
        let first = members[0].clone();
        for member in &members[1..] {
            first
                .add_learner(
                    member.node_id(),
                    format!("in-process-{}", member.node_id().0),
                    true,
                )
                .await
                .expect("add a learner");
        }
        if size > 1 {
            let voters: BTreeSet<NodeId> = members.iter().map(RaftStore::node_id).collect();
            first
                .change_membership(voters)
                .await
                .expect("make every member a voter");
        }
        let cluster = Self { network, members };
        cluster.wait_for_leader().await;
        cluster
    }

    /// The network (to isolate members).
    pub fn network(&self) -> &InProcessNetwork {
        &self.network
    }

    /// Every member, node 1 first.
    pub fn members(&self) -> &[RaftStore] {
        &self.members
    }

    /// The member with this node id.
    ///
    /// # Panics
    ///
    /// Panics for an id that is not a member.
    pub fn member(&self, node: NodeId) -> &RaftStore {
        self.members
            .iter()
            .find(|member| member.node_id() == node)
            .expect("a member of the cluster")
    }

    /// The member that leads and has taken office (`is_self`); waits for one.
    ///
    /// # Panics
    ///
    /// Panics when no member takes office in time.
    pub async fn wait_for_leader(&self) -> RaftStore {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(leader) = self.members.iter().find(|member| {
                member
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
            }) {
                return leader.clone();
            }
            assert!(Instant::now() < deadline, "no member took office");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A member that does not lead now.
    ///
    /// # Panics
    ///
    /// Panics when no leader is found in time or the cluster has one member.
    pub async fn a_follower(&self) -> RaftStore {
        let leader = self.wait_for_leader().await.node_id();
        self.members
            .iter()
            .find(|member| {
                member.node_id() != leader && member.status().role != StoreRole::Shutdown
            })
            .expect("a member that does not lead")
            .clone()
    }

    /// Hands leadership to another member and waits until it took office.
    ///
    /// # Panics
    ///
    /// Panics when the hand-over fails.
    pub async fn hand_over(&self) -> RaftStore {
        let leader = self.wait_for_leader().await;
        let target = self.a_follower().await;
        let campaigner = target.clone();
        leader
            .step_down(
                target.node_id(),
                move || async move { campaigner.campaign().await },
                WAIT,
            )
            .await
            .expect("leadership moves");
        let deadline = Instant::now() + WAIT;
        loop {
            let next = self.wait_for_leader().await;
            if next.node_id() != leader.node_id() {
                return next;
            }
            assert!(Instant::now() < deadline, "leadership did not move");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Stops every member cleanly.
    pub async fn shutdown(&self) {
        for member in &self.members {
            let _ = member.shutdown().await;
        }
    }
}

#[async_trait::async_trait]
impl ClusterFixture for InProcessCluster {
    async fn leader(&self) -> Arc<dyn Store> {
        Arc::new(self.wait_for_leader().await)
    }

    async fn follower(&self) -> Arc<dyn Store> {
        Arc::new(self.a_follower().await)
    }

    async fn change_leader(&self) {
        self.hand_over().await;
    }
}
