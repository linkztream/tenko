//! The live state of the cluster port: which node is connected, what its heartbeats say,
//! and the kill switches of its TLS connections. In memory only; the registry writes
//! `last_seen` from here at most every five minutes.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tenko_core::{NodeId, Timestamp};
use tokio::sync::mpsc;

use crate::{model::ConnectionView, mtls::KillSwitch, probe::timestamp_to_proto, proto::v1};

/// How long a revoked node's connections stay open after the revocation directive, so
/// the directive reaches the node before the connection closes.
pub const REVOKE_GRACE: Duration = Duration::from_millis(300);

struct Session {
    id: u64,
    view: ConnectionView,
    push: mpsc::Sender<Result<v1::Directive, tonic::Status>>,
}

/// Heartbeat sessions and connections of the nodes on this controller.
#[derive(Default)]
pub struct Sessions {
    next: AtomicU64,
    by_node: Mutex<HashMap<NodeId, Vec<Session>>>,
    connections: Mutex<HashMap<NodeId, Vec<Weak<KillSwitch>>>>,
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sessions")
            .field("connected", &self.connected().len())
            .finish_non_exhaustive()
    }
}

/// A heartbeat session, closed when dropped.
pub struct SessionGuard {
    sessions: Arc<Sessions>,
    node: NodeId,
    id: u64,
}

impl SessionGuard {
    /// The node.
    pub fn node(&self) -> NodeId {
        self.node
    }

    /// Changes the session's view (a beat arrived).
    pub fn update(&self, change: impl FnOnce(&mut ConnectionView)) {
        let mut sessions = self.sessions.lock_sessions();
        if let Some(session) = sessions
            .get_mut(&self.node)
            .and_then(|list| list.iter_mut().find(|session| session.id == self.id))
        {
            change(&mut session.view);
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock_sessions();
        if let Some(list) = sessions.get_mut(&self.node) {
            list.retain(|session| session.id != self.id);
            if list.is_empty() {
                sessions.remove(&self.node);
            }
        }
    }
}

impl Sessions {
    /// No sessions.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, Vec<Session>>> {
        self.by_node.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_connections(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<NodeId, Vec<Weak<KillSwitch>>>> {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a heartbeat session; directives for the node go to `push`.
    pub fn open(
        self: &Arc<Self>,
        node: NodeId,
        view: ConnectionView,
        push: mpsc::Sender<Result<v1::Directive, tonic::Status>>,
    ) -> SessionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock_sessions()
            .entry(node)
            .or_default()
            .push(Session { id, view, push });
        SessionGuard {
            sessions: Arc::clone(self),
            node,
            id,
        }
    }

    /// The newest session of a node.
    pub fn view(&self, node: NodeId) -> Option<ConnectionView> {
        self.lock_sessions()
            .get(&node)
            .and_then(|list| list.last())
            .map(|session| session.view.clone())
    }

    /// Every connected node with its newest session.
    pub fn connected(&self) -> Vec<(NodeId, ConnectionView)> {
        let mut out: Vec<(NodeId, ConnectionView)> = self
            .lock_sessions()
            .iter()
            .filter_map(|(node, list)| list.last().map(|session| (*node, session.view.clone())))
            .collect();
        out.sort_by_key(|(node, _)| *node);
        out
    }

    /// Remembers a TLS connection of a node, so a revocation can close it.
    pub fn track(&self, node: NodeId, kill: &Arc<KillSwitch>) {
        let mut connections = self.lock_connections();
        let list = connections.entry(node).or_default();
        list.retain(|weak| weak.strong_count() > 0);
        list.push(Arc::downgrade(kill));
    }

    /// Open TLS connections of a node.
    pub fn connection_count(&self, node: NodeId) -> usize {
        self.lock_connections().get(&node).map_or(0, |list| {
            list.iter()
                .filter_map(Weak::upgrade)
                .filter(|kill| !kill.is_killed())
                .count()
        })
    }

    /// Closes every tracked connection (the server stops).
    pub fn kill_all(&self) {
        let all: Vec<Weak<KillSwitch>> = self
            .lock_connections()
            .drain()
            .flat_map(|(_, list)| list)
            .collect();
        for switch in all.iter().filter_map(Weak::upgrade) {
            switch.kill();
        }
    }

    /// Tells every session of a revoked node, then closes its connections after
    /// [`REVOKE_GRACE`].
    pub fn revoke(self: &Arc<Self>, node: NodeId, now: Timestamp) {
        let pushes: Vec<_> = self
            .lock_sessions()
            .get(&node)
            .map(|list| list.iter().map(|session| session.push.clone()).collect())
            .unwrap_or_default();
        for push in pushes {
            let _ = push.try_send(Ok(v1::Directive {
                sequence: 0,
                server_time: Some(timestamp_to_proto(now)),
                renew: false,
                revoked: true,
                detail: "this node was revoked; enrol it again to reconnect".to_owned(),
            }));
        }
        let sessions = Arc::clone(self);
        let kill = move || {
            let switches = sessions
                .lock_connections()
                .remove(&node)
                .unwrap_or_default();
            for switch in switches.iter().filter_map(Weak::upgrade) {
                switch.kill();
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    tokio::time::sleep(REVOKE_GRACE).await;
                    kill();
                });
            }
            Err(_) => kill(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> ConnectionView {
        ConnectionView {
            since: "2026-10-10T08:00:00Z".parse().expect("time"),
            peer: None,
            major: 1,
            version: "0.0.1".to_owned(),
            last_beat: None,
            buffered_batches: 0,
            buffered_bytes: 0,
            dropped_batches: 0,
            certificate_not_after: None,
            controller: None,
        }
    }

    #[tokio::test]
    async fn sessions_open_update_and_close() {
        let sessions = Sessions::new();
        let (push, _rx) = mpsc::channel(4);
        let guard = sessions.open(NodeId(1001), view(), push);
        guard.update(|view| view.buffered_batches = 3);
        assert_eq!(
            sessions
                .view(NodeId(1001))
                .map(|view| view.buffered_batches),
            Some(3)
        );
        assert_eq!(sessions.connected().len(), 1);
        drop(guard);
        assert!(sessions.view(NodeId(1001)).is_none());
        assert_eq!(sessions.connected().len(), 0);
    }

    #[tokio::test]
    async fn revocation_pushes_a_directive_and_kills_connections() {
        let sessions = Sessions::new();
        let (push, mut rx) = mpsc::channel(4);
        let _guard = sessions.open(NodeId(1002), view(), push);
        let kill = KillSwitch::new();
        sessions.track(NodeId(1002), &kill);
        assert_eq!(sessions.connection_count(NodeId(1002)), 1);
        sessions.revoke(NodeId(1002), Timestamp::now());
        let directive = rx.recv().await.expect("directive").expect("ok");
        assert!(directive.revoked);
        tokio::time::sleep(REVOKE_GRACE * 2).await;
        assert!(kill.is_killed());
        assert_eq!(sessions.connection_count(NodeId(1002)), 0);
    }
}
