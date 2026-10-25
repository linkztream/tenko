//! The role switch of `tenko serve` (OPS-01): which roles this node runs.
//!
//! The set is decided once, at start, in this order:
//!
//! 1. `--roles` on the command line, when given: it pins the set, and the stored set is not
//!    used ([`crate::config::Resolved::roles_pinned`]);
//! 2. else the node's stored set, the row of `nodes.roles` keyed by its node id
//!    (`PUT /api/v1/nodes/{id}/roles`): a controller reads it from the store, a node without
//!    the controller role from the configuration it received from the controllers
//!    (`<data_dir>/node/config/state.cbor`). The `controller` role is taken from the file
//!    whatever the stored set says: it follows the cluster membership;
//! 3. else `roles` of `tenko.toml` (or `TENKO_ROLES`), which a controller also writes as its
//!    stored set the first time (origin `seed`).
//!
//! A change applies at the next start. Every controller follows its own row in the store, so
//! a change made through any controller reaches it: under a service manager it stops with
//! exit status 12 a moment later ([`crate::upgrade::restart`]), so the answer of the request
//! reaches the client first; otherwise it logs what to do and `/system/status` carries
//! `node.roles.restart_required`. A node without the controller role does the same when the
//! row reaches it through the configuration stream.
//!
//! Privileges stay the operator's: the probe's raw methods and the dhcp role's direct mode
//! need `CAP_NET_RAW` and `AF_PACKET`, which the systemd drop-ins `probe.conf` and
//! `dhcp-direct.conf` grant, and the roles need their ports on the host firewall. The
//! installer prepares them ([`crate::prepared`]): for every role outside the Hardened
//! profile, for the chosen ones in Hardened. A node that runs such a role without
//! `CAP_NET_RAW` in its bounding and effective sets carries the status warning
//! `node.roles.privileges` naming the role, the capability and the installer command that
//! prepares it; a role the installer did not prepare carries `node.roles.unprepared`; the
//! answers of the role routes carry the same findings for the configured set, and
//! `prepared` per role.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures::{StreamExt as _, future::BoxFuture};
use tenko_api::{
    dto::system::{PreparedRoles, StatusWarning},
    routes::node_roles::{
        NodeRoleService, OwnNode, RESTART_NOTICE, RoleHost, dns_resolver_finding,
    },
    state::AppState,
};
use tenko_cluster::node_sync::{
    local::NodeConfig,
    roles::{NODE_ROLES, NodeRolesRecord, RolesOrigin},
};
use tenko_core::{NodeId, RequestCtx, Role, RoleSet, SystemComponent, Timestamp, codec::from_cbor};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreError, WatchFilter, WriteBatch};
use tokio::sync::watch;

use crate::{
    config::Resolved,
    prepared::Machine,
    upgrade::restart::{self, Restart},
};

/// How long a scheduled restart waits, so that the answer of the request reaches the client.
const RESTART_DELAY: Duration = Duration::from_secs(2);

/// How often the stored set is read again when the store's change stream is not open.
const REFRESH: Duration = Duration::from_secs(30);

/// How long the seed waits between two attempts while the store refuses writes.
const SEED_RETRY: Duration = Duration::from_secs(5);

/// The file in which `deploy/install.sh` records what it did to the host.
pub const INSTALLER_STATE: &str = "/etc/tenko/installer.state";

/// The roles of a start: `file` (the file's or `--roles`), unless `pinned`, the stored set
/// with the controller role as the file says.
pub fn effective(file: RoleSet, pinned: bool, stored: Option<RoleSet>) -> RoleSet {
    match stored {
        Some(stored) if !pinned => stored
            .roles()
            .filter(|role| *role != Role::Controller)
            .chain(file.contains(Role::Controller).then_some(Role::Controller))
            .collect(),
        _ => file,
    }
}

/// One line for the start log.
pub fn describe(running: RoleSet, pinned: bool, stored: Option<RoleSet>) -> String {
    let source = if pinned {
        "pinned by --roles"
    } else if stored.is_some() {
        "the node's stored set"
    } else {
        "set in tenko.toml"
    };
    format!("roles {running} ({source})")
}

/// Reads the stored set of `node`.
///
/// # Errors
///
/// The store's error.
pub async fn stored(store: &dyn Store, node: NodeId) -> Result<Option<RoleSet>, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(view
        .get_typed(&NODE_ROLES, &node.0)?
        .map(|(record, _)| record.role_set()))
}

/// Writes `roles` as the stored set of `node` when it has none. Returns whether it wrote.
///
/// # Errors
///
/// The store's error.
pub async fn seed(store: &dyn Store, node: NodeId, roles: RoleSet) -> Result<bool, StoreError> {
    let view = store.read(ReadConsistency::Local).await?;
    if view.get_typed(&NODE_ROLES, &node.0)?.is_some() {
        return Ok(false);
    }
    drop(view);
    let ctx = RequestCtx::system(SystemComponent::Cluster);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.expect_typed(&NODE_ROLES, &node.0, None);
    batch.put_typed(
        &NODE_ROLES,
        &node.0,
        &NodeRolesRecord::new(roles, RolesOrigin::Seed, Timestamp::now()),
    )?;
    match store.propose(batch).await {
        Ok(_) => Ok(true),
        // Another start, or an administrator, was first.
        Err(StoreError::PreconditionFailed(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The stored set in the configuration a node without the controller role received: the
/// row of `nodes.roles` it holds (the stream carries only the node's own rows).
pub fn held(config: &NodeConfig) -> Option<RoleSet> {
    let row = config
        .rows
        .iter()
        .find(|row| row.table == NODE_ROLES.name().as_str())?;
    match from_cbor::<NodeRolesRecord>(&row.value.0) {
        Ok(record) => Some(record.role_set()),
        Err(error) => {
            tracing::warn!(%error, "the stored role set of this node does not decode; the file's roles apply");
            None
        }
    }
}

/// The roles of a node without the controller role at start: [`effective`] over the
/// configuration it holds in `config_dir` (`<data_dir>/node/config`).
pub fn at_node_start(resolved: &Resolved, config_dir: &Path) -> RoleSet {
    let files = tenko_cluster::node_sync::local::ConfigFiles::new(config_dir);
    let stored = match files.load() {
        Ok(config) => config.as_ref().and_then(held),
        Err(error) => {
            tracing::warn!(code = %error.code(), "{}; the file's roles apply", error.detail());
            None
        }
    };
    let roles = effective(resolved.roles, resolved.roles_pinned, stored);
    tracing::info!("{}", describe(roles, resolved.roles_pinned, stored));
    roles
}

/// Whether the installer pointed the host's resolver at this node: a non-empty `use_self`
/// in the text of its state file.
pub fn uses_self(state: &str) -> bool {
    state.lines().any(|line| {
        line.strip_prefix("use_self=")
            .is_some_and(|value| !value.trim().is_empty())
    })
}

/// What the role service needs from this process.
#[derive(Debug, Clone)]
pub struct ServeHost {
    /// Whether a service manager starts the process again after exit status 12.
    pub supervised: bool,
    /// What the installer prepared the machine for, and the capabilities of the process.
    pub machine: Machine,
    /// The installer's state file, when the platform has one.
    pub installer_state: Option<PathBuf>,
}

impl ServeHost {
    /// The host of the server `resolved` describes.
    pub fn of(resolved: &Resolved) -> Self {
        Self {
            supervised: restart::supervised(),
            machine: Machine::of(resolved),
            installer_state: cfg!(target_os = "linux").then(|| PathBuf::from(INSTALLER_STATE)),
        }
    }
}

impl RoleHost for ServeHost {
    fn supervised(&self) -> bool {
        self.supervised
    }

    fn findings(
        &self,
        configured: RoleSet,
        _running: RoleSet,
    ) -> BoxFuture<'_, Vec<StatusWarning>> {
        Box::pin(async move {
            let mut findings = Vec::new();
            findings.extend(self.machine.privilege_gaps(configured));
            findings.extend(self.machine.unprepared(configured));
            if !configured.contains(Role::Dns)
                && let Some(path) = &self.installer_state
            {
                let text = tokio::fs::read_to_string(path).await.unwrap_or_default();
                if uses_self(&text) {
                    findings.push(dns_resolver_finding(&path.display().to_string()));
                }
            }
            findings
        })
    }

    fn prepared(&self) -> Option<PreparedRoles> {
        self.machine.prepared()
    }
}

/// What the role switch of a controller needs at start.
pub struct Parts {
    /// The store.
    pub store: Arc<dyn Store>,
    /// The API state, for the status warnings.
    pub state: AppState,
    /// This node.
    pub own: OwnNode,
    /// The roles of the file (or `--roles`), which seed the stored set.
    pub file: RoleSet,
    /// The host.
    pub host: ServeHost,
    /// The restart request of the server.
    pub restart: Restart,
    /// Ends the follower.
    pub stop: watch::Receiver<bool>,
}

/// The role switch of a controller: the service for the API, and the task that seeds the
/// stored set and follows it.
pub fn start(parts: Parts) -> (Arc<NodeRoleService>, tokio::task::JoinHandle<()>) {
    let Parts {
        store,
        state,
        own,
        file,
        host,
        restart,
        stop,
    } = parts;
    // The start check of the roles this node runs: CAP_NET_RAW where a role needs it, and
    // what the installer did not prepare. Both are health rows until the next start.
    if let Some(warning) = host.machine.privilege_gaps(own.running) {
        tracing::warn!(
            code = %warning.code,
            capability = host.machine.raw_detail().unwrap_or_default(),
            "{}",
            warning.detail
        );
        state.set_notice(warning);
    }
    if let Some(warning) = host.machine.unprepared(own.running) {
        tracing::warn!(code = %warning.code, "{}", warning.detail);
        state.set_notice(warning);
    }
    let service = Arc::new(NodeRoleService::new(
        Arc::clone(&store),
        own,
        Arc::new(host.clone()),
    ));
    let task = tokio::spawn(async move {
        if !own.pinned {
            seed_until_written(store.as_ref(), own.id, file, stop.clone()).await;
        }
        follow(
            &Follower {
                store,
                state,
                own,
                supervised: host.supervised,
                restart,
            },
            stop,
        )
        .await;
    });
    (service, task)
}

async fn seed_until_written(
    store: &dyn Store,
    node: NodeId,
    roles: RoleSet,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        match seed(store, node, roles).await {
            Ok(true) => {
                tracing::info!(roles = %roles, "the roles of tenko.toml are the node's stored set");
                return;
            }
            Ok(false) => return,
            Err(error) => {
                tracing::debug!(%error, "the stored role set could not be seeded yet");
            }
        }
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            () = tokio::time::sleep(SEED_RETRY) => {}
        }
    }
}

/// What the follower of a controller's own row needs.
pub struct Follower {
    /// The store.
    pub store: Arc<dyn Store>,
    /// The API state, for the restart notice.
    pub state: AppState,
    /// This node.
    pub own: OwnNode,
    /// Whether a service manager starts the process again.
    pub supervised: bool,
    /// The restart request of the server.
    pub restart: Restart,
}

impl Follower {
    /// Acts on the stored set `stored`: schedules the restart under a service manager, or
    /// publishes the restart notice. Returns whether a restart was scheduled.
    pub fn apply(&self, stored: Option<RoleSet>) -> bool {
        let wanted = effective(self.own.running, self.own.pinned, stored);
        if wanted == self.own.running {
            self.state.clear_notice(RESTART_NOTICE);
            return false;
        }
        if self.supervised {
            let restart = self.restart.clone();
            let reason = format!("the roles of this node changed to {wanted}");
            tokio::spawn(async move {
                tokio::time::sleep(RESTART_DELAY).await;
                restart.request(reason);
            });
            return true;
        }
        tracing::warn!(
            configured = %wanted,
            running = %self.own.running,
            "the roles of this node changed; restart tenko serve to apply them"
        );
        self.state.set_notice(StatusWarning {
            code: RESTART_NOTICE.to_owned(),
            detail: format!(
                "the roles of this node changed to {wanted}; restart the server to apply the \
                 change (running: {})",
                self.own.running
            ),
            params: [
                ("configured".to_owned(), wanted.to_string()),
                ("running".to_owned(), self.own.running.to_string()),
            ]
            .into_iter()
            .collect(),
        });
        false
    }
}

/// Follows the controller's own row of `nodes.roles` until `stop`.
async fn follow(follower: &Follower, mut stop: watch::Receiver<bool>) {
    let filter = WatchFilter::tables([NODE_ROLES.name().clone()]);
    let mut changes = None;
    let mut last: Option<Option<RoleSet>> = None;
    loop {
        let revision = match follower.store.read(ReadConsistency::Local).await {
            Ok(view) => {
                match view.get_typed(&NODE_ROLES, &follower.own.id.0) {
                    Ok(row) => {
                        let stored = row.map(|(record, _)| record.role_set());
                        if last != Some(stored) {
                            last = Some(stored);
                            if follower.apply(stored) {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the stored role set does not read");
                    }
                }
                Some(view.revision())
            }
            Err(error) => {
                tracing::debug!(%error, "the stored role set could not be read");
                None
            }
        };
        if changes.is_none() {
            changes = revision
                .and_then(|revision| follower.store.watch(Some(revision), filter.clone()).ok());
        }
        let woke = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            () = tokio::time::sleep(REFRESH) => true,
            item = async {
                if let Some(stream) = changes.as_mut() {
                    stream.next().await
                } else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    None
                }
            } => matches!(item, Some(Ok(_))),
        };
        if !woke {
            changes = None;
        }
    }
}

/// Follows the stored set in the configuration a node without the controller role receives,
/// and acts like [`Follower::apply`] on a change: a restart under a service manager, a log
/// line otherwise. Returns when a restart was requested or `stop` is set.
pub async fn follow_on_node(
    mut config: watch::Receiver<Arc<NodeConfig>>,
    running: RoleSet,
    file: RoleSet,
    pinned: bool,
    restart: Restart,
    mut stop: watch::Receiver<bool>,
) {
    let supervised = restart::supervised();
    let mut warned = None;
    loop {
        let wanted = {
            let held_config = config.borrow_and_update();
            // Before the first sync the node runs on its file.
            (held_config.revision > 0).then(|| effective(file, pinned, held(&held_config)))
        };
        if let Some(wanted) = wanted
            && wanted != running
        {
            if supervised {
                tokio::time::sleep(RESTART_DELAY).await;
                restart.request(format!("the roles of this node changed to {wanted}"));
                return;
            }
            if warned != Some(wanted) {
                warned = Some(wanted);
                tracing::warn!(
                    configured = %wanted,
                    running = %running,
                    "the roles of this node changed; restart tenko serve to apply them"
                );
            }
        }
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            changed = config.changed() => if changed.is_err() { return },
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_cluster::node_sync::local::HeldRow;
    use tenko_core::{codec::to_cbor, serde_util::HexBytes};
    use tenko_store::MemStore;

    use super::*;

    fn roles(text: &str) -> RoleSet {
        text.parse().expect("roles")
    }

    #[test]
    fn the_pin_then_the_stored_set_then_the_file() {
        let file = roles("controller,dns");
        let stored = roles("controller,dns,dhcp,probe");
        // --roles pins.
        assert_eq!(effective(file, true, Some(stored)), file);
        // Otherwise the stored set decides.
        assert_eq!(effective(file, false, Some(stored)), stored);
        // Without one, the file.
        assert_eq!(effective(file, false, None), file);
        // The controller role is the file's, whatever the stored set says.
        assert_eq!(
            effective(file, false, Some(roles("dns"))),
            roles("controller,dns")
        );
        assert_eq!(
            effective(roles("probe"), false, Some(roles("controller,probe"))),
            roles("probe")
        );
        assert_eq!(
            describe(file, true, Some(stored)),
            "roles controller,dns (pinned by --roles)"
        );
        assert_eq!(
            describe(stored, false, Some(stored)),
            "roles controller,dns,dhcp,probe (the node's stored set)"
        );
        assert_eq!(
            describe(file, false, None),
            "roles controller,dns (set in tenko.toml)"
        );
    }

    #[tokio::test]
    async fn the_file_seeds_the_stored_set_once() {
        let store = MemStore::default();
        let node = NodeId(1);
        assert_eq!(stored(&store, node).await.expect("read"), None);
        assert!(
            seed(&store, node, roles("controller,dns"))
                .await
                .expect("seed")
        );
        assert_eq!(
            stored(&store, node).await.expect("read"),
            Some(roles("controller,dns"))
        );
        // A later start with another file does not overwrite the stored set.
        assert!(!seed(&store, node, roles("controller")).await.expect("seed"));
        assert_eq!(
            stored(&store, node).await.expect("read"),
            Some(roles("controller,dns"))
        );
    }

    #[test]
    fn a_node_reads_its_held_row() {
        let record = NodeRolesRecord::new(roles("probe"), RolesOrigin::Api, Timestamp::now());
        let mut config = NodeConfig {
            revision: 7,
            applied_at: None,
            rows: vec![HeldRow {
                table: "nodes.roles".to_owned(),
                key: HexBytes(NODE_ROLES.key(&1001).to_vec()),
                value: HexBytes(to_cbor(&record).expect("encode").to_vec()),
            }],
        };
        assert_eq!(held(&config), Some(roles("probe")));
        config.rows[0].value = HexBytes(vec![0xff]);
        assert_eq!(held(&config), None, "a row that does not decode is ignored");
        config.rows.clear();
        assert_eq!(held(&config), None);
    }

    #[test]
    fn the_resolver_of_the_host() {
        assert!(uses_self("version=1\nuse_self=resolved\n"));
        assert!(!uses_self("use_self=\n"));
        assert!(!uses_self(""));
    }

    /// A host whose process lacks `CAP_NET_RAW`, on a machine the installer prepared for
    /// the controller and dns roles under Hardened.
    fn hardened_host() -> ServeHost {
        ServeHost {
            supervised: false,
            machine: Machine {
                record: Some((
                    PathBuf::from("/etc/tenko/prepared-roles"),
                    crate::prepared::Record::parse("profile=hardened\nroles=controller,dns\n"),
                )),
                ..Machine::bare(false)
            },
            installer_state: None,
        }
    }

    #[tokio::test]
    async fn the_start_raises_the_privileges_and_the_preparation() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let state = AppState::new(Arc::clone(&store));
        let (stop_tx, stop) = watch::channel(false);
        let (service, task) = start(Parts {
            store: Arc::clone(&store),
            state: state.clone(),
            own: OwnNode {
                id: NodeId(1),
                running: roles("controller,dns,probe"),
                pinned: true,
            },
            file: roles("controller,dns,probe"),
            host: hardened_host(),
            restart: Restart::new(),
            stop,
        });
        let notices = state.notices_list();
        let privileges = notices
            .iter()
            .find(|warning| warning.code == "node.roles.privileges")
            .expect("the health row of the capability");
        assert_eq!(privileges.params["roles"], "probe");
        assert_eq!(privileges.params["capability"], "CAP_NET_RAW");
        assert_eq!(
            privileges.params["command"],
            "sudo bash install.sh --prepare --roles controller,dns,probe"
        );
        let unprepared = notices
            .iter()
            .find(|warning| warning.code == "node.roles.unprepared")
            .expect("the health row of the preparation");
        assert_eq!(unprepared.params["missing"], "probe.conf");
        // The answer of the role routes says the same per role.
        let answer = service.get(NodeId(1)).await.expect("roles");
        let prepared = answer.prepared.expect("the record");
        assert!(prepared.roles[1].prepared, "dns");
        assert!(!prepared.roles[3].prepared, "probe");
        assert!(
            answer
                .findings
                .iter()
                .any(|finding| finding.code == "node.roles.unprepared")
        );
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn a_changed_set_restarts_a_supervised_controller() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let state = AppState::new(Arc::clone(&store));
        let own = OwnNode {
            id: NodeId(1),
            running: roles("controller,dns"),
            pinned: false,
        };
        let restart = Restart::new();
        let unsupervised = Follower {
            store: Arc::clone(&store),
            state: state.clone(),
            own,
            supervised: false,
            restart: restart.clone(),
        };
        assert!(!unsupervised.apply(Some(roles("controller,dns"))));
        assert_eq!(state.notices_list(), Vec::new());
        assert!(!unsupervised.apply(Some(roles("controller,dns,dhcp"))));
        assert_eq!(state.notices_list()[0].code, RESTART_NOTICE);
        assert!(!unsupervised.apply(None), "back to the file's set");
        assert_eq!(state.notices_list(), Vec::new());
        let supervised = Follower {
            supervised: true,
            ..unsupervised
        };
        assert!(supervised.apply(Some(roles("controller"))));
        let reason = tokio::time::timeout(Duration::from_secs(10), restart.requested())
            .await
            .expect("the restart is requested");
        assert!(reason.contains("changed to controller"), "{reason}");
    }

    #[tokio::test]
    async fn the_follower_sees_a_change_made_elsewhere() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let state = AppState::new(Arc::clone(&store));
        let own = OwnNode {
            id: NodeId(1),
            running: roles("controller,dns"),
            pinned: false,
        };
        let restart = Restart::new();
        let (stop_tx, stop) = watch::channel(false);
        let (_service, task) = start(Parts {
            store: Arc::clone(&store),
            state,
            own,
            file: roles("controller,dns"),
            host: ServeHost {
                supervised: true,
                machine: Machine::bare(true),
                installer_state: None,
            },
            restart: restart.clone(),
            stop,
        });
        // The seed lands first; then another controller stores a new set.
        tokio::time::timeout(Duration::from_secs(10), async {
            while stored(store.as_ref(), NodeId(1))
                .await
                .expect("read")
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("seeded");
        let ctx = RequestCtx::system(SystemComponent::Api);
        let mut batch = WriteBatch::for_request(&ctx);
        batch
            .put_typed(
                &NODE_ROLES,
                &1,
                &NodeRolesRecord::new(roles("controller,dhcp"), RolesOrigin::Api, ctx.now),
            )
            .expect("row");
        store.propose(batch).await.expect("written");
        let reason = tokio::time::timeout(Duration::from_secs(20), restart.requested())
            .await
            .expect("the restart is requested");
        assert!(reason.contains("controller,dhcp"), "{reason}");
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
}
