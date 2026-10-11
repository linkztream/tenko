//! The scanner of the probe role (SCAN-01 to SCAN-09) inside `tenko serve`, and `tenko node
//! scan`.
//!
//! | Module | Contents |
//! |---|---|
//! | [`supervisor`] | runs the scanner on the configuration in force, swaps it atomically, carries out the controllers' commands |
//! | [`control`] | the `scans` start step of a controller: the scan control and the probe role in process |
//! | [`relay`] | the local buffer of the probe role in process |
//! | [`cli`] | `tenko node scan` |
//!
//! On a probe node the scanner hands its batches to the agent's observation buffer, which
//! sends them to the controllers over the mutual TLS node transport and keeps them through
//! outages; the configuration comes from the controllers through the agent's sync (OPS-28),
//! and until the node holds one it runs on the `[scan]` section of its own `tenko.toml`,
//! which it offers as its initial configuration. On a controller node that also runs the
//! probe role, the scanner follows the store directly ([`control`]). docs/scanning.md
//! describes the methods, the limits and the files; docs/node-sync.md the sync.

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use tenko_cluster::{
    buffer::{DEFAULT_MAX_BATCH_BYTES, ObservationBuffer},
    client::Agent,
    identity::create_private_dir,
    node_sync::{local::NodeConfig, payload},
    probe::ProbeBatch,
    proto::v1,
};
use tenko_core::{NodeId, SecretId, codec::from_cbor};
use tenko_scan::{
    ScanError,
    config::{SNMP_SECRET_PURPOSE, ScanConfig, SecretText},
    control::model::{ProbeConfigRecord, tables::PROBE_CONFIG},
    scanner::{BatchSink, Environment, Mode, Scanner},
    secrets::{SecretSource, VaultSecrets},
    status::ScanPaths,
};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use crate::config::Resolved;

pub mod cli;
pub mod control;
pub mod relay;
pub mod supervisor;

pub use cli::{ScanArgs, ScanCommand};
use supervisor::{Build, Desired, ScanCommands, ScopeReports, Supervisor};

/// How long the scanner may take to stop.
pub const STOP_TIMEOUT: std::time::Duration = supervisor::SWAP_TIMEOUT;

/// Batches into the observation buffer of a probe node's agent.
#[derive(Debug)]
pub struct AgentSink(Arc<Agent>);

impl AgentSink {
    /// A sink into `agent`'s buffer.
    pub fn new(agent: Arc<Agent>) -> Self {
        Self(agent)
    }
}

#[async_trait]
impl BatchSink for AgentSink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        self.0
            .push_run(&batch, run)
            .map_err(|error| ScanError::io(format!("[{}] {}", error.code(), error.detail())))
    }
}

/// Batches dropped into the `incoming/` directory of a node's buffer, which the running
/// node process adopts within a second (`tenko node scan run`).
#[derive(Debug, Clone)]
pub struct IncomingSink {
    buffer: PathBuf,
}

impl IncomingSink {
    /// A sink into the buffer directory `buffer`.
    pub fn new(buffer: PathBuf) -> Self {
        Self { buffer }
    }
}

#[async_trait]
impl BatchSink for IncomingSink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        create_private_dir(&self.buffer)
            .map_err(|error| ScanError::io(error.detail().to_owned()))?;
        let mut count = 0u32;
        for part in batch.split_to_fit(DEFAULT_MAX_BATCH_BYTES - 128) {
            ObservationBuffer::drop_incoming(&self.buffer, &part.encode_with_run(run))
                .map_err(|error| ScanError::io(error.to_string()))?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

/// Warns about SNMP passwords written into the configuration file in clear.
pub(crate) fn warn_inline_secrets(config: &ScanConfig) {
    for device in &config.snmp.devices {
        if device.auth_password.is_some() || device.privacy_password.is_some() {
            tracing::warn!(
                device = %device.address,
                "an SNMP password is written in clear in tenko.toml; prefer \
                 auth_password_file and privacy_password_file with restricted permissions, \
                 or vault secrets in the configuration the controllers hold"
            );
        }
    }
}

/// The values of `wanted` among `values` (secret id and bytes), as the scanner takes
/// them; values that are not UTF-8 are left out with a warning.
pub(crate) fn vault_secrets<'a>(
    values: impl Iterator<Item = (SecretId, &'a [u8])>,
    wanted: &[SecretId],
) -> VaultSecrets {
    let mut out = VaultSecrets::new();
    for (secret, bytes) in values {
        if !wanted.contains(&secret) {
            continue;
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => out.insert(secret, SecretText::new(text)),
            Err(_) => {
                tracing::warn!(%secret, "an SNMP secret is not text; it is not used");
            }
        }
    }
    out
}

/// The configuration a probe node applies: its row of `scan.probe_config` from the
/// controllers once it holds one, else its own `[scan]` section.
pub fn desired_of(held: &NodeConfig, node: NodeId, local: &ScanConfig) -> Desired {
    let key = PROBE_CONFIG.key(&node.0);
    let Some(bytes) = held.get(PROBE_CONFIG.name().as_str(), key.as_ref()) else {
        return Desired::local(local.clone());
    };
    match from_cbor::<ProbeConfigRecord>(bytes) {
        Ok(record) => match record.config.validate_stored() {
            Ok(()) => Desired::synced(record.config, held.revision),
            Err(error) => Desired::refused(held.revision, error.detail().to_owned()),
        },
        Err(error) => Desired::refused(
            held.revision,
            format!("the scan configuration does not decode: {error}"),
        ),
    }
}

/// The SNMP secrets of a probe node: fetched from the connected controller over mutual
/// TLS on each poll and held in memory only (S3-Q19).
#[derive(Debug)]
pub struct AgentSecrets(Arc<Agent>);

#[async_trait]
impl SecretSource for AgentSecrets {
    async fn fetch(&self, secrets: &[SecretId]) -> Result<VaultSecrets, ScanError> {
        let held = self
            .0
            .secrets(&[SNMP_SECRET_PURPOSE])
            .await
            .map_err(|error| {
                ScanError::unavailable(format!("[{}] {}", error.code(), error.detail()))
            })?;
        Ok(vault_secrets(
            secrets.iter().filter_map(|secret| {
                held.get(SNMP_SECRET_PURPOSE, *secret)
                    .map(|bytes| (*secret, bytes))
            }),
            secrets,
        ))
    }
}

/// The scope reports of a probe node, sent with `Config.Report`.
struct AgentReports(Arc<Agent>);

impl ScopeReports for AgentReports {
    fn report(&self, report: v1::ConfigReport) {
        self.0.report_config(report);
    }
}

/// Starts the scanner supervisor of a probe node with its agent: the configuration from
/// the agent's sync (the `[scan]` section until the node holds one, offered at the first
/// connection without passwords), commands through the agent, SNMP secrets from the
/// controllers, batches into the agent's buffer. Returns its tasks; they end when `stop`
/// turns true.
pub fn start_on_node(
    resolved: &Resolved,
    agent: &Arc<Agent>,
    stop: watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let node = agent.credentials().identity.node;
    let local = resolved.config.scan.clone();
    warn_inline_secrets(&local);
    let (offer, lacking) = local.offer_form();
    match tenko_core::codec::to_cbor(&offer) {
        Ok(bytes) => agent.set_offer(PROBE_CONFIG.name().as_str(), payload::CBOR, bytes.to_vec()),
        Err(error) => tracing::warn!(%error, "the [scan] section cannot be offered"),
    }
    for device in lacking {
        tracing::info!(
            %device,
            "once the controllers hold this probe's configuration, the SNMP device needs a vault \
             secret picked by an administrator; passwords never leave the probe"
        );
    }
    let environment = Environment::host().with_secrets(Arc::new(AgentSecrets(Arc::clone(agent))));
    let sink: Arc<dyn BatchSink> = Arc::new(AgentSink::new(Arc::clone(agent)));
    let paths = ScanPaths::new(&resolved.data_dir);
    let build: Build = Arc::new(move |config| {
        Scanner::new(
            config.clone(),
            paths.clone(),
            Arc::clone(&sink),
            &environment,
            Mode::Service,
        )
    });
    let supervisor = Supervisor::new(
        &resolved.data_dir,
        build,
        Arc::new(AgentReports(Arc::clone(agent))),
    );
    agent.set_command_handler(Arc::new(ScanCommands(Arc::clone(&supervisor))));
    let mut configs = agent.config();
    let first = desired_of(&configs.borrow_and_update(), node, &local);
    let (desired_tx, desired) = watch::channel(first);
    let mut follow_stop = stop.clone();
    let follow = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = follow_stop.wait_for(|stopped| *stopped) => return,
                changed = configs.changed() => if changed.is_err() { return; },
            }
            let wanted = desired_of(&configs.borrow_and_update(), node, &local);
            desired_tx.send_if_modified(|current| {
                if *current == wanted {
                    false
                } else {
                    *current = wanted;
                    true
                }
            });
        }
    });
    vec![follow, tokio::spawn(supervisor.run(desired, stop))]
}

#[cfg(test)]
mod tests {
    use tenko_cluster::node_sync::local::HeldRow;
    use tenko_core::{Timestamp, codec::to_cbor, serde_util::HexBytes};
    use tenko_scan::control::model::ProbeConfigOrigin;

    use super::*;

    fn held(node: u64, config: &ScanConfig, revision: u64) -> NodeConfig {
        let record = ProbeConfigRecord {
            node: NodeId(node),
            config: config.clone(),
            secrets: Vec::new(),
            origin: ProbeConfigOrigin::Api,
            updated_at: Timestamp::now(),
            updated_by: None,
        };
        NodeConfig {
            revision,
            applied_at: None,
            rows: vec![HeldRow {
                table: PROBE_CONFIG.name().as_str().to_owned(),
                key: HexBytes(PROBE_CONFIG.key(&node).to_vec()),
                value: HexBytes(to_cbor(&record).expect("cbor").to_vec()),
            }],
        }
    }

    #[test]
    fn the_stored_configuration_wins_once_the_node_holds_one() {
        let local = ScanConfig {
            prefixes: vec!["198.51.100.0/24".to_owned()],
            ..ScanConfig::default()
        };
        let stored = ScanConfig {
            prefixes: vec!["192.0.2.0/24".to_owned()],
            ..ScanConfig::default()
        };
        assert_eq!(
            desired_of(&NodeConfig::default(), NodeId(1001), &local),
            Desired::local(local.clone())
        );
        let synced = held(1001, &stored, 42);
        assert_eq!(
            desired_of(&synced, NodeId(1001), &local),
            Desired::synced(stored, 42)
        );
        // Another node's row is not this node's configuration.
        assert_eq!(
            desired_of(&synced, NodeId(1002), &local),
            Desired::local(local.clone())
        );
        let mut broken = synced.clone();
        broken.rows[0].value = HexBytes(vec![0xff]);
        let refused = desired_of(&broken, NodeId(1001), &local);
        assert_eq!(refused.config, None);
        assert_eq!(refused.revision, 42);
        assert!(refused.error.is_some());
    }

    #[test]
    fn only_the_asked_secrets_that_are_text_are_kept() {
        let a = SecretId::from(Uuid::now_v7());
        let b = SecretId::from(Uuid::now_v7());
        let c = SecretId::from(Uuid::now_v7());
        let values: Vec<(SecretId, &[u8])> = vec![
            (a, b"correct horse".as_slice()),
            (b, &[0xff, 0xfe]),
            (c, b"other"),
        ];
        let secrets = vault_secrets(values.into_iter(), &[a, b]);
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets.get(a).map(SecretText::expose),
            Some("correct horse")
        );
    }
}
