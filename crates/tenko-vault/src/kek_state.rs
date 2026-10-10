//! The replicated state of the installation's key-encryption keys (ADR 0014).
//!
//! Every controller of a cluster holds the same KEK generations, each sealed with its own
//! provider. What they share through the store is the knowledge about them, never the
//! material:
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `vault.kek_state` | `()` | [`KekState`]: the active generation, every generation of the installation, the KEK epoch and the online rotation in progress |
//! | `vault.kek_acks` | (generation id, node) | [`KekAck`]: a controller holds the generation of an online rotation |
//! | `vault.kek_protection` | node | [`ProtectionRecord`]: how the controller protects its KEK now, and the strongest protection it ever had (R15) |
//! | `vault.alarms` | alarm key | [`VaultAlarm`]: a downgrade of the KEK protection or a refused plain generation |
//!
//! The counter [`KEK_EPOCH`](crate::KEK_EPOCH) moves in the same batch that changes
//! [`KekState::active`], so a controller that reads both from one view sees which epoch the
//! active generation belongs to.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{NodeId, Revision, Timestamp};
use tenko_store::{ReadView, ReadViewExt, StoreError};

use crate::kek::KekProtection;

/// The code of a KEK downgrade: an alarm, an audit action and a status warning.
pub const DOWNGRADE_CODE: &str = "vault.kek.downgrade";

/// The tables of the replicated KEK state.
pub mod tables {
    use tenko_core::{NodeId, table::TableDef};

    use super::{KekAck, KekState, ProtectionRecord, VaultAlarm};

    /// The one record of the installation's KEK state, under the key `()`.
    pub const STATE: TableDef<(), KekState> = TableDef::new("vault.kek_state");
    /// Acknowledgements of a new generation by (generation id, node).
    pub const ACKS: TableDef<(String, NodeId), KekAck> = TableDef::new("vault.kek_acks");
    /// The KEK protection of each controller.
    pub const PROTECTION: TableDef<NodeId, ProtectionRecord> =
        TableDef::new("vault.kek_protection");
    /// Alarms of the vault by a stable key, so a repeated cause updates one record.
    pub const ALARMS: TableDef<String, VaultAlarm> = TableDef::new("vault.alarms");
}

/// Audit actions of the KEK state.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// An administrator asked for an online rotation.
    pub const ROTATE_REQUEST: AuditAction = AuditAction::from_static("vault.kek.rotate_request");
    /// Every reachable controller holds the generation of an online rotation; it became
    /// active.
    pub const ACTIVATE: AuditAction = AuditAction::from_static("vault.kek.activate");
    /// An online rotation failed (a controller did not acknowledge in time).
    pub const ROTATE_FAILED: AuditAction = AuditAction::from_static("vault.kek.rotate_failed");
    /// The KEK protection of a controller became weaker, or a plain generation was refused.
    pub const DOWNGRADE: AuditAction = AuditAction::from_static("vault.kek.downgrade");
}

/// One KEK generation of the installation, as the state lists it (no material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KekGeneration {
    /// The identifier envelopes name.
    pub id: String,
    /// When the state first listed it.
    pub created_at: Timestamp,
    /// The controller that created it, when known.
    #[serde(default)]
    pub created_by: Option<NodeId>,
}

/// The phase of an online rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPhase {
    /// Asked for; the leader creates the new generation next.
    Requested,
    /// The new generation exists; controllers fetch it and acknowledge.
    Distributing,
    /// The new generation is active; envelopes are re-wrapped under it.
    Rewrapping,
    /// Finished.
    Done,
    /// Stopped; see [`RotationRecord::error`].
    Failed,
}

impl RotationPhase {
    /// Whether the rotation still runs.
    pub fn is_running(self) -> bool {
        matches!(
            self,
            RotationPhase::Requested | RotationPhase::Distributing | RotationPhase::Rewrapping
        )
    }

    /// The `snake_case` name.
    pub fn as_str(self) -> &'static str {
        match self {
            RotationPhase::Requested => "requested",
            RotationPhase::Distributing => "distributing",
            RotationPhase::Rewrapping => "rewrapping",
            RotationPhase::Done => "done",
            RotationPhase::Failed => "failed",
        }
    }
}

/// The online rotation in progress, or the last one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    /// Where it stands.
    pub phase: RotationPhase,
    /// When it was asked for.
    pub requested_at: Timestamp,
    /// Who asked (a principal subject such as `user:…`).
    pub requested_by: String,
    /// When the phase last changed.
    pub updated_at: Timestamp,
    /// The new generation, once created.
    #[serde(default)]
    pub generation: Option<String>,
    /// When the new generation was created (the start of the distribution).
    #[serde(default)]
    pub distributing_since: Option<Timestamp>,
    /// Reachable controllers that have not acknowledged the new generation yet.
    #[serde(default)]
    pub waiting_for: Vec<NodeId>,
    /// Controllers that were unreachable during the distribution; they fetch the
    /// generation when they start.
    #[serde(default)]
    pub unreachable: Vec<NodeId>,
    /// Envelopes re-wrapped so far.
    #[serde(default)]
    pub rewrapped: u64,
    /// Why it failed.
    #[serde(default)]
    pub error: Option<String>,
    /// When it ended.
    #[serde(default)]
    pub finished_at: Option<Timestamp>,
}

impl RotationRecord {
    /// A new request.
    pub fn requested(at: Timestamp, by: String) -> Self {
        Self {
            phase: RotationPhase::Requested,
            requested_at: at,
            requested_by: by,
            updated_at: at,
            generation: None,
            distributing_since: None,
            waiting_for: Vec::new(),
            unreachable: Vec::new(),
            rewrapped: 0,
            error: None,
            finished_at: None,
        }
    }
}

/// The installation's KEK state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KekState {
    /// The value of [`KEK_EPOCH`](crate::KEK_EPOCH) that [`active`](Self::active) belongs
    /// to.
    pub epoch: u64,
    /// The generation every controller wraps new data keys with.
    pub active: String,
    /// Every generation of the installation that envelopes may name, oldest first, the
    /// active one included.
    pub generations: Vec<KekGeneration>,
    /// The generation of an online rotation that is being distributed and is not active
    /// yet.
    #[serde(default)]
    pub pending: Option<KekGeneration>,
    /// The online rotation in progress, or the last one.
    #[serde(default)]
    pub rotation: Option<RotationRecord>,
    /// Generations of failed rotations: some controllers hold them, no envelope names them,
    /// and nobody fetches them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub abandoned: Vec<String>,
}

impl KekState {
    /// Whether the state lists the generation `id` (active, earlier, pending or abandoned).
    pub fn knows(&self, id: &str) -> bool {
        self.generations
            .iter()
            .any(|generation| generation.id == id)
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.id == id)
            || self.abandoned.iter().any(|abandoned| abandoned == id)
    }

    /// Ends the distribution of the pending generation without activating it.
    pub(crate) fn abandon_pending(&mut self) {
        if let Some(pending) = self.pending.take()
            && !self.abandoned.contains(&pending.id)
        {
            self.abandoned.push(pending.id);
        }
    }

    /// Forgets every generation but the active one: after a complete re-wrap no envelope
    /// names another, so no controller needs to fetch them.
    pub(crate) fn keep_active_only(&mut self) {
        let active = self.active.clone();
        self.generations
            .retain(|generation| generation.id == active);
    }

    /// The identifiers of the generations an envelope may name and a controller must
    /// hold: the listed ones, then the pending one.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.generations
            .iter()
            .chain(self.pending.as_ref())
            .map(|generation| generation.id.as_str())
    }

    /// When the state first listed `id`.
    pub fn created_at(&self, id: &str) -> Option<Timestamp> {
        self.generations
            .iter()
            .chain(self.pending.as_ref())
            .find(|generation| generation.id == id)
            .map(|generation| generation.created_at)
    }

    /// Whether an online rotation is running.
    pub fn rotating(&self) -> bool {
        self.rotation
            .as_ref()
            .is_some_and(|rotation| rotation.phase.is_running())
    }

    /// Lists `id` as a generation (once).
    pub(crate) fn list(&mut self, id: &str, at: Timestamp, by: Option<NodeId>) {
        if !self
            .generations
            .iter()
            .any(|generation| generation.id == id)
        {
            self.generations.push(KekGeneration {
                id: id.to_owned(),
                created_at: at,
                created_by: by,
            });
        }
    }
}

/// A controller holds the generation of an online rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KekAck {
    /// When it acknowledged.
    pub at: Timestamp,
}

/// How a controller protects its active KEK, and the strongest protection it ever had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionRecord {
    /// The strongest protection seen on this controller ([`KekProtection::rank`]).
    pub strongest: KekProtection,
    /// The protection at the last start.
    pub current: KekProtection,
    /// The configured provider (`dpapi`, `systemd_creds`, `systemd_credential`, `file`).
    pub provider: String,
    /// The active KEK at the last start.
    pub kek: String,
    /// When the record was written.
    pub updated_at: Timestamp,
}

impl ProtectionRecord {
    /// Whether the current protection is weaker than the strongest seen.
    pub fn downgraded(&self) -> bool {
        self.current.rank() < self.strongest.rank()
    }
}

/// What a vault alarm is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAlarmKind {
    /// The KEK protection of a controller became weaker than it was (`vault.kek.downgrade`).
    KekDowngrade,
    /// A plain generation newer than a sealed one was refused (`vault.kek.downgrade`, cause
    /// `plain_generation`).
    PlainRefused,
}

/// A vault alarm (routed to the `system` event topic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAlarm {
    /// What it is about.
    pub kind: VaultAlarmKind,
    /// The stable code: `vault.kek.downgrade`.
    pub code: String,
    /// The controller it concerns.
    pub node: NodeId,
    /// When it was raised last.
    pub at: Timestamp,
    /// When it was raised first.
    pub first_at: Timestamp,
    /// How often it was raised.
    pub count: u32,
    /// Parameters for the message (`from`, `to`, `generation`, `file`); never key material.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// The KEK state and its revision, when the store has one.
///
/// # Errors
///
/// The store's error.
pub fn read_state(view: &dyn ReadView) -> Result<Option<(KekState, Revision)>, StoreError> {
    view.get_typed(&tables::STATE, &())
}

/// The protection record of `node`.
///
/// # Errors
///
/// The store's error.
pub fn read_protection(
    view: &dyn ReadView,
    node: NodeId,
) -> Result<Option<(ProtectionRecord, Revision)>, StoreError> {
    view.get_typed(&tables::PROTECTION, &node)
}

/// Every controller's protection record, by node.
///
/// # Errors
///
/// The store's error.
pub fn protection_records(
    view: &dyn ReadView,
) -> Result<Vec<(NodeId, ProtectionRecord)>, StoreError> {
    Ok(view
        .scan_typed(
            &tables::PROTECTION,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(node, record, _)| (node, record))
        .collect())
}

/// The nodes that acknowledged generation `id`.
///
/// # Errors
///
/// The store's error.
pub fn acks_of(view: &dyn ReadView, id: &str) -> Result<Vec<NodeId>, StoreError> {
    // A string key ends in a terminator, so its encoding is a prefix of exactly the keys
    // whose first part is that string.
    let prefix = tenko_core::codec::key::encode_key(&id.to_owned());
    Ok(view
        .scan_typed(
            &tables::ACKS,
            tenko_store::KeyRange::prefix(prefix),
            usize::MAX,
            false,
        )?
        .into_iter()
        .filter(|((generation, _), _, _)| generation == id)
        .map(|((_, node), _, _)| node)
        .collect())
}

/// The alarm key of a KEK downgrade on `node`.
pub fn downgrade_alarm_key(node: NodeId) -> String {
    format!("kek_downgrade/{node}")
}

/// The alarm key of a refused plain generation on `node`.
pub fn refused_alarm_key(node: NodeId, generation: u32) -> String {
    format!("plain_refused/{node}/{generation}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    #[test]
    fn the_state_knows_listed_and_pending_generations() {
        let mut state = KekState {
            epoch: 3,
            active: "dpapi-2-b".to_owned(),
            generations: Vec::new(),
            pending: None,
            rotation: None,
            abandoned: Vec::new(),
        };
        state.list("dpapi-1-a", at("2026-10-10T10:00:00Z"), None);
        state.list("dpapi-2-b", at("2026-10-10T11:00:00Z"), Some(NodeId(1)));
        state.list("dpapi-2-b", at("2026-10-10T12:00:00Z"), None);
        assert_eq!(state.generations.len(), 2);
        state.pending = Some(KekGeneration {
            id: "dpapi-3-c".to_owned(),
            created_at: at("2026-10-10T13:00:00Z"),
            created_by: Some(NodeId(1)),
        });
        assert!(state.knows("dpapi-3-c"));
        assert!(!state.knows("dpapi-4-d"));
        assert_eq!(
            state.ids().collect::<Vec<_>>(),
            ["dpapi-1-a", "dpapi-2-b", "dpapi-3-c"]
        );
        assert_eq!(
            state.created_at("dpapi-2-b"),
            Some(at("2026-10-10T11:00:00Z"))
        );
        assert!(!state.rotating());
        state.rotation = Some(RotationRecord::requested(
            at("2026-10-10T13:00:00Z"),
            "user:x".to_owned(),
        ));
        assert!(state.rotating());
    }

    #[test]
    fn downgrades_compare_ranks() {
        let record = ProtectionRecord {
            strongest: KekProtection::SystemdCreds { tpm2: true },
            current: KekProtection::PlainFile,
            provider: "file".to_owned(),
            kek: "file-00".to_owned(),
            updated_at: at("2026-10-10T10:00:00Z"),
        };
        assert!(record.downgraded());
        let same = ProtectionRecord {
            current: KekProtection::SystemdCreds { tpm2: true },
            ..record
        };
        assert!(!same.downgraded());
    }
}
