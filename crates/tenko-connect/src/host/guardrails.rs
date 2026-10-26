//! The guardrails of network-controller writes as settings in the store
//! (`connect.guardrails`, plan 2.6): the configured protected paths and the move
//! parallelism, the same on every controller, changed through the API with audit.
//!
//! The server seeds the table from [`Guardrails::default`] when it is empty ([`seed`]) and
//! follows it ([`follow`]); the network-controller adapter reads the guardrails in force at
//! every call, so a change applies to the next plan, write or revert without a restart.
//! Uplinks and management networks of the topology stay protected whatever is stored.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use futures::StreamExt as _;
use tenko_core::{
    ObjectKind, ObjectRef, RequestCtx, Revision, SystemComponent,
    audit::{AuditAction, AuditDraft, FieldChange},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreError, WatchFilter, WriteBatch};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use super::HostError;
use crate::{ConnectorError, Guardrails, L2Receipt, ProtectedPath, TopologySnapshot, WriteMode};

/// The guardrails (singleton).
pub const SETTINGS: TableDef<(), Guardrails> = TableDef::new("connect.guardrails");

/// The audit action of a change.
pub const UPDATE_ACTION: &str = "connect.guardrails.update";

/// The code of guardrails outside their limits.
pub const INVALID: &str = "connect.guardrails.invalid";

/// The most protected paths.
pub const MAX_PROTECTED: usize = 256;
/// The largest `max_parallel`.
pub const MAX_PARALLEL: usize = 64;
/// The longest device or network reference.
pub const MAX_REF_LEN: usize = 128;

fn invalid(field: &str, detail: impl Into<String>) -> HostError {
    HostError::new(INVALID, 422, detail).with_param("field", field)
}

/// Checks the limits: `max_parallel` 1 to 64; at most 256 protected paths, without
/// duplicates; a VLAN id 1 to 4094; device and network references of 1 to 128 characters.
///
/// # Errors
///
/// 422 `connect.guardrails.invalid` with the parameter `field`.
pub fn validate(guardrails: &Guardrails) -> Result<(), HostError> {
    if !(1..=MAX_PARALLEL).contains(&guardrails.max_parallel) {
        return Err(invalid(
            "max_parallel",
            format!("max_parallel is 1 to {MAX_PARALLEL}"),
        ));
    }
    if guardrails.protected.len() > MAX_PROTECTED {
        return Err(invalid(
            "protected",
            format!("at most {MAX_PROTECTED} protected paths"),
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, path) in guardrails.protected.iter().enumerate() {
        let field = format!("protected[{index}]");
        let reference = match path {
            ProtectedPath::Port { device, .. } => Some(&device.0),
            ProtectedPath::Network { network } => Some(&network.0),
            ProtectedPath::Vlan { vid } => {
                if !(1..=4094).contains(vid) {
                    return Err(invalid(&field, "a VLAN id is 1 to 4094"));
                }
                None
            }
            ProtectedPath::Client { .. } => None,
        };
        if let Some(reference) = reference {
            let length = reference.trim().chars().count();
            if length == 0 || length > MAX_REF_LEN || reference.chars().any(char::is_control) {
                return Err(invalid(
                    &field,
                    format!(
                        "a device or network reference has 1 to {MAX_REF_LEN} characters without control characters"
                    ),
                ));
            }
        }
        if !seen.insert(format!("{path:?}")) {
            return Err(invalid(&field, "a protected path is listed twice"));
        }
    }
    Ok(())
}

/// Checks the undo steps of an applied change against `guardrails` and a fresh
/// `topology` before a revert writes them: an undo is a write like any other, so a path
/// that became protected since the change is refused (CONN-09). A dry run or a receipt
/// without undo steps writes nothing and passes.
///
/// # Errors
///
/// [`ConnectorError::GuardrailRefused`] with the rule of the first step that is refused.
pub fn check_undo(
    guardrails: &Guardrails,
    receipt: &L2Receipt,
    topology: &TopologySnapshot,
) -> Result<(), ConnectorError> {
    if receipt.mode != WriteMode::Apply {
        return Ok(());
    }
    receipt
        .undo
        .iter()
        .try_for_each(|step| guardrails.check(step, topology))
}

/// The object of the audit records: the system.
fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

/// The guardrails in force (the stored ones, else the defaults) with the revision of the
/// stored ones.
///
/// # Errors
///
/// The store's error.
pub async fn read(store: &dyn Store) -> Result<(Guardrails, Option<Revision>), HostError> {
    let view = store.read(ReadConsistency::Local).await?;
    Ok(match view.get_typed(&SETTINGS, &())? {
        Some((guardrails, revision)) => (guardrails, Some(revision)),
        None => (Guardrails::default(), None),
    })
}

/// Stores `defaults` when no guardrails are stored yet; `true` when it wrote them. A
/// concurrent seed of another controller is not an error.
///
/// # Errors
///
/// The store's error.
pub async fn seed(store: &dyn Store, defaults: &Guardrails) -> Result<bool, HostError> {
    let view = store.read(ReadConsistency::Local).await?;
    if view.get_typed(&SETTINGS, &())?.is_some() {
        return Ok(false);
    }
    drop(view);
    let ctx = RequestCtx::system(SystemComponent::Connector);
    let mut batch = WriteBatch::for_request(&ctx);
    batch.expect_typed(&SETTINGS, &(), None);
    batch.put_typed(&SETTINGS, &(), defaults)?;
    match store.propose(batch).await {
        Ok(_) => Ok(true),
        Err(StoreError::PreconditionFailed(_)) => Ok(false),
        Err(error) => Err(HostError::coded(&error)),
    }
}

/// Replaces the guardrails, if they are still at `expect` (`None`: whatever is stored);
/// audited as `connect.guardrails.update` with the changes of `max_parallel` and of the
/// protected paths. Returns the guardrails and their new revision.
///
/// # Errors
///
/// 422 `connect.guardrails.invalid`, 409 `sys.store.precondition_failed` when `expect` is
/// stale or a concurrent change won, or the store's error.
pub async fn update(
    store: &dyn Store,
    ctx: &RequestCtx,
    guardrails: Guardrails,
    expect: Option<Revision>,
) -> Result<(Guardrails, Revision), HostError> {
    validate(&guardrails)?;
    let view = store.read(ReadConsistency::Local).await?;
    let current = view.get_typed(&SETTINGS, &())?;
    drop(view);
    let current_revision = current.as_ref().map(|(_, revision)| *revision);
    let stale = || HostError::coded(&StoreError::PreconditionFailed(Vec::new()));
    if expect.is_some() && expect != current_revision {
        return Err(stale());
    }
    let old = current.map_or_else(Guardrails::default, |(old, _)| old);
    let mut batch = WriteBatch::for_request(ctx);
    batch.expect_typed(&SETTINGS, &(), current_revision);
    batch.put_typed(&SETTINGS, &(), &guardrails)?;
    let mut draft = AuditDraft::success(
        AuditAction::from_static(UPDATE_ACTION),
        vec![system_object()],
    )
    .with_source_ip(ctx.source_ip);
    if old.max_parallel != guardrails.max_parallel {
        draft = draft.with_change(FieldChange {
            object: None,
            field: "max_parallel".to_owned(),
            old: Some(old.max_parallel.to_string()),
            new: Some(guardrails.max_parallel.to_string()),
        });
    }
    if old.protected != guardrails.protected {
        draft = draft.with_change(FieldChange {
            object: None,
            field: "protected".to_owned(),
            old: Some(render(&old.protected)),
            new: Some(render(&guardrails.protected)),
        });
    }
    batch.audit(draft);
    match store.propose(batch).await {
        Ok(committed) => Ok((guardrails, committed.revision)),
        Err(StoreError::PreconditionFailed(_)) => Err(stale()),
        Err(error) => Err(HostError::coded(&error)),
    }
}

/// The protected paths as audit text: `port:<device>/<port>`, `network:<id>`,
/// `vlan:<vid>`, `client:<mac>`, comma-separated.
fn render(paths: &[ProtectedPath]) -> String {
    paths
        .iter()
        .map(|path| match path {
            ProtectedPath::Port { device, port } => format!("port:{device}/{port}"),
            ProtectedPath::Network { network } => format!("network:{network}"),
            ProtectedPath::Vlan { vid } => format!("vlan:{vid}"),
            ProtectedPath::Client { mac } => format!("client:{mac}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The guardrails in force now, and a task that keeps the receiver current while the
/// table changes on any controller, until `stop` turns true.
///
/// # Errors
///
/// The store's error of the first read.
pub async fn follow(
    store: Arc<dyn Store>,
    mut stop: watch::Receiver<bool>,
) -> Result<(watch::Receiver<Guardrails>, JoinHandle<()>), HostError> {
    // The stream opens before the first read, so no change falls between the two.
    let filter = || WatchFilter::tables([SETTINGS.name().clone()]);
    let mut stream = store.watch(None, filter()).ok();
    let (current, _) = read(store.as_ref()).await?;
    let (sender, receiver) = watch::channel(current);
    let task = tokio::spawn(async move {
        loop {
            let alive = tokio::select! {
                () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
                alive = async {
                    if let Some(stream) = &mut stream {
                        matches!(stream.next().await, Some(Ok(_)))
                    } else {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        false
                    }
                } => alive,
            };
            if !alive {
                stream = store.watch(None, filter()).ok();
            }
            match read(store.as_ref()).await {
                Ok((guardrails, _)) => {
                    sender.send_if_modified(|current| {
                        let changed = *current != guardrails;
                        if changed {
                            *current = guardrails;
                        }
                        changed
                    });
                }
                Err(error) => tracing::warn!(%error, "the guardrails could not be read"),
            }
        }
    });
    Ok((receiver, task))
}

#[cfg(test)]
mod tests {
    use tenko_core::{AuthStrength, Principal, SessionId, UserId};
    use tenko_store::{KeyRange, MemStore};

    use super::*;
    use crate::{DeviceRef, L2Change, L2Plan, NetworkRef, ProfileRef};

    fn admin() -> RequestCtx {
        RequestCtx::new(Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Passkey,
        })
    }

    fn port(device: &str, port: u16) -> ProtectedPath {
        ProtectedPath::Port {
            device: DeviceRef(device.to_owned()),
            port,
        }
    }

    #[test]
    fn values_outside_the_limits_are_refused_with_the_field() {
        validate(&Guardrails::default()).expect("the defaults are valid");
        let cases = [
            (
                Guardrails {
                    max_parallel: 0,
                    ..Guardrails::default()
                },
                "max_parallel",
            ),
            (
                Guardrails {
                    max_parallel: 65,
                    ..Guardrails::default()
                },
                "max_parallel",
            ),
            (
                Guardrails {
                    protected: vec![ProtectedPath::Vlan { vid: 4095 }],
                    ..Guardrails::default()
                },
                "protected[0]",
            ),
            (
                Guardrails {
                    protected: vec![ProtectedPath::Network {
                        network: NetworkRef(String::new()),
                    }],
                    ..Guardrails::default()
                },
                "protected[0]",
            ),
            (
                Guardrails {
                    protected: vec![port("sw-1", 1), port("sw-1", 1)],
                    ..Guardrails::default()
                },
                "protected[1]",
            ),
            (
                Guardrails {
                    protected: (0..=256).map(|index| port("sw-1", index)).collect(),
                    ..Guardrails::default()
                },
                "protected",
            ),
        ];
        for (guardrails, field) in cases {
            let error = validate(&guardrails).expect_err("refused").into_coded();
            assert_eq!(error.code, INVALID);
            assert_eq!(error.status, 422);
            assert_eq!(error.params.get("field").map(String::as_str), Some(field));
        }
    }

    fn empty_topology() -> TopologySnapshot {
        TopologySnapshot {
            observed_at: tenko_core::Timestamp::now(),
            devices: Vec::new(),
            links: Vec::new(),
            clients: Vec::new(),
            networks: Vec::new(),
            profiles: Vec::new(),
            wlans: Vec::new(),
        }
    }

    fn receipt(mode: WriteMode) -> L2Receipt {
        let profile = |name: &str| L2Change::SetPortProfile {
            device: DeviceRef("sw-1".to_owned()),
            port: 1,
            profile: ProfileRef(name.to_owned()),
        };
        L2Receipt {
            plan: L2Plan {
                change: profile("iot"),
                read_at: tenko_core::Timestamp::now(),
                fingerprint: "abc".to_owned(),
                diff: Vec::new(),
                warnings: Vec::new(),
                undo: Vec::new(),
            },
            mode,
            applied_at: tenko_core::Timestamp::now(),
            verified: true,
            undo: vec![profile("home")],
        }
    }

    #[test]
    fn a_revert_is_refused_when_its_path_became_protected() {
        let applied = receipt(WriteMode::Apply);
        let topology = empty_topology();
        // The port was free when the change was applied.
        check_undo(&Guardrails::default(), &applied, &topology).expect("free");
        // It is protected now: the undo would write it, so the revert is refused.
        let now = Guardrails {
            protected: vec![port("sw-1", 1)],
            ..Guardrails::default()
        };
        match check_undo(&now, &applied, &topology) {
            Err(ConnectorError::GuardrailRefused { rule }) => {
                assert_eq!(rule, "connect.guardrail.protected_port");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // A dry run wrote nothing and has nothing to undo.
        check_undo(&now, &receipt(WriteMode::DryRun), &topology).expect("dry run");
    }

    #[tokio::test]
    async fn seed_update_and_follow() {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        assert!(
            seed(store.as_ref(), &Guardrails::default())
                .await
                .expect("seed")
        );
        assert!(
            !seed(store.as_ref(), &Guardrails::default())
                .await
                .expect("seeded")
        );
        let (current, revision) = read(store.as_ref()).await.expect("read");
        assert_eq!(current, Guardrails::default());
        let (stop_tx, stop) = watch::channel(false);
        let (mut followed, task) = follow(Arc::clone(&store), stop).await.expect("follow");
        assert_eq!(*followed.borrow(), Guardrails::default());

        let next = Guardrails {
            protected: vec![port("sw-1", 1)],
            max_parallel: 2,
        };
        let (stored, new_revision) = update(store.as_ref(), &admin(), next.clone(), revision)
            .await
            .expect("update");
        assert_eq!(stored, next);
        assert!(Some(new_revision) > revision);
        tokio::time::timeout(
            Duration::from_secs(5),
            followed.wait_for(|seen| *seen == next),
        )
        .await
        .expect("followed in time")
        .expect("followed");

        // A stale revision is refused.
        let error = update(store.as_ref(), &admin(), Guardrails::default(), revision)
            .await
            .expect_err("stale");
        assert_eq!(error.0.status, 409);

        // The change is audited with what changed.
        let view = store.read(ReadConsistency::Local).await.expect("view");
        let records: Vec<_> = view
            .scan_typed(
                &tenko_store::tables::AUDIT,
                KeyRange::all(),
                usize::MAX,
                false,
            )
            .expect("audit")
            .into_iter()
            .map(|(_, record, _)| record)
            .filter(|record| record.draft.action.as_str() == UPDATE_ACTION)
            .collect();
        assert_eq!(records.len(), 1);
        let fields: Vec<&str> = records[0]
            .draft
            .details
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(fields, ["max_parallel", "protected"]);
        stop_tx.send(true).expect("stop");
        task.await.expect("task");
    }
}
