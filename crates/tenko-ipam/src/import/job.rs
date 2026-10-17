//! The apply job of an import: one `import.chunk` step per chunk, then `import.finish`.
//!
//! A chunk step reconciles its slice of the frozen model with the store as the earlier
//! chunks left it, plans the commands with [`IpamService::plan`](crate::IpamService::plan),
//! adds the operator secrets of its hosts ([`Vault::stage_put`](tenko_vault::Vault::stage_put))
//! and their references to the same batch, and stages it ([`tenko_jobs::stage`]): the
//! chunk commits together with its step record, so a crash never leaves half a chunk.
//! The step is idempotent: run again, it reconciles again and plans only what is missing.
//!
//! When a later chunk fails, the engine compensates the finished chunks in reverse:
//! each chunk records its request and the objects it changed in `import.chunk_changes`
//! (in the same batch, so the job record stays small), and the
//! compensation reads their history entries of that request (IPAM-09) to delete what
//! was created and restore what was updated, and deletes the secrets it stored. Replaced
//! secrets are deleted only by the final `import.finish` step, so a rollback can point
//! the hosts back at them.
//!
//! Chunks are cut so that each chunk's batch stays under half of the configured chunk
//! size by estimate (the store refuses batches over 16 MiB) and under a command limit.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::{Arc, Weak},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, HostId, ImportId, JobId, MessageKey, ObjectKind, ObjectRef, RequestCtx, RequestId,
    audit::Digest,
    codec::{encode_key, from_cbor, to_cbor},
    ipam::{CustomValue, FieldKey, Meta},
    secret::SecretRef,
    serde_util::HexBytes,
    table::TableDef,
};
use tenko_jobs::{
    GroupKey, JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind,
    StepOutcome, StepPreview, StepSpec,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use tenko_vault::{
    SecretBytes, SecretPurpose, SecretSpec,
    operator::{self, CredentialRole},
};

use super::{
    codes, connectors,
    model::ImportModel,
    reconcile::{self, CredentialOp, HOST_CREDENTIALS, HostCredential, WorkItem},
    service::{ImportService, Prepared},
};
use crate::{
    IpamCommand,
    command::{
        AddressPatch, HostPatch, InterfacePatch, PrefixPatch, UpdateAddress, UpdateHost,
        UpdateInterface, UpdatePrefix, UpdateVlan, VlanPatch,
    },
    error::{IpamError, IpamResult},
    history::{ChangeAction, read_history},
    object::IpamObject,
    plan::PlanOptions,
};

/// Kind of the apply job.
pub const APPLY_JOB: &str = "import.apply";
/// Kind of a chunk step.
pub const CHUNK_STEP: &str = "import.chunk";
/// Kind of the final step.
pub const FINISH_STEP: &str = "import.finish";
/// Title of the job (a UI message key).
pub const APPLY_TITLE: &str = "import.job.apply";
/// Summary key of a chunk's preview.
pub const CHUNK_PREVIEW: &str = "import.job.chunk_preview";
/// Summary key of the final step's preview.
pub const FINISH_PREVIEW: &str = "import.job.finish_preview";
/// Purpose of the operator secrets an import stores.
pub const CREDENTIAL_PURPOSE: &str = "import.host_credential";

/// Parameters of a chunk step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkParams {
    /// The import.
    pub import: ImportId,
    /// The chunk's position, from 0.
    pub chunk: u32,
    /// Chunks in the job.
    pub chunks: u32,
    /// First work item, inclusive.
    pub first: u32,
    /// Last work item, exclusive.
    pub last: u32,
    /// The frozen model's digest.
    pub model: Digest,
}

/// Parameters of the final step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishParams {
    /// The import.
    pub import: ImportId,
}

/// A credential a chunk stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The host.
    pub host: HostId,
    /// The new secret.
    pub secret: SecretRef,
    /// The reference it replaced, if any (its secret is deleted by `import.finish`).
    #[serde(default)]
    pub previous: Option<HostCredential>,
}

/// What a chunk did, for its compensation and the final step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkOutput {
    /// The request whose history entries the chunk wrote.
    pub request: Option<RequestId>,
    /// The objects the chunk created or updated, in plan order (derived changes left out).
    #[serde(default)]
    pub changed: Vec<(ObjectRef, ChangeAction)>,
    /// The credentials it stored.
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

/// What each chunk changed, by job and chunk. The step output only names the row, so the
/// job record stays small however large the import is; the final step removes the rows.
pub static CHUNK_CHANGES: TableDef<(JobId, u32), ChunkOutput> =
    TableDef::new("import.chunk_changes");

/// The output of a chunk step: where its changes are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// The chunk's position.
    pub chunk: u32,
}

/// The step kind of chunks.
pub fn chunk_step_kind() -> StepKind {
    StepKind::from_static(CHUNK_STEP)
}

/// The step kind of the final step.
pub fn finish_step_kind() -> StepKind {
    StepKind::from_static(FINISH_STEP)
}

/// Registers the import steps with the engine.
pub fn register_steps(engine: &mut JobEngine, service: Weak<ImportService>) {
    engine.register(Arc::new(ChunkStep {
        service: service.clone(),
    }));
    engine.register(Arc::new(FinishStep { service }));
}

/// Cuts the work items into chunks: contiguous, each under half of `chunk_bytes` by
/// estimate and at most `max_commands` commands. Always at least one chunk.
pub fn cut_chunks(
    items: &[WorkItem],
    model: &ImportModel,
    chunk_bytes: usize,
    max_commands: usize,
) -> Vec<Range<usize>> {
    let budget = (chunk_bytes / 2).max(64 * 1024);
    let max_commands = max_commands.max(1);
    let mut chunks = Vec::new();
    let (mut start, mut bytes, mut commands) = (0, 0, 0);
    for (index, item) in items.iter().enumerate() {
        let (b, c) = (item.estimated_bytes(model), item.estimated_commands(model));
        if index > start && (bytes + b > budget || commands + c > max_commands) {
            chunks.push(start..index);
            start = index;
            bytes = 0;
            commands = 0;
        }
        bytes += b;
        commands += c;
    }
    chunks.push(start..items.len());
    chunks
}

fn spec_error(error: &tenko_core::codec::CodecError) -> IpamError {
    IpamError::new("sys.internal", 500, error.to_string())
}

/// The job that applies an import in `chunks`.
///
/// # Errors
///
/// Returns an internal error if the parameters do not encode.
pub fn apply_job(id: ImportId, model: Digest, chunks: &[Range<usize>]) -> IpamResult<JobSpec> {
    let count = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
    let mut steps = Vec::with_capacity(chunks.len() + 1);
    for (index, range) in chunks.iter().enumerate() {
        let params = ChunkParams {
            import: id,
            chunk: u32::try_from(index).unwrap_or(u32::MAX),
            chunks: count,
            first: u32::try_from(range.start).unwrap_or(u32::MAX),
            last: u32::try_from(range.end).unwrap_or(u32::MAX),
            model,
        };
        steps.push(StepSpec {
            kind: chunk_step_kind(),
            params: HexBytes(to_cbor(&params).map_err(|e| spec_error(&e))?.to_vec()),
            timeout: Some(Duration::from_secs(600)),
        });
    }
    steps.push(StepSpec {
        kind: finish_step_kind(),
        params: HexBytes(
            to_cbor(&FinishParams { import: id })
                .map_err(|e| spec_error(&e))?
                .to_vec(),
        ),
        timeout: Some(Duration::from_secs(120)),
    });
    Ok(JobSpec {
        kind: JobKind::from_static(APPLY_JOB),
        title: MessageKey::from_static(APPLY_TITLE),
        targets: vec![ObjectRef::from(id)],
        steps,
        timeout: Duration::from_secs(60 * 60),
        group: GroupKey::new("import").ok(),
        group_limit: None,
        idempotency: None,
        node: None,
    })
}

fn failed(code: &'static str, status: u16, detail: impl Into<String>) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, detail)))
}

fn ipam_error(error: IpamError) -> StepError {
    StepError::Coded(Box::new(error.into_coded()))
}

fn service_gone() -> StepError {
    failed(
        codes::APPLY_FAILED,
        503,
        "the import service is not running on this node",
    )
}

/// The `import.chunk` step.
struct ChunkStep {
    service: Weak<ImportService>,
}

#[async_trait::async_trait]
impl StepHandler for ChunkStep {
    fn kind(&self) -> StepKind {
        chunk_step_kind()
    }

    /// Idempotent: a re-run reconciles against the store again and plans only what is
    /// missing.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: ChunkParams =
            from_cbor(params).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(CHUNK_PREVIEW),
            args: BTreeMap::from([
                ("chunk".to_owned(), (params.chunk + 1).to_string()),
                ("chunks".to_owned(), params.chunks.to_string()),
                ("items".to_owned(), (params.last - params.first).to_string()),
            ]),
            changes: vec![ObjectRef::from(params.import)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: ChunkParams =
            from_cbor(params).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        let service = self.service.upgrade().ok_or_else(service_gone)?;
        let prepared = service
            .frozen(params.import, params.model)
            .await
            .map_err(ipam_error)?;
        let range = params.first as usize..params.last as usize;
        let Some(items) = prepared.items.get(range) else {
            return Err(StepError::InvalidParams(
                "chunk outside the model".to_owned(),
            ));
        };
        let view = cx.store.read(ReadConsistency::Linearizable).await?;
        let reconciled = reconcile::reconcile(
            view.as_ref(),
            &prepared.model,
            &prepared.mapping.options,
            items,
        )
        .map_err(ipam_error)?;
        if reconciled.blocked {
            return Err(failed(
                codes::PLAN_BLOCKED,
                409,
                "the store changed: an item conflicts and the conflict policy refuses the import",
            ));
        }
        let options = PlanOptions {
            acknowledge: prepared.mapping.options.acknowledge.clone(),
        };
        let plan = service
            .ipam()
            .plan(view.as_ref(), &cx.request, &options, &reconciled.commands)
            .map_err(ipam_error)?;
        let unacknowledged = plan.unacknowledged();
        if !unacknowledged.is_empty() {
            return Err(failed(
                crate::error::codes::PLAN_UNACKNOWLEDGED,
                409,
                format!(
                    "the chunk needs an acknowledgement of: {}",
                    unacknowledged.join(", ")
                ),
            ));
        }
        let mut batch = plan.to_batch();
        let mut output = ChunkOutput {
            request: Some(cx.request.request),
            changed: plan
                .changes
                .iter()
                .filter(|change| !change.derived)
                .map(|change| (change.object, change.action))
                .collect(),
            credentials: Vec::new(),
        };
        if !reconciled.credentials.is_empty() {
            output.credentials = stage_credentials(
                &service,
                &prepared,
                &reconciled.credentials,
                params.import,
                &mut batch,
                cx,
            )
            .await?;
        }
        batch
            .put_typed(&CHUNK_CHANGES, &(cx.job, params.chunk), &output)
            .map_err(StepError::Store)?;
        tenko_jobs::stage(cx, batch)?;
        let reference = ChunkRef {
            chunk: params.chunk,
        };
        let bytes = to_cbor(&reference).map_err(|e| StepError::coded(&e))?;
        Ok(StepOutcome::Done {
            output: Some(bytes),
        })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let Some(output) = output else {
            return Ok(());
        };
        let reference: ChunkRef =
            from_cbor(output).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        let service = self.service.upgrade().ok_or_else(service_gone)?;
        let view = cx.store.read(ReadConsistency::Linearizable).await?;
        let key = (cx.job, reference.chunk);
        let Some((output, _)) = view.get_typed(&CHUNK_CHANGES, &key)? else {
            return Ok(());
        };
        let commands = match output.request {
            Some(request) => {
                revert_commands(view.as_ref(), request, &output.changed).map_err(ipam_error)?
            }
            None => Vec::new(),
        };
        let mut batch = if commands.is_empty() {
            WriteBatch::for_request(&cx.request)
        } else {
            let options = PlanOptions::acknowledging(Vec::<String>::new());
            service
                .ipam()
                .plan(view.as_ref(), &cx.request, &options, &commands)
                .map_err(ipam_error)?
                .to_batch()
        };
        if let Some(vault) = service.vault() {
            for stored in output.credentials.iter().rev() {
                // The secrets model (WP2.1): the new secret's record and binding go, the
                // previous credential is bound to the host again. A secret that a
                // connector instance references already stays, with its record.
                let referenced = !connectors::referencing(view.as_ref(), stored.secret.secret)
                    .map_err(ipam_error)?
                    .is_empty();
                if !referenced {
                    vault.stage_delete(&mut batch, &cx.request, stored.secret);
                }
                operator::stage_unbind(&mut batch, stored.host, stored.secret.secret);
                if !referenced {
                    operator::stage_forget(&mut batch, stored.secret.secret);
                }
                match &stored.previous {
                    Some(previous) => {
                        batch
                            .put_typed(&HOST_CREDENTIALS, &stored.host, previous)
                            .map_err(StepError::Store)?;
                        operator::stage_bind(
                            &mut batch,
                            stored.host,
                            previous.secret.secret,
                            CredentialRole::Admin,
                            cx.request.now,
                        )
                        .map_err(StepError::Store)?;
                    }
                    None => {
                        batch.delete_typed(&HOST_CREDENTIALS, &stored.host);
                    }
                }
            }
        }
        batch.delete_typed(&CHUNK_CHANGES, &key);
        tenko_jobs::stage(cx, batch)?;
        Ok(())
    }
}

/// Adds the operator secrets of a chunk's hosts and their references to the batch: one
/// secret per host holding its login and password, unless the stored one already holds
/// the same value. Returns what was stored, for the compensation and the final step.
async fn stage_credentials(
    service: &ImportService,
    prepared: &Prepared,
    ops: &[CredentialOp],
    import: ImportId,
    batch: &mut WriteBatch,
    cx: &StepContext,
) -> Result<Vec<StoredCredential>, StepError> {
    let vault = service.vault().ok_or_else(|| {
        failed(
            codes::CREDENTIALS_VAULT_REQUIRED,
            403,
            "credentials need the vault, which this server does not have",
        )
    })?;
    let mut stored = Vec::new();
    for op in ops {
        let Some(value) = prepared.credentials.0.get(&op.host) else {
            continue;
        };
        let bytes = value.to_secret_bytes();
        if let Some(existing) = &op.existing
            && vault
                .get_system(&cx.request, existing.secret)
                .await
                .is_ok_and(|current| current.expose() == bytes.as_slice())
        {
            continue;
        }
        let spec = SecretSpec::new(SecretPurpose::from_static(CREDENTIAL_PURPOSE))
            .owned_by(ObjectRef::from(op.host_id))
            .labelled(format!("Login and password of {}", op.host));
        let secret = vault
            .stage_put(
                batch,
                &cx.request,
                tenko_core::secret::SecretClass::Operator,
                spec,
                &SecretBytes::from_slice(&bytes),
            )
            .map_err(|e| StepError::coded(&e))?;
        let row = HostCredential {
            secret,
            login: value.login.is_some(),
            password: value.password.is_some(),
            import,
            at: cx.request.now,
        };
        batch
            .put_typed(&HOST_CREDENTIALS, &op.host_id, &row)
            .map_err(StepError::Store)?;
        // The shared model of operator secrets (WP2.1): a record (the login becomes the
        // user name, the value keeps this layout) and an `admin` binding to the host, in
        // place of the binding of the credential it replaces.
        let record = operator::imported_record(
            secret.secret,
            op.host.as_str(),
            value.login.as_deref().map(String::as_str),
            cx.request.now,
        );
        operator::stage_record(batch, &record).map_err(StepError::Store)?;
        if let Some(existing) = &op.existing {
            operator::stage_unbind(batch, op.host_id, existing.secret.secret);
        }
        operator::stage_bind(
            batch,
            op.host_id,
            secret.secret,
            CredentialRole::Admin,
            cx.request.now,
        )
        .map_err(StepError::Store)?;
        stored.push(StoredCredential {
            host: op.host_id,
            secret,
            previous: op.existing.clone(),
        });
    }
    Ok(stored)
}

/// The commands that undo a chunk, from the history entries its request wrote: created
/// objects are soft-deleted (newest first), updated ones get their earlier values back.
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn revert_commands(
    view: &dyn ReadView,
    request: RequestId,
    changed: &[(ObjectRef, ChangeAction)],
) -> IpamResult<Vec<IpamCommand>> {
    let mut commands = Vec::new();
    let mut seen = BTreeSet::new();
    for (object, action) in changed.iter().rev() {
        if !seen.insert((*object, *action)) {
            continue;
        }
        let entries = read_history(view, *object, None, 64, true)?;
        let Some((_, entry)) = entries.into_iter().find(|(_, e)| e.request == request) else {
            continue;
        };
        match entry.action {
            ChangeAction::Create => {
                let live = crate::query::get_object(view, *object)
                    .ok()
                    .and_then(|o| o.meta().map(|m| !m.is_deleted()))
                    .unwrap_or(false);
                if live
                    && !matches!(
                        object.kind,
                        ObjectKind::Tenant | ObjectKind::Vrf | ObjectKind::Site
                    )
                {
                    commands.push(IpamCommand::Delete {
                        object: *object,
                        expected: None,
                        cascade: !matches!(object.kind, ObjectKind::Prefix),
                    });
                }
            }
            ChangeAction::Update => {
                if let (Some(before), Some(after)) = (entry.before, entry.after)
                    && let Some(command) = revert_update(&before, &after)
                {
                    commands.push(command);
                }
            }
            _ => {}
        }
    }
    // Tenants, VRFs and sites the import created go last, once nothing refers to them.
    for (object, action) in changed.iter().rev() {
        if *action == ChangeAction::Create
            && matches!(
                object.kind,
                ObjectKind::Tenant | ObjectKind::Vrf | ObjectKind::Site
            )
        {
            let entries = read_history(view, *object, None, 64, true)?;
            if entries.iter().any(|(_, e)| e.request == request) {
                commands.push(IpamCommand::Delete {
                    object: *object,
                    expected: None,
                    cascade: false,
                });
            }
        }
    }
    Ok(commands)
}

/// The metadata part of a revert patch: the fields that differ between before and after.
#[allow(clippy::type_complexity)]
fn revert_meta(
    before: &Meta,
    after: &Meta,
) -> (
    Option<Option<String>>,
    Option<BTreeSet<tenko_core::ipam::Tag>>,
    Option<BTreeMap<FieldKey, Option<CustomValue>>>,
) {
    let description = (before.description != after.description).then(|| before.description.clone());
    let tags = (before.tags != after.tags).then(|| before.tags.clone());
    let mut custom: BTreeMap<FieldKey, Option<CustomValue>> = BTreeMap::new();
    for (key, value) in &after.custom {
        if before.custom.get(key) != Some(value) {
            custom.insert(key.clone(), before.custom.get(key).cloned());
        }
    }
    (description, tags, (!custom.is_empty()).then_some(custom))
}

fn changed<T: PartialEq + Clone>(before: &T, after: &T) -> Option<T> {
    (before != after).then(|| before.clone())
}

/// The update that restores `before` over `after`.
fn revert_update(before: &IpamObject, after: &IpamObject) -> Option<IpamCommand> {
    match (before, after) {
        (IpamObject::Prefix(b), IpamObject::Prefix(a)) => {
            let (description, tags, custom) = revert_meta(&b.meta, &a.meta);
            Some(IpamCommand::UpdatePrefix(UpdatePrefix {
                id: b.id,
                expected: None,
                patch: PrefixPatch {
                    cidr: None,
                    role: changed(&b.role, &a.role),
                    status: changed(&b.status, &a.status),
                    vlan: changed(&b.vlan, &a.vlan),
                    site: changed(&b.site, &a.site),
                    alarm: changed(&b.alarm, &a.alarm),
                    alloc: changed(&b.alloc, &a.alloc),
                    dns_reverse: changed(&b.dns_reverse, &a.dns_reverse),
                    tags,
                    custom,
                    description,
                },
            }))
        }
        (IpamObject::Host(b), IpamObject::Host(a)) => {
            let (description, tags, custom) = revert_meta(&b.meta, &a.meta);
            Some(IpamCommand::UpdateHost(UpdateHost {
                id: b.id,
                expected: None,
                patch: HostPatch {
                    name: None,
                    mode: changed(&b.mode, &a.mode),
                    lock: changed(&b.lock, &a.lock),
                    site: changed(&b.site, &a.site),
                    tags,
                    custom,
                    description,
                },
            }))
        }
        (IpamObject::Interface(b), IpamObject::Interface(a)) => {
            let (description, tags, custom) = revert_meta(&b.meta, &a.meta);
            Some(IpamCommand::UpdateInterface(UpdateInterface {
                id: b.id,
                expected: None,
                patch: InterfacePatch {
                    name: None,
                    mac: changed(&b.mac, &a.mac),
                    duid: changed(&b.duid, &a.duid),
                    client_id: changed(&b.client_id, &a.client_id),
                    tags,
                    custom,
                    description,
                },
            }))
        }
        (IpamObject::Address(b), IpamObject::Address(a)) => {
            let (description, tags, custom) = revert_meta(&b.meta, &a.meta);
            Some(IpamCommand::UpdateAddress(UpdateAddress {
                id: b.id,
                expected: None,
                patch: AddressPatch {
                    ip: None,
                    status: changed(&b.status, &a.status),
                    interface: changed(&b.interface, &a.interface),
                    dns_name: changed(&b.dns_name, &a.dns_name),
                    tags,
                    custom,
                    description,
                },
            }))
        }
        (IpamObject::Vlan(b), IpamObject::Vlan(a)) => {
            let (description, tags, custom) = revert_meta(&b.meta, &a.meta);
            Some(IpamCommand::UpdateVlan(UpdateVlan {
                id: b.id,
                expected: None,
                patch: VlanPatch {
                    name: changed(&b.name, &a.name),
                    tags,
                    custom,
                    description,
                    ..VlanPatch::default()
                },
            }))
        }
        _ => None,
    }
}

/// The `import.finish` step: deletes the secrets that chunks replaced, now that nothing
/// can roll the job back any more.
struct FinishStep {
    service: Weak<ImportService>,
}

#[async_trait::async_trait]
impl StepHandler for FinishStep {
    fn kind(&self) -> StepKind {
        finish_step_kind()
    }

    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: FinishParams =
            from_cbor(params).map_err(|e| StepError::InvalidParams(e.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(FINISH_PREVIEW),
            args: BTreeMap::new(),
            changes: vec![ObjectRef::from(params.import)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, _params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let service = self.service.upgrade().ok_or_else(service_gone)?;
        let view = cx.store.read(ReadConsistency::Linearizable).await?;
        let rows = view.scan_typed(
            &CHUNK_CHANGES,
            KeyRange::prefix(encode_key(&cx.job)),
            usize::MAX,
            false,
        )?;
        let mut batch = WriteBatch::for_request(&cx.request);
        for (key, output, _) in rows {
            if let Some(vault) = service.vault() {
                for secret in output
                    .credentials
                    .iter()
                    .filter_map(|c| c.previous.as_ref().map(|p| p.secret))
                {
                    // A replaced credential that a person bound to another host stays.
                    if !operator::hosts_of(view.as_ref(), secret.secret)
                        .map_err(StepError::Store)?
                        .is_empty()
                    {
                        continue;
                    }
                    // Nor does one that a connector instance references.
                    let instances = connectors::referencing(view.as_ref(), secret.secret)
                        .map_err(ipam_error)?;
                    if !instances.is_empty() {
                        tracing::info!(
                            secret = %secret.secret,
                            instances = instances.len(),
                            "a replaced credential is kept: connector instances reference it"
                        );
                        continue;
                    }
                    vault.stage_delete(&mut batch, &cx.request, secret);
                    operator::stage_forget(&mut batch, secret.secret);
                }
            }
            batch.delete_typed(&CHUNK_CHANGES, &key);
        }
        tenko_jobs::stage(cx, batch)?;
        if let Err(error) = service.ipam().flush_alarms().await {
            tracing::warn!(%error, "utilization alarms not written after the import");
        }
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Ok(())
    }
}

/// The context a job step plans with, for tests.
pub fn step_request(cx: &StepContext) -> &RequestCtx {
    &cx.request
}

/// Reads the credential reference of a host, for tests and tools.
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn host_credential(view: &dyn ReadView, host: HostId) -> IpamResult<Option<HostCredential>> {
    Ok(view
        .get_typed(&HOST_CREDENTIALS, &host)?
        .map(|(row, _)| row))
}
