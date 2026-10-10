//! Previewing and submitting VLAN provisions: one background job per request, and an
//! idempotency receipt per request key (API-04).

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    IdempotencyKey, MessageKey, ObjectRef, PrefixId, RequestCtx, Revision, VlanId,
    audit::Digest,
    codec::{canonical_sha256, to_cbor},
    ipam::{PrefixRole, Status, Vlan},
    serde_util::{HexBytes, to_hex},
    table::TableDef,
};
use tenko_jobs::{GroupKey, JobKind, JobSpec, ManualTask, StepKind, StepSpec};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, StoreError, WriteBatch};
use utoipa::ToSchema;

use super::{
    AUTOMATIC_TIMEOUT_SECS, CONTROLLER_PARALLELISM, CONTROLLER_STEP_TIMEOUT_SECS, ControllerMode,
    ControllerPreview, MANUAL_TIMEOUT_SECS, MAX_NETWORK_NAME, MAX_RELAYS, PROVISION_JOB,
    PROVISION_TITLE, PrefixTarget, VlanProvisionPreview, VlanProvisionRequest,
    VlanProvisionSubmitted, VlanStepPreview, VlanTarget, codes,
    controllers::{ControllerInfo, Controllers, NetworkSpec},
    steps::{self, VlanStepParams},
};
use crate::{
    command::{IpamCommand, PrefixInput, VlanInput},
    error::{IpamError, IpamResult, codes as ipam_codes},
    plan::{PlanOptions, PlanWarning},
    query,
    service::IpamService,
};

/// The stored answer of a provision submitted with an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VlanReceipt {
    /// SHA-256 over the canonical CBOR of the request.
    pub fingerprint: Digest,
    /// The first answer.
    pub submitted: VlanProvisionSubmitted,
}

/// Answers of provisions submitted with an idempotency key, by (principal subject, key).
pub static RECEIPTS: TableDef<(String, String), VlanReceipt> = TableDef::new("ipam.vlan_receipts");

/// What the job of a computed preview runs.
struct Computed {
    preview: VlanProvisionPreview,
    params: VlanStepParams,
    steps: Vec<(&'static str, Option<ManualTask>)>,
    connector: Option<ControllerInfo>,
}

fn invalid(detail: impl Into<String>, field: &str) -> IpamError {
    IpamError::new(codes::INVALID_REQUEST, 400, detail)
        .titled("Invalid VLAN provision")
        .param("field", field)
        .field(field, codes::INVALID_REQUEST)
}

fn validate(request: &VlanProvisionRequest) -> IpamResult<()> {
    match (&request.vlan, &request.create) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                "name either an existing VLAN (`vlan`) or a new one (`create`), not both",
                "vlan",
            ));
        }
        (None, None) => {
            return Err(invalid(
                "name an existing VLAN (`vlan`) or a new one (`create`)",
                "create",
            ));
        }
        _ => {}
    }
    if let Some(name) = &request.network_name {
        let length = name.trim().chars().count();
        if length == 0 || length > MAX_NETWORK_NAME {
            return Err(invalid(
                format!("the network name must have 1 to {MAX_NETWORK_NAME} characters"),
                "network_name",
            ));
        }
    }
    if request.dhcp_relay.len() > MAX_RELAYS {
        return Err(invalid(
            format!("at most {MAX_RELAYS} DHCP relay targets"),
            "dhcp_relay",
        ));
    }
    if request.manual && request.connector.is_some() {
        return Err(invalid(
            "a manual network step names no connector",
            "connector",
        ));
    }
    Ok(())
}

fn warning(
    code: &str,
    message: impl Into<String>,
    vlan: VlanId,
    params: &[(&str, String)],
    requires_ack: bool,
    request: &VlanProvisionRequest,
) -> PlanWarning {
    PlanWarning {
        code: code.to_owned(),
        message: message.into(),
        object: Some(ObjectRef::from(vlan)),
        params: params
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
        requires_ack,
        acknowledged: request.acknowledge.iter().any(|c| c == code),
    }
}

/// The controller of the network step and what it would change.
async fn resolve_controller(
    controllers: &Controllers,
    request: &VlanProvisionRequest,
    spec: &NetworkSpec,
    vlan: VlanId,
    cx: &RequestCtx,
) -> IpamResult<(ControllerPreview, Vec<PlanWarning>, Option<ControllerInfo>)> {
    let manual = |reason: &str, candidates: Vec<ControllerInfo>| ControllerPreview {
        mode: ControllerMode::Manual,
        reason: Some(reason.to_owned()),
        connector: None,
        network: spec.clone(),
        diff: Vec::new(),
        warnings: Vec::new(),
        read_at: None,
        candidates,
    };
    let Some(port) = controllers.get() else {
        let reason = if request.manual {
            codes::MANUAL_REQUESTED
        } else {
            codes::NO_CONTROLLER
        };
        if request.connector.is_some() {
            return Err(IpamError::new(
                codes::CONTROLLERS_UNAVAILABLE,
                503,
                "the network controllers are not available on this server",
            )
            .titled("Network controllers unavailable"));
        }
        return Ok((manual(reason, Vec::new()), Vec::new(), None));
    };
    let listed = port
        .controllers()
        .await
        .map_err(IpamError::from_coded_error)?;
    let enabled: Vec<ControllerInfo> = listed.iter().filter(|c| c.enabled).cloned().collect();
    if request.manual {
        return Ok((manual(codes::MANUAL_REQUESTED, enabled), Vec::new(), None));
    }
    let chosen = match request.connector {
        Some(id) => named(&listed, id)?,
        None => match enabled.as_slice() {
            [] => return Ok((manual(codes::NO_CONTROLLER, Vec::new()), Vec::new(), None)),
            [only] => only.clone(),
            several => {
                let warning = warning(
                    codes::CONTROLLER_AMBIGUOUS,
                    format!(
                        "{} network controllers are configured and none is named; the network \
                         step is left to a person unless the request names a connector",
                        several.len()
                    ),
                    vlan,
                    &[("count", several.len().to_string())],
                    true,
                    request,
                );
                return Ok((
                    manual(codes::CONTROLLER_AMBIGUOUS, enabled.clone()),
                    vec![warning],
                    None,
                ));
            }
        },
    };
    let plan = port
        .plan_network(chosen.id, spec, cx.principal.user())
        .await
        .map_err(IpamError::from_coded_error)?;
    Ok(planned(chosen, enabled, plan, spec, vlan, request))
}

/// The connector a request names, when it is an enabled network controller.
fn named(listed: &[ControllerInfo], id: tenko_core::ConnectorId) -> IpamResult<ControllerInfo> {
    let found = listed.iter().find(|c| c.id == id).cloned().ok_or_else(|| {
        IpamError::new(
            codes::CONTROLLER_UNKNOWN,
            404,
            format!("connector {id} is not a network controller of this server"),
        )
        .titled("Unknown network controller")
        .param("connector", id)
        .field("connector", codes::CONTROLLER_UNKNOWN)
    })?;
    if !found.enabled {
        return Err(IpamError::new(
            codes::CONTROLLER_DISABLED,
            409,
            format!("connector {} is disabled", found.name),
        )
        .titled("Network controller disabled")
        .param("connector", id)
        .field("connector", codes::CONTROLLER_DISABLED));
    }
    Ok(found)
}

/// The network step through a chosen controller, from its plan.
fn planned(
    chosen: ControllerInfo,
    enabled: Vec<ControllerInfo>,
    plan: super::controllers::NetworkPlan,
    spec: &NetworkSpec,
    vlan: VlanId,
    request: &VlanProvisionRequest,
) -> (ControllerPreview, Vec<PlanWarning>, Option<ControllerInfo>) {
    let mut warnings = Vec::new();
    let mode = if plan.diff.is_empty() {
        ControllerMode::Unchanged
    } else if !chosen.writes_enabled {
        warnings.push(warning(
            codes::CONTROLLER_READ_ONLY,
            format!(
                "connector {} does not allow writes (TGL-20); the network step is left to a person",
                chosen.name
            ),
            vlan,
            &[("connector", chosen.name.clone())],
            true,
            request,
        ));
        ControllerMode::Manual
    } else {
        ControllerMode::Automatic
    };
    if mode == ControllerMode::Automatic && plan.diff.iter().any(|line| line.before.is_some()) {
        warnings.push(warning(
            codes::NETWORK_CHANGES,
            format!(
                "the controller has a network on VLAN {} already; the write changes it",
                spec.vid
            ),
            vlan,
            &[("vid", spec.vid.to_string())],
            true,
            request,
        ));
    }
    let reason = (mode == ControllerMode::Manual).then(|| codes::CONTROLLER_READ_ONLY.to_owned());
    let automatic = (mode != ControllerMode::Manual).then(|| chosen.clone());
    (
        ControllerPreview {
            mode,
            reason,
            connector: Some(chosen),
            network: spec.clone(),
            diff: plan.diff,
            warnings: plan.warnings,
            read_at: Some(plan.read_at),
            candidates: enabled,
        },
        warnings,
        automatic,
    )
}

fn step_preview(
    kind: &str,
    step_kind: &str,
    automatic: bool,
    text: String,
    params: &BTreeMap<String, String>,
) -> VlanStepPreview {
    VlanStepPreview {
        kind: kind.to_owned(),
        step_kind: step_kind.to_owned(),
        automatic,
        text,
        params: params.clone(),
    }
}

/// The VLAN of a request: the existing one it names, or the one it creates (as planned).
fn target_of(
    view: &dyn ReadView,
    request: &VlanProvisionRequest,
) -> IpamResult<(VlanTarget, Option<VlanInput>)> {
    if let Some(id) = request.vlan {
        let vlan: Vlan = query::get(view, id)?;
        if vlan.meta.is_deleted() {
            return Err(IpamError::deleted(ObjectRef::from(id)));
        }
        return Ok((
            VlanTarget {
                id: vlan.id,
                vid: vlan.vid,
                name: vlan.name.clone(),
                site: vlan.site,
                existing: true,
                status: vlan.status,
            },
            None,
        ));
    }
    let new = request
        .create
        .as_ref()
        .ok_or_else(|| invalid("name an existing VLAN or a new one", "create"))?;
    let id = VlanId::generate();
    Ok((
        VlanTarget {
            id,
            vid: new.vid,
            name: new.name.trim().to_owned(),
            site: new.site,
            existing: false,
            status: Status::Planned,
        },
        Some(VlanInput {
            id: Some(id),
            vid: new.vid,
            vni: new.vni,
            name: new.name.clone(),
            site: new.site,
            status: Some(Status::Planned),
            tags: new.tags.clone(),
            custom: BTreeMap::new(),
            description: new.description.clone(),
        }),
    ))
}

/// The steps of the job: their kinds with the manual task, and their previews.
struct JobSteps {
    steps: Vec<(&'static str, Option<ManualTask>)>,
    previews: Vec<VlanStepPreview>,
    task: Option<ManualTask>,
}

fn job_steps(
    target: &VlanTarget,
    prefix: Option<&PrefixInput>,
    intent: bool,
    spec: &NetworkSpec,
    controller: &ControllerPreview,
) -> JobSteps {
    let mut args = BTreeMap::from([
        ("vid".to_owned(), target.vid.to_string()),
        ("name".to_owned(), spec.name.clone()),
    ]);
    if let Some(input) = prefix {
        args.insert("cidr".to_owned(), input.cidr.to_string());
    }
    if let Some(info) = &controller.connector {
        args.insert("connector".to_owned(), info.name.clone());
    }
    let mut out = JobSteps {
        steps: Vec::new(),
        previews: Vec::new(),
        task: None,
    };
    if intent {
        out.steps.push((steps::INTENT, None));
        out.previews.push(step_preview(
            "ipam.intent",
            steps::INTENT,
            true,
            match prefix {
                Some(input) => format!(
                    "Create {} and the network {} in IPAM as planned",
                    describe(target),
                    input.cidr
                ),
                None => format!(
                    "Create VLAN {} ({}) in IPAM as planned",
                    target.vid, target.name
                ),
            },
            &args,
        ));
    }
    if controller.mode == ControllerMode::Manual {
        let task = ManualTask {
            instruction: MessageKey::from_static("ipam.vlan.task.network"),
            args: args.clone(),
            undo: None,
        };
        out.steps.push((steps::MANUAL, Some(task.clone())));
        out.previews.push(step_preview(
            "l2.manual",
            steps::MANUAL,
            false,
            format!(
                "Create the network {} on VLAN {} on the switches and access points",
                spec.name, spec.vid
            ),
            &args,
        ));
        out.task = Some(task);
    } else {
        out.steps.push((steps::CONTROLLER, None));
        out.previews.push(step_preview(
            "l2.network",
            steps::CONTROLLER,
            true,
            format!(
                "Create the network {} on VLAN {} through {}: dry run, write, read back and compare",
                spec.name,
                spec.vid,
                controller
                    .connector
                    .as_ref()
                    .map_or("the network controller", |c| c.name.as_str())
            ),
            &args,
        ));
    }
    if intent {
        out.steps.push((steps::ACTIVATE, None));
        out.previews.push(step_preview(
            "activate",
            steps::ACTIVATE,
            true,
            format!("Set VLAN {} and its network active", target.vid),
            &args,
        ));
    }
    out
}

async fn compute(
    ipam: &IpamService,
    controllers: &Controllers,
    view: &dyn ReadView,
    request: &VlanProvisionRequest,
    cx: &RequestCtx,
) -> IpamResult<Computed> {
    validate(request)?;
    let (target, create) = target_of(view, request)?;
    let prefix = request.prefix.as_ref().map(|new| PrefixInput {
        id: Some(PrefixId::generate()),
        vrf: new.vrf,
        cidr: new.cidr,
        role: Some(PrefixRole::Network),
        status: Some(Status::Planned),
        vlan: Some(target.id),
        site: target.site,
        alarm: None,
        alloc: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: new.description.clone(),
    });
    let mut commands = Vec::new();
    if let Some(input) = &create {
        commands.push(IpamCommand::CreateVlan(input.clone()));
    }
    if let Some(input) = &prefix {
        commands.push(IpamCommand::CreatePrefix(input.clone()));
    }
    let plan = if commands.is_empty() {
        None
    } else {
        Some(ipam.plan(
            view,
            cx,
            &PlanOptions::acknowledging(request.acknowledge.iter().cloned()),
            &commands,
        )?)
    };
    let spec = NetworkSpec {
        vid: target.vid,
        name: request
            .network_name
            .as_deref()
            .map_or_else(|| target.name.clone(), |name| name.trim().to_owned()),
        dhcp_relay: request.dhcp_relay.clone(),
    };
    let (controller, controller_warnings, connector) =
        resolve_controller(controllers, request, &spec, target.id, cx).await?;
    let JobSteps {
        steps,
        previews,
        task,
    } = job_steps(
        &target,
        prefix.as_ref(),
        !commands.is_empty(),
        &spec,
        &controller,
    );
    let mut warnings: Vec<PlanWarning> = plan
        .as_ref()
        .map(|plan| plan.warnings.clone())
        .unwrap_or_default();
    warnings.extend(controller_warnings);
    let unacknowledged: BTreeSet<String> = warnings
        .iter()
        .filter(|w| w.requires_ack && !w.acknowledged)
        .map(|w| w.code.clone())
        .collect();
    let params = VlanStepParams {
        vlan: target.id,
        vid: target.vid,
        name: target.name.clone(),
        create,
        prefix: prefix.clone(),
        connector: connector.as_ref().map(|c| c.id),
        network: spec,
        expected_diff: controller.diff.clone(),
        task: task.clone(),
    };
    Ok(Computed {
        preview: VlanProvisionPreview {
            prefix: prefix.as_ref().map(|input| PrefixTarget {
                id: input.id.unwrap_or_else(PrefixId::generate),
                cidr: input.cidr,
                vrf: input.vrf,
            }),
            vlan: target,
            plan: plan.map(|plan| plan.view()),
            controller,
            steps: previews,
            warnings,
            unacknowledged: unacknowledged.into_iter().collect(),
            base_revision: view.revision().0,
        },
        params,
        steps,
        connector,
    })
}

fn describe(target: &VlanTarget) -> String {
    if target.existing {
        format!("the link to VLAN {} ({})", target.vid, target.name)
    } else {
        format!("VLAN {} ({})", target.vid, target.name)
    }
}

/// The preview of a provision (the dry run), at least at `at_least` when given: the IPAM
/// plan, the controller's read-back diff and the steps of the job. Writes nothing.
///
/// # Errors
///
/// `ipam.vlan.invalid_request`, the planning errors (`ipam.vlan.duplicate`,
/// `ipam.prefix.overlap`, ...), `ipam.vlan.controller_unknown`,
/// `ipam.vlan.controller_disabled`, and the controller's errors (a guardrail refusal such
/// as `connect.guardrail.protected_vlan`, `connect.unreachable`).
pub async fn preview(
    ipam: &IpamService,
    controllers: &Controllers,
    request: &VlanProvisionRequest,
    cx: &RequestCtx,
    at_least: Option<Revision>,
) -> IpamResult<VlanProvisionPreview> {
    let view = ipam.view(at_least).await?;
    Ok(compute(ipam, controllers, view.as_ref(), request, cx)
        .await?
        .preview)
}

/// Submits a provision: computes the preview again from a fresh view, refuses while a
/// warning that needs an acknowledgement is not acknowledged, and starts the job. A
/// repeated idempotency key returns the first answer with `replayed: true`; another
/// request under the same key is 422 `ipam.idempotency_mismatch`.
///
/// # Errors
///
/// The errors of [`preview`], 409 `ipam.plan.unacknowledged`, 503 `ipam.move.no_engine`
/// without the job engine, and the engine's errors.
pub async fn submit(
    ipam: &IpamService,
    controllers: &Controllers,
    request: &VlanProvisionRequest,
    cx: &RequestCtx,
) -> IpamResult<VlanProvisionSubmitted> {
    let fingerprint = Digest(canonical_sha256(request)?);
    let key = cx
        .idempotency
        .as_ref()
        .map(|key| (cx.principal.subject(), key.as_str().to_owned()));
    if let Some(key) = &key
        && let Some(receipt) = receipt(ipam, key).await?
    {
        return replay(receipt, &fingerprint);
    }
    let view = ipam.store().read(ReadConsistency::Linearizable).await?;
    let computed = compute(ipam, controllers, view.as_ref(), request, cx).await?;
    drop(view);
    if !computed.preview.unacknowledged.is_empty() {
        return Err(IpamError::new(
            ipam_codes::PLAN_UNACKNOWLEDGED,
            409,
            format!(
                "the provision needs an acknowledgement of: {}",
                computed.preview.unacknowledged.join(", ")
            ),
        )
        .titled("Warnings need an acknowledgement")
        .param("codes", computed.preview.unacknowledged.join(",")));
    }
    let spec = job_spec(&computed, cx)?;
    let job_id = ipam.jobs().submit(spec, cx).await?;
    let submitted = VlanProvisionSubmitted {
        job_id,
        vlan: computed.params.vlan,
        prefix: computed.params.prefix.as_ref().and_then(|p| p.id),
        preview: computed.preview,
        replayed: false,
    };
    if let Some(key) = key {
        let stored = VlanReceipt {
            fingerprint,
            submitted: submitted.clone(),
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        batch.expect_typed(&RECEIPTS, &key, None);
        batch.put_typed(&RECEIPTS, &key, &stored)?;
        match ipam.store().propose(batch).await {
            Ok(_) => {}
            Err(StoreError::PreconditionFailed(_)) => {
                // A concurrent request with the same key finished first; the engine
                // deduplicated the job by its derived key.
                if let Some(receipt) = receipt(ipam, &key).await? {
                    return replay(receipt, &fingerprint);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(submitted)
}

async fn receipt(ipam: &IpamService, key: &(String, String)) -> IpamResult<Option<VlanReceipt>> {
    let view = ipam.store().read(ReadConsistency::Local).await?;
    Ok(view.get_typed(&RECEIPTS, key)?.map(|(receipt, _)| receipt))
}

fn replay(receipt: VlanReceipt, fingerprint: &Digest) -> IpamResult<VlanProvisionSubmitted> {
    if receipt.fingerprint != *fingerprint {
        return Err(IpamError::new(
            ipam_codes::IDEMPOTENCY_MISMATCH,
            422,
            "the idempotency key was used before for a different provision",
        )
        .titled("Idempotency key reused"));
    }
    let mut submitted = receipt.submitted;
    submitted.replayed = true;
    Ok(submitted)
}

fn job_spec(computed: &Computed, cx: &RequestCtx) -> IpamResult<JobSpec> {
    let mut steps = Vec::with_capacity(computed.steps.len());
    for (kind, task) in &computed.steps {
        let params = VlanStepParams {
            task: task.clone(),
            ..computed.params.clone()
        };
        steps.push(StepSpec {
            kind: StepKind::new(*kind)?,
            params: HexBytes(to_cbor(&params)?.to_vec()),
            timeout: (*kind == steps::CONTROLLER)
                .then(|| Duration::from_secs(CONTROLLER_STEP_TIMEOUT_SECS)),
        });
    }
    let mut targets = vec![ObjectRef::from(computed.params.vlan)];
    if let Some(prefix) = computed.params.prefix.as_ref().and_then(|p| p.id) {
        targets.push(prefix.into());
    }
    if let Some(connector) = &computed.connector {
        targets.push(connector.id.into());
    }
    let (group, group_limit) = match &computed.connector {
        Some(connector) => (
            Some(GroupKey::new(format!("{PROVISION_JOB}.{}", connector.id))?),
            Some(CONTROLLER_PARALLELISM),
        ),
        None => (None, None),
    };
    let manual = computed
        .steps
        .iter()
        .any(|(kind, _)| *kind == steps::MANUAL);
    let idempotency = match &cx.idempotency {
        Some(key) => {
            let mut hasher = Sha256::new();
            hasher.update(cx.principal.subject().as_bytes());
            hasher.update([0]);
            hasher.update(key.as_str().as_bytes());
            let digest = hasher.finalize();
            Some(IdempotencyKey::new(format!(
                "{PROVISION_JOB}.{}",
                to_hex(&digest[..16])
            ))?)
        }
        None => None,
    };
    Ok(JobSpec {
        kind: JobKind::from_static(PROVISION_JOB),
        title: MessageKey::from_static(PROVISION_TITLE),
        targets,
        steps,
        timeout: Duration::from_secs(if manual {
            MANUAL_TIMEOUT_SECS
        } else {
            AUTOMATIC_TIMEOUT_SECS
        }),
        group,
        group_limit,
        idempotency,
    })
}
