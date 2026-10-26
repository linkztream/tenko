//! `ipam.move.dhcp` (IPAM-19 step 2) with Tenko DHCP (plan section 2.3, WP8.1): the
//! reservation of a moved `reserved` host in the target scope.
//!
//! A reservation is not a row of its own: the `dhcp` role derives it from IPAM intent (a
//! `reserved` host's interface with a MAC address or client identifier and an `active` or
//! `planned` address inside a served prefix). The intent step already wrote the new
//! address as `planned`, so while the move runs the interface holds both addresses and
//! both scopes hold a reservation, as IPAM-19 asks (keep the old one until the move is
//! observed).
//!
//! The step is automatic when the submit found an enabled Tenko scope on the target
//! prefix ([`DhcpStepPlan`] in its parameters): it waits until the configuration image the
//! role serves is at least at the revision of the new address ([`DhcpRolePort`], the
//! revision the status route reports), so the reservation is served before the device is
//! moved, and keeps both revisions as its output (JSON of [`MoveDhcpOutput`]). It fails
//! with 503 `ipam.move.dhcp_not_served` when the image does not get there within
//! [`DHCP_WAIT_SECS`], and the job rolls back. A server without the role in its process
//! has nothing to wait for: the reservation is intent, and the step records that.
//! Its compensation releases a lease the client already took at the new address, through
//! the node command `dhcp.lease.release`; the intent step's compensation removes the new
//! address and with it the new reservation.
//!
//! Without a Tenko scope on the target it is the manual task of Phase 1.
//!
//! The cleanup step uses the same port to release the old lease
//! ([`release_held`]): the old reservation goes with the old address.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, OnceLock},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, MacAddr, MessageKey, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{Lease, tables::LEASES},
};
use tenko_jobs::{
    JobEngine, ManualTask, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt};

use super::steps::{MoveCleanupStep, MoveStepParams};
use crate::tables::{ADDRESSES, INTERFACES};

/// The preview kind of the automatic step.
pub const PREVIEW_KIND: &str = "dhcp.reservation";
/// How long the step waits for the role's image to hold the new reservation.
pub const DHCP_WAIT_SECS: u64 = 60;
/// Between two reads of the image revision while the step waits.
const POLL: Duration = Duration::from_millis(25);

/// Stable codes of the DHCP step.
pub mod codes {
    /// The role's configuration image did not reach the new reservation in time (503).
    pub const NOT_SERVED: &str = "ipam.move.dhcp_not_served";
    /// The role could not release a lease (`cause` names the role's code).
    pub const RELEASE_FAILED: &str = "ipam.move.dhcp_release_failed";
}

/// What the submit found for the DHCP step: the Tenko scope of the target prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpStepPlan {
    /// The scope, by its prefix.
    pub scope: PrefixId,
}

/// What the automatic DHCP step found, kept as JSON in the step's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveDhcpOutput {
    /// The revision that wrote the new address, which the reservation derives from.
    pub address_revision: u64,
    /// The revision of the role's image when it held the reservation; `null` when no
    /// `dhcp` role runs in this process.
    #[serde(default)]
    pub image_revision: Option<u64>,
}

/// What a release did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The lease is released now.
    Released,
    /// No lease to release: none, not bound any more, or changed meanwhile.
    Nothing,
}

/// The `dhcp` role of this process, as a move reaches it.
#[async_trait::async_trait]
pub trait DhcpRolePort: Send + Sync {
    /// The revision of the configuration image the role serves (`dhcp.status`).
    fn image_revision(&self) -> Revision;

    /// Releases the lease of `addr` in `vrf` through the node command
    /// `dhcp.lease.release` (with its version precondition).
    ///
    /// # Errors
    ///
    /// The role's error when the store refused the write.
    async fn release(
        &self,
        vrf: VrfId,
        addr: Ipv4Addr,
        reason: &str,
    ) -> Result<Released, CodedError>;

    /// What the role saw of the client `mac` the move job `job` moves (its row of
    /// `dhcp.moving`, ADR 0027): its last DHCP message and its last one on the move's
    /// target scope. None when the role's image holds no such client.
    fn activity(&self, job: JobId, mac: MacAddr) -> Option<ClientActivity> {
        let _ = (job, mac);
        None
    }
}

/// What the `dhcp` role saw of a client a move job moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientActivity {
    /// The client's last DHCP message.
    pub last: Option<Timestamp>,
    /// Its last message whose scope is the move's target: the client reconnected.
    pub on_target: Option<Timestamp>,
}

/// Waits at most `wait` until the role's image is at `revision`; whether it got there.
pub(super) async fn image_at(role: &dyn DhcpRolePort, revision: Revision, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if role.image_revision() >= revision {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The slot of the role: empty until the role runs, filled once by `tenko serve`.
#[derive(Clone, Default)]
pub struct DhcpMoves(Arc<OnceLock<Arc<dyn DhcpRolePort>>>);

impl std::fmt::Debug for DhcpMoves {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DhcpMoves")
            .field(&self.0.get().is_some())
            .finish()
    }
}

impl DhcpMoves {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// A slot holding `role`.
    pub fn with(role: Arc<dyn DhcpRolePort>) -> Self {
        let slot = Self::default();
        slot.set(role);
        slot
    }

    /// Sets the role once; a second call changes nothing.
    pub fn set(&self, role: Arc<dyn DhcpRolePort>) {
        let _ = self.0.set(role);
    }

    /// The role, once it runs.
    pub fn get(&self) -> Option<&Arc<dyn DhcpRolePort>> {
        self.0.get()
    }
}

/// Registers the automatic DHCP step and the cleanup that releases the old lease, over
/// `slot`, in place of the manual handlers of [`super::move_step_handlers`].
pub fn register_steps(engine: &mut JobEngine, slot: &DhcpMoves) {
    engine.register(Arc::new(MoveDhcpStep::new(slot.clone())));
    engine.register(Arc::new(MoveCleanupStep::with_dhcp(slot.clone())));
    // ADR 0027: the moving client, whose removal waits for the role's image.
    super::lease::register_steps(engine, slot);
}

/// The MAC address of the moved interface.
pub(super) fn interface_mac(
    view: &dyn ReadView,
    params: &MoveStepParams,
) -> Result<Option<MacAddr>, StepError> {
    let Some(interface) = params.interface else {
        return Ok(None);
    };
    Ok(view
        .get_typed(&INTERFACES, &interface)?
        .and_then(|(interface, _)| interface.mac))
}

/// Releases the lease of `ip` in `vrf` when `mac` holds it bound at `now`; nothing for an
/// address of another client, another family or no lease.
///
/// # Errors
///
/// 503 `ipam.move.dhcp_release_failed` when the role could not write the release.
pub(super) async fn release_held(
    role: &dyn DhcpRolePort,
    view: &dyn ReadView,
    vrf: VrfId,
    ip: IpAddr,
    mac: Option<MacAddr>,
    now: Timestamp,
    reason: &str,
) -> Result<Released, StepError> {
    let (IpAddr::V4(addr), Some(mac)) = (ip, mac) else {
        return Ok(Released::Nothing);
    };
    let held = view
        .get_typed(&LEASES, &(vrf, addr))?
        .map(|(lease, _): (Lease, _)| lease)
        .filter(|lease| lease.is_bound(now) && lease.client.mac() == Some(mac.octets()));
    if held.is_none() {
        return Ok(Released::Nothing);
    }
    role.release(vrf, addr, reason).await.map_err(|error| {
        StepError::Coded(Box::new(
            CodedError::new(
                codes::RELEASE_FAILED,
                503,
                format!(
                    "the lease of {addr} could not be released: {}",
                    error.detail
                ),
            )
            .with_param("addr", addr.to_string())
            .with_param("cause", error.code.clone()),
        ))
    })
}

/// The handler of `ipam.move.dhcp`; without a plan in the parameters every step is the
/// manual task.
#[derive(Debug, Clone, Default)]
pub struct MoveDhcpStep {
    slot: DhcpMoves,
    wait: Option<Duration>,
}

impl MoveDhcpStep {
    /// The handler over the role's slot.
    pub fn new(slot: DhcpMoves) -> Self {
        Self { slot, wait: None }
    }

    /// The same with another wait for the image (tests).
    #[must_use]
    pub fn with_wait(mut self, wait: Duration) -> Self {
        self.wait = Some(wait);
        self
    }

    fn task(params: &MoveStepParams) -> ManualTask {
        params.task.clone().unwrap_or_else(|| ManualTask {
            instruction: MessageKey::from_static("ipam.move.task.dhcp"),
            args: params.args(),
            undo: None,
        })
    }

    /// Waits until the role's image is at `revision`; the image's revision, or the one it
    /// reached when the wait ran out.
    async fn wait_for(
        &self,
        role: &dyn DhcpRolePort,
        revision: Revision,
    ) -> Result<Revision, Revision> {
        let wait = self.wait.unwrap_or(Duration::from_secs(DHCP_WAIT_SECS));
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let image = role.image_revision();
            if image >= revision {
                return Ok(image);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(image);
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

fn not_served(params: &MoveStepParams, revision: Revision, image: Revision) -> StepError {
    StepError::Coded(Box::new(
        CodedError::new(
            codes::NOT_SERVED,
            503,
            format!(
                "the dhcp role did not serve the reservation of {} within {DHCP_WAIT_SECS} s: \
                 its configuration image is at revision {image}, the new address at {revision}",
                params.new_ip
            ),
        )
        .with_title("The DHCP role is behind")
        .with_param("new_ip", params.new_ip.to_string())
        .with_param("revision", revision.0.to_string())
        .with_param("image_revision", image.0.to_string()),
    ))
}

#[async_trait::async_trait]
impl StepHandler for MoveDhcpStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(super::steps::DHCP)
    }

    /// Running it again waits for the same revision, which the image has by then.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params = MoveStepParams::decode(params)?;
        if params.dhcp.is_some() {
            return Ok(StepPreview {
                summary: MessageKey::from_static("ipam.move.step.dhcp"),
                args: params.args(),
                changes: params.changes(),
                manual: None,
                warnings: Vec::new(),
            });
        }
        let task = Self::task(&params);
        Ok(StepPreview {
            summary: task.instruction.clone(),
            args: task.args.clone(),
            changes: params.changes(),
            manual: Some(task),
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = MoveStepParams::decode(params)?;
        if params.dhcp.is_none() {
            return Ok(StepOutcome::Manual(Self::task(&params)));
        }
        let view = cx.store.read(ReadConsistency::Local).await?;
        let Some((_, revision)) = view.get_typed(&ADDRESSES, &params.new_address)? else {
            return Err(StepError::Coded(Box::new(
                CodedError::new(
                    crate::codes::REFERENCE_MISSING,
                    409,
                    format!("the new address {} of the move is gone", params.new_ip),
                )
                .with_param("ip", params.new_ip.to_string()),
            )));
        };
        drop(view);
        let image = if let Some(role) = self.slot.get() {
            Some(
                self.wait_for(role.as_ref(), revision)
                    .await
                    .map_err(|image| not_served(&params, revision, image))?,
            )
        } else {
            tracing::info!(
                job = %cx.job,
                new_ip = %params.new_ip,
                "no dhcp role in this process; the reservation of the move is in intent"
            );
            None
        };
        let output = MoveDhcpOutput {
            address_revision: revision.0,
            image_revision: image.map(|image| image.0),
        };
        let bytes = serde_json::to_vec(&output)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepOutcome::Done {
            output: Some(bytes.into()),
        })
    }

    async fn compensate(
        &self,
        params: &[u8],
        _output: Option<&[u8]>,
        cx: &StepContext,
    ) -> Result<(), StepError> {
        let params = MoveStepParams::decode(params)?;
        // ADR 0027: the moving client goes first, before anything is undone.
        super::lease::clear(cx, Some(&self.slot)).await?;
        let (Some(_), Some(role)) = (&params.dhcp, self.slot.get()) else {
            return Ok(());
        };
        let view = cx.store.read(ReadConsistency::Local).await?;
        let mac = interface_mac(view.as_ref(), &params)?;
        release_held(
            role.as_ref(),
            view.as_ref(),
            params.vrf,
            params.new_ip,
            mac,
            Timestamp::now(),
            "the move rolled back",
        )
        .await
        .map(drop)
    }
}
