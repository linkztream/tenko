//! The link from IPAM to DNS (WP4.4, plan sections 2.5 and 2.6, DNS-22, IPAM-13, IPAM-19):
//! the records of the intent, the reverse zones of the prefixes and the actuator that
//! writes them through the zone service of `tenko-dns`.
//!
//! | Module | What |
//! |---|---|
//! | [`reverse`] | PTR names, the reverse zones of a prefix, the RFC 2317 form |
//! | [`plan`] | the planner: zones to create or adopt, reverse zones that follow their template, RRset changes per zone, findings |
//! | this module | [`DnsActuator`]: the dry run and the writes, as the reconciler's driver and for the move step |
//!
//! The actuator writes only RRsets of the origin `ipam` (the zone service refuses the rest
//! with `dns.record.origin`), one batch per zone and run, so every zone moves its serial
//! once per run by its own policy and the audit records the actuator's principal. The
//! reconciler runs it after its proposals (`dns_actuator` in its settings); the move step
//! `ipam.move.dns` runs it for the names of one device.

pub mod moves;
pub mod plan;
pub mod reverse;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenko_core::{
    RequestCtx, Revision,
    dns::{Origin, RecordData, Rtype, ScopeName, ZoneKind},
};
use tenko_dns::zone::{
    NewZone, ZoneChange, ZoneService,
    records::{Change, Op},
};
use tenko_store::WriteBatch;
use utoipa::ToSchema;

pub use self::plan::{
    DnsFinding, DnsPlan, MoveOverride, PlanOptions, REVERSE_TEMPLATES, RecordChange,
    ReverseTemplate, ZoneAdopt, ZoneBatch, ZoneCreate, ZoneFollow,
};
use crate::error::{IpamError, IpamResult};

/// What happens to an `ipam` RRset whose address lost its name or its intent.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OrphanRule {
    /// The actuator deletes it.
    #[default]
    Remove,
    /// It stays, and the reconciler proposes it as an orphan for a person to decide.
    Propose,
}

/// A batch or a zone write that failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsFailure {
    /// The zone apex.
    pub zone: String,
    /// The error code.
    pub code: String,
    /// The error in English.
    pub detail: String,
}

/// What one run of the actuator did; part of the reconciler's run report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsActuation {
    /// Reverse zones created.
    pub zones_created: u32,
    /// Existing zones adopted as reverse zones of a prefix.
    pub zones_adopted: u32,
    /// Reverse zones that took new SOA values or name servers from their template.
    #[serde(default)]
    pub zones_followed: u32,
    /// RRsets written or deleted.
    pub rrsets_changed: u32,
    /// Batches committed (one per zone and chunk).
    pub batches: u32,
    /// Writes that failed; the next run tries again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<DnsFailure>,
    /// The revision of the last write; `null` when nothing was written.
    #[schema(value_type = Option<u64>)]
    pub revision: Option<Revision>,
}

/// Registers the automatic move step `ipam.move.dns` over the actuator; it replaces the
/// manual step of [`crate::moves::move_step_handlers`].
pub fn register_steps(engine: &mut tenko_jobs::JobEngine, actuator: &Arc<DnsActuator>) {
    engine.register(Arc::new(crate::moves::dns::MoveDnsStep::new(Arc::clone(
        actuator,
    ))));
}

fn ipam_error(error: tenko_dns::zone::ZoneError) -> IpamError {
    IpamError::from_coded_error(error.into_coded())
}

/// The zone changes of planned RRset changes: `set` or `delete`, in the default scope,
/// with the origin `ipam` and the zone's default TTL for a new RRset.
pub fn zone_changes(changes: &[RecordChange]) -> Vec<Change> {
    changes
        .iter()
        .map(|change| Change {
            op: if change.is_delete() {
                Op::Delete
            } else {
                Op::Set
            },
            scope: ScopeName::DEFAULT,
            name: change.name.clone(),
            rtype: change.rtype,
            ttl: None,
            records: change.after.clone(),
            take_over: false,
            origin: Origin::Ipam,
        })
        .collect()
}

/// The actuator: plans from a read view and writes through the zone service.
pub struct DnsActuator {
    zones: Arc<ZoneService>,
}

impl std::fmt::Debug for DnsActuator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsActuator").finish_non_exhaustive()
    }
}

impl DnsActuator {
    /// An actuator over the zone service.
    pub fn new(zones: Arc<ZoneService>) -> Self {
        Self { zones }
    }

    /// The zone service.
    pub fn zones(&self) -> &Arc<ZoneService> {
        &self.zones
    }

    /// The plan of the current state, without writing (the dry run).
    ///
    /// # Errors
    ///
    /// Store errors.
    pub async fn dry_run(&self, options: &PlanOptions) -> IpamResult<DnsPlan> {
        let view = self.zones.view(None).await.map_err(ipam_error)?;
        plan::plan(view.as_ref(), options)
    }

    /// Plans and writes: the reverse zones to create and adopt first, then, planned again
    /// over them, the reverse zones that follow their template and the RRset changes of
    /// every zone. A failed zone is reported and the others go on.
    ///
    /// # Errors
    ///
    /// Store errors while planning; write errors are in the report.
    pub async fn run(&self, cx: &RequestCtx, options: &PlanOptions) -> IpamResult<DnsActuation> {
        let mut report = DnsActuation::default();
        let first = self.dry_run(options).await?;
        let mut at_least = None;
        if !first.create.is_empty() || !first.adopt.is_empty() {
            at_least = self.zones_of(cx, &first, &mut report).await;
        }
        let planned = if at_least.is_some() {
            let view = self.zones.view(at_least).await.map_err(ipam_error)?;
            plan::plan(view.as_ref(), options)?
        } else {
            first
        };
        self.follow(cx, &planned, &mut report).await;
        self.write(cx, &planned.batches, &mut report).await;
        Ok(report)
    }

    /// Brings the reverse zones that follow their template up to date and records what
    /// they copied. The SOA change expects the zone row the plan read, so a zone an
    /// operator changes meanwhile fails and stays as it is; each zone write is audited by
    /// the zone service.
    async fn follow(&self, cx: &RequestCtx, planned: &DnsPlan, report: &mut DnsActuation) {
        let mut stamps = WriteBatch::for_request(cx);
        let mut any = false;
        for follow in &planned.follow {
            if follow.soa.is_some() || follow.description.is_some() {
                let change = ZoneChange {
                    soa: follow.soa.clone(),
                    description: follow.description.clone(),
                    ..ZoneChange::default()
                };
                if let Err(error) = self
                    .zones
                    .update(cx, follow.zone, change, Some(follow.revision))
                    .await
                {
                    failure(report, &follow.name, &error);
                    continue;
                }
            }
            if let Some(name_servers) = &follow.name_servers {
                let change = Change {
                    op: Op::Set,
                    scope: ScopeName::DEFAULT,
                    name: follow.name.clone(),
                    rtype: Rtype::NS,
                    ttl: None,
                    records: name_servers
                        .iter()
                        .map(|host| RecordData::Ns { host: host.clone() })
                        .collect(),
                    take_over: false,
                    origin: follow.ns_origin,
                };
                if let Err(error) = self
                    .zones
                    .change_records(cx, follow.zone, &[change], false)
                    .await
                {
                    failure(report, &follow.name, &error);
                    continue;
                }
            }
            report.zones_followed += 1;
            any |= stamp(&mut stamps, follow.zone, &follow.stamp);
        }
        for (zone, template) in &planned.stamps {
            any |= stamp(&mut stamps, *zone, template);
        }
        if any && let Err(error) = self.zones.store().propose(stamps).await {
            tracing::warn!(%error, "the DNS actuator could not record the reverse-zone templates");
        }
    }

    /// Writes the batches of a plan; failures go to the report.
    pub async fn write(&self, cx: &RequestCtx, batches: &[ZoneBatch], report: &mut DnsActuation) {
        for batch in batches {
            for chunk in plan::chunks(&batch.changes) {
                match self
                    .zones
                    .change_records(cx, batch.zone, &zone_changes(chunk), false)
                    .await
                {
                    Ok(outcome) => {
                        report.rrsets_changed +=
                            u32::try_from(outcome.diff.len()).unwrap_or(u32::MAX);
                        if let Some(written) = outcome.written {
                            report.batches += 1;
                            report.revision = Some(written.revision);
                        }
                    }
                    Err(error) => {
                        let coded = error.coded();
                        tracing::warn!(zone = %batch.name, code = %coded.code, "the DNS actuator's batch failed");
                        report.failures.push(DnsFailure {
                            zone: batch.name.to_string(),
                            code: coded.code.to_string(),
                            detail: coded.detail.clone(),
                        });
                    }
                }
            }
        }
    }

    /// Creates and adopts the reverse zones of a plan; returns the revision of the last
    /// write.
    async fn zones_of(
        &self,
        cx: &RequestCtx,
        planned: &DnsPlan,
        report: &mut DnsActuation,
    ) -> Option<Revision> {
        let mut last = None;
        for create in &planned.create {
            let new = NewZone {
                name: create.name.clone(),
                kind: ZoneKind::Primary,
                tenant: create.tenant,
                scopes: Vec::new(),
                serial: create.serial,
                soa: create.soa.clone(),
                name_servers: create.name_servers.clone(),
                transfer: tenko_core::dns::TransferPolicy::default(),
                update: tenko_core::dns::UpdatePolicy::default(),
                dnssec: tenko_core::dns::DnssecPolicy::default(),
                source: None,
                description: Some(plan::reverse_description(&create.source)),
                reverse_of: Some(create.prefix),
                catalog: false,
            };
            match self.zones.create(cx, new).await {
                Ok(written) => {
                    report.zones_created += 1;
                    last = Some(written.revision);
                }
                Err(error) => failure(report, &create.name, &error),
            }
        }
        for adopt in &planned.adopt {
            let change = ZoneChange {
                reverse_of: Some(Some(adopt.prefix)),
                ..ZoneChange::default()
            };
            match self.zones.update(cx, adopt.zone, change, None).await {
                Ok(written) => {
                    report.zones_adopted += 1;
                    last = Some(written.revision);
                }
                Err(error) => failure(report, &adopt.name, &error),
            }
        }
        last
    }
}

fn stamp(
    batch: &mut WriteBatch,
    zone: tenko_core::dns::ZoneId,
    template: &ReverseTemplate,
) -> bool {
    match batch.put_typed(&REVERSE_TEMPLATES, &zone, template) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(%error, "a reverse-zone template does not encode");
            false
        }
    }
}

fn failure(
    report: &mut DnsActuation,
    zone: &tenko_core::dns::DnsName,
    error: &tenko_dns::zone::ZoneError,
) {
    let coded = error.coded();
    tracing::warn!(%zone, code = %coded.code, "the DNS actuator's zone write failed");
    report.failures.push(DnsFailure {
        zone: zone.to_string(),
        code: coded.code.to_string(),
        detail: coded.detail.clone(),
    });
}
