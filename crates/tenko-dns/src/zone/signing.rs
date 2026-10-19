//! The signer's entry points on the zone service (WP6.3, ADR 0018): the signing state of a
//! zone (`dns.sign_state`), the writes of a signing pass and the start of a key rollover.
//!
//! A signing pass writes the rows of the signer (origin `dnssec`) through here as one
//! change set: the row changes, the next serial with its signature, the journal entry of
//! the change (or a journal reset when the pass changes more than an import would journal,
//! so a secondary asking for an older serial gets AXFR) and the new signing state. A full
//! pass of a large zone writes its rows in chunks first and the serial, the apex and the
//! state last. Every batch carries the leader epoch when the signer runs as the leader.

use std::sync::Arc;

use tenko_core::{
    ObjectRef, RequestCtx, Revision, SystemComponent,
    audit::AuditDraft,
    dns::{
        DnssecMode, JournalEntry, KeyRole, RrSet, RrSetKey, Rtype, ScopeName, SignState, Zone,
        ZoneId, audit, codes,
        tables::{RRSETS, SIGN_STATE},
    },
    ipam::Stamp,
};
use tenko_jobs::JobSpec;
use tenko_store::{ReadView, ReadViewExt, WriteBatch};

use super::{
    JournalLimits, ZoneError, ZoneResult, ZoneService,
    import::JOURNAL_RECORDS,
    journal, journal_records,
    records::{self, Diff},
    soa_serial, stage_delete, stage_put,
};
use crate::dnssec::pass::RowChange;

/// The request context of the signer's own writes.
pub fn signer_ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

/// A new batch of the signer, fenced with the leader epoch when it has one.
pub fn signer_batch(epoch: Option<u64>) -> WriteBatch {
    let mut batch = WriteBatch::for_request(&signer_ctx());
    batch.idempotency = None;
    if let Some(epoch) = epoch {
        batch.preconditions.push(tenko_store::fence(epoch));
    }
    batch
}

/// Adds row changes to a batch, each expecting the revision it was read at.
///
/// # Errors
///
/// A codec error.
pub fn stage_changes(batch: &mut WriteBatch, changes: &[RowChange]) -> ZoneResult<()> {
    for change in changes {
        batch.expect_typed(
            &RRSETS,
            &change.key,
            change.old.as_ref().map(|(_, revision)| *revision),
        );
        match (&change.old, &change.new) {
            (old, Some(new)) => stage_put(batch, old.as_ref().map(|(row, _)| row), new)?,
            (Some((old, _)), None) => stage_delete(batch, old),
            (None, None) => {}
        }
    }
    Ok(())
}

/// The serial step of one scope in a signing pass: the SOA before and after.
#[derive(Debug, Clone)]
pub struct SoaStep {
    /// The scope.
    pub scope: ScopeName,
    /// The SOA as read, with its revision.
    pub old: (RrSet, Revision),
    /// The SOA with the next serial.
    pub new: RrSet,
}

/// Adds the serial step of a scope and its journal entry, or a journal reset when
/// `journal` is false (the pass wrote chunks or changes more than [`JOURNAL_RECORDS`]
/// records).
///
/// # Errors
///
/// A store or codec error.
pub fn stage_soa_step(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: &Zone,
    step: &SoaStep,
    changes: &[RowChange],
    journal_it: bool,
    limits: JournalLimits,
) -> ZoneResult<()> {
    let key = step.old.0.key();
    batch.expect_typed(&RRSETS, &key, Some(step.old.1));
    stage_put(batch, Some(&step.old.0), &step.new)?;
    let diffs: Vec<Diff> = changes
        .iter()
        .map(|change| Diff {
            key: change.key.clone(),
            before: change.old.as_ref().map(|(row, _)| row.clone()),
            after: change.new.clone(),
        })
        .collect();
    let (removed, added) = records::journal_diff(diffs.iter());
    if journal_it && removed.len() + added.len() <= JOURNAL_RECORDS {
        let mut journal_removed: Vec<_> = journal_records(&step.old.0).collect();
        journal_removed.extend(removed);
        let mut journal_added: Vec<_> = journal_records(&step.new).collect();
        journal_added.extend(added);
        journal::stage_append(
            batch,
            view,
            limits,
            &JournalEntry {
                zone: zone.id,
                scope: step.scope.clone(),
                from_serial: soa_serial(&step.old.0).unwrap_or_default(),
                to_serial: soa_serial(&step.new).unwrap_or_default(),
                revision: view.revision(),
                at: step.new.updated.at,
                removed: journal_removed,
                added: journal_added,
            },
        )?;
    } else {
        journal::stage_reset(batch, view, zone.id, &step.scope)?;
    }
    Ok(())
}

/// The key of the SOA of a zone scope.
pub fn soa_key(zone: &Zone, scope: &ScopeName) -> RrSetKey {
    RrSetKey {
        zone: zone.id,
        scope: scope.clone(),
        name: zone.name.clone(),
        rtype: Rtype::SOA,
    }
}

/// The SOA of a scope with the next serial of the zone's policy.
pub fn next_soa(zone: &Zone, scope: &ScopeName, old: &RrSet, stamp: &Stamp) -> RrSet {
    let current = soa_serial(old).unwrap_or_default();
    let next = super::serial::next(zone.serial, current, stamp.at);
    super::soa_rrset(zone, scope, &zone.soa, next, stamp.clone())
}

impl ZoneService {
    /// The signing state of a zone, with its revision.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn sign_state(
        view: &dyn ReadView,
        zone: ZoneId,
    ) -> ZoneResult<Option<(SignState, Revision)>> {
        Ok(view.get_typed(&SIGN_STATE, &zone)?)
    }

    /// The journal limits the signer appends with.
    pub fn journal_limits(&self) -> JournalLimits {
        self.config.journal
    }

    /// The vault, for the signer's keys.
    pub fn vault_handle(&self) -> Option<Arc<dyn tenko_vault::Vault>> {
        self.vault.clone()
    }

    /// Starts a key rollover of `role` for a zone signed online
    /// (`POST /dns/zones/{id}/dnssec/rollover`): submits the job of
    /// [`crate::dnssec::rollover`], records it in the signing state and audits the request
    /// as `dns.key.rollover`.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`; `dns.dnssec.not_online` (409) when the zone is not signed
    /// online or has no key of the role; `dns.dnssec.rollover_running` (409); `dns.zone.invalid`
    /// for a role the policy does not use; or a store or job error.
    pub async fn start_rollover(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        role: KeyRole,
        spec: impl Fn(&Zone, &SignState) -> JobSpec,
    ) -> ZoneResult<tenko_core::JobId> {
        {
            let view = self.view(None).await?;
            let zone = Self::zone(view.as_ref(), id)?.zone;
            let not_online = |reason: &str| {
                ZoneError::new(
                    codes::DNSSEC_NOT_ONLINE,
                    409,
                    format!("zone {}: {reason}", zone.name),
                )
                .param("zone", zone.name.as_str())
                .param(
                    "mode",
                    match zone.dnssec.mode {
                        DnssecMode::Off => "off",
                        DnssecMode::Online => "online",
                        DnssecMode::Imported => "imported",
                    },
                )
            };
            if zone.dnssec.mode != DnssecMode::Online {
                return Err(not_online("the zone is not signed online"));
            }
            let csk = zone.dnssec.csk;
            if csk != (role == KeyRole::Csk) {
                return Err(ZoneError::zone_invalid(
                    "role",
                    if csk {
                        "the zone signs with a combined key; roll the csk"
                    } else {
                        "the zone signs with a ksk and a zsk; roll one of them"
                    },
                ));
            }
            let Some((state, _)) = Self::sign_state(view.as_ref(), id)? else {
                return Err(not_online("the zone has no keys yet"));
            };
            if !state
                .keys
                .iter()
                .any(|key| key.role == role && key.state == tenko_core::dns::KeyState::Active)
            {
                return Err(not_online("the zone has no active key of this role yet"));
            }
            if let Some(job) = state.rollover_job {
                return Err(ZoneError::new(
                    codes::DNSSEC_ROLLOVER_RUNNING,
                    409,
                    format!("a key rollover of zone {} runs as job {job}", zone.name),
                )
                .param("zone", zone.name.as_str())
                .param("job", job.to_string()));
            }
            let job_spec = spec(&zone, &state);
            drop(view);
            let job = self.jobs.submit(job_spec, cx).await?;
            // The job's first step records it in the signing state; the request is audited
            // here, naming the job.
            let mut batch = WriteBatch::for_request(cx);
            batch.audit(
                AuditDraft::success(audit::KEY_ROLLOVER, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("zone", zone.name.as_str())
                    .with_context("role", crate::dnssec::keys::role_name(role))
                    .with_context("job", job.to_string()),
            );
            self.store.propose(batch).await?;
            Ok(job)
        }
    }
}
