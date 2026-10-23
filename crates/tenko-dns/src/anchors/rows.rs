//! The rows of the trust anchors and negative trust anchors through the zone service
//! (`dns.trust_anchors`, `dns.ntas`, `dns.ntas.by_zone`): the routes of `/dns/trust-anchors`
//! and `/dns/ntas` write them here as inline jobs with their audit records, and the
//! status reads them. The profile rules (the root's protection outside the Lab profile,
//! the expiry the Hardened profile requires) are the callers' facts, passed in.

use tenko_core::{
    ObjectKind, ObjectRef, RequestCtx, Revision, Timestamp,
    audit::AuditDraft,
    dns::{
        AnchorKey, DnsName, NegativeTrustAnchor, NtaId, TrustAnchor, audit, codes,
        tables::{NTAS, NTAS_BY_ZONE, TRUST_ANCHORS},
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use crate::zone::{Planned, Written, ZoneError, ZoneResult, ZoneService, check_expect};

/// A trust anchor row as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRow {
    /// The anchor.
    pub anchor: TrustAnchor,
    /// The revision of the row.
    pub revision: Revision,
}

/// A negative trust anchor row as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtaRow {
    /// The anchor.
    pub nta: NegativeTrustAnchor,
    /// The revision of the row.
    pub revision: Revision,
}

fn anchor_not_found(zone: &DnsName) -> ZoneError {
    ZoneError::new(
        codes::TRUST_ANCHOR_NOT_FOUND,
        404,
        format!("no trust anchor for {zone}"),
    )
    .param("zone", zone.to_string())
}

fn root_protected(what: &str) -> ZoneError {
    ZoneError::new(
        codes::TRUST_ANCHOR_ROOT_PROTECTED,
        409,
        format!("the root's trust anchor is not {what} outside the Lab profile"),
    )
    .param("zone", ".")
}

fn nta_not_found(id: NtaId) -> ZoneError {
    ZoneError::new(
        codes::NTA_NOT_FOUND,
        404,
        format!("negative trust anchor {id} does not exist"),
    )
    .param("id", id.to_string())
}

fn nothing_written() -> ZoneError {
    ZoneError::new(
        "sys.internal",
        500,
        "the write planned for the trust anchor left nothing written",
    )
}

fn target() -> Vec<ObjectRef> {
    vec![ObjectRef::singleton(ObjectKind::DnsKey)]
}

impl ZoneService {
    /// Every trust anchor row, by zone.
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn trust_anchors(view: &dyn ReadView) -> ZoneResult<Vec<AnchorRow>> {
        let mut rows: Vec<AnchorRow> = view
            .scan_typed(&TRUST_ANCHORS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, anchor, revision)| AnchorRow { anchor, revision })
            .collect();
        rows.sort_by(|a, b| a.anchor.zone.as_str().cmp(b.anchor.zone.as_str()));
        Ok(rows)
    }

    /// The trust anchor row of `zone`.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.not_found`, or a store error.
    pub fn trust_anchor(view: &dyn ReadView, zone: &DnsName) -> ZoneResult<AnchorRow> {
        let (anchor, revision) = view
            .get_typed(&TRUST_ANCHORS, zone)?
            .ok_or_else(|| anchor_not_found(zone))?;
        Ok(AnchorRow { anchor, revision })
    }

    /// Adds `key` to the trust anchor of `zone`, creating the row; with `replace_root`
    /// the root's keys are replaced by it, which only the Lab profile (`lab`) allows.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.root_protected` for the root outside Lab, or without
    /// `replace_root`; `dns.trust_anchor.invalid` for a key that does not fit; a store
    /// or job error.
    pub async fn add_trust_anchor(
        &self,
        cx: &RequestCtx,
        zone: DnsName,
        key: AnchorKey,
        replace_root: bool,
        lab: bool,
    ) -> ZoneResult<(TrustAnchor, Written)> {
        if zone.is_root() && !(replace_root && lab) {
            return Err(root_protected("added to"));
        }
        if replace_root && !zone.is_root() {
            return Err(ZoneError::new(
                codes::TRUST_ANCHOR_INVALID,
                400,
                "replace_root applies to the root only",
            )
            .param("field", "replace_root")
            .param("reason", "the zone is not the root"));
        }
        key.validate()?;
        let (anchor, written) = self
            .execute(cx, |view| {
                let existing = view.get_typed(&TRUST_ANCHORS, &zone)?;
                let revision = existing.as_ref().map(|(_, revision)| *revision);
                let mut anchor = match existing {
                    Some((anchor, _)) if !replace_root => anchor,
                    _ => TrustAnchor {
                        zone: zone.clone(),
                        keys: Vec::new(),
                        last_query: None,
                        next_query: None,
                    },
                };
                anchor.keys.push(key.clone());
                // A refresh follows the change.
                anchor.next_query = Some(cx.now);
                anchor.validate(lab)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&TRUST_ANCHORS, &zone, revision);
                batch.put_typed(&TRUST_ANCHORS, &zone, &anchor)?;
                batch.audit(
                    AuditDraft::success(audit::TRUST_ANCHOR_ADD, target())
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", zone.to_string())
                        .with_context("key_tag", key.key_tag.to_string())
                        .with_context("replace_root", replace_root.to_string()),
                );
                Ok(Planned::write(
                    anchor.clone(),
                    batch,
                    format!("add a trust anchor key for {zone}"),
                    target(),
                ))
            })
            .await?;
        Ok((anchor, written.ok_or_else(nothing_written)?))
    }

    /// Removes the trust anchor of `zone`; the root's only under the Lab profile.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.not_found`, `dns.trust_anchor.root_protected`, 412 when
    /// `expect` is stale, or a store or job error.
    pub async fn remove_trust_anchor(
        &self,
        cx: &RequestCtx,
        zone: &DnsName,
        expect: Option<Revision>,
        lab: bool,
    ) -> ZoneResult<Written> {
        if zone.is_root() && !lab {
            return Err(root_protected("removed"));
        }
        let ((), written) = self
            .execute(cx, |view| {
                let row = Self::trust_anchor(view, zone)?;
                check_expect(expect, row.revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&TRUST_ANCHORS, zone, Some(row.revision));
                batch.delete_typed(&TRUST_ANCHORS, zone);
                batch.audit(
                    AuditDraft::success(audit::TRUST_ANCHOR_REMOVE, target())
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", zone.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("remove the trust anchor of {zone}"),
                    target(),
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }

    /// Asks the trust anchor service to refresh `zone` now: the row's next query is now.
    ///
    /// # Errors
    ///
    /// `dns.trust_anchor.not_found`, or a store or job error.
    pub async fn refresh_trust_anchor(
        &self,
        cx: &RequestCtx,
        zone: &DnsName,
    ) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |view| {
                let row = Self::trust_anchor(view, zone)?;
                let mut anchor = row.anchor;
                anchor.next_query = Some(cx.now);
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&TRUST_ANCHORS, zone, Some(row.revision));
                batch.put_typed(&TRUST_ANCHORS, zone, &anchor)?;
                batch.audit(
                    AuditDraft::success(audit::TRUST_ANCHOR_REFRESH, target())
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", zone.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("refresh the trust anchor of {zone}"),
                    target(),
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }

    /// Every negative trust anchor row that has not expired at `now`, by zone.
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn ntas(view: &dyn ReadView, now: Timestamp) -> ZoneResult<Vec<NtaRow>> {
        let mut rows: Vec<NtaRow> = view
            .scan_typed(&NTAS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, nta, _)| now < nta.expires_at)
            .map(|(_, nta, revision)| NtaRow { nta, revision })
            .collect();
        rows.sort_by(|a, b| {
            a.nta
                .zone
                .as_str()
                .cmp(b.nta.zone.as_str())
                .then(a.nta.id.cmp(&b.nta.id))
        });
        Ok(rows)
    }

    /// Creates a negative trust anchor for `zone` until `expires_at` (seven days when
    /// absent, which `hardened` refuses).
    ///
    /// # Errors
    ///
    /// `dns.nta.invalid`, or a store or job error.
    pub async fn create_nta(
        &self,
        cx: &RequestCtx,
        zone: DnsName,
        expires_at: Option<Timestamp>,
        reason: String,
        hardened: bool,
    ) -> ZoneResult<(NegativeTrustAnchor, Written)> {
        let expires_at = NegativeTrustAnchor::expiry_for(cx.now, expires_at, hardened)?;
        let nta = NegativeTrustAnchor {
            id: NtaId::generate(),
            zone,
            expires_at,
            reason: reason.trim().to_owned(),
            created_by: cx.principal.clone(),
            created_at: cx.now,
        };
        nta.validate()?;
        let (nta, written) = self
            .execute(cx, |_view| {
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&NTAS, &nta.id, None);
                batch.put_typed(&NTAS, &nta.id, &nta)?;
                batch.put_typed(&NTAS_BY_ZONE, &(nta.zone.clone(), nta.id), &())?;
                batch.audit(
                    AuditDraft::success(audit::NTA_CREATE, target())
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", nta.zone.to_string())
                        .with_context("id", nta.id.to_string())
                        .with_context("expires_at", nta.expires_at.to_rfc3339())
                        .with_context("reason", nta.reason.clone()),
                );
                Ok(Planned::write(
                    nta.clone(),
                    batch,
                    format!("create a negative trust anchor for {}", nta.zone),
                    target(),
                ))
            })
            .await?;
        Ok((nta, written.ok_or_else(nothing_written)?))
    }

    /// Deletes the negative trust anchor `id` before its expiry.
    ///
    /// # Errors
    ///
    /// `dns.nta.not_found`, or a store or job error.
    pub async fn delete_nta(&self, cx: &RequestCtx, id: NtaId) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |view| {
                let (nta, revision) = view
                    .get_typed(&NTAS, &id)?
                    .ok_or_else(|| nta_not_found(id))?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&NTAS, &id, Some(revision));
                batch.delete_typed(&NTAS, &id);
                batch.delete_typed(&NTAS_BY_ZONE, &(nta.zone.clone(), id));
                batch.audit(
                    AuditDraft::success(audit::NTA_DELETE, target())
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", nta.zone.to_string())
                        .with_context("id", id.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the negative trust anchor of {}", nta.zone),
                    target(),
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }
}
