//! The flip of a zone in place and the release of its frozen names (Windows takeover plan
//! section 2.6, ADR 0034; MIG-04).
//!
//! A flip to primary turns a secondary zone into a primary zone in one change set: the
//! row takes the kind `primary`, the operator's SOA values and no source, the apex NS set
//! becomes the operator's, the SOA continues from the copy's serial with one journal entry,
//! and every other RRset stays with an origin that says where it came from:
//!
//! | The copy's RRset | Origin after the flip |
//! |---|---|
//! | A, AAAA and DHCID at a name that holds a DHCID RRset; a PTR with a target that is such a name in a zone of the same tenant Tenko holds | `transfer` (frozen until a takeover adopts it or [`ZoneService::release`] releases it) |
//! | Every other RRset of origin `transfer` | `ad` |
//! | An RRset of another origin (a zone flipped back before its next transfer) | unchanged |
//!
//! The transfer service stops refreshing the zone with the same commit: it follows the
//! zone rows, and a refresh that read the zone before the flip finds the row changed and
//! writes nothing ([`super::secondary`]).
//!
//! A flip to secondary turns a primary zone back into a secondary of the named primaries:
//! the records stay until the next transfer replaces every one of them with the copy's
//! (a copy whose SOA a transfer did not write is fetched whole, whatever its serial), and
//! the owners of its names go, since a secondary takes no updates.
//!
//! Both directions refuse a catalog zone (`dns.zone.flip.catalog`), a zone of the other
//! kind (`dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`) and a zone with
//! scopes besides `default` (transfers fill that scope only); both are audited as
//! `dns.zone.flip` with the RRsets by origin afterwards.

use std::collections::{BTreeMap, BTreeSet};

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        DnsName, FlipOriginCount, Origin, RecordData, RrSet, Rtype, ScopeName, SecondarySource,
        Zone, ZoneFlip, ZoneFlipReport, ZoneId, ZoneKind, ZoneRelease, ZoneReleaseReport, audit,
        codes,
        tables::{RRSETS, TRANSFER_STATE, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{ReadView, ReadViewExt, WriteBatch};

use super::{
    Planned, ZoneError, ZoneResult, ZoneService, internal_nothing_written, kind_name, node,
    ns_rrset, origin_index, ownership,
    records::{self, Diff, origin_name},
    rrset_range, stage_delete, stage_put,
};

/// The most RRsets a flip or a release changes: they are written as one change set.
pub const FLIP_MAX: usize = super::secondary::CHUNK;

/// The DHCID record type (RFC 4701).
const DHCID: Rtype = Rtype(49);

/// A stored RRset with its revision.
type Stored = (RrSet, Revision);

fn refusal(code: &'static str, zone: &Zone, reason: &str) -> ZoneError {
    ZoneError::new(code, 409, format!("{}: {reason}", zone.name))
        .param("zone", zone.name.as_str())
        .param("kind", kind_name(zone.kind))
}

/// Refuses a catalog zone and a zone whose kind is not `from`.
fn check_kind(zone: &Zone, from: ZoneKind) -> ZoneResult<()> {
    if zone.catalog {
        return Err(refusal(
            codes::ZONE_FLIP_CATALOG,
            zone,
            "a catalog zone keeps its own rule",
        ));
    }
    match (from, zone.kind) {
        (ZoneKind::Secondary, ZoneKind::Secondary) | (ZoneKind::Primary, ZoneKind::Primary) => {
            Ok(())
        }
        (ZoneKind::Secondary, _) => Err(refusal(
            codes::ZONE_FLIP_NOT_SECONDARY,
            zone,
            "only a secondary zone flips to primary",
        )),
        _ => Err(refusal(
            codes::ZONE_FLIP_NOT_PRIMARY,
            zone,
            "only a primary zone flips to secondary or releases frozen names",
        )),
    }
}

/// Every RRset of a zone, refused above [`FLIP_MAX`].
fn zone_rrsets(view: &dyn ReadView, zone: &Zone) -> ZoneResult<Vec<Stored>> {
    let rows = view.scan_typed(
        &RRSETS,
        rrset_range(zone.id, None, None),
        FLIP_MAX + 1,
        false,
    )?;
    if rows.len() > FLIP_MAX {
        return Err(ZoneError::zone_invalid(
            "rrsets",
            &format!("a flip or a release writes one change set of at most {FLIP_MAX} RRsets"),
        ));
    }
    Ok(rows
        .into_iter()
        .map(|(_, rrset, revision)| (rrset, revision))
        .collect())
}

/// Whether `target` is a name that holds a DHCID RRset: in `zone` itself (`own`), or in
/// the zone of the same tenant with the longest apex above it.
fn dhcp_name(
    view: &dyn ReadView,
    zones: &[super::ZoneRow],
    zone: &Zone,
    own: &BTreeSet<&DnsName>,
    target: &DnsName,
) -> ZoneResult<bool> {
    let holder = zones
        .iter()
        .map(|row| &row.zone)
        .filter(|other| other.tenant == zone.tenant && target.is_subdomain_of(&other.name))
        .max_by_key(|other| other.name.label_count());
    match holder {
        None => Ok(false),
        Some(other) if other.id == zone.id => Ok(own.contains(target)),
        Some(other) => Ok(node(view, other.id, &ScopeName::DEFAULT, target)?
            .iter()
            .any(|(rrset, _)| rrset.rtype == DHCID)),
    }
}

/// The origin a `transfer` RRset of the copy takes at a flip to primary (the table of the
/// module).
fn flipped_origin(
    view: &dyn ReadView,
    zones: &[super::ZoneRow],
    zone: &Zone,
    own: &BTreeSet<&DnsName>,
    rrset: &RrSet,
) -> ZoneResult<Origin> {
    let frozen = match rrset.rtype {
        Rtype::A | Rtype::AAAA | DHCID => own.contains(&rrset.name),
        Rtype::PTR => {
            let mut any = false;
            for data in rrset.records()? {
                if let RecordData::Ptr { target } = data
                    && dhcp_name(view, zones, zone, own, &target)?
                {
                    any = true;
                    break;
                }
            }
            any
        }
        _ => false,
    };
    Ok(if frozen { Origin::Transfer } else { Origin::Ad })
}

/// The RRsets by origin, in the order of the origins, for the report and the audit record.
#[derive(Default)]
struct Counts(BTreeMap<u8, FlipOriginCount>);

impl Counts {
    fn add(&mut self, origin: Origin) {
        self.0
            .entry(origin_index(origin))
            .or_insert(FlipOriginCount { origin, rrsets: 0 })
            .rrsets += 1;
    }
}

impl ZoneService {
    /// Flips a zone between secondary and primary in place (the module's rules).
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid` (the request, a zone with other scopes, a
    /// zone whose settings a secondary cannot keep, more than [`FLIP_MAX`] RRsets),
    /// `dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`, `dns.zone.flip.catalog`,
    /// or a store or job error.
    #[allow(clippy::too_many_lines, reason = "one plan of a flip, both directions")]
    pub async fn flip(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        flip: &ZoneFlip,
    ) -> ZoneResult<ZoneFlipReport> {
        flip.validate()?;
        let limits = self.config.journal;
        let ((kind, serial, origins), written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, id)?;
                let before = row.zone;
                let stamp = Stamp::new(cx.now, cx.principal.clone());
                let mut zone = before.clone();
                zone.kind = flip.target();
                zone.updated = stamp.clone();
                if zone.scopes.len() > 1 {
                    return Err(ZoneError::zone_invalid(
                        "scopes",
                        "a zone that flips has only the scope `default`",
                    ));
                }
                let rrsets = zone_rrsets(view, &before)?;
                let mut batch = WriteBatch::for_request(cx);
                let mut counts = Counts::default();
                let serial;
                match flip {
                    ZoneFlip::Primary { soa, ns } => {
                        check_kind(&before, ZoneKind::Secondary)?;
                        if !rrsets.iter().any(|(rrset, _)| rrset.rtype == Rtype::SOA) {
                            return Err(ZoneError::zone_invalid(
                                "kind",
                                "the zone holds no copy yet; a flip keeps the records of a transfer",
                            ));
                        }
                        zone.source = None;
                        zone.soa = soa.clone();
                        zone.validate()?;
                        let own: BTreeSet<&DnsName> = rrsets
                            .iter()
                            .filter(|(rrset, _)| rrset.rtype == DHCID)
                            .map(|(rrset, _)| &rrset.name)
                            .collect();
                        let zones = Self::zones(view)?;
                        let scope = ScopeName::DEFAULT;
                        let new_ns = ns_rrset(&zone, &scope, ns, zone.soa.ttl, stamp.clone())?;
                        new_ns.check(&zone.name)?;
                        let mut old_ns = None;
                        for (rrset, revision) in &rrsets {
                            if rrset.name == zone.name && rrset.rtype == Rtype::SOA {
                                continue;
                            }
                            if rrset.name == zone.name && rrset.rtype == Rtype::NS {
                                old_ns = Some((rrset, *revision));
                                continue;
                            }
                            if rrset.origin != Origin::Transfer {
                                counts.add(rrset.origin);
                                continue;
                            }
                            let origin = flipped_origin(view, &zones, &before, &own, rrset)?;
                            counts.add(origin);
                            if origin == rrset.origin {
                                continue;
                            }
                            let mut next = rrset.clone();
                            next.origin = origin;
                            next.updated = stamp.clone();
                            batch.expect_typed(&RRSETS, &rrset.key(), Some(*revision));
                            stage_put(&mut batch, Some(rrset), &next)?;
                        }
                        batch.expect_typed(&RRSETS, &new_ns.key(), old_ns.map(|(_, rev)| rev));
                        stage_put(&mut batch, old_ns.map(|(rrset, _)| rrset), &new_ns)?;
                        let diff = Diff {
                            key: new_ns.key(),
                            before: old_ns.map(|(rrset, _)| rrset.clone()),
                            after: Some(new_ns.clone()),
                        };
                        let (removed, added) = records::journal_diff(std::iter::once(&diff));
                        let step = records::stage_serial_step(
                            &mut batch, view, &zone, &scope, &stamp, limits, removed, added,
                        )?;
                        serial = step.to;
                        // The apex SOA and NS are the operator's.
                        counts.add(Origin::Manual);
                        counts.add(Origin::Manual);
                        batch.delete_typed(&TRANSFER_STATE, &id);
                    }
                    ZoneFlip::Secondary { primaries } => {
                        check_kind(&before, ZoneKind::Primary)?;
                        zone.source = Some(SecondarySource {
                            primaries: primaries.clone(),
                        });
                        zone.validate()?;
                        if ownership::stage_zone_owners_delete(&mut batch, view, id, FLIP_MAX)? {
                            return Err(ZoneError::zone_invalid(
                                "owners",
                                &format!("a flip removes at most {FLIP_MAX} owners of names"),
                            ));
                        }
                        serial = Self::scope_serial(view, &before, &ScopeName::DEFAULT)?
                            .unwrap_or_default();
                        for (rrset, _) in &rrsets {
                            counts.add(rrset.origin);
                        }
                    }
                }
                batch.expect_typed(&ZONES, &id, Some(row.revision));
                batch.put_typed(&ZONES, &id, &zone)?;
                let origins: Vec<FlipOriginCount> = counts.0.into_values().collect();
                let mut draft = AuditDraft::success(audit::ZONE_FLIP, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", zone.name.as_str())
                    .with_context("from", kind_name(before.kind))
                    .with_context("to", kind_name(zone.kind))
                    .with_context("serial", serial.to_string());
                for item in &origins {
                    draft = draft.with_context(
                        format!("rrsets.{}", origin_name(item.origin)),
                        item.rrsets.to_string(),
                    );
                }
                batch.audit(draft);
                Ok(Planned::write(
                    (zone.kind, serial, origins),
                    batch,
                    format!("flip zone {} to {}", zone.name, kind_name(zone.kind)),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        let written = written.ok_or_else(internal_nothing_written)?;
        Ok(ZoneFlipReport {
            zone: id,
            kind,
            serial,
            origins,
            revision: written.revision,
        })
    }

    /// Releases the remaining frozen (`transfer`) RRsets of a primary zone to `manual`, or
    /// deletes them with a serial step and a journal entry; a dry run lists them. Audited
    /// as `dns.zone.release`.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid` for more than [`FLIP_MAX`] RRsets,
    /// `dns.zone.flip.not_primary`, `dns.zone.flip.catalog`, or a store or job error.
    pub async fn release(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        release: ZoneRelease,
    ) -> ZoneResult<ZoneReleaseReport> {
        let limits = self.config.journal;
        let plan = |view: &dyn ReadView| -> ZoneResult<Planned<(Vec<DnsName>, u32)>> {
            let row = Self::zone(view, id)?;
            let zone = row.zone;
            check_kind(&zone, ZoneKind::Primary)?;
            let frozen: Vec<Stored> = zone_rrsets(view, &zone)?
                .into_iter()
                .filter(|(rrset, _)| rrset.origin == Origin::Transfer)
                .collect();
            let names: BTreeSet<&DnsName> = frozen.iter().map(|(rrset, _)| &rrset.name).collect();
            let result = (
                names.into_iter().cloned().collect(),
                u32::try_from(frozen.len()).unwrap_or(u32::MAX),
            );
            if release.dry_run || frozen.is_empty() {
                return Ok(Planned::nothing(result));
            }
            let stamp = Stamp::new(cx.now, cx.principal.clone());
            let mut batch = WriteBatch::for_request(cx);
            let mut diffs = Vec::new();
            for (rrset, revision) in &frozen {
                batch.expect_typed(&RRSETS, &rrset.key(), Some(*revision));
                if release.delete {
                    stage_delete(&mut batch, rrset);
                    diffs.push(Diff {
                        key: rrset.key(),
                        before: Some(rrset.clone()),
                        after: None,
                    });
                } else {
                    let mut next = rrset.clone();
                    next.origin = Origin::Manual;
                    next.updated = stamp.clone();
                    stage_put(&mut batch, Some(rrset), &next)?;
                }
            }
            let scopes: BTreeSet<&ScopeName> = diffs.iter().map(|diff| &diff.key.scope).collect();
            for scope in scopes {
                let (removed, added) =
                    records::journal_diff(diffs.iter().filter(|diff| &diff.key.scope == scope));
                records::stage_serial_step(
                    &mut batch, view, &zone, scope, &stamp, limits, removed, added,
                )?;
            }
            batch.expect_typed(&ZONES, &id, Some(row.revision));
            batch.audit(
                AuditDraft::success(audit::ZONE_RELEASE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", zone.name.as_str())
                    .with_context("action", if release.delete { "delete" } else { "manual" })
                    .with_context("names", result.0.len().to_string())
                    .with_context("rrsets", result.1.to_string()),
            );
            Ok(Planned::write(
                result,
                batch,
                format!("release the frozen names of zone {}", zone.name),
                vec![ObjectRef::from(id)],
            ))
        };
        let ((names, rrsets), written) = if release.dry_run {
            let view = self.view(None).await?;
            (plan(view.as_ref())?.result, None)
        } else {
            self.execute(cx, plan).await?
        };
        Ok(ZoneReleaseReport {
            zone: id,
            deleted: release.delete,
            dry_run: release.dry_run,
            names,
            rrsets,
            revision: written.map(|written| written.revision),
        })
    }
}
