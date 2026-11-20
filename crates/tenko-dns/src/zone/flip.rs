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
//! | A, AAAA and DHCID at a name below the apex that holds a DHCID RRset and nothing but A, AAAA and DHCID (a DHCP name); a PTR with a target that is a DHCP name of a zone of the same tenant Tenko holds | `transfer` (frozen until a takeover adopts it or [`ZoneService::release`] releases it) |
//! | A and AAAA at a name of the new NS set | `manual` |
//! | Every other RRset of origin `transfer` | `ad` |
//! | An RRset of another origin (a zone flipped back before its next transfer) | unchanged |
//!
//! The transfer service stops refreshing the zone with the same commit: every batch of a
//! refresh expects the zone row as the refresh read it before it fetched, so a refresh
//! that started before the flip writes nothing ([`super::secondary`]). A signed copy, and a
//! copy whose last transfer was written in part, are refused.
//!
//! A flip to secondary turns a primary zone back into a secondary of the named primaries:
//! the records stay until the next transfer replaces every one of them with the copy's
//! (a copy whose SOA a transfer did not write is fetched whole, whatever its serial), and
//! the owners of its names go, since a secondary takes no updates.
//!
//! Both directions refuse a catalog zone (`dns.zone.flip.catalog`), a zone of the other
//! kind (`dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`), a zone with scopes
//! besides `default` (transfers fill that scope only) and a zone past the bounds of one
//! change set ([`FLIP_MAX`], [`FLIP_MAX_RECORDS`], [`FLIP_MAX_BYTES`]); both are audited
//! as `dns.zone.flip`. The plan runs on a blocking thread, and a node runs one flip or
//! release at a time ([`FLIP_BUSY`]).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::Ordering,
};

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        DnsName, DnssecMode, FlipOriginCount, Origin, RecordData, RrSet, Rtype, ScopeName,
        SecondarySource, Zone, ZoneFlip, ZoneFlipReport, ZoneId, ZoneKind, ZoneRelease,
        ZoneReleaseReport, audit, codes,
        tables::{RRSETS, TRANSFER_STATE, ZONES},
    },
    ipam::Stamp,
};
use tenko_store::{ReadView, ReadViewExt, WriteBatch};

use super::{
    JournalLimits, Planned, ZoneError, ZoneResult, ZoneService, internal_nothing_written,
    kind_name, node, ns_rrset, origin_index, ownership,
    records::{self, Diff, origin_name},
    rrset_range,
    secondary::MEMBER_OF,
    stage_delete, stage_put,
};

/// The most RRsets a flip changes, or a release acts on: one change set, as a transfer
/// writes one ([`super::secondary::CHUNK`]).
pub const FLIP_MAX: usize = super::secondary::CHUNK;

/// The most records a flip or a release reads: each PTR record may cost one read of its
/// target, so this bounds the reads of one plan.
pub const FLIP_MAX_RECORDS: usize = 50_000;

/// The most stored bytes of the RRsets a flip or a release reads: half the 16 MiB a store
/// batch takes, so that the change set written from them fits with its journal entry.
pub const FLIP_MAX_BYTES: usize = 8 << 20;

/// The code of a flip or a release while another one runs on the node (429).
pub const FLIP_BUSY: &str = "dns.zone.flip.busy";

/// RRsets read per store read. One: a stored RRset is bounded only by the store batch that
/// wrote it (16 MiB, up to 4,096 records of up to 65,535 octets each), so a read of more
/// could hold many times [`FLIP_MAX_BYTES`] before its bytes are counted; read one at a
/// time, a plan holds at most the bound plus one RRset.
const PAGE: usize = 1;

/// The DHCID record type (RFC 4701).
const DHCID: Rtype = Rtype(49);

/// A stored RRset with its revision.
type Stored = (RrSet, Revision);

/// What a planned flip reports.
type Flipped = (ZoneKind, u32, Vec<FlipOriginCount>);

/// Refuses a catalog zone and a zone whose kind is not `from`.
fn check_kind(zone: &Zone, from: ZoneKind) -> ZoneResult<()> {
    let (code, reason) = if zone.catalog {
        (
            codes::ZONE_FLIP_CATALOG,
            "a catalog zone keeps its own rule",
        )
    } else if zone.kind == from {
        return Ok(());
    } else if from == ZoneKind::Secondary {
        (
            codes::ZONE_FLIP_NOT_SECONDARY,
            "only a secondary zone flips to primary",
        )
    } else {
        (
            codes::ZONE_FLIP_NOT_PRIMARY,
            "only a primary zone flips to secondary or releases frozen names",
        )
    };
    Err(
        ZoneError::new(code, 409, format!("{}: {reason}", zone.name))
            .param("zone", zone.name.as_str())
            .param("kind", kind_name(zone.kind)),
    )
}

/// The RRsets of a zone that `keep` takes, page by page, refused past the bounds.
fn scan(
    view: &dyn ReadView,
    zone: ZoneId,
    keep: impl Fn(&RrSet) -> bool,
) -> ZoneResult<Vec<Stored>> {
    let (mut out, mut records, mut bytes) = (Vec::new(), 0usize, 0usize);
    let mut cursor = None;
    loop {
        let mut range = rrset_range(zone, None, None);
        if let Some(cursor) = cursor.take() {
            range = range.after(cursor);
        }
        let rows = view.scan(RRSETS.name(), range, PAGE, false)?;
        let last = rows.len() < PAGE;
        for (key, versioned) in rows {
            cursor = Some(key);
            let rrset: RrSet = RRSETS.decode(&versioned.value)?;
            if !keep(&rrset) {
                continue;
            }
            records += rrset.rdata.len();
            bytes += versioned.value.len();
            out.push((rrset, versioned.revision));
            if out.len() > FLIP_MAX || records > FLIP_MAX_RECORDS || bytes > FLIP_MAX_BYTES {
                return Err(ZoneError::zone_invalid(
                    "rrsets",
                    &format!(
                        "one change set takes at most {FLIP_MAX} RRsets, {FLIP_MAX_RECORDS} records and {FLIP_MAX_BYTES} bytes"
                    ),
                ));
            }
        }
        if last {
            return Ok(out);
        }
    }
}

/// The DHCP names among `rrsets` of the zone `apex`: below the apex, with a DHCID RRset and
/// nothing but A, AAAA and DHCID.
fn dhcp_names<'a>(
    apex: &DnsName,
    rrsets: impl IntoIterator<Item = &'a RrSet>,
) -> BTreeSet<&'a DnsName> {
    let mut names: BTreeMap<&DnsName, bool> = BTreeMap::new();
    let mut other = BTreeSet::new();
    for rrset in rrsets.into_iter().filter(|rrset| &rrset.name != apex) {
        match rrset.rtype {
            DHCID => {
                names.insert(&rrset.name, true);
            }
            Rtype::A | Rtype::AAAA => {
                names.entry(&rrset.name).or_insert(false);
            }
            _ => {
                other.insert(&rrset.name);
            }
        }
    }
    names
        .into_iter()
        .filter(|(name, dhcid)| *dhcid && !other.contains(name))
        .map(|(name, _)| name)
        .collect()
}

/// Whether PTR targets are DHCP names, each target looked up once: in the zone itself, or
/// in the zone of the same tenant with the longest apex above it.
struct Targets<'a> {
    view: &'a dyn ReadView,
    zone: ZoneId,
    own: &'a BTreeSet<&'a DnsName>,
    apexes: BTreeMap<DnsName, ZoneId>,
    seen: BTreeMap<DnsName, bool>,
}

impl Targets<'_> {
    fn dhcp(&mut self, target: &DnsName) -> ZoneResult<bool> {
        if let Some(known) = self.seen.get(target) {
            return Ok(*known);
        }
        let mut suffix = Some(target.clone());
        let mut holder = None;
        while let Some(name) = suffix {
            if let Some(id) = self.apexes.get(&name) {
                holder = Some((*id, name));
                break;
            }
            suffix = name.parent();
        }
        let found = match holder {
            None => false,
            Some((id, _)) if id == self.zone => self.own.contains(target),
            Some((id, apex)) => {
                let node = node(self.view, id, &ScopeName::DEFAULT, target)?;
                !dhcp_names(&apex, node.iter().map(|(rrset, _)| rrset)).is_empty()
            }
        };
        self.seen.insert(target.clone(), found);
        Ok(found)
    }
}

/// Whether a type belongs to a signed zone.
fn is_dnssec(rtype: Rtype) -> bool {
    matches!(
        rtype,
        Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM | Rtype::DNSKEY
    )
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

/// Plans a flip to primary into `batch`: the origins, the apex, the serial step.
fn to_primary(
    view: &dyn ReadView,
    zone: &mut Zone,
    before: &Zone,
    rrsets: &[Stored],
    (soa, ns): (&tenko_core::dns::SoaDefaults, &[DnsName]),
    (stamp, limits): (&Stamp, JournalLimits),
    (batch, counts): (&mut WriteBatch, &mut Counts),
) -> ZoneResult<u32> {
    if !rrsets.iter().any(|(rrset, _)| rrset.rtype == Rtype::SOA) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "the zone holds no copy yet; a flip keeps the records of a transfer",
        ));
    }
    if rrsets.iter().any(|(rrset, _)| is_dnssec(rrset.rtype)) {
        return Err(ZoneError::zone_invalid(
            "dnssec",
            "the copy is signed, and a flip changes the SOA and the NS set its signatures cover; only an unsigned zone flips",
        ));
    }
    if let Some((stamp, _)) = view.get_typed(&TRANSFER_STATE, &before.id)?
        && rrsets.iter().any(|(rrset, _)| {
            rrset.origin == Origin::Transfer && rrset.updated.at > stamp.refreshed
        })
    {
        return Err(ZoneError::zone_invalid(
            "kind",
            "the last transfer of the zone was written in part; transfer it again before the flip",
        ));
    }
    zone.source = None;
    zone.soa = soa.clone();
    // The flip takes a member out of its catalog's hands.
    if zone
        .description
        .as_deref()
        .is_some_and(|text| text.starts_with(MEMBER_OF))
    {
        zone.description = None;
    }
    zone.validate()?;
    let own = dhcp_names(&before.name, rrsets.iter().map(|(rrset, _)| rrset));
    let mut targets = Targets {
        view,
        zone: before.id,
        own: &own,
        apexes: ZoneService::zones(view)?
            .into_iter()
            .filter(|row| row.zone.tenant == before.tenant)
            .map(|row| (row.zone.name, row.zone.id))
            .collect(),
        seen: BTreeMap::new(),
    };
    let scope = ScopeName::DEFAULT;
    let new_ns = ns_rrset(zone, &scope, ns, zone.soa.ttl, stamp.clone())?;
    new_ns.check(&zone.name)?;
    let mut old_ns = None;
    for (rrset, revision) in rrsets {
        if rrset.name == zone.name && matches!(rrset.rtype, Rtype::SOA | Rtype::NS) {
            if rrset.rtype == Rtype::NS {
                old_ns = Some((rrset, *revision));
            }
            continue;
        }
        if rrset.origin != Origin::Transfer {
            counts.add(rrset.origin);
            continue;
        }
        let origin = match rrset.rtype {
            Rtype::A | Rtype::AAAA if ns.contains(&rrset.name) => Origin::Manual,
            Rtype::A | Rtype::AAAA | DHCID if own.contains(&rrset.name) => Origin::Transfer,
            Rtype::PTR => {
                let mut frozen = false;
                for data in rrset.records()? {
                    if let RecordData::Ptr { target } = data
                        && targets.dhcp(&target)?
                    {
                        frozen = true;
                        break;
                    }
                }
                if frozen { Origin::Transfer } else { Origin::Ad }
            }
            _ => Origin::Ad,
        };
        counts.add(origin);
        if origin == rrset.origin {
            continue;
        }
        let mut next = rrset.clone();
        next.origin = origin;
        next.updated = stamp.clone();
        batch.expect_typed(&RRSETS, &rrset.key(), Some(*revision));
        stage_put(batch, Some(rrset), &next)?;
    }
    batch.expect_typed(&RRSETS, &new_ns.key(), old_ns.map(|(_, rev)| rev));
    stage_put(batch, old_ns.map(|(rrset, _)| rrset), &new_ns)?;
    let diff = Diff {
        key: new_ns.key(),
        before: old_ns.map(|(rrset, _)| rrset.clone()),
        after: Some(new_ns.clone()),
    };
    let (removed, added) = records::journal_diff(std::iter::once(&diff));
    let step =
        records::stage_serial_step(batch, view, zone, &scope, stamp, limits, removed, added)?;
    // The apex SOA and NS are the operator's.
    counts.add(Origin::Manual);
    counts.add(Origin::Manual);
    batch.delete_typed(&TRANSFER_STATE, &before.id);
    Ok(step.to)
}

/// Plans a flip (the module's rules).
#[allow(clippy::too_many_lines, reason = "one plan of a flip, both directions")]
fn plan_flip(
    view: &dyn ReadView,
    cx: &RequestCtx,
    id: ZoneId,
    flip: &ZoneFlip,
    limits: JournalLimits,
) -> ZoneResult<Planned<Flipped>> {
    let row = ZoneService::zone(view, id)?;
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
    let mut batch = WriteBatch::for_request(cx);
    let mut counts = Counts::default();
    let mut draft = AuditDraft::success(audit::ZONE_FLIP, vec![ObjectRef::from(id)])
        .with_source_ip(cx.source_ip)
        .with_context("name", zone.name.as_str())
        .with_context("from", kind_name(before.kind))
        .with_context("to", kind_name(zone.kind));
    let serial = match flip {
        ZoneFlip::Primary { soa, ns } => {
            check_kind(&before, ZoneKind::Secondary)?;
            let rrsets = scan(view, id, |_| true)?;
            to_primary(
                view,
                &mut zone,
                &before,
                &rrsets,
                (soa, ns),
                (&stamp, limits),
                (&mut batch, &mut counts),
            )?
        }
        ZoneFlip::Secondary { primaries } => {
            check_kind(&before, ZoneKind::Primary)?;
            if zone.update.kerberos.is_some() {
                return Err(ZoneError::zone_invalid(
                    "update.kerberos",
                    "a secondary zone takes no secure updates: remove `kerberos` from the zone's update policy first, then flip",
                ));
            }
            if zone.dnssec.mode == DnssecMode::Online {
                return Err(ZoneError::zone_invalid(
                    "dnssec.mode",
                    "a secondary zone is not signed online: set the zone's signing to off first, then flip",
                ));
            }
            zone.source = Some(SecondarySource {
                primaries: primaries.clone(),
            });
            zone.validate()?;
            for (rrset, _) in scan(view, id, |_| true)? {
                counts.add(rrset.origin);
            }
            let staged = batch.mutations.len();
            if ownership::stage_zone_owners_delete(&mut batch, view, id, FLIP_MAX)? {
                return Err(ZoneError::zone_invalid(
                    "owners",
                    &format!("a flip removes at most {FLIP_MAX} owners of names"),
                ));
            }
            let keys: Vec<&str> = primaries
                .iter()
                .filter_map(|primary| primary.key.as_ref().map(DnsName::as_str))
                .collect();
            let servers: Vec<String> = primaries
                .iter()
                .map(|primary| std::net::SocketAddr::new(primary.address, primary.port).to_string())
                .collect();
            draft = draft
                .with_context("primaries", servers.join(", "))
                .with_context("keys", keys.join(", "))
                .with_context("owners", (batch.mutations.len() - staged).to_string());
            ZoneService::scope_serial(view, &before, &ScopeName::DEFAULT)?.unwrap_or_default()
        }
    };
    batch.expect_typed(&ZONES, &id, Some(row.revision));
    batch.put_typed(&ZONES, &id, &zone)?;
    let origins: Vec<FlipOriginCount> = counts.0.into_values().collect();
    draft = draft.with_context("serial", serial.to_string());
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
}

/// Plans a release (or its dry run, which writes nothing).
fn plan_release(
    view: &dyn ReadView,
    cx: &RequestCtx,
    id: ZoneId,
    release: ZoneRelease,
    limits: JournalLimits,
) -> ZoneResult<Planned<(Vec<DnsName>, u32)>> {
    let row = ZoneService::zone(view, id)?;
    let zone = row.zone;
    check_kind(&zone, ZoneKind::Primary)?;
    let frozen = scan(view, id, |rrset| rrset.origin == Origin::Transfer)?;
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
}

/// The node's one flip or release; the next one is refused while it runs.
struct Running<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Runs a plan on a blocking thread.
async fn blocking<T: Send + 'static>(
    plan: impl FnOnce() -> ZoneResult<T> + Send + 'static,
) -> ZoneResult<T> {
    tokio::task::spawn_blocking(plan).await.map_err(|error| {
        ZoneError::new(
            tenko_core::error::codes::INTERNAL,
            500,
            format!("the plan of a flip ended: {error}"),
        )
    })?
}

impl ZoneService {
    fn running(&self) -> ZoneResult<Running<'_>> {
        if self.flipping.swap(true, Ordering::AcqRel) {
            return Err(ZoneError::new(
                FLIP_BUSY,
                429,
                "a flip or a release of a zone runs on this node; start this one when it has ended",
            ));
        }
        Ok(Running(&self.flipping))
    }

    /// Flips a zone between secondary and primary in place (the module's rules).
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid` (the request, a zone with other scopes, a
    /// signed or partly written copy, a setting a secondary cannot keep, a zone past the
    /// bounds), `dns.zone.flip.not_secondary`, `dns.zone.flip.not_primary`,
    /// `dns.zone.flip.catalog`, [`FLIP_BUSY`], or a store or job error.
    pub async fn flip(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        flip: &ZoneFlip,
    ) -> ZoneResult<ZoneFlipReport> {
        flip.validate()?;
        let _running = self.running()?;
        let limits = self.config.journal;
        let ((kind, serial, origins), written) = self
            .execute_async(cx, |view| {
                let (cx, flip) = (cx.clone(), flip.clone());
                blocking(move || plan_flip(view.as_ref(), &cx, id, &flip, limits))
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
    /// `dns.zone.not_found`, `dns.zone.invalid` for frozen RRsets past the bounds,
    /// `dns.zone.flip.not_primary`, `dns.zone.flip.catalog`, [`FLIP_BUSY`], or a store or
    /// job error.
    pub async fn release(
        &self,
        cx: &RequestCtx,
        id: ZoneId,
        release: ZoneRelease,
    ) -> ZoneResult<ZoneReleaseReport> {
        let _running = self.running()?;
        let limits = self.config.journal;
        let ((names, rrsets), written) = self
            .execute_async(cx, |view| {
                let cx = cx.clone();
                blocking(move || plan_release(view.as_ref(), &cx, id, release, limits))
            })
            .await?;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tenko_core::SystemComponent;

    use super::*;

    #[tokio::test]
    async fn a_node_runs_one_flip_or_release_at_a_time() {
        let zones = ZoneService::with_direct_jobs(
            Arc::new(tenko_store::MemStore::default()),
            None,
            super::super::ZoneConfig::default(),
        );
        let cx = RequestCtx::system(SystemComponent::Dns);
        let held = zones.running().expect("the first runs");
        let busy = zones
            .release(&cx, ZoneId::generate(), ZoneRelease::default())
            .await
            .expect_err("the second waits");
        assert!(busy.is(FLIP_BUSY), "{busy:?}");
        drop(held);
        let gone = zones
            .release(&cx, ZoneId::generate(), ZoneRelease::default())
            .await
            .expect_err("no such zone");
        assert!(gone.is(codes::ZONE_NOT_FOUND), "{gone:?}");
    }
}
