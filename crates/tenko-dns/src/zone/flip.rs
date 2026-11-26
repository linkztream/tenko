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
    sync::Arc,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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

/// The code of a flip or a release while another one runs on the node, or of a dry run
/// while [`DRY_RUNS`] run (429).
pub const FLIP_BUSY: &str = "dns.zone.flip.busy";

/// The dry runs of a release a node plans at once, beside its one flip or release: two, so
/// that a dry run neither waits for a flip nor holds one back, and canceled ones cannot pile
/// up beyond two plans.
pub const DRY_RUNS: usize = 2;

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

/// The RRsets of a zone that `keep` takes, page by page, refused past the bounds; the scan
/// ends once it holds `want` of them.
fn scan(
    view: &dyn ReadView,
    zone: ZoneId,
    keep: impl Fn(&RrSet) -> bool,
    want: usize,
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
        if last || out.len() >= want {
            return Ok(out);
        }
    }
}

/// The DHCP names of a copy of the zone `apex`: below the apex, with a DHCID RRset and
/// nothing but A, AAAA and DHCID, and not the target of an NS or SRV record of the copy (a
/// server's name freezes whatever DHCID its primary serves there).
fn dhcp_names<'a>(apex: &DnsName, rrsets: &'a [Stored]) -> ZoneResult<BTreeSet<&'a DnsName>> {
    let mut servers = BTreeSet::new();
    for (rrset, _) in rrsets {
        if matches!(rrset.rtype, Rtype::NS | Rtype::SRV) {
            for data in rrset.records()? {
                match data {
                    RecordData::Ns { host } => servers.insert(host),
                    RecordData::Srv { target, .. } => servers.insert(target),
                    _ => false,
                };
            }
        }
    }
    let mut names: BTreeMap<&DnsName, bool> = BTreeMap::new();
    let mut other = BTreeSet::new();
    for (rrset, _) in rrsets
        .iter()
        .filter(|(rrset, _)| &rrset.name != apex && !servers.contains(&rrset.name))
    {
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
    Ok(names
        .into_iter()
        .filter(|(name, dhcid)| *dhcid && !other.contains(name))
        .map(|(name, _)| name)
        .collect())
}

/// Whether PTR targets are frozen DHCP names, each target looked up once: in the zone
/// itself, or in the zone of the same tenant with the longest apex above it, which must be a
/// primary zone a flip froze the name in (the forward zones flip first).
struct Targets<'a> {
    view: &'a dyn ReadView,
    zone: ZoneId,
    own: &'a BTreeSet<&'a DnsName>,
    apexes: BTreeMap<DnsName, (ZoneId, ZoneKind)>,
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
            if let Some(found) = self.apexes.get(&name) {
                holder = Some(*found);
                break;
            }
            suffix = name.parent();
        }
        let found = match holder {
            Some((id, _)) if id == self.zone => self.own.contains(target),
            Some((id, ZoneKind::Primary)) => node(self.view, id, &ScopeName::DEFAULT, target)?
                .iter()
                .any(|(rrset, _)| rrset.rtype == DHCID && rrset.origin == Origin::Transfer),
            _ => false,
        };
        self.seen.insert(target.clone(), found);
        Ok(found)
    }
}

/// Whether an RRset of the zone `apex` belongs to a signed zone (a DS at the apex counts,
/// one below it is a delegation's).
fn is_signed(rrset: &RrSet, apex: &DnsName) -> bool {
    matches!(
        rrset.rtype,
        Rtype::RRSIG
            | Rtype::NSEC
            | Rtype::NSEC3
            | Rtype::NSEC3PARAM
            | Rtype::DNSKEY
            | Rtype::CDS
            | Rtype::CDNSKEY
    ) || (rrset.rtype == Rtype::DS && &rrset.name == apex)
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

/// Refuses a copy a flip cannot keep: none yet, a signed one, or one a transfer wrote in
/// part.
fn check_copy(view: &dyn ReadView, before: &Zone, rrsets: &[Stored]) -> ZoneResult<()> {
    if !rrsets.iter().any(|(rrset, _)| rrset.rtype == Rtype::SOA) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "the zone holds no copy yet; a flip keeps the records of a transfer",
        ));
    }
    if rrsets
        .iter()
        .any(|(rrset, _)| is_signed(rrset, &before.name))
    {
        return Err(ZoneError::zone_invalid(
            "dnssec",
            "the copy is signed, and a flip changes the SOA and the NS set its signatures cover; only an unsigned zone flips",
        ));
    }
    // A transfer writes its stamp with its last batch: a `transfer` RRset newer than the
    // stamp, or one without a stamp at all, was written by a transfer that did not finish.
    let refreshed = view
        .get_typed(&TRANSFER_STATE, &before.id)?
        .map(|(stamp, _)| stamp.refreshed);
    if rrsets.iter().any(|(rrset, _)| {
        rrset.origin == Origin::Transfer && refreshed.is_none_or(|at| rrset.updated.at > at)
    }) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "the last transfer of the zone was written in part; transfer it again before the flip",
        ));
    }
    Ok(())
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
    check_copy(view, before, rrsets)?;
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
    let own = dhcp_names(&before.name, rrsets)?;
    let mut targets = Targets {
        view,
        zone: before.id,
        own: &own,
        apexes: ZoneService::zones(view)?
            .into_iter()
            .filter(|row| row.zone.tenant == before.tenant)
            .map(|row| (row.zone.name, (row.zone.id, row.zone.kind)))
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
            // A primary is always served: the flip serves a takeover run's unserved copy.
            if !before.served {
                zone.served = true;
                draft = draft.with_context("served", "true");
            }
            let rrsets = scan(view, id, |_| true, usize::MAX)?;
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
            // The counters, not a scan: a zone that grew past the bounds since its flip still
            // flips back, and its records stay as they are until the next transfer.
            for (origin, rrsets) in ZoneService::summary(view, &before)?.origins {
                let rrsets = u32::try_from(rrsets).unwrap_or(u32::MAX);
                counts
                    .0
                    .insert(origin_index(origin), FlipOriginCount { origin, rrsets });
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
    // The store selects by name, not by origin: the origin counters say how many frozen
    // RRsets there are, so the scan stops at the last one, and a zone past the bound is
    // refused before anything is read.
    let held = ZoneService::summary(view, &zone)?
        .origins
        .into_iter()
        .find(|(origin, _)| *origin == Origin::Transfer)
        .map_or(0, |(_, count)| usize::try_from(count).unwrap_or(usize::MAX));
    if held > FLIP_MAX {
        return Err(ZoneError::zone_invalid(
            "rrsets",
            &format!("a release acts on at most {FLIP_MAX} frozen RRsets"),
        ));
    }
    let frozen = if held == 0 {
        Vec::new()
    } else {
        scan(view, id, |rrset| rrset.origin == Origin::Transfer, held)?
    };
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

/// The plans of flips and releases a node runs: one flip or release that writes, and up to
/// [`DRY_RUNS`] dry runs beside it. A plan holds its permit itself, so a request that ends
/// (a client gone, a timeout) frees it only when its plan has ended too.
pub(crate) struct Permits {
    writes: Arc<Semaphore>,
    dry_runs: Arc<Semaphore>,
}

impl Default for Permits {
    fn default() -> Self {
        Self {
            writes: Arc::new(Semaphore::new(1)),
            dry_runs: Arc::new(Semaphore::new(DRY_RUNS)),
        }
    }
}

impl Permits {
    fn take(&self, dry_run: bool) -> ZoneResult<Arc<OwnedSemaphorePermit>> {
        let pool = if dry_run {
            &self.dry_runs
        } else {
            &self.writes
        };
        let permit = Arc::clone(pool).try_acquire_owned().map_err(|_| {
            ZoneError::new(
                FLIP_BUSY,
                429,
                "a flip or a release of a zone runs on this node; start this one when it has ended",
            )
        })?;
        Ok(Arc::new(permit))
    }
}

/// Runs a plan on a blocking thread, which holds `permit` until the plan ends.
async fn blocking<T: Send + 'static>(
    permit: &Arc<OwnedSemaphorePermit>,
    plan: impl FnOnce() -> ZoneResult<T> + Send + 'static,
) -> ZoneResult<T> {
    let permit = Arc::clone(permit);
    let plan = move || {
        let _permit = permit;
        plan()
    };
    tokio::task::spawn_blocking(plan).await.map_err(|error| {
        ZoneError::new(
            tenko_core::error::codes::INTERNAL,
            500,
            format!("the plan of a flip ended: {error}"),
        )
    })?
}

impl ZoneService {
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
        let permit = self.flips.take(false)?;
        let limits = self.config.journal;
        let ((kind, serial, origins), written) = self
            .execute_async(cx, |view| {
                let (cx, flip) = (cx.clone(), flip.clone());
                blocking(&permit, move || {
                    plan_flip(view.as_ref(), &cx, id, &flip, limits)
                })
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
        let permit = self.flips.take(release.dry_run)?;
        let limits = self.config.journal;
        let ((names, rrsets), written) = self
            .execute_async(cx, |view| {
                let cx = cx.clone();
                blocking(&permit, move || {
                    plan_release(view.as_ref(), &cx, id, release, limits)
                })
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
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    use tenko_core::{
        SystemComponent, TableName,
        dns::{DnssecPolicy, SerialPolicy, SoaDefaults, TransferPolicy, UpdatePolicy},
    };
    use tenko_store::{
        ChangeStream, Committed, DerivedIndex, Leadership, MemStore, ReadConsistency, Store,
        StoreError, StoreStatus, Versioned, WatchFilter,
    };

    use super::*;
    use crate::zone::NewZone;

    /// A store whose reads of a zone row wait, while armed, until the test lets them go.
    struct Held {
        inner: Arc<MemStore>,
        armed: AtomicBool,
        entered: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    struct HeldView {
        inner: Arc<dyn ReadView>,
        store: Arc<Held>,
    }

    impl ReadView for HeldView {
        fn revision(&self) -> Revision {
            self.inner.revision()
        }

        fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
            if table == ZONES.name() && self.store.armed.load(Ordering::SeqCst) {
                let _ = self.store.entered.lock().expect("entered").send(());
                let _ = self.store.release.lock().expect("release").recv();
            }
            self.inner.get(table, key)
        }

        fn scan(
            &self,
            table: &TableName,
            range: tenko_store::KeyRange,
            limit: usize,
            reverse: bool,
        ) -> Result<Vec<(bytes::Bytes, Versioned)>, StoreError> {
            self.inner.scan(table, range, limit, reverse)
        }

        fn counter(&self, counter: &tenko_core::CounterKey) -> Result<u64, StoreError> {
            self.inner.counter(counter)
        }
    }

    struct HeldStore(Arc<Held>);

    #[async_trait::async_trait]
    impl Store for HeldStore {
        async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
            self.0.inner.propose(batch).await
        }

        async fn read(
            &self,
            consistency: ReadConsistency,
        ) -> Result<Arc<dyn ReadView>, StoreError> {
            Ok(Arc::new(HeldView {
                inner: self.0.inner.read(consistency).await?,
                store: Arc::clone(&self.0),
            }))
        }

        fn watch(
            &self,
            from: Option<Revision>,
            filter: WatchFilter,
        ) -> Result<ChangeStream, StoreError> {
            self.0.inner.watch(from, filter)
        }

        fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
            self.0.inner.register_index(index)
        }

        fn status(&self) -> StoreStatus {
            self.0.inner.status()
        }

        fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
            self.0.inner.leadership()
        }
    }

    fn cx() -> RequestCtx {
        RequestCtx::system(SystemComponent::Dns)
    }

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    async fn primary(zones: &ZoneService) -> ZoneId {
        zones
            .create(
                &cx(),
                NewZone {
                    name: name("example.test"),
                    kind: ZoneKind::Primary,
                    tenant: None,
                    scopes: Vec::new(),
                    serial: SerialPolicy::default(),
                    soa: SoaDefaults::new(
                        name("ns1.example.test"),
                        name("hostmaster.example.test"),
                    ),
                    name_servers: vec![name("ns1.example.test")],
                    transfer: TransferPolicy::default(),
                    update: UpdatePolicy::default(),
                    dnssec: DnssecPolicy::default(),
                    source: None,
                    description: None,
                    reverse_of: None,
                    catalog: false,
                },
            )
            .await
            .expect("zone")
            .zone
            .id
    }

    #[tokio::test]
    async fn a_node_runs_one_write_and_a_few_dry_runs_at_a_time() {
        let zones = ZoneService::with_direct_jobs(
            Arc::new(MemStore::default()),
            None,
            super::super::ZoneConfig::default(),
        );
        let id = primary(&zones).await;
        let write = zones.flips.take(false).expect("the write runs");
        let busy = zones
            .release(&cx(), id, ZoneRelease::default())
            .await
            .expect_err("a second write waits");
        assert!(busy.is(FLIP_BUSY), "{busy:?}");
        let dry = ZoneRelease {
            delete: false,
            dry_run: true,
        };
        zones
            .release(&cx(), id, dry)
            .await
            .expect("a dry run beside the write");
        drop(write);
        let held: Vec<_> = (0..DRY_RUNS)
            .map(|_| zones.flips.take(true).expect("a dry run"))
            .collect();
        let busy = zones
            .release(&cx(), id, dry)
            .await
            .expect_err("one dry run more waits");
        assert!(busy.is(FLIP_BUSY), "{busy:?}");
        zones
            .release(&cx(), id, ZoneRelease::default())
            .await
            .expect("a write beside the dry runs");
        drop(held);
    }

    /// A request that ends while its plan runs (a client gone) keeps its permit until the
    /// plan has ended: the plan waits in a store read the test holds.
    #[tokio::test]
    async fn a_request_dropped_mid_plan_frees_its_permit_when_the_plan_ends() {
        let (entered, on_enter) = mpsc::channel();
        let (let_go, release) = mpsc::channel();
        let held = Arc::new(Held {
            inner: Arc::new(MemStore::default()),
            armed: AtomicBool::new(false),
            entered: Mutex::new(entered),
            release: Mutex::new(release),
        });
        let zones = ZoneService::with_direct_jobs(
            Arc::new(HeldStore(Arc::clone(&held))),
            None,
            super::super::ZoneConfig::default(),
        );
        let id = primary(&zones).await;
        held.armed.store(true, Ordering::SeqCst);
        let request = {
            let zones = Arc::clone(&zones);
            tokio::spawn(async move { zones.release(&cx(), id, ZoneRelease::default()).await })
        };
        tokio::task::spawn_blocking(move || on_enter.recv())
            .await
            .expect("joined")
            .expect("the plan reads");
        held.armed.store(false, Ordering::SeqCst);
        request.abort();
        assert!(request.await.is_err_and(|error| error.is_cancelled()));
        let busy = zones
            .release(&cx(), id, ZoneRelease::default())
            .await
            .expect_err("the plan still runs");
        assert!(busy.is(FLIP_BUSY), "{busy:?}");
        let_go.send(()).expect("let the plan go");
        tenko_core::testing::wait_until_async("the permit is back", || async {
            zones.flips.writes.available_permits() == 1
        })
        .await;
        zones
            .release(&cx(), id, ZoneRelease::default())
            .await
            .expect("a write after the plan ended");
    }
}
