//! The owners of a zone's names (identity plan section 3.6, WP13.4): the locator-name list
//! the update path protects, the owner view, and what an administrator does with an owner.
//!
//! In a zone with ownership on, `dns.name_owners` holds the owner of each name a secure
//! update created or claimed ([`crate::update`]). This module reads those rows for the view
//! and changes them on an administrator's request:
//!
//! | Call | What it does |
//! |---|---|
//! | [`ZoneService::owners`] | A page of the owners of a zone scope in name order, filtered by a subtree and by an owner (its SID or its principal) |
//! | [`ZoneService::release_owner`] | Removes the owner of a name and returns the name's dynamic RRsets to the origin `ad`: the name is claimable again, by the host it names or a privileged principal, never by any principal the lists allow |
//! | [`ZoneService::assign_owner`] | Gives a name an owner (a principal of one of the zone's realms, with its SID when known), replacing the one it had; a name without records is held for the new owner for the zone's owner hold; a name holding a manual, IPAM or DHCP record is refused, since only privileged principals change those |
//! | [`ZoneService::import_owners`] | The owner field of MIG-06: owners a migration adapter read from the source (the owner SID of each Windows `dnsNode`), written as `imported` |
//!
//! Locator names and wildcard names never keep an owner (only privileged principals change
//! them), so none of these calls gives them one. Each change is one batch with its audit
//! record (`dns.owner.assign`, `dns.owner.release`) and expects the rows it read, like every
//! write of the zone service. None of this changes what the zone serves, so the serial and
//! the journal stay as they are.

use std::time::Duration;

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    codec::key::encode_key,
    dns::{
        DnsName, NameOwner, NameOwnerKey, Origin, OwnerSource, PrincipalName, RrSet, ScopeName,
        Sid, Zone, ZoneId, audit, codes,
        tables::{NAME_OWNERS, ZONES},
    },
    ipam::Stamp,
    timestamp::Timestamp,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt as _, WriteBatch};

use super::{Planned, Written, ZoneError, ZoneResult, ZoneService, node, stage_put};

/// The first labels of the names Active Directory's controllers register (section 3.6):
/// `_ldap`, `_kerberos`, `_kpasswd` and `_gc` SRV names, and the A records of the
/// application partitions.
pub const LOCATOR_LABELS: [&str; 6] = [
    "_ldap",
    "_kerberos",
    "_kpasswd",
    "_gc",
    "domaindnszones",
    "forestdnszones",
];

/// The most owners one [`ZoneService::import_owners`] call writes.
pub const MAX_IMPORTED_OWNERS: usize = 1_000;

/// The most owner rows one page of [`ZoneService::owners`] reads, matching or not: a page
/// that reaches it ends early with a cursor, so a filter that matches nothing does not scan
/// the whole table in one request.
pub const MAX_SCANNED_PER_PAGE: usize = 10_000;

/// Whether `name` is a locator name of `zone`, which only privileged principals change and
/// which keeps no owner: the apex (its A and AAAA records locate the domain), every name of
/// a zone whose apex starts with `_msdcs` and every name with a label `_msdcs` (the
/// forest-wide locator records, `gc._msdcs` among them), and every name whose first label
/// is one of [`LOCATOR_LABELS`] (the site forms such as `_ldap._tcp.<site>._sites` too).
pub fn is_locator(zone: &DnsName, name: &DnsName) -> bool {
    if name == zone {
        return true;
    }
    let msdcs = |label: &str| label.eq_ignore_ascii_case("_msdcs");
    if zone.labels().next().is_some_and(msdcs) || name.labels().any(msdcs) {
        return true;
    }
    name.labels().next().is_some_and(|first| {
        LOCATOR_LABELS
            .iter()
            .any(|known| first.eq_ignore_ascii_case(known))
    })
}

/// Whether `name` keeps no owner: a locator name of `zone` or a wildcard name (`*` first),
/// which answers every name of the zone that does not exist.
pub fn keeps_no_owner(zone: &DnsName, name: &DnsName) -> bool {
    is_locator(zone, name) || name.labels().next() == Some("*")
}

/// The filter of an owner list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerFilter {
    /// The zone scope.
    pub scope: ScopeName,
    /// Only the names at or below this name.
    pub below: Option<DnsName>,
    /// Only the names of this owner: its SID (`S-1-...`) or its principal, without regard
    /// to ASCII case.
    pub owner: Option<String>,
}

impl OwnerFilter {
    /// Every owner of a scope.
    pub fn scope(scope: ScopeName) -> Self {
        Self {
            scope,
            below: None,
            owner: None,
        }
    }

    fn matches(&self, key: &NameOwnerKey, owner: &NameOwner) -> bool {
        if let Some(below) = &self.below
            && !key.name.is_subdomain_of(below)
        {
            return false;
        }
        match &self.owner {
            None => true,
            Some(wanted) => {
                owner
                    .sid
                    .as_ref()
                    .is_some_and(|sid| sid.to_string().eq_ignore_ascii_case(wanted))
                    || owner.principal.to_string().eq_ignore_ascii_case(wanted)
            }
        }
    }
}

/// One owner row with its revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRow {
    /// The zone, the scope and the name.
    pub key: NameOwnerKey,
    /// The owner.
    pub owner: NameOwner,
    /// The row's revision.
    pub revision: Revision,
}

/// A page of owners, and the store key to continue after.
pub type OwnerPage = (Vec<OwnerRow>, Option<Vec<u8>>);

/// An administrator's assignment of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAssignment {
    /// The zone scope.
    pub scope: ScopeName,
    /// The name, inside the zone.
    pub name: DnsName,
    /// The new owner: a principal of one of the zone's realms.
    pub principal: PrincipalName,
    /// Its SID, when known (`Get-ADComputer <name> | Select SID`); without one the owner
    /// is matched by its principal name.
    pub sid: Option<Sid>,
    /// The row's revision the caller read, or none to replace whatever stands.
    pub expect: Option<Revision>,
}

/// What a release did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerReleased {
    /// The owner that was removed.
    pub owner: NameOwner,
    /// The dynamic RRsets of the name that returned to the origin `ad`.
    pub claimable: usize,
    /// The write.
    pub written: Written,
}

/// What an assignment did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAssigned {
    /// The owner now.
    pub owner: NameOwner,
    /// The owner before, if any.
    pub previous: Option<NameOwner>,
    /// The write.
    pub written: Written,
}

/// One owner a migration adapter read (MIG-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedOwner {
    /// The name, inside the zone.
    pub name: DnsName,
    /// The owner's principal, as the source names it.
    pub principal: PrincipalName,
    /// The owner's SID from the source's security descriptor.
    pub sid: Option<Sid>,
}

/// What an owner import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnersImported {
    /// Owners written.
    pub written: usize,
    /// Names left without an owner because they keep none: locator and wildcard names, and
    /// names that hold a manual, IPAM or DHCP record.
    pub skipped: usize,
}

fn owner_off(zone: &Zone) -> ZoneError {
    ZoneError::new(
        codes::OWNER_OFF,
        409,
        format!(
            "the zone {} keeps no owners: it has no Kerberos settings",
            zone.name
        ),
    )
}

fn protected(name: &DnsName) -> ZoneError {
    ZoneError::new(
        codes::OWNER_PROTECTED,
        409,
        format!("{name} keeps no owner: only privileged principals change it"),
    )
    .param("name", name.to_string())
}

fn invalid(field: &str, reason: impl Into<String>) -> ZoneError {
    let reason = reason.into();
    ZoneError::new(codes::OWNER_INVALID, 400, format!("{field}: {reason}"))
        .param("field", field)
        .param("reason", reason)
}

fn static_name(name: &DnsName) -> ZoneError {
    ZoneError::new(
        codes::OWNER_PROTECTED,
        409,
        format!(
            "{name} holds a manual, IPAM or DHCP record, which only privileged principals change; delete it before giving the name an owner"
        ),
    )
    .param("name", name.to_string())
}

/// Whether the name holds a record that only privileged principals change.
fn holds_static(rrsets: &[(RrSet, Revision)]) -> bool {
    rrsets
        .iter()
        .any(|(rrset, _)| matches!(rrset.origin, Origin::Manual | Origin::Ipam | Origin::Dhcp))
}

fn not_found(name: &DnsName) -> ZoneError {
    ZoneError::new(
        codes::OWNER_NOT_FOUND,
        404,
        format!("{name} has no owner in this scope"),
    )
    .param("name", name.to_string())
}

/// The checks every owner change shares: the zone keeps owners, has the scope, the name is
/// inside it and keeps an owner, and the principal is of one of the zone's realms.
fn check_target(
    zone: &Zone,
    scope: &ScopeName,
    name: &DnsName,
    principal: Option<&PrincipalName>,
) -> ZoneResult<()> {
    let Some(kerberos) = &zone.update.kerberos else {
        return Err(owner_off(zone));
    };
    if !zone.has_scope(scope) {
        return Err(ZoneError::zone_invalid(
            "scope",
            "the zone has no such scope",
        ));
    }
    if !name.is_subdomain_of(&zone.name) {
        return Err(invalid("name", format!("{name} is outside the zone")));
    }
    if keeps_no_owner(&zone.name, name) {
        return Err(protected(name));
    }
    if let Some(principal) = principal
        && !kerberos.accepts_realm(principal.realm())
    {
        return Err(invalid(
            "principal",
            format!(
                "the realm {} is not one of the zone's realms",
                principal.realm()
            ),
        ));
    }
    Ok(())
}

fn owner_key(zone: ZoneId, scope: &ScopeName, name: &DnsName) -> NameOwnerKey {
    NameOwnerKey {
        zone,
        scope: scope.clone(),
        name: name.clone(),
    }
}

/// Whether the name holds records the zone serves (the signer's rows aside).
fn has_records(rrsets: &[(RrSet, Revision)]) -> bool {
    rrsets
        .iter()
        .any(|(rrset, _)| rrset.origin != Origin::Dnssec)
}

/// The end of the owner hold for a name without records, from `now`.
fn hold_from(zone: &Zone, now: Timestamp) -> Timestamp {
    let days = zone
        .update
        .kerberos
        .as_ref()
        .map_or(0, |kerberos| kerberos.owner_hold_days);
    now.checked_add(Duration::from_secs(u64::from(days) * 86_400))
        .unwrap_or(now)
}

impl ZoneService {
    /// The owners of a zone scope in name order (the key order of `dns.name_owners`),
    /// from after `after` (a store key of a previous page), filtered; at most `limit`, and
    /// the key to continue from when more may follow.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn owners(
        view: &dyn ReadView,
        zone: &Zone,
        filter: &OwnerFilter,
        after: Option<&[u8]>,
        limit: usize,
    ) -> ZoneResult<OwnerPage> {
        let mut out = Vec::new();
        let prefix = encode_key(&(zone.id, filter.scope.clone()));
        let mut cursor = super::page_start(&prefix, after)?;
        let step = limit.clamp(64, 4096);
        let mut scanned = 0_usize;
        loop {
            let mut range = KeyRange::prefix(prefix.clone());
            if let Some(cursor) = &cursor {
                range = range.after(cursor.clone());
            }
            let rows = view.scan(NAME_OWNERS.name(), range, step, false)?;
            let exhausted = rows.len() < step;
            for (key, versioned) in rows {
                cursor = Some(key.to_vec());
                scanned += 1;
                let owner: NameOwner = NAME_OWNERS.decode(&versioned.value)?;
                let key = NAME_OWNERS.decode_key(&key).map_err(|error| {
                    ZoneError::new(
                        "sys.internal",
                        500,
                        format!("a stored owner key does not decode: {error}"),
                    )
                })?;
                if filter.matches(&key, &owner) {
                    out.push(OwnerRow {
                        key,
                        owner,
                        revision: versioned.revision,
                    });
                    if out.len() == limit {
                        return Ok((out, cursor));
                    }
                }
                if scanned >= MAX_SCANNED_PER_PAGE {
                    return Ok((out, cursor));
                }
            }
            if exhausted {
                return Ok((out, None));
            }
        }
    }

    /// Releases a name from its owner: the owner row goes, and the name's `dynamic` RRsets
    /// return to the origin `ad`, so that the next secure update that changes the name is
    /// held to the claim rule (the host the name carries, or a privileged principal) rather
    /// than taken by any principal the lists allow. Records of other origins stay as they
    /// are; a name without records is simply new again.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.owner.off`, `dns.zone.invalid` (the scope),
    /// `dns.owner.protected`, `dns.owner.not_found`, 412 when `expect` is not the row's
    /// revision, or a store or job error.
    pub async fn release_owner(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        scope: &ScopeName,
        name: &DnsName,
        expect: Option<Revision>,
    ) -> ZoneResult<OwnerReleased> {
        let ((owner, claimable), written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, zone)?;
                check_target(&row.zone, scope, name, None)?;
                let key = owner_key(zone, scope, name);
                let Some((owner, revision)) = view.get_typed(&NAME_OWNERS, &key)? else {
                    return Err(not_found(name));
                };
                super::check_expect(expect, revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ZONES, &zone, Some(row.revision));
                batch.expect_typed(&NAME_OWNERS, &key, Some(revision));
                // A dynamic RRset written to the name after this read would stay dynamic
                // on a name without an owner, open to any principal: every write of a new
                // dynamic RRset in the zone bumps this counter, so it makes the release
                // plan again.
                let added = super::origin_added(zone, Origin::Dynamic);
                batch.expect_counter(added.clone(), view.counter(&added)?);
                batch.delete_typed(&NAME_OWNERS, &key);
                let stamp = Stamp::new(cx.now, cx.principal.clone());
                let mut claimable = 0_usize;
                for (rrset, rrset_revision) in node(view, zone, scope, name)? {
                    if rrset.origin != Origin::Dynamic {
                        continue;
                    }
                    let mut marked = rrset.clone();
                    marked.origin = Origin::Ad;
                    marked.updated = stamp.clone();
                    batch.expect_typed(
                        &tenko_core::dns::tables::RRSETS,
                        &rrset.key(),
                        Some(rrset_revision),
                    );
                    stage_put(&mut batch, Some(&rrset), &marked)?;
                    claimable += 1;
                }
                let mut draft =
                    AuditDraft::success(audit::OWNER_RELEASE, vec![ObjectRef::from(zone)])
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", row.zone.name.as_str())
                        .with_context("scope", scope.as_str())
                        .with_context("name", name.as_str())
                        .with_context("principal", owner.principal.to_string())
                        .with_context("claimable", claimable.to_string());
                if let Some(sid) = &owner.sid {
                    draft = draft.with_context("sid", sid.to_string());
                }
                batch.audit(draft);
                Ok(Planned::write(
                    (owner, claimable),
                    batch,
                    format!("release {name} from its owner"),
                    vec![ObjectRef::from(zone)],
                ))
            })
            .await?;
        Ok(OwnerReleased {
            owner,
            claimable,
            written: written.ok_or_else(super::internal_nothing_written)?,
        })
    }

    /// Gives a name an owner, replacing the one it had. A name with records is owned from
    /// now; a name without records is held for the new owner until the zone's owner hold
    /// has passed (after which it is a new name again, as for a removed name).
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.owner.off`, `dns.zone.invalid` (the scope),
    /// `dns.owner.protected`, `dns.owner.invalid` (the name outside the zone, a realm the
    /// zone does not accept), 412 when `expect` is not the row's revision, or a store or
    /// job error.
    pub async fn assign_owner(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        assignment: &OwnerAssignment,
    ) -> ZoneResult<OwnerAssigned> {
        let OwnerAssignment {
            scope,
            name,
            principal,
            sid,
            expect,
        } = assignment;
        let ((owner, previous), written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, zone)?;
                check_target(&row.zone, scope, name, Some(principal))?;
                let key = owner_key(zone, scope, name);
                let before = view.get_typed(&NAME_OWNERS, &key)?;
                if let Some(expect) = expect {
                    match &before {
                        Some((_, revision)) => super::check_expect(Some(*expect), *revision)?,
                        None => super::check_expect(Some(*expect), Revision(0))?,
                    }
                }
                let rrsets = node(view, zone, scope, name)?;
                if holds_static(&rrsets) {
                    return Err(static_name(name));
                }
                let owner = NameOwner {
                    sid: sid.clone(),
                    principal: principal.clone(),
                    since: cx.now,
                    hold_until: (!has_records(&rrsets)).then(|| hold_from(&row.zone, cx.now)),
                    how: OwnerSource::Assigned,
                };
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ZONES, &zone, Some(row.revision));
                batch.expect_typed(
                    &NAME_OWNERS,
                    &key,
                    before.as_ref().map(|(_, revision)| *revision),
                );
                batch.put_typed(&NAME_OWNERS, &key, &owner)?;
                let mut draft =
                    AuditDraft::success(audit::OWNER_ASSIGN, vec![ObjectRef::from(zone)])
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", row.zone.name.as_str())
                        .with_context("scope", scope.as_str())
                        .with_context("name", name.as_str())
                        .with_context("principal", principal.to_string());
                if let Some(sid) = sid {
                    draft = draft.with_context("sid", sid.to_string());
                }
                if let Some((previous, _)) = &before {
                    draft = draft.with_context("previous", previous.principal.to_string());
                }
                batch.audit(draft);
                let previous = before.map(|(previous, _)| previous);
                Ok(Planned::write(
                    (owner, previous),
                    batch,
                    format!("assign {name} to {principal}"),
                    vec![ObjectRef::from(zone)],
                ))
            })
            .await?;
        Ok(OwnerAssigned {
            owner,
            previous,
            written: written.ok_or_else(super::internal_nothing_written)?,
        })
    }

    /// Writes the owners a migration adapter read from the source (MIG-06), as `imported`,
    /// in one batch: every name inside the zone, of one of its realms; a locator or
    /// wildcard name keeps no owner and is counted as skipped. An owner the name has is
    /// replaced. At most [`MAX_IMPORTED_OWNERS`] per call.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.owner.off`, `dns.zone.invalid` (the scope),
    /// `dns.owner.invalid` (too many, a name outside the zone, a realm the zone does not
    /// accept, a name twice), or a store or job error.
    pub async fn import_owners(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        scope: &ScopeName,
        owners: &[ImportedOwner],
    ) -> ZoneResult<OwnersImported> {
        if owners.len() > MAX_IMPORTED_OWNERS {
            return Err(invalid(
                "owners",
                format!("at most {MAX_IMPORTED_OWNERS} owners per import"),
            ));
        }
        let (result, _) = self
            .execute(cx, |view| {
                let row = Self::zone(view, zone)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ZONES, &zone, Some(row.revision));
                let mut result = OwnersImported::default();
                let mut seen = std::collections::BTreeSet::new();
                for imported in owners {
                    if !seen.insert(imported.name.clone()) {
                        return Err(invalid(
                            "owners",
                            format!("{} appears twice", imported.name),
                        ));
                    }
                    match check_target(&row.zone, scope, &imported.name, Some(&imported.principal))
                    {
                        Ok(()) => {}
                        Err(error) if error.is(codes::OWNER_PROTECTED) => {
                            result.skipped += 1;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                    let key = owner_key(zone, scope, &imported.name);
                    let before = view.get_typed(&NAME_OWNERS, &key)?;
                    let rrsets = node(view, zone, scope, &imported.name)?;
                    // A static name stays with privileged principals, as on assignment.
                    if holds_static(&rrsets) {
                        result.skipped += 1;
                        continue;
                    }
                    let owner = NameOwner {
                        sid: imported.sid.clone(),
                        principal: imported.principal.clone(),
                        since: cx.now,
                        hold_until: (!has_records(&rrsets)).then(|| hold_from(&row.zone, cx.now)),
                        how: OwnerSource::Imported,
                    };
                    batch.expect_typed(
                        &NAME_OWNERS,
                        &key,
                        before.as_ref().map(|(_, revision)| *revision),
                    );
                    batch.put_typed(&NAME_OWNERS, &key, &owner)?;
                    result.written += 1;
                }
                if result.written == 0 {
                    return Ok(Planned::nothing(result));
                }
                batch.audit(
                    AuditDraft::success(audit::OWNER_ASSIGN, vec![ObjectRef::from(zone)])
                        .with_source_ip(cx.source_ip)
                        .with_context("zone", row.zone.name.as_str())
                        .with_context("scope", scope.as_str())
                        .with_context("imported", result.written.to_string())
                        .with_context("skipped", result.skipped.to_string()),
                );
                let summary = format!("import {} owners", result.written);
                Ok(Planned::write(
                    result,
                    batch,
                    summary,
                    vec![ObjectRef::from(zone)],
                ))
            })
            .await?;
        Ok(result)
    }
}

/// Stages the deletion of every owner row of a removed zone scope.
pub(crate) fn stage_scope_owners_delete(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
) -> ZoneResult<()> {
    let rows = view.scan(
        NAME_OWNERS.name(),
        KeyRange::prefix(encode_key(&(zone, scope.clone()))),
        usize::MAX,
        false,
    )?;
    for (key, _) in rows {
        batch.delete(NAME_OWNERS.name().clone(), key);
    }
    Ok(())
}

/// Stages the deletion of every owner row of a zone that `view` holds, at most `limit`;
/// whether more remain. Used when the zone is deleted.
pub(crate) fn stage_zone_owners_delete(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: ZoneId,
    limit: usize,
) -> ZoneResult<bool> {
    let rows = view.scan(
        NAME_OWNERS.name(),
        KeyRange::prefix(encode_key(&zone)),
        limit.saturating_add(1),
        false,
    )?;
    let more = rows.len() > limit;
    for (key, _) in rows.into_iter().take(limit) {
        batch.delete(NAME_OWNERS.name().clone(), key);
    }
    Ok(more)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    #[test]
    fn the_locator_names_of_active_directory() {
        let zone = name("corp.example.test");
        for locator in [
            "corp.example.test",
            "_ldap._tcp.corp.example.test",
            "_ldap._tcp.Default-First-Site-Name._sites.corp.example.test",
            "_ldap._tcp.dc._msdcs.corp.example.test",
            "_kerberos._udp.corp.example.test",
            "_kpasswd._tcp.corp.example.test",
            "_gc._tcp.corp.example.test",
            "gc._msdcs.corp.example.test",
            "DomainDnsZones.corp.example.test",
            "_ldap._tcp.ForestDnsZones.corp.example.test",
        ] {
            assert!(is_locator(&zone, &name(locator)), "{locator}");
            assert!(keeps_no_owner(&zone, &name(locator)), "{locator}");
        }
        let msdcs = name("_msdcs.corp.example.test");
        assert!(is_locator(
            &msdcs,
            &name("6f3c0a2e-1111-4222-8333-944455556666._msdcs.corp.example.test")
        ));
        for host in [
            "pc01.corp.example.test",
            "ldap.corp.example.test",
            "kerberos.corp.example.test",
            "web._tcp.corp.example.test",
        ] {
            assert!(!is_locator(&zone, &name(host)), "{host}");
            assert!(!keeps_no_owner(&zone, &name(host)), "{host}");
        }
        assert!(keeps_no_owner(&zone, &name("*.corp.example.test")));
    }
}
