//! Access lists (`dns.acls`): named lists of prefixes, TSIG keys and `any` for transfers,
//! updates and queries; the first entry that matches decides.
//!
//! A list has a unique name (1 to 64 characters, compared without case) and at most
//! [`MAX_ENTRIES`] entries. A list named by a zone (transfer or update policy) cannot be
//! deleted (`dns.acl.in_use`). Every change is an inline job with its `dns.acl.*` audit
//! record.

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        Acl, AclEntry, AclId, Zone, audit, codes,
        tables::{ACLS, ZONES},
    },
    error::codes as sys,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{Planned, Written, ZoneError, ZoneResult, ZoneService, check_expect};

/// Entries one list holds at most.
pub const MAX_ENTRIES: usize = 1_000;

/// A new access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAcl {
    /// A unique name.
    pub name: String,
    /// The entries, in order.
    pub entries: Vec<AclEntry>,
    /// Free text.
    pub description: Option<String>,
}

/// Changes to an access list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclChange {
    /// The name.
    pub name: Option<String>,
    /// The entries.
    pub entries: Option<Vec<AclEntry>>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// An access list as read, with what names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRow {
    /// The list.
    pub acl: Acl,
    /// The zones that name it (`zone:<name>`).
    pub used_by: Vec<String>,
    /// The revision of the row.
    pub revision: Revision,
}

fn invalid(field: &str, reason: &str) -> ZoneError {
    ZoneError::new(sys::INVALID_VALUE, 400, format!("{field}: {reason}"))
        .param("field", field)
        .param("reason", reason)
}

fn check(acl: &Acl) -> ZoneResult<()> {
    let name = acl.name.as_str();
    if name.trim() != name || name.is_empty() || name.chars().count() > 64 {
        return Err(invalid(
            "name",
            "1 to 64 characters without surrounding spaces",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("name", "control characters are not allowed"));
    }
    if acl.entries.len() > MAX_ENTRIES {
        return Err(invalid(
            "entries",
            "an access list has at most 1000 entries",
        ));
    }
    Ok(())
}

fn not_found(id: AclId) -> ZoneError {
    ZoneError::new(
        codes::ACL_NOT_FOUND,
        404,
        format!("access list {id} does not exist"),
    )
    .param("id", id.to_string())
}

fn names_acl(zone: &Zone, id: AclId) -> bool {
    zone.transfer.allow.contains(&id) || zone.update.allowed.contains(&id)
}

impl ZoneService {
    /// Every access list, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn acls(view: &dyn ReadView) -> ZoneResult<Vec<AclRow>> {
        let zones: Vec<Zone> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, zone, _)| zone)
            .collect();
        let mut rows: Vec<AclRow> = view
            .scan_typed(&ACLS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, acl, revision)| AclRow {
                used_by: used_by(&zones, acl.id),
                acl,
                revision,
            })
            .collect();
        rows.sort_by(|a, b| {
            a.acl
                .name
                .to_lowercase()
                .cmp(&b.acl.name.to_lowercase())
                .then(a.acl.id.cmp(&b.acl.id))
        });
        Ok(rows)
    }

    /// One access list.
    ///
    /// # Errors
    ///
    /// `dns.acl.not_found`, or the store's error.
    pub fn acl(view: &dyn ReadView, id: AclId) -> ZoneResult<AclRow> {
        let (acl, revision) = view.get_typed(&ACLS, &id)?.ok_or_else(|| not_found(id))?;
        let zones: Vec<Zone> = view
            .scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, zone, _)| zone)
            .collect();
        Ok(AclRow {
            used_by: used_by(&zones, id),
            acl,
            revision,
        })
    }

    /// Creates an access list.
    ///
    /// # Errors
    ///
    /// `sys.invalid_value` for a bad or taken name, or a store or job error.
    pub async fn create_acl(&self, cx: &RequestCtx, new: NewAcl) -> ZoneResult<(Acl, Written)> {
        let acl = Acl {
            id: AclId::generate(),
            name: new.name,
            entries: new.entries,
            description: new
                .description
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty()),
        };
        check(&acl)?;
        let (acl, written) = self
            .execute(cx, |view| {
                unique_name(view, &acl)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ACLS, &acl.id, None);
                batch.put_typed(&ACLS, &acl.id, &acl)?;
                batch.audit(
                    AuditDraft::success(audit::ACL_CREATE, vec![ObjectRef::from(acl.id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", acl.name.clone()),
                );
                Ok(Planned::write(
                    acl.clone(),
                    batch,
                    format!("create access list {}", acl.name),
                    vec![ObjectRef::from(acl.id)],
                ))
            })
            .await?;
        Ok((acl, written.ok_or_else(super::internal_nothing_written)?))
    }

    /// Changes an access list; with `expect`, only the row at that revision.
    ///
    /// # Errors
    ///
    /// `dns.acl.not_found`, `sys.invalid_value`, 412 when `expect` is stale, or a store or
    /// job error.
    pub async fn update_acl(
        &self,
        cx: &RequestCtx,
        id: AclId,
        change: AclChange,
        expect: Option<Revision>,
    ) -> ZoneResult<(Acl, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view.get_typed(&ACLS, &id)?.ok_or_else(|| not_found(id))?;
            check_expect(expect, revision)?;
            let mut acl = before.clone();
            if let Some(name) = &change.name {
                acl.name.clone_from(name);
            }
            if let Some(entries) = &change.entries {
                acl.entries.clone_from(entries);
            }
            if let Some(description) = &change.description {
                acl.description =
                    Some(description.trim().to_owned()).filter(|text| !text.is_empty());
            }
            check(&acl)?;
            if acl == before {
                return Ok(Planned::nothing(acl));
            }
            unique_name(view, &acl)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&ACLS, &id, Some(revision));
            batch.put_typed(&ACLS, &id, &acl)?;
            batch.audit(
                AuditDraft::success(audit::ACL_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", acl.name.clone()),
            );
            Ok(Planned::write(
                acl.clone(),
                batch,
                format!("change access list {}", acl.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes an access list no zone names.
    ///
    /// # Errors
    ///
    /// `dns.acl.not_found`, `dns.acl.in_use`, 412 when `expect` is stale, or a store or job
    /// error.
    pub async fn delete_acl(
        &self,
        cx: &RequestCtx,
        id: AclId,
        expect: Option<Revision>,
    ) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |view| {
                let row = Self::acl(view, id)?;
                check_expect(expect, row.revision)?;
                if !row.used_by.is_empty() {
                    return Err(ZoneError::new(
                        codes::ACL_IN_USE,
                        409,
                        format!(
                            "access list {} is named by {}",
                            row.acl.name,
                            row.used_by.join(", ")
                        ),
                    )
                    .param("id", id.to_string())
                    .param("by", row.used_by.join(",")));
                }
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&ACLS, &id, Some(row.revision));
                batch.delete_typed(&ACLS, &id);
                // A zone that starts to name the list meanwhile makes the batch stale.
                for (zone_id, _, revision) in
                    view.scan_typed(&ZONES, KeyRange::all(), usize::MAX, false)?
                {
                    batch.expect_typed(&ZONES, &zone_id, Some(revision));
                }
                batch.audit(
                    AuditDraft::success(audit::ACL_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", row.acl.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete access list {}", row.acl.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        written.ok_or_else(super::internal_nothing_written)
    }
}

fn used_by(zones: &[Zone], id: AclId) -> Vec<String> {
    let mut names: Vec<String> = zones
        .iter()
        .filter(|zone| names_acl(zone, id))
        .map(|zone| format!("zone:{}", zone.name))
        .collect();
    names.sort();
    names
}

fn unique_name(view: &dyn ReadView, acl: &Acl) -> ZoneResult<()> {
    let taken = view
        .scan_typed(&ACLS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| id != acl.id && other.name.to_lowercase() == acl.name.to_lowercase());
    if taken {
        return Err(invalid("name", "an access list of this name exists"));
    }
    Ok(())
}
