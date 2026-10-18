//! Views (`dns.views`, DNS-20): the rows the view table of the catalog is compiled from.
//!
//! A view has a unique name (1 to 64 characters, compared without case), up to
//! [`MAX_RULES`] match rules that must all hold, a scope map that names zone scopes with
//! weights, an optional recursion access list and its position `order`. The positions are
//! kept unique and without gaps, from 1: a view created or moved to a position pushes the
//! views from there one down, and a deleted view closes its gap; the rows whose position
//! moves are written in the same batch. A position past the end is the end.
//!
//! The rules against other rows, checked in the batch that writes the view:
//!
//! - every zone of the scope map exists and has the scope named (`dns.view.invalid`), and
//!   the batch expects the zone rows, so a scope removed meanwhile makes it stale;
//! - the recursion access list exists (`dns.view.invalid`), and the batch expects it;
//! - a view named by a forwarding rule cannot be deleted (`dns.view.in_use`).
//!
//! The other direction lives with the owners of the rows: a zone scope named by a view
//! cannot be removed from its zone and a zone named by a view cannot be deleted
//! ([`stage_zone_refs`], called by the zone service), and an access list a view names for
//! recursion is in use (`super::acl`).
//!
//! No row is the implicit default view: a query no view matches sees the default scope of
//! every zone and recurses as the profile's default allows. Every change is an inline job
//! with its `dns.view.*` audit record; the role's catalog follows the rows through the feed.

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        AclId, DnsError, MatchRule, ScopeName, ScopeWeight, View, ViewId, Zone, ZoneId, audit,
        codes,
        tables::{ACLS, FORWARDERS, VIEWS, ZONES},
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{Planned, Written, ZoneError, ZoneResult, ZoneService, check_expect};

/// Rules one view holds at most.
pub const MAX_RULES: usize = 32;

/// Values one rule lists at most (prefixes, addresses, types, suffixes).
pub const MAX_RULE_VALUES: usize = 1_000;

/// Entries of one scope map at most.
pub const MAX_SCOPES: usize = 256;

/// Views at most.
pub const MAX_VIEWS: usize = 1_000;

/// A new view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewView {
    /// A unique name.
    pub name: String,
    /// The tests.
    pub rules: Vec<MatchRule>,
    /// The scopes per zone with their weights.
    pub scope_map: Vec<ScopeWeight>,
    /// The position, from 1; past the end is the end.
    pub order: u32,
    /// The recursion access list; the profile's default when `None`.
    pub recursion: Option<AclId>,
    /// Free text.
    pub description: Option<String>,
}

/// Changes to a view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewChange {
    /// The name.
    pub name: Option<String>,
    /// The tests, replacing all of them.
    pub rules: Option<Vec<MatchRule>>,
    /// The scope map, replacing it.
    pub scope_map: Option<Vec<ScopeWeight>>,
    /// The position.
    pub order: Option<u32>,
    /// The recursion access list.
    pub recursion: Option<AclId>,
    /// Follow the profile's default (clears `recursion`).
    pub default_recursion: bool,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// A view as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    /// The view.
    pub view: View,
    /// The revision of the row.
    pub revision: Revision,
}

fn invalid(field: &str, reason: &str) -> ZoneError {
    DnsError::invalid(codes::VIEW_INVALID, field, reason).into()
}

fn not_found(id: ViewId) -> ZoneError {
    ZoneError::new(
        codes::VIEW_NOT_FOUND,
        404,
        format!("view {id} does not exist"),
    )
    .param("id", id.to_string())
}

/// `dns.view.in_use` for the object `id`, named by `by` (`view:<name>`,
/// `forwarder:<suffix>`).
fn in_use(what: &str, id: &str, by: &[String]) -> ZoneError {
    ZoneError::new(
        codes::VIEW_IN_USE,
        409,
        format!("{what} is named by {}", by.join(", ")),
    )
    .param("id", id)
    .param("by", by.join(","))
}

fn trimmed(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn rule_values(rule: &MatchRule) -> usize {
    match rule {
        MatchRule::ClientSubnet { prefixes } => prefixes.len(),
        MatchRule::Transport { transports } => transports.len(),
        MatchRule::Interface { addresses } => addresses.len(),
        MatchRule::Qtype { types } => types.len(),
        MatchRule::Qname { suffixes } => suffixes.len(),
        MatchRule::TimeOfDay { .. } => 1,
    }
}

/// The view's own checks: the model's, the limits and the description.
fn check_own(view: &View) -> ZoneResult<()> {
    view.validate()?;
    if view.rules.len() > MAX_RULES {
        return Err(invalid("rules", "a view has at most 32 rules"));
    }
    if view
        .rules
        .iter()
        .any(|rule| rule_values(rule) > MAX_RULE_VALUES)
    {
        return Err(invalid("rules", "a rule lists at most 1000 values"));
    }
    if view.scope_map.len() > MAX_SCOPES {
        return Err(invalid("scope_map", "a view maps at most 256 zone scopes"));
    }
    if view
        .description
        .as_deref()
        .is_some_and(|text| text.chars().count() > 1_000)
    {
        return Err(invalid("description", "at most 1000 characters"));
    }
    Ok(())
}

/// The checks against other rows, staged as expectations in `batch`: the name is free,
/// every zone scope of the map exists, the recursion access list exists.
fn check_refs(batch: &mut WriteBatch, read: &dyn ReadView, view: &View) -> ZoneResult<()> {
    let taken = read
        .scan_typed(&VIEWS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| {
            id != view.id && other.name.to_lowercase() == view.name.to_lowercase()
        });
    if taken {
        return Err(invalid("name", "a view of this name exists"));
    }
    let mut zones: Vec<ZoneId> = Vec::new();
    for entry in &view.scope_map {
        let Some((zone, revision)) = read.get_typed(&ZONES, &entry.zone)? else {
            return Err(ZoneError::from(DnsError::invalid(
                codes::VIEW_INVALID,
                "scope_map",
                "the zone does not exist",
            ))
            .param("zone", entry.zone.to_string()));
        };
        if !zone.has_scope(&entry.scope) {
            return Err(ZoneError::from(DnsError::invalid(
                codes::VIEW_INVALID,
                "scope_map",
                "the zone has no such scope",
            ))
            .param("zone", zone.name.to_string())
            .param("scope", entry.scope.to_string()));
        }
        if !zones.contains(&entry.zone) {
            zones.push(entry.zone);
            batch.expect_typed(&ZONES, &entry.zone, Some(revision));
        }
    }
    if let Some(acl) = view.recursion {
        let Some((_, revision)) = read.get_typed(&ACLS, &acl)? else {
            return Err(ZoneError::from(DnsError::invalid(
                codes::VIEW_INVALID,
                "recursion",
                "the access list does not exist",
            ))
            .param("acl", acl.to_string()));
        };
        batch.expect_typed(&ACLS, &acl, Some(revision));
    }
    Ok(())
}

/// Every view row in position order (then id).
fn ordered(read: &dyn ReadView) -> ZoneResult<Vec<ViewRow>> {
    let mut rows: Vec<ViewRow> = read
        .scan_typed(&VIEWS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, view, revision)| ViewRow { view, revision })
        .collect();
    rows.sort_by_key(|row| (row.view.order, row.view.id));
    Ok(rows)
}

/// Puts `view` at `position` (from 1, clamped to the list) among `others` (in position
/// order, `view` not among them), numbers every view from 1, and stages `view` and every
/// other row whose position moves. The batch expects every row it read, so a concurrent
/// insert or move makes it stale. Returns the view and the number of other rows moved.
fn stage_order(
    batch: &mut WriteBatch,
    mut view: View,
    position: u32,
    others: Vec<ViewRow>,
) -> ZoneResult<(View, usize)> {
    let index = usize::try_from(position.max(1) - 1)
        .unwrap_or(usize::MAX)
        .min(others.len());
    let mut list: Vec<Option<ViewRow>> = others.into_iter().map(Some).collect();
    list.insert(index, None);
    let mut moved = 0;
    for (at, slot) in list.into_iter().enumerate() {
        let number = u32::try_from(at + 1).unwrap_or(u32::MAX);
        match slot {
            None => view.order = number,
            Some(mut row) => {
                batch.expect_typed(&VIEWS, &row.view.id, Some(row.revision));
                if row.view.order != number {
                    row.view.order = number;
                    batch.put_typed(&VIEWS, &row.view.id, &row.view)?;
                    moved += 1;
                }
            }
        }
    }
    batch.put_typed(&VIEWS, &view.id, &view)?;
    Ok((view, moved))
}

fn nothing_written() -> ZoneError {
    ZoneError::new(
        tenko_core::error::codes::INTERNAL,
        500,
        "the write reported no commit",
    )
}

impl ZoneService {
    /// Every view, in position order.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn dns_views(read: &dyn ReadView) -> ZoneResult<Vec<ViewRow>> {
        ordered(read)
    }

    /// One view.
    ///
    /// # Errors
    ///
    /// `dns.view.not_found`, or the store's error.
    pub fn dns_view(read: &dyn ReadView, id: ViewId) -> ZoneResult<ViewRow> {
        let (view, revision) = read.get_typed(&VIEWS, &id)?.ok_or_else(|| not_found(id))?;
        Ok(ViewRow { view, revision })
    }

    /// Creates a view at its position.
    ///
    /// # Errors
    ///
    /// `dns.view.invalid`, or a store or job error.
    pub async fn create_view(&self, cx: &RequestCtx, new: NewView) -> ZoneResult<(View, Written)> {
        let view = View {
            id: ViewId::generate(),
            name: new.name,
            rules: new.rules,
            scope_map: new.scope_map,
            order: new.order,
            recursion: new.recursion,
            description: trimmed(new.description),
        };
        check_own(&view)?;
        let position = new.order;
        let (view, written) = self
            .execute(cx, |read| {
                let mut batch = WriteBatch::for_request(cx);
                check_refs(&mut batch, read, &view)?;
                let others = ordered(read)?;
                if others.len() >= MAX_VIEWS {
                    return Err(invalid("name", "at most 1000 views"));
                }
                batch.expect_typed(&VIEWS, &view.id, None);
                let (view, _) = stage_order(&mut batch, view.clone(), position, others)?;
                batch.audit(
                    AuditDraft::success(audit::VIEW_CREATE, vec![ObjectRef::from(view.id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", view.name.clone())
                        .with_context("order", view.order.to_string()),
                );
                Ok(Planned::write(
                    view.clone(),
                    batch,
                    format!("create view {}", view.name),
                    vec![ObjectRef::from(view.id)],
                ))
            })
            .await?;
        Ok((view, written.ok_or_else(nothing_written)?))
    }

    /// Changes a view; with `expect`, only the row at that revision.
    ///
    /// # Errors
    ///
    /// `dns.view.not_found`, `dns.view.invalid`, 412 when `expect` is stale, or a store or
    /// job error.
    pub async fn update_view(
        &self,
        cx: &RequestCtx,
        id: ViewId,
        change: ViewChange,
        expect: Option<Revision>,
    ) -> ZoneResult<(View, Option<Written>)> {
        self.execute(cx, |read| {
            let row = Self::dns_view(read, id)?;
            check_expect(expect, row.revision)?;
            let before = row.view;
            let mut view = before.clone();
            if let Some(name) = &change.name {
                view.name.clone_from(name);
            }
            if let Some(rules) = &change.rules {
                view.rules.clone_from(rules);
            }
            if let Some(scope_map) = &change.scope_map {
                view.scope_map.clone_from(scope_map);
            }
            if change.default_recursion {
                view.recursion = None;
            } else if let Some(acl) = change.recursion {
                view.recursion = Some(acl);
            }
            if let Some(description) = &change.description {
                view.description = trimmed(Some(description.clone()));
            }
            check_own(&view)?;
            let others: Vec<ViewRow> = ordered(read)?
                .into_iter()
                .filter(|other| other.view.id != id)
                .collect();
            // The current position among the others unless a new one is asked for.
            let current = others
                .iter()
                .position(|other| (other.view.order, other.view.id) > (before.order, before.id))
                .unwrap_or(others.len());
            let position = change
                .order
                .unwrap_or_else(|| u32::try_from(current + 1).unwrap_or(u32::MAX));
            let mut batch = WriteBatch::for_request(cx);
            check_refs(&mut batch, read, &view)?;
            batch.expect_typed(&VIEWS, &id, Some(row.revision));
            let (view, moved) = stage_order(&mut batch, view, position, others)?;
            if view == before && moved == 0 {
                return Ok(Planned::nothing(view));
            }
            batch.audit(
                AuditDraft::success(audit::VIEW_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", view.name.clone())
                    .with_context("order", view.order.to_string()),
            );
            Ok(Planned::write(
                view.clone(),
                batch,
                format!("change view {}", view.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a view no forwarding rule names; the views after it move up one.
    ///
    /// # Errors
    ///
    /// `dns.view.not_found`, `dns.view.in_use`, 412 when `expect` is stale, or a store or
    /// job error.
    pub async fn delete_view(
        &self,
        cx: &RequestCtx,
        id: ViewId,
        expect: Option<Revision>,
    ) -> ZoneResult<Written> {
        let ((), written) = self
            .execute(cx, |read| {
                let row = Self::dns_view(read, id)?;
                check_expect(expect, row.revision)?;
                let rules = read.scan_typed(&FORWARDERS, KeyRange::all(), usize::MAX, false)?;
                let mut by: Vec<String> = rules
                    .iter()
                    .filter(|(_, rule, _)| rule.view == Some(id))
                    .map(|(_, rule, _)| format!("forwarder:{}", rule.suffix))
                    .collect();
                by.sort();
                if !by.is_empty() {
                    return Err(in_use(
                        &format!("view {}", row.view.name),
                        &id.to_string(),
                        &by,
                    ));
                }
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&VIEWS, &id, Some(row.revision));
                batch.delete_typed(&VIEWS, &id);
                // A rule that starts to name the view meanwhile makes the batch stale.
                for (rule_id, _, revision) in &rules {
                    batch.expect_typed(&FORWARDERS, rule_id, Some(*revision));
                }
                for (at, mut other) in ordered(read)?
                    .into_iter()
                    .filter(|other| other.view.id != id)
                    .enumerate()
                {
                    let number = u32::try_from(at + 1).unwrap_or(u32::MAX);
                    batch.expect_typed(&VIEWS, &other.view.id, Some(other.revision));
                    if other.view.order != number {
                        other.view.order = number;
                        batch.put_typed(&VIEWS, &other.view.id, &other.view)?;
                    }
                }
                batch.audit(
                    AuditDraft::success(audit::VIEW_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", row.view.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete view {}", row.view.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        written.ok_or_else(nothing_written)
    }
}

/// The views that name a scope of `zone` (`scope` `None`: any scope), as `view:<name>`.
///
/// # Errors
///
/// The store's error.
pub fn naming_views(
    read: &dyn ReadView,
    zone: ZoneId,
    scope: Option<&ScopeName>,
) -> ZoneResult<Vec<String>> {
    let mut by: Vec<String> = read
        .scan_typed(&VIEWS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, view, _)| {
            view.scope_map
                .iter()
                .any(|entry| entry.zone == zone && scope.is_none_or(|scope| &entry.scope == scope))
        })
        .map(|(_, view, _)| format!("view:{}", view.name))
        .collect();
    by.sort();
    by.dedup();
    Ok(by)
}

/// The zone side of the scope rule: refuses a change that removes a scope a view names
/// (`after` `None`: the zone's deletion), and makes the batch expect every view row, so a
/// view that starts to name the scope meanwhile makes it stale. A change that removes no
/// scope stages nothing.
///
/// # Errors
///
/// `dns.view.in_use`, or the store's error.
pub fn stage_zone_refs(
    batch: &mut WriteBatch,
    read: &dyn ReadView,
    before: &Zone,
    after: Option<&Zone>,
) -> ZoneResult<()> {
    let removed: Vec<&ScopeName> = before
        .scopes
        .iter()
        .map(|scope| &scope.name)
        .filter(|name| after.is_none_or(|zone| !zone.has_scope(name)))
        .collect();
    if removed.is_empty() {
        return Ok(());
    }
    for scope in &removed {
        let by = naming_views(read, before.id, Some(scope))?;
        if !by.is_empty() {
            let what = match after {
                Some(_) => format!("scope {scope} of zone {}", before.name),
                None => format!("zone {}", before.name),
            };
            return Err(in_use(&what, &before.id.to_string(), &by)
                .param("zone", before.name.to_string())
                .param("scope", scope.to_string()));
        }
    }
    for (id, _, revision) in read.scan_typed(&VIEWS, KeyRange::all(), usize::MAX, false)? {
        batch.expect_typed(&VIEWS, &id, Some(revision));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
