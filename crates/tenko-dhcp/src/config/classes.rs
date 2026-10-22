//! Classes (`dhcp.classes`), policies (`dhcp.policies`) and MAC filters (`dhcp.filters`)
//! as rows with their validation (plan section 2.4, P3-Q12, DHCP-03, DHCP-08). Matching
//! them against requests is WP8.4's (the compiled matcher of the role) and the hook of
//! [`super::effective`].
//!
//! - A class name is unique. A class named by a scope, a pool or a policy term refuses
//!   deletion (`dhcp.class.in_use`).
//! - A policy belongs to a scope or to the server. Its name is unique among the policies of
//!   its scope (or of the server); its classes must exist; its range lies inside its
//!   scope's prefix (`dhcp.pool.outside`). Without an order it goes after the last policy
//!   of its scope. Deleting it deletes its option set.
//! - A filter's MAC pattern is unique (`dhcp.filter.exists`).

use tenko_core::{
    ObjectRef, PrefixId, RequestCtx, Revision,
    audit::AuditDraft,
    dhcp::{
        Class, ClassId, Condition, Filter, FilterId, FilterKind, MacPattern, Match, OptionOwner,
        Policy, PolicyAction, PolicyId, PoolSettings, Scope, Term, audit, codes,
        tables::{CLASSES, FILTERS, POLICIES, POOLS, SCOPES},
    },
};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    ConfigError, ConfigResult, ConfigService, Planned, Written, check_expect, delete_option_set,
    live_prefix,
    scopes::{expect_classes, scope_of},
    stamp, text,
};

/// A class as read, with what names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassRow {
    /// The class.
    pub class: Class,
    /// The scopes, pools and policies that name it (`scope:<prefix>`, `pool:<range>`,
    /// `policy:<id>`).
    pub used_by: Vec<String>,
    /// The revision of the row.
    pub revision: Revision,
}

/// Changes to a class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassChange {
    /// The name.
    pub name: Option<String>,
    /// The matches.
    pub matches: Option<Vec<Match>>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// A policy as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRow {
    /// The policy.
    pub policy: Policy,
    /// The revision of the row.
    pub revision: Revision,
}

/// A new policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPolicy {
    /// The name.
    pub name: String,
    /// The scope; none for the server.
    pub scope: Option<PrefixId>,
    /// The order; after the last policy of the scope when none.
    pub order: Option<u32>,
    /// Whether it applies; true when none.
    pub enabled: Option<bool>,
    /// When it applies.
    pub condition: Condition,
    /// What it does.
    pub action: PolicyAction,
    /// Free text.
    pub description: Option<String>,
}

/// Changes to a policy; the scope does not change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyChange {
    /// The name.
    pub name: Option<String>,
    /// The order.
    pub order: Option<u32>,
    /// Whether it applies.
    pub enabled: Option<bool>,
    /// When it applies.
    pub condition: Option<Condition>,
    /// What it does.
    pub action: Option<PolicyAction>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// Which policies to list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyFilter {
    /// Only the policies of this scope.
    pub scope: Option<PrefixId>,
    /// Only the server-level policies.
    pub server: bool,
}

/// A filter entry as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRow {
    /// The entry.
    pub filter: Filter,
    /// The revision of the row.
    pub revision: Revision,
}

/// Changes to a filter entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterChange {
    /// The addresses.
    pub mac: Option<MacPattern>,
    /// Allow or deny.
    pub kind: Option<FilterKind>,
    /// Why; an empty string clears it.
    pub note: Option<String>,
}

fn class_not_found(id: ClassId) -> ConfigError {
    ConfigError::not_found(codes::CLASS_NOT_FOUND, "class", id)
}

fn policy_not_found(id: PolicyId) -> ConfigError {
    ConfigError::not_found(codes::POLICY_NOT_FOUND, "policy", id)
}

fn filter_not_found(id: FilterId) -> ConfigError {
    ConfigError::not_found(codes::FILTER_NOT_FOUND, "filter entry", id)
}

/// The classes a policy's condition names.
fn policy_classes(condition: &Condition) -> Vec<ClassId> {
    let mut classes = Vec::new();
    for term in &condition.terms {
        if let Term::Class(id) | Term::NotClass(id) = term
            && !classes.contains(id)
        {
            classes.push(*id);
        }
    }
    classes
}

/// Who names each class: scopes, pools and policies, with their revisions for the delete.
struct Users {
    scopes: Vec<(PrefixId, Scope, Revision)>,
    pools: Vec<(tenko_core::RangeId, PoolSettings, Revision)>,
    policies: Vec<(PolicyId, Policy, Revision)>,
}

impl Users {
    fn read(view: &dyn ReadView) -> ConfigResult<Self> {
        Ok(Self {
            scopes: view.scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)?,
            pools: view.scan_typed(&POOLS, KeyRange::all(), usize::MAX, false)?,
            policies: view.scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)?,
        })
    }

    fn of(&self, id: ClassId) -> Vec<String> {
        let mut by: Vec<String> = Vec::new();
        by.extend(
            self.scopes
                .iter()
                .filter(|(_, scope, _)| scope.classes.contains(&id))
                .map(|(prefix, _, _)| format!("scope:{prefix}")),
        );
        by.extend(
            self.pools
                .iter()
                .filter(|(_, pool, _)| pool.classes.contains(&id))
                .map(|(range, _, _)| format!("pool:{range}")),
        );
        by.extend(
            self.policies
                .iter()
                .filter(|(_, policy, _)| policy_classes(&policy.condition).contains(&id))
                .map(|(policy, _, _)| format!("policy:{policy}")),
        );
        by
    }
}

fn unique_class_name(view: &dyn ReadView, class: &Class) -> ConfigResult<()> {
    let taken = view
        .scan_typed(&CLASSES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| id != class.id && other.name == class.name);
    if taken {
        return Err(ConfigError::invalid(
            codes::CLASS_INVALID,
            "name",
            "a class of this name exists",
        ));
    }
    Ok(())
}

/// The policy checks that need the store: the scope exists, the range lies in its prefix,
/// the classes exist (their versions expected in `batch`), the name is unique in the
/// scope.
fn check_policy(view: &dyn ReadView, batch: &mut WriteBatch, policy: &Policy) -> ConfigResult<()> {
    policy.validate()?;
    if let Some(prefix) = policy.scope {
        let (_, revision) = scope_of(view, prefix)?;
        batch.expect_typed(&SCOPES, &prefix, Some(revision));
        let (row, _) = live_prefix(view, prefix)?;
        if let Some(range) = &policy.action.range
            && !(row.cidr.contains(&range.first) && row.cidr.contains(&range.last))
        {
            return Err(ConfigError::new(
                codes::POOL_OUTSIDE,
                400,
                format!("the policy's range lies outside {}", row.cidr),
            )
            .param("range", format!("{}-{}", range.first, range.last))
            .param("prefix", row.cidr.to_string()));
        }
    }
    expect_classes(view, batch, &policy_classes(&policy.condition))?;
    let taken = view
        .scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| {
            id != policy.id && other.scope == policy.scope && other.name == policy.name
        });
    if taken {
        return Err(ConfigError::invalid(
            codes::POLICY_INVALID,
            "name",
            "a policy of this name exists in the scope",
        ));
    }
    Ok(())
}

fn unique_filter(view: &dyn ReadView, filter: &Filter) -> ConfigResult<()> {
    let taken = view
        .scan_typed(&FILTERS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .any(|(id, other, _)| id != filter.id && other.mac == filter.mac);
    if taken {
        return Err(ConfigError::new(
            codes::FILTER_EXISTS,
            409,
            format!("an entry for {} exists", filter.mac),
        )
        .param("mac", filter.mac.to_string()));
    }
    Ok(())
}

impl ConfigService {
    // ----- classes ----------------------------------------------------------------------

    /// Every class, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn classes(view: &dyn ReadView) -> ConfigResult<Vec<ClassRow>> {
        let users = Users::read(view)?;
        let mut rows: Vec<ClassRow> = view
            .scan_typed(&CLASSES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(id, class, revision)| ClassRow {
                used_by: users.of(id),
                class,
                revision,
            })
            .collect();
        rows.sort_by(|a, b| {
            a.class
                .name
                .cmp(&b.class.name)
                .then(a.class.id.cmp(&b.class.id))
        });
        Ok(rows)
    }

    /// One class.
    ///
    /// # Errors
    ///
    /// `dhcp.class.not_found`, or the store's error.
    pub fn class(view: &dyn ReadView, id: ClassId) -> ConfigResult<ClassRow> {
        let (class, revision) = view
            .get_typed(&CLASSES, &id)?
            .ok_or_else(|| class_not_found(id))?;
        Ok(ClassRow {
            used_by: Users::read(view)?.of(id),
            class,
            revision,
        })
    }

    /// Creates a class.
    ///
    /// # Errors
    ///
    /// `dhcp.class.invalid` (also for a taken name), or a store or job error.
    pub async fn create_class(
        &self,
        cx: &RequestCtx,
        name: String,
        matches: Vec<Match>,
        description: Option<String>,
    ) -> ConfigResult<(Class, Written)> {
        let now = stamp(cx);
        let class = Class {
            id: ClassId::generate(),
            name,
            matches,
            description: text(description.as_deref()),
            created: now.clone(),
            updated: now,
        };
        class.validate()?;
        self.execute_write(cx, |view| {
            unique_class_name(view, &class)?;
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&CLASSES, &class.id, None);
            batch.put_typed(&CLASSES, &class.id, &class)?;
            batch.audit(
                AuditDraft::success(audit::CLASS_CREATE, vec![ObjectRef::from(class.id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", class.name.clone()),
            );
            Ok(Planned::write(
                class.clone(),
                batch,
                format!("create the DHCP class {}", class.name),
                vec![ObjectRef::from(class.id)],
            ))
        })
        .await
    }

    /// Changes a class.
    ///
    /// # Errors
    ///
    /// `dhcp.class.not_found`, `dhcp.class.invalid`, 412 when `expect` is stale, or a store
    /// or job error.
    pub async fn update_class(
        &self,
        cx: &RequestCtx,
        id: ClassId,
        change: ClassChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(Class, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&CLASSES, &id)?
                .ok_or_else(|| class_not_found(id))?;
            check_expect(expect, revision)?;
            let mut after = before.clone();
            if let Some(name) = &change.name {
                after.name.clone_from(name);
            }
            if let Some(matches) = &change.matches {
                after.matches.clone_from(matches);
            }
            if let Some(description) = &change.description {
                after.description = text(Some(description));
            }
            after.validate()?;
            if after == before {
                return Ok(Planned::nothing(after));
            }
            unique_class_name(view, &after)?;
            after.updated = stamp(cx);
            let mut batch = WriteBatch::for_request(cx);
            batch.expect_typed(&CLASSES, &id, Some(revision));
            batch.put_typed(&CLASSES, &id, &after)?;
            batch.audit(
                AuditDraft::success(audit::CLASS_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", after.name.clone()),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the DHCP class {}", after.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a class nothing names.
    ///
    /// # Errors
    ///
    /// `dhcp.class.not_found`, `dhcp.class.in_use`, 412 when `expect` is stale, or a store
    /// or job error.
    pub async fn delete_class(
        &self,
        cx: &RequestCtx,
        id: ClassId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (class, revision) = view
                    .get_typed(&CLASSES, &id)?
                    .ok_or_else(|| class_not_found(id))?;
                check_expect(expect, revision)?;
                let users = Users::read(view)?;
                let by = users.of(id);
                if !by.is_empty() {
                    return Err(ConfigError::new(
                        codes::CLASS_IN_USE,
                        409,
                        format!("the class {} is named by {}", class.name, by.join(", ")),
                    )
                    .param("id", id.to_string())
                    .param("by", by.join(",")));
                }
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&CLASSES, &id, Some(revision));
                batch.delete_typed(&CLASSES, &id);
                // A scope, pool or policy that starts to name the class meanwhile makes the
                // batch stale; their writes expect the class's version as well.
                for (prefix, _, revision) in &users.scopes {
                    batch.expect_typed(&SCOPES, prefix, Some(*revision));
                }
                for (range, _, revision) in &users.pools {
                    batch.expect_typed(&POOLS, range, Some(*revision));
                }
                for (policy, _, revision) in &users.policies {
                    batch.expect_typed(&POLICIES, policy, Some(*revision));
                }
                batch.audit(
                    AuditDraft::success(audit::CLASS_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", class.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the DHCP class {}", class.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        Ok(written)
    }

    // ----- policies ---------------------------------------------------------------------

    /// The policies, by scope (server-level ones last) and order.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn policies(view: &dyn ReadView, filter: PolicyFilter) -> ConfigResult<Vec<PolicyRow>> {
        let mut rows: Vec<PolicyRow> = view
            .scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(_, policy, _)| {
                filter.scope.is_none_or(|scope| policy.scope == Some(scope))
                    && (!filter.server || policy.scope.is_none())
            })
            .map(|(_, policy, revision)| PolicyRow { policy, revision })
            .collect();
        rows.sort_by_key(|row| {
            (
                row.policy.scope.is_none(),
                row.policy.scope,
                row.policy.order,
                row.policy.id,
            )
        });
        Ok(rows)
    }

    /// One policy.
    ///
    /// # Errors
    ///
    /// `dhcp.policy.not_found`, or the store's error.
    pub fn policy(view: &dyn ReadView, id: PolicyId) -> ConfigResult<PolicyRow> {
        let (policy, revision) = view
            .get_typed(&POLICIES, &id)?
            .ok_or_else(|| policy_not_found(id))?;
        Ok(PolicyRow { policy, revision })
    }

    /// Creates a policy.
    ///
    /// # Errors
    ///
    /// `dhcp.policy.invalid`, `dhcp.scope.not_found`, `dhcp.pool.outside`,
    /// `dhcp.class.not_found`, `dhcp.lease_times.invalid`, `dhcp.ddns.invalid`, or a store
    /// or job error.
    pub async fn create_policy(
        &self,
        cx: &RequestCtx,
        new: NewPolicy,
    ) -> ConfigResult<(Policy, Written)> {
        let id = PolicyId::generate();
        self.execute_write(cx, |view| {
            let order = match new.order {
                Some(order) => order,
                None => view
                    .scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)?
                    .into_iter()
                    .filter(|(_, policy, _)| policy.scope == new.scope)
                    .map(|(_, policy, _)| policy.order.saturating_add(1))
                    .max()
                    .unwrap_or(0),
            };
            let now = stamp(cx);
            let policy = Policy {
                id,
                name: new.name.clone(),
                scope: new.scope,
                order,
                enabled: new.enabled.unwrap_or(true),
                condition: new.condition.clone(),
                action: new.action.clone(),
                description: text(new.description.as_deref()),
                created: now.clone(),
                updated: now,
            };
            let mut batch = WriteBatch::for_request(cx);
            check_policy(view, &mut batch, &policy)?;
            batch.expect_typed(&POLICIES, &id, None);
            batch.put_typed(&POLICIES, &id, &policy)?;
            batch.audit(
                AuditDraft::success(audit::POLICY_CREATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", policy.name.clone()),
            );
            Ok(Planned::write(
                policy.clone(),
                batch,
                format!("create the DHCP policy {}", policy.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Changes a policy, its order included.
    ///
    /// # Errors
    ///
    /// `dhcp.policy.not_found`, the validation codes of [`ConfigService::create_policy`],
    /// 412 when `expect` is stale, or a store or job error.
    pub async fn update_policy(
        &self,
        cx: &RequestCtx,
        id: PolicyId,
        change: PolicyChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(Policy, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&POLICIES, &id)?
                .ok_or_else(|| policy_not_found(id))?;
            check_expect(expect, revision)?;
            let mut after = before.clone();
            if let Some(name) = &change.name {
                after.name.clone_from(name);
            }
            if let Some(order) = change.order {
                after.order = order;
            }
            if let Some(enabled) = change.enabled {
                after.enabled = enabled;
            }
            if let Some(condition) = &change.condition {
                after.condition.clone_from(condition);
            }
            if let Some(action) = &change.action {
                after.action.clone_from(action);
            }
            if let Some(description) = &change.description {
                after.description = text(Some(description));
            }
            if after == before {
                after.validate()?;
                return Ok(Planned::nothing(after));
            }
            after.updated = stamp(cx);
            let mut batch = WriteBatch::for_request(cx);
            check_policy(view, &mut batch, &after)?;
            batch.expect_typed(&POLICIES, &id, Some(revision));
            batch.put_typed(&POLICIES, &id, &after)?;
            batch.audit(
                AuditDraft::success(audit::POLICY_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("name", after.name.clone()),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the DHCP policy {}", after.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a policy with its option set.
    ///
    /// # Errors
    ///
    /// `dhcp.policy.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete_policy(
        &self,
        cx: &RequestCtx,
        id: PolicyId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (policy, revision) = view
                    .get_typed(&POLICIES, &id)?
                    .ok_or_else(|| policy_not_found(id))?;
                check_expect(expect, revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&POLICIES, &id, Some(revision));
                batch.delete_typed(&POLICIES, &id);
                delete_option_set(view, &mut batch, OptionOwner::Policy(id))?;
                batch.audit(
                    AuditDraft::success(audit::POLICY_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("name", policy.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the DHCP policy {}", policy.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        Ok(written)
    }

    // ----- filters ----------------------------------------------------------------------

    /// Every filter entry, by pattern.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn filters(view: &dyn ReadView) -> ConfigResult<Vec<FilterRow>> {
        let mut rows: Vec<FilterRow> = view
            .scan_typed(&FILTERS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, filter, revision)| FilterRow { filter, revision })
            .collect();
        rows.sort_by(|a, b| {
            a.filter
                .mac
                .to_string()
                .cmp(&b.filter.mac.to_string())
                .then(a.filter.id.cmp(&b.filter.id))
        });
        Ok(rows)
    }

    /// One filter entry.
    ///
    /// # Errors
    ///
    /// `dhcp.filter.not_found`, or the store's error.
    pub fn filter(view: &dyn ReadView, id: FilterId) -> ConfigResult<FilterRow> {
        let (filter, revision) = view
            .get_typed(&FILTERS, &id)?
            .ok_or_else(|| filter_not_found(id))?;
        Ok(FilterRow { filter, revision })
    }

    /// Adds a filter entry.
    ///
    /// # Errors
    ///
    /// `dhcp.filter.invalid`, `dhcp.filter.exists`, or a store or job error.
    pub async fn create_filter(
        &self,
        cx: &RequestCtx,
        mac: MacPattern,
        kind: FilterKind,
        note: Option<String>,
    ) -> ConfigResult<(Filter, Written)> {
        let now = stamp(cx);
        let filter = Filter {
            id: FilterId::generate(),
            mac,
            kind,
            note: text(note.as_deref()),
            created: now.clone(),
            updated: now,
        };
        filter.validate()?;
        self.execute_write(cx, |view| {
            unique_filter(view, &filter)?;
            let mut batch = WriteBatch::for_request(cx);
            for (id, _, revision) in
                view.scan_typed(&FILTERS, KeyRange::all(), usize::MAX, false)?
            {
                batch.expect_typed(&FILTERS, &id, Some(revision));
            }
            batch.expect_typed(&FILTERS, &filter.id, None);
            batch.put_typed(&FILTERS, &filter.id, &filter)?;
            batch.audit(
                AuditDraft::success(audit::FILTER_CREATE, vec![ObjectRef::from(filter.id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("mac", filter.mac.to_string())
                    .with_context("kind", kind_name(filter.kind)),
            );
            Ok(Planned::write(
                filter.clone(),
                batch,
                format!("{} {} in DHCP", kind_name(filter.kind), filter.mac),
                vec![ObjectRef::from(filter.id)],
            ))
        })
        .await
    }

    /// Changes a filter entry.
    ///
    /// # Errors
    ///
    /// `dhcp.filter.not_found`, `dhcp.filter.invalid`, `dhcp.filter.exists`, 412 when
    /// `expect` is stale, or a store or job error.
    pub async fn update_filter(
        &self,
        cx: &RequestCtx,
        id: FilterId,
        change: FilterChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(Filter, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&FILTERS, &id)?
                .ok_or_else(|| filter_not_found(id))?;
            check_expect(expect, revision)?;
            let mut after = before.clone();
            if let Some(mac) = change.mac {
                after.mac = mac;
            }
            if let Some(kind) = change.kind {
                after.kind = kind;
            }
            if let Some(note) = &change.note {
                after.note = text(Some(note));
            }
            after.validate()?;
            if after == before {
                return Ok(Planned::nothing(after));
            }
            unique_filter(view, &after)?;
            after.updated = stamp(cx);
            let mut batch = WriteBatch::for_request(cx);
            if after.mac != before.mac {
                for (other, _, revision) in
                    view.scan_typed(&FILTERS, KeyRange::all(), usize::MAX, false)?
                {
                    if other != id {
                        batch.expect_typed(&FILTERS, &other, Some(revision));
                    }
                }
            }
            batch.expect_typed(&FILTERS, &id, Some(revision));
            batch.put_typed(&FILTERS, &id, &after)?;
            batch.audit(
                AuditDraft::success(audit::FILTER_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("mac", after.mac.to_string())
                    .with_context("kind", kind_name(after.kind)),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the DHCP filter entry {}", after.mac),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a filter entry.
    ///
    /// # Errors
    ///
    /// `dhcp.filter.not_found`, 412 when `expect` is stale, or a store or job error.
    pub async fn delete_filter(
        &self,
        cx: &RequestCtx,
        id: FilterId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (filter, revision) = view
                    .get_typed(&FILTERS, &id)?
                    .ok_or_else(|| filter_not_found(id))?;
                check_expect(expect, revision)?;
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&FILTERS, &id, Some(revision));
                batch.delete_typed(&FILTERS, &id);
                batch.audit(
                    AuditDraft::success(audit::FILTER_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("mac", filter.mac.to_string()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the DHCP filter entry {}", filter.mac),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        Ok(written)
    }
}

fn kind_name(kind: FilterKind) -> &'static str {
    match kind {
        FilterKind::Allow => "allow",
        FilterKind::Deny => "deny",
    }
}
