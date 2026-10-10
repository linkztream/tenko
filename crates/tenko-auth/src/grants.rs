//! Scoped grants (IAM-01): which rules and roles a grant may carry, how roles order for
//! delegation, and when one scope rule lies inside another.
//!
//! A grant gives a role over one rule: a VRF, a site with or without its child sites, or a
//! prefix with or without the prefixes inside it ([`ScopeRule`]). Tenant and object rules
//! exist in the core model but are not granted in Phase 1. Global roles stay in
//! `UserRecord::roles`.
//!
//! [`rule_within`] decides "a scope inside its own" for delegation and for the grants of a
//! scoped token: it answers `true` only when every object the inner rule covers is covered
//! by the outer one, and is conservative where the containment depends on data that can
//! change (a prefix and its subtree inside a site).

use tenko_core::{Anchors, ObjectKind, ObjectRef, ScopeRule};

use crate::roles::RoleName;

/// Roles a scoped grant may carry: the administrator role stays global (it administers
/// users, settings and the system, which no scope reaches) and the auditor role is global
/// only (owner decision S3-Q18).
pub const fn grantable_role(role: RoleName) -> bool {
    matches!(role, RoleName::Operator | RoleName::Viewer)
}

/// Rules a grant may carry: a VRF, a site or a prefix.
pub const fn grantable_rule(rule: &ScopeRule) -> bool {
    matches!(
        rule,
        ScopeRule::Vrf(_) | ScopeRule::Site { .. } | ScopeRule::Prefix { .. }
    )
}

/// The object a rule is anchored at: the VRF, site or prefix it names.
pub fn rule_object(rule: &ScopeRule) -> ObjectRef {
    match rule {
        ScopeRule::Tenant(id) => ObjectRef::from(*id),
        ScopeRule::Vrf(id) => ObjectRef::from(*id),
        ScopeRule::Site { id, .. } => ObjectRef::from(*id),
        ScopeRule::Prefix { id, .. } => ObjectRef::from(*id),
        ScopeRule::Object(object) => *object,
    }
}

/// Whether the anchors show that the object a rule names exists: a VRF anchors to itself,
/// a site to itself first, a prefix to a chain that starts with itself.
pub fn rule_exists(rule: &ScopeRule, anchors: &Anchors) -> bool {
    match rule {
        ScopeRule::Vrf(id) => anchors.vrf == Some(*id),
        ScopeRule::Site { id, .. } => anchors.sites.first() == Some(id),
        ScopeRule::Prefix { id, .. } => anchors
            .prefixes
            .first()
            .and_then(|chain| chain.first())
            .is_some_and(|first| first == id),
        ScopeRule::Tenant(id) => anchors.tenant == Some(*id),
        ScopeRule::Object(object) => anchors.object == Some(*object),
    }
}

/// Whether `outer` covers everything `inner` covers. `anchors` finds the anchors of a
/// site or prefix (the chain of its ancestors, its VRF); `None` makes every answer that
/// needs them `false`.
///
/// - A VRF lies inside the same VRF.
/// - A site lies inside the same site (a subtree rule covers a rule without subtree) and
///   inside every ancestor's subtree rule.
/// - A prefix lies inside the same prefix (as for sites), inside the subtree rule of every
///   ancestor prefix, and inside the rule of its VRF.
/// - Nothing else: a prefix and the prefixes below it can belong to other sites, and a site
///   spans VRFs.
pub fn rule_within(
    inner: &ScopeRule,
    outer: &ScopeRule,
    anchors: &dyn Fn(&ObjectRef) -> Option<Anchors>,
) -> bool {
    if inner == outer {
        return true;
    }
    match (inner, outer) {
        (ScopeRule::Vrf(a), ScopeRule::Vrf(b)) => a == b,
        (
            ScopeRule::Site {
                id: a,
                subtree: inner_subtree,
            },
            ScopeRule::Site {
                id: b,
                subtree: outer_subtree,
            },
        ) => {
            if a == b {
                *outer_subtree || !*inner_subtree
            } else {
                *outer_subtree
                    && anchors(&ObjectRef::from(*a)).is_some_and(|found| {
                        found.sites.first() == Some(a) && found.sites.contains(b)
                    })
            }
        }
        (
            ScopeRule::Prefix {
                id: a,
                subtree: inner_subtree,
            },
            ScopeRule::Prefix {
                id: b,
                subtree: outer_subtree,
            },
        ) => {
            if a == b {
                *outer_subtree || !*inner_subtree
            } else {
                *outer_subtree
                    && anchors(&ObjectRef::from(*a)).is_some_and(|found| {
                        found
                            .prefixes
                            .first()
                            .is_some_and(|chain| chain.first() == Some(a) && chain.contains(b))
                    })
            }
        }
        (ScopeRule::Prefix { id, .. }, ScopeRule::Vrf(vrf)) => {
            anchors(&ObjectRef::from(*id)).is_some_and(|found| found.vrf == Some(*vrf))
        }
        _ => false,
    }
}

/// A short description of a rule for audit records: `vrf:<id>`, `site:<id>`,
/// `site:<id>/subtree`, `prefix:<id>`, `prefix:<id>/subtree`.
pub fn describe(rule: &ScopeRule) -> String {
    match rule {
        ScopeRule::Tenant(id) => format!("tenant:{id}"),
        ScopeRule::Vrf(id) => format!("vrf:{id}"),
        ScopeRule::Site { id, subtree } => {
            format!("site:{id}{}", if *subtree { "/subtree" } else { "" })
        }
        ScopeRule::Prefix { id, subtree } => {
            format!("prefix:{id}{}", if *subtree { "/subtree" } else { "" })
        }
        ScopeRule::Object(object) => format!("object:{object}"),
    }
}

/// Whether the kind of object a rule names is one the rule kind expects (used when
/// validating that the named object exists).
pub const fn rule_kind(rule: &ScopeRule) -> ObjectKind {
    match rule {
        ScopeRule::Tenant(_) => ObjectKind::Tenant,
        ScopeRule::Vrf(_) => ObjectKind::Vrf,
        ScopeRule::Site { .. } => ObjectKind::Site,
        ScopeRule::Prefix { .. } => ObjectKind::Prefix,
        ScopeRule::Object(object) => object.kind,
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{PrefixId, SiteId, VrfId};

    use super::*;

    struct World {
        vrf: VrfId,
        other_vrf: VrfId,
        root: PrefixId,
        child: PrefixId,
        site: SiteId,
        child_site: SiteId,
    }

    fn world() -> World {
        World {
            vrf: VrfId::generate(),
            other_vrf: VrfId::generate(),
            root: PrefixId::generate(),
            child: PrefixId::generate(),
            site: SiteId::generate(),
            child_site: SiteId::generate(),
        }
    }

    fn anchors_of(world: &World) -> impl Fn(&ObjectRef) -> Option<Anchors> + '_ {
        move |object: &ObjectRef| {
            if *object == ObjectRef::from(world.child) {
                Some(Anchors {
                    object: Some(*object),
                    vrf: Some(world.vrf),
                    prefixes: vec![vec![world.child, world.root]],
                    ..Anchors::default()
                })
            } else if *object == ObjectRef::from(world.root) {
                Some(Anchors {
                    object: Some(*object),
                    vrf: Some(world.vrf),
                    prefixes: vec![vec![world.root]],
                    ..Anchors::default()
                })
            } else if *object == ObjectRef::from(world.child_site) {
                Some(Anchors {
                    object: Some(*object),
                    sites: vec![world.child_site, world.site],
                    ..Anchors::default()
                })
            } else {
                None
            }
        }
    }

    fn prefix(id: PrefixId, subtree: bool) -> ScopeRule {
        ScopeRule::Prefix { id, subtree }
    }

    fn site(id: SiteId, subtree: bool) -> ScopeRule {
        ScopeRule::Site { id, subtree }
    }

    #[test]
    fn prefixes_lie_inside_their_ancestors_subtrees_and_their_vrf() {
        let w = world();
        let anchors = anchors_of(&w);
        assert!(rule_within(
            &prefix(w.child, true),
            &prefix(w.root, true),
            &anchors
        ));
        assert!(rule_within(
            &prefix(w.child, false),
            &prefix(w.root, true),
            &anchors
        ));
        assert!(!rule_within(
            &prefix(w.child, false),
            &prefix(w.root, false),
            &anchors
        ));
        assert!(!rule_within(
            &prefix(w.root, true),
            &prefix(w.child, true),
            &anchors
        ));
        assert!(rule_within(
            &prefix(w.root, false),
            &prefix(w.root, true),
            &anchors
        ));
        assert!(!rule_within(
            &prefix(w.root, true),
            &prefix(w.root, false),
            &anchors
        ));
        assert!(rule_within(
            &prefix(w.child, true),
            &ScopeRule::Vrf(w.vrf),
            &anchors
        ));
        assert!(!rule_within(
            &prefix(w.child, true),
            &ScopeRule::Vrf(w.other_vrf),
            &anchors
        ));
        assert!(!rule_within(
            &ScopeRule::Vrf(w.vrf),
            &prefix(w.root, true),
            &anchors
        ));
    }

    #[test]
    fn sites_lie_inside_their_ancestors_subtrees() {
        let w = world();
        let anchors = anchors_of(&w);
        assert!(rule_within(
            &site(w.child_site, true),
            &site(w.site, true),
            &anchors
        ));
        assert!(!rule_within(
            &site(w.child_site, false),
            &site(w.site, false),
            &anchors
        ));
        assert!(rule_within(
            &site(w.site, false),
            &site(w.site, true),
            &anchors
        ));
        assert!(!rule_within(
            &site(w.site, true),
            &site(w.child_site, true),
            &anchors
        ));
        // A prefix is never inside a site: its subtree can belong to other sites.
        assert!(!rule_within(
            &prefix(w.child, false),
            &site(w.site, true),
            &anchors
        ));
        assert!(!rule_within(
            &ScopeRule::Vrf(w.vrf),
            &site(w.site, true),
            &anchors
        ));
    }

    #[test]
    fn unknown_objects_lie_nowhere_but_in_themselves() {
        let w = world();
        let none = |_: &ObjectRef| None;
        let unknown = PrefixId::generate();
        assert!(rule_within(
            &prefix(unknown, true),
            &prefix(unknown, true),
            &none
        ));
        assert!(!rule_within(
            &prefix(unknown, true),
            &prefix(w.root, true),
            &none
        ));
        assert!(!rule_within(
            &prefix(unknown, true),
            &ScopeRule::Vrf(w.vrf),
            &none
        ));
    }

    #[test]
    fn only_operator_and_viewer_over_vrf_site_and_prefix_rules_are_granted() {
        let w = world();
        assert!(grantable_role(RoleName::Operator) && grantable_role(RoleName::Viewer));
        assert!(!grantable_role(RoleName::Admin) && !grantable_role(RoleName::Auditor));
        assert!(grantable_rule(&ScopeRule::Vrf(w.vrf)));
        assert!(grantable_rule(&site(w.site, false)));
        assert!(grantable_rule(&prefix(w.root, true)));
        assert!(!grantable_rule(&ScopeRule::Tenant(
            tenko_core::TenantId::generate()
        )));
        assert!(!grantable_rule(&ScopeRule::Object(ObjectRef::from(w.root))));
        assert_eq!(
            describe(&prefix(w.root, true)),
            format!("prefix:{}/subtree", w.root)
        );
        assert_eq!(rule_kind(&site(w.site, true)), ObjectKind::Site);
        assert_eq!(rule_object(&ScopeRule::Vrf(w.vrf)), ObjectRef::from(w.vrf));
    }

    #[test]
    fn existence_is_read_from_the_anchors() {
        let w = world();
        let anchors = anchors_of(&w)(&ObjectRef::from(w.child)).expect("anchors");
        assert!(rule_exists(&prefix(w.child, true), &anchors));
        assert!(
            !rule_exists(&prefix(w.root, true), &anchors),
            "an ancestor is not the object"
        );
        assert!(rule_exists(
            &ScopeRule::Vrf(w.vrf),
            &Anchors {
                vrf: Some(w.vrf),
                ..Anchors::default()
            }
        ));
    }
}
