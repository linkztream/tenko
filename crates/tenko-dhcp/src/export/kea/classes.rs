//! `client-classes`: the filters, the boot echoes, Tenko's classes and the policies.
//!
//! The order is the one Kea evaluates in, and `member()` names only classes above it:
//! `DROP` (the deny filters), `tenko.allow` (the allow filters, when a restricted scope
//! needs it), the boot classes, Tenko's classes by name, the policies' classes in Tenko's
//! order, the policies' option classes, then what the subnets add (pool admission, the
//! scopes' moved options).

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use tenko_core::dhcp::{FilterKind, Join, Match, OptionOwner, OptionValue, Policy, Term};

use super::{
    Cx, at, boot_fields, codes,
    expr::{self, Expr},
    lease_params,
};

/// The class of the allow filters.
pub(crate) const ALLOW: &str = "tenko.allow";
/// The class of PXE clients that get option 60 and option 43 as Tenko sends them.
const PXE: &str = "tenko.pxe";
/// The class of UEFI HTTP boot clients that get option 60 echoed.
const HTTP_BOOT: &str = "tenko.http-boot";
/// Option 43 as Tenko sends it to a PXE client: discovery control 8 (no boot server
/// discovery, use the boot file), then the end.
const PXE_DISCOVERY: [u8; 4] = [0x06, 0x01, 0x08, 0xff];
/// The boot options Tenko sends to boot clients without being asked (WP8.4).
const BOOT_UNASKED: [u16; 6] = [66, 67, 208, 209, 210, 211];

/// Names Tenko's classes and the exported policies.
pub(crate) fn name(cx: &mut Cx<'_>) {
    for class in cx.data.classes.values() {
        cx.class_names.insert(class.id, class.name.clone());
    }
    for policy in cx.policies.clone() {
        let name = match policy.scope.and_then(|scope| cx.data.prefixes.get(&scope)) {
            Some(prefix) => format!("policy.{}.{}", prefix.cidr, policy.name),
            None => format!("policy.{}", policy.name),
        };
        cx.policy_names.insert(policy.id, name);
    }
}

/// The name of a policy's option class, when the policy has options.
pub(crate) fn options_class(cx: &Cx<'_>, policy: &Policy) -> Option<String> {
    let values = cx.values(OptionOwner::Policy(policy.id));
    (!values.is_empty())
        .then(|| {
            cx.policy_names
                .get(&policy.id)
                .map(|name| format!("{name}.options"))
        })
        .flatten()
}

/// The option codes of `dhcp4` a policy sets.
pub(crate) fn policy_codes(cx: &Cx<'_>, policy: &Policy) -> BTreeSet<u16> {
    cx.values(OptionOwner::Policy(policy.id))
        .iter()
        .filter(|value| value.space.is_dhcp4())
        .map(|value| value.code)
        .collect()
}

fn mac_patterns(cx: &Cx<'_>, kind: FilterKind) -> Expr {
    Expr::or(
        cx.data
            .filters
            .values()
            .filter(|filter| filter.kind == kind)
            .map(|filter| {
                expr::of_match(&Match::Mac {
                    pattern: filter.mac,
                })
                .0
            }),
    )
}

fn any_boot(cx: &Cx<'_>) -> bool {
    cx.data
        .option_sets
        .values()
        .flat_map(|set| set.values.iter())
        .any(|value| value.space.is_dhcp4() && value.code == 67)
}

fn holds(cx: &Cx<'_>, code: u16) -> bool {
    cx.data
        .option_sets
        .values()
        .flat_map(|set| set.values.iter())
        .any(|value| value.space.is_dhcp4() && value.code == code)
}

/// The classes before the policies: `DROP`, the allow class, the boot classes and
/// Tenko's classes.
pub(crate) fn early(cx: &mut Cx<'_>) -> Vec<Value> {
    let mut out = Vec::new();
    let denied = cx
        .data
        .filters
        .values()
        .filter(|filter| filter.kind == FilterKind::Deny)
        .count();
    if denied > 0 {
        out.push(json!({
            "name": "DROP",
            "test": mac_patterns(cx, FilterKind::Deny).render(),
        }));
        cx.report.push(
            at("filters", "deny"),
            codes::FILTER_DENY,
            format!(
                "Kea has no deny list: the {denied} deny entr{} became Kea's DROP class, which drops every packet of a matching client without an answer, as Tenko does",
                if denied == 1 { "y" } else { "ies" }
            ),
        );
    }
    if cx.need_allow {
        out.push(json!({
            "name": ALLOW,
            "test": mac_patterns(cx, FilterKind::Allow).render(),
        }));
    }
    if any_boot(cx) {
        let mut pxe = vec![
            cx.options
                .entry(&OptionValue::v4(60, b"PXEClient".to_vec()), true),
        ];
        if !holds(cx, 43) {
            pxe.push(
                cx.options
                    .entry(&OptionValue::v4(43, PXE_DISCOVERY.to_vec()), true),
            );
        }
        out.push(json!({
            "name": PXE,
            "test": expr::of_match(&Match::VendorClass { value: "PXEClient".into(), prefix: true }).0.render(),
            "option-data": pxe,
        }));
        let http = vec![
            cx.options
                .entry(&OptionValue::v4(60, b"HTTPClient".to_vec()), true),
        ];
        out.push(json!({
            "name": HTTP_BOOT,
            "test": expr::of_match(&Match::VendorClass { value: "HTTPClient".into(), prefix: true }).0.render(),
            "option-data": http,
        }));
    }
    let mut classes: Vec<_> = cx.data.classes.values().collect();
    classes.sort_by(|a, b| a.name.cmp(&b.name));
    for class in classes {
        let (test, exact) = expr::of_matches(&class.matches);
        if !exact {
            cx.report.push(
                at("class", &class.name),
                codes::CLASS_PARTIAL,
                "a user class match reads the whole option 77 or its first RFC 3004 instance in Kea; Tenko also matches a later instance",
            );
        }
        let mut entry = Map::new();
        entry.insert("name".into(), json!(class.name));
        entry.insert("test".into(), json!(test.render()));
        if let Some(description) = &class.description {
            entry.insert("user-context".into(), json!({"description": description}));
        }
        out.push(Value::Object(entry));
    }
    out
}

/// A policy's condition, and whether it translated exactly.
fn condition(cx: &mut Cx<'_>, policy: &Policy, label: &str) -> Expr {
    let mut exact = true;
    let mut missing = false;
    let terms: Vec<Expr> = policy
        .condition
        .terms
        .iter()
        .map(|term| match term {
            Term::Class(id) | Term::NotClass(id) => {
                let base = if let Some(name) = cx.class_names.get(id) {
                    Expr::member(name)
                } else {
                    missing = true;
                    Expr::False
                };
                if matches!(term, Term::NotClass(_)) {
                    base.negate()
                } else {
                    base
                }
            }
            Term::Match(item) | Term::NotMatch(item) => {
                let (base, is_exact) = expr::of_match(item);
                exact &= is_exact;
                if matches!(term, Term::NotMatch(_)) {
                    base.negate()
                } else {
                    base
                }
            }
        })
        .collect();
    if missing {
        cx.report.push(
            at("policy", label),
            codes::POLICY_CLASS_MISSING,
            "a term names a class that no longer exists; it is false, as in Tenko",
        );
    }
    if !exact {
        cx.report.push(
            at("policy", label),
            codes::POLICY_PARTIAL,
            "a user class term reads the whole option 77 or its first RFC 3004 instance in Kea; Tenko also matches a later instance",
        );
    }
    match policy.condition.join {
        Join::And => Expr::and(terms),
        Join::Or => Expr::or(terms),
    }
}

fn label(cx: &Cx<'_>, policy: &Policy) -> String {
    match policy.scope.and_then(|scope| cx.data.prefixes.get(&scope)) {
        Some(prefix) => format!("{} ({})", policy.name, prefix.cidr),
        None => format!("{} (server)", policy.name),
    }
}

/// The policies' classes: one per policy with its test and lease times, then the option
/// classes; and the report of the disabled policies and of what did not translate.
pub(crate) fn policies(cx: &mut Cx<'_>) -> Vec<Value> {
    let mut disabled: Vec<&Policy> = cx
        .data
        .policies
        .values()
        .filter(|policy| !policy.enabled)
        .collect();
    disabled.sort_by_key(|policy| (policy.scope, policy.order));
    for policy in disabled {
        let label = label(cx, policy);
        cx.report.push(
            at("policy", label),
            codes::POLICY_DISABLED,
            "the policy is disabled and is left out; Kea has no disabled classes",
        );
    }
    let subnets = cx.subnet_ids.len();
    let mut matches = Vec::new();
    let mut option_classes = Vec::new();
    for policy in cx.policies.clone() {
        let Some(name) = cx.policy_names.get(&policy.id).cloned() else {
            continue;
        };
        let label = label(cx, policy);
        let test = condition(cx, policy, &label);
        let mut entry = Map::new();
        entry.insert("name".into(), json!(name));
        entry.insert("test".into(), json!(test.render()));
        if let Some(lease) = &policy.action.lease {
            lease_params(lease, false, &mut entry);
            if lease.t1_secs.is_some() || lease.t2_secs.is_some() {
                cx.report.push(
                    at("policy", &label),
                    codes::POLICY_TIMERS,
                    "the policy's T1 and T2 are left out: Kea's classes carry lease times but no timers, so the subnet's apply",
                );
            }
            if policy.scope.is_some() && subnets > 1 {
                cx.report.push(
                    at("policy", &label),
                    codes::POLICY_LEASE_EVERYWHERE,
                    "Kea applies a class's lease times in every subnet: the lease time of this scope policy also applies to matching clients of the other scopes",
                );
            }
        }
        if policy.action.ddns.is_some() {
            cx.report.push(
                at("policy", &label),
                codes::POLICY_DDNS,
                "the policy's DDNS settings are left out: Kea 2.6 sets DDNS behaviour per subnet, not per client class",
            );
        }
        let mut context = Map::new();
        context.insert("tenko-policy".into(), json!(policy.name));
        context.insert("order".into(), json!(policy.order));
        if let Some(description) = &policy.description {
            context.insert("description".into(), json!(description));
        }
        entry.insert("user-context".into(), Value::Object(context));
        matches.push(Value::Object(entry));
        if let Some(options) = options_class(cx, policy) {
            let values = cx.values(OptionOwner::Policy(policy.id));
            let data = cx.option_data(values, &label, |value| {
                value.space.is_dhcp4() && BOOT_UNASKED.contains(&value.code)
            });
            let mut entry = Map::new();
            entry.insert("name".into(), json!(options));
            entry.insert("test".into(), json!(Expr::member(&name).render()));
            entry.insert("only-if-required".into(), json!(true));
            entry.insert("option-data".into(), Value::Array(data));
            boot_fields(values, &mut entry);
            option_classes.push(Value::Object(entry));
        }
    }
    matches.extend(option_classes);
    matches
}
