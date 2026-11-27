//! What a delegated session reaches (ADR 0038 decision 5, `docs/plans/windows-takeover-plan.md`
//! section 2.16.2).
//!
//! A delegated session is a session of the administrator who approved a takeover script's
//! request ([`crate::approval`]), presented by the script as a `tnka_` bearer secret from the
//! approval's source address only. It acts for one takeover run (`tenko_core::migrate::run`):
//! its delegation is the run's id. It is default-deny: before any handler runs, the API's
//! authentication layer calls the one check of its requests,
//! [`AuthService::admit_delegated`](crate::AuthService::admit_delegated), which refuses
//! (403 `auth.delegation.refused`, `params.reason`) every (method, route template) that
//! [`TAKEOVER`] does not list (`unlisted`), a listed one whose condition does not hold
//! (`condition`), and every request of a session whose run is not open (`run`) but its own
//! sign-out. So the account routes, which never call `authorize`, are closed to it. Every
//! object a listed route's path names must exist and be the run's: a missing object and an
//! object of another run answer the same 404, so that the session never learns that objects
//! outside its run exist. Inside the list the approver's rights apply as for any session,
//! and each listed handler checks its body against the run's plan.
//!
//! It is never fresh: its `authenticated_at` is the Unix epoch, and every check of a recent
//! sign-in refuses it explicitly too, so it never creates a token, registers a factor, changes
//! a password, deletes a credential or ends sessions. The one listed operation behind a recent
//! sign-in, the creation of a mirror (which mints the mirror's token), is held to
//! [`WithinApproval`](Condition::WithinApproval) instead: within five minutes of the approval
//! on Tenko's clock. So are the pairing and the deletion of a run's mirror, and the removal
//! of a run's scope. A sitting deletes a mirror, and removes or rebuilds a scope, only when an
//! earlier sitting made it ([`made_by_sitting`]), so that one approval allows one cycle.
//!
//! It lives at most [`LIFETIME`] from the approval (or the profile's absolute lifetime, if
//! shorter) and [`IDLE`] since its last recorded request (or the profile's idle lifetime, if
//! shorter); a controller whose clock stands before the session's last recorded request or
//! its approval ([`stands_before`]) ends it, and while the clock guard holds issuing it is
//! refused and kept, so a step back the guard holds never extends it. It ends too at its own
//! sign-out, at its revocation in the session list, and when the approver is disabled or no
//! longer holds the administrator role.
//!
//! A route added to the API later is outside the list until it is listed here, with the plan
//! check of its handler.

use std::time::Duration;

use ipnet::IpNet;
use serde_json::json;
use tenko_core::{
    DelegationId, MirrorId, Principal, Timestamp,
    auth::Delegated,
    clock::stands_before,
    dns::{Acl, AclId, TransferPolicy, ZoneFlip},
    ipam::Stamp,
    migrate::{
        plan::{PlanOperation, TakeoverPlan},
        run::RunRecord,
    },
};

use crate::service::FRESH_AUTHENTICATION;

/// The longest life of a delegated session, from the approval.
pub const LIFETIME: Duration = Duration::from_secs(8 * 3_600);
/// The idle limit of a delegated session under every profile.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// How long after the approval a delegated session may create, pair or delete a mirror, or
/// remove a run's scope.
pub const MIRROR_WINDOW: Duration = FRESH_AUTHENTICATION;

/// When a listed operation is open to a delegated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Whenever the session is alive.
    Always,
    /// Within [`MIRROR_WINDOW`] of the approval.
    WithinApproval,
    /// While no person has started the run's window (a missing run passes, to be refused as
    /// `run`).
    BeforeWindow,
    /// Once a person has started the run's window (a missing run passes, to be refused as
    /// `run`).
    AfterWindow,
}

impl Condition {
    /// Whether the condition holds for `delegated`, whose run row is `run`, at `now`.
    pub fn holds(self, delegated: &Delegated, run: Option<&RunRecord>, now: Timestamp) -> bool {
        match self {
            Self::Always => true,
            Self::WithinApproval => within_approval(delegated, now),
            Self::BeforeWindow => run.is_none_or(|run| run.window.is_none()),
            Self::AfterWindow => run.is_none_or(|run| run.window.is_some()),
        }
    }
}

/// What a path parameter of a listed operation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// A takeover run (`migrate.runs`): the session's own only, else 404
    /// `migrate.run.not_found`.
    Run,
    /// A DNS zone (`dns.zones`) the run created (its `created` stamp names the run), else 404
    /// `dns.zone.not_found`.
    Zone,
    /// A mirror (`migrate.mirrors`) the run created (its `created` stamp names the run), else
    /// 404 `migrate.mirror.not_found`. A deletion reaches only a mirror made before the
    /// session's approval, else 403 `condition`: a sitting never deletes what it made itself.
    Mirror,
}

/// One operation of the allow-list: the method and the route template below the API base, as
/// the OpenAPI document names them, when it is open, and the path parameters that name an
/// object of the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The upper-case method.
    pub method: &'static str,
    /// The route template.
    pub route: &'static str,
    /// When it is open.
    pub condition: Condition,
    /// The path parameters that name an object, each with its kind.
    pub objects: &'static [(&'static str, Object)],
}

/// The operations a takeover run's delegated session reaches. The list of zones holds the
/// run's zones only, a zone it creates is an unserved secondary of its plan, created only
/// before a person started the run's window, as its mirrors are, and it deletes an
/// unserved zone of its run only (each handler's rule). It reads its run's mirrors, pairs its
/// two mirrors with each other and deletes them, and nothing else of a mirror. It prepares the
/// scopes of its plan from its run's mirrors, switched off, and removes such a scope while
/// nobody else touched it ([`scope_in_plan`] and the handlers' rules). Once a person started
/// the run's window it reads its zones' records and transfer state, has them transferred,
/// reads its mirrors' snapshots, and flips its zones with its plan's values only
/// ([`flip_in_plan`]), which writes the run's transfer list ([`run_lists`]).
pub const TAKEOVER: &[Entry] = &[
    Entry {
        method: "GET",
        route: "/health",
        condition: Condition::Always,
        objects: &[],
    },
    Entry {
        method: "GET",
        route: "/system/ca-root",
        condition: Condition::Always,
        objects: &[],
    },
    Entry {
        method: "POST",
        route: "/auth/logout",
        condition: Condition::Always,
        objects: &[],
    },
    Entry {
        method: "POST",
        route: "/migrate/mirrors",
        condition: Condition::WithinApproval,
        objects: &[],
    },
    Entry {
        method: "GET",
        route: "/migrate/runs/{id}",
        condition: Condition::Always,
        objects: &[("id", Object::Run)],
    },
    Entry {
        method: "GET",
        route: "/dns/zones",
        condition: Condition::Always,
        objects: &[],
    },
    Entry {
        method: "POST",
        route: "/dns/zones",
        condition: Condition::BeforeWindow,
        objects: &[],
    },
    Entry {
        method: "DELETE",
        route: "/dns/zones/{id}",
        condition: Condition::Always,
        objects: &[("id", Object::Zone)],
    },
    Entry {
        method: "POST",
        route: "/dns/zones/{id}/flip",
        condition: Condition::AfterWindow,
        objects: &[("id", Object::Zone)],
    },
    Entry {
        method: "GET",
        route: "/dns/zones/{id}/records",
        condition: Condition::AfterWindow,
        objects: &[("id", Object::Zone)],
    },
    Entry {
        method: "GET",
        route: "/dns/zones/{id}/transfer",
        condition: Condition::AfterWindow,
        objects: &[("id", Object::Zone)],
    },
    Entry {
        method: "POST",
        route: "/dns/zones/{id}/transfer",
        condition: Condition::AfterWindow,
        objects: &[("id", Object::Zone)],
    },
    Entry {
        method: "GET",
        route: "/migrate/mirrors/{id}",
        condition: Condition::Always,
        objects: &[("id", Object::Mirror)],
    },
    Entry {
        method: "GET",
        route: "/migrate/mirrors/{id}/snapshot",
        condition: Condition::AfterWindow,
        objects: &[("id", Object::Mirror)],
    },
    Entry {
        method: "PATCH",
        route: "/migrate/mirrors/{id}",
        condition: Condition::WithinApproval,
        objects: &[("id", Object::Mirror)],
    },
    Entry {
        method: "DELETE",
        route: "/migrate/mirrors/{id}",
        condition: Condition::WithinApproval,
        objects: &[("id", Object::Mirror)],
    },
    Entry {
        method: "POST",
        route: "/migrate/mirrors/{id}/scopes/{cidr}/prepare",
        condition: Condition::Always,
        objects: &[("id", Object::Mirror)],
    },
    Entry {
        method: "DELETE",
        route: "/migrate/runs/{id}/scopes/{cidr}",
        condition: Condition::WithinApproval,
        objects: &[("id", Object::Run)],
    },
];

/// The entry of `method` on `route` (the template below the API base), if [`TAKEOVER`] lists
/// it.
pub fn entry(method: &str, route: &str) -> Option<&'static Entry> {
    TAKEOVER
        .iter()
        .find(|entry| entry.method == method && entry.route == route)
}

/// Whether `now` lies within [`MIRROR_WINDOW`] of the approval, on a clock that does not stand
/// before it ([`stands_before`]) and while the clock guard does not hold issuing.
pub fn within_approval(delegated: &Delegated, now: Timestamp) -> bool {
    crate::approval::clock_plausible().is_ok()
        && !stands_before(now, delegated.approved_at)
        && now.saturating_since(delegated.approved_at) <= MIRROR_WINDOW
}

/// Whether the sitting of `delegated`, acting as `principal`, made what `created` stamps: its
/// session, or its run at or after its approval (a clock set back within the tolerance
/// still names the session). Such an object is never deleted, removed or rebuilt in the same
/// sitting (403 `condition`): a mirror whose token the sitting may hold, or a scope it
/// prepared.
pub fn made_by_sitting(delegated: &Delegated, principal: &Principal, created: &Stamp) -> bool {
    created.by == *principal
        || (created.by.delegation() == Some(delegated.id) && created.at >= delegated.approved_at)
}

/// Whether a mirror a delegated session creates stays inside its plan: the Windows DHCP
/// exporter of one of the plan's DHCP servers (the mirror is named for it), its token bound to
/// the mirror host's address alone (`source_prefixes`, a /32 or /128).
pub fn mirror_in_plan(
    plan: &TakeoverPlan,
    name: &str,
    kind: &str,
    source_prefixes: &[String],
) -> bool {
    let host = IpNet::from(plan.mirror_host.address);
    kind == tenko_core::ir::mirror::SourceKindLabel::WINDOWS_DHCP
        && plan
            .dhcp_servers
            .iter()
            .any(|server| server.name.as_str().eq_ignore_ascii_case(name))
        && matches!(source_prefixes, [only] if only.parse::<IpNet>().is_ok_and(|net| net == host))
}

/// Whether the run's plan prepares the scope `cidr`: it lists the prepare and the network.
pub fn scope_in_plan(plan: &TakeoverPlan, cidr: IpNet) -> bool {
    plan.operations.contains(&PlanOperation::Prepare)
        && matches!(cidr, IpNet::V4(net) if plan.scopes.contains(&net))
}

/// Whether a flip of a run's zone is its plan's: the plan flips, and the body is the one of its
/// direction that the zone's create implies (the node under the domain as the SOA's primary
/// name and the one name server; the PDC emulator's first address), compared as a whole, so
/// that no SOA value, name server, primary, port or key of the caller's passes.
pub fn flip_in_plan(plan: &TakeoverPlan, flip: &ZoneFlip) -> bool {
    let (node, domain) = (plan.node_name.as_str(), plan.domain.as_str());
    let pdc = plan.controllers.iter().find(|controller| controller.pdc);
    let planned = match flip {
        ZoneFlip::Primary { .. } => json!({
            "to": "primary",
            "soa": { "mname": format!("{node}.{domain}"), "rname": format!("hostmaster.{domain}") },
            "ns": [format!("{node}.{domain}")],
        }),
        ZoneFlip::Secondary { .. } => json!({
            "to": "secondary",
            "primaries": [{ "address": pdc.and_then(|pdc| pdc.addresses.first()) }],
        }),
    };
    plan.operations.contains(&PlanOperation::Flip)
        && serde_json::from_value::<ZoneFlip>(planned).is_ok_and(|planned| planned == *flip)
}

/// What a run's flip to primary writes for the transfers to the domain controllers: the list
/// `takeover-<run>`, whose id is the run's, with one host prefix per address of the plan's
/// controllers, and the zone's transfer settings that allow it and notify each address,
/// unsigned, since the controllers' secondaries cannot sign (plan section 2.11).
pub fn run_lists(plan: &TakeoverPlan, run: DelegationId) -> Option<(Acl, TransferPolicy)> {
    let addresses: Vec<_> = plan.controllers.iter().flat_map(|c| &c.addresses).collect();
    let (id, name) = (AclId::from_uuid(run.uuid()), format!("takeover-{run}"));
    let entries: Vec<_> = (addresses.iter())
        .map(|a| json!({ "kind": "prefix", "prefix": IpNet::from(**a).to_string() }))
        .collect();
    let notify: Vec<_> = addresses.iter().map(|a| json!({ "address": a })).collect();
    let acl = serde_json::from_value(json!({ "id": id, "name": name, "entries": entries }));
    let transfer = json!({ "allow": [id], "notify": notify, "require_tsig": false });
    Some((acl.ok()?, serde_json::from_value(transfer).ok()?))
}

/// The partner a run's mirror `id` may be paired with: the run's other mirror, in a plan of
/// exactly two DHCP servers (paired whether or not they share a failover relationship).
pub fn run_partner(plan: &TakeoverPlan, run: &RunRecord, id: MirrorId) -> Option<MirrorId> {
    match (plan.dhcp_servers.len(), run.mirrors.as_slice()) {
        (2, [one, other]) if one.mirror == id => Some(other.mirror),
        (2, [one, other]) if other.mirror == id => Some(one.mirror),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{ApprovalId, DelegationId};

    use super::*;

    fn delegated(approved_at: Timestamp) -> Delegated {
        Delegated {
            id: DelegationId::generate(),
            approval: ApprovalId::generate(),
            approved_at,
        }
    }

    fn at(secs: i128) -> Timestamp {
        Timestamp::from_unix_nanos(secs * 1_000_000_000).expect("in range")
    }

    fn admits(delegated: &Delegated, method: &str, route: &str, now: Timestamp) -> bool {
        entry(method, route).is_some_and(|entry| entry.condition.holds(delegated, None, now))
    }

    #[test]
    fn the_list_is_default_deny() {
        let session = delegated(at(1_000));
        assert!(admits(&session, "GET", "/system/ca-root", at(1_000)));
        assert!(admits(&session, "POST", "/auth/logout", at(30_000)));
        assert!(admits(&session, "GET", "/migrate/runs/{id}", at(30_000)));
        assert!(admits(&session, "GET", "/migrate/mirrors/{id}", at(30_000)));
        let prepare = "/migrate/mirrors/{id}/scopes/{cidr}/prepare";
        assert!(admits(&session, "POST", prepare, at(30_000)));
        assert!(admits(&session, "POST", "/dns/zones", at(30_000)));
        for (method, route) in [
            ("PATCH", "/migrate/mirrors/{id}"),
            ("DELETE", "/migrate/mirrors/{id}"),
            ("DELETE", "/migrate/runs/{id}/scopes/{cidr}"),
        ] {
            assert!(
                admits(&session, method, route, at(1_300)),
                "{method} {route}"
            );
            assert!(
                !admits(&session, method, route, at(1_301)),
                "{method} {route}"
            );
        }
        for (method, route) in [
            ("GET", "/auth/session"),
            ("POST", "/auth/tokens"),
            ("POST", "/auth/approvals/{id}/approve"),
            ("DELETE", "/auth/sessions/{id}"),
            ("POST", "/system/ca-root"),
            ("get", "/system/ca-root"),
            ("GET", "/dns/zones/{id}"),
            ("PATCH", "/dns/zones/{id}"),
            ("POST", "/migrate/mirrors/{id}/scopes/{cidr}/takeover"),
            ("GET", "/migrate/runs"),
            ("POST", "/migrate/runs/{id}/close"),
            ("POST", "/migrate/mirrors/{id}/token"),
        ] {
            assert!(
                !admits(&session, method, route, at(1_000)),
                "{method} {route}"
            );
        }
    }

    #[test]
    fn the_window_conditions_hold_with_the_window_only() {
        let session = delegated(at(1_000));
        let mut run = RunRecord {
            id: session.id,
            domain: "corp.example.test".parse().expect("a name"),
            created_at: at(1_000),
            sittings: Vec::new(),
            mirrors: Vec::new(),
            window: None,
        };
        let create = entry("POST", "/dns/zones").expect("listed");
        let after = [
            ("POST", "/dns/zones/{id}/flip"),
            ("GET", "/dns/zones/{id}/records"),
            ("GET", "/dns/zones/{id}/transfer"),
            ("POST", "/dns/zones/{id}/transfer"),
            ("GET", "/migrate/mirrors/{id}/snapshot"),
        ]
        .map(|(method, route)| entry(method, route).expect("listed"));
        // A missing run passes, for the run's own refusal to answer.
        assert!(create.condition.holds(&session, None, at(30_000)));
        assert!(create.condition.holds(&session, Some(&run), at(30_000)));
        for entry in after {
            assert!(entry.condition.holds(&session, None, at(30_000)));
            assert!(!entry.condition.holds(&session, Some(&run), at(30_000)));
        }
        run.window = Some(tenko_core::migrate::run::RunWindow {
            started_by: "admin".to_owned(),
            started_at: at(2_000),
            mirrors: Vec::new(),
        });
        assert!(!create.condition.holds(&session, Some(&run), at(1_000)));
        for entry in after {
            let (method, route) = (entry.method, entry.route);
            let open = entry.condition.holds(&session, Some(&run), at(30_000));
            assert!(open, "{method} {route}");
        }
        let always = entry("GET", "/migrate/runs/{id}").expect("listed");
        assert!(always.condition.holds(&session, Some(&run), at(30_000)));
    }

    #[test]
    fn a_sitting_made_what_its_session_stamped_whatever_the_clock() {
        let session = delegated(at(1_000));
        let principal = |delegation| Principal::User {
            id: tenko_core::UserId::generate(),
            session: tenko_core::SessionId::generate(),
            strength: tenko_core::AuthStrength::Password,
            delegation: Some(delegation),
        };
        let (own, other) = (principal(session.id), principal(session.id));
        let stamp = |by: &Principal, secs| Stamp::new(at(secs), by.clone());
        // The session's own stamp, at and 3 s before the approval (a clock set back).
        assert!(made_by_sitting(&session, &own, &stamp(&own, 1_000)));
        assert!(made_by_sitting(&session, &own, &stamp(&own, 997)));
        // Another session of the run: its stamp after the approval only.
        assert!(made_by_sitting(&session, &own, &stamp(&other, 1_000)));
        assert!(!made_by_sitting(&session, &own, &stamp(&other, 997)));
        let foreign = principal(DelegationId::generate());
        assert!(!made_by_sitting(&session, &own, &stamp(&foreign, 1_000)));
    }

    #[test]
    fn a_scope_is_in_the_plan_when_the_plan_prepares_that_network() {
        let mut plan: TakeoverPlan =
            serde_json::from_value(crate::testing::approval::plan()).expect("a plan");
        let net = |text: &str| text.parse::<IpNet>().expect("a network");
        assert!(scope_in_plan(&plan, net("192.0.2.0/24")));
        for outside in ["192.0.2.0/25", "198.51.100.0/24", "2001:db8::/64"] {
            assert!(!scope_in_plan(&plan, net(outside)), "{outside}");
        }
        plan.operations
            .retain(|operation| *operation != PlanOperation::Prepare);
        assert!(!scope_in_plan(&plan, net("192.0.2.0/24")));
    }

    #[test]
    fn a_flip_is_in_the_plan_with_the_plans_values_only() {
        let mut plan: TakeoverPlan =
            serde_json::from_value(crate::testing::approval::plan()).expect("a plan");
        let flip =
            |body: serde_json::Value| -> ZoneFlip { serde_json::from_value(body).expect("a flip") };
        let soa =
            json!({ "mname": "tenko.corp.example.test", "rname": "hostmaster.corp.example.test" });
        let to_primary = json!({ "to": "primary", "soa": soa, "ns": ["tenko.corp.example.test"] });
        let back = json!({ "to": "secondary", "primaries": [{ "address": "192.0.2.11" }] });
        assert!(flip_in_plan(&plan, &flip(to_primary.clone())));
        assert!(flip_in_plan(&plan, &flip(back.clone())));
        for (mut body, pointer, value) in [
            (
                to_primary.clone(),
                "/soa/mname",
                json!("ns1.corp.example.test"),
            ),
            (to_primary.clone(), "/soa/refresh", json!(60)),
            (to_primary.clone(), "/ns/1", json!("ns1.corp.example.test")),
            (back.clone(), "/primaries/0/address", json!("192.0.2.12")),
            (back.clone(), "/primaries/0/port", json!(5353)),
            (
                back.clone(),
                "/primaries/0/key",
                json!("xfr.corp.example.test"),
            ),
            (
                back.clone(),
                "/primaries/1",
                json!({ "address": "192.0.2.11" }),
            ),
        ] {
            let (parent, field) = pointer.rsplit_once('/').expect("a pointer");
            let target = body.pointer_mut(parent).expect("the parent");
            match target {
                serde_json::Value::Array(items) => items.push(value),
                _ => target[field] = value,
            }
            assert!(!flip_in_plan(&plan, &flip(body)), "{pointer}");
        }
        plan.operations
            .retain(|operation| *operation != PlanOperation::Flip);
        assert!(!flip_in_plan(&plan, &flip(to_primary)));
        assert!(!flip_in_plan(&plan, &flip(back)));
    }

    #[test]
    fn a_runs_list_holds_the_plans_controllers_only() {
        let plan: TakeoverPlan =
            serde_json::from_value(crate::testing::approval::plan()).expect("a plan");
        let run = DelegationId::generate();
        let (acl, transfer) = run_lists(&plan, run).expect("the run's lists");
        assert_eq!(acl.id.uuid(), run.uuid());
        assert_eq!(acl.name, format!("takeover-{run}"));
        let entries = serde_json::to_value(&acl.entries).expect("JSON");
        let expected = json!([
            { "kind": "prefix", "prefix": "192.0.2.11/32", "deny": false },
            { "kind": "prefix", "prefix": "192.0.2.12/32", "deny": false }
        ]);
        assert_eq!(entries, expected);
        let transfer = serde_json::to_value(&transfer).expect("JSON");
        let expected = json!({
            "allow": [acl.id],
            "notify": [{ "address": "192.0.2.11", "port": 53 }, { "address": "192.0.2.12", "port": 53 }],
            "require_tsig": false,
            "xot": false
        });
        assert_eq!(transfer, expected);
    }

    #[test]
    fn a_mirror_pairs_with_the_runs_other_mirror_in_a_two_server_plan_only() {
        let plan: TakeoverPlan =
            serde_json::from_value(crate::testing::approval::plan()).expect("a plan");
        let [one, other, outside] = [(); 3].map(|()| MirrorId::generate());
        let mut run = RunRecord {
            id: DelegationId::generate(),
            domain: plan.domain.clone(),
            created_at: at(1_000),
            sittings: Vec::new(),
            mirrors: Vec::new(),
            window: None,
        };
        for (server, mirror) in plan.dhcp_servers.iter().zip([one, other]) {
            run.mirrors.push(tenko_core::migrate::run::RunMirror {
                server: server.name.clone(),
                mirror,
            });
        }
        assert_eq!(run_partner(&plan, &run, one), Some(other));
        assert_eq!(run_partner(&plan, &run, other), Some(one));
        assert_eq!(run_partner(&plan, &run, outside), None);
        for servers in [1, 3] {
            let mut other_size = plan.clone();
            other_size.dhcp_servers = vec![plan.dhcp_servers[0].clone(); servers];
            assert_eq!(
                run_partner(&other_size, &run, one),
                None,
                "{servers} servers"
            );
        }
        run.mirrors.truncate(1);
        assert_eq!(run_partner(&plan, &run, one), None);
    }

    #[test]
    fn a_mirror_is_created_within_five_minutes_of_the_approval_only() {
        let session = delegated(at(1_000));
        assert!(admits(&session, "POST", "/migrate/mirrors", at(1_000)));
        assert!(admits(&session, "POST", "/migrate/mirrors", at(1_300)));
        assert!(!admits(&session, "POST", "/migrate/mirrors", at(1_301)));
        // A clock within the tolerance before the approval, and one set back further.
        assert!(admits(&session, "POST", "/migrate/mirrors", at(996)));
        assert!(!admits(&session, "POST", "/migrate/mirrors", at(994)));
    }

    #[test]
    fn the_mirror_window_is_closed_while_issuing_is_held() {
        use tenko_core::clock::testing;
        let session = delegated(at(1_000));
        let jump = testing::hold_jump(-240_000, at(1_000));
        assert!(!admits(&session, "POST", "/migrate/mirrors", at(1_061)));
        drop(jump);
        // A forward start gap holds no issuing: the window is open as usual.
        let _gap = testing::hold_gap(240_000);
        assert!(admits(&session, "POST", "/migrate/mirrors", at(1_061)));
    }
}
