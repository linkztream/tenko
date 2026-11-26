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
//! on Tenko's clock.
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
use tenko_core::{Timestamp, auth::Delegated, clock::stands_before, migrate::plan::TakeoverPlan};

use crate::service::FRESH_AUTHENTICATION;

/// The longest life of a delegated session, from the approval.
pub const LIFETIME: Duration = Duration::from_secs(8 * 3_600);
/// The idle limit of a delegated session under every profile.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// How long after the approval a delegated session may create a mirror.
pub const MIRROR_WINDOW: Duration = FRESH_AUTHENTICATION;

/// When a listed operation is open to a delegated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Whenever the session is alive.
    Always,
    /// Within [`MIRROR_WINDOW`] of the approval.
    WithinApproval,
}

impl Condition {
    /// Whether the condition holds for `delegated` at `now`.
    pub fn holds(self, delegated: &Delegated, now: Timestamp) -> bool {
        match self {
            Self::Always => true,
            Self::WithinApproval => within_approval(delegated, now),
        }
    }
}

/// What a path parameter of a listed operation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// A takeover run (`migrate.runs`): the session's own only, else 404
    /// `migrate.run.not_found`.
    Run,
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

/// The operations a takeover run's delegated session reaches. The reads of its zones, mirrors
/// and jobs, and the operations of the run's phases join with their plan checks and the run's
/// stages; the flip and the takeover only after the window started.
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
        entry(method, route).is_some_and(|entry| entry.condition.holds(delegated, now))
    }

    #[test]
    fn the_list_is_default_deny() {
        let session = delegated(at(1_000));
        assert!(admits(&session, "GET", "/system/ca-root", at(1_000)));
        assert!(admits(&session, "POST", "/auth/logout", at(30_000)));
        assert!(admits(&session, "GET", "/migrate/runs/{id}", at(30_000)));
        for (method, route) in [
            ("GET", "/auth/session"),
            ("POST", "/auth/tokens"),
            ("POST", "/auth/approvals/{id}/approve"),
            ("DELETE", "/auth/sessions/{id}"),
            ("POST", "/system/ca-root"),
            ("get", "/system/ca-root"),
            ("POST", "/dns/zones/{id}/flip"),
            ("POST", "/migrate/mirrors/{id}/scopes/{cidr}/takeover"),
            ("GET", "/migrate/runs"),
            ("POST", "/migrate/runs/{id}/close"),
        ] {
            assert!(
                !admits(&session, method, route, at(1_000)),
                "{method} {route}"
            );
        }
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
