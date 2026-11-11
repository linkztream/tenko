//! The check journal of one request: what the request's principal had to pass while it
//! ran.
//!
//! The API's idempotency middleware runs the handler of a keyed `POST` inside [`record`]
//! and keeps the journal with the stored response, so that a replay of the response first
//! runs the same checks again against the principal as it is now: a role removed since, a
//! grant narrowed or a sign-in that is no longer fresh refuses the replay as it would
//! refuse the request.
//!
//! The journal is a tokio task-local. [`RbacAuthorizer`](crate::authz::RbacAuthorizer)
//! notes every check that passes and every scope it computes, and the fresh-session rule
//! of the account service notes that it was met; outside [`record`] a note is one
//! task-local presence test and nothing else (no allocation). Only what concerns the
//! principal the journal was opened for is noted: a check the handler makes as the system
//! is not the caller's to pass again. A check made on another task or a blocking thread is
//! not seen, which is why the middleware also compares a stamp of the principal's roles,
//! strength, session and flags, and why a request whose journal is empty is never
//! replayed.
//!
//! What is kept is what running the checks again needs, and no copy of a grant:
//!
//! - **Checks**, as (action, object). For a kind that scoped grants reach
//!   ([`is_scoped_kind`]) the object is the kind as a whole ([`anywhere`]): whether one
//!   object lies in a scope depends on where the object is now (it may be gone after the
//!   request that is replayed deleted it), while what the principal may do is its grants.
//! - **Scopes**, as (action, kind, SHA-256 of the scope filter): for a scoped kind, the
//!   objects the principal's grants reach. A replay compares the filter as it is now; a
//!   grant narrowed (or widened) since changes it.
//! - **The fresh-session flag**.
//!
//! At most [`MAX_CHECKS`] distinct entries of each list are kept; a request that makes
//! more overflows the journal and cannot be replayed.

use std::{cell::RefCell, future::Future};

use sha2::{Digest as _, Sha256};
use tenko_core::{Action, ObjectKind, ObjectRef, Principal, ScopeFilter, codec::to_cbor};

use crate::authz::{anywhere, is_scoped_kind};

/// Most distinct entries one list of a journal keeps; more overflow it.
pub const MAX_CHECKS: usize = 1024;

/// What one request needed to pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journal {
    /// The checks that passed, distinct, in order; scoped kinds as the kind as a whole.
    pub checks: Vec<(Action, ObjectRef)>,
    /// The scopes of scoped kinds, distinct, in order: SHA-256 of the scope filter.
    pub scopes: Vec<(Action, ObjectKind, [u8; 32])>,
    /// Whether the request needed a sign-in within the last five minutes, and had it.
    pub fresh_session: bool,
    /// Whether the request made more than [`MAX_CHECKS`] distinct checks or scopes, or its
    /// scope of one kind changed while it ran.
    pub overflow: bool,
}

impl Journal {
    /// Whether nothing was noted.
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty() && self.scopes.is_empty() && !self.fresh_session && !self.overflow
    }
}

/// A journal and the principal it notes for.
struct Open {
    principal: Principal,
    journal: Journal,
}

tokio::task_local! {
    static JOURNAL: RefCell<Open>;
}

/// Runs `future` with a journal for `principal` and returns its output with what the
/// journal noted.
pub async fn record<F: Future>(principal: Principal, future: F) -> (F::Output, Journal) {
    let open = Open {
        principal,
        journal: Journal::default(),
    };
    JOURNAL
        .scope(RefCell::new(open), async move {
            let output = future.await;
            let journal = JOURNAL.with(|open| std::mem::take(&mut open.borrow_mut().journal));
            (output, journal)
        })
        .await
}

/// SHA-256 of a scope filter, as a journal keeps it. Canonical: the rules are digested as
/// a set (each rule encoded whole, sorted, without duplicates), so the same grants in
/// another order or after a reload of the index give the same digest. The match names
/// every variant and each rule is encoded with all its fields, so a field or variant added
/// to the types takes part without a change here.
pub fn scope_digest(filter: &ScopeFilter) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"tenko scope v1\0");
    match filter {
        ScopeFilter::All => hash.update(b"all"),
        ScopeFilter::Nothing => hash.update(b"nothing"),
        ScopeFilter::Only(rules) => {
            hash.update(b"only");
            let mut encoded: Vec<Vec<u8>> = rules
                .iter()
                .map(|rule| {
                    to_cbor(rule)
                        .map(|bytes| bytes.to_vec())
                        .unwrap_or_default()
                })
                .collect();
            encoded.sort();
            encoded.dedup();
            for rule in encoded {
                hash.update(u64::try_from(rule.len()).unwrap_or(u64::MAX).to_be_bytes());
                hash.update(&rule);
            }
        }
    }
    hash.finalize().into()
}

/// Inserts `entry` into the sorted `list`; `false` when the list is full.
fn insert<T: Ord>(list: &mut Vec<T>, entry: T) -> bool {
    match list.binary_search(&entry) {
        Ok(_) => true,
        Err(_) if list.len() == MAX_CHECKS => false,
        Err(at) => {
            list.insert(at, entry);
            true
        }
    }
}

/// Notes a check that passed for `principal`, when a journal records this task for it.
/// Returns whether the scope of the object's kind is wanted and not noted yet (the caller
/// computes it, which notes it). The authorizer calls it; it is public for authorizers and
/// tests outside this crate. A note can only make a replay stricter.
pub fn note_check(principal: &Principal, action: Action, object: &ObjectRef) -> bool {
    JOURNAL
        .try_with(|open| {
            let mut open = open.borrow_mut();
            if open.principal != *principal || open.journal.overflow {
                return false;
            }
            let scoped = is_scoped_kind(object.kind);
            let entry = (
                action,
                if scoped {
                    anywhere(object.kind)
                } else {
                    *object
                },
            );
            if !insert(&mut open.journal.checks, entry) {
                open.journal.overflow = true;
                return false;
            }
            scoped
                && !open
                    .journal
                    .scopes
                    .iter()
                    .any(|(noted, kind, _)| *noted == action && *kind == object.kind)
        })
        .unwrap_or(false)
}

/// Notes the scope a principal's grants give it on a kind, when a journal records this
/// task for the principal.
pub fn note_scope(principal: &Principal, action: Action, kind: ObjectKind, filter: &ScopeFilter) {
    let _ = JOURNAL.try_with(|open| {
        let mut open = open.borrow_mut();
        if open.principal != *principal || open.journal.overflow || !is_scoped_kind(kind) {
            return;
        }
        let digest = scope_digest(filter);
        if let Some(noted) = open
            .journal
            .scopes
            .iter()
            .find(|(noted, noted_kind, _)| *noted == action && *noted_kind == kind)
        {
            // Two different answers within one request: the grants changed under it.
            if noted.2 != digest {
                open.journal.overflow = true;
            }
            return;
        }
        if !insert(&mut open.journal.scopes, (action, kind, digest)) {
            open.journal.overflow = true;
        }
    });
}

/// Notes that the request met the fresh-session rule, when a journal records this task.
pub fn note_fresh_session() {
    let _ = JOURNAL.try_with(|open| open.borrow_mut().journal.fresh_session = true);
}

#[cfg(test)]
mod tests {
    use tenko_core::SystemComponent;

    use super::*;

    fn caller() -> Principal {
        Principal::Token {
            id: uuid::Uuid::from_u128(1).into(),
            owner: uuid::Uuid::from_u128(2).into(),
        }
    }

    #[tokio::test]
    async fn notes_inside_a_record_for_its_principal_only() {
        // Outside a record nothing happens and nothing fails.
        assert!(!note_check(
            &caller(),
            Action::Read,
            &anywhere(ObjectKind::Prefix)
        ));
        note_fresh_session();

        let one = ObjectRef::new(ObjectKind::Prefix, uuid::Uuid::from_u128(7));
        let node = ObjectRef::new(ObjectKind::Node, uuid::Uuid::from_u128(8));
        let ((), journal) = record(caller(), async {
            // A scoped kind is noted as the kind, and its scope is wanted once.
            assert!(note_check(&caller(), Action::Update, &one));
            note_scope(
                &caller(),
                Action::Update,
                ObjectKind::Prefix,
                &ScopeFilter::All,
            );
            assert!(!note_check(
                &caller(),
                Action::Update,
                &anywhere(ObjectKind::Prefix)
            ));
            // A global-only kind keeps its object.
            assert!(!note_check(&caller(), Action::Read, &node));
            // A check made as the system is not the caller's.
            let system = Principal::system(SystemComponent::Api);
            assert!(!note_check(&system, Action::Delete, &one));
            note_scope(
                &system,
                Action::Delete,
                ObjectKind::Prefix,
                &ScopeFilter::All,
            );
            note_fresh_session();
        })
        .await;
        assert_eq!(
            journal.checks,
            vec![
                (Action::Read, node),
                (Action::Update, anywhere(ObjectKind::Prefix)),
            ]
        );
        assert_eq!(
            journal.scopes,
            vec![(
                Action::Update,
                ObjectKind::Prefix,
                scope_digest(&ScopeFilter::All)
            )]
        );
        assert!(journal.fresh_session);
        assert!(!journal.overflow);

        let ((), empty) = record(caller(), async {}).await;
        assert!(empty.is_empty());
    }

    #[test]
    fn the_scope_digest_is_canonical() {
        use tenko_core::{ScopeRule, SiteId, TenantId};
        let tenant = ScopeRule::Tenant(TenantId::from(uuid::Uuid::from_u128(3)));
        let site = ScopeRule::Site {
            id: SiteId::from(uuid::Uuid::from_u128(4)),
            subtree: true,
        };
        let one = ScopeFilter::Only(vec![tenant.clone(), site.clone()]);
        let other_order = ScopeFilter::Only(vec![site.clone(), tenant.clone(), site.clone()]);
        assert_eq!(scope_digest(&one), scope_digest(&other_order));
        let narrower = ScopeFilter::Only(vec![tenant]);
        assert_ne!(scope_digest(&one), scope_digest(&narrower));
        let not_subtree = ScopeFilter::Only(vec![ScopeRule::Site {
            id: SiteId::from(uuid::Uuid::from_u128(4)),
            subtree: false,
        }]);
        assert_ne!(
            scope_digest(&not_subtree),
            scope_digest(&ScopeFilter::Only(vec![site]))
        );
        assert_ne!(
            scope_digest(&ScopeFilter::All),
            scope_digest(&ScopeFilter::Nothing)
        );
        assert_ne!(
            scope_digest(&ScopeFilter::Nothing),
            scope_digest(&ScopeFilter::Only(Vec::new()))
        );
    }

    #[tokio::test]
    async fn too_many_checks_or_a_changing_scope_overflow_the_journal() {
        let ((), journal) = record(caller(), async {
            for n in 0..=MAX_CHECKS {
                let id = uuid::Uuid::from_u128(n as u128 + 1);
                note_check(
                    &caller(),
                    Action::Read,
                    &ObjectRef::new(ObjectKind::Node, id),
                );
            }
        })
        .await;
        assert!(journal.overflow);
        assert_eq!(journal.checks.len(), MAX_CHECKS);
        assert!(!journal.is_empty());

        let ((), journal) = record(caller(), async {
            note_scope(
                &caller(),
                Action::Read,
                ObjectKind::Prefix,
                &ScopeFilter::All,
            );
            note_scope(
                &caller(),
                Action::Read,
                ObjectKind::Prefix,
                &ScopeFilter::Nothing,
            );
        })
        .await;
        assert!(journal.overflow);
    }
}
