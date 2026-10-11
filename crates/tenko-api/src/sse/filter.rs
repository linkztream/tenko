//! The scoped event filter (IAM-01, WP3.2): what of each server-sent event a principal may
//! see. Installed by the server with
//! `state.events().set_filter(Box::new(ScopedEvents::new(authorizer, scope, store)))`.
//!
//! Events carry references, never bodies, but references name objects, so a scoped
//! principal receives only the references it may read ([`Admission::Only`]; the hub
//! re-encodes the event for it) and an event left without references is not sent:
//!
//! - **Object references** pass when the principal reads the object: a global role or
//!   global token grant passes every object of the kind; a scoped grant passes the objects
//!   whose anchors one of its rules covers ([`tenko_ipam::scope::ScopeIndex`]), and every
//!   tenant, VRF, site and custom field definition as context. Jobs and proposals anchor
//!   to what they change. Anchors are resolved once per reference and index revision and
//!   shared by every subscriber.
//! - **Events without references** (a changed table, an alarm, a metrics snapshot) pass
//!   when the principal reads the kind the topic stands for: IPAM, jobs and discovery for
//!   any grant that reaches them; audit, import, system, admin, connectors, secrets,
//!   cluster and metrics only with a global read (or the token scope of the metrics and
//!   audit objects).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll, Waker},
};

use tenko_auth::authz::{AUDIT_OBJECT, METRICS_OBJECT, is_context_kind};
use tenko_core::{
    Action, AnchorMode, Anchors, Authorizer, ObjectKind, ObjectRef, Principal, Revision,
    ScopeFilter,
};
use tenko_ipam::scope::ScopeIndex;
use tenko_store::{AnchorResolver, ReadConsistency, Store};

use super::{Admission, EventFilter, Topic};

/// Most anchors kept between events.
const CACHE_LIMIT: usize = 4_096;

/// The event filter of scoped authorization.
pub struct ScopedEvents {
    authorizer: Arc<dyn Authorizer>,
    index: Arc<ScopeIndex>,
    store: Arc<dyn Store>,
    /// Anchors by reference, with the index revision they were computed at.
    cache: Mutex<HashMap<ObjectRef, (Revision, Anchors)>>,
}

impl std::fmt::Debug for ScopedEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedEvents").finish_non_exhaustive()
    }
}

impl ScopedEvents {
    /// A filter over the authorizer of the server, the anchors index and the store (for
    /// the targets of jobs and the subjects of proposals).
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        index: Arc<ScopeIndex>,
        store: Arc<dyn Store>,
    ) -> Self {
        Self {
            authorizer,
            index,
            store,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The anchors of an object: from the cache at the index revision, else from the index
    /// (jobs and proposals read from the local copy of the store). The hub asks once per
    /// subscriber with the same references, so an event resolves each reference once.
    fn cached_anchors(&self, object: &ObjectRef) -> Option<Anchors> {
        let revision = self.index.revision();
        {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((at, anchors)) = cache.get(object)
                && *at == revision
            {
                return Some(anchors.clone());
            }
        }
        let anchors = match object.kind {
            ObjectKind::Job | ObjectKind::Proposal => self.stored_anchors(object)?,
            _ => self.index.anchors(object),
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(*object, (revision, anchors.clone()));
        Some(anchors)
    }

    /// The anchors of a job or a proposal, read from the local copy of the store.
    fn stored_anchors(&self, object: &ObjectRef) -> Option<Anchors> {
        // A local read is answered at once; anything else counts as not readable now.
        let mut read = self.store.read(ReadConsistency::Local);
        let Poll::Ready(Ok(view)) = read.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            return None;
        };
        AnchorResolver::anchors(self.index.as_ref(), view.as_ref(), object).ok()
    }

    /// Whether a reference passes, with `scope` the principal's read scope of its kind.
    fn admits(&self, scope: &ScopeFilter, object: &ObjectRef) -> bool {
        match scope {
            ScopeFilter::All => true,
            ScopeFilter::Nothing => false,
            ScopeFilter::Only(_) if is_context_kind(object.kind) => true,
            ScopeFilter::Only(_) => self
                .cached_anchors(object)
                .is_some_and(|anchors| scope.admits(&anchors, AnchorMode::Any)),
        }
    }

    /// Whether `principal` may see an event of `topic` that names no object.
    fn reads_topic(&self, principal: &Principal, topic: Topic) -> bool {
        let reaches = |kind: ObjectKind| {
            !matches!(
                self.authorizer.scope(principal, Action::Read, kind),
                ScopeFilter::Nothing
            )
        };
        let global = |object: ObjectRef| {
            self.authorizer
                .check(principal, Action::Read, &object)
                .is_ok()
        };
        match topic {
            Topic::Ipam => reaches(ObjectKind::Prefix),
            Topic::Jobs => reaches(ObjectKind::Job),
            Topic::Discovery => reaches(ObjectKind::Observation),
            Topic::Audit => global(AUDIT_OBJECT),
            Topic::Metrics => global(METRICS_OBJECT),
            Topic::Import => global(ObjectRef::singleton(ObjectKind::Import)),
            Topic::System => global(ObjectRef::singleton(ObjectKind::System)),
            Topic::Admin => global(ObjectRef::singleton(ObjectKind::User)),
            Topic::Connectors => global(ObjectRef::singleton(ObjectKind::Connector)),
            Topic::Secrets => global(ObjectRef::singleton(ObjectKind::Secret)),
            Topic::Cluster => global(ObjectRef::singleton(ObjectKind::Node)),
        }
    }
}

impl EventFilter for ScopedEvents {
    fn admit(&self, principal: &Principal, topic: Topic, objects: &[ObjectRef]) -> bool {
        self.select(principal, topic, objects) == Admission::All
    }

    fn select(&self, principal: &Principal, topic: Topic, objects: &[ObjectRef]) -> Admission {
        if matches!(principal, Principal::System { .. }) {
            return Admission::All;
        }
        if objects.is_empty() || topic == Topic::Audit {
            return if self.reads_topic(principal, topic) {
                Admission::All
            } else {
                Admission::None
            };
        }
        let mut scopes: Vec<(ObjectKind, ScopeFilter)> = Vec::new();
        let mut kept = Vec::with_capacity(objects.len());
        for object in objects {
            let position = scopes.iter().position(|(kind, _)| *kind == object.kind);
            let position = position.unwrap_or_else(|| {
                let scope = self.authorizer.scope(principal, Action::Read, object.kind);
                scopes.push((object.kind, scope));
                scopes.len() - 1
            });
            if self.admits(&scopes[position].1, object) {
                kept.push(*object);
            }
        }
        if kept.len() == objects.len() {
            Admission::All
        } else if kept.is_empty() {
            Admission::None
        } else {
            Admission::Only(kept)
        }
    }
}
