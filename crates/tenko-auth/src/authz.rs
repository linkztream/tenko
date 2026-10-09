//! The [`Authorizer`] of Slice 1: global roles, the strength rules of TGL-02, TGL-03 and
//! IAM-07 (the index follows `vault.operator_index`, so the first operator secret takes
//! effect at once), and [`ScopeFilter::All`] or [`ScopeFilter::Nothing`] (object scopes are Slice 3).
//!
//! Authorization runs on every request and must not touch the store, so the roles and the
//! settings it needs are kept in a derived index ([`AuthIndex`]) that the store builds at
//! registration and keeps current in revision order (ADR 0011, decision 8): a role change
//! or a disabled account takes effect with the commit that made it.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, ObjectKind, ObjectRef, Principal, Revision,
    ScopeFilter, UserId,
};
use tenko_store::{
    ChangeSet, DerivedIndex, IndexImage, KeyRange, ReadView, ReadViewExt, StoreError, WatchFilter,
    downcast_image,
};

use tenko_vault::tables::OPERATOR_INDEX;

use crate::{
    model::{SETTINGS, USERS},
    roles::{RoleName, interactive_only, required_strength, satisfies},
    settings::SecuritySettings,
};

/// What authorization needs to know about a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthz {
    /// Global roles.
    pub roles: Vec<RoleName>,
    /// Disabled accounts are refused.
    pub disabled: bool,
    /// The break-glass account.
    pub break_glass: bool,
}

/// One built image of the index.
#[derive(Debug, Clone, Default)]
pub struct AuthImage {
    revision: Revision,
    users: HashMap<UserId, UserAuthz>,
    settings: SecuritySettings,
    operator_secrets: bool,
}

impl AuthImage {
    /// The user's authorization data.
    pub fn user(&self, id: UserId) -> Option<&UserAuthz> {
        self.users.get(&id)
    }

    /// The security settings.
    pub fn settings(&self) -> &SecuritySettings {
        &self.settings
    }

    /// Whether the vault holds an operator secret (the condition of IAM-07).
    pub fn operator_secrets(&self) -> bool {
        self.operator_secrets
    }

    fn load_operator_secrets(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.operator_secrets = !view
            .scan(OPERATOR_INDEX.name(), KeyRange::all(), 1, false)?
            .is_empty();
        Ok(())
    }

    fn load_user(&mut self, view: &dyn ReadView, id: UserId) -> Result<(), StoreError> {
        match view.get_typed(&USERS, &id)? {
            Some((user, _)) => {
                self.users.insert(
                    id,
                    UserAuthz {
                        roles: user.roles,
                        disabled: user.disabled,
                        break_glass: user.break_glass,
                    },
                );
            }
            None => {
                self.users.remove(&id);
            }
        }
        Ok(())
    }

    fn load_settings(&mut self, view: &dyn ReadView) -> Result<(), StoreError> {
        self.settings = view
            .get_typed(&SETTINGS, &())?
            .map(|(settings, _)| settings)
            .unwrap_or_default();
        Ok(())
    }
}

impl IndexImage for AuthImage {
    fn revision(&self) -> Revision {
        self.revision
    }

    fn memory_bytes(&self) -> usize {
        self.users.len() * (std::mem::size_of::<UserAuthz>() + 32)
    }
}

/// The derived index of user roles and security settings.
#[derive(Debug, Default)]
pub struct AuthIndex {
    live: ArcSwap<AuthImage>,
}

impl AuthIndex {
    /// An empty index; the store fills it at registration.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current image.
    pub fn image(&self) -> Arc<AuthImage> {
        self.live.load_full()
    }
}

/// Largest number of users read when the index is built.
const MAX_USERS: usize = 1_000_000;

impl DerivedIndex for AuthIndex {
    fn name(&self) -> &'static str {
        "auth.index"
    }

    fn filter(&self) -> WatchFilter {
        WatchFilter::tables([
            USERS.name().clone(),
            SETTINGS.name().clone(),
            OPERATOR_INDEX.name().clone(),
        ])
    }

    fn build(&self, view: &dyn ReadView) -> Result<Box<dyn IndexImage>, StoreError> {
        let mut image = AuthImage {
            revision: view.revision(),
            ..AuthImage::default()
        };
        for (id, user, _) in view.scan_typed(&USERS, KeyRange::all(), MAX_USERS, false)? {
            image.users.insert(
                id,
                UserAuthz {
                    roles: user.roles,
                    disabled: user.disabled,
                    break_glass: user.break_glass,
                },
            );
        }
        image.load_settings(view)?;
        image.load_operator_secrets(view)?;
        Ok(Box::new(image))
    }

    fn install(&self, image: Box<dyn IndexImage>) {
        if let Some(image) = downcast_image::<AuthImage>(image) {
            self.live.store(Arc::from(image));
        }
    }

    fn apply(&self, changes: &ChangeSet, view: &dyn ReadView) {
        let mut image = AuthImage::clone(&self.live.load());
        image.revision = changes.revision;
        for change in &changes.changes {
            let result = if &change.table == USERS.name() {
                match USERS.decode_key(&change.key) {
                    Ok(id) => image.load_user(view, id),
                    Err(error) => Err(error.into()),
                }
            } else if &change.table == SETTINGS.name() {
                image.load_settings(view)
            } else if &change.table == OPERATOR_INDEX.name() {
                image.load_operator_secrets(view)
            } else {
                Ok(())
            };
            if let Err(error) = result {
                // Keep serving the previous state of this entry; the next build repairs it.
                tracing::error!(%error, revision = %changes.revision, "auth index update failed");
            }
        }
        self.live.store(Arc::new(image));
    }
}

/// Role-based authorization over the [`AuthIndex`].
#[derive(Debug, Clone)]
pub struct RbacAuthorizer {
    index: Arc<AuthIndex>,
}

impl RbacAuthorizer {
    /// An authorizer over the index.
    pub fn new(index: Arc<AuthIndex>) -> Self {
        Self { index }
    }

    fn decide(
        &self,
        principal: &Principal,
        action: Action,
        kind: ObjectKind,
    ) -> Result<(), DenyReason> {
        let image = self.index.image();
        match principal {
            Principal::System { .. } => Ok(()),
            // Probes and peers get their own grants with enrolment (Slice 2).
            Principal::Node { .. } => Err(DenyReason::MissingPermission),
            Principal::User { id, strength, .. } => {
                let user = image
                    .user(*id)
                    .filter(|user| !user.disabled)
                    .ok_or(DenyReason::Unauthenticated)?;
                if !user.roles.iter().any(|role| role.allows(action, kind)) {
                    return Err(DenyReason::MissingPermission);
                }
                let required = required_strength(
                    &user.roles,
                    image.settings(),
                    action,
                    image.operator_secrets(),
                );
                if satisfies(*strength, required) {
                    Ok(())
                } else {
                    Err(DenyReason::StepUpRequired { required })
                }
            }
            Principal::Token { owner, .. } => {
                let user = image
                    .user(*owner)
                    .filter(|user| !user.disabled && !user.break_glass)
                    .ok_or(DenyReason::Unauthenticated)?;
                if interactive_only(action, kind)
                    || !user.roles.iter().any(|role| role.allows(action, kind))
                {
                    return Err(DenyReason::MissingPermission);
                }
                Ok(())
            }
        }
    }
}

impl Authorizer for RbacAuthorizer {
    fn check(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        self.decide(principal, action, object.kind)
            .map_err(|reason| Denied {
                action,
                object: *object,
                reason,
            })
    }

    fn scope(&self, principal: &Principal, action: Action, kind: ObjectKind) -> ScopeFilter {
        if self.decide(principal, action, kind).is_ok() {
            ScopeFilter::All
        } else {
            ScopeFilter::Nothing
        }
    }
}
