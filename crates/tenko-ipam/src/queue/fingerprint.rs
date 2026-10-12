//! What a plan does, comparable across two plans of the same commands made at different
//! times (S3-Q13: "an item whose plan is unchanged applies").
//!
//! Two plans are the same when they change the same objects in the same way: the same
//! objects with the same actions and the same field changes (old and new values), and the
//! same warning codes. What differs between any two plannings is left out: the time and
//! actor stamps of `meta.created` and `meta.deleted` (`meta.revision` and `meta.updated`
//! are never in a diff), and the identifiers of objects the plan creates without the
//! command naming them, which are replaced by their order of creation (`new#1`, ...) in
//! the objects and in every field value that mentions them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{ObjectKind, ObjectRef};
use utoipa::ToSchema;

use crate::{ChangeAction, IpamPlan, PlanView};

/// Fields that differ between two plannings of the same change.
const STAMPS: [&str; 2] = ["meta.created", "meta.deleted"];

/// The comparable form of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Fingerprint {
    /// Every change, in plan order.
    pub changes: Vec<ChangePrint>,
    /// The warning codes, sorted.
    pub warnings: Vec<String>,
}

/// One change of a [`Fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ChangePrint {
    /// The kind of the object.
    pub kind: ObjectKind,
    /// The object identifier, or `new#<n>` for the n-th object the plan creates.
    pub object: String,
    /// What happens.
    pub action: ChangeAction,
    /// Whether the change follows from another one.
    pub derived: bool,
    /// The changed fields: name, old value, new value.
    pub fields: Vec<(String, Option<String>, Option<String>)>,
}

impl Fingerprint {
    /// The fingerprint of a plan.
    pub fn of_plan(plan: &IpamPlan) -> Self {
        Self::of_view(&plan.view())
    }

    /// The fingerprint of a plan view.
    pub fn of_view(view: &PlanView) -> Self {
        let mut created: BTreeMap<String, String> = BTreeMap::new();
        for change in &view.changes {
            if change.action == ChangeAction::Create {
                let next = format!("new#{}", created.len() + 1);
                created.entry(change.object.id.to_string()).or_insert(next);
            }
        }
        let rename = |text: &str| -> String {
            let mut text = text.to_owned();
            for (id, placeholder) in &created {
                if text.contains(id.as_str()) {
                    text = text.replace(id.as_str(), placeholder);
                }
            }
            text
        };
        let object_name = |object: &ObjectRef| -> String {
            let id = object.id.to_string();
            created.get(&id).cloned().unwrap_or(id)
        };
        let changes = view
            .changes
            .iter()
            .map(|change| ChangePrint {
                kind: change.object.kind,
                object: object_name(&change.object),
                action: change.action,
                derived: change.derived,
                fields: change
                    .fields
                    .iter()
                    .filter(|field| !STAMPS.contains(&field.field.as_str()))
                    .map(|field| {
                        (
                            field.field.clone(),
                            field.old.as_deref().map(rename),
                            field.new.as_deref().map(rename),
                        )
                    })
                    .collect(),
            })
            .collect();
        let mut warnings: Vec<String> = view
            .warnings
            .iter()
            .map(|warning| warning.code.clone())
            .collect();
        warnings.sort();
        Self { changes, warnings }
    }

    /// Whether the plan changes nothing.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{ObjectKind, ObjectRef, audit::FieldChange};
    use uuid::Uuid;

    use super::*;
    use crate::plan::{PlanSummary, PlannedChange};

    fn change(object: ObjectRef, action: ChangeAction, fields: &[(&str, &str)]) -> PlannedChange {
        PlannedChange {
            object,
            action,
            before: None,
            after: None,
            fields: fields
                .iter()
                .map(|(field, new)| FieldChange {
                    object: None,
                    field: (*field).to_owned(),
                    old: None,
                    new: Some((*new).to_owned()),
                })
                .collect(),
            derived: false,
        }
    }

    fn view(changes: Vec<PlannedChange>) -> PlanView {
        PlanView {
            base_revision: tenko_core::Revision(3),
            summary: PlanSummary {
                counts: Vec::new(),
                warnings: std::collections::BTreeMap::new(),
                unacknowledged: Vec::new(),
                lines: Vec::new(),
                mutations: 0,
                preconditions: 0,
            },
            changes,
            warnings: Vec::new(),
            results: Vec::new(),
        }
    }

    #[test]
    fn created_identifiers_and_stamps_do_not_count() {
        let host = |n: u128| ObjectRef::new(ObjectKind::Host, Uuid::from_u128(n));
        let interface = |n: u128| ObjectRef::new(ObjectKind::Interface, Uuid::from_u128(n));
        let first = view(vec![
            change(
                host(1),
                ChangeAction::Create,
                &[("name", "a.example.test"), ("meta.created", "monday")],
            ),
            change(
                interface(2),
                ChangeAction::Create,
                &[("host", &Uuid::from_u128(1).to_string())],
            ),
        ]);
        let second = view(vec![
            change(
                host(7),
                ChangeAction::Create,
                &[("name", "a.example.test"), ("meta.created", "friday")],
            ),
            change(
                interface(8),
                ChangeAction::Create,
                &[("host", &Uuid::from_u128(7).to_string())],
            ),
        ]);
        assert_eq!(Fingerprint::of_view(&first), Fingerprint::of_view(&second));
        assert_eq!(
            Fingerprint::of_view(&first).changes[1].fields[0]
                .2
                .as_deref(),
            Some("new#1")
        );
    }

    #[test]
    fn another_value_or_object_is_another_plan() {
        let address = ObjectRef::new(ObjectKind::Address, Uuid::from_u128(5));
        let other = ObjectRef::new(ObjectKind::Address, Uuid::from_u128(6));
        let reserved = view(vec![change(
            address,
            ChangeAction::Update,
            &[("status", "reserved")],
        )]);
        let active = view(vec![change(
            address,
            ChangeAction::Update,
            &[("status", "active")],
        )]);
        let elsewhere = view(vec![change(
            other,
            ChangeAction::Update,
            &[("status", "reserved")],
        )]);
        let fingerprint = Fingerprint::of_view(&reserved);
        assert_ne!(fingerprint, Fingerprint::of_view(&active));
        assert_ne!(fingerprint, Fingerprint::of_view(&elsewhere));
        assert!(Fingerprint::of_view(&view(Vec::new())).is_empty());
    }
}
