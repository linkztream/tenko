//! Custom field definitions (IPAM-08). Definitions have no soft delete: a definition no
//! object uses is removed for good.

use tenko_core::{
    CustomFieldId, ObjectRef,
    codec::encode_key,
    ipam::{CustomFieldDef, FieldKey},
};
use tenko_store::KeyRange;

use super::{Planner, fields_counter, tenancy::name_taken};
use crate::{
    command::{CustomFieldInput, UpdateCustomField},
    custom,
    error::{IpamError, IpamResult, codes},
    history::ChangeAction,
    object::IpamObject,
    tables::{CUSTOM_FIELD_KEYS, CUSTOM_FIELDS, FIELD_USAGE},
};

impl Planner<'_> {
    pub(super) fn load_custom_field_by_id(
        &mut self,
        id: CustomFieldId,
    ) -> IpamResult<(CustomFieldDef, Option<tenko_core::Revision>)> {
        self.ws
            .get_typed(&CUSTOM_FIELDS, &id, true)?
            .ok_or_else(|| IpamError::not_found(id.into()))
    }

    fn load_custom_field(
        &mut self,
        key: &FieldKey,
    ) -> IpamResult<(CustomFieldDef, Option<tenko_core::Revision>)> {
        let Some((id, _)) =
            self.ws
                .get_typed(&CUSTOM_FIELD_KEYS, &key.as_str().to_owned(), true)?
        else {
            return Err(IpamError::new(
                codes::NOT_FOUND,
                404,
                format!("custom field {key} does not exist"),
            )
            .titled("Object not found")
            .param("kind", "custom_field")
            .param("key", key));
        };
        self.load_custom_field_by_id(id)
    }

    fn uses_of(&self, key: &FieldKey) -> IpamResult<usize> {
        Ok(self
            .ws
            .scan(
                FIELD_USAGE.name(),
                &KeyRange::prefix(encode_key(&key.as_str().to_owned())),
            )?
            .len())
    }

    pub(super) fn create_custom_field(
        &mut self,
        input: &CustomFieldInput,
    ) -> IpamResult<ObjectRef> {
        let key_text = input.key.as_str().to_owned();
        if self.ws.exists(&CUSTOM_FIELD_KEYS, &key_text, true)? {
            return Err(name_taken("custom field", input.key.as_str()));
        }
        let id = match input.id {
            Some(id) => {
                if self.ws.exists(&CUSTOM_FIELDS, &id, true)? {
                    let object: ObjectRef = id.into();
                    return Err(IpamError::new(
                        codes::ID_TAKEN,
                        409,
                        format!("{object} exists already"),
                    )
                    .param("kind", object.kind)
                    .param("id", object.id));
                }
                id
            }
            None => loop {
                let id = CustomFieldId::from(self.new_uuid());
                if !self.ws.exists(&CUSTOM_FIELDS, &id, true)? {
                    break id;
                }
            },
        };
        let def = CustomFieldDef {
            id,
            key: input.key.clone(),
            kind: input.kind.clone(),
            applies_to: input.applies_to.clone(),
            required: input.required,
        };
        check_definition(&def)?;
        self.ws.expect_and_bump(&fields_counter())?;
        self.ws.put_typed(&CUSTOM_FIELDS, &id, &def)?;
        self.ws.put_typed(&CUSTOM_FIELD_KEYS, &key_text, &id)?;
        self.reset_defs();
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::CustomField(def)),
            false,
        )?;
        Ok(id.into())
    }

    pub(super) fn update_custom_field(
        &mut self,
        update: &UpdateCustomField,
    ) -> IpamResult<ObjectRef> {
        let (before, revision) = self.load_custom_field(&update.key)?;
        super::check_expected(before.id.into(), update.expected, revision)?;
        let mut after = before.clone();
        let patch = &update.patch;
        if let Some(kind) = &patch.kind
            && *kind != before.kind
        {
            if self.uses_of(&before.key)? > 0 {
                self.expect_no_new_references(before.id.into())?;
                custom::check_kind_change(&before.key, &before.kind, kind).map_err(|problem| {
                    IpamError::new(problem.code, 409, problem.message.clone())
                        .titled("Incompatible custom field change")
                        .param("key", &problem.key)
                        .field("kind", problem.code)
                })?;
            }
            after.kind = kind.clone();
        }
        if let Some(applies_to) = &patch.applies_to {
            after.applies_to.clone_from(applies_to);
        }
        if let Some(required) = patch.required {
            after.required = required;
        }
        if after == before {
            return Ok(before.id.into());
        }
        check_definition(&after)?;
        self.ws.expect_and_bump(&fields_counter())?;
        self.ws.put_typed(&CUSTOM_FIELDS, &after.id, &after)?;
        self.reset_defs();
        self.record(
            before.id.into(),
            ChangeAction::Update,
            Some(IpamObject::CustomField(before.clone())),
            Some(IpamObject::CustomField(after)),
            false,
        )?;
        Ok(before.id.into())
    }

    pub(super) fn delete_custom_field(
        &mut self,
        key: &FieldKey,
        expected: Option<tenko_core::Revision>,
    ) -> IpamResult<ObjectRef> {
        let (before, revision) = self.load_custom_field(key)?;
        super::check_expected(before.id.into(), expected, revision)?;
        self.expect_no_new_references(before.id.into())?;
        let uses = self.uses_of(key)?;
        if uses > 0 {
            return Err(IpamError::in_use(before.id.into(), "objects", uses));
        }
        self.ws.expect_and_bump(&fields_counter())?;
        self.ws.delete_typed(&CUSTOM_FIELDS, &before.id);
        self.ws
            .delete_typed(&CUSTOM_FIELD_KEYS, &key.as_str().to_owned());
        self.reset_defs();
        self.record(
            before.id.into(),
            ChangeAction::Remove,
            Some(IpamObject::CustomField(before.clone())),
            None,
            false,
        )?;
        Ok(before.id.into())
    }
}

fn check_definition(def: &CustomFieldDef) -> IpamResult<()> {
    let problems = custom::validate_definition(def);
    let Some(first) = problems.first() else {
        return Ok(());
    };
    let mut error = IpamError::new(first.code, 400, first.message.clone())
        .titled("Invalid custom field definition")
        .param("key", &first.key);
    for problem in &problems {
        error = error.field("definition", problem.code);
    }
    Err(error)
}
