//! The planner: turns commands into changes over a [`Workspace`].
//!
//! The per-kind rules live in sibling modules (`tenancy`, `space`, `hosts`, `fields`), each
//! an `impl Planner` block; this module holds the driver and the shared helpers: loading
//! with read tracking, revision checks, metadata, usage indexes, history, audit and
//! warnings.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use tenko_core::{
    CounterKey, ObjectKind, ObjectRef, Principal, RequestCtx, Revision, SystemComponent,
    audit::{AuditAction, AuditDraft, Digest},
    codec::canonical_sha256,
    ipam::{CustomFieldDef, CustomValue, FieldKey, Meta, Stamp, Status, Tag},
};
use tenko_store::{KeyRange, ReadView};
use uuid::Uuid;

use super::{IpamPlan, PlanOptions, PlanWarning, PlannedChange, Receipt, workspace::Workspace};
use crate::{
    command::IpamCommand,
    custom, diff,
    error::{IpamError, IpamResult, codes},
    history::{ChangeAction, HistoryEntry},
    object::{Entity, IpamObject},
    tables::{CUSTOM_FIELDS, FIELD_USAGE, HISTORY, RECEIPTS, TAG_USAGE, refs_counter},
};

mod fields;
mod hosts;
mod reserve;
mod space;
mod tenancy;

/// The counter of the custom field definitions; bumped by every definition change and
/// expected by every plan that validates custom values.
pub(crate) fn fields_counter() -> CounterKey {
    CounterKey::new("ipam.fields")
}

/// Whether a principal is automation (IPAM-16): discovery, connectors, the reconciler,
/// imports and cluster nodes. People (sessions and personal tokens) and the API acting for
/// them are not, so a lock never stops a manual edit.
pub fn is_automation(principal: &Principal) -> bool {
    match principal {
        Principal::Node { .. } => true,
        Principal::System { component, .. } => matches!(
            component,
            SystemComponent::Reconciler
                | SystemComponent::Connector
                | SystemComponent::Scan
                | SystemComponent::Import
        ),
        Principal::User { .. } | Principal::Token { .. } => false,
    }
}

/// Whether a status may change from `from` to `to` (IPAM-05). Staying is always allowed.
///
/// | From | To |
/// |---|---|
/// | planned | active, reserved, deprecated |
/// | reserved | planned, active, deprecated |
/// | active | reserved, deprecated |
/// | deprecated | active |
pub fn status_transition_allowed(from: Status, to: Status) -> bool {
    use Status::{Active, Deprecated, Planned, Reserved};
    from == to
        || matches!(
            (from, to),
            (Planned, Active | Reserved | Deprecated)
                | (Reserved, Planned | Active | Deprecated)
                | (Active, Reserved | Deprecated)
                | (Deprecated, Active)
        )
}

/// Longest name of tenants, VRFs, sites, VLANs and interfaces.
const MAX_NAME: usize = 128;
/// Longest description.
const MAX_DESCRIPTION: usize = 4096;
/// Name of the tenant and VRF created on first use.
pub(crate) const DEFAULT_NAME: &str = "default";

pub(crate) struct Planner<'v> {
    pub(super) ws: Workspace<'v>,
    pub(super) cx: &'v RequestCtx,
    options: &'v PlanOptions,
    history_index: u32,
    id_index: u32,
    changes: Vec<PlannedChange>,
    warnings: Vec<PlanWarning>,
    audit: Vec<AuditDraft>,
    /// Hosts whose reservation identifiers are checked at the end (IPAM-18).
    pub(super) reservation_checks: BTreeSet<tenko_core::HostId>,
    defs: Option<BTreeMap<FieldKey, CustomFieldDef>>,
    pub(super) default_tenant: Option<tenko_core::TenantId>,
    pub(super) default_vrf: Option<tenko_core::VrfId>,
    /// The commands as planned (allocation hints filled in).
    pub(super) planned: Vec<IpamCommand>,
}

impl<'v> Planner<'v> {
    pub(crate) fn new(
        view: &'v dyn ReadView,
        cx: &'v RequestCtx,
        options: &'v PlanOptions,
    ) -> Self {
        Self {
            ws: Workspace::new(view),
            cx,
            options,
            history_index: 0,
            id_index: 0,
            changes: Vec::new(),
            warnings: Vec::new(),
            audit: Vec::new(),
            reservation_checks: BTreeSet::new(),
            defs: None,
            default_tenant: None,
            default_vrf: None,
            planned: Vec::new(),
        }
    }

    pub(crate) fn run(mut self, commands: &[IpamCommand]) -> IpamResult<IpamPlan> {
        let base = self.ws.revision();
        let receipt_key = self
            .cx
            .idempotency
            .as_ref()
            .map(|key| (self.cx.principal.subject(), key.as_str().to_owned()));
        let fingerprint = fingerprint(commands)?;
        if let Some(key) = &receipt_key
            && let Some((mut receipt, revision)) = self.ws.get_typed(&RECEIPTS, key, true)?
        {
            if receipt.fingerprint != fingerprint {
                return Err(IpamError::new(
                    codes::IDEMPOTENCY_MISMATCH,
                    422,
                    "the idempotency key was used before for a different request",
                )
                .titled("Idempotency key reused"));
            }
            receipt.revision = revision.unwrap_or_default();
            return Ok(IpamPlan {
                base,
                principal: self.cx.principal.clone(),
                at: self.cx.now,
                request: self.cx.request,
                source_ip: self.cx.source_ip,
                commands: commands.to_vec(),
                changes: Vec::new(),
                warnings: Vec::new(),
                results: receipt.results.clone(),
                preconditions: Vec::new(),
                mutations: Vec::new(),
                audit: Vec::new(),
                replay: Some(receipt),
            });
        }

        let mut results = Vec::with_capacity(commands.len());
        for command in commands {
            let result = self.command(command)?;
            results.push(result);
        }
        self.check_reservations()?;
        if let Some(check) = self.options.reservation {
            self.check_reservation(&check)?;
        }

        if let Some(key) = receipt_key
            && self.ws.has_writes()
        {
            let receipt = Receipt {
                fingerprint,
                results: results.clone(),
                request: self.cx.request,
                at: self.cx.now,
                revision: Revision::ZERO,
            };
            self.ws.put_typed(&RECEIPTS, &key, &receipt)?;
        }
        Ok(self.finish(base, results))
    }

    /// Plans the tenant and the VRF named `default` exactly as the first write that needs
    /// them creates them; the plan is empty when both exist. The results are the tenant and
    /// the VRF.
    pub(crate) fn run_defaults(mut self) -> IpamResult<IpamPlan> {
        let base = self.ws.revision();
        let tenant = self.default_tenant()?;
        let vrf = self.default_vrf()?;
        Ok(self.finish(base, vec![tenant.into(), vrf.into()]))
    }

    /// The plan of what the planner collected.
    fn finish(mut self, base: Revision, results: Vec<ObjectRef>) -> IpamPlan {
        for warning in &mut self.warnings {
            warning.acknowledged =
                warning.requires_ack && self.options.acknowledge.contains(&warning.code);
        }
        if let Some(action) = &self.options.audit_as {
            self.audit = merge_audit(action, std::mem::take(&mut self.audit));
        }
        let principal = self.cx.principal.clone();
        let (preconditions, mutations) = self.ws.into_parts();
        IpamPlan {
            base,
            principal,
            at: self.cx.now,
            request: self.cx.request,
            source_ip: self.cx.source_ip,
            commands: self.planned,
            changes: self.changes,
            warnings: self.warnings,
            results,
            preconditions,
            mutations,
            audit: self.audit,
            replay: None,
        }
    }

    fn command(&mut self, command: &IpamCommand) -> IpamResult<ObjectRef> {
        let mut planned = command.clone();
        let result = match command {
            IpamCommand::CreateTenant(input) => self.create_tenant(input),
            IpamCommand::UpdateTenant(update) => self.update_tenant(update),
            IpamCommand::CreateVrf(input) => self.create_vrf(input),
            IpamCommand::UpdateVrf(update) => self.update_vrf(update),
            IpamCommand::CreateSite(input) => self.create_site(input),
            IpamCommand::UpdateSite(update) => self.update_site(update),
            IpamCommand::CreateVlan(input) => self.create_vlan(input),
            IpamCommand::UpdateVlan(update) => self.update_vlan(update),
            IpamCommand::CreatePrefix(input) => self.create_prefix(input),
            IpamCommand::UpdatePrefix(update) => self.update_prefix(update),
            IpamCommand::CreateRange(input) => self.create_range(input),
            IpamCommand::UpdateRange(update) => self.update_range(update),
            IpamCommand::CreateAddress(input) => self.create_address(input),
            IpamCommand::UpdateAddress(update) => self.update_address(update),
            IpamCommand::CreateHost(input) => self.create_host(input),
            IpamCommand::UpdateHost(update) => self.update_host(update),
            IpamCommand::CreateInterface(input) => self.create_interface(input, None),
            IpamCommand::UpdateInterface(update) => self.update_interface(update),
            IpamCommand::Delete {
                object,
                expected,
                cascade,
            } => self.delete(*object, *expected, *cascade),
            IpamCommand::Restore { object, expected } => self.restore(*object, *expected),
            IpamCommand::SetLock {
                host,
                lock,
                expected,
            } => self.set_lock(*host, *lock, *expected),
            IpamCommand::SetMode {
                host,
                mode,
                expected,
            } => self.set_mode(*host, *mode, *expected),
            IpamCommand::AllocateAddress(alloc) => {
                let (result, ip) = self.allocate_address(alloc)?;
                if let IpamCommand::AllocateAddress(planned) = &mut planned {
                    planned.hint = Some(ip);
                }
                Ok(result)
            }
            IpamCommand::AllocatePrefix(alloc) => {
                let (result, cidr) = self.allocate_prefix(alloc)?;
                if let IpamCommand::AllocatePrefix(planned) = &mut planned {
                    planned.hint = Some(cidr);
                }
                Ok(result)
            }
            IpamCommand::CreateCustomField(input) => self.create_custom_field(input),
            IpamCommand::UpdateCustomField(update) => self.update_custom_field(update),
            IpamCommand::DeleteCustomField { key, expected } => {
                self.delete_custom_field(key, *expected)
            }
        }?;
        self.planned.push(planned);
        Ok(result)
    }

    fn delete(
        &mut self,
        object: ObjectRef,
        expected: Option<Revision>,
        cascade: bool,
    ) -> IpamResult<ObjectRef> {
        match object.kind {
            ObjectKind::Tenant => self.delete_tenant(object.id.into(), expected),
            ObjectKind::Vrf => self.delete_vrf(object.id.into(), expected),
            ObjectKind::Site => self.delete_site(object.id.into(), expected),
            ObjectKind::Vlan => self.delete_vlan(object.id.into(), expected),
            ObjectKind::Prefix => self.delete_prefix(object.id.into(), expected, cascade),
            ObjectKind::Range => self.delete_range(object.id.into(), expected, false),
            ObjectKind::Address => self.delete_address(object.id.into(), expected, false),
            ObjectKind::Host => self.delete_host(object.id.into(), expected, cascade),
            ObjectKind::Interface => {
                self.delete_interface(object.id.into(), expected, cascade, false)
            }
            ObjectKind::CustomField => {
                let (def, _) = self.load_custom_field_by_id(object.id.into())?;
                self.delete_custom_field(&def.key, expected)
            }
            other => Err(IpamError::invalid(
                "object",
                format!("{other} objects are not managed by IPAM"),
            )),
        }
    }

    fn restore(&mut self, object: ObjectRef, expected: Option<Revision>) -> IpamResult<ObjectRef> {
        match object.kind {
            ObjectKind::Tenant => self.restore_tenant(object.id.into(), expected),
            ObjectKind::Vrf => self.restore_vrf(object.id.into(), expected),
            ObjectKind::Site => self.restore_site(object.id.into(), expected),
            ObjectKind::Vlan => self.restore_vlan(object.id.into(), expected),
            ObjectKind::Prefix => self.restore_prefix(object.id.into(), expected),
            ObjectKind::Range => self.restore_range(object.id.into(), expected, false),
            ObjectKind::Address => self.restore_address(object.id.into(), expected, false),
            ObjectKind::Host => self.restore_host(object.id.into(), expected),
            ObjectKind::Interface => self.restore_interface(object.id.into(), expected, false),
            other => Err(IpamError::invalid(
                "object",
                format!("{other} objects cannot be restored"),
            )),
        }
    }

    // ----- shared helpers -------------------------------------------------------------

    pub(super) fn stamp(&self) -> Stamp {
        Stamp::new(self.cx.now, self.cx.principal.clone())
    }

    pub(super) fn automation(&self) -> bool {
        is_automation(&self.cx.principal)
    }

    /// A new identifier: a UUIDv7 with the request time and bits derived from the request
    /// id and a counter, so planning the same request twice yields the same identifiers.
    pub(super) fn new_uuid(&mut self) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(self.cx.request.0.as_bytes());
        hasher.update(self.id_index.to_be_bytes());
        self.id_index += 1;
        let digest = hasher.finalize();
        let mut random = [0u8; 10];
        random.copy_from_slice(&digest[..10]);
        let millis = u64::try_from(self.cx.now.unix_nanos() / 1_000_000).unwrap_or(0);
        uuid::Builder::from_unix_timestamp_millis(millis, &random).into_uuid()
    }

    /// The identifier for a new object: the client's (which must be unused) or a new one.
    pub(super) fn claim_id<T: Entity>(&mut self, id: Option<T::Id>) -> IpamResult<T::Id> {
        match id {
            Some(id) => {
                if self.ws.exists(T::table(), &id, true)? {
                    let object: ObjectRef = id.into();
                    return Err(IpamError::new(
                        codes::ID_TAKEN,
                        409,
                        format!("{object} exists already"),
                    )
                    .param("kind", object.kind)
                    .param("id", object.id));
                }
                Ok(id)
            }
            None => loop {
                // Derived identifiers repeat when a caller plans twice under one request
                // id; skip any that exist (the absence is a precondition of the batch).
                let id = T::Id::from(self.new_uuid());
                if !self.ws.exists(T::table(), &id, true)? {
                    return Ok(id);
                }
            },
        }
    }

    /// Loads an object with read tracking; its `meta.revision` is the stored revision
    /// (zero when the plan created it). The second value is the view revision (`None`
    /// when staged by this plan).
    pub(super) fn load<T: Entity>(&mut self, id: T::Id) -> IpamResult<(T, Option<Revision>)> {
        self.try_load::<T>(id)?
            .ok_or_else(|| IpamError::not_found(id.into()))
    }

    pub(super) fn try_load<T: Entity>(
        &mut self,
        id: T::Id,
    ) -> IpamResult<Option<(T, Option<Revision>)>> {
        Ok(self
            .ws
            .get_typed(T::table(), &id, true)?
            .map(|(mut object, revision)| {
                object.meta_mut().revision = revision.unwrap_or_default();
                (object, revision)
            }))
    }

    /// Loads an object for a change: it must exist, match `expected` and, unless
    /// `allow_deleted`, not be deleted.
    pub(super) fn load_for_change<T: Entity>(
        &mut self,
        id: T::Id,
        expected: Option<Revision>,
        allow_deleted: bool,
    ) -> IpamResult<T> {
        let (object, revision) = self.load::<T>(id)?;
        check_expected(id.into(), expected, revision)?;
        if !allow_deleted && object.meta().is_deleted() {
            return Err(IpamError::deleted(id.into()));
        }
        Ok(object)
    }

    /// Loads a referenced object that must exist and be live.
    pub(super) fn load_live<T: Entity>(&mut self, id: T::Id, field: &str) -> IpamResult<T> {
        match self.try_load::<T>(id)? {
            Some((object, _)) if !object.meta().is_deleted() => Ok(object),
            _ => Err(IpamError::reference_missing(field, id.into())),
        }
    }

    /// Stages an object (its stored `meta.revision` is always zero).
    pub(super) fn write<T: Entity>(&mut self, object: &T) -> IpamResult<()> {
        let mut stored = object.clone();
        stored.meta_mut().revision = Revision::ZERO;
        self.ws.put_typed(T::table(), &object.id(), &stored)
    }

    /// Records one change: history row, audit draft and preview entry.
    pub(super) fn record(
        &mut self,
        object: ObjectRef,
        action: ChangeAction,
        before: Option<IpamObject>,
        after: Option<IpamObject>,
        derived: bool,
    ) -> IpamResult<()> {
        let fields = diff::diff(before.as_ref(), after.as_ref());
        let index = self.history_index;
        self.history_index += 1;
        let entry = HistoryEntry {
            object,
            action,
            at: self.cx.now,
            by: self.cx.principal.clone(),
            request: self.cx.request,
            job_kind: Some(crate::jobs::edit_job_kind()),
            before: before.clone(),
            after: after.clone(),
            changes: fields.clone(),
            revision: Revision::ZERO,
        };
        // The base revision keeps keys apart when a caller plans twice under one request.
        let base = self.ws.revision();
        self.ws.put_typed(
            &HISTORY,
            &(object, self.cx.now, self.cx.request, base, index),
            &entry,
        )?;
        let audit_action =
            AuditAction::new(format!("ipam.{}.{}", object.kind.as_str(), action.as_str()))?;
        let mut draft =
            AuditDraft::success(audit_action, vec![object]).with_source_ip(self.cx.source_ip);
        draft.details.changes.clone_from(&fields);
        if derived {
            draft = draft.with_context("derived", "true");
        }
        self.audit.push(draft);
        self.changes.push(PlannedChange {
            object,
            action,
            before,
            after,
            fields,
            derived,
        });
        Ok(())
    }

    /// Adds a warning.
    pub(super) fn warn(
        &mut self,
        code: &str,
        message: impl Into<String>,
        object: Option<ObjectRef>,
        params: &[(&str, String)],
        requires_ack: bool,
    ) {
        self.warnings.push(PlanWarning {
            code: code.to_owned(),
            message: message.into(),
            object,
            params: params
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
            requires_ack,
            acknowledged: false,
        });
    }

    /// Fails with `ipam.status.transition` unless the change is allowed (IPAM-05).
    pub(super) fn check_transition(object: ObjectRef, from: Status, to: Status) -> IpamResult<()> {
        if status_transition_allowed(from, to) {
            Ok(())
        } else {
            Err(IpamError::new(
                codes::STATUS_TRANSITION,
                409,
                format!("{object} cannot change status from {from:?} to {to:?}"),
            )
            .titled("Status change not allowed")
            .param("from", status_name(from))
            .param("to", status_name(to))
            .field("status", codes::STATUS_TRANSITION))
        }
    }

    /// Warns when a live child is active inside a planned or deprecated parent.
    pub(super) fn check_parent_status(
        &mut self,
        child: ObjectRef,
        status: Status,
        parent: ObjectRef,
        parent_status: Status,
    ) {
        if status == Status::Active && matches!(parent_status, Status::Deprecated | Status::Planned)
        {
            self.warn(
                codes::WARN_PARENT_STATUS,
                format!(
                    "{child} is active inside {parent}, which is {}",
                    status_name(parent_status)
                ),
                Some(child),
                &[
                    ("parent", parent.to_string()),
                    ("parent_status", status_name(parent_status).to_owned()),
                ],
                false,
            );
        }
    }

    // ----- metadata, tags and custom fields ---------------------------------------------

    /// Fills new metadata from input fields, validating the custom values.
    pub(super) fn new_meta(
        &mut self,
        kind: ObjectKind,
        tags: &BTreeSet<Tag>,
        custom: &BTreeMap<FieldKey, CustomValue>,
        description: Option<&String>,
    ) -> IpamResult<Meta> {
        let mut meta = Meta::new(self.stamp());
        meta.tags.clone_from(tags);
        meta.custom.clone_from(custom);
        meta.description = clean_description(description)?;
        self.validate_custom(kind, &meta.custom)?;
        Ok(meta)
    }

    /// Applies the metadata part of a patch; returns whether anything changed.
    pub(super) fn patch_meta(
        &mut self,
        kind: ObjectKind,
        meta: &mut Meta,
        tags: Option<&BTreeSet<Tag>>,
        custom: Option<&BTreeMap<FieldKey, Option<CustomValue>>>,
        description: Option<&Option<String>>,
    ) -> IpamResult<()> {
        if let Some(tags) = tags {
            meta.tags.clone_from(tags);
        }
        if let Some(description) = description {
            meta.description = clean_description(description.as_ref())?;
        }
        if let Some(custom) = custom {
            for (key, value) in custom {
                match value {
                    Some(value) => {
                        meta.custom.insert(key.clone(), value.clone());
                    }
                    None => {
                        meta.custom.remove(key);
                    }
                }
            }
        }
        self.validate_custom(kind, &meta.custom)?;
        meta.updated = self.stamp();
        Ok(())
    }

    /// The custom field definitions, read once per plan and covered by the definitions
    /// counter.
    pub(super) fn custom_defs(&mut self) -> IpamResult<&BTreeMap<FieldKey, CustomFieldDef>> {
        if self.defs.is_none() {
            self.ws.expect(&fields_counter())?;
            let defs = self
                .ws
                .scan_typed(&CUSTOM_FIELDS, &KeyRange::all())?
                .into_iter()
                .map(|(_, def)| (def.key.clone(), def))
                .collect();
            self.defs = Some(defs);
        }
        Ok(self.defs.get_or_insert_with(BTreeMap::new))
    }

    /// Forgets the cached definitions after a definition change in this plan.
    pub(super) fn reset_defs(&mut self) {
        self.defs = None;
    }

    fn validate_custom(
        &mut self,
        kind: ObjectKind,
        values: &BTreeMap<FieldKey, CustomValue>,
    ) -> IpamResult<()> {
        let defs = self.custom_defs()?;
        let problems = custom::validate_values(kind, values, defs);
        let Some(first) = problems.first() else {
            return Ok(());
        };
        let mut error = IpamError::new(first.code, 400, first.message.clone())
            .titled("Invalid custom field value")
            .param("key", &first.key);
        for problem in &problems {
            error = error.field(format!("custom.{}", problem.key), problem.code);
        }
        Err(error)
    }

    /// Keeps `ipam.tag_usage` and `ipam.field_usage` in step with an object's metadata.
    /// `None` means the object is absent or deleted. A field that gains a user bumps the
    /// definition's reference counter, so a concurrent removal of the definition retries.
    pub(super) fn sync_usage(
        &mut self,
        object: ObjectRef,
        old: Option<&Meta>,
        new: Option<&Meta>,
    ) -> IpamResult<()> {
        let old_tags: BTreeSet<&str> = old
            .map(|m| m.tags.iter().map(Tag::as_str).collect())
            .unwrap_or_default();
        let new_tags: BTreeSet<&str> = new
            .map(|m| m.tags.iter().map(Tag::as_str).collect())
            .unwrap_or_default();
        for tag in old_tags.difference(&new_tags) {
            self.ws
                .delete_typed(&TAG_USAGE, &((*tag).to_owned(), object));
        }
        for tag in new_tags.difference(&old_tags) {
            self.ws
                .put_typed(&TAG_USAGE, &((*tag).to_owned(), object), &())?;
        }
        let old_keys: BTreeSet<&FieldKey> =
            old.map(|m| m.custom.keys().collect()).unwrap_or_default();
        let new_keys: BTreeSet<&FieldKey> =
            new.map(|m| m.custom.keys().collect()).unwrap_or_default();
        for key in old_keys.difference(&new_keys) {
            self.ws
                .delete_typed(&FIELD_USAGE, &(key.as_str().to_owned(), object));
        }
        let added: Vec<FieldKey> = new_keys
            .difference(&old_keys)
            .map(|key| (*key).clone())
            .collect();
        for key in added {
            self.ws
                .put_typed(&FIELD_USAGE, &(key.as_str().to_owned(), object), &())?;
            if let Some(def) = self.custom_defs()?.get(&key) {
                let reference: ObjectRef = def.id.into();
                self.ws.bump(&refs_counter(reference));
            }
        }
        Ok(())
    }

    /// Notes that something now references `object`: a delete planned concurrently from an
    /// older view then fails its reference precondition and retries.
    pub(super) fn add_reference(&mut self, object: ObjectRef) {
        self.ws.bump(&refs_counter(object));
    }

    /// Expects no new references to `object` while this plan is in flight.
    pub(super) fn expect_no_new_references(&mut self, object: ObjectRef) -> IpamResult<()> {
        self.ws.expect(&refs_counter(object))?;
        Ok(())
    }
}

/// Fails with `ipam.revision_mismatch` when the caller expected another revision.
pub(super) fn check_expected(
    object: ObjectRef,
    expected: Option<Revision>,
    actual: Option<Revision>,
) -> IpamResult<()> {
    match (expected, actual) {
        (None, _) => Ok(()),
        (Some(expected), Some(actual)) if expected == actual => Ok(()),
        (Some(expected), actual) => Err(IpamError::revision_mismatch(
            object,
            expected,
            actual.unwrap_or_default(),
        )),
    }
}

/// Trims and validates a name.
pub(super) fn clean_name(field: &str, name: &str) -> IpamResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_NAME {
        return Err(IpamError::invalid(
            field,
            format!("{field} must be 1 to {MAX_NAME} characters"),
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(IpamError::invalid(
            field,
            format!("{field} must not contain control characters"),
        ));
    }
    Ok(trimmed.to_owned())
}

fn clean_description(description: Option<&String>) -> IpamResult<Option<String>> {
    let Some(text) = description else {
        return Ok(None);
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_DESCRIPTION {
        return Err(IpamError::invalid(
            "description",
            format!("description must be at most {MAX_DESCRIPTION} characters"),
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

/// The `snake_case` name of a status.
pub(super) fn status_name(status: Status) -> &'static str {
    match status {
        Status::Planned => "planned",
        Status::Active => "active",
        Status::Reserved => "reserved",
        Status::Deprecated => "deprecated",
    }
}

/// The fingerprint of a command list for idempotency receipts: allocation hints are
/// removed because the service fills them per attempt.
/// One audit draft for the drafts of a plan ([`PlanOptions::audit_as`]): the action given,
/// every object in the order the drafts name them, every field change with the object it
/// belongs to, and the context of the drafts (the first value of a key wins). No drafts,
/// no draft.
fn merge_audit(action: &AuditAction, drafts: Vec<AuditDraft>) -> Vec<AuditDraft> {
    let Some(first) = drafts.first() else {
        return drafts;
    };
    let mut merged =
        AuditDraft::success(action.clone(), Vec::new()).with_source_ip(first.source_ip);
    for draft in drafts {
        let own = draft.objects.first().copied();
        for object in draft.objects {
            if !merged.objects.contains(&object) {
                merged.objects.push(object);
            }
        }
        merged
            .details
            .changes
            .extend(draft.details.changes.into_iter().map(|mut change| {
                change.object = change.object.or(own);
                change
            }));
        for (key, value) in draft.details.context {
            merged.details.context.entry(key).or_insert(value);
        }
    }
    vec![merged]
}

fn fingerprint(commands: &[IpamCommand]) -> IpamResult<Digest> {
    let stripped: Vec<IpamCommand> = commands
        .iter()
        .cloned()
        .map(|mut command| {
            match &mut command {
                IpamCommand::AllocateAddress(alloc) => alloc.hint = None,
                IpamCommand::AllocatePrefix(alloc) => alloc.hint = None,
                _ => {}
            }
            command
        })
        .collect();
    Ok(Digest(canonical_sha256(&stripped)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_transitions_follow_the_table() {
        use Status::{Active, Deprecated, Planned, Reserved};
        assert!(status_transition_allowed(Planned, Active));
        assert!(status_transition_allowed(Active, Deprecated));
        assert!(status_transition_allowed(Deprecated, Active));
        assert!(status_transition_allowed(Reserved, Planned));
        assert!(!status_transition_allowed(Active, Planned));
        assert!(!status_transition_allowed(Deprecated, Planned));
        assert!(!status_transition_allowed(Deprecated, Reserved));
        for status in [Planned, Active, Reserved, Deprecated] {
            assert!(status_transition_allowed(status, status));
        }
    }

    #[test]
    fn automation_principals() {
        assert!(is_automation(&Principal::system(
            SystemComponent::Reconciler
        )));
        assert!(is_automation(&Principal::system(SystemComponent::Import)));
        assert!(is_automation(&Principal::Node {
            id: tenko_core::NodeId(2)
        }));
        assert!(!is_automation(&Principal::system(SystemComponent::Api)));
        assert!(!is_automation(&Principal::Token {
            id: tenko_core::ApiTokenId::generate(),
            owner: tenko_core::UserId::generate(),
        }));
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(clean_name("name", "  lab ").expect("name"), "lab");
        assert!(clean_name("name", " ").is_err());
        assert!(clean_name("name", &"x".repeat(129)).is_err());
        assert!(clean_name("name", "a\u{7}b").is_err());
    }
}
