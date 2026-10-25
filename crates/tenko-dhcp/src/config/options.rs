//! Options (plan section 2.4, DHCP-02): the built-in catalog, custom definitions
//! (`dhcp.option_defs`) and the option sets of the levels (`dhcp.option_sets`, one per
//! owner).
//!
//! A value is written in wire form or typed; a typed value is encoded with the type of its
//! code (the catalog for `dhcp4`, else the custom definition of its space and code), and
//! every value is checked against that type before it is stored. Codes the server sets
//! itself are refused (`dhcp.option.code_reserved`); a code without a definition is
//! `dhcp.option.unknown`. A definition's type does not change while an option set uses it,
//! and a used definition is not deleted (`dhcp.option_def.in_use`).

use tenko_core::{
    InterfaceId, ObjectKind, ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dhcp::{
        CATALOG_V4, OptionData, OptionDef, OptionDefId, OptionKind, OptionLevel, OptionOwner,
        OptionSet, OptionSpace, OptionValue, SERVER_MANAGED_V4, audit, codes, kind_of,
        scope_object, server_object,
        tables::{OPTION_DEFS, OPTION_SETS, POLICIES, SCOPES, SHARED_NETWORKS},
    },
    ipam::RangeRole,
    serde_util::HexBytes,
};
use tenko_ipam::tables::{INTERFACES, RANGES};
use tenko_store::{KeyRange, ReadView, ReadViewExt, WriteBatch};

use super::{
    ConfigError, ConfigResult, ConfigService, Planned, Written, check_expect, stamp, text,
};

/// One entry of the catalog as the API lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogItem {
    /// The space.
    pub space: OptionSpace,
    /// The code.
    pub code: u16,
    /// The name, as Kea names it.
    pub name: &'static str,
    /// The type.
    pub kind: OptionKind,
    /// Whether it holds a list.
    pub array: bool,
    /// Whether the server sets it itself (never in an option set).
    pub server_managed: bool,
}

/// The codes the server sets itself, with Kea's names and their types; pad and end are
/// left out.
const MANAGED: [(u8, &str, OptionKind, bool); 16] = [
    (50, "dhcp-requested-address", OptionKind::Ipv4Address, false),
    (51, "dhcp-lease-time", OptionKind::U32, false),
    (52, "dhcp-option-overload", OptionKind::U8, false),
    (53, "dhcp-message-type", OptionKind::U8, false),
    (54, "dhcp-server-identifier", OptionKind::Ipv4Address, false),
    (55, "dhcp-parameter-request-list", OptionKind::U8, true),
    (56, "dhcp-message", OptionKind::String, false),
    (57, "dhcp-max-message-size", OptionKind::U16, false),
    (58, "dhcp-renewal-time", OptionKind::U32, false),
    (59, "dhcp-rebinding-time", OptionKind::U32, false),
    (61, "dhcp-client-identifier", OptionKind::Binary, false),
    (81, "fqdn", OptionKind::Binary, false),
    (82, "dhcp-agent-options", OptionKind::Binary, false),
    (93, "client-system", OptionKind::U16, true),
    (97, "uuid-guid", OptionKind::Binary, false),
    (118, "subnet-selection", OptionKind::Ipv4Address, false),
];

/// The built-in DHCPv4 catalog with the server-managed codes, by code.
pub fn catalog() -> Vec<CatalogItem> {
    let mut items: Vec<CatalogItem> = CATALOG_V4
        .iter()
        .map(|entry| CatalogItem {
            space: OptionSpace::dhcp4(),
            code: u16::from(entry.code),
            name: entry.name,
            kind: entry.kind,
            array: entry.array,
            server_managed: false,
        })
        .collect();
    items.extend(
        MANAGED
            .iter()
            .filter(|(code, ..)| SERVER_MANAGED_V4.contains(code))
            .map(|(code, name, kind, array)| CatalogItem {
                space: OptionSpace::dhcp4(),
                code: u16::from(*code),
                name,
                kind: *kind,
                array: *array,
                server_managed: true,
            }),
    );
    items.sort_by_key(|item| item.code);
    items
}

/// The name of an option: the catalog's for `dhcp4`, else its definition's.
pub fn option_name(space: &OptionSpace, code: u16, defs: &[OptionDef]) -> Option<String> {
    if space.is_dhcp4()
        && let Ok(code) = u8::try_from(code)
    {
        if let Some(entry) = tenko_core::dhcp::catalog_v4(code) {
            return Some(entry.name.to_owned());
        }
        if let Some((_, name, ..)) = MANAGED.iter().find(|(managed, ..)| *managed == code) {
            return Some((*name).to_owned());
        }
    }
    defs.iter()
        .find(|def| &def.space == space && def.code == code)
        .map(|def| def.name.clone())
}

/// The name and the typed view of a value, when its code has a type and the data decodes.
pub fn describe(value: &OptionValue, defs: &[OptionDef]) -> (Option<String>, Option<OptionData>) {
    let typed = kind_of(&value.space, value.code, defs)
        .and_then(|(kind, array)| value.typed(kind, array).ok());
    (option_name(&value.space, value.code, defs), typed)
}

/// A custom definition as read, with how many option sets use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionDefRow {
    /// The definition.
    pub def: OptionDef,
    /// The option sets that hold a value of its space and code.
    pub used_by: u32,
    /// The revision of the row.
    pub revision: Revision,
}

/// A new custom definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOptionDef {
    /// The space.
    pub space: OptionSpace,
    /// The code.
    pub code: u16,
    /// The name.
    pub name: String,
    /// The type.
    pub kind: OptionKind,
    /// Whether it holds a list.
    pub array: bool,
    /// The vendor class of a vendor space.
    pub vendor_class: Option<String>,
    /// Free text.
    pub description: Option<String>,
}

/// Changes to a custom definition; the space and the code do not change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionDefChange {
    /// The name.
    pub name: Option<String>,
    /// The type (refused while used).
    pub kind: Option<OptionKind>,
    /// Whether it holds a list (refused while used).
    pub array: Option<bool>,
    /// The vendor class; an empty string clears it.
    pub vendor_class: Option<String>,
    /// Free text; an empty string clears it.
    pub description: Option<String>,
}

/// An option set as read; an owner without a set reads as an empty set at revision 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionSetRow {
    /// The set.
    pub set: OptionSet,
    /// The revision of the row; 0 for no row.
    pub revision: Revision,
}

/// One value to set: in wire form or typed, exactly one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionInput {
    /// The space.
    pub space: OptionSpace,
    /// The code.
    pub code: u16,
    /// The data in wire form.
    pub data: Option<Vec<u8>>,
    /// The data typed.
    pub typed: Option<OptionData>,
}

fn def_not_found(id: OptionDefId) -> ConfigError {
    ConfigError::not_found(codes::OPTION_DEF_NOT_FOUND, "option definition", id)
}

/// Every custom definition.
pub(crate) fn defs(view: &dyn ReadView) -> ConfigResult<Vec<OptionDef>> {
    Ok(view
        .scan_typed(&OPTION_DEFS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, def, _)| def)
        .collect())
}

/// The option sets that hold a value of `space` and `code`, with their revisions.
fn sets_using(
    view: &dyn ReadView,
    space: &OptionSpace,
    code: u16,
) -> ConfigResult<Vec<(OptionOwner, Revision)>> {
    Ok(view
        .scan_typed(&OPTION_SETS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, set, _)| {
            set.values
                .iter()
                .any(|value| &value.space == space && value.code == code)
        })
        .map(|(owner, _, revision)| (owner, revision))
        .collect())
}

fn check_unique(view: &dyn ReadView, def: &OptionDef) -> ConfigResult<()> {
    for other in defs(view)? {
        if other.id == def.id || other.space != def.space {
            continue;
        }
        if other.code == def.code {
            return Err(ConfigError::new(
                codes::OPTION_DEF_EXISTS,
                409,
                format!("option {} {} has a definition already", def.space, def.code),
            )
            .param("space", def.space.as_str())
            .param("code", def.code.to_string()));
        }
        if other.name == def.name {
            return Err(ConfigError::invalid(
                codes::OPTION_INVALID,
                "name",
                "a definition of this name exists in the space",
            ));
        }
    }
    Ok(())
}

/// Where an owner lives: the object its set is audited on and the version its set's batch
/// expects.
struct OwnerRow {
    object: ObjectRef,
    expect: Option<(tenko_core::names::TableName, Vec<u8>, Revision)>,
}

fn owner_row(view: &dyn ReadView, owner: OptionOwner) -> ConfigResult<OwnerRow> {
    let versioned = |table: &tenko_core::names::TableName, key: Vec<u8>, revision| {
        Some((table.clone(), key, revision))
    };
    Ok(match owner {
        OptionOwner::Server => OwnerRow {
            object: server_object(),
            expect: None,
        },
        OptionOwner::SharedNetwork(id) => {
            let (_, revision) = view.get_typed(&SHARED_NETWORKS, &id)?.ok_or_else(|| {
                ConfigError::not_found(codes::SHARED_NETWORK_NOT_FOUND, "shared network", id)
            })?;
            OwnerRow {
                object: server_object(),
                expect: versioned(
                    SHARED_NETWORKS.name(),
                    SHARED_NETWORKS.key(&id).to_vec(),
                    revision,
                ),
            }
        }
        OptionOwner::Scope(prefix) => {
            let (_, revision) = super::scopes::scope_of(view, prefix)?;
            OwnerRow {
                object: scope_object(prefix),
                expect: versioned(SCOPES.name(), SCOPES.key(&prefix).to_vec(), revision),
            }
        }
        OptionOwner::Pool(range) => {
            let Some((row, revision)) = view.get_typed(&RANGES, &range)?.filter(|(row, _)| {
                !row.meta.is_deleted()
                    && matches!(row.role, RangeRole::DhcpPool | RangeRole::DhcpPdPool)
            }) else {
                return Err(ConfigError::new(
                    codes::POOL_NOT_FOUND,
                    404,
                    format!("range {range} is no DHCP pool"),
                )
                .param("range", range.to_string()));
            };
            OwnerRow {
                object: scope_object(row.prefix),
                expect: versioned(RANGES.name(), RANGES.key(&range).to_vec(), revision),
            }
        }
        OptionOwner::Policy(id) => {
            let (_, revision) = view
                .get_typed(&POLICIES, &id)?
                .ok_or_else(|| ConfigError::not_found(codes::POLICY_NOT_FOUND, "policy", id))?;
            OwnerRow {
                object: ObjectRef::from(id),
                expect: versioned(POLICIES.name(), POLICIES.key(&id).to_vec(), revision),
            }
        }
        OptionOwner::Host(interface) => {
            let Some((_, revision)) = view
                .get_typed(&INTERFACES, &interface)?
                .filter(|(row, _)| !row.meta.is_deleted())
            else {
                return Err(ConfigError::new(
                    "ipam.not_found",
                    404,
                    format!("interface {interface} does not exist"),
                )
                .param("kind", "interface")
                .param("id", interface.to_string()));
            };
            OwnerRow {
                object: interface_object(interface),
                expect: versioned(
                    INTERFACES.name(),
                    INTERFACES.key(&interface).to_vec(),
                    revision,
                ),
            }
        }
    })
}

/// An IPAM interface as an object.
pub(crate) fn interface_object(interface: InterfaceId) -> ObjectRef {
    ObjectRef::new(ObjectKind::Interface, interface.0)
}

/// Turns inputs into values: typed data is encoded with its code's type; `index` names the
/// input in errors.
fn values_of(inputs: &[OptionInput], defs: &[OptionDef]) -> ConfigResult<Vec<OptionValue>> {
    let mut values = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let field = format!("values[{index}]");
        let data = match (&input.data, &input.typed) {
            (Some(data), None) => data.clone(),
            (None, Some(typed)) => {
                let Some((kind, array)) = kind_of(&input.space, input.code, defs) else {
                    return Err(ConfigError::new(
                        codes::OPTION_UNKNOWN,
                        400,
                        format!("option {} {} has no definition", input.space, input.code),
                    )
                    .param("space", input.space.as_str())
                    .param("code", input.code.to_string()));
                };
                typed
                    .encode(kind, array)
                    .map_err(|reason| ConfigError::invalid(codes::OPTION_INVALID, &field, reason))?
            }
            _ => {
                return Err(ConfigError::invalid(
                    codes::OPTION_INVALID,
                    &field,
                    "give the data in wire form or typed, not both and not neither",
                ));
            }
        };
        values.push(OptionValue {
            space: input.space.clone(),
            code: input.code,
            data: HexBytes(data),
        });
    }
    Ok(values)
}

impl ConfigService {
    /// Every custom definition, by space and code.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn option_defs(view: &dyn ReadView) -> ConfigResult<Vec<OptionDefRow>> {
        let sets: Vec<OptionSet> = view
            .scan_typed(&OPTION_SETS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, set, _)| set)
            .collect();
        let mut rows: Vec<OptionDefRow> = view
            .scan_typed(&OPTION_DEFS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, def, revision)| {
                let used = sets
                    .iter()
                    .filter(|set| {
                        set.values
                            .iter()
                            .any(|value| value.space == def.space && value.code == def.code)
                    })
                    .count();
                OptionDefRow {
                    used_by: u32::try_from(used).unwrap_or(u32::MAX),
                    def,
                    revision,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            (&a.def.space, a.def.code, a.def.id).cmp(&(&b.def.space, b.def.code, b.def.id))
        });
        Ok(rows)
    }

    /// One custom definition.
    ///
    /// # Errors
    ///
    /// `dhcp.option_def.not_found`, or the store's error.
    pub fn option_def(view: &dyn ReadView, id: OptionDefId) -> ConfigResult<OptionDefRow> {
        let (def, revision) = view
            .get_typed(&OPTION_DEFS, &id)?
            .ok_or_else(|| def_not_found(id))?;
        let used = sets_using(view, &def.space, def.code)?.len();
        Ok(OptionDefRow {
            used_by: u32::try_from(used).unwrap_or(u32::MAX),
            def,
            revision,
        })
    }

    /// Creates a custom definition.
    ///
    /// # Errors
    ///
    /// `dhcp.option.invalid`, `dhcp.option.code_reserved`, `dhcp.option_def.exists`, or a
    /// store or job error.
    pub async fn create_option_def(
        &self,
        cx: &RequestCtx,
        new: NewOptionDef,
    ) -> ConfigResult<(OptionDef, Written)> {
        let now = stamp(cx);
        let def = OptionDef {
            id: OptionDefId::generate(),
            space: new.space,
            code: new.code,
            name: new.name,
            kind: new.kind,
            array: new.array,
            vendor_class: text(new.vendor_class.as_deref()),
            description: text(new.description.as_deref()),
            created: now.clone(),
            updated: now,
        };
        def.validate()?;
        self.execute_write(cx, |view| {
            check_unique(view, &def)?;
            let mut batch = WriteBatch::for_request(cx);
            // Every other definition: one created meanwhile for the same code makes the
            // batch stale.
            for (id, _, revision) in
                view.scan_typed(&OPTION_DEFS, KeyRange::all(), usize::MAX, false)?
            {
                batch.expect_typed(&OPTION_DEFS, &id, Some(revision));
            }
            batch.expect_typed(&OPTION_DEFS, &def.id, None);
            batch.put_typed(&OPTION_DEFS, &def.id, &def)?;
            batch.audit(
                AuditDraft::success(audit::OPTION_DEF_CREATE, vec![ObjectRef::from(def.id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("option", format!("{} {}", def.space, def.code))
                    .with_context("name", def.name.clone()),
            );
            Ok(Planned::write(
                def.clone(),
                batch,
                format!(
                    "define the DHCP option {} {} ({})",
                    def.space, def.code, def.name
                ),
                vec![ObjectRef::from(def.id)],
            ))
        })
        .await
    }

    /// Changes a custom definition.
    ///
    /// # Errors
    ///
    /// `dhcp.option_def.not_found`, `dhcp.option.invalid`, `dhcp.option_def.in_use` for a
    /// change of type of a used definition, 412 when `expect` is stale, or a store or job
    /// error.
    pub async fn update_option_def(
        &self,
        cx: &RequestCtx,
        id: OptionDefId,
        change: OptionDefChange,
        expect: Option<Revision>,
    ) -> ConfigResult<(OptionDef, Option<Written>)> {
        self.execute(cx, |view| {
            let (before, revision) = view
                .get_typed(&OPTION_DEFS, &id)?
                .ok_or_else(|| def_not_found(id))?;
            check_expect(expect, revision)?;
            let mut after = before.clone();
            if let Some(name) = &change.name {
                after.name.clone_from(name);
            }
            if let Some(kind) = change.kind {
                after.kind = kind;
            }
            if let Some(array) = change.array {
                after.array = array;
            }
            if let Some(vendor_class) = &change.vendor_class {
                after.vendor_class = text(Some(vendor_class));
            }
            if let Some(description) = &change.description {
                after.description = text(Some(description));
            }
            after.validate()?;
            if after == before {
                return Ok(Planned::nothing(after));
            }
            check_unique(view, &after)?;
            let mut batch = WriteBatch::for_request(cx);
            if after.kind != before.kind || after.array != before.array {
                let using = sets_using(view, &before.space, before.code)?;
                if !using.is_empty() {
                    return Err(in_use(id, &using));
                }
                // A set that starts to use the code meanwhile makes the batch stale.
                for (owner, revision) in view
                    .scan_typed(&OPTION_SETS, KeyRange::all(), usize::MAX, false)?
                    .into_iter()
                    .map(|(owner, _, revision)| (owner, revision))
                {
                    batch.expect_typed(&OPTION_SETS, &owner, Some(revision));
                }
            }
            after.updated = stamp(cx);
            batch.expect_typed(&OPTION_DEFS, &id, Some(revision));
            batch.put_typed(&OPTION_DEFS, &id, &after)?;
            batch.audit(
                AuditDraft::success(audit::OPTION_DEF_UPDATE, vec![ObjectRef::from(id)])
                    .with_source_ip(cx.source_ip)
                    .with_context("option", format!("{} {}", after.space, after.code))
                    .with_context("name", after.name.clone()),
            );
            Ok(Planned::write(
                after.clone(),
                batch,
                format!("change the DHCP option definition {}", after.name),
                vec![ObjectRef::from(id)],
            ))
        })
        .await
    }

    /// Deletes a custom definition no option set uses.
    ///
    /// # Errors
    ///
    /// `dhcp.option_def.not_found`, `dhcp.option_def.in_use`, 412 when `expect` is stale,
    /// or a store or job error.
    pub async fn delete_option_def(
        &self,
        cx: &RequestCtx,
        id: OptionDefId,
        expect: Option<Revision>,
    ) -> ConfigResult<Written> {
        let ((), written) = self
            .execute_write(cx, |view| {
                let (def, revision) = view
                    .get_typed(&OPTION_DEFS, &id)?
                    .ok_or_else(|| def_not_found(id))?;
                check_expect(expect, revision)?;
                let using = sets_using(view, &def.space, def.code)?;
                if !using.is_empty() {
                    return Err(in_use(id, &using));
                }
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&OPTION_DEFS, &id, Some(revision));
                batch.delete_typed(&OPTION_DEFS, &id);
                for (owner, _, revision) in
                    view.scan_typed(&OPTION_SETS, KeyRange::all(), usize::MAX, false)?
                {
                    batch.expect_typed(&OPTION_SETS, &owner, Some(revision));
                }
                batch.audit(
                    AuditDraft::success(audit::OPTION_DEF_DELETE, vec![ObjectRef::from(id)])
                        .with_source_ip(cx.source_ip)
                        .with_context("option", format!("{} {}", def.space, def.code))
                        .with_context("name", def.name.clone()),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("delete the DHCP option definition {}", def.name),
                    vec![ObjectRef::from(id)],
                ))
            })
            .await?;
        Ok(written)
    }

    /// Every option set, of one level or all, by owner.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub fn option_sets(
        view: &dyn ReadView,
        level: Option<OptionLevel>,
    ) -> ConfigResult<Vec<OptionSetRow>> {
        Ok(view
            .scan_typed(&OPTION_SETS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .filter(|(owner, _, _)| level.is_none_or(|level| owner.level() == level))
            .map(|(_, set, revision)| OptionSetRow { set, revision })
            .collect())
    }

    /// The option set of an owner; an existing owner without a set reads as an empty set at
    /// revision 0.
    ///
    /// # Errors
    ///
    /// The not-found code of the owner's kind, or the store's error.
    pub fn option_set(view: &dyn ReadView, owner: OptionOwner) -> ConfigResult<OptionSetRow> {
        if let Some((set, revision)) = view.get_typed(&OPTION_SETS, &owner)? {
            return Ok(OptionSetRow { set, revision });
        }
        owner_row(view, owner)?;
        Ok(OptionSetRow {
            set: OptionSet {
                owner,
                values: Vec::new(),
                updated: stamp(&RequestCtx::system(tenko_core::SystemComponent::Dhcp)),
            },
            revision: Revision::ZERO,
        })
    }

    /// The object the option set of `owner` is authorized and audited on, when the owner
    /// exists.
    ///
    /// # Errors
    ///
    /// The not-found code of the owner's kind, or the store's error.
    pub fn option_owner_object(view: &dyn ReadView, owner: OptionOwner) -> ConfigResult<ObjectRef> {
        Ok(owner_row(view, owner)?.object)
    }

    /// Replaces the options of an owner; no values removes the set.
    ///
    /// # Errors
    ///
    /// The not-found code of the owner's kind, `dhcp.option.invalid`,
    /// `dhcp.option.unknown`, `dhcp.option.code_reserved`, 412 when `expect` is stale, or a
    /// store or job error.
    pub async fn set_option_set(
        &self,
        cx: &RequestCtx,
        owner: OptionOwner,
        inputs: Vec<OptionInput>,
        expect: Option<Revision>,
    ) -> ConfigResult<(OptionSet, Option<Written>)> {
        self.execute(cx, |view| {
            let owner_row = owner_row(view, owner)?;
            let current = view.get_typed(&OPTION_SETS, &owner)?;
            let revision = current
                .as_ref()
                .map_or(Revision::ZERO, |(_, revision)| *revision);
            check_expect(expect, revision)?;
            let defs = defs(view)?;
            let set = OptionSet {
                owner,
                values: values_of(&inputs, &defs)?,
                updated: stamp(cx),
            };
            set.validate(&defs)?;
            if current
                .as_ref()
                .is_some_and(|(before, _)| before.values == set.values)
                || (current.is_none() && set.values.is_empty())
            {
                return Ok(Planned::nothing(current.map_or(set, |(before, _)| before)));
            }
            let mut batch = WriteBatch::for_request(cx);
            if let Some((table, key, revision)) = owner_row.expect {
                batch.expect_version(table, key, Some(revision));
            }
            // The definitions the values were checked against.
            for def in &defs {
                if set
                    .values
                    .iter()
                    .any(|value| value.space == def.space && value.code == def.code)
                {
                    let (_, revision) = view
                        .get_typed(&OPTION_DEFS, &def.id)?
                        .ok_or_else(|| def_not_found(def.id))?;
                    batch.expect_typed(&OPTION_DEFS, &def.id, Some(revision));
                }
            }
            batch.expect_typed(
                &OPTION_SETS,
                &owner,
                (revision > Revision::ZERO).then_some(revision),
            );
            if set.values.is_empty() {
                batch.delete_typed(&OPTION_SETS, &owner);
            } else {
                batch.put_typed(&OPTION_SETS, &owner, &set)?;
            }
            batch.audit(
                AuditDraft::success(audit::OPTION_SET, vec![owner_row.object])
                    .with_source_ip(cx.source_ip)
                    .with_context("owner", owner.to_path())
                    .with_context("count", set.values.len().to_string()),
            );
            Ok(Planned::write(
                set.clone(),
                batch,
                format!("set the DHCP options of {}", owner.to_path()),
                vec![owner_row.object],
            ))
        })
        .await
    }

    /// Clears the options of an owner.
    ///
    /// # Errors
    ///
    /// 412 when `expect` is stale, or a store or job error; an owner without a set is no
    /// error.
    pub async fn delete_option_set(
        &self,
        cx: &RequestCtx,
        owner: OptionOwner,
        expect: Option<Revision>,
    ) -> ConfigResult<Option<Written>> {
        let ((), written) = self
            .execute(cx, |view| {
                let Some((_, revision)) = view.get_typed(&OPTION_SETS, &owner)? else {
                    owner_row(view, owner)?;
                    check_expect(expect, Revision::ZERO)?;
                    return Ok(Planned::nothing(()));
                };
                check_expect(expect, revision)?;
                let object =
                    owner_row(view, owner).map_or_else(|_| server_object(), |row| row.object);
                let mut batch = WriteBatch::for_request(cx);
                batch.expect_typed(&OPTION_SETS, &owner, Some(revision));
                batch.delete_typed(&OPTION_SETS, &owner);
                batch.audit(
                    AuditDraft::success(audit::OPTION_SET, vec![object])
                        .with_source_ip(cx.source_ip)
                        .with_context("owner", owner.to_path())
                        .with_context("count", "0"),
                );
                Ok(Planned::write(
                    (),
                    batch,
                    format!("clear the DHCP options of {}", owner.to_path()),
                    vec![object],
                ))
            })
            .await?;
        Ok(written)
    }
}

fn in_use(id: OptionDefId, using: &[(OptionOwner, Revision)]) -> ConfigError {
    let by: Vec<String> = using.iter().map(|(owner, _)| owner.to_path()).collect();
    ConfigError::new(
        codes::OPTION_DEF_IN_USE,
        409,
        format!("{} option set(s) use the definition", by.len()),
    )
    .param("id", id.to_string())
    .param("by", by.join(","))
}
