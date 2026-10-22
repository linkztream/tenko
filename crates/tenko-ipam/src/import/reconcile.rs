//! Reconcile: the import model against the store, item by item, into IPAM commands.
//!
//! Every model item is looked up by its natural key (tenant, VRF and site name, VLAN id,
//! CIDR, host name, interface name, address). A missing item becomes a create command
//! with a client-chosen identifier, so later commands of the same chunk refer to it; an
//! existing item that differs in a field the source sets becomes an update under the
//! [`ConflictPolicy`]; an equal item becomes nothing. Reconciling the same model twice
//! therefore plans nothing the second time (idempotent re-apply, and the empty plan of the
//! round trip, E1). The import never deletes and never clears a field the source leaves
//! empty; tags are added, not replaced.
//!
//! Items come in dependency order ([`work_items`]): tenants, VRFs and sites, VLANs,
//! prefixes (supernets before their children), hosts with their interfaces, addresses. A
//! chunk of the apply job reconciles a contiguous slice against the store as earlier
//! chunks left it.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, HostId, ImportId, InterfaceId, ObjectKind, PrefixId, SiteId, TenantId, Timestamp,
    VlanId, VrfId,
    codec::encode_key,
    ipam::{
        Address, CustomFieldDef, CustomValue, FieldKey, Host, Interface, Prefix, PrefixRole, Range,
        Status, Tag, UtilizationAlarm, Vlan,
    },
    ir::{LossEntry, SourceLocation},
    net::HostName,
    secret::SecretRef,
    serde_util::HexBytes,
    table::TableDef,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use super::{
    codes,
    mapping::{ConflictPolicy, CredentialPolicy, ImportOptions},
    model::{ImportModel, ModelAddress, ModelHost, ModelInterface, ModelPrefix, ModelVlan},
    translate::{DEFAULT_NAME, ItemKey, vrf_key},
};
use crate::{
    IpamCommand,
    command::{
        AddressInput, AddressPatch, HostInput, HostPatch, InterfaceInput, InterfacePatch,
        PrefixInput, PrefixPatch, SiteInput, TenantInput, UpdateAddress, UpdateHost,
        UpdateInterface, UpdatePrefix, UpdateVlan, VlanInput, VlanPatch, VrfInput,
    },
    custom,
    error::IpamResult,
    plan::status_transition_allowed,
    tables::{
        ADDRESS_IPS, ADDRESSES, HOST_INTERFACES, HOST_NAMES, HOSTS, INTERFACES, PREFIX_CIDRS,
        PREFIX_RANGES, PREFIXES, RANGES, SITE_NAMES, TENANT_NAMES, VLAN_VIDS, VLANS, VRF_NAMES,
    },
};

/// The credential reference of a host created by an import: one operator secret per host
/// holding its login and password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostCredential {
    /// The secret in the vault.
    pub secret: SecretRef,
    /// Whether the secret holds a login.
    pub login: bool,
    /// Whether the secret holds a password.
    pub password: bool,
    /// The import that wrote it.
    pub import: ImportId,
    /// When.
    pub at: Timestamp,
}

/// Host credentials of imports, by host (references only; the values are in the vault).
pub static HOST_CREDENTIALS: TableDef<HostId, HostCredential> =
    TableDef::new("import.host_credentials");

/// One unit of work, in dependency order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkItem {
    /// A tenant named by the import.
    Tenant(String),
    /// A VRF named by the import (in the import's tenant).
    Vrf(String),
    /// A site named by the import.
    Site(String),
    /// A VLAN of the model, by index.
    Vlan(usize),
    /// A prefix of the model, by index.
    Prefix(usize),
    /// A host of the model with its interfaces and credential, by index.
    Host(usize),
    /// An address of the model, by index.
    Address(usize),
}

impl WorkItem {
    /// A rough upper bound of the bytes this item adds to a write batch (object, history
    /// row, audit draft, index rows, preconditions), for cutting chunks.
    pub fn estimated_bytes(&self, model: &ImportModel) -> usize {
        match self {
            WorkItem::Tenant(_) | WorkItem::Vrf(_) | WorkItem::Site(_) | WorkItem::Vlan(_) => 2_048,
            WorkItem::Prefix(_) => 3_072,
            WorkItem::Host(index) => {
                let host = &model.hosts[*index];
                3_072 + host.interfaces.len() * 2_560 + 2_048
            }
            WorkItem::Address(_) => 3_584,
        }
    }

    /// How many commands the item may produce.
    pub fn estimated_commands(&self, model: &ImportModel) -> usize {
        match self {
            WorkItem::Host(index) => 1 + model.hosts[*index].interfaces.len(),
            _ => 1,
        }
    }
}

fn is_default(name: &str) -> bool {
    name.eq_ignore_ascii_case(DEFAULT_NAME)
}

/// The work items of a model in dependency order.
pub fn work_items(model: &ImportModel, options: &ImportOptions) -> Vec<WorkItem> {
    let mut items = Vec::new();
    let mut tenants: BTreeMap<String, String> = BTreeMap::new();
    let mut vrfs: BTreeMap<String, String> = BTreeMap::new();
    let mut sites: BTreeMap<String, String> = BTreeMap::new();
    let add = |set: &mut BTreeMap<String, String>, name: Option<&str>| {
        if let Some(name) = name
            && !is_default(name)
        {
            set.entry(name.to_lowercase())
                .or_insert_with(|| name.to_owned());
        }
    };
    add(&mut tenants, options.tenant.as_deref());
    add(&mut vrfs, options.vrf.as_deref());
    for host in &model.hosts {
        add(&mut tenants, host.tenant.as_deref());
        add(&mut sites, host.site.as_deref());
    }
    for prefix in &model.prefixes {
        add(&mut vrfs, prefix.vrf.as_deref());
        add(&mut sites, prefix.site.as_deref());
    }
    for vlan in &model.vlans {
        add(&mut sites, vlan.site.as_deref());
    }
    for address in &model.addresses {
        add(&mut vrfs, address.vrf.as_deref());
    }
    items.extend(tenants.into_values().map(WorkItem::Tenant));
    items.extend(vrfs.into_values().map(WorkItem::Vrf));
    items.extend(sites.into_values().map(WorkItem::Site));
    items.extend((0..model.vlans.len()).map(WorkItem::Vlan));
    items.extend((0..model.prefixes.len()).map(WorkItem::Prefix));
    items.extend((0..model.hosts.len()).map(WorkItem::Host));
    items.extend((0..model.addresses.len()).map(WorkItem::Address));
    items
}

/// What reconciling did to an item.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ItemAction {
    /// The item is new.
    Create,
    /// The item exists and differs; it is updated.
    Update,
    /// The item exists and is equal.
    Unchanged,
    /// The item exists and differs; the conflict policy keeps the store's values.
    Kept,
}

/// The outcome of one model item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ItemOutcome {
    /// The item.
    pub key: ItemKey,
    /// What happens.
    pub action: ItemAction,
    /// The fields that differ (update or kept).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// A credential to write for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialOp {
    /// The host by name (the values are keyed by it).
    pub host: HostName,
    /// The host's identifier (client-chosen when the host is new).
    pub host_id: HostId,
    /// The credential an earlier import stored for the host.
    pub existing: Option<HostCredential>,
}

/// The result of reconciling a slice of work items.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reconciled {
    /// The commands, in order.
    pub commands: Vec<IpamCommand>,
    /// One outcome per item that maps to a model item (tenants, VRFs and sites included).
    pub outcomes: Vec<ItemOutcome>,
    /// Credentials of hosts in the slice.
    pub credentials: Vec<CredentialOp>,
    /// Problems found on the way (conflicts kept, invalid tags or custom values).
    pub issues: Vec<LossEntry>,
    /// Whether a conflict under [`ConflictPolicy::Fail`] blocks the import.
    pub blocked: bool,
    /// The supernet steps: existing networks the slice turns into supernets, with the
    /// number of imported networks inside each.
    pub supernet_steps: BTreeMap<PrefixId, usize>,
}

/// Reconciles `items` of `model` against `view`.
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn reconcile(
    view: &dyn ReadView,
    model: &ImportModel,
    options: &ImportOptions,
    items: &[WorkItem],
) -> IpamResult<Reconciled> {
    let mut r = Reconciler::new(view, model, options)?;
    for item in items {
        r.item(item)?;
    }
    Ok(r.out)
}

struct Reconciler<'a> {
    view: &'a dyn ReadView,
    model: &'a ImportModel,
    options: &'a ImportOptions,
    defs: BTreeMap<FieldKey, CustomFieldDef>,
    reported_undefined: BTreeSet<String>,
    tenants: HashMap<String, Option<TenantId>>,
    vrfs: HashMap<String, Option<VrfId>>,
    sites: HashMap<String, Option<SiteId>>,
    vlans: HashMap<(Option<SiteId>, u16), Option<VlanId>>,
    hosts: HashMap<(String, HostName), Option<HostId>>,
    interfaces: HashMap<(HostId, String), InterfaceId>,
    out: Reconciled,
}

impl<'a> Reconciler<'a> {
    fn new(
        view: &'a dyn ReadView,
        model: &'a ImportModel,
        options: &'a ImportOptions,
    ) -> IpamResult<Self> {
        let defs = crate::query::custom_fields(view)?
            .into_iter()
            .map(|def| (def.key.clone(), def))
            .collect();
        Ok(Self {
            view,
            model,
            options,
            defs,
            reported_undefined: BTreeSet::new(),
            tenants: HashMap::new(),
            vrfs: HashMap::new(),
            sites: HashMap::new(),
            vlans: HashMap::new(),
            hosts: HashMap::new(),
            interfaces: HashMap::new(),
            out: Reconciled::default(),
        })
    }

    fn issue(&mut self, location: &SourceLocation, code: &'static str, detail: String) {
        self.out.issues.push(LossEntry {
            location: location.clone(),
            code: code.into(),
            detail,
        });
    }

    fn outcome(&mut self, key: ItemKey, action: ItemAction, fields: Vec<String>) {
        self.out.outcomes.push(ItemOutcome {
            key,
            action,
            fields,
        });
    }

    /// Applies the conflict policy to a difference: whether the update goes ahead.
    fn conflict(&mut self, key: &ItemKey, fields: &[String], location: &SourceLocation) -> bool {
        match self.options.conflict {
            ConflictPolicy::Update => true,
            policy => {
                self.issue(
                    location,
                    codes::CONFLICT_KEPT,
                    format!(
                        "{} differs from the store in {}; {}",
                        key.label(),
                        fields.join(", "),
                        if policy == ConflictPolicy::Fail {
                            "the conflict policy refuses the import"
                        } else {
                            "the store's values are kept"
                        }
                    ),
                );
                if policy == ConflictPolicy::Fail {
                    self.out.blocked = true;
                }
                false
            }
        }
    }

    // ----- names -----------------------------------------------------------------------

    fn tenant_id(&mut self, name: Option<&str>) -> IpamResult<Option<TenantId>> {
        let name = name
            .or(self.options.tenant.as_deref())
            .unwrap_or(DEFAULT_NAME);
        let key = name.to_lowercase();
        if let Some(id) = self.tenants.get(&key) {
            return Ok(*id);
        }
        let id = self.view.get_typed(&TENANT_NAMES, &key)?.map(|(id, _)| id);
        self.tenants.insert(key, id);
        Ok(id)
    }

    /// The VRF of an item; `None` when it does not exist (yet).
    fn vrf_id(&mut self, name: Option<&str>) -> IpamResult<Option<VrfId>> {
        let key = vrf_key(name, self.options.vrf.as_deref());
        if let Some(id) = self.vrfs.get(&key) {
            return Ok(*id);
        }
        let tenant = if is_default(&key) {
            self.tenant_id(Some(DEFAULT_NAME))?
        } else {
            self.tenant_id(None)?
        };
        let id = match tenant {
            Some(tenant) => self
                .view
                .get_typed(&VRF_NAMES, &(tenant, key.clone()))?
                .map(|(id, _)| id),
            None => None,
        };
        self.vrfs.insert(key, id);
        Ok(id)
    }

    /// The VRF field of a new object: `None` for the default VRF.
    fn vrf_input(&mut self, name: Option<&str>) -> IpamResult<Option<VrfId>> {
        if is_default(&vrf_key(name, self.options.vrf.as_deref())) {
            return Ok(None);
        }
        self.vrf_id(name)
    }

    /// The tenant field of a new object: `None` for the default tenant.
    fn tenant_input(&mut self, name: Option<&str>) -> IpamResult<Option<TenantId>> {
        let name = name.or(self.options.tenant.as_deref());
        match name {
            Some(name) if !is_default(name) => self.tenant_id(Some(name)),
            _ => Ok(None),
        }
    }

    fn site_id(&mut self, name: &str) -> IpamResult<Option<SiteId>> {
        let key = name.to_lowercase();
        if let Some(id) = self.sites.get(&key) {
            return Ok(*id);
        }
        let id = self.view.get_typed(&SITE_NAMES, &key)?.map(|(id, _)| id);
        self.sites.insert(key, id);
        Ok(id)
    }

    fn vlan_id(&mut self, site: Option<&str>, vid: u16) -> IpamResult<Option<VlanId>> {
        let site = match site {
            Some(site) => self.site_id(site)?,
            None => None,
        };
        if let Some(id) = self.vlans.get(&(site, vid)) {
            return Ok(*id);
        }
        let id = self
            .view
            .get_typed(&VLAN_VIDS, &(site, vid))?
            .map(|(id, _)| id);
        self.vlans.insert((site, vid), id);
        Ok(id)
    }

    fn host_id(&mut self, tenant: Option<&str>, name: &HostName) -> IpamResult<Option<HostId>> {
        let tenant_key = tenant
            .or(self.options.tenant.as_deref())
            .unwrap_or(DEFAULT_NAME)
            .to_lowercase();
        if let Some(id) = self.hosts.get(&(tenant_key.clone(), name.clone())) {
            return Ok(*id);
        }
        let id = match self.tenant_id(tenant)? {
            Some(tenant) => self
                .view
                .get_typed(&HOST_NAMES, &(tenant, name.clone()))?
                .map(|(id, _)| id),
            None => None,
        };
        self.hosts.insert((tenant_key, name.clone()), id);
        Ok(id)
    }

    /// The live interfaces of an existing host, by name.
    fn host_interfaces(&mut self, host: HostId) -> IpamResult<BTreeMap<String, Interface>> {
        let rows = self.view.scan_typed(
            &HOST_INTERFACES,
            KeyRange::prefix(tenko_core::codec::encode_key(&host)),
            usize::MAX,
            false,
        )?;
        let mut interfaces = BTreeMap::new();
        for ((_, id), (), _) in rows {
            if let Some((interface, _)) = self.view.get_typed(&INTERFACES, &id)?
                && !interface.meta.is_deleted()
            {
                self.interfaces.insert((host, interface.name.clone()), id);
                interfaces.insert(interface.name.clone(), interface);
            }
        }
        Ok(interfaces)
    }

    // ----- metadata --------------------------------------------------------------------

    fn tags(&mut self, tags: &[String], location: &SourceLocation) -> BTreeSet<Tag> {
        let mut set = BTreeSet::new();
        for tag in tags {
            match Tag::new(tag) {
                Ok(tag) => {
                    set.insert(tag);
                }
                Err(_) => self.issue(
                    location,
                    codes::VALUE_INVALID,
                    format!("`{tag}` is not a valid tag; it is left out"),
                ),
            }
        }
        set
    }

    fn custom(
        &mut self,
        kind: ObjectKind,
        values: &BTreeMap<String, String>,
        location: &SourceLocation,
    ) -> BTreeMap<FieldKey, CustomValue> {
        let mut out = BTreeMap::new();
        for (key, text) in values {
            let Ok(field) = FieldKey::new(key) else {
                continue;
            };
            let Some(def) = self.defs.get(&field).cloned() else {
                if self.reported_undefined.insert(key.clone()) {
                    self.issue(
                        location,
                        codes::CUSTOM_UNDEFINED,
                        format!("the custom field `{key}` is not defined; its values are left out"),
                    );
                }
                continue;
            };
            if !def.applies_to.contains(&kind) {
                self.issue(
                    location,
                    codes::VALUE_INVALID,
                    format!("the custom field `{key}` does not apply to {kind} objects; the value is left out"),
                );
                continue;
            }
            match custom::parse_value(&field, &def.kind, text) {
                Ok(value) => {
                    out.insert(field, value);
                }
                Err(problem) => self.issue(
                    location,
                    codes::VALUE_INVALID,
                    format!("{}; the value is left out", problem.message),
                ),
            }
        }
        out
    }

    // ----- items -----------------------------------------------------------------------

    fn item(&mut self, item: &WorkItem) -> IpamResult<()> {
        match item {
            WorkItem::Tenant(name) => self.tenant(name),
            WorkItem::Vrf(name) => self.vrf(name),
            WorkItem::Site(name) => self.site(name),
            WorkItem::Vlan(index) => self.vlan(&self.model.vlans[*index]),
            WorkItem::Prefix(index) => self.prefix(&self.model.prefixes[*index]),
            WorkItem::Host(index) => self.host(&self.model.hosts[*index]),
            WorkItem::Address(index) => self.address(&self.model.addresses[*index]),
        }
    }

    fn tenant(&mut self, name: &str) -> IpamResult<()> {
        if self.tenant_id(Some(name))?.is_some() {
            return Ok(());
        }
        let id = TenantId::generate();
        self.tenants.insert(name.to_lowercase(), Some(id));
        self.out
            .commands
            .push(IpamCommand::CreateTenant(TenantInput {
                id: Some(id),
                name: name.to_owned(),
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }));
        Ok(())
    }

    fn vrf(&mut self, name: &str) -> IpamResult<()> {
        if self.vrf_id(Some(name))?.is_some() {
            return Ok(());
        }
        let id = VrfId::generate();
        let tenant = self.tenant_input(None)?;
        self.vrfs.insert(name.to_lowercase(), Some(id));
        self.out.commands.push(IpamCommand::CreateVrf(VrfInput {
            id: Some(id),
            tenant,
            name: name.to_owned(),
            rd: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }));
        Ok(())
    }

    fn site(&mut self, name: &str) -> IpamResult<()> {
        if self.site_id(name)?.is_some() {
            return Ok(());
        }
        let id = SiteId::generate();
        self.sites.insert(name.to_lowercase(), Some(id));
        self.out.commands.push(IpamCommand::CreateSite(SiteInput {
            id: Some(id),
            name: name.to_owned(),
            parent: None,
            ad_site: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }));
        Ok(())
    }

    fn vlan(&mut self, vlan: &ModelVlan) -> IpamResult<()> {
        let key = ItemKey::Vlan {
            site: vlan.site.clone(),
            vid: vlan.vid,
        };
        let site = match &vlan.site {
            Some(site) => self.site_id(site)?,
            None => None,
        };
        let Some(id) = self.vlan_id(vlan.site.as_deref(), vlan.vid)? else {
            let id = VlanId::generate();
            self.vlans.insert((site, vlan.vid), Some(id));
            self.out.commands.push(IpamCommand::CreateVlan(VlanInput {
                id: Some(id),
                vid: vlan.vid,
                vni: None,
                name: vlan
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("VLAN {}", vlan.vid)),
                site,
                status: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }));
            self.outcome(key, ItemAction::Create, Vec::new());
            return Ok(());
        };
        let Some((existing, _)) = self.view.get_typed(&VLANS, &id)? else {
            return Ok(());
        };
        let differs = vlan.name.as_ref().is_some_and(|n| *n != existing.name);
        if differs && self.conflict(&key, &["name".to_owned()], &vlan.origin) {
            self.out.commands.push(IpamCommand::UpdateVlan(UpdateVlan {
                id,
                expected: None,
                patch: VlanPatch {
                    name: vlan.name.clone(),
                    ..VlanPatch::default()
                },
            }));
            self.outcome(key, ItemAction::Update, vec!["name".to_owned()]);
        } else {
            let action = if differs {
                ItemAction::Kept
            } else {
                ItemAction::Unchanged
            };
            self.outcome(key, action, Vec::new());
        }
        Ok(())
    }

    fn alarm(
        &mut self,
        prefix: &ModelPrefix,
        existing: Option<UtilizationAlarm>,
    ) -> Option<UtilizationAlarm> {
        let warn = prefix.alarm_warn.or(existing.map(|a| a.warn_pct))?;
        let crit = prefix.alarm_crit.or(existing.map(|a| a.crit_pct))?;
        if prefix.alarm_warn.is_none() && prefix.alarm_crit.is_none() {
            return existing;
        }
        if let Ok(alarm) = UtilizationAlarm::new(warn, crit) {
            Some(alarm)
        } else {
            self.issue(
                &prefix.origin,
                codes::VALUE_INVALID,
                format!(
                    "the alarm thresholds {warn}/{crit} of {} are not ordered; they are left out",
                    prefix.cidr
                ),
            );
            existing
        }
    }

    #[allow(clippy::too_many_lines)] // One comparison per prefix field.
    fn prefix(&mut self, prefix: &ModelPrefix) -> IpamResult<()> {
        let key = ItemKey::Prefix {
            vrf: vrf_key(prefix.vrf.as_deref(), self.options.vrf.as_deref()),
            cidr: prefix.cidr.to_string(),
        };
        let vlan = match prefix.vlan {
            Some(vid) => self.vlan_id(prefix.site.as_deref(), vid)?,
            None => None,
        };
        let site = match &prefix.site {
            Some(site) => self.site_id(site)?,
            None => None,
        };
        let tags = self.tags(&prefix.tags, &prefix.origin);
        let custom = self.custom(ObjectKind::Prefix, &prefix.custom, &prefix.origin);
        let existing = match self.vrf_id(prefix.vrf.as_deref())? {
            Some(vrf) => match self.view.get_typed(&PREFIX_CIDRS, &(vrf, prefix.cidr))? {
                Some((id, _)) => self.view.get_typed(&PREFIXES, &id)?.map(|(p, _)| p),
                None => None,
            },
            None => None,
        };
        let Some(existing) = existing else {
            if !self.supernet_step(prefix)? {
                self.outcome(key, ItemAction::Kept, Vec::new());
                return Ok(());
            }
            let alarm = self.alarm(prefix, None);
            let vrf = self.vrf_input(prefix.vrf.as_deref())?;
            self.out
                .commands
                .push(IpamCommand::CreatePrefix(PrefixInput {
                    id: Some(PrefixId::generate()),
                    vrf,
                    cidr: prefix.cidr,
                    role: prefix.role,
                    status: prefix.status,
                    vlan,
                    site,
                    alarm,
                    alloc: prefix.alloc,
                    tags,
                    custom,
                    description: prefix.description.clone(),
                }));
            self.outcome(key, ItemAction::Create, Vec::new());
            return Ok(());
        };
        let mut patch = PrefixPatch::default();
        let mut fields = Vec::new();
        if let Some(role) = prefix.role
            && role != existing.role
        {
            patch.role = Some(role);
            fields.push("role".to_owned());
            if role == PrefixRole::Supernet {
                // The networks of the import inside it need no supernet step of their own.
                self.out.supernet_steps.entry(existing.id).or_default();
            }
        }
        if let Some(status) = prefix.status
            && status != existing.status
        {
            if status_transition_allowed(existing.status, status) {
                patch.status = Some(status);
                fields.push("status".to_owned());
            } else {
                self.transition_issue(&key, existing.status, status, &prefix.origin);
            }
        }
        if prefix.vlan.is_some() && vlan != existing.vlan {
            patch.vlan = Some(vlan);
            fields.push("vlan".to_owned());
        }
        if prefix.site.is_some() && site != existing.site {
            patch.site = Some(site);
            fields.push("site".to_owned());
        }
        let alarm = self.alarm(prefix, existing.alarm);
        if alarm != existing.alarm {
            patch.alarm = Some(alarm);
            fields.push("alarm".to_owned());
        }
        if let Some(alloc) = prefix.alloc
            && alloc != existing.alloc
        {
            patch.alloc = Some(alloc);
            fields.push("alloc".to_owned());
        }
        meta_patch(
            &existing.meta,
            prefix.description.as_ref(),
            &tags,
            &custom,
            &mut fields,
            |d, t, c| {
                patch.description = d;
                patch.tags = t;
                patch.custom = c;
            },
        );
        if fields.is_empty() {
            self.outcome(key, ItemAction::Unchanged, Vec::new());
        } else if self.conflict(&key, &fields, &prefix.origin) {
            self.out
                .commands
                .push(IpamCommand::UpdatePrefix(UpdatePrefix {
                    id: existing.id,
                    expected: None,
                    patch,
                }));
            self.outcome(key, ItemAction::Update, fields);
        } else {
            self.outcome(key, ItemAction::Kept, fields);
        }
        Ok(())
    }

    /// The supernet step (the owner's backlog): a new network inside an existing network
    /// of the store turns that network into a supernet, once per network, with an update
    /// the plan warns about (`ipam.prefix.becomes_supernet`, to acknowledge) instead of
    /// refusing every network inside with `ipam.prefix.overlap`. A network a DHCP scope
    /// serves (`dhcp.scope.attached`) or one with ranges stays a network: the imported
    /// network is left out with `import.prefix.in_network`, and its addresses go to the
    /// existing network. Returns whether the imported network can be created.
    fn supernet_step(&mut self, prefix: &ModelPrefix) -> IpamResult<bool> {
        let Some(vrf) = self.vrf_id(prefix.vrf.as_deref())? else {
            return Ok(true);
        };
        let Some(parent) = self.store_parent(vrf, &prefix.cidr)? else {
            return Ok(true);
        };
        if parent.role != PrefixRole::Network {
            return Ok(true);
        }
        if let Some(count) = self.out.supernet_steps.get_mut(&parent.id) {
            *count += 1;
            return Ok(true);
        }
        let reason = if self
            .view
            .get_typed(&tenko_core::dhcp::tables::SCOPES, &parent.id)?
            .is_some()
        {
            Some("a DHCP scope serves it")
        } else if self.has_ranges(parent.id)? {
            Some("it has ranges")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.issue(
                &prefix.origin,
                codes::PREFIX_IN_NETWORK,
                format!(
                    "{} lies in the network {}, which stays a network because {reason}; {} is not created and its addresses go to {}",
                    prefix.cidr, parent.cidr, prefix.cidr, parent.cidr
                ),
            );
            return Ok(false);
        }
        self.out
            .commands
            .push(IpamCommand::UpdatePrefix(UpdatePrefix {
                id: parent.id,
                expected: None,
                patch: PrefixPatch {
                    role: Some(PrefixRole::Supernet),
                    ..PrefixPatch::default()
                },
            }));
        self.out.supernet_steps.insert(parent.id, 1);
        self.outcome(
            ItemKey::Prefix {
                vrf: vrf_key(prefix.vrf.as_deref(), self.options.vrf.as_deref()),
                cidr: parent.cidr.to_string(),
            },
            ItemAction::Update,
            vec!["role".to_owned()],
        );
        Ok(true)
    }

    /// The most specific live prefix of the store that contains `cidr` (not `cidr` itself).
    fn store_parent(&self, vrf: VrfId, cidr: &IpNet) -> IpamResult<Option<Prefix>> {
        for length in (0..cidr.prefix_len()).rev() {
            let Ok(net) = IpNet::new(cidr.network(), length) else {
                continue;
            };
            if let Some((id, _)) = self.view.get_typed(&PREFIX_CIDRS, &(vrf, net.trunc()))?
                && let Some((parent, _)) = self.view.get_typed(&PREFIXES, &id)?
                && !parent.meta.is_deleted()
            {
                return Ok(Some(parent));
            }
        }
        Ok(None)
    }

    /// Whether a prefix has live ranges.
    fn has_ranges(&self, prefix: PrefixId) -> IpamResult<bool> {
        let rows = self.view.scan_typed(
            &PREFIX_RANGES,
            KeyRange::prefix(encode_key(&prefix)),
            usize::MAX,
            false,
        )?;
        for ((_, range), (), _) in rows {
            if let Some((range, _)) = self.view.get_typed(&RANGES, &range)? {
                let range: Range = range;
                if !range.meta.is_deleted() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn transition_issue(
        &mut self,
        key: &ItemKey,
        from: Status,
        to: Status,
        location: &SourceLocation,
    ) {
        self.issue(
            location,
            codes::VALUE_INVALID,
            format!(
                "{} cannot change status from {} to {}; the status is left as it is",
                key.label(),
                status_name(from),
                status_name(to)
            ),
        );
    }

    fn interface_input(interface: &ModelInterface, host: Option<HostId>) -> InterfaceInput {
        InterfaceInput {
            id: Some(InterfaceId::generate()),
            host,
            name: interface.name.clone(),
            mac: interface.mac,
            duid: interface.duid.clone(),
            client_id: interface.client_id.as_deref().and_then(hex_bytes),
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }
    }

    fn host(&mut self, host: &ModelHost) -> IpamResult<()> {
        let key = ItemKey::Host {
            name: host.name.to_string(),
        };
        let site = match &host.site {
            Some(site) => self.site_id(site)?,
            None => None,
        };
        let tags = self.tags(&host.tags, &host.origin);
        let custom = self.custom(ObjectKind::Host, &host.custom, &host.origin);
        let tenant_key = host
            .tenant
            .as_deref()
            .or(self.options.tenant.as_deref())
            .unwrap_or(DEFAULT_NAME)
            .to_lowercase();
        let existing = match self.host_id(host.tenant.as_deref(), &host.name)? {
            Some(id) => self.view.get_typed(&HOSTS, &id)?.map(|(h, _)| h),
            None => None,
        };
        let host_id = match existing {
            None => {
                let id = HostId::generate();
                let tenant = self.tenant_input(host.tenant.as_deref())?;
                let interfaces: Vec<InterfaceInput> = host
                    .interfaces
                    .iter()
                    .map(|i| Self::interface_input(i, None))
                    .collect();
                for (model, input) in host.interfaces.iter().zip(&interfaces) {
                    if let Some(interface) = input.id {
                        self.interfaces.insert((id, model.name.clone()), interface);
                    }
                    self.outcome(
                        ItemKey::Interface {
                            host: host.name.to_string(),
                            name: model.name.clone(),
                        },
                        ItemAction::Create,
                        Vec::new(),
                    );
                }
                self.hosts.insert((tenant_key, host.name.clone()), Some(id));
                self.out.commands.push(IpamCommand::CreateHost(HostInput {
                    id: Some(id),
                    tenant,
                    name: host.name.clone(),
                    mode: host.mode,
                    lock: host.lock,
                    site,
                    interfaces,
                    tags,
                    custom,
                    description: host.description.clone(),
                }));
                self.outcome(key, ItemAction::Create, Vec::new());
                id
            }
            Some(existing) => {
                self.update_host(host, &existing, key, site, &tags, &custom);
                self.host_interfaces_update(host, existing.id)?;
                existing.id
            }
        };
        if self.options.credentials == CredentialPolicy::Import
            && self.model.credentials.iter().any(|c| c.host == host.name)
        {
            let existing = self
                .view
                .get_typed(&HOST_CREDENTIALS, &host_id)?
                .map(|(row, _)| row);
            self.out.credentials.push(CredentialOp {
                host: host.name.clone(),
                host_id,
                existing,
            });
        }
        Ok(())
    }

    fn update_host(
        &mut self,
        host: &ModelHost,
        existing: &Host,
        key: ItemKey,
        site: Option<SiteId>,
        tags: &BTreeSet<Tag>,
        custom: &BTreeMap<FieldKey, CustomValue>,
    ) {
        let mut patch = HostPatch::default();
        let mut fields = Vec::new();
        if let Some(mode) = host.mode
            && mode != existing.mode
        {
            patch.mode = Some(mode);
            fields.push("mode".to_owned());
        }
        if let Some(lock) = host.lock
            && lock != existing.lock
        {
            patch.lock = Some(lock);
            fields.push("lock".to_owned());
        }
        if host.site.is_some() && site != existing.site {
            patch.site = Some(site);
            fields.push("site".to_owned());
        }
        meta_patch(
            &existing.meta,
            host.description.as_ref(),
            tags,
            custom,
            &mut fields,
            |d, t, c| {
                patch.description = d;
                patch.tags = t;
                patch.custom = c;
            },
        );
        if fields.is_empty() {
            self.outcome(key, ItemAction::Unchanged, Vec::new());
        } else if self.conflict(&key, &fields, &host.origin) {
            self.out.commands.push(IpamCommand::UpdateHost(UpdateHost {
                id: existing.id,
                expected: None,
                patch,
            }));
            self.outcome(key, ItemAction::Update, fields);
        } else {
            self.outcome(key, ItemAction::Kept, fields);
        }
    }

    fn host_interfaces_update(&mut self, host: &ModelHost, host_id: HostId) -> IpamResult<()> {
        let existing = self.host_interfaces(host_id)?;
        for interface in &host.interfaces {
            let key = ItemKey::Interface {
                host: host.name.to_string(),
                name: interface.name.clone(),
            };
            let Some(current) = existing.get(&interface.name) else {
                let input = Self::interface_input(interface, Some(host_id));
                if let Some(id) = input.id {
                    self.interfaces
                        .insert((host_id, interface.name.clone()), id);
                }
                self.out.commands.push(IpamCommand::CreateInterface(input));
                self.outcome(key, ItemAction::Create, Vec::new());
                continue;
            };
            let mut patch = InterfacePatch::default();
            let mut fields = Vec::new();
            if interface.mac.is_some() && interface.mac != current.mac {
                patch.mac = Some(interface.mac);
                fields.push("mac".to_owned());
            }
            if interface.duid.is_some() && interface.duid != current.duid {
                patch.duid = Some(interface.duid.clone());
                fields.push("duid".to_owned());
            }
            let client_id = interface.client_id.as_deref().and_then(hex_bytes);
            if client_id.is_some() && client_id != current.client_id {
                patch.client_id = Some(client_id);
                fields.push("client_id".to_owned());
            }
            if fields.is_empty() {
                self.outcome(key, ItemAction::Unchanged, Vec::new());
            } else if self.conflict(&key, &fields, &interface.origin) {
                self.out
                    .commands
                    .push(IpamCommand::UpdateInterface(UpdateInterface {
                        id: current.id,
                        expected: None,
                        patch,
                    }));
                self.outcome(key, ItemAction::Update, fields);
            } else {
                self.outcome(key, ItemAction::Kept, fields);
            }
        }
        Ok(())
    }

    /// The interface an address goes on: known from this chunk or the store.
    fn interface_of(&mut self, address: &ModelAddress) -> IpamResult<Option<InterfaceId>> {
        let (Some(host), Some(name)) = (&address.host, &address.interface) else {
            return Ok(None);
        };
        let tenant = self.model.host(host).and_then(|h| h.tenant.clone());
        let Some(host_id) = self.host_id(tenant.as_deref(), host)? else {
            return Ok(None);
        };
        if let Some(id) = self.interfaces.get(&(host_id, name.clone())) {
            return Ok(Some(*id));
        }
        let interfaces = self.host_interfaces(host_id)?;
        Ok(interfaces.get(name).map(|i| i.id))
    }

    fn address(&mut self, address: &ModelAddress) -> IpamResult<()> {
        let key = ItemKey::Address {
            vrf: vrf_key(address.vrf.as_deref(), self.options.vrf.as_deref()),
            ip: address.ip.to_string(),
        };
        let tags = self.tags(&address.tags, &address.origin);
        let custom = self.custom(ObjectKind::Address, &address.custom, &address.origin);
        let interface = self.interface_of(address)?;
        let existing = match self.vrf_id(address.vrf.as_deref())? {
            Some(vrf) => match self.view.get_typed(&ADDRESS_IPS, &(vrf, address.ip))? {
                Some((id, _)) => self.view.get_typed(&ADDRESSES, &id)?.map(|(a, _)| a),
                None => None,
            },
            None => None,
        };
        let Some(existing) = existing else {
            let vrf = self.vrf_input(address.vrf.as_deref())?;
            self.out
                .commands
                .push(IpamCommand::CreateAddress(AddressInput {
                    id: Some(AddressId::generate()),
                    vrf,
                    ip: address.ip,
                    status: address.status,
                    interface,
                    dns_name: address.dns_name.clone(),
                    tags,
                    custom,
                    description: address.description.clone(),
                }));
            self.outcome(key, ItemAction::Create, Vec::new());
            return Ok(());
        };
        self.update_address(address, &existing, key, interface, &tags, &custom);
        Ok(())
    }

    fn update_address(
        &mut self,
        address: &ModelAddress,
        existing: &Address,
        key: ItemKey,
        interface: Option<InterfaceId>,
        tags: &BTreeSet<Tag>,
        custom: &BTreeMap<FieldKey, CustomValue>,
    ) {
        let mut patch = AddressPatch::default();
        let mut fields = Vec::new();
        if address.host.is_some() && interface.is_some() && interface != existing.interface {
            patch.interface = Some(interface);
            fields.push("interface".to_owned());
        }
        if let Some(status) = address.status
            && status != existing.status
        {
            if status_transition_allowed(existing.status, status) {
                patch.status = Some(status);
                fields.push("status".to_owned());
            } else {
                self.transition_issue(&key, existing.status, status, &address.origin);
            }
        }
        if address.dns_name.is_some() && address.dns_name != existing.dns_name {
            patch.dns_name = Some(address.dns_name.clone());
            fields.push("dns_name".to_owned());
        }
        meta_patch(
            &existing.meta,
            address.description.as_ref(),
            tags,
            custom,
            &mut fields,
            |d, t, c| {
                patch.description = d;
                patch.tags = t;
                patch.custom = c;
            },
        );
        if fields.is_empty() {
            self.outcome(key, ItemAction::Unchanged, Vec::new());
        } else if self.conflict(&key, &fields, &address.origin) {
            self.out
                .commands
                .push(IpamCommand::UpdateAddress(UpdateAddress {
                    id: existing.id,
                    expected: None,
                    patch,
                }));
            self.outcome(key, ItemAction::Update, fields);
        } else {
            self.outcome(key, ItemAction::Kept, fields);
        }
    }
}

type MetaParts = (
    Option<Option<String>>,
    Option<BTreeSet<Tag>>,
    Option<BTreeMap<FieldKey, Option<CustomValue>>>,
);

/// Compares the metadata the source sets with the stored metadata and hands the patch
/// parts to `set`: the description when it differs, the union of tags when the source
/// adds one, the custom values that differ.
fn meta_patch(
    meta: &tenko_core::ipam::Meta,
    description: Option<&String>,
    tags: &BTreeSet<Tag>,
    custom: &BTreeMap<FieldKey, CustomValue>,
    fields: &mut Vec<String>,
    set: impl FnOnce(
        Option<Option<String>>,
        Option<BTreeSet<Tag>>,
        Option<BTreeMap<FieldKey, Option<CustomValue>>>,
    ),
) {
    let mut parts: MetaParts = (None, None, None);
    if let Some(description) = description
        && meta.description.as_deref() != Some(description.trim())
    {
        parts.0 = Some(Some(description.clone()));
        fields.push("description".to_owned());
    }
    if !tags.is_subset(&meta.tags) {
        parts.1 = Some(meta.tags.union(tags).cloned().collect());
        fields.push("tags".to_owned());
    }
    let changed: BTreeMap<FieldKey, Option<CustomValue>> = custom
        .iter()
        .filter(|(key, value)| meta.custom.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), Some(value.clone())))
        .collect();
    if !changed.is_empty() {
        for key in changed.keys() {
            fields.push(format!("custom.{key}"));
        }
        parts.2 = Some(changed);
    }
    set(parts.0, parts.1, parts.2);
}

fn hex_bytes(hex: &str) -> Option<HexBytes> {
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect();
    bytes.map(HexBytes)
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Planned => "planned",
        Status::Active => "active",
        Status::Reserved => "reserved",
        Status::Deprecated => "deprecated",
    }
}

/// The live prefixes of the store by VRF name (lowercase), for translation.
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn known_prefixes(view: &dyn ReadView) -> IpamResult<super::translate::KnownPrefixes> {
    let mut names: HashMap<VrfId, String> = HashMap::new();
    let mut known: BTreeMap<String, Vec<(IpNet, tenko_core::ipam::PrefixRole)>> = BTreeMap::new();
    for ((vrf, _), id, _) in view.scan_typed(&PREFIX_CIDRS, KeyRange::all(), usize::MAX, false)? {
        let name = if let Some(name) = names.get(&vrf) {
            name.clone()
        } else {
            let name = view
                .get_typed(&crate::tables::VRFS, &vrf)?
                .map_or_else(String::new, |(v, _)| v.name.to_lowercase());
            names.insert(vrf, name.clone());
            name
        };
        if let Some((prefix, _)) = view.get_typed(&PREFIXES, &id)? {
            known
                .entry(name)
                .or_default()
                .push((prefix.cidr, prefix.role));
        }
    }
    Ok(super::translate::KnownPrefixes(known))
}

/// Unused imports guard for kinds only referenced in docs.
#[allow(dead_code)]
fn _kinds(_: &Prefix, _: &Vlan, _: IpAddr) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_client_ids() {
        assert_eq!(hex_bytes("01ab"), Some(HexBytes(vec![0x01, 0xab])));
        assert_eq!(hex_bytes("zz"), None);
    }
}
