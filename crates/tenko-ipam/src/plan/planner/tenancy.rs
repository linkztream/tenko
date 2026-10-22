//! Tenants, VRFs, sites and VLANs (IPAM-01, IPAM-03, IPAM-04), and the default tenant and
//! VRF created on first use.

use tenko_core::{
    ObjectRef, Revision, SiteId, TenantId, VlanId, VrfId,
    codec::encode_key,
    ipam::{Host, Prefix, Site, Status, Tenant, Vlan, Vrf},
};
use tenko_store::KeyRange;

use super::{DEFAULT_NAME, Planner, clean_name};
use crate::{
    command::{
        SiteInput, TenantInput, UpdateSite, UpdateTenant, UpdateVlan, UpdateVrf, VlanInput,
        VrfInput,
    },
    error::{IpamError, IpamResult, codes},
    history::ChangeAction,
    object::{Entity, IpamObject},
    tables::{
        HOST_NAMES, HOSTS, PREFIX_CIDRS, PREFIXES, SITE_NAMES, SITES, TENANT_NAMES, VLAN_VIDS,
        VLANS, VRF_NAMES, tree_counter,
    },
};

/// Largest VXLAN network identifier.
const MAX_VNI: u32 = 0x00FF_FFFF;

impl Planner<'_> {
    // ----- defaults ---------------------------------------------------------------------

    /// The tenant named `default`, created on first use.
    pub(super) fn default_tenant(&mut self) -> IpamResult<TenantId> {
        if let Some(id) = self.default_tenant {
            return Ok(id);
        }
        let existing = self
            .ws
            .get_typed(&TENANT_NAMES, &DEFAULT_NAME.to_owned(), true)?;
        let id = if let Some((id, _)) = existing {
            id
        } else {
            let input = TenantInput {
                id: None,
                name: DEFAULT_NAME.to_owned(),
                tags: std::collections::BTreeSet::new(),
                custom: std::collections::BTreeMap::new(),
                description: Some("Created on first use".to_owned()),
            };
            self.create_tenant_derived(&input, true)?.id
        };
        self.default_tenant = Some(id);
        Ok(id)
    }

    /// The VRF named `default` of the default tenant, created on first use.
    pub(super) fn default_vrf(&mut self) -> IpamResult<VrfId> {
        if let Some(id) = self.default_vrf {
            return Ok(id);
        }
        let tenant = self.default_tenant()?;
        let key = (tenant, DEFAULT_NAME.to_owned());
        let existing = self.ws.get_typed(&VRF_NAMES, &key, true)?;
        let id = if let Some((id, _)) = existing {
            id
        } else {
            let input = VrfInput {
                id: None,
                tenant: Some(tenant),
                name: DEFAULT_NAME.to_owned(),
                rd: None,
                tags: std::collections::BTreeSet::new(),
                custom: std::collections::BTreeMap::new(),
                description: Some("Created on first use".to_owned()),
            };
            self.create_vrf_inner(&input, true)?
        };
        self.default_vrf = Some(id);
        Ok(id)
    }

    // ----- tenants ----------------------------------------------------------------------

    pub(super) fn create_tenant(&mut self, input: &TenantInput) -> IpamResult<ObjectRef> {
        Ok(self.create_tenant_derived(input, false)?.id.into())
    }

    fn create_tenant_derived(&mut self, input: &TenantInput, derived: bool) -> IpamResult<Tenant> {
        let name = clean_name("name", &input.name)?;
        let id = self.claim_id::<Tenant>(input.id)?;
        self.claim_tenant_name(&name)?;
        let meta = self.new_meta(
            Tenant::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let tenant = Tenant {
            id,
            name,
            dns: tenko_core::dns::TenantDns::default(),
            meta,
        };
        self.write(&tenant)?;
        self.ws
            .put_typed(&TENANT_NAMES, &tenant.name.to_lowercase(), &id)?;
        self.sync_usage(id.into(), None, Some(&tenant.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Tenant(tenant.clone())),
            derived,
        )?;
        Ok(tenant)
    }

    fn claim_tenant_name(&mut self, name: &str) -> IpamResult<()> {
        let key = name.to_lowercase();
        if self.ws.exists(&TENANT_NAMES, &key, true)? {
            return Err(name_taken("tenant", name));
        }
        Ok(())
    }

    pub(super) fn update_tenant(&mut self, update: &UpdateTenant) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Tenant>(update.id, update.expected, false)?;
        let mut after = before.clone();
        let patch = &update.patch;
        if let Some(name) = &patch.name {
            let name = clean_name("name", name)?;
            if name.to_lowercase() != before.name.to_lowercase() {
                self.claim_tenant_name(&name)?;
                self.ws
                    .delete_typed(&TENANT_NAMES, &before.name.to_lowercase());
            }
            after.name = name;
        }
        if let Some(dns) = &patch.dns {
            if let Some(zone) = dns.default_zone
                && dns.default_zone != before.dns.default_zone
            {
                self.check_default_zone(before.id, zone)?;
            }
            after.dns = dns.clone();
        }
        self.patch_meta(
            Tenant::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |p, t| {
            p.ws.put_typed(&TENANT_NAMES, &t.name.to_lowercase(), &t.id)
        })
    }

    // Backlog: the tenant's default zone. The zone must be a primary forward zone of the
    // tenant or one without a tenant; the read is tracked, so a zone deleted or moved
    // meanwhile makes the plan stale.
    fn check_default_zone(
        &mut self,
        tenant: TenantId,
        zone: tenko_core::dns::ZoneId,
    ) -> IpamResult<()> {
        use tenko_core::dns::{DnsName, ZoneKind, codes::DEFAULT_ZONE_INVALID, tables::ZONES};
        let found = self
            .ws
            .get_typed(&ZONES, &zone, true)?
            .map(|(zone, _)| zone);
        let reason = match &found {
            None => Some("missing"),
            Some(found) if found.kind != ZoneKind::Primary => Some("not_primary"),
            Some(found)
                if DnsName::new("arpa").is_ok_and(|arpa| found.name.is_subdomain_of(&arpa)) =>
            {
                Some("reverse")
            }
            Some(found) if found.tenant.is_some_and(|owner| owner != tenant) => {
                Some("other_tenant")
            }
            Some(_) => None,
        };
        let Some(reason) = reason else {
            return Ok(());
        };
        let name = found.map_or_else(|| zone.to_string(), |found| found.name.to_string());
        Err(IpamError::new(
            DEFAULT_ZONE_INVALID,
            409,
            format!(
                "{name} cannot be the default zone of the tenant ({reason}): it must be a primary forward zone of the tenant or one without a tenant"
            ),
        )
        .titled("Not a default zone for the tenant")
        .param("zone", zone)
        .param("reason", reason)
        .field("dns.default_zone", DEFAULT_ZONE_INVALID))
    }

    pub(super) fn delete_tenant(
        &mut self,
        id: TenantId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Tenant>(id, expected, false)?;
        self.expect_no_new_references(id.into())?;
        let vrfs = self
            .ws
            .scan_keys(&VRF_NAMES, &KeyRange::prefix(encode_key(&id)))?;
        if !vrfs.is_empty() {
            return Err(IpamError::in_use(id.into(), "VRFs", vrfs.len()));
        }
        let hosts = self
            .ws
            .scan_keys(&HOST_NAMES, &KeyRange::prefix(encode_key(&id)))?;
        if !hosts.is_empty() {
            return Err(IpamError::in_use(id.into(), "hosts", hosts.len()));
        }
        self.ws
            .delete_typed(&TENANT_NAMES, &before.name.to_lowercase());
        if self.default_tenant == Some(id) {
            self.default_tenant = None;
        }
        self.soft_delete(before, false)
    }

    pub(super) fn restore_tenant(
        &mut self,
        id: TenantId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Tenant>(id, expected, true)?;
        require_deleted(&before)?;
        self.claim_tenant_name(&before.name)?;
        self.ws
            .put_typed(&TENANT_NAMES, &before.name.to_lowercase(), &id)?;
        self.undelete(before, false)
    }

    // ----- VRFs -------------------------------------------------------------------------

    pub(super) fn create_vrf(&mut self, input: &VrfInput) -> IpamResult<ObjectRef> {
        Ok(self.create_vrf_inner(input, false)?.into())
    }

    fn create_vrf_inner(&mut self, input: &VrfInput, derived: bool) -> IpamResult<VrfId> {
        let name = clean_name("name", &input.name)?;
        let tenant = match input.tenant {
            Some(tenant) => tenant,
            None => self.default_tenant()?,
        };
        self.load_live::<Tenant>(tenant, "tenant")?;
        self.add_reference(tenant.into());
        let id = self.claim_id::<Vrf>(input.id)?;
        let key = (tenant, name.to_lowercase());
        if self.ws.exists(&VRF_NAMES, &key, true)? {
            return Err(name_taken("VRF", &name));
        }
        let rd = optional_text("rd", input.rd.as_ref())?;
        let meta = self.new_meta(
            Vrf::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let vrf = Vrf {
            id,
            tenant,
            name,
            rd,
            meta,
        };
        self.write(&vrf)?;
        self.ws.put_typed(&VRF_NAMES, &key, &id)?;
        self.sync_usage(id.into(), None, Some(&vrf.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Vrf(vrf)),
            derived,
        )?;
        Ok(id)
    }

    pub(super) fn update_vrf(&mut self, update: &UpdateVrf) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vrf>(update.id, update.expected, false)?;
        let mut after = before.clone();
        let patch = &update.patch;
        if let Some(name) = &patch.name {
            let name = clean_name("name", name)?;
            if name.to_lowercase() != before.name.to_lowercase() {
                if self
                    .ws
                    .exists(&VRF_NAMES, &(before.tenant, name.to_lowercase()), true)?
                {
                    return Err(name_taken("VRF", &name));
                }
                self.ws
                    .delete_typed(&VRF_NAMES, &(before.tenant, before.name.to_lowercase()));
            }
            after.name = name;
        }
        if let Some(rd) = &patch.rd {
            after.rd = optional_text("rd", rd.as_ref())?;
        }
        self.patch_meta(
            Vrf::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |p, v| {
            p.ws.put_typed(&VRF_NAMES, &(v.tenant, v.name.to_lowercase()), &v.id)
        })
    }

    pub(super) fn delete_vrf(
        &mut self,
        id: VrfId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vrf>(id, expected, false)?;
        self.ws.expect(&tree_counter(id))?;
        let prefixes = self
            .ws
            .scan_keys(&PREFIX_CIDRS, &KeyRange::prefix(encode_key(&id)))?;
        if !prefixes.is_empty() {
            return Err(IpamError::in_use(id.into(), "prefixes", prefixes.len()));
        }
        self.ws
            .delete_typed(&VRF_NAMES, &(before.tenant, before.name.to_lowercase()));
        if self.default_vrf == Some(id) {
            self.default_vrf = None;
        }
        self.soft_delete(before, false)
    }

    pub(super) fn restore_vrf(
        &mut self,
        id: VrfId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vrf>(id, expected, true)?;
        require_deleted(&before)?;
        self.load_live::<Tenant>(before.tenant, "tenant")?;
        self.add_reference(before.tenant.into());
        let key = (before.tenant, before.name.to_lowercase());
        if self.ws.exists(&VRF_NAMES, &key, true)? {
            return Err(name_taken("VRF", &before.name));
        }
        self.ws.put_typed(&VRF_NAMES, &key, &id)?;
        self.undelete(before, false)
    }

    // ----- sites ------------------------------------------------------------------------

    pub(super) fn create_site(&mut self, input: &SiteInput) -> IpamResult<ObjectRef> {
        let name = clean_name("name", &input.name)?;
        let id = self.claim_id::<Site>(input.id)?;
        if self.ws.exists(&SITE_NAMES, &name.to_lowercase(), true)? {
            return Err(name_taken("site", &name));
        }
        if let Some(parent) = input.parent {
            self.load_live::<Site>(parent, "parent")?;
            self.add_reference(parent.into());
        }
        let ad_site = optional_text("ad_site", input.ad_site.as_ref())?;
        let meta = self.new_meta(
            Site::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let site = Site {
            id,
            name,
            parent: input.parent,
            ad_site,
            meta,
        };
        self.write(&site)?;
        self.ws
            .put_typed(&SITE_NAMES, &site.name.to_lowercase(), &id)?;
        self.sync_usage(id.into(), None, Some(&site.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Site(site)),
            false,
        )?;
        Ok(id.into())
    }

    pub(super) fn update_site(&mut self, update: &UpdateSite) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Site>(update.id, update.expected, false)?;
        let mut after = before.clone();
        let patch = &update.patch;
        if let Some(name) = &patch.name {
            let name = clean_name("name", name)?;
            if name.to_lowercase() != before.name.to_lowercase() {
                if self.ws.exists(&SITE_NAMES, &name.to_lowercase(), true)? {
                    return Err(name_taken("site", &name));
                }
                self.ws
                    .delete_typed(&SITE_NAMES, &before.name.to_lowercase());
            }
            after.name = name;
        }
        if let Some(parent) = patch.parent {
            if parent != before.parent
                && let Some(parent) = parent
            {
                self.load_live::<Site>(parent, "parent")?;
                self.check_site_cycle(before.id, parent)?;
                self.add_reference(parent.into());
            }
            after.parent = parent;
        }
        if let Some(ad_site) = &patch.ad_site {
            after.ad_site = optional_text("ad_site", ad_site.as_ref())?;
        }
        self.patch_meta(
            Site::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |p, s| {
            p.ws.put_typed(&SITE_NAMES, &s.name.to_lowercase(), &s.id)
        })
    }

    /// Fails with `ipam.site.cycle` if `site` is an ancestor of (or is) `parent`.
    fn check_site_cycle(&mut self, site: SiteId, parent: SiteId) -> IpamResult<()> {
        let mut cursor = Some(parent);
        let mut steps = 0;
        while let Some(current) = cursor {
            if current == site || steps > 64 {
                return Err(IpamError::new(
                    codes::SITE_CYCLE,
                    409,
                    "a site cannot be nested inside itself",
                )
                .titled("Site nesting cycle")
                .field("parent", codes::SITE_CYCLE));
            }
            let (next, _) = self.load::<Site>(current)?;
            cursor = next.parent;
            steps += 1;
        }
        Ok(())
    }

    pub(super) fn delete_site(
        &mut self,
        id: SiteId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Site>(id, expected, false)?;
        self.expect_no_new_references(id.into())?;
        let children = self
            .ws
            .scan_typed(&SITES, &KeyRange::all())?
            .into_iter()
            .filter(|(_, s)| s.parent == Some(id) && !s.meta.is_deleted())
            .count();
        if children > 0 {
            return Err(IpamError::in_use(id.into(), "sites", children));
        }
        let vlans = self
            .ws
            .scan_typed(&VLANS, &KeyRange::all())?
            .into_iter()
            .filter(|(_, v): &(VlanId, Vlan)| v.site == Some(id) && !v.meta.is_deleted())
            .count();
        if vlans > 0 {
            return Err(IpamError::in_use(id.into(), "VLANs", vlans));
        }
        let prefixes = self
            .ws
            .scan_typed(&PREFIXES, &KeyRange::all())?
            .into_iter()
            .filter(|(_, p): &(_, Prefix)| p.site == Some(id) && !p.meta.is_deleted())
            .count();
        if prefixes > 0 {
            return Err(IpamError::in_use(id.into(), "prefixes", prefixes));
        }
        let hosts = self
            .ws
            .scan_typed(&HOSTS, &KeyRange::all())?
            .into_iter()
            .filter(|(_, h): &(_, Host)| h.site == Some(id) && !h.meta.is_deleted())
            .count();
        if hosts > 0 {
            return Err(IpamError::in_use(id.into(), "hosts", hosts));
        }
        self.ws
            .delete_typed(&SITE_NAMES, &before.name.to_lowercase());
        self.soft_delete(before, false)
    }

    pub(super) fn restore_site(
        &mut self,
        id: SiteId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Site>(id, expected, true)?;
        require_deleted(&before)?;
        if let Some(parent) = before.parent {
            self.load_live::<Site>(parent, "parent")?;
            self.add_reference(parent.into());
        }
        if self
            .ws
            .exists(&SITE_NAMES, &before.name.to_lowercase(), true)?
        {
            return Err(name_taken("site", &before.name));
        }
        self.ws
            .put_typed(&SITE_NAMES, &before.name.to_lowercase(), &id)?;
        self.undelete(before, false)
    }

    // ----- VLANs ------------------------------------------------------------------------

    pub(super) fn create_vlan(&mut self, input: &VlanInput) -> IpamResult<ObjectRef> {
        check_vid(input.vid)?;
        check_vni(input.vni)?;
        let name = clean_name("name", &input.name)?;
        let id = self.claim_id::<Vlan>(input.id)?;
        if let Some(site) = input.site {
            self.load_live::<Site>(site, "site")?;
            self.add_reference(site.into());
        }
        self.claim_vid(input.site, input.vid)?;
        let meta = self.new_meta(
            Vlan::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let vlan = Vlan {
            id,
            vid: input.vid,
            vni: input.vni,
            name,
            site: input.site,
            status: input.status.unwrap_or(Status::Active),
            meta,
        };
        self.write(&vlan)?;
        self.ws.put_typed(&VLAN_VIDS, &(vlan.site, vlan.vid), &id)?;
        self.sync_usage(id.into(), None, Some(&vlan.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Vlan(vlan)),
            false,
        )?;
        Ok(id.into())
    }

    fn claim_vid(&mut self, site: Option<SiteId>, vid: u16) -> IpamResult<()> {
        if self.ws.exists(&VLAN_VIDS, &(site, vid), true)? {
            return Err(IpamError::new(
                codes::VLAN_DUPLICATE,
                409,
                format!("VLAN {vid} exists already at this site"),
            )
            .titled("Duplicate VLAN")
            .param("vid", vid)
            .field("vid", codes::VLAN_DUPLICATE));
        }
        Ok(())
    }

    pub(super) fn update_vlan(&mut self, update: &UpdateVlan) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vlan>(update.id, update.expected, false)?;
        let mut after = before.clone();
        let patch = &update.patch;
        if let Some(vid) = patch.vid {
            check_vid(vid)?;
            after.vid = vid;
        }
        if let Some(vni) = patch.vni {
            check_vni(vni)?;
            after.vni = vni;
        }
        if let Some(name) = &patch.name {
            after.name = clean_name("name", name)?;
        }
        if let Some(site) = patch.site {
            if site != before.site
                && let Some(site) = site
            {
                self.load_live::<Site>(site, "site")?;
                self.add_reference(site.into());
            }
            after.site = site;
        }
        if (after.site, after.vid) != (before.site, before.vid) {
            self.claim_vid(after.site, after.vid)?;
            self.ws.delete_typed(&VLAN_VIDS, &(before.site, before.vid));
        }
        if let Some(status) = patch.status {
            Self::check_transition(before.id.into(), before.status, status)?;
            after.status = status;
        }
        self.patch_meta(
            Vlan::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |p, v| {
            p.ws.put_typed(&VLAN_VIDS, &(v.site, v.vid), &v.id)
        })
    }

    pub(super) fn delete_vlan(
        &mut self,
        id: VlanId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vlan>(id, expected, false)?;
        self.expect_no_new_references(id.into())?;
        let prefixes = self
            .ws
            .scan_typed(&PREFIXES, &KeyRange::all())?
            .into_iter()
            .filter(|(_, p): &(_, Prefix)| p.vlan == Some(id) && !p.meta.is_deleted())
            .count();
        if prefixes > 0 {
            return Err(IpamError::in_use(id.into(), "prefixes", prefixes));
        }
        self.ws.delete_typed(&VLAN_VIDS, &(before.site, before.vid));
        self.soft_delete(before, false)
    }

    pub(super) fn restore_vlan(
        &mut self,
        id: VlanId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Vlan>(id, expected, true)?;
        require_deleted(&before)?;
        if let Some(site) = before.site {
            self.load_live::<Site>(site, "site")?;
            self.add_reference(site.into());
        }
        self.claim_vid(before.site, before.vid)?;
        self.ws
            .put_typed(&VLAN_VIDS, &(before.site, before.vid), &id)?;
        self.undelete(before, false)
    }

    // ----- generic update, delete and restore -------------------------------------------

    /// Writes an update unless nothing a reviewer sees changed; `index` re-stages the
    /// object's uniqueness keys.
    pub(super) fn finish_update<T: Entity>(
        &mut self,
        before: &T,
        after: &T,
        index: impl FnOnce(&mut Self, &T) -> IpamResult<()>,
    ) -> IpamResult<ObjectRef> {
        let reference = before.object_ref();
        let before_object = before.clone().into_object();
        let after_object = after.clone().into_object();
        if crate::diff::same(&before_object, &after_object) {
            return Ok(reference);
        }
        index(self, after)?;
        self.write(after)?;
        self.sync_usage(reference, Some(before.meta()), Some(after.meta()))?;
        self.record(
            reference,
            ChangeAction::Update,
            Some(before_object),
            Some(after_object),
            false,
        )?;
        Ok(reference)
    }

    /// Marks an object deleted; the caller removed its uniqueness keys already.
    pub(super) fn soft_delete<T: Entity>(
        &mut self,
        before: T,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let reference = before.object_ref();
        let mut after = before.clone();
        after.meta_mut().deleted = Some(self.stamp());
        after.meta_mut().updated = self.stamp();
        self.write(&after)?;
        self.sync_usage(reference, Some(before.meta()), None)?;
        self.record(
            reference,
            ChangeAction::Delete,
            Some(before.into_object()),
            Some(after.into_object()),
            derived,
        )?;
        Ok(reference)
    }

    /// Clears the deletion mark; the caller re-claimed the uniqueness keys already.
    pub(super) fn undelete<T: Entity>(
        &mut self,
        before: T,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let after = before.clone();
        self.undelete_as(before, after, derived)
    }

    /// Clears the deletion mark of `after`, a possibly adjusted copy of `before`.
    pub(super) fn undelete_as<T: Entity>(
        &mut self,
        before: T,
        mut after: T,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let reference = before.object_ref();
        after.meta_mut().deleted = None;
        after.meta_mut().updated = self.stamp();
        self.write(&after)?;
        self.sync_usage(reference, None, Some(after.meta()))?;
        self.record(
            reference,
            ChangeAction::Restore,
            Some(before.into_object()),
            Some(after.into_object()),
            derived,
        )?;
        Ok(reference)
    }
}

/// Fails with `ipam.not_deleted` unless the object is deleted.
pub(super) fn require_deleted<T: Entity>(object: &T) -> IpamResult<()> {
    if object.meta().is_deleted() {
        Ok(())
    } else {
        let reference = object.object_ref();
        Err(IpamError::new(
            codes::NOT_DELETED,
            409,
            format!("{reference} is not deleted"),
        )
        .titled("The object is not deleted")
        .param("kind", reference.kind)
        .param("id", reference.id))
    }
}

/// `ipam.name_taken`.
pub(super) fn name_taken(kind: &str, name: &str) -> IpamError {
    IpamError::new(
        codes::NAME_TAKEN,
        409,
        format!("a {kind} named {name} exists already"),
    )
    .titled("Name already in use")
    .param("kind", kind)
    .param("name", name)
    .field("name", codes::NAME_TAKEN)
}

fn optional_text(field: &str, text: Option<&String>) -> IpamResult<Option<String>> {
    match text.map(|t| t.trim()) {
        None | Some("") => Ok(None),
        Some(text) => clean_name(field, text).map(Some),
    }
}

fn check_vid(vid: u16) -> IpamResult<()> {
    if (1..=4094).contains(&vid) {
        Ok(())
    } else {
        Err(IpamError::invalid(
            "vid",
            format!("VLAN id {vid} is outside 1 to 4094"),
        ))
    }
}

fn check_vni(vni: Option<u32>) -> IpamResult<()> {
    match vni {
        Some(vni) if vni > MAX_VNI => Err(IpamError::invalid(
            "vni",
            format!("VNI {vni} is above {MAX_VNI}"),
        )),
        _ => Ok(()),
    }
}
