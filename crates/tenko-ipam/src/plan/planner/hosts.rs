//! Hosts and interfaces (IPAM-08, IPAM-12, IPAM-14, IPAM-16, IPAM-18).
//!
//! - A locked host refuses changes from automation (`ipam.host.locked`, 423) and only
//!   people lock or unlock it; manual edits always pass (IPAM-16).
//! - A `reserved` host needs a MAC (for IPv4) or a DUID (for IPv6) on an interface before
//!   a reservation can be created; the plan warns when one is missing (IPAM-18).

use std::{collections::BTreeSet, net::IpAddr};

use tenko_core::{
    HostId, InterfaceId, ObjectRef, Revision,
    codec::encode_key,
    ipam::{Address, AssignmentMode, Host, Interface, Site, Tenant},
};
use tenko_store::KeyRange;

use super::{
    Planner, clean_name,
    tenancy::{name_taken, require_deleted},
};
use crate::{
    command::{HostInput, InterfaceInput, UpdateHost, UpdateInterface},
    error::{IpamError, IpamResult, codes},
    history::ChangeAction,
    object::{Entity, IpamObject},
    tables::{HOST_INTERFACES, HOST_NAMES, INTERFACE_ADDRESSES, INTERFACE_MACS, refs_counter},
};

impl Planner<'_> {
    /// Fails with `ipam.host.locked` when automation touches a locked host (IPAM-16).
    pub(super) fn check_unlocked(&self, host: &Host) -> IpamResult<()> {
        if host.lock && self.automation() {
            return Err(IpamError::new(
                codes::HOST_LOCKED,
                423,
                format!("host {} is locked against automation", host.name),
            )
            .titled("The host is locked")
            .param("host", &host.name));
        }
        Ok(())
    }

    // ----- hosts ------------------------------------------------------------------------

    pub(super) fn create_host(&mut self, input: &HostInput) -> IpamResult<ObjectRef> {
        let tenant = match input.tenant {
            Some(tenant) => tenant,
            None => self.default_tenant()?,
        };
        self.load_live::<Tenant>(tenant, "tenant")?;
        self.add_reference(tenant.into());
        let id = self.claim_id::<Host>(input.id)?;
        if self
            .ws
            .exists(&HOST_NAMES, &(tenant, input.name.clone()), true)?
        {
            return Err(name_taken("host", input.name.as_str()));
        }
        if let Some(site) = input.site {
            self.load_live::<Site>(site, "site")?;
            self.add_reference(site.into());
        }
        let meta = self.new_meta(
            Host::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let host = Host {
            id,
            tenant,
            name: input.name.clone(),
            mode: input.mode.unwrap_or(AssignmentMode::Static),
            lock: input.lock.unwrap_or(false),
            site: input.site,
            decommissioned: None,
            meta,
        };
        self.write(&host)?;
        self.ws
            .put_typed(&HOST_NAMES, &(tenant, host.name.clone()), &id)?;
        self.sync_usage(id.into(), None, Some(&host.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Host(host)),
            false,
        )?;
        for (index, interface) in input.interfaces.iter().enumerate() {
            if interface.host.is_some_and(|other| other != id) {
                return Err(IpamError::invalid(
                    &format!("interfaces[{index}].host"),
                    "an interface listed with a host belongs to that host",
                ));
            }
            self.create_interface(interface, Some(id))?;
        }
        self.reservation_checks.insert(id);
        Ok(id.into())
    }

    pub(super) fn update_host(&mut self, update: &UpdateHost) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(update.id, update.expected, false)?;
        self.check_unlocked(&before)?;
        let patch = &update.patch;
        let mut after = before.clone();
        if let Some(name) = &patch.name
            && *name != before.name
        {
            if self
                .ws
                .exists(&HOST_NAMES, &(before.tenant, name.clone()), true)?
            {
                return Err(name_taken("host", name.as_str()));
            }
            self.ws
                .delete_typed(&HOST_NAMES, &(before.tenant, before.name.clone()));
            after.name = name.clone();
        }
        if let Some(mode) = patch.mode {
            if mode == AssignmentMode::Reserved && before.mode != AssignmentMode::Reserved {
                self.check_host_pools(before.id)?;
            }
            after.mode = mode;
        }
        if let Some(lock) = patch.lock
            && lock != before.lock
        {
            if self.automation() {
                return Err(lock_manual_only());
            }
            after.lock = lock;
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
        self.patch_meta(
            Host::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.reservation_checks.insert(before.id);
        self.finish_update(&before, &after, |p, h| {
            p.ws.put_typed(&HOST_NAMES, &(h.tenant, h.name.clone()), &h.id)
        })
    }

    pub(super) fn set_lock(
        &mut self,
        id: HostId,
        lock: bool,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        if self.automation() {
            return Err(lock_manual_only());
        }
        let before = self.load_for_change::<Host>(id, expected, false)?;
        if before.lock == lock {
            return Ok(id.into());
        }
        let mut after = before.clone();
        after.lock = lock;
        after.meta.updated = self.stamp();
        self.write(&after)?;
        self.record(
            id.into(),
            if lock {
                ChangeAction::Lock
            } else {
                ChangeAction::Unlock
            },
            Some(IpamObject::Host(before)),
            Some(IpamObject::Host(after)),
            false,
        )?;
        Ok(id.into())
    }

    pub(super) fn set_mode(
        &mut self,
        id: HostId,
        mode: AssignmentMode,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(id, expected, false)?;
        self.check_unlocked(&before)?;
        let mut after = before.clone();
        if mode == AssignmentMode::Reserved && before.mode != AssignmentMode::Reserved {
            self.check_host_pools(id)?;
        }
        after.mode = mode;
        after.meta.updated = self.stamp();
        self.reservation_checks.insert(id);
        self.finish_update(&before, &after, |_, _| Ok(()))
    }

    pub(super) fn delete_host(
        &mut self,
        id: HostId,
        expected: Option<Revision>,
        cascade: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(id, expected, false)?;
        self.check_unlocked(&before)?;
        self.expect_no_new_references(id.into())?;
        let interfaces = self.interfaces_of(id, false)?;
        if !cascade {
            let mut addresses = 0;
            for interface in &interfaces {
                addresses += self.addresses_of(interface.id, false)?.len();
            }
            if addresses > 0 {
                return Err(IpamError::in_use(id.into(), "addresses", addresses));
            }
        }
        for interface in interfaces {
            self.delete_interface(interface.id, None, cascade, true)?;
        }
        self.ws
            .delete_typed(&HOST_NAMES, &(before.tenant, before.name.clone()));
        self.reservation_checks.remove(&id);
        self.soft_delete(before, false)
    }

    pub(super) fn restore_host(
        &mut self,
        id: HostId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(id, expected, true)?;
        require_deleted(&before)?;
        self.load_live::<Tenant>(before.tenant, "tenant")?;
        self.add_reference(before.tenant.into());
        if let Some(site) = before.site {
            self.load_live::<Site>(site, "site")?;
            self.add_reference(site.into());
        }
        let key = (before.tenant, before.name.clone());
        if self.ws.exists(&HOST_NAMES, &key, true)? {
            return Err(name_taken("host", before.name.as_str()));
        }
        self.ws.put_typed(&HOST_NAMES, &key, &id)?;
        let deleted = before.meta.deleted.clone();
        let reference = self.undelete(before, false)?;
        for interface in self.interfaces_of(id, true)? {
            if interface.meta.is_deleted() && interface.meta.deleted == deleted {
                self.restore_interface(interface.id, None, true)?;
            }
        }
        self.reservation_checks.insert(id);
        Ok(reference)
    }

    /// A host that becomes `reserved` must not have an address inside a DHCP pool
    /// (IPAM-23): its reservations would collide with the pool.
    fn check_host_pools(&mut self, host: HostId) -> IpamResult<()> {
        for interface in self.interfaces_of(host, false)? {
            for address in self.addresses_of(interface.id, false)? {
                let (prefix, _) = self.load::<tenko_core::ipam::Prefix>(address.prefix)?;
                self.ws.expect(&crate::tables::alloc_counter(prefix.id))?;
                self.check_pool(
                    &prefix,
                    address.ip,
                    Some(AssignmentMode::Reserved),
                    address.id.into(),
                )?;
            }
        }
        Ok(())
    }
    // ----- interfaces -------------------------------------------------------------------

    /// The interfaces of a host (loaded, tracked).
    pub(super) fn interfaces_of(
        &mut self,
        host: HostId,
        with_deleted: bool,
    ) -> IpamResult<Vec<Interface>> {
        let keys = self
            .ws
            .scan_keys(&HOST_INTERFACES, &KeyRange::prefix(encode_key(&host)))?;
        let mut out = Vec::with_capacity(keys.len());
        for (_, id) in keys {
            if let Some((interface, _)) = self.try_load::<Interface>(id)?
                && (with_deleted || !interface.meta.is_deleted())
            {
                out.push(interface);
            }
        }
        Ok(out)
    }

    /// The addresses of an interface (loaded, tracked).
    pub(super) fn addresses_of(
        &mut self,
        interface: InterfaceId,
        with_deleted: bool,
    ) -> IpamResult<Vec<Address>> {
        let keys = self.ws.scan_keys(
            &INTERFACE_ADDRESSES,
            &KeyRange::prefix(encode_key(&interface)),
        )?;
        let mut out = Vec::with_capacity(keys.len());
        for (_, id) in keys {
            if let Some((address, _)) = self.try_load::<Address>(id)?
                && address.interface == Some(interface)
                && (with_deleted || !address.meta.is_deleted())
            {
                out.push(address);
            }
        }
        Ok(out)
    }

    /// Fails with `ipam.name_taken` when another live interface of the host has the name.
    fn check_interface_name(
        &mut self,
        host: HostId,
        name: &str,
        exclude: Option<InterfaceId>,
    ) -> IpamResult<()> {
        let taken = self
            .interfaces_of(host, false)?
            .into_iter()
            .any(|i| Some(i.id) != exclude && i.name.eq_ignore_ascii_case(name));
        if taken {
            return Err(name_taken("interface", name));
        }
        Ok(())
    }

    /// Warns when another live interface has the MAC address.
    fn check_mac(&mut self, interface: InterfaceId, mac: tenko_core::MacAddr) -> IpamResult<()> {
        let others: Vec<InterfaceId> = self
            .ws
            .scan_keys(&INTERFACE_MACS, &KeyRange::prefix(encode_key(&mac)))?
            .into_iter()
            .map(|(_, id)| id)
            .filter(|id| *id != interface)
            .collect();
        if let Some(other) = others.first() {
            self.warn(
                codes::WARN_DUPLICATE_MAC,
                format!("MAC address {mac} is also on interface {other}"),
                Some(interface.into()),
                &[("mac", mac.to_string()), ("other", other.to_string())],
                false,
            );
        }
        Ok(())
    }

    pub(super) fn create_interface(
        &mut self,
        input: &InterfaceInput,
        host: Option<HostId>,
    ) -> IpamResult<ObjectRef> {
        let Some(host_id) = host.or(input.host) else {
            return Err(IpamError::invalid("host", "an interface needs a host"));
        };
        let host = self.load_live::<Host>(host_id, "host")?;
        self.check_unlocked(&host)?;
        self.ws.expect_and_bump(&refs_counter(host_id.into()))?;
        let name = clean_name("name", &input.name)?;
        self.check_interface_name(host_id, &name, None)?;
        let id = self.claim_id::<Interface>(input.id)?;
        if let Some(mac) = input.mac {
            self.check_mac(id, mac)?;
        }
        let meta = self.new_meta(
            Interface::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let interface = Interface {
            id,
            host: host_id,
            name,
            mac: input.mac,
            duid: input.duid.clone(),
            client_id: input.client_id.clone(),
            meta,
        };
        self.write(&interface)?;
        self.ws.put_typed(&HOST_INTERFACES, &(host_id, id), &())?;
        if let Some(mac) = interface.mac {
            self.ws.put_typed(&INTERFACE_MACS, &(mac, id), &())?;
        }
        self.sync_usage(id.into(), None, Some(&interface.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Interface(interface)),
            false,
        )?;
        self.reservation_checks.insert(host_id);
        Ok(id.into())
    }

    pub(super) fn update_interface(&mut self, update: &UpdateInterface) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Interface>(update.id, update.expected, false)?;
        let host = self.load_live::<Host>(before.host, "host")?;
        self.check_unlocked(&host)?;
        let patch = &update.patch;
        let mut after = before.clone();
        if let Some(name) = &patch.name {
            let name = clean_name("name", name)?;
            if !name.eq_ignore_ascii_case(&before.name) {
                self.ws.expect_and_bump(&refs_counter(host.id.into()))?;
                self.check_interface_name(host.id, &name, Some(before.id))?;
            }
            after.name = name;
        }
        if let Some(mac) = patch.mac
            && mac != before.mac
        {
            if let Some(old) = before.mac {
                self.ws.delete_typed(&INTERFACE_MACS, &(old, before.id));
            }
            if let Some(new) = mac {
                self.check_mac(before.id, new)?;
            }
            after.mac = mac;
        }
        if let Some(duid) = &patch.duid {
            after.duid.clone_from(duid);
        }
        if let Some(client_id) = &patch.client_id {
            after.client_id.clone_from(client_id);
        }
        self.patch_meta(
            Interface::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.reservation_checks.insert(host.id);
        self.finish_update(&before, &after, |p, i| match i.mac {
            Some(mac) => p.ws.put_typed(&INTERFACE_MACS, &(mac, i.id), &()),
            None => Ok(()),
        })
    }

    pub(super) fn delete_interface(
        &mut self,
        id: InterfaceId,
        expected: Option<Revision>,
        cascade: bool,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Interface>(id, expected, false)?;
        let (host, _) = self.load::<Host>(before.host)?;
        self.check_unlocked(&host)?;
        self.expect_no_new_references(id.into())?;
        let addresses = self.addresses_of(id, false)?;
        if !addresses.is_empty() {
            if !cascade {
                return Err(IpamError::in_use(id.into(), "addresses", addresses.len()));
            }
            for address in addresses {
                self.delete_address(address.id, None, true)?;
            }
        }
        if let Some(mac) = before.mac {
            self.ws.delete_typed(&INTERFACE_MACS, &(mac, id));
        }
        self.reservation_checks.insert(host.id);
        self.soft_delete(before, derived)
    }

    pub(super) fn restore_interface(
        &mut self,
        id: InterfaceId,
        expected: Option<Revision>,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Interface>(id, expected, true)?;
        require_deleted(&before)?;
        let host = self.load_live::<Host>(before.host, "host")?;
        self.check_unlocked(&host)?;
        self.ws.expect_and_bump(&refs_counter(host.id.into()))?;
        self.check_interface_name(host.id, &before.name, Some(id))?;
        if let Some(mac) = before.mac {
            self.check_mac(id, mac)?;
            self.ws.put_typed(&INTERFACE_MACS, &(mac, id), &())?;
        }
        let deleted = before.meta.deleted.clone();
        let reference = self.undelete(before, derived)?;
        for address in self.addresses_of(id, true)? {
            if address.meta.is_deleted() && address.meta.deleted == deleted {
                self.restore_address(address.id, None, true)?;
            }
        }
        self.reservation_checks.insert(host.id);
        Ok(reference)
    }

    // ----- IPAM-18 ----------------------------------------------------------------------

    /// Warns for every touched `reserved` host that lacks the identifier a reservation
    /// needs: a MAC (or client identifier) for IPv4, a DUID for IPv6.
    pub(super) fn check_reservations(&mut self) -> IpamResult<()> {
        let hosts: BTreeSet<HostId> = std::mem::take(&mut self.reservation_checks);
        for id in hosts {
            let Some((host, _)) = self.ws.get_typed(&crate::tables::HOSTS, &id, false)? else {
                continue;
            };
            if host.meta.is_deleted() || host.mode != AssignmentMode::Reserved {
                continue;
            }
            let mut has_mac = false;
            let mut has_duid = false;
            let mut families = BTreeSet::new();
            let keys = self
                .ws
                .scan_keys(&HOST_INTERFACES, &KeyRange::prefix(encode_key(&id)))?;
            for (_, interface_id) in keys {
                let Some((interface, _)) =
                    self.ws
                        .get_typed(&crate::tables::INTERFACES, &interface_id, false)?
                else {
                    continue;
                };
                if interface.meta.is_deleted() {
                    continue;
                }
                has_mac |= interface.mac.is_some() || interface.client_id.is_some();
                has_duid |= interface.duid.is_some();
                let addresses = self.ws.scan_keys(
                    &INTERFACE_ADDRESSES,
                    &KeyRange::prefix(encode_key(&interface_id)),
                )?;
                for (_, address_id) in addresses {
                    if let Some((address, _)) =
                        self.ws
                            .get_typed(&crate::tables::ADDRESSES, &address_id, false)?
                        && !address.meta.is_deleted()
                        && address.interface == Some(interface_id)
                    {
                        families.insert(matches!(address.ip, IpAddr::V6(_)));
                    }
                }
            }
            let needs_mac = families.contains(&false) && !has_mac;
            let needs_duid = families.contains(&true) && !has_duid;
            let needs_any = families.is_empty() && !has_mac && !has_duid;
            if needs_mac || needs_duid || needs_any {
                let missing = match (needs_mac, needs_duid) {
                    (true, true) => "MAC address and DUID",
                    (true, false) => "MAC address",
                    (false, true) => "DUID",
                    (false, false) => "MAC address or DUID",
                };
                self.warn(
                    codes::WARN_RESERVATION_IDENTIFIER,
                    format!(
                        "host {} is reserved but has no {missing} for its reservation",
                        host.name
                    ),
                    Some(id.into()),
                    &[
                        ("host", host.name.to_string()),
                        ("missing", missing.to_owned()),
                    ],
                    false,
                );
            }
        }
        Ok(())
    }
}

fn lock_manual_only() -> IpamError {
    IpamError::new(
        codes::HOST_LOCK_MANUAL_ONLY,
        403,
        "only people lock and unlock hosts",
    )
    .titled("Locking is manual")
    .field("lock", codes::HOST_LOCK_MANUAL_ONLY)
}
