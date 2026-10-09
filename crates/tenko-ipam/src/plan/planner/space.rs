//! Prefixes, ranges and addresses (IPAM-02, IPAM-05 to IPAM-07, IPAM-23), and next free
//! allocation.
//!
//! Rules:
//!
//! - Inside one VRF, prefixes nest but never overlap otherwise: the same network twice, a
//!   prefix inside a network (only supernets contain prefixes) and a network around other
//!   prefixes are intent conflicts (`ipam.prefix.overlap`, IPAM-23). Across VRFs anything
//!   goes (IPAM-01).
//! - Every live address belongs to the most specific live prefix containing it; creating,
//!   resizing, deleting and restoring prefixes moves addresses accordingly.
//! - Ranges live in network prefixes and do not overlap each other; a DHCP pool never
//!   covers the address of a `reserved` host (IPAM-23).

use std::net::IpAddr;

use ipnet::IpNet;
use tenko_core::{
    AddressId, ObjectRef, PrefixId, RangeId, Revision, VrfId,
    codec::encode_key,
    ipam::{
        Address, AssignmentMode, Host, Interface, Prefix, PrefixRole, Range, RangeRole, Site,
        Status, UtilizationAlarm, Vlan, Vrf,
    },
};
use tenko_store::KeyRange;

use super::{Planner, tenancy::require_deleted};
use crate::{
    alloc::{first_free, first_free_block},
    command::{
        AddressInput, AllocateAddress, AllocatePrefix, PrefixInput, RangeInput, UpdateAddress,
        UpdatePrefix, UpdateRange,
    },
    error::{IpamError, IpamResult, codes},
    history::ChangeAction,
    net::{
        Family, bounds, contains_ip, contains_net, has_host_bits, host_bounds, ip_to_u128,
        net_from, u128_to_ip,
    },
    object::{Entity, IpamObject},
    tables::{
        ADDRESS_IPS, ADDRESSES, INTERFACE_ADDRESSES, PREFIX_CIDRS, PREFIX_RANGES, alloc_counter,
        tree_counter,
    },
};

/// Where a prefix goes in its VRF's tree.
pub(super) struct Placement {
    role: PrefixRole,
    parent: Option<Prefix>,
    descendants: Vec<(IpNet, PrefixId)>,
}

impl Planner<'_> {
    // ----- the prefix set of a VRF (covered by the tree counter) ----------------------

    fn prefix_at(&mut self, vrf: VrfId, cidr: IpNet) -> IpamResult<Option<PrefixId>> {
        Ok(self
            .ws
            .get_typed(&PREFIX_CIDRS, &(vrf, cidr), false)?
            .map(|(id, _)| id))
    }

    /// The most specific live prefix strictly containing `cidr`.
    fn parent_of(&mut self, vrf: VrfId, cidr: &IpNet) -> IpamResult<Option<PrefixId>> {
        let family = Family::of_net(cidr);
        let value = ip_to_u128(cidr.network());
        for len in (0..cidr.prefix_len()).rev() {
            if let Some(id) = self.prefix_at(vrf, net_from(family, value, len))? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The most specific live prefix containing `ip`.
    fn containing(&mut self, vrf: VrfId, ip: IpAddr) -> IpamResult<Option<PrefixId>> {
        let family = Family::of(ip);
        let value = ip_to_u128(ip);
        for len in (0..=family.bits()).rev() {
            if let Some(id) = self.prefix_at(vrf, net_from(family, value, len))? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The live prefixes strictly inside `cidr`, in pre-order.
    fn descendants(&self, vrf: VrfId, cidr: &IpNet) -> IpamResult<Vec<(IpNet, PrefixId)>> {
        let family = Family::of_net(cidr);
        let (_, last) = bounds(cidr);
        let range = KeyRange {
            start: std::ops::Bound::Included(PREFIX_CIDRS.key(&(vrf, *cidr))),
            end: std::ops::Bound::Included(
                PREFIX_CIDRS.key(&(vrf, net_from(family, last, family.bits()))),
            ),
        };
        Ok(self
            .ws
            .scan_typed(&PREFIX_CIDRS, &range)?
            .into_iter()
            .filter(|((_, net), _)| net != cidr)
            .map(|((_, net), id)| (net, id))
            .collect())
    }

    /// Live addresses of the VRF in `[first, last]`, in order.
    fn addresses_between(
        &self,
        vrf: VrfId,
        family: Family,
        first: u128,
        last: u128,
    ) -> IpamResult<Vec<(IpAddr, AddressId)>> {
        let range = KeyRange {
            start: std::ops::Bound::Included(ADDRESS_IPS.key(&(vrf, u128_to_ip(family, first)))),
            end: std::ops::Bound::Included(ADDRESS_IPS.key(&(vrf, u128_to_ip(family, last)))),
        };
        Ok(self
            .ws
            .scan_typed(&ADDRESS_IPS, &range)?
            .into_iter()
            .map(|((_, ip), id)| (ip, id))
            .collect())
    }

    /// Checks the place of a prefix in its VRF (IPAM-23) and finds its parent and the
    /// prefixes it would contain. `exclude` is the prefix itself when it moves.
    fn place_prefix(
        &mut self,
        vrf: VrfId,
        cidr: &IpNet,
        role: Option<PrefixRole>,
        exclude: Option<PrefixId>,
    ) -> IpamResult<Placement> {
        if let Some(existing) = self.prefix_at(vrf, *cidr)?
            && Some(existing) != exclude
        {
            return Err(overlap(cidr, cidr));
        }
        let parent = match self.parent_of(vrf, cidr)? {
            Some(id) if Some(id) != exclude => Some(self.load::<Prefix>(id)?.0),
            _ => None,
        };
        if let Some(parent) = &parent
            && parent.role == PrefixRole::Network
        {
            return Err(overlap(cidr, &parent.cidr));
        }
        let descendants: Vec<(IpNet, PrefixId)> = self
            .descendants(vrf, cidr)?
            .into_iter()
            .filter(|(_, id)| Some(*id) != exclude)
            .collect();
        let role = role.unwrap_or(if descendants.is_empty() {
            PrefixRole::Network
        } else {
            PrefixRole::Supernet
        });
        if role == PrefixRole::Network
            && let Some((child, _)) = descendants.first()
        {
            return Err(overlap(cidr, child));
        }
        Ok(Placement {
            role,
            parent,
            descendants,
        })
    }

    /// The live addresses whose most specific prefix is `prefix` (loaded, tracked).
    fn own_addresses(
        &mut self,
        prefix: &Prefix,
        descendants: &[(IpNet, PrefixId)],
    ) -> IpamResult<Vec<Address>> {
        let inner = top_level(descendants);
        let family = Family::of_net(&prefix.cidr);
        let (first, last) = bounds(&prefix.cidr);
        let mut own = Vec::new();
        for (ip, id) in self.addresses_between(prefix.vrf, family, first, last)? {
            if inside(&inner, ip_to_u128(ip)) {
                continue;
            }
            let (address, _) = self.load::<Address>(id)?;
            if address.prefix == prefix.id {
                own.push(address);
            }
        }
        Ok(own)
    }

    /// Moves the live addresses that now belong to `prefix` (inside it, outside its
    /// descendants, which keep theirs) to it: after the prefix was created or restored.
    fn adopt_addresses(
        &mut self,
        prefix: &Prefix,
        descendants: &[(IpNet, PrefixId)],
    ) -> IpamResult<()> {
        self.reparent(prefix.vrf, &prefix.cidr, &top_level(descendants))
    }

    /// Gives every live address of `region` (outside the `skip` intervals) its most
    /// specific live prefix as the prefix set stands in this plan (IPAM-02).
    fn reparent(&mut self, vrf: VrfId, region: &IpNet, skip: &[(u128, u128)]) -> IpamResult<()> {
        // An address created meanwhile in the region would belong to the most specific
        // prefix around it, which bumps that prefix's allocation counter: expect it, so this
        // plan goes stale instead of missing the address.
        if let Some(parent) = self.parent_of(vrf, region)? {
            self.ws.expect(&alloc_counter(parent))?;
        }
        let family = Family::of_net(region);
        let (first, last) = bounds(region);
        for (ip, id) in self.addresses_between(vrf, family, first, last)? {
            if inside(skip, ip_to_u128(ip)) {
                continue;
            }
            let Some(target) = self.containing(vrf, ip)? else {
                continue;
            };
            let (address, _) = self.load::<Address>(id)?;
            if address.prefix != target {
                self.ws.expect_and_bump(&alloc_counter(address.prefix))?;
                self.ws.expect_and_bump(&alloc_counter(target))?;
                self.move_address(address, target)?;
            }
        }
        Ok(())
    }

    fn move_address(&mut self, before: Address, prefix: PrefixId) -> IpamResult<()> {
        let mut after = before.clone();
        after.prefix = prefix;
        after.meta.updated = self.stamp();
        self.write(&after)?;
        self.record(
            before.id.into(),
            ChangeAction::Update,
            Some(IpamObject::Address(before)),
            Some(IpamObject::Address(after)),
            true,
        )
    }

    fn nibble_warning(&mut self, prefix: &Prefix) {
        if let IpNet::V6(net) = prefix.cidr
            && net.prefix_len() % 4 != 0
        {
            self.warn(
                codes::WARN_NIBBLE,
                format!(
                    "{} is not on a nibble boundary; IPv6 prefixes should be a multiple of 4 bits long",
                    prefix.cidr
                ),
                Some(prefix.id.into()),
                &[
                    ("cidr", prefix.cidr.to_string()),
                    ("length", net.prefix_len().to_string()),
                ],
                true,
            );
        }
    }

    fn check_references(
        &mut self,
        vlan: Option<tenko_core::VlanId>,
        site: Option<tenko_core::SiteId>,
    ) -> IpamResult<()> {
        if let Some(vlan) = vlan {
            self.load_live::<Vlan>(vlan, "vlan")?;
            self.add_reference(vlan.into());
        }
        if let Some(site) = site {
            self.load_live::<Site>(site, "site")?;
            self.add_reference(site.into());
        }
        Ok(())
    }

    // ----- prefixes ---------------------------------------------------------------------

    pub(super) fn create_prefix(&mut self, input: &PrefixInput) -> IpamResult<ObjectRef> {
        Ok(self.create_prefix_inner(input)?.into())
    }

    fn create_prefix_inner(&mut self, input: &PrefixInput) -> IpamResult<PrefixId> {
        check_cidr("cidr", &input.cidr)?;
        let vrf = match input.vrf {
            Some(vrf) => vrf,
            None => self.default_vrf()?,
        };
        self.load_live::<Vrf>(vrf, "vrf")?;
        self.ws.expect_and_bump(&tree_counter(vrf))?;
        let id = self.claim_id::<Prefix>(input.id)?;
        let placement = self.place_prefix(vrf, &input.cidr, input.role, None)?;
        self.check_references(input.vlan, input.site)?;
        let alarm = check_alarm(input.alarm)?;
        let status = input.status.unwrap_or(Status::Active);
        let meta = self.new_meta(
            Prefix::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let prefix = Prefix {
            id,
            vrf,
            cidr: input.cidr,
            role: placement.role,
            status,
            vlan: input.vlan,
            site: input.site,
            alarm,
            alloc: input.alloc.unwrap_or_default(),
            meta,
        };
        self.nibble_warning(&prefix);
        if let Some(parent) = &placement.parent {
            self.check_parent_status(id.into(), status, parent.id.into(), parent.status);
        }
        self.write(&prefix)?;
        self.ws.put_typed(&PREFIX_CIDRS, &(vrf, prefix.cidr), &id)?;
        self.ws.expect_and_bump(&alloc_counter(id))?;
        self.sync_usage(id.into(), None, Some(&prefix.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Prefix(prefix.clone())),
            false,
        )?;
        self.adopt_addresses(&prefix, &placement.descendants)?;
        Ok(id)
    }

    pub(super) fn update_prefix(&mut self, update: &UpdatePrefix) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Prefix>(update.id, update.expected, false)?;
        let id = before.id;
        let vrf = before.vrf;
        let patch = &update.patch;
        let mut after = before.clone();
        self.ws.expect(&tree_counter(vrf))?;
        let role = patch.role.unwrap_or(before.role);
        let moved = patch.cidr.is_some_and(|cidr| cidr != before.cidr);
        let descendants = if let Some(cidr) = patch.cidr.filter(|cidr| *cidr != before.cidr) {
            let descendants = self.move_prefix(&before, cidr, role)?;
            after.cidr = cidr;
            descendants
        } else {
            self.descendants(vrf, &before.cidr)?
        };
        if role != before.role {
            self.check_role_change(&after, role, &descendants)?;
            after.role = role;
        }
        if let Some(status) = patch.status {
            Self::check_transition(id.into(), before.status, status)?;
            after.status = status;
        }
        if let Some(vlan) = patch.vlan {
            if vlan != before.vlan {
                self.check_references(vlan, None)?;
            }
            after.vlan = vlan;
        }
        if let Some(site) = patch.site {
            if site != before.site {
                self.check_references(None, site)?;
            }
            after.site = site;
        }
        if let Some(alarm) = patch.alarm {
            after.alarm = check_alarm(alarm)?;
        }
        if let Some(alloc) = patch.alloc {
            after.alloc = alloc;
        }
        self.patch_meta(
            Prefix::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        if after.cidr != before.cidr {
            self.nibble_warning(&after);
        }
        let reference = self.finish_update(&before, &after, |_, _| Ok(()))?;
        if moved {
            // Addresses can move in or out of the prefix, and into prefixes it now
            // surrounds: recompute the old and the new space.
            self.reparent(vrf, &before.cidr, &[])?;
            self.reparent(vrf, &after.cidr, &[])?;
        }
        Ok(reference)
    }

    /// Moves a prefix to a new network of the same family: everything it holds must fit.
    /// Returns the prefixes inside the new network.
    fn move_prefix(
        &mut self,
        before: &Prefix,
        cidr: IpNet,
        role: PrefixRole,
    ) -> IpamResult<Vec<(IpNet, PrefixId)>> {
        let (id, vrf) = (before.id, before.vrf);
        check_cidr("cidr", &cidr)?;
        if Family::of_net(&cidr) != Family::of_net(&before.cidr) {
            return Err(IpamError::invalid(
                "cidr",
                "a prefix cannot change its address family",
            ));
        }
        self.ws.expect_and_bump(&tree_counter(vrf))?;
        self.ws.expect_and_bump(&alloc_counter(id))?;
        let old_descendants = self.descendants(vrf, &before.cidr)?;
        let own = self.own_addresses(before, &old_descendants)?;
        let ranges = self.ranges_of(id, false)?;
        self.ws.delete_typed(&PREFIX_CIDRS, &(vrf, before.cidr));
        let placement = self.place_prefix(vrf, &cidr, Some(role), Some(id))?;
        let orphaned = old_descendants
            .iter()
            .filter(|(child, _)| !contains_net(&cidr, child))
            .count()
            + own.iter().filter(|a| !contains_ip(&cidr, a.ip)).count()
            + ranges
                .iter()
                .filter(|r| !contains_ip(&cidr, r.first) || !contains_ip(&cidr, r.last))
                .count();
        if orphaned > 0 {
            return Err(IpamError::new(
                codes::PREFIX_RESIZE_ORPHANS,
                409,
                format!(
                    "{cidr} would leave {orphaned} prefixes, addresses or ranges of {} outside",
                    before.cidr
                ),
            )
            .titled("Resize would orphan contents")
            .param("cidr", cidr)
            .param("count", orphaned)
            .field("cidr", codes::PREFIX_RESIZE_ORPHANS));
        }
        self.ws.put_typed(&PREFIX_CIDRS, &(vrf, cidr), &id)?;
        Ok(placement.descendants)
    }

    /// A supernet with children stays a supernet; a network with ranges stays a network.
    fn check_role_change(
        &mut self,
        prefix: &Prefix,
        role: PrefixRole,
        descendants: &[(IpNet, PrefixId)],
    ) -> IpamResult<()> {
        match role {
            PrefixRole::Network if !descendants.is_empty() => Err(IpamError::new(
                codes::PREFIX_HAS_CHILDREN,
                409,
                format!("{} contains prefixes and must stay a supernet", prefix.cidr),
            )
            .titled("The prefix has child prefixes")
            .param("cidr", prefix.cidr)
            .field("role", codes::PREFIX_HAS_CHILDREN)),
            PrefixRole::Supernet if !self.ranges_of(prefix.id, false)?.is_empty() => {
                Err(IpamError::new(
                    codes::PREFIX_HAS_RANGES,
                    409,
                    format!("{} has ranges and must stay a network", prefix.cidr),
                )
                .titled("The prefix has ranges")
                .param("cidr", prefix.cidr)
                .field("role", codes::PREFIX_HAS_RANGES))
            }
            _ => Ok(()),
        }
    }

    pub(super) fn delete_prefix(
        &mut self,
        id: PrefixId,
        expected: Option<Revision>,
        cascade: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Prefix>(id, expected, false)?;
        let vrf = before.vrf;
        self.ws.expect_and_bump(&tree_counter(vrf))?;
        self.ws.expect_and_bump(&alloc_counter(id))?;
        let ranges = self.ranges_of(id, false)?;
        if !ranges.is_empty() {
            if !cascade {
                return Err(IpamError::in_use(id.into(), "ranges", ranges.len()));
            }
            for range in ranges {
                self.delete_range(range.id, None, true)?;
            }
        }
        let descendants = self.descendants(vrf, &before.cidr)?;
        let own = self.own_addresses(&before, &descendants)?;
        self.ws.delete_typed(&PREFIX_CIDRS, &(vrf, before.cidr));
        if !own.is_empty() {
            if cascade {
                for address in own {
                    self.delete_address(address.id, None, true)?;
                }
            } else {
                match self.parent_of(vrf, &before.cidr)? {
                    Some(parent) => {
                        self.load::<Prefix>(parent)?;
                        self.ws.expect_and_bump(&alloc_counter(parent))?;
                        for address in own {
                            self.move_address(address, parent)?;
                        }
                    }
                    None => {
                        return Err(IpamError::in_use(id.into(), "addresses", own.len()));
                    }
                }
            }
        }
        self.soft_delete(before, false)
    }

    pub(super) fn restore_prefix(
        &mut self,
        id: PrefixId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Prefix>(id, expected, true)?;
        require_deleted(&before)?;
        let vrf = before.vrf;
        self.load_live::<Vrf>(vrf, "vrf")?;
        self.check_references(before.vlan, before.site)?;
        self.ws.expect_and_bump(&tree_counter(vrf))?;
        self.ws.expect_and_bump(&alloc_counter(id))?;
        let placement = self.place_prefix(vrf, &before.cidr, Some(before.role), Some(id))?;
        self.ws.put_typed(&PREFIX_CIDRS, &(vrf, before.cidr), &id)?;
        let deleted = before.meta.deleted.clone();
        let restored = before.clone();
        let reference = self.undelete(before, false)?;
        // Ranges and addresses deleted together with the prefix come back with it.
        for range in self.ranges_of(id, true)? {
            if range.meta.is_deleted() && range.meta.deleted == deleted {
                self.restore_range(range.id, None, true)?;
            }
        }
        let mut restored_live = restored;
        restored_live.meta.deleted = None;
        self.adopt_addresses(&restored_live, &placement.descendants)?;
        let together: Vec<AddressId> = self
            .ws
            .scan_typed(&ADDRESSES, &KeyRange::all())?
            .into_iter()
            .filter(|(_, a): &(AddressId, Address)| {
                a.vrf == vrf
                    && a.meta.is_deleted()
                    && a.meta.deleted == deleted
                    && contains_ip(&restored_live.cidr, a.ip)
            })
            .map(|(id, _)| id)
            .collect();
        for address in together {
            self.restore_address(address, None, true)?;
        }
        Ok(reference)
    }

    // ----- ranges -----------------------------------------------------------------------

    /// The ranges of a prefix (loaded, tracked); deleted ones only with `with_deleted`.
    pub(super) fn ranges_of(
        &mut self,
        prefix: PrefixId,
        with_deleted: bool,
    ) -> IpamResult<Vec<Range>> {
        let ids = self
            .ws
            .scan_keys(&PREFIX_RANGES, &KeyRange::prefix(encode_key(&prefix)))?;
        let mut ranges = Vec::with_capacity(ids.len());
        for (_, id) in ids {
            if let Some((range, _)) = self.try_load::<Range>(id)?
                && (with_deleted || !range.meta.is_deleted())
            {
                ranges.push(range);
            }
        }
        Ok(ranges)
    }

    /// Checks a range against its prefix and the other ranges.
    fn check_range(&mut self, prefix: &Prefix, range: &Range) -> IpamResult<()> {
        if prefix.role != PrefixRole::Network {
            return Err(IpamError::new(
                codes::RANGE_NOT_IN_NETWORK,
                409,
                format!("{} is a supernet; ranges belong to networks", prefix.cidr),
            )
            .titled("Ranges belong to networks")
            .param("cidr", prefix.cidr)
            .field("prefix", codes::RANGE_NOT_IN_NETWORK));
        }
        if Family::of(range.first) != Family::of(range.last)
            || ip_to_u128(range.first) > ip_to_u128(range.last)
        {
            return Err(IpamError::invalid(
                "last",
                format!(
                    "{} to {} is not an ascending range of one family",
                    range.first, range.last
                ),
            ));
        }
        if !contains_ip(&prefix.cidr, range.first) || !contains_ip(&prefix.cidr, range.last) {
            return Err(IpamError::new(
                codes::RANGE_OUTSIDE_PREFIX,
                409,
                format!(
                    "{} to {} is not inside {}",
                    range.first, range.last, prefix.cidr
                ),
            )
            .titled("Range outside its prefix")
            .param("cidr", prefix.cidr)
            .field("first", codes::RANGE_OUTSIDE_PREFIX));
        }
        let (first, last) = (ip_to_u128(range.first), ip_to_u128(range.last));
        for other in self.ranges_of(prefix.id, false)? {
            if other.id != range.id
                && ip_to_u128(other.first) <= last
                && first <= ip_to_u128(other.last)
            {
                return Err(IpamError::new(
                    codes::RANGE_OVERLAP,
                    409,
                    format!(
                        "{} to {} overlaps the range {} to {}",
                        range.first, range.last, other.first, other.last
                    ),
                )
                .titled("Ranges overlap")
                .param("range", format!("{}-{}", range.first, range.last))
                .param("existing", format!("{}-{}", other.first, other.last))
                .field("first", codes::RANGE_OVERLAP));
            }
        }
        if range.role == RangeRole::DhcpPool {
            let family = Family::of(range.first);
            for (ip, address) in self.addresses_between(prefix.vrf, family, first, last)? {
                let (address, _) = self.load::<Address>(address)?;
                if let Some(host) = self.host_of_address(&address)?
                    && host.mode == AssignmentMode::Reserved
                {
                    return Err(IpamError::new(
                        codes::RANGE_COVERS_RESERVATION,
                        409,
                        format!(
                            "the DHCP pool would cover {ip}, the reservation of host {}",
                            host.name
                        ),
                    )
                    .titled("DHCP pool covers a reservation")
                    .param("ip", ip)
                    .param("host", host.name)
                    .field("first", codes::RANGE_COVERS_RESERVATION));
                }
            }
        }
        Ok(())
    }

    pub(super) fn create_range(&mut self, input: &RangeInput) -> IpamResult<ObjectRef> {
        let prefix = self.load_live::<Prefix>(input.prefix, "prefix")?;
        let id = self.claim_id::<Range>(input.id)?;
        self.ws.expect_and_bump(&alloc_counter(prefix.id))?;
        let status = input.status.unwrap_or(Status::Active);
        let meta = self.new_meta(
            Range::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let range = Range {
            id,
            prefix: prefix.id,
            first: input.first,
            last: input.last,
            role: input.role,
            lease_secs: None,
            status,
            meta,
        };
        self.check_range(&prefix, &range)?;
        self.check_parent_status(id.into(), status, prefix.id.into(), prefix.status);
        self.write(&range)?;
        self.ws.put_typed(&PREFIX_RANGES, &(prefix.id, id), &())?;
        self.sync_usage(id.into(), None, Some(&range.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Range(range)),
            false,
        )?;
        Ok(id.into())
    }

    pub(super) fn update_range(&mut self, update: &UpdateRange) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Range>(update.id, update.expected, false)?;
        let prefix = self.load_live::<Prefix>(before.prefix, "prefix")?;
        let patch = &update.patch;
        let mut after = before.clone();
        if let Some(first) = patch.first {
            after.first = first;
        }
        if let Some(last) = patch.last {
            after.last = last;
        }
        if let Some(role) = patch.role {
            after.role = role;
        }
        if let Some(status) = patch.status {
            Self::check_transition(before.id.into(), before.status, status)?;
            after.status = status;
        }
        if (after.first, after.last, after.role) != (before.first, before.last, before.role) {
            self.ws.expect_and_bump(&alloc_counter(prefix.id))?;
            self.check_range(&prefix, &after)?;
        }
        self.patch_meta(
            Range::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |_, _| Ok(()))
    }

    pub(super) fn delete_range(
        &mut self,
        id: RangeId,
        expected: Option<Revision>,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Range>(id, expected, false)?;
        self.ws.expect_and_bump(&alloc_counter(before.prefix))?;
        self.soft_delete(before, derived)
    }

    pub(super) fn restore_range(
        &mut self,
        id: RangeId,
        expected: Option<Revision>,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Range>(id, expected, true)?;
        require_deleted(&before)?;
        let prefix = self.load_live::<Prefix>(before.prefix, "prefix")?;
        self.ws.expect_and_bump(&alloc_counter(prefix.id))?;
        let mut live = before.clone();
        live.meta.deleted = None;
        self.check_range(&prefix, &live)?;
        self.undelete(before, derived)
    }

    // ----- addresses --------------------------------------------------------------------

    /// The host an address is assigned to, if any.
    pub(super) fn host_of_address(&mut self, address: &Address) -> IpamResult<Option<Host>> {
        let Some(interface) = address.interface else {
            return Ok(None);
        };
        let Some((interface, _)) = self.try_load::<Interface>(interface)? else {
            return Ok(None);
        };
        Ok(self.try_load::<Host>(interface.host)?.map(|(host, _)| host))
    }

    /// The live host behind a live interface, checked against the lock (IPAM-16).
    fn interface_host(&mut self, interface: tenko_core::InterfaceId) -> IpamResult<Host> {
        let iface = self.load_live::<Interface>(interface, "interface")?;
        let host = self.load_live::<Host>(iface.host, "interface")?;
        self.check_unlocked(&host)?;
        Ok(host)
    }

    /// Finds the prefix of a new or moved address and checks it (IPAM-23).
    fn place_address(
        &mut self,
        vrf: VrfId,
        ip: IpAddr,
        mode: Option<AssignmentMode>,
        object: ObjectRef,
    ) -> IpamResult<Prefix> {
        self.ws.expect(&tree_counter(vrf))?;
        if self.ws.exists(&ADDRESS_IPS, &(vrf, ip), true)? {
            return Err(IpamError::new(
                codes::ADDRESS_DUPLICATE,
                409,
                format!("{ip} exists already in the VRF"),
            )
            .titled("Duplicate address")
            .param("ip", ip)
            .field("ip", codes::ADDRESS_DUPLICATE));
        }
        let Some(prefix) = self.containing(vrf, ip)? else {
            return Err(IpamError::new(
                codes::ADDRESS_NO_PREFIX,
                409,
                format!("no prefix of the VRF contains {ip}"),
            )
            .titled("No prefix for the address")
            .param("ip", ip)
            .field("ip", codes::ADDRESS_NO_PREFIX));
        };
        let (prefix, _) = self.load::<Prefix>(prefix)?;
        if prefix.role == PrefixRole::Network
            && let IpNet::V4(net) = prefix.cidr
            && net.prefix_len() <= 30
            && (ip == IpAddr::V4(net.network()) || ip == IpAddr::V4(net.broadcast()))
        {
            return Err(IpamError::new(
                codes::ADDRESS_NETWORK_OR_BROADCAST,
                409,
                format!(
                    "{ip} is the network or broadcast address of {}",
                    prefix.cidr
                ),
            )
            .titled("Network or broadcast address")
            .param("ip", ip)
            .param("cidr", prefix.cidr)
            .field("ip", codes::ADDRESS_NETWORK_OR_BROADCAST));
        }
        if prefix.role == PrefixRole::Supernet {
            self.warn(
                codes::WARN_ADDRESS_IN_SUPERNET,
                format!("{ip} lies directly in the supernet {}", prefix.cidr),
                Some(object),
                &[("ip", ip.to_string()), ("cidr", prefix.cidr.to_string())],
                false,
            );
        }
        self.ws.expect_and_bump(&alloc_counter(prefix.id))?;
        self.check_pool(&prefix, ip, mode, object)?;
        Ok(prefix)
    }

    /// The DHCP pool rule of IPAM-23 for one address.
    pub(super) fn check_pool(
        &mut self,
        prefix: &Prefix,
        ip: IpAddr,
        mode: Option<AssignmentMode>,
        object: ObjectRef,
    ) -> IpamResult<()> {
        let value = ip_to_u128(ip);
        for range in self.ranges_of(prefix.id, false)? {
            if Family::of(range.first) != Family::of(ip)
                || value < ip_to_u128(range.first)
                || value > ip_to_u128(range.last)
            {
                continue;
            }
            let label = format!("{}-{}", range.first, range.last);
            match range.role {
                RangeRole::DhcpPool if mode == Some(AssignmentMode::Reserved) => {
                    return Err(IpamError::new(
                        codes::ADDRESS_IN_DHCP_POOL,
                        409,
                        format!("{ip} is a reservation inside the DHCP pool {label}"),
                    )
                    .titled("Reservation inside a DHCP pool")
                    .param("ip", ip)
                    .param("range", label)
                    .field("ip", codes::ADDRESS_IN_DHCP_POOL));
                }
                RangeRole::DhcpPool => self.warn(
                    codes::ADDRESS_IN_DHCP_POOL,
                    format!("{ip} lies inside the DHCP pool {label}"),
                    Some(object),
                    &[("ip", ip.to_string()), ("range", label)],
                    false,
                ),
                RangeRole::Reserved => self.warn(
                    codes::WARN_ADDRESS_IN_RANGE,
                    format!("{ip} lies inside the reserved range {label}"),
                    Some(object),
                    &[("ip", ip.to_string()), ("range", label)],
                    false,
                ),
                RangeRole::Infrastructure => {}
            }
        }
        Ok(())
    }

    pub(super) fn create_address(&mut self, input: &AddressInput) -> IpamResult<ObjectRef> {
        Ok(self.create_address_inner(input)?.into())
    }

    fn create_address_inner(&mut self, input: &AddressInput) -> IpamResult<AddressId> {
        let vrf = match input.vrf {
            Some(vrf) => vrf,
            None => self.default_vrf()?,
        };
        self.load_live::<Vrf>(vrf, "vrf")?;
        let host = match input.interface {
            Some(interface) => {
                let host = self.interface_host(interface)?;
                self.add_reference(interface.into());
                Some(host)
            }
            None => None,
        };
        let id = self.claim_id::<Address>(input.id)?;
        let prefix = self.place_address(vrf, input.ip, host.as_ref().map(|h| h.mode), id.into())?;
        let status = input.status.unwrap_or(Status::Active);
        self.check_parent_status(id.into(), status, prefix.id.into(), prefix.status);
        let meta = self.new_meta(
            Address::KIND,
            &input.tags,
            &input.custom,
            input.description.as_ref(),
        )?;
        let address = Address {
            id,
            vrf,
            ip: input.ip,
            prefix: prefix.id,
            status,
            interface: input.interface,
            dns_name: input.dns_name.clone(),
            meta,
        };
        self.write(&address)?;
        self.ws.put_typed(&ADDRESS_IPS, &(vrf, address.ip), &id)?;
        if let Some(interface) = address.interface {
            self.ws
                .put_typed(&INTERFACE_ADDRESSES, &(interface, id), &())?;
        }
        if let Some(host) = host {
            self.reservation_checks.insert(host.id);
        }
        self.sync_usage(id.into(), None, Some(&address.meta))?;
        self.record(
            id.into(),
            ChangeAction::Create,
            None,
            Some(IpamObject::Address(address)),
            false,
        )?;
        Ok(id)
    }

    pub(super) fn update_address(&mut self, update: &UpdateAddress) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Address>(update.id, update.expected, false)?;
        let id = before.id;
        let patch = &update.patch;
        let mut after = before.clone();
        let old_host = self.host_of_address(&before)?;
        if let Some(host) = &old_host {
            self.check_unlocked(host)?;
            self.reservation_checks.insert(host.id);
        }
        let interface = patch.interface.unwrap_or(before.interface);
        let new_host = if interface == before.interface {
            old_host
        } else {
            if let Some(old) = before.interface {
                self.ws.delete_typed(&INTERFACE_ADDRESSES, &(old, id));
            }
            match interface {
                Some(new) => {
                    let host = self.interface_host(new)?;
                    self.add_reference(new.into());
                    self.ws.put_typed(&INTERFACE_ADDRESSES, &(new, id), &())?;
                    self.reservation_checks.insert(host.id);
                    Some(host)
                }
                None => None,
            }
        };
        after.interface = interface;
        let mode = new_host.as_ref().map(|h| h.mode);
        if let Some(ip) = patch.ip.filter(|ip| *ip != before.ip) {
            self.ws.delete_typed(&ADDRESS_IPS, &(before.vrf, before.ip));
            self.ws.expect_and_bump(&alloc_counter(before.prefix))?;
            let prefix = self.place_address(before.vrf, ip, mode, id.into())?;
            after.ip = ip;
            after.prefix = prefix.id;
        } else if interface != before.interface {
            let (prefix, _) = self.load::<Prefix>(before.prefix)?;
            self.ws.expect(&alloc_counter(prefix.id))?;
            self.check_pool(&prefix, before.ip, mode, id.into())?;
        }
        if let Some(status) = patch.status {
            Self::check_transition(id.into(), before.status, status)?;
            after.status = status;
        }
        if let Some(dns_name) = &patch.dns_name {
            after.dns_name.clone_from(dns_name);
        }
        self.patch_meta(
            Address::KIND,
            &mut after.meta,
            patch.tags.as_ref(),
            patch.custom.as_ref(),
            patch.description.as_ref(),
        )?;
        self.finish_update(&before, &after, |p, a| {
            p.ws.put_typed(&ADDRESS_IPS, &(a.vrf, a.ip), &a.id)
        })
    }

    pub(super) fn delete_address(
        &mut self,
        id: AddressId,
        expected: Option<Revision>,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Address>(id, expected, false)?;
        if let Some(host) = self.host_of_address(&before)? {
            self.check_unlocked(&host)?;
            self.reservation_checks.insert(host.id);
        }
        self.ws.delete_typed(&ADDRESS_IPS, &(before.vrf, before.ip));
        self.ws.expect_and_bump(&alloc_counter(before.prefix))?;
        self.soft_delete(before, derived)
    }

    pub(super) fn restore_address(
        &mut self,
        id: AddressId,
        expected: Option<Revision>,
        derived: bool,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Address>(id, expected, true)?;
        require_deleted(&before)?;
        self.load_live::<Vrf>(before.vrf, "vrf")?;
        let host = match before.interface {
            Some(interface) => {
                let host = self.interface_host(interface)?;
                self.add_reference(interface.into());
                self.reservation_checks.insert(host.id);
                Some(host)
            }
            None => None,
        };
        let prefix = self.place_address(before.vrf, before.ip, host.map(|h| h.mode), id.into())?;
        self.ws
            .put_typed(&ADDRESS_IPS, &(before.vrf, before.ip), &id)?;
        let mut after = before.clone();
        after.prefix = prefix.id;
        self.undelete_as(before, after, derived)
    }

    // ----- next free (IPAM-07) ------------------------------------------------------------

    /// Space of a prefix that next free never hands out: its ranges and its child
    /// prefixes.
    fn blocked_in(&mut self, prefix: &Prefix) -> IpamResult<Vec<(u128, u128)>> {
        let mut blocked: Vec<(u128, u128)> = self
            .ranges_of(prefix.id, false)?
            .iter()
            .map(|r| (ip_to_u128(r.first), ip_to_u128(r.last)))
            .collect();
        blocked.extend(top_level(&self.descendants(prefix.vrf, &prefix.cidr)?));
        Ok(blocked)
    }

    pub(super) fn allocate_address(
        &mut self,
        alloc: &AllocateAddress,
    ) -> IpamResult<(ObjectRef, IpAddr)> {
        let prefix = self.load_live::<Prefix>(alloc.prefix, "prefix")?;
        let family = Family::of_net(&prefix.cidr);
        let vrf = prefix.vrf;
        self.ws.expect(&tree_counter(vrf))?;
        self.ws.expect_and_bump(&alloc_counter(prefix.id))?;
        let policy = alloc.policy.unwrap_or(prefix.alloc);
        let (host_lo, host_hi) = if prefix.role == PrefixRole::Network {
            host_bounds(&prefix.cidr)
        } else {
            bounds(&prefix.cidr)
        };
        let (lo, hi, mut blocked) = match alloc.range {
            Some(range_id) => {
                let range = self.load_live::<tenko_core::ipam::Range>(range_id, "range")?;
                if range.prefix != prefix.id {
                    return Err(IpamError::invalid(
                        "range",
                        format!("range {range_id} does not belong to prefix {}", prefix.cidr),
                    ));
                }
                (
                    ip_to_u128(range.first).max(host_lo),
                    ip_to_u128(range.last).min(host_hi),
                    top_level(&self.descendants(vrf, &prefix.cidr)?),
                )
            }
            None => (host_lo, host_hi, self.blocked_in(&prefix)?),
        };
        let hinted = match alloc.hint {
            Some(hint) if Family::of(hint) == family => {
                let value = ip_to_u128(hint);
                (lo..=hi).contains(&value)
                    && !inside(&crate::alloc::merge(blocked.clone()), value)
                    && !self.ws.exists(&ADDRESS_IPS, &(vrf, hint), false)?
            }
            _ => false,
        };
        let value = if hinted {
            alloc.hint.map(ip_to_u128)
        } else {
            blocked.extend(
                self.addresses_between(vrf, family, lo, hi)?
                    .into_iter()
                    .map(|(ip, _)| (ip_to_u128(ip), ip_to_u128(ip))),
            );
            first_free(lo, hi, blocked, policy)
        };
        let Some(value) = value else {
            return Err(IpamError::new(
                codes::ADDRESS_FULL,
                409,
                format!("no free address left in {}", prefix.cidr),
            )
            .titled("No free address")
            .param("cidr", prefix.cidr));
        };
        let ip = u128_to_ip(family, value);
        let input = AddressInput {
            id: alloc.id,
            vrf: Some(vrf),
            ip,
            status: alloc.status,
            interface: alloc.interface,
            dns_name: alloc.dns_name.clone(),
            tags: alloc.tags.clone(),
            custom: alloc.custom.clone(),
            description: alloc.description.clone(),
        };
        let id = self.create_address_inner(&input)?;
        Ok((id.into(), ip))
    }

    pub(super) fn allocate_prefix(
        &mut self,
        alloc: &AllocatePrefix,
    ) -> IpamResult<(ObjectRef, IpNet)> {
        let parent = self.load_live::<Prefix>(alloc.parent, "parent")?;
        let family = Family::of_net(&parent.cidr);
        if parent.role != PrefixRole::Supernet {
            return Err(overlap(&parent.cidr, &parent.cidr));
        }
        if alloc.length <= parent.cidr.prefix_len() || alloc.length > family.bits() {
            return Err(IpamError::invalid(
                "length",
                format!(
                    "length {} must be longer than /{} and at most /{}",
                    alloc.length,
                    parent.cidr.prefix_len(),
                    family.bits()
                ),
            ));
        }
        let vrf = parent.vrf;
        self.ws.expect(&tree_counter(vrf))?;
        self.ws.expect(&alloc_counter(parent.id))?;
        let policy = alloc.policy.unwrap_or(parent.alloc);
        let (lo, hi) = bounds(&parent.cidr);
        let hinted = match alloc.hint {
            Some(hint)
                if Family::of_net(&hint) == family
                    && hint.prefix_len() == alloc.length
                    && !has_host_bits(&hint)
                    && contains_net(&parent.cidr, &hint) =>
            {
                let (first, last) = bounds(&hint);
                self.parent_of(vrf, &hint)? == Some(parent.id)
                    && self.prefix_at(vrf, hint)?.is_none()
                    && self.descendants(vrf, &hint)?.is_empty()
                    && self.addresses_between(vrf, family, first, last)?.is_empty()
            }
            _ => false,
        };
        let start = if hinted {
            alloc.hint.map(|hint| ip_to_u128(hint.network()))
        } else {
            let mut blocked = top_level(&self.descendants(vrf, &parent.cidr)?);
            blocked.extend(
                self.addresses_between(vrf, family, lo, hi)?
                    .into_iter()
                    .map(|(ip, _)| (ip_to_u128(ip), ip_to_u128(ip))),
            );
            first_free_block(family, lo, hi, alloc.length, blocked, policy)
        };
        let Some(start) = start else {
            return Err(IpamError::new(
                codes::PREFIX_FULL,
                409,
                format!("no free /{} left in {}", alloc.length, parent.cidr),
            )
            .titled("No free prefix")
            .param("cidr", parent.cidr)
            .param("length", alloc.length));
        };
        let cidr = net_from(family, start, alloc.length);
        let input = PrefixInput {
            id: alloc.id,
            vrf: Some(vrf),
            cidr,
            role: Some(alloc.role.unwrap_or(PrefixRole::Network)),
            status: alloc.status,
            vlan: alloc.vlan,
            site: alloc.site,
            alarm: alloc.alarm,
            alloc: None,
            tags: alloc.tags.clone(),
            custom: alloc.custom.clone(),
            description: alloc.description.clone(),
        };
        let id = self.create_prefix_inner(&input)?;
        Ok((id.into(), cidr))
    }
}

/// `ipam.prefix.overlap` (IPAM-23).
fn overlap(cidr: &IpNet, existing: &IpNet) -> IpamError {
    IpamError::new(
        codes::PREFIX_OVERLAP,
        409,
        format!("{cidr} overlaps {existing}"),
    )
    .titled("Prefix overlaps an existing prefix in the VRF")
    .param("cidr", existing)
    .field("cidr", codes::PREFIX_OVERLAP)
}

fn check_cidr(field: &str, cidr: &IpNet) -> IpamResult<()> {
    if has_host_bits(cidr) {
        return Err(IpamError::new(
            codes::PREFIX_HOST_BITS,
            400,
            format!("{cidr} has host bits set; the network is {}", cidr.trunc()),
        )
        .titled("Network with host bits")
        .param("cidr", cidr)
        .param("network", cidr.trunc())
        .field(field, codes::PREFIX_HOST_BITS));
    }
    Ok(())
}

fn check_alarm(alarm: Option<UtilizationAlarm>) -> IpamResult<Option<UtilizationAlarm>> {
    match alarm {
        None => Ok(None),
        Some(alarm) => UtilizationAlarm::new(alarm.warn_pct, alarm.crit_pct)
            .map(Some)
            .map_err(|error| IpamError::invalid("alarm", error.to_string())),
    }
}

/// The maximal intervals of a pre-ordered list of nested prefixes.
fn top_level(descendants: &[(IpNet, PrefixId)]) -> Vec<(u128, u128)> {
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (net, _) in descendants {
        let (first, last) = bounds(net);
        match out.last() {
            Some((_, end)) if first <= *end => {}
            _ => out.push((first, last)),
        }
    }
    out
}

/// Whether `value` lies in one of the sorted, disjoint intervals.
fn inside(intervals: &[(u128, u128)], value: u128) -> bool {
    let index = intervals.partition_point(|(first, _)| *first <= value);
    index > 0 && intervals[index - 1].1 >= value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_and_inside() {
        let nets: Vec<(IpNet, PrefixId)> = ["192.0.2.0/25", "192.0.2.0/26", "192.0.2.192/26"]
            .iter()
            .map(|n| (n.parse().expect("net"), PrefixId::generate()))
            .collect();
        let top = top_level(&nets);
        assert_eq!(top.len(), 2);
        let ip = |s: &str| ip_to_u128(s.parse().expect("ip"));
        assert!(inside(&top, ip("192.0.2.5")));
        assert!(!inside(&top, ip("192.0.2.130")));
        assert!(inside(&top, ip("192.0.2.255")));
    }
}
