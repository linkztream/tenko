//! The check of a DHCP reservation over the state after the commands
//! ([`crate::reserve`], IPAM-18, IPAM-23).
//!
//! Every object the check reads is read with tracking, and the allocation counter of the
//! address's prefix is expected, so a concurrent change of another reservation in the scope
//! (a host's mode, an interface's identity, an address created, moved or rebound) makes the
//! plan stale and the service plans again.

use std::ops::Bound;

use tenko_core::{
    HostId,
    dhcp::{codes as dhcp_codes, tables::SCOPES},
    ipam::{Address, AssignmentMode, Host, Interface, Prefix, Status},
    serde_util::to_hex,
};
use tenko_store::KeyRange;

use super::Planner;
use crate::{
    error::{IpamError, IpamResult},
    net::{Family, bounds, u128_to_ip},
    reserve::{ReservationCheck, identity},
    tables::{ADDRESS_IPS, alloc_counter},
};

impl Planner<'_> {
    /// Fails unless the address is a reservation the `dhcp` role derives on its own: a live
    /// address of status `active` or `planned` on a live interface with a client identity of
    /// a live `reserved` host, in a prefix with a scope, and no other `reserved` host
    /// presenting that identity in the scope.
    pub(super) fn check_reservation(&mut self, check: &ReservationCheck) -> IpamResult<()> {
        let address = self.load_live::<Address>(check.address, "address")?;
        let prefix = self.load_live::<Prefix>(address.prefix, "prefix")?;
        if self.ws.get_typed(&SCOPES, &prefix.id, true)?.is_none() {
            return Err(IpamError::new(
                dhcp_codes::SCOPE_NOT_FOUND,
                404,
                format!(
                    "{} has no DHCP scope, so {} cannot be reserved; create the scope first",
                    prefix.cidr, address.ip
                ),
            )
            .titled("The network has no DHCP scope")
            .param("prefix", prefix.id));
        }
        let Some(interface_id) = address.interface else {
            return Err(IpamError::invalid(
                "interface",
                "a reservation needs the address on an interface",
            ));
        };
        let interface = self.load_live::<Interface>(interface_id, "interface")?;
        let host = self.load_live::<Host>(interface.host, "host")?;
        let family = Family::of(address.ip);
        let Some(key) = identity(&interface, family) else {
            let what = match family {
                Family::V4 => "a MAC address or a client identifier",
                Family::V6 => "a DUID or a MAC address",
            };
            return Err(IpamError::new(
                dhcp_codes::RESERVATION_NO_IDENTITY,
                409,
                format!(
                    "interface {} of host {} has no {what}, so no reservation of {} exists (IPAM-18)",
                    interface.name, host.name, address.ip
                ),
            )
            .titled("The interface has no client identity")
            .param("host", host.id)
            .field("mac", dhcp_codes::RESERVATION_NO_IDENTITY));
        };
        if host.mode != AssignmentMode::Reserved || !reserves(address.status) {
            return Err(IpamError::invalid(
                "status",
                "a reservation needs a reserved host and an address of status active or planned",
            ));
        }
        self.ws.expect(&alloc_counter(prefix.id))?;
        if let Some(other) = self.client_taken(&prefix, &address, host.id, &key)? {
            return Err(IpamError::new(
                dhcp_codes::RESERVATION_CONFLICT,
                409,
                format!(
                    "host {} already presents this client identity in {} (IPAM-23)",
                    other.name, prefix.cidr
                ),
            )
            .titled("The client is reserved for another host")
            .param("client", to_hex(&key))
            .param("hosts", sorted_pair(host.id, other.id))
            .field("mac", dhcp_codes::RESERVATION_CONFLICT));
        }
        Ok(())
    }

    /// Another live `reserved` host whose interface presents `key` on an active or planned
    /// address of the prefix, if any.
    fn client_taken(
        &mut self,
        prefix: &Prefix,
        address: &Address,
        host: HostId,
        key: &[u8],
    ) -> IpamResult<Option<Host>> {
        let family = Family::of(address.ip);
        let (first, last) = bounds(&prefix.cidr);
        let range = KeyRange {
            start: Bound::Included(ADDRESS_IPS.key(&(address.vrf, u128_to_ip(family, first)))),
            end: Bound::Included(ADDRESS_IPS.key(&(address.vrf, u128_to_ip(family, last)))),
        };
        let ids: Vec<_> = self
            .ws
            .scan_typed(&ADDRESS_IPS, &range)?
            .into_iter()
            .map(|(_, id)| id)
            .filter(|id| *id != address.id)
            .collect();
        for id in ids {
            let Some((other, _)) = self.try_load::<Address>(id)? else {
                continue;
            };
            if other.meta.is_deleted() || other.prefix != prefix.id || !reserves(other.status) {
                continue;
            }
            let Some(interface_id) = other.interface else {
                continue;
            };
            let Some((interface, _)) = self.try_load::<Interface>(interface_id)? else {
                continue;
            };
            if interface.meta.is_deleted() || interface.host == host {
                continue;
            }
            let Some((owner, _)) = self.try_load::<Host>(interface.host)? else {
                continue;
            };
            if owner.meta.is_deleted() || owner.mode != AssignmentMode::Reserved {
                continue;
            }
            if identity(&interface, family).as_deref() == Some(key) {
                return Ok(Some(owner));
            }
        }
        Ok(None)
    }
}

/// The statuses of an address that make a reservation.
fn reserves(status: Status) -> bool {
    matches!(status, Status::Active | Status::Planned)
}

/// Two hosts, sorted, separated by a comma.
fn sorted_pair(a: HostId, b: HostId) -> String {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    format!("{first},{second}")
}
