//! Reserving an address in DHCP: the commands of `POST /addresses/{id}/reserve` and
//! `POST /addresses/reserve`.
//!
//! A DHCP reservation is not a row of its own: the `dhcp` role derives it from a host of mode
//! `reserved`, an interface of that host with a client identity and an address of status
//! `active` or `planned` on that interface inside a prefix with a scope (docs/dhcp.md
//! section 2). Reserving an address therefore writes IPAM rows only: the host (an existing
//! one set to `reserved`, or a new one), the interface (an existing one of the host with its
//! MAC address and client identifier, or a new one) and the address (bound to the
//! interface, with status `active` or `planned`; created when the request names an address
//! IPAM does not hold yet).
//!
//! [`commands`] reads the objects from a view and returns the commands, each change pinned
//! to the revision it read (`expected`), so that the plan fails with
//! `ipam.revision_mismatch` rather than overwrite a change made in between. It refuses an
//! address that another `reserved` host already holds (`dhcp.reservation.conflict`,
//! IPAM-23). The rest is checked by the planner over the state after the commands
//! ([`ReservationCheck`], carried in [`PlanOptions::reservation`](crate::PlanOptions)): the
//! address lies in a prefix with a scope (`dhcp.scope.not_found`), the interface has a
//! client identity (`dhcp.reservation.no_identity`, IPAM-18) and no other `reserved` host
//! presents the same identity in the scope (`dhcp.reservation.conflict`, IPAM-23). Every
//! reservation request of one scope expects and bumps the counter [`reserve_counter`], so
//! two of them never commit from the same view.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    AddressId, CounterKey, HostId, InterfaceId, MacAddr, PrefixId, VrfId,
    codec::encode_key,
    dhcp::{codes as dhcp_codes, lease::MAX_IDENTITY, write_identity},
    ipam::{Address, AssignmentMode, Host, Interface, Status},
    net::HostName,
    serde_util::HexBytes,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use crate::{
    Entity, IpamCommand,
    command::{
        AddressInput, AddressPatch, HostInput, InterfaceInput, InterfacePatch, UpdateAddress,
        UpdateInterface, nullable,
    },
    error::{IpamError, IpamResult, codes},
    net::Family,
    query,
    tables::{ADDRESS_IPS, HOST_INTERFACES, TENANT_NAMES, VRF_NAMES},
};

/// The name of a new interface when the request names none.
pub const DEFAULT_INTERFACE: &str = "eth0";

/// What a reservation request asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReserveInput {
    /// The address by value (`POST /addresses/reserve` only): an address IPAM does not hold
    /// yet in the VRF is created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "192.0.2.20")]
    pub ip: Option<IpAddr>,
    /// The VRF of `ip`; the default VRF when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub vrf: Option<VrfId>,
    /// An existing host. When neither `host` nor `new_host` is given, the host of the
    /// address's interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub host: Option<HostId>,
    /// The name of a new host of mode `reserved` in the default tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "printer01")]
    pub new_host: Option<HostName>,
    /// An existing interface of the host. When neither `interface` nor `new_interface` is
    /// given, the address's interface when it belongs to the host, else the host's only
    /// interface, else a new interface `eth0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub interface: Option<InterfaceId>,
    /// The name of a new interface of the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_interface: Option<String>,
    /// The MAC address the interface gets; absent keeps the interface's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "02:00:5e:10:00:01")]
    pub mac: Option<MacAddr>,
    /// The DHCPv4 client identifier (option 61) in hexadecimal; absent keeps the
    /// interface's, `null` clears it. When set, the reservation is keyed by it instead of
    /// the MAC address.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, nullable)]
    pub client_id: Option<Option<HexBytes>>,
    /// The status of the address afterwards, `active` or `planned`; absent keeps an active
    /// or planned address as it is and makes any other one active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

/// Which address a request reserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveTarget {
    /// An existing address, by identifier (the identifier route).
    Address(AddressId),
    /// An address by value, from [`ReserveInput::ip`] and [`ReserveInput::vrf`].
    ByValue,
}

/// The check the planner makes after the commands of a reservation (see the module
/// documentation). Not part of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationCheck {
    /// The address reserved.
    pub address: AddressId,
}

/// The commands of a reservation and the objects they end with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    /// The commands, in order: host, interface, address. Empty when everything is in place.
    pub commands: Vec<IpamCommand>,
    /// The check the plan makes afterwards.
    pub check: ReservationCheck,
    /// The address.
    pub address: AddressId,
    /// The host.
    pub host: HostId,
    /// The interface.
    pub interface: InterfaceId,
}

/// The counter every reservation request of a scope expects and bumps.
pub fn reserve_counter(prefix: PrefixId) -> CounterKey {
    CounterKey::with("ipam.reserve", &prefix)
}

/// The client identity a reservation of an address of `family` is keyed by, as the `dhcp`
/// role's configuration image derives it: for IPv4 the client identifier when the
/// interface has one, else the MAC address as an Ethernet `chaddr`; for IPv6 the DUID, else
/// the MAC address. None without either (IPAM-18).
pub fn identity(interface: &Interface, family: Family) -> Option<Vec<u8>> {
    match family {
        Family::V4 => {
            let mac = interface.mac.map(MacAddr::octets);
            let client_id = interface.client_id.as_ref().map(|id| id.0.as_slice());
            if client_id.is_none() && mac.is_none() {
                return None;
            }
            let mut out = [0u8; MAX_IDENTITY];
            let chaddr = mac.as_ref().map_or(&[][..], |octets| octets.as_slice());
            let len = write_identity(1, chaddr, client_id, &mut out);
            Some(out[..len].to_vec())
        }
        Family::V6 => match (&interface.duid, interface.mac) {
            (Some(duid), _) => Some([&[0u8][..], duid.as_bytes()].concat()),
            (None, Some(mac)) => Some([&[1u8][..], &mac.octets()[..]].concat()),
            (None, None) => None,
        },
    }
}

/// Reads one object, live or deleted, with its revision.
fn read<T: Entity>(view: &dyn ReadView, id: T::Id) -> IpamResult<Option<T>> {
    match query::get::<T>(view, id) {
        Ok(object) => Ok(Some(object)),
        Err(error) if error.is(codes::NOT_FOUND) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reads a live object; none when it is absent or deleted.
fn read_live<T: Entity>(view: &dyn ReadView, id: T::Id) -> IpamResult<Option<T>> {
    Ok(read::<T>(view, id)?.filter(|object| !object.meta().is_deleted()))
}

/// Reads a live object a request names; `ipam.reference_missing` otherwise.
fn named<T: Entity>(view: &dyn ReadView, id: T::Id, field: &str) -> IpamResult<T> {
    read_live::<T>(view, id)?.ok_or_else(|| IpamError::reference_missing(field, id.into()))
}

/// The default VRF, when it exists.
fn default_vrf(view: &dyn ReadView) -> IpamResult<Option<VrfId>> {
    let Some((tenant, _)) = view.get_typed(&TENANT_NAMES, &"default".to_owned())? else {
        return Ok(None);
    };
    Ok(view
        .get_typed(&VRF_NAMES, &(tenant, "default".to_owned()))?
        .map(|(vrf, _)| vrf))
}

/// The live interfaces of a host, by identifier.
fn interfaces_of(view: &dyn ReadView, host: HostId) -> IpamResult<Vec<Interface>> {
    let range = KeyRange::prefix(encode_key(&host));
    let mut out = Vec::new();
    for ((_, id), (), _) in view.scan_typed(&HOST_INTERFACES, range, usize::MAX, false)? {
        if let Some(interface) = read_live::<Interface>(view, id)? {
            out.push(interface);
        }
    }
    Ok(out)
}

/// The address of a request: the existing one, or none when the value route names an
/// address IPAM does not hold yet.
fn find_address(
    view: &dyn ReadView,
    target: ReserveTarget,
    input: &ReserveInput,
) -> IpamResult<(Option<Address>, IpAddr)> {
    match target {
        ReserveTarget::Address(id) => {
            if input.ip.is_some() || input.vrf.is_some() {
                return Err(IpamError::invalid(
                    "ip",
                    "the address is named by the path; leave out ip and vrf",
                ));
            }
            let address = query::get::<Address>(view, id)?;
            if address.meta.is_deleted() {
                return Err(IpamError::deleted(id.into()));
            }
            let ip = address.ip;
            Ok((Some(address), ip))
        }
        ReserveTarget::ByValue => {
            let Some(ip) = input.ip else {
                return Err(IpamError::invalid("ip", "name the address to reserve"));
            };
            let vrf = match input.vrf {
                Some(vrf) => Some(vrf),
                None => default_vrf(view)?,
            };
            let found = match vrf {
                Some(vrf) => match view.get_typed(&ADDRESS_IPS, &(vrf, ip))? {
                    Some((id, _)) => read_live::<Address>(view, id)?,
                    None => None,
                },
                None => None,
            };
            Ok((found, ip))
        }
    }
}

/// Refuses what a request may not combine.
fn validate(input: &ReserveInput, family: Family) -> IpamResult<()> {
    if family == Family::V6 && matches!(input.client_id, Some(Some(_))) {
        return Err(IpamError::invalid(
            "client_id",
            "a client identifier keys DHCPv4 reservations; an IPv6 reservation uses the interface's DUID or MAC address",
        ));
    }
    if let Some(status) = input.status
        && !matches!(status, Status::Active | Status::Planned)
    {
        return Err(IpamError::invalid(
            "status",
            "a reservation needs an address of status active or planned",
        ));
    }
    if input.host.is_some() && input.new_host.is_some() {
        return Err(IpamError::invalid(
            "new_host",
            "name an existing host or a new one, not both",
        ));
    }
    if input.interface.is_some() && input.new_interface.is_some() {
        return Err(IpamError::invalid(
            "new_interface",
            "name an existing interface or a new one, not both",
        ));
    }
    Ok(())
}

/// The host a request reserves for.
enum HostChoice {
    /// An existing live host.
    Existing(Box<Host>),
    /// A new host of mode `reserved`.
    New(HostName),
}

/// The host: the one named, a new one, else the host of the address's interface.
fn choose_host(
    view: &dyn ReadView,
    input: &ReserveInput,
    bound_host: Option<&Host>,
) -> IpamResult<HostChoice> {
    if let Some(id) = input.host {
        return Ok(HostChoice::Existing(Box::new(named::<Host>(
            view, id, "host",
        )?)));
    }
    if let Some(name) = &input.new_host {
        return Ok(HostChoice::New(name.clone()));
    }
    bound_host
        .map(|host| HostChoice::Existing(Box::new(host.clone())))
        .ok_or_else(|| {
            IpamError::invalid(
                "host",
                "the address belongs to no host; name a host or a new one",
            )
        })
}

/// The interface: the one named (of the host), else the address's interface when it
/// belongs to the host, else the host's only interface; none means a new interface.
fn choose_interface(
    view: &dyn ReadView,
    input: &ReserveInput,
    host: &HostChoice,
    bound: Option<&Interface>,
) -> IpamResult<Option<Interface>> {
    let HostChoice::Existing(host) = host else {
        if input.interface.is_some() {
            return Err(IpamError::invalid(
                "interface",
                "a new host has no interfaces yet; name a new interface",
            ));
        }
        return Ok(None);
    };
    if let Some(id) = input.interface {
        let interface = named::<Interface>(view, id, "interface")?;
        if interface.host != host.id {
            return Err(IpamError::invalid(
                "interface",
                "the interface belongs to another host",
            ));
        }
        return Ok(Some(interface));
    }
    if input.new_interface.is_some() {
        return Ok(None);
    }
    if let Some(bound) = bound.filter(|bound| bound.host == host.id) {
        return Ok(Some(bound.clone()));
    }
    let mut interfaces = interfaces_of(view, host.id)?;
    Ok(if interfaces.len() == 1 {
        interfaces.pop()
    } else {
        None
    })
}

/// The commands that reserve an address (see the module documentation).
///
/// # Errors
///
/// `ipam.validation` for a request that names both an existing and a new host or
/// interface, an interface of another host, a client identifier on an IPv6 address, a
/// status other than `active` or `planned`, an `ip` on the identifier route or none on the
/// value route, or an unbound address without a host; `ipam.not_found` for an unknown
/// address; `ipam.object_deleted` for a deleted one; `ipam.reference_missing` for an unknown
/// host or interface; `dhcp.reservation.conflict` (409) when another `reserved` host holds
/// the address; store errors.
pub fn commands(
    view: &dyn ReadView,
    target: ReserveTarget,
    input: &ReserveInput,
) -> IpamResult<Reservation> {
    let (address, ip) = find_address(view, target, input)?;
    validate(input, Family::of(ip))?;
    let bound: Option<Interface> = match address.as_ref().and_then(|a| a.interface) {
        Some(id) => read_live::<Interface>(view, id)?,
        None => None,
    };
    let bound_host: Option<Host> = match &bound {
        Some(interface) => read_live::<Host>(view, interface.host)?,
        None => None,
    };
    let host = choose_host(view, input, bound_host.as_ref())?;
    // IPAM-23: an address another reserved host holds stays that host's reservation.
    if let Some(other) = &bound_host
        && other.mode == AssignmentMode::Reserved
        && !matches!(&host, HostChoice::Existing(host) if host.id == other.id)
    {
        return Err(IpamError::new(
            dhcp_codes::RESERVATION_CONFLICT,
            409,
            format!("{ip} is already the reservation of host {}", other.name),
        )
        .titled("The address is reserved for another host")
        .param("address", ip)
        .param("hosts", other.id));
    }
    let interface = choose_interface(view, input, &host, bound.as_ref())?;

    let host_id = match &host {
        HostChoice::Existing(host) => host.id,
        HostChoice::New(_) => HostId::generate(),
    };
    let interface_id = interface
        .as_ref()
        .map_or_else(InterfaceId::generate, |interface| interface.id);
    let mut commands = host_commands(input, &host, host_id, interface.as_ref(), interface_id);
    let address_id = if let Some(address) = &address {
        commands.extend(address_update(input, address, interface_id));
        address.id
    } else {
        let id = AddressId::generate();
        commands.push(IpamCommand::CreateAddress(AddressInput {
            id: Some(id),
            vrf: input.vrf,
            ip,
            status: Some(input.status.unwrap_or(Status::Active)),
            interface: Some(interface_id),
            dns_name: None,
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        }));
        id
    };
    Ok(Reservation {
        commands,
        check: ReservationCheck {
            address: address_id,
        },
        address: address_id,
        host: host_id,
        interface: interface_id,
    })
}

/// The commands of the host and the interface.
fn host_commands(
    input: &ReserveInput,
    host: &HostChoice,
    host_id: HostId,
    interface: Option<&Interface>,
    interface_id: InterfaceId,
) -> Vec<IpamCommand> {
    let new_interface = |host: Option<HostId>| InterfaceInput {
        id: Some(interface_id),
        host,
        name: input
            .new_interface
            .clone()
            .unwrap_or_else(|| DEFAULT_INTERFACE.to_owned()),
        mac: input.mac,
        duid: None,
        client_id: input.client_id.clone().flatten(),
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    };
    let mut commands = Vec::new();
    match host {
        HostChoice::New(name) => commands.push(IpamCommand::CreateHost(HostInput {
            id: Some(host_id),
            tenant: None,
            name: name.clone(),
            mode: Some(AssignmentMode::Reserved),
            lock: None,
            site: None,
            interfaces: vec![new_interface(None)],
            tags: BTreeSet::new(),
            custom: BTreeMap::new(),
            description: None,
        })),
        HostChoice::Existing(host) => {
            if host.mode != AssignmentMode::Reserved {
                commands.push(IpamCommand::SetMode {
                    host: host.id,
                    mode: AssignmentMode::Reserved,
                    expected: Some(host.meta.revision),
                });
            }
            match interface {
                None => commands.push(IpamCommand::CreateInterface(new_interface(Some(host.id)))),
                Some(interface) => commands.extend(interface_update(input, interface)),
            }
        }
    }
    commands
}

/// The change of an existing interface: the MAC address and the client identifier the
/// request sets; none when they are as asked.
fn interface_update(input: &ReserveInput, interface: &Interface) -> Option<IpamCommand> {
    let mac = input.mac.filter(|mac| interface.mac != Some(*mac));
    let client_id = input
        .client_id
        .clone()
        .filter(|id| *id != interface.client_id);
    (mac.is_some() || client_id.is_some()).then(|| {
        IpamCommand::UpdateInterface(UpdateInterface {
            id: interface.id,
            expected: Some(interface.meta.revision),
            patch: InterfacePatch {
                mac: mac.map(Some),
                client_id,
                ..InterfacePatch::default()
            },
        })
    })
}

/// The change of an existing address: bound to the interface, with an active or planned
/// status; none when it is both already.
fn address_update(
    input: &ReserveInput,
    address: &Address,
    interface: InterfaceId,
) -> Option<IpamCommand> {
    let status = match input.status {
        Some(status) if status != address.status => Some(status),
        Some(_) => None,
        None if matches!(address.status, Status::Active | Status::Planned) => None,
        None => Some(Status::Active),
    };
    let rebind = address.interface != Some(interface);
    (status.is_some() || rebind).then(|| {
        IpamCommand::UpdateAddress(UpdateAddress {
            id: address.id,
            expected: Some(address.meta.revision),
            patch: AddressPatch {
                status,
                interface: rebind.then_some(Some(interface)),
                ..AddressPatch::default()
            },
        })
    })
}
