//! Rows for the tests of the configuration service: IPAM prefixes, ranges, hosts,
//! interfaces and addresses with documentation addresses and MACs, and a store with them.

use std::{net::IpAddr, sync::Arc};

use tenko_core::{
    AddressId, HostId, InterfaceId, PrefixId, Principal, RangeId, RequestCtx, SystemComponent,
    TenantId, VrfId,
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    net::{HostName, MacAddr},
    serde_util::HexBytes,
};
use tenko_ipam::tables::{
    ADDRESS_IPS, ADDRESSES, HOST_INTERFACES, HOSTS, INTERFACE_ADDRESSES, INTERFACES, PREFIX_RANGES,
    PREFIXES, RANGES,
};
use tenko_store::{MemStore, Store, WriteBatch};

/// The principal of test writes.
pub(crate) fn principal() -> Principal {
    Principal::system(SystemComponent::Api)
}

/// A request context of the API.
pub(crate) fn cx() -> RequestCtx {
    RequestCtx::new(principal())
}

/// A fixed stamp.
pub(crate) fn stamp() -> Stamp {
    Stamp::new("2026-10-22T12:00:00Z".parse().expect("time"), principal())
}

pub(crate) fn meta(deleted: bool) -> Meta {
    let mut meta = Meta::new(stamp());
    if deleted {
        meta.deleted = Some(stamp());
    }
    meta
}

/// A prefix.
pub(crate) fn prefix(vrf: VrfId, cidr: &str, role: PrefixRole) -> Prefix {
    Prefix {
        id: PrefixId::generate(),
        vrf,
        cidr: cidr.parse().expect("cidr"),
        role,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        dns_reverse: None,
        meta: meta(false),
    }
}

/// A range of a prefix.
pub(crate) fn range(prefix: PrefixId, first: &str, last: &str, role: RangeRole) -> Range {
    Range {
        id: RangeId::generate(),
        prefix,
        first: first.parse().expect("first"),
        last: last.parse().expect("last"),
        role,
        lease_secs: None,
        delegated_len: None,
        status: Status::Active,
        meta: meta(false),
    }
}

/// A host.
pub(crate) fn host(name: &str, mode: AssignmentMode) -> Host {
    Host {
        id: HostId::generate(),
        tenant: TenantId::generate(),
        name: HostName::new(name).expect("host name"),
        mode,
        lock: false,
        site: None,
        meta: meta(false),
    }
}

/// An interface of a host with a MAC of the documentation block and a client identifier.
pub(crate) fn interface(host: HostId, mac: Option<u8>, client_id: Option<&[u8]>) -> Interface {
    Interface {
        id: InterfaceId::generate(),
        host,
        name: "eth0".to_owned(),
        mac: mac.map(|last| MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])),
        duid: None,
        client_id: client_id.map(|id| HexBytes(id.to_vec())),
        meta: meta(false),
    }
}

/// An address of a prefix.
pub(crate) fn address(prefix: &Prefix, ip: &str, interface: Option<InterfaceId>) -> Address {
    Address {
        id: AddressId::generate(),
        vrf: prefix.vrf,
        ip: ip.parse().expect("ip"),
        prefix: prefix.id,
        status: Status::Active,
        interface,
        dns_name: None,
        meta: meta(false),
    }
}

/// Writes IPAM rows straight into the store, with the indexes the service reads.
#[derive(Default)]
pub(crate) struct Ipam {
    pub(crate) prefixes: Vec<Prefix>,
    pub(crate) ranges: Vec<Range>,
    pub(crate) hosts: Vec<Host>,
    pub(crate) interfaces: Vec<Interface>,
    pub(crate) addresses: Vec<Address>,
}

impl Ipam {
    pub(crate) async fn write(&self, store: &Arc<dyn Store>) {
        let mut batch = WriteBatch::new(principal(), stamp().at);
        for prefix in &self.prefixes {
            batch
                .put_typed(&PREFIXES, &prefix.id, prefix)
                .expect("prefix");
        }
        for range in &self.ranges {
            batch.put_typed(&RANGES, &range.id, range).expect("range");
            batch
                .put_typed(&PREFIX_RANGES, &(range.prefix, range.id), &())
                .expect("index");
        }
        for host in &self.hosts {
            batch.put_typed(&HOSTS, &host.id, host).expect("host");
        }
        for interface in &self.interfaces {
            batch
                .put_typed(&INTERFACES, &interface.id, interface)
                .expect("interface");
            batch
                .put_typed(&HOST_INTERFACES, &(interface.host, interface.id), &())
                .expect("index");
        }
        for address in &self.addresses {
            batch
                .put_typed(&ADDRESSES, &address.id, address)
                .expect("address");
            batch
                .put_typed(&ADDRESS_IPS, &(address.vrf, address.ip), &address.id)
                .expect("index");
            if let Some(interface) = address.interface {
                batch
                    .put_typed(&INTERFACE_ADDRESSES, &(interface, address.id), &())
                    .expect("index");
            }
        }
        store.propose(batch).await.expect("IPAM rows");
    }
}

/// An empty in-memory store.
pub(crate) fn store() -> Arc<dyn Store> {
    Arc::new(MemStore::default())
}

/// The IPv4 address as an `IpAddr`.
pub(crate) fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}
