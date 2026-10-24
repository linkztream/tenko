//! The rows of the configuration image from a read view (plan section 2.2).
//!
//! [`data`] reads every row the role serves from: the `dhcp` configuration, optionally the
//! leases, and the IPAM prefixes, ranges, hosts, interfaces and addresses. [`scope_data`]
//! reads only what the image of one scope needs (the scope, its shared network, the server
//! level, its exclusions and pools, the IPAM rows of its prefix and the hosts of its
//! addresses), for the routes that show one scope: the image built from it holds the same
//! scope as the image built from [`data`].

use std::{collections::BTreeMap, net::IpAddr};

use tenko_core::{
    AddressId, HostId, PrefixId, RangeId, Revision, VrfId,
    codec::key::encode_key,
    dhcp::{
        OptionOwner,
        tables::{
            CLASSES, EXCLUSIONS, FILTERS, LEASES, LEASES6, OPTION_DEFS, OPTION_SETS, POLICIES,
            POOLS, SCOPES, SETTINGS, SHARED_NETWORKS,
        },
    },
    ipam::{Address, Prefix, Range},
};
use tenko_ipam::tables::{
    ADDRESS_IPS, ADDRESSES, HOSTS, INTERFACES, PREFIX_RANGES, PREFIXES, RANGES,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::ConfigResult;
use crate::feed::DhcpData;

/// Every row of a table as a map.
fn all<K, V>(
    view: &dyn ReadView,
    table: &tenko_core::table::TableDef<K, V>,
) -> ConfigResult<BTreeMap<K, V>>
where
    K: tenko_core::codec::key::KeyCodec + Ord,
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    Ok(view
        .scan_typed(table, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect())
}

/// Every row the role serves from, at the view's revision; the leases only with
/// `with_leases`.
///
/// # Errors
///
/// The store's error.
pub fn data(view: &dyn ReadView, with_leases: bool) -> ConfigResult<DhcpData> {
    Ok(DhcpData {
        revision: view.revision(),
        settings: view
            .get_typed(&SETTINGS, &())?
            .map(|(settings, _)| settings),
        scopes: all(view, &SCOPES)?,
        shared_networks: all(view, &SHARED_NETWORKS)?,
        pools: all(view, &POOLS)?,
        exclusions: all(view, &EXCLUSIONS)?,
        option_defs: all(view, &OPTION_DEFS)?,
        option_sets: all(view, &OPTION_SETS)?,
        classes: all(view, &CLASSES)?,
        policies: all(view, &POLICIES)?,
        filters: all(view, &FILTERS)?,
        leases: if with_leases {
            all(view, &LEASES)?
        } else {
            BTreeMap::new()
        },
        // WP9.1: the DHCPv6 leases.
        leases6: if with_leases {
            all(view, &LEASES6)?
        } else {
            BTreeMap::new()
        },
        prefixes: all(view, &PREFIXES)?,
        ranges: all(view, &RANGES)?,
        hosts: all(view, &HOSTS)?,
        interfaces: all(view, &INTERFACES)?,
        addresses: all(view, &ADDRESSES)?,
    })
}

/// The key range of a VRF's addresses inside `net` in a table keyed `(VrfId, address)`.
pub(crate) fn address_range<A: tenko_core::codec::key::KeyCodec>(
    vrf: VrfId,
    first: A,
    last: A,
) -> KeyRange {
    let mut end = encode_key(&(vrf, last)).to_vec();
    // Any key of the same width up to `last` sorts below `last`'s encoding with one more
    // octet.
    end.push(0);
    KeyRange::between(encode_key(&(vrf, first)), end)
}

/// The ranges of a prefix, live ones only.
///
/// # Errors
///
/// The store's error.
pub(crate) fn ranges_of(
    view: &dyn ReadView,
    prefix: PrefixId,
) -> ConfigResult<Vec<(Range, Revision)>> {
    let mut ranges = Vec::new();
    for ((_, id), (), _) in view.scan_typed(
        &PREFIX_RANGES,
        KeyRange::prefix(encode_key(&prefix)),
        usize::MAX,
        false,
    )? {
        if let Some((range, revision)) = view.get_typed(&RANGES, &id)?
            && !range.meta.is_deleted()
        {
            ranges.push((range, revision));
        }
    }
    Ok(ranges)
}

/// The live addresses of a prefix.
///
/// # Errors
///
/// The store's error.
pub(crate) fn addresses_of(view: &dyn ReadView, prefix: &Prefix) -> ConfigResult<Vec<Address>> {
    let range = match prefix.cidr {
        ipnet::IpNet::V4(net) => address_range(
            prefix.vrf,
            IpAddr::V4(net.network()),
            IpAddr::V4(net.broadcast()),
        ),
        ipnet::IpNet::V6(net) => address_range(
            prefix.vrf,
            IpAddr::V6(net.network()),
            IpAddr::V6(net.broadcast()),
        ),
    };
    let mut addresses = Vec::new();
    for (_, id, _) in view.scan_typed(&ADDRESS_IPS, range, usize::MAX, false)? {
        let id: AddressId = id;
        if let Some((address, _)) = view.get_typed(&ADDRESSES, &id)?
            && !address.meta.is_deleted()
            && address.prefix == prefix.id
        {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

/// What the image of one scope needs; an empty image (no scope) when the prefix has no
/// scope or does not exist.
///
/// # Errors
///
/// The store's error.
pub fn scope_data(view: &dyn ReadView, prefix: PrefixId) -> ConfigResult<DhcpData> {
    let mut data = DhcpData::at(view.revision());
    data.settings = view
        .get_typed(&SETTINGS, &())?
        .map(|(settings, _)| settings);
    data.option_defs = all(view, &OPTION_DEFS)?;
    data.classes = all(view, &CLASSES)?;
    data.filters = all(view, &FILTERS)?;
    let Some((scope, _)) = view.get_typed(&SCOPES, &prefix)? else {
        return Ok(data);
    };
    let Some((row, _)) = view.get_typed(&PREFIXES, &prefix)? else {
        return Ok(data);
    };
    let mut owners = vec![OptionOwner::Server, OptionOwner::Scope(prefix)];
    if let Some(network) = scope.shared_network {
        owners.push(OptionOwner::SharedNetwork(network));
        if let Some((network_row, _)) = view.get_typed(&SHARED_NETWORKS, &network)? {
            data.shared_networks.insert(network, network_row);
        }
    }
    for (key, exclusion, _) in view.scan_typed(
        &EXCLUSIONS,
        KeyRange::prefix(encode_key(&prefix)),
        usize::MAX,
        false,
    )? {
        data.exclusions.insert(key, exclusion);
    }
    for (range, _) in ranges_of(view, prefix)? {
        let id: RangeId = range.id;
        if let Some((settings, _)) = view.get_typed(&POOLS, &id)? {
            data.pools.insert(id, settings);
        }
        owners.push(OptionOwner::Pool(id));
        data.ranges.insert(id, range);
    }
    for (id, policy, _) in view.scan_typed(&POLICIES, KeyRange::all(), usize::MAX, false)? {
        if policy.scope.is_none() || policy.scope == Some(prefix) {
            owners.push(OptionOwner::Policy(id));
            data.policies.insert(id, policy);
        }
    }
    for address in addresses_of(view, &row)? {
        if let Some(interface_id) = address.interface
            && !data.interfaces.contains_key(&interface_id)
            && let Some((interface, _)) = view.get_typed(&INTERFACES, &interface_id)?
        {
            let host_id: HostId = interface.host;
            if !data.hosts.contains_key(&host_id)
                && let Some((host, _)) = view.get_typed(&HOSTS, &host_id)?
            {
                data.hosts.insert(host_id, host);
            }
            owners.push(OptionOwner::Host(interface_id));
            data.interfaces.insert(interface_id, interface);
        }
        data.addresses.insert(address.id, address);
    }
    for owner in owners {
        if let Some((set, _)) = view.get_typed(&OPTION_SETS, &owner)? {
            data.option_sets.insert(owner, set);
        }
    }
    data.scopes.insert(prefix, scope);
    data.prefixes.insert(prefix, row);
    Ok(data)
}
