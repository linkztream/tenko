//! The synthetic address tree: one VRF, a supernet (/48), mid-level prefixes (/56), leaf
//! prefixes (/64) under them, and hosts with one interface and one address each. Documentation values only: IPv6 under
//! `2001:db8:100::/48`, names under `example.test`.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
    time::Instant,
};

use anyhow::{Context as _, Result};
use tenko_core::{AddressId, HostId, InterfaceId, PrefixId, RequestCtx, VrfId, ipam::PrefixRole};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::{AddressInput, HostInput, InterfaceInput, PrefixInput, VrfInput},
};

/// The base of the address space: `2001:db8:100::/48`.
const BASE: u128 = 0x2001_0db8_0100_0000_0000_0000_0000_0000;

/// What was created.
#[derive(Debug, Clone)]
pub struct Dataset {
    pub supernet: PrefixId,
    /// The /56 prefixes.
    pub mids: Vec<PrefixId>,
    /// The /64 prefixes, `leaves_per_mid` under each /56, in order.
    pub leaves: Vec<PrefixId>,
    /// The hosts of each leaf, in creation order.
    pub hosts: Vec<Vec<HostId>>,
    pub load_secs: f64,
}

fn prefix_input(
    vrf: VrfId,
    id: PrefixId,
    cidr: &str,
    role: Option<PrefixRole>,
) -> Result<PrefixInput> {
    Ok(PrefixInput {
        id: Some(id),
        vrf: Some(vrf),
        cidr: cidr.parse().with_context(|| format!("network {cidr}"))?,
        role,
        status: None,
        vlan: None,
        site: None,
        alarm: None,
        alloc: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    })
}

/// The /64 number `index` (of the /48) as a network in CIDR notation.
pub fn network(index: usize) -> String {
    let base = BASE | ((index as u128) << 64);
    format!("{}/64", Ipv6Addr::from(base))
}

/// The /56 number `index` as a network in CIDR notation.
pub fn mid_network(index: usize) -> String {
    let base = BASE | ((index as u128) << 72);
    format!("{}/56", Ipv6Addr::from(base))
}

/// The number of the /64 for leaf `j` under mid `m` (a /56 holds 256 of them).
pub fn leaf_number(m: usize, j: usize) -> usize {
    m * 256 + j
}

/// The address of host number `host` in prefix number `index`.
fn address(index: usize, host: usize) -> Ipv6Addr {
    Ipv6Addr::from(BASE | ((index as u128) << 64) | (host as u128 + 1))
}

/// Creates the tree through [`IpamService::execute`]: one request for the VRF and the
/// prefixes, then one request of `2 x hosts_per_leaf` commands (host with its interface,
/// then its address) per leaf. At most 256 mids (a /48 holds that many /56).
pub async fn load(
    ipam: &IpamService,
    ctx: &RequestCtx,
    mids: usize,
    leaves_per_mid: usize,
    hosts_per_leaf: usize,
) -> Result<Dataset> {
    let prefixes = mids * leaves_per_mid;
    let hosts_per_prefix = hosts_per_leaf;
    let started = Instant::now();
    let vrf = VrfId::generate();
    let supernet = PrefixId::generate();
    let mid_ids: Vec<PrefixId> = (0..mids).map(|_| PrefixId::generate()).collect();
    let prefix_ids: Vec<PrefixId> = (0..prefixes).map(|_| PrefixId::generate()).collect();

    let mut commands = vec![IpamCommand::CreateVrf(VrfInput {
        id: Some(vrf),
        tenant: None,
        name: "bench".to_owned(),
        rd: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    })];
    commands.push(IpamCommand::CreatePrefix(prefix_input(
        vrf,
        supernet,
        &format!("{}/48", Ipv6Addr::from(BASE)),
        Some(PrefixRole::Supernet),
    )?));
    for (m, id) in mid_ids.iter().enumerate() {
        commands.push(IpamCommand::CreatePrefix(prefix_input(
            vrf,
            *id,
            &mid_network(m),
            Some(PrefixRole::Supernet),
        )?));
    }
    for (index, id) in prefix_ids.iter().enumerate() {
        let number = leaf_number(index / leaves_per_mid, index % leaves_per_mid);
        commands.push(IpamCommand::CreatePrefix(prefix_input(
            vrf,
            *id,
            &network(number),
            None,
        )?));
    }
    ipam.execute(&commands, ctx, &PlanOptions::default())
        .await
        .context("create the VRF and the prefixes")?;

    let mut hosts = Vec::with_capacity(prefixes);
    for index in 0..prefixes {
        let number = leaf_number(index / leaves_per_mid, index % leaves_per_mid);
        let mut commands = Vec::with_capacity(hosts_per_prefix * 2);
        let mut ids = Vec::with_capacity(hosts_per_prefix);
        for host in 0..hosts_per_prefix {
            let (host_id, interface) = (HostId::generate(), InterfaceId::generate());
            let name = format!("h{index:03}-{host:03}");
            commands.push(IpamCommand::CreateHost(HostInput {
                id: Some(host_id),
                tenant: None,
                name: name.parse().with_context(|| format!("host name {name}"))?,
                mode: None,
                lock: None,
                site: None,
                interfaces: vec![InterfaceInput {
                    id: Some(interface),
                    host: None,
                    name: "eth0".to_owned(),
                    mac: None,
                    duid: None,
                    client_id: None,
                    tags: BTreeSet::new(),
                    custom: BTreeMap::new(),
                    description: None,
                }],
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }));
            let dns_name = format!("{name}.example.test");
            commands.push(IpamCommand::CreateAddress(AddressInput {
                id: Some(AddressId::generate()),
                vrf: Some(vrf),
                ip: address(number, host).into(),
                status: None,
                interface: Some(interface),
                dns_name: Some(
                    dns_name
                        .parse()
                        .with_context(|| format!("name {dns_name}"))?,
                ),
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }));
            ids.push(host_id);
        }
        ipam.execute(&commands, ctx, &PlanOptions::default())
            .await
            .with_context(|| format!("create the hosts of prefix {index}"))?;
        hosts.push(ids);
    }
    Ok(Dataset {
        supernet,
        mids: mid_ids,
        leaves: prefix_ids,
        hosts,
        load_secs: started.elapsed().as_secs_f64(),
    })
}
