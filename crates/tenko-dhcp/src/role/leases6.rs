//! The node commands over both lease families (WP9.4): `dhcp.leases.list` with the DHCPv6
//! leases of `dhcp.leases6` after the DHCPv4 ones, the correlation of each lease with the
//! lease of the other family that names the same MAC address (DHCP-11), the merged
//! history read, and `dhcp.lease6.release`.

use std::{collections::HashMap, net::Ipv6Addr};

use tenko_core::{
    Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease6, Lease6Event, Lease6Kind, LeaseEventKind, tables},
    net::Duid,
};
use tenko_store::{ReadConsistency, ReadViewExt as _, StoreError, WriteBatch};

use super::{
    CommandResult, LocalNode, Outcome, Output,
    commands::{self, Lease6Row, LeaseListArgs, LeasePeer, Release6Args, Resume, page_limit},
    state_name,
};

/// The arguments of a command, or the empty arguments when it has none.
fn decode<T: serde::de::DeserializeOwned + Default>(args: &[u8]) -> Result<T, CommandResult> {
    if args.is_empty() {
        return Ok(T::default());
    }
    tenko_core::codec::from_cbor(args)
        .map_err(|error| CommandResult::rejected(format!("the arguments: {error}")))
}

fn not_found6(addr: Ipv6Addr) -> CommandResult {
    CommandResult::coded(
        Outcome::Rejected,
        tenko_core::dhcp::codes::LEASE_NOT_FOUND,
        format!("no lease holds {addr}"),
    )
}

/// Keeps the better of two peers per MAC address.
fn offer(peers: &mut HashMap<[u8; 6], LeasePeer>, mac: [u8; 6], peer: LeasePeer) {
    match peers.get(&mac) {
        Some(held) if !peer.better_than(held) => {}
        _ => {
            peers.insert(mac, peer);
        }
    }
}

impl LocalNode {
    /// `dhcp.leases.list` over both families: the DHCPv4 page first, then the DHCPv6 leases
    /// in VRF and address order as far as the page has room.
    pub(super) fn list_both(&self, raw: &[u8]) -> CommandResult {
        let args: LeaseListArgs = match decode(raw) {
            Ok(args) => args,
            Err(result) => return result,
        };
        let limit = page_limit(args.limit);
        let mut page = commands::LeasePage {
            items: Vec::new(),
            next: None,
            items6: Vec::new(),
            next6: None,
        };
        if args.wants_v4() {
            let listed = self.list(raw);
            let Output::Leases(v4) = listed.output else {
                return listed;
            };
            page.items = v4.items;
            page.next = v4.next;
        }
        if args.wants_v6() && page.next.is_none() {
            let room = limit - page.items.len().min(limit);
            let after = args.after6.and_then(|resume| resume.key());
            let (rows, more) = {
                let table = self.leases6.read();
                let addr = args.addr_filter6();
                let mut matching: Vec<&Lease6> = table
                    .iter()
                    .filter(|lease| args.matches6_with(lease, addr.as_ref()))
                    .filter(|lease| after.is_none_or(|after| (lease.vrf, lease.addr6()) > after))
                    .collect();
                matching.sort_unstable_by_key(|lease| (lease.vrf, lease.addr6()));
                let more = matching.len() > room;
                let rows: Vec<(Lease6, Revision)> = matching
                    .into_iter()
                    .take(room)
                    .map(|lease| {
                        (
                            lease.clone(),
                            table
                                .row_revision(lease.vrf, lease.addr6())
                                .unwrap_or(Revision::ZERO),
                        )
                    })
                    .collect();
                (rows, more)
            };
            if more {
                page.next6 = Some(match rows.last() {
                    Some((lease, _)) => Resume::From((lease.vrf, lease.addr6())),
                    None => args.after6.unwrap_or(Resume::Start),
                });
            }
            page.items6 = rows
                .into_iter()
                .map(|(lease, revision)| self.row6_of(lease, revision))
                .collect();
        }
        self.correlate(&mut page);
        let count = page.items.len() + page.items6.len();
        CommandResult::done(
            format!("{count} lease(s) read"),
            Output::Leases(Box::new(page)),
        )
    }

    /// The API's view of a DHCPv6 row: its revision, and whether it is the client's
    /// reservation (by DUID, else by MAC address).
    pub(super) fn row6_of(&self, lease: Lease6, revision: Revision) -> Lease6Row {
        let image = self.server().map(|server| server.image());
        let reservation = image.as_ref().and_then(|image| {
            image
                .v6()
                .reservation(lease.scope, lease.duid.as_bytes(), lease.mac())
                .map(|held| (held.addr, held.host))
        });
        Lease6Row {
            reserved: reservation.is_some_and(|(addr, _)| addr == lease.addr6()),
            host: reservation.map(|(_, host)| host),
            peer: None,
            address_lease: None,
            revision,
            lease,
        }
    }

    /// Sets the peer of every row of `page`: the lease of the other family whose client
    /// has the same MAC address. One pass over each table, only for the addresses on the
    /// page.
    fn correlate(&self, page: &mut commands::LeasePage) {
        let wanted4: Vec<[u8; 6]> = page
            .items
            .iter()
            .filter_map(|row| row.lease.client.mac())
            .collect();
        if !wanted4.is_empty() {
            let mut peers = HashMap::new();
            for lease in self.leases6.read().iter() {
                if let Some(mac) = lease.mac().filter(|mac| wanted4.contains(mac)) {
                    let peer = LeasePeer {
                        vrf: lease.vrf,
                        addr: std::net::IpAddr::V6(lease.addr6()),
                        state: lease.state,
                        ends: lease.ends,
                    };
                    offer(&mut peers, mac, peer);
                }
            }
            for row in &mut page.items {
                row.peer = row
                    .lease
                    .client
                    .mac()
                    .and_then(|mac| peers.get(&mac).copied());
            }
        }
        let wanted6: Vec<[u8; 6]> = page
            .items6
            .iter()
            .filter_map(|row| row.lease.mac())
            .collect();
        if !wanted6.is_empty() {
            let mut peers = HashMap::new();
            for lease in self.leases.read().iter() {
                if let Some(mac) = lease.client.mac().filter(|mac| wanted6.contains(mac)) {
                    let peer = LeasePeer {
                        vrf: lease.vrf,
                        addr: std::net::IpAddr::V4(lease.addr),
                        state: lease.state,
                        ends: lease.ends,
                    };
                    offer(&mut peers, mac, peer);
                }
            }
            for row in &mut page.items6 {
                row.peer = row.lease.mac().and_then(|mac| peers.get(&mac).copied());
            }
        }
        // WP9.4: a delegated prefix names the router's address lease (the same DUID).
        let routers: Vec<(VrfId, Duid)> = page
            .items6
            .iter()
            .filter(|row| row.lease.kind == Lease6Kind::Pd)
            .map(|row| (row.lease.vrf, row.lease.duid.clone()))
            .collect();
        if !routers.is_empty() {
            let mut addresses: HashMap<(VrfId, Duid), LeasePeer> = HashMap::new();
            for lease in self.leases6.read().iter() {
                if lease.kind != Lease6Kind::Na {
                    continue;
                }
                let key = (lease.vrf, lease.duid.clone());
                if !routers.contains(&key) {
                    continue;
                }
                let peer = LeasePeer {
                    vrf: lease.vrf,
                    addr: std::net::IpAddr::V6(lease.addr6()),
                    state: lease.state,
                    ends: lease.ends,
                };
                match addresses.get(&key) {
                    Some(held) if !peer.better_than(held) => {}
                    _ => {
                        addresses.insert(key, peer);
                    }
                }
            }
            for row in &mut page.items6 {
                if row.lease.kind == Lease6Kind::Pd {
                    row.address_lease = addresses
                        .get(&(row.lease.vrf, row.lease.duid.clone()))
                        .copied();
                }
            }
        }
    }

    /// `dhcp.lease6.release`: the DHCPv6 row becomes `released` now, with a history row of
    /// kind `reclaimed`, under a version precondition, as `dhcp.lease.release` does.
    pub(super) async fn release6(&self, raw: &[u8]) -> CommandResult {
        let args: Release6Args = match tenko_core::codec::from_cbor(raw) {
            Ok(args) => args,
            Err(error) => return CommandResult::rejected(format!("the arguments: {error}")),
        };
        match self.release6_row(&args).await {
            Ok(row) => CommandResult::done(
                format!("the lease of {} is released", args.addr),
                Output::Lease6(Box::new(row)),
            ),
            Err(result) => result,
        }
    }

    async fn release6_row(&self, args: &Release6Args) -> Result<Lease6Row, CommandResult> {
        let now = Timestamp::now();
        let vrf = self.vrf_of6(args.vrf, args.addr)?;
        let key = (vrf, args.addr);
        let failed = |error: StoreError| CommandResult::failed(error.to_string());
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(failed)?;
        let (lease, revision) = view
            .get_typed(&tables::LEASES6, &key)
            .map_err(failed)?
            .ok_or_else(|| not_found6(args.addr))?;
        drop(view);
        if !lease.is_bound(now) {
            return Err(CommandResult::coded(
                Outcome::Rejected,
                tenko_core::dhcp::codes::LEASE_STATE,
                format!(
                    "the lease of {} is {} and holds no binding to release",
                    args.addr,
                    state_name(lease.state)
                ),
            ));
        }
        let mut row = Lease6 {
            state: BindingState::Released,
            ends: now,
            preferred_ends: now,
            node: self.node,
            ..lease.clone()
        };
        let event = Lease6Event::of(&row, LeaseEventKind::Reclaimed, now);
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Dhcp),
            now,
        );
        // The release expires the lease's IPAM facts in the same batch.
        if let Some(observed) = self
            .observations6
            .observe6(&row, Some(&lease), &mut batch)
            .map_err(failed)?
        {
            row.observed_at = Some(observed);
        }
        batch.expect_typed(&tables::LEASES6, &key, Some(revision));
        batch
            .put_typed(&tables::LEASES6, &key, &row)
            .map_err(failed)?;
        batch
            .put_typed(&tables::HISTORY6, &(now, vrf, args.addr), &event)
            .map_err(failed)?;
        match self.store.propose(batch).await {
            Ok(committed) => {
                self.leases6.apply_at(row.clone(), committed.revision);
                crate::lease::metrics::HISTORY_WRITTEN
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(self.row6_of(row, committed.revision))
            }
            Err(StoreError::PreconditionFailed(_)) => Err(CommandResult::coded(
                Outcome::Rejected,
                tenko_core::dhcp::codes::LEASE_STATE,
                format!(
                    "the lease of {} changed meanwhile; read it again",
                    args.addr
                ),
            )),
            Err(error @ (StoreError::NoQuorum | StoreError::Timeout | StoreError::Storage(_))) => {
                Err(CommandResult::coded(
                    Outcome::Failed,
                    tenko_core::dhcp::codes::STORE_REFUSED,
                    format!("the store refused the release: {error}"),
                ))
            }
            Err(error) => Err(CommandResult::failed(error.to_string())),
        }
    }

    /// The VRF of an IPv6 address: the one given, else the only VRF in which the DHCPv6
    /// table holds a lease of it.
    fn vrf_of6(&self, vrf: Option<VrfId>, addr: Ipv6Addr) -> Result<VrfId, CommandResult> {
        if let Some(vrf) = vrf {
            return Ok(vrf);
        }
        let table = self.leases6.read();
        let mut vrfs: Vec<VrfId> = table
            .iter()
            .filter(|lease| lease.addr6() == addr)
            .map(|lease| lease.vrf)
            .collect();
        vrfs.sort_unstable();
        vrfs.dedup();
        match vrfs.as_slice() {
            [] => Err(not_found6(addr)),
            [vrf] => Ok(*vrf),
            _ => Err(CommandResult::rejected(format!(
                "{addr} has leases in {} VRFs; name the VRF",
                vrfs.len()
            ))),
        }
    }
}
