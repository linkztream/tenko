//! The DHCPv6 leases as Kea's memfile lease file (`kea-leases6.csv`), in the columns Kea
//! 2.6 writes and reads (schema 5.0):
//!
//! `address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id`
//!
//! - An `active` address lease (`IA_NA`, lease type 0, prefix length 128) is state 0
//!   (default) with the client's DUID and IAID, `valid_lifetime` the time from `cltt` to
//!   `ends`, `pref_lifetime` the time from `cltt` to `preferred_ends`, `expire` the end in
//!   seconds since the epoch.
//! - The link-layer address the engine learned (RFC 6939, else the DUID) is `hwaddr` with
//!   its hardware type, and `hwaddr_source` Kea's bit for where it came from: 2 for the
//!   DUID, 8 for the relay's option.
//! - An `abandoned` lease (declined) is state 1 with the empty DUID `00:00:00` and no client,
//!   held until its end, as Kea keeps a declined address (Kea's empty DUID is three zero
//!   octets).
//! - An `active` delegated prefix (`IA_PD`, WP9.4) is lease type 2 with the prefix's first
//!   address and its delegated length, the client's DUID, IAID and link-layer address as
//!   for an address, and no names (the DDNS worker leaves prefixes alone).
//! - The other states hold no address for a client and are left out, as Kea removes
//!   reclaimed leases.
//! - `fqdn_fwd` and `fqdn_rev` are 1 when the DDNS worker wrote the AAAA and the PTR
//!   record, and `hostname` is the name written, else the name of the client's option 39.
//! - `subnet_id` is the Kea subnet of the lease's scope; a lease of a scope the export
//!   left out is reported. `user_context` is empty and `pool_id` 0.

use std::fmt::Write as _;

use tenko_core::dhcp::{BindingState, Lease6, Lease6Kind};

use crate::export::kea::{
    Cx, at, codes,
    leases::{escape, seconds},
    subnets::colon_hex,
};

/// The header line.
pub const HEADER: &str = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id";

/// Kea's `HWADDR_SOURCE_DUID`.
const SOURCE_DUID: u32 = 2;
/// Kea's `HWADDR_SOURCE_CLIENT_ADDR_RELAY_OPTION`.
const SOURCE_RELAY_OPTION: u32 = 8;

/// The link-layer address inside a DUID-LLT or DUID-LL.
fn duid_link_layer(duid: &[u8]) -> Option<&[u8]> {
    match duid.get(..2)? {
        [0, 1] => duid.get(8..),
        [0, 3] => duid.get(4..),
        _ => None,
    }
}

/// Kea's lease type of an address (`IA_NA`).
const TYPE_NA: u8 = 0;
/// Kea's lease type of a delegated prefix (`IA_PD`).
const TYPE_PD: u8 = 2;

fn line(lease: &Lease6, subnet: u32, out: &mut String) {
    let (lease_type, prefix_len) = match lease.kind {
        Lease6Kind::Na => (TYPE_NA, 128),
        Lease6Kind::Pd => (TYPE_PD, lease.prefix_len),
    };
    let cltt = seconds(lease.cltt);
    let expire = seconds(lease.ends);
    let valid = (expire - cltt).max(1);
    let preferred = (seconds(lease.preferred_ends) - cltt).clamp(0, valid);
    let declined = lease.state == BindingState::Abandoned;
    let duid = lease.duid.as_bytes();
    let (duid_text, iaid, hwaddr, hwtype, source) = if declined {
        ("00:00:00".to_owned(), 0, String::new(), 0, 0)
    } else {
        let (hwaddr, hwtype, source) = match &lease.link_layer {
            Some(address) if !address.0.is_empty() => (
                colon_hex(&address.0),
                lease.link_layer_type.unwrap_or(1),
                if duid_link_layer(duid) == Some(address.0.as_slice()) {
                    SOURCE_DUID
                } else {
                    SOURCE_RELAY_OPTION
                },
            ),
            _ => (String::new(), 0, 0),
        };
        (colon_hex(duid), lease.iaid, hwaddr, hwtype, source)
    };
    // A delegated prefix has no name: the DDNS worker leaves prefixes alone.
    let hostname = if declined || lease.kind == Lease6Kind::Pd {
        String::new()
    } else {
        lease
            .ddns
            .forward
            .as_ref()
            .map(|name| format!("{name}."))
            .or_else(|| lease.fqdn.clone())
            .map(|name| escape(&name))
            .unwrap_or_default()
    };
    let _ = writeln!(
        out,
        "{},{duid_text},{valid},{expire},{subnet},{preferred},{lease_type},{iaid},{prefix_len},{},{},{hostname},{hwaddr},{},,{hwtype},{source},0",
        lease.addr6(),
        u8::from(lease.ddns.forward.is_some() && !declined),
        u8::from(lease.ddns.reverse.is_some() && !declined),
        u8::from(declined),
    );
}

/// The lease file of the DHCPv6 leases in the rows.
pub(crate) fn csv(cx: &mut Cx<'_>) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    let mut left_out = Vec::new();
    for lease in cx.data.leases6.values() {
        let kept = match lease.kind {
            Lease6Kind::Na => {
                matches!(lease.state, BindingState::Active | BindingState::Abandoned)
            }
            Lease6Kind::Pd => lease.state == BindingState::Active,
        };
        if !kept {
            continue;
        }
        match cx.subnet_ids6.get(&lease.scope) {
            Some(subnet) => line(lease, *subnet, &mut out),
            None => left_out.push(lease.addr6()),
        }
    }
    if !left_out.is_empty() {
        let shown: Vec<String> = left_out.iter().take(10).map(ToString::to_string).collect();
        cx.report.push(
            at("DHCPv6 leases", format!("{} lease(s)", left_out.len())),
            codes::LEASE_SCOPE,
            format!(
                "{} DHCPv6 lease(s) of scopes the export left out are not in the lease file: {}{}",
                left_out.len(),
                shown.join(", "),
                if left_out.len() > shown.len() {
                    ", ..."
                } else {
                    ""
                }
            ),
        );
    }
    out
}
