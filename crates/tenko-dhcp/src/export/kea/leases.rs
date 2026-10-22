//! The leases as Kea's memfile lease file (`kea-leases4.csv`), in the columns Kea 2.6
//! writes and reads (schema 3.0):
//!
//! `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id`
//!
//! - An `active` lease is state 0 (default) with the client's hardware address (colon
//!   separated) and client identifier, `valid_lifetime` the time from `cltt` to `ends` and
//!   `expire` the end in seconds since the epoch.
//! - An `abandoned` lease (declined, or found in use by the probe) is state 1 (declined)
//!   without a client, held until its end, as Kea keeps a declined address.
//! - The other states (`free`, `expired`, `released`, `reset`, `backup`) hold no address
//!   for a client and are left out, as Kea removes reclaimed leases.
//! - `fqdn_fwd` and `fqdn_rev` are 1 when the DDNS worker wrote the A and the PTR record,
//!   and `hostname` is the name written, else the name the client sent. A comma in a
//!   value is written as `&#x2c`, as Kea escapes it.
//! - `subnet_id` is the Kea subnet of the lease's scope; a lease of a scope the export
//!   left out is reported. `user_context` is empty and `pool_id` 0.

use std::fmt::Write as _;

use tenko_core::dhcp::{BindingState, Lease};

use super::{Cx, at, codes, subnets::colon_hex};

/// The header line.
pub const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id";

fn seconds(time: tenko_core::Timestamp) -> i64 {
    i64::try_from(time.unix_nanos().div_euclid(1_000_000_000)).unwrap_or(0)
}

fn escape(text: &str) -> String {
    text.replace(',', "&#x2c")
}

fn line(lease: &Lease, subnet: u32, out: &mut String) {
    let expire = seconds(lease.ends);
    let lifetime = (expire - seconds(lease.cltt)).max(1);
    let declined = lease.state == BindingState::Abandoned;
    let (hwaddr, client_id) = if declined {
        (String::new(), String::new())
    } else {
        (
            colon_hex(&lease.client.chaddr.0),
            lease
                .client
                .client_id
                .as_ref()
                .map(|id| colon_hex(&id.0))
                .unwrap_or_default(),
        )
    };
    let forward = lease.ddns.forward.is_some();
    let reverse = lease.ddns.reverse.is_some();
    let hostname = if declined {
        String::new()
    } else {
        lease
            .ddns
            .forward
            .as_ref()
            .map(|name| format!("{name}."))
            .or_else(|| lease.fqdn.clone())
            .or_else(|| lease.hostname.clone())
            .map(|name| escape(&name))
            .unwrap_or_default()
    };
    let _ = writeln!(
        out,
        "{},{hwaddr},{client_id},{lifetime},{expire},{subnet},{},{},{hostname},{},,0",
        lease.addr,
        u8::from(forward),
        u8::from(reverse),
        u8::from(declined),
    );
}

/// The lease file of the leases in the rows.
pub(crate) fn csv(cx: &mut Cx<'_>) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    let mut left_out = Vec::new();
    for lease in cx.data.leases.values() {
        if !matches!(lease.state, BindingState::Active | BindingState::Abandoned) {
            continue;
        }
        match cx.subnet_ids.get(&lease.scope) {
            Some(subnet) => line(lease, *subnet, &mut out),
            None => left_out.push(lease.addr),
        }
    }
    if !left_out.is_empty() {
        let shown: Vec<String> = left_out.iter().take(10).map(ToString::to_string).collect();
        cx.report.push(
            at("leases", format!("{} lease(s)", left_out.len())),
            codes::LEASE_SCOPE,
            format!(
                "{} lease(s) of scopes the export left out are not in the lease file: {}{}",
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
