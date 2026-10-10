//! The tables the probe reads from a switch and their decoding into [`DeviceTables`].
//!
//! | Table | MIB | Used for |
//! |---|---|---|
//! | `system` | SNMPv2-MIB | name, description and type of the device |
//! | `ifTable`, `ifXTable` | IF-MIB | interfaces, their names and MAC addresses |
//! | `ipNetToPhysicalTable` | IP-MIB | IPv4 and IPv6 neighbours |
//! | `ipNetToMediaTable` | RFC1213-MIB | IPv4 ARP entries of older devices |
//! | `dot1dBasePortTable` | BRIDGE-MIB | bridge port to `ifIndex` |
//! | `dot1qTpFdbTable` | Q-BRIDGE-MIB | MAC addresses per VLAN and port |
//! | `dot1dTpFdbTable` | BRIDGE-MIB | MAC addresses per port without VLANs |
//! | `lldpRemTable`, `lldpLocPortTable` | LLDP-MIB | neighbours and local port names |
//!
//! The decoders take the rows of one column each and are tolerant: an entry whose index
//! or value is malformed is skipped, never an error.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tenko_core::MacAddr;

use super::{
    ArpEntry, DeviceTables, FdbEntry, Interface, LldpNeighbour, PollOptions,
    ber::{Oid, Value, VarBind},
    client::Client,
};
use crate::error::ScanError;

/// A column of a table: the arcs of the table entry and the column number.
type Column = (&'static [u32], u32);

const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];

const IF_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1];
const IF_X_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
const IP_NET_TO_PHYSICAL_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 4, 35, 1];
const IP_NET_TO_MEDIA_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 4, 22, 1];
const DOT1D_BASE_PORT_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1];
const DOT1Q_TP_FDB_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1];
const DOT1D_TP_FDB_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1];
const LLDP_REM_ENTRY: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
const LLDP_LOC_PORT_ENTRY: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 7, 1];

pub(crate) const IF_DESCR: Column = (IF_ENTRY, 2);
pub(crate) const IF_PHYS_ADDRESS: Column = (IF_ENTRY, 6);
pub(crate) const IF_NAME: Column = (IF_X_ENTRY, 1);
pub(crate) const IF_ALIAS: Column = (IF_X_ENTRY, 18);
pub(crate) const IP_NET_TO_PHYSICAL_PHYS_ADDRESS: Column = (IP_NET_TO_PHYSICAL_ENTRY, 4);
pub(crate) const IP_NET_TO_PHYSICAL_TYPE: Column = (IP_NET_TO_PHYSICAL_ENTRY, 6);
pub(crate) const IP_NET_TO_MEDIA_PHYS_ADDRESS: Column = (IP_NET_TO_MEDIA_ENTRY, 2);
pub(crate) const IP_NET_TO_MEDIA_TYPE: Column = (IP_NET_TO_MEDIA_ENTRY, 4);
pub(crate) const DOT1D_BASE_PORT_IF_INDEX: Column = (DOT1D_BASE_PORT_ENTRY, 2);
pub(crate) const DOT1Q_TP_FDB_PORT: Column = (DOT1Q_TP_FDB_ENTRY, 2);
pub(crate) const DOT1Q_TP_FDB_STATUS: Column = (DOT1Q_TP_FDB_ENTRY, 3);
pub(crate) const DOT1D_TP_FDB_PORT: Column = (DOT1D_TP_FDB_ENTRY, 2);
pub(crate) const DOT1D_TP_FDB_STATUS: Column = (DOT1D_TP_FDB_ENTRY, 3);
pub(crate) const LLDP_REM_CHASSIS_ID_SUBTYPE: Column = (LLDP_REM_ENTRY, 4);
pub(crate) const LLDP_REM_CHASSIS_ID: Column = (LLDP_REM_ENTRY, 5);
pub(crate) const LLDP_REM_PORT_ID_SUBTYPE: Column = (LLDP_REM_ENTRY, 6);
pub(crate) const LLDP_REM_PORT_ID: Column = (LLDP_REM_ENTRY, 7);
pub(crate) const LLDP_REM_PORT_DESC: Column = (LLDP_REM_ENTRY, 8);
pub(crate) const LLDP_REM_SYS_NAME: Column = (LLDP_REM_ENTRY, 9);
pub(crate) const LLDP_LOC_PORT_ID_SUBTYPE: Column = (LLDP_LOC_PORT_ENTRY, 2);
pub(crate) const LLDP_LOC_PORT_ID: Column = (LLDP_LOC_PORT_ENTRY, 3);
pub(crate) const LLDP_LOC_PORT_DESC: Column = (LLDP_LOC_PORT_ENTRY, 4);

/// `LldpChassisIdSubtype` and `LldpPortIdSubtype`: the subtype of a MAC address.
const CHASSIS_SUBTYPE_MAC: i64 = 4;
const CHASSIS_SUBTYPE_NETWORK_ADDRESS: i64 = 5;
const PORT_SUBTYPE_MAC: i64 = 3;
const PORT_SUBTYPE_NETWORK_ADDRESS: i64 = 4;

/// The arcs of a column.
pub(crate) fn column_arcs(column: Column) -> Vec<u32> {
    let mut arcs = column.0.to_vec();
    arcs.push(column.1);
    arcs
}

/// The object identifier of a column.
pub(crate) fn column_oid(column: Column) -> Oid {
    Oid(column_arcs(column))
}

/// The text of an `OCTET STRING`: lossy UTF-8, control characters removed, trimmed, cut to
/// 255 characters; `None` when nothing is left.
pub(crate) fn clean_text(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let without_controls: String = text.chars().filter(|c| !c.is_control()).collect();
    let cut: String = without_controls.trim().chars().take(255).collect();
    (!cut.is_empty()).then_some(cut)
}

fn value_text(value: &Value) -> Option<String> {
    value.as_octets().and_then(clean_text)
}

/// A MAC address from six octets that are not all zero.
fn value_mac(value: &Value) -> Option<MacAddr> {
    let octets: [u8; 6] = value.as_octets()?.try_into().ok()?;
    (octets != [0; 6]).then(|| MacAddr::new(octets))
}

/// The arcs of `row` after the column, `None` for rows of another column.
fn index_of(row: &VarBind, column: Column) -> Option<&[u32]> {
    let arcs = row.oid.arcs();
    let (entry, number) = column;
    arcs.strip_prefix(entry)?
        .split_first()
        .and_then(
            |(found, rest)| {
                if *found == number { Some(rest) } else { None }
            },
        )
}

/// The integer values of the rows of one column by index.
fn integers(rows: &[VarBind], column: Column) -> HashMap<&[u32], i64> {
    rows.iter()
        .filter_map(|row| Some((index_of(row, column)?, row.value.as_integer()?)))
        .collect()
}

/// The values of the rows of one column by index, in index order.
fn values(rows: &[VarBind], column: Column) -> BTreeMap<&[u32], &Value> {
    rows.iter()
        .filter_map(|row| Some((index_of(row, column)?, &row.value)))
        .collect()
}

fn octet(arc: u32) -> Option<u8> {
    u8::try_from(arc).ok()
}

fn octets<const N: usize>(arcs: &[u32]) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    if arcs.len() != N {
        return None;
    }
    for (slot, arc) in out.iter_mut().zip(arcs) {
        *slot = octet(*arc)?;
    }
    Some(out)
}

/// The interfaces from the rows of `ifDescr`, `ifPhysAddress`, `ifName` and `ifAlias`.
pub(crate) fn decode_interfaces(
    descr: &[VarBind],
    phys_address: &[VarBind],
    name: &[VarBind],
    alias: &[VarBind],
) -> BTreeMap<u32, Interface> {
    let mut interfaces: BTreeMap<u32, Interface> = BTreeMap::new();
    for row in descr {
        if let Some([if_index]) = index_of(row, IF_DESCR) {
            interfaces.entry(*if_index).or_default().descr = value_text(&row.value);
        }
    }
    for row in phys_address {
        if let Some([if_index]) = index_of(row, IF_PHYS_ADDRESS) {
            interfaces.entry(*if_index).or_default().mac = value_mac(&row.value);
        }
    }
    for row in name {
        if let Some([if_index]) = index_of(row, IF_NAME) {
            interfaces.entry(*if_index).or_default().name = value_text(&row.value);
        }
    }
    for row in alias {
        if let Some([if_index]) = index_of(row, IF_ALIAS) {
            interfaces.entry(*if_index).or_default().alias = value_text(&row.value);
        }
    }
    interfaces
}

/// The index of `ipNetToPhysicalTable`: `ifIndex.addressType.length.address`.
fn physical_index(index: &[u32]) -> Option<(u32, IpAddr)> {
    match index {
        [if_index, 1, 4, address @ ..] => {
            let octets: [u8; 4] = octets(address)?;
            Some((*if_index, IpAddr::V4(Ipv4Addr::from(octets))))
        }
        [if_index, 2, 16, address @ ..] => {
            let octets: [u8; 16] = octets(address)?;
            Some((*if_index, IpAddr::V6(Ipv6Addr::from(octets))))
        }
        _ => None,
    }
}

/// The index of `ipNetToMediaTable`: `ifIndex.a.b.c.d`.
fn media_index(index: &[u32]) -> Option<(u32, IpAddr)> {
    match index {
        [if_index, address @ ..] => {
            let octets: [u8; 4] = octets(address)?;
            Some((*if_index, IpAddr::V4(Ipv4Addr::from(octets))))
        }
        [] => None,
    }
}

fn invalid_indexes(rows: &[VarBind], column: Column) -> HashSet<&[u32]> {
    integers(rows, column)
        .into_iter()
        .filter(|(_, state)| *state == 2)
        .map(|(index, _)| index)
        .collect()
}

/// The ARP and neighbour entries from `ipNetToPhysicalTable` and `ipNetToMediaTable`.
///
/// Entries whose type is `invalid(2)`, whose MAC address is not six octets or is all
/// zero, and duplicates are dropped; the result is sorted.
pub(crate) fn decode_arp(
    physical: &[VarBind],
    physical_type: &[VarBind],
    media: &[VarBind],
    media_type: &[VarBind],
) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    let invalid = invalid_indexes(physical_type, IP_NET_TO_PHYSICAL_TYPE);
    for row in physical {
        let Some(index) = index_of(row, IP_NET_TO_PHYSICAL_PHYS_ADDRESS) else {
            continue;
        };
        if invalid.contains(index) {
            continue;
        }
        if let (Some((if_index, ip)), Some(mac)) = (physical_index(index), value_mac(&row.value)) {
            entries.push(ArpEntry { if_index, ip, mac });
        }
    }
    let invalid = invalid_indexes(media_type, IP_NET_TO_MEDIA_TYPE);
    for row in media {
        let Some(index) = index_of(row, IP_NET_TO_MEDIA_PHYS_ADDRESS) else {
            continue;
        };
        if invalid.contains(index) {
            continue;
        }
        if let (Some((if_index, ip)), Some(mac)) = (media_index(index), value_mac(&row.value)) {
            entries.push(ArpEntry { if_index, ip, mac });
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// The rows of the bridge tables.
pub(crate) struct FdbRows<'a> {
    /// `dot1dBasePortIfIndex`.
    pub base_port_if_index: &'a [VarBind],
    /// `dot1qTpFdbPort`.
    pub q_port: &'a [VarBind],
    /// `dot1qTpFdbStatus`.
    pub q_status: &'a [VarBind],
    /// `dot1dTpFdbPort`.
    pub d_port: &'a [VarBind],
    /// `dot1dTpFdbStatus`.
    pub d_status: &'a [VarBind],
}

/// `learned(3)` and `mgmt(5)` are kept, and rows without a status; `other`, `invalid` and
/// `self` (the addresses of the bridge itself) are not.
fn fdb_status_kept(status: Option<i64>) -> bool {
    matches!(status, None | Some(3 | 5))
}

fn mac_from_arcs(arcs: &[u32]) -> Option<MacAddr> {
    octets::<6>(arcs).map(MacAddr::new)
}

/// The forwarding database from the Q-BRIDGE table, or from the BRIDGE table when the
/// Q-BRIDGE table has no rows.
pub(crate) fn decode_fdb(rows: &FdbRows<'_>) -> Vec<FdbEntry> {
    let if_of_port: HashMap<u32, u32> = rows
        .base_port_if_index
        .iter()
        .filter_map(|row| {
            let [port] = index_of(row, DOT1D_BASE_PORT_IF_INDEX)? else {
                return None;
            };
            Some((*port, u32::try_from(row.value.as_integer()?).ok()?))
        })
        .collect();

    let mut entries = Vec::new();
    let mut add = |mac: MacAddr, vlan: Option<u16>, port_value: &Value| {
        let Some(bridge_port) = port_value
            .as_integer()
            .and_then(|port| u32::try_from(port).ok())
            .filter(|port| *port != 0)
        else {
            return;
        };
        entries.push(FdbEntry {
            mac,
            vlan,
            bridge_port,
            if_index: if_of_port.get(&bridge_port).copied(),
        });
    };

    if rows.q_port.is_empty() {
        let statuses = integers(rows.d_status, DOT1D_TP_FDB_STATUS);
        for row in rows.d_port {
            let Some(index) = index_of(row, DOT1D_TP_FDB_PORT) else {
                continue;
            };
            let Some(mac) = mac_from_arcs(index) else {
                continue;
            };
            if fdb_status_kept(statuses.get(index).copied()) {
                add(mac, None, &row.value);
            }
        }
    } else {
        let statuses = integers(rows.q_status, DOT1Q_TP_FDB_STATUS);
        for row in rows.q_port {
            let Some(index) = index_of(row, DOT1Q_TP_FDB_PORT) else {
                continue;
            };
            let [fdb_id, address @ ..] = index else {
                continue;
            };
            let Some(mac) = mac_from_arcs(address) else {
                continue;
            };
            if !fdb_status_kept(statuses.get(index).copied()) {
                continue;
            }
            let vlan = u16::try_from(*fdb_id)
                .ok()
                .filter(|vlan| (1..=4094).contains(vlan));
            add(mac, vlan, &row.value);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

fn hex_with_colons(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An `LldpChassisId` or `LldpPortId` by its subtype: MAC and network addresses in their
/// usual text form, everything else as text.
fn format_lldp_id(
    subtype: Option<i64>,
    value: &Value,
    mac_subtype: i64,
    network_address_subtype: i64,
) -> Option<String> {
    let octets = value.as_octets()?;
    if octets.is_empty() {
        return None;
    }
    if subtype == Some(mac_subtype) {
        return Some(match <[u8; 6]>::try_from(octets) {
            Ok(mac) => MacAddr::new(mac).to_string(),
            Err(_) => hex_with_colons(octets),
        });
    }
    if subtype == Some(network_address_subtype) {
        let address = match octets {
            [1, a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            [2, rest @ ..] => <[u8; 16]>::try_from(rest)
                .ok()
                .map(|bytes| IpAddr::V6(Ipv6Addr::from(bytes))),
            _ => None,
        };
        return Some(address.map_or_else(|| hex_with_colons(octets), |ip| ip.to_string()));
    }
    clean_text(octets)
}

/// The rows of the LLDP tables.
pub(crate) struct LldpRows<'a> {
    /// `lldpRemChassisIdSubtype`.
    pub chassis_id_subtype: &'a [VarBind],
    /// `lldpRemChassisId`.
    pub chassis_id: &'a [VarBind],
    /// `lldpRemPortIdSubtype`.
    pub port_id_subtype: &'a [VarBind],
    /// `lldpRemPortId`.
    pub port_id: &'a [VarBind],
    /// `lldpRemPortDesc`.
    pub port_desc: &'a [VarBind],
    /// `lldpRemSysName`.
    pub sys_name: &'a [VarBind],
    /// `lldpLocPortIdSubtype`.
    pub local_port_id_subtype: &'a [VarBind],
    /// `lldpLocPortId`.
    pub local_port_id: &'a [VarBind],
    /// `lldpLocPortDesc`.
    pub local_port_desc: &'a [VarBind],
}

/// The LLDP neighbours, in the order of the table (`timeMark.localPortNum.remIndex`).
///
/// The local port is the formatted `lldpLocPortId`; when its subtype is a MAC or network
/// address, which does not name a port to a person, `lldpLocPortDesc` is preferred.
/// Neighbours that announce nothing are dropped.
pub(crate) fn decode_lldp(rows: &LldpRows<'_>) -> Vec<LldpNeighbour> {
    let chassis_subtype = values(rows.chassis_id_subtype, LLDP_REM_CHASSIS_ID_SUBTYPE);
    let chassis_id = values(rows.chassis_id, LLDP_REM_CHASSIS_ID);
    let port_subtype = values(rows.port_id_subtype, LLDP_REM_PORT_ID_SUBTYPE);
    let port_id = values(rows.port_id, LLDP_REM_PORT_ID);
    let port_desc = values(rows.port_desc, LLDP_REM_PORT_DESC);
    let sys_name = values(rows.sys_name, LLDP_REM_SYS_NAME);
    let local_subtype = values(rows.local_port_id_subtype, LLDP_LOC_PORT_ID_SUBTYPE);
    let local_id = values(rows.local_port_id, LLDP_LOC_PORT_ID);
    let local_desc = values(rows.local_port_desc, LLDP_LOC_PORT_DESC);

    let keys: BTreeSet<&[u32]> = [
        &chassis_id,
        &chassis_subtype,
        &port_id,
        &port_subtype,
        &port_desc,
        &sys_name,
    ]
    .into_iter()
    .flat_map(|column| column.keys().copied())
    .filter(|key| key.len() == 3)
    .collect();

    let subtype_of = |column: &BTreeMap<&[u32], &Value>, key: &[u32]| {
        column.get(key).and_then(|value| value.as_integer())
    };
    let mut neighbours = Vec::new();
    for key in keys {
        let remote_chassis = chassis_id.get(key).and_then(|value| {
            format_lldp_id(
                subtype_of(&chassis_subtype, key),
                value,
                CHASSIS_SUBTYPE_MAC,
                CHASSIS_SUBTYPE_NETWORK_ADDRESS,
            )
        });
        let remote_port = port_id.get(key).and_then(|value| {
            format_lldp_id(
                subtype_of(&port_subtype, key),
                value,
                PORT_SUBTYPE_MAC,
                PORT_SUBTYPE_NETWORK_ADDRESS,
            )
        });
        let remote_port_desc = port_desc.get(key).and_then(|value| value_text(value));
        let remote_sys_name = sys_name.get(key).and_then(|value| value_text(value));
        if remote_chassis.is_none()
            && remote_port.is_none()
            && remote_port_desc.is_none()
            && remote_sys_name.is_none()
        {
            continue;
        }
        let local_key = &key[1..2];
        let subtype = subtype_of(&local_subtype, local_key);
        let by_id = local_id.get(local_key).and_then(|value| {
            format_lldp_id(
                subtype,
                value,
                PORT_SUBTYPE_MAC,
                PORT_SUBTYPE_NETWORK_ADDRESS,
            )
        });
        let by_desc = local_desc
            .get(local_key)
            .and_then(|value| value_text(value));
        let local_port = if matches!(
            subtype,
            Some(PORT_SUBTYPE_MAC | PORT_SUBTYPE_NETWORK_ADDRESS)
        ) {
            by_desc.or(by_id)
        } else {
            by_id.or(by_desc)
        };
        neighbours.push(LldpNeighbour {
            local_port,
            remote_chassis,
            remote_port,
            remote_port_desc,
            remote_sys_name,
        });
    }
    neighbours
}

/// Reads the tables of the device one column at a time. A failure of one walk is
/// recorded and the rows read before it are kept; authentication failures and
/// cancellation end the poll.
struct Collector<'c, 'a> {
    client: &'c mut Client<'a>,
    max_rows: usize,
    truncated: bool,
    failures: Vec<String>,
    failed_in_a_row: u32,
    succeeded: bool,
    stopped: bool,
}

impl Collector<'_, '_> {
    fn record(&mut self, name: &str, error: &ScanError) -> Result<(), ScanError> {
        match error.code() {
            "scan.cancelled" | "scan.snmp.auth" => return Err(error.clone()),
            "scan.snmp.timeout" | "scan.io" => {
                if !self.succeeded {
                    // Discovery worked but nothing else gets through: there is nothing to
                    // report but the error.
                    return Err(error.clone());
                }
                self.failed_in_a_row += 1;
                if self.failed_in_a_row >= 2 && !self.stopped {
                    self.stopped = true;
                    self.failures
                        .push(format!("{name}: {}: {}", error.code(), error.detail()));
                    self.failures
                        .push("remaining tables skipped: the device stopped answering".to_owned());
                    return Ok(());
                }
            }
            _ => {}
        }
        self.failures
            .push(format!("{name}: {}: {}", error.code(), error.detail()));
        Ok(())
    }

    async fn walk(&mut self, name: &str, column: Column) -> Result<Vec<VarBind>, ScanError> {
        let mut rows = Vec::new();
        if self.stopped {
            return Ok(rows);
        }
        match self
            .client
            .walk_into(&column_oid(column), self.max_rows, &mut rows)
            .await
        {
            Ok(truncated) => {
                self.failed_in_a_row = 0;
                self.succeeded = true;
                self.truncated |= truncated;
            }
            Err(error) => self.record(name, &error)?,
        }
        Ok(rows)
    }
}

fn oid_text(value: &Value) -> Option<String> {
    match value {
        Value::Oid(oid) => Some(oid.to_string()),
        _ => None,
    }
}

impl Collector<'_, '_> {
    async fn system(&mut self, tables: &mut DeviceTables) -> Result<(), ScanError> {
        let system = [SYS_DESCR, SYS_OBJECT_ID, SYS_NAME].map(Oid::new);
        match self.client.get(&system).await {
            Ok(bindings) => {
                self.failed_in_a_row = 0;
                self.succeeded = true;
                for binding in bindings {
                    match binding.oid.arcs() {
                        arcs if arcs == SYS_DESCR => tables.sys_descr = value_text(&binding.value),
                        arcs if arcs == SYS_OBJECT_ID => {
                            tables.sys_object_id = oid_text(&binding.value);
                        }
                        arcs if arcs == SYS_NAME => tables.sys_name = value_text(&binding.value),
                        _ => {}
                    }
                }
            }
            Err(error) => self.record("system", &error)?,
        }
        Ok(())
    }

    async fn interfaces(&mut self) -> Result<BTreeMap<u32, Interface>, ScanError> {
        let descr = self.walk("ifDescr", IF_DESCR).await?;
        let phys_address = self.walk("ifPhysAddress", IF_PHYS_ADDRESS).await?;
        let name = self.walk("ifName", IF_NAME).await?;
        let alias = self.walk("ifAlias", IF_ALIAS).await?;
        Ok(decode_interfaces(&descr, &phys_address, &name, &alias))
    }

    async fn arp(&mut self) -> Result<Vec<ArpEntry>, ScanError> {
        let physical = self
            .walk(
                "ipNetToPhysicalPhysAddress",
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
            )
            .await?;
        let physical_type = self
            .walk("ipNetToPhysicalType", IP_NET_TO_PHYSICAL_TYPE)
            .await?;
        let media = self
            .walk("ipNetToMediaPhysAddress", IP_NET_TO_MEDIA_PHYS_ADDRESS)
            .await?;
        let media_type = self.walk("ipNetToMediaType", IP_NET_TO_MEDIA_TYPE).await?;
        Ok(decode_arp(&physical, &physical_type, &media, &media_type))
    }

    async fn bridge(&mut self) -> Result<Vec<FdbEntry>, ScanError> {
        let base_port_if_index = self
            .walk("dot1dBasePortIfIndex", DOT1D_BASE_PORT_IF_INDEX)
            .await?;
        let q_port = self.walk("dot1qTpFdbPort", DOT1Q_TP_FDB_PORT).await?;
        let (mut q_status, mut d_port, mut d_status) = (Vec::new(), Vec::new(), Vec::new());
        if q_port.is_empty() {
            d_port = self.walk("dot1dTpFdbPort", DOT1D_TP_FDB_PORT).await?;
            d_status = self.walk("dot1dTpFdbStatus", DOT1D_TP_FDB_STATUS).await?;
        } else {
            q_status = self.walk("dot1qTpFdbStatus", DOT1Q_TP_FDB_STATUS).await?;
        }
        Ok(decode_fdb(&FdbRows {
            base_port_if_index: &base_port_if_index,
            q_port: &q_port,
            q_status: &q_status,
            d_port: &d_port,
            d_status: &d_status,
        }))
    }

    async fn lldp(&mut self) -> Result<Vec<LldpNeighbour>, ScanError> {
        let chassis_id_subtype = self
            .walk("lldpRemChassisIdSubtype", LLDP_REM_CHASSIS_ID_SUBTYPE)
            .await?;
        let chassis_id = self.walk("lldpRemChassisId", LLDP_REM_CHASSIS_ID).await?;
        let port_id_subtype = self
            .walk("lldpRemPortIdSubtype", LLDP_REM_PORT_ID_SUBTYPE)
            .await?;
        let port_id = self.walk("lldpRemPortId", LLDP_REM_PORT_ID).await?;
        let port_desc = self.walk("lldpRemPortDesc", LLDP_REM_PORT_DESC).await?;
        let sys_name = self.walk("lldpRemSysName", LLDP_REM_SYS_NAME).await?;
        let local_port_id_subtype = self
            .walk("lldpLocPortIdSubtype", LLDP_LOC_PORT_ID_SUBTYPE)
            .await?;
        let local_port_id = self.walk("lldpLocPortId", LLDP_LOC_PORT_ID).await?;
        let local_port_desc = self.walk("lldpLocPortDesc", LLDP_LOC_PORT_DESC).await?;
        Ok(decode_lldp(&LldpRows {
            chassis_id_subtype: &chassis_id_subtype,
            chassis_id: &chassis_id,
            port_id_subtype: &port_id_subtype,
            port_id: &port_id,
            port_desc: &port_desc,
            sys_name: &sys_name,
            local_port_id_subtype: &local_port_id_subtype,
            local_port_id: &local_port_id,
            local_port_desc: &local_port_desc,
        }))
    }
}

/// Polls all tables of the device behind `client`.
pub(crate) async fn read_tables(
    client: &mut Client<'_>,
    options: &PollOptions,
) -> Result<DeviceTables, ScanError> {
    let mut collector = Collector {
        client,
        max_rows: options.max_rows,
        truncated: false,
        failures: Vec::new(),
        failed_in_a_row: 0,
        succeeded: false,
        stopped: false,
    };
    let mut tables = DeviceTables::default();
    collector.system(&mut tables).await?;
    tables.interfaces = collector.interfaces().await?;
    tables.arp = collector.arp().await?;
    tables.fdb = collector.bridge().await?;
    tables.lldp = collector.lldp().await?;
    tables.truncated = collector.truncated;
    tables.failures = collector.failures;
    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(column: Column, index: &[u32], value: Value) -> VarBind {
        VarBind {
            oid: Oid(column_arcs(column)
                .into_iter()
                .chain(index.iter().copied())
                .collect()),
            value,
        }
    }

    fn octets_value(bytes: &[u8]) -> Value {
        Value::OctetString(bytes.to_vec())
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
    }

    fn mac_value(last: u8) -> Value {
        octets_value(&mac(last).octets())
    }

    #[test]
    fn text_is_cleaned() {
        assert_eq!(
            clean_text(b"  switch-a.example.net \r\n"),
            Some("switch-a.example.net".into())
        );
        assert_eq!(clean_text(b"a\x00b\x07c\x1bd"), Some("abcd".into()));
        assert_eq!(clean_text(b""), None);
        assert_eq!(clean_text(b" \t\n"), None);
        assert_eq!(
            clean_text(&[b'x'; 300]).map(|text| text.chars().count()),
            Some(255)
        );
        assert_eq!(
            clean_text("Gi\u{f6}teborg".as_bytes()),
            Some("Gi\u{f6}teborg".into())
        );
        let lossy = clean_text(&[b'o', b'k', 0xFF, 0xFE]).expect("text");
        assert!(lossy.starts_with("ok"));
        // The cut is by characters, not octets.
        let long = "\u{e5}".repeat(300);
        assert_eq!(
            clean_text(long.as_bytes()).map(|text| text.chars().count()),
            Some(255)
        );
    }

    #[test]
    fn interfaces_merge_the_columns() {
        let descr = [
            row(IF_DESCR, &[1], octets_value(b"GigabitEthernet0/1")),
            row(IF_DESCR, &[2], octets_value(b"GigabitEthernet0/2")),
            row(IF_DESCR, &[1, 2], octets_value(b"malformed index")),
        ];
        let phys = [
            row(IF_PHYS_ADDRESS, &[1], mac_value(0x11)),
            row(IF_PHYS_ADDRESS, &[2], octets_value(&[])),
            row(IF_PHYS_ADDRESS, &[3], octets_value(&[0; 6])),
            row(IF_PHYS_ADDRESS, &[4], octets_value(&[1, 2, 3])),
        ];
        let name = [row(IF_NAME, &[1], octets_value(b"Gi0/1"))];
        let alias = [
            row(IF_ALIAS, &[1], octets_value(b"uplink")),
            row(IF_ALIAS, &[2], octets_value(b"")),
        ];
        let interfaces = decode_interfaces(&descr, &phys, &name, &alias);
        assert_eq!(interfaces.len(), 4);
        assert_eq!(
            interfaces[&1],
            Interface {
                name: Some("Gi0/1".into()),
                descr: Some("GigabitEthernet0/1".into()),
                alias: Some("uplink".into()),
                mac: Some(mac(0x11)),
            }
        );
        assert_eq!(interfaces[&2].mac, None);
        assert_eq!(interfaces[&2].alias, None);
        assert_eq!(interfaces[&3].mac, None);
        assert_eq!(interfaces[&4].mac, None);
    }

    #[test]
    fn arp_entries_skip_invalid_rows_and_duplicates() {
        let v6 = |last: u32| -> Vec<u32> {
            let mut index = vec![
                1, 2, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            index.push(last);
            index
        };
        let physical = [
            row(
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
                &[1, 1, 4, 192, 0, 2, 1],
                mac_value(1),
            ),
            row(IP_NET_TO_PHYSICAL_PHYS_ADDRESS, &v6(1), mac_value(1)),
            row(IP_NET_TO_PHYSICAL_PHYS_ADDRESS, &v6(2), mac_value(2)),
            row(
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
                &[1, 1, 4, 192, 0, 2, 7],
                octets_value(&[0; 6]),
            ),
            row(
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
                &[1, 1, 4, 192, 0, 2, 8],
                octets_value(&[1, 2, 3, 4, 5]),
            ),
            // Zoned and unknown address types, and out-of-range octets, are skipped.
            row(
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
                &[1, 3, 8, 192, 0, 2, 9, 0, 0, 0, 1],
                mac_value(9),
            ),
            row(
                IP_NET_TO_PHYSICAL_PHYS_ADDRESS,
                &[1, 1, 4, 192, 0, 2, 300],
                mac_value(9),
            ),
        ];
        let physical_type = [
            row(IP_NET_TO_PHYSICAL_TYPE, &v6(2), Value::Integer(2)),
            row(IP_NET_TO_PHYSICAL_TYPE, &v6(1), Value::Integer(3)),
        ];
        let media = [
            row(
                IP_NET_TO_MEDIA_PHYS_ADDRESS,
                &[1, 192, 0, 2, 1],
                mac_value(1),
            ),
            row(
                IP_NET_TO_MEDIA_PHYS_ADDRESS,
                &[2, 192, 0, 2, 10],
                mac_value(10),
            ),
            row(
                IP_NET_TO_MEDIA_PHYS_ADDRESS,
                &[2, 192, 0, 2, 11],
                mac_value(11),
            ),
        ];
        let media_type = [row(
            IP_NET_TO_MEDIA_TYPE,
            &[2, 192, 0, 2, 11],
            Value::Integer(2),
        )];
        let entries = decode_arp(&physical, &physical_type, &media, &media_type);
        let expected = vec![
            ArpEntry {
                if_index: 1,
                ip: "192.0.2.1".parse().expect("ip"),
                mac: mac(1),
            },
            ArpEntry {
                if_index: 1,
                ip: "2001:db8::1".parse().expect("ip"),
                mac: mac(1),
            },
            ArpEntry {
                if_index: 2,
                ip: "192.0.2.10".parse().expect("ip"),
                mac: mac(10),
            },
        ];
        assert_eq!(entries, expected);
    }

    fn fdb_rows<'a>(
        base: &'a [VarBind],
        q_port: &'a [VarBind],
        q_status: &'a [VarBind],
        d_port: &'a [VarBind],
        d_status: &'a [VarBind],
    ) -> FdbRows<'a> {
        FdbRows {
            base_port_if_index: base,
            q_port,
            q_status,
            d_port,
            d_status,
        }
    }

    #[test]
    fn q_bridge_entries_are_filtered_by_status_and_port() {
        let base = [
            row(DOT1D_BASE_PORT_IF_INDEX, &[1], Value::Integer(101)),
            row(DOT1D_BASE_PORT_IF_INDEX, &[2], Value::Integer(102)),
        ];
        let index = |fdb: u32, last: u32| vec![fdb, 0, 0, 0x5e, 0, 0x53, last];
        let q_port = [
            row(DOT1Q_TP_FDB_PORT, &index(10, 1), Value::Integer(1)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 2), Value::Integer(2)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 3), Value::Integer(5)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 4), Value::Integer(1)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 5), Value::Integer(1)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 6), Value::Integer(0)),
            row(DOT1Q_TP_FDB_PORT, &index(0, 7), Value::Integer(2)),
            row(DOT1Q_TP_FDB_PORT, &index(5000, 8), Value::Integer(2)),
            row(DOT1Q_TP_FDB_PORT, &index(20, 9), Value::Integer(-3)),
            row(DOT1Q_TP_FDB_PORT, &[20, 0, 0, 0x5e], Value::Integer(1)),
        ];
        let status = |fdb: u32, last: u32, value: i64| {
            row(
                DOT1Q_TP_FDB_STATUS,
                &index(fdb, last),
                Value::Integer(value),
            )
        };
        let q_status = [
            status(10, 1, 3),
            status(20, 2, 3),
            status(20, 3, 5),
            status(20, 4, 4),
            status(20, 5, 2),
            status(20, 6, 3),
            status(0, 7, 3),
            // No status row for 5000/8 and 20/9: kept (9 has a negative port and is dropped).
        ];
        let entries = decode_fdb(&fdb_rows(&base, &q_port, &q_status, &[], &[]));
        let expected = vec![
            FdbEntry {
                mac: mac(1),
                vlan: Some(10),
                bridge_port: 1,
                if_index: Some(101),
            },
            FdbEntry {
                mac: mac(2),
                vlan: Some(20),
                bridge_port: 2,
                if_index: Some(102),
            },
            FdbEntry {
                mac: mac(3),
                vlan: Some(20),
                bridge_port: 5,
                if_index: None,
            },
            FdbEntry {
                mac: mac(7),
                vlan: None,
                bridge_port: 2,
                if_index: Some(102),
            },
            FdbEntry {
                mac: mac(8),
                vlan: None,
                bridge_port: 2,
                if_index: Some(102),
            },
        ];
        assert_eq!(entries, expected);
    }

    #[test]
    fn the_bridge_mib_is_used_when_the_q_bridge_table_is_empty() {
        let base = [row(DOT1D_BASE_PORT_IF_INDEX, &[3], Value::Integer(7))];
        let index = |last: u32| vec![0, 0, 0x5e, 0, 0x53, last];
        let d_port = [
            row(DOT1D_TP_FDB_PORT, &index(1), Value::Integer(3)),
            row(DOT1D_TP_FDB_PORT, &index(2), Value::Integer(3)),
            row(DOT1D_TP_FDB_PORT, &index(3), Value::Integer(4)),
        ];
        let d_status = [
            row(DOT1D_TP_FDB_STATUS, &index(1), Value::Integer(3)),
            row(DOT1D_TP_FDB_STATUS, &index(2), Value::Integer(4)),
            row(DOT1D_TP_FDB_STATUS, &index(3), Value::Integer(5)),
        ];
        let entries = decode_fdb(&fdb_rows(&base, &[], &[], &d_port, &d_status));
        assert_eq!(
            entries,
            vec![
                FdbEntry {
                    mac: mac(1),
                    vlan: None,
                    bridge_port: 3,
                    if_index: Some(7)
                },
                FdbEntry {
                    mac: mac(3),
                    vlan: None,
                    bridge_port: 4,
                    if_index: None
                },
            ]
        );
        // With Q-BRIDGE rows present the BRIDGE rows are not read.
        let q_port = [row(
            DOT1Q_TP_FDB_PORT,
            &[1, 0, 0, 0x5e, 0, 0x53, 9],
            Value::Integer(3),
        )];
        let entries = decode_fdb(&fdb_rows(&base, &q_port, &[], &d_port, &d_status));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mac, mac(9));
    }

    fn lldp_rows(rows: &[Vec<VarBind>; 9]) -> LldpRows<'_> {
        LldpRows {
            chassis_id_subtype: &rows[0],
            chassis_id: &rows[1],
            port_id_subtype: &rows[2],
            port_id: &rows[3],
            port_desc: &rows[4],
            sys_name: &rows[5],
            local_port_id_subtype: &rows[6],
            local_port_id: &rows[7],
            local_port_desc: &rows[8],
        }
    }

    #[test]
    fn lldp_ids_are_formatted_by_subtype() {
        let key = [3u32, 1, 1];
        let key2 = [3u32, 2, 1];
        let key3 = [3u32, 3, 1];
        let rows = [
            vec![
                row(LLDP_REM_CHASSIS_ID_SUBTYPE, &key, Value::Integer(4)),
                row(LLDP_REM_CHASSIS_ID_SUBTYPE, &key2, Value::Integer(5)),
                row(LLDP_REM_CHASSIS_ID_SUBTYPE, &key3, Value::Integer(5)),
            ],
            vec![
                row(LLDP_REM_CHASSIS_ID, &key, mac_value(0xa0)),
                row(LLDP_REM_CHASSIS_ID, &key2, octets_value(&[1, 192, 0, 2, 5])),
                row(
                    LLDP_REM_CHASSIS_ID,
                    &key3,
                    octets_value(&[
                        2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
                    ]),
                ),
            ],
            vec![
                row(LLDP_REM_PORT_ID_SUBTYPE, &key, Value::Integer(3)),
                row(LLDP_REM_PORT_ID_SUBTYPE, &key2, Value::Integer(5)),
                row(LLDP_REM_PORT_ID_SUBTYPE, &key3, Value::Integer(7)),
            ],
            vec![
                row(LLDP_REM_PORT_ID, &key, mac_value(0xa1)),
                row(LLDP_REM_PORT_ID, &key2, octets_value(b"Te1/0/48\x00")),
                row(LLDP_REM_PORT_ID, &key3, octets_value(b"")),
            ],
            vec![row(
                LLDP_REM_PORT_DESC,
                &key3,
                octets_value(b" port three "),
            )],
            vec![row(
                LLDP_REM_SYS_NAME,
                &key,
                octets_value(b"ap-b.example.net"),
            )],
            vec![],
            vec![],
            vec![],
        ];
        let neighbours = decode_lldp(&lldp_rows(&rows));
        assert_eq!(
            neighbours,
            vec![
                LldpNeighbour {
                    local_port: None,
                    remote_chassis: Some("00:00:5e:00:53:a0".into()),
                    remote_port: Some("00:00:5e:00:53:a1".into()),
                    remote_port_desc: None,
                    remote_sys_name: Some("ap-b.example.net".into()),
                },
                LldpNeighbour {
                    local_port: None,
                    remote_chassis: Some("192.0.2.5".into()),
                    remote_port: Some("Te1/0/48".into()),
                    remote_port_desc: None,
                    remote_sys_name: None,
                },
                LldpNeighbour {
                    local_port: None,
                    remote_chassis: Some("2001:db8::5".into()),
                    remote_port: None,
                    remote_port_desc: Some("port three".into()),
                    remote_sys_name: None,
                },
            ]
        );
    }

    #[test]
    fn lldp_local_ports_prefer_a_name_over_an_address() {
        let remote = |local: u32| [5u32, local, 1];
        let mut rows: [Vec<VarBind>; 9] = Default::default();
        for local in 1..=4 {
            rows[5].push(row(
                LLDP_REM_SYS_NAME,
                &remote(local),
                octets_value(format!("peer{local}.example.net").as_bytes()),
            ));
        }
        // Port 1: interface name; port 2: MAC with a description; port 3: MAC without one;
        // port 4: no local port row at all.
        rows[6].push(row(LLDP_LOC_PORT_ID_SUBTYPE, &[1], Value::Integer(5)));
        rows[6].push(row(LLDP_LOC_PORT_ID_SUBTYPE, &[2], Value::Integer(3)));
        rows[6].push(row(LLDP_LOC_PORT_ID_SUBTYPE, &[3], Value::Integer(3)));
        rows[7].push(row(LLDP_LOC_PORT_ID, &[1], octets_value(b"Gi0/1")));
        rows[7].push(row(LLDP_LOC_PORT_ID, &[2], mac_value(0x12)));
        rows[7].push(row(LLDP_LOC_PORT_ID, &[3], mac_value(0x13)));
        rows[8].push(row(
            LLDP_LOC_PORT_DESC,
            &[1],
            octets_value(b"GigabitEthernet0/1"),
        ));
        rows[8].push(row(LLDP_LOC_PORT_DESC, &[2], octets_value(b"Port 2")));
        let neighbours = decode_lldp(&lldp_rows(&rows));
        let ports: Vec<_> = neighbours.iter().map(|n| n.local_port.clone()).collect();
        assert_eq!(
            ports,
            vec![
                Some("Gi0/1".to_owned()),
                Some("Port 2".to_owned()),
                Some("00:00:5e:00:53:13".to_owned()),
                None,
            ]
        );
    }

    #[test]
    fn empty_neighbours_and_wrong_index_lengths_are_dropped() {
        let mut rows: [Vec<VarBind>; 9] = Default::default();
        rows[1].push(row(LLDP_REM_CHASSIS_ID, &[1, 1, 1], octets_value(b"")));
        rows[5].push(row(
            LLDP_REM_SYS_NAME,
            &[1, 1],
            octets_value(b"short index"),
        ));
        rows[5].push(row(
            LLDP_REM_SYS_NAME,
            &[1, 1, 1, 1],
            octets_value(b"long index"),
        ));
        assert_eq!(decode_lldp(&lldp_rows(&rows)), Vec::new());
    }
}
