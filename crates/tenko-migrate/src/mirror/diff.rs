//! The diff of a mirrored scope against Tenko's scope of the same network (plan section
//! 2.5): the IPAM prefix, the pools, the exclusions, the lease time, the options at the
//! server, scope and reservation level, the reservations and the DDNS settings, each row
//! saying what the prepare would do. Only differences are rows: two scopes that agree give
//! none.
//!
//! Option data is compared in text form, the form the IR carries: Tenko's value is decoded
//! with its definition and written as the mirror writes it (addresses, numbers, names
//! without the final dot), both sides in lowercase. A reservation is found in Tenko by its
//! address and by its identity (the MAC address through IPAM's index, the client identifier
//! among the scope's hosts); a host at the address with another identity while the identity
//! is on another host is a row the operator decides.

use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpNet;
use tenko_core::{
    HostId, PrefixId,
    dhcp::{OptionData, OptionDef, OptionOwner, OptionValue, SERVER_MANAGED_V4, tables::SCOPES},
    ipam::{AssignmentMode, Host, Interface, RangeRole},
    ir::dhcp::{IrOption, IrReservation, IrScope},
    migrate::Snapshot,
};
use tenko_dhcp::config::{load, options::describe};
use tenko_ipam::tables::{INTERFACE_MACS, INTERFACES, PREFIX_CIDRS, PREFIXES};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{DiffAction, DiffKind, DiffRow, MirrorError, ScopeDiff};

fn row(kind: DiffKind, item: impl Into<String>, action: DiffAction) -> DiffRow {
    DiffRow {
        kind,
        item: item.into(),
        mirror: None,
        tenko: None,
        action,
        reason: None,
    }
}

impl DiffRow {
    fn values(mut self, mirror: Option<String>, tenko: Option<String>) -> Self {
        self.mirror = mirror;
        self.tenko = tenko;
        self
    }

    fn because(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }
}

/// The prefix of the network: the one with a DHCP scope, else any IPAM prefix of it.
fn prefix_of(view: &dyn ReadView, cidr: IpNet) -> Result<Option<(PrefixId, bool)>, MirrorError> {
    for (prefix, _, _) in view.scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)? {
        if view
            .get_typed(&PREFIXES, &prefix)?
            .is_some_and(|(row, _)| row.cidr == cidr && !row.meta.is_deleted())
        {
            return Ok(Some((prefix, true)));
        }
    }
    Ok(view
        .scan_typed(&PREFIX_CIDRS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .find(|((_, net), _, _)| *net == cidr)
        .map(|(_, prefix, _)| (prefix, false)))
}

/// The text form of an option value as the IR writes it.
fn texts(value: &OptionValue, defs: &[OptionDef]) -> Vec<String> {
    let Some(data) = describe(value, defs).1 else {
        return vec![tenko_core::serde_util::to_hex(&value.data.0)];
    };
    let all = |items: &mut dyn Iterator<Item = String>| items.collect::<Vec<_>>();
    match data {
        OptionData::Ipv4 { values } => all(&mut values.iter().map(ToString::to_string)),
        OptionData::Ipv6 { values } => all(&mut values.iter().map(ToString::to_string)),
        OptionData::Ipv6Prefix { values } => all(&mut values.iter().map(ToString::to_string)),
        OptionData::Unsigned(values) => all(&mut values.iter().map(ToString::to_string)),
        OptionData::Signed(value) => vec![value.to_string()],
        OptionData::Bool(values) => all(&mut values.iter().map(|on| u8::from(*on).to_string())),
        OptionData::Text(text) => vec![text],
        OptionData::Names(names) => all(&mut names.iter().map(ToString::to_string)),
        OptionData::Routes(routes) => all(&mut routes
            .iter()
            .map(|route| format!("{} {}", route.destination, route.router))),
        OptionData::Binary(bytes) => vec![tenko_core::serde_util::to_hex(&bytes.0)],
        OptionData::Empty => Vec::new(),
    }
}

/// Values compared as the operator reads them: trimmed, lowercase, no final dot.
fn normalized(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().trim_end_matches('.').to_lowercase())
        .collect()
}

/// The key of an IR option within its level; a class-qualified option keeps its class.
fn option_key(option: &IrOption) -> String {
    match (&option.vendor_class, &option.user_class) {
        (Some(class), _) => format!("{}@vendor {class}", option.code),
        (_, Some(class)) => format!("{}@user {class}", option.code),
        _ => option.code.to_string(),
    }
}

/// The rows of one option level. `server` follows the rule of section 2.5: a server option
/// is created only where Tenko's server set has none of that code, a different value is
/// the operator's decision, and Tenko's own server options stay.
fn options(
    rows: &mut Vec<DiffRow>,
    level: &str,
    mirror: &[IrOption],
    tenko: Option<&[OptionValue]>,
    defs: &[OptionDef],
    server: bool,
) {
    let tenko: BTreeMap<String, Vec<String>> = tenko
        .unwrap_or_default()
        .iter()
        .filter(|value| value.space.is_dhcp4())
        .map(|value| (value.code.to_string(), texts(value, defs)))
        .collect();
    let mut seen = BTreeSet::new();
    for option in mirror {
        if u8::try_from(option.code).is_ok_and(|code| SERVER_MANAGED_V4.contains(&code)) {
            continue;
        }
        let key = option_key(option);
        let ours = tenko.get(&key);
        seen.insert(key.clone());
        let action = match ours {
            None => DiffAction::Create,
            Some(ours) if normalized(ours) == normalized(&option.values) => continue,
            Some(_) if server => DiffAction::Decide,
            Some(_) => DiffAction::Update,
        };
        let mut found = row(DiffKind::Option, format!("{level}:{key}"), action).values(
            Some(option.values.join(", ")),
            ours.map(|ours| ours.join(", ")),
        );
        if action == DiffAction::Decide {
            found = found.because("Tenko's server options already set this code");
        }
        rows.push(found);
    }
    if !server {
        for (key, ours) in tenko.iter().filter(|(key, _)| !seen.contains(*key)) {
            rows.push(
                row(
                    DiffKind::Option,
                    format!("{level}:{key}"),
                    DiffAction::Remove,
                )
                .values(None, Some(ours.join(", "))),
            );
        }
    }
}

fn identity(reservation: &IrReservation) -> String {
    match (&reservation.client.client_id, &reservation.client.mac) {
        (Some(id), _) => format!("client-id {}", tenko_core::serde_util::to_hex(&id.0)),
        (None, Some(mac)) => format!("mac {mac}"),
        (None, None) => String::new(),
    }
}

fn holds(interface: &Interface, reservation: &IrReservation) -> bool {
    match (&reservation.client.client_id, &reservation.client.mac) {
        (Some(id), _) => interface.client_id.as_ref() == Some(id),
        (None, Some(mac)) => interface.mac.as_ref() == Some(mac),
        (None, None) => false,
    }
}

/// The diff of `scope` of `snapshot` against Tenko's scope of the same network;
/// `losses_open` comes from the caller, who holds the acknowledgments.
///
/// # Errors
///
/// [`MirrorError::ScopeNotFound`], a store error.
#[allow(
    clippy::too_many_lines,
    reason = "one block per kind of row, read top to bottom"
)]
pub fn diff(
    view: &dyn ReadView,
    snapshot: &Snapshot,
    scope: IpNet,
    losses_open: u32,
) -> Result<ScopeDiff, MirrorError> {
    let ir: &IrScope = snapshot
        .envelope
        .scope(&scope)
        .ok_or(MirrorError::ScopeNotFound(snapshot.mirror, scope))?;
    let found = prefix_of(view, scope)?;
    let data = match found {
        Some((prefix, true)) => load::scope_data(view, prefix)?,
        _ => tenko_dhcp::feed::DhcpData::at(view.revision()),
    };
    let tenko_scope = found.and_then(|(prefix, _)| data.scopes.get(&prefix));
    let defs: Vec<OptionDef> = data.option_defs.values().cloned().collect();
    let set = |owner: OptionOwner| {
        data.option_sets
            .get(&owner)
            .map(|set| set.values.as_slice())
    };
    let mut rows = Vec::new();
    if found.is_none() {
        rows.push(row(DiffKind::Prefix, scope.to_string(), DiffAction::Create));
    }

    let range = |first: &dyn ToString, last: &dyn ToString| {
        format!("{}-{}", first.to_string(), last.to_string())
    };
    let pools: BTreeSet<String> = data
        .ranges
        .values()
        .filter(|range| range.role == RangeRole::DhcpPool)
        .map(|pool| range(&pool.first, &pool.last))
        .collect();
    let exclusions: BTreeSet<String> = data
        .exclusions
        .values()
        .map(|exclusion| range(&exclusion.first, &exclusion.last))
        .collect();
    for (kind, mirror, tenko) in [
        (
            DiffKind::Pool,
            ir.ranges
                .iter()
                .map(|r| range(&r.first, &r.last))
                .collect::<BTreeSet<_>>(),
            pools,
        ),
        (
            DiffKind::Exclusion,
            ir.exclusions
                .iter()
                .map(|r| range(&r.first, &r.last))
                .collect(),
            exclusions,
        ),
    ] {
        rows.extend(mirror.difference(&tenko).map(|item| {
            row(kind, item.clone(), DiffAction::Create).values(Some(item.clone()), None)
        }));
        rows.extend(tenko.difference(&mirror).map(|item| {
            row(kind, item.clone(), DiffAction::Remove).values(None, Some(item.clone()))
        }));
    }

    let tenko_lease = tenko_scope
        .and_then(|scope| scope.lease)
        .map(|lease| lease.default_secs);
    if let Some(secs) = ir.lease_secs
        && tenko_lease != Some(secs)
    {
        let action = if tenko_scope.is_some() {
            DiffAction::Update
        } else {
            DiffAction::Create
        };
        rows.push(row(DiffKind::LeaseTime, "lease_secs", action).values(
            Some(secs.to_string()),
            tenko_lease.map(|secs| secs.to_string()),
        ));
    }

    options(
        &mut rows,
        "server",
        &snapshot.envelope.dhcp.server_options,
        set(OptionOwner::Server),
        &defs,
        true,
    );
    let prefix = found.map(|(prefix, _)| prefix);
    options(
        &mut rows,
        "scope",
        &ir.options,
        prefix.and_then(|prefix| set(OptionOwner::Scope(prefix))),
        &defs,
        false,
    );

    // Reservations: Tenko's at each address, and the hosts that hold each identity.
    let by_ip: BTreeMap<std::net::IpAddr, (&Host, &Interface)> = data
        .addresses
        .values()
        .filter_map(|address| {
            let interface = data.interfaces.get(&address.interface?)?;
            let host = data.hosts.get(&interface.host)?;
            Some((address.ip, (host, interface)))
        })
        .collect();
    let mut mirrored = BTreeSet::new();
    for reservation in &ir.reservations {
        mirrored.insert(reservation.ip);
        let item = reservation.ip.to_string();
        let identity_host = holder(view, &data, reservation)?;
        let at_ip = by_ip.get(&reservation.ip);
        let mine = Some(identity(reservation));
        let theirs = at_ip.map(|(host, interface)| {
            format!(
                "host {} ({})",
                host.name,
                interface
                    .mac
                    .map_or_else(String::new, |mac| format!("mac {mac}"))
            )
        });
        let (action, interface) = match (at_ip, identity_host) {
            (None, None) => (Some(DiffAction::Create), None),
            (Some((host, interface)), _) if holds(interface, reservation) => (
                (host.mode != AssignmentMode::Reserved).then_some(DiffAction::Update),
                Some(*interface),
            ),
            (Some((host, _)), Some(other)) if other != host.id => {
                rows.push(
                    row(DiffKind::Reservation, item.clone(), DiffAction::Decide)
                        .values(mine, theirs)
                        .because("the address and the client's identity are on two hosts"),
                );
                continue;
            }
            (at_ip, _) => (
                Some(DiffAction::Attach),
                at_ip.map(|(_, interface)| *interface),
            ),
        };
        if let Some(action) = action {
            rows.push(row(DiffKind::Reservation, item.clone(), action).values(mine, theirs));
        }
        options(
            &mut rows,
            &item,
            &reservation.options,
            interface.and_then(|interface| set(OptionOwner::Host(interface.id))),
            &defs,
            false,
        );
    }
    for (ip, (host, _)) in &by_ip {
        if host.mode == AssignmentMode::Reserved && !mirrored.contains(ip) {
            rows.push(
                row(DiffKind::Reservation, ip.to_string(), DiffAction::Remove)
                    .values(None, Some(format!("host {}", host.name))),
            );
        }
    }

    if let Some(mirror) = ir
        .ddns
        .as_ref()
        .or(snapshot.envelope.dhcp.server_ddns.as_ref())
    {
        let tenko = tenko_scope.map(|scope| &scope.ddns);
        // The forward zone and the TTL are Tenko's own settings; the mirror carries neither.
        let mut compared = mirror.clone();
        if let Some(tenko) = tenko {
            compared.forward_zone = tenko.forward_zone;
            compared.ttl = tenko.ttl;
        }
        if tenko != Some(&compared) {
            let text = |policy: &tenko_core::dhcp::DdnsPolicy| {
                serde_json::to_string(policy).unwrap_or_default()
            };
            let action = if tenko.is_some() {
                DiffAction::Update
            } else {
                DiffAction::Create
            };
            rows.push(
                row(DiffKind::Ddns, "ddns", action).values(Some(text(mirror)), tenko.map(text)),
            );
        }
    }

    rows.sort_by(|a, b| (a.kind, &a.item).cmp(&(b.kind, &b.item)));
    Ok(ScopeDiff {
        mirror: snapshot.mirror,
        scope,
        sequence: snapshot.sequence,
        source_active: ir.active,
        tenko_scope: tenko_scope.map(|scope| scope.prefix),
        tenko_enabled: tenko_scope.is_some_and(|scope| scope.enabled),
        rows,
        losses_open,
    })
}

/// The host whose interface holds the reservation's identity: by MAC address through IPAM's
/// index, by client identifier among the hosts of the scope.
fn holder(
    view: &dyn ReadView,
    data: &tenko_dhcp::feed::DhcpData,
    reservation: &IrReservation,
) -> Result<Option<HostId>, MirrorError> {
    if let Some(id) = &reservation.client.client_id {
        return Ok(data
            .interfaces
            .values()
            .find(|interface| interface.client_id.as_ref() == Some(id))
            .map(|interface| interface.host));
    }
    let Some(mac) = reservation.client.mac else {
        return Ok(None);
    };
    for ((_, interface), (), _) in view.scan_typed(
        &INTERFACE_MACS,
        KeyRange::prefix(tenko_core::codec::encode_key(&(mac,))),
        usize::MAX,
        false,
    )? {
        if let Some((interface, _)) = view.get_typed(&INTERFACES, &interface)?
            && !interface.meta.is_deleted()
        {
            return Ok(Some(interface.host));
        }
    }
    Ok(None)
}
