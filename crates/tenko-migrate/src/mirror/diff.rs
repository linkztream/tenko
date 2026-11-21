//! The diff of a mirrored scope against Tenko's scope of the same network (plan section
//! 2.5): the IPAM prefix, the pools, the exclusions, the lease time, the options at the
//! server, scope and reservation level, the reservations and the DDNS settings, each row
//! saying what the prepare would do. Only differences are rows: two scopes that agree give
//! none, and a row never promises what the prepare cannot do.
//!
//! - The network is looked up in the default VRF, where the prepare creates it.
//! - Option data is compared in text form, the form the IR carries: Tenko's value is decoded
//!   with its definition and written as the mirror writes it. Domain names compare without
//!   case and without the final dot; every other value compares as written (a boot file name
//!   keeps its case). A code Tenko has no definition for cannot be compared and is the
//!   operator's decision. An option the source sets for a vendor or user class is the
//!   operator's decision too: Tenko's option sets carry no class (it sets such options
//!   through a class and a policy), and it never takes part in the matching of the plain code.
//! - A reservation is found in Tenko by its address and by its identity (the MAC address and
//!   the client identifier, wherever IPAM holds them). The identity on a host at another
//!   address is attached; an address on a host with another identity, and the address and
//!   the identity on two hosts, are the operator's decision.
//! - The lease time compares with Tenko's effective one: the scope's, else the server's.
//! - The MAC filters: the scope's restriction to the allow list and the source's entries
//!   against Tenko's server-wide filters, so that a takeover is never silently less
//!   restrictive than the source.
//! - For a paired mirror (plan section 2.15), rows of kind `partner` name every
//!   configuration difference of the scope between the two mirrors' latest snapshots; the
//!   operator decides each. Differences are normal: Windows copies a scope's settings to
//!   its partner only when its replication is run.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ipnet::IpNet;
use tenko_core::{
    InterfaceId, MirrorId, PrefixId,
    dhcp::{
        DhcpSettings, Filter, FilterKind, MacPattern, OptionData, OptionDef, OptionOwner,
        OptionValue, SERVER_MANAGED_V4,
        tables::{FILTERS, OPTION_SETS, SCOPES},
    },
    ipam::{AssignmentMode, Host, Interface, RangeRole},
    ir::dhcp::{IrOption, IrReservation, IrScope},
    migrate::Snapshot,
    serde_util::{HexBytes, to_hex},
};
use tenko_dhcp::config::{load, options::describe};
use tenko_ipam::tables::{INTERFACE_MACS, INTERFACES, PREFIX_CIDRS, TENANT_NAMES, VRF_NAMES};
use tenko_store::{KeyRange, ReadView, ReadViewExt};

use super::{DiffAction, DiffKind, DiffRow, MirrorError, ScopeDiff};

fn row(kind: DiffKind, item: impl Into<String>, action: DiffAction) -> DiffRow {
    DiffRow {
        kind,
        item: item.into(),
        mirror: None,
        tenko: None,
        partner: None,
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

/// The prefix of the network in the default VRF, and whether it has a DHCP scope.
fn prefix_of(view: &dyn ReadView, cidr: IpNet) -> Result<Option<(PrefixId, bool)>, MirrorError> {
    let default = "default".to_owned();
    let Some((tenant, _)) = view.get_typed(&TENANT_NAMES, &default)? else {
        return Ok(None);
    };
    let Some((vrf, _)) = view.get_typed(&VRF_NAMES, &(tenant, default))? else {
        return Ok(None);
    };
    let Some((prefix, _)) = view.get_typed(&PREFIX_CIDRS, &(vrf, cidr))? else {
        return Ok(None);
    };
    Ok(Some((prefix, view.get_typed(&SCOPES, &prefix)?.is_some())))
}

/// Tenko's text of an option value as the IR writes it, and whether it holds domain names;
/// none when Tenko has no definition to decode it with.
fn texts(value: &OptionValue, defs: &[OptionDef]) -> Option<(Vec<String>, bool)> {
    let data = describe(value, defs).1?;
    let all = |items: &mut dyn Iterator<Item = String>| items.collect::<Vec<_>>();
    let names = matches!(data, OptionData::Names(_));
    let values = match data {
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
        OptionData::Binary(bytes) => vec![to_hex(&bytes.0)],
        OptionData::Empty => Vec::new(),
    };
    Some((values, names))
}

/// Whether the mirror's values equal Tenko's: domain names without case and the final dot,
/// everything else as written.
fn same(mirror: &[String], tenko: &[String], names: bool) -> bool {
    let norm = |value: &String| {
        let value = value.trim();
        if names {
            value.trim_end_matches('.').to_lowercase()
        } else {
            value.to_owned()
        }
    };
    mirror.len() == tenko.len() && mirror.iter().zip(tenko).all(|(a, b)| norm(a) == norm(b))
}

/// The rows of one option level. `server` follows the rule of section 2.5: a server option
/// is created only where Tenko's server set has none of that code, a different value is
/// the operator's decision, and Tenko's own server options stay.
fn options(
    rows: &mut Vec<DiffRow>,
    level: &str,
    mirror: &[IrOption],
    tenko: &[OptionValue],
    defs: &[OptionDef],
    server: bool,
) {
    let tenko: BTreeMap<u16, Option<(Vec<String>, bool)>> = tenko
        .iter()
        .filter(|value| value.space.is_dhcp4())
        .map(|value| (value.code, texts(value, defs)))
        .collect();
    let shown =
        |found: &Option<(Vec<String>, bool)>| found.as_ref().map(|(values, _)| values.join(", "));
    let mut seen = BTreeSet::new();
    for option in mirror {
        if u8::try_from(option.code).is_ok_and(|code| SERVER_MANAGED_V4.contains(&code)) {
            continue;
        }
        let values = Some(option.values.join(", "));
        if let Some(class) = option.vendor_class.as_ref().or(option.user_class.as_ref()) {
            rows.push(
                row(
                    DiffKind::Option,
                    format!("{level}:{}@{class}", option.code),
                    DiffAction::Decide,
                )
                .values(values, None)
                .because("Tenko's option sets carry no class: set it through a class and a policy"),
            );
            continue;
        }
        seen.insert(option.code);
        let item = format!("{level}:{}", option.code);
        let found = match tenko.get(&option.code) {
            None => row(DiffKind::Option, item, DiffAction::Create).values(values, None),
            Some(None) => row(DiffKind::Option, item, DiffAction::Decide)
                .values(values, None)
                .because("Tenko has no definition of this code to compare its value with"),
            Some(Some((ours, names))) if same(&option.values, ours, *names) => continue,
            Some(ours) if server => row(DiffKind::Option, item, DiffAction::Decide)
                .values(values, shown(ours))
                .because("Tenko's server options already set this code"),
            Some(ours) => {
                row(DiffKind::Option, item, DiffAction::Update).values(values, shown(ours))
            }
        };
        rows.push(found);
    }
    if !server {
        for (code, ours) in tenko.iter().filter(|(code, _)| !seen.contains(*code)) {
            rows.push(
                row(
                    DiffKind::Option,
                    format!("{level}:{code}"),
                    DiffAction::Remove,
                )
                .values(None, shown(ours)),
            );
        }
    }
}

/// The rows of the MAC filters (DHCP-08): whether the scope is restricted to the allow list,
/// and the source's entries Tenko's server-wide filters lack. Tenko's own deny entries stay,
/// as its own server options do; its own allow entries on a scope the source restricts are
/// the operator's decision, since they admit clients the source does not serve.
fn filters(
    rows: &mut Vec<DiffRow>,
    ir: &IrScope,
    snapshot: &Snapshot,
    tenko: &[Filter],
    restricted: Option<bool>,
) {
    if restricted != Some(ir.restricted) && (restricted.is_some() || ir.restricted) {
        let action = if restricted.is_some() {
            DiffAction::Update
        } else {
            DiffAction::Create
        };
        rows.push(row(DiffKind::Filter, "restricted", action).values(
            Some(ir.restricted.to_string()),
            restricted.map(|on| on.to_string()),
        ));
    }
    let mirrored: BTreeSet<String> = snapshot
        .envelope
        .dhcp
        .filters
        .iter()
        .map(|filter| filter_item(filter.kind, &filter.mac))
        .collect();
    let ours: BTreeSet<String> = tenko
        .iter()
        .map(|filter| filter_item(filter.kind, &filter.mac))
        .collect();
    rows.extend(mirrored.difference(&ours).map(|item| {
        row(DiffKind::Filter, item.clone(), DiffAction::Create).values(Some(item.clone()), None)
    }));
    if ir.restricted {
        rows.extend(
            ours.difference(&mirrored)
                .filter(|item| item.starts_with("allow "))
                .map(|item| {
                    row(DiffKind::Filter, item.clone(), DiffAction::Decide)
                        .values(None, Some(item.clone()))
                        .because("Tenko's allow entry admits a client on this scope that the source does not serve")
                }),
        );
    }
}

/// What the partner rows compare of one scope of a snapshot (plan section 2.15), by item:
/// the pools, the exclusions, the lease time, the options at every level, the reservations,
/// the DDNS settings and the MAC filters, each as text.
fn configuration(snapshot: &Snapshot, ir: &IrScope) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let range = |r: &tenko_core::ir::dhcp::IrRange| format!("{}-{}", r.first, r.last);
    for pool in &ir.ranges {
        out.insert(format!("pool {}", range(pool)), range(pool));
    }
    for exclusion in &ir.exclusions {
        out.insert(format!("exclusion {}", range(exclusion)), range(exclusion));
    }
    if let Some(secs) = ir.lease_secs {
        out.insert("lease_secs".to_owned(), secs.to_string());
    }
    let mut options = |level: &str, options: &[IrOption]| {
        for option in options {
            let class = option.vendor_class.as_ref().or(option.user_class.as_ref());
            let item = match class {
                Some(class) => format!("{level}:{}@{class}", option.code),
                None => format!("{level}:{}", option.code),
            };
            out.insert(item, option.values.join(", "));
        }
    };
    options("server", &snapshot.envelope.dhcp.server_options);
    options("scope", &ir.options);
    for reservation in &ir.reservations {
        options(&reservation.ip.to_string(), &reservation.options);
    }
    for reservation in &ir.reservations {
        let name = (reservation.name.as_ref().map(ToString::to_string))
            .or_else(|| reservation.source_name.clone())
            .map(|name| format!("name {name}"));
        let text = std::iter::once(identity(reservation))
            .chain(name)
            .chain(reservation.description.clone())
            .collect::<Vec<_>>()
            .join(", ");
        out.insert(format!("reservation {}", reservation.ip), text);
    }
    if let Some(ddns) = ir
        .ddns
        .as_ref()
        .or(snapshot.envelope.dhcp.server_ddns.as_ref())
    {
        out.insert(
            "ddns".to_owned(),
            serde_json::to_string(ddns).unwrap_or_default(),
        );
    }
    out.insert("restricted".to_owned(), ir.restricted.to_string());
    for filter in &snapshot.envelope.dhcp.filters {
        let item = filter_item(filter.kind, &filter.mac);
        out.insert(item.clone(), item);
    }
    out
}

/// A filter entry as the item of a row: `allow 00:00:5e:00:53:20`.
fn filter_item(kind: FilterKind, mac: &MacPattern) -> String {
    format!("{} {mac}", kind.as_str())
}

/// The partner rows: every configuration difference of the scope between the mirror's
/// snapshot and its partner's, which the operator decides (Windows copies a scope's
/// settings to its partner only when someone runs the replication).
fn partner_rows(
    rows: &mut Vec<DiffRow>,
    snapshot: &Snapshot,
    ir: &IrScope,
    partner: Option<&Snapshot>,
) {
    let decide = |item: &str, mine: Option<&String>, theirs: Option<&String>, reason: &str| {
        let mut row = row(DiffKind::Partner, item, DiffAction::Decide).because(reason);
        row.mirror = mine.cloned();
        row.partner = theirs.cloned();
        row
    };
    let Some(partner) = partner else {
        rows.push(decide(
            "snapshot",
            None,
            None,
            "the partner mirror holds no snapshot yet",
        ));
        return;
    };
    let Some(theirs) = partner.envelope.scope(&ir.cidr) else {
        rows.push(decide(
            "scope",
            Some(&ir.cidr.to_string()),
            None,
            "the partner's snapshot holds no such scope",
        ));
        return;
    };
    let mine = configuration(snapshot, ir);
    let theirs = configuration(partner, theirs);
    for item in mine.keys().chain(theirs.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (mine.get(item), theirs.get(item));
        if a != b {
            rows.push(decide(
                item,
                a,
                b,
                "the partners differ; Windows copies a scope's settings to the partner only when its replication is run",
            ));
        }
    }
}

fn identity(reservation: &IrReservation) -> String {
    match (&reservation.client.client_id, &reservation.client.mac) {
        (Some(id), _) => format!("client-id {}", to_hex(&id.0)),
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

/// The interfaces that hold a client identifier, wherever IPAM keeps them; read once, and
/// only when a reservation is keyed by one.
fn client_ids(view: &dyn ReadView) -> Result<HashMap<HexBytes, Interface>, MirrorError> {
    Ok(view
        .scan_typed(&INTERFACES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, interface, _)| !interface.meta.is_deleted())
        .filter_map(|(_, interface, _)| Some((interface.client_id.clone()?, interface)))
        .collect())
}

/// The interface that holds the reservation's identity: by client identifier, else by MAC
/// address through IPAM's index.
fn holder(
    view: &dyn ReadView,
    ids: &mut Option<HashMap<HexBytes, Interface>>,
    reservation: &IrReservation,
) -> Result<Option<Interface>, MirrorError> {
    if let Some(id) = &reservation.client.client_id {
        if ids.is_none() {
            *ids = Some(client_ids(view)?);
        }
        return Ok(ids.as_ref().and_then(|ids| ids.get(id)).cloned());
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
            return Ok(Some(interface));
        }
    }
    Ok(None)
}

/// The values of an owner's option set; none when it has none.
fn set_of(
    view: &dyn ReadView,
    owner: Option<OptionOwner>,
) -> Result<Vec<OptionValue>, MirrorError> {
    let Some(owner) = owner else {
        return Ok(Vec::new());
    };
    Ok(view
        .get_typed(&OPTION_SETS, &owner)?
        .map(|(set, _)| set.values)
        .unwrap_or_default())
}

/// The diff of `scope` of `snapshot` against Tenko's scope of the same network, and for a
/// paired mirror against the partner's latest snapshot (`partner`: its id and its snapshot,
/// none while it has none); `losses_open` comes from the caller, who holds the
/// acknowledgments.
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
    partner: Option<(MirrorId, Option<Snapshot>)>,
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
    let prefix = found.map(|(prefix, _)| prefix);
    let tenko_scope = prefix.and_then(|prefix| data.scopes.get(&prefix));
    let defs: Vec<OptionDef> = data.option_defs.values().cloned().collect();
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

    if let Some(secs) = ir.lease_secs {
        let server = data
            .settings
            .clone()
            .unwrap_or_else(DhcpSettings::default)
            .lease;
        let effective =
            tenko_scope.map(|scope| scope.lease.as_ref().unwrap_or(&server).default_secs);
        if effective != Some(secs) {
            let action = if tenko_scope.is_some() {
                DiffAction::Update
            } else {
                DiffAction::Create
            };
            rows.push(row(DiffKind::LeaseTime, "lease_secs", action).values(
                Some(secs.to_string()),
                effective.map(|secs| secs.to_string()),
            ));
        }
    }

    options(
        &mut rows,
        "server",
        &snapshot.envelope.dhcp.server_options,
        &set_of(view, Some(OptionOwner::Server))?,
        &defs,
        true,
    );
    options(
        &mut rows,
        "scope",
        &ir.options,
        &set_of(view, prefix.map(OptionOwner::Scope))?,
        &defs,
        false,
    );

    // Reservations: Tenko's at each address, and the interfaces that hold each identity.
    let by_ip: BTreeMap<std::net::IpAddr, (&Host, &Interface)> = data
        .addresses
        .values()
        .filter_map(|address| {
            let interface = data.interfaces.get(&address.interface?)?;
            let host = data.hosts.get(&interface.host)?;
            Some((address.ip, (host, interface)))
        })
        .collect();
    let mut ids = None;
    let mut mirrored = BTreeSet::new();
    for reservation in &ir.reservations {
        mirrored.insert(reservation.ip);
        let item = reservation.ip.to_string();
        let holder = holder(view, &mut ids, reservation)?;
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
        let decide = |reason: &str| {
            row(DiffKind::Reservation, item.clone(), DiffAction::Decide)
                .values(mine.clone(), theirs.clone())
                .because(reason)
        };
        let (action, interface): (Option<DiffAction>, Option<InterfaceId>) = match (at_ip, &holder)
        {
            (None, None) => (Some(DiffAction::Create), None),
            (Some((host, interface)), _) if holds(interface, reservation) => (
                (host.mode != AssignmentMode::Reserved).then_some(DiffAction::Update),
                Some(interface.id),
            ),
            (Some((host, _)), Some(other)) if other.host != host.id => {
                rows.push(decide(
                    "the address and the client's identity are on two hosts",
                ));
                continue;
            }
            (Some((_, interface)), None)
                if interface.mac.is_some() || interface.client_id.is_some() =>
            {
                rows.push(decide(
                    "the address is held by a host with another identity",
                ));
                continue;
            }
            (Some((_, interface)), _) => (Some(DiffAction::Attach), Some(interface.id)),
            (None, Some(other)) => (Some(DiffAction::Attach), Some(other.id)),
        };
        if let Some(action) = action {
            rows.push(row(DiffKind::Reservation, item.clone(), action).values(mine, theirs));
        }
        options(
            &mut rows,
            &item,
            &reservation.options,
            &set_of(view, interface.map(OptionOwner::Host))?,
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

    let tenko_filters: Vec<Filter> = view
        .scan_typed(&FILTERS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(_, filter, _)| filter)
        .collect();
    filters(
        &mut rows,
        ir,
        snapshot,
        &tenko_filters,
        tenko_scope.map(|scope| scope.restricted),
    );
    if let Some((_, theirs)) = &partner {
        partner_rows(&mut rows, snapshot, ir, theirs.as_ref());
    }

    rows.sort_by(|a, b| (a.kind, &a.item).cmp(&(b.kind, &b.item)));
    Ok(ScopeDiff {
        mirror: snapshot.mirror,
        scope,
        sequence: snapshot.sequence,
        source_active: ir.active,
        tenko_scope: tenko_scope.map(|scope| scope.prefix),
        tenko_enabled: tenko_scope.is_some_and(|scope| scope.enabled),
        partner_sequence: partner
            .as_ref()
            .and_then(|(_, theirs)| Some(theirs.as_ref()?.sequence)),
        partner: partner.map(|(id, _)| id),
        rows,
        losses_open,
    })
}
