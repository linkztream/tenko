//! The preview of a move: items, new addresses, steps, timeout and warnings, from a read
//! view. A submit computes the same preview again and starts the jobs from it.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use tenko_core::{
    AddressId, ObjectKind, ObjectRef, RequestCtx,
    codec::{canonical_sha256, encode_key},
    dhcp::{DhcpSettings, LeaseTimes, Scope, tables as dhcp_tables},
    ipam::{
        Address, AssignmentMode, Host, Interface, Prefix, PrefixRole, Range, RangeRole, Status,
        Tag, Vlan,
    },
    net::Fqdn,
    serde_util::to_hex,
};
use tenko_jobs::ManualTask;
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use uuid::Uuid;

use super::{
    DEFAULT_TIMEOUT_SECS, MAX_OBJECTS, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS, MOVE_FAILED_TAG,
    MoveDns, MoveItem, MoveL2, MoveL2Action, MovePreview, MoveRequest, MoveStepPreview, MoveTarget,
    MoveTimeoutSource, codes,
    l2::{self, L2Plans},
    steps::L2StepPlan,
};
use crate::{
    alloc::first_free,
    command::{AddressInput, IpamCommand},
    error::{IpamError, IpamResult, codes as ipam_codes},
    net::{Family, bounds, contains_ip, host_bounds, host_mask, ip_to_u128, u128_to_ip},
    plan::{PlanOptions, PlanWarning, plan},
    query,
    service::IpamConfig,
    tables::{ADDRESS_IPS, ADDRESSES, HOST_INTERFACES, INTERFACE_ADDRESSES, PREFIX_RANGES},
};

/// One step of an item's job: what the preview shows and what the job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StepPlan {
    /// The preview kind (`ipam.intent`, `dhcp.manual`, ...).
    pub kind: &'static str,
    /// The engine's step kind.
    pub step_kind: &'static str,
    /// Whether Tenko does it.
    pub automatic: bool,
    /// English description.
    pub text: String,
    /// Message arguments and references.
    pub params: BTreeMap<String, String>,
    /// The task of a manual step.
    pub task: Option<ManualTask>,
    /// The step's own timeout (the observation timeout, the controller step's limit).
    pub timeout: Option<Duration>,
    /// The change of an automatic L2 step.
    pub l2: Option<L2StepPlan>,
    /// The zone of an automatic DNS step.
    pub dns: Option<super::dns::DnsStepPlan>,
    /// The scope of an automatic DHCP step.
    pub dhcp: Option<super::dhcp::DhcpStepPlan>,
}

impl StepPlan {
    fn preview(&self) -> MoveStepPreview {
        MoveStepPreview {
            kind: self.kind.to_owned(),
            step_kind: self.step_kind.to_owned(),
            automatic: self.automatic,
            text: self.text.clone(),
            params: self.params.clone(),
        }
    }
}

/// A computed move: the preview and, per item, the plans of its steps.
#[derive(Debug, Clone)]
pub(super) struct Computed {
    pub preview: MovePreview,
    pub steps: Vec<Vec<StepPlan>>,
}

fn invalid(detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_REQUEST, 400, detail).titled("Invalid move request")
}

fn refused(code: &'static str, object: ObjectRef, detail: impl Into<String>) -> IpamError {
    IpamError::new(code, 422, detail)
        .titled("The object cannot move")
        .param("kind", object.kind)
        .param("id", object.id)
}

/// Computes the preview of a move (the dry run, API-09).
///
/// # Errors
///
/// 400 `ipam.move.invalid_request` (empty, too many objects, duplicates, a timeout or
/// parallelism out of bounds), 404 `ipam.not_found`, 409 `ipam.object_deleted`, 422 for
/// objects that cannot move (`ipam.move.*`), 423 `ipam.host.locked`, 409
/// `ipam.address.full`, and the errors of planning the new addresses.
pub fn preview(
    view: &dyn ReadView,
    cx: &RequestCtx,
    config: &IpamConfig,
    request: &MoveRequest,
) -> IpamResult<MovePreview> {
    let base = compute(view, cx, config, request)?;
    let l2 = super::l2::offline(&base.items, &base.target);
    Ok(finish(base, l2, request)?.preview)
}

/// What one candidate address brings along.
struct Candidate {
    address: Address,
    requested: ObjectRef,
    host: Option<Host>,
    interface: Option<Interface>,
}

#[allow(clippy::too_many_lines)] // One pass from request to items; split it and the flow is lost.
pub(super) fn compute(
    view: &dyn ReadView,
    cx: &RequestCtx,
    config: &IpamConfig,
    request: &MoveRequest,
) -> IpamResult<Base> {
    if request.objects.is_empty() {
        return Err(invalid("a move needs at least one object"));
    }
    if request.objects.len() > MAX_OBJECTS {
        return Err(
            invalid(format!("a move takes at most {MAX_OBJECTS} objects"))
                .param("count", request.objects.len()),
        );
    }
    let distinct: BTreeSet<ObjectRef> = request.objects.iter().copied().collect();
    if distinct.len() != request.objects.len() {
        return Err(invalid("an object is named twice"));
    }
    let target = query::get::<Prefix>(view, request.target)?;
    if target.meta.is_deleted() {
        return Err(IpamError::deleted(target.id.into()));
    }
    if target.role != PrefixRole::Network {
        return Err(IpamError::new(
            codes::TARGET_NOT_NETWORK,
            422,
            format!(
                "{} is a supernet; addresses move into networks",
                target.cidr
            ),
        )
        .titled("The target is not a network")
        .param("cidr", target.cidr));
    }
    let family = Family::of_net(&target.cidr);
    let vlan: Option<Vlan> = match target.vlan {
        Some(vlan) => Some(query::get::<Vlan>(view, vlan)?),
        None => None,
    };
    let ranges = live_ranges(view, &target)?;
    let scope = tenko_scope(view, &target)?;
    let lease = target_lease(view, &ranges, scope.as_ref())?;
    let (timeout_secs, timeout_source) = timeout(request.timeout_secs, lease)?;
    let parallelism = request.parallelism.unwrap_or(config.move_parallelism);
    if !(1..=64).contains(&parallelism) {
        return Err(invalid("parallelism must be 1 to 64").param("parallelism", parallelism));
    }

    // Expand the request into addresses.
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen = BTreeSet::new();
    for object in &request.objects {
        for candidate in expand(view, *object, &target, family)? {
            if seen.insert(candidate.address.id) {
                candidates.push(candidate);
            }
        }
    }

    // Choose the new addresses; items of one move never share one.
    let mut taken: BTreeSet<u128> = BTreeSet::new();
    let mut items = Vec::with_capacity(candidates.len());
    let mut commands = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        let (new_ip, reason) = choose(view, &target, &ranges, candidate.address.ip, &taken)?;
        taken.insert(ip_to_u128(new_ip));
        let new_address = new_address_id(view, cx, index)?;
        let mut tags = candidate.address.meta.tags.clone();
        tags.retain(|tag| tag.as_str() != MOVE_FAILED_TAG);
        commands.push(IpamCommand::CreateAddress(AddressInput {
            id: Some(new_address),
            vrf: Some(target.vrf),
            ip: new_ip,
            status: Some(Status::Planned),
            interface: candidate.address.interface,
            dns_name: candidate.address.dns_name.clone(),
            tags,
            custom: candidate.address.meta.custom.clone(),
            description: candidate.address.meta.description.clone(),
        }));
        let mac = candidate.interface.as_ref().and_then(|i| i.mac);
        items.push(MoveItem {
            object: candidate.address.id.into(),
            requested: candidate.requested,
            host: candidate.host.as_ref().map(|h| h.id),
            host_name: candidate.host.as_ref().map(|h| h.name.clone()),
            mode: candidate.host.as_ref().map(|h| h.mode),
            interface: candidate.address.interface,
            mac,
            old_ip: candidate.address.ip,
            new_ip,
            new_address,
            same_host_part: reason.is_none(),
            reason: reason.map(str::to_owned),
            dns: candidate.address.dns_name.clone().map(|name| MoveDns {
                name,
                old: Some(candidate.address.ip),
                new: Some(new_ip),
                zone: None,
                remove: Vec::new(),
                add: Vec::new(),
            }),
            l2: MoveL2::default(),
            steps: Vec::new(),
            warnings: Vec::new(),
        });
    }

    // The new addresses must plan cleanly; their warnings belong to the items.
    let options = PlanOptions::acknowledging(request.acknowledge.iter().cloned());
    let planned = plan(view, cx, &options, &commands)?;
    let mut warnings: Vec<PlanWarning> = planned.warnings.clone();
    if let ipnet::IpNet::V6(net) = target.cidr
        && net.prefix_len() % 4 != 0
    {
        warnings.push(PlanWarning {
            code: ipam_codes::WARN_NIBBLE.to_owned(),
            message: format!("the target {} is not on a nibble boundary", target.cidr),
            object: Some(target.id.into()),
            params: BTreeMap::from([("cidr".to_owned(), target.cidr.to_string())]),
            requires_ack: true,
            acknowledged: false,
        });
    }
    warnings.extend(dns_collisions(view, &target, &candidates, &items)?);
    warnings.extend(dns_records(view, &candidates, &mut items)?);

    Ok(Base {
        target: MoveTarget {
            prefix: target.id,
            cidr: target.cidr,
            vrf: target.vrf,
            vlan: target.vlan,
            vid: vlan.as_ref().map(|v| v.vid),
            lease_secs: lease,
        },
        timeout_secs,
        timeout_source,
        parallelism,
        revision: view.revision().0,
        hosts: candidates
            .iter()
            .map(|c| c.host.as_ref().map(|h| ObjectRef::from(h.id)))
            .collect(),
        dhcp: candidates
            .iter()
            .map(|c| dhcp_plan(scope.as_ref(), c))
            .collect(),
        items,
        warnings,
    })
}

/// The Tenko scope of the target when it serves: enabled, on an IPv4 network (DHCPv6 is
/// Slice 9).
fn tenko_scope(view: &dyn ReadView, target: &Prefix) -> IpamResult<Option<Scope>> {
    if !matches!(target.cidr, ipnet::IpNet::V4(_)) {
        return Ok(None);
    }
    Ok(view
        .get_typed(&dhcp_tables::SCOPES, &target.id)?
        .map(|(scope, _)| scope)
        .filter(|scope| scope.enabled))
}

/// The DHCP lease of the target's pools in seconds: the longest `lease_secs` of its pool
/// ranges; with a Tenko scope, the longest default time a pool's client gets (the pool's
/// setting, else the range's `lease_secs`, else the scope's, else the server's), and the
/// scope's own when it has no pool.
fn target_lease(
    view: &dyn ReadView,
    ranges: &[Range],
    scope: Option<&Scope>,
) -> IpamResult<Option<u32>> {
    let pools = ranges
        .iter()
        .filter(|range| range.role == RangeRole::DhcpPool);
    let Some(scope) = scope else {
        return Ok(pools.filter_map(lease_of).max());
    };
    let settings: DhcpSettings = view
        .get_typed(&dhcp_tables::SETTINGS, &())?
        .map(|(settings, _)| settings)
        .unwrap_or_default();
    let scope_lease = scope.lease.unwrap_or(settings.lease);
    let mut longest: Option<u32> = None;
    for range in pools {
        let pool = view
            .get_typed(&dhcp_tables::POOLS, &range.id)?
            .and_then(|(pool, _)| pool.lease);
        let lease = pool
            .or_else(|| range.lease_secs.map(LeaseTimes::fixed))
            .unwrap_or(scope_lease);
        longest = longest.max(Some(lease.default_secs));
    }
    Ok(Some(longest.unwrap_or(scope_lease.default_secs)))
}

/// The automatic DHCP step of a candidate: a Tenko scope on the target and an interface
/// the role can reserve for (a MAC address or a client identifier, IPAM-18).
fn dhcp_plan(scope: Option<&Scope>, candidate: &Candidate) -> Option<super::dhcp::DhcpStepPlan> {
    let scope = scope?;
    let interface = candidate.interface.as_ref()?;
    (interface.mac.is_some() || interface.client_id.is_some()).then_some(
        super::dhcp::DhcpStepPlan {
            scope: scope.prefix,
        },
    )
}

/// The part of a move computed from the store, before the L2 steps.
#[derive(Debug, Clone)]
pub(super) struct Base {
    pub target: MoveTarget,
    pub timeout_secs: u32,
    pub timeout_source: MoveTimeoutSource,
    pub parallelism: u32,
    pub revision: u64,
    /// The items, without their L2 step and steps.
    pub items: Vec<MoveItem>,
    /// The host of each item.
    pub hosts: Vec<Option<ObjectRef>>,
    /// The automatic DHCP step of each item, when the target has a Tenko scope.
    pub dhcp: Vec<Option<super::dhcp::DhcpStepPlan>>,
    /// The warnings of the plan, the target and the DNS names.
    pub warnings: Vec<PlanWarning>,
}

/// Completes a move with the L2 steps: the steps of every item, the warnings with their
/// acknowledgements and the fingerprint.
///
/// # Errors
///
/// `sys.internal` when the fingerprint does not encode.
pub(super) fn finish(base: Base, l2: L2Plans, request: &MoveRequest) -> IpamResult<Computed> {
    let Base {
        target,
        timeout_secs,
        timeout_source,
        parallelism,
        revision,
        mut items,
        hosts,
        dhcp,
        mut warnings,
    } = base;
    warnings.extend(l2.warnings);
    for warning in &mut warnings {
        warning.acknowledged = warning.requires_ack && request.acknowledge.contains(&warning.code);
    }
    let mut all_steps = Vec::with_capacity(items.len());
    for (((item, host_ref), l2), dhcp) in items.iter_mut().zip(&hosts).zip(l2.items).zip(&dhcp) {
        item.l2 = l2;
        item.warnings = warnings
            .iter()
            .filter(|w| {
                w.object == Some(item.new_address.into())
                    || w.object == Some(item.object)
                    || (w.object.is_some() && w.object == *host_ref)
            })
            .cloned()
            .collect();
        let steps = step_plans(item, &target, timeout_secs, dhcp.as_ref());
        item.steps = steps.iter().map(StepPlan::preview).collect();
        all_steps.push(steps);
    }
    let unacknowledged: BTreeSet<String> = warnings
        .iter()
        .filter(|w| w.requires_ack && !w.acknowledged)
        .map(|w| w.code.clone())
        .collect();
    let fingerprint = fingerprint(&target, &items)?;
    Ok(Computed {
        preview: MovePreview {
            target,
            timeout_secs,
            timeout_source,
            parallelism,
            base_revision: revision,
            items,
            warnings,
            unacknowledged: unacknowledged.into_iter().collect(),
            controllers: l2.controllers,
            fingerprint,
        },
        steps: all_steps,
    })
}

/// What the fingerprint of a move covers: per item the address, the new address, the
/// step kinds and the L2 decision with its change and diff. The identifiers of the new
/// addresses and the times of the reads are left out, so two computations of the same
/// plan agree.
#[derive(serde::Serialize)]
struct Fingerprinted<'a> {
    target: tenko_core::PrefixId,
    items: Vec<FingerprintedItem<'a>>,
}

#[derive(serde::Serialize)]
struct FingerprintedItem<'a> {
    object: ObjectRef,
    new_ip: IpAddr,
    steps: Vec<&'a str>,
    action: super::MoveL2Action,
    reason: Option<&'a str>,
    connector: Option<tenko_core::ConnectorId>,
    change: Option<&'a crate::vlan::controllers::AttachmentChange>,
    diff: &'a [crate::vlan::controllers::DiffEntry],
}

fn fingerprint(target: &MoveTarget, items: &[MoveItem]) -> IpamResult<String> {
    let value = Fingerprinted {
        target: target.prefix,
        items: items
            .iter()
            .map(|item| FingerprintedItem {
                object: item.object,
                new_ip: item.new_ip,
                steps: item.steps.iter().map(|s| s.step_kind.as_str()).collect(),
                action: item.l2.action,
                reason: item.l2.reason.as_deref(),
                connector: item.l2.connector_id(),
                change: item.l2.change.as_ref(),
                diff: &item.l2.diff,
            })
            .collect(),
    };
    let digest = canonical_sha256(&value)?;
    Ok(to_hex(&digest[..16]))
}

/// The DHCP lease of a pool in seconds.
fn lease_of(range: &Range) -> Option<u32> {
    range.lease_secs
}

/// The observation timeout and how it was chosen.
fn timeout(requested: Option<u32>, lease: Option<u32>) -> IpamResult<(u32, MoveTimeoutSource)> {
    if let Some(secs) = requested {
        if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) {
            return Err(invalid(format!(
                "timeout_secs must be {MIN_TIMEOUT_SECS} to {MAX_TIMEOUT_SECS}"
            ))
            .param("timeout_secs", secs));
        }
        return Ok((secs, MoveTimeoutSource::Request));
    }
    Ok(match lease {
        Some(lease) => ((lease / 2).max(MIN_TIMEOUT_SECS), MoveTimeoutSource::Lease),
        None => (DEFAULT_TIMEOUT_SECS, MoveTimeoutSource::Default),
    })
}

fn live_ranges(view: &dyn ReadView, prefix: &Prefix) -> IpamResult<Vec<Range>> {
    let keys = view.scan_typed(
        &PREFIX_RANGES,
        KeyRange::prefix(encode_key(&prefix.id)),
        usize::MAX,
        false,
    )?;
    let mut out = Vec::new();
    for ((_, id), (), _) in keys {
        let range = query::get::<Range>(view, id)?;
        if !range.meta.is_deleted() {
            out.push(range);
        }
    }
    Ok(out)
}

/// The addresses a requested object moves.
fn expand(
    view: &dyn ReadView,
    object: ObjectRef,
    target: &Prefix,
    family: Family,
) -> IpamResult<Vec<Candidate>> {
    let inside =
        |address: &Address| address.vrf == target.vrf && contains_ip(&target.cidr, address.ip);
    match object.kind {
        ObjectKind::Host => {
            let host = query::get::<Host>(view, object.id.into())?;
            if host.meta.is_deleted() {
                return Err(IpamError::deleted(object));
            }
            check_host(&host)?;
            let mut out = Vec::new();
            let interfaces = view.scan_typed(
                &HOST_INTERFACES,
                KeyRange::prefix(encode_key(&host.id)),
                usize::MAX,
                false,
            )?;
            for ((_, interface_id), (), _) in interfaces {
                let interface = query::get::<Interface>(view, interface_id)?;
                if interface.meta.is_deleted() {
                    continue;
                }
                let addresses = view.scan_typed(
                    &INTERFACE_ADDRESSES,
                    KeyRange::prefix(encode_key(&interface_id)),
                    usize::MAX,
                    false,
                )?;
                for ((_, address_id), (), _) in addresses {
                    let address = query::get::<Address>(view, address_id)?;
                    if address.meta.is_deleted()
                        || address.interface != Some(interface_id)
                        || Family::of(address.ip) != family
                        || inside(&address)
                    {
                        continue;
                    }
                    out.push(Candidate {
                        address,
                        requested: object,
                        host: Some(host.clone()),
                        interface: Some(interface.clone()),
                    });
                }
            }
            if out.is_empty() {
                return Err(refused(
                    codes::NOTHING_TO_MOVE,
                    object,
                    format!(
                        "host {} has no address of the family of {} outside it",
                        host.name, target.cidr
                    ),
                ));
            }
            Ok(out)
        }
        ObjectKind::Address => {
            let address = query::get::<Address>(view, object.id.into())?;
            if address.meta.is_deleted() {
                return Err(IpamError::deleted(object));
            }
            if Family::of(address.ip) != family {
                return Err(refused(
                    codes::FAMILY_MISMATCH,
                    object,
                    format!("{} cannot move into {}", address.ip, target.cidr),
                ));
            }
            if inside(&address) {
                return Err(refused(
                    codes::ALREADY_IN_TARGET,
                    object,
                    format!("{} is inside {} already", address.ip, target.cidr),
                ));
            }
            let (interface, host) = match address.interface {
                Some(interface) => {
                    let interface = query::get::<Interface>(view, interface)?;
                    let host = query::get::<Host>(view, interface.host)?;
                    check_host(&host)?;
                    (Some(interface), Some(host))
                }
                None => (None, None),
            };
            Ok(vec![Candidate {
                address,
                requested: object,
                host,
                interface,
            }])
        }
        _ => Err(refused(
            codes::UNSUPPORTED_OBJECT,
            object,
            format!("{object} is neither a host nor an address"),
        )),
    }
}

/// Refuses unmanaged and locked hosts.
fn check_host(host: &Host) -> IpamResult<()> {
    if host.mode == AssignmentMode::Unmanaged {
        return Err(refused(
            codes::UNMANAGED,
            host.id.into(),
            format!("host {} is unmanaged; nothing may touch it", host.name),
        )
        .param("host", &host.name));
    }
    if host.lock {
        return Err(IpamError::new(
            ipam_codes::HOST_LOCKED,
            423,
            format!("host {} is locked; unlock it to move it", host.name),
        )
        .titled("The host is locked")
        .param("host", &host.name));
    }
    Ok(())
}

/// The new address: the same host part when possible, else the next free one.
fn choose(
    view: &dyn ReadView,
    target: &Prefix,
    ranges: &[Range],
    old: IpAddr,
    taken: &BTreeSet<u128>,
) -> IpamResult<(IpAddr, Option<&'static str>)> {
    let family = Family::of_net(&target.cidr);
    let (first, last) = bounds(&target.cidr);
    let (lo, hi) = host_bounds(&target.cidr);
    let candidate = first | (ip_to_u128(old) & host_mask(family, target.cidr.prefix_len()));
    let in_range = |value: u128| {
        ranges
            .iter()
            .any(|r| value >= ip_to_u128(r.first) && value <= ip_to_u128(r.last))
    };
    let used = |value: u128| -> IpamResult<bool> {
        Ok(taken.contains(&value)
            || view
                .get_typed(&ADDRESS_IPS, &(target.vrf, u128_to_ip(family, value)))?
                .is_some())
    };
    let reason = if candidate < lo || candidate > hi {
        Some(codes::HOST_PART_OUTSIDE)
    } else if in_range(candidate) {
        Some(codes::HOST_PART_RESERVED)
    } else if used(candidate)? {
        Some(codes::HOST_PART_TAKEN)
    } else {
        return Ok((u128_to_ip(family, candidate), None));
    };
    let mut blocked: Vec<(u128, u128)> = ranges
        .iter()
        .map(|r| (ip_to_u128(r.first), ip_to_u128(r.last)))
        .collect();
    blocked.extend(taken.iter().map(|value| (*value, *value)));
    let addresses = view.scan_typed(
        &ADDRESS_IPS,
        KeyRange {
            start: std::ops::Bound::Included(
                ADDRESS_IPS.key(&(target.vrf, u128_to_ip(family, first))),
            ),
            end: std::ops::Bound::Included(
                ADDRESS_IPS.key(&(target.vrf, u128_to_ip(family, last))),
            ),
        },
        usize::MAX,
        false,
    )?;
    blocked.extend(addresses.iter().map(|((_, ip), _, _)| {
        let value = ip_to_u128(*ip);
        (value, value)
    }));
    let Some(value) = first_free(lo, hi, blocked, target.alloc) else {
        return Err(IpamError::new(
            ipam_codes::ADDRESS_FULL,
            409,
            format!("no free address left in {}", target.cidr),
        )
        .titled("No free address")
        .param("cidr", target.cidr));
    };
    Ok((u128_to_ip(family, value), reason))
}

/// An identifier for the new address of item `index`: derived from the request, so
/// planning twice in one request gives the same one, and skipping any that exist.
fn new_address_id(view: &dyn ReadView, cx: &RequestCtx, index: usize) -> IpamResult<AddressId> {
    let millis = u64::try_from(cx.now.unix_nanos() / 1_000_000).unwrap_or(0);
    for attempt in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(b"ipam.move");
        hasher.update(cx.request.0.as_bytes());
        hasher.update(u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(attempt.to_be_bytes());
        let digest = hasher.finalize();
        let mut random = [0u8; 10];
        random.copy_from_slice(&digest[..10]);
        let id =
            AddressId::from(uuid::Builder::from_unix_timestamp_millis(millis, &random).into_uuid());
        if view.get_typed(&ADDRESSES, &id)?.is_none() {
            return Ok(id);
        }
    }
    Ok(AddressId::from(Uuid::now_v7()))
}

/// Warns when another object of the target VRF already carries an item's DNS name.
fn dns_collisions(
    view: &dyn ReadView,
    target: &Prefix,
    candidates: &[Candidate],
    items: &[MoveItem],
) -> IpamResult<Vec<PlanWarning>> {
    let names: BTreeMap<&Fqdn, &MoveItem> = items
        .iter()
        .filter_map(|item| item.dns.as_ref().map(|dns| (&dns.name, item)))
        .collect();
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let moving_hosts: BTreeSet<_> = candidates
        .iter()
        .filter_map(|c| c.host.as_ref().map(|h| h.id))
        .collect();
    let moving: BTreeSet<AddressId> = candidates.iter().map(|c| c.address.id).collect();
    let mut warnings = Vec::new();
    let mut reported = BTreeSet::new();
    for (_, address, _) in view.scan_typed(&ADDRESSES, KeyRange::all(), usize::MAX, false)? {
        if address.meta.is_deleted() || address.vrf != target.vrf || moving.contains(&address.id) {
            continue;
        }
        let Some(name) = &address.dns_name else {
            continue;
        };
        let Some(item) = names.get(name) else {
            continue;
        };
        if let Some(interface) = address.interface
            && let Some((interface, _)) = view.get_typed(&crate::tables::INTERFACES, &interface)?
            && moving_hosts.contains(&interface.host)
        {
            continue;
        }
        if !reported.insert(name.clone()) {
            continue;
        }
        let proposed = propose_name(name);
        warnings.push(PlanWarning {
            code: codes::DNS_COLLISION.to_owned(),
            message: format!(
                "{name} already points to {} in the target VRF; consider {proposed}",
                address.ip
            ),
            object: Some(item.object),
            params: BTreeMap::from([
                ("name".to_owned(), name.to_string()),
                ("ip".to_owned(), address.ip.to_string()),
                ("proposed".to_owned(), proposed),
            ]),
            requires_ack: true,
            acknowledged: false,
        });
    }
    Ok(warnings)
}

/// Fills the DNS change of every item from the actuator's dry run (the zone that makes
/// the DNS step automatic, the records it removes and writes) and warns when another
/// origin holds a record the step needs: the step would stop with the same code.
fn dns_records(
    view: &dyn ReadView,
    candidates: &[Candidate],
    items: &mut [MoveItem],
) -> IpamResult<Vec<PlanWarning>> {
    let moved: Vec<crate::dns::moves::MovedAddress> = candidates
        .iter()
        .zip(items.iter())
        .map(|(candidate, item)| crate::dns::moves::MovedAddress {
            old: candidate.address.clone(),
            new_id: item.new_address,
            new_ip: item.new_ip,
        })
        .collect();
    let changes = crate::dns::moves::preview(view, &moved)?;
    let mut warnings = Vec::new();
    for (item, change) in items.iter_mut().zip(changes) {
        let Some(dns) = &mut item.dns else {
            continue;
        };
        dns.zone = change.zone.as_ref().map(ToString::to_string);
        dns.remove = change.remove;
        dns.add = change.add;
        if !change.held.is_empty() {
            warnings.push(PlanWarning {
                code: codes::DNS_COLLISION.to_owned(),
                message: format!(
                    "the DNS step of {} will stop: {}",
                    dns.name,
                    change.held.join("; ")
                ),
                object: Some(item.object),
                params: BTreeMap::from([
                    ("name".to_owned(), dns.name.to_string()),
                    ("held".to_owned(), change.held.join("; ")),
                ]),
                requires_ack: true,
                acknowledged: false,
            });
        }
    }
    Ok(warnings)
}

/// A free-looking alternative name: `-2` on the first label.
fn propose_name(name: &Fqdn) -> String {
    match name.as_str().split_once('.') {
        Some((first, rest)) => format!("{first}-2.{rest}"),
        None => format!("{name}-2"),
    }
}

fn params(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn manual(instruction: &'static str, args: &BTreeMap<String, String>) -> ManualTask {
    ManualTask {
        instruction: tenko_core::MessageKey::from_static(instruction),
        args: args.clone(),
        undo: None,
    }
}

/// The steps of one item's job, in order (see the module documentation).
#[allow(clippy::too_many_lines)] // One entry per step kind, in job order.
pub(super) fn step_plans(
    item: &MoveItem,
    target: &MoveTarget,
    timeout_secs: u32,
    dhcp: Option<&super::dhcp::DhcpStepPlan>,
) -> Vec<StepPlan> {
    let mut base = params(&[
        ("prefix", target.prefix.to_string()),
        ("cidr", target.cidr.to_string()),
        ("vrf", target.vrf.to_string()),
        ("old_ip", item.old_ip.to_string()),
        ("new_ip", item.new_ip.to_string()),
        ("address", item.object.id.to_string()),
        ("new_address", item.new_address.to_string()),
    ]);
    if let Some(vlan) = target.vlan {
        base.insert("vlan".to_owned(), vlan.to_string());
    }
    if let Some(vid) = target.vid {
        base.insert("vid".to_owned(), vid.to_string());
    }
    if let Some(name) = &item.host_name {
        base.insert("host".to_owned(), name.to_string());
    }
    if let Some(mac) = item.mac {
        base.insert("mac".to_owned(), mac.to_string());
    }
    let who = item
        .host_name
        .as_ref()
        .map_or_else(|| item.old_ip.to_string(), ToString::to_string);
    let mut steps = vec![StepPlan {
        kind: "ipam.intent",
        step_kind: super::steps::INTENT,
        automatic: true,
        text: format!(
            "Add {} as planned intent{}; keep {} until cleanup",
            item.new_ip,
            item.host_name
                .as_ref()
                .map(|n| format!(" on {n}"))
                .unwrap_or_default(),
            item.old_ip
        ),
        params: base.clone(),
        task: None,
        timeout: None,
        l2: None,
        dns: None,
        dhcp: None,
    }];
    if item.mode == Some(AssignmentMode::Reserved)
        && let Some(plan) = dhcp
    {
        let mac = item.mac.map_or_else(
            || "its client identifier".to_owned(),
            |m| format!("MAC {m}"),
        );
        steps.push(StepPlan {
            kind: super::dhcp::PREVIEW_KIND,
            step_kind: super::steps::DHCP,
            automatic: true,
            text: format!(
                "Reserve {} for {mac} in the Tenko scope {} from the planned address, and wait \
                 until the dhcp role serves it; the old reservation stays until cleanup",
                item.new_ip, target.cidr
            ),
            params: base.clone(),
            task: None,
            timeout: None,
            l2: None,
            dns: None,
            dhcp: Some(plan.clone()),
        });
    } else if item.mode == Some(AssignmentMode::Reserved) {
        let mac = item.mac.map_or_else(
            || "its MAC address or DUID".to_owned(),
            |m| format!("MAC {m}"),
        );
        steps.push(StepPlan {
            kind: "dhcp.manual",
            step_kind: super::steps::DHCP,
            automatic: false,
            text: format!(
                "Create a DHCP reservation of {} for {mac} in the scope of {}; keep the old one until cleanup",
                item.new_ip, target.cidr
            ),
            params: base.clone(),
            task: Some(manual("ipam.move.task.dhcp", &base)),
            timeout: None,
            l2: None,
            dns: None,
            dhcp: None,
        });
    }
    if let Some(dns) = &item.dns
        && let Some(zone) = &dns.zone
    {
        let mut args = base.clone();
        args.insert("name".to_owned(), dns.name.to_string());
        args.insert("zone".to_owned(), zone.clone());
        steps.push(StepPlan {
            kind: "dns.records",
            step_kind: super::steps::DNS,
            automatic: true,
            text: format!(
                "Point {} to {} in {zone}: remove the address and reverse records of {} and write those of {}",
                dns.name, item.new_ip, item.old_ip, item.new_ip
            ),
            params: args,
            task: None,
            timeout: None,
            l2: None,
            dns: Some(super::dns::DnsStepPlan { zone: zone.clone() }),
            dhcp: None,
        });
    } else if let Some(dns) = &item.dns {
        let mut args = base.clone();
        args.insert("name".to_owned(), dns.name.to_string());
        steps.push(StepPlan {
            kind: "dns.manual",
            step_kind: super::steps::DNS,
            automatic: false,
            text: format!(
                "Point {} to {} (address and reverse records); remove the old records at cleanup",
                dns.name, item.new_ip
            ),
            params: args.clone(),
            task: Some(manual("ipam.move.task.dns", &args)),
            timeout: None,
            l2: None,
            dns: None,
            dhcp: None,
        });
    }
    if item.mode == Some(AssignmentMode::Static) {
        steps.push(StepPlan {
            kind: "device.manual",
            step_kind: super::steps::DEVICE,
            automatic: false,
            text: format!(
                "Reconfigure {who} to {}/{}",
                item.new_ip,
                target.cidr.prefix_len()
            ),
            params: base.clone(),
            task: Some(manual("ipam.move.task.device", &base)),
            timeout: None,
            l2: None,
            dns: None,
            dhcp: None,
        });
    }
    if let Some(step) = l2_step(item, target, &base, &who) {
        steps.push(step);
    }
    let mut observe = base.clone();
    observe.insert("timeout_secs".to_owned(), timeout_secs.to_string());
    steps.push(StepPlan {
        kind: "observe",
        step_kind: super::steps::OBSERVE,
        automatic: false,
        text: format!(
            "Confirm that {who} is seen at {} in {}; the move rolls back after {timeout_secs} s",
            item.new_ip, target.cidr
        ),
        params: observe.clone(),
        task: Some(manual("ipam.move.task.observe", &observe)),
        timeout: Some(Duration::from_secs(u64::from(timeout_secs))),
        l2: None,
        dns: None,
        dhcp: None,
    });
    steps.push(StepPlan {
        kind: "cleanup",
        step_kind: super::steps::CLEANUP,
        automatic: true,
        text: format!("Remove {} and make {} active", item.old_ip, item.new_ip),
        params: base,
        task: None,
        timeout: None,
        l2: None,
        dns: None,
        dhcp: None,
    });
    steps
}

/// The L2 step of an item: through the network controller, by a person, or none when
/// the device is in the target VLAN already or moves with another address.
fn l2_step(
    item: &MoveItem,
    target: &MoveTarget,
    base: &BTreeMap<String, String>,
    who: &str,
) -> Option<StepPlan> {
    let l2 = &item.l2;
    if !l2.has_step() {
        return None;
    }
    let args = l2::args(l2, base);
    let text = l2::text(l2, who, &target.cidr.to_string(), target.vid);
    if l2.automatic() {
        let (Some(connector), Some(change), Some(attachment), Some(mac)) =
            (&l2.connector, &l2.change, &l2.attachment, item.mac)
        else {
            return None;
        };
        return Some(StepPlan {
            kind: "l2.controller",
            step_kind: super::steps::CONTROLLER,
            automatic: true,
            text,
            params: args,
            task: None,
            timeout: Some(Duration::from_secs(super::steps::CONTROLLER_TIMEOUT_SECS)),
            l2: Some(L2StepPlan {
                connector: connector.id,
                connector_name: connector.name.clone(),
                mac,
                change: change.clone(),
                attachment: attachment.clone(),
                action: l2.action,
                diff: l2.diff.clone(),
            }),
            dns: None,
            dhcp: None,
        });
    }
    debug_assert_eq!(l2.action, MoveL2Action::Manual);
    Some(StepPlan {
        kind: "l2.move",
        step_kind: super::steps::L2,
        automatic: false,
        text,
        params: args.clone(),
        task: Some(manual(l2::instruction(l2), &args)),
        timeout: None,
        l2: None,
        dns: None,
        dhcp: None,
    })
}

/// The tag that marks a failed move.
pub(super) fn move_failed_tag() -> IpamResult<Tag> {
    Ok(Tag::new(MOVE_FAILED_TAG)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_rules() {
        assert_eq!(
            timeout(None, None).expect("default"),
            (DEFAULT_TIMEOUT_SECS, MoveTimeoutSource::Default)
        );
        assert_eq!(
            timeout(None, Some(86_400)).expect("half"),
            (43_200, MoveTimeoutSource::Lease)
        );
        assert_eq!(timeout(None, Some(300)).expect("floor").0, MIN_TIMEOUT_SECS);
        assert_eq!(
            timeout(Some(900), Some(86_400)).expect("asked"),
            (900, MoveTimeoutSource::Request)
        );
        assert!(timeout(Some(299), None).is_err());
        assert!(timeout(Some(MAX_TIMEOUT_SECS + 1), None).is_err());
    }

    #[test]
    fn proposed_names_suffix_the_first_label() {
        let name: Fqdn = "nas01.example.test".parse().expect("name");
        assert_eq!(propose_name(&name), "nas01-2.example.test");
        assert_eq!(move_failed_tag().expect("tag").as_str(), MOVE_FAILED_TAG);
    }
}
