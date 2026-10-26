//! The L2 step of a move (IPAM-19 step 4): how each device gets into the target VLAN,
//! decided from one fresh read of every enabled network controller. The decision itself
//! ([`decide_all`]) is pure over those reads, so the rules are tested without a controller.

// The controllers' port reports `CodedError`s, so the guardrail check returns it as well.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use tenko_core::{AddressId, CodedError, InterfaceId, ObjectRef, RequestCtx};

use super::{
    MoveAttachment, MoveItem, MoveL2, MoveL2Action, MoveL2Problem, MoveMedium, MoveNudge,
    MoveNudgeAction, MoveTarget, codes,
};
use crate::{
    plan::PlanWarning,
    vlan::controllers::{
        AttachmentChange, ControllerAttachments, ControllerClient, ControllerInfo,
        ControllerNetwork, Controllers, DiffEntry, NudgeChange, guardrail,
    },
};

/// The L2 steps of a move's items, in item order, with the warnings they raise.
#[derive(Debug, Clone, Default)]
pub(super) struct L2Plans {
    /// One per item.
    pub items: Vec<MoveL2>,
    /// Refusals and unreadable controllers.
    pub warnings: Vec<PlanWarning>,
    /// The enabled network controllers that were read.
    pub controllers: Vec<ControllerInfo>,
    /// Whether a controller that sees a device of the move offers a nudge (ADR 0028).
    pub nudge_offered: bool,
}

/// What the nudges of a move follow (ADR 0028): the request's switch and `[dhcp.moves]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NudgeOptions {
    /// Whether the move bounces or kicks at all (`MoveRequest::nudge`).
    pub enabled: bool,
    /// How long a bounce keeps the port down.
    pub down_secs: u16,
    /// How long the job waits for the client to come back by itself first.
    pub reappear_secs: u32,
}

/// A guardrail check of a nudge (`NetworkControllers::check_nudge`).
pub(super) type NudgeCheck<'a> =
    &'a (dyn Fn(&ControllerAttachments, &NudgeChange) -> Result<(), CodedError> + Sync);

/// Decides the nudge of every automatic L2 step from the controllers' reads (ADR 0028): a
/// port bounce after a port profile change, a client kick after a per-client VLAN, when the
/// controller offers it and its guardrails let it; otherwise none, with the reason. Returns
/// whether a controller that sees a device of the move offers a nudge at all.
pub(super) fn nudge_all(
    items: &mut [MoveL2],
    reads: &[Read],
    options: NudgeOptions,
    check: NudgeCheck<'_>,
) -> bool {
    let mut offered = false;
    for l2 in items.iter_mut() {
        let Some(info) = &l2.connector else {
            continue;
        };
        offered |= info.bounce || info.kick;
        if !l2.automatic() {
            continue;
        }
        let Some(state) = reads
            .iter()
            .find(|read| read.info.id == info.id)
            .and_then(|read| read.state.as_ref().ok())
        else {
            continue;
        };
        l2.nudge = nudge_of(l2, info, state, options, check);
    }
    offered
}

fn nudge_of(
    l2: &MoveL2,
    info: &ControllerInfo,
    state: &ControllerAttachments,
    options: NudgeOptions,
    check: NudgeCheck<'_>,
) -> Option<MoveNudge> {
    let (change, action, capable) = match (&l2.change, &l2.attachment) {
        (Some(AttachmentChange::SetPortProfile { device, port, .. }), _) => (
            NudgeChange::BouncePort {
                device: device.clone(),
                port: *port,
                down_secs: options.down_secs,
            },
            MoveNudgeAction::Bounce,
            info.bounce,
        ),
        (Some(AttachmentChange::SetClientVlan { mac, .. }), _) => (
            NudgeChange::KickClient { mac: *mac },
            MoveNudgeAction::Kick,
            info.kick,
        ),
        _ => return None,
    };
    let mut nudge = MoveNudge {
        action: MoveNudgeAction::None,
        reason: None,
        problem: None,
        change: Some(change),
        reappear_secs: options.reappear_secs,
    };
    if !capable {
        nudge.reason = Some(codes::NUDGE_NO_CAPABILITY.to_owned());
        nudge.change = None;
        return Some(nudge);
    }
    if let Some(change) = &nudge.change
        && let Err(error) = check(state, change)
    {
        nudge.reason = Some(codes::NUDGE_REFUSED.to_owned());
        nudge.problem = Some(MoveL2Problem {
            code: error.code.to_string(),
            detail: error.detail,
        });
        return Some(nudge);
    }
    if !options.enabled {
        nudge.reason = Some(codes::NUDGE_OFF.to_owned());
        return Some(nudge);
    }
    nudge.action = action;
    Some(nudge)
}

/// What one enabled controller answered.
#[derive(Debug, Clone)]
pub(super) struct Read {
    /// The controller.
    pub info: ControllerInfo,
    /// Where its clients are attached, or why it could not be read.
    pub state: Result<ControllerAttachments, CodedError>,
}

/// A guardrail check of the controllers' port (`NetworkControllers::check_attachment`).
pub(super) type Check<'a> =
    &'a (dyn Fn(&ControllerAttachments, &AttachmentChange) -> Result<(), CodedError> + Sync);

fn manual(reason: &str) -> MoveL2 {
    MoveL2 {
        action: MoveL2Action::Manual,
        reason: Some(reason.to_owned()),
        ..MoveL2::default()
    }
}

/// The L2 steps without any controller: manual, because the target has no VLAN or no
/// controller is configured.
pub(super) fn offline(items: &[MoveItem], target: &MoveTarget) -> L2Plans {
    let reason = if target.vid.is_none() {
        codes::L2_NO_VLAN
    } else {
        codes::L2_NO_CONTROLLER
    };
    L2Plans {
        items: shared_or(items, |_| manual(reason)),
        ..L2Plans::default()
    }
}

/// Every item through `decide`, except that a later address of an interface shares the
/// L2 step of the first one.
fn shared_or(items: &[MoveItem], mut decide: impl FnMut(&MoveItem) -> MoveL2) -> Vec<MoveL2> {
    let mut first: BTreeMap<InterfaceId, AddressId> = BTreeMap::new();
    items
        .iter()
        .map(|item| {
            if let Some(interface) = item.interface {
                if let Some(with) = first.get(&interface) {
                    return MoveL2 {
                        action: MoveL2Action::Shared,
                        reason: Some(codes::L2_SAME_INTERFACE.to_owned()),
                        with: Some(*with),
                        ..MoveL2::default()
                    };
                }
                first.insert(interface, item.object.id.into());
            }
            decide(item)
        })
        .collect()
}

/// Reads the enabled network controllers once and decides the L2 step of every item. A
/// controller that cannot be read leaves the devices it might see to a person, with a
/// warning; nothing here fails the preview.
pub(super) async fn plan(
    controllers: &Controllers,
    items: &[MoveItem],
    target: &MoveTarget,
    cx: &RequestCtx,
    nudges: NudgeOptions,
) -> L2Plans {
    let Some(vid) = target.vid else {
        return offline(items, target);
    };
    let Some(port) = controllers.get() else {
        return offline(items, target);
    };
    let user = cx.principal.user();
    let listed = match port.controllers().await {
        Ok(listed) => listed,
        Err(error) => {
            let problem = MoveL2Problem {
                code: error.code.to_string(),
                detail: error.detail.clone(),
            };
            return L2Plans {
                items: shared_or(items, |_| MoveL2 {
                    problem: Some(problem.clone()),
                    ..manual(codes::L2_UNAVAILABLE)
                }),
                warnings: vec![unavailable_warning(None, &error, true)],
                controllers: Vec::new(),
                nudge_offered: false,
            };
        }
    };
    let enabled: Vec<ControllerInfo> = listed.into_iter().filter(|c| c.enabled).collect();
    if enabled.is_empty() {
        return offline(items, target);
    }
    let mut reads = Vec::with_capacity(enabled.len());
    if items.iter().any(|item| item.mac.is_some()) {
        for info in &enabled {
            reads.push(Read {
                info: info.clone(),
                state: port.attachments(info.id, user).await,
            });
        }
    }
    let check = |state: &ControllerAttachments, change: &AttachmentChange| {
        port.check_attachment(state, change)
    };
    let mut plans = decide_all(items, vid, &reads, &check);
    let check_nudge =
        |state: &ControllerAttachments, change: &NudgeChange| port.check_nudge(state, change);
    plans.nudge_offered = nudge_all(&mut plans.items, &reads, nudges, &check_nudge);
    plans.controllers = enabled;
    plans
}

/// Decides the L2 step of every item from the controllers' reads.
pub(super) fn decide_all(
    items: &[MoveItem],
    vid: u16,
    reads: &[Read],
    check: Check<'_>,
) -> L2Plans {
    let decided = shared_or(items, |item| decide(item, vid, reads, check));
    let mut warnings = Vec::new();
    for (item, l2) in items.iter().zip(&decided) {
        if l2.reason.as_deref() == Some(codes::L2_REFUSED_REASON) {
            warnings.push(refused_warning(item, l2));
        }
    }
    let unavailable_matters = decided
        .iter()
        .any(|l2| l2.reason.as_deref() == Some(codes::L2_UNAVAILABLE));
    for read in reads {
        if let Err(error) = &read.state {
            warnings.push(unavailable_warning(
                Some(&read.info),
                error,
                unavailable_matters,
            ));
        }
    }
    L2Plans {
        items: decided,
        warnings,
        controllers: Vec::new(),
        nudge_offered: false,
    }
}

fn refused_warning(item: &MoveItem, l2: &MoveL2) -> PlanWarning {
    let who = item
        .host_name
        .as_ref()
        .map_or_else(|| item.old_ip.to_string(), ToString::to_string);
    let rule = l2.problem.as_ref().map_or("", |p| p.code.as_str());
    PlanWarning {
        code: codes::L2_REFUSED.to_owned(),
        message: format!(
            "a guardrail refuses the network change of {who} ({rule}); a person moves it, if that is intended"
        ),
        object: Some(item.object),
        params: BTreeMap::from([
            ("host".to_owned(), who),
            ("rule".to_owned(), rule.to_owned()),
        ]),
        requires_ack: true,
        acknowledged: false,
    }
}

fn unavailable_warning(
    info: Option<&ControllerInfo>,
    error: &CodedError,
    requires_ack: bool,
) -> PlanWarning {
    let name = info.map_or_else(|| "the network controllers".to_owned(), |c| c.name.clone());
    let mut params = BTreeMap::from([
        ("connector".to_owned(), name.clone()),
        ("error".to_owned(), error.code.to_string()),
    ]);
    if let Some(info) = info {
        params.insert("id".to_owned(), info.id.to_string());
    }
    PlanWarning {
        code: codes::CONTROLLER_UNAVAILABLE.to_owned(),
        message: format!(
            "{name} could not be read ({}: {}); devices it may see are moved by a person",
            error.code, error.detail
        ),
        object: info.map(|c| ObjectRef::from(c.id)),
        params,
        requires_ack,
        acknowledged: false,
    }
}

/// The SSIDs that carry the VLAN, sorted.
fn ssids_of<'a>(states: impl Iterator<Item = &'a ControllerAttachments>, vid: u16) -> Vec<String> {
    let set: BTreeSet<String> = states
        .flat_map(|state| state.wlans.iter())
        .filter(|wlan| wlan.enabled && wlan.vlan == Some(vid))
        .map(|wlan| wlan.ssid.clone())
        .collect();
    set.into_iter().collect()
}

fn decide(item: &MoveItem, vid: u16, reads: &[Read], check: Check<'_>) -> MoveL2 {
    let ok = || reads.iter().filter_map(|read| read.state.as_ref().ok());
    let Some(mac) = item.mac else {
        return MoveL2 {
            ssids: ssids_of(ok(), vid),
            ..manual(codes::L2_NO_MAC)
        };
    };
    let seen: Vec<(&ControllerInfo, &ControllerAttachments, &ControllerClient)> = reads
        .iter()
        .filter_map(|read| {
            let state = read.state.as_ref().ok()?;
            state.client(mac).map(|client| (&read.info, state, client))
        })
        .collect();
    match seen.as_slice() {
        [] => {
            let failed = reads.iter().find_map(|read| read.state.as_ref().err());
            match failed {
                Some(error) => MoveL2 {
                    problem: Some(MoveL2Problem {
                        code: error.code.to_string(),
                        detail: error.detail.clone(),
                    }),
                    ssids: ssids_of(ok(), vid),
                    ..manual(codes::L2_UNAVAILABLE)
                },
                None => MoveL2 {
                    ssids: ssids_of(ok(), vid),
                    ..manual(codes::L2_NOT_SEEN)
                },
            }
        }
        [(info, state, client)] => on_controller(info, state, client, vid, check),
        _ => MoveL2 {
            ssids: ssids_of(ok(), vid),
            ..manual(codes::L2_AMBIGUOUS)
        },
    }
}

/// Where the controller sees a client.
fn attachment_of(state: &ControllerAttachments, client: &ControllerClient) -> MoveAttachment {
    let port = client
        .port
        .and_then(|index| state.port(&client.device, index));
    let profile = port.and_then(|p| p.profile.clone());
    MoveAttachment {
        medium: if client.port.is_some() {
            MoveMedium::Wired
        } else {
            MoveMedium::Wireless
        },
        device: client.device.clone(),
        device_name: state
            .device(&client.device)
            .map_or_else(|| client.device.clone(), |d| d.name.clone()),
        port: client.port,
        port_name: port.and_then(|p| p.name.clone()),
        profile_name: profile.as_deref().map(|id| {
            state
                .profile(id)
                .map_or_else(|| id.to_owned(), |p| p.name.clone())
        }),
        profile,
        ssid: client.ssid.clone(),
        network_name: client.network.as_deref().map(|id| {
            state
                .network(id)
                .map_or_else(|| id.to_owned(), |n| n.name.clone())
        }),
        network: client.network.clone(),
        vlan: client.vlan,
    }
}

fn refuse(mut l2: MoveL2, code: &str, detail: String) -> MoveL2 {
    l2.action = MoveL2Action::Manual;
    l2.reason = Some(codes::L2_REFUSED_REASON.to_owned());
    l2.problem = Some(MoveL2Problem {
        code: code.to_owned(),
        detail,
    });
    l2
}

fn left_to_person(mut l2: MoveL2, reason: &str) -> MoveL2 {
    l2.action = MoveL2Action::Manual;
    l2.reason = Some(reason.to_owned());
    l2
}

/// Whether an access point carries a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carry {
    Yes,
    No,
    Unknown,
}

/// Whether the access point `ap` carries `network`: one of its SSIDs carries the VLAN, or
/// its uplink switch port has the VLAN untagged or a profile with the network; without
/// an uplink port or a profile on it, Tenko cannot tell.
fn carries(
    state: &ControllerAttachments,
    ap: &str,
    network: &ControllerNetwork,
    vid: u16,
) -> Carry {
    if state.wlans.iter().any(|wlan| {
        wlan.enabled && wlan.vlan == Some(vid) && wlan.access_points.iter().any(|a| a == ap)
    }) {
        return Carry::Yes;
    }
    let uplink = state.links.iter().find_map(|link| {
        let far = if link.a.device == ap {
            &link.b
        } else if link.b.device == ap {
            &link.a
        } else {
            return None;
        };
        let index: u16 = far.port.as_deref()?.parse().ok()?;
        state.port(&far.device, index)
    });
    let Some(port) = uplink else {
        return Carry::Unknown;
    };
    if port.native_vlan == Some(vid) {
        return Carry::Yes;
    }
    match port.profile.as_deref().and_then(|id| state.profile(id)) {
        Some(profile)
            if profile.native_network.as_deref() == Some(network.id.as_str())
                || profile.tagged.contains(&network.id) =>
        {
            Carry::Yes
        }
        Some(_) => Carry::No,
        None => Carry::Unknown,
    }
}

#[allow(clippy::too_many_lines)] // The wired and wireless rules side by side, in order.
fn on_controller(
    info: &ControllerInfo,
    state: &ControllerAttachments,
    client: &ControllerClient,
    vid: u16,
    check: Check<'_>,
) -> MoveL2 {
    let mut l2 = MoveL2 {
        connector: Some(info.clone()),
        attachment: Some(attachment_of(state, client)),
        ssids: ssids_of(std::iter::once(state), vid),
        read_at: Some(state.observed_at),
        ..MoveL2::default()
    };
    if client.vlan == Some(vid) {
        l2.action = MoveL2Action::Unchanged;
        l2.reason = Some(codes::L2_ALREADY_THERE.to_owned());
        return l2;
    }
    let networks: Vec<&ControllerNetwork> = state
        .networks
        .iter()
        .filter(|n| n.vlan == Some(vid))
        .collect();
    let Some(network) = networks
        .iter()
        .find(|n| !n.management)
        .or_else(|| networks.first())
        .copied()
    else {
        return left_to_person(l2, codes::L2_NO_NETWORK);
    };
    l2.network_name = Some(network.name.clone());
    if client.management {
        return refuse(
            l2,
            guardrail::MANAGEMENT_CLIENT,
            format!("{} is the controller or Tenko's host", client.mac),
        );
    }
    if network.management {
        return refuse(
            l2,
            guardrail::PROTECTED_NETWORK,
            format!("{} (VLAN {vid}) is a management network", network.name),
        );
    }
    let mac = client.mac;
    let change = if let Some(index) = client.port {
        let Some(port) = state.port(&client.device, index) else {
            return left_to_person(l2, codes::L2_NO_PORT);
        };
        let device = l2
            .attachment
            .as_ref()
            .map_or_else(|| client.device.clone(), |a| a.device_name.clone());
        if port.uplink {
            return refuse(
                l2,
                guardrail::UPLINK,
                format!("port {index} of {device} is an uplink"),
            );
        }
        if port.management {
            return refuse(
                l2,
                guardrail::MANAGEMENT_PORT,
                format!("Tenko or the controller is reached through port {index} of {device}"),
            );
        }
        let others = state.others_on_port(&client.device, index, mac);
        if others > 0 {
            l2.others_on_port = Some(u32::try_from(others).unwrap_or(u32::MAX));
            return left_to_person(l2, codes::L2_SHARED_PORT);
        }
        // A port whose profile has the target network untagged already needs no change.
        if port
            .profile
            .as_deref()
            .and_then(|id| state.profile(id))
            .is_some_and(|p| p.native_network.as_deref() == Some(network.id.as_str()))
        {
            l2.action = MoveL2Action::Unchanged;
            l2.reason = Some(codes::L2_ALREADY_THERE.to_owned());
            return l2;
        }
        let mut candidates: Vec<_> = state
            .profiles
            .iter()
            .filter(|p| p.native_network.as_deref() == Some(network.id.as_str()))
            .collect();
        candidates.sort_by(|a, b| {
            (!a.tagged.is_empty(), &a.name, &a.id).cmp(&(!b.tagged.is_empty(), &b.name, &b.id))
        });
        let Some(profile) = candidates.first() else {
            return left_to_person(l2, codes::L2_NO_PROFILE);
        };
        if port.profile.as_deref() == Some(profile.id.as_str()) {
            l2.action = MoveL2Action::Unchanged;
            l2.reason = Some(codes::L2_ALREADY_THERE.to_owned());
            return l2;
        }
        l2.profile_name = Some(profile.name.clone());
        l2.diff = vec![DiffEntry {
            path: format!("devices/{}/ports/{index}/profile", client.device),
            before: l2.attachment.as_ref().and_then(|a| a.profile_name.clone()),
            after: Some(profile.name.clone()),
        }];
        if port.up {
            l2.notes.push(codes::NOTE_LINK_FLAP.to_owned());
        }
        if port.profile.is_none() {
            l2.notes.push(codes::NOTE_NO_UNDO.to_owned());
        }
        if !profile.tagged.is_empty() {
            l2.notes.push(codes::NOTE_TAGGED.to_owned());
        }
        AttachmentChange::SetPortProfile {
            device: client.device.clone(),
            port: index,
            profile: profile.id.clone(),
        }
    } else {
        if client.ssid.is_none() {
            return left_to_person(l2, codes::L2_NO_PORT);
        }
        match carries(state, &client.device, network, vid) {
            Carry::No if l2.ssids.is_empty() => return left_to_person(l2, codes::L2_NO_SSID),
            Carry::No => return left_to_person(l2, codes::L2_JOIN_SSID),
            Carry::Unknown => l2.notes.push(codes::NOTE_CARRY_UNKNOWN.to_owned()),
            Carry::Yes => {}
        }
        l2.notes.push(codes::NOTE_RECONNECT.to_owned());
        l2.diff = vec![DiffEntry {
            path: format!("clients/{mac}/network"),
            before: l2.attachment.as_ref().and_then(|a| a.network_name.clone()),
            after: Some(network.name.clone()),
        }];
        AttachmentChange::SetClientVlan {
            mac,
            network: network.id.clone(),
        }
    };
    if let Err(error) = check(state, &change) {
        let code = error.code.to_string();
        return refuse(l2, &code, error.detail);
    }
    l2.change = Some(change);
    if !info.writes_enabled {
        return left_to_person(l2, codes::L2_READ_ONLY);
    }
    l2.action = match l2.change {
        Some(AttachmentChange::SetPortProfile { .. }) => MoveL2Action::PortProfile,
        _ => MoveL2Action::ClientVlan,
    };
    l2
}

/// The message arguments of an item's L2 step on top of the step's base arguments.
pub(super) fn args(l2: &MoveL2, base: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut args = base.clone();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            args.insert(key.to_owned(), value);
        }
    };
    put("action", Some(action_name(l2.action).to_owned()));
    put("reason", l2.reason.clone());
    put("connector", l2.connector.as_ref().map(|c| c.name.clone()));
    if let Some(attachment) = &l2.attachment {
        put("device", Some(attachment.device_name.clone()));
        put("port", attachment.port.map(|p| p.to_string()));
        put("port_name", attachment.port_name.clone());
        put("ssid", attachment.ssid.clone());
        put("current_profile", attachment.profile_name.clone());
        put("current_network", attachment.network_name.clone());
    }
    put("profile", l2.profile_name.clone());
    put("network", l2.network_name.clone());
    put("count", l2.others_on_port.map(|n| n.to_string()));
    put("rule", l2.problem.as_ref().map(|p| p.code.clone()));
    if l2.reason.as_deref() == Some(codes::L2_JOIN_SSID) {
        put("ssid", l2.ssids.first().cloned());
    }
    put("ssids", (!l2.ssids.is_empty()).then(|| l2.ssids.join(", ")));
    if let Some(line) = l2.diff.first() {
        put("path", Some(line.path.clone()));
        put("before", line.before.clone());
        put("after", line.after.clone());
    }
    args
}

/// The wire name of an action.
pub(super) const fn action_name(action: MoveL2Action) -> &'static str {
    match action {
        MoveL2Action::PortProfile => "port_profile",
        MoveL2Action::ClientVlan => "client_vlan",
        MoveL2Action::Manual => "manual",
        MoveL2Action::Unchanged => "unchanged",
        MoveL2Action::Shared => "shared",
    }
}

/// The message key of the manual task of an L2 step a person does.
pub(super) fn instruction(l2: &MoveL2) -> &'static str {
    let reason = l2.reason.as_deref().unwrap_or_default();
    match reason {
        codes::L2_NO_VLAN => "ipam.move.task.l2",
        codes::L2_READ_ONLY => match l2.change {
            Some(AttachmentChange::SetPortProfile { .. }) => "ipam.move.task.l2_port",
            _ => "ipam.move.task.l2_client",
        },
        codes::L2_NO_PROFILE => "ipam.move.task.l2_port_vlan",
        codes::L2_SHARED_PORT => "ipam.move.task.l2_shared_port",
        codes::L2_JOIN_SSID => "ipam.move.task.l2_ssid",
        codes::L2_NO_NETWORK => "ipam.move.task.l2_network",
        codes::L2_REFUSED_REASON => "ipam.move.task.l2_refused",
        _ => "ipam.move.task.l2_vlan",
    }
}

/// The English text of an item's L2 step, for the preview and the job.
pub(super) fn text(l2: &MoveL2, who: &str, cidr: &str, vid: Option<u16>) -> String {
    let vid_text = vid.map_or_else(|| format!("the network {cidr}"), |v| format!("VLAN {v}"));
    let connector = l2
        .connector
        .as_ref()
        .map_or("the network controller", |c| c.name.as_str());
    let attachment = l2.attachment.as_ref();
    let device = attachment.map_or("its switch", |a| a.device_name.as_str());
    let port = attachment
        .and_then(|a| a.port)
        .map_or_else(String::new, |p| p.to_string());
    let profile = l2.profile_name.as_deref().unwrap_or("?");
    let network = l2.network_name.as_deref().unwrap_or("?");
    let mac = match &l2.change {
        Some(
            AttachmentChange::SetClientVlan { mac, .. } | AttachmentChange::ClearClientVlan { mac },
        ) => mac.to_string(),
        _ => who.to_owned(),
    };
    match l2.action {
        MoveL2Action::PortProfile => format!(
            "Give port {port} of {device} the port profile {profile} ({vid_text} untagged) through {connector}: dry run, write, read back and compare"
        ),
        MoveL2Action::ClientVlan => format!(
            "Set the VLAN override of {who} to the network {network} ({vid_text}) through {connector}, on {}: dry run, write, read back and compare",
            attachment.and_then(|a| a.ssid.as_deref()).map_or_else(
                || device.to_owned(),
                |ssid| format!("{device} (SSID {ssid})")
            )
        ),
        MoveL2Action::Unchanged => format!("{who} is in {vid_text} already"),
        MoveL2Action::Shared => format!("{who} moves with the other address of its interface"),
        MoveL2Action::Manual => match l2.reason.as_deref().unwrap_or_default() {
            codes::L2_NO_VLAN => format!("Move {who} to {vid_text}"),
            codes::L2_READ_ONLY => match l2.change {
                Some(AttachmentChange::SetPortProfile { .. }) => format!(
                    "On {connector}, give port {port} of {device} the port profile {profile} ({vid_text} untagged); writes through it are off"
                ),
                _ => format!(
                    "On {connector}, set the VLAN override of {mac} to the network {network} ({vid_text}); writes through it are off"
                ),
            },
            codes::L2_NO_PROFILE => format!(
                "Set port {port} of {device} to {vid_text} untagged; no port profile on {connector} carries it"
            ),
            codes::L2_SHARED_PORT => format!(
                "Move {who} to {vid_text} by hand: port {port} of {device} serves {} other devices, and a profile change would move them all",
                l2.others_on_port.unwrap_or_default()
            ),
            codes::L2_JOIN_SSID => format!(
                "Join {who} to the wireless network {}, which carries {vid_text}; its access point {device} does not carry it",
                l2.ssids.first().map_or("?", String::as_str)
            ),
            codes::L2_NO_NETWORK => format!(
                "Create the network for {vid_text} on {connector} (provision the VLAN), then move {who} to it"
            ),
            codes::L2_REFUSED_REASON => format!(
                "Move {who} to {vid_text} by hand if that is intended: Tenko never changes this path ({})",
                l2.problem.as_ref().map_or("guardrail", |p| p.code.as_str())
            ),
            _ => format!(
                "Move {who} to {vid_text}: set its switch port to {vid_text} untagged, or join it to a wireless network that carries {vid_text}"
            ),
        },
    }
}

#[cfg(test)]
mod tests;
