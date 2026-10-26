//! Domain rules of the IPAM crate that `lifecycle.rs` does not cover: cascade deletes and
//! restores, prefix resizing and role changes, ranges and DHCP reservations, VLANs, sites,
//! names, the default tenant and VRF, IPv4 network and broadcast addresses, custom fields,
//! tags, idempotency, `If-Match` revisions, history, audit drafts, dry runs, status
//! transitions, locks and utilization alarms of supernets.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use tenko_core::{
    AddressId, HostId, IdempotencyKey, InterfaceId, ObjectKind, ObjectRef, PrefixId, RangeId,
    RequestCtx, Revision, SiteId, SystemComponent, TenantId, VlanId, VrfId,
    codec::encode_key,
    ipam::{
        Address, AssignmentMode, CustomKind, CustomValue, FieldKey, Host, Prefix, PrefixRole,
        Range, RangeRole, Site, Status, Tag, Tenant, UtilizationAlarm, Vrf,
    },
};
use tenko_ipam::{
    AlarmEvent, AlarmLevel, ChangeAction, IpamCommand, PlanOptions, codes,
    command::{
        AddressPatch, AllocateAddress, CustomFieldInput, CustomFieldPatch, HostPatch,
        InterfaceInput, InterfacePatch, PrefixPatch, RangePatch, SiteInput, SitePatch, TenantInput,
        TenantPatch, UpdateAddress, UpdateCustomField, UpdateHost, UpdateInterface, UpdatePrefix,
        UpdateRange, UpdateSite, UpdateTenant, UpdateVlan, UpdateVrf, VlanInput, VlanPatch,
        VrfPatch,
    },
    custom,
    history::read_history,
    query,
    tables::{
        ADDRESS_IPS, ALARMS, CUSTOM_FIELD_KEYS, CUSTOM_FIELDS, FIELD_USAGE, HISTORY, PREFIX_CIDRS,
        PREFIX_RANGES, TAG_USAGE,
    },
};
use tenko_store::{KeyRange, Mutation, ReadViewExt, Store, tables::AUDIT};

// ----- local builders -----------------------------------------------------------------

fn delete(object: impl Into<ObjectRef>, cascade: bool) -> IpamCommand {
    IpamCommand::Delete {
        object: object.into(),
        expected: None,
        cascade,
    }
}

fn restore(object: impl Into<ObjectRef>) -> IpamCommand {
    IpamCommand::Restore {
        object: object.into(),
        expected: None,
    }
}

fn update_prefix(id: PrefixId, patch: PrefixPatch) -> IpamCommand {
    IpamCommand::UpdatePrefix(UpdatePrefix {
        id,
        expected: None,
        patch,
    })
}

fn resize(id: PrefixId, cidr: &str) -> IpamCommand {
    update_prefix(
        id,
        PrefixPatch {
            cidr: Some(net(cidr)),
            ..PrefixPatch::default()
        },
    )
}

fn describe_prefix(id: PrefixId, text: &str) -> IpamCommand {
    update_prefix(
        id,
        PrefixPatch {
            description: Some(Some(text.to_owned())),
            ..PrefixPatch::default()
        },
    )
}

fn update_address(id: AddressId, patch: AddressPatch) -> IpamCommand {
    IpamCommand::UpdateAddress(UpdateAddress {
        id,
        expected: None,
        patch,
    })
}

fn renumber(id: AddressId, to: &str) -> IpamCommand {
    update_address(
        id,
        AddressPatch {
            ip: Some(ip(to)),
            ..AddressPatch::default()
        },
    )
}

fn update_range(id: RangeId, patch: RangePatch) -> IpamCommand {
    IpamCommand::UpdateRange(UpdateRange {
        id,
        expected: None,
        patch,
    })
}

fn site(name: &str, parent: Option<SiteId>) -> SiteInput {
    SiteInput {
        id: Some(SiteId::generate()),
        name: name.to_owned(),
        parent,
        ad_site: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

fn reparent(id: SiteId, parent: Option<SiteId>) -> IpamCommand {
    IpamCommand::UpdateSite(UpdateSite {
        id,
        expected: None,
        patch: SitePatch {
            parent: Some(parent),
            ..SitePatch::default()
        },
    })
}

fn vlan(vid: u16, name: &str, site: Option<SiteId>) -> VlanInput {
    VlanInput {
        id: Some(VlanId::generate()),
        vid,
        vni: None,
        name: name.to_owned(),
        site,
        status: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

fn tenant(name: &str) -> TenantInput {
    TenantInput {
        id: Some(TenantId::generate()),
        name: name.to_owned(),
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    }
}

fn key(text: &str) -> FieldKey {
    FieldKey::new(text).expect("field key")
}

fn tag(text: &str) -> Tag {
    Tag::new(text).expect("tag")
}

fn tags(items: &[&str]) -> BTreeSet<Tag> {
    items.iter().map(|t| tag(t)).collect()
}

fn field(
    text: &str,
    kind: CustomKind,
    applies_to: &[ObjectKind],
    required: bool,
) -> CustomFieldInput {
    CustomFieldInput {
        id: None,
        key: key(text),
        kind,
        applies_to: applies_to.to_vec(),
        required,
    }
}

fn values(items: &[(&str, CustomValue)]) -> BTreeMap<FieldKey, CustomValue> {
    items.iter().map(|(k, v)| (key(k), v.clone())).collect()
}

/// The history of an object, oldest first.
async fn history_of(
    service: &tenko_ipam::IpamService,
    object: ObjectRef,
) -> Vec<tenko_ipam::HistoryEntry> {
    let view = snapshot(service).await;
    read_history(view.as_ref(), object, None, 1_000, false)
        .expect("history")
        .into_iter()
        .map(|(_, entry)| entry)
        .collect()
}

async fn actions_of(service: &tenko_ipam::IpamService, object: ObjectRef) -> Vec<ChangeAction> {
    history_of(service, object)
        .await
        .into_iter()
        .map(|entry| entry.action)
        .collect()
}

/// The stored alarm event of a prefix, if any level change was ever written.
async fn alarm_of(service: &tenko_ipam::IpamService, prefix: PrefixId) -> Option<AlarmEvent> {
    let view = snapshot(service).await;
    view.get_typed(&ALARMS, &prefix)
        .expect("read")
        .map(|(event, _)| event)
}

// ----- cascade delete, restore and the move to the parent ----------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn cascade_delete_takes_ranges_and_addresses_and_restore_brings_them_back() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let early = address(None, "192.0.2.201");
    let early_id = early.id.expect("id");
    let kept = [
        address(None, "192.0.2.10"),
        address(None, "192.0.2.120"),
        address(None, "192.0.2.200"),
    ];
    let kept_ids: Vec<AddressId> = kept.iter().map(|a| a.id.expect("id")).collect();
    let mut commands = vec![
        IpamCommand::CreatePrefix(network),
        IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.100",
            "192.0.2.150",
            RangeRole::DhcpPool,
        )),
        IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.1",
            "192.0.2.5",
            RangeRole::Infrastructure,
        )),
        IpamCommand::CreateAddress(early),
    ];
    commands.extend(kept.into_iter().map(IpamCommand::CreateAddress));
    let created = run(&service, commands).await;
    let pool_id: RangeId = id_of(created.results[1]);
    let infra_id: RangeId = id_of(created.results[2]);
    let vrf = fetch::<Prefix>(&service, network_id).await.vrf;

    // One address goes first, in a request of its own: the prefix restore leaves it alone.
    run(&service, vec![delete(early_id, false)]).await;

    // Ranges block a plain delete.
    let error = run_err(&service, vec![delete(network_id, false)], codes::IN_USE).await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(error.coded().params["by"], "ranges");
    assert_eq!(error.coded().params["count"], "2");

    // The cascade plan shows one change per object; all but the prefix itself are derived.
    let cx = person();
    let plan = service
        .preview(
            &[delete(network_id, true)],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    assert_eq!(plan.changes.len(), 6, "prefix, two ranges, three addresses");
    assert!(
        plan.changes
            .iter()
            .all(|c| c.action == ChangeAction::Delete)
    );
    assert_eq!(plan.changes.iter().filter(|c| c.derived).count(), 5);
    let applied = service.apply(&plan, &cx).await.expect("apply");

    let view = service.view(Some(applied.revision)).await.expect("view");
    assert!(
        view.get_typed(&PREFIX_CIDRS, &(vrf, net("192.0.2.0/24")))
            .expect("read")
            .is_none(),
        "the network is free again"
    );
    for (n, id) in kept_ids.iter().enumerate() {
        let address = query::get::<Address>(view.as_ref(), *id).expect("address");
        assert!(address.meta.is_deleted(), "address {n}");
        assert!(
            view.get_typed(&ADDRESS_IPS, &(vrf, address.ip))
                .expect("read")
                .is_none()
        );
    }
    for id in [pool_id, infra_id] {
        assert!(
            query::get::<Range>(view.as_ref(), id)
                .expect("range")
                .meta
                .is_deleted()
        );
    }
    // Memberships stay, so that a restore finds the ranges.
    let members = view
        .scan_typed(
            &PREFIX_RANGES,
            KeyRange::prefix(encode_key(&network_id)),
            10,
            false,
        )
        .expect("scan");
    assert_eq!(members.len(), 2);
    assert!(service.tree().prefix(network_id).is_none());

    // The restore brings back what went with the prefix, and only that.
    let restored = run(&service, vec![restore(network_id)]).await;
    let view = service.view(Some(restored.revision)).await.expect("view");
    assert!(
        view.get_typed(&PREFIX_CIDRS, &(vrf, net("192.0.2.0/24")))
            .expect("read")
            .is_some()
    );
    for id in &kept_ids {
        let address = query::get::<Address>(view.as_ref(), *id).expect("address");
        assert!(!address.meta.is_deleted(), "{} is back", address.ip);
        assert_eq!(address.prefix, network_id);
        assert!(
            view.get_typed(&ADDRESS_IPS, &(vrf, address.ip))
                .expect("read")
                .is_some()
        );
    }
    for id in [pool_id, infra_id] {
        assert!(
            !query::get::<Range>(view.as_ref(), id)
                .expect("range")
                .meta
                .is_deleted()
        );
    }
    assert!(
        query::get::<Address>(view.as_ref(), early_id)
            .expect("address")
            .meta
            .is_deleted(),
        "an address deleted earlier stays deleted"
    );

    // The tree followed along: three addresses, 55 reserved by the ranges (5 plus 50 free
    // pool addresses), 254 assignable.
    let utilization = service.tree().utilization(network_id).expect("utilization");
    assert_eq!(
        (
            utilization.capacity,
            utilization.used,
            utilization.reserved,
            utilization.free
        ),
        (254, 3, 55, 196)
    );
    assert_eq!(utilization.by_role[&RangeRole::DhcpPool], (51, 1));
    assert_eq!(utilization.by_role[&RangeRole::Infrastructure], (5, 0));

    assert_eq!(
        actions_of(&service, network_id.into()).await,
        [
            ChangeAction::Create,
            ChangeAction::Delete,
            ChangeAction::Restore
        ]
    );
    assert_eq!(
        actions_of(&service, kept_ids[0].into()).await,
        [
            ChangeAction::Create,
            ChangeAction::Delete,
            ChangeAction::Restore
        ]
    );
    assert_eq!(
        actions_of(&service, early_id.into()).await,
        [ChangeAction::Create, ChangeAction::Delete]
    );
}

#[tokio::test]
async fn deleting_a_network_without_cascade_hands_its_addresses_to_the_parent() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.0/26");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    let items = [
        address(None, "192.0.2.10"),
        address(None, "192.0.2.20"),
        address(None, "192.0.2.100"),
    ];
    let ids: Vec<AddressId> = items.iter().map(|a| a.id.expect("id")).collect();
    let mut commands = vec![
        IpamCommand::CreatePrefix(outer),
        IpamCommand::CreatePrefix(inner),
    ];
    commands.extend(items.into_iter().map(IpamCommand::CreateAddress));
    run(&service, commands).await;
    let vrf = fetch::<Prefix>(&service, outer_id).await.vrf;
    assert_eq!(fetch::<Address>(&service, ids[0]).await.prefix, inner_id);
    assert_eq!(fetch::<Address>(&service, ids[2]).await.prefix, outer_id);

    let cx = person();
    let plan = service
        .preview(
            &[delete(inner_id, false)],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    assert_eq!(plan.changes.len(), 3, "the prefix and two address moves");
    let moves: Vec<_> = plan.changes.iter().filter(|c| c.derived).collect();
    assert_eq!(moves.len(), 2);
    assert!(moves.iter().all(|c| c.action == ChangeAction::Update));
    service.apply(&plan, &cx).await.expect("apply");

    for id in &ids {
        let address = fetch::<Address>(&service, *id).await;
        assert!(!address.meta.is_deleted());
        assert_eq!(address.prefix, outer_id, "{}", address.ip);
    }
    let view = snapshot(&service).await;
    assert!(
        view.get_typed(&ADDRESS_IPS, &(vrf, ip("192.0.2.10")))
            .expect("read")
            .is_some(),
        "the addresses stay in the uniqueness table"
    );
    let trail = history_of(&service, ids[0].into()).await;
    assert_eq!(
        trail.iter().map(|e| e.action).collect::<Vec<_>>(),
        [ChangeAction::Create, ChangeAction::Update]
    );
    let change = trail[1]
        .changes
        .iter()
        .find(|c| c.field == "prefix")
        .expect("prefix change");
    assert_eq!(change.old.as_deref(), Some(inner_id.to_string().as_str()));
    assert_eq!(change.new.as_deref(), Some(outer_id.to_string().as_str()));
    assert_eq!(
        service.tree().containing(vrf, ip("192.0.2.10")),
        Some(outer_id)
    );
    let utilization = service.tree().utilization(outer_id).expect("utilization");
    assert_eq!((utilization.capacity, utilization.used), (256, 3));

    // Restoring the network takes its addresses back from the supernet.
    run(&service, vec![restore(inner_id)]).await;
    assert_eq!(fetch::<Address>(&service, ids[0]).await.prefix, inner_id);
    assert_eq!(fetch::<Address>(&service, ids[1]).await.prefix, inner_id);
    assert_eq!(fetch::<Address>(&service, ids[2]).await.prefix, outer_id);
    assert_eq!(
        service.tree().containing(vrf, ip("192.0.2.20")),
        Some(inner_id)
    );
}

#[tokio::test]
async fn deleting_a_prefix_with_addresses_and_no_parent_is_in_use() {
    let (service, _) = service();
    let network = prefix(None, "198.51.100.0/24");
    let network_id = network.id.expect("id");
    let items = [
        address(None, "198.51.100.10"),
        address(None, "198.51.100.11"),
    ];
    let ids: Vec<AddressId> = items.iter().map(|a| a.id.expect("id")).collect();
    let mut commands = vec![IpamCommand::CreatePrefix(network)];
    commands.extend(items.into_iter().map(IpamCommand::CreateAddress));
    run(&service, commands).await;

    let error = run_err(&service, vec![delete(network_id, false)], codes::IN_USE).await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(error.coded().params["by"], "addresses");
    assert_eq!(error.coded().params["count"], "2");
    assert!(
        !fetch::<Prefix>(&service, network_id)
            .await
            .meta
            .is_deleted()
    );
    assert!(!fetch::<Address>(&service, ids[0]).await.meta.is_deleted());

    // The cascade removes everything, and an empty prefix needs no cascade.
    run(&service, vec![delete(network_id, true)]).await;
    assert!(fetch::<Address>(&service, ids[0]).await.meta.is_deleted());
    let empty = prefix(None, "203.0.113.0/24");
    let empty_id = empty.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(empty)]).await;
    run(&service, vec![delete(empty_id, false)]).await;
}

// ----- resize and role changes ----------------------------------------------------------

#[tokio::test]
async fn a_resize_that_would_orphan_contents_is_refused() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let high = address(None, "192.0.2.200");
    let high_id = high.id.expect("id");
    let created = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateAddress(high),
            IpamCommand::CreateRange(range(
                network_id,
                "192.0.2.150",
                "192.0.2.160",
                RangeRole::Reserved,
            )),
        ],
    )
    .await;
    let range_id: RangeId = id_of(created.results[2]);
    let vrf = fetch::<Prefix>(&service, network_id).await.vrf;

    let error = run_err(
        &service,
        vec![resize(network_id, "192.0.2.0/25")],
        codes::PREFIX_RESIZE_ORPHANS,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(
        error.coded().params["count"],
        "2",
        "the address and the range"
    );
    assert_eq!(
        fetch::<Prefix>(&service, network_id).await.cidr,
        net("192.0.2.0/24")
    );

    // Another family is not a resize.
    let error = run_err(
        &service,
        vec![resize(network_id, "2001:db8::/48")],
        codes::VALIDATION,
    )
    .await;
    assert_eq!(status_of(&error), 400);

    // Once the contents are gone, the prefix shrinks and grows again.
    run(
        &service,
        vec![delete(high_id, false), delete(range_id, false)],
    )
    .await;
    run(&service, vec![resize(network_id, "192.0.2.0/25")]).await;
    let view = snapshot(&service).await;
    assert!(
        view.get_typed(&PREFIX_CIDRS, &(vrf, net("192.0.2.0/25")))
            .expect("read")
            .is_some()
    );
    assert!(
        view.get_typed(&PREFIX_CIDRS, &(vrf, net("192.0.2.0/24")))
            .expect("read")
            .is_none()
    );
    assert_eq!(
        service.tree().prefix(network_id),
        Some((vrf, net("192.0.2.0/25")))
    );
    run(&service, vec![resize(network_id, "192.0.2.0/24")]).await;
    assert_eq!(
        service.tree().prefix(network_id),
        Some((vrf, net("192.0.2.0/24")))
    );
}

#[tokio::test]
async fn a_resize_that_grows_the_prefix_adopts_addresses_from_the_parent() {
    let (service, _) = service();
    let outer = supernet(None, "198.51.100.0/24");
    let inner = prefix(None, "198.51.100.0/26");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    let (inside, beyond) = (
        address(None, "198.51.100.100"),
        address(None, "198.51.100.200"),
    );
    let (inside_id, beyond_id) = (inside.id.expect("id"), beyond.id.expect("id"));
    let created = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
            IpamCommand::CreateAddress(inside),
            IpamCommand::CreateAddress(beyond),
        ],
    )
    .await;
    // Addresses directly in a supernet are allowed, with a warning.
    assert!(
        created
            .warnings
            .iter()
            .any(|w| w.code == codes::WARN_ADDRESS_IN_SUPERNET)
    );
    assert_eq!(fetch::<Address>(&service, inside_id).await.prefix, outer_id);

    let cx = person();
    let plan = service
        .preview(
            &[resize(inner_id, "198.51.100.0/25")],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    let adopted: Vec<_> = plan.changes.iter().filter(|c| c.derived).collect();
    assert_eq!(adopted.len(), 1, "one address moves");
    assert_eq!(adopted[0].object, ObjectRef::from(inside_id));
    service.apply(&plan, &cx).await.expect("apply");
    assert_eq!(fetch::<Address>(&service, inside_id).await.prefix, inner_id);
    assert_eq!(fetch::<Address>(&service, beyond_id).await.prefix, outer_id);
    let utilization = service.tree().utilization(inner_id).expect("utilization");
    assert_eq!((utilization.capacity, utilization.used), (126, 1));

    // Shrinking back would leave the adopted address outside.
    run_err(
        &service,
        vec![resize(inner_id, "198.51.100.0/26")],
        codes::PREFIX_RESIZE_ORPHANS,
    )
    .await;
}

#[tokio::test]
async fn growing_a_network_around_a_sibling_overlaps_unless_it_becomes_a_supernet() {
    let (service, _) = service();
    let outer = supernet(None, "203.0.113.0/24");
    let first = prefix(None, "203.0.113.0/26");
    let second = prefix(None, "203.0.113.64/26");
    let (first_id, second_id) = (first.id.expect("id"), second.id.expect("id"));
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(first),
            IpamCommand::CreatePrefix(second),
        ],
    )
    .await;
    let error = run_err(
        &service,
        vec![resize(first_id, "203.0.113.0/25")],
        codes::PREFIX_OVERLAP,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    run(
        &service,
        vec![update_prefix(
            first_id,
            PrefixPatch {
                cidr: Some(net("203.0.113.0/25")),
                role: Some(PrefixRole::Supernet),
                ..PrefixPatch::default()
            },
        )],
    )
    .await;
    assert_eq!(service.tree().children(first_id), [second_id]);
    let vrf = fetch::<Prefix>(&service, first_id).await.vrf;
    let nodes = service.tree().tree(vrf, None, None);
    let node = nodes.iter().find(|n| n.id == second_id).expect("node");
    assert_eq!(node.parent, Some(first_id));
    assert_eq!(node.depth, 2);
}

#[tokio::test]
async fn growing_a_supernet_around_its_own_parent_hands_the_addresses_down() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = supernet(None, "192.0.2.0/25");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    let item = address(None, "192.0.2.10");
    let address_id = item.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
            IpamCommand::CreateAddress(item),
        ],
    )
    .await;
    let vrf = fetch::<Prefix>(&service, outer_id).await.vrf;
    assert_eq!(
        fetch::<Address>(&service, address_id).await.prefix,
        inner_id
    );

    // The inner supernet grows to /23 and so becomes the parent of the former outer one: the
    // address is now inside the /24, the most specific live prefix containing it (IPAM-02).
    run(&service, vec![resize(inner_id, "192.0.2.0/23")]).await;
    assert_eq!(
        service.tree().containing(vrf, ip("192.0.2.10")),
        Some(outer_id)
    );
    assert_eq!(
        fetch::<Address>(&service, address_id).await.prefix,
        outer_id,
        "the address must follow the most specific prefix"
    );
}

// ----- plans that are overtaken by an address -------------------------------------------------
//
// A plan that moves addresses between prefixes reads the addresses of a range without a
// precondition when it finds none. An address created in the meantime must still end up in the
// most specific prefix: the plan is refused as stale (and planned again), or it adopts the
// address.

/// Applies a previewed plan after an address arrived; when the plan is stale, plans again.
async fn apply_after_late_address(
    service: &tenko_ipam::IpamService,
    plan: &tenko_ipam::IpamPlan,
    cx: &RequestCtx,
) {
    match service.apply(plan, cx).await {
        Ok(_) => {}
        Err(error) => {
            assert_eq!(error.code_str(), codes::PLAN_STALE);
            service
                .execute(&plan.commands, cx, &PlanOptions::default())
                .await
                .expect("planned again");
        }
    }
}

#[tokio::test]
async fn a_new_prefix_planned_before_an_address_arrives_still_adopts_it() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.160/27");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    run(&service, vec![IpamCommand::CreatePrefix(outer)]).await;
    let cx = person();
    let plan = service
        .preview(
            &[IpamCommand::CreatePrefix(inner)],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    let late = address(None, "192.0.2.181");
    let late_id = late.id.expect("id");
    run(&service, vec![IpamCommand::CreateAddress(late)]).await;
    assert_eq!(fetch::<Address>(&service, late_id).await.prefix, outer_id);

    apply_after_late_address(&service, &plan, &cx).await;
    assert_eq!(
        fetch::<Address>(&service, late_id).await.prefix,
        inner_id,
        "192.0.2.181 lies in 192.0.2.160/27, the most specific prefix"
    );
}

#[tokio::test]
async fn a_resize_planned_before_an_address_arrives_still_adopts_it() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.160/28");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
        ],
    )
    .await;
    let cx = person();
    let plan = service
        .preview(
            &[resize(inner_id, "192.0.2.160/27")],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    let late = address(None, "192.0.2.181");
    let late_id = late.id.expect("id");
    run(&service, vec![IpamCommand::CreateAddress(late)]).await;
    assert_eq!(fetch::<Address>(&service, late_id).await.prefix, outer_id);

    apply_after_late_address(&service, &plan, &cx).await;
    assert_eq!(
        fetch::<Prefix>(&service, inner_id).await.cidr,
        net("192.0.2.160/27")
    );
    assert_eq!(
        fetch::<Address>(&service, late_id).await.prefix,
        inner_id,
        "192.0.2.181 lies in the grown prefix"
    );
}

#[tokio::test]
async fn a_restore_planned_before_an_address_arrives_still_adopts_it() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.160/27");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
        ],
    )
    .await;
    run(&service, vec![delete(inner_id, false)]).await;
    let cx = person();
    let plan = service
        .preview(&[restore(inner_id)], &cx, &PlanOptions::default(), None)
        .await
        .expect("preview");
    let late = address(None, "192.0.2.181");
    let late_id = late.id.expect("id");
    run(&service, vec![IpamCommand::CreateAddress(late)]).await;
    assert_eq!(fetch::<Address>(&service, late_id).await.prefix, outer_id);

    apply_after_late_address(&service, &plan, &cx).await;
    assert!(!fetch::<Prefix>(&service, inner_id).await.meta.is_deleted());
    assert_eq!(
        fetch::<Address>(&service, late_id).await.prefix,
        inner_id,
        "192.0.2.181 lies in the restored prefix"
    );
}

#[tokio::test]
async fn a_delete_planned_before_an_address_arrives_is_refused_as_stale() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.160/27");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
        ],
    )
    .await;
    let cx = person();
    let plan = service
        .preview(
            &[delete(inner_id, false)],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    let late = address(None, "192.0.2.181");
    let late_id = late.id.expect("id");
    run(&service, vec![IpamCommand::CreateAddress(late)]).await;
    assert_eq!(fetch::<Address>(&service, late_id).await.prefix, inner_id);

    apply_after_late_address(&service, &plan, &cx).await;
    assert!(fetch::<Prefix>(&service, inner_id).await.meta.is_deleted());
    assert_eq!(
        fetch::<Address>(&service, late_id).await.prefix,
        outer_id,
        "the address moved up with the delete"
    );
}

#[tokio::test]
async fn role_changes_respect_children_and_ranges() {
    let (service, _) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let child = prefix(None, "192.0.2.0/26");
    let lone = supernet(None, "198.51.100.0/24");
    let ranged = prefix(None, "203.0.113.0/24");
    let (outer_id, lone_id, ranged_id) = (
        outer.id.expect("id"),
        lone.id.expect("id"),
        ranged.id.expect("id"),
    );
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(child),
            IpamCommand::CreatePrefix(lone),
            IpamCommand::CreatePrefix(ranged),
            IpamCommand::CreateRange(range(
                ranged_id,
                "203.0.113.10",
                "203.0.113.20",
                RangeRole::DhcpPool,
            )),
        ],
    )
    .await;
    let set_role = |id, role| {
        vec![update_prefix(
            id,
            PrefixPatch {
                role: Some(role),
                ..PrefixPatch::default()
            },
        )]
    };
    let error = run_err(
        &service,
        set_role(outer_id, PrefixRole::Network),
        codes::PREFIX_HAS_CHILDREN,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    let error = run_err(
        &service,
        set_role(ranged_id, PrefixRole::Supernet),
        codes::PREFIX_HAS_RANGES,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(
        fetch::<Prefix>(&service, outer_id).await.role,
        PrefixRole::Supernet
    );
    assert_eq!(
        fetch::<Prefix>(&service, ranged_id).await.role,
        PrefixRole::Network
    );

    // Without children or ranges, both directions work.
    run(&service, set_role(lone_id, PrefixRole::Network)).await;
    assert_eq!(
        fetch::<Prefix>(&service, lone_id).await.role,
        PrefixRole::Network
    );
    run(&service, set_role(lone_id, PrefixRole::Supernet)).await;
    assert_eq!(
        fetch::<Prefix>(&service, lone_id).await.role,
        PrefixRole::Supernet
    );
}

// ----- ranges and DHCP reservations ----------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn ranges_refuse_overlap_supernets_and_space_outside_the_network() {
    let (service, _) = service();
    let outer = supernet(None, "198.51.100.0/24");
    let network = prefix(None, "192.0.2.0/24");
    let (outer_id, network_id) = (outer.id.expect("id"), network.id.expect("id"));
    let created = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateRange(range(
                network_id,
                "192.0.2.100",
                "192.0.2.199",
                RangeRole::DhcpPool,
            )),
        ],
    )
    .await;
    let pool_id: RangeId = id_of(created.results[2]);

    for (first, last) in [
        ("192.0.2.150", "192.0.2.210"),
        ("192.0.2.90", "192.0.2.100"),
        ("192.0.2.199", "192.0.2.210"),
        ("192.0.2.120", "192.0.2.130"),
        ("192.0.2.1", "192.0.2.250"),
    ] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateRange(range(
                network_id,
                first,
                last,
                RangeRole::Reserved,
            ))],
            codes::RANGE_OVERLAP,
        )
        .await;
        assert_eq!(status_of(&error), 409, "{first}-{last}");
    }
    // Touching ranges do not overlap.
    let adjacent = run(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.200",
            "192.0.2.210",
            RangeRole::Reserved,
        ))],
    )
    .await;
    let adjacent_id: RangeId = id_of(adjacent.results[0]);

    // A supernet holds no ranges.
    let error = run_err(
        &service,
        vec![IpamCommand::CreateRange(range(
            outer_id,
            "198.51.100.10",
            "198.51.100.20",
            RangeRole::Reserved,
        ))],
        codes::RANGE_NOT_IN_NETWORK,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    // The range stays inside its network and ascends within one family.
    run_err(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.250",
            "192.0.3.5",
            RangeRole::Reserved,
        ))],
        codes::RANGE_OUTSIDE_PREFIX,
    )
    .await;
    let error = run_err(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.60",
            "192.0.2.50",
            RangeRole::Reserved,
        ))],
        codes::VALIDATION,
    )
    .await;
    assert_eq!(status_of(&error), 400);
    run_err(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.50",
            "2001:db8::50",
            RangeRole::Reserved,
        ))],
        codes::VALIDATION,
    )
    .await;

    // Updates are checked the same way.
    run_err(
        &service,
        vec![update_range(
            adjacent_id,
            RangePatch {
                first: Some(ip("192.0.2.150")),
                ..RangePatch::default()
            },
        )],
        codes::RANGE_OVERLAP,
    )
    .await;
    run(
        &service,
        vec![update_range(
            adjacent_id,
            RangePatch {
                last: Some(ip("192.0.2.220")),
                ..RangePatch::default()
            },
        )],
    )
    .await;

    // A deleted range frees its space; restoring it into taken space is refused.
    run(&service, vec![delete(pool_id, false)]).await;
    let replacement = run(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.150",
            "192.0.2.160",
            RangeRole::Reserved,
        ))],
    )
    .await;
    assert_eq!(replacement.results.len(), 1);
    run_err(&service, vec![restore(pool_id)], codes::RANGE_OVERLAP).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn dhcp_pools_and_reservations_exclude_each_other() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let (printer, printer_if) = host(
        "printer",
        AssignmentMode::Reserved,
        Some("00-00-5E-00-53-10"),
    );
    let (nas, nas_eth) = host("nas01", AssignmentMode::Static, Some("00-00-5E-00-53-11"));
    let mut reservation = address(None, "192.0.2.50");
    reservation.interface = Some(printer_if);
    let created = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateHost(printer),
            IpamCommand::CreateHost(nas),
            IpamCommand::CreateAddress(reservation),
            IpamCommand::CreateRange(range(
                network_id,
                "192.0.2.40",
                "192.0.2.60",
                RangeRole::Reserved,
            )),
        ],
    )
    .await;
    let held_id: RangeId = id_of(created.results[4]);

    // A reserved-role range may cover the reservation; turning it into a pool may not.
    let error = run_err(
        &service,
        vec![update_range(
            held_id,
            RangePatch {
                role: Some(RangeRole::DhcpPool),
                ..RangePatch::default()
            },
        )],
        codes::RANGE_COVERS_RESERVATION,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(error.coded().params["host"], "printer");
    assert_eq!(error.coded().params["ip"], "192.0.2.50");
    run(&service, vec![delete(held_id, false)]).await;
    run_err(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.40",
            "192.0.2.60",
            RangeRole::DhcpPool,
        ))],
        codes::RANGE_COVERS_RESERVATION,
    )
    .await;

    // A pool beside the reservation is fine, but may not grow over it.
    let created = run(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.101",
            "192.0.2.120",
            RangeRole::DhcpPool,
        ))],
    )
    .await;
    let pool_id: RangeId = id_of(created.results[0]);
    run_err(
        &service,
        vec![update_range(
            pool_id,
            RangePatch {
                first: Some(ip("192.0.2.45")),
                ..RangePatch::default()
            },
        )],
        codes::RANGE_COVERS_RESERVATION,
    )
    .await;

    // A reserved host's address inside the pool is refused.
    let mut inside = address(None, "192.0.2.110");
    inside.interface = Some(printer_if);
    let error = run_err(
        &service,
        vec![IpamCommand::CreateAddress(inside)],
        codes::ADDRESS_IN_DHCP_POOL,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    // A static host or an address without a host only warns.
    let mut static_inside = address(None, "192.0.2.111");
    static_inside.interface = Some(nas_eth);
    let static_id = static_inside.id.expect("id");
    let applied = run(&service, vec![IpamCommand::CreateAddress(static_inside)]).await;
    let warning = applied
        .warnings
        .iter()
        .find(|w| w.code == codes::ADDRESS_IN_DHCP_POOL)
        .expect("warning");
    assert!(!warning.requires_ack);
    let applied = run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.112"))],
    )
    .await;
    assert!(
        applied
            .warnings
            .iter()
            .any(|w| w.code == codes::ADDRESS_IN_DHCP_POOL)
    );

    // Assigning an address inside the pool to the reserved host is refused as well.
    run_err(
        &service,
        vec![update_address(
            static_id,
            AddressPatch {
                interface: Some(Some(printer_if)),
                ..AddressPatch::default()
            },
        )],
        codes::ADDRESS_IN_DHCP_POOL,
    )
    .await;
    // Reserved-role ranges only warn about addresses inside them.
    run(
        &service,
        vec![IpamCommand::CreateRange(range(
            network_id,
            "192.0.2.200",
            "192.0.2.210",
            RangeRole::Reserved,
        ))],
    )
    .await;
    let applied = run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.205"))],
    )
    .await;
    assert!(
        applied
            .warnings
            .iter()
            .any(|w| w.code == codes::WARN_ADDRESS_IN_RANGE)
    );
}

#[tokio::test]
async fn switching_a_host_to_reserved_inside_a_pool_is_refused() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let (nas, nas_eth) = host("nas01", AssignmentMode::Static, Some("00-00-5E-00-53-11"));
    let nas_id = nas.id.expect("id");
    let mut inside = address(None, "192.0.2.111");
    inside.interface = Some(nas_eth);
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateHost(nas),
            IpamCommand::CreateAddress(inside),
            IpamCommand::CreateRange(range(
                network_id,
                "192.0.2.101",
                "192.0.2.120",
                RangeRole::DhcpPool,
            )),
        ],
    )
    .await;
    // IPAM-23: a reservation that overlaps a dynamic pool is a conflict, however it arises.
    run_err(
        &service,
        vec![IpamCommand::SetMode {
            host: nas_id,
            mode: AssignmentMode::Reserved,
            expected: None,
        }],
        codes::ADDRESS_IN_DHCP_POOL,
    )
    .await;
    assert_eq!(
        fetch::<Host>(&service, nas_id).await.mode,
        AssignmentMode::Static
    );
}

// ----- VLANs and sites ----------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn vlan_ids_are_unique_per_site() {
    let (service, _) = service();
    let (berlin, paris) = (site("berlin", None), site("paris", None));
    let (berlin_id, paris_id) = (berlin.id.expect("id"), paris.id.expect("id"));
    run(
        &service,
        vec![
            IpamCommand::CreateSite(berlin),
            IpamCommand::CreateSite(paris),
        ],
    )
    .await;
    let (ten_berlin, ten_paris, ten_global, twenty_berlin) = (
        vlan(10, "users", Some(berlin_id)),
        vlan(10, "users", Some(paris_id)),
        vlan(10, "users", None),
        vlan(20, "voice", Some(berlin_id)),
    );
    let ids: Vec<VlanId> = [&ten_berlin, &ten_paris, &ten_global, &twenty_berlin]
        .iter()
        .map(|v| v.id.expect("id"))
        .collect();
    run(
        &service,
        vec![
            IpamCommand::CreateVlan(ten_berlin),
            IpamCommand::CreateVlan(ten_paris),
            IpamCommand::CreateVlan(ten_global),
            IpamCommand::CreateVlan(twenty_berlin),
        ],
    )
    .await;
    let patch = |id: VlanId, patch: VlanPatch| {
        vec![IpamCommand::UpdateVlan(UpdateVlan {
            id,
            expected: None,
            patch,
        })]
    };

    for (site, label) in [(Some(berlin_id), "berlin"), (None, "global")] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateVlan(vlan(10, "again", site))],
            codes::VLAN_DUPLICATE,
        )
        .await;
        assert_eq!(status_of(&error), 409, "{label}");
        assert_eq!(error.coded().params["vid"], "10");
    }
    // Renumbering or moving onto a taken id is refused.
    run_err(
        &service,
        patch(
            ids[3],
            VlanPatch {
                vid: Some(10),
                ..VlanPatch::default()
            },
        ),
        codes::VLAN_DUPLICATE,
    )
    .await;
    run_err(
        &service,
        patch(
            ids[1],
            VlanPatch {
                site: Some(Some(berlin_id)),
                ..VlanPatch::default()
            },
        ),
        codes::VLAN_DUPLICATE,
    )
    .await;
    run_err(
        &service,
        patch(
            ids[1],
            VlanPatch {
                site: Some(None),
                ..VlanPatch::default()
            },
        ),
        codes::VLAN_DUPLICATE,
    )
    .await;
    // A free target works, and frees the old id.
    run(
        &service,
        patch(
            ids[3],
            VlanPatch {
                site: Some(Some(paris_id)),
                ..VlanPatch::default()
            },
        ),
    )
    .await;
    run(
        &service,
        vec![IpamCommand::CreateVlan(vlan(20, "voice", Some(berlin_id)))],
    )
    .await;

    // A deleted VLAN frees its id; restoring into a taken id is refused.
    run(&service, vec![delete(ids[0], false)]).await;
    run(
        &service,
        vec![IpamCommand::CreateVlan(vlan(10, "users2", Some(berlin_id)))],
    )
    .await;
    run_err(&service, vec![restore(ids[0])], codes::VLAN_DUPLICATE).await;

    // Range checks and users.
    for vid in [0, 4095] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateVlan(vlan(vid, "bad", None))],
            codes::VALIDATION,
        )
        .await;
        assert_eq!(status_of(&error), 400, "{vid}");
    }
    let mut big = vlan(30, "overlay", None);
    big.vni = Some(16_777_216);
    run_err(
        &service,
        vec![IpamCommand::CreateVlan(big)],
        codes::VALIDATION,
    )
    .await;
    let mut tagged = prefix(None, "192.0.2.0/24");
    tagged.vlan = Some(ids[2]);
    run(&service, vec![IpamCommand::CreatePrefix(tagged)]).await;
    let error = run_err(&service, vec![delete(ids[2], false)], codes::IN_USE).await;
    assert_eq!(error.coded().params["by"], "prefixes");
}

#[tokio::test]
async fn sites_cannot_be_their_own_ancestors() {
    let (service, _) = service();
    let a = site("hq", None);
    let a_id = a.id.expect("id");
    let b = site("branch", Some(a_id));
    let b_id = b.id.expect("id");
    let c = site("lab", Some(b_id));
    let c_id = c.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreateSite(a),
            IpamCommand::CreateSite(b),
            IpamCommand::CreateSite(c),
        ],
    )
    .await;
    for (child, parent) in [(a_id, a_id), (a_id, b_id), (a_id, c_id), (b_id, c_id)] {
        let error = run_err(
            &service,
            vec![reparent(child, Some(parent))],
            codes::SITE_CYCLE,
        )
        .await;
        assert_eq!(status_of(&error), 409);
    }
    assert_eq!(fetch::<Site>(&service, a_id).await.parent, None);
    // A parent that is not an ancestor is fine, and so is no parent.
    run(&service, vec![reparent(c_id, Some(a_id))]).await;
    run(&service, vec![reparent(b_id, None)]).await;
    // A missing parent is a reference error; a parent with children cannot go.
    run_err(
        &service,
        vec![IpamCommand::CreateSite(site(
            "ghost",
            Some(SiteId::generate()),
        ))],
        codes::REFERENCE_MISSING,
    )
    .await;
    let error = run_err(&service, vec![delete(a_id, false)], codes::IN_USE).await;
    assert_eq!(error.coded().params["by"], "sites");
    run(&service, vec![delete(c_id, false), delete(a_id, false)]).await;
}

// ----- names ------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn names_are_unique_in_their_scope_without_regard_to_case() {
    let (service, _) = service();
    let lab = tenant("Lab");
    let lab_id = lab.id.expect("id");
    let other = tenant("Other");
    let other_id = other.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreateTenant(lab),
            IpamCommand::CreateTenant(other),
        ],
    )
    .await;
    for name in ["lab", "LAB", "  Lab  "] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateTenant(tenant(name))],
            codes::NAME_TAKEN,
        )
        .await;
        assert_eq!(status_of(&error), 409, "{name}");
        assert_eq!(error.coded().params["kind"], "tenant");
    }
    run_err(
        &service,
        vec![IpamCommand::UpdateTenant(UpdateTenant {
            id: other_id,
            expected: None,
            patch: TenantPatch {
                name: Some("lAb".to_owned()),
                ..TenantPatch::default()
            },
        })],
        codes::NAME_TAKEN,
    )
    .await;
    // Renaming to its own name in another case is the same object.
    run(
        &service,
        vec![IpamCommand::UpdateTenant(UpdateTenant {
            id: lab_id,
            expected: None,
            patch: TenantPatch {
                name: Some("LAB".to_owned()),
                ..TenantPatch::default()
            },
        })],
    )
    .await;
    assert_eq!(fetch::<Tenant>(&service, lab_id).await.name, "LAB");
    // A deleted name is free; restoring into a taken name is refused.
    run(&service, vec![delete(lab_id, false)]).await;
    run(&service, vec![IpamCommand::CreateTenant(tenant("lab"))]).await;
    run_err(&service, vec![restore(lab_id)], codes::NAME_TAKEN).await;

    // VRF names are per tenant.
    let mut red = vrf("red");
    red.tenant = Some(other_id);
    run(&service, vec![IpamCommand::CreateVrf(red)]).await;
    let mut again = vrf("RED");
    again.tenant = Some(other_id);
    let error = run_err(
        &service,
        vec![IpamCommand::CreateVrf(again)],
        codes::NAME_TAKEN,
    )
    .await;
    assert_eq!(error.coded().params["kind"], "VRF");
    let default_tenant_vrf = vrf("red");
    run(
        &service,
        vec![IpamCommand::CreateVrf(default_tenant_vrf.clone())],
    )
    .await;
    let blue = vrf("blue");
    let blue_id = blue.id.expect("id");
    run(&service, vec![IpamCommand::CreateVrf(blue)]).await;
    run_err(
        &service,
        vec![IpamCommand::UpdateVrf(UpdateVrf {
            id: blue_id,
            expected: None,
            patch: VrfPatch {
                name: Some("Red".to_owned()),
                ..VrfPatch::default()
            },
        })],
        codes::NAME_TAKEN,
    )
    .await;

    // Site names are global, host names per tenant, interface names per host.
    run(&service, vec![IpamCommand::CreateSite(site("hq", None))]).await;
    run_err(
        &service,
        vec![IpamCommand::CreateSite(site("HQ", None))],
        codes::NAME_TAKEN,
    )
    .await;
    let (nas, _) = host("nas01", AssignmentMode::Static, None);
    let nas_id = nas.id.expect("id");
    let (nas_again, _) = host("nas01", AssignmentMode::Static, None);
    run(&service, vec![IpamCommand::CreateHost(nas)]).await;
    let error = run_err(
        &service,
        vec![IpamCommand::CreateHost(nas_again)],
        codes::NAME_TAKEN,
    )
    .await;
    assert_eq!(error.coded().params["kind"], "host");
    let (mut elsewhere, _) = host("nas01", AssignmentMode::Static, None);
    elsewhere.tenant = Some(other_id);
    run(&service, vec![IpamCommand::CreateHost(elsewhere)]).await;
    let interface = |name: &str, host: HostId| InterfaceInput {
        id: None,
        host: Some(host),
        name: name.to_owned(),
        mac: None,
        duid: None,
        client_id: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
    };
    run(
        &service,
        vec![IpamCommand::CreateInterface(interface("eth1", nas_id))],
    )
    .await;
    for name in ["eth1", "ETH1", "eth0"] {
        run_err(
            &service,
            vec![IpamCommand::CreateInterface(interface(name, nas_id))],
            codes::NAME_TAKEN,
        )
        .await;
    }

    // Custom field keys are names too.
    let owner = field("owner", CustomKind::Text, &[ObjectKind::Prefix], false);
    run(
        &service,
        vec![IpamCommand::CreateCustomField(owner.clone())],
    )
    .await;
    run_err(
        &service,
        vec![IpamCommand::CreateCustomField(owner)],
        codes::NAME_TAKEN,
    )
    .await;
}

#[tokio::test]
async fn the_default_tenant_and_vrf_are_created_once_and_reused() {
    let (service, _) = service();
    let cx = person();
    let plan = service
        .preview(
            &[
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreatePrefix(prefix(None, "198.51.100.0/24")),
            ],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    assert_eq!(plan.changes.len(), 4);
    let derived: Vec<ObjectKind> = plan
        .changes
        .iter()
        .filter(|c| c.derived)
        .map(|c| c.object.kind)
        .collect();
    assert_eq!(derived.len(), 2);
    assert!(derived.contains(&ObjectKind::Tenant) && derived.contains(&ObjectKind::Vrf));
    let lines = plan.summary().lines;
    for expected in ["1 tenant created", "1 VRF created", "2 prefixes created"] {
        assert!(lines.contains(&expected.to_owned()), "{lines:?}");
    }
    service.apply(&plan, &cx).await.expect("apply");

    let tenants = all_of::<Tenant>(&service).await;
    let vrfs = all_of::<Vrf>(&service).await;
    assert_eq!((tenants.len(), vrfs.len()), (1, 1));
    assert_eq!(
        (tenants[0].name.as_str(), vrfs[0].name.as_str()),
        ("default", "default")
    );
    assert_eq!(vrfs[0].tenant, tenants[0].id);

    // The next requests reuse them, whatever they create.
    let cx = person();
    let plan = service
        .preview(
            &[
                IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/24")),
                IpamCommand::CreateAddress(address(None, "203.0.113.5")),
                IpamCommand::CreateAddress(address(None, "192.0.2.5")),
            ],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    assert!(plan.changes.iter().all(|c| !c.derived));
    service.apply(&plan, &cx).await.expect("apply");
    assert_eq!(all_of::<Tenant>(&service).await.len(), 1);
    assert_eq!(all_of::<Vrf>(&service).await.len(), 1);
    for prefix in all_of::<Prefix>(&service).await {
        assert_eq!(prefix.vrf, vrfs[0].id);
    }
    for address in all_of::<Address>(&service).await {
        assert_eq!(address.vrf, vrfs[0].id);
    }
}

#[tokio::test]
async fn an_existing_tenant_called_default_is_adopted() {
    let (service, _) = service();
    let own = tenant("default");
    let own_id = own.id.expect("id");
    run(&service, vec![IpamCommand::CreateTenant(own)]).await;
    run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    assert_eq!(all_of::<Tenant>(&service).await.len(), 1);
    let vrfs = all_of::<Vrf>(&service).await;
    assert_eq!(vrfs.len(), 1);
    assert_eq!(vrfs[0].tenant, own_id);
    // The name is taken like any other.
    run_err(
        &service,
        vec![IpamCommand::CreateTenant(tenant("Default"))],
        codes::NAME_TAKEN,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_requests_create_one_default_tenant_and_vrf() {
    let (service, _) = service();
    let mut tasks = tokio::task::JoinSet::new();
    for cidr in [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/48",
    ] {
        let service = service.clone();
        tasks.spawn(async move {
            try_run(
                &service,
                vec![IpamCommand::CreatePrefix(prefix(None, cidr))],
            )
            .await
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.expect("task").expect("every request succeeds");
    }
    assert_eq!(all_of::<Tenant>(&service).await.len(), 1);
    let vrfs = all_of::<Vrf>(&service).await;
    assert_eq!(vrfs.len(), 1);
    let prefixes = all_of::<Prefix>(&service).await;
    assert_eq!(prefixes.len(), 4);
    assert!(prefixes.iter().all(|p| p.vrf == vrfs[0].id));
}

// ----- IPv4 network and broadcast addresses --------------------------------------------------

#[tokio::test]
async fn ipv4_network_and_broadcast_addresses_are_refused() {
    let (service, _) = service();
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreatePrefix(prefix(None, "198.51.100.0/30")),
            IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/31")),
            IpamCommand::CreatePrefix(prefix(None, "203.0.113.9/32")),
        ],
    )
    .await;
    for refused in ["192.0.2.0", "192.0.2.255", "198.51.100.0", "198.51.100.3"] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateAddress(address(None, refused))],
            codes::ADDRESS_NETWORK_OR_BROADCAST,
        )
        .await;
        assert_eq!(status_of(&error), 409, "{refused}");
        assert_eq!(error.coded().params["ip"], refused);
    }
    // Everything else, including both addresses of a /31 and the single address of a /32.
    let accepted = [
        "192.0.2.1",
        "192.0.2.254",
        "198.51.100.1",
        "198.51.100.2",
        "203.0.113.0",
        "203.0.113.1",
        "203.0.113.9",
    ];
    let mut ids = Vec::new();
    for ip in accepted {
        let item = address(None, ip);
        ids.push(item.id.expect("id"));
        run(&service, vec![IpamCommand::CreateAddress(item)]).await;
    }
    // Renumbering onto one is refused as well.
    run_err(
        &service,
        vec![renumber(ids[0], "192.0.2.255")],
        codes::ADDRESS_NETWORK_OR_BROADCAST,
    )
    .await;
    // A missing prefix and a duplicate have codes of their own.
    run_err(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.3.1"))],
        codes::ADDRESS_NO_PREFIX,
    )
    .await;
    run_err(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.1"))],
        codes::ADDRESS_DUPLICATE,
    )
    .await;
}

// ----- custom fields and tags ---------------------------------------------------------------

fn prefix_with(cidr: &str, custom: BTreeMap<FieldKey, CustomValue>) -> IpamCommand {
    let mut item = prefix(None, cidr);
    item.custom = custom;
    IpamCommand::CreatePrefix(item)
}

fn address_with(ip: &str, custom: BTreeMap<FieldKey, CustomValue>) -> IpamCommand {
    let mut item = address(None, ip);
    item.custom = custom;
    IpamCommand::CreateAddress(item)
}

fn clear_custom(key_text: &str) -> BTreeMap<FieldKey, Option<CustomValue>> {
    BTreeMap::from([(key(key_text), None)])
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn custom_values_are_validated_against_their_definitions() {
    let (service, _) = service();
    let text = |s: &str| CustomValue::Text(s.to_owned());
    // No definition, no value.
    let error = run_err(
        &service,
        vec![prefix_with(
            "192.0.2.0/24",
            values(&[("owner", text("lab"))]),
        )],
        custom::UNKNOWN,
    )
    .await;
    assert_eq!(status_of(&error), 400);
    assert_eq!(error.coded().params["key"], "owner");

    let defined = run(
        &service,
        vec![
            IpamCommand::CreateCustomField(field(
                "owner",
                CustomKind::Text,
                &[ObjectKind::Prefix, ObjectKind::Address],
                false,
            )),
            IpamCommand::CreateCustomField(field(
                "cost",
                CustomKind::Integer,
                &[ObjectKind::Prefix],
                false,
            )),
            IpamCommand::CreateCustomField(field(
                "tier",
                CustomKind::Select {
                    options: vec!["gold".to_owned(), "silver".to_owned()],
                },
                &[ObjectKind::Address],
                false,
            )),
            IpamCommand::CreateCustomField(field(
                "purpose",
                CustomKind::Text,
                &[ObjectKind::Vlan],
                true,
            )),
        ],
    )
    .await;
    assert_eq!(defined.results.len(), 4);
    assert!(
        defined
            .results
            .iter()
            .all(|r| r.kind == ObjectKind::CustomField)
    );

    // The type must match, the value must obey the rules of its type, the field must apply to
    // the kind of the object, and required fields need a value.
    run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    let cases: Vec<(&str, IpamCommand, &str)> = vec![
        (
            "text in an integer field",
            prefix_with("198.51.100.0/24", values(&[("cost", text("3"))])),
            custom::TYPE_MISMATCH,
        ),
        (
            "integer in a text field",
            prefix_with(
                "198.51.100.0/24",
                values(&[("owner", CustomValue::Integer(1))]),
            ),
            custom::TYPE_MISMATCH,
        ),
        (
            "control character",
            prefix_with("198.51.100.0/24", values(&[("owner", text("bad\u{7}"))])),
            custom::INVALID,
        ),
        (
            "unknown select option",
            address_with(
                "192.0.2.10",
                values(&[("tier", CustomValue::Select("bronze".to_owned()))]),
            ),
            custom::INVALID,
        ),
        (
            "field of another kind",
            address_with("192.0.2.10", values(&[("cost", CustomValue::Integer(3))])),
            custom::NOT_APPLICABLE,
        ),
        (
            "required field missing",
            IpamCommand::CreateVlan(vlan(10, "users", None)),
            custom::REQUIRED,
        ),
    ];
    for (label, command, code) in cases {
        let error = run_err(&service, vec![command], code).await;
        assert_eq!(status_of(&error), 400, "{label}");
    }

    // Valid values are stored and indexed.
    let mut users = vlan(10, "users", None);
    users.custom = values(&[("purpose", text("staff"))]);
    let applied = run(
        &service,
        vec![
            prefix_with(
                "198.51.100.0/24",
                values(&[("owner", text("lab")), ("cost", CustomValue::Integer(3))]),
            ),
            address_with(
                "192.0.2.10",
                values(&[
                    ("owner", text("lab")),
                    ("tier", CustomValue::Select("gold".to_owned())),
                ]),
            ),
            IpamCommand::CreateVlan(users),
        ],
    )
    .await;
    let stored = fetch::<Prefix>(&service, id_of(applied.results[0])).await;
    assert_eq!(stored.meta.custom.len(), 2);
    assert_eq!(stored.meta.custom[&key("cost")], CustomValue::Integer(3));
    let view = snapshot(&service).await;
    let usage = |name: &str| {
        view.scan_typed(
            &FIELD_USAGE,
            KeyRange::prefix(encode_key(&name.to_owned())),
            100,
            false,
        )
        .expect("scan")
        .len()
    };
    assert_eq!(
        (
            usage("owner"),
            usage("cost"),
            usage("tier"),
            usage("purpose")
        ),
        (2, 1, 1, 1)
    );

    // Invalid definitions.
    let invalid = |input: CustomFieldInput| vec![IpamCommand::CreateCustomField(input)];
    run_err(
        &service,
        invalid(field("empty", CustomKind::Text, &[], false)),
        custom::INVALID_DEFINITION,
    )
    .await;
    run_err(
        &service,
        invalid(field(
            "twice",
            CustomKind::Text,
            &[ObjectKind::Prefix, ObjectKind::Prefix],
            false,
        )),
        custom::INVALID_DEFINITION,
    )
    .await;
    run_err(
        &service,
        invalid(field(
            "options",
            CustomKind::Select {
                options: vec!["a".to_owned(), "a".to_owned()],
            },
            &[ObjectKind::Prefix],
            false,
        )),
        custom::INVALID_DEFINITION,
    )
    .await;
    run_err(
        &service,
        invalid(field(
            "empty_select",
            CustomKind::Select {
                options: Vec::new(),
            },
            &[ObjectKind::Prefix],
            false,
        )),
        custom::INVALID_DEFINITION,
    )
    .await;
}

#[tokio::test]
async fn a_used_custom_field_cannot_be_deleted_until_its_values_are_gone() {
    let (service, _) = service();
    let owner = field("owner", CustomKind::Text, &[ObjectKind::Prefix], false);
    let defined = run(&service, vec![IpamCommand::CreateCustomField(owner)]).await;
    let definition = defined.results[0];
    let item = {
        let mut item = prefix(None, "192.0.2.0/24");
        item.custom = values(&[("owner", CustomValue::Text("lab".to_owned()))]);
        item
    };
    let prefix_id = item.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(item)]).await;

    let delete_field = || {
        vec![IpamCommand::DeleteCustomField {
            key: key("owner"),
            expected: None,
        }]
    };
    let error = run_err(&service, delete_field(), codes::IN_USE).await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(error.coded().params["by"], "objects");
    assert_eq!(error.coded().params["count"], "1");

    // Removing the value releases the definition.
    run(
        &service,
        vec![update_prefix(
            prefix_id,
            PrefixPatch {
                custom: Some(clear_custom("owner")),
                ..PrefixPatch::default()
            },
        )],
    )
    .await;
    assert!(
        fetch::<Prefix>(&service, prefix_id)
            .await
            .meta
            .custom
            .is_empty()
    );
    run(&service, delete_field()).await;
    let view = snapshot(&service).await;
    assert_eq!(
        query::custom_fields(view.as_ref()).expect("fields").len(),
        0
    );
    assert!(
        view.get_typed(&CUSTOM_FIELD_KEYS, &"owner".to_owned())
            .expect("read")
            .is_none()
    );
    assert_eq!(
        view.scan_typed(&CUSTOM_FIELDS, KeyRange::all(), 10, false)
            .expect("scan")
            .len(),
        0
    );
    assert_eq!(
        actions_of(&service, definition).await,
        [ChangeAction::Create, ChangeAction::Remove]
    );
    // The key is unknown again, and deleting it twice is a lookup error.
    let command = prefix_with(
        "198.51.100.0/24",
        values(&[("owner", CustomValue::Text("lab".to_owned()))]),
    );
    run_err(&service, vec![command], custom::UNKNOWN).await;
    let error = run_err(&service, delete_field(), codes::NOT_FOUND).await;
    assert_eq!(status_of(&error), 404);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn custom_field_definitions_may_gain_options_but_not_lose_used_ones() {
    let (service, _) = service();
    run(
        &service,
        vec![
            IpamCommand::CreateCustomField(field(
                "tier",
                CustomKind::Select {
                    options: vec!["gold".to_owned(), "silver".to_owned()],
                },
                &[ObjectKind::Address],
                false,
            )),
            IpamCommand::CreateCustomField(field(
                "cost",
                CustomKind::Integer,
                &[ObjectKind::Prefix],
                false,
            )),
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            address_with(
                "192.0.2.10",
                values(&[("tier", CustomValue::Select("gold".to_owned()))]),
            ),
        ],
    )
    .await;
    let patch = |name: &str, patch: CustomFieldPatch| {
        vec![IpamCommand::UpdateCustomField(UpdateCustomField {
            key: key(name),
            expected: None,
            patch,
        })]
    };
    let select = |options: &[&str]| CustomKind::Select {
        options: options.iter().map(|o| (*o).to_owned()).collect(),
    };
    run(
        &service,
        patch(
            "tier",
            CustomFieldPatch {
                kind: Some(select(&["gold", "silver", "bronze"])),
                ..CustomFieldPatch::default()
            },
        ),
    )
    .await;
    let error = run_err(
        &service,
        patch(
            "tier",
            CustomFieldPatch {
                kind: Some(select(&["silver", "bronze"])),
                ..CustomFieldPatch::default()
            },
        ),
        custom::INCOMPATIBLE_CHANGE,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    // A field with values keeps its type.
    run(
        &service,
        vec![prefix_with(
            "198.51.100.0/24",
            values(&[("cost", CustomValue::Integer(7))]),
        )],
    )
    .await;
    run_err(
        &service,
        patch(
            "cost",
            CustomFieldPatch {
                kind: Some(CustomKind::Text),
                ..CustomFieldPatch::default()
            },
        ),
        custom::INCOMPATIBLE_CHANGE,
    )
    .await;

    // Making a field required takes effect for new objects.
    run(
        &service,
        patch(
            "cost",
            CustomFieldPatch {
                required: Some(true),
                ..CustomFieldPatch::default()
            },
        ),
    )
    .await;
    run_err(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/24"))],
        custom::REQUIRED,
    )
    .await;
    run(
        &service,
        vec![prefix_with(
            "203.0.113.0/24",
            values(&[("cost", CustomValue::Integer(1))]),
        )],
    )
    .await;
}

type TagCounts = BTreeMap<String, (u64, BTreeMap<String, u64>)>;

async fn tag_counts(service: &tenko_ipam::IpamService) -> TagCounts {
    let view = snapshot(service).await;
    query::tags(view.as_ref())
        .expect("tags")
        .into_iter()
        .map(|t| (t.tag, (t.count, t.by_kind)))
        .collect()
}

#[tokio::test]
async fn tags_are_counted_and_disappear_with_a_soft_delete() {
    let (service, _) = service();
    let mut network = prefix(None, "192.0.2.0/24");
    network.tags = tags(&["prod", "edge"]);
    let network_id = network.id.expect("id");
    let mut item = address(None, "192.0.2.10");
    item.tags = tags(&["prod"]);
    let address_id = item.id.expect("id");
    let mut lab = vrf("lab");
    lab.tags = tags(&["edge"]);
    run(
        &service,
        vec![
            IpamCommand::CreateVrf(lab),
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateAddress(item),
        ],
    )
    .await;
    let counts = tag_counts(&service).await;
    assert_eq!(
        counts.keys().map(String::as_str).collect::<Vec<_>>(),
        ["edge", "prod"]
    );
    assert_eq!(counts["prod"].0, 2);
    assert_eq!(
        counts["prod"].1,
        BTreeMap::from([("address".to_owned(), 1), ("prefix".to_owned(), 1)])
    );
    assert_eq!(
        counts["edge"].1,
        BTreeMap::from([("prefix".to_owned(), 1), ("vrf".to_owned(), 1)])
    );

    // A soft delete takes the tags of the object out of the counts.
    run(&service, vec![delete(address_id, false)]).await;
    assert_eq!(tag_counts(&service).await["prod"].0, 1);
    // Replacing the tags of an object updates them.
    run(
        &service,
        vec![update_prefix(
            network_id,
            PrefixPatch {
                tags: Some(tags(&["staging"])),
                ..PrefixPatch::default()
            },
        )],
    )
    .await;
    let counts = tag_counts(&service).await;
    assert!(!counts.contains_key("prod"), "{counts:?}");
    assert_eq!(counts["staging"].0, 1);
    assert_eq!(counts["edge"].0, 1, "only the VRF keeps it");
    // The prefix goes with its tag, and comes back with it.
    run(&service, vec![delete(network_id, true)]).await;
    assert!(!tag_counts(&service).await.contains_key("staging"));
    run(&service, vec![restore(network_id)]).await;
    assert_eq!(tag_counts(&service).await["staging"].0, 1);
    // Restoring the address brings its tag back too.
    run(&service, vec![restore(address_id)]).await;
    assert_eq!(tag_counts(&service).await["prod"].0, 1);
    let view = snapshot(&service).await;
    let rows = view
        .scan_typed(&TAG_USAGE, KeyRange::all(), 100, false)
        .expect("scan");
    assert_eq!(
        rows.len(),
        3,
        "edge on the VRF, staging on the prefix, prod on the address"
    );
}

// ----- idempotency, If-Match, history, audit and dry runs --------------------------------------

const T0: i128 = 1_790_000_000_000_000_000;
const SECOND: i128 = 1_000_000_000;

#[tokio::test]
async fn an_idempotency_key_replays_the_same_commands_and_refuses_other_ones() {
    let (service, store) = service();
    let owner = principal();
    let key = IdempotencyKey::new("create-lab-1").expect("key");
    let commands = vec![
        IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
        IpamCommand::CreateAddress(address(None, "192.0.2.5")),
    ];
    let first_cx = request_of(&owner, T0).with_idempotency(key.clone());
    let first = service
        .execute(&commands, &first_cx, &PlanOptions::default())
        .await
        .expect("first");
    assert!(!first.replayed);
    let revision = revision_of(&store);

    // The same commands under the same key, as a new request, replay the first result.
    let again_cx = request_of(&owner, T0 + 60 * SECOND).with_idempotency(key.clone());
    let replay = service
        .execute(&commands, &again_cx, &PlanOptions::default())
        .await
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.results, first.results);
    assert_eq!(replay.revision, first.revision);
    assert!(replay.job_id.is_none());
    assert_eq!(revision_of(&store), revision, "a replay writes nothing");
    assert_eq!(all_of::<Prefix>(&service).await.len(), 1);
    assert_eq!(all_of::<Address>(&service).await.len(), 1);
    let plan = service
        .preview(&commands, &again_cx, &PlanOptions::default(), None)
        .await
        .expect("preview");
    assert!(plan.replay.is_some() && plan.is_empty());

    // Other commands under the key are refused, however similar they look.
    let other = vec![IpamCommand::CreatePrefix(prefix(None, "198.51.100.0/24"))];
    let error = service
        .execute(&other, &again_cx, &PlanOptions::default())
        .await
        .expect_err("mismatch");
    assert_eq!(error.code_str(), codes::IDEMPOTENCY_MISMATCH);
    assert_eq!(status_of(&error), 422);
    let fewer = vec![commands[0].clone()];
    let error = service
        .execute(&fewer, &again_cx, &PlanOptions::default())
        .await
        .expect_err("mismatch");
    assert_eq!(error.code_str(), codes::IDEMPOTENCY_MISMATCH);

    // Keys belong to a principal.
    let someone_else = request_of(&principal(), T0).with_idempotency(key.clone());
    let applied = service
        .execute(&other, &someone_else, &PlanOptions::default())
        .await
        .expect("another principal");
    assert!(!applied.replayed);

    // A failed request does not use up its key.
    let retry_key = IdempotencyKey::new("create-lab-2").expect("key");
    let failing = vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/25"))];
    let cx = request_of(&owner, T0 + 120 * SECOND).with_idempotency(retry_key.clone());
    let error = service
        .execute(&failing, &cx, &PlanOptions::default())
        .await
        .expect_err("overlap");
    assert_eq!(error.code_str(), codes::PREFIX_OVERLAP);
    let fixed = vec![IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/24"))];
    let applied = service
        .execute(&fixed, &cx, &PlanOptions::default())
        .await
        .expect("fixed");
    assert!(!applied.replayed);
    let replay = service
        .execute(&fixed, &cx, &PlanOptions::default())
        .await
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.results, applied.results);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_with_one_key_apply_once() {
    let (service, _) = service();
    let owner = principal();
    let key = IdempotencyKey::new("create-once").expect("key");
    let commands = vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))];
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..8 {
        let service = service.clone();
        let commands = commands.clone();
        let cx = request_of(&owner, T0 + n * SECOND).with_idempotency(key.clone());
        tasks.spawn(async move {
            service
                .execute(&commands, &cx, &PlanOptions::default())
                .await
        });
    }
    let mut applied = Vec::new();
    while let Some(done) = tasks.join_next().await {
        applied.push(done.expect("task").expect("every request succeeds"));
    }
    assert_eq!(applied.iter().filter(|a| !a.replayed).count(), 1);
    assert!(applied.iter().all(|a| a.results == applied[0].results));
    assert_eq!(all_of::<Prefix>(&service).await.len(), 1);
}

#[tokio::test]
async fn if_match_revisions_guard_updates_deletes_and_restores() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network)]).await;
    let update = |expected: Option<Revision>, text: &str| {
        vec![IpamCommand::UpdatePrefix(UpdatePrefix {
            id: network_id,
            expected,
            patch: PrefixPatch {
                description: Some(Some(text.to_owned())),
                ..PrefixPatch::default()
            },
        })]
    };
    let r1 = fetch::<Prefix>(&service, network_id).await.meta.revision;
    run(&service, update(Some(r1), "one")).await;
    let r2 = fetch::<Prefix>(&service, network_id).await.meta.revision;
    assert!(r2 > r1);

    // The old revision no longer matches.
    let error = run_err(&service, update(Some(r1), "two"), codes::REVISION_MISMATCH).await;
    assert_eq!(status_of(&error), 412);
    assert_eq!(error.coded().params["expected"], r1.to_string());
    assert_eq!(error.coded().params["actual"], r2.to_string());
    // Writes to other objects do not move it.
    run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.10"))],
    )
    .await;
    assert_eq!(
        fetch::<Prefix>(&service, network_id).await.meta.revision,
        r2
    );
    run(&service, update(Some(r2), "two")).await;
    let r3 = fetch::<Prefix>(&service, network_id).await.meta.revision;

    // Delete and restore check it too.
    let remove = |expected| {
        vec![IpamCommand::Delete {
            object: network_id.into(),
            expected,
            cascade: true,
        }]
    };
    run_err(&service, remove(Some(r2)), codes::REVISION_MISMATCH).await;
    run(&service, remove(Some(r3))).await;
    let deleted = fetch::<Prefix>(&service, network_id).await.meta.revision;
    assert!(deleted > r3);
    let bring_back = |expected| {
        vec![IpamCommand::Restore {
            object: network_id.into(),
            expected,
        }]
    };
    let error = run_err(&service, bring_back(Some(r3)), codes::REVISION_MISMATCH).await;
    assert_eq!(status_of(&error), 412);
    run(&service, bring_back(Some(deleted))).await;
    assert!(
        !fetch::<Prefix>(&service, network_id)
            .await
            .meta
            .is_deleted()
    );

    // Hosts: lock and mode take a revision as well.
    let (nas, _) = host("nas01", AssignmentMode::Static, None);
    let nas_id = nas.id.expect("id");
    run(&service, vec![IpamCommand::CreateHost(nas)]).await;
    let stale = fetch::<Host>(&service, nas_id).await.meta.revision;
    run(
        &service,
        vec![IpamCommand::SetMode {
            host: nas_id,
            mode: AssignmentMode::Dynamic,
            expected: Some(stale),
        }],
    )
    .await;
    run_err(
        &service,
        vec![IpamCommand::SetLock {
            host: nas_id,
            lock: true,
            expected: Some(stale),
        }],
        codes::REVISION_MISMATCH,
    )
    .await;
    // An object that does not exist is not found, whatever the revision.
    let error = run_err(
        &service,
        vec![IpamCommand::UpdatePrefix(UpdatePrefix {
            id: PrefixId::generate(),
            expected: Some(Revision(1)),
            patch: PrefixPatch::default(),
        })],
        codes::NOT_FOUND,
    )
    .await;
    assert_eq!(status_of(&error), 404);
}

#[tokio::test]
async fn history_lists_each_change_in_order_with_its_field_changes() {
    let (service, _) = service();
    let owner = principal();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let object = ObjectRef::from(network_id);
    let steps = [
        vec![IpamCommand::CreatePrefix(network)],
        vec![update_prefix(
            network_id,
            PrefixPatch {
                description: Some(Some("lab".to_owned())),
                status: Some(Status::Deprecated),
                ..PrefixPatch::default()
            },
        )],
        vec![delete(network_id, false)],
        vec![restore(network_id)],
    ];
    let mut contexts = Vec::new();
    for (n, commands) in steps.iter().enumerate() {
        let cx = request_of(&owner, T0 + i128::try_from(n).expect("small") * SECOND);
        service
            .execute(commands, &cx, &PlanOptions::default())
            .await
            .expect("step");
        contexts.push(cx);
    }
    let entries = history_of(&service, object).await;
    assert_eq!(
        entries.iter().map(|e| e.action).collect::<Vec<_>>(),
        [
            ChangeAction::Create,
            ChangeAction::Update,
            ChangeAction::Delete,
            ChangeAction::Restore
        ]
    );
    for (entry, cx) in entries.iter().zip(&contexts) {
        assert_eq!(entry.object, object);
        assert_eq!(entry.by, owner);
        assert_eq!(entry.request, cx.request);
        assert_eq!(entry.at, cx.now);
        assert_eq!(entry.job_kind, Some(tenko_ipam::jobs::edit_job_kind()));
    }
    assert!(entries.windows(2).all(|w| w[0].revision < w[1].revision));
    assert!(entries[0].before.is_none() && entries[0].after.is_some());
    let create = entries[0]
        .changes
        .iter()
        .find(|c| c.field == "cidr")
        .expect("cidr");
    assert_eq!(
        (create.old.as_deref(), create.new.as_deref()),
        (None, Some("192.0.2.0/24"))
    );

    // The update lists exactly the fields that changed, and none of the bookkeeping.
    let fields: BTreeMap<&str, (Option<&str>, Option<&str>)> = entries[1]
        .changes
        .iter()
        .map(|c| (c.field.as_str(), (c.old.as_deref(), c.new.as_deref())))
        .collect();
    assert_eq!(
        fields,
        BTreeMap::from([
            ("meta.description", (None, Some("lab"))),
            ("status", (Some("active"), Some("deprecated"))),
        ])
    );
    assert!(entries[2].changes.iter().any(|c| c.field == "meta.deleted"));
    assert!(entries[3].changes.iter().any(|c| c.field == "meta.deleted"));

    // The API view pages newest first.
    let view = snapshot(&service).await;
    let first = query::history(view.as_ref(), object, None, Some(3)).expect("page");
    assert_eq!(
        first.items.iter().map(|e| e.action).collect::<Vec<_>>(),
        [
            ChangeAction::Restore,
            ChangeAction::Delete,
            ChangeAction::Update
        ]
    );
    let cursor = first.next_cursor.expect("more");
    let second = query::history(view.as_ref(), object, Some(&cursor), Some(3)).expect("page");
    assert_eq!(
        second.items.iter().map(|e| e.action).collect::<Vec<_>>(),
        [ChangeAction::Create]
    );
    assert!(second.next_cursor.is_none());
    // Other objects have their own history.
    assert_eq!(
        history_of(&service, PrefixId::generate().into())
            .await
            .len(),
        0
    );
}

#[tokio::test]
async fn a_plan_carries_one_audit_draft_and_one_history_row_per_change() {
    let (service, store) = service();
    let cx = person();
    let commands = [
        IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
        IpamCommand::CreateAddress(address(None, "192.0.2.5")),
        IpamCommand::CreateAddress(address(None, "192.0.2.6")),
    ];
    let plan = service
        .preview(&commands, &cx, &PlanOptions::default(), None)
        .await
        .expect("preview");
    // Three objects, and the default tenant and VRF they need.
    assert_eq!(plan.changes.len(), 5);
    assert_eq!(plan.audit.len(), plan.changes.len());
    let history_rows = plan
        .mutations
        .iter()
        .filter(|m| matches!(m, Mutation::Put { table, .. } if table == HISTORY.name()))
        .count();
    assert_eq!(history_rows, plan.changes.len());
    for (change, draft) in plan.changes.iter().zip(&plan.audit) {
        assert_eq!(draft.objects, [change.object]);
        assert_eq!(
            draft.action.as_str(),
            format!("ipam.{}.create", change.object.kind.as_str())
        );
    }

    let audit_before = {
        let view = snapshot(&service).await;
        view.scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
            .len()
    };
    let applied = service.apply(&plan, &cx).await.expect("apply");
    let view = service.view(Some(applied.revision)).await.expect("view");
    let records = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit");
    assert_eq!(records.len() - audit_before, 5);
    let sequence: Vec<u64> = records.iter().map(|(seq, _, _)| seq.0).collect();
    assert!(
        sequence.windows(2).all(|w| w[1] == w[0] + 1),
        "gap-free: {sequence:?}"
    );
    for (_, record, revision) in &records[audit_before..] {
        assert_eq!(*revision, applied.revision);
        assert_eq!(record.principal, cx.principal);
        assert_eq!(record.request, Some(cx.request));
        assert_eq!(record.at, cx.now);
    }
    // Each object has its create entry in the history with the same request.
    for change in &plan.changes {
        let entries = history_of(&service, change.object).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request, cx.request);
    }

    // A plan that changes nothing writes nothing.
    let network_id: PrefixId = id_of(plan.results[0]);
    run(&service, vec![describe_prefix(network_id, "same")]).await;
    let (nas, _) = host("nas01", AssignmentMode::Static, None);
    let nas_id = nas.id.expect("id");
    run(&service, vec![IpamCommand::CreateHost(nas)]).await;
    let revision = revision_of(&store);
    let audit_head = store.status().audit_head;
    let cx = person();
    let noops = [
        describe_prefix(network_id, "same"),
        update_prefix(network_id, PrefixPatch::default()),
        IpamCommand::SetLock {
            host: nas_id,
            lock: false,
            expected: None,
        },
        IpamCommand::SetMode {
            host: nas_id,
            mode: AssignmentMode::Static,
            expected: None,
        },
    ];
    let plan = service
        .preview(&noops, &cx, &PlanOptions::default(), None)
        .await
        .expect("preview");
    assert!(plan.is_empty());
    assert!(plan.mutations.is_empty() && plan.audit.is_empty() && plan.changes.is_empty());
    assert_eq!(plan.results.len(), 4);
    assert_eq!(plan.summary().lines, ["no changes"]);
    let applied = service.apply(&plan, &cx).await.expect("apply");
    assert!(applied.job_id.is_none());
    assert_eq!(applied.results, plan.results);
    let executed = service
        .execute(&noops, &cx, &PlanOptions::default())
        .await
        .expect("execute");
    assert!(executed.job_id.is_none());
    let nothing = service
        .execute(&[], &cx, &PlanOptions::default())
        .await
        .expect("empty request");
    assert_eq!(nothing.results.len(), 0);
    assert_eq!(revision_of(&store), revision);
    assert_eq!(store.status().audit_head, audit_head);
}

#[tokio::test]
async fn a_dry_run_leaves_the_store_untouched_and_a_stale_plan_is_refused() {
    let (service, store) = service();
    run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    let revision = revision_of(&store);
    let audit_head = store.status().audit_head;
    let tree_revision = service.tree().revision();

    let planned = prefix(None, "198.51.100.0/24");
    let planned_id = planned.id.expect("id");
    let commands = vec![
        IpamCommand::CreatePrefix(planned),
        IpamCommand::CreateAddress(address(None, "198.51.100.7")),
        IpamCommand::AllocateAddress(allocate(planned_id)),
    ];
    let cx = person();
    let plan = service
        .preview(&commands, &cx, &PlanOptions::default(), None)
        .await
        .expect("preview");
    assert_eq!(plan.changes.len(), 3);
    assert_eq!(
        plan.summary().lines,
        ["2 addresses created", "1 prefix created"]
    );
    // A failing dry run answers with its error and changes nothing either.
    let overlapping = vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/25"))];
    let error = service
        .preview(&overlapping, &cx, &PlanOptions::default(), None)
        .await
        .expect_err("overlap");
    assert_eq!(error.code_str(), codes::PREFIX_OVERLAP);

    assert_eq!(revision_of(&store), revision);
    assert_eq!(store.status().audit_head, audit_head);
    assert_eq!(service.tree().revision(), tree_revision);
    assert!(service.tree().prefix(planned_id).is_none());
    assert!(!exists::<Prefix>(&service, planned_id).await);
    assert_eq!(all_of::<Address>(&service).await.len(), 0);

    // Applying the previewed plan does what it showed, in one revision.
    let applied = service.apply(&plan, &cx).await.expect("apply");
    assert_eq!(applied.revision, revision.next());
    assert_eq!(applied.results, plan.results);
    assert_eq!(all_of::<Address>(&service).await.len(), 2);
    // The same plan cannot be applied twice.
    let error = service.apply(&plan, &cx).await.expect_err("twice");
    assert_eq!(error.code_str(), codes::PLAN_STALE);
    assert_eq!(status_of(&error), 409);

    // A plan that is overtaken by a change to what it read is stale as well.
    let cx = person();
    let slow = service
        .preview(
            &[IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/24"))],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "2001:db8::/48"))],
    )
    .await;
    let error = service.apply(&slow, &cx).await.expect_err("overtaken");
    assert_eq!(error.code_str(), codes::PLAN_STALE);
    // Planning again works.
    service
        .execute(
            &[IpamCommand::CreatePrefix(prefix(None, "203.0.113.0/24"))],
            &cx,
            &PlanOptions::default(),
        )
        .await
        .expect("fresh plan");
}

// ----- status transitions, locks and alarms ---------------------------------------------------

const STATUSES: [Status; 4] = [
    Status::Planned,
    Status::Active,
    Status::Reserved,
    Status::Deprecated,
];

/// The pairs IPAM-05 refuses; every other pair is allowed.
const REFUSED: [(Status, Status); 3] = [
    (Status::Active, Status::Planned),
    (Status::Deprecated, Status::Planned),
    (Status::Deprecated, Status::Reserved),
];

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Planned => "planned",
        Status::Active => "active",
        Status::Reserved => "reserved",
        Status::Deprecated => "deprecated",
    }
}

#[tokio::test]
async fn every_status_pair_of_a_prefix_follows_the_transition_table() {
    let (service, _) = service();
    let mut n = 0;
    for from in STATUSES {
        for to in STATUSES {
            let mut item = prefix(None, &format!("2001:db8:{n:x}::/48"));
            item.status = Some(from);
            let id = item.id.expect("id");
            run(&service, vec![IpamCommand::CreatePrefix(item)]).await;
            let result = try_run(
                &service,
                vec![update_prefix(
                    id,
                    PrefixPatch {
                        status: Some(to),
                        ..PrefixPatch::default()
                    },
                )],
            )
            .await;
            let label = format!("{} to {}", status_name(from), status_name(to));
            let stored = fetch::<Prefix>(&service, id).await.status;
            if REFUSED.contains(&(from, to)) {
                let error = result.expect_err(&label);
                assert_eq!(error.code_str(), codes::STATUS_TRANSITION, "{label}");
                assert_eq!(status_of(&error), 409, "{label}");
                assert_eq!(error.coded().params["from"], status_name(from));
                assert_eq!(error.coded().params["to"], status_name(to));
                assert_eq!(stored, from, "{label} must leave the status alone");
            } else {
                result.unwrap_or_else(|e| panic!("{label}: {e:?}"));
                assert_eq!(stored, to, "{label}");
            }
            n += 1;
        }
    }
}

#[tokio::test]
async fn ranges_addresses_and_vlans_share_the_transition_table() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let wide = prefix(None, "198.51.100.0/24");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreatePrefix(wide),
        ],
    )
    .await;
    let mut n = 0u8;
    for from in STATUSES {
        for to in STATUSES {
            n += 1;
            let mut pool = range(
                network_id,
                &format!("192.0.2.{}", n * 10),
                &format!("192.0.2.{}", n * 10 + 5),
                RangeRole::Reserved,
            );
            pool.status = Some(from);
            let pool_id = RangeId::generate();
            pool.id = Some(pool_id);
            let mut item = address(None, &format!("198.51.100.{n}"));
            item.status = Some(from);
            let address_id = item.id.expect("id");
            let mut segment = vlan(u16::from(n), "segment", None);
            segment.status = Some(from);
            let vlan_id = segment.id.expect("id");
            run(
                &service,
                vec![
                    IpamCommand::CreateRange(pool),
                    IpamCommand::CreateAddress(item),
                    IpamCommand::CreateVlan(segment),
                ],
            )
            .await;
            let updates: [(&str, IpamCommand); 3] = [
                (
                    "range",
                    update_range(
                        pool_id,
                        RangePatch {
                            status: Some(to),
                            ..RangePatch::default()
                        },
                    ),
                ),
                (
                    "address",
                    update_address(
                        address_id,
                        AddressPatch {
                            status: Some(to),
                            ..AddressPatch::default()
                        },
                    ),
                ),
                (
                    "vlan",
                    IpamCommand::UpdateVlan(UpdateVlan {
                        id: vlan_id,
                        expected: None,
                        patch: VlanPatch {
                            status: Some(to),
                            ..VlanPatch::default()
                        },
                    }),
                ),
            ];
            for (kind, command) in updates {
                let label = format!("{kind} {} to {}", status_name(from), status_name(to));
                let result = try_run(&service, vec![command]).await;
                if REFUSED.contains(&(from, to)) {
                    let error = result.expect_err(&label);
                    assert_eq!(error.code_str(), codes::STATUS_TRANSITION, "{label}");
                } else {
                    result.unwrap_or_else(|e| panic!("{label}: {e:?}"));
                }
            }
        }
    }
}

fn describe_host(id: HostId, text: &str) -> IpamCommand {
    IpamCommand::UpdateHost(UpdateHost {
        id,
        expected: None,
        patch: HostPatch {
            description: Some(Some(text.to_owned())),
            ..HostPatch::default()
        },
    })
}
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
#[tokio::test]
async fn a_locked_host_refuses_automation_but_not_people() {
    let (service, store) = service();
    let (mut nas, eth0) = host("nas01", AssignmentMode::Static, Some("00-00-5E-00-53-01"));
    nas.lock = Some(true);
    let nas_id = nas.id.expect("id");
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    let mut assigned = address(None, "192.0.2.50");
    assigned.interface = Some(eth0);
    let assigned_id = assigned.id.expect("id");
    let loose = address(None, "192.0.2.60");
    let loose_id = loose.id.expect("id");
    let (web, _) = host("web01", AssignmentMode::Static, Some("00-00-5E-00-53-02"));
    let web_id = web.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(network),
            IpamCommand::CreateHost(nas),
            IpamCommand::CreateAddress(assigned),
            IpamCommand::CreateAddress(loose),
            IpamCommand::CreateHost(web),
        ],
    )
    .await;
    assert!(fetch::<Host>(&service, nas_id).await.lock);

    let eth1 = InterfaceId::generate();
    let mut extra_address = address(None, "192.0.2.70");
    extra_address.interface = Some(eth0);
    let host_patch = |patch: HostPatch| {
        IpamCommand::UpdateHost(UpdateHost {
            id: nas_id,
            expected: None,
            patch,
        })
    };
    let blocked: Vec<(&str, IpamCommand)> = vec![
        (
            "update host",
            host_patch(HostPatch {
                description: Some(Some("rack 3".to_owned())),
                ..HostPatch::default()
            }),
        ),
        (
            "rename host",
            host_patch(HostPatch {
                name: Some("nas02".parse().expect("name")),
                ..HostPatch::default()
            }),
        ),
        (
            "unlock through update",
            host_patch(HostPatch {
                lock: Some(false),
                ..HostPatch::default()
            }),
        ),
        (
            "set mode",
            IpamCommand::SetMode {
                host: nas_id,
                mode: AssignmentMode::Reserved,
                expected: None,
            },
        ),
        ("delete host", delete(nas_id, false)),
        ("delete host with cascade", delete(nas_id, true)),
        (
            "add interface",
            IpamCommand::CreateInterface(InterfaceInput {
                id: Some(eth1),
                host: Some(nas_id),
                name: "eth1".to_owned(),
                mac: None,
                duid: None,
                client_id: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            }),
        ),
        (
            "update interface",
            IpamCommand::UpdateInterface(UpdateInterface {
                id: eth0,
                expected: None,
                patch: InterfacePatch {
                    name: Some("lan0".to_owned()),
                    ..InterfacePatch::default()
                },
            }),
        ),
        ("delete interface", delete(eth0, true)),
        (
            "assign a new address",
            IpamCommand::CreateAddress(extra_address),
        ),
        (
            "allocate an address",
            IpamCommand::AllocateAddress(AllocateAddress {
                interface: Some(eth0),
                ..allocate(network_id)
            }),
        ),
        (
            "update an address",
            update_address(
                assigned_id,
                AddressPatch {
                    dns_name: Some(Some("nas01.example.test".parse().expect("name"))),
                    ..AddressPatch::default()
                },
            ),
        ),
        ("renumber an address", renumber(assigned_id, "192.0.2.51")),
        (
            "unassign an address",
            update_address(
                assigned_id,
                AddressPatch {
                    interface: Some(None),
                    ..AddressPatch::default()
                },
            ),
        ),
        ("delete an address", delete(assigned_id, false)),
        (
            "move another address onto the host",
            update_address(
                loose_id,
                AddressPatch {
                    interface: Some(Some(eth0)),
                    ..AddressPatch::default()
                },
            ),
        ),
    ];
    let before = revision_of(&store);
    for (label, command) in &blocked {
        let error = try_run_as(&service, vec![command.clone()], &automation())
            .await
            .expect_err(label);
        assert_eq!(error.code_str(), codes::HOST_LOCKED, "{label}: {error:?}");
        assert_eq!(status_of(&error), 423, "{label}");
        assert_eq!(revision_of(&store), before, "{label} wrote");
    }
    // Every kind of automation is stopped.
    for component in [
        SystemComponent::Reconciler,
        SystemComponent::Connector,
        SystemComponent::Scan,
        SystemComponent::Import,
    ] {
        let cx = RequestCtx::system(component);
        run_err_as(
            &service,
            vec![blocked[0].1.clone()],
            &cx,
            codes::HOST_LOCKED,
        )
        .await;
    }
    let node = RequestCtx::new(tenko_core::Principal::Node {
        id: tenko_core::NodeId(2),
    });
    run_err_as(
        &service,
        vec![blocked[0].1.clone()],
        &node,
        codes::HOST_LOCKED,
    )
    .await;
    // Only people lock and unlock.
    for lock in [true, false] {
        let error = run_err_as(
            &service,
            vec![IpamCommand::SetLock {
                host: web_id,
                lock,
                expected: None,
            }],
            &automation(),
            codes::HOST_LOCK_MANUAL_ONLY,
        )
        .await;
        assert_eq!(status_of(&error), 403);
    }
    assert_eq!(revision_of(&store), before);

    // What is not on the locked host stays open to automation: a prefix, an address without
    // an interface and an unlocked host.
    try_run_as(
        &service,
        vec![describe_prefix(network_id, "managed")],
        &automation(),
    )
    .await
    .expect("prefix");
    try_run_as(
        &service,
        vec![update_address(
            loose_id,
            AddressPatch {
                dns_name: Some(Some("loose.example.test".parse().expect("name"))),
                ..AddressPatch::default()
            },
        )],
        &automation(),
    )
    .await
    .expect("address without a host");
    try_run_as(
        &service,
        vec![IpamCommand::SetMode {
            host: web_id,
            mode: AssignmentMode::Dynamic,
            expected: None,
        }],
        &automation(),
    )
    .await
    .expect("unlocked host");
    // The API and personal tokens act for people and are not automation.
    for cx in [
        RequestCtx::system(SystemComponent::Api),
        RequestCtx::new(tenko_core::Principal::Token {
            id: tenko_core::ApiTokenId::generate(),
            owner: tenko_core::UserId::generate(),
        }),
    ] {
        try_run_as(&service, vec![describe_host(nas_id, "by a token")], &cx)
            .await
            .expect("not automation");
    }

    // People edit a locked host freely, in the ways automation could not.
    for label in [
        "update host",
        "rename host",
        "set mode",
        "add interface",
        "update interface",
        "assign a new address",
        "allocate an address",
        "update an address",
        "unassign an address",
    ] {
        let (_, command) = blocked.iter().find(|(l, _)| *l == label).expect("command");
        try_run(&service, vec![command.clone()])
            .await
            .unwrap_or_else(|e| panic!("{label}: {e:?}"));
    }
    // After a person unlocks it, automation may edit the host.
    run(
        &service,
        vec![IpamCommand::SetLock {
            host: nas_id,
            lock: false,
            expected: None,
        }],
    )
    .await;
    try_run_as(
        &service,
        vec![describe_host(nas_id, "after unlock")],
        &automation(),
    )
    .await
    .expect("unlocked");
    // A person may delete a locked host.
    run(
        &service,
        vec![IpamCommand::SetLock {
            host: nas_id,
            lock: true,
            expected: None,
        }],
    )
    .await;
    run(&service, vec![delete(nas_id, true)]).await;
    assert!(fetch::<Host>(&service, nas_id).await.meta.is_deleted());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn ipam_10_supernet_alarms_follow_the_addresses_in_use_and_never_the_allocation() {
    let (service, _) = service();
    let mut outer = supernet(None, "192.0.2.0/24");
    outer.alarm = Some(UtilizationAlarm::new(25, 50).expect("alarm"));
    let outer_id = outer.id.expect("id");
    let first = prefix(None, "192.0.2.0/26");
    let first_id = first.id.expect("id");
    let second = prefix(None, "192.0.2.64/26");
    let second_id = second.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(outer)]).await;
    let vrf = fetch::<Prefix>(&service, outer_id).await.vrf;

    // Half of the space allocated to two empty networks: 0 % in use, no alarm.
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(first),
            IpamCommand::CreatePrefix(second),
        ],
    )
    .await;
    assert!(
        alarm_of(&service, outer_id).await.is_none(),
        "allocation alone raises no alarm"
    );
    let node = |nodes: &[tenko_ipam::TreeNode]| {
        nodes
            .iter()
            .find(|n| n.id == outer_id)
            .expect("node")
            .clone()
    };
    let empty = node(&service.tree().tree(vrf, None, None));
    assert_eq!(empty.level, AlarmLevel::Normal);
    assert_eq!(empty.children, 2);
    assert_eq!(
        (
            empty.utilization.covered.as_str(),
            empty.utilization.size.as_str()
        ),
        ("128", "256"),
        "the allocation is a figure of its own"
    );
    // The two networks lose their network and broadcast addresses.
    assert_eq!(empty.utilization.capacity, "252");
    assert_eq!(empty.utilization.in_use, "0");
    assert!(empty.utilization.percent.abs() < f64::EPSILON);

    // A reserved range of 62 addresses in the first network: 62 of 252, below 25 %.
    run(
        &service,
        vec![IpamCommand::CreateRange(range(
            first_id,
            "192.0.2.1",
            "192.0.2.62",
            RangeRole::Reserved,
        ))],
    )
    .await;
    assert!(alarm_of(&service, outer_id).await.is_none());
    // One address in the second network: 63 of 252 is 25 %, the warning threshold.
    run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.65"))],
    )
    .await;
    let event = alarm_of(&service, outer_id).await.expect("warning");
    assert_eq!(
        (event.level, event.previous),
        (AlarmLevel::Warning, AlarmLevel::Normal)
    );
    assert_eq!(
        (event.permille, event.used, event.reserved, event.capacity),
        (250, 1, 62, 252)
    );
    assert_eq!((event.warn_pct, event.crit_pct), (Some(25), Some(50)));

    // An address inside the reserved range is counted once: the range holds one fewer.
    run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.10"))],
    )
    .await;
    let busy = node(&service.tree().tree(vrf, None, None));
    assert_eq!(
        (
            busy.utilization.used.as_str(),
            busy.utilization.reserved.as_str(),
            busy.utilization.in_use.as_str()
        ),
        ("2", "61", "63")
    );
    assert_eq!(busy.utilization.by_role[0].role, RangeRole::Reserved);
    assert_eq!(busy.utilization.by_role[0].size, "62");

    // A range in the second network and two addresses directly in the supernet: 126 of
    // 252, the critical threshold.
    run(
        &service,
        vec![
            IpamCommand::CreateRange(range(
                second_id,
                "192.0.2.66",
                "192.0.2.126",
                RangeRole::DhcpPool,
            )),
            IpamCommand::CreateAddress(address(None, "192.0.2.200")),
            IpamCommand::CreateAddress(address(None, "192.0.2.201")),
        ],
    )
    .await;
    let event = alarm_of(&service, outer_id).await.expect("critical");
    assert_eq!(
        (event.level, event.previous, event.permille),
        (AlarmLevel::Critical, AlarmLevel::Warning, 500)
    );
    let full = node(&service.tree().tree(vrf, None, None));
    assert_eq!(full.level, AlarmLevel::Critical);
    assert_eq!(
        full.utilization.covered, "128",
        "the allocation did not change"
    );

    // Deleting the second network with its range and address: 64 of 254 (its network and
    // broadcast addresses are usable again), back to a warning.
    run(&service, vec![delete(second_id, true)]).await;
    let event = alarm_of(&service, outer_id).await.expect("warning");
    assert_eq!(
        (event.level, event.previous, event.capacity, event.permille),
        (AlarmLevel::Warning, AlarmLevel::Critical, 254, 252)
    );
    // Deleting the first takes its range and address: 2 of 256, below the threshold.
    run(&service, vec![delete(first_id, true)]).await;
    let event = alarm_of(&service, outer_id).await.expect("normal");
    assert_eq!(
        (event.level, event.previous, event.permille),
        (AlarmLevel::Normal, AlarmLevel::Warning, 8)
    );
    // Restoring the first brings its range back.
    run(&service, vec![restore(first_id)]).await;
    let event = alarm_of(&service, outer_id).await.expect("warning again");
    assert_eq!(event.level, AlarmLevel::Warning);
    // Deleting the alarmed prefix itself clears its alarm.
    run(&service, vec![delete(outer_id, true)]).await;
    let event = alarm_of(&service, outer_id).await.expect("cleared");
    assert_eq!(
        (event.level, event.previous),
        (AlarmLevel::Normal, AlarmLevel::Warning)
    );
    // Restoring brings the level back.
    run(&service, vec![restore(outer_id)]).await;
    assert_eq!(
        alarm_of(&service, outer_id).await.expect("event").level,
        AlarmLevel::Warning
    );
}

#[tokio::test]
async fn ipam_10_supernet_utilization_sums_its_tree_and_counts_an_address_once() {
    let (service, _) = service();
    // 198.51.100.0/23 holds a nested supernet /24 with two networks and one network of its
    // own; an address lies directly in the nested supernet.
    let outer = supernet(None, "198.51.100.0/23");
    let outer_id = outer.id.expect("id");
    let inner = supernet(None, "198.51.100.0/24");
    let inner_id = inner.id.expect("id");
    let a = prefix(None, "198.51.100.0/26");
    let a_id = a.id.expect("id");
    let b = prefix(None, "198.51.100.64/26");
    let c = prefix(None, "198.51.101.0/25");
    let c_id = c.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
            IpamCommand::CreatePrefix(a),
            IpamCommand::CreatePrefix(b),
            IpamCommand::CreatePrefix(c),
        ],
    )
    .await;
    let vrf = fetch::<Prefix>(&service, outer_id).await.vrf;
    let empty = service.tree().utilization(outer_id).expect("utilization");
    assert_eq!(
        (empty.used, empty.reserved, empty.covered, empty.size),
        (0, 0, 384, 512),
        "a tree without addresses is at 0 % with its allocation apart"
    );
    // Three networks lose two addresses each.
    assert_eq!(empty.capacity, 506);
    assert_eq!(empty.permille(), 0);

    run(
        &service,
        vec![
            IpamCommand::CreateAddress(address(None, "198.51.100.10")),
            IpamCommand::CreateAddress(address(None, "198.51.100.11")),
            IpamCommand::CreateAddress(address(None, "198.51.100.200")),
            IpamCommand::CreateAddress(address(None, "198.51.101.5")),
            IpamCommand::CreateRange(range(
                c_id,
                "198.51.101.20",
                "198.51.101.29",
                RangeRole::Infrastructure,
            )),
        ],
    )
    .await;
    let outer = service.tree().utilization(outer_id).expect("utilization");
    // Each address once, though the first two lie two levels down.
    assert_eq!((outer.used, outer.reserved, outer.in_use()), (4, 10, 14));
    assert_eq!(outer.free, 506 - 14);
    let inner = service.tree().utilization(inner_id).expect("utilization");
    assert_eq!((inner.used, inner.reserved, inner.capacity), (3, 0, 252));
    assert_eq!((inner.covered, inner.size), (128, 256));
    let network = service.tree().utilization(a_id).expect("utilization");
    assert_eq!((network.used, network.capacity, network.size), (2, 62, 64));
    // The sum of the parts equals the whole: the networks plus what lies directly inside.
    let view = service
        .tree()
        .tree(vrf, None, None)
        .into_iter()
        .find(|n| n.id == outer_id)
        .expect("node");
    assert_eq!(view.utilization.in_use, "14");
    assert_eq!(view.utilization.used, "4");
    assert_eq!(view.utilization.by_role[0].role, RangeRole::Infrastructure);
    assert_eq!(view.children, 2);
}

// ----- lookups and state errors ---------------------------------------------------------------

#[tokio::test]
async fn lookups_and_state_errors_have_their_own_codes() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network.clone())]).await;

    let error = run_err(
        &service,
        vec![describe_prefix(PrefixId::generate(), "x")],
        codes::NOT_FOUND,
    )
    .await;
    assert_eq!(status_of(&error), 404);
    let error = run_err(
        &service,
        vec![IpamCommand::CreatePrefix(network)],
        codes::ID_TAKEN,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    let error = run_err(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "198.51.100.1/24"))],
        codes::PREFIX_HOST_BITS,
    )
    .await;
    assert_eq!(status_of(&error), 400);
    assert_eq!(error.coded().params["network"], "198.51.100.0/24");

    // References must exist and be live.
    let mut with_vlan = prefix(None, "198.51.100.0/24");
    with_vlan.vlan = Some(VlanId::generate());
    let error = run_err(
        &service,
        vec![IpamCommand::CreatePrefix(with_vlan)],
        codes::REFERENCE_MISSING,
    )
    .await;
    assert_eq!(error.coded().params["field"], "vlan");
    let mut with_interface = address(None, "192.0.2.10");
    with_interface.interface = Some(InterfaceId::generate());
    run_err(
        &service,
        vec![IpamCommand::CreateAddress(with_interface)],
        codes::REFERENCE_MISSING,
    )
    .await;
    let mut in_vrf = prefix(None, "198.51.100.0/24");
    in_vrf.vrf = Some(VrfId::generate());
    run_err(
        &service,
        vec![IpamCommand::CreatePrefix(in_vrf)],
        codes::REFERENCE_MISSING,
    )
    .await;

    // Deleted objects: no second delete, no update, no restore of what is alive.
    run_err(&service, vec![restore(network_id)], codes::NOT_DELETED).await;
    run(&service, vec![delete(network_id, false)]).await;
    let error = run_err(
        &service,
        vec![delete(network_id, false)],
        codes::OBJECT_DELETED,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    run_err(
        &service,
        vec![describe_prefix(network_id, "x")],
        codes::OBJECT_DELETED,
    )
    .await;
    // Only IPAM kinds are managed here.
    let error = run_err(
        &service,
        vec![delete(
            ObjectRef::new(ObjectKind::User, network_id.uuid()),
            false,
        )],
        codes::VALIDATION,
    )
    .await;
    assert_eq!(status_of(&error), 400);
}

#[tokio::test]
async fn host_expansion_shows_live_interfaces_and_hosts() {
    use tenko_ipam::query::{self, AddressRow, Deleted, HostExpander, HostSummary, ListQuery};

    let (service, _) = service();
    let (input, interface) = host("host-01", AssignmentMode::Static, Some("00-00-5E-00-53-03"));
    let host_id = input.id.expect("id");
    let mut first = address(None, "192.0.2.10");
    first.interface = Some(interface);
    let mut second = address(None, "192.0.2.11");
    second.interface = Some(interface);
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreateHost(input),
            IpamCommand::CreateAddress(first),
            IpamCommand::CreateAddress(second),
            IpamCommand::CreateAddress(address(None, "192.0.2.12")),
        ],
    )
    .await;
    let rows = |deleted: Deleted| {
        let service = service.clone();
        async move {
            let view = service.view(None).await.expect("view");
            let query = ListQuery {
                deleted,
                ..ListQuery::default()
            };
            let page = query::list::<Address>(view.as_ref(), &query).expect("list");
            let mut expander = HostExpander::new(view.as_ref());
            let mut rows: Vec<AddressRow> = page.items.into_iter().map(AddressRow::from).collect();
            for row in &mut rows {
                expander.expand(row).expect("expand");
            }
            rows
        }
    };
    let live = rows(Deleted::Exclude).await;
    assert_eq!(live.len(), 3);
    for row in &live[..2] {
        let detail = row.interface_detail.as_ref().expect("interface");
        assert_eq!((detail.id, detail.name.as_str()), (interface, "eth0"));
        assert!(detail.mac.is_some());
        assert_eq!(
            row.host,
            Some(HostSummary {
                id: host_id,
                name: "host-01".parse().expect("name"),
                mode: AssignmentMode::Static,
                lock: false,
            })
        );
    }
    assert_eq!((&live[2].interface_detail, &live[2].host), (&None, &None));

    // Deleted with their host: the restore view shows no interface or host.
    run(
        &service,
        vec![IpamCommand::Delete {
            object: host_id.into(),
            expected: None,
            cascade: true,
        }],
    )
    .await;
    let gone = rows(Deleted::Only).await;
    assert_eq!(gone.len(), 2);
    for row in &gone {
        assert_eq!(row.address.interface, Some(interface));
        assert_eq!((&row.interface_detail, &row.host), (&None, &None));
    }
}

#[tokio::test]
async fn defaults_are_ensured_once_by_the_system_and_reused_by_first_use() {
    let (service, _) = service();
    let cx = RequestCtx::system(SystemComponent::Setup);
    let first = service.ensure_defaults(&cx).await.expect("defaults");
    assert!(first.job_id.is_some(), "the first call writes");
    let (tenant, vrf): (TenantId, VrfId) = match first.results[..] {
        [tenant, vrf] => (tenant.id.into(), vrf.id.into()),
        _ => panic!("two results: {:?}", first.results),
    };
    let view = service.view(Some(first.revision)).await.expect("view");
    let tenants = query::list::<Tenant>(view.as_ref(), &query::ListQuery::default())
        .expect("tenants")
        .items;
    let vrfs = query::list::<Vrf>(view.as_ref(), &query::ListQuery::default())
        .expect("vrfs")
        .items;
    assert_eq!(tenants.len(), 1);
    assert_eq!(
        (tenants[0].id, tenants[0].name.as_str()),
        (tenant, "default")
    );
    assert_eq!(vrfs.len(), 1);
    assert_eq!((vrfs[0].id, vrfs[0].name.as_str()), (vrf, "default"));
    assert_eq!(vrfs[0].tenant, tenant);
    // Audited under the system principal of the call, with the history entries.
    let records = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit");
    assert_eq!(records.len(), 2, "one record per object");
    for (_, record, _) in &records {
        assert_eq!(record.principal, cx.principal);
        assert_eq!(record.request, Some(cx.request));
    }
    for object in [ObjectRef::from(tenant), ObjectRef::from(vrf)] {
        let history = read_history(view.as_ref(), object, None, 10, false).expect("history");
        assert_eq!(history.len(), 1, "{object}");
        assert_eq!(history[0].1.action, ChangeAction::Create);
    }
    drop(view);

    // Again: nothing is written, the answer names the same objects.
    let again = service
        .ensure_defaults(&RequestCtx::system(SystemComponent::Ipam))
        .await
        .expect("again");
    assert_eq!(again.job_id, None);
    assert_eq!(again.revision, first.revision);
    assert_eq!(again.results, first.results);
    // The first write that needs a VRF uses the ensured one.
    let applied = run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    let view = service.view(Some(applied.revision)).await.expect("view");
    let created =
        query::get::<Prefix>(view.as_ref(), applied.results[0].id.into()).expect("prefix");
    assert_eq!(created.vrf, vrf);
    assert_eq!(
        query::list::<Vrf>(view.as_ref(), &query::ListQuery::default())
            .expect("vrfs")
            .items
            .len(),
        1
    );
}

#[tokio::test]
async fn defaults_created_on_first_use_are_kept_by_a_later_ensure() {
    let (service, _) = service();
    let applied = run(
        &service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    let view = service.view(Some(applied.revision)).await.expect("view");
    let created =
        query::get::<Prefix>(view.as_ref(), applied.results[0].id.into()).expect("prefix");
    drop(view);
    let ensured = service
        .ensure_defaults(&RequestCtx::system(SystemComponent::Ipam))
        .await
        .expect("defaults");
    assert_eq!(ensured.job_id, None, "nothing to write");
    assert_eq!(ensured.results[1], ObjectRef::from(created.vrf));
}
