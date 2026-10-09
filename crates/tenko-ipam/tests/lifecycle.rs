//! End-to-end rules of the IPAM domain over `MemStore`: defaults, overlap, most specific
//! prefix, next free, soft delete and restore with history, locks, alarms and
//! acknowledgements.

mod common;

use common::*;
use tenko_core::{
    ObjectRef, PrefixId,
    ipam::{Address, AssignmentMode, Prefix, PrefixRole, RangeRole, Status},
};
use tenko_ipam::{
    AlarmLevel, ChangeAction, IpamCommand, PlanOptions, codes,
    command::{PrefixPatch, UpdatePrefix},
    history::read_history,
    tables::{ADDRESSES, ALARMS, PREFIXES},
};
use tenko_store::ReadViewExt;

#[tokio::test]
async fn defaults_overlap_and_most_specific_prefix() {
    let (service, store) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.0/26");
    let applied = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(outer.clone()),
            IpamCommand::CreatePrefix(inner.clone()),
            IpamCommand::CreateAddress(address(None, "192.0.2.10")),
            IpamCommand::CreateAddress(address(None, "192.0.2.200")),
        ],
    )
    .await;
    assert!(applied.job_id.is_some());
    let view = service.view(Some(applied.revision)).await.expect("view");
    let (outer_stored, _) = view
        .get_typed(&PREFIXES, &outer.id.expect("id"))
        .expect("read")
        .expect("outer");
    let (inner_stored, _) = view
        .get_typed(&PREFIXES, &inner.id.expect("id"))
        .expect("read")
        .expect("inner");
    assert_eq!(
        outer_stored.vrf, inner_stored.vrf,
        "both in the default VRF"
    );
    assert_eq!(inner_stored.role, PrefixRole::Network);
    let addresses: Vec<Address> = view
        .scan_typed(&ADDRESSES, tenko_store::KeyRange::all(), 10, false)
        .expect("scan")
        .into_iter()
        .map(|(_, a, _)| a)
        .collect();
    for address in &addresses {
        let expected = if address.ip.to_string() == "192.0.2.10" {
            inner_stored.id
        } else {
            outer_stored.id
        };
        assert_eq!(address.prefix, expected, "{}", address.ip);
    }

    // The same network again, and a prefix inside a network, overlap (IPAM-23).
    for cidr in ["192.0.2.0/26", "192.0.2.0/27"] {
        let error = service
            .execute(
                &[IpamCommand::CreatePrefix(prefix(
                    Some(outer_stored.vrf),
                    cidr,
                ))],
                &person(),
                &PlanOptions::default(),
            )
            .await
            .expect_err("overlap");
        assert_eq!(error.code_str(), codes::PREFIX_OVERLAP, "{cidr}");
    }
    // Another VRF may hold the same space (IPAM-01).
    let other = vrf("lab");
    run(
        &service,
        vec![
            IpamCommand::CreateVrf(other.clone()),
            IpamCommand::CreatePrefix(prefix(other.id, "192.0.2.0/26")),
        ],
    )
    .await;

    // A new prefix between the two takes over the addresses inside it.
    let middle = supernet(Some(outer_stored.vrf), "192.0.2.128/25");
    let applied = run(&service, vec![IpamCommand::CreatePrefix(middle.clone())]).await;
    let view = service.view(Some(applied.revision)).await.expect("view");
    let moved = view
        .scan_typed(&ADDRESSES, tenko_store::KeyRange::all(), 10, false)
        .expect("scan")
        .into_iter()
        .map(|(_, a, _)| a)
        .find(|a| a.ip.to_string() == "192.0.2.200")
        .expect("address");
    assert_eq!(moved.prefix, middle.id.expect("id"));
    drop(store);
}

#[tokio::test]
async fn next_free_skips_ranges_and_used_addresses() {
    let (service, _) = service();
    let net = prefix(None, "198.51.100.0/28");
    let id = net.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(net),
            IpamCommand::CreateRange(range(
                id,
                "198.51.100.1",
                "198.51.100.3",
                RangeRole::Infrastructure,
            )),
            IpamCommand::CreateAddress(address(None, "198.51.100.4")),
        ],
    )
    .await;
    let mut got = Vec::new();
    for _ in 0..3 {
        let applied = run(&service, vec![IpamCommand::AllocateAddress(allocate(id))]).await;
        let view = service.view(Some(applied.revision)).await.expect("view");
        let address: ObjectRef = applied.results[0];
        let (stored, _) = view
            .get_typed(&ADDRESSES, &address.id.into())
            .expect("read")
            .expect("address");
        got.push(stored.ip.to_string());
    }
    assert_eq!(got, ["198.51.100.5", "198.51.100.6", "198.51.100.7"]);
    let utilization = service.tree().utilization(id).expect("utilization");
    assert_eq!(utilization.capacity, 14);
    assert_eq!(utilization.used, 4);
    assert_eq!(utilization.reserved, 3);
}

#[tokio::test]
async fn soft_delete_and_restore_keep_history() {
    let (service, _) = service();
    let net = prefix(None, "203.0.113.0/24");
    let item = address(None, "203.0.113.9");
    let address_id = item.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(net),
            IpamCommand::CreateAddress(item.clone()),
        ],
    )
    .await;
    let reference = ObjectRef::from(address_id);
    run(
        &service,
        vec![IpamCommand::Delete {
            object: reference,
            expected: None,
            cascade: false,
        }],
    )
    .await;
    // The address is free again while deleted.
    run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "203.0.113.10"))],
    )
    .await;
    let restored = run(
        &service,
        vec![IpamCommand::Restore {
            object: reference,
            expected: None,
        }],
    )
    .await;
    let view = service.view(Some(restored.revision)).await.expect("view");
    let (stored, _) = view
        .get_typed(&ADDRESSES, &address_id)
        .expect("read")
        .expect("address");
    assert!(!stored.meta.is_deleted());
    let history = read_history(view.as_ref(), reference, None, 10, false).expect("history");
    let actions: Vec<ChangeAction> = history.iter().map(|(_, e)| e.action).collect();
    assert_eq!(
        actions,
        [
            ChangeAction::Create,
            ChangeAction::Delete,
            ChangeAction::Restore
        ]
    );
    assert!(
        history
            .iter()
            .all(|(_, e)| e.revision > tenko_core::Revision::ZERO)
    );

    // Restoring onto a taken address is a conflict.
    let taken = address(None, "203.0.113.20");
    let taken_ref = ObjectRef::from(taken.id.expect("id"));
    run(&service, vec![IpamCommand::CreateAddress(taken.clone())]).await;
    run(
        &service,
        vec![IpamCommand::Delete {
            object: taken_ref,
            expected: None,
            cascade: false,
        }],
    )
    .await;
    run(
        &service,
        vec![IpamCommand::CreateAddress(address(None, "203.0.113.20"))],
    )
    .await;
    let error = service
        .execute(
            &[IpamCommand::Restore {
                object: taken_ref,
                expected: None,
            }],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("conflict");
    assert_eq!(error.code_str(), codes::ADDRESS_DUPLICATE);
}

#[tokio::test]
async fn lock_stops_automation_but_not_people() {
    let (service, _) = service();
    let (host, interface) = host("nas01", AssignmentMode::Static, Some("00-00-5E-00-53-01"));
    let host_id = host.id.expect("id");
    run(
        &service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreateHost(host),
            IpamCommand::SetLock {
                host: host_id,
                lock: true,
                expected: None,
            },
        ],
    )
    .await;
    let mut assigned = address(None, "192.0.2.50");
    assigned.interface = Some(interface);
    let command = vec![IpamCommand::CreateAddress(assigned)];
    let error = service
        .execute(&command, &automation(), &PlanOptions::default())
        .await
        .expect_err("locked");
    assert_eq!(error.code_str(), codes::HOST_LOCKED);
    service
        .execute(&command, &person(), &PlanOptions::default())
        .await
        .expect("a person may edit a locked host");
    let error = service
        .execute(
            &[IpamCommand::SetLock {
                host: host_id,
                lock: false,
                expected: None,
            }],
            &automation(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("manual only");
    assert_eq!(error.code_str(), codes::HOST_LOCK_MANUAL_ONLY);
}

#[tokio::test]
async fn reserved_host_without_mac_warns() {
    let (service, _) = service();
    let (host, interface) = host("printer", AssignmentMode::Reserved, None);
    let mut assigned = address(None, "192.0.2.60");
    assigned.interface = Some(interface);
    let applied = run(
        &service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreateHost(host),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    assert!(
        applied
            .warnings
            .iter()
            .any(|w| w.code == codes::WARN_RESERVATION_IDENTIFIER)
    );
}

#[tokio::test]
async fn nibble_boundary_needs_acknowledgement() {
    let (service, _) = service();
    let command = vec![IpamCommand::CreatePrefix(prefix(None, "2001:db8::/62"))];
    let error = service
        .execute(&command, &person(), &PlanOptions::default())
        .await
        .expect_err("ack");
    assert_eq!(error.code_str(), codes::PLAN_UNACKNOWLEDGED);
    service
        .execute(
            &command,
            &person(),
            &PlanOptions::acknowledging([codes::WARN_NIBBLE]),
        )
        .await
        .expect("acknowledged");
}

#[tokio::test]
async fn alarms_fire_and_clear() {
    let (service, _) = service();
    let net = alarmed(None, "192.0.2.0/29", 50, 80);
    let id: PrefixId = net.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(net)]).await;
    // Capacity 6: 3 used is 50 %, 5 used is 83 %.
    let mut last = None;
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        last = Some(
            run(
                &service,
                vec![IpamCommand::CreateAddress(address(None, ip))],
            )
            .await,
        );
    }
    let view = service.view(last.map(|a| a.revision)).await.expect("view");
    let (event, _) = view.get_typed(&ALARMS, &id).expect("read").expect("alarm");
    assert_eq!(event.level, AlarmLevel::Warning);
    for ip in ["192.0.2.4", "192.0.2.5"] {
        run(
            &service,
            vec![IpamCommand::CreateAddress(address(None, ip))],
        )
        .await;
    }
    let view = service.view(None).await.expect("view");
    let (event, _) = view.get_typed(&ALARMS, &id).expect("read").expect("alarm");
    assert_eq!(event.level, AlarmLevel::Critical);
    assert_eq!(event.previous, AlarmLevel::Warning);
    // Removing the thresholds clears the alarm.
    run(
        &service,
        vec![IpamCommand::UpdatePrefix(UpdatePrefix {
            id,
            expected: None,
            patch: PrefixPatch {
                alarm: Some(None),
                ..PrefixPatch::default()
            },
        })],
    )
    .await;
    let view = service.view(None).await.expect("view");
    let (event, _) = view.get_typed(&ALARMS, &id).expect("read").expect("alarm");
    assert_eq!(event.level, AlarmLevel::Normal);
}

#[tokio::test]
async fn status_transitions_are_checked() {
    let (service, _) = service();
    let net = prefix(None, "198.51.100.0/24");
    let id = net.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(net)]).await;
    let update = |status| {
        vec![IpamCommand::UpdatePrefix(UpdatePrefix {
            id,
            expected: None,
            patch: PrefixPatch {
                status: Some(status),
                ..PrefixPatch::default()
            },
        })]
    };
    let error = service
        .execute(&update(Status::Planned), &person(), &PlanOptions::default())
        .await
        .expect_err("active to planned");
    assert_eq!(error.code_str(), codes::STATUS_TRANSITION);
    run(&service, update(Status::Deprecated)).await;
    let view = service.view(None).await.expect("view");
    let (stored, revision) = view
        .get_typed(&PREFIXES, &id)
        .expect("read")
        .expect("prefix");
    assert_eq!(stored.status, Status::Deprecated);
    // A stale If-Match revision is refused.
    let error = service
        .execute(
            &[IpamCommand::UpdatePrefix(UpdatePrefix {
                id,
                expected: Some(tenko_core::Revision(revision.0 - 1)),
                patch: PrefixPatch {
                    description: Some(Some("lab".to_owned())),
                    ..PrefixPatch::default()
                },
            })],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("stale");
    assert_eq!(error.code_str(), codes::REVISION_MISMATCH);
    let _: Option<Prefix> = None;
}
