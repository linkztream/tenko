//! The lifecycle of a host through the service: decommissioning releases its addresses and
//! DNS names, a decommissioned host takes no address, and reinstating binds back what is
//! still free and warns about what is not.

mod common;

use std::sync::Arc;

use common::*;
use tenko_core::{
    AddressId, HostId, InterfaceId, ObjectRef,
    audit::AuditRecord,
    ipam::{Address, AssignmentMode, Host, Interface},
};
use tenko_ipam::{
    ChangeAction, IpamCommand, IpamService, PlanOptions, codes,
    command::{AddressPatch, DecommissionHost, UpdateAddress},
    history::read_history,
    query::{self, HostLifecycle, ListQuery},
};
use tenko_store::{KeyRange, ReadViewExt, tables::AUDIT};

/// A network with one host `app01` (eth0, MAC :01) holding two addresses and a second
/// host `other01` (MAC :02) holding none.
struct Lab {
    service: Arc<IpamService>,
    app: HostId,
    eth0: InterfaceId,
    named: AddressId,
    bare: AddressId,
    other_eth0: InterfaceId,
}

impl Lab {
    async fn new() -> Self {
        let (service, _store) = service();
        let (app_input, eth0) = host("app01", AssignmentMode::Static, Some("00:00:5e:00:53:01"));
        let app = app_input.id.expect("id");
        let (other_input, other_eth0) =
            host("other01", AssignmentMode::Static, Some("00:00:5e:00:53:02"));
        let mut named = address(None, "192.0.2.10");
        named.interface = Some(eth0);
        named.dns_name = Some("app01.example.test".parse().expect("name"));
        let named_id = named.id.expect("id");
        let mut bare = address(None, "192.0.2.11");
        bare.interface = Some(eth0);
        let bare_id = bare.id.expect("id");
        run(
            &service,
            vec![
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreateHost(app_input),
                IpamCommand::CreateHost(other_input),
                IpamCommand::CreateAddress(named),
                IpamCommand::CreateAddress(bare),
            ],
        )
        .await;
        Self {
            service,
            app,
            eth0,
            named: named_id,
            bare: bare_id,
            other_eth0,
        }
    }

    fn decommission(&self, keep_dns: bool) -> IpamCommand {
        IpamCommand::DecommissionHost(DecommissionHost {
            host: self.app,
            reason: Some("replaced by a new guest".to_owned()),
            keep_dns,
            expected: None,
        })
    }

    fn reinstate(&self) -> IpamCommand {
        IpamCommand::ReinstateHost {
            host: self.app,
            expected: None,
        }
    }

    async fn host(&self) -> Host {
        fetch::<Host>(&self.service, self.app).await
    }

    async fn address(&self, id: AddressId) -> Address {
        fetch::<Address>(&self.service, id).await
    }

    /// Puts the named address on the interface of the other host.
    async fn give_named_to_other(&self) {
        run(
            &self.service,
            vec![IpamCommand::UpdateAddress(UpdateAddress {
                id: self.named,
                expected: None,
                patch: AddressPatch {
                    interface: Some(Some(self.other_eth0)),
                    ..AddressPatch::default()
                },
            })],
        )
        .await;
    }
}

fn name_of(address: &Address) -> Option<String> {
    address.dns_name.as_ref().map(ToString::to_string)
}

fn audit_actions(plan: &tenko_ipam::IpamPlan) -> Vec<&str> {
    plan.audit
        .iter()
        .map(|draft| draft.action.as_str())
        .collect()
}

#[tokio::test]
async fn decommissioning_a_host_releases_its_addresses_and_records_the_lost_names() {
    let lab = Lab::new().await;
    let applied = run(&lab.service, vec![lab.decommission(false)]).await;
    assert_eq!(applied.results, [ObjectRef::from(lab.app)]);
    assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);

    let named = lab.address(lab.named).await;
    let bare = lab.address(lab.bare).await;
    assert_eq!(named.interface, None);
    assert_eq!(bare.interface, None);
    assert_eq!(
        name_of(&named),
        None,
        "the DNS name is released with the address"
    );
    assert!(!named.meta.is_deleted() && !bare.meta.is_deleted());

    let host = lab.host().await;
    assert!(host.is_decommissioned());
    let record = host.decommissioned.expect("the record");
    assert_eq!(record.reason.as_deref(), Some("replaced by a new guest"));
    assert!(!record.kept_dns);
    assert_eq!(record.released.len(), 2);
    let released = |id: AddressId| {
        record
            .released
            .iter()
            .find(|released| released.address == id)
            .expect("a released address")
    };
    assert_eq!(released(lab.named).interface, lab.eth0);
    assert_eq!(
        released(lab.named)
            .dns_name
            .as_ref()
            .map(ToString::to_string),
        Some("app01.example.test".to_owned())
    );
    assert_eq!(released(lab.bare).interface, lab.eth0);
    assert_eq!(released(lab.bare).dns_name, None, "it had no name to lose");

    // The interface stays, so the reconciler still knows the MAC address of the host.
    let interface = fetch::<Interface>(&lab.service, lab.eth0).await;
    assert!(!interface.meta.is_deleted());
    assert_eq!(interface.host, lab.app);
}

#[tokio::test]
async fn keeping_the_dns_names_releases_the_addresses_but_not_the_names() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(true)]).await;
    let named = lab.address(lab.named).await;
    assert_eq!(named.interface, None);
    assert_eq!(name_of(&named).as_deref(), Some("app01.example.test"));
    let record = lab.host().await.decommissioned.expect("the record");
    assert!(record.kept_dns);
    assert_eq!(record.released.len(), 2);
    assert!(
        record
            .released
            .iter()
            .all(|released| released.dns_name.is_none()),
        "{:?}",
        record.released
    );
}

#[tokio::test]
async fn the_reason_of_a_decommission_is_trimmed_and_bounded() {
    let lab = Lab::new().await;
    let with_reason = |reason: String| {
        IpamCommand::DecommissionHost(DecommissionHost {
            host: lab.app,
            reason: Some(reason),
            keep_dns: false,
            expected: None,
        })
    };
    let error = run_err(
        &lab.service,
        vec![with_reason("x".repeat(1_025))],
        codes::VALIDATION,
    )
    .await;
    assert_eq!(status_of(&error), 400);
    assert!(
        !lab.host().await.is_decommissioned(),
        "a refused request changes nothing"
    );

    run(&lab.service, vec![with_reason("  \t ".to_owned())]).await;
    let record = lab.host().await.decommissioned.expect("the record");
    assert_eq!(record.reason, None, "a blank reason is no reason");
}

#[tokio::test]
async fn a_decommission_is_one_host_change_and_the_address_changes_around_it() {
    let lab = Lab::new().await;
    let cx = person();
    let plan = lab
        .service
        .preview(
            &[lab.decommission(false)],
            &cx,
            &PlanOptions::default(),
            None,
        )
        .await
        .expect("preview");
    let actions = audit_actions(&plan);
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == "ipam.host.decommission")
            .count(),
        1,
        "{actions:?}"
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == "ipam.address.update")
            .count(),
        2,
        "the address changes stay address updates: {actions:?}"
    );
    assert_eq!(actions.len(), plan.changes.len());
    let host_draft = plan
        .audit
        .iter()
        .find(|draft| draft.action.as_str() == "ipam.host.decommission")
        .expect("the host draft");
    assert_eq!(host_draft.objects, [ObjectRef::from(lab.app)]);

    // A preview writes nothing.
    assert!(!lab.host().await.is_decommissioned());

    let applied = lab.service.apply(&plan, &cx).await.expect("apply");
    let view = lab
        .service
        .view(Some(applied.revision))
        .await
        .expect("view");

    // The history shows an update of the host and an update of each address.
    let history =
        read_history(view.as_ref(), ObjectRef::from(lab.app), None, 10, false).expect("history");
    let actions: Vec<ChangeAction> = history.iter().map(|(_, entry)| entry.action).collect();
    assert_eq!(actions, [ChangeAction::Create, ChangeAction::Update]);
    let update = &history[1].1;
    assert!(update.before.is_some() && update.after.is_some());
    let address_history =
        read_history(view.as_ref(), ObjectRef::from(lab.named), None, 10, false).expect("history");
    assert_eq!(address_history.len(), 2, "created, then unassigned");
    assert_eq!(address_history[1].1.action, ChangeAction::Update);

    // The stored audit trail holds the lifecycle action.
    let records: Vec<AuditRecord> = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect();
    let committed: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| record.revision == applied.revision)
        .collect();
    assert_eq!(committed.len(), 3);
    assert!(
        committed.iter().any(
            |record| record.draft.action.as_str() == "ipam.host.decommission"
                && record.draft.objects == [ObjectRef::from(lab.app)]
        ),
        "{:?}",
        committed
            .iter()
            .map(|record| record.draft.action.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn decommissioning_a_host_twice_is_a_conflict() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    let before = lab.host().await;
    let error = run_err(
        &lab.service,
        vec![lab.decommission(false)],
        codes::HOST_DECOMMISSIONED,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(
        lab.host().await.decommissioned,
        before.decommissioned,
        "the first record stays"
    );
}

#[tokio::test]
async fn a_decommissioned_host_takes_no_address_on_its_interfaces() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;

    // Creating an address on its interface.
    let mut fresh = address(None, "192.0.2.50");
    fresh.interface = Some(lab.eth0);
    let error = run_err(
        &lab.service,
        vec![IpamCommand::CreateAddress(fresh)],
        codes::HOST_DECOMMISSIONED,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    // Binding a released address to it again.
    let error = run_err(
        &lab.service,
        vec![IpamCommand::UpdateAddress(UpdateAddress {
            id: lab.bare,
            expected: None,
            patch: AddressPatch {
                interface: Some(Some(lab.eth0)),
                ..AddressPatch::default()
            },
        })],
        codes::HOST_DECOMMISSIONED,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    assert_eq!(lab.address(lab.bare).await.interface, None);

    // An address without an interface, and another host's interface, are not affected.
    run(
        &lab.service,
        vec![IpamCommand::CreateAddress(address(None, "192.0.2.51"))],
    )
    .await;
    let mut other = address(None, "192.0.2.52");
    other.interface = Some(lab.other_eth0);
    run(&lab.service, vec![IpamCommand::CreateAddress(other)]).await;
}

#[tokio::test]
async fn reinstating_a_host_binds_its_addresses_again_and_restores_the_names() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    let applied = run(&lab.service, vec![lab.reinstate()]).await;
    assert_eq!(applied.results, [ObjectRef::from(lab.app)]);
    assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);

    let host = lab.host().await;
    assert!(!host.is_decommissioned());
    assert_eq!(host.decommissioned, None);
    let named = lab.address(lab.named).await;
    let bare = lab.address(lab.bare).await;
    assert_eq!(named.interface, Some(lab.eth0));
    assert_eq!(bare.interface, Some(lab.eth0));
    assert_eq!(name_of(&named).as_deref(), Some("app01.example.test"));
    assert_eq!(name_of(&bare), None);

    // Active again: it takes addresses and can be decommissioned once more.
    let mut fresh = address(None, "192.0.2.50");
    fresh.interface = Some(lab.eth0);
    run(&lab.service, vec![IpamCommand::CreateAddress(fresh)]).await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    assert_eq!(
        lab.host()
            .await
            .decommissioned
            .expect("the record")
            .released
            .len(),
        3
    );
}

#[tokio::test]
async fn the_audit_action_of_a_reinstatement_is_the_lifecycle_action() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    let plan = lab
        .service
        .preview(&[lab.reinstate()], &person(), &PlanOptions::default(), None)
        .await
        .expect("preview");
    let actions = audit_actions(&plan);
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == "ipam.host.reinstate")
            .count(),
        1,
        "{actions:?}"
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == "ipam.address.update")
            .count(),
        2,
        "{actions:?}"
    );
    assert_eq!(plan.warnings, Vec::<tenko_ipam::PlanWarning>::new());
}

#[tokio::test]
async fn reinstating_keeps_a_name_the_address_got_in_the_meantime() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    run(
        &lab.service,
        vec![IpamCommand::UpdateAddress(UpdateAddress {
            id: lab.named,
            expected: None,
            patch: AddressPatch {
                dns_name: Some(Some("spare.example.test".parse().expect("name"))),
                ..AddressPatch::default()
            },
        })],
    )
    .await;
    let applied = run(&lab.service, vec![lab.reinstate()]).await;
    assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
    let named = lab.address(lab.named).await;
    assert_eq!(named.interface, Some(lab.eth0));
    assert_eq!(name_of(&named).as_deref(), Some("spare.example.test"));
}

#[tokio::test]
async fn reinstating_warns_about_an_address_another_host_took_in_the_meantime() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    lab.give_named_to_other().await;

    let applied = run(&lab.service, vec![lab.reinstate()]).await;
    assert_eq!(applied.warnings.len(), 1, "{:?}", applied.warnings);
    let warning = &applied.warnings[0];
    assert_eq!(warning.code, codes::WARN_REINSTATE_SKIPPED);
    assert_eq!(warning.code, "ipam.host.reinstate_skipped");
    assert!(
        !warning.requires_ack,
        "a skipped address does not stop the reinstatement"
    );
    assert_eq!(warning.object, Some(ObjectRef::from(lab.named)));
    assert_eq!(warning.params["address"], lab.named.to_string());
    assert_eq!(warning.params["ip"], "192.0.2.10");
    assert_eq!(warning.params["cause"], "assigned");

    // The host is active; the address stays where it is; the free one came back.
    assert!(!lab.host().await.is_decommissioned());
    assert_eq!(lab.address(lab.named).await.interface, Some(lab.other_eth0));
    assert_eq!(lab.address(lab.bare).await.interface, Some(lab.eth0));
}

#[tokio::test]
async fn reinstating_warns_about_a_deleted_address() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    run(
        &lab.service,
        vec![IpamCommand::Delete {
            object: lab.bare.into(),
            expected: None,
            cascade: false,
        }],
    )
    .await;
    let applied = run(&lab.service, vec![lab.reinstate()]).await;
    assert_eq!(applied.warnings.len(), 1, "{:?}", applied.warnings);
    let warning = &applied.warnings[0];
    assert_eq!(warning.code, codes::WARN_REINSTATE_SKIPPED);
    assert_eq!(warning.params["address"], lab.bare.to_string());
    assert_eq!(warning.params["cause"], "deleted");
    let deleted = lab.address(lab.bare).await;
    assert_eq!(warning.params["ip"], deleted.ip.to_string());
    assert_eq!(lab.address(lab.named).await.interface, Some(lab.eth0));
    assert!(lab.address(lab.bare).await.meta.is_deleted());
    assert!(!lab.host().await.is_decommissioned());
}

#[tokio::test]
async fn reinstating_warns_when_the_interface_is_gone() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    run(
        &lab.service,
        vec![IpamCommand::Delete {
            object: lab.eth0.into(),
            expected: None,
            cascade: false,
        }],
    )
    .await;
    let applied = run(&lab.service, vec![lab.reinstate()]).await;
    assert_eq!(applied.warnings.len(), 2, "{:?}", applied.warnings);
    assert!(
        applied
            .warnings
            .iter()
            .all(|warning| warning.code == codes::WARN_REINSTATE_SKIPPED
                && warning.params["cause"] == "interface_gone"),
        "{:?}",
        applied.warnings
    );
    for id in [lab.named, lab.bare] {
        assert_eq!(lab.address(id).await.interface, None);
    }
    assert!(!lab.host().await.is_decommissioned());
}

#[tokio::test]
async fn reinstating_an_active_host_is_a_conflict() {
    let lab = Lab::new().await;
    let error = run_err(
        &lab.service,
        vec![lab.reinstate()],
        codes::HOST_NOT_DECOMMISSIONED,
    )
    .await;
    assert_eq!(status_of(&error), 409);

    // And again after a full round trip.
    run(&lab.service, vec![lab.decommission(false)]).await;
    run(&lab.service, vec![lab.reinstate()]).await;
    run_err(
        &lab.service,
        vec![lab.reinstate()],
        codes::HOST_NOT_DECOMMISSIONED,
    )
    .await;
}

#[tokio::test]
async fn a_stale_revision_refuses_the_lifecycle_commands() {
    let lab = Lab::new().await;
    let stale = lab.host().await.meta.revision;
    // Any change of the host moves its revision on.
    run(
        &lab.service,
        vec![IpamCommand::SetLock {
            host: lab.app,
            lock: true,
            expected: None,
        }],
    )
    .await;
    let error = run_err(
        &lab.service,
        vec![IpamCommand::DecommissionHost(DecommissionHost {
            host: lab.app,
            reason: None,
            keep_dns: false,
            expected: Some(stale),
        })],
        codes::REVISION_MISMATCH,
    )
    .await;
    assert_eq!(status_of(&error), 412);
    assert!(!lab.host().await.is_decommissioned());
}

#[tokio::test]
async fn a_locked_host_is_decommissioned_by_a_person_but_not_by_automation() {
    let lab = Lab::new().await;
    run(
        &lab.service,
        vec![IpamCommand::SetLock {
            host: lab.app,
            lock: true,
            expected: None,
        }],
    )
    .await;
    let error = run_err_as(
        &lab.service,
        vec![lab.decommission(false)],
        &automation(),
        codes::HOST_LOCKED,
    )
    .await;
    assert_eq!(status_of(&error), 423);
    assert!(!lab.host().await.is_decommissioned());
    run(&lab.service, vec![lab.decommission(false)]).await;
    assert!(lab.host().await.is_decommissioned());
}

#[tokio::test]
async fn an_unknown_host_cannot_be_decommissioned_or_reinstated() {
    let lab = Lab::new().await;
    let missing = HostId::generate();
    let decommission = IpamCommand::DecommissionHost(DecommissionHost {
        host: missing,
        reason: None,
        keep_dns: false,
        expected: None,
    });
    run_err(&lab.service, vec![decommission], codes::NOT_FOUND).await;
    let reinstate = IpamCommand::ReinstateHost {
        host: missing,
        expected: None,
    };
    run_err(&lab.service, vec![reinstate], codes::NOT_FOUND).await;
}

#[tokio::test]
async fn the_host_list_filters_by_lifecycle_state() {
    let lab = Lab::new().await;
    run(&lab.service, vec![lab.decommission(false)]).await;
    let list = async |lifecycle: Option<HostLifecycle>| {
        let view = lab.service.view(None).await.expect("view");
        let query = ListQuery {
            lifecycle,
            ..ListQuery::default()
        };
        let mut hosts: Vec<String> = query::list::<Host>(view.as_ref(), &query)
            .expect("list")
            .items
            .into_iter()
            .map(|host| host.name.to_string())
            .collect();
        hosts.sort();
        hosts
    };
    assert_eq!(HostLifecycle::default(), HostLifecycle::Active);
    assert_eq!(list(Some(HostLifecycle::Active)).await, ["other01"]);
    assert_eq!(list(Some(HostLifecycle::Decommissioned)).await, ["app01"]);
    assert_eq!(list(Some(HostLifecycle::All)).await, ["app01", "other01"]);
    assert_eq!(
        list(None).await,
        ["app01", "other01"],
        "the service lists every host unless it is asked for a state"
    );

    run(&lab.service, vec![lab.reinstate()]).await;
    assert_eq!(
        list(Some(HostLifecycle::Decommissioned)).await,
        Vec::<String>::new()
    );
    assert_eq!(
        list(Some(HostLifecycle::Active)).await,
        ["app01", "other01"]
    );
}
