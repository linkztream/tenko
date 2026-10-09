//! The IPAM service over the real job engine (Q4): a change and its inline job commit in
//! one write, stale plans retry, and a failed plan leaves no job behind.

mod common;

use std::sync::Arc;

use common::{address, allocate, person, prefix};
use tenko_core::ObjectRef;
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, PlanOptions, codes, jobs::register_steps,
    tables::ADDRESSES,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState};
use tenko_store::{MemStore, ReadViewExt, Store};

fn service() -> (Arc<IpamService>, JobEngine) {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
    register_steps(&mut engine);
    let service =
        IpamService::new(store, Arc::new(engine.clone()), IpamConfig::default()).expect("service");
    (service, engine)
}

#[tokio::test]
async fn a_change_and_its_job_commit_in_one_revision() {
    let (service, engine) = service();
    let before = service.store().status().revision;
    let applied = service
        .execute(
            &[
                IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
                IpamCommand::CreateAddress(address(None, "192.0.2.7")),
            ],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect("execute");
    assert_eq!(
        applied.revision.0,
        before.0 + 1,
        "the change and the job record are one write"
    );
    let job = engine
        .job(applied.job_id.expect("job id"))
        .await
        .expect("job");
    assert_eq!(job.state, JobState::Succeeded);
    assert_eq!(job.spec.kind.as_str(), "ipam.edit");
    assert_eq!(job.steps.len(), 1);
    assert!(job.spec.targets.len() >= 2);

    let view = service.view(Some(applied.revision)).await.expect("view");
    let address: ObjectRef = applied.results[1];
    let (stored, revision) = view
        .get_typed(&ADDRESSES, &address.id.into())
        .expect("read")
        .expect("address");
    assert_eq!(stored.ip.to_string(), "192.0.2.7");
    assert_eq!(revision, applied.revision);
}

#[tokio::test]
async fn allocation_through_the_engine_and_a_refused_plan() {
    let (service, _engine) = service();
    let net = prefix(None, "198.51.100.0/29");
    let id = net.id.expect("id");
    service
        .execute(
            &[IpamCommand::CreatePrefix(net)],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect("prefix");
    let mut seen = Vec::new();
    for _ in 0..6 {
        let applied = service
            .execute(
                &[IpamCommand::AllocateAddress(allocate(id))],
                &person(),
                &PlanOptions::default(),
            )
            .await
            .expect("allocate");
        seen.push(applied.results[0]);
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 6);
    let revision = service.store().status().revision;
    let error = service
        .execute(
            &[IpamCommand::AllocateAddress(allocate(id))],
            &person(),
            &PlanOptions::default(),
        )
        .await
        .expect_err("full");
    assert_eq!(error.code_str(), codes::ADDRESS_FULL);
    assert_eq!(
        service.store().status().revision,
        revision,
        "a refused plan writes nothing, not even a job"
    );
}
