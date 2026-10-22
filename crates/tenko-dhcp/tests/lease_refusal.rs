//! The refusal path (P3-Q14, WP7.2 content 5) on the Raft store with its test hook: while
//! the file that `TENKO_TEST_REFUSE_WRITES_FILE` names exists, the store refuses every write
//! with `NoQuorum`. The variable is process-wide, so the test runs the scenario in a child
//! process of this test binary that has it set (the environment of the test process itself
//! is never changed).
//!
//! The scenario: a lease commits; the store refuses; the renewal's commit fails and the
//! gate closes; the hand-off refuses; the renewal is answered for the time the lease has
//! left and nothing is written; a new client is dropped and counted; the health finding
//! `dhcp.role.store_refused` is raised; the file goes away, a trial commits after the
//! interval and the finding clears.

mod lease_support;

use std::{path::PathBuf, process::Command, sync::Arc, time::Duration};

use lease_support::{NODE, addr, change, completions, from_now};
use tenko_core::{
    PrefixId, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind},
};
use tenko_dhcp::{
    lease::{
        CommitSettings, LeaseIndex, LeaseTable, SharedLeases, StoreLeases, WhileRefused, metrics,
        rebuild_from_view, refusal::FINDING,
    },
    store::{CommitError, LeaseStore, SubmitError, Ticket},
};
use tenko_store::{
    ReadConsistency, Store,
    raft::{RaftStore, RaftStoreConfig},
    test_hooks::REFUSE_WRITES_FILE,
};
use tokio_util::sync::CancellationToken;

const CHILD: &str = "TENKO_LEASE_REFUSAL_CHILD";

#[test]
fn the_store_hook_refuses_and_the_role_answers_from_its_table() {
    let dir = tempfile::tempdir().expect("a directory");
    let output = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "child_refusal",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, dir.path())
        .env(REFUSE_WRITES_FILE, dir.path().join("refuse"))
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("REFUSAL OK"),
        "the child failed:\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "the child process of the_store_hook_refuses_and_the_role_answers_from_its_table"]
fn child_refusal() {
    let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(scenario(dir));
    println!("REFUSAL OK");
}

#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn scenario(dir: PathBuf) {
    let refuse = PathBuf::from(std::env::var_os(REFUSE_WRITES_FILE).expect("the hook is set"));
    let mut config = RaftStoreConfig::new(dir.join("data"));
    config.fsync_probe_samples = 0;
    let raft = Arc::new(RaftStore::open(config).await.expect("the store opens"));
    let store: Arc<dyn Store> = raft.clone();
    let leases = SharedLeases::new(LeaseIndex::new());
    let settings = CommitSettings {
        retry_after: Duration::from_millis(300),
        ..CommitSettings::default()
    };
    let (lease_store, committer) =
        StoreLeases::new(Arc::clone(&store), leases.clone(), NODE, settings);
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));

    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let granted = change(
        LeaseEventKind::Granted,
        vrf,
        scope,
        addr(30),
        4,
        BindingState::Active,
        Timestamp::now(),
        from_now(3_600),
    );
    lease_store.submit(&granted, Ticket(1)).expect("queued");
    let done = completions(&lease_store, 1, Duration::from_secs(10)).await;
    assert!(done[0].outcome.is_ok(), "{done:?}");
    let before = leases.read().get(vrf, addr(30)).cloned().expect("the row");

    // The hook refuses: the renewal's commit fails with the store's refusal.
    std::fs::write(&refuse, b"").expect("the hook file");
    let refused_before = metrics::STORE_REFUSED.get();
    let mut renewal = granted.clone();
    renewal.kind = LeaseEventKind::Renewed;
    renewal.cltt = from_now(1);
    renewal.ends = from_now(7_200);
    lease_store.submit(&renewal, Ticket(2)).expect("queued");
    let done = completions(&lease_store, 1, Duration::from_secs(10)).await;
    assert!(
        matches!(&done[0].outcome, Err(CommitError::Refused(text)) if text.contains("quorum")),
        "{done:?}"
    );
    assert_eq!(metrics::STORE_REFUSED.get(), refused_before + 1);
    assert!(!lease_store.accepting());
    assert_eq!(
        lease_store.submit(&renewal, Ticket(3)),
        Err(SubmitError::Refused)
    );
    let finding = lease_store.gate().finding().expect("raised");
    assert_eq!(finding.code, FINDING);
    assert_eq!(finding.code, "dhcp.role.store_refused");

    // What the role answers meanwhile: the renewal for its remaining time, the newcomer
    // nothing.
    let dropped_before = metrics::DROPPED.get(metrics::DropReason::StoreRefused as u16);
    {
        let table = leases.read();
        let verdict = lease_store
            .gate()
            .decide(&*table, &renewal, Timestamp::now());
        assert!(
            matches!(verdict, WhileRefused::Remaining { secs } if secs > 3_500 && secs <= 3_600)
        );
        let newcomer = change(
            LeaseEventKind::Granted,
            vrf,
            scope,
            addr(31),
            5,
            BindingState::Active,
            Timestamp::now(),
            from_now(3_600),
        );
        assert_eq!(
            lease_store
                .gate()
                .decide(&*table, &newcomer, Timestamp::now()),
            WhileRefused::Drop
        );
    }
    assert_eq!(
        metrics::DROPPED.get(metrics::DropReason::StoreRefused as u16),
        dropped_before + 1
    );
    // Reads go on and show that nothing was written.
    let view = store
        .read(ReadConsistency::Local)
        .await
        .expect("reads go on");
    let stored = rebuild_from_view(view.as_ref()).expect("rebuilt");
    assert_eq!(stored.get(vrf, addr(30)), Some(&before));

    // The hook is removed: the trial after the interval commits and clears the finding.
    std::fs::remove_file(&refuse).expect("removed");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(lease_store.accepting());
    lease_store.submit(&renewal, Ticket(4)).expect("queued");
    let done = completions(&lease_store, 1, Duration::from_secs(10)).await;
    assert!(done[0].outcome.is_ok(), "{done:?}");
    assert!(lease_store.gate().finding().is_none());
    assert_eq!(
        leases.read().get(vrf, addr(30)).map(|lease| lease.ends),
        Some(renewal.ends)
    );
    stop.cancel();
    task.await.expect("the committer");
    raft.shutdown().await.expect("the store shuts down");
}
