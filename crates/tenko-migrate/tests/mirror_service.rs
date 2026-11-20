//! The mirror service over the store and the auth service (WP14.1, E73 and the diff half of
//! E74): the push with its sequence, hash, floor and refusals, the token that owns the
//! sequence, the losses and their acknowledgment, the freshness and the findings, the
//! metrics, and a second service over the same store. Time comes from the environment's clock.

use std::{sync::Arc, time::Duration};

use proptest::prelude::*;
use tenko_auth::{
    clock::{Clock, MockClock},
    settings::Profile,
    testing::TestEnv,
};
use tenko_core::{
    Coded, Credentials, JobId, MirrorId, RequestCtx, TakeoverId, Timestamp, UserId,
    ir::{MirrorSnapshot, SourceKindLabel},
    metrics::{Registry, encode},
    migrate::{Takeover, TakeoverState, tables},
};
use tenko_migrate::mirror::{
    DiffAction, MirrorError, MirrorPatch, MirrorService, body,
    service::{NewMirror, content_hash, register_metrics},
};
use tenko_store::{
    CoalescerConfig, KeyRange, MemStore, MemStoreConfig, ReadConsistency, ReadViewExt, Store,
    WriteBatch, tables as store_tables,
};

const FIXTURE: &str = include_str!("../../tenko-core/tests/fixtures/mirror/snapshot.json");
const INACTIVE: &str =
    include_str!("../../tenko-core/tests/fixtures/mirror/snapshot-inactive.json");

struct Lab {
    env: TestEnv,
    admin: RequestCtx,
    service: MirrorService,
    id: MirrorId,
    pusher: RequestCtx,
    start: Timestamp,
}

fn service_on(store: Arc<dyn Store>, env: &TestEnv) -> MirrorService {
    let clock: Arc<dyn Clock> = env.clock.clone();
    MirrorService::new(store, Arc::clone(&env.service)).with_clock(clock)
}

impl Lab {
    async fn new() -> Self {
        Self::over(None).await
    }

    /// A lab whose mirror service writes to `store` instead of the environment's.
    async fn over(store: Option<Arc<dyn Store>>) -> Self {
        let (env, session) = TestEnv::installed(Profile::Home).await;
        let admin = env.session_ctx(&session).await.expect("a session");
        let service = service_on(store.unwrap_or_else(|| env.store.clone()), &env);
        let (item, token) = service
            .create(
                &admin,
                NewMirror {
                    name: "dc1".to_owned(),
                    kind: SourceKindLabel::new("windows-dhcp").expect("label"),
                    interval_secs: None,
                    token_expires_in_days: Some(30),
                },
            )
            .await
            .expect("created");
        let pusher = env
            .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
            .await
            .unwrap_or_else(|_| admin.clone());
        let start = env.now();
        Self {
            env,
            admin,
            service,
            id: item.mirror.id,
            pusher,
            start,
        }
    }

    /// Moves the clock to `secs` after the start.
    fn at(&self, secs: u64) {
        let clock: &MockClock = &self.env.clock;
        clock.set(
            self.start
                .checked_add(Duration::from_secs(secs))
                .expect("time"),
        );
    }

    async fn push(&self, secs: u64, snapshot: MirrorSnapshot) -> Result<bool, MirrorError> {
        self.at(secs);
        self.service.admit(self.id).await?;
        Ok(self
            .service
            .push(&self.pusher, self.id, snapshot)
            .await?
            .changed)
    }

    fn revision(&self) -> u64 {
        self.env.store.status().revision.get()
    }

    async fn audit(&self, action: &str) -> usize {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view");
        view.scan_typed(&store_tables::AUDIT, KeyRange::all(), 100_000, false)
            .expect("audit")
            .into_iter()
            .filter(|(_, record, _)| record.draft.action.as_str() == action)
            .count()
    }
}

fn fixture(sequence: u64) -> MirrorSnapshot {
    let mut snapshot = body::decode(FIXTURE.as_bytes(), false).expect("the fixture");
    snapshot.sequence = sequence;
    snapshot
}

fn inactive(sequence: u64) -> MirrorSnapshot {
    let mut snapshot = body::decode(INACTIVE.as_bytes(), false).expect("the fixture");
    snapshot.sequence = sequence;
    snapshot
}

fn code(result: Result<bool, MirrorError>) -> &'static str {
    result.expect_err("refused").code()
}

#[tokio::test]
async fn an_unchanged_push_writes_nothing_and_a_changed_one_writes_once() {
    let lab = Lab::new().await;
    assert!(lab.push(0, fixture(1)).await.expect("first"));
    assert_eq!(lab.audit("migrate.mirror.push").await, 1);
    let revision = lab.revision();
    assert!(!lab.push(10, fixture(2)).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision, "an unchanged push writes nothing");

    let item = lab.service.get(lab.id).await.expect("item");
    assert_eq!(
        item.mirror.last_sequence,
        Some(2),
        "the freshness in memory"
    );
    assert_eq!(
        item.counts
            .map(|counts| (counts.scopes, counts.reservations, counts.leases)),
        Some((1, 30, 60))
    );
    assert_eq!(item.losses_open, 4);

    assert!(lab.push(20, inactive(3)).await.expect("changed"));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
    assert_eq!(lab.service.snapshot(lab.id).await.expect("row").sequence, 3);

    // Ten minutes on, an unchanged push writes the row's freshness once.
    let revision = lab.revision();
    assert!(!lab.push(20 + 600, inactive(4)).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision.saturating_add(1));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
}

#[tokio::test]
async fn replays_floods_and_disabled_mirrors_are_refused_and_audited_once_a_minute() {
    let lab = Lab::new().await;
    lab.push(0, fixture(5)).await.expect("first");
    let replay = lab.push(10, fixture(5)).await.expect_err("replay");
    assert_eq!(
        (replay.code(), replay.params()["last"].as_str()),
        ("migrate.mirror.sequence", "5")
    );
    assert_eq!(code(lab.push(15, fixture(6)).await), "migrate.mirror.rate");
    let error = lab.service.admit(lab.id).await.expect_err("rate");
    assert_eq!(error.params()["retry_after"], "5");

    for secs in [30, 31, 40, 89] {
        lab.at(secs);
        lab.service
            .refused(&lab.pusher, lab.id, &MirrorError::TooLarge { limit: 1 })
            .await;
    }
    assert_eq!(lab.audit("migrate.mirror.refuse").await, 1, "once a minute");
    lab.at(91);
    lab.service
        .refused(&lab.pusher, lab.id, &MirrorError::TooLarge { limit: 1 })
        .await;
    assert_eq!(lab.audit("migrate.mirror.refuse").await, 2);

    lab.service
        .update(
            &lab.admin,
            lab.id,
            MirrorPatch {
                enabled: Some(false),
                ..MirrorPatch::default()
            },
        )
        .await
        .expect("disabled");
    assert_eq!(
        code(lab.push(200, fixture(9)).await),
        "migrate.mirror.disabled"
    );
    let unknown = lab.service.admit(MirrorId::generate()).await;
    assert_eq!(
        unknown.expect_err("unknown").code(),
        "migrate.mirror.not_found"
    );
}

#[tokio::test]
async fn a_new_token_starts_a_new_series_of_sequences() {
    let lab = Lab::new().await;
    lab.push(0, fixture(u64::MAX))
        .await
        .expect("an absurd sequence");
    assert_eq!(
        code(lab.push(10, fixture(2)).await),
        "migrate.mirror.sequence"
    );
    let (item, token) = lab
        .service
        .replace_token(&lab.admin, lab.id, None)
        .await
        .expect("token");
    assert_eq!(
        item.mirror.last_sequence, None,
        "the series of the old token is gone"
    );
    let pusher = lab
        .env
        .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
        .await
        .expect("the new token");
    lab.at(20);
    lab.service.admit(lab.id).await.expect("admitted");
    let accepted = lab
        .service
        .push(&pusher, lab.id, fixture(1))
        .await
        .expect("accepted");
    assert_eq!(accepted.sequence, 1);
}

#[tokio::test]
async fn a_second_service_reads_the_freshness_and_the_sequence_from_the_row() {
    let lab = Lab::new().await;
    lab.push(0, fixture(7)).await.expect("first");
    // A restart, or another controller: nothing in memory, the row stands in.
    let other = service_on(lab.env.store.clone(), &lab.env);
    lab.at(30);
    let item = other.get(lab.id).await.expect("item");
    assert_eq!(
        (item.mirror.last_sequence, item.age_secs, item.stale),
        (Some(7), Some(30), false)
    );
    other.admit(lab.id).await.expect("admitted");
    let replay = other
        .push(&lab.pusher, lab.id, fixture(7))
        .await
        .expect_err("replay");
    assert_eq!(replay.code(), "migrate.mirror.sequence");
}

#[tokio::test]
async fn losses_are_acknowledged_as_read_until_they_change() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let losses = lab.service.losses(lab.id).await.expect("losses");
    assert_eq!(losses.entries.len(), 4);
    let lease = losses
        .entries
        .iter()
        .find(|item| item.entry.code == "migrate.loss.lease_state")
        .expect("the lease entry");
    assert_eq!(lease.scope, Some("192.0.2.0/24".parse().expect("net")));
    assert_eq!(
        losses.entries[0].scope, None,
        "a policy named by its name holds for every scope"
    );

    let unknown = lab
        .service
        .ack(&lab.admin, lab.id, 1, &["nope".to_owned()])
        .await;
    assert_eq!(unknown.expect_err("refused").code(), "sys.invalid_request");
    let keys: Vec<String> = losses.entries.iter().map(|item| item.key.clone()).collect();
    lab.service
        .ack(&lab.admin, lab.id, 1, &keys[..2])
        .await
        .expect("acked");
    let scope = "192.0.2.0/24".parse().expect("net");
    assert_eq!(
        lab.service
            .diff(lab.id, scope)
            .await
            .expect("diff")
            .losses_open,
        2
    );

    // The policy's entry changes: its acknowledgment lapses, and the report that was read
    // is no longer the one an acknowledgment answers.
    let mut changed = fixture(2);
    changed.losses.entries[0].detail.push_str(" (changed)");
    lab.push(10, changed).await.expect("pushed");
    assert_eq!(lab.service.get(lab.id).await.expect("item").losses_open, 3);
    let moved = lab.service.ack(&lab.admin, lab.id, 1, &keys[..1]).await;
    let moved = moved.expect_err("moved");
    assert_eq!(
        (moved.code(), moved.params()["latest"].as_str()),
        ("migrate.mirror.snapshot_moved", "2")
    );
    assert_eq!(lab.audit("migrate.mirror.losses_ack").await, 1);
}

#[tokio::test]
async fn the_fixture_against_an_empty_tenko_is_all_to_create() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let scope = "192.0.2.0/24".parse().expect("net");
    let diff = lab.service.diff(lab.id, scope).await.expect("diff");
    assert!(diff.source_active && !diff.tenko_enabled && diff.tenko_scope.is_none());
    let items: Vec<(String, DiffAction)> = diff
        .rows
        .iter()
        .filter(|row| row.kind != tenko_migrate::mirror::DiffKind::Reservation)
        .map(|row| (row.item.clone(), row.action))
        .collect();
    let create = |item: &str| (item.to_owned(), DiffAction::Create);
    assert_eq!(
        items,
        [
            create("192.0.2.0/24"),
            create("192.0.2.100-192.0.2.199"),
            create("192.0.2.100-192.0.2.109"),
            create("lease_secs"),
            create("192.0.2.10:3"),
            create("192.0.2.20:66"),
            create("192.0.2.20:67"),
            create("scope:15"),
            (
                "scope:1@Microsoft Windows 2000 Options".to_owned(),
                DiffAction::Decide
            ),
            create("scope:3"),
            create("scope:42"),
            create("scope:6"),
            create("server:15"),
            create("server:252"),
            create("server:6"),
            create("ddns"),
        ]
    );
    let reservations = diff.rows.len() - items.len();
    assert_eq!(reservations, 30);
    let missing = lab
        .service
        .diff(lab.id, "198.51.100.0/24".parse().expect("net"))
        .await;
    assert_eq!(
        missing.expect_err("no scope").code(),
        "migrate.mirror.scope_not_found"
    );
}

#[tokio::test]
async fn findings_follow_the_freshness_the_token_and_the_takeovers() {
    let lab = Lab::new().await;
    let codes = |findings: Vec<tenko_migrate::mirror::Finding>| {
        findings
            .into_iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        [] as [&str; 0]
    );
    lab.push(0, fixture(1)).await.expect("first");
    lab.at(181);
    let item = lab.service.get(lab.id).await.expect("item");
    assert!(item.stale && item.age_secs == Some(181));
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        ["migrate.mirror.stale"]
    );
    lab.push(181, fixture(2)).await.expect("again");
    assert!(!lab.service.get(lab.id).await.expect("item").stale);

    // A scope taken over that the source serves again.
    let mut batch = WriteBatch::for_request(&lab.admin);
    let takeover = Takeover {
        id: TakeoverId::generate(),
        mirror: lab.id,
        scope: "192.0.2.0/24".parse().expect("net"),
        sequence: 2,
        state: TakeoverState::Done,
        counts: tenko_core::migrate::TakeoverCounts::default(),
        adopted_leases: Vec::new(),
        adopted_names: Vec::new(),
        frozen_names: Vec::new(),
        skipped: Vec::new(),
        before: Vec::new(),
        job: JobId::generate(),
        at: lab.env.now(),
        by: UserId::generate(),
    };
    batch
        .put_typed(&tables::TAKEOVERS, &takeover.id, &takeover)
        .expect("row");
    lab.env.store.propose(batch).await.expect("committed");
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        ["migrate.mirror.scope_active"]
    );
    lab.push(191, inactive(3)).await.expect("inactive");
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        [] as [&str; 0]
    );

    // The token expires in thirty days: the finding comes fourteen days ahead.
    lab.push(17 * 86_400, inactive(4)).await.expect("fresh");
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        ["migrate.mirror.token_expiring"]
    );
}

#[tokio::test]
async fn the_metrics_count_each_outcome_under_its_name() {
    let lab = Lab::new().await;
    let registry = Registry::new();
    register_metrics(&registry);
    lab.push(0, fixture(1)).await.expect("changed");
    lab.push(10, fixture(2)).await.expect("unchanged");
    lab.service
        .refused(&lab.pusher, lab.id, &MirrorError::TooLarge { limit: 1 })
        .await;
    lab.service.refresh_metrics().await.expect("metrics");
    let mut text = String::new();
    encode(&registry.snapshot(), &mut text);
    for (outcome, total) in [("changed", 1), ("unchanged", 1), ("refused", 1)] {
        let line = format!(
            "tenko_migrate_mirror_pushes_total{{mirror=\"{}\",outcome=\"{outcome}\"}} {total}",
            lab.id
        );
        assert!(text.contains(&line), "{line} in\n{text}");
    }
}

#[tokio::test]
async fn a_snapshot_the_store_cannot_hold_is_too_large() {
    let small: Arc<dyn Store> = Arc::new(MemStore::new(MemStoreConfig {
        coalescer: CoalescerConfig {
            max_batch_bytes: 16 * 1024,
            ..CoalescerConfig::default()
        },
        ..MemStoreConfig::default()
    }));
    let lab = Lab::over(Some(small)).await;
    lab.at(0);
    lab.service.admit(lab.id).await.expect("admitted");
    let error = lab.service.push(&lab.admin, lab.id, fixture(1)).await;
    let error = error.expect_err("too large");
    assert_eq!(
        (error.code(), error.http_status()),
        ("migrate.mirror.too_large", 413)
    );
}

#[tokio::test]
async fn a_new_token_stops_the_old_and_deletion_takes_everything() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let key = lab.service.losses(lab.id).await.expect("losses").entries[0]
        .key
        .clone();
    lab.service
        .ack(&lab.admin, lab.id, 1, &[key])
        .await
        .expect("acked");
    let (item, token) = lab
        .service
        .replace_token(&lab.admin, lab.id, None)
        .await
        .expect("token");
    assert_eq!(item.mirror.token, token.info.id);
    lab.service
        .delete(&lab.admin, lab.id)
        .await
        .expect("deleted");
    let view = lab
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    assert!(
        view.get_typed(&tables::MIRRORS, &lab.id)
            .expect("row")
            .is_none()
    );
    assert!(
        view.get_typed(&tables::SNAPSHOTS, &lab.id)
            .expect("row")
            .is_none()
    );
    assert_eq!(
        view.scan_typed(&tables::LOSS_ACKS, KeyRange::all(), 10, false)
            .expect("acks")
            .len(),
        0
    );
    let gone = lab
        .env
        .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
        .await
        .expect_err("the token went with the mirror");
    assert_eq!(gone.code(), "auth.unauthenticated");
    let missing = lab.service.get(lab.id).await;
    assert_eq!(
        missing.expect_err("gone").code(),
        "migrate.mirror.not_found"
    );
}

#[tokio::test]
async fn a_name_that_makes_no_account_is_refused_on_create_and_change() {
    let lab = Lab::new().await;
    let renamed = lab
        .service
        .update(
            &lab.admin,
            lab.id,
            MirrorPatch {
                name: Some("dc 1".to_owned()),
                ..MirrorPatch::default()
            },
        )
        .await;
    assert_eq!(
        renamed.expect_err("a space").code(),
        "migrate.mirror.invalid_settings"
    );
    let taken = lab
        .service
        .create(
            &lab.admin,
            NewMirror {
                name: "dc1".to_owned(),
                kind: SourceKindLabel::new("windows-dhcp").expect("label"),
                interval_secs: None,
                token_expires_in_days: None,
            },
        )
        .await
        .expect_err("taken");
    assert_eq!(
        (taken.code(), taken.params()["name"].as_str()),
        ("migrate.mirror.exists", "dc1")
    );
}

proptest! {
    /// The content hash ignores the sequence and the time of a push, and nothing else of the
    /// fixture: every push of an unchanged source is unchanged.
    #[test]
    fn the_content_hash_ignores_the_sequence_and_the_time(
        sequence in 1u64..,
        seconds in 0u64..10_000_000,
        lease in 0usize..60,
    ) {
        let base = fixture(1);
        let mut moved = base.clone();
        moved.sequence = sequence;
        moved.taken_at = base.taken_at.checked_add(Duration::from_secs(seconds)).expect("time");
        prop_assert_eq!(content_hash(&moved).expect("hash"), content_hash(&base).expect("hash"));
        let mut renewed = base.clone();
        renewed.dhcp.leases[lease].expires = Some(moved.taken_at);
        prop_assert_ne!(content_hash(&renewed).expect("hash"), content_hash(&base).expect("hash"));
    }
}
