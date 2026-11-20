//! The mirror service over the store and the auth service (WP14.1, E73 and the diff half of
//! E74): the push with its sequence, hash, floor and refusals, the losses and their
//! acknowledgment, the freshness and the findings, and the diff of the fixture against an
//! empty Tenko.

use std::{sync::Arc, time::Duration};

use proptest::prelude::*;
use tenko_auth::{settings::Profile, testing::TestEnv};
use tenko_core::{
    Coded, Credentials, MirrorId, RequestCtx,
    ir::{MirrorSnapshot, SourceKindLabel},
    migrate::tables,
};
use tenko_migrate::mirror::{
    DiffAction, DiffKind, MirrorError, MirrorPatch, MirrorService, body, service::NewMirror,
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables as store_tables};

const FIXTURE: &str = include_str!("../../tenko-core/tests/fixtures/mirror/snapshot.json");
const INACTIVE: &str =
    include_str!("../../tenko-core/tests/fixtures/mirror/snapshot-inactive.json");

struct Lab {
    env: TestEnv,
    admin: RequestCtx,
    service: MirrorService,
    id: MirrorId,
    pusher: RequestCtx,
}

impl Lab {
    async fn new() -> Self {
        let (env, session) = TestEnv::installed(Profile::Home).await;
        let admin = env.session_ctx(&session).await.expect("a session");
        let service = MirrorService::new(env.store.clone(), Arc::clone(&env.service));
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
            .expect("the mirror token authenticates");
        Self {
            env,
            admin,
            service,
            id: item.mirror.id,
            pusher,
        }
    }

    /// The pusher's context `secs` after the start.
    fn at(&self, secs: u64) -> RequestCtx {
        let mut ctx = self.pusher.clone();
        ctx.now = self
            .pusher
            .now
            .checked_add(Duration::from_secs(secs))
            .expect("time");
        ctx
    }

    async fn push(&self, secs: u64, snapshot: MirrorSnapshot) -> Result<bool, MirrorError> {
        let ctx = self.at(secs);
        self.service.admit(self.id, ctx.now).await?;
        Ok(self.service.push(&ctx, self.id, snapshot).await?.changed)
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

#[tokio::test]
async fn an_unchanged_push_writes_nothing_and_a_changed_one_writes_once() {
    let lab = Lab::new().await;
    assert!(lab.push(0, fixture(1)).await.expect("first"));
    assert_eq!(lab.audit("migrate.mirror.push").await, 1);
    let revision = lab.revision();
    assert!(!lab.push(10, fixture(2)).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision, "an unchanged push writes nothing");
    assert_eq!(lab.audit("migrate.mirror.push").await, 1);

    let item = lab.service.get(lab.id, lab.at(10).now).await.expect("item");
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

    let inactive = body::decode(INACTIVE.as_bytes(), false).expect("inactive");
    let mut later = inactive.clone();
    later.sequence = 3;
    assert!(lab.push(20, later).await.expect("changed"));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
    assert_eq!(lab.service.snapshot(lab.id).await.expect("row").sequence, 3);

    // Ten minutes on, an unchanged push writes the row's freshness once.
    let mut again = inactive;
    again.sequence = 4;
    let revision = lab.revision();
    assert!(!lab.push(20 + 600, again).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision.saturating_add(1));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
}

#[tokio::test]
async fn replays_floods_and_disabled_mirrors_are_refused_and_audited_once_a_minute() {
    let lab = Lab::new().await;
    lab.push(0, fixture(5)).await.expect("first");
    let code = |result: Result<bool, MirrorError>| result.expect_err("refused").code();
    assert_eq!(
        code(lab.push(10, fixture(5)).await),
        "migrate.mirror.sequence"
    );
    assert_eq!(
        code(lab.push(20, fixture(4)).await),
        "migrate.mirror.sequence"
    );
    assert_eq!(code(lab.push(25, fixture(6)).await), "migrate.mirror.rate");
    let error = lab
        .service
        .admit(lab.id, lab.at(25).now)
        .await
        .expect_err("rate");
    assert_eq!(error.params()["retry_after"], "5");

    for secs in [30, 31] {
        lab.service
            .refused(&lab.at(secs), lab.id, &MirrorError::TooLarge { limit: 1 })
            .await;
    }
    assert_eq!(lab.audit("migrate.mirror.refuse").await, 1, "once a minute");
    lab.service
        .refused(&lab.at(91), lab.id, &MirrorError::TooLarge { limit: 1 })
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
    let unknown = lab
        .service
        .admit(MirrorId::generate(), lab.at(300).now)
        .await;
    assert_eq!(
        unknown.expect_err("unknown").code(),
        "migrate.mirror.not_found"
    );
}

#[tokio::test]
async fn losses_are_acknowledged_until_they_change() {
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
    let policy = &losses.entries[0];
    assert_eq!(
        policy.scope, None,
        "a policy named by its name holds for every scope"
    );

    let unknown = lab
        .service
        .ack(&lab.admin, lab.id, &["nope".to_owned()])
        .await;
    assert_eq!(unknown.expect_err("refused").code(), "sys.invalid_request");
    let keys: Vec<String> = losses.entries.iter().map(|item| item.key.clone()).collect();
    lab.service
        .ack(&lab.admin, lab.id, &keys[..2])
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

    // The policy's entry changes: its acknowledgment lapses.
    let mut changed = fixture(2);
    changed.losses.entries[0].detail.push_str(" (changed)");
    lab.push(10, changed).await.expect("pushed");
    let item = lab.service.get(lab.id, lab.at(10).now).await.expect("item");
    assert_eq!(item.losses_open, 3);
    assert_eq!(lab.audit("migrate.mirror.losses_ack").await, 1);
}

#[tokio::test]
async fn the_fixture_against_an_empty_tenko_is_all_to_create() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let scope = "192.0.2.0/24".parse().expect("net");
    let diff = lab.service.diff(lab.id, scope).await.expect("diff");
    assert!(diff.source_active && !diff.tenko_enabled && diff.tenko_scope.is_none());
    let count = |kind: DiffKind| diff.rows.iter().filter(|row| row.kind == kind).count();
    assert_eq!(
        [
            DiffKind::Prefix,
            DiffKind::Pool,
            DiffKind::Exclusion,
            DiffKind::LeaseTime,
            DiffKind::Reservation,
            DiffKind::Ddns
        ]
        .map(count),
        [1, 1, 1, 1, 30, 1]
    );
    assert!(count(DiffKind::Option) >= 8, "{:?}", diff.rows);
    assert!(diff.rows.iter().all(|row| row.action == DiffAction::Create));
    assert!(
        diff.rows
            .iter()
            .any(|row| row.item == "192.0.2.10:3" && row.mirror.as_deref() == Some("192.0.2.254"))
    );
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
async fn a_mirror_turns_stale_after_three_intervals_and_fresh_with_a_push() {
    let lab = Lab::new().await;
    let codes = |findings: Vec<tenko_migrate::mirror::Finding>| {
        findings
            .into_iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>()
    };
    let start = lab.at(0).now;
    assert_eq!(
        codes(lab.service.findings(start).await.expect("findings")),
        [] as [&str; 0]
    );
    lab.push(0, fixture(1)).await.expect("first");
    let late = lab.at(181).now;
    let item = lab.service.get(lab.id, late).await.expect("item");
    assert!(item.stale && item.age_secs == Some(181));
    assert_eq!(
        codes(lab.service.findings(late).await.expect("findings")),
        ["migrate.mirror.stale"]
    );
    lab.push(181, fixture(2)).await.expect("again");
    let item = lab.service.get(lab.id, late).await.expect("item");
    assert!(!item.stale);
    // The token expires in thirty days: the finding comes fourteen days ahead.
    let soon = lab.at(17 * 86_400).now;
    lab.push(17 * 86_400, fixture(3)).await.expect("fresh");
    assert_eq!(
        codes(lab.service.findings(soon).await.expect("findings")),
        ["migrate.mirror.token_expiring"]
    );
}

#[tokio::test]
async fn a_new_token_stops_the_old_and_deletion_takes_everything() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    lab.service
        .ack(
            &lab.admin,
            lab.id,
            &[lab.service.losses(lab.id).await.expect("l").entries[0]
                .key
                .clone()],
        )
        .await
        .expect("acked");
    let (item, token) = lab
        .service
        .replace_token(&lab.admin, lab.id, None)
        .await
        .expect("token");
    assert_eq!(item.mirror.token, token.info.id);
    assert!(
        lab.env
            .ctx_for(&Credentials::Bearer(token.token.expose().to_owned()))
            .await
            .is_ok()
    );
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
    assert_eq!(
        lab.service
            .get(lab.id, lab.at(0).now)
            .await
            .expect_err("gone")
            .code(),
        "migrate.mirror.not_found"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Whatever sequences arrive, a push is accepted exactly when its sequence is above every
    /// accepted one, and only a change of content writes.
    #[test]
    fn sequences_rise_strictly_and_only_content_writes(
        pushes in proptest::collection::vec((1u64..20, any::<bool>()), 1..12)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("rt");
        runtime.block_on(async {
            let lab = Lab::new().await;
            let mut last: Option<u64> = None;
            let mut stored_inactive: Option<bool> = None;
            for (step, (sequence, inactive)) in pushes.into_iter().enumerate() {
                let mut snapshot = body::decode(
                    if inactive { INACTIVE } else { FIXTURE }.as_bytes(),
                    false,
                ).expect("fixture");
                snapshot.sequence = sequence;
                let result = lab.push(10 * step as u64, snapshot).await;
                if last.is_some_and(|last| sequence <= last) {
                    prop_assert_eq!(result.expect_err("replay").code(), "migrate.mirror.sequence");
                } else {
                    let changed = result.expect("accepted");
                    prop_assert_eq!(changed, stored_inactive != Some(inactive));
                    last = Some(sequence);
                    stored_inactive = Some(inactive);
                }
            }
            Ok(())
        })?;
    }
}
