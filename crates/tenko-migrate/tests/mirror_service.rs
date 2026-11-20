//! The mirror service over the store and the auth service (WP14.1, E73 and the diff half of
//! E74): the push with its sequence, hash, floor and refusals, the token that owns the
//! sequence, the losses and their acknowledgment, the freshness and the findings, the
//! metrics, a second service over the same store, what is stored how often, the names, the
//! source prefixes, and a snapshot at every bound. Time comes from the environment's clock.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use proptest::prelude::*;
use tenko_auth::{
    clock::{Clock, MockClock},
    service::MirrorTokenTerms,
    settings::{Profile, SettingsPatch},
    testing::TestEnv,
};
use tenko_core::{
    ApiTokenId, Coded, Credentials, JobId, MirrorId, Principal, RequestCtx, Revision, TakeoverId,
    Timestamp, UserId,
    ir::{
        MirrorSnapshot, SourceKindLabel,
        mirror::{
            MAX_BODY_BYTES, MAX_FILTERS, MAX_INFLATED_BYTES, MAX_ITEMS, MAX_LEASES, MAX_LOSSES,
            MAX_RESERVATIONS, MAX_SCOPES,
        },
    },
    metrics::{Registry, encode},
    migrate::{MAX_MIRRORS, Snapshot, Takeover, TakeoverState, losses, tables},
};
use tenko_migrate::mirror::{
    DiffAction, MirrorError, MirrorPatch, MirrorService, body,
    service::{NewMirror, content_hashes, register_metrics},
};
use tenko_store::{
    ChangeStream, CoalescerConfig, Committed, DerivedIndex, KeyRange, Leadership, MemStore,
    MemStoreConfig, ReadConsistency, ReadView, ReadViewExt, Store, StoreError, StoreStatus,
    WatchFilter, WriteBatch, tables as store_tables,
};
use tokio::sync::oneshot;

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

/// A store that, once armed, holds its next write until the test lets it go, so that the
/// test can write between a read and the write that follows it.
struct Gate {
    inner: Arc<dyn Store>,
    held: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

impl Gate {
    fn new(inner: Arc<dyn Store>) -> Self {
        Self {
            inner,
            held: Mutex::new(None),
        }
    }

    /// Holds the next write: the first receiver hears when it arrived, the sender lets it go.
    fn arm(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (arrived, heard) = oneshot::channel();
        let (go, gone) = oneshot::channel();
        *self.held.lock().expect("the gate") = Some((arrived, gone));
        (heard, go)
    }
}

#[async_trait::async_trait]
impl Store for Gate {
    async fn propose(&self, batch: WriteBatch) -> Result<Committed, StoreError> {
        let held = self.held.lock().expect("the gate").take();
        if let Some((arrived, go)) = held {
            let _ = arrived.send(());
            let _ = go.await;
        }
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

fn service_on(store: Arc<dyn Store>, env: &TestEnv) -> MirrorService {
    let clock: Arc<dyn Clock> = env.clock.clone();
    MirrorService::new(store, Arc::clone(&env.service)).with_clock(clock)
}

impl Lab {
    async fn new() -> Self {
        Self::over(|store| store).await
    }

    /// A lab whose mirror service writes to the store `store` makes of the environment's.
    async fn over(store: impl FnOnce(Arc<dyn Store>) -> Arc<dyn Store>) -> Self {
        let (env, session) = TestEnv::installed(Profile::Home).await;
        let admin = env.session_ctx(&session).await.expect("a session");
        let base: Arc<dyn Store> = env.store.clone();
        let service = service_on(store(base), &env);
        let (item, _) = service
            .create(&admin, new_mirror("dc1", &[]))
            .await
            .expect("created");
        // What the route hands the service for the token's request, once it checked the token.
        let pusher = RequestCtx::new(Principal::Token {
            id: item.mirror.token,
            owner: item.mirror.account,
        });
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

    fn pusher_token(&self) -> ApiTokenId {
        let Principal::Token { id, .. } = self.pusher.principal else {
            panic!("the pusher is a token");
        };
        id
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

fn new_mirror(name: &str, sources: &[&str]) -> NewMirror {
    NewMirror {
        name: name.to_owned(),
        kind: SourceKindLabel::new("windows-dhcp").expect("label"),
        interval_secs: None,
        token: MirrorTokenTerms {
            expires_in_days: Some(30),
            source_prefixes: sources.iter().map(|&prefix| prefix.to_owned()).collect(),
        },
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
        (item.mirror.last_sequence, item.stored_sequence),
        (Some(2), Some(1)),
        "the freshness in memory, the stored snapshot of the first push"
    );
    assert_eq!(
        item.counts
            .map(|counts| (counts.scopes, counts.reservations, counts.leases)),
        Some((1, 30, 60))
    );
    assert_eq!(item.losses_open, 4);

    // A scope that turned inactive is a changed configuration: written at once.
    assert!(lab.push(20, inactive(3)).await.expect("changed"));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
    assert_eq!(lab.service.snapshot(lab.id).await.expect("row").sequence, 3);

    // Half the stale threshold on, an unchanged push writes the row's freshness once.
    let revision = lab.revision();
    assert!(!lab.push(20 + 80, inactive(4)).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision, "within 90 s of the row's push");
    assert!(!lab.push(20 + 90, inactive(5)).await.expect("unchanged"));
    assert_eq!(lab.revision(), revision.saturating_add(1));
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
}

#[tokio::test]
async fn changed_leases_alone_are_written_every_ten_minutes_without_an_audit_record() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let revision = lab.revision();
    // Leases come and go, and the loss entry of a lease in another state changes: the
    // configuration is unchanged.
    let churned = |sequence: u64, step: usize| {
        let mut snapshot = fixture(sequence);
        snapshot.dhcp.leases.truncate(60 - step);
        for entry in &mut snapshot.losses.entries {
            if entry.code == losses::LEASE_STATE {
                entry.detail = format!("{} ({step})", entry.detail);
            }
        }
        snapshot
    };
    assert!(!lab.push(60, churned(2, 1)).await.expect("churn"));
    assert_eq!(
        lab.revision(),
        revision,
        "nothing within the freshness period"
    );
    let newest = lab
        .service
        .newest(lab.id, lab.pusher_token())
        .expect("held");
    assert_eq!((newest.sequence, newest.leases.len()), (2, 59));
    assert!(!lab.push(120, churned(3, 2)).await.expect("churn"));
    assert_eq!(lab.revision(), revision + 1, "the row's freshness only");
    assert_eq!(lab.service.snapshot(lab.id).await.expect("row").sequence, 1);

    assert!(!lab.push(600, churned(4, 3)).await.expect("churn"));
    let stored = lab.service.snapshot(lab.id).await.expect("row");
    assert_eq!(
        (stored.sequence, stored.envelope.dhcp.leases.len()),
        (4, 57)
    );
    assert_eq!(
        lab.audit("migrate.mirror.push").await,
        1,
        "no record of its own"
    );
    let item = lab.service.get(lab.id).await.expect("item");
    assert_eq!(
        (item.stored_sequence, item.mirror.stored_at),
        (Some(4), Some(stored.received))
    );
    assert_eq!(item.counts.map(|counts| counts.leases), Some(57));
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
        .replace_token(&lab.admin, lab.id, &MirrorTokenTerms::default())
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
async fn a_push_whose_token_is_replaced_before_its_write_is_a_revoked_token_s() {
    let mut gate = None;
    let lab = Lab::over(|store| {
        let held = Arc::new(Gate::new(store));
        gate = Some(Arc::clone(&held));
        held
    })
    .await;
    let gate = gate.expect("the gate");
    lab.at(0);
    lab.service.admit(lab.id).await.expect("admitted");
    // The push has read the row and waits at its write while the token is replaced; the
    // write then meets the new row, and the next attempt reads it again.
    let (arrived, go) = gate.arm();
    let (pushed, replaced) = tokio::join!(
        lab.service.push(&lab.pusher, lab.id, fixture(u64::MAX)),
        async {
            arrived.await.expect("the push reached its write");
            let replaced = lab
                .service
                .replace_token(&lab.admin, lab.id, &MirrorTokenTerms::default())
                .await;
            go.send(()).expect("let go");
            replaced
        }
    );
    replaced.expect("replaced");
    let refused = pushed.expect_err("the old token's push");
    assert_eq!(
        (refused.code(), refused.http_status()),
        ("auth.unauthenticated", 401)
    );
    let item = lab.service.get(lab.id).await.expect("item");
    assert_eq!(
        (item.mirror.last_sequence, item.mirror.last_hash),
        (None, None)
    );
    // The same refusal for a push that arrives after the replacement.
    lab.at(10);
    lab.service.admit(lab.id).await.expect("admitted");
    let late = lab.service.push(&lab.pusher, lab.id, fixture(2)).await;
    assert_eq!(late.expect_err("refused").code(), "auth.unauthenticated");
}

#[tokio::test]
async fn a_second_service_reads_the_freshness_and_the_sequence_from_the_row() {
    let lab = Lab::new().await;
    // Unchanged pushes every minute: the row is written when 90 s have passed since its
    // last push, at 0 and 120 here, not at 60 and 180.
    for (secs, sequence) in [(0, 7), (60, 8), (120, 9), (180, 10)] {
        lab.push(secs, fixture(sequence)).await.expect("pushed");
    }
    // A restart, or another controller: nothing in memory, the row stands in, never stale
    // while pushes arrive and at most 90 s behind.
    let other = service_on(lab.env.store.clone(), &lab.env);
    lab.at(200);
    let item = other.get(lab.id).await.expect("item");
    assert_eq!(
        (item.mirror.last_sequence, item.age_secs, item.stale),
        (Some(9), Some(80), false)
    );
    other.admit(lab.id).await.expect("admitted");
    let replay = other
        .push(&lab.pusher, lab.id, fixture(9))
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
    let stale = lab.service.findings().await.expect("findings");
    assert_eq!(
        (stale[0].code, stale[0].mirrors.as_slice()),
        (
            "migrate.mirror.stale",
            [(lab.id, "dc1".to_owned())].as_slice()
        ),
        "by id, since names are not unique"
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
        partner: None,
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

// ---------------------------------------------------------------------------------------
// The exporter's snapshots, the binding to a server, the pair (plan section 2.15)

const EXPORTER_CORP: &str =
    include_str!("../../../deploy/windows/mirror/tests/fixtures/expected-snapshot.json");
const EXPORTER_LAB: &str =
    include_str!("../../../deploy/windows/mirror/tests/fixtures/lab-dc1/expected-snapshot.json");
const PARTNER: &str = include_str!("../../tenko-core/tests/fixtures/mirror/snapshot-partner.json");

/// Another mirror of the lab with the context its exporter's pushes carry.
async fn another(lab: &Lab, name: &str) -> (MirrorId, RequestCtx) {
    let (item, _) = lab
        .service
        .create(&lab.admin, new_mirror(name, &[]))
        .await
        .expect("created");
    let pusher = RequestCtx::new(Principal::Token {
        id: item.mirror.token,
        owner: item.mirror.account,
    });
    (item.mirror.id, pusher)
}

async fn push_as(
    lab: &Lab,
    id: MirrorId,
    pusher: &RequestCtx,
    snapshot: MirrorSnapshot,
) -> Result<bool, MirrorError> {
    lab.service.admit(id).await?;
    Ok(lab.service.push(pusher, id, snapshot).await?.changed)
}

fn pair(partner: Option<MirrorId>) -> MirrorPatch {
    MirrorPatch {
        partner: Some(partner),
        ..MirrorPatch::default()
    }
}

/// The exporter's own expected output (the Pester suites hold the script to these files)
/// decodes, validates, is stored, and every loss entry carries a code of the server's set
/// and is placed in its scope whenever its column names an address: one fixture tested by
/// both sides, so that the two cannot read the contract differently unnoticed.
#[tokio::test]
async fn the_exporters_snapshots_carry_the_servers_codes_and_place_every_entry() {
    for (name, text) in [("corp", EXPORTER_CORP), ("lab", EXPORTER_LAB)] {
        let lab = Lab::new().await;
        let snapshot = body::decode(text.as_bytes(), false).expect(name);
        lab.push(0, snapshot).await.expect(name);
        let report = lab.service.losses(lab.id).await.expect("losses");
        assert!(!report.entries.is_empty(), "{name}");
        for item in &report.entries {
            let entry = &item.entry;
            assert!(
                losses::ALL.contains(&entry.code.as_ref()),
                "{name}: the server knows no code {}",
                entry.code
            );
            let column = entry.location.column.as_deref().unwrap_or_default();
            let names_an_address = column
                .split([',', '=', ':'])
                .any(|part| part.trim().parse::<std::net::IpAddr>().is_ok());
            assert_eq!(
                item.scope.is_some(),
                names_an_address,
                "{name}: the entry at `{column}` ({}) is placed in its scope exactly when it names an address",
                entry.code
            );
        }
    }
}

/// The lab server's snapshot (Windows Server 2025, an allow list that is on and empty):
/// option 81 is not among its options, and the diff shows the scope's restriction.
#[tokio::test]
async fn the_lab_servers_snapshot_is_diffed_with_its_restriction_and_without_option_81() {
    let lab = Lab::new().await;
    let snapshot = body::decode(EXPORTER_LAB.as_bytes(), false).expect("the lab snapshot");
    let scope = "192.0.2.0/24".parse().expect("net");
    let restricted = snapshot.scope(&scope).expect("scope").restricted;
    assert!(restricted && snapshot.dhcp.server_options.is_empty());
    lab.push(0, snapshot.clone()).await.expect("pushed");
    let diff = lab.service.diff(lab.id, scope).await.expect("diff");
    let rows: Vec<(String, DiffAction)> = diff
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.kind,
                tenko_migrate::mirror::DiffKind::Filter | tenko_migrate::mirror::DiffKind::Option
            )
        })
        .map(|row| (row.item.clone(), row.action))
        .collect();
    let create = |item: &str| (item.to_owned(), DiffAction::Create);
    assert_eq!(
        rows,
        [
            create("scope:15"),
            create("scope:3"),
            create("scope:6"),
            create("restricted"),
        ]
    );
    assert_eq!(
        diff.losses_open, 5,
        "a name, three reservations the allow list does not list, the failover"
    );

    // What the server did with option 81 as an ordinary option before the exporter left it
    // out: it validated, and the diff (and so a prepare) never offered it, since 81 is a code
    // the server writes itself and an option set never holds.
    let mut with_81 = snapshot;
    with_81.sequence += 1;
    let option = |column: &str| tenko_core::ir::dhcp::IrOption {
        code: 81,
        vendor_class: None,
        user_class: None,
        values: vec!["4".to_owned()],
        origin: tenko_core::ir::SourceLocation {
            sheet: Some("Get-DhcpServerv4OptionValue".to_owned()),
            row: None,
            column: Some(column.to_owned()),
        },
    };
    with_81.dhcp.server_options.push(option("81"));
    with_81.dhcp.scopes[0].options.push(option("192.0.2.0:81"));
    // A deny entry of the source is one Tenko's server-wide filters must hold too.
    with_81.dhcp.filters.push(tenko_core::ir::dhcp::IrFilter {
        mac: "00:00:5e:00:53:21".parse().expect("pattern"),
        kind: tenko_core::dhcp::FilterKind::Deny,
        description: None,
        origin: tenko_core::ir::SourceLocation::default(),
    });
    with_81.validate().expect("option 81 validates");
    lab.push(10, with_81).await.expect("pushed");
    let diff = lab.service.diff(lab.id, scope).await.expect("diff");
    assert!(
        diff.rows.iter().all(|row| !row.item.ends_with(":81")),
        "no row offers option 81"
    );
    assert!(
        diff.rows
            .iter()
            .any(|row| row.item == "deny 00:00:5e:00:53:21" && row.action == DiffAction::Create)
    );
}

#[tokio::test]
async fn an_unknown_loss_code_is_shown_counted_as_configuration_and_acknowledged() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let mut unknown = fixture(2);
    unknown.losses.entries.push(tenko_core::ir::LossEntry {
        location: tenko_core::ir::SourceLocation {
            sheet: Some("Get-DhcpServerv4Scope".to_owned()),
            row: None,
            column: Some("192.0.2.0".to_owned()),
        },
        code: std::borrow::Cow::Borrowed("migrate.loss.something_new"),
        detail: "a loss of a later exporter".to_owned(),
    });
    assert!(
        lab.push(10, unknown).await.expect("accepted"),
        "a changed configuration, audited"
    );
    assert_eq!(lab.audit("migrate.mirror.push").await, 2);
    let report = lab.service.losses(lab.id).await.expect("losses");
    let item = report
        .entries
        .iter()
        .find(|item| item.entry.code == "migrate.loss.something_new")
        .expect("shown");
    assert!(item.ack.is_none() && item.scope.is_some());
    assert_eq!(lab.service.get(lab.id).await.expect("item").losses_open, 5);
}

#[tokio::test]
async fn a_mirror_is_bound_to_the_server_of_its_first_push_until_its_token_is_replaced() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let row = lab.service.get(lab.id).await.expect("item").mirror;
    assert_eq!(row.server.as_deref(), Some("dc1.corp.example.test"));
    let mut upper = fixture(2);
    upper.source.server = "DC1.corp.example.test".to_owned();
    lab.push(10, upper.clone())
        .await
        .expect("a host name compares without case");

    let mut other = body::decode(PARTNER.as_bytes(), false).expect("partner");
    other.sequence = 3;
    let refused = lab.push(20, other).await.expect_err("another server");
    assert_eq!(
        (
            refused.code(),
            refused.http_status(),
            refused.params()["bound"].as_str(),
            refused.params()["server"].as_str()
        ),
        (
            "migrate.mirror.source",
            409,
            "dc1.corp.example.test",
            "dc2.corp.example.test"
        )
    );
    // The route writes the refusal to the audit log as it does for every refused push.
    lab.service.refused(&lab.pusher, lab.id, &refused).await;
    assert_eq!(lab.audit("migrate.mirror.refuse").await, 1);
    assert_eq!(lab.service.snapshot(lab.id).await.expect("row").sequence, 2);

    // A new token binds anew, with its first push even when the snapshot is unchanged.
    let (item, _) = lab
        .service
        .replace_token(&lab.admin, lab.id, &new_mirror("dc1", &[]).token)
        .await
        .expect("replaced");
    assert_eq!(item.mirror.server, None);
    let pusher = RequestCtx::new(Principal::Token {
        id: item.mirror.token,
        owner: item.mirror.account,
    });
    lab.at(30);
    upper.sequence = 1;
    let changed = push_as(&lab, lab.id, &pusher, upper)
        .await
        .expect("bound anew");
    assert!(!changed, "the snapshot is the stored one");
    let row = lab.service.get(lab.id).await.expect("item").mirror;
    assert_eq!(row.server.as_deref(), Some("DC1.corp.example.test"));
}

#[tokio::test]
async fn a_pair_is_set_on_both_rows_at_once_and_refused_when_it_cannot_be_one() {
    let lab = Lab::new().await;
    let (dc2, _) = another(&lab, "dc2").await;
    let (dc3, _) = another(&lab, "dc3").await;
    let partner_of = |id| {
        let service = &lab.service;
        async move { service.get(id).await.expect("item").mirror.partner }
    };
    let refusal = |result: Result<tenko_migrate::mirror::MirrorItem, MirrorError>| {
        let error = result.expect_err("refused");
        (error.code(), error.params()["reason"].clone())
    };

    let item = lab
        .service
        .update(&lab.admin, lab.id, pair(Some(dc2)))
        .await
        .expect("paired");
    assert_eq!(item.mirror.partner, Some(dc2));
    assert_eq!(partner_of(dc2).await, Some(lab.id));
    assert_eq!(
        lab.audit("migrate.mirror.update").await,
        1,
        "one record for both"
    );

    for (id, partner, reason) in [
        (lab.id, lab.id, "a mirror cannot be its own partner"),
        (lab.id, dc3, "the mirror is paired with another mirror"),
        (dc3, lab.id, "the partner is paired with another mirror"),
        (dc3, MirrorId::generate(), "no mirror of that id exists"),
    ] {
        assert_eq!(
            refusal(
                lab.service
                    .update(&lab.admin, id, pair(Some(partner)))
                    .await
            ),
            ("migrate.mirror.partner", reason.to_owned())
        );
    }
    assert_eq!(partner_of(dc3).await, None);

    // Taken apart on both rows; then a deleted partner leaves no pair behind.
    lab.service
        .update(&lab.admin, dc2, pair(None))
        .await
        .expect("apart");
    assert_eq!(
        (partner_of(lab.id).await, partner_of(dc2).await),
        (None, None)
    );
    lab.service
        .update(&lab.admin, lab.id, pair(Some(dc3)))
        .await
        .expect("paired");
    lab.service.delete(&lab.admin, dc3).await.expect("deleted");
    assert_eq!(partner_of(lab.id).await, None);
}

#[tokio::test]
async fn the_diff_of_the_fixture_pair_shows_exactly_the_fixtures_differences() {
    let lab = Lab::new().await;
    let (dc2, dc2_pusher) = another(&lab, "dc2").await;
    lab.push(0, fixture(1)).await.expect("dc1");
    lab.service
        .update(&lab.admin, lab.id, pair(Some(dc2)))
        .await
        .expect("paired");
    let scope = "192.0.2.0/24".parse().expect("net");
    let partner_rows = |diff: tenko_migrate::mirror::ScopeDiff| {
        diff.rows
            .into_iter()
            .filter(|row| row.kind == tenko_migrate::mirror::DiffKind::Partner)
            .map(|row| (row.item, row.mirror, row.partner, row.action))
            .collect::<Vec<_>>()
    };
    let before = lab.service.diff(lab.id, scope).await.expect("diff");
    assert_eq!((before.partner, before.partner_sequence), (Some(dc2), None));
    assert_eq!(
        partner_rows(before),
        [("snapshot".to_owned(), None, None, DiffAction::Decide)]
    );

    let partner = body::decode(PARTNER.as_bytes(), false).expect("the partner fixture");
    push_as(&lab, dc2, &dc2_pusher, partner).await.expect("dc2");
    let diff = lab.service.diff(lab.id, scope).await.expect("diff");
    assert_eq!(diff.partner_sequence, Some(1));
    // The leases differ too (one known to dc1 only, a shorter end, a conflict): they are no
    // configuration and make no row.
    assert_eq!(
        partner_rows(diff),
        [
            (
                "reservation 192.0.2.39".to_owned(),
                Some(format!(
                    "client-id {}, BOOTP terminal",
                    tenko_core::serde_util::to_hex(
                        &fixture(1).dhcp.scopes[0].reservations[29]
                            .client
                            .client_id
                            .clone()
                            .expect("an identifier")
                            .0
                    )
                )),
                None,
                DiffAction::Decide
            ),
            (
                "scope:42".to_owned(),
                Some("192.0.2.5".to_owned()),
                Some("192.0.2.6".to_owned()),
                DiffAction::Decide
            ),
        ]
    );
    // The partner's own diff names the same differences from its side.
    let theirs = partner_rows(lab.service.diff(dc2, scope).await.expect("diff"));
    assert_eq!(theirs.len(), 2);
}

#[tokio::test]
async fn either_mirror_of_a_pair_answers_for_a_scope_taken_over_from_the_pair() {
    let lab = Lab::new().await;
    let (dc2, dc2_pusher) = another(&lab, "dc2").await;
    lab.service
        .update(&lab.admin, lab.id, pair(Some(dc2)))
        .await
        .expect("paired");
    lab.push(0, inactive(1)).await.expect("dc1 inactive");
    let partner = body::decode(PARTNER.as_bytes(), false).expect("the partner fixture");
    push_as(&lab, dc2, &dc2_pusher, partner)
        .await
        .expect("dc2 active");
    let codes = |findings: Vec<tenko_migrate::mirror::Finding>| {
        findings
            .into_iter()
            .map(|finding| (finding.code, finding.mirrors.len()))
            .collect::<Vec<_>>()
    };
    assert_eq!(codes(lab.service.findings().await.expect("findings")), []);

    // The takeover is recorded on dc1; dc2 still serves the scope.
    let mut batch = WriteBatch::for_request(&lab.admin);
    let takeover = Takeover {
        id: TakeoverId::generate(),
        mirror: lab.id,
        scope: "192.0.2.0/24".parse().expect("net"),
        sequence: 1,
        state: TakeoverState::Done,
        counts: tenko_core::migrate::TakeoverCounts::default(),
        adopted_leases: Vec::new(),
        adopted_names: Vec::new(),
        frozen_names: Vec::new(),
        skipped: Vec::new(),
        before: Vec::new(),
        partner: None,
        job: JobId::generate(),
        at: lab.env.now(),
        by: UserId::generate(),
    };
    batch
        .put_typed(&tables::TAKEOVERS, &takeover.id, &takeover)
        .expect("row");
    lab.env.store.propose(batch).await.expect("committed");
    let found = lab.service.findings().await.expect("findings");
    assert_eq!(codes(found.clone()), [("migrate.mirror.scope_active", 1)]);
    assert_eq!(found[0].mirrors[0].0, dc2, "the partner that serves it");

    // Both go quiet: each is stale while the pair's scope is taken over, an error.
    lab.at(181);
    assert_eq!(
        codes(lab.service.findings().await.expect("findings")),
        [
            ("migrate.mirror.scope_active", 1),
            ("migrate.mirror.stale_after_takeover", 2)
        ]
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
    let lab = Lab::over(|_| small).await;
    let error = lab.push(0, fixture(1)).await.expect_err("too large");
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
        .replace_token(&lab.admin, lab.id, &MirrorTokenTerms::default())
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
async fn a_name_is_shown_only_and_the_account_is_the_mirror_s_id() {
    let lab = Lab::new().await;
    let account = |view: &dyn ReadView, id| {
        view.get_typed(&tenko_auth::model::USERS, &id)
            .expect("read")
            .expect("the account")
            .0
            .name
    };
    let view = lab
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let item = lab.service.get(lab.id).await.expect("item");
    assert_eq!(
        account(view.as_ref(), item.mirror.account),
        format!("mirror-{}", lab.id)
    );
    // A rename, spaces allowed, touches nothing but the name.
    let renamed = lab
        .service
        .update(
            &lab.admin,
            lab.id,
            MirrorPatch {
                name: Some("Office DHCP 1".to_owned()),
                ..MirrorPatch::default()
            },
        )
        .await
        .expect("renamed");
    assert_eq!(
        (renamed.mirror.account, renamed.mirror.token),
        (item.mirror.account, item.mirror.token)
    );
    let view = lab
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    assert_eq!(
        account(view.as_ref(), item.mirror.account),
        format!("mirror-{}", lab.id)
    );
    // Two mirrors may share a name: the CLI asks for the id when a name is not unique.
    let (twin, _) = lab
        .service
        .create(&lab.admin, new_mirror("Office DHCP 1", &[]))
        .await
        .expect("a second mirror of that name");
    assert_ne!(twin.mirror.id, lab.id);
    for name in [" lab", "Office\u{202E}1", "Office\n1"] {
        let refused = lab
            .service
            .update(
                &lab.admin,
                lab.id,
                MirrorPatch {
                    name: Some(name.to_owned()),
                    ..MirrorPatch::default()
                },
            )
            .await;
        assert_eq!(
            refused.expect_err(name).code(),
            "migrate.mirror.invalid_settings"
        );
    }
}

#[tokio::test]
async fn the_hardened_profile_needs_a_source_prefix_to_create_or_enable_a_mirror() {
    let lab = Lab::new().await;
    // Under Home a mirror's token may be bound, and the item says to what.
    let (bound, _) = lab
        .service
        .create(
            &lab.admin,
            new_mirror("dc2", &["192.0.2.10", "198.51.100.0/24"]),
        )
        .await
        .expect("bound");
    assert_eq!(
        bound.source_prefixes,
        ["192.0.2.10/32", "198.51.100.0/24"]
            .map(|prefix| prefix.parse::<ipnet::IpNet>().expect("prefix"))
    );
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
    hardened(&lab).await;
    let enable = MirrorPatch {
        enabled: Some(true),
        ..MirrorPatch::default()
    };
    let refused = lab
        .service
        .update(&lab.admin, lab.id, enable.clone())
        .await
        .expect_err("no prefix");
    assert_eq!(
        (refused.code(), refused.params()["field"].as_str()),
        ("migrate.mirror.invalid_settings", "source_prefixes")
    );
    lab.service
        .update(&lab.admin, bound.mirror.id, enable)
        .await
        .expect("a bound mirror is enabled");
    for refused in [
        lab.service
            .create(&lab.admin, new_mirror("dc3", &[]))
            .await
            .map(|_| ()),
        lab.service
            .replace_token(&lab.admin, lab.id, &MirrorTokenTerms::default())
            .await
            .map(|_| ()),
    ] {
        assert_eq!(
            refused.expect_err("no prefix").code(),
            "migrate.mirror.invalid_settings"
        );
    }
}

/// A snapshot with every counted list at its bound and every smaller list at `MAX_ITEMS`,
/// each item as large as the exporter writes it (the fixture's scope, reservation, lease and
/// loss entry), in /26 scopes of 198.18.0.0/15.
fn at_every_bound() -> serde_json::Value {
    let mut fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("json");
    let dhcp = fixture["dhcp"].clone();
    let mut scope = dhcp["scopes"][0].clone();
    let reservation = scope["reservations"][0].clone();
    let lease = dhcp["leases"][0].clone();
    let loss = fixture["losses"]["entries"][0].clone();
    let address =
        |n: usize| std::net::Ipv4Addr::from(0xC612_0000_u32 + u32::try_from(n).expect("n"));
    let mac = |n: usize| {
        let octets = u32::try_from(n).expect("n").to_be_bytes();
        format!(
            "00:00:5e:{:02x}:{:02x}:{:02x}",
            octets[1], octets[2], octets[3]
        )
    };
    let origin =
        |sheet: &str, column: String| serde_json::json!({ "sheet": sheet, "column": column });
    let per_scope = (MAX_RESERVATIONS / MAX_SCOPES, MAX_LEASES / MAX_SCOPES);
    let mut scopes = Vec::new();
    let mut leases = Vec::new();
    let cidr = |n: usize| format!("{}/26", address(n * 64));
    for n in 0..MAX_SCOPES {
        let base = n * 64;
        scope["cidr"] = cidr(n).into();
        scope["name"] = format!("Office {n}").into();
        scope["ranges"] = serde_json::json!([{ "first": address(base + 1).to_string(), "last": address(base + 62).to_string() }]);
        scope["exclusions"] = serde_json::json!([]);
        scope["origin"] = origin(
            "Get-DhcpServerv4Scope",
            format!("ScopeId={}", address(base)),
        );
        scope["reservations"] = (0..per_scope.0)
            .map(|r| {
                let mut reservation = reservation.clone();
                reservation["ip"] = address(base + 1 + r).to_string().into();
                reservation["client"] = serde_json::json!({ "mac": mac(base + r) });
                reservation["name"] = format!("printer{n}x{r}").into();
                reservation["origin"] = origin(
                    "Get-DhcpServerv4Reservation",
                    format!("IPAddress={}", address(base + 1 + r)),
                );
                reservation
            })
            .collect();
        scopes.push(scope.clone());
        for l in 0..per_scope.1 {
            let mut lease = lease.clone();
            lease["ip"] = address(base + 11 + l).to_string().into();
            lease["scope"] = cidr(n).into();
            lease["client"] = serde_json::json!({ "mac": mac(0x80_0000 + base + l) });
            lease["hostname"] = format!("LAPTOP-{n:04}-{l:02}.corp.example.test").into();
            lease["origin"] = origin(
                "Get-DhcpServerv4Lease",
                format!("IPAddress={}", address(base + 11 + l)),
            );
            leases.push(lease);
        }
    }
    let items = |make: &dyn Fn(usize) -> serde_json::Value,
                 count: usize|
     -> Vec<serde_json::Value> { (0..count).map(make).collect() };
    let dhcp = &mut fixture["dhcp"];
    dhcp["scopes"] = scopes.into();
    dhcp["leases"] = leases.into();
    dhcp["option_defs"] = items(&|_| dhcp_def(), MAX_ITEMS).into();
    dhcp["classes"] = items(&|i| serde_json::json!({ "name": format!("Class {i}"), "kind": "vendor", "data": "4d53465420352e30", "description": "a vendor class of the office", "origin": origin("Get-DhcpServerv4Class", format!("Name=Class {i}")) }), MAX_ITEMS).into();
    dhcp["policies"] = items(&|i| serde_json::json!({ "name": format!("Policy {i}"), "scope": cidr(i), "order": i, "enabled": true, "join": "or", "conditions": [{ "criterion": "vendor_class", "values": ["HP Printers"] }], "origin": origin("Get-DhcpServerv4Policy", format!("Name=Policy {i}")) }), MAX_ITEMS).into();
    dhcp["superscopes"] = items(&|i| serde_json::json!({ "name": format!("Building {i}"), "scopes": [cidr(i)], "origin": origin("Get-DhcpServerv4Superscope", format!("Name=Building {i}")) }), MAX_ITEMS).into();
    dhcp["failover"] = items(&|i| serde_json::json!({ "name": format!("Pair {i}"), "partner": "dhcp2.corp.example.test", "mode": "hot_standby", "scopes": [cidr(i)], "origin": origin("Get-DhcpServerv4Failover", format!("Name=Pair {i}")) }), MAX_ITEMS).into();
    dhcp["filters"] = items(&|i| serde_json::json!({ "mac": mac(0x40_0000 + i), "kind": "deny", "description": "a client the office keeps out", "origin": origin("Get-DhcpServerv4Filter", format!("MacAddress={}", mac(0x40_0000 + i))) }), MAX_FILTERS).into();
    fixture["losses"]["entries"] = items(
        &|i| {
            let mut entry = loss.clone();
            entry["location"]["column"] = format!("Name=Policy {i}").into();
            entry
        },
        MAX_LOSSES,
    )
    .into();
    fixture
}

fn dhcp_def() -> serde_json::Value {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("json");
    fixture["dhcp"]["option_defs"][0].clone()
}

fn gzip(text: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text).expect("gzip");
    encoder.finish().expect("gzip")
}

#[tokio::test]
async fn a_snapshot_at_every_bound_fits_one_batch_and_is_accepted() {
    let json = serde_json::to_vec(&at_every_bound()).expect("json");
    let wire = gzip(&json);
    assert!(wire.len() <= MAX_BODY_BYTES && json.len() <= MAX_INFLATED_BYTES);
    let snapshot = body::decode(&wire, true).expect("within every bound");
    assert_eq!(
        (
            snapshot.dhcp.scopes.len(),
            snapshot.reservation_count(),
            snapshot.dhcp.leases.len(),
            snapshot.losses.entries.len(),
            snapshot.dhcp.filters.len(),
        ),
        (
            MAX_SCOPES,
            MAX_RESERVATIONS,
            MAX_LEASES,
            MAX_LOSSES,
            MAX_FILTERS
        )
    );
    // The snapshot row with room to spare: at most three quarters of a batch.
    let row = tables::SNAPSHOTS
        .encode(&Snapshot {
            mirror: MirrorId::generate(),
            sequence: 1,
            hash: tenko_core::serde_util::HexBytes(vec![0; 32]),
            received: Timestamp::now(),
            envelope: snapshot.clone(),
        })
        .expect("cbor");
    let batch = CoalescerConfig::default().max_batch_bytes;
    println!(
        "at every bound: {} octets of JSON, {} gzipped, a snapshot row of {} octets",
        json.len(),
        wire.len(),
        row.len()
    );
    assert!(
        row.len() <= batch / 4 * 3,
        "{} octets of {batch}",
        row.len()
    );
    let lab = Lab::new().await;
    assert!(lab.push(0, snapshot).await.expect("accepted"));
}

#[test]
fn a_snapshot_over_a_bound_is_refused_with_the_count() {
    let snapshot = fixture(1);
    let mut over = snapshot.clone();
    over.dhcp.leases =
        std::iter::repeat_n(snapshot.dhcp.leases[0].clone(), MAX_LEASES + 1).collect();
    let refused = over.validate().expect_err("over");
    assert_eq!(
        (refused.path.as_str(), refused.reason.as_ref()),
        (
            "dhcp.leases",
            format!("{} items, more than {MAX_LEASES}", MAX_LEASES + 1).as_str()
        )
    );
}

proptest! {
    /// The configuration hash ignores the sequence, the time and the leases with their loss
    /// entries; the leases hash sees a lease that moved.
    #[test]
    fn the_configuration_hash_ignores_the_sequence_the_time_and_the_leases(
        sequence in 1u64..,
        seconds in 0u64..10_000_000,
        lease in 0usize..60,
    ) {
        let base = fixture(1);
        let (configuration, leases) = content_hashes(&base).expect("hash");
        let mut moved = base.clone();
        moved.sequence = sequence;
        moved.taken_at = base.taken_at.checked_add(Duration::from_secs(seconds)).expect("time");
        prop_assert_eq!(content_hashes(&moved).expect("hash"), (configuration.clone(), leases.clone()));
        let mut renewed = base.clone();
        renewed.dhcp.leases[lease].expires = Some(moved.taken_at);
        let (same, other) = content_hashes(&renewed).expect("hash");
        prop_assert_eq!(same, configuration.clone());
        prop_assert_ne!(other, leases);
        let mut inactive = base.clone();
        inactive.dhcp.scopes[0].active = false;
        prop_assert_ne!(content_hashes(&inactive).expect("hash").0, configuration);
    }
}

/// Switches the lab's installation to the Hardened profile.
async fn hardened(lab: &Lab) {
    lab.env
        .service
        .update_security_settings(
            &lab.admin,
            &SettingsPatch {
                profile: Some(Profile::Hardened),
                audit_export: Some(tenko_auth::settings::AuditExport::Optional),
                ..SettingsPatch::default()
            },
            None,
        )
        .await
        .expect("Hardened");
}

#[tokio::test]
async fn a_mirror_without_prefixes_stops_pushing_when_the_profile_turns_hardened() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("pushes under Home");
    hardened(&lab).await;
    let refused = lab.push(10, fixture(2)).await.expect_err("unbound");
    assert_eq!(
        (refused.code(), refused.http_status()),
        ("auth.unauthenticated", 401),
        "as a push from outside the prefixes is refused"
    );
    let found = lab.service.findings().await.expect("findings");
    let unbound = found
        .iter()
        .find(|finding| finding.code == "migrate.mirror.unbound")
        .expect("the finding");
    assert_eq!(unbound.mirrors, [(lab.id, "dc1".to_owned())]);
    // Prefixes that together bind nothing are refused, whatever the profile.
    for sources in [
        &["0.0.0.0/1", "128.0.0.0/1"][..],
        &["2001:db8::/32"],
        &["::ffff:10.0.0.0/104"],
    ] {
        let refused = lab
            .service
            .create(&lab.admin, new_mirror("dc2", sources))
            .await
            .expect_err("too short");
        assert_eq!(
            (refused.code(), refused.params()["field"].as_str()),
            ("migrate.mirror.invalid_settings", "source_prefixes"),
            "{sources:?}"
        );
    }
}

#[tokio::test]
async fn the_newest_leases_are_held_for_a_while_and_go_with_the_token() {
    let lab = Lab::new().await;
    lab.push(0, fixture(1)).await.expect("first");
    let lease_losses = fixture(1)
        .losses
        .entries
        .iter()
        .filter(|entry| entry.code == losses::LEASE_STATE)
        .count();
    let held = lab
        .service
        .newest(lab.id, lab.pusher_token())
        .expect("held");
    assert_eq!(
        (held.sequence, held.leases.len(), held.losses.len()),
        (1, 60, lease_losses),
        "the leases and their loss entries, nothing else"
    );
    // Three intervals after the push they are gone.
    lab.at(179);
    assert!(lab.service.newest(lab.id, lab.pusher_token()).is_some());
    lab.at(180);
    assert!(lab.service.newest(lab.id, lab.pusher_token()).is_none());

    // Disabling the mirror and replacing its token drop them at once.
    lab.push(200, fixture(2)).await.expect("again");
    let toggle = |enabled| MirrorPatch {
        enabled: Some(enabled),
        ..MirrorPatch::default()
    };
    lab.service
        .update(&lab.admin, lab.id, toggle(false))
        .await
        .expect("disabled");
    assert!(lab.service.newest(lab.id, lab.pusher_token()).is_none());
    lab.service
        .update(&lab.admin, lab.id, toggle(true))
        .await
        .expect("enabled");
    lab.push(210, fixture(3)).await.expect("again");
    let old = lab.pusher_token();
    let (_, token) = lab
        .service
        .replace_token(&lab.admin, lab.id, &MirrorTokenTerms::default())
        .await
        .expect("token");
    assert!(lab.service.newest(lab.id, old).is_none());
    assert!(lab.service.newest(lab.id, token.info.id).is_none());
}

#[tokio::test]
async fn an_installation_holds_a_bounded_number_of_mirrors() {
    let lab = Lab::new().await;
    for n in 1..MAX_MIRRORS {
        lab.service
            .create(&lab.admin, new_mirror(&format!("dc{n}"), &[]))
            .await
            .expect("within the bound");
    }
    let refused = lab
        .service
        .create(&lab.admin, new_mirror("one more", &[]))
        .await
        .expect_err("over the bound");
    assert_eq!(
        (
            refused.code(),
            refused.http_status(),
            refused.params()["max"].as_str()
        ),
        (
            "migrate.mirror.limit",
            409,
            MAX_MIRRORS.to_string().as_str()
        )
    );
}

#[tokio::test]
async fn one_push_of_a_mirror_is_in_flight_at_a_time() {
    let lab = Lab::new().await;
    let (other, _) = lab
        .service
        .create(&lab.admin, new_mirror("dc2", &[]))
        .await
        .expect("another mirror");
    lab.at(0);
    let held = lab.service.admit(lab.id).await.expect("admitted");
    // Past the floor, but the first push is still in flight.
    lab.at(10);
    let refused = lab.service.admit(lab.id).await.expect_err("in flight");
    assert_eq!(
        (refused.code(), refused.params()["retry_after"].as_str()),
        ("migrate.mirror.rate", "10")
    );
    lab.service
        .admit(other.mirror.id)
        .await
        .expect("another mirror is not held");
    drop(held);
    lab.service.admit(lab.id).await.expect("the push ended");
}

#[tokio::test]
async fn two_creations_at_once_hold_no_mirror_over_the_bound() {
    let mut gate = None;
    let lab = Lab::over(|store| {
        let held = Arc::new(Gate::new(store));
        gate = Some(Arc::clone(&held));
        held
    })
    .await;
    let gate = gate.expect("the gate");
    for n in 2..MAX_MIRRORS {
        lab.service
            .create(&lab.admin, new_mirror(&format!("dc{n}"), &[]))
            .await
            .expect("within the bound");
    }
    // One place is left. The first creation counted and waits at its write while the
    // second takes the place; the first then fails its write, counts again and is refused.
    let (arrived, go) = gate.arm();
    let (first, second) = tokio::join!(
        lab.service.create(&lab.admin, new_mirror("first", &[])),
        async {
            arrived.await.expect("the first reached its write");
            let second = lab
                .service
                .create(&lab.admin, new_mirror("second", &[]))
                .await;
            go.send(()).expect("let go");
            second
        }
    );
    second.expect("the last place");
    assert_eq!(
        first.expect_err("over the bound").code(),
        "migrate.mirror.limit"
    );
    assert_eq!(lab.service.list().await.expect("list").len(), MAX_MIRRORS);
}
