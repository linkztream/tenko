//! Port bounces and client kicks through the connector host (ADR 0028), against the sample
//! switch: the bounce with its pending record and the host's way back up, a caller that goes
//! away, a port stuck down with its condition, the re-enable of a record a previous process
//! left behind, every guardrail of the bounce and the kick one by one, the write switch, a
//! plugin without the capabilities, and the generic calls that refuse both.

use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, sync::Arc, time::Duration};

use tenko_connect::{
    DeviceRef, Guardrails, L2Change, ProtectedPath, guardrail,
    host::{
        ConnectorHost, HostConfig,
        backoff::BackoffPolicy,
        launch::LaunchSpec,
        normalize::{DiscardSink, ObservationSink},
        registry::{Bundled, PluginRegistry},
        service::{
            BOUNCES, BounceOutcome, ConnectorPatch, NUDGE_DIRECT, NewConnector, PORT_STUCK,
            PendingBounce,
        },
        supervisor::SupervisorConfig,
    },
    sample_switch::{self, SWITCH, mac},
};
use tenko_core::{
    AuthStrength, ConnectorId, JobId, Principal, RequestCtx, SessionId, Timestamp, UserId,
    audit::AuditRecord,
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch};
use tokio::sync::watch;

struct Fixture {
    store: Arc<MemStore>,
    host: Arc<ConnectorHost>,
}

fn registry(nudge: bool) -> PluginRegistry {
    let manifest = sample_switch::manifest(nudge);
    PluginRegistry::new(
        vec![Bundled {
            manifest: manifest.clone(),
            launch: LaunchSpec {
                expected: Some(manifest),
                program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample")),
                args: vec![
                    OsString::from("--mode"),
                    OsString::from(if nudge { "switch" } else { "switch-plain" }),
                ],
                cwd: None,
                env: Vec::new(),
            },
        }],
        None,
    )
}

fn fixture(nudge: bool) -> Fixture {
    let store = Arc::new(MemStore::default());
    let host = ConnectorHost::new(
        Arc::clone(&store) as Arc<dyn Store>,
        None,
        registry(nudge),
        HostConfig {
            supervisor: SupervisorConfig {
                ping_interval: Duration::from_millis(200),
                ping_timeout: Duration::from_millis(500),
                backoff: BackoffPolicy {
                    initial: Duration::from_millis(100),
                    max: Duration::from_millis(500),
                    factor: 2,
                    jitter_permille: 0,
                    reset_after: Duration::from_secs(60),
                },
                ..SupervisorConfig::default()
            },
            schedule: false,
            bounce_retry: Duration::from_millis(100),
            ..HostConfig::default()
        },
        Arc::new(DiscardSink) as Arc<dyn ObservationSink>,
    );
    Fixture { store, host }
}

fn admin() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    })
}

async fn switch(fx: &Fixture, settings: serde_json::Value, writes: bool) -> ConnectorId {
    let view = fx
        .host
        .create(
            &admin(),
            NewConnector {
                plugin: sample_switch::NAME.to_owned(),
                name: "Lab switch".to_owned(),
                settings,
                secrets: BTreeMap::new(),
                poll_interval_secs: None,
                call_timeout_secs: Some(10),
                writes_enabled: writes,
                enabled: true,
            },
        )
        .await
        .expect("create");
    let id = view.instance.id;
    for _ in 0..100 {
        if fx
            .host
            .get(id, None)
            .await
            .expect("view")
            .health
            .process
            .is_running()
        {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the sample switch did not start");
}

fn device() -> DeviceRef {
    DeviceRef(SWITCH.to_owned())
}

/// The administrative state of a port of the switch, as its topology reports it.
async fn enabled(fx: &Fixture, id: ConnectorId, port: u16) -> Option<bool> {
    let topology = fx.host.topology(id, None).await.expect("topology");
    topology
        .device(&device())
        .and_then(|d| d.ports.iter().find(|p| p.index == port))
        .and_then(|p| p.enabled)
}

async fn records(store: &MemStore) -> Vec<PendingBounce> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&BOUNCES, KeyRange::all(), usize::MAX, false)
        .expect("bounces")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

async fn audit(store: &MemStore, action: &str) -> Vec<AuditRecord> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record)
    .filter(|record: &AuditRecord| record.draft.action.as_str() == action)
    .collect()
}

async fn until(what: &str, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..150 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_bounce_takes_the_port_down_and_the_host_brings_it_up_with_audit() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), true).await;
    let job = JobId::generate();
    let started = Timestamp::now();
    let report = fx
        .host
        .bounce_port(id, &device(), 3, 1, &Guardrails::default(), Some(job), None)
        .await
        .expect("bounce");
    assert_eq!(report.outcome, BounceOutcome::Bounced, "{report:?}");
    let (down, up) = (report.down_at.expect("down"), report.up_at.expect("up"));
    assert!(down >= started && up.saturating_since(down) >= Duration::from_secs(1));
    assert_eq!(report.diff[0].before.as_deref(), Some("true"));
    assert_eq!(enabled(&fx, id, 3).await, Some(true));
    assert!(records(&fx.store).await.is_empty(), "the record is removed");
    for action in ["connect.port.bounce", "connect.port.enable"] {
        let audited = audit(&fx.store, action).await;
        assert_eq!(audited.len(), 1, "{action}");
        let context = &audited[0].draft.details.context;
        assert_eq!(context["job"], job.to_string(), "{action}");
        assert_eq!(
            (context["device"].as_str(), context["port"].as_str()),
            (SWITCH, "3")
        );
    }
}

#[tokio::test]
async fn the_port_comes_up_although_the_caller_went_away() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), true).await;
    let (switch_ref, none) = (device(), Guardrails::default());
    let call = fx
        .host
        .bounce_port(id, &switch_ref, 8, 2, &none, None, None);
    // The caller (a job that is cancelled or times out) stops waiting while the port is
    // down.
    assert!(
        tokio::time::timeout(Duration::from_millis(700), call)
            .await
            .is_err()
    );
    assert_eq!(enabled(&fx, id, 8).await, Some(false), "the port is down");
    assert_eq!(records(&fx.store).await.len(), 1, "the record is pending");
    until("the port to come up", async || {
        enabled(&fx, id, 8).await == Some(true) && records(&fx.store).await.is_empty()
    })
    .await;
}

#[tokio::test]
async fn a_port_that_does_not_come_up_is_stuck_until_the_host_brings_it_up() {
    let fx = fixture(true);
    let (_stop_tx, stop) = watch::channel(false);
    let _task = fx.host.start(stop);
    let id = switch(&fx, serde_json::json!({ "stuck": true }), true).await;
    let report = fx
        .host
        .bounce_port(id, &device(), 3, 1, &Guardrails::default(), None, None)
        .await
        .expect("bounce");
    let BounceOutcome::Stuck { error } = &report.outcome else {
        panic!("a stuck port, got {report:?}");
    };
    assert_eq!(error.code, "connect.unreachable");
    assert_eq!(enabled(&fx, id, 3).await, Some(false));
    let pending = records(&fx.store).await;
    assert_eq!(pending.len(), 1);
    assert!(pending[0].stuck.is_some() && pending[0].attempts >= 3);
    let conditions = fx.host.stuck_ports().await.expect("conditions");
    assert_eq!(conditions.len(), 1);
    assert_eq!(conditions[0].code, PORT_STUCK);
    assert_eq!(conditions[0].params["device"], SWITCH);
    assert_eq!(conditions[0].params["port"], "3");
    assert_eq!(conditions[0].params["connector"], "Lab switch");
    assert_eq!(audit(&fx.store, "connect.port.enable").await.len(), 1);
    // The controller recovers: the sweep brings the port up and the condition goes away.
    let patch = ConnectorPatch {
        settings: Some(serde_json::json!({ "stuck": false })),
        ..ConnectorPatch::default()
    };
    fx.host
        .update(&admin(), id, patch, None)
        .await
        .expect("update");
    until("the stuck port to come up", async || {
        records(&fx.store).await.is_empty()
    })
    .await;
    assert_eq!(enabled(&fx, id, 3).await, Some(true));
    assert_eq!(fx.host.stuck_ports().await.expect("conditions").len(), 0);
}

#[tokio::test]
async fn a_record_left_by_a_previous_process_is_re_enabled_at_the_start() {
    let fx = fixture(true);
    // The switch starts with port 3 off: a previous process took it down and stopped.
    let id = switch(&fx, serde_json::json!({ "ports_down": [3] }), true).await;
    assert_eq!(enabled(&fx, id, 3).await, Some(false));
    let now = Timestamp::now();
    let record = PendingBounce {
        connector: id,
        device: device(),
        port: 3,
        down_secs: 5,
        job: Some(JobId::generate()),
        on_behalf_of: None,
        diff: Vec::new(),
        restore: vec![L2Change::EnablePort {
            device: device(),
            port: 3,
            restore: r#"{"enabled":true}"#.to_owned(),
        }],
        created_at: now,
        down_at: Some(now),
        // Not due yet: a start brings every pending port up anyway.
        due: now.checked_add(Duration::from_secs(3600)).expect("time"),
        attempts: 0,
        stuck: None,
    };
    let mut batch = WriteBatch::for_request(&admin());
    batch
        .put_typed(&BOUNCES, &record.key(), &record)
        .expect("put");
    fx.store.propose(batch).await.expect("propose");

    let (_stop_tx, stop) = watch::channel(false);
    let _task = fx.host.start(stop);
    until("the start to bring the port up", async || {
        records(&fx.store).await.is_empty()
    })
    .await;
    assert_eq!(enabled(&fx, id, 3).await, Some(true));
    let enabled_audit = audit(&fx.store, "connect.port.enable").await;
    assert_eq!(enabled_audit.len(), 1);
    assert_eq!(enabled_audit[0].draft.details.context["reason"], "startup");
}

async fn refused_bounce(
    fx: &Fixture,
    id: ConnectorId,
    port: u16,
    guardrails: &Guardrails,
) -> String {
    fx.host
        .bounce_port(id, &device(), port, 1, guardrails, None, None)
        .await
        .expect_err("refused")
        .code()
        .to_owned()
}

#[tokio::test]
async fn every_guardrail_of_the_bounce_refuses_on_its_own() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), true).await;
    let none = Guardrails::default();
    let cases = [
        (1, guardrail::UPLINK),
        (2, guardrail::MANAGEMENT_PORT),
        (4, guardrail::SHARED_PORT),
        (5, guardrail::PORT_DOWN),
        (6, guardrail::UPLINK),
        (7, guardrail::SHARED_PORT),
        (9, guardrail::PORT_UNKNOWN),
    ];
    for (port, code) in cases {
        assert_eq!(
            refused_bounce(&fx, id, port, &none).await,
            code,
            "port {port}"
        );
    }
    let protected_port = Guardrails {
        protected: vec![ProtectedPath::Port {
            device: device(),
            port: 8,
        }],
        max_parallel: 10,
    };
    assert_eq!(
        refused_bounce(&fx, id, 8, &protected_port).await,
        guardrail::PROTECTED_PORT
    );
    let protected_client = Guardrails {
        protected: vec![ProtectedPath::Client { mac: mac(0x18) }],
        max_parallel: 10,
    };
    assert_eq!(
        refused_bounce(&fx, id, 8, &protected_client).await,
        guardrail::PROTECTED_CLIENT
    );
    let too_long = fx
        .host
        .bounce_port(id, &device(), 3, 31, &none, None, None)
        .await
        .expect_err("too long");
    assert_eq!(too_long.code(), "connect.bounce.invalid");
    // Nothing was written by any refusal.
    assert_eq!(records(&fx.store).await.len(), 0);
    assert_eq!(audit(&fx.store, "connect.port.bounce").await.len(), 0);
}

#[tokio::test]
async fn every_guardrail_of_the_kick_refuses_on_its_own_and_a_kick_is_audited() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), true).await;
    let none = Guardrails::default();
    let kick = async |low: u8, guardrails: &Guardrails| {
        fx.host
            .kick_client(id, mac(low), guardrails, None, None)
            .await
            .map(|report| report.mac)
            .map_err(|error| error.code().to_owned())
    };
    assert_eq!(
        kick(0x13, &none).await,
        Err(guardrail::NOT_WIRELESS.to_owned())
    );
    assert_eq!(
        kick(0x0b, &none).await,
        Err(guardrail::MANAGEMENT_CLIENT.to_owned())
    );
    assert_eq!(
        kick(0x99, &none).await,
        Err(guardrail::CLIENT_UNKNOWN.to_owned())
    );
    let protected = Guardrails {
        protected: vec![ProtectedPath::Client { mac: mac(0x21) }],
        max_parallel: 10,
    };
    assert_eq!(
        kick(0x21, &protected).await,
        Err(guardrail::PROTECTED_CLIENT.to_owned())
    );
    let job = JobId::generate();
    let report = fx
        .host
        .kick_client(id, mac(0x21), &none, Some(job), None)
        .await
        .expect("kick");
    assert_eq!(report.mac, mac(0x21));
    let audited = audit(&fx.store, "connect.client.kick").await;
    let succeeded: Vec<&AuditRecord> = audited
        .iter()
        .filter(|record| record.draft.details.context.get("job") == Some(&job.to_string()))
        .collect();
    assert_eq!(succeeded.len(), 1);
    assert_eq!(audited.len(), 5, "every refused kick is audited as well");
}

#[tokio::test]
async fn writes_off_and_a_plugin_without_the_capabilities_refuse_both() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), false).await;
    let none = Guardrails::default();
    let bounce = fx
        .host
        .bounce_port(id, &device(), 3, 1, &none, None, None)
        .await
        .expect_err("writes off");
    assert_eq!(bounce.code(), "connect.writes_disabled");
    let kick = fx
        .host
        .kick_client(id, mac(0x21), &none, None, None)
        .await
        .expect_err("writes off");
    assert_eq!(kick.code(), "connect.writes_disabled");

    let plain = fixture(false);
    let id = switch(&plain, serde_json::json!({}), true).await;
    let bounce = plain
        .host
        .bounce_port(id, &device(), 3, 1, &none, None, None)
        .await
        .expect_err("no capability");
    assert_eq!(bounce.code(), "connect.unsupported");
    let kick = plain
        .host
        .kick_client(id, mac(0x21), &none, None, None)
        .await
        .expect_err("no capability");
    assert_eq!(kick.code(), "connect.unsupported");
    assert_eq!(enabled(&plain, id, 3).await, Some(true));
}

#[tokio::test]
async fn the_generic_l2_calls_refuse_a_bounce_and_a_kick() {
    let fx = fixture(true);
    let id = switch(&fx, serde_json::json!({}), true).await;
    let none = Guardrails::default();
    for change in [
        L2Change::BouncePort {
            device: device(),
            port: 3,
            down_secs: 5,
        },
        L2Change::KickClient { mac: mac(0x21) },
    ] {
        let error = fx
            .host
            .plan_l2(id, &change, &none, None)
            .await
            .expect_err("direct");
        assert_eq!(error.code(), NUDGE_DIRECT);
    }
}
