//! Supervision of the sample plugin: start, restart after crashes with backoff, the circuit
//! breaker, a plugin that stops answering, a plugin that cannot start, and requested
//! restarts and stops.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use tenko_connect::{
    CallContext, ConnectorError,
    host::{
        backoff::{BackoffPolicy, CircuitPolicy},
        launch::{LaunchOptions, LaunchSpec},
        supervisor::{ProcessState, SupervisorConfig, SupervisorHandle, SupervisorStatus},
    },
    sample,
};
use tokio::sync::watch;

fn spec(mode: &str) -> LaunchSpec {
    LaunchSpec {
        expected: Some(sample::manifest()),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample")),
        args: vec![OsString::from("--mode"), OsString::from(mode)],
        cwd: None,
        env: Vec::new(),
    }
}

fn config() -> SupervisorConfig {
    SupervisorConfig {
        launch: LaunchOptions {
            handshake_timeout: Duration::from_secs(10),
            ..LaunchOptions::default()
        },
        ping_interval: Duration::from_millis(200),
        ping_timeout: Duration::from_millis(300),
        ping_failures: 2,
        shutdown_grace: Duration::from_secs(5),
        backoff: BackoffPolicy {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(400),
            factor: 2,
            jitter_permille: 0,
            reset_after: Duration::from_secs(60),
        },
        circuit: CircuitPolicy {
            threshold: 3,
            window: Duration::from_secs(60),
            open_for: Duration::from_secs(60),
        },
    }
}

/// Waits until the status satisfies `done`, at most `within`.
async fn wait_for(
    status: &mut watch::Receiver<SupervisorStatus>,
    within: Duration,
    done: impl Fn(&SupervisorStatus) -> bool,
) -> SupervisorStatus {
    let waited = tokio::time::timeout(within, async {
        loop {
            {
                let current = status.borrow_and_update();
                if done(&current) {
                    return current.clone();
                }
            }
            if status.changed().await.is_err() {
                return status.borrow().clone();
            }
        }
    })
    .await;
    let last = status.borrow().clone();
    waited.unwrap_or_else(|elapsed| panic!("status not reached ({elapsed}); last {last:?}"))
}

#[tokio::test]
async fn a_supervised_plugin_runs_and_stops() {
    let handle = SupervisorHandle::spawn(spec("normal"), config());
    let client = handle
        .client(Duration::from_secs(10))
        .await
        .expect("the plugin runs");
    client
        .check(
            &CallContext::with_settings(serde_json::json!({})),
            Duration::from_secs(5),
        )
        .await
        .expect("check");
    let status = handle.status();
    assert!(status.is_running(), "{status:?}");
    assert_eq!(status.restarts, 0);
    handle.stop().await;
    assert_eq!(handle.status().state, ProcessState::Stopped);
    let unavailable = handle.client(Duration::from_millis(100)).await;
    assert!(
        matches!(&unavailable, Err(ConnectorError::PluginUnavailable(detail)) if detail.contains("stopped")),
        "{unavailable:?}"
    );
}

#[tokio::test]
async fn a_crashing_plugin_is_restarted_until_the_circuit_opens() {
    let handle = SupervisorHandle::spawn(spec("crash-after-start"), config());
    let mut status = handle.subscribe();
    let running = wait_for(
        &mut status,
        Duration::from_secs(10),
        SupervisorStatus::is_running,
    )
    .await;
    assert_eq!(running.restarts, 0);
    let backoff = wait_for(&mut status, Duration::from_secs(10), |s| {
        matches!(s.state, ProcessState::Backoff { .. })
    })
    .await;
    assert_eq!(
        backoff.last_error.as_ref().map(|e| e.code.as_ref()),
        Some("connect.plugin.exited")
    );
    let restarted = wait_for(&mut status, Duration::from_secs(10), |s| {
        s.is_running() && s.restarts >= 1
    })
    .await;
    assert!(restarted.restarts >= 1);
    let open = wait_for(&mut status, Duration::from_secs(20), |s| {
        matches!(s.state, ProcessState::CircuitOpen { .. })
    })
    .await;
    assert!(open.consecutive_failures >= 3, "{open:?}");
    // A requested restart closes the circuit and starts at once.
    handle.restart().await;
    wait_for(
        &mut status,
        Duration::from_secs(10),
        SupervisorStatus::is_running,
    )
    .await;
    handle.stop().await;
}

#[tokio::test]
async fn a_plugin_that_stops_answering_is_killed_and_restarted() {
    let handle = SupervisorHandle::spawn(spec("freeze-on-check"), config());
    let mut status = handle.subscribe();
    let client = handle.client(Duration::from_secs(10)).await.expect("runs");
    // The check freezes every worker of the plugin: no answer, not even to pings.
    let frozen = client
        .check(
            &CallContext::with_settings(serde_json::json!({})),
            Duration::from_millis(500),
        )
        .await;
    assert!(frozen.is_err(), "{frozen:?}");
    let failed = wait_for(&mut status, Duration::from_secs(10), |s| {
        s.last_error
            .as_ref()
            .is_some_and(|e| e.code == "connect.plugin.unresponsive")
    })
    .await;
    assert!(failed.last_error.is_some());
    let restarted = wait_for(&mut status, Duration::from_secs(10), |s| {
        s.is_running() && s.restarts >= 1
    })
    .await;
    assert!(restarted.restarts >= 1);
    handle.stop().await;
}

#[tokio::test]
async fn a_plugin_that_cannot_start_fails_without_restarts() {
    let handle = SupervisorHandle::spawn(spec("protocol-2"), config());
    let mut status = handle.subscribe();
    let failed = wait_for(&mut status, Duration::from_secs(10), |s| {
        s.state == ProcessState::Failed
    })
    .await;
    assert_eq!(
        failed.last_error.as_ref().map(|e| e.code.as_ref()),
        Some("connect.plugin.protocol_mismatch")
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(handle.status().state, ProcessState::Failed);
    let unavailable = handle.client(Duration::from_millis(50)).await;
    assert!(
        matches!(&unavailable, Err(ConnectorError::PluginUnavailable(detail)) if detail.contains("protocol_mismatch")),
        "{unavailable:?}"
    );
    handle.stop().await;
}

#[tokio::test]
async fn a_requested_restart_replaces_the_process() {
    let handle = SupervisorHandle::spawn(spec("normal"), config());
    let mut status = handle.subscribe();
    let first = wait_for(
        &mut status,
        Duration::from_secs(10),
        SupervisorStatus::is_running,
    )
    .await;
    let ProcessState::Running { pid: first_pid, .. } = first.state else {
        unreachable!()
    };
    handle.restart().await;
    let second = wait_for(
        &mut status,
        Duration::from_secs(10),
        |s| matches!(s.state, ProcessState::Running { pid, .. } if pid != first_pid),
    )
    .await;
    assert_eq!(second.restarts, 1);
    assert_eq!(second.consecutive_failures, 0);
    handle.stop().await;
}
