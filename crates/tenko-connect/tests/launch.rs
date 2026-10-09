//! The host launcher against the sample plugin executable: the handshake, the token, typed
//! calls, timeouts, and every way a plugin can misbehave during its start or its calls.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use tenko_connect::{
    CallContext, ConnectorError, Health, Secrets,
    host::launch::{LaunchError, LaunchOptions, LaunchSpec, Launched, launch},
    sample::{self, CREDENTIAL_TAG},
};
use zeroize::Zeroizing;

fn sample_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample"))
}

fn spec(mode: &str) -> LaunchSpec {
    LaunchSpec {
        expected: Some(sample::manifest()),
        program: sample_exe(),
        args: vec![OsString::from("--mode"), OsString::from(mode)],
        cwd: None,
        env: Vec::new(),
    }
}

fn options() -> LaunchOptions {
    LaunchOptions {
        handshake_timeout: Duration::from_secs(10),
        ..LaunchOptions::default()
    }
}

async fn start(mode: &str) -> Launched {
    launch(&spec(mode), &options())
        .await
        .unwrap_or_else(|error| panic!("the sample in mode {mode} did not start: {error}"))
}

fn ctx(settings: serde_json::Value) -> CallContext {
    CallContext::with_settings(settings)
}

const CALL: Duration = Duration::from_secs(10);

#[tokio::test]
async fn a_plugin_starts_answers_and_stops_gracefully() {
    let launched = start("normal").await;
    assert_eq!(launched.manifest, sample::manifest());
    assert_eq!(launched.protocol, 1);
    assert!(launched.pid().is_some());

    let pong = launched.client.ping(CALL).await.expect("ping");
    assert_eq!(pong.name, "sample");

    let health = launched
        .client
        .check(&ctx(serde_json::json!({})), CALL)
        .await
        .expect("check");
    assert_eq!(health.health, Health::Healthy);

    let mut secrets = Secrets::new();
    secrets.insert("api_key", Zeroizing::new(b"value-for-the-test".to_vec()));
    let call = CallContext {
        secrets,
        ..ctx(serde_json::json!({ "hosts": 7, "page_size": 3, "site": "lab-a" }))
    };
    let polled = launched.client.poll(&call, None, CALL).await.expect("poll");
    assert_eq!(polled.pages, 3);
    assert_eq!(polled.batch.hosts.len(), 7);
    assert!(polled.batch.complete);
    assert!(!polled.batch.more);
    assert_eq!(polled.warnings, Vec::<String>::new());
    assert!(
        polled.batch.hosts[6]
            .tags
            .contains(&CREDENTIAL_TAG.to_owned())
    );
    assert!(polled.batch.hosts[6].tags.contains(&"lab-a".to_owned()));

    // Settings the plugin rejects come back as invalid settings, and the plugin lives on.
    let rejected = launched
        .client
        .poll(&ctx(serde_json::json!({ "colour": "blue" })), None, CALL)
        .await;
    assert!(
        matches!(rejected, Err(ConnectorError::InvalidSettings(_))),
        "{rejected:?}"
    );
    launched.client.ping(CALL).await.expect("still alive");

    // A capability the plugin does not declare is unsupported.
    let topology = launched
        .client
        .topology(&ctx(serde_json::json!({})), CALL)
        .await;
    assert_eq!(topology, Err(ConnectorError::Unsupported));

    let ended = launched.stop(Duration::from_secs(5)).await;
    assert!(ended.starts_with("exited"), "{ended}");
}

#[tokio::test]
async fn calls_without_the_token_are_refused() {
    let launched = start("normal").await;
    let channel =
        tenko_connect::transport::channel(launched.allocation.endpoint(), Duration::from_secs(5))
            .await
            .expect("channel");
    let stranger =
        tenko_connect::host::client::PluginClient::new(channel, &"0".repeat(64)).expect("client");
    let refused = stranger.ping(CALL).await;
    assert!(
        matches!(&refused, Err(ConnectorError::PluginFailed(message)) if message.contains("token")),
        "{refused:?}"
    );
    launched.stop(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_plugin_that_ignores_the_token_is_detectable() {
    let launched = start("ignore-token").await;
    let channel =
        tenko_connect::transport::channel(launched.allocation.endpoint(), Duration::from_secs(5))
            .await
            .expect("channel");
    let stranger =
        tenko_connect::host::client::PluginClient::new(channel, &"0".repeat(64)).expect("client");
    assert!(stranger.ping(CALL).await.is_ok());
    launched.stop(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_hanging_handshake_times_out() {
    let options = LaunchOptions {
        handshake_timeout: Duration::from_millis(800),
        ..LaunchOptions::default()
    };
    let error = launch(&spec("hang-handshake"), &options)
        .await
        .expect_err("hangs");
    assert_eq!(
        error,
        LaunchError::HandshakeTimeout(Duration::from_millis(800))
    );
}

#[tokio::test]
async fn a_broken_handshake_is_reported_with_the_exit() {
    let error = launch(&spec("broken-handshake"), &options())
        .await
        .expect_err("broken");
    assert!(
        matches!(
            error,
            LaunchError::HandshakeInvalid(_) | LaunchError::Exited { .. }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_protocol_mismatch_is_a_clear_error_both_ways() {
    let error = launch(&spec("protocol-2"), &options())
        .await
        .expect_err("mismatch");
    assert_eq!(
        error,
        LaunchError::ProtocolMismatch {
            host: vec![1],
            plugin: vec![2]
        }
    );
    assert!(error.to_string().contains("no common protocol version"));
    assert!(error.is_permanent());

    let future_host = LaunchOptions {
        protocols: vec![7],
        ..options()
    };
    let error = launch(&spec("normal"), &future_host)
        .await
        .expect_err("mismatch");
    assert_eq!(
        error,
        LaunchError::ProtocolMismatch {
            host: vec![7],
            plugin: vec![1]
        }
    );
}

#[tokio::test]
async fn a_manifest_that_differs_from_the_installed_one_is_refused() {
    let error = launch(&spec("wrong-version"), &options())
        .await
        .expect_err("mismatch");
    let LaunchError::ManifestMismatch(detail) = &error else {
        panic!("expected a manifest mismatch, got {error:?}");
    };
    assert!(detail.contains("9.9.9"), "{detail}");

    let mut other = spec("normal");
    if let Some(manifest) = other.expected.as_mut() {
        "other".clone_into(&mut manifest.name);
    }
    let error = launch(&other, &options()).await.expect_err("wrong plugin");
    assert!(
        matches!(&error, LaunchError::Refused { code, .. } if code == "wrong_plugin"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_missing_executable_cannot_be_spawned() {
    let mut missing = spec("normal");
    missing.program = std::env::temp_dir().join("tenko-no-such-plugin-executable");
    let error = launch(&missing, &options()).await.expect_err("missing");
    assert!(matches!(error, LaunchError::Spawn { .. }), "{error:?}");
}

#[tokio::test]
async fn a_hanging_call_times_out_and_the_plugin_still_answers_pings() {
    let launched = start("hang-calls").await;
    let started = std::time::Instant::now();
    let result = launched
        .client
        .poll(
            &ctx(serde_json::json!({})),
            None,
            Duration::from_millis(400),
        )
        .await;
    assert_eq!(
        result,
        Err(ConnectorError::Timeout(Duration::from_millis(400)))
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    launched.client.ping(CALL).await.expect("ping");
    launched.stop(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_crash_during_a_call_is_a_plugin_failure() {
    let mut launched = start("crash-on-poll").await;
    let result = launched
        .client
        .poll(&ctx(serde_json::json!({})), None, CALL)
        .await;
    assert!(
        matches!(
            result,
            Err(ConnectorError::PluginUnavailable(_) | ConnectorError::PluginFailed(_))
        ),
        "{result:?}"
    );
    let status = tokio::time::timeout(Duration::from_secs(5), launched.child.wait())
        .await
        .expect("exits")
        .expect("status");
    assert_eq!(status.code(), Some(101));
}

#[tokio::test]
async fn closing_standard_input_stops_a_well_behaved_plugin() {
    let mut launched = start("normal").await;
    drop(launched.stdin.take());
    let status = tokio::time::timeout(Duration::from_secs(8), launched.child.wait())
        .await
        .expect("exits after its input closed")
        .expect("status");
    assert!(status.success(), "{status}");

    let mut stubborn = start("ignore-stdin-close").await;
    drop(stubborn.stdin.take());
    let waited = tokio::time::timeout(Duration::from_secs(1), stubborn.child.wait()).await;
    assert!(waited.is_err(), "a stubborn plugin keeps running");
    let ended = stubborn.stop(Duration::from_secs(5)).await;
    assert!(ended.starts_with("exited"), "{ended}");
}

#[tokio::test]
async fn malformed_hosts_are_dropped_with_warnings() {
    let launched = start("malformed-hosts").await;
    let polled = launched
        .client
        .poll(&ctx(serde_json::json!({})), None, CALL)
        .await
        .expect("poll");
    assert_eq!(polled.batch.hosts.len(), 1);
    assert_eq!(polled.warnings.len(), 1, "{:?}", polled.warnings);
    launched.stop(Duration::from_secs(5)).await;
}
