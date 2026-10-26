//! The conformance suite behind `tenko plugin test`: what any plugin, in any language, must
//! do to be run by the Tenko host.
//!
//! The suite starts the plugin three times: once for the main checks, once offering only a
//! protocol version nobody speaks, and once to close its standard input. Checks that reach
//! the remote system run with the settings and secrets the caller gives (or the schema
//! defaults); without a real system to talk to, a timely answer with a coded error passes,
//! a timeout, a crash or an uncoded internal error fails.
//!
//! | Check | Passes when |
//! |---|---|
//! | `launch` | the handshake completes within the timeout |
//! | `manifest` | the manifest is valid, equal to `plugin.json` when given, and lists this platform |
//! | `ping` | `Ping` answers with the manifest's name and version |
//! | `token` | calls without the token and with a wrong token are refused (UNAUTHENTICATED, `connect.plugin.token`) |
//! | `concurrency` | 16 parallel pings answer |
//! | `check` | `Check` answers in time with a health value or a coded error, and the plugin lives on |
//! | `capability.<name>` | a basic read of each declared capability answers in time and well-formed |
//! | `undeclared` | the services the manifest does not declare answer UNIMPLEMENTED |
//! | `malformed_request` | settings that are not JSON are refused with INVALID_ARGUMENT, and the plugin lives on |
//! | `shutdown` | `Shutdown` answers and the process exits with status 0 within 5 s |
//! | `protocol_mismatch` | a launch offering only an unknown version is refused with `protocol_mismatch` |
//! | `stdin_close` | closing standard input ends the process within 5 s |

use std::{
    collections::HashSet,
    fmt,
    path::PathBuf,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tenko_core::{MacAddr, net::Fqdn};
use tonic::Code;

use crate::{
    ActuatorIntent, CallContext, Capability, ConnectorError, DeviceRef, L2Change, MigrationArea,
    MigrationScope, SUPPORTED_PROTOCOLS, Secrets, WebhookRequest,
    host::launch::{LaunchError, LaunchOptions, LaunchSpec, Launched, launch},
    manifest::Manifest,
    proto::v1,
    status::{ERROR_CODE, TOKEN_METADATA, TOKEN_REFUSED},
    transport,
};

/// How the suite runs.
#[derive(Debug, Clone)]
pub struct SuiteOptions {
    /// Settings for the checks that reach the remote system; the schema defaults when
    /// `None`.
    pub settings: Option<serde_json::Value>,
    /// Secrets for those checks.
    pub secrets: Secrets,
    /// Timeout of one call.
    pub call_timeout: Duration,
    /// Timeout of the handshake.
    pub handshake_timeout: Duration,
    /// Where Unix sockets live.
    pub runtime_dir: Option<PathBuf>,
}

impl Default for SuiteOptions {
    fn default() -> Self {
        Self {
            settings: None,
            secrets: Secrets::new(),
            call_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            runtime_dir: None,
        }
    }
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The plugin does what the protocol requires.
    Pass,
    /// It does not.
    Fail,
    /// The check could not run (an earlier failure).
    Skip,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "FAIL",
            Outcome::Skip => "skip",
        })
    }
}

/// The result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// The check, for example `token` or `capability.inventory`.
    pub id: String,
    /// The outcome.
    pub outcome: Outcome,
    /// What was seen, in English.
    pub detail: String,
    /// How long the check took.
    pub elapsed_ms: u64,
}

/// The results of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The plugin name, when the handshake told it.
    pub plugin: Option<String>,
    /// The plugin version, when the handshake told it.
    pub version: Option<String>,
    /// The checks, in order.
    pub checks: Vec<CheckResult>,
}

impl Report {
    /// Whether no check failed.
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.outcome != Outcome::Fail)
    }

    /// The result of a check.
    pub fn check(&self, id: &str) -> Option<&CheckResult> {
        self.checks.iter().find(|check| check.id == id)
    }

    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks
            .iter()
            .filter(|check| check.outcome == Outcome::Fail)
    }
}

/// Ping concurrency of the `concurrency` check.
const PARALLEL_PINGS: usize = 16;

/// How long a process may take to exit when asked.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// A protocol version no plugin speaks.
const UNKNOWN_PROTOCOL: u32 = 999;

struct Run {
    checks: Vec<CheckResult>,
}

impl Run {
    fn record(&mut self, id: impl Into<String>, started: Instant, outcome: Result<String, String>) {
        let (outcome, detail) = match outcome {
            Ok(detail) => (Outcome::Pass, detail),
            Err(detail) => (Outcome::Fail, detail),
        };
        self.checks.push(CheckResult {
            id: id.into(),
            outcome,
            detail,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
    }

    fn skip(&mut self, id: impl Into<String>, why: &str) {
        self.checks.push(CheckResult {
            id: id.into(),
            outcome: Outcome::Skip,
            detail: why.to_owned(),
            elapsed_ms: 0,
        });
    }
}

/// Runs the suite against a plugin.
pub async fn run(spec: &LaunchSpec, options: &SuiteOptions) -> Report {
    let launch_options = LaunchOptions {
        runtime_dir: options.runtime_dir.clone(),
        handshake_timeout: options.handshake_timeout,
        connect_timeout: Duration::from_secs(5),
        protocols: SUPPORTED_PROTOCOLS.to_vec(),
        host_version: crate::version().to_owned(),
        log_label: Some("conformance".to_owned()),
    };
    let mut run = Run { checks: Vec::new() };
    let started = Instant::now();
    let launched = launch(spec, &launch_options).await;
    let mut launched = match launched {
        Ok(launched) => {
            run.record(
                "launch",
                started,
                Ok(format!(
                    "handshake completed: protocol {}, pid {}",
                    launched.protocol,
                    launched
                        .pid()
                        .map_or_else(|| "?".to_owned(), |pid| pid.to_string())
                )),
            );
            launched
        }
        Err(error) => {
            run.record("launch", started, Err(error.to_string()));
            for id in [
                "manifest",
                "ping",
                "token",
                "concurrency",
                "check",
                "undeclared",
                "malformed_request",
                "shutdown",
                "protocol_mismatch",
                "stdin_close",
            ] {
                run.skip(id, "the plugin did not start");
            }
            return Report {
                plugin: spec.expected.as_ref().map(|m| m.name.clone()),
                version: spec.expected.as_ref().map(|m| m.version.clone()),
                checks: run.checks,
            };
        }
    };
    let manifest = launched.manifest.clone();
    main_checks(&mut run, &mut launched, &manifest, options).await;
    shutdown_check(&mut run, launched).await;
    protocol_mismatch_check(&mut run, spec, &launch_options, &manifest).await;
    stdin_close_check(&mut run, spec, &launch_options).await;
    Report {
        plugin: Some(manifest.name),
        version: Some(manifest.version),
        checks: run.checks,
    }
}

/// Fails when the process has exited.
fn alive(launched: &mut Launched) -> Result<(), String> {
    match launched.child.try_wait() {
        Ok(Some(status)) => Err(format!("the plugin exited earlier ({status})")),
        _ => Ok(()),
    }
}

/// An error that is part of the protocol: a coded answer about the remote system or the
/// request, not a timeout, a crash or an internal failure.
fn coded(error: &ConnectorError) -> bool {
    !matches!(
        error,
        ConnectorError::Timeout(_)
            | ConnectorError::PluginUnavailable(_)
            | ConnectorError::PluginFailed(_)
            | ConnectorError::Protocol(_)
    )
}

async fn main_checks(
    run: &mut Run,
    launched: &mut Launched,
    manifest: &Manifest,
    options: &SuiteOptions,
) {
    let timeout = options.call_timeout;

    let ctx = manifest_check(run, manifest, options);

    // ping
    let started = Instant::now();
    let result = match launched
        .client
        .ping(timeout.min(Duration::from_secs(5)))
        .await
    {
        Ok(pong) if pong.name == manifest.name && pong.version == manifest.version => {
            Ok(format!("{} {}", pong.name, pong.version))
        }
        Ok(pong) => Err(format!(
            "the ping names `{} {}`, the manifest `{} {}`",
            pong.name, pong.version, manifest.name, manifest.version
        )),
        Err(error) => Err(error.to_string()),
    };
    run.record("ping", started, result);

    // token
    let started = Instant::now();
    let result = token_check(launched, timeout).await;
    run.record("token", started, result);

    // concurrency
    let started = Instant::now();
    let pings = futures::future::join_all(
        (0..PARALLEL_PINGS).map(|_| launched.client.ping(timeout.min(Duration::from_secs(10)))),
    )
    .await;
    let failed = pings.iter().filter(|ping| ping.is_err()).count();
    let result = if failed == 0 {
        Ok(format!("{PARALLEL_PINGS} parallel pings answered"))
    } else {
        Err(format!(
            "{failed} of {PARALLEL_PINGS} parallel pings failed"
        ))
    };
    run.record("concurrency", started, result);

    // check
    let started = Instant::now();
    let result = match alive(launched) {
        Err(error) => Err(error),
        Ok(()) => match launched.client.check(&ctx, timeout).await {
            Ok(report) => still_alive(launched, format!("health {:?}", report.health)).await,
            Err(error) if coded(&error) => {
                still_alive(launched, format!("answered with the coded error {error}")).await
            }
            Err(error) => Err(error.to_string()),
        },
    };
    run.record("check", started, result);

    // capability.<name>
    for capability in &manifest.capabilities {
        let started = Instant::now();
        let result = match alive(launched) {
            Err(error) => Err(error),
            Ok(()) => capability_check(launched, *capability, &ctx, timeout).await,
        };
        run.record(
            format!("capability.{}", capability.as_str()),
            started,
            result,
        );
    }

    // undeclared
    let started = Instant::now();
    let result = match alive(launched) {
        Err(error) => Err(error),
        Ok(()) => undeclared_check(launched, manifest, &ctx, timeout).await,
    };
    run.record("undeclared", started, result);

    // malformed_request
    let started = Instant::now();
    let result = match alive(launched) {
        Err(error) => Err(error),
        Ok(()) => malformed_check(launched, timeout).await,
    };
    run.record("malformed_request", started, result);
}

/// The `manifest` check; returns the context of the remote checks.
fn manifest_check(run: &mut Run, manifest: &Manifest, options: &SuiteOptions) -> CallContext {
    let started = Instant::now();
    let given = options
        .settings
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let settings = manifest.validate_settings(&given);
    let mut notes = Vec::new();
    if let Err(error) = &settings {
        notes.push(format!(
            "the settings for the remote checks do not satisfy the schema ({error}); they are sent as given"
        ));
    }
    for decl in manifest.secrets.iter().filter(|decl| decl.required) {
        if options.secrets.get(&decl.purpose).is_none() {
            notes.push(format!(
                "the required secret `{}` was not given",
                decl.purpose
            ));
        }
    }
    let result = if manifest.supports_this_platform() {
        Ok(if notes.is_empty() {
            format!(
                "valid; capabilities {}",
                manifest
                    .capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!("valid; {}", notes.join("; "))
        })
    } else {
        Err(format!(
            "the manifest lists the platforms {:?}, not {}",
            manifest.platforms,
            crate::manifest::current_platform()
        ))
    };
    run.record("manifest", started, result);
    CallContext {
        instance: None,
        settings: settings.unwrap_or(given),
        secrets: options.secrets.clone(),
        request_id: "conformance".to_owned(),
    }
}

/// The ping that must still answer after a call.
async fn still_alive(launched: &mut Launched, detail: String) -> Result<String, String> {
    match launched.client.ping(Duration::from_secs(5)).await {
        Ok(_) => Ok(detail),
        Err(error) => Err(format!(
            "{detail}, but the plugin no longer answers pings: {error}"
        )),
    }
}

async fn token_check(launched: &Launched, timeout: Duration) -> Result<String, String> {
    let channel = transport::channel(launched.allocation.endpoint(), Duration::from_secs(5))
        .await
        .map_err(|error| format!("cannot open a second connection: {error:?}"))?;
    let mut client = v1::plugin_client::PluginClient::new(channel);
    let mut without = tonic::Request::new(v1::PingRequest {});
    without.set_timeout(timeout);
    let mut wrong = tonic::Request::new(v1::PingRequest {});
    wrong.set_timeout(timeout);
    wrong.metadata_mut().insert(
        TOKEN_METADATA,
        tonic::metadata::MetadataValue::from_static(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    for (what, request) in [("without a token", without), ("with a wrong token", wrong)] {
        match client.ping(request).await {
            Ok(_) => return Err(format!("a call {what} was answered")),
            Err(status) if status.code() != Code::Unauthenticated => {
                return Err(format!(
                    "a call {what} was refused with {:?} instead of Unauthenticated",
                    status.code()
                ));
            }
            Err(status) => {
                let code = status
                    .metadata()
                    .get(ERROR_CODE)
                    .and_then(|value| value.to_str().ok());
                if code != Some(TOKEN_REFUSED) {
                    return Err(format!(
                        "a call {what} was refused without the error code {TOKEN_REFUSED}"
                    ));
                }
            }
        }
    }
    Ok("calls without the token and with a wrong token are refused".to_owned())
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per capability, in the order of the manifest's list"
)]
async fn capability_check(
    launched: &mut Launched,
    capability: Capability,
    ctx: &CallContext,
    timeout: Duration,
) -> Result<String, String> {
    let client = launched.client.clone();
    let answered = match capability {
        Capability::Inventory => match client.poll(ctx, None, timeout).await {
            Ok(polled) => {
                if !polled.warnings.is_empty() {
                    return Err(format!(
                        "the inventory carries malformed values: {}",
                        polled
                            .warnings
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ")
                    ));
                }
                let mut ids = HashSet::new();
                if let Some(host) = polled
                    .batch
                    .hosts
                    .iter()
                    .find(|host| !ids.insert(host.external_id.as_str()))
                {
                    return Err(format!(
                        "the inventory reports `{}` twice",
                        host.external_id
                    ));
                }
                let vendors = match polled.batch.vendors.len() {
                    0 => String::new(),
                    count => format!(", {count} vendor facts"),
                };
                Ok(format!(
                    "{} hosts in {} page(s){vendors}",
                    polled.batch.hosts.len(),
                    polled.pages
                ))
            }
            Err(error) => Err(error),
        },
        Capability::Webhook => {
            let webhook = WebhookRequest {
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body: bytes::Bytes::from_static(b"{}"),
            };
            client
                .webhook(ctx, &webhook, timeout)
                .await
                .map(|batch| match batch {
                    Some((batch, _)) => {
                        format!("an empty call reported {} hosts", batch.hosts.len())
                    }
                    None => "an empty call reported nothing".to_owned(),
                })
        }
        Capability::NetworkController => client.topology(ctx, timeout).await.map(|topology| {
            format!(
                "{} devices, {} clients, {} networks",
                topology.devices.len(),
                topology.clients.len(),
                topology.networks.len()
            )
        }),
        Capability::Actuator => {
            let name = Fqdn::new("conformance.example.test")
                .map_err(|error| format!("internal: {error}"))?;
            client
                .actuator_plan(ctx, &ActuatorIntent::DnsRecordsRemove { name }, timeout)
                .await
                .map(|plan| format!("planned {} change(s), nothing written", plan.diff.len()))
        }
        Capability::PortBounce => match client.plan(ctx, &probe_bounce(), timeout).await {
            Ok(plan) => {
                bounce_plan_problem(&plan)?;
                Ok(format!(
                    "planned a bounce of {} change(s) with its way back up, nothing written",
                    plan.diff.len()
                ))
            }
            Err(error) => Err(error),
        },
        Capability::ClientKick => client.plan(ctx, &probe_kick(), timeout).await.map(|plan| {
            format!(
                "planned a kick of {} change(s), nothing written",
                plan.diff.len()
            )
        }),
        Capability::Migration => {
            let scope = MigrationScope {
                areas: [MigrationArea::Ipam].into_iter().collect(),
                zones: Vec::new(),
            };
            client
                .migration_read(ctx, &scope, timeout)
                .await
                .map(|(ir, loss)| {
                    format!(
                        "{} networks, {} hosts, {} addresses, {} losses",
                        ir.networks.len(),
                        ir.hosts.len(),
                        ir.addresses.len(),
                        loss.entries.len()
                    )
                })
        }
    };
    match answered {
        Ok(detail) => still_alive(launched, detail).await,
        Err(error) if coded(&error) => {
            still_alive(launched, format!("answered with the coded error {error}")).await
        }
        Err(error) => Err(error.to_string()),
    }
}

/// The bounce the suite plans: a port of a switch no controller has.
fn probe_bounce() -> L2Change {
    L2Change::BouncePort {
        device: DeviceRef(PROBE_DEVICE.to_owned()),
        port: 1,
        down_secs: crate::DEFAULT_DOWN_SECS,
    }
}

/// The kick the suite plans: a documentation MAC address.
fn probe_kick() -> L2Change {
    L2Change::KickClient {
        mac: MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0xfe]),
    }
}

/// The device of [`probe_bounce`].
const PROBE_DEVICE: &str = "conformance-switch";

/// What is wrong with the plan of a bounce: it must name the planned change and carry
/// exactly one `EnablePort` of the same port in its `undo`, so the host can bring the port
/// up again without the receipt.
fn bounce_plan_problem(plan: &crate::L2Plan) -> Result<(), String> {
    let L2Change::BouncePort { device, port, .. } = &plan.change else {
        return Err("the plan of a bounce names another change".to_owned());
    };
    match plan.undo.as_slice() {
        [
            L2Change::EnablePort {
                device: up_device,
                port: up_port,
                ..
            },
        ] if up_device == device && up_port == port => Ok(()),
        _ => Err(
            "the plan of a bounce must carry exactly one EnablePort of the same port in `undo`"
                .to_owned(),
        ),
    }
}

async fn undeclared_check(
    launched: &mut Launched,
    manifest: &Manifest,
    ctx: &CallContext,
    timeout: Duration,
) -> Result<String, String> {
    let client = launched.client.clone();
    let mut probed = Vec::new();
    let expect_unsupported = |name: &str, result: Result<(), ConnectorError>| match result {
        Err(ConnectorError::Unsupported) => Ok(()),
        Ok(()) => Err(format!("the undeclared `{name}` answered a call")),
        Err(error) => Err(format!(
            "the undeclared `{name}` answered {error} instead of UNIMPLEMENTED"
        )),
    };
    if !manifest.has(Capability::Inventory) {
        expect_unsupported(
            "inventory",
            client.poll_page(ctx, None, timeout).await.map(|_| ()),
        )?;
        probed.push("inventory");
    } else if !manifest.has(Capability::Webhook) {
        let webhook = WebhookRequest {
            headers: Vec::new(),
            body: bytes::Bytes::new(),
        };
        expect_unsupported(
            "webhook",
            client.webhook(ctx, &webhook, timeout).await.map(|_| ()),
        )?;
        probed.push("webhook");
    }
    if !manifest.has(Capability::NetworkController) {
        expect_unsupported(
            "network_controller",
            client.topology(ctx, timeout).await.map(|_| ()),
        )?;
        probed.push("network_controller");
    }
    if !manifest.has(Capability::Actuator) {
        let name =
            Fqdn::new("conformance.example.test").map_err(|error| format!("internal: {error}"))?;
        expect_unsupported(
            "actuator",
            client
                .actuator_plan(ctx, &ActuatorIntent::DnsRecordsRemove { name }, timeout)
                .await
                .map(|_| ()),
        )?;
        probed.push("actuator");
    }
    if !manifest.has(Capability::Migration) {
        expect_unsupported(
            "migration",
            client
                .migration_read(ctx, &MigrationScope::default(), timeout)
                .await
                .map(|_| ()),
        )?;
        probed.push("migration");
    }
    // ADR 0028: a network controller without the bounce or the kick refuses their changes.
    if manifest.has(Capability::NetworkController) {
        if !manifest.has(Capability::PortBounce) {
            expect_unsupported(
                "port_bounce",
                client.plan(ctx, &probe_bounce(), timeout).await.map(|_| ()),
            )?;
            probed.push("port_bounce");
        }
        if !manifest.has(Capability::ClientKick) {
            expect_unsupported(
                "client_kick",
                client.plan(ctx, &probe_kick(), timeout).await.map(|_| ()),
            )?;
            probed.push("client_kick");
        }
    }
    Ok(if probed.is_empty() {
        "every capability is declared".to_owned()
    } else {
        format!("{} answer UNIMPLEMENTED", probed.join(", "))
    })
}

async fn malformed_check(launched: &mut Launched, timeout: Duration) -> Result<String, String> {
    let mut client = v1::plugin_client::PluginClient::new(launched.client.channel());
    let request = launched.client.authorized(
        v1::CheckRequest {
            context: Some(v1::CallContext {
                instance_id: String::new(),
                settings_json: "{not json".to_owned(),
                secrets: Vec::new(),
                request_id: "conformance".to_owned(),
            }),
        },
        timeout,
    );
    let answered = tokio::time::timeout(timeout, client.check(request)).await;
    let detail = match answered {
        Err(_) => return Err(format!("no answer within {timeout:?}")),
        Ok(Ok(_)) => return Err("settings that are not JSON were accepted".to_owned()),
        Ok(Err(status)) if status.code() == Code::InvalidArgument => {
            "settings that are not JSON are refused with INVALID_ARGUMENT".to_owned()
        }
        Ok(Err(status)) => {
            return Err(format!(
                "settings that are not JSON were refused with {:?} instead of InvalidArgument",
                status.code()
            ));
        }
    };
    still_alive(launched, detail).await
}

async fn shutdown_check(run: &mut Run, mut launched: Launched) {
    let started = Instant::now();
    if let Err(error) = alive(&mut launched) {
        run.record("shutdown", started, Err(error));
        return;
    }
    let asked = launched.client.shutdown(Duration::from_secs(5)).await;
    let result = match asked {
        Err(error) => Err(format!("Shutdown failed: {error}")),
        Ok(()) => match tokio::time::timeout(EXIT_GRACE, launched.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok("exited with status 0".to_owned()),
            Ok(Ok(status)) => Err(format!("exited with {status} instead of 0")),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err(format!("still running {EXIT_GRACE:?} after Shutdown")),
        },
    };
    run.record("shutdown", started, result);
    let _ = launched.child.kill().await;
}

async fn protocol_mismatch_check(
    run: &mut Run,
    spec: &LaunchSpec,
    options: &LaunchOptions,
    manifest: &Manifest,
) {
    let started = Instant::now();
    let offer = LaunchOptions {
        protocols: vec![UNKNOWN_PROTOCOL],
        ..options.clone()
    };
    let result = match launch(spec, &offer).await {
        Err(LaunchError::ProtocolMismatch { plugin, .. }) if plugin == manifest.protocol => {
            Ok(format!("refused with protocol_mismatch naming {plugin:?}"))
        }
        Err(LaunchError::ProtocolMismatch { plugin, .. }) => Err(format!(
            "refused with protocol_mismatch naming {plugin:?}, but the manifest declares {:?}",
            manifest.protocol
        )),
        Err(error) => Err(format!(
            "an unknown protocol version was not refused with protocol_mismatch: {error}"
        )),
        Ok(launched) => {
            let _ = launched.stop(Duration::from_secs(1)).await;
            Err(format!("protocol {UNKNOWN_PROTOCOL} was accepted"))
        }
    };
    run.record("protocol_mismatch", started, result);
}

async fn stdin_close_check(run: &mut Run, spec: &LaunchSpec, options: &LaunchOptions) {
    let started = Instant::now();
    let result = match launch(spec, options).await {
        Err(error) => Err(format!("the plugin did not start again: {error}")),
        Ok(mut launched) => {
            drop(launched.stdin.take());
            match tokio::time::timeout(EXIT_GRACE, launched.child.wait()).await {
                Ok(Ok(status)) => Ok(format!("exited ({status})")),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => {
                    let _ = launched.child.kill().await;
                    Err(format!(
                        "still running {EXIT_GRACE:?} after its standard input closed"
                    ))
                }
            }
        }
    };
    run.record("stdin_close", started, result);
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "plugin {} {}",
            self.plugin.as_deref().unwrap_or("?"),
            self.version.as_deref().unwrap_or("?")
        )?;
        let width = self
            .checks
            .iter()
            .map(|check| check.id.len())
            .max()
            .unwrap_or(0);
        for check in &self.checks {
            writeln!(
                f,
                "{:<4}  {:<width$}  {:>6} ms  {}",
                check.outcome.to_string(),
                check.id,
                check.elapsed_ms,
                check.detail
            )?;
        }
        let failed = self.failures().count();
        if failed == 0 {
            write!(f, "conformance: every check passed")
        } else {
            write!(f, "conformance: {failed} check(s) failed")
        }
    }
}
