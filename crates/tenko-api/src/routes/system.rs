//! Health, status, the internal CA root and the OpenAPI document; in-app updates and the
//! module switch in the submodules [`updates`] and [`modules`]. The metrics moved to their
//! own area, `routes/metrics.rs` (WP3.0, owned by WP3.5).
//!
//! Area: system. Owner: WP1.7 (`GET /system/ca-root`: WP1.8b; [`updates`] and [`modules`]:
//! WP2.10).
//! Requirements: API-01, API-10, OPS-05, OPS-19, OPS-22, OPS-24, OPS-25.
//!
//! Liveness, readiness, the CA root and the OpenAPI document are open. `GET /system/status`
//! needs an authenticated principal with read access to the system.
//!
//! `GET /openapi.json` answers the committed `docs/api/openapi.json`, embedded at build
//! time, byte for byte: the document that `tenko openapi` prints and CI compares with the
//! generated one, so the route, the file and the command agree (E3).
//!
//! `GET /system/ca-root` answers the root certificate of the internal CA while the listener
//! is in TLS mode a, so that admin clients and the first-run wizard can install it (Q5). The
//! server binary provides it as the request extension `Arc<CaRootSource>`; without it, or
//! in another TLS mode, the answer is 404 `tls.no_internal_ca`.
//!
//! `GET /health` and `GET /system/status` name the version the server runs as: the request
//! extension [`RunningVersion`] when the server binary provides it (under the version layout
//! of in-app updates, the version the update service reports), else the crate version.
//!
//! `GET /system/status` shows the leader-only work of the controller (`leader`) when the
//! server binary provides the request extension [`LeaderSource`] (the leader supervisor,
//! WP3.1b); a leader service that gave up adds the warning
//! `cluster.leader.service_failing`, and a clock that differs from the leader's by more
//! than five seconds the warning `cluster.clock_skew` (R35).

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use tenko_cluster::ca::{TlsMode, TlsService};
use tenko_core::{Action, ObjectKind, ObjectRef, Timestamp};
use tenko_store::{ReadConsistency, StoreRole};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    dto::system::{
        DataFormatStatus, Health, HostStatus, LeaderServiceState, LeaderStatus, NodeStatus,
        Readiness, StatusWarning, StoreSummary, SystemStatus, UiStatus,
    },
    extract::Ctx,
    host::{HostSample, low_disk_limit},
    problem::{ApiError, ProblemDetails, codes},
    state::AppState,
};

pub mod diagnostics;
pub mod modules;
pub mod updates;

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .merge(diagnostics::routes())
        .merge(modules::routes())
        .merge(updates::routes())
        .routes(routes!(health))
        .routes(routes!(ready))
        .routes(routes!(system_status))
        .routes(routes!(get_ca_root))
        .routes(routes!(openapi_document))
}

/// The committed OpenAPI document (`docs/api/openapi.json`), served by
/// `GET /openapi.json`. `tenko openapi` writes it anew; CI fails when it differs from the
/// generated document.
pub const OPENAPI_DOCUMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/api/openapi.json"
));

/// Media type of `GET /system/ca-root`.
pub const PEM_FILE: &str = "application/x-pem-file";

/// Stable code of `GET /system/ca-root` when the internal CA does not serve the listener.
pub const NO_INTERNAL_CA: &str = "tls.no_internal_ca";

/// `Cache-Control` of `GET /system/ca-root`: the root changes only when the CA is created
/// again, so clients and proxies may keep it for an hour.
const CA_ROOT_CACHE: &str = "public, max-age=3600";

/// `Content-Disposition` of `GET /system/ca-root`.
const CA_ROOT_FILE: &str = "attachment; filename=\"tenko-ca-root.pem\"";

/// The internal CA root behind `GET /system/ca-root`: the PEM of the root certificate and
/// the TLS service whose mode decides whether it is the root clients need. The server binary
/// adds it as the request extension `Arc<CaRootSource>` when it runs the internal CA. Holds
/// no key material.
#[derive(Debug, Clone)]
pub struct CaRootSource {
    tls: TlsService,
    root_pem: Arc<str>,
    /// SHA-256 of the root certificate, hex, as the server prints it at readiness.
    fingerprint: Arc<str>,
}

impl CaRootSource {
    /// A source for the root `root_pem` (one PEM certificate) of the CA that issues the
    /// certificate of `tls`, with the root's SHA-256 `fingerprint` in hex.
    pub fn new(
        tls: TlsService,
        root_pem: impl Into<Arc<str>>,
        fingerprint: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            tls,
            root_pem: root_pem.into(),
            fingerprint: fingerprint.into(),
        }
    }

    /// The root while the listener is in TLS mode a (internal CA), `None` in the other
    /// modes.
    pub fn current(&self) -> Option<Arc<str>> {
        matches!(self.tls.status().mode, TlsMode::InternalCa).then(|| Arc::clone(&self.root_pem))
    }

    /// The SHA-256 fingerprint of the root (hex) while the listener is in TLS mode a,
    /// `None` in the other modes.
    pub fn fingerprint(&self) -> Option<Arc<str>> {
        matches!(self.tls.status().mode, TlsMode::InternalCa).then(|| Arc::clone(&self.fingerprint))
    }
}

/// The version this server runs as, as the update service sees it (OPS-24). The server
/// binary adds it as a request extension, so that the liveness probe, which the UI asks
/// to see the restart into a newly installed version, names the same version as
/// `GET /system/updates`. Without it the handlers report the crate version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningVersion(Arc<str>);

impl RunningVersion {
    /// The running version `version`, for example `0.4.1`.
    pub fn new(version: impl Into<Arc<str>>) -> Self {
        Self(version.into())
    }

    /// The version.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where `GET /system/status` reads the leader-only work of this controller: the leader
/// supervisor of the server binary adds it as a request extension.
#[derive(Clone)]
pub struct LeaderSource(Arc<dyn Fn() -> LeaderStatus + Send + Sync>);

impl LeaderSource {
    /// A source that answers what `read` returns at the time of the request.
    pub fn new(read: impl Fn() -> LeaderStatus + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// The leader-only work now.
    pub fn current(&self) -> LeaderStatus {
        (self.0)()
    }
}

impl std::fmt::Debug for LeaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderSource").finish_non_exhaustive()
    }
}

/// Where `GET /system/status` reads the data-directory format: the server binary adds it
/// as a request extension and refreshes what it answers in the background.
#[derive(Clone)]
pub struct DataFormatSource(Arc<dyn Fn() -> Option<DataFormatStatus> + Send + Sync>);

impl DataFormatSource {
    /// A source that answers what `read` returns at the time of the request.
    pub fn new(read: impl Fn() -> Option<DataFormatStatus> + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// The format now, if known.
    pub fn current(&self) -> Option<DataFormatStatus> {
        (self.0)()
    }
}

impl std::fmt::Debug for DataFormatSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataFormatSource").finish_non_exhaustive()
    }
}

/// Warning code of a format migration that waits for voters with an older binary.
pub const MIGRATION_BLOCKED: &str = "upgrade.migration_blocked";

/// Warning code of a `dns` role that has stopped answering.
pub const DNS_ROLE_NOT_SERVING: &str = "dns.role.not_serving";

/// Warning code of a `dns` role whose index is far behind the store.
pub const DNS_ROLE_LAGGING: &str = "dns.role.lagging";

/// Revisions a `dns` role may be behind the store before the status warns.
pub const DNS_LAG_WARNING: u64 = 1_000;

/// The warnings of the `dns` role of this node: not answering, or far behind the store.
pub fn dns_role_warnings(role: &tenko_dns::status::DnsStatus) -> Vec<StatusWarning> {
    use tenko_core::dns::{AnchorState, findings};
    let mut params = std::collections::BTreeMap::new();
    params.insert("node".to_owned(), role.node.to_string());
    if !role.serving {
        return vec![StatusWarning {
            code: DNS_ROLE_NOT_SERVING.to_owned(),
            detail: "the dns role of this node has stopped answering queries".to_owned(),
            params,
        }];
    }
    if role.lag > DNS_LAG_WARNING {
        params.insert("lag".to_owned(), role.lag.to_string());
        return vec![StatusWarning {
            code: DNS_ROLE_LAGGING.to_owned(),
            detail: format!(
                "the dns role answers from revision {}, {} revisions behind the store",
                role.revision, role.lag
            ),
            params,
        }];
    }
    // WP10.2: the validator's findings (recursion plan section 2.3): the clock, stale and
    // pending anchors, the negative trust anchors in force, the rules whose upstream
    // strips the DNSSEC records.
    let mut warnings = Vec::new();
    let node = |extra: &[(&str, String)]| {
        let mut params = params.clone();
        for (key, value) in extra {
            params.insert((*key).to_owned(), value.clone());
        }
        params
    };
    if role
        .validation
        .as_ref()
        .is_some_and(|report| report.clock_wrong)
    {
        warnings.push(StatusWarning {
            code: findings::VALIDATION_CLOCK.to_owned(),
            detail: "the root's DNSKEY set fails as expired or not yet valid: the clock is \
                     probably wrong (OPS-09); validation stays on"
                .to_owned(),
            params: node(&[]),
        });
    }
    for anchor in &role.trust_anchors {
        if anchor.trusted().next().is_none() {
            warnings.push(StatusWarning {
                code: findings::TRUST_ANCHOR_STALE.to_owned(),
                detail: format!(
                    "every trust anchor key of {} is revoked or pending: the zone cannot be \
                     validated; add the current anchor",
                    anchor.zone
                ),
                params: node(&[("zone", anchor.zone.to_string())]),
            });
        }
        for key in anchor
            .keys
            .iter()
            .filter(|key| key.state == AnchorState::AddPend)
        {
            warnings.push(StatusWarning {
                code: findings::TRUST_ANCHOR_PENDING.to_owned(),
                detail: format!(
                    "key {} of {} waits for its add hold-down (RFC 5011)",
                    key.key_tag, anchor.zone
                ),
                params: node(&[
                    ("zone", anchor.zone.to_string()),
                    ("key_tag", key.key_tag.to_string()),
                ]),
            });
        }
    }
    for nta in &role.active_ntas {
        warnings.push(StatusWarning {
            code: findings::NTA_ACTIVE.to_owned(),
            detail: format!(
                "names under {} are insecure instead of bogus until {}: {}",
                nta.zone,
                nta.expires_at.to_rfc3339(),
                nta.reason
            ),
            params: node(&[
                ("zone", nta.zone.to_string()),
                ("id", nta.id.to_string()),
                ("expires_at", nta.expires_at.to_rfc3339()),
            ]),
        });
    }
    for (rule, suffix) in &role.stripping_rules {
        warnings.push(StatusWarning {
            code: findings::FORWARDER_STRIPS_DNSSEC.to_owned(),
            detail: format!(
                "the upstream of forwarding rule {suffix} answers without the DNSSEC records \
                 of a secure zone, so its answers are bogus; set validate = false on the rule \
                 or change the upstream"
            ),
            params: node(&[("rule", rule.to_string()), ("suffix", suffix.clone())]),
        });
    }
    warnings
    // WP10.2: end.
}

// WP7.5: the health rows of the dhcp role.
/// Warning code of a `dhcp` role that answers no request: no listener, or stopped.
pub const DHCP_ROLE_NOT_SERVING: &str = "dhcp.role.not_serving";

/// Warning code of a `dhcp` role whose lease writes the store refuses (P3-Q14).
pub const DHCP_ROLE_STORE_REFUSED: &str = tenko_dhcp::lease::refusal::FINDING;

/// Warning code of a profile that expects conflict detection while no `probe` role runs
/// (TGL-16 under Hardened).
pub const DHCP_PROBE_MISSING: &str = "dhcp.probe.missing";

/// The warnings of the `dhcp` role of this node.
pub fn dhcp_role_warnings(role: &tenko_dhcp::role::DhcpStatus) -> Vec<StatusWarning> {
    let node = || {
        let mut params = std::collections::BTreeMap::new();
        params.insert("node".to_owned(), role.node.to_string());
        params
    };
    let mut warnings = Vec::new();
    if !role.serving {
        warnings.push(StatusWarning {
            code: DHCP_ROLE_NOT_SERVING.to_owned(),
            detail: if role.listeners.is_empty() {
                "the dhcp role of this node has no listener ([dhcp] listen is empty), so it \
                 answers no DHCP request"
                    .to_owned()
            } else {
                "the dhcp role of this node has stopped answering DHCP requests".to_owned()
            },
            params: node(),
        });
    }
    if let Some(refusal) = &role.refusal {
        let mut params = node();
        params.insert("since".to_owned(), refusal.since.to_rfc3339());
        params.insert("refused".to_owned(), refusal.refused.to_string());
        params.insert("dropped".to_owned(), refusal.dropped.to_string());
        warnings.push(StatusWarning {
            code: DHCP_ROLE_STORE_REFUSED.to_owned(),
            detail: format!(
                "the store refuses the dhcp role's lease writes since {}: renewals are \
                 answered for the time their leases have left and new requests are dropped \
                 ({})",
                refusal.since.to_rfc3339(),
                refusal.detail
            ),
            params,
        });
    }
    if role.probe_expected && !role.probe {
        warnings.push(StatusWarning {
            code: DHCP_PROBE_MISSING.to_owned(),
            detail: "the security profile expects conflict detection before an offer, and \
                     no probe role runs on this node"
                .to_owned(),
            params: node(),
        });
    }
    warnings
}

// WP8.2: the health row of the lease conflicts (IPAM-23).
/// Warning code of addresses that two MAC addresses hold across leases and sightings.
pub const IPAM_LEASE_CONFLICT: &str = "ipam.lease_conflict";

/// The addresses a lease-conflict warning names; the rest are counted.
const CONFLICTS_NAMED: usize = 5;

/// The warning of the lease conflicts of the reconciliation view, none when there is none.
pub fn lease_conflict_warning(
    conflicts: &[tenko_ipam::reconcile::view::ReconcileRow],
) -> Option<StatusWarning> {
    if conflicts.is_empty() {
        return None;
    }
    let named: Vec<String> = conflicts
        .iter()
        .take(CONFLICTS_NAMED)
        .map(|row| {
            let macs = row
                .macs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" and ");
            if macs.is_empty() {
                row.address.to_string()
            } else {
                format!("{} ({macs})", row.address)
            }
        })
        .collect();
    let more = conflicts.len().saturating_sub(CONFLICTS_NAMED);
    let mut params = std::collections::BTreeMap::new();
    params.insert("count".to_owned(), conflicts.len().to_string());
    params.insert(
        "addresses".to_owned(),
        conflicts
            .iter()
            .take(CONFLICTS_NAMED)
            .map(|row| row.address.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    Some(StatusWarning {
        code: IPAM_LEASE_CONFLICT.to_owned(),
        detail: format!(
            "{} address(es) held by more than one MAC address across leases and sightings, \
             never resolved automatically (IPAM-23): {}{}; see the reconciliation view",
            conflicts.len(),
            named.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        ),
        params,
    })
}

/// The warning of a pending migration that voters block, naming them.
pub fn data_format_warnings(format: &DataFormatStatus) -> Vec<StatusWarning> {
    let Some(pending) = &format.pending else {
        return Vec::new();
    };
    if pending.blocked_by.is_empty() {
        return Vec::new();
    }
    let nodes = pending
        .blocked_by
        .iter()
        .map(|blocker| blocker.node.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut params = std::collections::BTreeMap::new();
    params.insert("stored".to_owned(), format.stored.to_string());
    params.insert("target".to_owned(), pending.target.to_string());
    params.insert("nodes".to_owned(), nodes.clone());
    vec![StatusWarning {
        code: MIGRATION_BLOCKED.to_owned(),
        detail: format!(
            "the data stays in format {} until every voter runs a binary that knows format {}; \
             upgrade controller(s) {nodes}",
            format.stored, pending.target
        ),
        params,
    }]
}

/// Warning code of a leader service that gave up and waits for its restart.
pub const LEADER_SERVICE_FAILING: &str = "cluster.leader.service_failing";

/// Warning code of a controller whose clock differs from the leader's by more than
/// [`CLOCK_SKEW_TOLERANCE_MS`].
pub const CLOCK_SKEW: &str = "cluster.clock_skew";

/// The clock skew between controllers that is tolerated, in milliseconds (R35).
pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 5_000;

/// Warning code of a data directory whose file system is running out of room.
pub const DISK_LOW: &str = "node.disk.low";

/// `node.disk.low`: the file system of the data directory has less than
/// [`LOW_DISK_SHARE`](crate::host::LOW_DISK_SHARE) percent or less than one GiB available,
/// whichever is more. `None` while it has room, or when the size could not be read; the warning
/// is computed from the latest reading on every status request, so it clears when space is back.
pub fn disk_low_warning(
    host: &HostSample,
    path: Option<&std::path::Path>,
) -> Option<StatusWarning> {
    let (total, available) = (host.disk_total?, host.disk_available?);
    if !host.disk_is_low() {
        return None;
    }
    let path = path
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let mut params = std::collections::BTreeMap::new();
    params.insert("available".to_owned(), available.to_string());
    params.insert("total".to_owned(), total.to_string());
    params.insert("limit".to_owned(), low_disk_limit(total).to_string());
    params.insert("path".to_owned(), path.clone());
    Some(StatusWarning {
        code: DISK_LOW.to_owned(),
        detail: format!(
            "the file system of the data directory {path} has {} of {} available",
            gib(available),
            gib(total)
        ),
        params,
    })
}

/// Bytes in GiB with one decimal, for the English text of a finding.
#[allow(clippy::cast_precision_loss)]
fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / f64::from(1_u32 << 30))
}

/// The warnings of the leader-only work: one per service that gave up, and one when this
/// controller's clock differs from the leader's by more than [`CLOCK_SKEW_TOLERANCE_MS`].
pub fn leader_warnings(leader: &LeaderStatus) -> Vec<StatusWarning> {
    let skew = leader
        .clock_skew_ms
        .filter(|skew| skew.unsigned_abs() > CLOCK_SKEW_TOLERANCE_MS.unsigned_abs())
        .map(|skew| {
            let mut params = std::collections::BTreeMap::new();
            params.insert("skew_ms".to_owned(), skew.to_string());
            params.insert(
                "tolerance_ms".to_owned(),
                CLOCK_SKEW_TOLERANCE_MS.to_string(),
            );
            StatusWarning {
                code: CLOCK_SKEW.to_owned(),
                detail: format!(
                    "the clock of this controller differs from the leader's by {skew} ms"
                ),
                params,
            }
        });
    leader
        .services
        .iter()
        .filter(|service| service.state == LeaderServiceState::Restarting)
        .map(|service| {
            let error = service.last_error.clone().unwrap_or_default();
            let mut params = std::collections::BTreeMap::new();
            params.insert("service".to_owned(), service.name.clone());
            params.insert("error".to_owned(), error.clone());
            params.insert("restarts".to_owned(), service.restarts.to_string());
            StatusWarning {
                code: LEADER_SERVICE_FAILING.to_owned(),
                detail: format!(
                    "the leader service {} gave up and is restarted: {error}",
                    service.name
                ),
                params,
            }
        })
        .chain(skew)
        .collect()
}

/// The version of the extension, else the crate version.
fn running_version(extension: Option<&Extension<RunningVersion>>) -> String {
    extension.map_or_else(
        || crate::version().to_owned(),
        |Extension(running)| running.as_str().to_owned(),
    )
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    operation_id = "health",
    summary = "Liveness probe",
    responses(
        (status = 200, description = "The process answers", body = Health)
    ),
    security()
)]
async fn health(running: Option<Extension<RunningVersion>>) -> Json<Health> {
    Json(Health {
        status: "ok".to_owned(),
        version: running_version(running.as_ref()),
    })
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "system",
    operation_id = "ready",
    summary = "Readiness probe",
    responses(
        (status = 200, description = "The node serves requests", body = Readiness),
        (status = 503, description = "Not ready: starting, catching up or shutting down", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn ready(State(state): State<AppState>) -> Result<Json<Readiness>, ApiError> {
    let not_ready = |reason: &str| {
        ApiError::new(
            codes::NOT_READY,
            503,
            format!("the node is not ready: {reason}"),
        )
        .with_param("reason", reason)
    };
    if state.events().is_shutting_down() {
        return Err(not_ready("shutting_down"));
    }
    if !state.is_ready() {
        return Err(not_ready("starting"));
    }
    if state.store.status().role == StoreRole::Shutdown {
        return Err(not_ready("store_stopped"));
    }
    let view = state
        .store
        .read(ReadConsistency::Local)
        .await
        .map_err(|_| not_ready("store_unavailable"))?;
    Ok(Json(Readiness {
        status: "ready".to_owned(),
        revision: view.revision(),
    }))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one extractor per part of the status, each optional"
)]
#[utoipa::path(
    get,
    path = "/system/status",
    tag = "system",
    operation_id = "system_status",
    summary = "Get the status of the installation: version, store, certificates and warnings",
    responses(
        (status = 200, description = "Status of this node", body = SystemStatus),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn system_status(
    State(state): State<AppState>,
    running: Option<Extension<RunningVersion>>,
    leader: Option<Extension<LeaderSource>>,
    backup: Option<Extension<Arc<dyn super::backup::BackupService>>>,
    format: Option<Extension<DataFormatSource>>,
    dns: Option<Extension<super::dns::DnsNodeSlot>>,
    zones: Option<Extension<Arc<tenko_dns::zone::ZoneService>>>,
    // WP7.5: the dhcp role's health rows.
    dhcp: Option<Extension<super::dhcp::DhcpNodeSlot>>,
    // WP8.2: the lease conflicts of IPAM-23.
    ipam: Option<Extension<Arc<tenko_ipam::IpamService>>>,
    Ctx(ctx): Ctx,
) -> Result<Json<SystemStatus>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &system_object())?;
    Ok(Json(
        assemble(
            &state, ctx.now, running, leader, backup, format, dns, zones, dhcp, ipam,
        )
        .await,
    ))
}

/// The status document with every part the server binary provides: what
/// `GET /system/status` answers, and what `GET /system/diagnostics` reads its findings
/// from.
#[allow(
    clippy::too_many_arguments,
    reason = "one source per part of the status, each optional"
)]
pub(crate) async fn assemble(
    state: &AppState,
    now: Timestamp,
    running: Option<Extension<RunningVersion>>,
    leader: Option<Extension<LeaderSource>>,
    backup: Option<Extension<Arc<dyn super::backup::BackupService>>>,
    format: Option<Extension<DataFormatSource>>,
    dns: Option<Extension<super::dns::DnsNodeSlot>>,
    zones: Option<Extension<Arc<tenko_dns::zone::ZoneService>>>,
    dhcp: Option<Extension<super::dhcp::DhcpNodeSlot>>,
    ipam: Option<Extension<Arc<tenko_ipam::IpamService>>>,
) -> SystemStatus {
    let mut status = status_of(state, now);
    status.version = running_version(running.as_ref());
    if let Some(Extension(source)) = leader {
        let leader = source.current();
        status.warnings.extend(leader_warnings(&leader));
        status.leader = Some(leader);
    }
    let (backup, backup_warnings) =
        super::backup::summary_of(backup.as_ref().map(|Extension(service)| service)).await;
    status.backup = backup;
    status.warnings.extend(backup_warnings);
    if let Some(format) = format.and_then(|Extension(source)| source.current()) {
        status.warnings.extend(data_format_warnings(&format));
        status.data_format = Some(format);
    }
    if let Some(Extension(slot)) = dns
        && let Some(role) = slot.status()
    {
        status.warnings.extend(dns_role_warnings(&role));
    }
    if let Some(Extension(slot)) = dhcp
        && let Some(role) = slot.status()
    {
        status.warnings.extend(dhcp_role_warnings(&role));
    }
    // WP8.2: two MAC addresses on one address across leases and sightings (IPAM-23), the
    // conflict rows of the reconciliation view; never resolved automatically.
    if let Some(Extension(ipam)) = ipam
        && let Ok(view) = ipam.view(None).await
        && let Ok(conflicts) = tenko_ipam::reconcile::view::lease_conflicts(view.as_ref(), now)
    {
        status.warnings.extend(lease_conflict_warning(&conflicts));
    }
    // End of the WP8.2 block.
    // WP6.3: the clock and expiry findings of signed zones (OPS-09), each naming its zone.
    if let Some(Extension(zones)) = zones
        && let Ok(view) = zones.view(None).await
        && let Ok(findings) = tenko_dns::dnssec::health::all(view.as_ref(), now)
    {
        status
            .warnings
            .extend(findings.into_iter().map(|finding| StatusWarning {
                code: finding.code.to_owned(),
                detail: finding.detail,
                params: finding.params,
            }));
    }
    status
}

/// Downloads the root certificate of the internal CA (TLS mode a), for installation on
/// admin clients. Open: the certificate is public.
#[utoipa::path(
    get,
    path = "/system/ca-root",
    tag = "system",
    operation_id = "get_ca_root",
    summary = "Download the root certificate of the internal CA as PEM",
    responses(
        (status = 200, description = "The root certificate of the internal CA", body = String, content_type = "application/x-pem-file",
            headers(
                ("Cache-Control" = String, description = "`public, max-age=3600`"),
                ("Content-Disposition" = String, description = "`attachment; filename=\"tenko-ca-root.pem\"`")
            )),
        (status = 404, description = "The listener does not use the internal CA (`tls.no_internal_ca`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn get_ca_root(source: Option<Extension<Arc<CaRootSource>>>) -> Result<Response, ApiError> {
    let root = source
        .and_then(|Extension(source)| source.current())
        .ok_or_else(|| {
            ApiError::new(
                NO_INTERNAL_CA,
                404,
                "the server certificate does not come from the internal CA: it is imported or \
                 TLS ends in a reverse proxy, so there is no internal CA root to install",
            )
        })?;
    let mut response = root.to_string().into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PEM_FILE));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CA_ROOT_CACHE),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(CA_ROOT_FILE),
    );
    Ok(response)
}

/// The status document of the node.
pub(crate) fn status_of(state: &AppState, now: Timestamp) -> SystemStatus {
    let platform = &state.platform;
    let store = state.store.status();
    let listener = platform.listener.load_full();
    let (tls, mut warnings) = match &listener {
        Some(listener) => {
            let (tls, warnings) = listener.status(now);
            (Some(tls), warnings)
        }
        None => (None, Vec::new()),
    };
    let ui = listener.as_ref().map_or(
        UiStatus {
            stub: crate::ui::UI_STUB,
            from_directory: false,
        },
        |listener| listener.ui(),
    );
    warnings.extend(state.notices_list());
    let (kek, kek_warnings) = state
        .kek()
        .map_or_else(|| (None, Vec::new()), |kek| super::kek::summary_of(&kek));
    warnings.extend(kek_warnings);
    let host = platform.host.current();
    if let Some(host) = &host {
        warnings.extend(disk_low_warning(host, platform.host.data_dir().as_deref()));
    }
    if ui.stub {
        warnings.push(crate::dto::system::StatusWarning {
            code: "sys.ui.stub".to_owned(),
            detail: "this development build serves a placeholder page instead of the web UI"
                .to_owned(),
            params: std::collections::BTreeMap::new(),
        });
    }
    SystemStatus {
        version: crate::version().to_owned(),
        started_at: platform.started_at,
        uptime_seconds: platform.started.elapsed().as_secs(),
        node: NodeStatus {
            id: platform.node.id,
            roles: platform.node.roles.clone(),
        },
        store: StoreSummary {
            role: serde_json::to_value(store.role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default(),
            leader: store.leader,
            revision: store.revision,
            lag: store.lag,
            audit_head: store.audit_head,
            journal_oldest: store.journal_oldest,
            journal_len: store.journal_len,
            data_bytes: store.data_bytes,
            disk_bytes: store.disk_bytes,
            quorum: store.quorum.into(),
        },
        tls,
        ui,
        modules: state.modules(),
        warnings,
        cluster: state.cluster_status(),
        kek,
        leader: None,
        backup: None,
        data_format: None,
        host: host.map(|host| HostStatus {
            cpu_percent: host.cpu_percent.map(f64::from),
            memory_total: host.memory_total,
            memory_available: host.memory_available,
            disk_total: host.disk_total,
            disk_available: host.disk_available,
            sampled_at: host.sampled_at,
        }),
    }
}

/// The object of system-wide reads (status, metrics, audit).
pub(crate) fn system_object() -> ObjectRef {
    ObjectRef::new(ObjectKind::System, Uuid::nil())
}

#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "system",
    operation_id = "openapi_document",
    summary = "Get the OpenAPI document of this API",
    responses(
        (status = 200, description = "The OpenAPI document", body = Object, content_type = "application/json")
    ),
    security()
)]
async fn openapi_document() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        OPENAPI_DOCUMENT,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode},
    };
    use tenko_cluster::ca::{TlsPolicy, TrustedProxies};
    use tower::ServiceExt as _;

    use super::*;

    const ROOT: &str = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";

    fn tls(mode: TlsMode) -> TlsService {
        TlsService::new(mode, TlsPolicy::default()).expect("tls service")
    }

    const FINGERPRINT: &str = "4f0c2b7e9a1d6c3b8e5f7a2d9c1b4e6f8a3d5c7e9b1f2a4c6e8d0b3f5a7c9e1";

    #[test]
    fn the_fingerprint_follows_the_tls_mode() {
        let internal = CaRootSource::new(tls(TlsMode::InternalCa), ROOT, FINGERPRINT);
        assert_eq!(internal.fingerprint().as_deref(), Some(FINGERPRINT));
        let proxied = CaRootSource::new(tls(reverse_proxy()), ROOT, FINGERPRINT);
        assert!(proxied.fingerprint().is_none());
    }

    fn reverse_proxy() -> TlsMode {
        TlsMode::ReverseProxy {
            trusted_proxies: TrustedProxies::default(),
            proxy_protocol: false,
            public_host: "ddi.example.org".to_owned(),
        }
    }

    async fn get(source: Option<CaRootSource>) -> (StatusCode, HeaderMap, String) {
        let mut router = crate::router();
        if let Some(source) = source {
            router = router.layer(Extension(Arc::new(source)));
        }
        let request = Request::get("/api/v1/system/ca-root")
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (
            status,
            headers,
            String::from_utf8(body.to_vec()).expect("UTF-8"),
        )
    }

    #[tokio::test]
    async fn the_root_is_served_in_internal_ca_mode() {
        let source = CaRootSource::new(tls(TlsMode::InternalCa), ROOT, FINGERPRINT);
        let (status, headers, body) = get(Some(source)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, ROOT);
        assert_eq!(headers[header::CONTENT_TYPE], PEM_FILE);
        assert_eq!(headers[header::CACHE_CONTROL], CA_ROOT_CACHE);
        assert_eq!(headers[header::CONTENT_DISPOSITION], CA_ROOT_FILE);
    }

    #[tokio::test]
    async fn other_modes_answer_no_internal_ca() {
        let source = CaRootSource::new(tls(reverse_proxy()), ROOT, FINGERPRINT);
        let (status, headers, body) = get(Some(source)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        let problem: serde_json::Value = serde_json::from_str(&body).expect("problem JSON");
        assert_eq!(problem["code"], NO_INTERNAL_CA);
        assert!(!body.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn without_a_source_the_answer_is_no_internal_ca() {
        let (status, _, body) = get(None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let problem: serde_json::Value = serde_json::from_str(&body).expect("problem JSON");
        assert_eq!(problem["code"], NO_INTERNAL_CA);
    }

    #[test]
    fn the_source_follows_a_mode_switch() {
        let service = tls(TlsMode::InternalCa);
        let source = CaRootSource::new(service.clone(), ROOT, FINGERPRINT);
        assert_eq!(source.current().as_deref(), Some(ROOT));
        service.set_mode(reverse_proxy()).expect("switch");
        assert_eq!(source.current(), None);
    }

    /// The `version` member of the JSON answer of `GET path`, with `running` as the
    /// request extension when given.
    async fn version_at(path: &str, running: Option<RunningVersion>) -> String {
        let mut router = crate::router();
        if let Some(running) = running {
            router = router.layer(Extension(running));
        }
        let request = Request::get(format!("/api/v1{path}"))
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        json["version"].as_str().expect("version").to_owned()
    }

    #[tokio::test]
    async fn the_openapi_route_serves_the_committed_bytes() {
        let request = Request::get("/api/v1/openapi.json")
            .body(Body::empty())
            .expect("request");
        let response = crate::router().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("body");
        assert_eq!(body.as_ref(), OPENAPI_DOCUMENT.as_bytes());
        assert!(
            OPENAPI_DOCUMENT.ends_with(
                "}
"
            ),
            "the pretty-printed file"
        );
    }

    #[tokio::test]
    async fn health_and_status_name_the_running_version_of_the_server_binary() {
        for path in ["/health", "/system/status"] {
            assert_eq!(version_at(path, None).await, crate::version(), "{path}");
            assert_eq!(
                version_at(path, Some(RunningVersion::new("9.8.7"))).await,
                "9.8.7",
                "{path}"
            );
        }
    }

    #[test]
    fn a_leader_service_that_gave_up_is_a_warning() {
        use crate::dto::system::LeaderServiceStatus;

        let service = |name: &str, state, error: Option<&str>| LeaderServiceStatus {
            name: name.to_owned(),
            state,
            restarts: 2,
            last_error: error.map(str::to_owned),
            since: None,
        };
        let leader = LeaderStatus {
            leads: true,
            epoch: Some(4),
            since: None,
            clock_skew_ms: None,
            services: vec![
                service("jobs.runner", LeaderServiceState::Running, None),
                service(
                    "vault.kek_rotation",
                    LeaderServiceState::Restarting,
                    Some("the store has no quorum"),
                ),
            ],
        };
        let warnings = leader_warnings(&leader);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, LEADER_SERVICE_FAILING);
        let skewed = LeaderStatus {
            clock_skew_ms: Some(-6_200),
            ..leader.clone()
        };
        let warnings = leader_warnings(&skewed);
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[1].code, CLOCK_SKEW);
        assert_eq!(warnings[1].params["skew_ms"], "-6200");
        let within = LeaderStatus {
            clock_skew_ms: Some(4_900),
            ..leader.clone()
        };
        assert_eq!(leader_warnings(&within).len(), 1);
        assert_eq!(warnings[0].params["service"], "vault.kek_rotation");
        assert_eq!(warnings[0].params["restarts"], "2");
        let source = LeaderSource::new(move || leader.clone());
        assert_eq!(source.current().epoch, Some(4));
        let json = serde_json::to_value(source.current()).expect("JSON");
        assert_eq!(json["services"][1]["state"], "restarting");
    }

    #[test]
    fn a_blocked_migration_names_the_voters() {
        use crate::dto::system::{FormatBlocker, PendingMigration};
        let current = DataFormatStatus {
            stored: 3,
            binary: 3,
            pending: None,
        };
        assert_eq!(data_format_warnings(&current), Vec::new());
        let running = DataFormatStatus {
            stored: 2,
            binary: 3,
            pending: Some(PendingMigration {
                target: 3,
                blocked_by: Vec::new(),
            }),
        };
        assert_eq!(data_format_warnings(&running), Vec::new());
        let blocked = DataFormatStatus {
            pending: Some(PendingMigration {
                target: 3,
                blocked_by: vec![FormatBlocker {
                    node: tenko_core::NodeId(1002),
                    version: Some("0.1.0".to_owned()),
                    data_format: Some(2),
                }],
            }),
            ..running
        };
        let warnings = data_format_warnings(&blocked);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, MIGRATION_BLOCKED);
        assert_eq!(warnings[0].params["nodes"], "1002");
        assert_eq!(warnings[0].params["target"], "3");
        let source = DataFormatSource::new(move || Some(blocked.clone()));
        let json = serde_json::to_value(source.current()).expect("JSON");
        assert_eq!(json["pending"]["blocked_by"][0]["node"], 1002);
        assert_eq!(json["stored"], 2);
    }

    #[test]
    fn a_data_directory_short_of_room_is_a_warning_that_clears_with_the_space() {
        let gib = 1_u64 << 30;
        let host = |available| HostSample {
            cpu_percent: None,
            memory_total: None,
            memory_available: None,
            disk_total: Some(50 * gib),
            disk_available: Some(available),
            sampled_at: Timestamp::now(),
        };
        let path = std::path::Path::new("/srv/tenko-data");
        let low = disk_low_warning(&host(4 * gib), Some(path)).expect("4 of 50 GiB is low");
        assert_eq!(low.code, DISK_LOW);
        assert_eq!(low.params["available"], (4 * gib).to_string());
        assert_eq!(low.params["total"], (50 * gib).to_string());
        assert_eq!(low.params["limit"], (5 * gib).to_string());
        assert_eq!(low.params["path"], path.display().to_string());
        assert!(low.detail.contains("4.0 GiB of 50.0 GiB"), "{}", low.detail);
        assert_eq!(disk_low_warning(&host(5 * gib), Some(path)), None);
        assert_eq!(
            disk_low_warning(&HostSample::blank(Timestamp::now()), None),
            None
        );
    }

    #[test]
    fn the_status_carries_the_host_and_its_disk_finding() {
        let state = AppState::default();
        state.host().set_data_dir(std::env::temp_dir());
        let status = status_of(&state, Timestamp::now());
        let host = status
            .host
            .as_ref()
            .expect("the data directory's file system is read");
        assert!(host.disk_total.is_some_and(|total| total > 0));
        assert!(host.disk_available.is_some());
        let json = serde_json::to_value(&status).expect("json");
        assert!(json["host"]["disk_total"].is_u64());
        assert!(json["host"]["sampled_at"].is_string());
        assert!(
            json["host"].get("cpu_percent").is_none(),
            "no earlier reading"
        );
        // Whether this machine's temp directory is short of room decides the finding.
        let low = status
            .warnings
            .iter()
            .any(|warning| warning.code == DISK_LOW);
        assert_eq!(
            low,
            state
                .host()
                .current()
                .is_some_and(|host| host.disk_is_low())
        );
    }
}
