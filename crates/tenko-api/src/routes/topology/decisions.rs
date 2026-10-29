//! The root of the map, the SSID view and the decisions a person takes on them (U7).
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /topology/root` | 200 [`RootDecision`], `ETag` of the stored choice | 403, 503 |
//! | `PUT /topology/root` | 200 [`RootDecision`] after the choice | 400, 403, 409 `ipam.topology.no_candidate`, 412, 503 |
//! | `DELETE /topology/root` | 204 | 403, 404 `ipam.topology.not_stored`, 412, 503 |
//! | `GET /topology/ssids` | 200 [`SsidView`] | 403, 503 |
//! | `PUT /topology/ssids/{ssid}/policy` | 200 [`StoredWlanPolicy`] | 400, 403, 412, 422, 503 |
//! | `DELETE /topology/ssids/{ssid}/policy` | 204, the default applies again | 403, 404, 412, 422, 503 |
//! | `PUT /topology/ssids/{ssid}/exceptions/{host}` | 200 [`WlanException`] | 400, 403, 404, 412, 422, 503 |
//! | `DELETE /topology/ssids/{ssid}/exceptions/{host}` | 204 | 403, 404, 412, 422, 503 |
//!
//! The reads need [`Action::Read`] on observations, as the map does. The root and the SSID
//! policies are IPAM writes of the network's layer 2: [`Action::Update`] on VLANs; an
//! exception is a decision about one host: [`Action::Update`] on that host. Every write
//! takes an optional `If-Match` with the stored row's revision (412
//! `ipam.revision_mismatch` when it changed) and writes its audit record in the same batch.
//! Nothing here writes to a network controller (CONN-08, CONN-09).

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tenko_core::{Action, HostId, ObjectKind, ObjectRef, Revision};
use tenko_ipam::topology::{
    RootDecision, RootSource, SsidView, StoredWlanPolicy, WlanException, WlanPolicy,
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::Topology;
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    routes::common::{Ipam, IpamJson, IpamPath, authorize, if_match, new_of, with_etag},
    state::AppState,
};

/// The body of `PUT /topology/root`: the source the map follows.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChooseRoot {
    /// The source whose candidate is the root.
    pub source: RootSource,
}

/// The body of `PUT /topology/ssids/{ssid}/policy`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetWlanPolicy {
    /// Track: the WLAN rules read the SSID; ignore: they skip it.
    pub policy: WlanPolicy,
}

/// The body of `PUT /topology/ssids/{ssid}/exceptions/{host}`; may be empty.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct KeepOnWlan {
    /// Why the host stays on this WLAN: at most 1,024 bytes, no control characters other
    /// than line breaks and tabs.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The SSID of a path: the path carries it percent-encoded.
#[derive(Debug, Deserialize)]
pub(super) struct SsidPath {
    ssid: String,
}

/// The SSID and host of a path.
#[derive(Debug, Deserialize)]
pub(super) struct ExceptionPath {
    ssid: String,
    host: HostId,
}

/// The routes of the decisions.
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            get_topology_root,
            choose_topology_root,
            clear_topology_root
        ))
        .routes(routes!(list_topology_ssids))
        .routes(routes!(set_wlan_policy, clear_wlan_policy))
        .routes(routes!(keep_on_wlan, clear_wlan_exception))
}

fn layer_two() -> ObjectRef {
    new_of(ObjectKind::Vlan)
}

/// The root of the map with its candidates: the controller's gateway and the next hop of
/// this node's default route, whether they disagree, and the stored choice.
#[utoipa::path(
    get,
    path = "/topology/root",
    tag = "topology",
    operation_id = "get_topology_root",
    summary = "Get the root of the topology map",
    responses(
        (status = 200, description = "The candidates, the root and the stored choice; the `ETag` is the choice's revision", body = RootDecision),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_topology_root(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    filters: Filters,
) -> Result<Response, ApiError> {
    filters.only(&["at_least"])?;
    let at_least = filters.parse::<u64>("at_least")?.map(Revision);
    authorize(&app, &cx, Action::Read, new_of(ObjectKind::Observation))?;
    let decision = topology.root(at_least, cx.principal.user()).await?;
    let revision = decision.choice.as_ref().map(|choice| choice.revision);
    let response = Json(decision).into_response();
    Ok(match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    })
}

/// "Use this": the map follows the candidate of `source` from now on; the disagreement of
/// the same candidates raises no finding again. Audited as `ipam.topology_root.choose`.
#[utoipa::path(
    put,
    path = "/topology/root",
    tag = "topology",
    operation_id = "choose_topology_root",
    summary = "Choose the root of the topology map",
    request_body = ChooseRoot,
    params(crate::routes::common::IfMatch),
    responses(
        (status = 200, description = "The root after the choice", body = RootDecision),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: the choice needs `update` on VLANs", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The source names no root now (`ipam.topology.no_candidate`), or a concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The choice changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn choose_topology_root(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    headers: HeaderMap,
    IpamJson(body): IpamJson<ChooseRoot>,
) -> Result<Json<RootDecision>, ApiError> {
    authorize(&app, &cx, Action::Update, layer_two())?;
    let decision = topology
        .choose_root(&cx, body.source, if_match(&headers)?)
        .await?;
    Ok(Json(decision))
}

/// Forgets the chosen root; the ranked sources decide again. Audited as
/// `ipam.topology_root.clear`.
#[utoipa::path(
    delete,
    path = "/topology/root",
    tag = "topology",
    operation_id = "clear_topology_root",
    summary = "Forget the chosen root of the topology map",
    params(crate::routes::common::IfMatch),
    responses(
        (status = 204, description = "The ranked sources decide again"),
        (status = 403, description = "Not allowed: needs `update` on VLANs", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No root was chosen (`ipam.topology.not_stored`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The choice changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn clear_topology_root(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(&app, &cx, Action::Update, layer_two())?;
    topology.clear_root(&cx, if_match(&headers)?).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The SSID view: every SSID of the network controllers with the VLAN it carries, the
/// networks of that VLAN, the policy of the WLAN rules and the count of findings, and the
/// clients by VLAN with their access point and band. Read from the controllers only
/// (CONN-05). A principal whose grants cover only some hosts sees the clients of those.
#[utoipa::path(
    get,
    path = "/topology/ssids",
    tag = "topology",
    operation_id = "list_topology_ssids",
    summary = "List the SSIDs with their VLANs and clients",
    responses(
        (status = 200, description = "The SSIDs", body = SsidView),
        (status = 403, description = "The principal may not read observations", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_topology_ssids(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    Topology(topology): Topology,
    filters: Filters,
) -> Result<Json<SsidView>, ApiError> {
    filters.only(&["at_least"])?;
    let at_least = filters.parse::<u64>("at_least")?.map(Revision);
    authorize(&app, &cx, Action::Read, new_of(ObjectKind::Observation))?;
    let mut view = topology.ssids(at_least, cx.principal.user()).await?;
    if !ipam.read_scope(&cx, ObjectKind::Observation).is_all() {
        let hosts = ipam.read_scope(&cx, ObjectKind::Host);
        for entry in &mut view.ssids {
            for vlan in &mut entry.vlans {
                vlan.clients.retain(|client| {
                    client
                        .host
                        .is_some_and(|host| hosts.admits(&ObjectRef::from(host)))
                });
            }
            entry.clients = entry.vlans.iter().map(|vlan| vlan.clients.len()).sum();
            entry.findings = entry
                .vlans
                .iter()
                .flat_map(|vlan| &vlan.clients)
                .map(|client| client.findings.len())
                .sum();
        }
    }
    Ok(Json(view))
}

/// Sets whether the WLAN rules read an SSID. Audited as `ipam.wlan_policy.set`.
#[utoipa::path(
    put,
    path = "/topology/ssids/{ssid}/policy",
    tag = "topology",
    operation_id = "set_wlan_policy",
    summary = "Set the policy of an SSID",
    params(
        ("ssid" = String, Path, description = "The SSID, percent-encoded"),
        crate::routes::common::IfMatch
    ),
    request_body = SetWlanPolicy,
    responses(
        (status = 200, description = "The stored policy", body = StoredWlanPolicy),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: needs `update` on VLANs", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The policy changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The SSID is empty, longer than 32 octets or has control characters (`ipam.topology.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn set_wlan_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    IpamPath(path): IpamPath<SsidPath>,
    headers: HeaderMap,
    IpamJson(body): IpamJson<SetWlanPolicy>,
) -> Result<Response, ApiError> {
    authorize(&app, &cx, Action::Update, layer_two())?;
    let row = topology
        .set_policy(&cx, &path.ssid, body.policy, if_match(&headers)?)
        .await?;
    let revision = row.revision;
    Ok(with_etag(Json(row).into_response(), revision))
}

/// Removes the policy of an SSID, so its default applies again (ignore for a guest SSID,
/// track otherwise). Audited as `ipam.wlan_policy.clear`.
#[utoipa::path(
    delete,
    path = "/topology/ssids/{ssid}/policy",
    tag = "topology",
    operation_id = "clear_wlan_policy",
    summary = "Remove the policy of an SSID",
    params(
        ("ssid" = String, Path, description = "The SSID, percent-encoded"),
        crate::routes::common::IfMatch
    ),
    responses(
        (status = 204, description = "The default applies again"),
        (status = 403, description = "Not allowed: needs `update` on VLANs", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No policy is set (`ipam.topology.not_stored`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The policy changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The SSID is invalid (`ipam.topology.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn clear_wlan_policy(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    IpamPath(path): IpamPath<SsidPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(&app, &cx, Action::Update, layer_two())?;
    topology
        .clear_policy(&cx, &path.ssid, if_match(&headers)?)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// "Keep on this WLAN": the WLAN rules skip this host on this SSID from now on; the
/// findings about the pair go away at the next derivation. Audited as
/// `ipam.wlan_exception.keep` on the host.
#[utoipa::path(
    put,
    path = "/topology/ssids/{ssid}/exceptions/{host}",
    tag = "topology",
    operation_id = "keep_on_wlan",
    summary = "Keep a host on a WLAN",
    params(
        ("ssid" = String, Path, description = "The SSID, percent-encoded"),
        ("host" = String, Path, description = "Host identifier"),
        crate::routes::common::IfMatch
    ),
    request_body = KeepOnWlan,
    responses(
        (status = 200, description = "The stored exception", body = WlanException),
        (status = 400, description = "The body or the host identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: needs `update` on the host", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change won (`sys.store.precondition_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The exception changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The SSID or the reason is invalid (`ipam.topology.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn keep_on_wlan(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    IpamPath(path): IpamPath<ExceptionPath>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    authorize(&app, &cx, Action::Update, ObjectRef::from(path.host))?;
    // An empty body keeps without a reason.
    let body: KeepOnWlan = if body.iter().all(u8::is_ascii_whitespace) {
        KeepOnWlan::default()
    } else {
        serde_json::from_slice(&body).map_err(|error| {
            ApiError::from_coded_error(
                tenko_core::CodedError::new(
                    tenko_core::error::codes::INVALID_REQUEST,
                    400,
                    format!("the body is not a valid request: {error}"),
                )
                .with_param("part", "body"),
            )
        })?
    };
    let reason = body.reason;
    let row = topology
        .keep(&cx, path.host, &path.ssid, reason, if_match(&headers)?)
        .await?;
    let revision = row.revision;
    Ok(with_etag(Json(row).into_response(), revision))
}

/// Removes the exception: the WLAN rules read the host on the SSID again. Audited as
/// `ipam.wlan_exception.clear` on the host.
#[utoipa::path(
    delete,
    path = "/topology/ssids/{ssid}/exceptions/{host}",
    tag = "topology",
    operation_id = "clear_wlan_exception",
    summary = "Remove a WLAN exception",
    params(
        ("ssid" = String, Path, description = "The SSID, percent-encoded"),
        ("host" = String, Path, description = "Host identifier"),
        crate::routes::common::IfMatch
    ),
    responses(
        (status = 204, description = "The rules read the pair again"),
        (status = 400, description = "The host identifier is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed: needs `update` on the host", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such exception (`ipam.topology.not_stored`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "The exception changed since `If-Match` (`ipam.revision_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The SSID is invalid (`ipam.topology.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM or the topology is not configured", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn clear_wlan_exception(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Topology(topology): Topology,
    IpamPath(path): IpamPath<ExceptionPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(&app, &cx, Action::Update, ObjectRef::from(path.host))?;
    topology
        .forget(&cx, path.host, &path.ssid, if_match(&headers)?)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests;
