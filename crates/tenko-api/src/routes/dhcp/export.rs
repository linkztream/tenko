//! The Kea export (WP9.3, MIG-16, `docs/dhcp.md` section 18): `GET /dhcp/export?format=kea`
//! and its variant without the leases (`leases=false`).
//!
//! The route reads every DHCP row and the IPAM rows the scopes derive from at one
//! revision, the DNS zones' names and, when the `dhcp` role runs in this process, its
//! DHCPv4 and DHCPv6 listeners, and answers [`tenko_dhcp::export::kea`]'s export: the
//! `kea-dhcp4` and `kea-dhcp6` configurations, their memfile lease files, the
//! `kea-dhcp-ddns` skeleton and the loss report of both families ([`DhcpExport`]).
//! It is server-wide configuration and the leases are personal data, so the caller needs
//! `dhcp.read` on the `dhcp_scope` singleton (global roles only), and every export is
//! audited as `dhcp.export` with the format, whether the leases were included and the
//! counts.

use axum::{
    Extension, Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Action, CodedError,
    audit::AuditDraft,
    dhcp::{audit, codes as dhcp_codes, server_object},
    ir::LossEntry,
};
use tenko_dhcp::{
    config::load,
    export::kea::{self, KeaInput},
};
use tenko_store::WriteBatch;
use utoipa::ToSchema;

use super::{Configs, DhcpExportParams, DhcpNodeSlot, settings};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

// WP9.3, the DHCPv6 half: the answer of the route, in this file of the export so that the
// DHCPv6 lease file joins it; it supersedes `model::DhcpExport`, which no route names now.
/// The Kea export (P3-Q17): the configurations of both families, their leases and what
/// did not map.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpExport {
    /// The `kea-dhcp4` configuration file: `{"Dhcp4": {..}}` for Kea 2.6.
    #[schema(value_type = Object)]
    pub dhcp4: serde_json::Value,
    /// The `kea-dhcp6` configuration file: `{"Dhcp6": {..}}` for Kea 2.6. Absent when no
    /// scope is on an IPv6 prefix and the role has no DHCPv6 listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub dhcp6: Option<serde_json::Value>,
    /// A `kea-dhcp-ddns` configuration skeleton (`{"DhcpDdns": {..}}`) with the forward and
    /// reverse domains of the scopes of both families that write names; its DNS servers
    /// and TSIG keys are the operator's. Absent when no scope writes names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub dhcp_ddns: Option<serde_json::Value>,
    /// The DHCPv4 leases as Kea's memfile lease file (`kea-leases4.csv`), when asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases4_csv: Option<String>,
    /// The DHCPv6 leases as Kea's memfile lease file (`kea-leases6.csv`), when asked for
    /// and `dhcp6` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases6_csv: Option<String>,
    /// What Kea does not express as Tenko does, for both families: one entry per item,
    /// with a stable code (`export.kea.*`).
    #[serde(default)]
    pub losses: Vec<LossEntry>,
}

fn unknown_format(format: &str) -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            dhcp_codes::EXPORT_FORMAT,
            400,
            format!("the export format `{format}` is not known; `kea` is"),
        )
        .with_title("Unknown export format")
        .with_param("format", format.to_owned()),
    )
}

#[utoipa::path(
    get,
    path = "/dhcp/export",
    tag = "dhcp",
    operation_id = "export_dhcp",
    summary = "Export the DHCP configuration and leases (Kea JSON)",
    description = "Scope: `dhcp.read` on the server-wide DHCP configuration (global roles). \
                   The Kea 2.6 export (MIG-16): `dhcp4` is the `kea-dhcp4` configuration file, \
                   `dhcp6` the `kea-dhcp6` one when there is a DHCPv6 scope or listener, \
                   `leases4_csv` and `leases6_csv` the memfile lease files (unless \
                   `leases=false`), `dhcp_ddns` a `kea-dhcp-ddns` skeleton when a scope writes \
                   names, `losses` what Kea does not express as Tenko does. The export is \
                   audited (`dhcp.export`).",
    params(DhcpExportParams),
    responses(
        (status = 200, description = "The export", body = DhcpExport),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_value`), or the export format is not known (`dhcp.export.format`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dhcp.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The DHCP module is off (`dhcp.module.disabled`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn export_dhcp(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    configs: Configs,
    slot: Option<Extension<DhcpNodeSlot>>,
    Query(params): Query<DhcpExportParams>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &server_object())?;
    let format = params.format.as_deref().unwrap_or("kea");
    if format != "kea" {
        return Err(unknown_format(format));
    }
    let leases = params.leases.unwrap_or(true);
    let service = configs.get()?;
    let view = service.view(None).await?;
    let data = load::data(view.as_ref(), leases)?;
    let zones = kea::zone_names(view.as_ref())?;
    let profile = settings::profile(view.as_ref())?;
    let conflict_detection = data
        .settings
        .as_ref()
        .and_then(|settings| settings.conflict_detection)
        .unwrap_or_else(|| settings::profile_defaults(profile).conflict_detection);
    drop(view);
    let status = slot.and_then(|Extension(slot)| slot.status());
    let listeners = status.as_ref().map(|status| status.listeners.clone());
    let listeners6 = status.as_ref().map(|status| status.listeners6.clone());
    // WP9.4: the role's server DUID (WP9.2) gives `server-id`; without the role in this
    // process, or without DHCPv6, the export reports it as not known.
    let server_duid = status.and_then(|status| status.server_duid);
    let export = kea::export(&KeaInput {
        data: &data,
        zones: &zones,
        listeners: listeners.as_deref(),
        listeners6: listeners6.as_deref(),
        server_duid: server_duid.as_deref(),
        now: cx.now,
        leases,
        conflict_detection,
    });
    let subnets = data.scopes.len();
    let rows = |csv: Option<&String>| csv.map_or(0, |csv| csv.lines().count().saturating_sub(1));
    let lease_rows = rows(export.leases4_csv.as_ref()) + rows(export.leases6_csv.as_ref());
    let mut batch = WriteBatch::for_request(&cx);
    batch.audit(
        AuditDraft::success(audit::EXPORT, vec![server_object()])
            .with_context("format", "kea")
            .with_context("leases", leases.to_string())
            .with_context("scopes", subnets.to_string())
            .with_context("lease_rows", lease_rows.to_string())
            .with_context("losses", export.report.entries.len().to_string()),
    );
    service
        .commit_record(
            &cx,
            "dhcp.export in the format kea".to_owned(),
            vec![server_object()],
            batch,
        )
        .await?;
    Ok(Json(DhcpExport {
        dhcp4: export.dhcp4,
        dhcp6: export.dhcp6,
        dhcp_ddns: export.dhcp_ddns,
        leases4_csv: export.leases4_csv,
        leases6_csv: export.leases6_csv,
        losses: export.report.entries,
    })
    .into_response())
}
