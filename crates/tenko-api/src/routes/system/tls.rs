//! The certificates of the listener (OPS-22): what `GET /system/tls` tells about the TLS
//! mode, the served certificate, the files it comes from, the internal CA root and a newer
//! certificate that waits for a restart.
//!
//! Area: system. Requirements: OPS-22, TGL-08.
//!
//! | Endpoint | Who | Success | Notable errors |
//! |---|---|---|---|
//! | `GET /system/tls` | read the system | 200 [`TlsDetails`] | 503 `sys.not_ready` before the listener runs |
//!
//! Read from what the listener holds: the TLS service of the server binary, which publishes
//! the served certificate, the imported paths, the replacement setting and the pending
//! certificate. The private key is never read here; only its path is named. The status
//! warnings of the same facts (`sys.tls.certificate_expiry`, `sys.tls.certificate_pending`)
//! stay in `GET /system/status`.

use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use tenko_cluster::ca::{CertInfo, ExpiryState, TlsMode};
use tenko_core::{Action, Timestamp};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{CaRootSource, system_object};
use crate::{
    dto::system::{
        CertificateState, ImportedTls, InternalCaTls, PendingTlsCertificate, ReverseProxyTls,
        TlsCertificate, TlsDetails,
    },
    extract::Ctx,
    problem::{ApiError, ProblemDetails, codes},
    server::ListenerInfo,
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_tls))
}

/// The route the CA root is downloaded from.
const CA_ROOT_PATH: &str = "/api/v1/system/ca-root";

#[utoipa::path(
    get,
    path = "/system/tls",
    tag = "system",
    operation_id = "get_tls",
    summary = "Get the TLS mode and certificates of this node's listener",
    responses(
        (status = 200, description = "The TLS mode, the served certificate and what belongs to the mode", body = TlsDetails),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The listener is not running yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_tls(
    State(state): State<AppState>,
    ca_root: Option<Extension<Arc<CaRootSource>>>,
    Ctx(ctx): Ctx,
) -> Result<Json<TlsDetails>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &system_object())?;
    let listener = state.platform.listener.load_full().ok_or_else(|| {
        ApiError::new(
            codes::NOT_READY,
            503,
            "the node is not ready: the listener is not running",
        )
        .with_param("reason", "starting")
    })?;
    let ca_root = ca_root.as_ref().map(|Extension(source)| source.as_ref());
    Ok(Json(details_of(&listener, ca_root, ctx.now)))
}

/// The answer for the listener `listener` at `now`; `ca_root` is the internal CA's root
/// source of the server binary, if it runs the CA.
pub(crate) fn details_of(
    listener: &ListenerInfo,
    ca_root: Option<&CaRootSource>,
    now: Timestamp,
) -> TlsDetails {
    let status = listener.tls.status();
    let mode = listener.mode_of(&status.mode);
    let certificate = status
        .certificate
        .as_ref()
        .map(|info| certificate_of(info, status.chain_len, now));
    let pending = status
        .pending
        .as_ref()
        .map(|pending| PendingTlsCertificate {
            certificate: certificate_of(&pending.certificate, pending.chain_len, now),
            detected_at: pending.detected_at,
        });
    let mut details = TlsDetails {
        mode,
        min_version: mode.terminates_tls().then(|| {
            if listener.policy.tls13_only {
                "1.3"
            } else {
                "1.2"
            }
            .to_owned()
        }),
        hsts: listener.hsts && mode != crate::dto::system::TlsMode::Plain,
        certificate,
        loaded_at: status.loaded_at,
        last_error: status.last_error.clone(),
        pending,
        imported: None,
        internal_ca: None,
        reverse_proxy: None,
    };
    match &status.mode {
        TlsMode::InternalCa => {
            let root = ca_root.and_then(CaRootSource::info);
            details.internal_ca = Some(InternalCaTls {
                root_subject: root.as_ref().map(|info| info.subject.clone()),
                root_not_after: root.as_ref().map(|info| info.not_after),
                root_sha256: root.map(|info| info.sha256),
                download_path: CA_ROOT_PATH.to_owned(),
            });
        }
        TlsMode::Imported {
            cert_path,
            key_path,
        } => {
            details.imported = Some(ImportedTls {
                cert_path: cert_path.display().to_string(),
                key_path: key_path.display().to_string(),
                watch_interval_secs: status.watch_interval.map(|interval| interval.as_secs()),
                accept_external_replacement: status.accept_replacement,
            });
        }
        TlsMode::ReverseProxy {
            trusted_proxies,
            proxy_protocol,
            public_host,
        } if mode != crate::dto::system::TlsMode::Plain => {
            details.reverse_proxy = Some(ReverseProxyTls {
                trusted_proxies: trusted_proxies
                    .networks()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                proxy_protocol: *proxy_protocol,
                public_host: public_host.clone(),
            });
        }
        TlsMode::ReverseProxy { .. } => {}
    }
    details
}

fn certificate_of(info: &CertInfo, chain_len: usize, now: Timestamp) -> TlsCertificate {
    let expiry = info.expiry(now);
    TlsCertificate {
        subject: info.subject.clone(),
        issuer: info.issuer.clone(),
        dns_names: info.dns_names.clone(),
        ip_addresses: info.ip_addresses.iter().map(ToString::to_string).collect(),
        not_before: info.not_before,
        not_after: info.not_after,
        days_left: expiry.days_left,
        state: match expiry.state {
            ExpiryState::Valid => CertificateState::Valid,
            ExpiryState::Warning => CertificateState::Warning,
            ExpiryState::Critical => CertificateState::Critical,
            ExpiryState::Expired => CertificateState::Expired,
            ExpiryState::NotYetValid => CertificateState::NotYetValid,
        },
        chain_len: u32::try_from(chain_len).unwrap_or(u32::MAX),
        sha256: info.sha256.clone(),
    }
}

#[cfg(test)]
mod tests;
