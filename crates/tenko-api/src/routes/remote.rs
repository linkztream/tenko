//! Remote access hand-off from the host view (API-11).
//!
//! Area: secrets. Owner: WP2.1.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /hosts/{id}/remote?protocol=rdp` | 200 an `.rdp` file (`application/x-rdp`, as an attachment) | 400 `sys.invalid_query`, 403, 404 `ipam.not_found`, 422 `remote.interface_unknown`, `remote.address_unknown` |
//! | `GET /hosts/{id}/remote?protocol=ssh` | 200 [`SshHandoff`] with the `ssh://` URI | as above |
//!
//! Neither answer carries a secret: the `.rdp` file asks for the password when it opens
//! (`prompt for credentials:i:1`), and the password reaches the clipboard only through
//! `POST /secrets/{id}/reveal`, audited (IAM-16).
//!
//! # Target, port and user
//!
//! - `address` (an IP address of the host, or the DNS name of one of its addresses) is used
//!   as given; else `interface` narrows the
//!   choice to one interface of the host; the target is then the first live address (IPv4
//!   first) of the host or interface, by its DNS name when it has one, else the host name.
//! - `port` defaults to 3389 for RDP and 22 for SSH.
//! - `user` is used as given; else the user name of the credential bound to the host with
//!   the role `rdp` or `ssh`, else the `admin` one, when the caller may read secrets
//!   (viewers never learn a bound user name).
//!
//! Reading needs [`Action::Read`] on the host.

mod handoff;

use std::{net::IpAddr, sync::Arc};

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_core::{
    Action, CodedError, HostId, InterfaceId, ObjectRef,
    codec::key::encode_key,
    ipam::{Address, Host, Interface},
};
use tenko_ipam::{
    query,
    tables::{HOST_INTERFACES, INTERFACE_ADDRESSES},
};
use tenko_store::{KeyRange, ReadViewExt};
use tenko_vault::operator::{CredentialRole, OperatorSecrets};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    auth::RouteError,
    common::{Ipam, IpamPath},
    secrets::handoff_username,
};
use crate::{
    extract::Ctx,
    list::Filters,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

/// The routes under a host (IPAM module): `/hosts/{id}/remote`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_host_remote))
}

/// The protocol of a hand-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteProtocol {
    /// Remote Desktop: an `.rdp` file.
    Rdp,
    /// SSH: an `ssh://` URI.
    Ssh,
}

/// The query of `GET /hosts/{id}/remote`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RemoteParams {
    /// `rdp` or `ssh`.
    #[param(inline)]
    pub protocol: RemoteProtocol,
    /// An interface of the host to connect through.
    pub interface: Option<InterfaceId>,
    /// An IP address of the host, or the DNS name of one of its addresses, used as given.
    pub address: Option<String>,
    /// The TCP port, 1 to 65535 (default 3389 for RDP, 22 for SSH).
    pub port: Option<u16>,
    /// The user name; by default the one of the credential bound to the host.
    pub user: Option<String>,
}

/// The SSH hand-off: the URI for the operating system's SSH handler, without a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SshHandoff {
    /// `ssh://[user@]host[:port]`; the port only when it is not 22.
    pub uri: String,
    /// The target: a DNS name, an IP address or the host name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The user name, when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Longest user name accepted in the query.
const MAX_USER_CHARS: usize = 256;

fn unknown(code: &'static str, field: &str, detail: impl Into<String>) -> RouteError {
    RouteError::from(ApiError::from_coded_error(
        CodedError::new(code, 422, detail)
            .with_title("Unprocessable content")
            .with_param("field", field),
    ))
}

/// The live interfaces of a host, by name.
fn interfaces(view: &dyn tenko_store::ReadView, host: HostId) -> Result<Vec<Interface>, ApiError> {
    let ids = view
        .scan_typed(
            &HOST_INTERFACES,
            KeyRange::prefix(encode_key(&(host,))),
            usize::MAX,
            false,
        )
        .map_err(ApiError::from)?;
    let mut out = Vec::new();
    for ((_, id), (), _) in ids {
        if let Ok(interface) = query::get::<Interface>(view, id)
            && !interface.meta.is_deleted()
        {
            out.push(interface);
        }
    }
    out.sort_by_key(|interface| interface.name.to_lowercase());
    Ok(out)
}

/// The live addresses of an interface.
fn addresses(
    view: &dyn tenko_store::ReadView,
    interface: InterfaceId,
) -> Result<Vec<Address>, ApiError> {
    let ids = view
        .scan_typed(
            &INTERFACE_ADDRESSES,
            KeyRange::prefix(encode_key(&(interface,))),
            usize::MAX,
            false,
        )
        .map_err(ApiError::from)?;
    let mut out = Vec::new();
    for ((_, id), (), _) in ids {
        if let Ok(address) = query::get::<Address>(view, id)
            && !address.meta.is_deleted()
        {
            out.push(address);
        }
    }
    Ok(out)
}

/// Builds the hand-off of a host for RDP (an `.rdp` file) or SSH (an `ssh://` URI): the
/// target, the port and the user name, never a secret. The password goes to the clipboard
/// through the audited reveal of the bound credential.
#[utoipa::path(
    get,
    path = "/hosts/{id}/remote",
    tag = "secrets",
    operation_id = "get_host_remote",
    summary = "Get the RDP file or SSH URI of a host",
    params(("id" = String, Path, description = "Host identifier"), RemoteParams),
    responses(
        (status = 200, description = "For `rdp` an `.rdp` file as an attachment (CRLF line ends, it prompts for the password); for `ssh` the URI", content(
            (String = "application/x-rdp"),
            (SshHandoff = "application/json")
        )),
        (status = 400, description = "A parameter is missing, unknown or malformed (`sys.invalid_query`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed (`auth.forbidden`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such host (`ipam.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The interface or address does not belong to the host (`remote.interface_unknown`, `remote.address_unknown`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "IPAM not configured (`ipam.unavailable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_host_remote(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Ipam(ipam): Ipam,
    secrets: Option<Extension<Arc<OperatorSecrets>>>,
    IpamPath(id): IpamPath<HostId>,
    filters: Filters,
) -> Result<Response, RouteError> {
    let query = parse(&filters)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(id))?;
    let view = ipam.view(None).await.map_err(ApiError::from)?;
    let host = query::get::<Host>(view.as_ref(), id).map_err(ApiError::from)?;
    let target = target(view.as_ref(), &host, query.interface, query.address)?;
    let role = match query.protocol {
        RemoteProtocol::Rdp => CredentialRole::Rdp,
        RemoteProtocol::Ssh => CredentialRole::Ssh,
    };
    let username = match query.user {
        Some(user) => Some(user),
        None => {
            handoff_username(
                &app,
                &cx,
                secrets.as_ref().map(|Extension(secrets)| secrets),
                id,
                role,
            )
            .await?
        }
    };
    respond(query.protocol, &host, target, query.port, username)
}

/// The parsed query.
struct Query {
    protocol: RemoteProtocol,
    interface: Option<InterfaceId>,
    address: Option<String>,
    port: Option<u16>,
    user: Option<String>,
}

fn parse(filters: &Filters) -> Result<Query, RouteError> {
    filters.only(&["protocol", "interface", "address", "port", "user"])?;
    let protocol = match filters.get("protocol")? {
        Some("rdp") => RemoteProtocol::Rdp,
        Some("ssh") => RemoteProtocol::Ssh,
        _ => {
            return Err(ApiError::invalid_query("protocol", "`rdp` or `ssh` is required").into());
        }
    };
    let interface: Option<InterfaceId> = filters.parse("interface")?;
    let address = filters.get("address")?.map(ToOwned::to_owned);
    let port: Option<u16> = filters.parse("port")?;
    if port == Some(0) {
        return Err(ApiError::invalid_query("port", "a port is 1 to 65535").into());
    }
    let user = match filters.get("user")? {
        Some(user)
            if user.chars().count() > MAX_USER_CHARS || user.chars().any(char::is_control) =>
        {
            return Err(ApiError::invalid_query(
                "user",
                "a user name has at most 256 visible characters",
            )
            .into());
        }
        other => other.map(ToOwned::to_owned),
    };
    Ok(Query {
        protocol,
        interface,
        address,
        port,
        user,
    })
}

/// Where to connect to: the address as given (an IP address of the host or interface, or
/// the DNS name of one of its addresses), else the first live address (IPv4 first) by its
/// DNS name when it has one, else the host name.
fn target(
    view: &dyn tenko_store::ReadView,
    host: &Host,
    interface: Option<InterfaceId>,
    address: Option<String>,
) -> Result<String, RouteError> {
    let mut candidates = interfaces(view, host.id)?;
    if let Some(wanted) = interface {
        candidates.retain(|interface| interface.id == wanted);
        if candidates.is_empty() {
            return Err(unknown(
                "remote.interface_unknown",
                "interface",
                "the interface is not a live interface of this host",
            ));
        }
    }
    let mut live = Vec::new();
    for interface in &candidates {
        live.extend(addresses(view, interface.id)?);
    }
    if let Some(wanted) = address {
        let ip: Option<IpAddr> = wanted.parse().ok();
        let name = wanted.trim_end_matches('.');
        let known = live.iter().any(|address| {
            Some(address.ip) == ip
                || address.dns_name.as_ref().is_some_and(|dns| {
                    dns.to_string()
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(name)
                })
        });
        if !known {
            return Err(unknown(
                "remote.address_unknown",
                "address",
                "the address is neither a live address of this host or interface nor the DNS name of one",
            ));
        }
        return Ok(ip.map_or_else(|| name.to_owned(), |ip| ip.to_string()));
    }
    live.sort_by_key(|address| (address.ip.is_ipv6(), address.ip));
    Ok(live.first().map_or_else(
        || host.name.to_string(),
        |address| {
            address
                .dns_name
                .as_ref()
                .map_or_else(|| address.ip.to_string(), ToString::to_string)
        },
    ))
}

/// The `.rdp` file or the SSH hand-off.
fn respond(
    protocol: RemoteProtocol,
    host: &Host,
    target: String,
    port: Option<u16>,
    username: Option<String>,
) -> Result<Response, RouteError> {
    match protocol {
        RemoteProtocol::Rdp => {
            let port = port.unwrap_or(handoff::DEFAULT_RDP_PORT);
            let text = handoff::rdp_file(&target, port, username.as_deref()).map_err(|_| {
                ApiError::invalid_query("address", "the target of the host is empty")
            })?;
            let name = handoff::rdp_file_name(&host.name.to_string());
            let mut response = text.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(handoff::RDP_MIME),
            );
            if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
                headers.insert(header::CONTENT_DISPOSITION, value);
            }
            Ok(response)
        }
        RemoteProtocol::Ssh => {
            let port = port.unwrap_or(handoff::DEFAULT_SSH_PORT);
            let uri = handoff::ssh_uri(&target, port, username.as_deref()).map_err(|_| {
                ApiError::invalid_query("address", "the target of the host is empty")
            })?;
            Ok(Json(SshHandoff {
                uri,
                host: target,
                port,
                username,
            })
            .into_response())
        }
    }
}

#[cfg(test)]
mod tests;
