//! Integration client certificates (ADR 0035; IAM-22, IAM-25): enrollment codes,
//! enrollment, the root of the integration listener's server certificate, and the listing and
//! revocation of certificates.
//!
//! Area: integrations.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `POST /integrations/enrollments` | 201 [`CreatedCode`], `Cache-Control: no-store` | 403 (`auth.step_up_required`, `integration.account`), 422 `integration.code.lifetime` |
//! | `GET /integrations/enrollments` | 200 [`CodeList`], newest first, never a secret | 403 |
//! | `DELETE /integrations/enrollments/{id}` | 204 | 403, 404 `integration.not_found` |
//! | `GET /integrations/ca` | 200 the internal root, PEM (public) | |
//! | `POST /integrations/enroll` | 201 the certificate, PEM (public: the code's proof authenticates) | 401 `integration.code.*`, 403 `integration.code.source`, `integration.enroll.transport`, `integration.account`, 409 `integration.key.used`, `integration.lineages`, 415, 422 `integration.request.invalid`, `integration.label` |
//! | `GET /integrations/certificates` | 200 [`CertificateList`] | 403 |
//! | `DELETE /integrations/certificates/{serial}` | 204: the lineage is revoked | 403, 404 `integration.not_found` |
//!
//! # The service
//!
//! The server adds [`ClientCerts`] as a request extension; without it every endpoint answers
//! `501` `sys.not_implemented`.
//!
//! # Authorization
//!
//! Every endpoint but the two public ones needs [`Action::Administer`] on users, an
//! administrator right; creating a code also needs an interactive sign-in within the last five
//! minutes, so a token never creates one. `POST /integrations/enroll` takes no session: the
//! request carries the code's id and an HMAC over the request's key, never the code's
//! secret. A request over plain HTTP is refused outside the Lab profile and withdraws the
//! code, as node enrollment does; a request through a trusted proxy that did not state the
//! scheme is refused outside Lab and the code kept.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_auth::{
    client_cert::{
        ClientCertError, ClientCerts, CreatedCode, EnrollInput, Issued, Issuer, NewCode, Renewal,
        model::{ClientCertRecord, EnrollmentCodeView},
    },
    settings::Profile,
};
use tenko_cluster::ca::{CaError, IntegrationCa, InternalCa, integration_request_key};
use tenko_core::{
    Action, CodedError, ObjectKind, ObjectRef, Principal, RequestCtx, Timestamp, UserId,
};
use tenko_store::Store;
use tenko_vault::Vault;
use tokio::sync::OnceCell;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    auth::{ApiJson, PublicCtx},
    not_implemented,
};
use crate::{
    extract::{ClientInfo, Ctx},
    problem::{ApiError, ProblemDetails},
    server::forwarded::{ConnInfo, UnstatedScheme},
    state::AppState,
};

/// The header that names the enrollment code.
pub const CODE_HEADER: &str = "tenko-enrollment-code";
/// The header that carries the enrollment's HMAC, hexadecimal.
pub const PROOF_HEADER: &str = "tenko-enrollment-proof";
/// The media type of an enrollment's body: a PKCS#10 request, DER (RFC 5967).
pub const PKCS10: &str = "application/pkcs10";
/// The media type of an issued certificate (RFC 8555, section 9.1).
pub const PEM_CHAIN: &str = "application/pem-certificate-chain";
/// The largest request body an enrollment reads; a P-256 request is about 250 octets.
pub const MAX_REQUEST: usize = 16 * 1024;

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_integration_codes, create_integration_code))
        .routes(routes!(withdraw_integration_code))
        .routes(routes!(integration_server_root))
        .routes(routes!(enroll_integration))
        .routes(routes!(list_integration_certificates))
        .routes(routes!(revoke_integration_certificate))
        .routes(routes!(renew_integration_certificate))
}

/// The path of the renewal, relative to the API base: the one operation the integration
/// listener serves without a token, to a certificate alone.
pub const RENEW_PATH: &str = "/integrations/certificate/renew";

/// The code of the status condition of lineages that do not renew (OPS-29).
pub const EXPIRING_NOTICE: &str = "integration.certificate_expiring";
/// The health warning while TGL-47 lets the integration listener accept TLS 1.2, under which
/// a host's client certificate is visible on the network path.
pub const TLS12_NOTICE: &str = "integration.tls12_allowed";

/// The answer of a renewal that is not due yet.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RenewalNotDue {
    /// Always `true`.
    pub not_due: bool,
    /// From when a renewal is accepted.
    pub renew_after: Timestamp,
}

/// Body of `GET /integrations/enrollments`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeList {
    /// Every code, newest first.
    pub items: Vec<EnrollmentCodeView>,
}

/// Body of `GET /integrations/certificates`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateList {
    /// The certificates, by serial.
    pub items: Vec<ClientCertRecord>,
}

/// Query of `GET /integrations/certificates`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CertificateQuery {
    /// Only the certificates of this service account.
    pub account: Option<UserId>,
}

/// Query of `POST /integrations/enroll`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EnrollQuery {
    /// The integrator's label of the host, 1 to 64 printable characters.
    pub label: String,
}

/// The integration CA of `tenko-cluster` as the issuer of the service: created on first use,
/// with the internal root its listener's server certificate chains to.
pub struct CaIssuer {
    store: Arc<dyn Store>,
    vault: Arc<dyn Vault>,
    internal: Arc<InternalCa>,
    integration: OnceCell<IntegrationCa>,
}

fn issuing(error: &CaError) -> ClientCertError {
    match error {
        CaError::InvalidCsr { reason } => ClientCertError::InvalidRequest {
            reason: reason.clone(),
        },
        other => ClientCertError::Issuing {
            reason: other.to_string(),
        },
    }
}

impl CaIssuer {
    /// The issuer over the store and the vault, with the internal root of the integration
    /// listener's server certificate.
    pub fn new(store: Arc<dyn Store>, vault: Arc<dyn Vault>, internal: Arc<InternalCa>) -> Self {
        Self {
            store,
            vault,
            internal,
            integration: OnceCell::new(),
        }
    }

    /// The integration root, when the integration CA exists; it is not created here.
    pub async fn integration_root(
        &self,
        ctx: &RequestCtx,
    ) -> Option<rustls::pki_types::CertificateDer<'static>> {
        if let Some(ca) = self.integration.get() {
            return Some(ca.root_der().clone());
        }
        match IntegrationCa::load(self.store.as_ref(), self.vault.as_ref(), ctx).await {
            Ok(Some(ca)) => {
                let root = ca.root_der().clone();
                let _ = self.integration.set(ca);
                Some(root)
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, "the integration CA cannot be loaded");
                None
            }
        }
    }

    async fn ca(&self, ctx: &RequestCtx) -> Result<&IntegrationCa, ClientCertError> {
        self.integration
            .get_or_try_init(|| async {
                IntegrationCa::load_or_init(self.store.as_ref(), self.vault.as_ref(), ctx).await
            })
            .await
            .map_err(|error| issuing(&error))
    }
}

#[async_trait]
impl Issuer for CaIssuer {
    fn request_key(&self, csr: &[u8]) -> Result<Vec<u8>, ClientCertError> {
        integration_request_key(csr).map_err(|error| issuing(&error))
    }

    async fn ensure_root(&self, ctx: &RequestCtx) -> Result<(), ClientCertError> {
        self.ca(ctx).await.map(|_| ())
    }

    async fn issue(
        &self,
        ctx: &RequestCtx,
        account: UserId,
        csr: &[u8],
        days: u32,
    ) -> Result<Issued, ClientCertError> {
        let issued = self
            .ca(ctx)
            .await?
            .issue(account, csr, ctx.now, days)
            .map_err(|error| issuing(&error))?;
        let identity = &issued.identity;
        Ok(Issued {
            pem: issued.chain_pem(),
            serial: identity.serial.clone(),
            key_sha256: identity.key_sha256.clone(),
            not_before: Timestamp(identity.not_before.0),
            not_after: Timestamp(identity.not_after.0),
        })
    }

    fn server_root_sha256(&self) -> String {
        self.internal.root_info().sha256.clone()
    }

    fn server_root_pem(&self) -> String {
        self.internal.root_pem()
    }
}

type Service = Option<Extension<Arc<ClientCerts>>>;

fn service_or_stub(
    service: Service,
    method: &str,
    path: &str,
) -> Result<Arc<ClientCerts>, ApiError> {
    service
        .map(|Extension(service)| service)
        .ok_or_else(|| not_implemented(method, path))
}

fn failed(error: &ClientCertError) -> ApiError {
    ApiError::from_coded_error(CodedError::from_coded(error))
}

fn administer(app: &AppState, principal: &Principal) -> Result<(), ApiError> {
    app.authorize(
        principal,
        Action::Administer,
        &ObjectRef::singleton(ObjectKind::User),
    )
}

fn refusal(code: &'static str, status: u16, detail: &str) -> ApiError {
    ApiError::from_coded_error(CodedError::new(code, status, detail))
}

/// What an enrollment request says before anything is checked against the store: the code
/// id and the proof from their headers, and the request body. The fuzz target
/// `integration_enroll` calls this.
///
/// # Errors
///
/// 401 `integration.code.invalid` for a missing or malformed code id or proof, 415 for
/// another media type, 422 `integration.request.invalid` for an empty or oversized body.
pub fn read_enroll_request(headers: &HeaderMap, body: &[u8]) -> Result<(Uuid, Vec<u8>), ApiError> {
    read_request_body(headers, body)?;
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let invalid = || {
        refusal(
            "integration.code.invalid",
            401,
            "the enrollment code or its proof is not valid",
        )
    };
    let code = header(CODE_HEADER)
        .and_then(|value| value.trim().parse::<Uuid>().ok())
        .ok_or_else(invalid)?;
    let proof = header(PROOF_HEADER)
        .map(str::trim)
        .filter(|value| value.len() == 64)
        .and_then(|value| tenko_auth::encoding::hex_decode(value).ok())
        .ok_or_else(invalid)?;
    Ok((code, proof))
}

/// The media type and size of a request body that carries a PKCS#10 request, as enrollment
/// and renewal read it.
fn read_request_body(headers: &HeaderMap, body: &[u8]) -> Result<(), ApiError> {
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media.is_some_and(|media| media.eq_ignore_ascii_case(PKCS10)) {
        return Err(refusal(
            "integration.request.media_type",
            415,
            "the body must be a PKCS#10 request (application/pkcs10, DER)",
        ));
    }
    if body.is_empty() || body.len() > MAX_REQUEST {
        return Err(refusal(
            "integration.request.invalid",
            422,
            "the body must be one PKCS#10 request of at most 16 KiB",
        ));
    }
    Ok(())
}

/// Creates a single-use enrollment code for a service account, shown once in this answer.
/// The code carries the fingerprint of the root the integration listener's certificate
/// chains to; the controller keeps the code's secret in the vault until the code is used,
/// withdrawn or expired.
#[utoipa::path(
    post,
    path = "/integrations/enrollments",
    tag = "access",
    operation_id = "create_integration_code",
    summary = "Create an enrollment code for an integration",
    request_body(content = NewCode, content_type = "application/json"),
    responses(
        (status = 201, description = "The code, shown once (`Cache-Control: no-store`)", body = CreatedCode),
        (status = 400, description = "The body is not valid JSON (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator, no sign-in in the last five minutes (`auth.step_up_required`), or the account is not an enabled service account (`integration.account`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A lifetime outside 60 to 3600 seconds (`integration.code.lifetime`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn create_integration_code(
    axum::extract::State(app): axum::extract::State<AppState>,
    Ctx(cx): Ctx,
    service: Service,
    auth: Option<Extension<Arc<tenko_auth::AuthService>>>,
    ApiJson(request): ApiJson<NewCode>,
) -> Result<Response, ApiError> {
    let service = service_or_stub(service, "POST", "/integrations/enrollments")?;
    app.authorize(
        &cx.principal,
        Action::Administer,
        &ObjectRef::from(request.account),
    )?;
    // The code outlives the session that makes it: only a fresh interactive sign-in makes
    // one, never a token. Without the authentication service nothing can check that.
    let Some(Extension(auth)) = &auth else {
        return Err(not_implemented("POST", "/integrations/enrollments"));
    };
    let Principal::User { id: creator, .. } = cx.principal else {
        return Err(ApiError::from_coded_error(
            CodedError::new(
                "auth.step_up_required",
                403,
                "an enrollment code needs an interactive sign-in within the last five minutes; a token cannot create one",
            )
            .with_param("required", "fresh"),
        ));
    };
    auth.require_fresh_session(&cx)
        .await
        .map_err(|error| ApiError::from_coded_error(CodedError::from_coded(&error)))?;
    let created = service
        .create_code(&cx, creator, &request)
        .await
        .map_err(|error| failed(&error))?;
    let mut response = (StatusCode::CREATED, Json(created)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Lists the enrollment codes, newest first: waiting, used, withdrawn and expired ones for
/// seven days. Never a secret.
#[utoipa::path(
    get,
    path = "/integrations/enrollments",
    tag = "access",
    operation_id = "list_integration_codes",
    summary = "List enrollment codes of integrations",
    responses(
        (status = 200, description = "Every code, newest first", body = CodeList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_integration_codes(
    axum::extract::State(app): axum::extract::State<AppState>,
    Ctx(cx): Ctx,
    service: Service,
) -> Result<Json<CodeList>, ApiError> {
    let service = service_or_stub(service, "GET", "/integrations/enrollments")?;
    administer(&app, &cx.principal)?;
    let items = service
        .list_codes(cx.now)
        .await
        .map_err(|error| failed(&error))?;
    Ok(Json(CodeList { items }))
}

/// Withdraws an enrollment code: a waiting code can no longer be used.
#[utoipa::path(
    delete,
    path = "/integrations/enrollments/{id}",
    tag = "access",
    operation_id = "withdraw_integration_code",
    summary = "Withdraw an enrollment code",
    params(("id" = Uuid, Path, description = "Code id")),
    responses(
        (status = 204, description = "Withdrawn"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such code (`integration.not_found`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn withdraw_integration_code(
    axum::extract::State(app): axum::extract::State<AppState>,
    Ctx(cx): Ctx,
    service: Service,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let service = service_or_stub(service, "DELETE", "/integrations/enrollments/{id}")?;
    administer(&app, &cx.principal)?;
    service
        .withdraw_code(&cx, id)
        .await
        .map_err(|error| failed(&error))?;
    Ok(StatusCode::NO_CONTENT)
}

/// The internal root in PEM: the root the integration listener's server certificate chains
/// to, in every TLS mode of the API listener. Public data; the integrator compares its
/// SHA-256 with the fingerprint the enrollment code carries before trusting it.
#[utoipa::path(
    get,
    path = "/integrations/ca",
    tag = "access",
    operation_id = "integration_server_root",
    summary = "The root of the integration listener",
    responses(
        (status = 200, description = "The internal root, PEM", body = String, content_type = "application/x-pem-file")
    ),
    security()
)]
async fn integration_server_root(service: Service) -> Result<Response, ApiError> {
    let service = service_or_stub(service, "GET", "/integrations/ca")?;
    let mut response = service.server_root_pem().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    Ok(response)
}

/// Enrolls an integration: the body is a PKCS#10 request over a key the integrator made, the
/// headers name the code and carry the HMAC of the code's secret over the account and the
/// key. The answer is the certificate; the code is used up.
#[utoipa::path(
    post,
    path = "/integrations/enroll",
    tag = "access",
    operation_id = "enroll_integration",
    summary = "Enroll an integration with a code",
    params(
        EnrollQuery,
        ("tenko-enrollment-code" = Uuid, Header, description = "The code id"),
        ("tenko-enrollment-proof" = String, Header, description = "HMAC-SHA-256 with the code's secret over the code id, the account id and the request's key, hexadecimal")
    ),
    request_body(content = Vec<u8>, content_type = "application/pkcs10"),
    responses(
        (status = 201, description = "The certificate (`Cache-Control: no-store`)", body = String, content_type = "application/pem-certificate-chain"),
        (status = 401, description = "The code or its proof is not valid (`integration.code.invalid`), was used (`integration.code.used`) or expired (`integration.code.expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The code may not be used from this address (`integration.code.source`), the request came over plain HTTP or through a proxy that did not state the scheme outside the Lab profile (`integration.enroll.transport`; over plain HTTP the code is withdrawn), or the account cannot hold certificates (`integration.account`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The key was enrolled before (`integration.key.used`) or the account holds eight lineages (`integration.lineages`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not `application/pkcs10` (`integration.request.media_type`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The request is not usable (`integration.request.invalid`) or the label is not (`integration.label`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn enroll_integration(
    axum::extract::State(app): axum::extract::State<AppState>,
    PublicCtx { ctx, .. }: PublicCtx,
    client: Option<Extension<ClientInfo>>,
    unstated: Option<Extension<UnstatedScheme>>,
    service: Service,
    Query(query): Query<EnrollQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let service = service_or_stub(service, "POST", "/integrations/enroll")?;
    let (code, proof) = read_enroll_request(&headers, &body)?;
    let client = client.as_ref().map(|Extension(client)| client);
    let plain = client.is_some_and(|client| client.peer.is_some() && !client.https);
    let silent = client.is_some_and(|client| client.peer.is_some()) && unstated.is_some();
    if (plain || silent) && profile(&app).await? != Profile::Lab {
        let error = if plain {
            service
                .refuse_plain_http(
                    &ctx,
                    code,
                    "the request came over plain HTTP; the code is withdrawn",
                )
                .await
        } else {
            ClientCertError::Transport(
                "the request came through a proxy that did not state the scheme",
            )
        };
        return Err(failed(&error));
    }
    let pem = service
        .enroll(
            &ctx,
            EnrollInput {
                code,
                proof,
                csr: body.to_vec(),
                label: query.label,
                source: client.and_then(|client| client.source_ip),
            },
        )
        .await
        .map_err(|error| failed(&error))?;
    let mut response = (StatusCode::CREATED, pem).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PEM_CHAIN));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Renews the certificate the connection presented, on the integration listener only and
/// with that certificate alone: the body is a PKCS#10 request over a new key, or over the
/// same key when a TPM holds it. Not due yet (before the last third of the lifetime), the
/// answer is 200 with the time it will be; renewed, it is 201 with the new certificate,
/// which takes over at its first presentation. A renewal from a certificate the lineage has
/// already replaced revokes the lineage.
#[utoipa::path(
    post,
    path = "/integrations/certificate/renew",
    tag = "access",
    operation_id = "renew_integration_certificate",
    summary = "Renew an integration certificate",
    request_body(content = Vec<u8>, content_type = "application/pkcs10"),
    responses(
        (status = 200, description = "Not due yet", body = RenewalNotDue),
        (status = 201, description = "The new certificate (`Cache-Control: no-store`)", body = String, content_type = "application/pem-certificate-chain"),
        (status = 401, description = "The certificate is no longer accepted (`integration.certificate.refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not on the integration listener (`integration.certificate.required`), or a renewal from a replaced certificate (`integration.renew.reuse`; the lineage is revoked)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The lineage renewed within the hour (`integration.renew.too_soon`) or the key was enrolled for another lineage (`integration.key.used`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 415, description = "The body is not `application/pkcs10` (`integration.request.media_type`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The request is not usable (`integration.request.invalid`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security()
)]
async fn renew_integration_certificate(
    PublicCtx { ctx, .. }: PublicCtx,
    connection: Option<Extension<ConnInfo>>,
    service: Service,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let service = service_or_stub(service, "POST", RENEW_PATH)?;
    let Some(client) = connection.and_then(|Extension(connection)| connection.client) else {
        return Err(refusal(
            "integration.certificate.required",
            403,
            "a renewal is served on the integration listener, to the certificate it renews",
        ));
    };
    read_request_body(&headers, &body)?;
    match service
        .renew(&ctx, &client.serial, client.account, &body)
        .await
        .map_err(|error| failed(&error))?
    {
        Renewal::NotDue { renew_after } => Ok(Json(RenewalNotDue {
            not_due: true,
            renew_after,
        })
        .into_response()),
        Renewal::Renewed { pem, .. } => {
            let mut response = (StatusCode::CREATED, pem).into_response();
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PEM_CHAIN));
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(response)
        }
    }
}

/// One pass of the integration alarms: removes the tokens of lapsed lineages, and sets or
/// clears the status conditions [`TLS12_NOTICE`] (while TGL-47 allows TLS 1.2) and
/// [`EXPIRING_NOTICE`] (while a lineage is in the last sixth of its lifetime without having
/// renewed).
pub async fn refresh_integration_notices(certs: &ClientCerts, state: &AppState) {
    // A lapsed lineage's tokens are removed, never moved (ADR 0035, decision 7);
    // another node's sweep of the same tokens ends in a conflict, harmless.
    if let Err(error) = certs.remove_lapsed_tokens(Timestamp::now()).await {
        tracing::debug!(%error, "lapsed bound tokens left for the next sweep");
    }
    if certs.index().policy().allow_tls12 {
        state.set_notice(crate::dto::system::StatusWarning {
            code: TLS12_NOTICE.to_owned(),
            detail: "the integration listener accepts TLS 1.2 (TGL-47), under which client certificates are visible on the network path; turn it off once no host needs it".to_owned(),
            params: std::collections::BTreeMap::new(),
        });
    } else {
        state.clear_notice(TLS12_NOTICE);
    }
    let expiring = certs.index().expiring(Timestamp::now());
    match expiring.first() {
        None => state.clear_notice(EXPIRING_NOTICE),
        Some(first) => state.set_notice(crate::dto::system::StatusWarning {
            code: EXPIRING_NOTICE.to_owned(),
            detail: format!(
                "{} integration certificate(s) have not renewed and expire soon, the first ({}) on {}; check the renewal timer of the automation host",
                expiring.len(),
                first.label,
                first.not_after.to_rfc3339()
            ),
            params: [
                ("count".to_owned(), expiring.len().to_string()),
                ("label".to_owned(), first.label.clone()),
                ("not_after".to_owned(), first.not_after.to_rfc3339()),
            ]
            .into_iter()
            .collect(),
        }),
    }
}

/// Runs [`refresh_integration_notices`] after every change of the records or the settings
/// and every hour, until `stop` turns true.
pub fn spawn_expiry_alarm(
    certs: Arc<ClientCerts>,
    state: AppState,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut changes = certs.index().subscribe();
        loop {
            refresh_integration_notices(&certs, &state).await;
            tokio::select! {
                followed = changes.changed() => if followed.is_err() { return },
                () = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {}
                _ = stop.changed() => return,
            }
        }
    })
}

/// The stored security profile; Standard when none is stored, so that a missing record
/// never allows plain HTTP.
async fn profile(app: &AppState) -> Result<Profile, ApiError> {
    use tenko_store::{ReadConsistency, ReadViewExt as _};
    let view = app.store.read(ReadConsistency::Local).await?;
    Ok(view
        .get_typed(&tenko_auth::model::SETTINGS, &())?
        .map_or(Profile::Standard, |(settings, _)| settings.profile))
}

/// Lists the integration certificates, of one service account or of all, by serial.
#[utoipa::path(
    get,
    path = "/integrations/certificates",
    tag = "access",
    operation_id = "list_integration_certificates",
    summary = "List integration certificates",
    params(CertificateQuery),
    responses(
        (status = 200, description = "The certificates by serial", body = CertificateList),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_integration_certificates(
    axum::extract::State(app): axum::extract::State<AppState>,
    Ctx(cx): Ctx,
    service: Service,
    Query(query): Query<CertificateQuery>,
) -> Result<Json<CertificateList>, ApiError> {
    let service = service_or_stub(service, "GET", "/integrations/certificates")?;
    administer(&app, &cx.principal)?;
    let items = service
        .list(query.account)
        .await
        .map_err(|error| failed(&error))?;
    Ok(Json(CertificateList { items }))
}

/// Revokes the lineage of a certificate: it and every renewal of it stop at once on every
/// controller, and its key never enrolls again.
#[utoipa::path(
    delete,
    path = "/integrations/certificates/{serial}",
    tag = "access",
    operation_id = "revoke_integration_certificate",
    summary = "Revoke an integration certificate and its lineage",
    params(("serial" = String, Path, description = "Serial, lower-case hexadecimal")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such certificate (`integration.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The lineage changed meanwhile (`integration.conflict`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revoke_integration_certificate(
    axum::extract::State(app): axum::extract::State<AppState>,
    Ctx(cx): Ctx,
    service: Service,
    Path(serial): Path<String>,
) -> Result<StatusCode, ApiError> {
    let service = service_or_stub(service, "DELETE", "/integrations/certificates/{serial}")?;
    administer(&app, &cx.principal)?;
    service
        .revoke(&cx, &serial, "revoked by an administrator")
        .await
        .map_err(|error| failed(&error))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::Request,
    };
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tenko_auth::{
        client_cert::{
            CODE_PREFIX, enrollment_proof,
            model::{CertState, CodeState},
        },
        model::{USERS, UserKind, UserRecord},
    };
    use tenko_cluster::ca::{CaPolicy, IntegrationIdentity, generate_csr};
    use tenko_core::SystemComponent;
    use tenko_store::{MemStore, WriteBatch};
    use tenko_vault::MemVault;
    use tower::ServiceExt;

    use super::*;
    use crate::{API_BASE, problem::PROBLEM_JSON, server::forwarded::IntegrationClient};

    struct Env {
        router: Router,
        store: Arc<dyn Store>,
        service: Arc<ClientCerts>,
        internal: Arc<InternalCa>,
        account: UserId,
    }

    async fn env(profile: Profile) -> Env {
        let store = Arc::new(MemStore::default());
        let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(store.clone()));
        let ctx = RequestCtx::system(SystemComponent::Api);
        let internal = Arc::new(
            InternalCa::load_or_init(&*store, vault.as_ref(), &ctx, CaPolicy::default())
                .await
                .expect("CA"),
        );
        let mut user = UserRecord::new(
            "backup".to_owned(),
            "Backup job".to_owned(),
            Vec::new(),
            ctx.now,
        );
        user.kind = UserKind::Service;
        let mut batch = WriteBatch::for_request(&ctx);
        batch.put_typed(&USERS, &user.id, &user).expect("user");
        batch
            .put_typed(&tenko_auth::model::SETTINGS, &(), &profile.defaults())
            .expect("settings");
        store.propose(batch).await.expect("stored");
        let store: Arc<dyn Store> = store;
        let issuer = Arc::new(CaIssuer::new(
            Arc::clone(&store),
            Arc::clone(&vault),
            Arc::clone(&internal),
        ));
        let service = Arc::new(ClientCerts::new(Arc::clone(&store), vault, issuer));
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let router = router
            .with_state(AppState::new(Arc::clone(&store)))
            .layer(Extension(Arc::clone(&service)));
        Env {
            router,
            store,
            service,
            internal,
            account: user.id,
        }
    }

    /// A code, and a request over a fresh key with its proof.
    struct Enrollment {
        code: Uuid,
        proof: String,
        csr: Vec<u8>,
    }

    impl Env {
        async fn enrollment(&self) -> Enrollment {
            let created = self
                .service
                .create_code(
                    &RequestCtx::system(SystemComponent::Api),
                    UserId::generate(),
                    &NewCode {
                        account: self.account,
                        lifetime_secs: None,
                        source: None,
                    },
                )
                .await
                .expect("code");
            let parts: Vec<&str> = created.code.split('.').collect();
            assert_eq!(parts[0], CODE_PREFIX);
            assert_eq!(parts[4], self.internal.root_info().sha256);
            let secret = tenko_auth::encoding::hex_decode(parts[3]).expect("secret");
            let code: Uuid = parts[1].parse().expect("id");
            let (_, csr) = generate_csr().expect("csr");
            let spki = integration_request_key(&csr).expect("key");
            let proof = enrollment_proof(&secret, code, self.account, &spki);
            Enrollment {
                code,
                proof: tenko_auth::encoding::hex_encode(&proof),
                csr,
            }
        }

        async fn code_state(&self, code: Uuid) -> CodeState {
            self.service
                .list_codes(Timestamp::now())
                .await
                .expect("list")
                .into_iter()
                .find(|view| view.id == code)
                .expect("listed")
                .state
        }
    }

    struct Reply {
        status: StatusCode,
        media: Option<String>,
        body: Vec<u8>,
    }

    impl Reply {
        fn problem(&self) -> String {
            assert_eq!(self.media.as_deref(), Some(PROBLEM_JSON));
            let body: serde_json::Value = serde_json::from_slice(&self.body).expect("JSON");
            body["code"].as_str().expect("code").to_owned()
        }
    }

    async fn send(router: &Router, request: Request<Body>) -> Reply {
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let media = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        Reply {
            status,
            media,
            body,
        }
    }

    /// `POST /integrations/enroll` from a peer, over HTTPS or plain HTTP, through a proxy that
    /// did or did not state the scheme.
    fn enroll_request(
        enrollment: &Enrollment,
        media: &str,
        https: bool,
        unstated: bool,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE}/integrations/enroll?label=backup-host"))
            .header(header::CONTENT_TYPE, media)
            .header(CODE_HEADER, enrollment.code.to_string())
            .header(PROOF_HEADER, enrollment.proof.clone())
            .body(Body::from(enrollment.csr.clone()))
            .expect("request");
        request.extensions_mut().insert(ClientInfo {
            source_ip: Some("192.0.2.21".parse().expect("address")),
            peer: Some("192.0.2.21:40000".parse().expect("peer")),
            https,
            host: None,
            via_proxy: unstated,
        });
        if unstated {
            request.extensions_mut().insert(UnstatedScheme);
        }
        request
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("{API_BASE}{path}"))
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn an_integration_enrolls_is_listed_and_revoked() {
        let env = env(Profile::Standard).await;
        let root = send(&env.router, get("/integrations/ca")).await;
        assert_eq!(root.status, StatusCode::OK);
        assert_eq!(
            String::from_utf8(root.body).expect("PEM"),
            env.internal.root_pem()
        );

        let enrollment = env.enrollment().await;
        let reply = send(
            &env.router,
            enroll_request(&enrollment, PKCS10, true, false),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        assert_eq!(reply.media.as_deref(), Some(PEM_CHAIN));
        let cert = CertificateDer::from_pem_slice(&reply.body).expect("one certificate");
        let identity = IntegrationIdentity::from_der(&cert).expect("an integration certificate");
        assert_eq!(identity.account, env.account);
        assert!(matches!(
            env.code_state(enrollment.code).await,
            CodeState::Used { .. }
        ));

        let listed = send(&env.router, get("/integrations/certificates")).await;
        let listed: CertificateList = serde_json::from_slice(&listed.body).expect("list");
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].serial, identity.serial);
        assert_eq!(listed.items[0].key_sha256, identity.key_sha256);

        let revoke = Request::builder()
            .method("DELETE")
            .uri(format!(
                "{API_BASE}/integrations/certificates/{}",
                identity.serial
            ))
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            send(&env.router, revoke).await.status,
            StatusCode::NO_CONTENT
        );
        let records = env.service.list(None).await.expect("list");
        assert_eq!(records[0].state, CertState::Revoked);
    }

    #[tokio::test]
    async fn plain_http_is_refused_outside_lab_and_withdraws_the_code() {
        for profile in [Profile::Home, Profile::Standard, Profile::Hardened] {
            let env = env(profile).await;
            let enrollment = env.enrollment().await;
            let reply = send(
                &env.router,
                enroll_request(&enrollment, PKCS10, false, false),
            )
            .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{profile:?}");
            assert_eq!(reply.problem(), "integration.enroll.transport");
            assert_eq!(env.code_state(enrollment.code).await, CodeState::Withdrawn);
        }
        let env = env(Profile::Lab).await;
        let enrollment = env.enrollment().await;
        let reply = send(
            &env.router,
            enroll_request(&enrollment, PKCS10, false, false),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_proxy_that_does_not_state_the_scheme_is_refused_and_the_code_kept() {
        let env = env(Profile::Standard).await;
        let enrollment = env.enrollment().await;
        let reply = send(&env.router, enroll_request(&enrollment, PKCS10, true, true)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.problem(), "integration.enroll.transport");
        assert_eq!(env.code_state(enrollment.code).await, CodeState::Pending);
    }

    #[tokio::test]
    async fn malformed_requests_are_refused_and_leave_the_code() {
        let env = env(Profile::Standard).await;
        let enrollment = env.enrollment().await;
        let wrong_media = send(
            &env.router,
            enroll_request(&enrollment, "application/json", true, false),
        )
        .await;
        assert_eq!(wrong_media.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(wrong_media.problem(), "integration.request.media_type");

        for (name, proof) in [
            ("no proof", None),
            ("a short proof", Some("00".to_owned())),
            ("another proof", Some("ab".repeat(32))),
        ] {
            let mut request = enroll_request(&enrollment, PKCS10, true, false);
            request.headers_mut().remove(PROOF_HEADER);
            if let Some(proof) = proof {
                request
                    .headers_mut()
                    .insert(PROOF_HEADER, HeaderValue::from_str(&proof).expect("header"));
            }
            let reply = send(&env.router, request).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{name}");
            assert_eq!(reply.problem(), "integration.code.invalid", "{name}");
        }
        // The code header carries the code's id alone; the whole code, secret included, is
        // not an id and is refused.
        let mut whole = enroll_request(&enrollment, PKCS10, true, false);
        whole.headers_mut().insert(
            CODE_HEADER,
            HeaderValue::from_str(&format!(
                "{CODE_PREFIX}.{}.{}.{}.{}",
                enrollment.code,
                env.account,
                "ab".repeat(32),
                "cd".repeat(32)
            ))
            .expect("header"),
        );
        let reply = send(&env.router, whole).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.problem(), "integration.code.invalid");
        let empty = Enrollment {
            code: enrollment.code,
            proof: enrollment.proof.clone(),
            csr: Vec::new(),
        };
        let reply = send(&env.router, enroll_request(&empty, PKCS10, true, false)).await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(env.code_state(enrollment.code).await, CodeState::Pending);
    }

    /// `POST /integrations/certificate/renew` with `csr`, from the connection of `client`
    /// when given (the integration listener), else from the API listener.
    fn renew_request(client: Option<IntegrationClient>, csr: Vec<u8>) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE}{RENEW_PATH}"))
            .header(header::CONTENT_TYPE, PKCS10)
            .body(Body::from(csr))
            .expect("request");
        if let Some(client) = client {
            request.extensions_mut().insert(ConnInfo {
                peer: "192.0.2.21:40000".parse().expect("peer"),
                tls: true,
                mode: Arc::new(tenko_cluster::ca::TlsMode::InternalCa),
                trusted: false,
                proxy: None,
                client: Some(Arc::new(client)),
            });
        }
        request
    }

    #[tokio::test]
    async fn a_renewal_is_served_to_the_certificate_on_the_integration_listener_only() {
        let env = env(Profile::Standard).await;
        let enrollment = env.enrollment().await;
        let reply = send(
            &env.router,
            enroll_request(&enrollment, PKCS10, true, false),
        )
        .await;
        let cert = CertificateDer::from_pem_slice(&reply.body).expect("certificate");
        let identity = IntegrationIdentity::from_der(&cert).expect("identity");
        let (_, csr) = generate_csr().expect("csr");

        let reply = send(&env.router, renew_request(None, csr.clone())).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.problem(), "integration.certificate.required");

        let client = IntegrationClient {
            serial: identity.serial.clone(),
            account: identity.account,
        };
        let reply = send(&env.router, renew_request(Some(client.clone()), csr)).await;
        assert_eq!(reply.status, StatusCode::OK, "a new certificate is not due");
        let body: RenewalNotDue = serde_json::from_slice(&reply.body).expect("JSON");
        assert!(body.not_due);
        assert!(body.renew_after.0 > identity.not_before.0);

        let reply = send(&env.router, renew_request(Some(client), Vec::new())).await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn without_the_service_every_route_is_a_stub() {
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        let router = router.with_state(AppState::new(Arc::new(MemStore::default())));
        for path in [
            "/integrations/ca",
            "/integrations/enrollments",
            "/integrations/certificates",
        ] {
            let reply = send(&router, get(path)).await;
            assert_eq!(reply.status, StatusCode::NOT_IMPLEMENTED, "{path}");
        }
    }

    #[tokio::test]
    async fn tls_1_2_raises_its_health_warning_while_allowed() {
        let env = env(Profile::Home).await;
        let state = AppState::new(Arc::clone(&env.store));
        let allow = |allow_tls12| {
            let mut settings = Profile::Home.defaults();
            settings.integrations = Some(tenko_auth::client_cert::model::IntegrationPolicy {
                allow_tls12,
                ..tenko_auth::client_cert::model::IntegrationPolicy::of(Profile::Home)
            });
            settings
        };
        let codes = |state: &AppState| -> Vec<String> {
            state
                .notices_list()
                .into_iter()
                .map(|notice| notice.code)
                .collect()
        };
        for (allowed, expected) in [(true, vec![TLS12_NOTICE.to_owned()]), (false, Vec::new())] {
            let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Api));
            batch
                .put_typed(&tenko_auth::model::SETTINGS, &(), &allow(allowed))
                .expect("settings");
            env.store.propose(batch).await.expect("stored");
            env.service
                .index()
                .load(env.store.as_ref())
                .await
                .expect("load");
            refresh_integration_notices(&env.service, &state).await;
            assert_eq!(codes(&state), expected, "allowed: {allowed}");
        }
    }
}
