//! The Kerberos account of secure dynamic updates and the owners of names (identity plan
//! sections 3.1, 3.6 and 4.3; WP13.0 declares the routes, WP13.3 builds the account
//! routes on the controller's account service, WP13.4 the owner view).
//!
//! Area: dns. Owner: WP13.0 (the contracts). Requirements: DNS-28, OPS-11.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them. Each checks the
//! caller's scope (and the interactive session where the table says so, which the
//! authorizer enforces by refusing a token) and then answers `501` with
//! `sys.not_implemented` until its package replaces it. The account is key material: its
//! routes authorize on `dns_key` (the scope `dns.keys`, an interactive session for every
//! change, like TSIG keys); the owners of a zone's names are read with the zone.
//!
//! | Endpoint | Scope | Purpose |
//! |---|---|---|
//! | `GET /dns/kerberos` | `dns.keys` | The account's status: key versions, SPNs, the last rotation and self-test, the findings, the contexts |
//! | `POST /dns/kerberos/adopt` | `dns.keys`, interactive | Take over a pre-staged computer account with its one-time password |
//! | `POST /dns/kerberos/import` | `dns.keys`, interactive | Import a keytab |
//! | `POST /dns/kerberos/check` | `dns.keys` | Run the self-test now |
//! | `POST /dns/kerberos/rotate` | `dns.keys`, interactive | Rotate the account's password now |
//! | `DELETE /dns/kerberos` | `dns.keys`, interactive | Delete the account and its keys from Tenko |
//! | `GET /dns/zones/{id}/owners` | `dns.read` | List the owners of the zone's names (paged) |
//!
//! The one-time password and the keytab arrive in the request body once and are never
//! stored: the adopt changes the password to one only Tenko knows and derives the keys
//! (ID-Q4), the import keeps the AES entries for the principal and not the file. Neither
//! the password nor a key ever appears in an answer or an audit record.

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tenko_auth::{authz::anywhere, service::SecretString};
use tenko_core::{
    Action, ObjectKind, ObjectRef, Timestamp,
    dns::{DnsName, KrbAccount, PrincipalName, Realm, ScopeName, Sid, ZoneId},
};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{DnsJobStarted, parse_id};
use crate::{
    dto::Page,
    extract::Ctx,
    list::PageParams,
    problem::{ApiError, ProblemDetails},
    routes::{auth::ApiJson, not_implemented},
    state::AppState,
};

/// The routes of the Kerberos account and the owners.
#[inline(never)]
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_kerberos, delete_dns_kerberos))
        .routes(routes!(adopt_dns_kerberos))
        .routes(routes!(import_dns_kerberos))
        .routes(routes!(check_dns_kerberos))
        .routes(routes!(rotate_dns_kerberos))
        .routes(routes!(list_dns_zone_owners))
}

/// One finding of the self-test (identity plan section 3.10).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KerberosFinding {
    /// The finding (`dns.gss.clock_skew`, `dns.gss.kvno_unknown`, `dns.gss.spn_missing`,
    /// ...).
    pub code: String,
    /// What was seen (the skew measured, the version seen, the SPN), in English.
    pub detail: String,
    /// When it was found.
    pub at: Timestamp,
}

/// The GSS-TSIG contexts of this node (identity plan section 3.3).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GssContexts {
    /// Negotiations in flight.
    pub negotiating: u64,
    /// Established contexts.
    pub established: u64,
    /// Negotiations refused in the last hour.
    pub refused_last_hour: u64,
}

/// Body of `GET /dns/kerberos` and the answer of `POST /dns/kerberos/check`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KerberosStatus {
    /// The account, metadata only; absent until one is adopted or imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<KrbAccount>,
    /// The findings of the last self-test, empty when it passed.
    #[serde(default)]
    pub findings: Vec<KerberosFinding>,
    /// The contexts of this node.
    pub contexts: GssContexts,
}

/// Body of `POST /dns/kerberos/adopt`: the pre-staged account and its one-time password
/// (ID-Q4). Tenko changes the password at once; the one given is used once and forgotten.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KerberosAdopt {
    /// The realm (`CORP.EXAMPLE.TEST`; case does not matter).
    pub realm: Realm,
    /// The account name as the administrator created it (`TENKO-DNS$`).
    pub name: String,
    /// The one-time password set by `New-ADComputer`.
    pub password: SecretString,
    /// The service principal names the account holds (`DNS/<fqdn>` per node, `HTTP/<fqdn>`
    /// for web sign-in); the self-test checks them.
    pub spns: Vec<String>,
    /// The KDCs, `host` or `host:port`; empty: found through `_kerberos._tcp.<realm>`.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// Days between password rotations, 0 to 365; absent: 30 (TGL-32; 0 under Lab only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_days: Option<u16>,
}

/// Body of `POST /dns/kerberos/import`: a keytab made with `ktpass` or `msktutil`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KerberosImport {
    /// The realm.
    pub realm: Realm,
    /// The keytab file (MIT format version 2) in base64url without padding (RFC 4648
    /// section 5).
    pub keytab: SecretString,
    /// The service principal names the account holds.
    pub spns: Vec<String>,
    /// The KDCs; empty: found through `_kerberos._tcp.<realm>`.
    #[serde(default)]
    pub kdcs: Vec<String>,
}

/// Filters of `GET /dns/zones/{id}/owners`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct OwnerParams {
    /// The zone scope; `default` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeName>,
    /// Only the names at or below this name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<DnsName>,
    /// Only the names of this owner, by SID or principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// The owner of one name (identity plan section 3.6).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NameOwnerItem {
    /// The zone scope.
    pub scope: ScopeName,
    /// The name.
    pub name: DnsName,
    /// The owner's SID, when the ticket carried a PAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<Sid>,
    /// The owner's principal.
    pub principal: PrincipalName,
    /// Since when.
    pub since: Timestamp,
    /// Until when the owner is held after the name's last record went; absent while the
    /// name has records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<Timestamp>,
}

#[utoipa::path(
    get,
    path = "/dns/kerberos",
    tag = "dns",
    operation_id = "get_dns_kerberos",
    summary = "Get the Kerberos account of secure updates",
    description = "Scope: `dns.keys`. The account's metadata (realm, name, SPNs, key versions with their numbers and states, the last rotation and self-test), the findings of the last self-test and the contexts of this node. Never a key.",
    responses(
        (status = 200, description = "The status; `account` absent until one is set up", body = KerberosStatus),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_dns_kerberos(State(app): State<AppState>, Ctx(cx): Ctx) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("GET", "/dns/kerberos"))
}

#[utoipa::path(
    post,
    path = "/dns/kerberos/adopt",
    tag = "dns",
    operation_id = "adopt_dns_kerberos",
    summary = "Take over a pre-staged computer account",
    description = "Scope: `dns.keys`, in an interactive session. Tenko obtains a ticket for `kadmin/changepw` with the one-time password, changes the password to a random one only Tenko knows, derives the AES keys, learns the key version from a service ticket for its own SPN, stores the keys in the vault and forgets both passwords (ID-Q4). Audited as `dns.krb.account.adopt`; the self-test runs after it.",
    request_body(content = KerberosAdopt, content_type = "application/json"),
    responses(
        (status = 201, description = "The account is Tenko's; the status with its findings", body = KerberosStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the account settings are invalid (`dns.krb.account.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change the account", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An account exists already for the realm (`dns.krb.account.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The KDC refused the one-time password (`dns.krb.password.refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No KDC of the realm answered (`dns.krb.kdc.unreachable`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn adopt_dns_kerberos(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<KerberosAdopt>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/kerberos/adopt"))
}

#[utoipa::path(
    post,
    path = "/dns/kerberos/import",
    tag = "dns",
    operation_id = "import_dns_kerberos",
    summary = "Import a keytab",
    description = "Scope: `dns.keys`, in an interactive session. The AES entries for the principal are stored in the vault; RC4 and DES entries are refused; the file is not kept. The password stays the administrator's, so Tenko does not rotate it (ID-Q5). Audited as `dns.krb.account.import`.",
    request_body(content = KerberosImport, content_type = "application/json"),
    responses(
        (status = 201, description = "The keys are held; the status with its findings", body = KerberosStatus),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the account settings are invalid (`dns.krb.account.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to change the account", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An account exists already for the realm (`dns.krb.account.exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The keytab does not parse or holds no AES entry for the principal (`dns.krb.keytab.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn import_dns_kerberos(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<KerberosImport>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Create, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/kerberos/import"))
}

#[utoipa::path(
    post,
    path = "/dns/kerberos/check",
    tag = "dns",
    operation_id = "check_dns_kerberos",
    summary = "Run the self-test of the Kerberos account now",
    description = "Scope: `dns.keys`. An AS exchange as the account, a TGS exchange for each SPN and its acceptance by the node's own acceptor, the KDC's time against the node's, the encryption types, a duplicate-SPN check when an LDAP provider of the realm is configured (identity plan section 3.1). Audited as `dns.krb.account.check` on failure or change.",
    responses(
        (status = 200, description = "The status with the findings of this run", body = KerberosStatus),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No account is set up (`dns.krb.account.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "No KDC of the realm answered (`dns.krb.kdc.unreachable`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn check_dns_kerberos(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Execute,
        &anywhere(ObjectKind::DnsKey),
    )?;
    Err(not_implemented("POST", "/dns/kerberos/check"))
}

#[utoipa::path(
    post,
    path = "/dns/kerberos/rotate",
    tag = "dns",
    operation_id = "rotate_dns_kerberos",
    summary = "Rotate the password of the Kerberos account now",
    description = "Scope: `dns.keys`, in an interactive session. A job: the new keys are written as pending, the change-password request is sent, the new key version is read back, the keys move to current and the old ones to previous (ID-Q5). Only for an account Tenko owns. Audited as `dns.krb.account.rotate`.",
    responses(
        (status = 202, description = "The rotation job started", body = DnsJobStarted),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to rotate", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No account is set up (`dns.krb.account.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The account was imported, so its password is not Tenko's (`dns.krb.account.not_owned`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn rotate_dns_kerberos(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Update, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("POST", "/dns/kerberos/rotate"))
}

#[utoipa::path(
    delete,
    path = "/dns/kerberos",
    tag = "dns",
    operation_id = "delete_dns_kerberos",
    summary = "Delete the Kerberos account from Tenko",
    description = "Scope: `dns.keys`, in an interactive session. Removes the keys from the vault and the metadata; the zones with Kerberos settings fall back to their other lists. The account in the directory is the administrator's to delete. Audited as `dns.krb.account.delete`.",
    responses(
        (status = 204, description = "The account is gone"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.keys`, or a token tries to delete", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No account is set up (`dns.krb.account.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn delete_dns_kerberos(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Delete, &anywhere(ObjectKind::DnsKey))?;
    Err(not_implemented("DELETE", "/dns/kerberos"))
}

#[utoipa::path(
    get,
    path = "/dns/zones/{id}/owners",
    tag = "dns",
    operation_id = "list_dns_zone_owners",
    summary = "List the owners of a zone's names",
    description = "Scope: `dns.read`. One row per name with an owner (identity plan section 3.6): the SID when the ticket carried a PAC, the principal, since when, and the hold after the name's last record went. Empty for a zone without ownership.",
    params(("id" = String, Path, description = "Zone identifier (UUID)"), PageParams, OwnerParams),
    responses(
        (status = 200, description = "A page of owners by scope and name", body = Page<NameOwnerItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal lacks the scope `dns.read`", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The zone does not exist (`dns.zone.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_dns_zone_owners(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    Query(_page): Query<PageParams>,
    Query(_filters): Query<OwnerParams>,
) -> Result<Response, ApiError> {
    let zone: ZoneId = parse_id(&id)?;
    app.authorize(&cx.principal, Action::Read, &ObjectRef::from(zone))?;
    Err(not_implemented("GET", "/dns/zones/{id}/owners"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_auth::authz::anywhere;
    use tenko_core::{Action, Authorizer, ObjectKind, ObjectRef, dns::ZoneId};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::routes;
    use crate::{
        API_BASE,
        routes::tenancy::testkit::{Policy, Reply},
        state::AppState,
    };

    const ZONE: &str = "0190d1c2-0000-7000-8000-000000000001";
    const STUB: &str = "sys.not_implemented";

    fn router(policy: Arc<Policy>) -> Router {
        let state = AppState {
            authorizer: Some(policy as Arc<dyn Authorizer>),
            ..AppState::default()
        };
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
        let builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().expect("text").to_owned())
            .unwrap_or_default();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON")
        };
        Reply {
            status,
            content_type,
            etag: None,
            body,
        }
    }

    fn adopt() -> Value {
        json!({
            "realm": "corp.example.test",
            "name": "TENKO-DNS$",
            "password": "one-time",
            "spns": ["DNS/ns1.corp.example.test"]
        })
    }

    #[tokio::test]
    async fn every_route_checks_its_scope_then_answers_the_stub() {
        let policy = Policy::new(true, true);
        let router = router(Arc::clone(&policy));
        send(&router, "GET", "/dns/kerberos", None)
            .await
            .assert_problem(501, STUB);
        send(&router, "POST", "/dns/kerberos/adopt", Some(adopt()))
            .await
            .assert_problem(501, STUB);
        send(
            &router,
            "POST",
            "/dns/kerberos/import",
            Some(json!({ "realm": "CORP.EXAMPLE.TEST", "keytab": "BQI", "spns": ["DNS/ns1.corp.example.test"] })),
        )
        .await
        .assert_problem(501, STUB);
        send(&router, "POST", "/dns/kerberos/check", None)
            .await
            .assert_problem(501, STUB);
        send(&router, "POST", "/dns/kerberos/rotate", None)
            .await
            .assert_problem(501, STUB);
        send(&router, "DELETE", "/dns/kerberos", None)
            .await
            .assert_problem(501, STUB);
        send(&router, "GET", &format!("/dns/zones/{ZONE}/owners"), None)
            .await
            .assert_problem(501, STUB);
        let zone: ZoneId = ZONE.parse().expect("id");
        assert_eq!(
            policy.asked(),
            [
                (Action::Read, anywhere(ObjectKind::DnsKey)),
                (Action::Create, anywhere(ObjectKind::DnsKey)),
                (Action::Create, anywhere(ObjectKind::DnsKey)),
                (Action::Execute, anywhere(ObjectKind::DnsKey)),
                (Action::Update, anywhere(ObjectKind::DnsKey)),
                (Action::Delete, anywhere(ObjectKind::DnsKey)),
                (Action::Read, ObjectRef::from(zone)),
            ]
        );
    }

    #[tokio::test]
    async fn a_reader_is_refused_every_change_and_a_bad_body_or_path_answers_first() {
        let policy = Policy::new(true, false);
        let router = router(Arc::clone(&policy));
        send(&router, "GET", "/dns/kerberos", None)
            .await
            .assert_problem(501, STUB);
        send(&router, "POST", "/dns/kerberos/adopt", Some(adopt()))
            .await
            .assert_problem(403, "auth.forbidden");
        send(&router, "POST", "/dns/kerberos/rotate", None)
            .await
            .assert_problem(403, "auth.forbidden");
        send(&router, "DELETE", "/dns/kerberos", None)
            .await
            .assert_problem(403, "auth.forbidden");
        // A realm that is not one, and a zone that is not a UUID: refused before the check.
        let reply = send(
            &router,
            "POST",
            "/dns/kerberos/adopt",
            Some(json!({ "realm": "a@b", "name": "X$", "password": "p", "spns": [] })),
        )
        .await;
        assert_eq!(reply.status.as_u16(), 400, "{}", reply.body);
        send(&router, "GET", "/dns/zones/not-a-uuid/owners", None)
            .await
            .assert_problem(400, "sys.invalid_request");
        assert_eq!(policy.asked().len(), 4, "{:?}", policy.asked());
    }
}
