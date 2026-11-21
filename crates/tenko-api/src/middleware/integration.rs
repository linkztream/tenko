//! The checks of a request that arrived on the integration listener (ADR 0035, decision 3).
//! The certificate is checked before authentication ([`certificate`]), so a request it refuses
//! never records the use of a token nor supersedes one; the token's owner after it
//! ([`owner`]). A request of the API listener has no integration certificate and passes
//! untouched.
//!
//! - The connection's certificate must still pass: its record is asked again at every
//!   request, so a revocation, a replacement past its overlap, an expiry or an end of the
//!   account ends a long-lived connection at its next request.
//! - A controller cut off from its quorum for more than [`ISOLATION_LIMIT`] answers nothing
//!   here: it cannot know of a revocation made elsewhere.
//! - No public operation is served here.
//! - The request must be authenticated by a token of the account the certificate names.

use std::sync::Arc;

use axum::{
    extract::Request,
    response::{IntoResponse as _, Response},
};
use tenko_auth::client_cert::{Acceptance, ClientCerts};
use tenko_core::{Principal, Timestamp};

use crate::{extract::AuthOutcome, problem::ApiError, server::forwarded::ConnInfo};

/// How long a controller without quorum contact keeps answering on the integration listener.
pub const ISOLATION_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

fn refuse(code: &'static str, status: u16, detail: &str) -> Response {
    ApiError::new(code, status, detail).into_response()
}

/// The refusal of a request on the integration listener by its certificate, or `None`; it
/// runs before authentication. `public` says whether the operation can be called without
/// credentials, `renewal` whether it is the renewal of the connection's certificate (which
/// the certificate alone authorizes, also a replaced one); `isolated_since` is when the
/// controller lost its quorum contact, if it did.
pub(crate) fn certificate(
    request: &Request,
    public: bool,
    renewal: bool,
    isolated_since: Option<Timestamp>,
) -> Option<Response> {
    let client = request.extensions().get::<ConnInfo>()?.client.clone()?;
    let now = Timestamp::now();
    if isolated_since.is_some_and(|since| now.saturating_since(since) > ISOLATION_LIMIT) {
        return Some(refuse(
            "integration.isolated",
            503,
            "this controller has been cut off from its cluster for too long to answer an integration",
        ));
    }
    let Some(certs) = request.extensions().get::<Arc<ClientCerts>>() else {
        return Some(refuse(
            "integration.unavailable",
            503,
            "integration certificates are not available on this controller",
        ));
    };
    match certs.index().accept(&client.serial, client.account, now) {
        Acceptance::Accepted(_) => {}
        Acceptance::RenewOnly(_) if renewal => {}
        Acceptance::RenewOnly(_) => {
            return Some(refuse(
                "integration.certificate.replaced",
                403,
                "this certificate was replaced by its renewal; use the new one",
            ));
        }
        Acceptance::Refused(_) => {
            return Some(refuse(
                "integration.certificate.refused",
                401,
                "this certificate is no longer accepted",
            ));
        }
    }
    if public && !renewal {
        return Some(refuse(
            "integration.public_route",
            404,
            "the integration listener serves no public operation; use the API listener",
        ));
    }
    None
}

/// The refusal of a request on the integration listener whose token is not of the account
/// the certificate names, or `None`; it runs after authentication. The renewal route needs
/// no token.
pub(crate) fn owner(request: &Request, renewal: bool) -> Option<Response> {
    let client = request.extensions().get::<ConnInfo>()?.client.clone()?;
    if renewal {
        return None;
    }
    let principal = request
        .extensions()
        .get::<AuthOutcome>()
        .and_then(AuthOutcome::principal);
    match principal {
        Some(Principal::Token { owner, .. }) if *owner == client.account => None,
        Some(_) => Some(refuse(
            "integration.token.wrong_account",
            403,
            "only a token of the service account the certificate names is accepted here",
        )),
        None => Some(refuse(
            "integration.token.required",
            401,
            "a token of the service account the certificate names is required",
        )),
    }
}

/// The certificate of a request that is presented for the first time since its renewal:
/// the records service and its serial, for [`note_presented`].
pub(crate) fn first_presentation(request: &Request) -> Option<(Arc<ClientCerts>, String)> {
    let client = request.extensions().get::<ConnInfo>()?.client.clone()?;
    let certs = request.extensions().get::<Arc<ClientCerts>>()?;
    let pending = certs
        .index()
        .record(&client.serial)
        .is_some_and(|record| record.state == tenko_auth::client_cert::model::CertState::Pending);
    pending.then(|| (Arc::clone(certs), client.serial.clone()))
}

/// Records the first presentation of a renewed certificate, which then replaces its
/// predecessor (ADR 0035, decision 6). A failure is logged: the next request tries again.
pub(crate) async fn note_presented(certs: Arc<ClientCerts>, serial: String) {
    let ctx = tenko_core::RequestCtx::system(tenko_core::SystemComponent::Api);
    if let Err(error) = certs.note_presented(&ctx, &serial).await {
        tracing::warn!(%serial, "the first presentation of a renewed certificate was not recorded: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use async_trait::async_trait;
    use axum::{body::Body, http::Method};
    use tenko_auth::{
        client_cert::{
            ClientCertError, Issued, Issuer,
            model::{CLIENT_CERTS, CertState, ClientCertRecord},
        },
        model::{USERS, UserKind, UserRecord},
    };
    use tenko_cluster::ca::TlsMode;
    use tenko_core::{
        ApiTokenId, AuthFlags, AuthStrength, RequestCtx, SessionId, SystemComponent, UserId,
        auth::Authenticated,
    };
    use tenko_store::{MemStore, Store, WriteBatch};
    use tenko_vault::MemVault;

    use super::*;
    use crate::{API_BASE, middleware::metrics::RouteTable, server::forwarded::IntegrationClient};

    /// Both checks in the order the middleware runs them, authentication aside.
    fn check(
        request: &Request,
        public: bool,
        renewal: bool,
        isolated_since: Option<Timestamp>,
    ) -> Option<Response> {
        certificate(request, public, renewal, isolated_since).or_else(|| owner(request, renewal))
    }

    /// Issues nothing: the gate only reads records.
    struct NoIssuer;

    #[async_trait]
    impl Issuer for NoIssuer {
        fn request_key(&self, _: &[u8]) -> Result<Vec<u8>, ClientCertError> {
            Err(ClientCertError::Conflict)
        }

        async fn ensure_root(&self, _: &RequestCtx) -> Result<(), ClientCertError> {
            Ok(())
        }

        async fn issue(
            &self,
            _: &RequestCtx,
            _: UserId,
            _: &[u8],
            _: u32,
        ) -> Result<Issued, ClientCertError> {
            Err(ClientCertError::Conflict)
        }

        fn server_root_sha256(&self) -> String {
            String::new()
        }

        fn server_root_pem(&self) -> String {
            String::new()
        }
    }

    struct Env {
        certs: Arc<ClientCerts>,
        account: UserId,
    }

    fn ago(seconds: u64) -> Timestamp {
        Timestamp(Timestamp::now().0 - Duration::from_secs(seconds))
    }

    fn ahead(seconds: u64) -> Timestamp {
        Timestamp(Timestamp::now().0 + Duration::from_secs(seconds))
    }

    /// A service account with a current certificate `current` and a certificate `replaced`
    /// whose overlap ended.
    async fn env() -> Env {
        let store = Arc::new(MemStore::default());
        let ctx = RequestCtx::system(SystemComponent::Api);
        let mut user = UserRecord::new("svc".to_owned(), "svc".to_owned(), Vec::new(), ctx.now);
        user.kind = UserKind::Service;
        let record = |serial: &str, state: CertState, ended: Option<Timestamp>| ClientCertRecord {
            serial: serial.to_owned(),
            account: user.id,
            generation: 0,
            lineage: uuid::Uuid::now_v7(),
            label: "host".to_owned(),
            key_sha256: "00".repeat(32),
            not_before: ago(3600),
            not_after: ahead(86_400),
            issued_at: ctx.now,
            state,
            presented_at: None,
            ended_at: ended,
            reason: None,
        };
        let mut batch = WriteBatch::for_request(&ctx);
        batch.put_typed(&USERS, &user.id, &user).expect("user");
        for (serial, state, ended) in [
            ("current", CertState::Current, None),
            ("replaced", CertState::Replaced, Some(ago(3600))),
        ] {
            batch
                .put_typed(
                    &CLIENT_CERTS,
                    &serial.to_owned(),
                    &record(serial, state, ended),
                )
                .expect("record");
        }
        store.propose(batch).await.expect("stored");
        let vault = Arc::new(MemVault::with_store(store.clone()));
        let store: Arc<dyn Store> = store;
        let certs = Arc::new(ClientCerts::new(
            Arc::clone(&store),
            vault,
            Arc::new(NoIssuer),
        ));
        certs.index().load(store.as_ref()).await.expect("load");
        Env {
            certs,
            account: user.id,
        }
    }

    fn token(owner: UserId) -> Principal {
        Principal::Token {
            id: ApiTokenId::generate(),
            owner,
        }
    }

    /// A request on the integration listener with the certificate `serial` of `env`'s
    /// account, authenticated as `principal`.
    fn request(env: &Env, serial: &str, principal: Option<Principal>) -> Request {
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(ConnInfo {
            peer: "192.0.2.30:50000".parse().expect("peer"),
            tls: true,
            mode: Arc::new(TlsMode::InternalCa),
            trusted: false,
            proxy: None,
            client: Some(Arc::new(IntegrationClient {
                serial: serial.to_owned(),
                account: env.account,
            })),
        });
        request.extensions_mut().insert(Arc::clone(&env.certs));
        if let Some(principal) = principal {
            request
                .extensions_mut()
                .insert(AuthOutcome(Ok(Authenticated {
                    principal,
                    user: None,
                    roles: BTreeSet::new(),
                    strength: AuthStrength::Password,
                    expires_at: None,
                    flags: AuthFlags::default(),
                })));
        }
        request
    }

    async fn code_of(refusal: Option<Response>) -> Option<(u16, String)> {
        let response = refusal?;
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        Some((status, body["code"].as_str().expect("code").to_owned()))
    }

    #[test]
    fn a_request_of_the_api_listener_passes_untouched() {
        assert!(check(&Request::new(Body::empty()), true, false, Some(ago(86_400))).is_none());
    }

    #[tokio::test]
    async fn only_a_token_of_the_certificates_account_passes() {
        let env = env().await;
        let account = env.account;
        assert!(
            check(
                &request(&env, "current", Some(token(account))),
                false,
                false,
                None
            )
            .is_none()
        );
        let session = Principal::User {
            id: account,
            session: SessionId::generate(),
            strength: AuthStrength::Password,
            delegation: None,
        };
        for (principal, status, code) in [
            (
                Some(token(UserId::generate())),
                403,
                "integration.token.wrong_account",
            ),
            (Some(session), 403, "integration.token.wrong_account"),
            (None, 401, "integration.token.required"),
        ] {
            let refusal = check(&request(&env, "current", principal), false, false, None);
            assert_eq!(code_of(refusal).await, Some((status, code.to_owned())));
        }
    }

    #[tokio::test]
    async fn the_certificate_public_routes_and_isolation_are_checked() {
        let env = env().await;
        let account = env.account;
        for (serial, public, isolated, status, code) in [
            ("current", true, None, 404, "integration.public_route"),
            (
                "unknown",
                false,
                None,
                401,
                "integration.certificate.refused",
            ),
            (
                "replaced",
                false,
                None,
                403,
                "integration.certificate.replaced",
            ),
            ("current", false, Some(ago(31)), 503, "integration.isolated"),
        ] {
            let refusal = check(
                &request(&env, serial, Some(token(account))),
                public,
                false,
                isolated,
            );
            assert_eq!(
                code_of(refusal).await,
                Some((status, code.to_owned())),
                "{serial} {public}"
            );
        }
        // A short loss of contact is tolerated.
        let recent = Some(ago(5));
        assert!(
            check(
                &request(&env, "current", Some(token(account))),
                false,
                false,
                recent
            )
            .is_none()
        );

        // The renewal needs no token, and a replaced certificate still reaches it.
        assert!(check(&request(&env, "replaced", None), true, true, None).is_none());
        assert!(check(&request(&env, "current", None), true, true, None).is_none());
        assert_eq!(
            code_of(check(&request(&env, "unknown", None), true, true, None)).await,
            Some((401, "integration.certificate.refused".to_owned()))
        );

        let mut bare = request(&env, "current", Some(token(account)));
        bare.extensions_mut().remove::<Arc<ClientCerts>>();
        assert_eq!(
            code_of(check(&bare, false, false, None)).await,
            Some((503, "integration.unavailable".to_owned()))
        );
    }

    #[test]
    fn the_route_table_knows_the_public_operations() {
        let table = RouteTable::get();
        let row =
            |path: &str, method: &Method| table.row(Some(&format!("{API_BASE}{path}")), method);
        for (path, method) in [
            ("/health", Method::GET),
            ("/integrations/enroll", Method::POST),
            ("/integrations/ca", Method::GET),
            ("/auth/login/password", Method::POST),
            ("/auth/password/check", Method::POST),
        ] {
            assert!(table.is_public(row(path, &method)), "{method} {path}");
        }
        for (path, method) in [
            ("/nodes", Method::GET),
            ("/integrations/certificates", Method::GET),
            ("/system/status", Method::GET),
        ] {
            assert!(!table.is_public(row(path, &method)), "{method} {path}");
        }
    }
}
