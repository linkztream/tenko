//! The flip and the release of a zone through the router (Windows takeover plan section
//! 2.6): the flip needs an interactive session, a flip to secondary passes its primaries
//! through the egress policy, the kinds are refused by their codes, and a zone goes to
//! secondary and back to primary with its records. The AD zones are in
//! `tenko-dns/tests/flip.rs`.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_core::{
    ApiTokenId, AuthFailure, AuthFlags, AuthStrength, Authenticated, Authenticator, Credentials,
    Principal, SessionId, Timestamp, UserId, auth::AuthFuture,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

/// A person with a session (`Bearer person`) and a personal token (`Bearer token`).
struct People(UserId);

impl Authenticator for People {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        _now: Timestamp,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            let principal = match credentials {
                Credentials::Bearer(token) if token == "person" => Principal::User {
                    id: self.0,
                    session: SessionId::generate(),
                    strength: AuthStrength::Passkey,
                },
                Credentials::Bearer(token) if token == "token" => Principal::Token {
                    id: ApiTokenId::generate(),
                    owner: self.0,
                },
                _ => return Err(AuthFailure::Missing),
            };
            Ok(Authenticated {
                principal,
                user: Some(self.0),
                roles: BTreeSet::new(),
                strength: AuthStrength::Passkey,
                expires_at: None,
                flags: AuthFlags::default(),
            })
        })
    }
}

fn app() -> Router {
    let store = Arc::new(MemStore::default());
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        None,
        ZoneConfig::default(),
    );
    let mut state = AppState::default();
    state.auth = Some(Arc::new(People(UserId::generate())));
    let (router, _) = tenko_api::api(state);
    router.layer(axum::Extension(service))
}

async fn post(router: &Router, as_who: &str, path: &str, body: Value) -> (u16, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {as_who}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

fn to_primary() -> Value {
    json!({"to": "primary", "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"}, "ns": ["ns1.example.test"]})
}

fn to_secondary(address: &str) -> Value {
    json!({"to": "secondary", "primaries": [{"address": address}]})
}

#[tokio::test]
async fn a_zone_flips_to_secondary_and_back_with_a_session_only() {
    let router = app();
    let (status, zone) = post(
        &router,
        "person",
        "/dns/zones",
        json!({"name": "example.test", "kind": "primary", "name_servers": ["ns1.example.test"],
               "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"}}),
    )
    .await;
    assert_eq!(status, 201, "{zone}");
    let id = zone["id"].as_str().expect("id").to_owned();
    let flip = format!("/dns/zones/{id}/flip");
    let release = format!("/dns/zones/{id}/release");

    let (status, body) = post(&router, "token", &flip, to_secondary("192.0.2.5")).await;
    assert_eq!((status, &body["code"]), (403, &json!("auth.forbidden")));
    let (status, body) = post(&router, "person", &flip, to_primary()).await;
    assert_eq!(
        (status, &body["code"]),
        (409, &json!("dns.zone.flip.not_secondary"))
    );
    for address in ["127.0.0.1", "169.254.169.254", "fe80::1"] {
        let (status, body) = post(&router, "person", &flip, to_secondary(address)).await;
        assert_eq!(
            (status, &body["code"]),
            (400, &json!("dns.zone.invalid")),
            "{address}"
        );
        assert_eq!(body["params"]["field"], "primaries");
    }
    let (status, body) = post(&router, "person", &release, json!({"dry_run": true})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        (&body["rrsets"], &body["dry_run"]),
        (&json!(0), &json!(true))
    );

    let (status, body) = post(&router, "person", &flip, to_secondary("192.0.2.5")).await;
    assert_eq!(
        (status, &body["kind"]),
        (200, &json!("secondary")),
        "{body}"
    );
    let serial = body["serial"].as_u64().expect("serial");
    let (status, body) = post(&router, "person", &release, json!({})).await;
    assert_eq!(
        (status, &body["code"]),
        (409, &json!("dns.zone.flip.not_primary"))
    );
    let (status, body) = post(&router, "token", &flip, to_primary()).await;
    assert_eq!((status, &body["code"]), (403, &json!("auth.forbidden")));

    // Back before any transfer: the records it held stay, the SOA moves on.
    let (status, body) = post(&router, "person", &flip, to_primary()).await;
    assert_eq!((status, &body["kind"]), (200, &json!("primary")), "{body}");
    assert!(body["serial"].as_u64().expect("serial") > serial);
    assert_eq!(body["origins"], json!([{"origin": "manual", "rrsets": 2}]));
}
