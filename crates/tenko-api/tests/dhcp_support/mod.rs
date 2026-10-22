//! The router of the DHCP route tests: the API with the IPAM service and the DHCP
//! configuration service on one in-memory store, the request helpers and the IPAM rows
//! the scopes need, written through the IPAM routes.

#![allow(dead_code, reason = "each test binary uses a part of the support")]

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_dhcp::config::ConfigService;
use tenko_ipam::IpamService;
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
use tower::ServiceExt;

pub const API: &str = "/api/v1";
pub const PROBLEM_JSON: &str = "application/problem+json";
pub const MISSING: &str = "0190d1c2-0000-7000-8000-0000000000ff";

/// A decoded answer.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    /// The `ETag` without quotes.
    pub fn etag(&self) -> String {
        self.headers
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .expect("text")
            .trim_matches('"')
            .to_owned()
    }

    #[track_caller]
    pub fn assert_status(&self, status: u16) -> &Self {
        assert_eq!(self.status.as_u16(), status, "{}", self.body);
        self
    }

    #[track_caller]
    pub fn assert_problem(&self, status: u16, code: &str) -> &Self {
        assert_eq!(self.status.as_u16(), status, "{}", self.body);
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .map(axum::http::HeaderValue::as_bytes),
            Some(PROBLEM_JSON.as_bytes())
        );
        assert_eq!(self.body["code"], code, "{}", self.body);
        self
    }

    /// A string member.
    pub fn text(&self, member: &str) -> String {
        self.body[member]
            .as_str()
            .unwrap_or_else(|| panic!("{member} in {}", self.body))
            .to_owned()
    }

    /// The `items` of a page.
    pub fn items(&self) -> Vec<Value> {
        self.body["items"].as_array().expect("items").clone()
    }
}

/// The router, the store and the services.
pub struct App {
    pub router: Router,
    pub store: Arc<MemStore>,
    pub config: Arc<ConfigService>,
}

impl App {
    pub fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let ipam =
            IpamService::with_direct_jobs(Arc::clone(&store) as Arc<dyn Store>).expect("IPAM");
        let config = ConfigService::with_direct_jobs(Arc::clone(&store) as Arc<dyn Store>);
        let (router, _) = tenko_api::api(AppState::default());
        let router = router
            .layer(axum::Extension(ipam))
            .layer(axum::Extension(Arc::clone(&config)));
        Self {
            router,
            store,
            config,
        }
    }

    /// The router without the configuration service.
    pub fn without_service() -> Router {
        let (router, _) = tenko_api::api(AppState::default());
        router
    }

    pub async fn send(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        send(&self.router, method, path, body, &[]).await
    }

    pub async fn send_with(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Reply {
        send(&self.router, method, path, body, extra).await
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, None).await
    }

    /// Creates a prefix through IPAM and returns its id.
    pub async fn prefix(&self, cidr: &str) -> String {
        self.prefix_with(json!({ "cidr": cidr })).await
    }

    pub async fn prefix_with(&self, body: Value) -> String {
        let reply = self.send("POST", "/prefixes", Some(body)).await;
        reply.assert_status(201);
        reply.body["item"]["id"].as_str().expect("id").to_owned()
    }

    /// Creates a range of a prefix through IPAM and returns its id.
    pub async fn range(&self, prefix: &str, first: &str, last: &str, role: &str) -> String {
        let reply = self
            .send(
                "POST",
                &format!("/prefixes/{prefix}/ranges"),
                Some(json!({ "first": first, "last": last, "role": role })),
            )
            .await;
        reply.assert_status(201);
        reply.body["item"]["id"].as_str().expect("id").to_owned()
    }

    /// Creates a host of `mode` with one interface (MAC `00:00:5e:00:53:<last>`) and an
    /// address; returns the interface's id.
    pub async fn host(&self, name: &str, mode: &str, mac_last: Option<u8>, ip: &str) -> String {
        let interface = uuid::Uuid::now_v7().to_string();
        let mut nic = json!({ "id": interface, "name": "eth0" });
        if let Some(last) = mac_last {
            nic["mac"] = json!(format!("00:00:5e:00:53:{last:02x}"));
        }
        self.send(
            "POST",
            "/hosts",
            Some(json!({ "name": name, "mode": mode, "interfaces": [nic] })),
        )
        .await
        .assert_status(201);
        self.send(
            "POST",
            "/addresses",
            Some(json!({ "ip": ip, "interface": interface })),
        )
        .await
        .assert_status(201);
        interface
    }

    /// A scope of a new prefix `cidr`; returns the prefix id.
    pub async fn scope(&self, cidr: &str) -> String {
        let prefix = self.prefix(cidr).await;
        self.send("POST", "/dhcp/scopes", Some(json!({ "prefix": prefix })))
            .await
            .assert_status(201);
        prefix
    }

    /// The audit actions in the store, in order.
    pub async fn audit_actions(&self) -> Vec<String> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft.action.as_str().to_owned())
        .filter(|action| action.starts_with("dhcp."))
        .collect()
    }
}

pub async fn send(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
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
        headers,
        body,
    }
}
