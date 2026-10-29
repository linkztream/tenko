//! Route tests of the root, the SSID view and the WLAN decisions, run against the sample
//! network controller (`tenko_connect::sample_switch`): its SSIDs lab (VLAN 20), iot (VLAN
//! 30) and guest (VLAN 40, a guest network) with the clients that are the cases of the two
//! WLAN rules. Test data lives in the documentation ranges.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
};
use serde_json::{Value, json};
use tenko_connect::sample_switch::{self, GUEST_SSID, IOT_SSID, SSID, mac};
use tenko_core::{Authorizer, RequestCtx, SystemComponent, Timestamp, observe::RadioBand};
use tenko_ipam::{
    IpamCommand, IpamService, PlanOptions,
    command::{HostInput, PrefixInput, VlanInput},
    topology::{
        TopologyConfig, TopologyGraph, TopologyService, WlanPolicy, build::Intent, stored::Stored,
        wlan,
    },
    vlan::{
        Controllers,
        controllers::ControllerClient,
        memory::{MemoryController, MemoryControllers},
    },
};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    API_BASE,
    routes::{
        tenancy::testkit::{Policy, Reply},
        topology::routes,
        vlans::host::topology_of,
    },
    state::AppState,
};

/// The sample network's SSID tree, bands included, as the host maps the controller's read.
#[test]
fn the_sample_network_gives_the_tree_of_ssid_vlan_and_clients_with_their_bands() {
    let connector = tenko_core::ConnectorId::generate();
    let table = Arc::new(topology_of(connector, &sample_switch::sample_topology()));
    let evaluation = wlan::evaluate(
        &[table],
        &Intent::default(),
        &Stored::default(),
        &TopologyGraph::default(),
        Timestamp::now(),
    );
    let names: Vec<&str> = evaluation.ssids.iter().map(|s| s.ssid.as_str()).collect();
    assert_eq!(names, [GUEST_SSID, IOT_SSID, SSID]);
    let lab = &evaluation.ssids[2];
    assert_eq!(lab.vid, Some(20));
    assert_eq!(lab.clients, 4, "0x21, Tenko's host 0x0b, 0x22 and 0x23");
    assert_eq!(lab.policy, WlanPolicy::Track);
    assert_eq!(lab.access_points, ["ap-a"]);
    let client = lab.vlans[0]
        .clients
        .iter()
        .find(|c| c.mac == mac(0x22))
        .expect("client");
    assert_eq!(client.band, Some(RadioBand::G2));
    assert_eq!(client.access_point, "ap-a");
    let guest = &evaluation.ssids[0];
    assert!(guest.guest);
    assert_eq!(
        guest.policy,
        WlanPolicy::Ignore,
        "a guest SSID is ignored by default"
    );
    assert!(
        evaluation.findings.is_empty(),
        "without intent nothing is classed and nothing judged"
    );
}

struct Lab {
    router: Router,
    hosts: std::collections::BTreeMap<u8, String>,
}

fn system() -> RequestCtx {
    RequestCtx::system(SystemComponent::Reconciler)
}

/// The sample controller in memory with intent: VLAN 20 on `192.0.2.0/24`, VLAN 30 (the IoT
/// role) on `198.51.100.0/24`; hosts for the clients 0x22 (IoT), 0x23, 0x31 (IoT) and 0x41
/// (IoT, on the guest SSID).
async fn sample_lab(authorizer: Option<Arc<dyn Authorizer>>) -> Lab {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
    let snapshot = sample_switch::sample_topology();
    let mut controller = MemoryController::new("sample.example.test");
    let table = topology_of(controller.info.id, &snapshot);
    controller.devices = table.devices;
    controller.wlans = table.wlans;
    controller.clients = snapshot
        .clients
        .iter()
        .map(|c| ControllerClient {
            mac: c.mac,
            ip: c.ip,
            device: c.device.0.clone(),
            port: c.port,
            ssid: c.ssid.clone(),
            network: c.network.as_ref().map(|n| n.0.clone()),
            vlan: c.vlan,
            name: c.name.clone(),
            management: c.management,
        })
        .collect();
    let controllers = Controllers::with(MemoryControllers::new(vec![controller]));
    let topology =
        TopologyService::new(Arc::clone(&service), controllers, TopologyConfig::default());
    let lab_vlan = tenko_core::VlanId::generate();
    let iot_vlan = tenko_core::VlanId::generate();
    let vlan = |id, vid: u16, name: &str, tags: Value| {
        IpamCommand::CreateVlan(
            serde_json::from_value::<VlanInput>(
                json!({"id": id, "vid": vid, "name": name, "tags": tags}),
            )
            .expect("vlan"),
        )
    };
    let network = |cidr: &str, vlan| {
        IpamCommand::CreatePrefix(
            serde_json::from_value::<PrefixInput>(json!({"cidr": cidr, "vlan": vlan}))
                .expect("prefix"),
        )
    };
    let mut commands = vec![
        vlan(lab_vlan, 20, "Lab", json!([])),
        vlan(iot_vlan, 30, "IoT", json!(["role:iot"])),
        network("192.0.2.0/24", lab_vlan),
        network("198.51.100.0/24", iot_vlan),
    ];
    let mut hosts = std::collections::BTreeMap::new();
    for (last, name, iot) in [
        (0x22u8, "sensor-a", true),
        (0x23, "laptop-b", false),
        (0x31, "sensor-b", true),
        (0x41, "sensor-c", true),
    ] {
        let id = tenko_core::HostId::generate();
        hosts.insert(last, id.to_string());
        commands.push(IpamCommand::CreateHost(
            serde_json::from_value::<HostInput>(json!({
                "id": id,
                "name": name,
                "mode": "dynamic",
                "tags": if iot { json!(["class:iot"]) } else { json!([]) },
                "interfaces": [{ "name": "eth0", "mac": mac(last).to_string() }],
            }))
            .expect("host"),
        ));
    }
    service
        .execute(&commands, &system(), &PlanOptions::default())
        .await
        .expect("intent");
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest(API_BASE, routes())
        .split_for_parts();
    let state = AppState {
        authorizer,
        ..AppState::default()
    };
    Lab {
        router: router
            .with_state(state)
            .layer(Extension(service))
            .layer(Extension(topology)),
        hosts,
    }
}

impl Lab {
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        if_match: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        if let Some(tag) = if_match {
            request = request.header(header::IF_MATCH, tag);
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let header_of = |name| {
            response
                .headers()
                .get(name)
                .map(|v: &header::HeaderValue| v.to_str().expect("text").to_owned())
        };
        let content_type = header_of(header::CONTENT_TYPE).unwrap_or_default();
        let etag = header_of(header::ETAG);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        Reply {
            status,
            content_type,
            etag,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    /// The finding kinds of each client of an SSID, by the client's MAC address.
    async fn findings_of(&self, ssid: &str) -> Vec<(String, Vec<String>)> {
        let view = self.send(Method::GET, "/topology/ssids", None, None).await;
        view.assert_json(200);
        let entry = view.body["ssids"]
            .as_array()
            .expect("ssids")
            .iter()
            .find(|s| s["ssid"] == ssid)
            .cloned()
            .expect("ssid");
        let mut out: Vec<(String, Vec<String>)> = entry["vlans"]
            .as_array()
            .expect("vlans")
            .iter()
            .flat_map(|v| v["clients"].as_array().cloned().unwrap_or_default())
            .map(|c| {
                let kinds = c["findings"]
                    .as_array()
                    .map(|k| {
                        k.iter()
                            .map(|k| k.as_str().unwrap_or_default().to_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                (c["mac"].as_str().unwrap_or_default().to_owned(), kinds)
            })
            .filter(|(_, kinds): &(String, Vec<String>)| !kinds.is_empty())
            .collect();
        out.sort();
        out
    }
}

fn path_ssid(ssid: &str) -> String {
    ssid.replace(' ', "%20")
}

#[tokio::test]
async fn the_rules_run_on_the_sample_network_and_keep_on_this_wlan_removes_one_host() {
    let lab = sample_lab(None).await;
    assert_eq!(
        lab.findings_of(SSID).await,
        [
            (mac(0x22).to_string(), vec!["wlan_class".to_owned()]),
            (mac(0x23).to_string(), vec!["wlan_prefix".to_owned()]),
        ]
    );
    assert!(
        lab.findings_of(IOT_SSID).await.is_empty(),
        "an IoT device at home"
    );
    assert!(
        lab.findings_of(GUEST_SSID).await.is_empty(),
        "the guest SSID is ignored by default"
    );

    let host = lab.hosts[&0x22].clone();
    let kept = lab
        .send(
            Method::PUT,
            &format!("/topology/ssids/{}/exceptions/{host}", path_ssid(SSID)),
            Some(json!({"reason": "a test bench"})),
            None,
        )
        .await;
    kept.assert_json(200);
    assert_eq!(kept.body["ssid"], SSID);
    let etag = kept.etag.clone().expect("etag");
    assert_eq!(
        lab.findings_of(SSID).await,
        [(mac(0x23).to_string(), vec!["wlan_prefix".to_owned()])],
        "the exception removes the finding of that host only"
    );
    // An empty body keeps too; a stale revision is refused.
    lab.send(
        Method::PUT,
        &format!("/topology/ssids/{}/exceptions/{host}", path_ssid(SSID)),
        None,
        Some(&etag),
    )
    .await
    .assert_json(200);
    lab.send(
        Method::PUT,
        &format!("/topology/ssids/{}/exceptions/{host}", path_ssid(SSID)),
        None,
        Some("\"1\""),
    )
    .await
    .assert_problem(412, "ipam.revision_mismatch");
    lab.send(
        Method::PUT,
        &format!(
            "/topology/ssids/{}/exceptions/{}",
            path_ssid(SSID),
            tenko_core::HostId::generate()
        ),
        None,
        None,
    )
    .await
    .assert_problem(404, "ipam.not_found");

    // Tracking the guest SSID judges its IoT device, whose VLAN has no IoT role; VLAN 40 has
    // no networks of intent, so its address is not judged.
    lab.send(
        Method::PUT,
        &format!("/topology/ssids/{}/policy", path_ssid(GUEST_SSID)),
        Some(json!({"policy": "track"})),
        None,
    )
    .await
    .assert_json(200);
    assert_eq!(
        lab.findings_of(GUEST_SSID).await,
        [(mac(0x41).to_string(), vec!["wlan_class".to_owned()])]
    );
    lab.send(
        Method::DELETE,
        &format!("/topology/ssids/{}/policy", path_ssid(GUEST_SSID)),
        None,
        None,
    )
    .await;
    assert!(
        lab.findings_of(GUEST_SSID).await.is_empty(),
        "the default applies again"
    );
    lab.send(
        Method::PUT,
        &format!("/topology/ssids/{}/policy", "x".repeat(33)),
        Some(json!({"policy": "track"})),
        None,
    )
    .await
    .assert_problem(422, "ipam.topology.invalid");
    lab.send(
        Method::DELETE,
        &format!("/topology/ssids/{}/exceptions/{host}", path_ssid(SSID)),
        None,
        None,
    )
    .await;
    assert_eq!(lab.findings_of(SSID).await.len(), 2);
}

#[tokio::test]
async fn the_root_of_the_sample_network_and_the_refusals() {
    let lab = sample_lab(None).await;
    // The sample controller manages no gateway and the test reads no route: no root.
    let root = lab.send(Method::GET, "/topology/root", None, None).await;
    root.assert_json(200);
    assert_eq!(root.body["candidates"], json!([]));
    assert_eq!(root.body["open"], false);
    lab.send(
        Method::PUT,
        "/topology/root",
        Some(json!({"source": "controller"})),
        None,
    )
    .await
    .assert_problem(409, "ipam.topology.no_candidate");
    lab.send(Method::DELETE, "/topology/root", None, None)
        .await
        .assert_problem(404, "ipam.topology.not_stored");

    // A reader reads, and writes nothing.
    let reader = sample_lab(Some(Policy::new(true, false) as Arc<dyn Authorizer>)).await;
    reader
        .send(Method::GET, "/topology/ssids", None, None)
        .await
        .assert_json(200);
    reader
        .send(
            Method::PUT,
            &format!("/topology/ssids/{}/policy", path_ssid(SSID)),
            Some(json!({"policy": "ignore"})),
            None,
        )
        .await
        .assert_problem(403, "auth.forbidden");
    let host = reader.hosts[&0x22].clone();
    reader
        .send(
            Method::PUT,
            &format!("/topology/ssids/{}/exceptions/{host}", path_ssid(SSID)),
            None,
            None,
        )
        .await
        .assert_problem(403, "auth.forbidden");
    reader
        .send(
            Method::PUT,
            "/topology/root",
            Some(json!({"source": "controller"})),
            None,
        )
        .await
        .assert_problem(403, "auth.forbidden");
}
