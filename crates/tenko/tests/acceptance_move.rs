//! The move flow of IPAM-19 against the real binary, through the public API: exit criterion
//! E8 as far as it runs without a network controller, and the DNS half of E17 (Phase 2,
//! WP4.4).
//!
//! - Manual DNS: a `reserved` host with a MAC and an address whose DNS name has no zone in
//!   Tenko moves from 192.0.2.0/24 to 198.51.100.0/24. The dry run previews the same host
//!   part and the steps in order; the submit starts one job; each manual step (DHCP, DNS,
//!   the L2 change and the observation) is completed through
//!   `POST /jobs/{id}/steps/{index}/complete` until the job succeeds; the new address is
//!   active on the interface and the old one is deleted.
//! - Automatic DNS (E17): the same host with its name in the Tenko zone `example.test`,
//!   among five devices with names. A reconciler run gives every name its A and PTR
//!   records with the origin `ipam` and creates the reverse zones of both prefixes; the
//!   preview shows the DNS step automatic with the records it removes and writes; the step
//!   moves them while the job waits for the L2 change, and a later run changes nothing.
//! - The actuator as a reconciler driver: a hand-deleted `ipam` record comes back with the
//!   audit action `dns.record.actuate`; a record taken over by hand stays and is proposed
//!   as held by another origin.
//! - Failure: the API offers no way to fail a manual step, and the observation timeout has
//!   a floor of 300 seconds, so the failure path is a cancellation of the waiting job: the
//!   engine compensates in reverse (the DNS records point to the old address again, the new
//!   address is removed, the old one stays) and ends the job `cancelled`, and the host
//!   carries the tag `move-failed`.
//! - E25 (Phase 3, WP8.1): the five-device lab with the `dhcp` role serving both networks
//!   in relay mode on loopback (the test is the relay agent and selects the scope with
//!   option 118). The reserved devices get their reservations from intent; the preview
//!   shows the DHCP step automatic (`dhcp.reservation`), the moving client marked first
//!   (`dhcp.prepare`) and the deadline from the device's own lease (ADR 0027); while the
//!   move waits for the L2 change both scopes offer the device its reservation; the lease
//!   the device then takes in the target network confirms the observation step without
//!   anyone ticking it, and the cleanup releases the old lease
//!   while the old reservation goes with the old address. The dynamic device's pool lease
//!   confirms its move, the static device stops at its manual step, and a cancel of a
//!   waiting move restores both reservations (the new one removed, the old one kept). A
//!   renewal right after a grant writes no fact and is counted.

mod serve_support;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, wait_for_setup_token};
use tenko_dhcp::v4::{Message, MessageType};

const SOURCE: &str = "192.0.2.0/24";
const TARGET: &str = "198.51.100.0/24";
const OLD_IP: &str = "192.0.2.15";
const NEW_IP: &str = "198.51.100.15";
const MAC: &str = "00-00-5E-00-53-20";
const DNS_NAME: &str = "printer.example.test";
const ZONE: &str = "example.test";
const OLD_PTR: &str = "15.2.0.192.in-addr.arpa";
const NEW_PTR: &str = "15.100.51.198.in-addr.arpa";
const JOB_TIMEOUT: Duration = Duration::from_secs(60);

/// The other devices with names in the zone (E17: five devices in all).
const DEVICES: [(&str, &str); 4] = [
    ("192.0.2.21", "cam1.example.test"),
    ("192.0.2.22", "cam2.example.test"),
    ("192.0.2.23", "sensor.example.test"),
    ("198.51.100.40", "plug.example.test"),
];

/// The preview step kinds of a `reserved` host whose DNS name has no zone in Tenko.
const STEP_KINDS: [&str; 6] = [
    "ipam.intent",
    "dhcp.manual",
    "dns.manual",
    "l2.move",
    "observe",
    "cleanup",
];

/// The same with the name in a zone Tenko serves: the DNS step is automatic.
const STEP_KINDS_DNS: [&str; 6] = [
    "ipam.intent",
    "dhcp.manual",
    "dns.records",
    "l2.move",
    "observe",
    "cleanup",
];

struct World {
    node: Node,
    server: Proc,
    api: Api,
    target: String,
    host: String,
    interface: String,
}

impl World {
    /// A fresh instance with the two prefixes and the host; with `zone`, the zone
    /// `example.test` exists before the addresses.
    fn new(zone: bool) -> Self {
        let mut node = Node::new();
        let server = node.start();
        let token = wait_for_setup_token(&server);
        let mut api = Api::new(&node);
        api.setup(&token);
        // The leader's own runs come rarely, so the runs the tests ask for do the work.
        api.put("/settings/reconciler", &quiet_settings())
            .expect(200);
        if zone {
            api.post(
                "/dns/zones",
                &json!({
                    "name": ZONE,
                    "kind": "primary",
                    "soa": { "mname": "ns1.example.test", "rname": "hostmaster.example.test" },
                    "name_servers": ["ns1.example.test"],
                }),
            )
            .expect(201);
        }
        api.post("/prefixes", &json!({ "cidr": SOURCE }))
            .expect(201);
        let target = api
            .post("/prefixes", &json!({ "cidr": TARGET }))
            .expect(201)["item"]["id"]
            .as_str()
            .expect("a prefix id")
            .to_owned();
        let host = api
            .post(
                "/hosts",
                &json!({
                    "name": "printer",
                    "mode": "reserved",
                    "interfaces": [{ "name": "eth0", "mac": MAC }],
                }),
            )
            .expect(201)["item"]["id"]
            .as_str()
            .expect("a host id")
            .to_owned();
        let interfaces = api.get(&format!("/hosts/{host}/interfaces")).expect(200);
        let interface = interfaces["items"][0]["id"]
            .as_str()
            .expect("the interface")
            .to_owned();
        api.post(
            "/addresses",
            &json!({ "ip": OLD_IP, "interface": interface, "dns_name": DNS_NAME }),
        )
        .expect(201);
        Self {
            node,
            server,
            api,
            target,
            host,
            interface,
        }
    }

    fn request(&self) -> Value {
        json!({
            "objects": [{ "kind": "host", "id": self.host }],
            "target": self.target,
        })
    }

    /// The live address with this IP, if any.
    fn address(&self, ip: &str) -> Option<Value> {
        self.api
            .list_all("/addresses")
            .into_iter()
            .find(|address| address["ip"] == ip)
    }

    fn host_tags(&self) -> Vec<String> {
        let host = self.api.get(&format!("/hosts/{}", self.host)).expect(200);
        host["meta"]["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|tag| tag.as_str().map(str::to_owned))
            .collect()
    }

    /// Submits the move and returns the one job.
    fn submit(&self) -> String {
        let submitted = self.api.post("/moves", &self.request()).expect(202);
        let jobs = submitted["jobs"].as_array().expect("jobs");
        assert_eq!(jobs.len(), 1, "one job per moved address: {submitted}");
        assert!(
            submitted["group"].as_str().is_some_and(|g| !g.is_empty()),
            "{submitted}"
        );
        jobs[0]["job_id"].as_str().expect("a job id").to_owned()
    }

    /// Waits until the job waits for a person and returns the index of that step.
    fn waiting_step(&self, job: &str) -> u64 {
        let detail = self.api.wait_for_job_until(job, JOB_TIMEOUT, |detail| {
            detail["job"]["state"] == "waiting"
                && detail["job"]["steps"].as_array().is_some_and(|steps| {
                    steps
                        .iter()
                        .any(|step| step["state"]["state"] == "waiting_for_manual")
                })
        });
        detail["job"]["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .find(|step| step["state"]["state"] == "waiting_for_manual")
            .and_then(|step| step["index"].as_u64())
            .expect("a waiting step")
    }

    /// Completes the waiting step and waits until it is done (or the job succeeded).
    fn complete(&self, job: &str, index: u64) {
        self.api
            .post_unkeyed(
                &format!("/jobs/{job}/steps/{index}/complete"),
                &json!({ "note": format!("done in the acceptance test, step {index}") }),
            )
            .expect(200);
        let detail = self.api.wait_for_job_until(job, JOB_TIMEOUT, |detail| {
            let state = &detail["job"]["state"];
            state == "succeeded"
                || (state == "waiting"
                    && detail["job"]["steps"]
                        .as_array()
                        .and_then(|steps| steps.get(usize::try_from(index).unwrap_or(0)))
                        .is_some_and(|step| step["state"]["state"] == "done"))
        });
        assert_ne!(detail["job"]["state"], "failed", "{detail}");
    }

    /// One reconciler run on demand; its report.
    fn reconcile(&self) -> Value {
        self.api
            .post_unkeyed("/proposals/reconcile", &json!({}))
            .expect(200)
    }

    /// The identifier of the zone with this apex.
    fn zone_id(&self, apex: &str) -> String {
        self.api
            .list_all("/dns/zones")
            .into_iter()
            .find(|zone| zone["name"] == apex)
            .and_then(|zone| zone["id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("no zone {apex}"))
    }

    /// The RRset of a zone at an owner and type, through `list_dns_records`.
    fn rrset(&self, apex: &str, owner: &str, rtype: &str) -> Option<Value> {
        let zone = self.zone_id(apex);
        self.api
            .list_all(&format!("/dns/zones/{zone}/records"))
            .into_iter()
            .find(|rrset| rrset["name"] == owner && rrset["type"] == rtype)
    }

    /// The addresses of an A RRset, sorted.
    fn a_records(&self, owner: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .rrset(ZONE, owner, "A")
            .map(|rrset| {
                assert_eq!(rrset["origin"], "ipam", "{rrset}");
                rrset["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|record| record["address"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// The target of the PTR at `owner` in the reverse zone `apex`.
    fn ptr(&self, apex: &str, owner: &str) -> Option<String> {
        self.rrset(apex, owner, "PTR").map(|rrset| {
            assert_eq!(rrset["origin"], "ipam", "{rrset}");
            rrset["records"][0]["target"]
                .as_str()
                .expect("a target")
                .to_owned()
        })
    }

    fn stop(mut self) {
        self.server.stop().assert_graceful_shutdown();
        drop(self.node);
    }
}

/// Reconciler settings with a long interval and debounce.
fn quiet_settings() -> Value {
    json!({
        "interval_secs": 86_400,
        "debounce_secs": 300,
        "orphan_after_secs": 604_800,
        "retention_secs": 2_592_000,
        "refresh_secs": 900,
        "purge_interval_secs": 3_600,
        "adopt": true,
        "dns_actuator": true,
        "dns_orphans": "remove"
    })
}

fn step_kinds(item: &Value) -> Vec<String> {
    item["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["kind"].as_str().unwrap_or_default().to_owned())
        .collect()
}

fn automatic(item: &Value) -> Vec<bool> {
    item["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["automatic"] == true)
        .collect()
}

/// The reverse name of a test address in the default /24 form.
fn ptr_name(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').rev().collect();
    format!("{}.in-addr.arpa", octets.join("."))
}

fn reverse_zone(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').rev().skip(1).collect();
    format!("{}.in-addr.arpa", octets.join("."))
}

#[test]
fn a_reserved_host_moves_after_its_manual_steps() {
    let world = World::new(false);

    // The dry run: the same host part, the steps in order, nothing written. The name has
    // no zone in Tenko, so the DNS step is a task for a person.
    let preview = world
        .api
        .post("/moves?dry_run=true", &world.request())
        .expect(200);
    assert_eq!(preview["target"]["cidr"], TARGET);
    assert_eq!(preview["timeout_source"], "default", "{preview}");
    let items = preview["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{preview}");
    let item = &items[0];
    assert_eq!(item["old_ip"], OLD_IP);
    assert_eq!(item["new_ip"], NEW_IP);
    assert_eq!(item["same_host_part"], true);
    assert_eq!(item["mode"], "reserved");
    assert_eq!(item["requested"]["id"], world.host.as_str());
    assert!(item["dns"]["zone"].is_null(), "{item}");
    assert_eq!(step_kinds(item), STEP_KINDS);
    assert_eq!(automatic(item), [true, false, false, false, false, true]);
    assert!(world.address(NEW_IP).is_none(), "a dry run writes nothing");

    // The submit: one job; the intent step runs at once and plans the new address.
    let job = world.submit();
    let mut completed = 0;
    loop {
        let detail = world.api.get(&format!("/jobs/{job}")).expect(200);
        if detail["job"]["state"] == "succeeded" {
            break;
        }
        let index = world.waiting_step(&job);
        if completed == 0 {
            let planned = world.address(NEW_IP).expect("the new intent");
            assert_eq!(planned["status"], "planned");
            assert_eq!(planned["interface"], world.interface.as_str());
        }
        world.complete(&job, index);
        completed += 1;
        assert!(completed <= 4, "more manual steps than the preview listed");
    }
    assert_eq!(completed, 4, "DHCP, DNS, L2 and the observation are manual");

    // The result: the new address active on the interface, the old one gone.
    let new = world.address(NEW_IP).expect("the new address");
    assert_eq!(new["status"], "active");
    assert_eq!(new["interface"], world.interface.as_str());
    assert_eq!(new["dns_name"], DNS_NAME);
    assert!(
        world.address(OLD_IP).is_none(),
        "the old address is deleted"
    );
    assert!(!world.host_tags().iter().any(|tag| tag == "move-failed"));

    // The audit records the completions and still verifies.
    let report = world.api.get("/audit/verify").expect(200);
    assert_eq!(report["intact"], true, "{report}");
    world.stop();
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn e17_the_dns_step_is_automatic_when_the_zone_is_in_tenko() {
    let world = World::new(true);
    for (ip, name) in DEVICES {
        world
            .api
            .post("/addresses", &json!({ "ip": ip, "dns_name": name }))
            .expect(201);
    }

    // A reconciler run: every name gets its A and PTR records, and both prefixes their
    // reverse zones (the tenant has a forward zone in Tenko).
    let run = world.reconcile();
    assert!(run["dns"].is_object(), "{run}");
    assert!(run["dns"]["failures"].is_null(), "{run}");
    let zones: Vec<String> = world
        .api
        .list_all("/dns/zones")
        .iter()
        .filter_map(|zone| zone["name"].as_str().map(str::to_owned))
        .collect();
    assert!(zones.contains(&reverse_zone(OLD_IP)), "{zones:?}");
    assert!(zones.contains(&reverse_zone(NEW_IP)), "{zones:?}");
    assert_eq!(world.a_records(DNS_NAME), [OLD_IP]);
    assert_eq!(
        world.ptr(&reverse_zone(OLD_IP), OLD_PTR).as_deref(),
        Some(DNS_NAME)
    );
    for (ip, name) in DEVICES {
        assert_eq!(world.a_records(name), [ip]);
        assert_eq!(
            world.ptr(&reverse_zone(ip), &ptr_name(ip)).as_deref(),
            Some(name)
        );
    }

    // The dry run shows the DNS step automatic with the records it changes.
    let preview = world
        .api
        .post("/moves?dry_run=true", &world.request())
        .expect(200);
    let item = &preview["items"][0];
    assert_eq!(item["dns"]["zone"], ZONE, "{item}");
    let remove: Vec<&str> = item["dns"]["remove"]
        .as_array()
        .expect("remove")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let add: Vec<&str> = item["dns"]["add"]
        .as_array()
        .expect("add")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        remove.contains(&"printer.example.test A 192.0.2.15"),
        "{remove:?}"
    );
    assert!(
        add.contains(&"printer.example.test A 198.51.100.15"),
        "{add:?}"
    );
    assert!(
        remove.iter().any(|line| line.starts_with(OLD_PTR)),
        "{remove:?}"
    );
    assert!(add.iter().any(|line| line.starts_with(NEW_PTR)), "{add:?}");
    assert_eq!(step_kinds(item), STEP_KINDS_DNS);
    assert_eq!(automatic(item), [true, false, true, false, false, true]);
    assert_eq!(
        world.a_records(DNS_NAME),
        [OLD_IP],
        "a dry run writes nothing"
    );

    // The job: DHCP by a person, then the DNS step moves the records while the job waits
    // for the L2 change.
    let job = world.submit();
    let dhcp = world.waiting_step(&job);
    world.complete(&job, dhcp);
    let l2 = world.waiting_step(&job);
    assert!(l2 > dhcp + 1, "the DNS step ran between them");
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);
    assert_eq!(world.ptr(&reverse_zone(OLD_IP), OLD_PTR), None);
    assert_eq!(
        world.ptr(&reverse_zone(NEW_IP), NEW_PTR).as_deref(),
        Some(DNS_NAME)
    );
    // The reconciler keeps what the step wrote while the move is in flight.
    let run = world.reconcile();
    assert_eq!(run["dns"]["rrsets_changed"], 0, "{run}");
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);
    world.complete(&job, l2);
    let observe = world.waiting_step(&job);
    world.complete(&job, observe);
    let detail = world.api.wait_for_job(&job, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");

    // After the cleanup the intent and the zones agree: a run changes nothing.
    let run = world.reconcile();
    assert_eq!(run["dns"]["rrsets_changed"], 0, "{run}");
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);
    assert_eq!(
        world.ptr(&reverse_zone(NEW_IP), NEW_PTR).as_deref(),
        Some(DNS_NAME)
    );
    let report = world.api.get("/audit/verify").expect(200);
    assert_eq!(report["intact"], true, "{report}");
    world.stop();
}

#[test]
fn e17_a_deleted_ipam_record_is_restored_and_a_taken_over_one_is_proposed() {
    let world = World::new(true);
    for (ip, name) in DEVICES {
        world
            .api
            .post("/addresses", &json!({ "ip": ip, "dns_name": name }))
            .expect(201);
    }
    world.reconcile();
    let zone = world.zone_id(ZONE);
    let (cam1_ip, cam1) = DEVICES[0];
    let (_, cam2) = DEVICES[1];

    // A person deletes one `ipam` RRset (it needs take_over) and replaces another.
    world
        .api
        .post(
            &format!("/dns/zones/{zone}/records/batch"),
            &json!({ "changes": [
                { "op": "delete", "name": cam1, "type": "A", "take_over": true },
                { "op": "set", "name": cam2, "type": "A", "take_over": true,
                  "records": [{ "type": "A", "address": "192.0.2.99" }] },
            ]}),
        )
        .expect(200);
    assert!(world.rrset(ZONE, cam1, "A").is_none());

    // The next run restores the deleted record and audits it as the actuator's.
    world.reconcile();
    assert_eq!(world.a_records(cam1), [cam1_ip]);
    let audit = world
        .api
        .get("/audit?action=dns.record.actuate&limit=100")
        .expect(200);
    let audit = audit["items"].as_array().cloned().unwrap_or_default();
    assert!(
        audit
            .iter()
            .any(|record| record["principal"].to_string().contains("reconciler")),
        "{audit:?}"
    );

    // The taken-over record stays manual and is proposed as held by another origin.
    let held = world.rrset(ZONE, cam2, "A").expect("the manual record");
    assert_eq!(held["origin"], "manual");
    assert_eq!(held["records"][0]["address"], "192.0.2.99");
    let proposals = world.api.list_all("/proposals?state=open&kind=conflict");
    let proposal = proposals
        .iter()
        .find(|proposal| proposal["rule"] == "ipam.reconcile.dns_record_held")
        .unwrap_or_else(|| panic!("no held proposal: {proposals:?}"));
    assert_eq!(proposal["params"]["name"], cam2, "{proposal}");
    assert_eq!(proposal["params"]["origin"], "manual", "{proposal}");
    world.stop();
}

#[test]
fn a_cancelled_move_rolls_back_and_marks_the_host() {
    let world = World::new(true);
    world.reconcile();
    assert_eq!(world.a_records(DNS_NAME), [OLD_IP]);
    let job = world.submit();
    let index = world.waiting_step(&job);
    assert!(
        world.address(NEW_IP).is_some(),
        "the intent step planned the new address"
    );
    // One task done, the DNS step moves the records, then the operator gives up.
    world.complete(&job, index);
    world.waiting_step(&job);
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);
    world
        .api
        .post_unkeyed(&format!("/jobs/{job}/cancel"), &json!({}))
        .expect(202);
    let detail = world.api.wait_for_job(&job, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "cancelled", "{detail}");
    assert!(
        !detail["job"]["error"].is_null(),
        "the reason is on the job"
    );
    let compensated = detail["job"]["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .filter(|step| step["state"]["state"] == "compensated")
        .count();
    assert!(
        compensated >= 2,
        "the DNS and intent steps were undone: {detail}"
    );

    // Rolled back: the records point to the old address, the new intent removed, the old
    // address kept, the host marked.
    assert_eq!(world.a_records(DNS_NAME), [OLD_IP]);
    assert_eq!(
        world.ptr(&reverse_zone(OLD_IP), OLD_PTR).as_deref(),
        Some(DNS_NAME)
    );
    assert_eq!(world.ptr(&reverse_zone(NEW_IP), NEW_PTR), None);
    assert!(world.address(NEW_IP).is_none(), "the new intent is removed");
    let old = world.address(OLD_IP).expect("the old address stays");
    assert_eq!(old["interface"], world.interface.as_str());
    assert!(
        world.host_tags().iter().any(|tag| tag == "move-failed"),
        "{:?}",
        world.host_tags()
    );

    // A second move succeeds and clears the mark.
    let job = world.submit();
    for _ in 0..3 {
        let index = world.waiting_step(&job);
        world
            .api
            .post_unkeyed(&format!("/jobs/{job}/steps/{index}/complete"), &json!({}))
            .expect(200);
        let _ = world.api.wait_for_job_until(&job, JOB_TIMEOUT, |detail| {
            detail["job"]["state"] == "succeeded"
                || detail["job"]["steps"][usize::try_from(index).unwrap_or(0)]["state"]["state"]
                    == "done"
        });
    }
    let detail = world.api.wait_for_job(&job, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");
    assert!(!world.host_tags().iter().any(|tag| tag == "move-failed"));
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);
    world.stop();
}

// E25 (WP8.1): the five-device lab with Tenko DHCP serving both networks.

/// The network part of the source and the target, for option 118.
const SOURCE_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 0);
const TARGET_NET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);

/// A UDP port that was free a moment ago.
fn udp_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// One request the test relays for a device: `client` is the last octet of its MAC address
/// (`00:00:5e:00:53:xx`), `link` the network of option 118 (RFC 3011) that selects the
/// scope, as the gateway's relay would.
#[derive(Debug, Clone, Copy)]
struct Ask {
    kind: MessageType,
    client: u8,
    link: Ipv4Addr,
    ciaddr: Option<Ipv4Addr>,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
}

impl Ask {
    fn new(kind: MessageType, client: u8, link: Ipv4Addr) -> Self {
        Self {
            kind,
            client,
            link,
            ciaddr: None,
            requested: None,
            server_id: None,
        }
    }

    fn code(&self) -> u8 {
        match self.kind {
            MessageType::Discover => 1,
            MessageType::Request => 3,
            other => panic!("{other:?} is not sent here"),
        }
    }

    fn xid(&self) -> u32 {
        u32::from_be_bytes([0x7e, self.link.octets()[0], self.code(), self.client])
    }

    fn mac(&self) -> [u8; 6] {
        [0x00, 0x00, 0x5e, 0x00, 0x53, self.client]
    }

    /// The BOOTREQUEST as a relay agent at 127.0.0.1 forwards it.
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; 240];
        out[0] = 1;
        out[1] = 1;
        out[2] = 6;
        out[3] = 1;
        out[4..8].copy_from_slice(&self.xid().to_be_bytes());
        if let Some(ciaddr) = self.ciaddr {
            out[12..16].copy_from_slice(&ciaddr.octets());
        }
        out[24..28].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        out[28..34].copy_from_slice(&self.mac());
        out[236..240].copy_from_slice(&[99, 130, 83, 99]);
        // No client identifier (option 61): the devices are known by their hardware
        // address, as the reservations of their interfaces are.
        out.extend_from_slice(&[53, 1, self.code()]);
        out.extend_from_slice(&[118, 4]);
        out.extend_from_slice(&self.link.octets());
        out.extend_from_slice(&[12, 8]);
        out.extend_from_slice(format!("device{:02x}", self.client).as_bytes());
        if let Some(requested) = self.requested {
            out.extend_from_slice(&[50, 4]);
            out.extend_from_slice(&requested.octets());
        }
        if let Some(server) = self.server_id {
            out.extend_from_slice(&[54, 4]);
            out.extend_from_slice(&server.octets());
        }
        out.push(255);
        out
    }
}

/// The relay agent of the test, in front of the node's relay-mode listener.
struct Relay {
    socket: UdpSocket,
    server: SocketAddrV4,
}

impl Relay {
    fn new(port: u16, server: u16) -> Self {
        let socket =
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).expect("bind the relay");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        Self {
            socket,
            server: SocketAddrV4::new(Ipv4Addr::LOCALHOST, server),
        }
    }

    /// Sends `ask` until an answer of the expected type comes, at most `within`.
    fn exchange(&self, ask: &Ask, expect: MessageType, within: Duration) -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while start.elapsed() < within {
            self.socket
                .send_to(&ask.bytes(), self.server)
                .expect("send");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                let Ok((len, _)) = self.socket.recv_from(&mut buf) else {
                    break;
                };
                let Ok(message) = Message::parse(&buf[..len]) else {
                    continue;
                };
                if message.xid() == ask.xid()
                    && message.message_type().ok().flatten() == Some(expect)
                {
                    return Some(buf[..len].to_vec());
                }
            }
        }
        None
    }

    /// The address the device is offered on `link`.
    fn offer(&self, client: u8, link: Ipv4Addr) -> Ipv4Addr {
        let offer = self
            .exchange(
                &Ask::new(MessageType::Discover, client, link),
                MessageType::Offer,
                Duration::from_secs(10),
            )
            .unwrap_or_else(|| panic!("no OFFER for device {client:02x} on {link}"));
        Message::parse(&offer).expect("parse").yiaddr()
    }

    /// Asks until the offer on `link` satisfies `wanted` (the role follows the store a
    /// moment behind, and an offer is held for ten seconds); the last offer.
    fn offer_until(
        &self,
        client: u8,
        link: Ipv4Addr,
        wanted: impl Fn(Ipv4Addr) -> bool,
    ) -> Ipv4Addr {
        let start = Instant::now();
        loop {
            let offered = self.offer(client, link);
            if wanted(offered) || start.elapsed() > Duration::from_secs(20) {
                return offered;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// A DORA exchange on `link`; the address of the ACK.
    fn dora(&self, client: u8, link: Ipv4Addr) -> Ipv4Addr {
        let offer = self
            .exchange(
                &Ask::new(MessageType::Discover, client, link),
                MessageType::Offer,
                Duration::from_secs(10),
            )
            .unwrap_or_else(|| panic!("no OFFER for device {client:02x} on {link}"));
        let offer = Message::parse(&offer).expect("parse");
        let mut request = Ask::new(MessageType::Request, client, link);
        request.requested = Some(offer.yiaddr());
        request.server_id = offer.server_identifier().expect("54");
        let ack = self
            .exchange(&request, MessageType::Ack, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("no ACK for device {client:02x} on {link}"));
        let ack = Message::parse(&ack).expect("parse");
        assert_eq!(ack.yiaddr(), offer.yiaddr());
        ack.yiaddr()
    }

    /// A renewal (RENEWING, `ciaddr` set) of `addr` on `link`.
    fn renew(&self, client: u8, link: Ipv4Addr, addr: Ipv4Addr) -> Ipv4Addr {
        let mut renew = Ask::new(MessageType::Request, client, link);
        renew.ciaddr = Some(addr);
        let ack = self
            .exchange(&renew, MessageType::Ack, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("no ACK for the renewal of {addr}"));
        Message::parse(&ack).expect("parse").yiaddr()
    }
}

/// The five devices of E25: (name, mode, last MAC octet, address, DNS name).
const LAB: [(&str, &str, u8, &str, Option<&str>); 5] = [
    ("printer", "reserved", 0x20, "192.0.2.15", Some(DNS_NAME)),
    ("cam1", "reserved", 0x21, "192.0.2.21", None),
    ("cam2", "reserved", 0x22, "192.0.2.22", None),
    ("sensor", "static", 0x23, "192.0.2.23", None),
    ("plug", "dynamic", 0x24, "192.0.2.24", None),
];

/// The E25 lab: one node with the `dhcp` role in relay mode on loopback, both networks
/// with a pool and a Tenko scope, the zone `example.test`, and the five devices.
struct DhcpLab {
    world: World,
    relay: Relay,
    hosts: Vec<String>,
}

impl DhcpLab {
    fn new() -> Self {
        let port = udp_port();
        let relay_port = udp_port();
        let relay = Relay::new(relay_port, port);
        let mut node = Node::new()
            .with_args(&["--roles", "controller,dhcp"])
            .with_config(&format!(
                "[dhcp]\nlisten = [{{ address = \"127.0.0.1\", mode = \"relay\" }}]\n\
                 port = {port}\nrelay_port = {relay_port}\nworkers = 2\n"
            ));
        let server = node.start();
        let line = format!("dhcp role answering on 127.0.0.1:{port} (relay)");
        server
            .wait_stdout_line(Duration::from_secs(10), |text| text.starts_with(&line))
            .unwrap_or_else(|| panic!("no dhcp line\n{}", server.diagnostics()));
        let token = wait_for_setup_token(&server);
        let mut api = Api::new(&node);
        api.setup(&token);
        // Runs on demand do the DNS work; a new fact (a lease) starts a run a second
        // later, which is how the observation step learns of a lease without polling.
        let mut settings = quiet_settings();
        settings["debounce_secs"] = json!(1);
        api.put("/settings/reconciler", &settings).expect(200);
        api.post(
            "/dns/zones",
            &json!({
                "name": ZONE,
                "kind": "primary",
                "soa": { "mname": "ns1.example.test", "rname": "hostmaster.example.test" },
                "name_servers": ["ns1.example.test"],
            }),
        )
        .expect(201);
        let mut target = String::new();
        for (cidr, pool) in [
            (SOURCE, ("192.0.2.100", "192.0.2.199")),
            (TARGET, ("198.51.100.100", "198.51.100.199")),
        ] {
            let prefix = api.post("/prefixes", &json!({ "cidr": cidr })).expect(201)["item"]["id"]
                .as_str()
                .expect("a prefix id")
                .to_owned();
            api.post(
                &format!("/prefixes/{prefix}/ranges"),
                &json!({ "first": pool.0, "last": pool.1, "role": "dhcp_pool" }),
            )
            .expect(201);
            api.post("/dhcp/scopes", &json!({ "prefix": prefix }))
                .expect(201);
            target = prefix;
        }
        let mut hosts = Vec::new();
        let mut first_interface = String::new();
        for (name, mode, client, ip, dns) in LAB {
            let host = api
                .post(
                    "/hosts",
                    &json!({
                        "name": name,
                        "mode": mode,
                        "interfaces": [{ "name": "eth0", "mac": format!("00-00-5E-00-53-{client:02X}") }],
                    }),
                )
                .expect(201)["item"]["id"]
                .as_str()
                .expect("a host id")
                .to_owned();
            let interfaces = api.get(&format!("/hosts/{host}/interfaces")).expect(200);
            let interface = interfaces["items"][0]["id"]
                .as_str()
                .expect("the interface")
                .to_owned();
            let mut address = json!({ "ip": ip, "interface": interface });
            if let Some(dns) = dns {
                address["dns_name"] = json!(dns);
            }
            api.post("/addresses", &address).expect(201);
            if first_interface.is_empty() {
                first_interface.clone_from(&interface);
            }
            hosts.push(host);
        }
        let world = World {
            node,
            server,
            api,
            target,
            host: hosts[0].clone(),
            interface: first_interface,
        };
        Self {
            world,
            relay,
            hosts,
        }
    }

    fn api(&self) -> &Api {
        &self.world.api
    }

    /// The move of the hosts at `devices` (indexes of [`LAB`]); its jobs in order.
    fn submit(&self, devices: &[usize]) -> Vec<String> {
        let objects: Vec<Value> = devices
            .iter()
            .map(|index| json!({ "kind": "host", "id": self.hosts[*index] }))
            .collect();
        let submitted = self
            .api()
            .post(
                "/moves",
                &json!({ "objects": objects, "target": self.world.target }),
            )
            .expect(202);
        submitted["jobs"]
            .as_array()
            .expect("jobs")
            .iter()
            .map(|job| job["job_id"].as_str().expect("a job id").to_owned())
            .collect()
    }

    /// The kind of the step the job waits at for a person.
    fn waiting_kind(&self, job: &str) -> (u64, String) {
        let index = self.world.waiting_step(job);
        let detail = self.api().get(&format!("/jobs/{job}")).expect(200);
        let kind = detail["job"]["steps"][usize::try_from(index).expect("index")]["kind"]
            .as_str()
            .expect("a kind")
            .to_owned();
        (index, kind)
    }

    /// The state of a lease row through the lease routes.
    fn lease_state(&self, addr: &str) -> String {
        self.api().get(&format!("/dhcp/leases/{addr}")).expect(200)["state"]
            .as_str()
            .expect("a state")
            .to_owned()
    }

    /// The text of `/metrics`.
    fn metrics(&self) -> String {
        self.api().get("/metrics").text
    }
}

fn addr(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

fn in_pool(addr: Ipv4Addr, net: Ipv4Addr) -> bool {
    addr.octets()[..3] == net.octets()[..3] && (100..=199).contains(&addr.octets()[3])
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn e25_the_dhcp_step_is_automatic_for_reserved_devices_and_a_lease_confirms_the_move() {
    let lab = DhcpLab::new();
    let world = &lab.world;
    let relay = &lab.relay;
    world.reconcile();
    assert_eq!(world.a_records(DNS_NAME), [OLD_IP]);

    // Before the move: the reserved devices get their reservations from intent in the
    // source scope, the dynamic plug an address of the pool.
    assert_eq!(relay.dora(0x20, SOURCE_NET), addr(OLD_IP));
    assert_eq!(relay.dora(0x21, SOURCE_NET), addr("192.0.2.21"));
    assert_eq!(relay.dora(0x22, SOURCE_NET), addr("192.0.2.22"));
    assert!(in_pool(relay.dora(0x24, SOURCE_NET), SOURCE_NET));
    // ADR 0031: a lease change writes no fact at all, a renewal included; the lease row is
    // the observation, and the counter of the facts the lease batch wrote is gone.
    assert_eq!(relay.renew(0x20, SOURCE_NET, addr(OLD_IP)), addr(OLD_IP));
    assert!(!lab.metrics().contains("tenko_dhcp_lease_facts_total"));

    // The preview of the printer and cam2: the DHCP step automatic for both, the DNS step
    // automatic for the printer. Both hold their lease of a day in the source scope, whose
    // next renewal (T1, twelve hours away) is later than the preparation limit of an hour:
    // no wait for the short lease, and the deadline is the end of that lease plus the
    // margin (docs/moves.md section 5).
    let preview = lab
        .api()
        .post(
            "/moves?dry_run=true",
            &json!({
                "objects": [
                    { "kind": "host", "id": lab.hosts[0] },
                    { "kind": "host", "id": lab.hosts[2] },
                ],
                "target": world.target,
            }),
        )
        .expect(200);
    assert_eq!(preview["timeout_source"], "lease", "{preview}");
    let longest = preview["timeout_secs"].as_u64().expect("secs");
    assert!((86_000..=86_460).contains(&longest), "{preview}");
    assert_eq!(
        preview["items"][0]["timing"]["prepare"], "limit",
        "{preview}"
    );
    assert_eq!(
        preview["items"][0]["timing"]["next_activity_source"], "lease",
        "{preview}"
    );
    let printer = &preview["items"][0];
    assert_eq!(
        step_kinds(printer),
        [
            "dhcp.prepare",
            "ipam.intent",
            "dhcp.reservation",
            "dns.records",
            "dhcp.short_lease",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );
    assert_eq!(
        automatic(printer),
        [true, true, true, true, false, false, false, true]
    );
    assert_eq!(
        step_kinds(&preview["items"][1]),
        [
            "dhcp.prepare",
            "ipam.intent",
            "dhcp.reservation",
            "dhcp.short_lease",
            "l2.move",
            "observe",
            "cleanup"
        ]
    );

    // The bulk move: each job plans its new address, waits until the role serves the new
    // reservation, moves the printer's records and waits for the L2 change. Both scopes
    // hold a reservation now.
    let jobs = lab.submit(&[0, 2]);
    for (job, client, old, new) in [
        (&jobs[0], 0x20, OLD_IP, NEW_IP),
        (&jobs[1], 0x22, "192.0.2.22", "198.51.100.22"),
    ] {
        let (index, kind) = lab.waiting_kind(job);
        assert_eq!(kind, "ipam.move.l2", "{job}");
        assert_eq!(relay.offer(client, TARGET_NET), addr(new));
        assert_eq!(relay.offer(client, SOURCE_NET), addr(old));
        world.complete(job, index);
        let (_, kind) = lab.waiting_kind(job);
        assert_eq!(kind, "ipam.move.observe", "{job}");
    }
    assert_eq!(world.a_records(DNS_NAME), [NEW_IP]);

    // The devices come up in the target network and take their new leases: the facts of
    // the leases confirm the observation steps, nobody ticks them.
    assert_eq!(relay.dora(0x20, TARGET_NET), addr(NEW_IP));
    assert_eq!(relay.dora(0x22, TARGET_NET), addr("198.51.100.22"));
    for (job, old, client) in [(&jobs[0], OLD_IP, 0x20), (&jobs[1], "192.0.2.22", 0x22)] {
        let detail = world.api.wait_for_job(job, JOB_TIMEOUT);
        assert_eq!(detail["job"]["state"], "succeeded", "{detail}");
        let observe = detail["job"]["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .find(|step| step["kind"] == "ipam.move.observe")
            .expect("the observation step")
            .clone();
        assert_eq!(observe["state"]["state"], "done", "{observe}");
        // The cleanup released the old lease, and the old reservation went with the old
        // address: the source scope offers the device an address of its pool.
        assert_eq!(lab.lease_state(old), "released");
        assert!(world.address(old).is_none());
        let offered = relay.offer_until(client, SOURCE_NET, |offered| offered != addr(old));
        assert!(in_pool(offered, SOURCE_NET), "{offered}");
    }
    let new = world.address(NEW_IP).expect("the new address");
    assert_eq!(new["status"], "active");

    // The dynamic plug: no DHCP step, and its lease from the target's pool confirms the
    // move although it is not the planned address.
    let plug = lab.submit(&[4]).remove(0);
    let (index, kind) = lab.waiting_kind(&plug);
    assert_eq!(kind, "ipam.move.l2");
    world.complete(&plug, index);
    assert!(in_pool(relay.dora(0x24, TARGET_NET), TARGET_NET));
    let detail = world.api.wait_for_job(&plug, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");

    // The static sensor stops at its manual step: nothing reconfigures it.
    let sensor = lab.submit(&[3]).remove(0);
    let (_, kind) = lab.waiting_kind(&sensor);
    assert_eq!(kind, "ipam.move.device");

    // cam1 is moved and cancelled while it waits for the L2 change: the rollback removes
    // the new reservation and keeps the old one.
    let cam1 = lab.submit(&[1]).remove(0);
    let (_, kind) = lab.waiting_kind(&cam1);
    assert_eq!(kind, "ipam.move.l2");
    assert_eq!(relay.offer(0x21, TARGET_NET), addr("198.51.100.21"));
    lab.api()
        .post_unkeyed(&format!("/jobs/{cam1}/cancel"), &json!({}))
        .expect(202);
    let detail = world.api.wait_for_job(&cam1, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "cancelled", "{detail}");
    assert!(world.address("198.51.100.21").is_none());
    let offered = relay.offer_until(0x21, TARGET_NET, |offered| offered != addr("198.51.100.21"));
    assert!(in_pool(offered, TARGET_NET), "{offered}");
    assert_eq!(relay.offer(0x21, SOURCE_NET), addr("192.0.2.21"));
    assert_eq!(lab.lease_state("192.0.2.21"), "active");

    let report = lab.api().get("/audit/verify").expect(200);
    assert_eq!(report["intact"], true, "{report}");
    let DhcpLab { world, .. } = lab;
    world.stop();
}
