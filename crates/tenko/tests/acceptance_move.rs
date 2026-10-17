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

mod serve_support;

use std::time::Duration;

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, wait_for_setup_token};

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
