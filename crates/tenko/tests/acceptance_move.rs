//! The move flow of IPAM-19 against the real binary, through the public API: the manual
//! steps of exit criterion E8 as far as Slice 1 has them (DHCP, DNS, the L2 change and the
//! observation are tasks a person ticks off; Tenko DHCP, DNS and the network controllers
//! automate them in later phases).
//!
//! - Success: a `reserved` host with a MAC and an address with a DNS name in 192.0.2.0/24
//!   moves to 198.51.100.0/24. The dry run previews the same host part and the steps in
//!   order; the submit starts one job; each manual step is completed through
//!   `POST /jobs/{id}/steps/{index}/complete` until the job succeeds; the new address is
//!   active on the interface and the old one is deleted.
//! - Failure: the API offers no way to fail a manual step, and the observation timeout has
//!   a floor of 300 seconds, so the failure path is a cancellation of the waiting job: the
//!   engine compensates in reverse (the new address is removed, the old one stays) and
//!   ends the job `cancelled`, and the host carries the tag `move-failed`.

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
const JOB_TIMEOUT: Duration = Duration::from_secs(60);

/// The preview step kinds of a `reserved` host whose address has a DNS name.
const STEP_KINDS: [&str; 6] = [
    "ipam.intent",
    "dhcp.manual",
    "dns.manual",
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
    /// A fresh instance with the two prefixes and the host.
    fn new() -> Self {
        let mut node = Node::new();
        let server = node.start();
        let token = wait_for_setup_token(&server);
        let mut api = Api::new(&node);
        api.setup(&token);
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

    fn stop(mut self) {
        self.server.stop().assert_graceful_shutdown();
        drop(self.node);
    }
}

fn step_kinds(item: &Value) -> Vec<String> {
    item["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["kind"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn a_reserved_host_moves_after_its_manual_steps() {
    let world = World::new();

    // The dry run: the same host part, the steps in order, nothing written.
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
    assert_eq!(step_kinds(item), STEP_KINDS);
    let automatic: Vec<bool> = item["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["automatic"] == true)
        .collect();
    assert_eq!(automatic, [true, false, false, false, false, true]);
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
        let summary = world
            .api
            .post_unkeyed(
                &format!("/jobs/{job}/steps/{index}/complete"),
                &json!({ "note": format!("done in the acceptance test, step {index}") }),
            )
            .expect(200);
        assert_eq!(summary["id"], job.as_str());
        completed += 1;
        assert!(completed <= 4, "more manual steps than the preview listed");
        let detail = world.api.wait_for_job_until(&job, JOB_TIMEOUT, |detail| {
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
fn a_cancelled_move_rolls_back_and_marks_the_host() {
    let world = World::new();
    let job = world.submit();
    let index = world.waiting_step(&job);
    assert!(
        world.address(NEW_IP).is_some(),
        "the intent step planned the new address"
    );
    // One task done, then the operator gives up.
    world
        .api
        .post_unkeyed(
            &format!("/jobs/{job}/steps/{index}/complete"),
            &json!({ "note": "reservation added" }),
        )
        .expect(200);
    world.waiting_step(&job);
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
    assert!(compensated >= 1, "the intent step was undone: {detail}");

    // Rolled back: the new intent removed, the old address kept, the host marked.
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
    for _ in 0..4 {
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
    world.stop();
}
